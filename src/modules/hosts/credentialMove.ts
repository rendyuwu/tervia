import {
  identityRecordFrom,
  keyRecordFrom,
  type IdentityDraft,
  type KeyDraft,
} from "@/modules/vault/editor/draft";
import type { VaultKeyFacts } from "@/modules/vault/keyInspect";
import { HOST_SSH_FIELDS, VAULT_SSH_FIELDS } from "@/modules/vault/resolve";
import {
  SECRET_ALREADY_STORED,
  vaultStore,
  type VaultSecretValue,
  type VaultStore,
} from "@/modules/vault/store";
import {
  HOST_KEYRING_SERVICE,
  VAULT_KEYRING_SERVICE,
  vaultAccount,
  type VaultAuthMode,
  type VaultIdentity,
  type VaultKey,
} from "@/modules/vault/types";
import { tauriSecretsIo, type SecretEntry, type SecretsIo } from "@/modules/vault/adapters";

import { hostsStore, type HostSecretInput, type HostsStore } from "./store";
import { CREDENTIAL_STAMP_INLINE, credentialStamp, type Host } from "./types";

// Where a host's credentials move into the vault and back, and the one
// module that spans both stores for that reason - see `TERVIA.md`'s "The
// vault" section. `modules/hosts` may import `modules/vault` (it already
// does, `./store.ts:2-21`); `modules/vault` must never import `modules/hosts`
// as a value (`vault/refs.ts:19-21`), so this file lives here, not there.
//
// Every account it touches is built from `HOST_SSH_FIELDS` / `VAULT_SSH_FIELDS`
// (`vault/resolve.ts`), never from a field name spelled out again - the one
// field that differs between the two sides (`keyPassphrase` on a host,
// `passphrase` on a key) is exactly the one a second spelling would get
// wrong.
//
// NOTHING HERE READS A SECRET. `SecretsIo.copy` moves a value in-process and
// never returns it; a field that copied is recorded as
// `SECRET_ALREADY_STORED`, the fourth secret-input state that means exactly
// that.

/**
 * One account move: the entry it is at now, and the entry it must be at.
 * `field` is the logical name shared with `HostSecretInput` /
 * `SshSecretValues` (`password` | `privateKey` | `keyPassphrase`), not
 * necessarily the account string on either side - see `VAULT_SSH_FIELDS`
 * for why the vault side's passphrase field differs.
 */
export type AccountMove = { field: string; from: SecretEntry; to: SecretEntry };

function hostEntry(hostId: string, field: string): SecretEntry {
  return { service: HOST_KEYRING_SERVICE, account: vaultAccount(hostId, field) };
}

function vaultEntry(id: string, field: string): SecretEntry {
  return { service: VAULT_KEYRING_SERVICE, account: vaultAccount(id, field) };
}

/**
 * Every account an inline host owns, mapped onto the vault accounts a new
 * identity (and, when `keyId` is given, a new key) will own.
 *
 * For an RDP host the list is the password row alone, using the same
 * `HOST_SSH_FIELDS.password` / `VAULT_SSH_FIELDS.password` names an SSH
 * password uses - the RDP-specific field constants carry the identical
 * string value, so there is no second mapping to keep in step with this one.
 */
export function convertMoves(host: Host, identityId: string, keyId: string | null): AccountMove[] {
  const moves: AccountMove[] = [
    {
      field: HOST_SSH_FIELDS.password,
      from: hostEntry(host.id, HOST_SSH_FIELDS.password),
      to: vaultEntry(identityId, VAULT_SSH_FIELDS.password),
    },
  ];
  if (host.protocol === "rdp" || keyId === null) return moves;
  moves.push(
    {
      field: HOST_SSH_FIELDS.privateKey,
      from: hostEntry(host.id, HOST_SSH_FIELDS.privateKey),
      to: vaultEntry(keyId, VAULT_SSH_FIELDS.privateKey),
    },
    {
      field: HOST_SSH_FIELDS.keyPassphrase,
      from: hostEntry(host.id, HOST_SSH_FIELDS.keyPassphrase),
      to: vaultEntry(keyId, VAULT_SSH_FIELDS.keyPassphrase),
    },
  );
  return moves;
}

/**
 * The reverse: every account the identity and its key own, mapped onto the
 * accounts this host will own - gated by the HOST's protocol, because an
 * inline RDP arm has one account and `nextRdpCredential` throws if key
 * material is handed to it (`./store.ts:677-679`).
 */
export function detachMoves(
  host: Host,
  identity: VaultIdentity,
  keyId: string | null,
): AccountMove[] {
  const password: AccountMove = {
    field: HOST_SSH_FIELDS.password,
    from: vaultEntry(identity.id, VAULT_SSH_FIELDS.password),
    to: hostEntry(host.id, HOST_SSH_FIELDS.password),
  };
  if (host.protocol === "rdp" || keyId === null) return [password];
  return [
    password,
    {
      field: HOST_SSH_FIELDS.privateKey,
      from: vaultEntry(keyId, VAULT_SSH_FIELDS.privateKey),
      to: hostEntry(host.id, HOST_SSH_FIELDS.privateKey),
    },
    {
      field: HOST_SSH_FIELDS.keyPassphrase,
      from: vaultEntry(keyId, VAULT_SSH_FIELDS.keyPassphrase),
      to: hostEntry(host.id, HOST_SSH_FIELDS.keyPassphrase),
    },
  ];
}

/** Every move, sequentially - one keychain write is a read-modify-write of the
 *  whole secrets file on Linux and Windows, the same reason
 *  `deleteAccounts` (`./store.ts:547-551`) is not a `Promise.all`. Keyed by
 *  `field`, so a caller reads "did this field copy" without re-deriving the
 *  account string. */
async function copyMoves(
  secrets: SecretsIo,
  moves: readonly AccountMove[],
): Promise<Record<string, boolean>> {
  const copied: Record<string, boolean> = {};
  for (const move of moves) {
    copied[move.field] = await secrets.copy(move.from, move.to);
  }
  return copied;
}

/** The `HostSecretInput` a detach copy produces: a field that copied is
 *  `SECRET_ALREADY_STORED`, everything else omitted. */
function hostSecretsFromCopies(copied: Record<string, boolean>): HostSecretInput {
  const out: HostSecretInput = {};
  if (copied[HOST_SSH_FIELDS.password]) out.password = SECRET_ALREADY_STORED;
  if (copied[HOST_SSH_FIELDS.privateKey]) out.privateKey = SECRET_ALREADY_STORED;
  if (copied[HOST_SSH_FIELDS.keyPassphrase]) out.keyPassphrase = SECRET_ALREADY_STORED;
  return out;
}

export type CredentialMoveDeps = {
  /** `identityHostRefs` and `findHost` are here for the two compensating
   *  deletes alone - see {@link undoConvertRecords} for why the first is the
   *  real lookup and not `() => []`, and {@link undoDetachCopies} for why the
   *  second re-reads rather than reasoning about what is stored. */
  hosts: Pick<HostsStore, "upsertHost" | "identityHostRefs" | "findHost">;
  vault: Pick<
    VaultStore,
    | "newIdentityId"
    | "newKeyId"
    | "upsertIdentity"
    | "upsertKey"
    | "findIdentity"
    | "findKey"
    | "deleteIdentity"
    | "deleteKey"
  >;
  secrets: SecretsIo;
};

/** Modelled on `ResolveDeps` / `defaultResolveDeps` (`vault/resolve.ts:141-143`),
 *  which is what makes this whole module exercisable under plain node against
 *  in-memory ports. */
export const defaultCredentialMoveDeps: CredentialMoveDeps = {
  hosts: hostsStore,
  vault: vaultStore,
  secrets: tauriSecretsIo,
};

/** Whether the STORED inline record needs a vault key: an SSH host owning
 *  private-key material, read off its own credential arm rather than the
 *  auth mode a caller might pick for the new identity. */
function inlineNeedsKey(host: Host): boolean {
  if (host.protocol !== "ssh") return false;
  const credential = host.credential;
  return credential.kind === "inline" && (credential.hasPrivateKey || credential.hasKeyPassphrase);
}

/**
 * The new identity's auth mode, read off the STORED inline arm - the SAME place
 * {@link inlineNeedsKey} reads from, which is the whole point of it existing.
 *
 * The two used to come from different places: this from the caller's draft,
 * `inlineNeedsKey` from the record. Every credential defect this round fixed was
 * that disagreement. A draft on "key" over a record holding no key made
 * `upsertIdentity` refuse ("uses key auth but names no key") AFTER the copies
 * had already landed, stranding a plaintext password at an unenumerable vault
 * account once per press; a draft on "password" over a record holding a PEM
 * minted a `VaultKey` that the normaliser then left nameless, and an unnamed key
 * is one Vault-page click from gone. Reading both from the record removes the
 * disagreement structurally rather than checking for it.
 *
 * Convert is an operation on the STORED record, and §1.4 already settles
 * "record, not mode" for which accounts travel; this is the same rule applied to
 * the field that says what those accounts are for. The user's edits to `name`,
 * `username`, `domain` and `description` still come from the draft: those carry
 * no invariant against the accounts being moved.
 *
 * RDP is `"password"`, as it has always been: an RDP inline arm has no auth mode
 * of its own, and its one account is a password. The non-inline arm is the
 * NARROWING and not a decision - `convertHostToVault`'s first pre-check has
 * already refused a bound host by the time this is called.
 */
function inlineAuthMode(host: Host): VaultAuthMode {
  if (host.protocol !== "ssh") return "password";
  const credential = host.credential;
  return credential.kind === "inline" ? credential.authMode : "password";
}

/**
 * Remove the vault records a convert just minted, because the host write that
 * was going to reference them refused.
 *
 * WHY DELETING THEM CANNOT COST ANYONE A RECORD THEY OWN: both ids came out of
 * `newIdentityId()` / `newKeyId()` a few statements earlier, inside this one
 * call, and nothing outside it has been handed either one - the host write is
 * the only thing that would have, and it is the call that just threw. So
 * neither id can name a record that existed before this operation. That is an
 * argument about where the ids came FROM, not about the delete, and it does not
 * carry over to an id that arrived from anywhere else: a compensating delete
 * over a pre-existing record would destroy something the user made.
 *
 * IDENTITY FIRST. `deleteKey` refuses while any identity still names the key
 * (`vault/store.ts:337-347`), and the identity minted above names it, so the
 * reverse order refuses its own cleanup and leaves both records behind.
 *
 * THE ACCOUNTS GO WITH THE RECORDS. Both deletes clear the record's vault
 * accounts as part of removing it (`vault/store.ts:323-327` and `:348-352`),
 * which is the half that matters: step 4 put a SECOND copy of the host's secret
 * at those accounts, and a cleanup that dropped only the records would leave
 * exactly the extra copy this whole feature exists to avoid.
 *
 * `identityHostRefs` is the real lookup, passed by name, rather than a
 * `() => []` shortcut. It finds no holders on the path this runs on - nothing
 * binds the new identity - and it is the store's own guard over the one case
 * the provenance argument does not cover: `upsertHost` throwing at its
 * `persist` (`./store.ts:798-802`), where the record is already in the plugin's
 * cache with a debounced retry behind it, so a host DOES name this identity and
 * the delete is refused rather than stranding that host.
 *
 * EVERY FAILURE IN HERE IS SWALLOWED - the same swallow, for the same reason,
 * as `vault/store.ts`'s key-secret rollback. The caller is already rethrowing
 * the host write's own error, which is the one the user can act on and the one
 * `HostEditorDialog`'s recovery arm branches on by instance (VLT-29). A cleanup
 * failure must never become the error that arrives there.
 */
async function undoConvertRecords(
  deps: CredentialMoveDeps,
  identityId: string,
  keyId: string | null,
): Promise<void> {
  try {
    await deps.vault.deleteIdentity(identityId, deps.hosts.identityHostRefs);
  } catch {
    // See above: this must not become the error the caller sees.
  }
  if (keyId === null) return;
  try {
    await deps.vault.deleteKey(keyId);
  } catch {
    // Attempted even when the identity delete threw, because the two records
    // fail independently and stopping here would leave a key holding a copy of
    // the private material with nothing naming it.
  }
}

/**
 * Move an inline host's credentials into a brand-new identity (and, when the
 * host stores key material, a brand-new key), then bind the host to it.
 *
 * The order is the whole design (research §5.3, and `./store.ts:804-812` is
 * where step 5 of it already happens):
 *
 * 1. Refuse unless the host is inline.
 * 2. Refuse when the host stores key material but no key was given.
 * 3. Refuse when the record authenticates BY key and stores none.
 * 4. Mint the new ids.
 * 5. Copy every account, sequentially.
 * 6. Write the key, when there is one, through `keyRecordFrom` - not a
 *    hand-assembled `VaultKey` (wave-3 boundary 7: one builder).
 * 7. Write the identity through `identityRecordFrom`, the single normaliser
 *    of `keyId` (wave-3 boundary 6, VLT-73).
 * 8. Bind the host. `releaseStaleAccounts` then clears its accounts, because
 *    a non-inline record owns none.
 * 9. Return all three records.
 *
 * Steps 5 to 8 do not move: copy-then-write is §4.5's ordering, where an orphan
 * account after a good write is the lesser evil and a crash between the copy
 * and the write must never cost a key. What step 8 gained is a FAILURE path.
 * `upsertHost` is the first call here that can refuse for anything other than
 * the three cheap pre-checks above - a dangling `proxyJumpId`, a tunnel target
 * that is not an SSH host, a jump cycle, a stamp that moved underneath the
 * caller - and until this fix every one of those refusals left the identity, the
 * key and a second copy of the host's secret behind, in a feature whose own
 * confirmation copy tells the user the point is fewer copies of one credential.
 * See {@link undoConvertRecords} for why undoing them is admissible here and
 * would not be for a record that already existed.
 *
 * THE IDENTITY'S AUTH MODE IS NOT A PARAMETER, deliberately (owner's decision,
 * 2026-09-01). It is derived from the stored record by {@link inlineAuthMode},
 * which is where the reasoning lives; the short version is that a caller able to
 * pass one was able to disagree with `inlineNeedsKey`, and both P0s this round
 * fixed were that disagreement. Removing the parameter is what makes the class
 * unreachable rather than merely guarded: no caller can get it wrong.
 */
export async function convertHostToVault(
  args: {
    /** The STORED record, as the caller loaded it. */
    host: Host;
    /** The new identity's non-secret fields. NOT `authMode` - see the note
     *  above and {@link inlineAuthMode}; these four are the ones the user may
     *  have edited and none of them carries an invariant. */
    identity: {
      name: string;
      username: string;
      domain: string;
      description: string;
    };
    /** The new key's name and facts. Required when the host stores key
     *  material, ignored when it does not. */
    key: { name: string; facts: VaultKeyFacts } | null;
  },
  deps: CredentialMoveDeps = defaultCredentialMoveDeps,
): Promise<{ host: Host; identity: VaultIdentity; key: VaultKey | null }> {
  if (credentialStamp(args.host) !== CREDENTIAL_STAMP_INLINE) {
    throw new Error(
      `hosts: "${args.host.name}" does not use its own credentials, so there is nothing to convert`,
    );
  }
  const needsKey = inlineNeedsKey(args.host);
  if (needsKey && !args.key) {
    throw new Error(
      `hosts: "${args.host.name}" stores a private key, and converting it needs a name for the new key`,
    );
  }
  const authMode = inlineAuthMode(args.host);
  // Deriving the mode from the record removes every DISAGREEMENT between the two
  // reads, but not this state, which one record can hold on its own: key auth
  // with `hasPrivateKey: false`, a key-auth host whose body was never stored.
  // `upsertIdentity` refuses it ("uses key auth but names no key") - and refuses
  // it at step 7, after the copies of step 5 have already landed on vault
  // accounts nothing will ever name. So it is refused HERE, beside the other two
  // pre-checks and before a single byte moves.
  if (authMode === "key" && !needsKey) {
    throw new Error(
      `hosts: "${args.host.name}" authenticates with a private key but stores none, so the new identity would name no key`,
    );
  }

  const keyId = needsKey ? deps.vault.newKeyId() : null;
  const identityId = deps.vault.newIdentityId();

  const copied = await copyMoves(deps.secrets, convertMoves(args.host, identityId, keyId));

  let key: VaultKey | null = null;
  if (keyId !== null && args.key) {
    const keyDraft: KeyDraft = {
      name: args.key.name,
      privateKey: "",
      passphrase: "",
      description: "",
    };
    const keySecrets: { privateKey?: VaultSecretValue; passphrase?: VaultSecretValue } = {};
    if (copied[HOST_SSH_FIELDS.privateKey]) keySecrets.privateKey = SECRET_ALREADY_STORED;
    if (copied[HOST_SSH_FIELDS.keyPassphrase]) keySecrets.passphrase = SECRET_ALREADY_STORED;
    const upserted = await deps.vault.upsertKey(
      keyRecordFrom(keyId, keyDraft, null, args.key.facts),
      keySecrets,
    );
    key = upserted.record;
  }

  const identityDraft: IdentityDraft = {
    name: args.identity.name,
    username: args.identity.username,
    domain: args.identity.domain,
    authMode,
    password: "",
    keyId: keyId ?? "",
    description: args.identity.description,
  };
  const identitySecrets: { password?: VaultSecretValue } = {};
  if (copied[HOST_SSH_FIELDS.password]) identitySecrets.password = SECRET_ALREADY_STORED;
  // `"keep"` - the identity names the key WHENEVER one was minted, and not only
  // when the mode uses it (owner's decision, 2026-09-01). This is accepted gap
  // 12's case: a host that once used key auth, now authenticates by password,
  // still carries its PEM. That PEM must travel (§1.4), and a `VaultKey` nothing
  // names is one Vault-page click from destroyed - `deleteKey`'s in-use guard
  // (`vault/store.ts:337-347`) has no holder to refuse over. So the record built
  // here is deliberately the one VLT-73 called off-spec, a key chip on a
  // password identity, and the owner took that trade with the consequence
  // understood: a misleading chip is strictly better than losing the user's only
  // copy of a private key. It reopens VLT-73's rendering question - what that
  // chip should say on a non-key identity - EARLIER than 6g, which is where that
  // was scheduled.
  //
  // The opt-out is a named argument on `identityRecordFrom`, never a
  // `VaultIdentity` assembled here: that function is VLT-73's single normaliser
  // (wave-3 boundary 6), and a second assembly in this file is the drift it
  // exists to prevent.
  const identityUpsert = await deps.vault.upsertIdentity(
    identityRecordFrom(identityId, identityDraft, "keep"),
    identitySecrets,
  );

  let nextHost: Host;
  try {
    nextHost = await deps.hosts.upsertHost(
      { ...args.host, credential: { kind: "identity", identityId } },
      {},
      credentialStamp(args.host),
    );
  } catch (e) {
    await undoConvertRecords(deps, identityId, keyId);
    // The ORIGINAL error, unchanged and by identity: `HostEditorDialog`'s
    // recovery arm tests `instanceof HostBindingChangedError` and reads
    // `hostId` / `expected` / `actual` off it (VLT-29), so wrapping this or
    // replacing it with the cleanup's own would turn a recoverable refusal
    // into an unrecognised one.
    throw e;
  }

  return { host: nextHost, identity: identityUpsert.record, key };
}

/**
 * Bind a host to an existing identity. Copies nothing: the host's own
 * accounts are released by `upsertHost`'s stale-account cleanup, which is
 * destructive, which is why the caller must already have confirmed -
 * `credentialChoice.ts`'s `credentialChangeNote` is where the user was told,
 * for the `bind` outcome.
 */
export async function bindHostToIdentity(
  args: { host: Host; identityId: string },
  deps: CredentialMoveDeps = defaultCredentialMoveDeps,
): Promise<Host> {
  const identity = await deps.vault.findIdentity(args.identityId);
  if (!identity) {
    throw new Error(
      `hosts: "${args.host.name}" cannot bind to identity ${args.identityId}, which no longer exists`,
    );
  }
  return deps.hosts.upsertHost(
    { ...args.host, credential: { kind: "identity", identityId: args.identityId } },
    {},
    credentialStamp(args.host),
  );
}

type SshInlineArgs = { user: string; authMode: VaultAuthMode };
type RdpInlineArgs = { username: string; domain: string };

function isRdpInlineArgs(inline: SshInlineArgs | RdpInlineArgs): inline is RdpInlineArgs {
  return "username" in inline;
}

/** The inline arm the store overwrites `has*` flags on once it knows what it
 *  actually wrote - the same placeholder pattern `HostEditorDialog.tsx:737-741`
 *  hands over. Refuses rather than guessing when `inline`'s shape does not
 *  match the host's own protocol, which no caller should be able to reach. */
function buildInlineRecord(host: Host, inline: SshInlineArgs | RdpInlineArgs): Host {
  if (host.protocol === "rdp" && isRdpInlineArgs(inline)) {
    return {
      ...host,
      credential: {
        kind: "inline",
        hostId: host.id,
        username: inline.username,
        domain: inline.domain.trim() || undefined,
        hasPassword: false,
      },
    };
  }
  if (host.protocol === "ssh" && !isRdpInlineArgs(inline)) {
    return {
      ...host,
      credential: {
        kind: "inline",
        hostId: host.id,
        user: inline.user,
        authMode: inline.authMode,
        hasPassword: false,
        hasPrivateKey: false,
        hasKeyPassphrase: false,
      },
    };
  }
  throw new Error(`hosts: "${host.name}" was handed an inline credential for the other protocol`);
}

/**
 * Undo the copies a detach just made onto the host's own accounts, because the
 * host write that was going to name them refused.
 *
 * WHY THESE ACCOUNTS ARE NOT ANYONE'S TO KEEP. The write refused, so the STORED
 * record is still `kind: "identity"` - and `secretFieldsFor` returns `[]` for a
 * non-inline credential (`./store.ts:203-207`), so the stored host names none of
 * these accounts. They hold bytes only because `copyMoves` put them there a few
 * statements earlier, in this call. The adjacent case lands the same way: if an
 * earlier `releaseStaleAccounts` failure had left an orphan at one of these
 * slots, the copy has already overwritten it, so what is deleted here was
 * unreferenced either way.
 *
 * ONLY WHAT ACTUALLY COPIED. `copyMoves` reports `false` for a source that held
 * nothing, and `secrets.copy` then wrote nothing, so a `false` field's
 * destination is an account this call never touched. What gets deleted is the
 * moves' own `to` entries, never a field name spelled out a second time - the
 * module header's rule - which is also why the RDP arm and the dangling-key arm
 * need no case of their own here: they carry fewer moves, and that is all.
 *
 * THE RE-READ, which is a guard and not a formality. Two paths end with the
 * stored record already INLINE and naming these very accounts: `upsertHost`
 * throwing at its `persist` (`./store.ts:798-802`), where the record is in the
 * plugin's cache with a debounced retry behind it, and a concurrent writer that
 * detached this host first - which is exactly what a stamp refusal reports.
 * Deleting there would not strand bytes, it would destroy the host's only copy
 * of a credential the vault may no longer hold. So the stored record is read
 * back and the cleanup runs only while it is still bound. A record that is GONE
 * does not stop it: nothing names the accounts then either. A re-read that
 * itself throws stops it, because an orphan is the lesser of the two outcomes -
 * §4.5's own ranking, one level up.
 *
 * EVERY FAILURE IN HERE IS SWALLOWED and every field is still attempted, for the
 * reason {@link undoConvertRecords} gives: the caller is rethrowing the host
 * write's own error, which is the one the user can act on.
 */
async function undoDetachCopies(
  deps: CredentialMoveDeps,
  hostId: string,
  moves: readonly AccountMove[],
  copied: Record<string, boolean>,
): Promise<void> {
  let stored: Host | undefined;
  try {
    stored = await deps.hosts.findHost(hostId);
  } catch {
    return; // See above: unable to tell, so delete nothing.
  }
  if (stored && stored.credential.kind !== "identity") return;
  for (const move of moves) {
    if (!copied[move.field]) continue;
    try {
      await deps.secrets.delete(move.to.service, move.to.account);
    } catch {
      // Swallowed, and the loop carries on: the fields fail independently, and
      // stopping at the first would leave the rest of a private key behind.
    }
  }
}

/**
 * Detach a host from its bound identity, taking its own copy of that
 * identity's stored secrets.
 *
 * A missing identity does NOT refuse: the host is already unable to connect,
 * and refusing would leave it that way permanently. Copy nothing and return a
 * `warning` naming the missing identity - the `VaultUpsert.warning` shape
 * (`vault/store.ts:28-33`) is the precedent. The same treatment applies, one
 * level down, to a dangling `keyId` on an identity that IS found: the
 * password still copies and the host still detaches, and only the key
 * material is reported missing.
 *
 * The copies land BEFORE the host write, the mirror of convert's ordering and
 * for the same reason (§4.5). So the same failure path applies: a refused
 * `upsertHost` left a plaintext copy of what may be a SHARED vault key at
 * `tervia-hosts::<hostId>::privateKey`, named by nothing, and unenumerable
 * because there is no `secrets_list`. {@link undoDetachCopies} takes them back.
 * The missing-identity arm below needs none of that: it copies nothing, so a
 * refusal there leaves nothing behind, and it must stay that way.
 */
export async function detachHostFromVault(
  args: {
    host: Host;
    inline: { user: string; authMode: VaultAuthMode } | { username: string; domain: string };
  },
  deps: CredentialMoveDeps = defaultCredentialMoveDeps,
): Promise<{ host: Host; warning?: string }> {
  if (args.host.credential.kind !== "identity") {
    throw new Error(`hosts: "${args.host.name}" is not bound to a vault identity`);
  }
  const identityId = args.host.credential.identityId;
  const identity = await deps.vault.findIdentity(identityId);

  if (!identity) {
    const record = buildInlineRecord(args.host, args.inline);
    const host = await deps.hosts.upsertHost(record, {}, credentialStamp(args.host));
    return {
      host,
      warning: `identity ${identityId} no longer exists - "${args.host.name}" now stores its own, empty credentials`,
    };
  }

  const key = identity.keyId ? await deps.vault.findKey(identity.keyId) : undefined;
  const moves = detachMoves(args.host, identity, key ? key.id : null);
  // BEFORE the copies, not between them and the write. `buildInlineRecord`
  // throws when `inline`'s shape does not match the host's protocol, and that
  // throw sat one statement past `copyMoves` - outside the `try` below, so
  // `undoDetachCopies` never ran over it. That is the exact orphan class the
  // rethrow arm exists to prevent, reachable one statement earlier. It is not
  // reachable from the shipped dialog today (the protocol toggle is create-mode
  // only, and this path is edit-only), but 6f/6g's callers would arm it, and
  // building the record first costs nothing: it reads no store and no keychain.
  const record = buildInlineRecord(args.host, args.inline);
  const copied = await copyMoves(deps.secrets, moves);
  const secrets = hostSecretsFromCopies(copied);
  let host: Host;
  try {
    host = await deps.hosts.upsertHost(record, secrets, credentialStamp(args.host));
  } catch (e) {
    await undoDetachCopies(deps, args.host.id, moves, copied);
    // The ORIGINAL error, unchanged and by identity, for the reason spelled out
    // at convert's own rethrow: `HostEditorDialog`'s recovery arm branches on
    // `instanceof HostBindingChangedError` and reads three fields off it
    // (VLT-29).
    throw e;
  }

  if (identity.keyId && !key) {
    return {
      host,
      warning: `identity "${identity.name}" names a key that no longer exists - only its password was copied`,
    };
  }
  return { host };
}
