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
  /** `identityHostRefs` is here for the compensating delete alone - see
   *  {@link undoConvertRecords} for why it is the real lookup and not `() => []`. */
  hosts: Pick<HostsStore, "upsertHost" | "identityHostRefs">;
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
 * 3. Mint the new ids.
 * 4. Copy every account, sequentially.
 * 5. Write the key, when there is one, through `keyRecordFrom` - not a
 *    hand-assembled `VaultKey` (wave-3 boundary 7: one builder).
 * 6. Write the identity through `identityRecordFrom`, the single normaliser
 *    of `keyId` (wave-3 boundary 6, VLT-73).
 * 7. Bind the host. `releaseStaleAccounts` then clears its accounts, because
 *    a non-inline record owns none.
 * 8. Return all three records.
 *
 * Steps 4 to 7 do not move: copy-then-write is §4.5's ordering, where an orphan
 * account after a good write is the lesser evil and a crash between the copy
 * and the write must never cost a key. What step 7 gained is a FAILURE path.
 * `upsertHost` is the first call here that can refuse for anything other than
 * the two cheap pre-checks above - a dangling `proxyJumpId`, a tunnel target
 * that is not an SSH host, a jump cycle, a stamp that moved underneath the
 * caller - and until this fix every one of those refusals left the identity, the
 * key and a second copy of the host's secret behind, in a feature whose own
 * confirmation copy tells the user the point is fewer copies of one credential.
 * See {@link undoConvertRecords} for why undoing them is admissible here and
 * would not be for a record that already existed.
 */
export async function convertHostToVault(
  args: {
    /** The STORED record, as the caller loaded it. */
    host: Host;
    /** The new identity's non-secret fields. */
    identity: {
      name: string;
      username: string;
      domain: string;
      authMode: VaultAuthMode;
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
    authMode: args.identity.authMode,
    password: "",
    keyId: keyId ?? "",
    description: args.identity.description,
  };
  const identitySecrets: { password?: VaultSecretValue } = {};
  if (copied[HOST_SSH_FIELDS.password]) identitySecrets.password = SECRET_ALREADY_STORED;
  const identityUpsert = await deps.vault.upsertIdentity(
    identityRecordFrom(identityId, identityDraft),
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
  const copied = await copyMoves(
    deps.secrets,
    detachMoves(args.host, identity, key ? key.id : null),
  );
  const secrets = hostSecretsFromCopies(copied);
  const record = buildInlineRecord(args.host, args.inline);
  const host = await deps.hosts.upsertHost(record, secrets, credentialStamp(args.host));

  if (identity.keyId && !key) {
    return {
      host,
      warning: `identity "${identity.name}" names a key that no longer exists - only its password was copied`,
    };
  }
  return { host };
}
