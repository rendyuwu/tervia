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
  VAULT_STAMP_ABSENT,
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
// as a value (`vault/refs.ts:25-27`), so this file lives here, not there.
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
 * `keyId` is the id of a key THIS OPERATION IS CREATING, never one it found:
 * these two moves overwrite whatever is at the destination, so a shared key's
 * accounts passed in here would take this host's private key and passphrase over
 * the ones every other identity using that key already depends on. Convert
 * passes `null` on its reuse path for exactly that reason.
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
 * material is handed to it (`./store.ts:681-683`).
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
 *  `deleteAccounts` (`./store.ts:533-541`) is not a `Promise.all`. Keyed by
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
 * `inlineNeedsKey` from the record. That disagreement is what produced both of
 * the defects below. A draft on "key" over a record holding no key made
 * `upsertIdentity` refuse ("uses key auth but names no key") AFTER the copies
 * had already landed, stranding a plaintext password at an unenumerable vault
 * account once per press; a draft on "password" over a record holding a PEM
 * minted a `VaultKey` that the normaliser then left nameless, and an unnamed key
 * is one Vault-page click from gone. Reading both from the record removes the
 * disagreement structurally rather than checking for it.
 *
 * Convert is an operation on the STORED record, and which accounts travel is
 * already settled by what the record holds rather than by any mode; this is the
 * same rule applied to the field that says what those accounts are for. The
 * user's edits to `name`, `username`, `domain` and `description` still come from
 * the draft: those carry no invariant against the accounts being moved.
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
 * The vault key that already holds the private key this host is about to move
 * in, if the vault holds one. `null` means "mint a new record", which is what
 * every convert did before this existed.
 *
 * PURE, and handed the list rather than reading it. The decision is the USER'S,
 * not this module's: reusing a record gives the new identity a key whose name,
 * description and passphrase belong to an earlier import, and getting that
 * wrong is silent - the connect works, using someone else's record. So the
 * caller looks up, offers, and passes the answer back through
 * {@link convertHostToVault}'s `key` argument.
 *
 * TWO conditions, and the second is not decoration. The fingerprint is what the
 * stored private key IS, so a match means the same public half means the same
 * private key. `hasPrivateKey` is what says the record's body is actually
 * there: a `VaultKey` can carry a fingerprint with no material behind it (a key
 * imported metadata-first, or one whose secret write failed), and binding a new
 * identity to that record produces an identity that cannot authenticate - while
 * the convert has already released the host's own copy, which was the only one
 * left.
 *
 * BOTH CONDITIONS ARE RE-ASSERTED AT THE WRITE, on the record that actually
 * resolves there - see {@link convertHostToVault}'s pre-check 4, which also
 * compares the fingerprint the caller matched on against the one that record
 * records now. This function being the only producer of a `reuseKeyId` today is
 * a fact about today, and the release the reuse path performs is destructive, so
 * the write does not take the offer's word for it.
 *
 * A BLANK OR ABSENT FINGERPRINT MATCHES NOTHING, on either side. `""` is what a
 * container this app could not open reports (`keyInspect.ts`'s sealed-container
 * rule maps it to `undefined`, but a record stored before that rule can hold the
 * empty string), and `"" === ""` would otherwise make every unreadable key a
 * candidate for every other one.
 *
 * THE FIRST MATCH WINS when several records share one fingerprint. That state is
 * reachable - importing one key file twice is all it takes - and there is no
 * honest way to pick between them here, so the caller names the record it is
 * offering and the choice is visible rather than silent.
 */
export function reusableVaultKey(keys: readonly VaultKey[], facts: VaultKeyFacts): VaultKey | null {
  const fingerprint = facts.fingerprint?.trim();
  if (!fingerprint) return null;
  return keys.find((k) => k.hasPrivateKey && k.fingerprint?.trim() === fingerprint) ?? null;
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
 * WHICH IS WHY THE PARAMETER IS `mintedKeyId` AND NOT "the key the identity
 * names". On the reuse path those are two different values: the identity names a
 * key that already existed, and nothing was minted, so `null` is what belongs
 * here. Handing the reused id over instead would satisfy every type in this file
 * and delete a key the user already had, along with both of its secrets -
 * `deleteKey` refuses only while an identity still names the key, and this
 * function deletes the identity FIRST, deliberately (see the next paragraph), so
 * the refusal that would have stopped it is the one it has just removed.
 *
 * IDENTITY FIRST. `deleteKey` refuses while any identity still names the key
 * (`vault/store.ts:388-398`), and the identity minted above names it, so the
 * reverse order refuses its own cleanup and leaves both records behind.
 *
 * THE ACCOUNTS GO WITH THE RECORDS. Both deletes clear the record's vault
 * accounts as part of removing it (`vault/store.ts:376-380` and `:401-405`),
 * which is the half that matters: step 4 put a SECOND copy of the host's secret
 * at those accounts, and a cleanup that dropped only the records would leave
 * exactly the extra copy this whole feature exists to avoid.
 *
 * `identityHostRefs` is the real lookup, passed by name, rather than a
 * `() => []` shortcut. It finds no holders on the path this runs on - nothing
 * binds the new identity - and it is the store's own guard over the one case
 * the provenance argument does not cover: `upsertHost` throwing at its
 * `persist` (`./store.ts:802-806`), where the record is already in the plugin's
 * cache with a debounced retry behind it, so a host DOES name this identity and
 * the delete is refused rather than stranding that host.
 *
 * EVERY FAILURE IN HERE IS SWALLOWED - the same swallow, for the same reason,
 * as `vault/store.ts`'s key-secret rollback. The caller is already rethrowing
 * the host write's own error, which is the one the user can act on and the one
 * `HostEditorDialog`'s recovery arm branches on by instance. A cleanup
 * failure must never become the error that arrives there.
 */
async function undoConvertRecords(
  deps: CredentialMoveDeps,
  identityId: string,
  mintedKeyId: string | null,
): Promise<void> {
  try {
    await deps.vault.deleteIdentity(identityId, deps.hosts.identityHostRefs);
  } catch {
    // See above: this must not become the error the caller sees.
  }
  if (mintedKeyId === null) return;
  try {
    await deps.vault.deleteKey(mintedKeyId);
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
 * The order is the whole design; step 8's second half is not written here at
 * all, but in `upsertHost`'s own trailing `releaseStaleAccounts` call in
 * `./store.ts`:
 *
 * 1. Refuse unless the host is inline.
 * 2. Refuse when the host stores key material but no key was given.
 * 3. Refuse when the record authenticates BY key and stores none.
 * 3b. Refuse when the key to reuse is gone, stores no private key, records no
 *     fingerprint, or records one other than the fingerprint the caller matched
 *     it on.
 * 4. Mint the new ids.
 * 5. Copy every account, sequentially.
 * 6. Write the key WHEN ONE IS BEING MINTED, through `keyRecordFrom` - not a
 *    hand-assembled `VaultKey`, because that builder is the only one.
 * 7. Write the identity through `identityRecordFrom`, the single normaliser
 *    of `keyId`.
 * 8. Bind the host. `releaseStaleAccounts` then clears its accounts, because
 *    a non-inline record owns none.
 * 9. Return all three records. On the reuse path the key is the EXISTING record,
 *    read at step 3b and written to by nothing here.
 *
 * Steps 5 to 8 do not move: copy-then-write is the ordering, where an orphan
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
 * THE IDENTITY'S AUTH MODE IS NOT A PARAMETER, deliberately. It is derived from
 * the stored record by {@link inlineAuthMode}, which is where the reasoning
 * lives; the short version is that a caller able to pass one was able to
 * disagree with `inlineNeedsKey`, and both of the defects {@link inlineAuthMode}
 * describes were that disagreement. Removing the parameter is what makes the
 * class unreachable rather than merely guarded: no caller can get it wrong.
 *
 * THE KEY, ON THE OTHER HAND, IS A DECISION AND SO IT IS A PARAMETER. `{name,
 * facts}` mints a new record; `{reuseKeyId, fingerprint}` points the new
 * identity at one the vault already holds ({@link reusableVaultKey} is what
 * finds a candidate). No lookup and no question happen here: reuse hands the new
 * identity a record whose name, description and passphrase belong to an earlier
 * import, so the user is the one who picks, and the caller passes the answer -
 * along with the fingerprint it matched that record on, which pre-check 4
 * compares against the record it resolves.
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
    /**
     * What the identity's key should be. Required when the host stores key
     * material, ignored when it does not - a host with nothing to move gets an
     * identity that names no key, whichever arm is passed.
     *
     * `{name, facts}` mints a new `VaultKey` from this host's own material.
     * `{reuseKeyId, fingerprint}` names one the vault already holds, found by
     * {@link reusableVaultKey} and CHOSEN BY THE USER; see the split at
     * `mintedKeyId` / `namedKeyId` below for what that changes, which is more
     * than which id ends up on the identity.
     *
     * `fingerprint` is THE ONE THE OFFER MATCHED ON, read off the body the
     * caller inspected - not off the record, which would make pre-check 4's
     * comparison a record against itself and assert nothing at all.
     */
    key:
      { name: string; facts: VaultKeyFacts } | { reuseKeyId: string; fingerprint: string } | null;
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

  // Which arm the caller picked, resolved once. `newKey` is null on the reuse
  // path and on the no-key path, which is what makes step 6 below a single
  // condition instead of a second reading of `args.key`. `reuse` is the whole
  // arm rather than its id alone, because pre-check 4 needs the fingerprint that
  // travelled with it and a second reading of `args.key` to fetch it is the
  // drift this one narrowing exists to prevent.
  const reuse = args.key && "reuseKeyId" in args.key ? args.key : null;
  const newKey = args.key && !("reuseKeyId" in args.key) ? args.key : null;
  const reuseKeyId = reuse?.reuseKeyId ?? null;

  // PRE-CHECK 4, beside the other three and before a byte moves, for the reason
  // the key-auth-with-no-body one gives: `upsertIdentity` refuses a `keyId` that
  // names nothing ("names a key that does not exist"), and it refuses it at step
  // 7, after step 5 has already copied this host's password onto a vault account
  // that no record will ever name. The window is small and real - the caller
  // listed the vault's keys to offer this one, and another window can delete it
  // between that list and this call.
  //
  // The lookup is also what answers "what does the caller get back": on reuse
  // `key` is this record, unchanged, rather than `null`. Nothing is written to
  // it, but the identity NAMES it, and a caller told `null` would read that as
  // "this identity has no key".
  //
  // AND IT RE-ASSERTS WHAT THE OFFER ALREADY CLAIMED, because this is the arm
  // that releases the host's own key without copying anything. Step 8 clears the
  // host's accounts as stale, so on this path the record in front of us is the
  // only place that private key survives - and "no copy is needed" has to be a
  // property of THIS record, not of whatever an earlier lookup examined.
  // {@link reusableVaultKey} returns only a record that has a body and a
  // non-blank fingerprint, so a record failing either is one no offer could have
  // named: the id came from somewhere else, or the record changed between the
  // offer and this call. Being the only producer of a `reuseKeyId` today is a
  // fact about today; a second producer of a mis-described record is refused here
  // whether or not anyone has written one yet.
  //
  // THE THIRD CONDITION IS THE ONE THE RECORD CANNOT ANSWER ON ITS OWN. A body
  // and a fingerprint say the record is COMPLETE; neither says it is the record
  // the offer was about. So the caller passes the fingerprint IT matched on and
  // the comparison happens here, against the record that actually resolves -
  // which is what catches an id that never came from an offer at all, and a
  // record replaced or re-imported at that id between the offer and this call.
  // Both sides are trimmed, exactly as {@link reusableVaultKey} trims them when
  // it makes the match: one value compared two ways is how two places that must
  // agree come apart.
  //
  // REFUSED, never quietly downgraded to minting a new key. A silent fallback
  // would leave the two paths indistinguishable afterwards - the identity would
  // name a fresh record and nothing would say the reuse the user asked for did
  // not happen - and callers already handle a refusal from the three pre-checks
  // above.
  let reusedKey: VaultKey | null = null;
  if (needsKey && reuse !== null) {
    reusedKey = (await deps.vault.findKey(reuse.reuseKeyId)) ?? null;
    if (!reusedKey) {
      throw new Error(
        `hosts: "${args.host.name}" cannot reuse vault key ${reuse.reuseKeyId}, which no longer exists`,
      );
    }
    if (!reusedKey.hasPrivateKey) {
      throw new Error(
        `hosts: "${args.host.name}" cannot reuse vault key "${reusedKey.name}", which stores no private key, so this host's own copy would be released against a record that holds none`,
      );
    }
    if (!reusedKey.fingerprint?.trim()) {
      throw new Error(
        `hosts: "${args.host.name}" cannot reuse vault key "${reusedKey.name}", which records no fingerprint, so nothing says it holds this host's private key`,
      );
    }
    if (reusedKey.fingerprint.trim() !== reuse.fingerprint.trim()) {
      throw new Error(
        `hosts: "${args.host.name}" cannot reuse vault key "${reusedKey.name}", which records a different fingerprint from the one this host's key was matched against, so its own private key would be released against a record holding other material`,
      );
    }
  }

  // ONE `keyId` WAS TWO VALUES ALL ALONG, and reuse is what separates them.
  //
  // `mintedKeyId` is the id THIS CALL created. It owns the vault accounts step 5
  // copies onto, it is what step 6 writes, and it is the only id the compensating
  // delete may ever touch. `null` on the reuse path, because nothing was minted.
  //
  // `namedKeyId` is what the new identity points at. On reuse that is a record
  // that already existed and is not this call's to write or to remove.
  //
  // Collapsing the two is the whole hazard of this feature, in both directions:
  //
  //   - `convertMoves(host, identityId, namedKeyId)` would copy THIS HOST's
  //     private key and passphrase over the shared key's own accounts. Same
  //     fingerprint means the same private key, but the PASSPHRASE can differ - a
  //     re-encrypted copy of one key is still that key - and writing this host's
  //     over it breaks every other identity using that record.
  //   - `undoConvertRecords(deps, identityId, namedKeyId)` would DELETE that
  //     record, with both of its secrets, whenever `upsertHost` refuses. See
  //     that function's own note for why its argument is the minted id by name.
  //
  // So both take `mintedKeyId` and only the identity draft takes `namedKeyId`.
  const mintedKeyId = needsKey && newKey ? deps.vault.newKeyId() : null;
  const namedKeyId = mintedKeyId ?? (needsKey ? reuseKeyId : null);
  const identityId = deps.vault.newIdentityId();

  const copied = await copyMoves(deps.secrets, convertMoves(args.host, identityId, mintedKeyId));

  let key: VaultKey | null = reusedKey;
  if (mintedKeyId !== null && newKey) {
    const keyDraft: KeyDraft = {
      name: newKey.name,
      privateKey: "",
      passphrase: "",
      description: "",
    };
    const keySecrets: { privateKey?: VaultSecretValue; passphrase?: VaultSecretValue } = {};
    if (copied[HOST_SSH_FIELDS.privateKey]) keySecrets.privateKey = SECRET_ALREADY_STORED;
    if (copied[HOST_SSH_FIELDS.keyPassphrase]) keySecrets.passphrase = SECRET_ALREADY_STORED;
    // `VAULT_STAMP_ABSENT` - the id was minted two statements ago, so "the store
    // holds nothing under it" is the truth rather than a waiver, and passing it
    // turns "convert only ever creates" from a property of this code into a
    // refusal the store enforces.
    const upserted = await deps.vault.upsertKey(
      keyRecordFrom(mintedKeyId, keyDraft, null, newKey.facts),
      keySecrets,
      VAULT_STAMP_ABSENT,
    );
    key = upserted.record;
  }

  const identityDraft: IdentityDraft = {
    name: args.identity.name,
    username: args.identity.username,
    domain: args.identity.domain,
    authMode,
    password: "",
    keyId: namedKeyId ?? "",
    description: args.identity.description,
  };
  const identitySecrets: { password?: VaultSecretValue } = {};
  if (copied[HOST_SSH_FIELDS.password]) identitySecrets.password = SECRET_ALREADY_STORED;
  // `"keep"` - the identity names the key WHENEVER one was minted, and not only
  // when the mode uses it, deliberately. The case is a host that once used key
  // auth, now authenticates by password, and still carries its PEM. That PEM
  // must travel, because the accounts that move are read off the stored record
  // and not off the mode, and a `VaultKey` nothing names is one Vault-page click
  // from destroyed - `deleteKey`'s in-use guard has no holder to refuse over. So
  // the record built here deliberately puts a key chip on a password identity,
  // and that trade was taken with the consequence understood: a
  // misleading chip is strictly better than losing the user's only copy of a
  // private key. What that chip should say on a non-key identity is still
  // unanswered.
  //
  // The opt-out is a named argument on `identityRecordFrom`, never a
  // `VaultIdentity` assembled here: that function is the single normaliser of
  // `keyId`, and a second assembly in this file is the drift it exists to
  // prevent.
  // `VAULT_STAMP_ABSENT` for the reason the key upsert above passes it: the id
  // came out of `newIdentityId()` in this call, so absent is what the store
  // genuinely holds under it.
  const identityUpsert = await deps.vault.upsertIdentity(
    identityRecordFrom(identityId, identityDraft, "keep"),
    identitySecrets,
    VAULT_STAMP_ABSENT,
  );

  let nextHost: Host;
  try {
    nextHost = await deps.hosts.upsertHost(
      { ...args.host, credential: { kind: "identity", identityId } },
      {},
      credentialStamp(args.host),
    );
  } catch (e) {
    await undoConvertRecords(deps, identityId, mintedKeyId);
    // The ORIGINAL error, unchanged and by identity: `HostEditorDialog`'s
    // recovery arm tests `instanceof HostBindingChangedError` and reads
    // `hostId` / `expected` / `actual` off it, so wrapping this or
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

/**
 * The inline shape a detach writes: the HOST's protocol says WHICH shape,
 * the identity being detached says the non-secret VALUES inside it -
 * {@link detachHostFromVault}'s own doc has the reasoning for why neither
 * comes from a caller any more.
 *
 * `identity` is `null` for exactly one caller: the dangling-identity arm,
 * which has nothing to derive from. It gets the empty user/username its own
 * warning already promises, never a fallback parameter - the whole point of
 * removing `inline` from the signature was that no caller, including this
 * one, can hand it a value that disagrees with the identity.
 */
function detachInlineFields(
  host: Host,
  identity: VaultIdentity | null,
): SshInlineArgs | RdpInlineArgs {
  if (host.protocol === "rdp") {
    return { username: identity?.username ?? "", domain: identity?.domain ?? "" };
  }
  return { user: identity?.username ?? "", authMode: identity?.authMode ?? "password" };
}

/** The inline arm the store overwrites `has*` flags on once it knows what it
 *  actually wrote - the same placeholder pattern `HostEditorDialog.tsx:737-741`
 *  hands over. Refuses rather than guessing when `inline`'s shape does not
 *  match the host's own protocol - a contract this function alone enforces:
 *  its two call sites, both in {@link detachHostFromVault}, derive `inline`
 *  from `host.protocol` itself via {@link detachInlineFields}, so neither can
 *  construct the mismatch this throw guards against. */
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
 * non-inline credential (`./store.ts:208-213`), so the stored host names none of
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
 * throwing at its `persist` (`./store.ts:802-806`), where the record is in the
 * plugin's cache with a debounced retry behind it, and a concurrent writer that
 * detached this host first - which is exactly what a stamp refusal reports.
 * Deleting there would not strand bytes, it would destroy the host's only copy
 * of a credential the vault may no longer hold. So the stored record is read
 * back and the cleanup runs only while it is still bound. A record that is GONE
 * does not stop it: nothing names the accounts then either. A re-read that
 * itself throws stops it, because an orphan is the lesser of the two outcomes -
 * the same ranking copy-then-write applies one level up.
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
 * (`vault/store.ts:31-36`) is the precedent. The same treatment applies, one
 * level down, to a dangling `keyId` on an identity that IS found: the
 * password still copies and the host still detaches, and only the key
 * material is reported missing.
 *
 * The copies land BEFORE the host write, the mirror of convert's ordering and
 * for the same reason. So the same failure path applies: a refused
 * `upsertHost` left a plaintext copy of what may be a SHARED vault key at
 * `tervia-hosts::<hostId>::privateKey`, named by nothing, and unenumerable
 * because there is no `secrets_list`. {@link undoDetachCopies} takes them back.
 * The missing-identity arm below needs none of that: it copies nothing, so a
 * refusal there leaves nothing behind, and it must stay that way.
 *
 * THE NON-SECRET INLINE FIELDS (`user`/`authMode` for SSH, `username`/`domain`
 * for RDP) ARE NOT A PARAMETER, on the grounds {@link convertHostToVault}'s
 * doc gives for `authMode` and {@link inlineAuthMode} describes in full: a
 * caller able to pass them was able to disagree with the identity this
 * function re-reads two statements below, for the secrets - and that
 * disagreement WAS the defect. The caller used to pass the editor's open-time
 * snapshot of the vault, which could go stale while the identity's username
 * or `authMode` changed in another window; the FRESH identity's `keyId` still
 * gated whether a key body copied ({@link detachMoves} reads it, not the
 * snapshot), so a host could land inline holding a freshly-copied private key
 * under a stale "password" `authMode` - the orphan state a Forget button was
 * added for, arrived at silently. {@link detachInlineFields} derives both
 * fields from the SAME identity this function reads for the secrets, so the
 * two cannot disagree, structurally rather than by discipline. The
 * dangling-identity arm passes `null` and gets the empty user/username its
 * own warning already promises - not a fallback parameter, which would put
 * the disagreement back for the one caller that cannot check it.
 */
export async function detachHostFromVault(
  args: { host: Host },
  deps: CredentialMoveDeps = defaultCredentialMoveDeps,
): Promise<{ host: Host; warning?: string }> {
  if (args.host.credential.kind !== "identity") {
    throw new Error(`hosts: "${args.host.name}" is not bound to a vault identity`);
  }
  const identityId = args.host.credential.identityId;
  const identity = await deps.vault.findIdentity(identityId);

  if (!identity) {
    const record = buildInlineRecord(args.host, detachInlineFields(args.host, null));
    const host = await deps.hosts.upsertHost(record, {}, credentialStamp(args.host));
    return {
      host,
      warning: `identity ${identityId} no longer exists - "${args.host.name}" now stores its own, empty credentials`,
    };
  }

  const key = identity.keyId ? await deps.vault.findKey(identity.keyId) : undefined;
  const moves = detachMoves(args.host, identity, key ? key.id : null);
  // BEFORE the copies, not between them and the write. `buildInlineRecord`
  // throws when its `inline` argument's shape does not match the host's
  // protocol, and that throw sat one statement past `copyMoves` - outside the
  // `try` below, so `undoDetachCopies` never ran over it. That is the exact
  // orphan class the rethrow arm exists to prevent, reachable one statement
  // earlier. `inline` is now {@link detachInlineFields}'s output, derived from
  // `args.host.protocol` itself, so the mismatch this ordering used to merely
  // risk is unreachable BY CONSTRUCTION rather than by discipline - no caller
  // passes a shape at all any more, let alone the wrong one. The order stays
  // anyway: it costs nothing (it reads no store and no keychain), and the
  // orphan class it guards against is real for every other throw in the `try`
  // below.
  const record = buildInlineRecord(args.host, detachInlineFields(args.host, identity));
  const copied = await copyMoves(deps.secrets, moves);
  const secrets = hostSecretsFromCopies(copied);
  let host: Host;
  try {
    host = await deps.hosts.upsertHost(record, secrets, credentialStamp(args.host));
  } catch (e) {
    await undoDetachCopies(deps, args.host.id, moves, copied);
    // The ORIGINAL error, unchanged and by identity, for the reason spelled out
    // at convert's own rethrow: `HostEditorDialog`'s recovery arm branches on
    // `instanceof HostBindingChangedError` and reads three fields off it.
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
