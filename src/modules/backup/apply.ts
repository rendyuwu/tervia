/**
 * Export / import the saved connections as a single passphrase-encrypted
 * `.tervia-backup` file, so moving to another machine is one import instead of
 * retyping every host and credential.
 *
 * The credentials live in the keychain and CANNOT travel with the store files on
 * their own - a keychain does not move between machines - which is exactly why
 * this exists and why the file is always encrypted: it carries SSH passwords,
 * SSH private keys, RDP passwords, identity passwords, vault private key bodies
 * and key passphrases, so a plaintext export would be a credential leak the
 * moment it touched Downloads or a synced folder. Sealing happens in the host
 * process (`modules/backup.rs`); `crypto.subtle` is not available to the webview
 * because the app origin is plain http.
 *
 * THE CREDENTIALS DO NOT PASS THROUGH HERE, AND THERE IS NO LONGER AN EXCEPTION.
 * An export sends keychain REFERENCES and Rust reads the values; an import gets
 * back only the metadata and tells Rust which ids may be written. The v1 read
 * path was the exception and it could not have been otherwise - a v1 file's
 * sealed block IS the credential map, so importing one meant holding it here
 * long enough to write it - and it is gone, along with the `backup_open` call
 * that fetched it. Nothing in this app hands a plaintext credential map to JS
 * any more. That is also why there is no RDP secret read-back helper anywhere in
 * the tree: `rdp_open` takes a reference precisely so an RDP password never
 * enters the webview, and a backup that read one would have thrown that away.
 *
 * A BINDING WHOSE TARGET DID NOT TRAVEL IS NEVER APPLIED - it is refused or
 * downgraded, and {@link resolveIdentityBindings} is where that is decided. An
 * incoming `{kind:"identity"}` is a claim about a vault, and applying one over a
 * host saved here would delete the secrets that host owns with nothing copied
 * anywhere first. So a host already saved here KEEPS its own credential; a host
 * that is NEW takes the binding when the identity it names will exist, because
 * there is no stored record whose accounts could be released, and arrives as a
 * blank inline row that one dialog fixes when it will not. Nothing here
 * strengthens the protection on any secret; what a vault binding buys is fewer
 * copies of one.
 */
import { invoke } from "@tauri-apps/api/core";

import { releaseRule } from "@/modules/forwards/controller";
import { listRules, upsertRule } from "@/modules/forwards/store";
import {
  findHost,
  listGroups,
  listHosts,
  upsertGroup,
  upsertHost,
  SECRET_ALREADY_STORED,
  type HostSecretInput,
} from "@/modules/hosts/store";
import { HOST_RDP_SECRET_FIELDS, HOST_SSH_SECRET_FIELDS, type Host } from "@/modules/hosts/types";
import { listIdentities, listKeys, upsertIdentity, upsertKey } from "@/modules/vault/store";
import {
  HOST_KEYRING_SERVICE,
  HOST_RDP_PASSWORD_FIELD,
  HOST_SSH_KEY_PASSPHRASE_FIELD,
  HOST_SSH_PASSWORD_FIELD,
  HOST_SSH_PRIVATE_KEY_FIELD,
  IDENTITY_PASSWORD_FIELD,
  KEY_PASSPHRASE_FIELD,
  KEY_PRIVATE_KEY_FIELD,
  VAULT_IDENTITY_SECRET_FIELDS,
  VAULT_KEYRING_SERVICE,
  VAULT_KEY_SECRET_FIELDS,
  vaultAccount,
  type VaultIdentity,
  type VaultKey,
} from "@/modules/vault/types";

import {
  BACKUP_KIND,
  BACKUP_VERSION,
  HOST_SECRET_GROUP,
  IDENTITY_SECRET_GROUP,
  KEY_SECRET_GROUP,
  SECRET_GROUPS,
  carryPins,
  clearDanglingJumps,
  clearDanglingRuleHosts,
  clearDanglingTunnels,
  mergeGroups,
  normaliseIdentityKeys,
  orderHostWrites,
  parseBackupFile,
  refuseProtocolConflicts,
  resolveIdentityBindings,
  sanitizePayload,
  type BackupFile,
  type BackupSecretGroup,
  type SealedBlob,
  type SecretRef,
} from "./file";

function reason(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/**
 * Keychain references for one host's every credential field.
 *
 * A vault-bound host contributes NONE: it owns no accounts of its own, so there
 * is nothing on the host service to read. Its identity's secrets live on another
 * service and belong to `IDENTITY_SECRET_GROUP`, which this function does not
 * build references for - it answers for one host and one group only.
 *
 * Exported for `scripts/backup-verify.ts`, which pins the producing half of
 * the {@link SECRET_ALREADY_STORED} contract: what travels on an export is
 * decided here, and a field this stops naming simply stops travelling.
 */
export function hostRefs(host: Host): SecretRef[] {
  if (host.credential.kind !== "inline") return [];
  const fields = host.protocol === "ssh" ? HOST_SSH_SECRET_FIELDS : HOST_RDP_SECRET_FIELDS;
  return fields.map((field) => ({
    group: HOST_SECRET_GROUP,
    id: host.id,
    field,
    service: HOST_KEYRING_SERVICE,
    account: vaultAccount(host.id, field),
  }));
}

/**
 * Keychain references for one identity's every credential field, and for one
 * key's.
 *
 * BOTH ON ONE SERVICE, and it is not a third one: identities and keys share
 * `tervia-vault`, so the two functions differ only in their field list and their
 * payload GROUP. The groups are three because the three record kinds draw their
 * ids from three separate collections - `HOST_SECRET_GROUP` and its neighbours in
 * `file.ts` carry that argument - and a group is not a service.
 *
 * A field enumerated here is asked for whether or not anything is stored at it;
 * the host process skips a reference that resolves to nothing, which keeps the
 * decision about what exists in the one place that can actually answer it.
 */
export function identityRefs(identity: VaultIdentity): SecretRef[] {
  return VAULT_IDENTITY_SECRET_FIELDS.map((field) => ({
    group: IDENTITY_SECRET_GROUP,
    id: identity.id,
    field,
    service: VAULT_KEYRING_SERVICE,
    account: vaultAccount(identity.id, field),
  }));
}

/** A key's private body and its passphrase. See {@link identityRefs}. */
export function keyRefs(key: VaultKey): SecretRef[] {
  return VAULT_KEY_SECRET_FIELDS.map((field) => ({
    group: KEY_SECRET_GROUP,
    id: key.id,
    field,
    service: VAULT_KEYRING_SERVICE,
    account: vaultAccount(key.id, field),
  }));
}

/**
 * The key one landed credential is remembered under: its payload GROUP, then the
 * record id and the field, which together are the account name.
 *
 * THE GROUP IS LOAD-BEARING and was not in the key before v3, where every
 * reference came from one group over one id space. v3 draws three groups from
 * three separate collections, so an id alone no longer says which record it
 * belongs to: an identity and a host sharing an id, each with a `password` field,
 * collide - and so do a key and a host on `privateKey`. {@link storedFields} would
 * then report {@link SECRET_ALREADY_STORED} for a host whose secret never landed
 * and the host would be written with `hasPassword: true` over nothing, which is a
 * presence flag taken from the file by the back door - the one thing this module
 * exists to stop.
 *
 * A REAL EXPORT CANNOT PRODUCE THAT COLLISION, because the three stores mint ids
 * independently; a HAND-MADE payload can, and an import is a trust boundary. That
 * is the same standard `arrivedBound` is held to below, and saying so is the
 * point - a guard nobody can reach is worth nothing.
 *
 * Exported so a check can build the set this module queries instead of spelling
 * the format a second time. A group dropped out of the key is still visible
 * through it: two groups would collapse into one entry.
 */
export function landedKey(group: BackupSecretGroup, id: string, field: string): string {
  return `${group}::${id}::${field}`;
}

/**
 * Serialize every saved record - hosts, groups, identities, keys and forward
 * rules - plus their keychain secrets into file text. Returns the counts
 * alongside it so the caller can say what it wrote without parsing the JSON
 * back out.
 *
 * References are built for EVERY field a host, identity or key could own,
 * including ones with nothing stored - the host process skips a reference
 * that resolves to nothing, which keeps the decision about what exists in the
 * one place that can actually answer it.
 */
export async function buildBackup(passphrase: string): Promise<{
  text: string;
  counts: { hosts: number; groups: number; identities: number; keys: number; rules: number };
}> {
  if (!passphrase) throw new Error("A passphrase is required.");
  const [hosts, groups, identities, keys, rules] = await Promise.all([
    listHosts(),
    listGroups(),
    listIdentities(),
    listKeys(),
    listRules(),
  ]);
  if (
    hosts.length === 0 &&
    groups.length === 0 &&
    identities.length === 0 &&
    keys.length === 0 &&
    rules.length === 0
  ) {
    throw new Error("There is nothing saved to export.");
  }

  const refs: SecretRef[] = [
    ...hosts.flatMap(hostRefs),
    ...identities.flatMap(identityRefs),
    ...keys.flatMap(keyRefs),
  ];

  const payload = await invoke<SealedBlob>("backup_seal_payload", {
    // The inventory only. Rust folds the credentials in under the group names in
    // SECRET_GROUPS and refuses to overwrite a key that is already here, so none
    // of these five lists can be replaced by a credential map.
    payload: JSON.stringify({ hosts, groups, identities, keys, rules }),
    refs,
    passphrase,
  });

  const file: BackupFile = {
    kind: BACKUP_KIND,
    version: BACKUP_VERSION,
    exportedAt: Date.now(),
    payload,
  };
  return {
    text: JSON.stringify(file, null, 2),
    counts: {
      hosts: hosts.length,
      groups: groups.length,
      identities: identities.length,
      keys: keys.length,
      rules: rules.length,
    },
  };
}

export type ImportCounts = {
  /** Hosts written that did not exist here before. */
  added: number;
  /** Existing ids the backup overwrote. */
  replaced: number;
  /** Hosts whose credential did not travel: the ONE field their auth mode needs
   *  was not among the ones this import wrote. Agent-auth SSH hosts are NOT
   *  counted - they have no secret by design, so reporting them as missing one
   *  would read as a broken import - and neither is a host that kept a vault
   *  binding it already had here, whose credential never needed to travel.
   *
   *  Answered from what the import WROTE, so a row re-imported over a credential
   *  this machine already holds is counted as well: the file carried none, even
   *  though the host connects. The alternative is reading the record back, which
   *  is a different question ("will this connect") and belongs to the list's
   *  presence pips rather than to a report about a file. */
  withoutSecrets: number;
  /** Hosts the store refused. The rest of the file still imported, and no
   *  credential was written for a host whose record did not land. */
  failed: number;
};

export type ImportGroupCounts = {
  /** Groups written that did not exist here before. */
  added: number;
  /** Existing ids the backup overwrote, name and all. */
  replaced: number;
  /** Not written: this machine already held that NAME under another id, so the
   *  file's hosts were repointed at the group holding it. */
  merged: number;
  /** Not written: this machine already held that ID under another name, so the
   *  local label - and every local host wearing it - was left alone. */
  keptNames: number;
  /** Groups the store refused. */
  failed: number;
};

export type ImportIdentityCounts = {
  /** Identities written that did not exist here before. */
  added: number;
  /** Existing ids the backup overwrote. */
  replaced: number;
  /** Identities whose password did not travel, counted only for the mode that
   *  NEEDS one. Key and agent auth have no password by design, so reporting them
   *  as missing it would read as a broken import - the same reason an agent-auth
   *  host is not counted. A key-auth identity may still own a password (one
   *  account, a key over SSH and a password over RDP), and the flag is written
   *  when that password lands; it is just not something to be missing. */
  withoutSecrets: number;
  /** Not written at all: key auth naming a key that will not exist here, so the
   *  identity is SKIPPED rather than downgraded to password auth. See
   *  `normaliseIdentityKeys`. */
  withoutKeys: number;
  /** Written with the `keyId` cleared: the key it named will not exist, and the
   *  mode does not need one. The identity authenticates exactly as before. */
  keysDropped: number;
  /** Identities the store refused. The rest of the file still imported. */
  failed: number;
};

export type ImportKeyCounts = {
  /** Keys written that did not exist here before. */
  added: number;
  /** Existing ids the backup overwrote. */
  replaced: number;
  /** Keys whose PRIVATE BODY did not travel: the one field that decides whether
   *  anything can be done with the record, exactly as a host is judged by the one
   *  field its auth mode needs. A passphrase without the body it unlocks does not
   *  make a usable key, so it does not clear this either. Includes a key
   *  re-imported over material this machine already holds - the file carried
   *  none, even though the key works. */
  withoutSecrets: number;
  /** Keys the store refused. */
  failed: number;
};

export type ImportRuleCounts = {
  /** Rules written that did not exist here before. */
  added: number;
  /** Existing ids the backup overwrote. */
  replaced: number;
  /** Not written: the rule named a host that will not exist here, or named an
   *  RDP host, which has no SSH session for a forward to ride. See
   *  `clearDanglingRuleHosts`. */
  dropped: number;
  /** Rules the store refused. */
  failed: number;
};

export type ImportResult = {
  ssh: ImportCounts;
  rdp: ImportCounts;
  groups: ImportGroupCounts;
  identities: ImportIdentityCounts;
  keys: ImportKeyCounts;
  rules: ImportRuleCounts;
  /** Entries dropped because they could not be a working record of their own
   *  kind: an undialable host, an unpickable group, a nameless identity or key,
   *  a rule with no port. One number across all five collections. */
  skipped: number;
  /** Rows refused because the host already saved under that id speaks the other
   *  protocol, and replacing it would delete secrets nothing copied first. See
   *  `refuseProtocolConflicts`. */
  protocolConflicts: number;
  /** Rows whose vault binding could not be applied, because a backup carries no
   *  vault. Each one either kept the credential already saved here or arrived as
   *  a blank inline host - never as a vault-bound record over someone else's
   *  secrets. See `resolveIdentityBindings`. */
  vaultBindingsDropped: number;
  /** Rows whose vault binding WAS applied: a host that is new to this machine,
   *  naming an identity that will exist once this import is done. Both halves are
   *  required, which is what makes applying free of any released account - there
   *  is no stored record to release one from. */
  vaultBindingsApplied: number;
  /** One line per refusal, so a partial import can say what it could not do
   *  rather than reporting a smaller number and no reason. */
  problems: string[];
};

const NO_COUNTS: ImportCounts = { added: 0, replaced: 0, withoutSecrets: 0, failed: 0 };

const NO_GROUP_COUNTS: ImportGroupCounts = {
  added: 0,
  replaced: 0,
  merged: 0,
  keptNames: 0,
  failed: 0,
};

const NO_IDENTITY_COUNTS: ImportIdentityCounts = {
  added: 0,
  replaced: 0,
  withoutSecrets: 0,
  withoutKeys: 0,
  keysDropped: 0,
  failed: 0,
};

const NO_KEY_COUNTS: ImportKeyCounts = { added: 0, replaced: 0, withoutSecrets: 0, failed: 0 };

const NO_RULE_COUNTS: ImportRuleCounts = { added: 0, replaced: 0, dropped: 0, failed: 0 };

/**
 * Decrypt and merge a backup into the local store. Merging is by host id, which
 * is stable across renames, so re-importing the same file updates rather than
 * duplicating. Nothing is deleted: a host that exists here but not in the file
 * is left alone.
 */
export async function applyBackup(text: string, passphrase: string): Promise<ImportResult> {
  if (!passphrase) throw new Error("A passphrase is required.");

  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    throw new Error("That file is not valid JSON.");
  }
  // No branch on the parsed version: there is one readable format, and
  // `parseBackupFile` has already refused every other envelope by name. A second
  // arm on `ParsedBackup` is what would put a branch back here.
  return applyV3(parseBackupFile(raw).payload, passphrase);
}

/**
 * What the host process wrote for ONE host, as store write instructions.
 *
 * `SECRET_ALREADY_STORED` per field, because the value is at the account and this
 * module never held it. Without it the store takes each flag from the stored
 * record, which for a host it has never seen is all-false over a live secret -
 * and an inline RDP host with `hasPassword: false` is refused by `RdpPane`'s
 * pre-flight even though the password is right there.
 *
 * PER FIELD, not per host: a row whose password travelled and whose private key
 * did not has to end up with one flag true and one false, and a per-host answer
 * gets one of them wrong either way.
 *
 * A field omitted here stays `undefined`, which is the store's "leave whatever is
 * stored alone" - the non-destructive choice when re-importing over a host whose
 * credential is already set up here and did not travel in the file.
 *
 * The field names are spelled out rather than looked up from `landed` by string,
 * so this stays coupled to `HostSecretInput`'s keys: a fourth account field is
 * unwritable until that type gains a key for it, which is where the omission
 * surfaces.
 *
 * Asked under `HOST_SECRET_GROUP` and never of a bare id, which {@link landedKey}
 * is what enforces: an identity's or a key's landed secret must not answer for a
 * host that happens to share its id.
 *
 * Exported for `scripts/backup-verify.ts` alongside {@link hostRefs}: between
 * them they are the whole producing half of the {@link SECRET_ALREADY_STORED}
 * contract, and the consumer half is pinned in `hosts-store-verify.ts`.
 */
export function storedFields(host: Host, landed: Set<string>): HostSecretInput {
  // A vault-bound host owns no accounts, so it has nothing to claim - and
  // `upsertHost` REFUSES a secret handed in with one rather than ignoring it, so
  // a stray field here would abort the row instead of being harmless.
  if (host.credential.kind !== "inline") return {};
  const has = (field: string): boolean => landed.has(landedKey(HOST_SECRET_GROUP, host.id, field));
  if (host.protocol === "rdp") {
    return has(HOST_RDP_PASSWORD_FIELD) ? { password: SECRET_ALREADY_STORED } : {};
  }
  return {
    ...(has(HOST_SSH_PASSWORD_FIELD) ? { password: SECRET_ALREADY_STORED } : {}),
    ...(has(HOST_SSH_PRIVATE_KEY_FIELD) ? { privateKey: SECRET_ALREADY_STORED } : {}),
    ...(has(HOST_SSH_KEY_PASSPHRASE_FIELD) ? { keyPassphrase: SECRET_ALREADY_STORED } : {}),
  };
}

/**
 * Whether this host arrived without the credential it needs.
 *
 * Answered from what the host process actually WROTE, never from the record's
 * own presence flags: the flags in the file describe the exporting machine's
 * keychain, and `stored` is the only report of this one's.
 *
 * PER FIELD, which is what {@link storedFields} promises and what a per-host
 * answer got wrong: a key-auth host whose passphrase travelled and whose private
 * key did not cannot connect, and "some field landed" reported it as fine. So the
 * question is asked of the ONE field the auth mode actually needs. A key
 * passphrase is not that field - a key with no passphrase is ordinary.
 *
 * A binding that is not inline is NOT counted, and there are two ways to be one.
 * A row this machine already had bound has its credential here and never needed
 * to travel; a row that is new and took the file's binding owns no account of its
 * own at all - what it needs is the identity's password, which the identity's own
 * counter answers for. Either way the question this asks is not about the host.
 */
export function arrivedWithoutSecret(host: Host, stored: HostSecretInput): boolean {
  if (host.credential.kind !== "inline") return false;
  if (host.protocol === "rdp") return stored.password === undefined;
  const mode = host.credential.authMode;
  if (mode === "agent") return false;
  if (mode === "key") return stored.privateKey === undefined;
  return stored.password === undefined;
}

/** "Added versus replaced" for one record that just landed, decided in one place
 *  rather than once per collection. `existing` is the ids READ BEFORE any write,
 *  so a row written twice in one import - a record pass and then a flag pass -
 *  cannot count itself as replacing itself. */
function tally(
  id: string,
  existing: Set<string>,
  counts: { added: number; replaced: number },
): void {
  if (existing.has(id)) counts.replaced++;
  else counts.added++;
}

/**
 * One incoming key's record, with the four fields that DESCRIBE a private key
 * resolved against what this machine already holds.
 *
 * A key id ALREADY IN THE VAULT whose `privateKey` did not land in this import
 * keeps the STORED `keyType`, `fingerprint`, `publicKey` and `encrypted`, and
 * the file's are discarded. Otherwise the file's fingerprint sits over this
 * machine's private key and the record names a key nobody holds: the duplicate
 * check at import and the copyable public key would both answer for material
 * that is not there.
 *
 * `encrypted` IS ONE OF THE FOUR, and it is in this list for exactly the reason
 * the two presence flags are not. A passphrase-encryption answer describes the
 * key MATERIAL - which is why `sanitizeKey` carries it through the trust
 * boundary at all, rather than forcing it the way it forces `hasPrivateKey` and
 * `hasPassphrase`, which describe the exporting machine's keychain. Material
 * facts belong to whichever body is actually stored here, so a file's
 * `encrypted: true` left standing over a stored body nobody replaced would make
 * `keyNeedsPassphrase` (`@/modules/vault/refs`) report a key as unusable
 * because of a passphrase on a DIFFERENT machine's key, and the Vault page
 * would say so on a row that is fine. It fails the other way round too: the
 * file's `false` over a stored encrypted body silences the one warning that row
 * needs.
 *
 * Called TWICE per key, and the record write passes `false` deliberately. Nothing
 * has landed at that point, so the conservative arm is the true one; the flag pass
 * calls it again with the real answer, and the file's fields land then - in the
 * same import, over the private key they actually describe.
 *
 * A key that is NEW keeps the file's fields whatever landed, because there is
 * nothing else to keep. Its `hasPrivateKey` stays false when no body arrived, so
 * the fingerprint reads as metadata for a key the user still has to add rather
 * than as a claim about one the store holds.
 *
 * `undefined` rather than a rebuild without the field, the same spelling
 * `normaliseIdentityKeys` uses to clear a `keyId`: the store persists as JSON, so
 * an absent field and an `undefined` one do not survive the write differently.
 * That covers `encrypted` twice over - a stored record written before that field
 * existed carries no answer, and "no inspection has answered this" is what
 * absent means on it, so copying the absence across is the honest result rather
 * than a gap.
 */
function keyRecord(key: VaultKey, stored: VaultKey | undefined, landedBody: boolean): VaultKey {
  if (!stored || landedBody) return key;
  return {
    ...key,
    keyType: stored.keyType,
    fingerprint: stored.fingerprint,
    publicKey: stored.publicKey,
    encrypted: stored.encrypted,
  };
}

/**
 * v3: the host process holds every credential while this validates the metadata,
 * for all five collections - hosts, groups, identities, keys and forward rules.
 *
 * REFERENCES CLEARED BEFORE ANYTHING IS WRITTEN. `upsertHost` refuses a jump or
 * tunnel host that is missing, is not an SSH host, is the row itself, or closes a
 * cycle - it throws instead of dropping the reference, so one bad row would
 * abandon the rest of the file. The same shape holds a collection over: an
 * identity's `keyId` and a rule's `hostId` are throws too, which is what
 * `normaliseIdentityKeys` and `clearDanglingRuleHosts` reconcile before any of
 * this runs.
 *
 * THEN THE WRITE ORDER ACROSS THE FIVE. The store ENFORCES some of it and not the
 * rest, and a reader will assume one rule covers both, so each line says which:
 *
 *   1. KEYS. Nothing references a key except an identity, so they answer to
 *      nobody and go first.
 *
 *   2. IDENTITIES, and 2-AFTER-1 IS ENFORCED: `upsertIdentity` throws on a
 *      `keyId` naming a key it cannot find, so a key written after the identity
 *      that names it costs every record queued behind it.
 *
 *   3. GROUPS, so a host lands with a label that resolves. `groupId` is the one
 *      reference the store does not check, so this is FOR THE USER rather than
 *      for the write: a host whose label lands later is merely ungrouped.
 *
 *   4. HOSTS, in `orderHostWrites` order. CHAIN ORDER IS ENFORCED, against what
 *      is on disk at that moment: `upsertHost` re-walks the whole chain on every
 *      write, so a host written before its jump host fails even though the file
 *      is internally consistent.
 *
 *      4-AFTER-2 IS NOT ENFORCED, and the gap is named because it looks
 *      symmetrical with 2-after-1 and is not. `writeHost` calls
 *      `assertBindingOwner`, which returns early for a binding that is not
 *      inline, and `assertReferences`, which reads jump and tunnel ids only -
 *      nothing there checks that a `{kind:"identity"}` binding names an identity
 *      that exists, so such a host SAVES either way. The only thing standing in
 *      the way is the id set `resolveIdentityBindings` was handed, which is why
 *      that set is built from what `normaliseIdentityKeys` RETURNED and not from
 *      what it was given.
 *
 *   5. RULES, and 5-AFTER-4 IS ENFORCED: `upsertRule` refuses a `hostId` that is
 *      not a SAVED SSH host, and it asks the store rather than the file, so a
 *      rule riding a host whose record was refused above is refused here too
 *      instead of saved as a rule that can never start.
 *
 *   6. SECRETS, all three groups in ONE `backup_apply_secrets` call.
 *
 *   7. THE PRESENCE FLAGS, one pass per collection that owns a secret.
 *
 * RECORDS BEFORE SECRETS is what 6 and 7 are. `backup_apply_secrets` writes every
 * credential in ONE Rust call, so the two cannot be interleaved - but they can be
 * made to follow. References are built only from the records that ALREADY LANDED,
 * in all three groups, which is what makes an orphan account impossible rather
 * than unlikely: every account written names a record that is in a store, so the
 * delete that owns it can still reach it. The old order wrote every credential
 * first, so a record write that threw left the rest of the file unimported AND
 * its credentials at accounts no record named - and nothing enumerates those.
 *
 * Every write is contained to its own record. A refusal is counted and reported,
 * never allowed to abandon the records behind it: a 40-host file whose host 12 the
 * store will not take must still import the other 39, and `problems` carries one
 * line per refusal caught, from the nine push sites below.
 *
 * EIGHT OF THE NINE NAME THE RECORD THEY REFUSED; the ninth is WRITE 6, and the
 * quantifier is worth being exact about because that arm is the one a reader
 * checks first. WRITE 6 is a single `backup_apply_secrets` call carrying every
 * account this import is going to write, so a throw there is ONE line covering
 * all of them and naming none - the same single line whether the file carried one
 * account or four hundred. A refusal SHORT of a throw pushes no line at all: a
 * `written[i]` that came back false is carried by the `withoutSecrets` counters
 * instead, where each collection decides for itself which field makes a record
 * incomplete. So the line count counts caught throws, never records and never
 * accounts.
 *
 * NO RECORD CAN PRODUCE TWO LINES, which is what lets the list be read as one
 * refusal per line. A record whose own write throws never reaches the collection
 * it would be reported from again - the `saved*` push sits after the await - and
 * a WRITE 6 throw leaves `landed` empty, which sends every record in WRITE 7 down
 * its `continue` before it can push a second time.
 */
async function applyV3(payload: SealedBlob, passphrase: string): Promise<ImportResult> {
  const opened = await invoke<{ handle: number; payload: string }>("backup_open_payload", {
    blob: payload,
    passphrase,
    groups: SECRET_GROUPS,
  });

  try {
    let meta: unknown;
    try {
      meta = JSON.parse(opened.payload);
    } catch {
      throw new Error("The encrypted payload did not contain readable connections.");
    }
    const parsed = sanitizePayload(meta);

    // Read BEFORE the first write, and every "did this exist here already?"
    // question below is asked of these lists rather than of the store: a record
    // pass and a flag pass both write the same row, and re-reading between them
    // would count the second write as replacing the first.
    const [existingHosts, existingGroups, existingIdentities, existingKeys, existingRules] =
      await Promise.all([listHosts(), listGroups(), listIdentities(), listKeys(), listRules()]);
    const existingIds = new Set(existingHosts.map((h) => h.id));
    const problems: string[] = [];

    // "WILL EXIST" IS A UNION, and it means the same thing here as it does one
    // pass up: the records arriving in this file, plus the ones already saved on
    // this machine. `normaliseIdentityKeys` answers that same question about KEYS
    // with exactly that union - a key the user already has is as good as one that
    // travelled - and two neighbouring passes answering one question two ways is
    // what reads as a bug to whoever finds one of them first. Narrowing either
    // side alone is the thing not to do.
    //
    // THE ORDER OF THESE TWO LINES IS STILL A GUARD. The FILE's half of the set
    // comes from what `normaliseIdentityKeys` RETURNED, never from
    // `parsed.identities` and never from the list it was handed: an identity it
    // skipped for a key that did not travel is not written, so a host bound to it
    // would name nothing while the binding's arrival released every account that
    // host owned. Building that half one line earlier reintroduces exactly that.
    //
    // THE SAVED HALF CANNOT SMUGGLE A SKIPPED IDENTITY BACK IN. Skipped means key
    // auth naming a key that will not exist, and an identity saved HERE under key
    // auth naming a key absent HERE is a state `upsertIdentity` refuses to
    // create. Nor can widening cost a credential: outcome 2 in
    // `resolveIdentityBindings` fires only when NO host is saved under that id,
    // and a host with no stored record owns no accounts, so the write has nothing
    // to release. The destructive case outcome 3 exists for is a SAVED INLINE
    // host, which this set never reaches.
    const normalised = normaliseIdentityKeys(parsed.identities, parsed.keys, existingKeys);
    const identityIds = new Set([
      ...normalised.identities.map((i) => i.id),
      ...existingIdentities.map((i) => i.id),
    ]);

    // The host credential passes come next, before anything reads a row's protocol
    // or binding: both of them decide what a row is allowed to BECOME, and both
    // exist because the alternative deletes a saved host's secrets.
    const kinds = refuseProtocolConflicts(parsed.hosts, existingHosts);
    const bound = resolveIdentityBindings(kinds.hosts, existingHosts, identityIds);
    // Pins keyed EXPLICITLY before any row is written, so the store never has to
    // infer which machine an imported pin came off. Its inference is written for a
    // spread of a saved record; a file is not one, and a file naming a different
    // address than the row saved here would have the saved address's verified key
    // replaced by the other machine's while the address about to be dialled was
    // left on TOFU.
    const pinned = carryPins(bound.hosts, existingHosts);

    // Handed the rows that SURVIVED those passes, not `parsed.hosts`: a row
    // `refuseProtocolConflicts` refused is not going to be written, and a rule
    // riding it would dangle. The passes still to come touch neither a row's id
    // nor its protocol, which are the only two fields this one reads.
    const ruled = clearDanglingRuleHosts(parsed.rules, pinned, existingHosts);

    const merged = mergeGroups(parsed.groups, existingGroups, pinned);

    // A jump host or a tunnel bastion may live in the file OR already be saved
    // here; both count as resolvable, which is why the saved list is passed in
    // rather than just the file's own ids.
    const cleared = clearDanglingTunnels(
      clearDanglingJumps(merged.hosts, existingHosts),
      existingHosts,
    );
    const incoming = orderHostWrites(cleared, existingHosts);

    const ssh: ImportCounts = { ...NO_COUNTS };
    const rdp: ImportCounts = { ...NO_COUNTS };
    const groups: ImportGroupCounts = {
      ...NO_GROUP_COUNTS,
      merged: merged.merged,
      keptNames: merged.keptNames,
    };
    const identities: ImportIdentityCounts = {
      ...NO_IDENTITY_COUNTS,
      withoutKeys: normalised.withoutKeys,
      keysDropped: normalised.keysDropped,
    };
    const keys: ImportKeyCounts = { ...NO_KEY_COUNTS };
    const rules: ImportRuleCounts = { ...NO_RULE_COUNTS, dropped: ruled.dropped };

    // WRITE 1: the keys. No secret and no flag handed over - `{}` leaves a stored
    // key's two flags exactly as they are, and a key that is new gets `false` for
    // both until the secrets pass says otherwise. A key that fails here is
    // counted and contributes no reference below, so nothing is written to an
    // account whose record is not in the store.
    const storedKeys = new Map(existingKeys.map((k) => [k.id, k]));
    const keyIds = new Set(existingKeys.map((k) => k.id));
    const savedKeys: VaultKey[] = [];
    for (const key of parsed.keys) {
      try {
        await upsertKey(keyRecord(key, storedKeys.get(key.id), false), {});
        tally(key.id, keyIds, keys);
        savedKeys.push(key);
      } catch (e) {
        keys.failed++;
        problems.push(`key "${key.name}" could not be saved: ${reason(e)}`);
      }
    }

    // WRITE 2: the identities, after the keys their `keyId`s name.
    //
    // An identity whose write FAILS was already counted as existing by
    // `identityIds` above, so a host bound to it saves with a binding naming
    // nothing. That costs no secret and cannot: outcome 2 in
    // `resolveIdentityBindings` only applies a binding to a host that is NEW, and
    // a host with no stored record has no account to release. What is left is a
    // new host that will not connect until one dialog fixes it, which is the same
    // place a refused binding leaves one.
    const identityStoreIds = new Set(existingIdentities.map((i) => i.id));
    const savedIdentities: VaultIdentity[] = [];
    for (const identity of normalised.identities) {
      try {
        await upsertIdentity(identity, {});
        tally(identity.id, identityStoreIds, identities);
        savedIdentities.push(identity);
      } catch (e) {
        identities.failed++;
        problems.push(`identity "${identity.name}" could not be saved: ${reason(e)}`);
      }
    }

    // WRITE 3: the groups, before the hosts wearing them.
    const groupIds = new Set(existingGroups.map((g) => g.id));
    for (const group of merged.groups) {
      try {
        await upsertGroup(group);
        tally(group.id, groupIds, groups);
      } catch (e) {
        // Contained for the same reason a host write is: a label the store will
        // not take must not cost the user the forty hosts behind it. The members
        // render as ungrouped, which is visible and fixable.
        groups.failed++;
        problems.push(`group "${group.name}" could not be saved: ${reason(e)}`);
      }
    }

    // WRITE 4: the host records, with no credential at all. A row that fails here
    // is counted and skipped, and crucially contributes no reference below - so
    // nothing is ever written to an account whose host is not in the store.
    const saved: Host[] = [];
    for (const host of incoming) {
      const counts = host.protocol === "ssh" ? ssh : rdp;
      try {
        await upsertHost(host, {});
        tally(host.id, existingIds, counts);
        saved.push(host);
      } catch (e) {
        counts.failed++;
        problems.push(`"${host.name}" could not be saved: ${reason(e)}`);
      }
    }

    // WRITE 5: the rules, after the hosts they ride.
    const ruleIds = new Set(existingRules.map((r) => r.id));
    for (const rule of ruled.rules) {
      try {
        // A REWRITE OF A RULE THAT IS UP RIGHT NOW HAS TO RELEASE IT FIRST, and
        // the release has to name the record as SAVED. `ssh/tunnel.ts` keys its
        // entry by host, remote host, remote port and local port, and an import
        // may rewrite any of those four under a live page-owned forward - after
        // which nothing left in the app names that entry: the close misses, the
        // session stays at `refs: 1`, and the local port stays bound for the
        // rest of the app's life. `existing` and never `rule`, because the
        // incoming row is precisely the one whose fields may differ.
        // `forwards/editor/RuleEditorDialog.tsx`'s save guards the same hazard
        // on the editor's path.
        //
        // ONLY FOR AN ID ALREADY SAVED. A rule id absent from `existingRules`
        // is a create; nothing is running under it, and releasing it would read
        // as if something might be.
        //
        // Inside the `try`, so a stop that reports costs this ONE rule and is
        // reported against it, the same containment every other write in this
        // function has - a close that fails must not abandon the rules behind
        // it.
        const existing = existingRules.find((r) => r.id === rule.id);
        if (existing) await releaseRule(existing);
        // `findHost` and not a list assembled here: `upsertRule` is asking whether
        // the host is SAVED, and answering out of the file would let a rule ride a
        // host the store just refused. `clearDanglingRuleHosts` has already turned
        // the file's own dangling references into `dropped`, so what reaches this
        // throw is a host that failed to write.
        await upsertRule(rule, findHost);
        tally(rule.id, ruleIds, rules);
      } catch (e) {
        rules.failed++;
        problems.push(`forward rule "${rule.name}" could not be saved: ${reason(e)}`);
      }
    }

    // The ids that arrived vault-bound. A file that declared a row's credential to
    // live in a vault does not also get to write a host-owned secret for it: the
    // two claims contradict each other, and honouring the second would let a
    // hand-made payload replace the credential this machine already has on a row
    // whose binding was just refused. So a downgraded row gets no reference either,
    // and the flags it keeps are the ones already on disk.
    //
    // NARROWER IN v3 AND STILL REACHABLE. A row that KEPT its binding owns no
    // accounts, so `hostRefs` already returns nothing for it; what this filter is
    // left doing is the DOWNGRADED row, whose credential is inline again and whose
    // fields `hostRefs` would therefore name. A real export cannot carry a
    // `hostSecrets` entry for a row it exported as vault-bound - but a hand-made
    // payload can, and an import is a trust boundary.
    const arrivedBound = new Set(
      parsed.hosts.filter((h) => h.credential.kind === "identity").map((h) => h.id),
    );
    // WRITE 6: every credential, in ONE call, for records that already landed in
    // all three groups. The order of the three does not matter to Rust - each
    // reference carries its own group - but it has to match the order `written` is
    // read back in, which is why the array is built once and indexed once.
    const refs: SecretRef[] = [
      ...savedKeys.flatMap(keyRefs),
      ...savedIdentities.flatMap(identityRefs),
      ...saved.filter((h) => !arrivedBound.has(h.id)).flatMap(hostRefs),
    ];
    let written: boolean[] = [];
    try {
      // Skipped entirely when there is nothing to ask for, which is the whole
      // file when every row is agent-auth or kept a vault binding.
      if (refs.length > 0) {
        written = await invoke<boolean[]>("backup_apply_secrets", {
          handle: opened.handle,
          refs,
        });
      }
    } catch (e) {
      // Reported rather than rethrown: the records are already saved, so throwing
      // here would report a whole import as failed after writing all of it. The
      // flags stay false, which is the safe direction - an SSH host resolves by
      // auth mode and never reads one, and an RDP host refuses to connect until
      // the password is re-entered, rather than claiming one that is not there.
      problems.push(`no stored credentials could be written to the keychain: ${reason(e)}`);
    }
    // Which ACCOUNT each credential landed at. A short or missing array is
    // treated as "nothing written" rather than trusted by index, so a protocol
    // change cannot make this claim a credential exists. Keyed by
    // {@link landedKey} - the account name under its own payload group, because
    // three groups over three id spaces means an id no longer identifies the
    // record it came off. See there for what a bare id costs.
    const landed = new Set<string>();
    refs.forEach((r, i) => {
      if (written[i] === true) landed.add(landedKey(r.group, r.id, r.field));
    });

    // WRITE 7: the presence flags, for what actually landed, one pass per
    // collection that owns a secret. A refusal in any of them is NOT a failed
    // record - the record is saved and the credential is at an account that record
    // names, so it is reachable and the next edit fixes the flag.
    //
    // A flag NEVER comes from the file, in any of the three. It is either
    // `SECRET_ALREADY_STORED` for something that landed, or omitted - and omitted
    // is the store's "leave whatever is there alone", which for a record it has
    // never seen is `false`. `writeSecret` in `vault/store.ts` is the one place
    // that decides it.
    for (const key of savedKeys) {
      const landedBody = landed.has(landedKey(KEY_SECRET_GROUP, key.id, KEY_PRIVATE_KEY_FIELD));
      const landedPhrase = landed.has(landedKey(KEY_SECRET_GROUP, key.id, KEY_PASSPHRASE_FIELD));
      // Judged by the ONE field that decides whether the record is usable, the
      // same way a host is judged by the field its auth mode needs.
      if (!landedBody) keys.withoutSecrets++;
      // The record already landed above carrying whatever `keyRecord` chose with
      // nothing yet known, so a key with neither secret has nothing left to say.
      if (!landedBody && !landedPhrase) continue;
      try {
        await upsertKey(keyRecord(key, storedKeys.get(key.id), landedBody), {
          ...(landedBody ? { privateKey: SECRET_ALREADY_STORED } : {}),
          ...(landedPhrase ? { passphrase: SECRET_ALREADY_STORED } : {}),
        });
      } catch (e) {
        problems.push(
          `key "${key.name}" was saved, but its stored material could not be ` +
            `recorded on it: ${reason(e)}`,
        );
      }
    }

    for (const identity of savedIdentities) {
      const landedPassword = landed.has(
        landedKey(IDENTITY_SECRET_GROUP, identity.id, IDENTITY_PASSWORD_FIELD),
      );
      // Only the mode that NEEDS a password can be missing one. The flag itself is
      // written for any mode, because one identity legitimately owns a password it
      // does not use over SSH.
      if (identity.authMode === "password" && !landedPassword) identities.withoutSecrets++;
      if (!landedPassword) continue;
      try {
        await upsertIdentity(identity, { password: SECRET_ALREADY_STORED });
      } catch (e) {
        problems.push(
          `identity "${identity.name}" was saved, but its stored password could ` +
            `not be recorded on it: ${reason(e)}`,
        );
      }
    }

    for (const host of saved) {
      const counts = host.protocol === "ssh" ? ssh : rdp;
      const stored = storedFields(host, landed);
      if (arrivedWithoutSecret(host, stored)) counts.withoutSecrets++;
      if (Object.keys(stored).length === 0) continue;
      try {
        await upsertHost(host, stored);
      } catch (e) {
        problems.push(
          `"${host.name}" was saved, but its stored credentials could not be ` +
            `recorded on it: ${reason(e)}`,
        );
      }
    }

    // A forward rule owns no secret and has no flag, so there is no fourth pass.

    return {
      ssh,
      rdp,
      groups,
      identities,
      keys,
      rules,
      skipped: parsed.skipped,
      protocolConflicts: kinds.conflicts,
      vaultBindingsDropped: bound.dropped,
      vaultBindingsApplied: bound.applied,
      problems,
    };
  } finally {
    // The handle holds decrypted credentials, so it is released on every path
    // out - including the one where validation threw. A failure to release is
    // swallowed: it would otherwise mask the real error, and the host process
    // caps how many parked payloads can accumulate.
    try {
      await invoke("backup_release", { handle: opened.handle });
    } catch {
      // Already gone, or the store is wedged; nothing useful to do here.
    }
  }
}
