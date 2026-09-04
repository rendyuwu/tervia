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
 * anywhere first. So a host already saved here KEEPS its own credential, and a
 * host that is new arrives as a blank inline row that one dialog fixes. Nothing
 * here strengthens the protection on any secret; what a vault binding buys is
 * fewer copies of one.
 */
import { invoke } from "@tauri-apps/api/core";

import {
  listGroups,
  listHosts,
  upsertGroup,
  upsertHost,
  SECRET_ALREADY_STORED,
  type HostSecretInput,
} from "@/modules/hosts/store";
import { HOST_RDP_SECRET_FIELDS, HOST_SSH_SECRET_FIELDS, type Host } from "@/modules/hosts/types";
import {
  HOST_KEYRING_SERVICE,
  HOST_RDP_PASSWORD_FIELD,
  HOST_SSH_KEY_PASSPHRASE_FIELD,
  HOST_SSH_PASSWORD_FIELD,
  HOST_SSH_PRIVATE_KEY_FIELD,
  vaultAccount,
} from "@/modules/vault/types";

import {
  BACKUP_KIND,
  BACKUP_VERSION,
  HOST_SECRET_GROUP,
  SECRET_GROUPS,
  carryPins,
  clearDanglingJumps,
  clearDanglingTunnels,
  mergeGroups,
  orderHostWrites,
  parseBackupFile,
  refuseProtocolConflicts,
  resolveIdentityBindings,
  sanitizePayload,
  type BackupFileV2,
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
 * Serialize every saved host and group plus the hosts' keychain secrets into
 * file text. Returns the counts alongside it so the caller can say what it wrote
 * without parsing the JSON back out.
 *
 * References are built for EVERY field a host could own, including ones with
 * nothing stored - the host process skips a reference that resolves to nothing,
 * which keeps the decision about what exists in the one place that can actually
 * answer it.
 */
export async function buildBackup(
  passphrase: string,
): Promise<{ text: string; sshCount: number; rdpCount: number }> {
  if (!passphrase) throw new Error("A passphrase is required.");
  const [hosts, groups] = await Promise.all([listHosts(), listGroups()]);
  if (hosts.length === 0) {
    throw new Error("There are no saved connections to export.");
  }

  const refs: SecretRef[] = hosts.flatMap(hostRefs);

  const payload = await invoke<SealedBlob>("backup_seal_payload", {
    // The inventory only. Rust folds the credentials in under the group names in
    // SECRET_GROUPS and refuses to overwrite a key that is already here, so
    // neither `hosts` nor `groups` can be replaced by a credential map.
    payload: JSON.stringify({ hosts, groups }),
    refs,
    passphrase,
  });

  const file: BackupFileV2 = {
    kind: BACKUP_KIND,
    version: BACKUP_VERSION,
    exportedAt: Date.now(),
    payload,
  };
  return {
    text: JSON.stringify(file, null, 2),
    sshCount: hosts.filter((h) => h.protocol === "ssh").length,
    rdpCount: hosts.filter((h) => h.protocol === "rdp").length,
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

export type ImportResult = {
  ssh: ImportCounts;
  rdp: ImportCounts;
  groups: ImportGroupCounts;
  /** Entries dropped because they could not be a working host or a pickable
   *  group. */
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
  return applyV2(parseBackupFile(raw).payload, passphrase);
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
 * Exported for `scripts/backup-verify.ts` alongside {@link hostRefs}: between
 * them they are the whole producing half of the {@link SECRET_ALREADY_STORED}
 * contract, and the consumer half is pinned in `hosts-store-verify.ts`.
 */
export function storedFields(host: Host, landed: Set<string>): HostSecretInput {
  // A vault-bound host owns no accounts, so it has nothing to claim - and
  // `upsertHost` REFUSES a secret handed in with one rather than ignoring it, so
  // a stray field here would abort the row instead of being harmless.
  if (host.credential.kind !== "inline") return {};
  const has = (field: string): boolean => landed.has(`${host.id}::${field}`);
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
 * A binding that is not inline is NOT counted. After `resolveIdentityBindings` the
 * only way a row is still vault-bound is that this machine already had it bound,
 * so its credential is here and never needed to travel.
 */
export function arrivedWithoutSecret(host: Host, stored: HostSecretInput): boolean {
  if (host.credential.kind !== "inline") return false;
  if (host.protocol === "rdp") return stored.password === undefined;
  const mode = host.credential.authMode;
  if (mode === "agent") return false;
  if (mode === "key") return stored.privateKey === undefined;
  return stored.password === undefined;
}

/** Write one host and tally it, so "added versus replaced" is decided in one
 *  place rather than at each call site. */
async function writeImported(
  host: Host,
  secrets: HostSecretInput,
  existingIds: Set<string>,
  counts: ImportCounts,
): Promise<void> {
  await upsertHost(host, secrets);
  if (existingIds.has(host.id)) counts.replaced++;
  else counts.added++;
}

/**
 * v2: the host process holds the credentials while this validates the metadata.
 *
 * Four orderings matter here, and each one is a failure the store now refuses
 * rather than tolerates:
 *
 *   GROUPS BEFORE HOSTS, so a host lands with a label that resolves. `groupId`
 *   is the one reference the store does not check, so this is for the user's
 *   benefit rather than the write's.
 *
 *   REFERENCES CLEARED BEFORE ANYTHING IS WRITTEN. `upsertHost` refuses a jump
 *   or tunnel host that is missing, is not an SSH host, is the row itself, or
 *   closes a cycle - it throws instead of dropping the reference, so one bad row
 *   would abandon the rest of the file.
 *
 *   HOSTS IN CHAIN ORDER, bastion first. The same guard is applied against what
 *   is on disk at that moment, so a host written before its jump host fails even
 *   though the file is internally consistent.
 *
 *   RECORDS BEFORE SECRETS, then the flags. `backup_apply_secrets` writes every
 *   credential in ONE Rust call, so the two cannot be interleaved - but they can
 *   be made to follow. References are built only from the rows whose record
 *   ALREADY LANDED, which is what makes an orphan account impossible rather than
 *   unlikely: every account written names a host that is in the store, so
 *   `deleteHost` can still reach it. The old order wrote every credential first,
 *   so a record write that threw left the rest of the file unimported AND its
 *   credentials at accounts no record named - and nothing enumerates those (§9.7).
 *
 * Every write is contained to its own row. A refusal is counted and reported,
 * never allowed to abandon the rows behind it: a 40-host file whose host 12 the
 * store will not take must still import the other 39.
 */
async function applyV2(payload: SealedBlob, passphrase: string): Promise<ImportResult> {
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

    const [existingHosts, existingGroups] = await Promise.all([listHosts(), listGroups()]);
    const existingIds = new Set(existingHosts.map((h) => h.id));
    const problems: string[] = [];

    // The credential passes come FIRST, before anything reads a row's protocol or
    // binding: both of them decide what a row is allowed to BECOME, and both
    // exist because the alternative deletes a saved host's secrets.
    const kinds = refuseProtocolConflicts(parsed.hosts, existingHosts);
    const bound = resolveIdentityBindings(kinds.hosts, existingHosts);
    // Pins keyed EXPLICITLY before any row is written, so the store never has to
    // infer which machine an imported pin came off. Its inference is written for a
    // spread of a saved record; a file is not one, and a file naming a different
    // address than the row saved here would have the saved address's verified key
    // replaced by the other machine's while the address about to be dialled was
    // left on TOFU.
    const pinned = carryPins(bound.hosts, existingHosts);

    const merged = mergeGroups(parsed.groups, existingGroups, pinned);
    const groupIds = new Set(existingGroups.map((g) => g.id));
    const groups: ImportGroupCounts = {
      ...NO_GROUP_COUNTS,
      merged: merged.merged,
      keptNames: merged.keptNames,
    };
    for (const group of merged.groups) {
      try {
        await upsertGroup(group);
        if (groupIds.has(group.id)) groups.replaced++;
        else groups.added++;
      } catch (e) {
        // Contained for the same reason a host write is: a label the store will
        // not take must not cost the user the forty hosts behind it. The members
        // render as ungrouped, which is visible and fixable.
        groups.failed++;
        problems.push(`group "${group.name}" could not be saved: ${reason(e)}`);
      }
    }

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

    // PASS ONE: the records, with no credential at all. A row that fails here is
    // counted and skipped, and crucially contributes no reference below - so
    // nothing is ever written to an account whose host is not in the store.
    const saved: Host[] = [];
    for (const host of incoming) {
      const counts = host.protocol === "ssh" ? ssh : rdp;
      try {
        await writeImported(host, {}, existingIds, counts);
        saved.push(host);
      } catch (e) {
        counts.failed++;
        problems.push(`"${host.name}" could not be saved: ${reason(e)}`);
      }
    }

    // The ids that arrived vault-bound. A file that declared a row's credential to
    // live in a vault does not also get to write a host-owned secret for it: the
    // two claims contradict each other, and honouring the second would let a
    // hand-made payload replace the credential this machine already has on a row
    // whose binding was just refused. So a downgraded row gets no reference either,
    // and the flags it keeps are the ones already on disk.
    const arrivedBound = new Set(
      parsed.hosts.filter((h) => h.credential.kind === "identity").map((h) => h.id),
    );
    const refs: SecretRef[] = saved.filter((h) => !arrivedBound.has(h.id)).flatMap(hostRefs);
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
    // `<hostId>::<field>`, which is the account name itself: one secret group and
    // one id space now, so nothing else is needed to tell two apart.
    const landed = new Set<string>();
    refs.forEach((r, i) => {
      if (written[i] === true) landed.add(`${r.id}::${r.field}`);
    });

    // PASS TWO: the presence flags for what actually landed. A refusal here is
    // NOT a failed host - the record is saved and the credential is at an account
    // that record names, so it is reachable and the next edit fixes the flag.
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

    return {
      ssh,
      rdp,
      groups,
      skipped: parsed.skipped,
      protocolConflicts: kinds.conflicts,
      vaultBindingsDropped: bound.dropped,
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
