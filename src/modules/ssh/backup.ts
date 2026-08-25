/**
 * Export / import saved hosts as a single passphrase-encrypted `.tervia-backup`
 * file, so moving to another machine is one import instead of retyping every
 * host and credential.
 *
 * The credentials live in the OS keychain and CANNOT travel with the store files
 * on their own - a keychain does not move between machines - which is exactly
 * why this exists and why the file is always encrypted: it carries SSH
 * passwords, SSH private keys and RDP passwords, so a plaintext export would be
 * a credential leak the moment it touched Downloads or a synced folder. Sealing
 * happens in the host process (`modules/backup.rs`); `crypto.subtle` is not
 * available to the webview because the app origin is plain http.
 *
 * THE CREDENTIALS DO NOT PASS THROUGH HERE. An export sends keychain
 * REFERENCES and Rust reads the values; an import gets back only the host
 * metadata and tells Rust which ids may be written. That is deliberate, and it
 * is why there is no RDP secret read-back helper anywhere in the tree:
 * `rdp_open` takes a reference precisely so an RDP password never enters the
 * webview, and a backup that read one would have thrown that away.
 *
 * The v1 path below is the exception, and it cannot be otherwise: a v1 file's
 * sealed block IS the credential map, so importing one means holding it here
 * long enough to write it. v1 is SSH-only and read-only.
 *
 * What does NOT travel yet: a vault-bound host's credential. The host record
 * itself is exported, but its identity and key live on the `tervia-vault`
 * service and are not in this payload - a format carrying them is 6g. Nothing
 * here makes a secret safer either way; what a vault binding buys is fewer
 * copies of one secret.
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
import {
  HOST_RDP_SECRET_FIELDS,
  HOST_SSH_SECRET_FIELDS,
  type Host,
  type SshHost,
} from "@/modules/hosts/types";
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
  clearDanglingJumps,
  clearDanglingTunnels,
  mergeGroups,
  orderHostWrites,
  parseBackupFile,
  sanitizePayload,
  sanitizeSecrets,
  type BackupFileV2,
  type BackupSecrets,
  type SealedBlob,
  type SecretRef,
} from "./backupFile";

/**
 * Keychain references for one host's every credential field.
 *
 * A vault-bound host contributes NONE: it owns no accounts of its own, so there
 * is nothing on the host service to read. Its identity's secrets are a separate
 * service and a later format.
 */
function hostRefs(host: Host): SecretRef[] {
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
    // The inventory only. Rust folds the credentials in under the group name in
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
  /** Hosts whose credentials did not travel. Agent-auth SSH hosts are NOT
   *  counted: they have no secret by design, so reporting them as missing one
   *  would read as a broken import. A vault-bound host IS counted - its
   *  credential is real and this format does not carry it yet. */
  withoutSecrets: number;
};

export type ImportResult = {
  ssh: ImportCounts;
  rdp: ImportCounts;
  /** Entries dropped because they could not be a working host or a pickable
   *  group. */
  skipped: number;
};

const NO_COUNTS: ImportCounts = { added: 0, replaced: 0, withoutSecrets: 0 };

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
  const parsed = parseBackupFile(raw);
  return parsed.version === 1
    ? applyV1(parsed.hosts, parsed.secrets, parsed.skipped, passphrase)
    : applyV2(parsed.payload, passphrase);
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
 */
function storedFields(host: Host, landed: Set<string>): HostSecretInput {
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
 */
function arrivedWithoutSecret(host: Host, stored: HostSecretInput): boolean {
  if (Object.keys(stored).length > 0) return false;
  if (host.credential.kind !== "inline") return true;
  return !(host.protocol === "ssh" && host.credential.authMode === "agent");
}

/**
 * Write one host and tally it. Shared by both format generations so the counting
 * rule cannot drift between them.
 */
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
 * Three orderings matter here, and each one is a failure the store now refuses
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

    const merged = mergeGroups(parsed.groups, existingGroups, parsed.hosts);
    for (const group of merged.groups) await upsertGroup(group);

    // A jump host or a tunnel bastion may live in the file OR already be saved
    // here; both count as resolvable, which is why the saved list is passed in
    // rather than just the file's own ids.
    const cleared = clearDanglingTunnels(
      clearDanglingJumps(merged.hosts, existingHosts),
      existingHosts,
    );
    const incoming = orderHostWrites(cleared, existingHosts);

    const refs: SecretRef[] = incoming.flatMap(hostRefs);
    const written = await invoke<boolean[]>("backup_apply_secrets", {
      handle: opened.handle,
      refs,
    });
    // Which ACCOUNT each credential landed at. A short or missing array is
    // treated as "nothing written" rather than trusted by index, so a protocol
    // change cannot make this claim a credential exists. Keyed by
    // `<hostId>::<field>`, which is the account name itself: one secret group and
    // one id space now, so nothing else is needed to tell two apart.
    const landed = new Set<string>();
    refs.forEach((r, i) => {
      if (written[i] === true) landed.add(`${r.id}::${r.field}`);
    });

    const ssh: ImportCounts = { ...NO_COUNTS };
    const rdp: ImportCounts = { ...NO_COUNTS };
    for (const host of incoming) {
      const counts = host.protocol === "ssh" ? ssh : rdp;
      const stored = storedFields(host, landed);
      if (arrivedWithoutSecret(host, stored)) counts.withoutSecrets++;
      await writeImported(host, stored, existingIds, counts);
    }

    return { ssh, rdp, skipped: parsed.skipped };
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

/**
 * v1: SSH only, and the one path where a plaintext credential still passes
 * through the webview - the sealed block in a v1 file is the credential map
 * itself, so there is nothing else to hand to the keychain.
 *
 * A v1 file predates groups and forward rules, so it carries neither: its rows
 * arrive as ordinary SSH hosts with an inline credential, and their `forwards`
 * are dropped at the parser (decision 7).
 */
async function applyV1(
  hosts: SshHost[],
  sealed: SealedBlob,
  skipped: number,
  passphrase: string,
): Promise<ImportResult> {
  // Decrypt BEFORE touching the store: a wrong passphrase must leave the
  // existing hosts exactly as they were, not half-merged.
  const plain = await invoke<string>("backup_open", { blob: sealed, passphrase });
  let secrets: BackupSecrets;
  try {
    secrets = sanitizeSecrets(JSON.parse(plain));
  } catch {
    throw new Error("The encrypted block did not contain readable credentials.");
  }

  const existingHosts = await listHosts();
  const existingIds = new Set(existingHosts.map((h) => h.id));
  // The same two passes and the same ordering as v2, for the same reason: the
  // store's reference guard does not care which format the row came out of.
  const incoming = orderHostWrites(clearDanglingJumps(hosts, existingHosts), existingHosts);

  const ssh: ImportCounts = { ...NO_COUNTS };
  for (const host of incoming) {
    // Real VALUES here, not `SECRET_ALREADY_STORED`: on this path the credential
    // is in hand, so the store writes it and derives the flag from that write.
    // `sanitizeSecrets` has already dropped anything empty, so a field left out
    // is one that did not travel - which the store reads as "leave whatever is
    // already in the keychain", the non-destructive choice when re-importing over
    // a host whose credential is set up here.
    const s = secrets[host.id];
    const stored: HostSecretInput = {
      ...(s?.password ? { password: s.password } : {}),
      ...(s?.privateKey ? { privateKey: s.privateKey } : {}),
      ...(s?.keyPassphrase ? { keyPassphrase: s.keyPassphrase } : {}),
    };
    if (arrivedWithoutSecret(host, stored)) ssh.withoutSecrets++;
    await writeImported(host, stored, existingIds, ssh);
  }

  return { ssh, rdp: { ...NO_COUNTS }, skipped };
}
