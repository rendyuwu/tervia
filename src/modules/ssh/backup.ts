/**
 * Export / import saved SSH and RDP connections as a single
 * passphrase-encrypted `.tervia-backup` file, so moving to another machine is
 * one import instead of retyping every host and credential.
 *
 * The credentials live in the OS keychain and CANNOT travel with the store
 * files on their own - a keychain does not move between machines - which is
 * exactly why this exists and why the file is always encrypted: it carries SSH
 * passwords, SSH private keys and RDP passwords, so a plaintext export would be
 * a credential leak the moment it touched Downloads or a synced folder. Sealing
 * happens in the host process (`modules/backup.rs`); `crypto.subtle` is not
 * available to the webview because the app origin is plain http.
 *
 * THE CREDENTIALS DO NOT PASS THROUGH HERE. An export sends keychain
 * REFERENCES and Rust reads the values; an import gets back only the connection
 * metadata and tells Rust which ids may be written. That is deliberate and it
 * is the reason `src/modules/rdp/connections.ts` has no secret read-back
 * helper: `rdp_open` takes a reference precisely so an RDP password never
 * enters the webview, and a backup that read one would have thrown that away.
 *
 * The v1 path below is the exception, and it cannot be otherwise: a v1 file's
 * sealed block IS the credential map, so importing one means holding it here
 * long enough to write it. v1 is SSH-only and read-only.
 */
import { invoke } from "@tauri-apps/api/core";
import {
  RDP_KEYRING_SERVICE,
  RDP_SECRET_FIELDS,
  rdpKeyringAccount,
  listConnections as listRdpConnections,
  upsertConnection as upsertRdpConnection,
  type RdpConnection,
} from "@/modules/rdp/connections";
import {
  SSH_KEYRING_SERVICE,
  SSH_SECRET_FIELDS,
  keyringAccount,
  listConnections,
  upsertConnection,
  type SshConnection,
} from "./connections";
import {
  BACKUP_KIND,
  BACKUP_VERSION,
  SECRET_GROUPS,
  clearDanglingJumps,
  clearDanglingTunnels,
  parseBackupFile,
  sanitizePayload,
  sanitizeSecrets,
  type BackupFileV2,
  type BackupSecrets,
  type SealedBlob,
  type SecretRef,
} from "./backupFile";

/** Keychain references for one connection's every credential field. */
function sshRefs(id: string): SecretRef[] {
  return SSH_SECRET_FIELDS.map((field) => ({
    group: "secrets" as const,
    id,
    field,
    service: SSH_KEYRING_SERVICE,
    account: keyringAccount(id, field),
  }));
}

function rdpRefs(id: string): SecretRef[] {
  return RDP_SECRET_FIELDS.map((field) => ({
    group: "rdpSecrets" as const,
    id,
    field,
    service: RDP_KEYRING_SERVICE,
    account: rdpKeyringAccount(id, field),
  }));
}

/**
 * Serialize every saved connection of both protocols plus its keychain secrets
 * into file text. Returns the counts alongside it so the caller can say what it
 * wrote without parsing the JSON back out.
 *
 * References are built for EVERY field of every connection, including ones with
 * nothing stored - the host process skips a reference that resolves to nothing,
 * which keeps the decision about what exists in the one place that can actually
 * answer it.
 */
export async function buildBackup(
  passphrase: string,
): Promise<{ text: string; sshCount: number; rdpCount: number }> {
  if (!passphrase) throw new Error("A passphrase is required.");
  const [connections, rdpConnections] = await Promise.all([
    listConnections(),
    listRdpConnections(),
  ]);
  if (connections.length === 0 && rdpConnections.length === 0) {
    throw new Error("There are no saved connections to export.");
  }

  const refs: SecretRef[] = [
    ...connections.flatMap((c) => sshRefs(c.id)),
    ...rdpConnections.flatMap((c) => rdpRefs(c.id)),
  ];

  const payload = await invoke<SealedBlob>("backup_seal_payload", {
    // The inventory only. Rust folds the credentials in under the group names
    // in SECRET_GROUPS and refuses to overwrite either key here.
    payload: JSON.stringify({ connections, rdpConnections }),
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
    sshCount: connections.length,
    rdpCount: rdpConnections.length,
  };
}

export type ImportCounts = {
  /** Connections written that did not exist here before. */
  added: number;
  /** Existing ids the backup overwrote. */
  replaced: number;
  /** Connections whose credentials did not travel (none were saved for them).
   *  Agent-auth SSH hosts are NOT counted: they have no secret by design, so
   *  reporting them as missing one would read as a broken import. */
  withoutSecrets: number;
};

export type ImportResult = {
  ssh: ImportCounts;
  rdp: ImportCounts;
  /** Entries dropped because they could not be a working connection, across
   *  both protocols. */
  skipped: number;
};

const NO_COUNTS: ImportCounts = { added: 0, replaced: 0, withoutSecrets: 0 };

/**
 * Decrypt and merge a backup into the local stores. Merging is by connection
 * id, which is stable across renames, so re-importing the same file updates
 * rather than duplicating. Nothing is deleted: a connection that exists here
 * but not in the file is left alone.
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
    ? applyV1(parsed.connections, parsed.secrets, parsed.skipped, passphrase)
    : applyV2(parsed.payload, passphrase);
}

/**
 * v2: the host process holds the credentials while this validates the metadata.
 *
 * Order matters. The secrets are written BEFORE the store rows, because
 * `upsertConnection` recomputes each `has*` flag by asking the keychain what is
 * actually there - so a row written first would pin every flag to false and the
 * UI would claim a credential-less host that connects fine.
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
    const { connections, rdpConnections, skipped } = sanitizePayload(meta);

    const [existingSsh, existingRdp] = await Promise.all([listConnections(), listRdpConnections()]);
    const existingSshIds = new Set(existingSsh.map((c) => c.id));
    const existingRdpIds = new Set(existingRdp.map((c) => c.id));
    // A jump host or a tunnel bastion may live in the file OR already be saved
    // here; both count as resolvable, so the union is what dangling references
    // are checked against.
    const knownSsh = new Set([...existingSshIds, ...connections.map((c) => c.id)]);
    const incomingSsh = clearDanglingJumps(connections, knownSsh);
    const incomingRdp = clearDanglingTunnels(rdpConnections, knownSsh);

    const refs: SecretRef[] = [
      ...incomingSsh.flatMap((c) => sshRefs(c.id)),
      ...incomingRdp.flatMap((c) => rdpRefs(c.id)),
    ];
    const written = await invoke<boolean[]>("backup_apply_secrets", {
      handle: opened.handle,
      refs,
    });
    // Which connections got at least one credential. A short or missing array
    // is treated as "nothing written" rather than trusted by index, so a
    // protocol change cannot make this claim a credential exists.
    const gotSecret = new Set<string>();
    refs.forEach((r, i) => {
      if (written[i] === true) gotSecret.add(`${r.group}:${r.id}`);
    });

    const ssh: ImportCounts = { ...NO_COUNTS };
    for (const conn of incomingSsh) {
      if (!gotSecret.has(`secrets:${conn.id}`) && conn.authMode !== "agent") ssh.withoutSecrets++;
      // Every field undefined: the keychain rows are already in place, and
      // undefined means "leave whatever is stored alone" - which is also the
      // non-destructive choice when re-importing over a host whose credential
      // is already set up here and did not travel in the file.
      await upsertConnection(conn as SshConnection, {});
      if (existingSshIds.has(conn.id)) ssh.replaced++;
      else ssh.added++;
    }

    const rdp: ImportCounts = { ...NO_COUNTS };
    for (const conn of incomingRdp) {
      if (!gotSecret.has(`rdpSecrets:${conn.id}`)) rdp.withoutSecrets++;
      await upsertRdpConnection(conn as RdpConnection, undefined);
      if (existingRdpIds.has(conn.id)) rdp.replaced++;
      else rdp.added++;
    }

    return { ssh, rdp, skipped };
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
 */
async function applyV1(
  connections: SshConnection[],
  sealed: SealedBlob,
  skipped: number,
  passphrase: string,
): Promise<ImportResult> {
  // Decrypt BEFORE touching the store: a wrong passphrase must leave the
  // existing connections exactly as they were, not half-merged.
  const plain = await invoke<string>("backup_open", { blob: sealed, passphrase });
  let secrets: BackupSecrets;
  try {
    secrets = sanitizeSecrets(JSON.parse(plain));
  } catch {
    throw new Error("The encrypted block did not contain readable credentials.");
  }

  const existing = await listConnections();
  const existingIds = new Set(existing.map((c) => c.id));
  const known = new Set([...existingIds, ...connections.map((c) => c.id)]);
  const incoming = clearDanglingJumps(connections, known);

  const ssh: ImportCounts = { ...NO_COUNTS };
  for (const conn of incoming) {
    const s = secrets[conn.id];
    if (!s && conn.authMode !== "agent") ssh.withoutSecrets++;
    await upsertConnection(conn as SshConnection, {
      // undefined means "leave whatever is already in the keychain", which is
      // the non-destructive choice when re-importing over a host whose
      // credential is already set up here.
      password: s?.password,
      privateKey: s?.privateKey,
      keyPassphrase: s?.keyPassphrase,
    });
    if (existingIds.has(conn.id)) ssh.replaced++;
    else ssh.added++;
  }

  return { ssh, rdp: { ...NO_COUNTS }, skipped };
}
