/**
 * Shape and validation for the `.tervia-backup` connection backup.
 *
 * An import is a TRUST BOUNDARY: the file came off a USB stick or a chat, and
 * whatever survives this module is written straight into the connections store
 * and later dialled. So every field is re-checked here rather than trusted -
 * a bad port would be sent to `TcpStream::connect`, a bad `proxyJumpId` would
 * make every connect fail with "a jump host in the chain no longer exists",
 * and a non-array `forwards` would bind nothing while looking configured.
 *
 * TWO FORMATS, and the difference is where the boundary sits:
 *
 * - **v1** (`.tervia-ssh`, kind `tervia-ssh-connections`) is SSH only, and its
 *   `connections` array is PLAINTEXT beside a sealed credential block. So the
 *   whole file is validated at parse time, before anything is decrypted.
 * - **v2** (`.tervia-backup`, kind `tervia-connections`) seals everything -
 *   both inventories and every credential - in one blob, because a v1 export
 *   leaks the machine inventory in plaintext while protecting only the
 *   passwords. That moves the boundary: `parseBackupFile` can only check the
 *   ENVELOPE, and {@link sanitizePayload} does the per-connection work after
 *   the host process has decrypted. Credentials never come back to JS at all
 *   in v2 - `backup_apply_secrets` writes them to the keychain from Rust.
 *
 * Only reading v1 is supported; every export is v2. Renaming the kind and the
 * extension was free because `release.yml` has never run, so the only v1 files
 * in existence are hand-made test ones.
 *
 * Kept free of Tauri imports (both connection imports are type-only, so they
 * are erased at compile time) so `scripts/ssh-backup-verify.ts` can exercise
 * the parser under plain node.
 */
import type { RdpConnection, RdpSizeMode } from "@/modules/rdp/connections";
import type { SshConnection, SshAuthMode, SshPortForward } from "./connections";

export const BACKUP_KIND = "tervia-connections";
export const BACKUP_VERSION = 2;
export const BACKUP_EXTENSION = "tervia-backup";

/** v1: SSH only, plaintext inventory, sealed credentials. Read, never written. */
export const BACKUP_KIND_V1 = "tervia-ssh-connections";
export const BACKUP_EXTENSION_V1 = "tervia-ssh";

/**
 * Top-level keys of the sealed payload that hold credentials rather than
 * inventory. Named here and passed to `backup_open_payload` so the host process
 * knows what to withhold from the metadata it hands back.
 */
export const SECRET_GROUPS = ["secrets", "rdpSecrets"] as const;
export type BackupSecretGroup = (typeof SECRET_GROUPS)[number];

/**
 * One credential, addressed by where it lives (`service` + `account` in the
 * keychain) and where it belongs in the payload (`group`/`id`/`field`).
 *
 * The point of the indirection: an export sends these instead of values, so the
 * plaintext is read by the host process and never enters the webview. An import
 * sends the same shape back for the ids that survived validation.
 */
export type SecretRef = {
  group: BackupSecretGroup;
  id: string;
  field: string;
  service: string;
  account: string;
};

/** Encrypted payload produced by the Rust sealing commands. */
export type SealedBlob = {
  kdf: string;
  iterations: number;
  salt: string;
  nonce: string;
  ciphertext: string;
};

/** Plaintext inside a v1 `secrets` blob, keyed by connection id. */
export type BackupSecrets = Record<
  string,
  { password?: string; privateKey?: string; keyPassphrase?: string }
>;

/** The v2 file. Everything of substance is inside `payload`. */
export type BackupFileV2 = {
  kind: typeof BACKUP_KIND;
  version: typeof BACKUP_VERSION;
  exportedAt: number;
  payload: SealedBlob;
};

/**
 * What `parseBackupFile` could establish without a passphrase. The version is
 * the discriminant because the two generations need different import paths, not
 * because the caller should care about the format.
 */
export type ParsedBackup =
  | { version: 1; connections: SshConnection[]; secrets: SealedBlob; skipped: number }
  | { version: 2; payload: SealedBlob };

/**
 * Fallback desktop size for a row whose own is unusable. Mirrors
 * `RDP_DEFAULT_PRESET` in `@/modules/rdp/connections`, duplicated rather than
 * imported because that module pulls in the Tauri plugin store and this one has
 * to stay loadable under plain node.
 */
const RDP_FALLBACK_WIDTH = 1600;
const RDP_FALLBACK_HEIGHT = 900;

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

const str = (v: unknown): string => (typeof v === "string" ? v : "");

/** A port is only usable if it is a whole number in range; 0 is not valid to dial. */
function port(v: unknown): number | null {
  return typeof v === "number" && Number.isInteger(v) && v >= 1 && v <= 65535 ? v : null;
}

function sanitizeForwards(v: unknown): SshPortForward[] | undefined {
  if (!Array.isArray(v)) return undefined;
  const out: SshPortForward[] = [];
  for (const raw of v) {
    if (!isRecord(raw)) continue;
    // A local port of 0 is meaningful here (bind an ephemeral port), unlike a
    // remote port, so it is allowed through as its own case.
    const localRaw = raw.localPort;
    const local =
      typeof localRaw === "number" &&
      Number.isInteger(localRaw) &&
      localRaw >= 0 &&
      localRaw <= 65535
        ? localRaw
        : null;
    const remotePort = port(raw.remotePort);
    const remoteHost = str(raw.remoteHost).trim();
    if (local === null || remotePort === null || !remoteHost) continue;
    out.push({ localPort: local, remoteHost, remotePort });
  }
  return out.length > 0 ? out : undefined;
}

/**
 * Validate one record. Returns null when the entry could not be a working
 * connection, so the caller can skip it and report the count instead of
 * importing something that fails at dial time.
 */
export function sanitizeConnection(raw: unknown): SshConnection | null {
  if (!isRecord(raw)) return null;
  const id = str(raw.id).trim();
  const host = str(raw.host).trim();
  const p = port(raw.port);
  if (!id || !host || p === null) return null;

  const authMode: SshAuthMode =
    raw.authMode === "key" || raw.authMode === "agent" ? raw.authMode : "password";
  const description = str(raw.description).trim();
  const proxyJumpId = str(raw.proxyJumpId).trim();
  const lastFingerprint = str(raw.lastFingerprint).trim();
  const lastConnectedAt = raw.lastConnectedAt;
  const forwards = sanitizeForwards(raw.forwards);

  return {
    id,
    // A blank name would render an unclickable row, so fall back to the host.
    name: str(raw.name).trim() || host,
    host,
    port: p,
    user: str(raw.user).trim(),
    authMode,
    // Recomputed by upsertConnection from what actually lands in the keychain;
    // never trusted from the file, or the UI pips would lie.
    hasPassword: false,
    hasPrivateKey: false,
    hasKeyPassphrase: false,
    ...(description ? { description } : {}),
    ...(typeof lastConnectedAt === "number" && Number.isFinite(lastConnectedAt)
      ? { lastConnectedAt }
      : {}),
    // Kept deliberately: it is the pinned host key. Carrying it over means the
    // new machine keeps the same TOFU anchor instead of blindly accepting
    // whatever answers on the first connect.
    ...(lastFingerprint ? { lastFingerprint } : {}),
    ...(proxyJumpId ? { proxyJumpId } : {}),
    ...(forwards ? { forwards } : {}),
  };
}

/** A desktop dimension, or null when it is not a size a canvas could hold. */
function dimension(v: unknown): number | null {
  return typeof v === "number" && Number.isInteger(v) && v >= 320 && v <= 16384 ? v : null;
}

/**
 * Validate one RDP record. Same contract as {@link sanitizeConnection}: null
 * means the entry could not be a working connection.
 *
 * Unlike the SSH side, a bad desktop size does NOT drop the row. It is the one
 * field a later build could legitimately widen (RDP-03 adds `"fit"`), and a
 * host is still perfectly dialable at a different resolution - so an unusable
 * size falls back instead of costing the user the connection.
 */
export function sanitizeRdpConnection(raw: unknown): RdpConnection | null {
  if (!isRecord(raw)) return null;
  const id = str(raw.id).trim();
  const host = str(raw.host).trim();
  const p = port(raw.port);
  if (!id || !host || p === null) return null;

  const domain = str(raw.domain).trim();
  const description = str(raw.description).trim();
  const certFingerprint = str(raw.certFingerprint).trim();
  const lastConnectedAt = raw.lastConnectedAt;
  const tunnelId = isRecord(raw.tunnel) ? str(raw.tunnel.sshConnectionId).trim() : "";
  // Only one member today, so anything else - including a mode a later build
  // writes - resolves to the mode this build can actually render.
  const sizeMode: RdpSizeMode = "preset";

  return {
    id,
    name: str(raw.name).trim() || host,
    host,
    port: p,
    username: str(raw.username).trim(),
    desktopWidth: dimension(raw.desktopWidth) ?? RDP_FALLBACK_WIDTH,
    desktopHeight: dimension(raw.desktopHeight) ?? RDP_FALLBACK_HEIGHT,
    sizeMode,
    // Recomputed from the keychain by upsertConnection, like the SSH flags.
    hasPassword: false,
    ...(domain ? { domain } : {}),
    ...(description ? { description } : {}),
    ...(typeof lastConnectedAt === "number" && Number.isFinite(lastConnectedAt)
      ? { lastConnectedAt }
      : {}),
    // The pinned certificate, carried for the same reason as SSH's host key:
    // the new machine keeps the TOFU anchor instead of accepting whatever
    // answers first.
    ...(certFingerprint ? { certFingerprint } : {}),
    ...(tunnelId ? { tunnel: { sshConnectionId: tunnelId } } : {}),
  };
}

function sanitizeSealed(raw: unknown): SealedBlob | null {
  if (!isRecord(raw)) return null;
  const kdf = str(raw.kdf);
  const salt = str(raw.salt);
  const nonce = str(raw.nonce);
  const ciphertext = str(raw.ciphertext);
  const iterations = raw.iterations;
  if (!kdf || !salt || !nonce || !ciphertext) return null;
  if (typeof iterations !== "number" || !Number.isInteger(iterations) || iterations < 1)
    return null;
  return { kdf, iterations, salt, nonce, ciphertext };
}

/**
 * Drop `proxyJumpId` references that point at nothing. `known` is every id that
 * will exist after the import (the file's own ids plus what is already saved).
 * A dangling jump id is not cosmetic: `resolveJumpHops` throws on it, so every
 * connect through that host would fail with a message about a host the user
 * never knowingly deleted.
 */
export function clearDanglingJumps(list: SshConnection[], known: Set<string>): SshConnection[] {
  return list.map((c) =>
    c.proxyJumpId && !known.has(c.proxyJumpId) ? { ...c, proxyJumpId: undefined } : c,
  );
}

/**
 * The RDP counterpart: drop a `tunnel` whose SSH connection did not come along.
 * `knownSsh` is every SSH id that will exist after the import.
 *
 * Same failure as a dangling jump, one protocol over - a tunnelled RDP row
 * whose bastion is missing cannot resolve a local port, so every connect fails
 * on a host the user never touched. Dropping the tunnel leaves a row that
 * dials `host:port` directly, which is at least a connection the user can see
 * and fix.
 */
export function clearDanglingTunnels(
  list: RdpConnection[],
  knownSsh: Set<string>,
): RdpConnection[] {
  return list.map((c) =>
    c.tunnel && !knownSsh.has(c.tunnel.sshConnectionId) ? { ...c, tunnel: undefined } : c,
  );
}

const NOT_A_BACKUP = "Not a Tervia connection backup file.";

/**
 * Parse and validate a backup file's envelope. Throws with a user-facing
 * message when the file is not a Tervia backup at all.
 *
 * For v1 this also validates every connection, because they are in the clear;
 * bad entries are skipped and counted rather than failing the whole import. For
 * v2 there is nothing else here to check until the payload is decrypted - see
 * {@link sanitizePayload}.
 */
export function parseBackupFile(raw: unknown): ParsedBackup {
  if (!isRecord(raw)) throw new Error(NOT_A_BACKUP);
  if (raw.kind !== BACKUP_KIND && raw.kind !== BACKUP_KIND_V1) throw new Error(NOT_A_BACKUP);
  const version = raw.version;
  if (typeof version !== "number" || !Number.isInteger(version) || version < 1) {
    throw new Error("Backup file has no usable version.");
  }
  if (version > BACKUP_VERSION) {
    throw new Error(
      `This backup was written by a newer Tervia (format v${version}); this build reads up to v${BACKUP_VERSION}.`,
    );
  }
  // The kind and the version have to agree. A file claiming v2 under the old
  // kind (or the reverse) is hand-edited or half-converted, and guessing which
  // half to believe would mean reading a plaintext inventory as a sealed one.
  const expectedKind = version === 1 ? BACKUP_KIND_V1 : BACKUP_KIND;
  if (raw.kind !== expectedKind) {
    throw new Error(`Backup file says format v${version} but is not a ${expectedKind} file.`);
  }

  if (version >= 2) {
    const payload = sanitizeSealed(raw.payload);
    if (!payload) throw new Error("Backup file is missing its encrypted payload.");
    return { version: 2, payload };
  }

  if (!Array.isArray(raw.connections)) throw new Error("Backup file has no connections list.");
  const secrets = sanitizeSealed(raw.secrets);
  if (!secrets) throw new Error("Backup file is missing its encrypted credentials block.");

  const connections: SshConnection[] = [];
  const seen = new Set<string>();
  let skipped = 0;
  for (const entry of raw.connections) {
    const conn = sanitizeConnection(entry);
    // A duplicate id would import twice and the second would silently win.
    if (!conn || seen.has(conn.id)) {
      skipped++;
      continue;
    }
    seen.add(conn.id);
    connections.push(conn);
  }

  return { version: 1, connections, secrets, skipped };
}

/**
 * Validate the decrypted v2 payload: both inventories, bad entries skipped and
 * counted. This is the v2 half of the trust boundary, and it runs on the same
 * data `parseBackupFile` checks for a v1 file - just after decryption instead of
 * before it.
 *
 * A missing inventory is not an error: a payload sealed by a build without one
 * of the two protocols is a legitimate file, so the absent list imports as
 * empty rather than failing.
 */
export function sanitizePayload(raw: unknown): {
  connections: SshConnection[];
  rdpConnections: RdpConnection[];
  skipped: number;
} {
  if (!isRecord(raw)) throw new Error("The encrypted payload did not contain any connections.");

  let skipped = 0;
  const connections: SshConnection[] = [];
  const rdpConnections: RdpConnection[] = [];

  if (raw.connections !== undefined && !Array.isArray(raw.connections)) {
    throw new Error("The encrypted payload's SSH connections are not a list.");
  }
  if (raw.rdpConnections !== undefined && !Array.isArray(raw.rdpConnections)) {
    throw new Error("The encrypted payload's RDP connections are not a list.");
  }

  const seenSsh = new Set<string>();
  for (const entry of Array.isArray(raw.connections) ? raw.connections : []) {
    const conn = sanitizeConnection(entry);
    if (!conn || seenSsh.has(conn.id)) {
      skipped++;
      continue;
    }
    seenSsh.add(conn.id);
    connections.push(conn);
  }

  // Ids are tracked per protocol, not globally: the two stores and the two
  // keychain services are separate, so an SSH row and an RDP row sharing an id
  // is odd but harmless, and rejecting one of them would lose a host.
  const seenRdp = new Set<string>();
  for (const entry of Array.isArray(raw.rdpConnections) ? raw.rdpConnections : []) {
    const conn = sanitizeRdpConnection(entry);
    if (!conn || seenRdp.has(conn.id)) {
      skipped++;
      continue;
    }
    seenRdp.add(conn.id);
    rdpConnections.push(conn);
  }

  return { connections, rdpConnections, skipped };
}

/**
 * Validate a decrypted **v1** secrets payload before any of it reaches the
 * keychain. v2 has no equivalent on this side: its credentials go from the
 * sealed blob to the keychain without JS ever holding them.
 */
export function sanitizeSecrets(raw: unknown): BackupSecrets {
  if (!isRecord(raw)) return {};
  const out: BackupSecrets = {};
  for (const [id, v] of Object.entries(raw)) {
    if (!isRecord(v)) continue;
    const entry: BackupSecrets[string] = {};
    if (typeof v.password === "string" && v.password) entry.password = v.password;
    if (typeof v.privateKey === "string" && v.privateKey) entry.privateKey = v.privateKey;
    if (typeof v.keyPassphrase === "string" && v.keyPassphrase) {
      entry.keyPassphrase = v.keyPassphrase;
    }
    if (Object.keys(entry).length > 0) out[id] = entry;
  }
  return out;
}
