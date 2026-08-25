/**
 * Shape and validation for the `.tervia-backup` connection backup.
 *
 * An import is a TRUST BOUNDARY: the file came off a USB stick or a chat, and
 * whatever survives this module is written straight into the host store and
 * later dialled. So every field is re-checked here rather than trusted - a bad
 * port would be sent to `TcpStream::connect`, a bad `proxyJumpId` would make
 * every connect fail with "a jump host in the chain no longer exists", and an
 * inline binding naming another host would authenticate with THAT host's
 * secrets.
 *
 * TWO FORMATS, and the difference is where the boundary sits:
 *
 * - **v1** (`.tervia-ssh`, kind `tervia-ssh-connections`) is SSH only, and its
 *   `connections` array is PLAINTEXT beside a sealed credential block. So the
 *   whole file is validated at parse time, before anything is decrypted.
 * - **v2** (`.tervia-backup`, kind `tervia-connections`) seals everything -
 *   the inventory and every credential - in one blob, because a v1 export
 *   leaks the machine inventory in plaintext while protecting only the
 *   passwords. That moves the boundary: `parseBackupFile` can only check the
 *   ENVELOPE, and {@link sanitizePayload} does the per-host work after the host
 *   process has decrypted. Credentials never come back to JS at all in v2 -
 *   `backup_apply_secrets` writes them to the keychain from Rust.
 *
 * Only reading v1 is supported; every export is v2.
 *
 * Kept free of the Tauri runtime so `scripts/ssh-backup-verify.ts` can exercise
 * the parser under plain node. `@/modules/hosts/types` and
 * `@/modules/vault/types` are both plain TypeScript with no IPC of their own,
 * which is why the one value import below is safe; anything reaching a store or
 * an `invoke` belongs in `backup.ts` instead.
 */
import {
  RDP_DEFAULT_PRESET,
  type Host,
  type HostBase,
  type HostGroup,
  type RdpHost,
  type RdpSizeMode,
  type SshHost,
} from "@/modules/hosts/types";
import type {
  RdpCredentialBinding,
  SshCredentialBinding,
  VaultAuthMode,
} from "@/modules/vault/types";

export const BACKUP_KIND = "tervia-connections";

/**
 * The format version - deliberately UNCHANGED while the payload shape beneath it
 * changed completely.
 *
 * The shape changed under the same number ON PURPOSE. No installed build of this
 * app exists, `release.yml` has never run on this repository and there is no
 * tag, so the only v2 files in existence are hand-made test ones and a payload
 * shape moving under a fixed number costs nothing today. Bumping to v3 here
 * would drag in the rest of 6g with it - the five-collection payload that also
 * carries identities, keys and forward rules, the dropped v1/v2 read path, and
 * with it the deletion of the last route where plaintext credentials reach JS.
 * 6g bumps this.
 */
export const BACKUP_VERSION = 2;
export const BACKUP_EXTENSION = "tervia-backup";

/** v1: SSH only, plaintext inventory, sealed credentials. Read, never written. */
export const BACKUP_KIND_V1 = "tervia-ssh-connections";
export const BACKUP_EXTENSION_V1 = "tervia-ssh";

/**
 * The one top-level payload key that holds credentials rather than inventory.
 *
 * ONE group now, where there were two. The two old stores had a keychain service
 * each (`tervia-ssh`, `tervia-rdp`) and an id space each, so a credential needed
 * the protocol to address it; one host store on one service (`tervia-hosts`)
 * with one id space does not.
 *
 * It must not collide with a payload key that carries inventory - `merge_secrets`
 * in `modules/backup.rs` refuses to write into a group the payload already
 * carries, precisely so a typo cannot replace the host list with a credential
 * map. `hostSecrets` is neither `hosts` nor `groups`.
 */
export const HOST_SECRET_GROUP = "hostSecrets";

/** Named here and passed to `backup_open_payload` so the host process knows what
 *  to withhold from the metadata it hands back. */
export const SECRET_GROUPS = [HOST_SECRET_GROUP] as const;
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
  | { version: 1; hosts: SshHost[]; secrets: SealedBlob; skipped: number }
  | { version: 2; payload: SealedBlob };

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

const str = (v: unknown): string => (typeof v === "string" ? v : "");

/** A port is only usable if it is a whole number in range; 0 is not valid to dial. */
function port(v: unknown): number | null {
  return typeof v === "number" && Number.isInteger(v) && v >= 1 && v <= 65535 ? v : null;
}

/** A desktop dimension, or null when it is not a size a canvas could hold. */
function dimension(v: unknown): number | null {
  return typeof v === "number" && Number.isInteger(v) && v >= 320 && v <= 16384 ? v : null;
}

/** An unknown mode - including one a later build writes - resolves to the mode
 *  every code path here can handle. */
function authMode(v: unknown): VaultAuthMode {
  return v === "key" || v === "agent" ? v : "password";
}

/**
 * The fields both protocols share, or null when the row could not be a working
 * host at all.
 */
function baseOf(raw: Record<string, unknown>): HostBase | null {
  const id = str(raw.id).trim();
  const host = str(raw.host).trim();
  const p = port(raw.port);
  if (!id || !host || p === null) return null;

  const groupId = str(raw.groupId).trim();
  const description = str(raw.description).trim();
  const lastConnectedAt = raw.lastConnectedAt;

  return {
    id,
    // A blank name would render an unclickable row, so fall back to the host.
    name: str(raw.name).trim() || host,
    host,
    port: p,
    // A group that did not travel leaves the host rendering as ungrouped, which
    // is visible and fixable, so the id rides along unchecked - the same call
    // the store makes on every write. `mergeGroups` is what repoints it when the
    // group exists here under a different id.
    ...(groupId ? { groupId } : {}),
    ...(description ? { description } : {}),
    ...(typeof lastConnectedAt === "number" && Number.isFinite(lastConnectedAt)
      ? { lastConnectedAt }
      : {}),
  };
}

/**
 * One host's credential binding.
 *
 * `hostId` is FORCED to the row's own id and never read from the file, and that
 * is not tidiness. `assertBindingOwner` refuses a mismatch, so a file whose
 * binding named another host would abort the whole import; and if it did not,
 * the imported host would resolve THAT host's keychain accounts - rotating one
 * password would change the other, with no error anywhere.
 *
 * An unreadable binding falls back to inline with a blank user rather than
 * dropping the row. That is what the old stores did with a blank `user` field,
 * and a host you can see and fix beats one that vanished without explanation.
 */
function sshBinding(raw: unknown, hostId: string): SshCredentialBinding {
  if (isRecord(raw) && raw.kind === "identity") {
    const identityId = str(raw.identityId).trim();
    if (identityId) return { kind: "identity", identityId };
  }
  const inline = isRecord(raw) ? raw : {};
  return {
    kind: "inline",
    hostId,
    user: str(inline.user).trim(),
    authMode: authMode(inline.authMode),
    // Never trusted from the file: a presence flag is a claim about THIS
    // machine's keychain, and the file is describing another one.
    hasPassword: false,
    hasPrivateKey: false,
    hasKeyPassphrase: false,
  };
}

/** The RDP half. Same contract, same forced `hostId`. */
function rdpBinding(raw: unknown, hostId: string): RdpCredentialBinding {
  if (isRecord(raw) && raw.kind === "identity") {
    const identityId = str(raw.identityId).trim();
    if (identityId) return { kind: "identity", identityId };
  }
  const inline = isRecord(raw) ? raw : {};
  const domain = str(inline.domain).trim();
  return {
    kind: "inline",
    hostId,
    username: str(inline.username).trim(),
    ...(domain ? { domain } : {}),
    hasPassword: false,
  };
}

function sshArm(base: HostBase, raw: Record<string, unknown>): SshHost {
  const proxyJumpId = str(raw.proxyJumpId).trim();
  const lastFingerprint = str(raw.lastFingerprint).trim();
  return {
    ...base,
    protocol: "ssh",
    credential: sshBinding(raw.credential, base.id),
    // Kept deliberately: it is the pinned host key. Carrying it over means the
    // new machine keeps the same TOFU anchor instead of blindly accepting
    // whatever answers on the first connect.
    ...(lastFingerprint ? { lastFingerprint } : {}),
    ...(proxyJumpId ? { proxyJumpId } : {}),
  };
}

function rdpArm(base: HostBase, raw: Record<string, unknown>): RdpHost {
  const certFingerprint = str(raw.certFingerprint).trim();
  const sshHostId = isRecord(raw.tunnel) ? str(raw.tunnel.sshHostId).trim() : "";
  // Only one member today, so anything else - including a mode a later build
  // writes - resolves to the mode this build can actually render.
  const sizeMode: RdpSizeMode = "preset";

  return {
    ...base,
    protocol: "rdp",
    credential: rdpBinding(raw.credential, base.id),
    // Unlike every other field, a bad desktop size does NOT drop the row. It is
    // the one field a later build could legitimately widen (RDP-08 adds
    // `"fit"`), and a host is still perfectly dialable at a different
    // resolution - so an unusable size falls back instead of costing the user
    // the connection.
    desktopWidth: dimension(raw.desktopWidth) ?? RDP_DEFAULT_PRESET.width,
    desktopHeight: dimension(raw.desktopHeight) ?? RDP_DEFAULT_PRESET.height,
    sizeMode,
    // The pinned certificate, carried for the same reason as SSH's host key:
    // the new machine keeps the TOFU anchor instead of accepting whatever
    // answers first.
    ...(certFingerprint ? { certFingerprint } : {}),
    ...(sshHostId ? { tunnel: { sshHostId } } : {}),
  };
}

/**
 * Validate one host record. Returns null when the entry could not be a working
 * host, so the caller can skip it and report the count instead of importing
 * something that fails at dial time.
 */
export function sanitizeHost(raw: unknown): Host | null {
  if (!isRecord(raw)) return null;
  const base = baseOf(raw);
  if (!base) return null;
  // No default protocol, and no guessing. An RDP row read as SSH would offer an
  // SSH handshake to port 3389, and a row naming neither cannot be dialled
  // either way - so it is skipped and counted, like any other unusable entry.
  if (raw.protocol === "ssh") return sshArm(base, raw);
  if (raw.protocol === "rdp") return rdpArm(base, raw);
  return null;
}

/**
 * Validate one group. Null when it could not be a pickable label: `upsertGroup`
 * refuses a blank name, because a group is chosen by name from a dropdown.
 */
export function sanitizeGroup(raw: unknown): HostGroup | null {
  if (!isRecord(raw)) return null;
  const id = str(raw.id).trim();
  const name = str(raw.name).trim();
  if (!id || !name) return null;
  const order = raw.order;
  return {
    id,
    name,
    ...(typeof order === "number" && Number.isFinite(order) ? { order } : {}),
  };
}

/**
 * Validate one record from a **v1** file, whose rows are the old SSH-only shape:
 * `user` and `authMode` at the top level, no `protocol`, no `credential`.
 *
 * The result is an ordinary {@link SshHost} with an inline binding, so a v1
 * import walks exactly the same write path as a v2 one. One v1 field cannot
 * survive: `forwards`, because a forward rule is its own record now (decision 7)
 * and the store has nowhere to put one. 6g drops this read path entirely.
 */
export function sanitizeLegacyHost(raw: unknown): SshHost | null {
  if (!isRecord(raw)) return null;
  const base = baseOf(raw);
  if (!base) return null;
  const proxyJumpId = str(raw.proxyJumpId).trim();
  const lastFingerprint = str(raw.lastFingerprint).trim();
  return {
    ...base,
    protocol: "ssh",
    credential: {
      kind: "inline",
      hostId: base.id,
      user: str(raw.user).trim(),
      authMode: authMode(raw.authMode),
      hasPassword: false,
      hasPrivateKey: false,
      hasKeyPassphrase: false,
    },
    ...(lastFingerprint ? { lastFingerprint } : {}),
    ...(proxyJumpId ? { proxyJumpId } : {}),
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
 * Hard cap on a jump chain, mirroring `MAX_JUMP_HOPS` in
 * `@/modules/hosts/jumps`. Duplicated rather than imported for the reason the
 * module header gives - that file reaches the vault resolver and the Tauri
 * runtime with it - and the two numbers have to agree, because a longer chain is
 * REFUSED by the store rather than truncated.
 */
const MAX_JUMP_CHAIN = 16;

/** Every host that will exist after the import, the file's version winning over
 *  the saved one. */
function hostIndex(incoming: Host[], existing: Host[]): Map<string, Host> {
  const byId = new Map(existing.map((h) => [h.id, h]));
  for (const host of incoming) byId.set(host.id, host);
  return byId;
}

/** The id a host reaches another host through, whichever field its protocol
 *  keeps it in. */
function referenceOf(host: Host): string | undefined {
  return host.protocol === "ssh" ? host.proxyJumpId : host.tunnel?.sshHostId;
}

/**
 * Whether `upsertHost` would ACCEPT this reference: every hop is a saved SSH
 * host, the walk never returns to `selfId`, and the chain is within the cap.
 *
 * It mirrors four refusals that live in `hosts/jumps.ts` and `hosts/store.ts` -
 * a missing hop, a hop that is not an SSH host, a cycle (including a host naming
 * itself), an over-long chain. All four THROW there, which is what makes
 * clearing them here load-bearing: an import that hands one over does not save a
 * row with a dangling reference, it aborts and leaves the rest of the file
 * unimported.
 */
function chainResolves(selfId: string, startId: string, byId: Map<string, Host>): boolean {
  const visited = new Set<string>([selfId]);
  let cursor: string | undefined = startId;
  let hops = 0;
  while (cursor) {
    if (visited.has(cursor)) return false;
    visited.add(cursor);
    const hop = byId.get(cursor);
    if (!hop || hop.protocol !== "ssh") return false;
    if (++hops > MAX_JUMP_CHAIN) return false;
    cursor = hop.proxyJumpId;
  }
  return true;
}

/**
 * The ids on one chain from `startId`, stopping at the first id that is not
 * there. Says nothing about whether the chain is usable - {@link chainResolves}
 * answers that.
 */
function chainOf(startId: string, byId: Map<string, Host>): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  let cursor: string | undefined = startId;
  while (cursor && !seen.has(cursor) && out.length <= MAX_JUMP_CHAIN) {
    seen.add(cursor);
    out.push(cursor);
    const hop = byId.get(cursor);
    cursor = hop ? referenceOf(hop) : undefined;
  }
  return out;
}

/**
 * Drop every `proxyJumpId` the host store would refuse. `existing` is what is
 * already saved here, because a jump host may live in the file OR on this
 * machine and both count as resolvable.
 *
 * A dangling jump id is not cosmetic and never was: it used to save and then
 * fail every connect through that host with a message about a host the user
 * never knowingly deleted. It now fails the WRITE, which is worse for an import
 * - one bad row abandons the rest of the file.
 *
 * Three refusals are new here because one merged store can express what two
 * separate ones could not: a jump host that is an RDP row, a host that names
 * ITSELF, and a cycle. A cycle clears the reference on every member rather than
 * picking a survivor - there is no principled winner, and keeping one would mean
 * this pass decided which of two hosts the user meant.
 */
export function clearDanglingJumps(incoming: Host[], existing: Host[]): Host[] {
  const byId = hostIndex(incoming, existing);
  return incoming.map((h) =>
    h.protocol === "ssh" && h.proxyJumpId && !chainResolves(h.id, h.proxyJumpId, byId)
      ? { ...h, proxyJumpId: undefined }
      : h,
  );
}

/**
 * The RDP counterpart: drop a `tunnel` whose SSH host the store would refuse.
 *
 * Same failure one protocol over - a tunnelled RDP row whose bastion is missing
 * cannot resolve a local port. Dropping the tunnel leaves a row that dials
 * `host:port` directly, which is at least a connection the user can see and fix.
 *
 * The bastion's OWN jump chain is walked too, not just the bastion: it is
 * resolved on the same connect, so the store applies the same check.
 */
export function clearDanglingTunnels(incoming: Host[], existing: Host[]): Host[] {
  const byId = hostIndex(incoming, existing);
  return incoming.map((h) =>
    h.protocol === "rdp" && h.tunnel && !chainResolves(h.id, h.tunnel.sshHostId, byId)
      ? { ...h, tunnel: undefined }
      : h,
  );
}

/**
 * The order the hosts have to be WRITTEN in: everything on a host's chain before
 * the host that reaches through it.
 *
 * Not cosmetic either. `upsertHost` re-walks the whole chain on every write and
 * judges it against WHAT IS ALREADY ON DISK, so writing a host before its
 * bastion throws. The two old stores had no reference guard at all, which is why
 * file order was good enough before and is not now.
 *
 * Run AFTER both clearing passes: this assumes every remaining reference
 * resolves and no chain loops. The `walking` guard is belt-and-braces, so a
 * cycle that somehow survived yields a bad order rather than a hang.
 */
export function orderHostWrites(incoming: Host[], existing: Host[]): Host[] {
  const byId = hostIndex(incoming, existing);
  const pending = new Map(incoming.map((h) => [h.id, h]));
  const emitted = new Set<string>();
  const walking = new Set<string>();
  const out: Host[] = [];

  const visit = (id: string): void => {
    const host = pending.get(id);
    if (!host || emitted.has(id) || walking.has(id)) return;
    walking.add(id);
    const reference = referenceOf(host);
    // The WHOLE chain, not only the first hop: a host three hops out that is
    // still unwritten fails the walk even when the direct target is on disk.
    if (reference) for (const hop of chainOf(reference, byId)) visit(hop);
    walking.delete(id);
    emitted.add(id);
    out.push(host);
  };

  for (const host of incoming) visit(host.id);
  return out;
}

/**
 * Merge the file's groups into the saved ones, and repoint the incoming hosts at
 * whatever group they end up in.
 *
 * Merging is by id, like hosts. The wrinkle is that a group also has to have a
 * UNIQUE NAME: `upsertGroup` refuses a second "prod", so a file whose "prod"
 * carries a different id than the local one would abort the import over a label.
 * A name already taken therefore RESOLVES to the group holding it, and the hosts
 * that named the incoming group are repointed. That is the merge the uniqueness
 * rule implies - two groups cannot share a name, so "prod" IS the group.
 *
 * The same pass covers two incoming groups colliding with each OTHER, which
 * would throw on the second write for the same reason.
 *
 * Returned together because applying one half without the other is the bug: a
 * repoint nobody applies leaves the host naming a group that was never written.
 */
export function mergeGroups(
  incoming: HostGroup[],
  existing: HostGroup[],
  hosts: Host[],
): { groups: HostGroup[]; hosts: Host[] } {
  // The store's own comparison, so `" prod"` and `"PROD"` are the collision they
  // look like. Duplicated because that helper is private to `hosts/store.ts`.
  const key = (name: string): string => name.trim().toLowerCase();
  const owner = new Map(existing.map((g) => [key(g.name), g.id]));
  const groups: HostGroup[] = [];
  const remap = new Map<string, string>();

  for (const group of incoming) {
    const held = owner.get(key(group.name));
    if (held !== undefined && held !== group.id) {
      remap.set(group.id, held);
      continue;
    }
    owner.set(key(group.name), group.id);
    groups.push(group);
  }

  if (remap.size === 0) return { groups, hosts };
  return {
    groups,
    hosts: hosts.map((h) => {
      const to = h.groupId ? remap.get(h.groupId) : undefined;
      return to ? { ...h, groupId: to } : h;
    }),
  };
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

  const hosts: SshHost[] = [];
  const seen = new Set<string>();
  let skipped = 0;
  for (const entry of raw.connections) {
    const host = sanitizeLegacyHost(entry);
    // A duplicate id would import twice and the second would silently win.
    if (!host || seen.has(host.id)) {
      skipped++;
      continue;
    }
    seen.add(host.id);
    hosts.push(host);
  }

  return { version: 1, hosts, secrets, skipped };
}

/**
 * Validate the decrypted v2 payload: the hosts and their groups, bad entries
 * skipped and counted. This is the v2 half of the trust boundary, and it runs on
 * the same data `parseBackupFile` checks for a v1 file - just after decryption
 * instead of before it.
 *
 * A missing collection is not an error: a payload sealed by a build without one
 * of them is a legitimate file, so the absent list imports as empty rather than
 * failing.
 */
export function sanitizePayload(raw: unknown): {
  hosts: Host[];
  groups: HostGroup[];
  skipped: number;
} {
  if (!isRecord(raw)) throw new Error("The encrypted payload did not contain any connections.");

  if (raw.hosts !== undefined && !Array.isArray(raw.hosts)) {
    throw new Error("The encrypted payload's hosts are not a list.");
  }
  if (raw.groups !== undefined && !Array.isArray(raw.groups)) {
    throw new Error("The encrypted payload's host groups are not a list.");
  }

  let skipped = 0;

  // Ids are ONE namespace now, across both protocols: one store, one keychain
  // service, so two rows sharing an id are the same accounts and the same record
  // slot. The two old stores could keep a `c-1` and an `r-1` apart; this dedupe
  // is what stops the second row silently overwriting the first.
  const hosts: Host[] = [];
  const seenHosts = new Set<string>();
  for (const entry of Array.isArray(raw.hosts) ? raw.hosts : []) {
    const host = sanitizeHost(entry);
    if (!host || seenHosts.has(host.id)) {
      skipped++;
      continue;
    }
    seenHosts.add(host.id);
    hosts.push(host);
  }

  const groups: HostGroup[] = [];
  const seenGroups = new Set<string>();
  for (const entry of Array.isArray(raw.groups) ? raw.groups : []) {
    const group = sanitizeGroup(entry);
    if (!group || seenGroups.has(group.id)) {
      skipped++;
      continue;
    }
    seenGroups.add(group.id);
    groups.push(group);
  }

  return { hosts, groups, skipped };
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
