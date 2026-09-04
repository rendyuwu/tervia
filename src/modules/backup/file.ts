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
 * Two of the checks are DESTRUCTIVE when they are missing rather than merely
 * wrong, because `upsertHost` releases every keychain account the new record can
 * no longer NAME: a row that arrives bound to a vault identity names none, and a
 * row that arrives on the other protocol names fewer. Landing either one over a
 * saved host deletes that host's secrets with nothing copied anywhere first, and
 * there is no `secrets_list` to find what is left (§9.7). See
 * {@link resolveIdentityBindings} and {@link refuseProtocolConflicts}.
 *
 * ONE FORMAT IS READ, and where the boundary sits follows from it.
 *
 * **v3** (`.tervia-backup`, kind `tervia-connections`) seals everything - the
 * inventory and every credential - in one blob, so `parseBackupFile` can check
 * only the ENVELOPE and {@link sanitizePayload} does the per-record work after
 * the host process has decrypted. Credentials never come back to JS at all:
 * `backup_apply_secrets` writes them to the keychain from Rust.
 *
 * v1 (`.tervia-ssh`, kind `tervia-ssh-connections`) and v2 are REFUSED, each by
 * a message that names the format it is refusing. There is no converter, so
 * that message is the only thing left to tell the user what they are holding -
 * and "not a Tervia backup" would be a lie about a file this app wrote.
 *
 * Kept free of the Tauri runtime so `scripts/backup-verify.ts` can exercise the
 * parser under plain node. That constraint matters more now: the value imports
 * below (`RDP_DEFAULT_PRESET`, `hostPins`) come from `@/modules/hosts/types`,
 * alongside type-only imports from `@/modules/vault/types` - both plain
 * TypeScript with no IPC of their own, which is why those imports are safe;
 * anything reaching a store or an `invoke` belongs in `apply.ts` instead.
 */
import {
  RDP_DEFAULT_PRESET,
  hostPins,
  type Host,
  type HostBase,
  type HostGroup,
  type HostPins,
  type RdpHost,
  type RdpSizeMode,
  type SshHost,
} from "@/modules/hosts/types";
import type {
  RdpCredentialBinding,
  SshCredentialBinding,
  VaultAuthMode,
  VaultIdentityBinding,
} from "@/modules/vault/types";

export const BACKUP_KIND = "tervia-connections";

/**
 * The format version. v3 is the only one this build reads, and the only one it
 * writes; {@link parseBackupFile} refuses v1 and v2 by name.
 *
 * The number is what the two refusals turn on, so it is the whole compatibility
 * story in one place: a file numbered below this one cannot be read at all,
 * because nothing converts a payload shape into this one.
 */
export const BACKUP_VERSION = 3;
export const BACKUP_EXTENSION = "tervia-backup";

/**
 * The v1 envelope's kind and extension. Neither is read for its contents any
 * more; both survive so the v1 refusal can NAME the shape it is refusing -
 * {@link parseBackupFile} matches the kind to reach that message instead of the
 * generic "not a Tervia backup", and the open dialog keeps offering the
 * extension so a `.tervia-ssh` file can be picked and told what it is rather
 * than being filtered out of the picker with no explanation.
 */
export const BACKUP_KIND_V1 = "tervia-ssh-connections";
export const BACKUP_EXTENSION_V1 = "tervia-ssh";

/**
 * The three top-level payload keys that hold credentials rather than inventory -
 * one per record kind that owns a secret. A host owns its inline credential, an
 * identity owns its password, a key owns its body and its passphrase.
 *
 * NONE of the three may collide with a payload key that carries inventory:
 * `hosts`, `groups`, `identities`, `keys`, `rules`. `merge_secrets` in
 * `modules/backup.rs` refuses to write into a group the payload already carries,
 * and it checks EVERY reference's group before inserting any, so a colliding
 * name fails the whole seal rather than replacing an inventory list with a
 * credential map partway through.
 *
 * Split by kind rather than pooled under one name, because a secret is addressed
 * `group`/`id`/`field` and the three kinds draw their ids from three separate
 * collections. Pooled, an id out of an untrusted file would say nothing about
 * which record it belongs to, and a key's body could be read back for an
 * identity that happened to share its id.
 *
 * One group for hosts and not two, which is the opposite move for the opposite
 * reason: the two old stores had a keychain service each (`tervia-ssh`,
 * `tervia-rdp`) and an id space each, so a credential needed the protocol to
 * address it; one host store on one service (`tervia-hosts`) with one id space
 * does not.
 */
export const HOST_SECRET_GROUP = "hostSecrets";
export const IDENTITY_SECRET_GROUP = "identitySecrets";
export const KEY_SECRET_GROUP = "keySecrets";

/** Named here and passed to `backup_open_payload` so the host process knows what
 *  to withhold from the metadata it hands back. A credential group missing from
 *  this list is not withheld - it stays in the payload and is handed to the
 *  webview in the clear, which is the one thing this whole path exists to
 *  prevent. */
export const SECRET_GROUPS = [HOST_SECRET_GROUP, IDENTITY_SECRET_GROUP, KEY_SECRET_GROUP] as const;
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

/** The file an export writes. Everything of substance is inside `payload`. */
export type BackupFileV2 = {
  kind: typeof BACKUP_KIND;
  version: typeof BACKUP_VERSION;
  exportedAt: number;
  payload: SealedBlob;
};

/**
 * What `parseBackupFile` could establish without a passphrase: that the envelope
 * is a readable one, and the sealed blob to hand the host process.
 *
 * Still a discriminated union with one arm, and the `version` field is why. It
 * is what makes a second readable format an added arm that every consumer has to
 * narrow for, rather than a silently widened object.
 */
export type ParsedBackup = { version: 3; payload: SealedBlob };

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
 * {@link resolveIdentityBindings} reuses that fallback by passing `undefined`
 * here, so "an inline binding with nothing in it" has one spelling.
 *
 * The identity arm below is preserved rather than applied. It is read here so the
 * later pass can see what the file ASKED for; a backup carries no vault, so
 * nothing downstream may act on that request.
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

/**
 * The pins one file row carries, keyed by address - or `undefined` when it
 * carries none.
 *
 * THE FLAT PIN BELONGS TO THE ADDRESS THE FILE NAMES, and saying so here is the
 * whole point of this function. `nextPins` in the host store has to give an
 * unkeyed pin an address, and with no map handed over it uses the STORED
 * record's: correct for a `{ ...stored, host: next }` spread, and wrong for a
 * file, whose row is not a spread of anything on this machine. A file may name
 * `c.example` for an id saved here as `b.example` - that is what `replaced`
 * counts - and filing the file's pin at `b.example` would replace a verified key
 * with a different machine's (every later connect to `b.example` aborts as a
 * MISMATCH and can never TOFU past it) while leaving `c.example`, the address
 * actually about to be dialled, silently unpinned. So the map is always EXPLICIT
 * by the time `upsertHost` sees it, and nothing infers anything.
 *
 * UNTRUSTED, like every other field here. An entry with a blank address or a
 * blank fingerprint is dropped: a blank key is an address nothing dials, and a
 * blank value would read as "a key is pinned here" to every consumer of the flat
 * projection while matching no server.
 *
 * ABSENT rather than `{}` when nothing survives, and that distinction is
 * load-bearing. `{}` is what the editor's Forget means - "every pin for this host
 * is discarded" - and an import may not say that on a file's behalf. `undefined`
 * is what the store reads as "leave whatever is stored alone", which is the same
 * non-destructive default the rest of this import takes.
 *
 * A map WINS over the flat field rather than merging with it. The store keeps the
 * flat field as a projection of the map at the row's own address, so a file where
 * the two disagree was hand-made, and the keyed map is the more specific claim.
 */
function pinsOf(raw: unknown, address: string, flat: string): HostPins | undefined {
  const keyed: Record<string, string> = {};
  if (isRecord(raw)) {
    for (const [at, fingerprint] of Object.entries(raw)) {
      const key = at.trim();
      const pin = str(fingerprint).trim();
      if (key && pin) keyed[key] = pin;
    }
  }
  if (Object.keys(keyed).length > 0) return keyed;
  return flat ? { [address]: flat } : undefined;
}

function sshArm(base: HostBase, raw: Record<string, unknown>): SshHost {
  const proxyJumpId = str(raw.proxyJumpId).trim();
  const lastFingerprint = str(raw.lastFingerprint).trim();
  const pins = pinsOf(raw.pins, base.host, lastFingerprint);
  return {
    ...base,
    protocol: "ssh",
    credential: sshBinding(raw.credential, base.id),
    // Kept deliberately: it is the pinned host key. Carrying it over means the
    // new machine keeps the same TOFU anchor instead of blindly accepting
    // whatever answers on the first connect.
    ...(lastFingerprint ? { lastFingerprint } : {}),
    // And the OTHER addresses this host has trusted, which is what makes a round
    // trip lossless: a build before keying wrote only the flat field, so the
    // fallback in `pinsOf` is also the migration for an older export.
    ...(pins ? { pins } : {}),
    ...(proxyJumpId ? { proxyJumpId } : {}),
  };
}

function rdpArm(base: HostBase, raw: Record<string, unknown>): RdpHost {
  const certFingerprint = str(raw.certFingerprint).trim();
  const pins = pinsOf(raw.pins, base.host, certFingerprint);
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
    // Keyed the same way on both arms - only the flat field's NAME differs.
    ...(pins ? { pins } : {}),
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
 * Drop every row whose id names a saved host of the OTHER protocol.
 *
 * Both rows are well-formed, so this is not validation: it is the one merge the
 * store cannot perform without losing a secret. `upsertHost` releases the
 * accounts the new record can no longer NAME, and an SSH row replaced by an RDP
 * one can name neither `privateKey` nor `keyPassphrase`, so both are deleted -
 * nothing copied them anywhere, nothing can enumerate what is left, and the row
 * that survives cannot connect with what it lost. The flip the other way loses
 * nothing (`password` is a field both protocols own) and is refused anyway: a
 * saved host silently becoming a different kind of machine is not what merging by
 * id promised.
 *
 * REFUSED rather than repaired, because there is no version of the row that is
 * both the file's and the saved one's. Deleting the saved host first is a
 * decision only its owner can make.
 */
export function refuseProtocolConflicts(
  incoming: Host[],
  existing: Host[],
): { hosts: Host[]; conflicts: number } {
  const byId = new Map(existing.map((h) => [h.id, h]));
  const hosts = incoming.filter((h) => (byId.get(h.id)?.protocol ?? h.protocol) === h.protocol);
  return { hosts, conflicts: incoming.length - hosts.length };
}

/** Whether the binding already saved here IS the one the file asked for, so
 *  keeping it costs the user nothing and there is nothing to report. */
function isSameIdentity(
  saved: SshCredentialBinding | RdpCredentialBinding,
  wanted: VaultIdentityBinding,
): boolean {
  return saved.kind === "identity" && saved.identityId === wanted.identityId;
}

/**
 * Never apply a vault binding, because this format carries no vault.
 *
 * A v2 payload holds hosts and groups and nothing else - no identities, no keys -
 * so an incoming `{kind:"identity"}` is a claim about the EXPORTING machine's
 * vault, in the same class as a `hasPassword` flag from the file. Unlike a flag it
 * is destructive: a vault-bound record owns no host accounts, so landing one over
 * a saved INLINE host makes every field that host owned stale and `upsertHost`
 * deletes all of them - password, private key and key passphrase. Nothing was
 * copied first, the identity it names does not exist here, and there is no
 * `secrets_list`, so those bytes are unreachable rather than untidy (§9.7).
 *
 * Two outcomes, decided by what is already saved under that id:
 *
 *   THE HOST IS ALREADY SAVED -> its own credential is KEPT, byte for byte. The
 *   file updates the metadata and says nothing about the credential, which is what
 *   `undefined` means everywhere else in this store. A machine re-importing its
 *   own backup keeps its vault binding this way, and the destructive path stops
 *   being unlikely and becomes unreachable: the binding KIND never changes across
 *   the write, so `releaseStaleAccounts` has nothing stale to release.
 *
 *   THE HOST IS NEW -> the binding is downgraded to the same blank inline one an
 *   unreadable binding falls back to. That is the state every host is in before
 *   someone types a password: in the list, editable, one dialog away from working.
 *   Refusing the row instead would throw away a good name, address, jump chain and
 *   pinned host key over a credential the file never carried.
 *
 * `dropped` counts only the rows where the file's binding was NOT honoured, so a
 * round trip of one machine's own backup reports zero.
 *
 * Run AFTER {@link refuseProtocolConflicts}: a saved record found here is then
 * known to speak this row's protocol, so its binding fits this row's arm.
 */
export function resolveIdentityBindings(
  incoming: Host[],
  existing: Host[],
): { hosts: Host[]; dropped: number } {
  const byId = new Map(existing.map((h) => [h.id, h]));
  let dropped = 0;
  const hosts = incoming.map((h): Host => {
    // Read off `h` once: narrowing `h.protocol` below re-widens `h.credential`,
    // so the identity arm has to be captured before the protocol guard.
    const wanted = h.credential;
    if (wanted.kind !== "identity") return h;
    const saved = byId.get(h.id);
    if (h.protocol === "ssh") {
      // `undefined` rather than a raw object: `sshBinding` owns the blank
      // fallback, so there is one spelling of "an inline binding with nothing in
      // it" rather than two that can drift.
      const keep = saved?.protocol === "ssh" ? saved.credential : sshBinding(undefined, h.id);
      if (!isSameIdentity(keep, wanted)) dropped++;
      return { ...h, credential: keep };
    }
    const keep = saved?.protocol === "rdp" ? saved.credential : rdpBinding(undefined, h.id);
    if (!isSameIdentity(keep, wanted)) dropped++;
    return { ...h, credential: keep };
  });
  return { hosts, dropped };
}

/**
 * Hand every incoming row an EXPLICIT pin map: what the file carried, over what
 * this machine already trusted.
 *
 * The store's `nextPins` believes a caller that hands it a map and infers an
 * address only for a caller that does not. This pass is what makes the import the
 * first kind. Without it the import was the second, and its inference is written
 * for a `{ ...stored, host: next }` spread rather than for a file - see
 * {@link pinsOf} for the two failures that follow when the file's address and the
 * saved one differ.
 *
 * A UNION, and the file only wins per ADDRESS. Nothing else about an import
 * deletes anything - "a host that exists here but not in the file is left alone" -
 * and a pin this machine verified for an address the file has never heard of is in
 * exactly that class. Replacing the map wholesale would drop it, which is a silent
 * TOFU downgrade for a machine the user has already trusted. The file DOES win at
 * an address both name, which is the same authority it has over every other field
 * on the row, and the same thing the store already did with a flat pin for an
 * unchanged address.
 *
 * `hostPins` on both sides rather than reading `pins` directly, so a saved record
 * written before keying and a file row written before keying are both read as the
 * one-entry maps they are.
 *
 * Left ABSENT when the union is empty: a row with no pins anywhere must not grow a
 * `{}`, which is Forget's spelling rather than "nothing to say".
 *
 * Run AFTER {@link refuseProtocolConflicts} and {@link resolveIdentityBindings},
 * which is only about ordering discipline: those two decide what a row may BECOME,
 * and this one may not put a pin on a row they are about to refuse. It touches
 * nothing but `pins`, so it cannot disturb the credential either of them chose.
 */
export function carryPins(incoming: Host[], existing: Host[]): Host[] {
  const byId = new Map(existing.map((h) => [h.id, h]));
  return incoming.map((h): Host => {
    const saved = byId.get(h.id);
    const pins: Record<string, string> = { ...(saved ? hostPins(saved) : {}), ...hostPins(h) };
    return Object.keys(pins).length > 0 ? { ...h, pins } : h;
  });
}

/**
 * Merge the file's groups into the saved ones, and repoint the incoming hosts at
 * whatever group they end up in.
 *
 * Merging is by id, like hosts, and the two collisions that follow from that pull
 * in opposite directions.
 *
 * A NAME ALREADY TAKEN under a different id resolves to the group holding it, and
 * the hosts that named the incoming group are repointed. A group has to have a
 * unique name - `upsertGroup` refuses a second "prod" - so a file whose "prod"
 * carries a different id than the local one would otherwise abort the import over
 * a label. That is the merge the uniqueness rule implies: two groups cannot share
 * a name, so "prod" IS the group. The same branch covers two incoming groups
 * colliding with each OTHER, which would throw on the second write.
 *
 * AN ID ALREADY TAKEN under a different name is left alone, and that is the one
 * place the file does NOT win. `upsertGroup` would accept the write - same id, so
 * no uniqueness to violate - and relabel every local host in that group: a file
 * where `g-9` is "prod" turns six local staging boxes into prod boxes, in a list
 * whose whole job is telling those two apart. Nothing is lost by keeping the local
 * label, since the id is unchanged and every host still resolves; a rename the
 * user did want costs them one edit, and `keptNames` is what says so out loud.
 * A changed `order` on such a group does not apply either - the row is skipped
 * whole rather than half-merged.
 *
 * Returned together because applying one half without the other is the bug: a
 * repoint nobody applies leaves the host naming a group that was never written.
 */
export function mergeGroups(
  incoming: HostGroup[],
  existing: HostGroup[],
  hosts: Host[],
): { groups: HostGroup[]; hosts: Host[]; merged: number; keptNames: number } {
  // The store's own comparison, so `" prod"` and `"PROD"` are the collision they
  // look like. Duplicated because that helper is private to `hosts/store.ts`.
  const key = (name: string): string => name.trim().toLowerCase();
  const owner = new Map(existing.map((g) => [key(g.name), g.id]));
  const savedName = new Map(existing.map((g) => [g.id, g.name]));
  const groups: HostGroup[] = [];
  const remap = new Map<string, string>();
  let keptNames = 0;

  for (const group of incoming) {
    // The id check comes FIRST, and skipping registers nothing in `owner`: the
    // local group already holds its own name there, under its own id.
    const saved = savedName.get(group.id);
    if (saved !== undefined && key(saved) !== key(group.name)) {
      keptNames++;
      continue;
    }
    const held = owner.get(key(group.name));
    if (held !== undefined && held !== group.id) {
      remap.set(group.id, held);
      continue;
    }
    owner.set(key(group.name), group.id);
    groups.push(group);
  }

  const merged = remap.size;
  if (merged === 0) return { groups, hosts, merged, keptNames };
  return {
    groups,
    merged,
    keptNames,
    hosts: hosts.map((h) => {
      const to = h.groupId ? remap.get(h.groupId) : undefined;
      return to ? { ...h, groupId: to } : h;
    }),
  };
}

const NOT_A_BACKUP = "Not a Tervia connection backup file.";

/**
 * Parse and validate a backup file's envelope. Throws with a user-facing
 * message when the file is not a Tervia backup at all, and with a message naming
 * the format when it is one this build cannot read.
 *
 * There is nothing else here to check until the payload is decrypted - see
 * {@link sanitizePayload}, which is the rest of this trust boundary.
 *
 * The older kind is still MATCHED, and only so the refusal can be specific. A
 * `.tervia-ssh` file that fell through to "not a Tervia connection backup file"
 * would be told a falsehood about a file this app wrote, and the user would have
 * no way to learn that the format, rather than the file, is what ended it.
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
  // The kind and the version have to agree, and this is checked BEFORE the two
  // refusals so that a half-edited file is told it is half-edited rather than
  // being named as a format it never was. A file claiming v2 under the old kind
  // (or the reverse) is hand-made either way.
  const expectedKind = version === 1 ? BACKUP_KIND_V1 : BACKUP_KIND;
  if (raw.kind !== expectedKind) {
    throw new Error(`Backup file says format v${version} but is not a ${expectedKind} file.`);
  }

  // Refused, not converted, and each by its own sentence. There is no code that
  // could turn either shape into this one: a v1 file's sealed block IS a
  // credential map, and reading it would mean holding plaintext credentials in
  // the webview - the exact thing every other path here was built to stop.
  if (version === 1) {
    throw new Error(
      "This is a Tervia v1 backup (.tervia-ssh). This build reads format v3 only, and there is no converter — the hosts in it have to be entered again.",
    );
  }
  if (version === 2) {
    throw new Error(
      "This backup is format v2 and this build reads format v3 only. There is no converter, and nothing in it can be imported.",
    );
  }

  const payload = sanitizeSealed(raw.payload);
  if (!payload) throw new Error("Backup file is missing its encrypted payload.");
  return { version: 3, payload };
}

/**
 * Validate the decrypted payload: the hosts and their groups, bad entries
 * skipped and counted. This is the second half of the trust boundary -
 * `parseBackupFile` can only reach the envelope, and everything of substance is
 * sealed until the host process has decrypted it.
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
