import {
  HOST_RDP_PASSWORD_FIELD,
  HOST_SSH_KEY_PASSPHRASE_FIELD,
  HOST_SSH_PASSWORD_FIELD,
  HOST_SSH_PRIVATE_KEY_FIELD,
  type RdpCredentialBinding,
  type SshCredentialBinding,
} from "@/modules/vault/types";

// One record per machine, discriminated on `protocol`.
//
// This replaces `SshConnection` and `RdpConnection`, so grouping,
// search and vault binding are built once instead of twice. The union
// discriminates on `protocol` rather than making every field optional, which is
// what keeps `desktopWidth` off an SSH row instead of making every consumer
// defensive about it.
//
// Nothing here makes a secret safer. The store holds metadata and presence flags
// only; on Linux a private key sits in a mode-0600 JSON file before and after
// this work. What a vault binding buys is FEWER COPIES of one secret.

export const HOSTS_STORE_PATH = "tervia-hosts.json";
export const HOSTS_KEY = "hosts";
export const HOST_GROUPS_KEY = "groups";
/**
 * The third key in the same file, and the only one that is not host data: the
 * marker saying the one-shot legacy secret purge has finished. It lives here
 * because this store OUTLIVES the two connection modules whose secrets that purge
 * clears, and it is listed beside the others so this stays the one place that says
 * what is in the file. See `legacyPurge.ts`.
 *
 * A FOURTH key lives in this file too, and is not spelled here because all three
 * stores share one name for it: `TOMBSTONES_KEY` in `src/lib/tombstones.ts`,
 * holding what `deleteHost` and `deleteGroup` leave behind.
 */
export const LEGACY_PURGE_KEY = "legacySecretsPurged";

/**
 * What a host and a group are called in a tombstone's `kind`.
 *
 * Both kinds share ONE tombstone list, because both live in one file and `kind`
 * is what tells them apart. The ids never collide - one is `h-` prefixed and the
 * other `g-` - but a merge has to know which list a resurrection belongs in, and
 * the id prefix is a convention this layer does not want to re-derive.
 */
export const HOST_TOMBSTONE_KIND = "host";
export const GROUP_TOMBSTONE_KIND = "group";

/** Seeds for a new row. A stored row always carries a real port. */
export const SSH_DEFAULT_PORT = 22;
export const RDP_DEFAULT_PORT = 3389;

/**
 * Every keychain field one host can own, by protocol, each in one list so a
 * caller that has to enumerate them cannot miss one. `backup/apply.ts`'s
 * `hostRefs` is that caller: an export builds a keychain reference per field,
 * and a field left out of the list simply does not travel.
 *
 * The field NAMES belong to `modules/vault` because `resolve.ts` is what
 * dereferences these accounts. The lists are here because the HOST is what owns
 * them, so enumerating one host's accounts is this module's job.
 */
export const HOST_SSH_SECRET_FIELDS = [
  HOST_SSH_PASSWORD_FIELD,
  HOST_SSH_PRIVATE_KEY_FIELD,
  HOST_SSH_KEY_PASSPHRASE_FIELD,
] as const;

export const HOST_RDP_SECRET_FIELDS = [HOST_RDP_PASSWORD_FIELD] as const;

/**
 * How the remote desktop's resolution is chosen.
 *
 * `"preset"` negotiates a fixed size and the pane letterboxes it. `"fit"` opens
 * at the pane's device-pixel size and asks the server to follow it over the
 * Display Control channel (MS-RDPEDISP).
 *
 * `desktopWidth`/`desktopHeight` stay meaningful in `"fit"`: they are the size
 * used when the pane cannot be measured at connect, and the size a server with
 * no Display Control channel stays at.
 */
export type RdpSizeMode = "preset" | "fit";

export const RDP_CLIPBOARD_MODES = ["both", "hostToRemote", "remoteToHost", "off"] as const;

/**
 * Which directions the RDP clipboard bridge carries.
 *
 * Derived from the list above so the runtime check and the type cannot drift.
 * Absent means `"both"`: optional-with-default on read, so no stored record
 * needs migrating. `"off"` does not register the CLIPRDR channel at all, so
 * the server is never told there is a clipboard.
 */
export type RdpClipboardMode = (typeof RDP_CLIPBOARD_MODES)[number];

/** One offered desktop resolution. */
export type RdpSizePreset = {
  /** Stable id, `<w>x<h>`. Only used as a `<select>` value / React key. */
  id: string;
  width: number;
  height: number;
  label: string;
};

/**
 * Resolutions offered in the host editor. 16:9 and 16:10 shapes plus 4:3, which
 * is still what a lot of server consoles are configured for.
 */
export const RDP_SIZE_PRESETS: readonly RdpSizePreset[] = [
  { id: "1024x768", width: 1024, height: 768, label: "1024 × 768 (4:3)" },
  { id: "1280x720", width: 1280, height: 720, label: "1280 × 720 (720p)" },
  { id: "1280x800", width: 1280, height: 800, label: "1280 × 800 (16:10)" },
  { id: "1366x768", width: 1366, height: 768, label: "1366 × 768" },
  { id: "1600x900", width: 1600, height: 900, label: "1600 × 900" },
  { id: "1920x1080", width: 1920, height: 1080, label: "1920 × 1080 (1080p)" },
  { id: "2560x1440", width: 2560, height: 1440, label: "2560 × 1440 (1440p)" },
];

export const RDP_DEFAULT_PRESET = RDP_SIZE_PRESETS[4];

/** `<Combobox>` value for fit mode in the host editor's size picker. Not a
 *  preset id, so `presetById` returns `undefined` for it and the editor falls
 *  through to `RDP_DEFAULT_PRESET` for the persisted fallback size. */
export const RDP_FIT_SIZE_ID = "fit";

/** Preset id for a width/height pair, or "" when it matches no preset (a row
 *  written by a later build offering a size this one does not). */
export function presetIdFor(width: number, height: number): string {
  return RDP_SIZE_PRESETS.find((p) => p.width === width && p.height === height)?.id ?? "";
}

export function presetById(id: string): RdpSizePreset | undefined {
  return RDP_SIZE_PRESETS.find((p) => p.id === id);
}

/**
 * Server keys this host has accepted, by the ADDRESS each was presented at.
 *
 * The key is the record's own `host` field, never the authority actually dialled.
 * Through a tunnel the backend connects to `127.0.0.1:<ephemeral>`, and keying on
 * that would make one machine look like a new server on every connect - the same
 * reason the pin was per host id to begin with. The port is no part of it either:
 * one server presents one key on every port it listens on.
 */
export type HostPins = Readonly<Record<string, string>>;

/** What both protocols hold in common. */
export type HostBase = {
  /** Opaque, `h-` prefixed. Stays stable across renames, because the keychain
   *  accounts and the pinned server keys are both derived from it. */
  id: string;
  name: string;
  host: string;
  port: number;
  /** At most one, directly. The group itself may nest under another
   *  (`HostGroup.parentId`), but this field still names exactly one group -
   *  an ancestor filter match runs through the chain of `HostGroup` records,
   *  never through a path stored here. */
  groupId?: string;
  /**
   * Free-form labels, cross-cutting rather than exclusive: unlike `groupId`
   * (at most one), a host can carry several. Normalised by
   * {@link normalizeHostTags} on every LOCAL write - the store, the host
   * editor, the backup importer - so a reader coming from one of those never
   * sees a blank entry, a duplicate spelling, or an over-length or
   * over-count array. A sync landing is carried as-is, like every other host
   * field, so that guarantee does not extend to a record another device
   * wrote. `undefined` means "no tags", never `[]` - the store never
   * persists an empty array, the same convention `pins` and `updatedAt`
   * already use for "not written yet".
   *
   * No managed tag record backs this, so there is no rename- or
   * delete-everywhere across the hosts that carry a tag - `KNOWN-LIMITS.md`
   * carries it, under "Host tags".
   */
  tags?: readonly string[];
  description?: string;
  /** Unix ms of the last successful connect. */
  lastConnectedAt?: number;
  /**
   * Every server key this host trusts, keyed by the address it was presented at.
   *
   * On {@link HostBase} rather than per arm, unlike `credential`: the shape does
   * not depend on `protocol`, so nothing here needs narrowing. Only the NAME of
   * the flat projection differs, which is what {@link hostFingerprint} is for.
   *
   * Keyed, rather than one pin per host, because re-pointing a host used to force
   * a choice between two bad options. Test verified against the pin of the machine
   * the record still named, so testing a new address meant pressing Forget first -
   * and Forget wrote the deletion straight to the store, so cancelling the dialog
   * left the host on TOFU with no pin and no trace. With a key per address, Test
   * simply finds no pin for an address never visited and takes the TOFU prompt,
   * while the pin for the saved address is not touched at all.
   *
   * `undefined` means "not keyed yet", NOT "no pins": see {@link hostPins}, which
   * is where a record written before this existed is read. An empty object is the
   * other thing - every pin for this host has been forgotten - so the two are not
   * interchangeable.
   *
   * WRITTEN BY THE STORE, which also keeps the flat projection in step. A caller
   * that hands `upsertHost` a map is stating which address each pin belongs to and
   * is believed; a caller that hands over only a flat pin has it attributed by
   * `nextPins`, which is the one place that inference lives.
   */
  pins?: HostPins;
  /**
   * Unix ms of the last change to this record's own content, stamped by the
   * store on every write.
   *
   * ABSENT IS NOT ZERO, AND MUST NOT BE BACKFILLED ON READ. A record with no
   * stamp has simply never been written by a build that stamps, and reading
   * that as "changed just now" would have every legacy record win every merge
   * it takes part in. A read never rewrites the file to add one; the next
   * ordinary save does.
   *
   * NEVER TRUSTED FROM THE CALLER - the store overwrites whatever arrives here,
   * for the reason `withPins` in `store.ts` gives about pins: an editor
   * round-trips the record it loaded, so honouring a caller's value would mean
   * a save never bumps the stamp. A restored backup is therefore stamped as a
   * local write, which it genuinely is: every sanitizer in `modules/backup` is
   * a whitelist, so an exported stamp is dropped at import rather than carried
   * through. The one writer that does NOT overwrite it is `applyRemote` in
   * `store.ts`, which lands an already-merged record at the timestamp the remote
   * gave it - the only caller that did not originate what it is writing.
   *
   * On {@link HostBase} rather than per arm, on the same grounds as `pins`: the
   * shape does not depend on `protocol`, so nothing needs narrowing.
   *
   * NOT moved by a connect or by pinning a key. Those write `lastConnectedAt`
   * and the pins, which are per-machine history and trust rather than record
   * content - see `patchHost` in `store.ts`.
   */
  updatedAt?: number;
};

/** A tag longer than this is truncated, not refused - a tag is a short label,
 *  not a place for prose (`description` already exists for that). */
export const HOST_TAG_MAX_LENGTH = 40;

/** A host past this many tags keeps its first `HOST_TAG_MAX_COUNT`, in the
 *  order given, and drops the rest: `HostCard`'s badge row has no
 *  overflow affordance, so this bounds how many badges one card can grow.
 *  It does not bound `page/TagStrip.tsx`, which shows one chip per tag in
 *  use across the whole fleet, not per host. */
export const HOST_TAG_MAX_COUNT = 24;

/**
 * `tags` normalised the one way every writer must agree on: trimmed, cut to
 * {@link HOST_TAG_MAX_LENGTH} Unicode CODE POINTS (not UTF-16 units, so a
 * surrogate pair straddling the cut survives whole rather than splitting)
 * with any trailing space the cut left behind trimmed too, blanks dropped,
 * deduped case-insensitively with the FIRST spelling kept (the same rule
 * `sameName` in `store.ts` already applies to a group's name), and capped at
 * {@link HOST_TAG_MAX_COUNT}.
 *
 * TOTAL: `tags` is `unknown` rather than `readonly string[] | undefined`
 * because a landed sync record was never run through this (see
 * {@link HostBase.tags}) and is read by the same code paths a local record
 * is, so a non-array value or a non-string entry is dropped rather than
 * thrown on - the shape every other reader of a landed record already
 * tolerates.
 *
 * Every LOCAL writer means every local writer: `store.ts`'s `writeHost`, the
 * host editor's save path, and `modules/backup/file.ts`'s `sanitizeHost` all
 * call this rather than each keeping its own idea of what counts as a valid
 * tag. `applyRemote` does not - see {@link HostBase.tags}.
 *
 * Returns `undefined` for "no tags left after normalising", never `[]` - see
 * {@link HostBase.tags}.
 */
export function normalizeHostTags(tags: unknown): readonly string[] | undefined {
  if (!Array.isArray(tags)) return undefined;
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of tags) {
    if (typeof raw !== "string") continue;
    const trimmed = Array.from(raw.trim()).slice(0, HOST_TAG_MAX_LENGTH).join("").trimEnd();
    if (!trimmed) continue;
    const key = trimmed.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(trimmed);
    if (out.length >= HOST_TAG_MAX_COUNT) break;
  }
  return out.length > 0 ? out : undefined;
}

/**
 * A machine reached over SSH.
 *
 * `credential` sits on each ARM of {@link Host} rather than on
 * {@link HostBase}, and that placement is the whole reason the union earns its
 * keep. On the base it would be independent of `protocol`, so
 * `host.protocol === "rdp"` would
 * narrow the desktop fields and leave the credential a two-protocol union that
 * every consumer then has to re-check. On the arm, one guard narrows both.
 */
export type SshHost = HostBase & {
  protocol: "ssh";
  credential: SshCredentialBinding;
  /**
   * ProxyJump: another SAVED HOST to tunnel through to reach this one. Chains
   * transitively - the jump host may carry its own `proxyJumpId`. Absent = a
   * direct connection.
   *
   * Must name a host whose `protocol` is `"ssh"`. The two old stores could not
   * express an RDP jump host; one merged store can, and it is meaningless, so
   * both the write guard and `resolveJumpHops` refuse it.
   */
  proxyJumpId?: string;
  /**
   * SHA256 fingerprint of the server key, pinned on first connect (TOFU).
   *
   * A PROJECTION of {@link HostBase.pins} at this record's current `host`, kept in
   * step by the store on every write. It exists because it is what every consumer
   * reads - `ssh-session.ts`, `tunnel.ts` and `jumps.ts` each pass it straight to
   * the backend as `expectedFingerprint` - and keeping the flat field valid for the
   * address the record names is what makes those call sites correct without any of
   * them knowing pins are keyed.
   */
  lastFingerprint?: string;
};

/** Reach this host through a saved SSH host's tunnel instead of dialling it
 *  directly. `sshHostId` must name a host whose `protocol` is `"ssh"`. */
export type RdpTunnel = { sshHostId: string };

export type RdpHost = HostBase & {
  protocol: "rdp";
  credential: RdpCredentialBinding;
  /** Negotiated desktop size. */
  desktopWidth: number;
  desktopHeight: number;
  sizeMode: RdpSizeMode;
  /**
   * SHA-256 fingerprint of the server's leaf certificate, pinned on first
   * connect (TOFU).
   *
   * A PROJECTION of {@link HostBase.pins} at this record's current `host`, on the
   * same terms as `SshHost.lastFingerprint`: `rdp/dial.ts` passes it straight to
   * the backend as `expectedCertFingerprint`.
   *
   * Still NOT keyed by the authority dialled, which is the part that was never a
   * shortcut. The same machine is `host:3389` dialled directly and
   * `127.0.0.1:<ephemeral>` dialled through a tunnel, so keying by authority would
   * make one machine look like two servers and the ephemeral port would look brand
   * new on every connect - a TOFU prompt that never stops asking. `pins` is keyed
   * by the address the RECORD names, which survives both.
   */
  certFingerprint?: string;
  tunnel?: RdpTunnel;
  /** Clipboard directions. Absent means `"both"`; see {@link RdpClipboardMode}. */
  clipboard?: RdpClipboardMode;
};

/**
 * One saved machine.
 *
 * Note what is absent: there is no `forwards` field. A forward rule is its own
 * record in `modules/forwards`, so a rule is edited in one place
 * whether or not the host it rides is on screen.
 */
export type Host = SshHost | RdpHost;

/** A label, not an owner - which is why deleting one clears `groupId` on its
 *  members instead of deleting them, and re-parents its own child groups to
 *  its OWN parent instead of deleting or orphaning them. `parentId` nests one
 *  group under another; absent, it is a root group. A `parentId` naming a
 *  group that no longer exists, naming itself, or sitting in a cycle with
 *  another group's `parentId` is read as root rather than refused - see
 *  `groupTree.ts`'s `buildGroupTree`, which every reader of this list goes
 *  through. `upsertGroup` (`store.ts`) refuses all three at WRITE time
 *  instead, on the pattern its jump-host chain check already set.
 *  `updatedAt` reads exactly as {@link HostBase.updatedAt} does, absent
 *  included.
 *
 *  `defaultIdentityId` names the vault identity a NEW host created in this
 *  group (or in a descendant with no default of its own -
 *  `groupTree.ts`'s `defaultIdentityFor` walks the chain) is pre-bound to,
 *  copied into the host's `credential` at CREATE time only - editing or
 *  clearing this field never moves a host that already exists, the same way
 *  `resolve.ts` never reads a group at all. One field, not one per protocol:
 *  a `VaultIdentity` is protocol-agnostic by design (its own doc in
 *  `modules/vault/types.ts`), so there is no per-protocol validity to
 *  narrow on. `upsertGroup` refuses a value naming no identity, but only
 *  when this field is the one changing - on `parentId`'s own pattern, so a
 *  dangling value arriving through sync never blocks a rename, and
 *  `defaultIdentityFor` skips a dangling value at read time and falls
 *  through to a live ancestor's instead of refusing anything or shadowing
 *  one further up the chain. */
export type HostGroup = {
  id: string;
  name: string;
  parentId?: string;
  order?: number;
  updatedAt?: number;
  defaultIdentityId?: string;
};

export function isSshHost(host: Host): host is SshHost {
  return host.protocol === "ssh";
}

export function isRdpHost(host: Host): host is RdpHost {
  return host.protocol === "rdp";
}

/**
 * The pinned server key for the address this record names, whichever field this
 * protocol keeps it in.
 *
 * Exported so a caller that only wants to ask "is a key pinned here" does not
 * have to know that SSH pins a host key and RDP pins a certificate.
 */
export function hostFingerprint(host: Host): string | undefined {
  return host.protocol === "ssh" ? host.lastFingerprint : host.certFingerprint;
}

/**
 * This host's pins keyed by address, which is also the MIGRATION off the pin that
 * used to be keyed by host id alone.
 *
 * Run on READ rather than as a one-shot pass over the store file, because there is
 * exactly one address an unkeyed pin can have been recorded against: a connect
 * pins what the machine at `host` presented, so a record with no map adopts its
 * flat pin onto `host`. Nothing is dropped, and no launch has to rewrite everyone's
 * rows to prove it - the map is persisted the next time the record is written for
 * any other reason.
 *
 * An EMPTY map is not a missing one. `{}` is how the editor says "the pins for this
 * host were forgotten", so adopting on emptiness would resurrect the pin Forget
 * had just discarded. Hence the check is `host.pins` present, and `{}` is present.
 */
export function hostPins(host: Host): HostPins {
  if (host.pins) return host.pins;
  const flat = hostFingerprint(host);
  return flat ? { [host.host]: flat } : {};
}

/**
 * One row for the Known Hosts page: one pinned key or certificate, at one
 * address, on one host. {@link hostPins} above is per-host and keyed by
 * address; this flattens every host's map into the shape a page listing
 * every pin across the whole store wants, one row per (host, address).
 */
export type KnownHostRow = {
  hostId: string;
  hostName: string;
  protocol: Host["protocol"];
  address: string;
  fingerprint: string;
};

/**
 * Every pinned key or certificate across every host, sorted by host name
 * then address (both case-insensitively), with the host id as a final
 * tie-break so two hosts sharing a name still sort the same way twice -
 * the read side of {@link HostPins} that nothing before the Known Hosts
 * page ever needed, because every earlier reader already held one host's
 * own record.
 */
export function knownHostRows(hosts: readonly Host[]): KnownHostRow[] {
  const rows: KnownHostRow[] = [];
  for (const host of hosts) {
    for (const [address, fingerprint] of Object.entries(hostPins(host))) {
      rows.push({
        hostId: host.id,
        hostName: host.name,
        protocol: host.protocol,
        address,
        fingerprint,
      });
    }
  }
  return rows.sort(
    (a, b) =>
      a.hostName.toLowerCase().localeCompare(b.hostName.toLowerCase()) ||
      a.address.toLowerCase().localeCompare(b.address.toLowerCase()) ||
      a.hostId.localeCompare(b.hostId),
  );
}

/** The value {@link credentialStamp} reports for a host that is not in the store. */
export const CREDENTIAL_STAMP_ABSENT = "absent";
/** The value {@link credentialStamp} reports for a host that owns its credentials. */
export const CREDENTIAL_STAMP_INLINE = "inline";

/**
 * What a host's credential binding IS, as one comparable string.
 *
 * A string rather than a structural comparison because the only question anyone
 * asks of it is "is this still the same thing it was", and a string makes that
 * one `!==` at the write instead of a deep compare each caller writes itself.
 *
 * Three values, and the third carries the id: `"absent"` for a record that is not
 * in the store at all, `"inline"` for one that owns its credentials, and
 * `identity:<identityId>` for one bound to a shared vault identity. Re-binding
 * from one identity to another therefore changes the stamp, which is the case a
 * bare `kind` comparison would miss.
 *
 * Deliberately NOT a hash of the whole record. This answers one question - has the
 * binding moved under a form that loaded it - and widening it to every field would
 * refuse ordinary concurrent edits to a name or a port, which last-write-wins
 * already handles correctly.
 */
export function credentialStamp(host: Host | null | undefined): string {
  if (!host) return CREDENTIAL_STAMP_ABSENT;
  const cred = host.credential;
  return cred.kind === "inline" ? CREDENTIAL_STAMP_INLINE : `identity:${cred.identityId}`;
}

/**
 * A save refused because the stored record's credential binding is no longer the
 * one the caller loaded.
 *
 * Refuse, never overwrite. The write this stops is silent and unrecoverable, and
 * it runs the OTHER direction from how it first reads: a form loads an INLINE
 * host; another writer converts that same row to a vault binding underneath it,
 * which releases all three keychain accounts, because a vault-bound record owns
 * none; the stale form saves anyway. It still believes the row is inline, so it
 * writes an inline credential back - and every field the user did not retype reads
 * its presence flag off the record as it is stored NOW, which is vault-bound and
 * owns nothing, so the flag comes back false for all three. Nothing is deleted a
 * second time and nothing is restored, because the accounts are already gone - but
 * the row loses its vault binding and is left claiming inline credentials it does
 * not have, with no error anywhere.
 *
 * (The mirror image - a form that loaded a VAULT-BOUND host saving after a stale
 * convert - still cannot happen through `save()` ITSELF: which credential that
 * function writes is decided by `boundIdentity` as this render holds it, not by
 * what is stored now, so a stale `save()` keeps writing `{kind:"identity"}` back
 * whatever changed underneath it. Narrowed to `save()` because it is no longer
 * true of the editor as a whole - its credential picker changes a bound
 * host's binding on purpose, through `convertHostToVault` / `bindHostToIdentity`
 * / `detachHostFromVault`, each a separate, immediately-committed write that
 * carries its own `credentialStamp` check rather than riding inside this one.)
 *
 * Carries `hostId` so a caller can re-read the record it was refused against
 * without having to hold one.
 */
export class HostBindingChangedError extends Error {
  readonly hostId: string;
  readonly expected: string;
  readonly actual: string;

  constructor(hostId: string, name: string, expected: string, actual: string) {
    super(
      `hosts: "${name}" changed while this editor was open - it was ` +
        `${describeStamp(expected)} and is now ${describeStamp(actual)}. Nothing was saved.`,
    );
    this.name = "HostBindingChangedError";
    this.hostId = hostId;
    this.expected = expected;
    this.actual = actual;
  }
}

/** The stamp in words, so the refusal names what changed rather than printing an
 *  internal token at the user. */
function describeStamp(stamp: string): string {
  if (stamp === CREDENTIAL_STAMP_ABSENT) return "deleted";
  if (stamp === CREDENTIAL_STAMP_INLINE) return "using credentials of its own";
  return "bound to a shared vault identity";
}
