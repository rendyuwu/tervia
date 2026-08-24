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
// This replaces `SshConnection` and `RdpConnection` (decision 2), so grouping,
// search and vault binding are built once instead of twice. The union
// discriminates on `protocol` rather than making every field optional, which is
// what keeps `desktopWidth` off an SSH row instead of making every consumer
// defensive about it.
//
// Nothing here makes a secret safer. The store holds metadata and presence flags
// only; on Linux a private key sits in a mode-0600 JSON file before and after
// this work, and the SSH connect path still round-trips plaintext through the
// webview on every connect and every ProxyJump hop. What a vault binding buys is
// FEWER COPIES of one secret.

export const HOSTS_STORE_PATH = "tervia-hosts.json";
export const HOSTS_KEY = "hosts";
export const HOST_GROUPS_KEY = "groups";

/** Seeds for a new row. A stored row always carries a real port. */
export const SSH_DEFAULT_PORT = 22;
export const RDP_DEFAULT_PORT = 3389;

/**
 * Every keychain field one host can own, by protocol, each in one list so a
 * caller that has to enumerate them cannot miss one. `backup.ts` is that caller:
 * an export builds a keychain reference per field, and a field left out of the
 * list simply does not travel.
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
 * `"preset"` is the only mode today: the desktop is negotiated at a fixed size
 * and the pane letterboxes it. It is persisted from day one anyway, so adding
 * `"fit"` (RDP-08) is a new union member and a new branch in the pane - not a
 * store migration over everyone's saved rows.
 */
export type RdpSizeMode = "preset";

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

/** Preset id for a width/height pair, or "" when it matches no preset (a row
 *  written by a later build offering a size this one does not). */
export function presetIdFor(width: number, height: number): string {
  return RDP_SIZE_PRESETS.find((p) => p.width === width && p.height === height)?.id ?? "";
}

export function presetById(id: string): RdpSizePreset | undefined {
  return RDP_SIZE_PRESETS.find((p) => p.id === id);
}

/** What both protocols hold in common. */
export type HostBase = {
  /** Opaque, `h-` prefixed. Stays stable across renames, because the keychain
   *  accounts and the pinned server key are both derived from it. */
  id: string;
  name: string;
  host: string;
  port: number;
  /** At most one, and groups do not nest (decision 6). */
  groupId?: string;
  description?: string;
  /** Unix ms of the last successful connect. */
  lastConnectedAt?: number;
};

/**
 * A machine reached over SSH.
 *
 * `credential` sits on each ARM of {@link Host} rather than on
 * {@link HostBase} - the one place this diverges from the plan's sketch. On the
 * base it would be independent of `protocol`, so `host.protocol === "rdp"` would
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
  /** SHA256 fingerprint of the server key, pinned on first connect (TOFU). */
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
   * Pinned per SAVED HOST, not per `host:port`, and that is not a shortcut. The
   * same machine is `host:3389` dialled directly and `127.0.0.1:<ephemeral>`
   * dialled through a tunnel - so keying by authority would make one machine
   * look like two servers, and the ephemeral port would look brand new on every
   * connect, i.e. a TOFU prompt that never stops asking. The host id is the only
   * identifier that survives both.
   */
  certFingerprint?: string;
  tunnel?: RdpTunnel;
};

/**
 * One saved machine.
 *
 * Note what is absent: there is no `forwards` field. A forward rule is its own
 * record in `modules/forwards` (decision 7), so a rule is edited in one place
 * whether or not the host it rides is on screen.
 */
export type Host = SshHost | RdpHost;

/** A label, not an owner - which is why deleting one clears `groupId` on its
 *  members instead of deleting them. */
export type HostGroup = { id: string; name: string; order?: number };

export function isSshHost(host: Host): host is SshHost {
  return host.protocol === "ssh";
}

export function isRdpHost(host: Host): host is RdpHost {
  return host.protocol === "rdp";
}

/**
 * The pinned server key, whichever field this protocol keeps it in.
 *
 * Exported so a caller that only wants to ask "is a key pinned here" does not
 * have to know that SSH pins a host key and RDP pins a certificate.
 */
export function hostFingerprint(host: Host): string | undefined {
  return host.protocol === "ssh" ? host.lastFingerprint : host.certFingerprint;
}
