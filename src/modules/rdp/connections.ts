import { invoke } from "@tauri-apps/api/core";
import { emit, listen, type UnlistenFn } from "@tauri-apps/api/event";
import { LazyStore } from "@tauri-apps/plugin-store";
import { useEffect, useState } from "react";

// Saved RDP hosts live in their own LazyStore, next to the SSH one. The store
// holds metadata and a flag marking that a password exists; the password itself
// goes in the OS keychain via secrets_* IPC.
//
// The one deliberate divergence from `ssh/connections.ts`: there is no
// `getConnectionSecrets` here, and there never should be. `rdp_open` takes a
// keychain REFERENCE and the host process reads the plaintext itself, so the
// password never enters the webview. Adding a read-back helper is all it would
// take to lose that property, so the helper does not exist - see `bridge.ts`
// for the one place a plaintext password is legitimately passed down (the
// dialog's Test button, for a draft that has not been saved yet).

const STORE_PATH = "tervia-rdp-connections.json";
const STORE_KEY = "connections";

export const RDP_KEYRING_SERVICE = "tervia-rdp";

const PASSWORD_FIELD = "password";

/** RDP's default port. A row always carries a real port, so this is only the
 *  seed for a new one. */
export const RDP_DEFAULT_PORT = 3389;

/**
 * How the remote desktop's resolution is chosen.
 *
 * `"preset"` is the only mode today: the desktop is negotiated at a fixed size
 * and the pane letterboxes it. It is persisted from day one anyway, so adding
 * `"fit"` (resize the desktop to the pane, RDP-08) is a new union member and a
 * new branch in the pane - not a store migration over everyone's saved rows.
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
 * Resolutions offered in the dialog. 16:9 and 16:10 shapes plus 4:3, which is
 * still what a lot of server consoles are configured for.
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

/**
 * Reach this host through a saved SSH connection's tunnel instead of dialling
 * it directly. Phase 5e owns the transport; the field is declared now so
 * attaching a tunnel later is a write to an optional key rather than a store
 * migration.
 *
 * Nothing in this phase reads it, and `bridge.ts` dials `host:port` directly.
 */
export type RdpTunnel = {
  /** Id of a saved SSH connection to forward through. */
  sshConnectionId: string;
};

export type RdpConnection = {
  id: string;
  name: string;
  host: string;
  port: number;
  username: string;
  /**
   * NetBIOS or DNS domain. Absent for a local account; a UPN
   * (`user@domain.example`) can go in `username` with this left unset instead,
   * which is what a modern Entra-joined host wants.
   */
  domain?: string;
  /** Negotiated desktop size. */
  desktopWidth: number;
  desktopHeight: number;
  sizeMode: RdpSizeMode;
  /** Password stored in the keychain under `<id>::password`. */
  hasPassword: boolean;
  /** UI note. */
  description?: string;
  /** Unix ms of the last successful connect. */
  lastConnectedAt?: number;
  /**
   * SHA-256 fingerprint of the server's leaf certificate, pinned on first
   * connect (TOFU).
   *
   * Pinned per SAVED CONNECTION, not per `host:port`, and that is not an
   * implementation shortcut. The same machine is `host:3389` dialled directly
   * and `127.0.0.1:<ephemeral>` dialled through the tunnel Phase 5e adds - so
   * keying by authority would make one machine look like two servers, and the
   * ephemeral port would look like a brand-new host on every single connect,
   * i.e. a TOFU prompt that never stops asking. The connection id is the only
   * identifier that survives both.
   */
  certFingerprint?: string;
  /** See {@link RdpTunnel}. Unused in this phase. */
  tunnel?: RdpTunnel;
};

const store = new LazyStore(STORE_PATH, { defaults: {}, autoSave: 200 });
const CHANGED_EVENT = "tervia://rdp-connections-changed";

// One serialized chain for every mutation, so two concurrent callers cannot
// interleave a read-modify-write and lose an update. Same reasoning as the SSH
// store: `markConnected` fires from a connect while the dialog may be saving an
// edit, and losing a freshly-pinned certificate would silently drop that host
// back to a TOFU prompt on the next connect.
let writeQueue: Promise<unknown> = Promise.resolve();
function enqueueWrite<T>(op: () => Promise<T>): Promise<T> {
  const run = writeQueue.then(op, op);
  // Keep the chain alive regardless of any single op's outcome.
  writeQueue = run.then(
    () => undefined,
    () => undefined,
  );
  return run;
}

/**
 * Keychain account for one field of one connection. Same `<id>::<field>` shape
 * `ssh/connections.ts` uses, so there is ONE keychain key format across both
 * protocols rather than two - and it is the string `rdp_open`'s keychain
 * reference carries, which is why this is exported.
 */
export function rdpKeyringAccount(id: string, field: string = PASSWORD_FIELD): string {
  return `${id}::${field}`;
}

export async function listConnections(): Promise<RdpConnection[]> {
  const raw = await store.get<RdpConnection[]>(STORE_KEY);
  return Array.isArray(raw) ? raw : [];
}

async function persist(list: RdpConnection[]): Promise<void> {
  await store.set(STORE_KEY, list);
  await Promise.all([store.save(), emit(CHANGED_EVENT)]);
}

export function newConnectionId(): string {
  // Opaque id. Stays stable across renames so keyring accounts don't drift, and
  // so the pinned certificate stays attached to the machine it came from.
  return `r-${Math.random().toString(36).slice(2, 10)}${Date.now().toString(36)}`;
}

/**
 * Create or replace one saved connection.
 *
 * `password` follows the SSH store's three-state convention: a string writes it
 * (or clears the entry when blank), and `undefined` means "leave whatever is
 * stored alone". The dialog relies on the third state: it never loads the saved
 * password, so an edit that does not touch the field must not wipe it.
 */
export async function upsertConnection(
  conn: RdpConnection,
  password?: string | null,
): Promise<void> {
  return enqueueWrite(async () => {
    // The flag has to agree with what is actually in the keyring, or the
    // dialog's "password saved" line lies and a connect fails with the
    // backend's "no password stored" message instead.
    const next = { ...conn, hasPassword: await writeSecret(conn.id, PASSWORD_FIELD, password) };
    const list = await listConnections();
    const idx = list.findIndex((c) => c.id === conn.id);
    if (idx >= 0) list[idx] = next;
    else list.push(next);
    await persist(list);
  });
}

export async function deleteConnection(id: string): Promise<void> {
  return enqueueWrite(async () => {
    await deleteSecret(id, PASSWORD_FIELD);
    await persist((await listConnections()).filter((c) => c.id !== id));
  });
}

export function onConnectionsChanged(cb: () => void): Promise<UnlistenFn> {
  return listen(CHANGED_EVENT, () => cb());
}

/**
 * Saved RDP hosts keyed by id, kept fresh across edits. Every surface that
 * renders an `rdp:<name>` label needs this same map (the tab strip, the pane
 * headers, the Workspaces panel), and each one loading it by hand is how one of
 * them ends up showing a stale host name after a rename.
 */
export function useRdpHosts(): Map<string, RdpConnection> {
  const [hosts, setHosts] = useState<Map<string, RdpConnection>>(() => new Map());
  useEffect(() => {
    const load = () =>
      void listConnections().then((list) => setHosts(new Map(list.map((c) => [c.id, c]))));
    load();
    const unsub = onConnectionsChanged(load);
    return () => {
      void unsub.then((fn) => fn());
    };
  }, []);
  return hosts;
}

/**
 * Read-modify-write one saved connection through the serialized queue. `patch`
 * returns the fields to change, or null to write nothing. A missing id is a
 * no-op: the connection was deleted mid-connect.
 */
async function patchConnection(
  id: string,
  patch: (current: RdpConnection) => Partial<RdpConnection> | null,
): Promise<void> {
  return enqueueWrite(async () => {
    const list = await listConnections();
    const idx = list.findIndex((c) => c.id === id);
    if (idx < 0) return;
    const next = patch(list[idx]);
    if (!next) return;
    list[idx] = { ...list[idx], ...next };
    await persist(list);
  });
}

/** Marks a successful connect: the timestamp, and the certificate the server
 *  actually presented. */
export async function markConnected(id: string, fingerprint: string): Promise<void> {
  return patchConnection(id, (c) => ({
    lastConnectedAt: Date.now(),
    certFingerprint: fingerprint || c.certFingerprint,
  }));
}

/**
 * Records a certificate the user just accepted in the first-connect dialog.
 *
 * Separate from `markConnected` because trusting a certificate and connecting
 * are two different steps, and only the first has happened here: the backend
 * pauses inside the TLS handshake, so nothing has authenticated yet. Pinning
 * only on a fully successful connect meant a wrong password re-asked the
 * certificate question on every retry, and a certificate accepted during the
 * dialog's Test was forgotten by the time the connection was saved.
 * `lastConnectedAt` is deliberately untouched: nothing has connected.
 */
export async function pinFingerprint(id: string, fingerprint: string): Promise<void> {
  if (!fingerprint) return;
  return patchConnection(id, (c) =>
    c.certFingerprint === fingerprint ? null : { certFingerprint: fingerprint },
  );
}

/** Clears the pinned certificate so the next connect re-pins via TOFU. Use
 *  after verifying a legitimate certificate rotation - which for RDP is routine,
 *  since a self-signed RDP certificate is regenerated on some reinstalls. */
export async function clearFingerprint(id: string): Promise<void> {
  return patchConnection(id, () => ({ certFingerprint: undefined }));
}

/**
 * Whether a value is now stored for this field, for the `hasPassword` flag.
 *
 * This is the ONLY keychain read in the module, and it deliberately does not
 * return the secret: it answers "is something stored", which is all the UI
 * needs, and never hands the plaintext to the caller.
 */
async function writeSecret(
  id: string,
  field: string,
  value: string | null | undefined,
): Promise<boolean> {
  if (value === undefined) {
    // No change requested. Ask whether anything is stored without reading it
    // out: an empty string back from `secrets_get` and a missing entry are the
    // same answer here, and neither is retained.
    try {
      const existing = await invoke<string | null>("secrets_get", {
        service: RDP_KEYRING_SERVICE,
        account: rdpKeyringAccount(id, field),
      });
      return !!existing && existing.length > 0;
    } catch {
      return false;
    }
  }
  const trimmed = value?.trim() ?? "";
  if (!trimmed) {
    await deleteSecret(id, field);
    return false;
  }
  await invoke("secrets_set", {
    service: RDP_KEYRING_SERVICE,
    account: rdpKeyringAccount(id, field),
    password: trimmed,
  });
  return true;
}

async function deleteSecret(id: string, field: string): Promise<void> {
  try {
    await invoke("secrets_delete", {
      service: RDP_KEYRING_SERVICE,
      account: rdpKeyringAccount(id, field),
    });
  } catch {
    // Already absent.
  }
}
