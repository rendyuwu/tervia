// Minimal Tauri runtime stub for vanilla-browser preview (vite dev).
// No-ops when the real Tauri runtime injects __TAURI_INTERNALS__ first.
// Backs @tauri-apps/plugin-store with localStorage so settings persist across
// reloads, and `fs_read_file` / `fs_write_file` the same way so the store files
// behind `lib/recoveredStore.ts` persist too. Other native commands resolve to
// undefined or empty: UI renders but native features (terminal, fs beyond those
// two commands, scm, ssh, dialog, updater, opener) stay inert.

declare global {
  interface Window {
    __TAURI_INTERNALS__?: TauriInternals;
  }
}

type InvokeArgs = Record<string, unknown> | undefined;
type Listener = (event: { event: string; id: number; payload: unknown }) => void;

interface TauriInternals {
  metadata: {
    currentWindow: { label: string };
    currentWebview: { label: string; windowLabel: string };
  };
  invoke: (cmd: string, args?: InvokeArgs, opts?: unknown) => Promise<unknown>;
  transformCallback: (cb?: (payload: unknown) => void, once?: boolean) => number;
  unregisterCallback?: (id: number) => void;
  convertFileSrc?: (path: string, protocol?: string) => string;
  plugins?: Record<string, unknown>;
}

if (typeof window !== "undefined" && !window.__TAURI_INTERNALS__) {
  console.warn(
    "[tauri-browser-shim] No Tauri runtime detected - installing stub APIs. " +
      "UI renders for preview only; native commands return empty results.",
  );

  const ua = navigator.userAgent.toLowerCase();
  const detectedPlatform: "windows" | "macos" | "linux" | "android" | "ios" = ua.includes("win")
    ? "windows"
    : ua.includes("mac")
      ? "macos"
      : ua.includes("android")
        ? "android"
        : ua.includes("iphone") || ua.includes("ipad")
          ? "ios"
          : "linux";

  // Backing storage for @tauri-apps/plugin-store: one bucket per store path,
  // serialized as JSON in localStorage.
  const STORE_PREFIX = "tervia:shim:store:";
  type StoreData = Record<string, unknown>;
  const loadStore = (path: string): StoreData => {
    try {
      return JSON.parse(localStorage.getItem(STORE_PREFIX + path) || "{}");
    } catch {
      return {};
    }
  };
  const saveStore = (path: string, data: StoreData): void => {
    try {
      localStorage.setItem(STORE_PREFIX + path, JSON.stringify(data));
    } catch {
      // Ignore quota or private mode failures.
    }
  };

  // The app data directory `appDataDir()` resolves to. A constant rather than
  // anything derived: nothing in a browser has one, and the only thing that
  // reads it is store path resolution, which needs a stable prefix and no more.
  // Without this, `plugin:path|resolve_directory` fell through to `null` and
  // `storeFilePaths` threw on `null.replace` - which recovery reported as an
  // "unreachable" store, one error toast per recovered store, at every launch.
  const PREVIEW_APP_DATA_DIR = "/tervia-preview";

  // Backing storage for `fs_read_file` / `fs_write_file`. A SECOND bucket beside
  // `STORE_PREFIX`, not the same one: the store plugin is keyed by bare file
  // name and these two commands are keyed by absolute path, so sharing a bucket
  // would make `tervia-hosts.json` and `/tervia-preview/tervia-hosts.json` two
  // names for one entry in one direction and none in the other.
  const FS_PREFIX = "tervia:shim:fs:";

  const handlePath = (op: string): unknown => {
    // Only the one op the store path needs. `join`, `basename` and the rest
    // still fall through to null, exactly as before.
    if (op === "resolve_directory") return PREVIEW_APP_DATA_DIR;
    return null;
  };

  const handleFsCommand = (cmd: string, args: InvokeArgs): unknown => {
    const a = (args ?? {}) as Record<string, unknown>;
    const path = String(a.path ?? "");
    if (cmd === "fs_read_file") {
      const content = localStorage.getItem(FS_PREFIX + path);
      // MUST reject rather than return null. The Rust command errors when
      // `metadata` fails, and `tauriStoreFileIo.read`'s catch is what turns that
      // into `{kind: "missing"}`. A null return would deserialise as an
      // `FsReadResult` with no `kind`, fall through that switch to
      // `{kind: "binary"}`, and recovery reads binary as a nul-filled file - so
      // a store file that is merely NEW would have a snapshot restored over it.
      if (content === null) throw new Error(`fs_read_file: ${path}: no such file or directory`);
      return { kind: "text", content, size: content.length };
    }
    // fs_write_file
    try {
      localStorage.setItem(FS_PREFIX + path, String(a.content ?? ""));
    } catch (e) {
      // Quota or private mode. Reject, like the real command does on a write it
      // could not make, so the caller reports it instead of believing it landed.
      throw e instanceof Error ? e : new Error(String(e));
    }
    return null;
  };

  // Assigns unique IDs to async-result callbacks that Tauri bindings register
  // for invoke completions and event subscriptions.
  const callbacks = new Map<number, (payload: unknown) => void>();
  let nextId = 1;
  const transformCallback = (cb?: (payload: unknown) => void, once = false): number => {
    const id = ++nextId;
    if (cb) {
      const wrapped = once
        ? (payload: unknown) => {
            callbacks.delete(id);
            cb(payload);
          }
        : cb;
      callbacks.set(id, wrapped);
    }
    return id;
  };
  const unregisterCallback = (id: number): void => {
    callbacks.delete(id);
  };

  // Event bus for plugin:event|listen/emit so React effects subscribing to
  // internal events don't reject. In-process only; Rust isn't running.
  const listeners = new Map<string, Set<{ id: number; cb: Listener }>>();

  const isPluginEvent = (cmd: string, op: string): boolean => cmd === `plugin:event|${op}`;

  const handleStore = (op: string, args: InvokeArgs): unknown => {
    const a = (args ?? {}) as Record<string, unknown>;
    const rid = String(a.rid ?? a.path ?? "");
    const key = String(a.key ?? "");

    switch (op) {
      case "load":
        return rid;
      case "get": {
        const data = loadStore(rid);
        const has = Object.prototype.hasOwnProperty.call(data, key);
        return has ? [data[key], true] : [null, false];
      }
      case "set": {
        const data = loadStore(rid);
        data[key] = a.value;
        saveStore(rid, data);
        return null;
      }
      case "has":
        return Object.prototype.hasOwnProperty.call(loadStore(rid), key);
      case "delete": {
        const data = loadStore(rid);
        const had = Object.prototype.hasOwnProperty.call(data, key);
        delete data[key];
        saveStore(rid, data);
        return had;
      }
      case "clear":
      case "reset":
        saveStore(rid, {});
        return null;
      case "keys":
        return Object.keys(loadStore(rid));
      case "values":
        return Object.values(loadStore(rid));
      case "entries":
        return Object.entries(loadStore(rid));
      case "length":
        return Object.keys(loadStore(rid)).length;
      case "save":
      case "close":
      case "reload":
        return null;
      default:
        return null;
    }
  };

  const handleEvent = (op: string, args: InvokeArgs): unknown => {
    const a = (args ?? {}) as Record<string, unknown>;
    const event = String(a.event ?? "");
    const handler = Number(a.handler ?? 0);

    if (op === "listen") {
      const cb = callbacks.get(handler);
      const id = ++nextId;
      if (cb) {
        const wrapped: Listener = (ev) => cb(ev);
        const set = listeners.get(event) ?? new Set();
        set.add({ id, cb: wrapped });
        listeners.set(event, set);
      }
      return id;
    }
    if (op === "unlisten") {
      const eventId = Number(a.eventId ?? 0);
      for (const [evt, set] of listeners) {
        for (const entry of set) {
          if (entry.id === eventId) {
            set.delete(entry);
            if (set.size === 0) listeners.delete(evt);
            return null;
          }
        }
      }
      return null;
    }
    if (op === "emit" || op === "emit_to") {
      const set = listeners.get(event);
      if (set) {
        for (const { id, cb } of set) {
          try {
            cb({ event, id, payload: a.payload });
          } catch {
            // Listener threw; keep dispatching.
          }
        }
      }
      return null;
    }
    return null;
  };

  const handleOs = (op: string): unknown => {
    switch (op) {
      case "platform":
        return detectedPlatform;
      case "version":
        return "0.0.0";
      case "family":
        return detectedPlatform === "windows" ? "windows" : "unix";
      case "arch":
        return "x86_64";
      case "locale":
        return navigator.language || "en-US";
      case "hostname":
        return location.hostname || "browser";
      case "eol":
        return detectedPlatform === "windows" ? "\r\n" : "\n";
      case "exe_extension":
        return detectedPlatform === "windows" ? "exe" : "";
      default:
        return null;
    }
  };

  const invoke = async (cmd: string, args?: InvokeArgs): Promise<unknown> => {
    // Tauri uses "plugin:<name>|<op>" for plugin commands and bare names for
    // app-defined IPC. Stub plugins imported during startup so React effects
    // don't reject; everything else returns null so callers fall back or fail
    // at the call site where the warning above explains what's missing.
    if (cmd.startsWith("plugin:store|")) {
      return handleStore(cmd.slice("plugin:store|".length), args);
    }
    if (cmd.startsWith("plugin:event|") || isPluginEvent(cmd, "listen")) {
      return handleEvent(cmd.slice("plugin:event|".length), args);
    }
    if (cmd.startsWith("plugin:os|")) {
      return handleOs(cmd.slice("plugin:os|".length));
    }
    if (cmd.startsWith("plugin:path|")) {
      return handlePath(cmd.slice("plugin:path|".length));
    }
    if (cmd === "fs_read_file" || cmd === "fs_write_file") {
      return handleFsCommand(cmd, args);
    }
    if (cmd.startsWith("plugin:window|") || cmd.startsWith("plugin:webview|")) {
      // show/hide/focus/setSize on the nonexistent Tauri window.
      return null;
    }
    if (cmd.startsWith("plugin:process|")) {
      return null;
    }
    if (cmd.startsWith("plugin:log|")) {
      return null;
    }
    if (cmd.startsWith("plugin:dialog|")) {
      // open/save/message/ask; null so callers treat as cancelled.
      return null;
    }
    if (cmd.startsWith("plugin:opener|")) {
      return null;
    }
    if (cmd.startsWith("plugin:autostart|")) {
      return cmd.endsWith("|is_enabled") ? false : null;
    }
    if (cmd.startsWith("plugin:updater|")) {
      return null;
    }
    if (cmd.startsWith("plugin:window-state|")) {
      return null;
    }
    // App-defined IPC commands (Rust #[tauri::command]); no Rust to call.
    return null;
  };

  window.__TAURI_INTERNALS__ = {
    metadata: {
      currentWindow: { label: "main" },
      currentWebview: { label: "main", windowLabel: "main" },
    },
    invoke,
    transformCallback,
    unregisterCallback,
    convertFileSrc: (path: string) => path,
    plugins: {},
  };

  // `@tauri-apps/api/event`'s `_unlisten` reaches for this global DIRECTLY, not
  // through `invoke`, so a shim that stubs only `invoke` leaves every
  // unsubscribe throwing on teardown - which is what an unmounting effect does
  // for every store listener at once. The real one drops the listener from the
  // plugin's own map; the `plugin:event|unlisten` call right after it is what
  // `handleEvent` above services, and that is where this shim's listeners
  // actually live - so this only has to exist and not throw. Declared by
  // `@tauri-apps/api` as required on `Window`, hence the cast rather than a
  // second declaration.
  (window as unknown as Record<string, unknown>).__TAURI_EVENT_PLUGIN_INTERNALS__ = {
    unregisterListener: () => {},
  };
}

export {};
