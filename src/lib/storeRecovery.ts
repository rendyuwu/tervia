import { invoke } from "@tauri-apps/api/core";
import { appDataDir } from "@tauri-apps/api/path";

import type { FsReadResult } from "./ipc";

// Crash recovery for a tauri-plugin-store JSON file.
//
// The plugin (2.4.4) saves with `fs::create_dir_all` + `fs::write` - an in-place
// truncate, no temp file, no rename, no fsync - and `StoreBuilder::build`
// SWALLOWS the load error of a file it cannot parse (`let _ = store_inner.load()`).
// Those two together are what makes the failure silent: a store file left
// zero-length or nul-filled by a power cut (plugins-workspace#3085) comes back as
// an EMPTY store, and the next autosave writes that emptiness over whatever was
// left of it.
//
// Survivable for a saved layout or a theme. Not survivable for credentials: the
// secret store writes atomically, so a lost store file leaves the private key in
// the keychain with no record naming it - bytes no code path can enumerate or
// delete.
//
// The mitigation is a `.bak` snapshot after each good load plus a check before
// the first read, and it needs no new Rust: `fs_read_file`, `fs_copy` and
// `fs_delete` already exist.
//
// One platform detail worth spelling out: a store path resolves against
// `BaseDirectory::AppData` (the plugin's `resolve_store_path`), which is
// `appDataDir()` here. Secrets resolve against `app_local_data_dir()`. Those are
// the same directory on Linux and DIFFERENT ones on Windows, so nothing here may
// be reused to reach a secret file.

/** Snapshot taken beside the store file it protects. */
export const SNAPSHOT_SUFFIX = ".bak";

/** How a store file looks on disk. Anything but `"ok"` means the primary cannot
 *  be trusted and the snapshot should be preferred. */
export type StoreFileState = "ok" | "missing" | "empty" | "nul" | "unparseable";

/**
 * One file as the host process can see it.
 *
 * `unreadable` is what `fs_read_file` reports for a nul-filled file: its
 * null-byte sniff classifies the buffer as binary rather than returning the
 * bytes, and that classification IS the corruption being looked for.
 */
export type StoreFileRead =
  { kind: "text"; content: string } | { kind: "unreadable" } | { kind: "missing" };

/**
 * The three filesystem operations recovery needs.
 *
 * An injectable port because `scripts/*-verify.ts` runs under plain node with no
 * Tauri runtime, and a torn store file is the one thing here that cannot be
 * reproduced by hand on a real machine.
 */
export type StoreFileIo = {
  /** Directory tauri-plugin-store resolves a store path against. */
  dir(): Promise<string>;
  read(path: string): Promise<StoreFileRead>;
  /** Byte copy that REPLACES `to`. `fs_copy` refuses an existing target, so the
   *  Tauri implementation unlinks first. */
  replace(from: string, to: string): Promise<void>;
};

export type StoreRecovery = {
  /** What the primary looked like before anything was done to it. */
  found: StoreFileState;
  /** True when the snapshot was copied over the primary. */
  recovered: boolean;
  /**
   * Worth telling the user about, or absent when nothing is. A caller shows this
   * as a toast; `src/lib` deliberately does not import one, so the notice travels
   * instead of the dependency.
   */
  note?: string;
};

/** Where a store file and its snapshot live. */
function paths(dir: string, fileName: string): { primary: string; snapshot: string } {
  // `appDataDir()` carries no trailing separator today; normalise anyway so a
  // future change cannot produce a double slash. Forward slashes are fine on
  // Windows - Rust's `PathBuf` accepts either.
  const primary = `${dir.replace(/[\\/]+$/, "")}/${fileName}`;
  return { primary, snapshot: primary + SNAPSHOT_SUFFIX };
}

function inspect(read: StoreFileRead): StoreFileState {
  if (read.kind === "missing") return "missing";
  if (read.kind === "unreadable") return "nul";
  // `trim` does not strip U+0000, so an all-nul buffer falls through to the
  // check below rather than reading as merely empty.
  if (read.content.trim() === "") return "empty";
  if (/^\0+$/.test(read.content)) return "nul";
  try {
    const parsed: unknown = JSON.parse(read.content);
    // A store file's top level is the key/value map, so an array or a bare
    // scalar is as unusable as a syntax error - and far likelier to be the tail
    // of a torn write that happened to parse.
    const usable = parsed !== null && typeof parsed === "object" && !Array.isArray(parsed);
    return usable ? "ok" : "unparseable";
  } catch {
    return "unparseable";
  }
}

/**
 * Put a usable store file in place, or report why there isn't one.
 *
 * MUST run before the store is first touched. `LazyStore` caches the promise of
 * its load, so by the time a read comes back empty the plugin has already
 * decided the file was worthless and the next autosave will overwrite it.
 */
export async function recoverStoreFile(
  fileName: string,
  io: StoreFileIo = tauriStoreFileIo,
): Promise<StoreRecovery> {
  const { primary, snapshot } = paths(await io.dir(), fileName);
  const found = inspect(await io.read(primary));
  if (found === "ok") return { found, recovered: false };

  const fallback = inspect(await io.read(snapshot));
  if (fallback !== "ok") {
    // Both absent is a first run, not a loss: say nothing.
    if (found === "missing" && fallback === "missing") return { found, recovered: false };
    return {
      found,
      recovered: false,
      note: `${fileName} is ${found} and its snapshot is ${fallback}`,
    };
  }

  await io.replace(snapshot, primary);
  return {
    found,
    recovered: true,
    note: `${fileName} was ${found}; restored from ${fileName}${SNAPSHOT_SUFFIX}`,
  };
}

/**
 * Snapshot a store file that has just loaded cleanly.
 *
 * Taken after the LOAD rather than after every save, which with `LazyStore`
 * means once per process: the snapshot is the state the app started from, so a
 * torn write costs this session's edits and nothing older. Exported so a caller
 * that wants a fresher one can take it after a save.
 */
export async function snapshotStoreFile(
  fileName: string,
  io: StoreFileIo = tauriStoreFileIo,
): Promise<void> {
  const { primary, snapshot } = paths(await io.dir(), fileName);
  if (inspect(await io.read(primary)) !== "ok") return;
  await io.replace(primary, snapshot);
}

export const tauriStoreFileIo: StoreFileIo = {
  dir: () => appDataDir(),
  read: async (path) => {
    try {
      const result = await invoke<FsReadResult>("fs_read_file", { path });
      return result.kind === "text"
        ? { kind: "text", content: result.content }
        : { kind: "unreadable" };
    } catch {
      // Absent, or unreadable for a reason we cannot act on. Either way there is
      // nothing here to trust.
      return { kind: "missing" };
    }
  },
  replace: async (from, to) => {
    try {
      await invoke("fs_delete", { path: to });
    } catch {
      // Nothing there to unlink.
    }
    await invoke("fs_copy", { from, to });
  },
};
