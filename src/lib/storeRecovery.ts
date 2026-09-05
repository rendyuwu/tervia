import { invoke } from "@tauri-apps/api/core";
import { appDataDir } from "@tauri-apps/api/path";

import type { FsReadResult } from "./ipc";

// Crash recovery for a JSON store file.
//
// The failure this exists for: a store file left zero-length or nul-filled by a
// power cut (plugins-workspace#3085) comes back as an EMPTY store, because a
// store layer that cannot parse the file has nothing else to report, and the
// next save writes that emptiness over whatever was left of it.
//
// Survivable for a saved layout or a theme. Not survivable for credentials: the
// secret store writes atomically, so a lost store file leaves the private key in
// the keychain with no record naming it - bytes no code path can enumerate or
// delete.
//
// The mitigation is a check before the first read plus a `.bak` snapshot after
// each good SAVE - not after each good load, which would leave the session that
// CREATES the file with no snapshot at all, since at first load there is nothing
// to copy. It needs no new Rust: `fs_read_file` and `fs_write_file` already exist,
// and the latter goes through the app's own atomic temp-plus-rename path.
//
// WHICH FILES. Five of the app's six store files go through `createRecoveredStore`
// and therefore through here: hosts, vault, forwards, workspaces and the CLI
// agents. `tervia-settings.json` is the sixth and does NOT - it is still read and
// written by `tauri-plugin-store` (2.4.3, per `src-tauri/Cargo.lock` and
// `pnpm-lock.yaml`; a comment here long said 2.4.4, which was never a version this
// repository pinned), whose `StoreBuilder::build` swallows the load
// error of a file it cannot parse (`let _ = store_inner.load()`) and whose save is
// `fs::create_dir_all` + `fs::write`, an in-place truncate with no temp file, no
// rename and no fsync. `KNOWN-LIMITS.md` records why that one stayed, and what
// would change the answer.
//
// EVERY function here is total: it reports a filesystem it could not work with
// instead of rejecting. A caller that caches the promise of this work - which is
// the only sane way to run it once - would otherwise cache a REJECTION, and then
// a single transient failure disables the store for the rest of the process. The
// module whose whole purpose is coping with a filesystem in a bad state must not
// fail worse than not having it.
//
// One platform detail worth spelling out: a store path resolves against
// `BaseDirectory::AppData` (the plugin's `resolve_store_path`), which is
// `appDataDir()` here. Secrets resolve against `app_local_data_dir()`. Those are
// the same directory on Linux and DIFFERENT ones on Windows, so nothing here may
// be reused to reach a secret file.

/** Snapshot taken beside the store file it protects. */
export const SNAPSHOT_SUFFIX = ".bak";

/**
 * How a store file looks on disk.
 *
 * `"ok"` is the only trustworthy answer. `"missing"`, `"empty"`, `"nul"` and
 * `"unparseable"` all mean the snapshot should be preferred. The last THREE mean
 * nothing can be decided, so nothing may be written over the primary either:
 * `"toolarge"` is a file `fs_read_file` will not return for its size,
 * `"unreadable"` is one it would not open at all, and `"unreachable"` is the
 * data directory itself failing.
 */
export type StoreFileState =
  "ok" | "missing" | "empty" | "nul" | "unparseable" | "toolarge" | "unreadable" | "unreachable";

/**
 * One file as the host process can see it.
 *
 * `binary` is what `fs_read_file` reports for a nul-filled file: its null-byte
 * sniff classifies the buffer as binary rather than returning the bytes, and
 * that classification IS the corruption being looked for. An `image`
 * classification lands here too - unreachable for a `.json` path in practice,
 * but it is the same "bytes where JSON should be" class.
 *
 * `toolarge` is deliberately NOT folded in with it. A 10 MB store file is real
 * data the plugin reads fine; calling it corruption would restore a snapshot
 * over it.
 *
 * `unreadable` is the same distinction one step further out, and it exists
 * because folding it into `missing` is a data-loss bug rather than a rounding
 * error: a file that is THERE and would not open (a lock during an update
 * handoff, a sharing violation, EACCES, a descriptor limit) must not be treated
 * as a first run. Everything downstream writes over a first run - the recovery
 * pass would restore a snapshot, the store layer would come up empty and save
 * that emptiness, and `modules/workspaces/store.ts` would persist a seeded
 * default. `missing` therefore means "the OS said there is no such file", never
 * "the read did not work out".
 */
export type StoreFileRead =
  | { kind: "text"; content: string }
  | { kind: "binary" }
  | { kind: "toolarge" }
  | { kind: "unreadable"; reason: string }
  | { kind: "missing" };

/**
 * The filesystem operations recovery needs.
 *
 * An injectable port because `scripts/*-verify.ts` runs under plain node with no
 * Tauri runtime, and a torn store file - or a write that fails - is the one thing
 * here that cannot be reproduced by hand on a real machine.
 */
export type StoreFileIo = {
  /** Directory tauri-plugin-store resolves a store path against. */
  dir(): Promise<string>;
  read(path: string): Promise<StoreFileRead>;
  /**
   * Write `content` over `path`, creating or replacing it.
   *
   * A write rather than a copy, on purpose. `fs_copy` refuses an existing target
   * (`fs/mutate.rs:85`), so copying meant unlinking first - and a delete that
   * fails (an antivirus or indexer holding the handle on Windows, a read-only
   * data directory) turned "the good snapshot is sitting right there" into an
   * `already exists` error. Both callers here have already READ and validated the
   * bytes they want in place, so `fs_write_file` does the whole job in one
   * command, through the app's atomic temp-plus-rename path.
   */
  write(path: string, content: string): Promise<void>;
};

export type StoreRecovery = {
  /**
   * What the primary looked like before anything was done to it, with ONE
   * deliberate exception: an absent primary beside a snapshot that could not be
   * read reports `"unreadable"` rather than `"missing"`, because the pair's
   * verdict is what a caller acts on and "there is nothing here" was not
   * established. See the branch in `recover` for what acting on the wrong one
   * costs.
   */
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

/** What one snapshot attempt did. */
export type StoreSnapshot = {
  /** True when the snapshot was written. False when the primary was not good
   *  enough to copy - which is the guard working, not a failure. */
  taken: boolean;
  /** Set only when the snapshot could not be WRITTEN, so a caller can say that
   *  the safety net is missing rather than assume it is there. */
  note?: string;
};

function reason(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/**
 * Where a store file and its snapshot live.
 *
 * Exported because `lib/fileKeyValueStore.ts` resolves the SAME primary path to
 * read and write it. Two derivations of `${dir}/${fileName}` would be two
 * conventions, and the day they disagreed the recovery pass would be checking a
 * different file from the one the store reads.
 */
export function storeFilePaths(
  dir: string,
  fileName: string,
): { primary: string; snapshot: string } {
  // `appDataDir()` carries no trailing separator today; normalise anyway so a
  // future change cannot produce a double slash. Forward slashes are fine on
  // Windows - Rust's `PathBuf` accepts either.
  const primary = `${dir.replace(/[\\/]+$/, "")}/${fileName}`;
  return { primary, snapshot: primary + SNAPSHOT_SUFFIX };
}

function inspect(read: StoreFileRead): StoreFileState {
  if (read.kind === "missing") return "missing";
  if (read.kind === "binary") return "nul";
  if (read.kind === "toolarge") return "toolarge";
  if (read.kind === "unreadable") return "unreadable";
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
 * MUST run before the store is first touched. Every store layer over this one
 * caches what its first read found, so by the time a read comes back empty the
 * store has already decided the file was worthless and the next save writes
 * that emptiness over it.
 *
 * Never rejects - see the module header.
 */
export async function recoverStoreFile(
  fileName: string,
  io: StoreFileIo = tauriStoreFileIo,
): Promise<StoreRecovery> {
  try {
    return await recover(fileName, io);
  } catch (e) {
    return {
      found: "unreachable",
      recovered: false,
      note: `${fileName} could not be checked: ${reason(e)}`,
    };
  }
}

async function recover(fileName: string, io: StoreFileIo): Promise<StoreRecovery> {
  const { primary, snapshot } = storeFilePaths(await io.dir(), fileName);
  const primaryRead = await io.read(primary);
  const found = inspect(primaryRead);
  if (found === "ok") return { found, recovered: false };
  if (primaryRead.kind === "unreadable") {
    // The file is THERE and would not open. Its bytes are unknown, so they may
    // be perfectly good - which makes restoring a snapshot over them the same
    // destruction as restoring over a too-large file, for the same reason: a
    // read this app could not make is not evidence about the contents.
    return {
      found,
      recovered: false,
      note: `${fileName} could not be read, so it was left as it is: ${primaryRead.reason}`,
    };
  }
  if (found === "toolarge") {
    // Not corruption: the plugin has no size limit and reads this fine. Say so
    // and stop - restoring a snapshot over it would destroy real data.
    return {
      found,
      recovered: false,
      note: `${fileName} is too large to check for corruption; left as it is`,
    };
  }

  const backup = await io.read(snapshot);
  const fallback = inspect(backup);
  if (backup.kind !== "text" || fallback !== "ok") {
    // Both absent is a first run, not a loss: say nothing.
    if (found === "missing" && fallback === "missing") return { found, recovered: false };
    // An absent primary beside a snapshot that could not be READ is NOT a first
    // run, and reporting it as one is a data-loss path rather than a wording
    // choice: a caller that seeds a default on "missing" persists it, and the
    // snapshot taken after that commit copies the default over the very `.bak`
    // whose contents nothing here ever saw. So the pair's verdict is the
    // snapshot's, which is the only honest thing to say - nothing was
    // established about what is here.
    if (found === "missing" && (fallback === "unreadable" || fallback === "toolarge")) {
      return {
        found: "unreadable",
        recovered: false,
        note: `${fileName} is missing and its snapshot is ${fallback}, so nothing here could be checked`,
      };
    }
    return {
      found,
      recovered: false,
      note: `${fileName} is ${found} and its snapshot is ${fallback}`,
    };
  }

  // The snapshot is metadata from the last process start; the SECRET store is
  // atomic and therefore current. So a restore can leave the two disagreeing: a
  // key whose fingerprint was rotated after the snapshot comes back naming the
  // OLD fingerprint while the keychain holds the new PEM, and the import dedupe
  // is on fingerprint - so importing the original key would "find" that record
  // and bind a host to the wrong material. Presence flags drift the same way,
  // permanently, because they are deliberately never read back. Nothing here
  // reconciles the two, and nothing above it does either.
  try {
    await io.write(primary, backup.content);
  } catch (e) {
    return {
      found,
      recovered: false,
      note: `${fileName} is ${found} and could not be restored from ${fileName}${SNAPSHOT_SUFFIX}: ${reason(e)}`,
    };
  }
  return {
    found,
    recovered: true,
    note: `${fileName} was ${found}; restored from ${fileName}${SNAPSHOT_SUFFIX}`,
  };
}

/**
 * Snapshot a store file that is currently good.
 *
 * The one thing this must never do is copy a torn primary over the last good
 * copy, which would turn a recoverable crash into a total loss - hence the
 * inspect before the write, and hence a caller may fire this after any save
 * without checking anything first.
 *
 * Never rejects - see the module header.
 */
export async function snapshotStoreFile(
  fileName: string,
  io: StoreFileIo = tauriStoreFileIo,
): Promise<StoreSnapshot> {
  try {
    const { primary, snapshot } = storeFilePaths(await io.dir(), fileName);
    const read = await io.read(primary);
    if (read.kind !== "text" || inspect(read) !== "ok") return { taken: false };
    await io.write(snapshot, read.content);
    return { taken: true };
  } catch (e) {
    return {
      taken: false,
      note: `${fileName}${SNAPSHOT_SUFFIX} could not be written: ${reason(e)}`,
    };
  }
}

export const tauriStoreFileIo: StoreFileIo = {
  dir: () => appDataDir(),
  read: async (path) => {
    try {
      const result = await invoke<FsReadResult>("fs_read_file", { path });
      switch (result.kind) {
        case "text":
          return { kind: "text", content: result.content };
        case "toolarge":
          return { kind: "toolarge" };
        default:
          return { kind: "binary" };
      }
    } catch (e) {
      // `fs_read_file` rejects for BOTH "there is no such file" and "there is a
      // file and it would not open", so the two have to be told apart here or
      // not at all - and telling them apart is the whole of what stops a file
      // that merely would not open being written over as though it were a first
      // run.
      //
      // Rust's `io::Error` Display always appends `(os error N)` for an OS
      // error, on every platform, whatever the localised text before it says.
      // 2 is ENOENT and Windows' ERROR_FILE_NOT_FOUND; 3 is Windows'
      // ERROR_PATH_NOT_FOUND. Anything else - EACCES, a sharing violation, a
      // descriptor limit, the command's own join error - is a file we did not
      // get to see.
      //
      // The unrecognised case falls to `unreadable`, which is the safe
      // direction: the cost of calling a first run unreadable is that a default
      // is not written until the first real change, and the cost of the reverse
      // is the file.
      // Anchored to the END, which `to_string()` always is. Unanchored would
      // match the suffix appearing anywhere in some future wrapped message, and
      // that is the direction that turns an unreadable file back into a first
      // run - the failure this whole distinction exists to prevent.
      const message = reason(e);
      return /\(os error (?:2|3)\)$/.test(message.trim())
        ? { kind: "missing" }
        : { kind: "unreadable", reason: message };
    }
  },
  write: (path, content) => invoke<void>("fs_write_file", { path, content }),
};
