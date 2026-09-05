import type { KeyValueStore } from "./recoveredStore";
import { storeFilePaths, type StoreFileIo, type StoreFileRead } from "./storeRecovery";

// A store file read and written whole, in place of `tauri-plugin-store`.
//
// The plugin saves with an in-place truncate plus write, so a multi-key commit
// is not one write and a crash between two of them leaves the file holding half
// an update - and a torn file is the failure `./storeRecovery` exists to clean
// up after. Reading and writing the WHOLE map through `fs_write_file` (which is
// `atomic::atomic_write`: stage into a sibling temp, `sync_all`, rename over the
// target) makes any number of `set`s followed by one `save()` a single atomic
// replacement. `deleteGroup` in `modules/hosts/store.ts` is the call site that
// needs it: it removes a group and clears `groupId` on its members in one
// `persist`, which the plugin could tear in half.
//
// What is deliberately absent: autosave, debounce, and retry. `set` touches
// nothing but the cache, and `save()` is the only thing that reaches disk, so
// there is exactly one moment a file changes and a caller can name it. A store
// layer that used to rely on a debounced retry behind a failed write no longer
// has one, and the comments at those call sites say so rather than implying a
// net that is gone.
//
// The cache is per webview. Nothing here notices another window's write on its
// own - `createRecoveredStore` drives {@link FileKeyValueStore.invalidate} from
// the change event, which is also why that method is on the type rather than
// hidden behind the `KeyValueStore` shape.

/** A whole-file store, plus the one thing its cache owner needs to say. */
export type FileKeyValueStore = KeyValueStore & {
  /**
   * Drop the cache. The next read re-reads the file.
   *
   * Cheap and total: it touches no filesystem and cannot fail, so a caller may
   * fire it from an event handler without a catch.
   */
  invalidate(): void;
};

/**
 * The parsed top level, or an empty map.
 *
 * Silent on anything unusable, and that is the division of labour rather than a
 * shortcut: `recoverStoreFile` has already run against this exact path by the
 * time anything here reads it, has already decided whether the snapshot was the
 * better copy, and has already produced the notice the user is shown. A second
 * complaint from this layer would be the same fault reported twice, in words
 * that name no file the first pair did not.
 */
function parseMap(read: StoreFileRead): Record<string, unknown> {
  if (read.kind !== "text") return {};
  try {
    const parsed: unknown = JSON.parse(read.content);
    if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) {
      return { ...(parsed as Record<string, unknown>) };
    }
  } catch {
    // Same as above: unparseable is recovery's answer to give, not this one's.
  }
  return {};
}

/**
 * A `KeyValueStore` backed by one JSON file, read whole and written whole.
 *
 * `fileName` is resolved with {@link storeFilePaths}, the same helper the
 * recovery pass uses, so the file this reads is by construction the file that
 * was checked and snapshotted.
 */
export function createFileKeyValueStore(fileName: string, files: StoreFileIo): FileKeyValueStore {
  let cache: Record<string, unknown> = {};
  let loaded = false;
  /** Bumped by `invalidate`, so a read already in flight when the file changed
   *  underneath it does not install what it found. */
  let generation = 0;
  /** The read in flight, shared: a store layer that lists two keys at once
   *  (`Promise.all([listGroups(), listHosts()])` in `modules/hosts/store.ts`)
   *  costs one file read rather than two. */
  let inFlight: Promise<void> | null = null;
  /**
   * Set when the last read REFUSED the file rather than not finding one.
   *
   * `fs_read_file` will not return a file over 10 MB, and the recovery pass
   * deliberately leaves such a file alone because it is real data rather than
   * corruption. Without this the same read would give an empty cache and the
   * next `save()` would write `{}` over it - the whole-file write turning a file
   * this layer merely cannot READ into a file it destroys. `missing` and
   * `binary` are NOT this case: recovery has already restored or reported them,
   * and coming up empty over either is the intended answer.
   */
  let refused: string | null = null;

  async function primaryPath(): Promise<string> {
    return storeFilePaths(await files.dir(), fileName).primary;
  }

  async function fill(): Promise<void> {
    // Loops instead of installing what it read: an `invalidate()` landing while
    // the read is in flight means these bytes are the PRE-change contents, and
    // caching them would leave this webview permanently behind the file. Each
    // turn of the loop awaits real IO, so it can only spin as fast as another
    // window commits.
    for (;;) {
      const gen = generation;
      const read = await files.read(await primaryPath());
      if (gen !== generation) continue;
      cache = parseMap(read);
      refused = read.kind === "toolarge" ? "it is too large to read" : null;
      loaded = true;
      return;
    }
  }

  function load(): Promise<void> {
    if (loaded) return Promise.resolve();
    return (inFlight ??= fill().finally(() => {
      inFlight = null;
    }));
  }

  return {
    async get<T>(key: string): Promise<T | undefined> {
      await load();
      return cache[key] as T | undefined;
    },
    /** Cache only. Nothing reaches disk until `save()`. */
    async set(key: string, value: unknown): Promise<void> {
      // Load first even though this writes nothing: a `set` on an unloaded cache
      // would make `save()` write a file holding this key alone, dropping every
      // other one the file already had.
      await load();
      cache[key] = value;
    },
    /** One `fs_write_file` of the whole map - the atomic replacement. */
    async save(): Promise<void> {
      await load();
      // A whole-file write can only be as good as the read it is built on.
      if (refused) throw new Error(`refusing to write ${fileName} over itself: ${refused}`);
      await files.write(await primaryPath(), JSON.stringify(cache));
    },
    invalidate(): void {
      generation++;
      loaded = false;
      cache = {};
      refused = null;
    },
  };
}
