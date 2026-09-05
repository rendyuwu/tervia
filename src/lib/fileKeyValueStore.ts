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
// nothing but memory, and `save()` is the only thing that reaches disk, so there
// is exactly one moment a file changes and a caller can name it. A store layer
// that used to rely on a debounced retry behind a failed write no longer has
// one, and the comments at those call sites say so rather than implying a net
// that is gone.
//
// TWO MAPS, NOT ONE, and that split is what makes the atomicity claim true. The
// cache is what the file said and is DROPPABLE: it is per webview, so another
// window's commit makes it wrong, and `createRecoveredStore` drives
// {@link FileKeyValueStore.invalidate} from the change event to say so. Pending
// holds what this session has `set` and NOT yet saved, and it survives an
// invalidation, because a change event is news about the file and says nothing
// about a commit this window is halfway through assembling. One map cost both
// halves of the guarantee: an event between the two `set`s of `deleteGroup`
// dropped the first one on the floor and wrote half the pair, and an event
// during `save()`'s own path resolution left `JSON.stringify` reading an emptied
// cache - so the commit wrote `{}`, and the snapshot after it copied `{}` over
// the last good `.bak`.

/**
 * How many times a read or a write rebuilds itself after the file changed under
 * it before it gives up and accepts a stale baseline.
 *
 * Small on purpose. The retry exists for the ordinary case - one other window
 * committing while this one is mid-operation, which clears on the next turn -
 * and not for a peer emitting faster than this process can do IO. Under that,
 * making progress with a slightly stale baseline beats not making progress.
 */
const CONTENDED_ATTEMPTS = 3;

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
  /** What the file said when it was last read. Dropped by `invalidate`. */
  let cache: Record<string, unknown> = {};
  /**
   * What this session has `set` since its last successful `save()`.
   *
   * Kept apart from the cache and NOT dropped by `invalidate`, so a commit being
   * assembled cannot be half-thrown-away by another window's news. It is also
   * what makes the "a failed `persist` is not rolled back because the record is
   * still in this session's view" reasoning in `modules/hosts/store.ts` and
   * `modules/vault/store.ts` actually true.
   */
  let pending: Record<string, unknown> = {};
  let loaded = false;
  /** Bumped by `invalidate`, so a read already in flight when the file changed
   *  underneath it does not install what it found. */
  let generation = 0;
  /** The read in flight, shared: a store layer that lists two keys at once
   *  (`Promise.all([listGroups(), listHosts()])` in `modules/hosts/store.ts`)
   *  costs one file read rather than two. */
  let inFlight: Promise<void> | null = null;
  /**
   * Set when the last read did not get to SEE the file, rather than finding
   * there was not one.
   *
   * Two reads land here. `fs_read_file` will not return a file over 10 MB, and
   * it rejects for a file that is there and would not open. Both leave the
   * contents unknown, and the recovery pass deliberately leaves both alone
   * because unknown contents may be perfectly good ones. Without this the same
   * read would give an empty cache and the next `save()` would write `{}` over
   * it - the whole-file write turning a file this layer merely cannot READ into
   * a file it destroys.
   *
   * `missing` and `binary` are NOT this case: recovery has already restored or
   * reported them, and coming up empty over either is the intended answer.
   */
  let refused: string | null = null;

  async function primaryPath(): Promise<string> {
    return storeFilePaths(await files.dir(), fileName).primary;
  }

  async function fill(): Promise<void> {
    // Retries instead of installing what it read: an `invalidate()` landing while
    // the read is in flight means these bytes are the PRE-change contents, and
    // caching them would leave this webview behind the file.
    //
    // BOUNDED, and the bound is the point. An unbounded loop here cannot be
    // starved by anything realistic - each turn awaits real IO - but "realistic"
    // is the wrong guarantee for a loop that would freeze `enqueueWrite` and
    // every mutation behind it rather than fail. Giving up installs the bytes
    // and leaves `loaded` FALSE, so a storm of change events degrades this to an
    // uncached store, which is slower and still correct, instead of a stuck one.
    for (let attempt = 1; ; attempt++) {
      const gen = generation;
      const read = await files.read(await primaryPath());
      const stale = gen !== generation;
      if (stale && attempt < CONTENDED_ATTEMPTS) continue;
      cache = parseMap(read);
      refused =
        read.kind === "toolarge"
          ? "it is too large to read"
          : read.kind === "unreadable"
            ? `it could not be read: ${read.reason}`
            : null;
      loaded = !stale;
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
      // An unsaved `set` is what this session should read back, so pending wins.
      // Checked before the load as well as after: before, so a key this session
      // just wrote costs no file read at all; after, because `load()` yields and
      // another caller can `set` across it.
      if (key in pending) return pending[key] as T | undefined;
      await load();
      return (key in pending ? pending[key] : cache[key]) as T | undefined;
    },
    /**
     * Remember the value. Nothing reaches disk, and nothing is read either.
     *
     * Deliberately does NOT load first. It used to, so that `save()` would not
     * write a file holding this key alone - but with the pending map that is no
     * longer what stops it (`save` loads), and loading here was the whole of the
     * torn-pair bug: an `invalidate()` between two `set`s made the second one's
     * `load()` re-read the file and drop the first one's value.
     */
    // eslint-disable-next-line @typescript-eslint/require-await -- the port is async.
    async set(key: string, value: unknown): Promise<void> {
      pending[key] = value;
    },
    /** One `fs_write_file` of the whole map - the atomic replacement. */
    async save(): Promise<void> {
      for (let attempt = 1; ; attempt++) {
        await load();
        // A whole-file write can only be as good as the read it is built on.
        if (refused) throw new Error(`refusing to write ${fileName} over itself: ${refused}`);

        // Build the payload BEFORE the last await, and re-check afterwards.
        // Both halves matter, and the first one is not a style preference:
        // argument evaluation is left to right, so `write(await path(), stringify(cache))`
        // stringifies AFTER the path resolves - and `dir()` is a real IPC round
        // trip, wide enough for a change event to empty the cache inside it. The
        // commit then wrote `{}`, and `snapshotAfterSave` called that `"ok"` and
        // copied it over the last good `.bak`.
        //
        // NOTHING MAY AWAIT between `load()` resolving and the `JSON.stringify`
        // below. `invalidate()` only ever runs from a Tauri event, which is a
        // macrotask, so the microtask checkpoint at `await load()` cannot run it
        // - that is the whole reason the payload is safe here, and an `await`
        // inserted into this gap would silently reopen the `{}` path.
        const gen = generation;
        // The exact keys this write carries. A `set` landing during the awaits
        // below joins `pending` but NOT this payload, so clearing `pending`
        // wholesale afterwards would drop that value unwritten while folding it
        // into `cache`, where it would then claim to be what the file says.
        const writing = { ...pending };
        const payload = JSON.stringify({ ...cache, ...writing });
        const path = await primaryPath();
        if (gen !== generation && attempt < CONTENDED_ATTEMPTS) {
          // The file changed under us. Re-read and rebuild rather than write a
          // payload whose baseline is stale: this session's own pending keys
          // still win, and the other window's other keys survive.
          //
          // Bounded for the reason `fill` is. Giving up writes this session's
          // pending keys over a stale baseline, which LOSES another window's
          // update - specifically, every commit landing between the last
          // completed read and this write, which is a time window rather than a
          // fixed count. Never a `{}`: the payload is built from a cache that a
          // completed read installed.
          //
          // This is a mode `tauri-plugin-store` did NOT have, and saying so
          // rather than implying the cost was already accepted: the plugin keyed
          // its collection by resolved path and handed both webviews the same
          // `StoreInner`, so one in-memory map served both and neither could
          // lose the other's key. It had the tearing this port exists to remove
          // instead. A whole-file store per webview trades that for this.
          continue;
        }
        await files.write(path, payload);
        // What was WRITTEN is now what the file says. A key whose pending value
        // changed while this write was in flight is newer than the bytes on
        // disk, so it stays pending and the next save carries it - dropping it
        // here is how a value the UI shows as saved ends up nowhere.
        //
        // An `invalidate()` that landed during the write leaves `loaded` false,
        // and the next read picks these bytes up from disk.
        Object.assign(cache, writing);
        for (const key of Object.keys(writing)) {
          // Reference identity, so "still the value that went out" holds only
          // for values not mutated in place. Nothing reaches it - every store
          // layer builds a fresh array - and a caller that mutated an array it
          // had already handed to `set` would lose the mutation at the
          // `JSON.stringify` above regardless of what happens here.
          if (Object.is(pending[key], writing[key])) delete pending[key];
        }
        return;
      }
    },
    invalidate(): void {
      generation++;
      loaded = false;
      cache = {};
      refused = null;
    },
  };
}
