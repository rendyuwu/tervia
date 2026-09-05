import { emit, listen } from "@tauri-apps/api/event";
import { LazyStore } from "@tauri-apps/plugin-store";

import {
  recoverStoreFile,
  snapshotStoreFile,
  tauriStoreFileIo,
  type StoreFileIo,
  type StoreRecovery,
} from "./storeRecovery";

// A tauri-plugin-store file with crash recovery in front of it, parameterised.
//
// The ordering is the whole content of this file, and it is the part that is easy
// to get subtly wrong once per module: recover a torn file BEFORE the plugin is
// touched at all (`LazyStore` caches the promise of its load, so a read that came
// back empty has already lost), force the load while the file is known good, then
// snapshot what it loaded from - and snapshot again after every save, because at
// first load there is no file to copy. `modules/vault`, `modules/hosts` and
// `modules/forwards` differ only in a file name, a load key and an event name -
// so they take this rather than three copies of the same thirty-five lines.
//
// The serialised write queue is here for the same reason and not a smaller one: it
// exists to stop two read-modify-writes against ONE store file from losing an
// update, so a store layer holding its own queue and a second caller holding
// another would serialise nothing at all.
//
// Everything here is total the way `./storeRecovery` is total: a filesystem
// failure degrades to "carry on with the store as found, and report what went
// wrong". The failure that motivated it is worth naming - the settle pass runs
// once and its promise is cached, so a cached REJECTION would leave the store
// unreadable and unwritable for the rest of the process, on a profile where the
// good snapshot is sitting next to the broken primary.

/** Every store in this family is a `LazyStore` with this autosave. */
const AUTO_SAVE_MS = 200;

/**
 * The plugin store, narrowed to what this wrapper drives.
 *
 * Injectable because `scripts/*-verify.ts` runs under plain node with no Tauri
 * runtime, and the settle ordering above is exactly the thing worth pinning down
 * before a UI exists.
 */
export type KeyValueStore = {
  get<T>(key: string): Promise<T | undefined | null>;
  set(key: string, value: unknown): Promise<void>;
  save(): Promise<void>;
};

/** Cross-window notification, injectable for the same reason. */
export type StoreBroadcast = {
  emit(event: string): Promise<void>;
  listen(event: string, cb: () => void): Promise<() => void>;
};

/** What distinguishes one store in this family from another. */
export type RecoveredStoreSpec = {
  /** Store file name, resolved against the directory the plugin uses. */
  path: string;
  /** A key read once to force the plugin's load while the file is known good.
   *  Any key would do; naming a real one keeps the intent readable. */
  loadKey: string;
  /** Emitted after every commit so another window reloads instead of showing a
   *  stale list. */
  changedEvent: string;
};

/** Ports, all defaulted to the real thing. */
export type RecoveredStoreDeps = {
  store?: KeyValueStore;
  files?: StoreFileIo;
  broadcast?: StoreBroadcast;
};

/** Persistence with crash recovery, narrowed to what a store layer uses. */
export type RecoveredStoreIo = {
  get<T>(key: string): Promise<T | null>;
  set(key: string, value: unknown): Promise<void>;
  /** Flush, snapshot, and tell every window. One call because they always happen
   *  together: a write that skips the broadcast leaves a stale list in the other
   *  window, and one that skips the snapshot leaves the session that CREATED the
   *  file with no `.bak` at all. */
  commit(): Promise<void>;
  /**
   * Serialise one read-modify-write against this store.
   *
   * On the port rather than in each store layer because the queue only means
   * anything if there is exactly one of it per store file - see the module header.
   * Every mutation a store layer exposes should go through this.
   */
  enqueueWrite<T>(op: () => Promise<T>): Promise<T>;
  onChanged(cb: () => void): Promise<() => void>;
  /**
   * Run the recovery pass and the first load, then hand back whatever the user
   * should be told - once.
   *
   * The startup entry point. Every other method awaits the same pass, so
   * recovery is never skipped; what this adds is that the NOTICE is available at
   * a deterministic moment instead of depending on whether some read happened to
   * come first.
   */
  ensureLoaded(): Promise<StoreRecovery | null>;
  /**
   * The recovery notice, returned ONCE so a caller can toast it exactly once.
   * `src/lib` cannot import a toast, so the notice travels instead of the
   * dependency. Prefer {@link RecoveredStoreIo.ensureLoaded} at startup: this is
   * `null` until the settle pass has run.
   *
   * Startup is not the only thing that fills the slot. A `.bak` that could not be
   * written after a save lands here too, so a UI that reads this only once misses
   * the case where the safety net went away mid-session: drain it on
   * {@link RecoveredStoreIo.onChanged} as well.
   */
  takeRecoveryNotice(): StoreRecovery | null;
};

const tauriStoreBroadcast: StoreBroadcast = {
  emit: (event) => emit(event),
  listen: (event, cb) => listen(event, () => cb()),
};

function reason(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/**
 * A chain that runs one operation at a time, and stays alive through a rejection.
 *
 * Every store in this family mutates by read-modify-write (list, change one row,
 * persist), so two callers in the same tick both read the pre-write list and one
 * update is simply lost. On a page with inline edits that is the ordinary case -
 * one mutation fires per field the user leaves - and the integrity guards make a
 * rejection ordinary too, so a rejection must not take the later writes with it.
 *
 * Exported as well as used below so a store layer that assembles its own
 * {@link RecoveredStoreIo} gets the real thing rather than a fourth copy of it.
 */
export function createWriteQueue(): <T>(op: () => Promise<T>) => Promise<T> {
  let queue: Promise<unknown> = Promise.resolve();
  return <T>(op: () => Promise<T>): Promise<T> => {
    const run = queue.then(op, op);
    queue = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  };
}

export function createRecoveredStore(
  spec: RecoveredStoreSpec,
  deps: RecoveredStoreDeps = {},
): RecoveredStoreIo {
  const store = deps.store ?? new LazyStore(spec.path, { defaults: {}, autoSave: AUTO_SAVE_MS });
  const files = deps.files ?? tauriStoreFileIo;
  const broadcast = deps.broadcast ?? tauriStoreBroadcast;
  const enqueueWrite = createWriteQueue();

  let notice: StoreRecovery | null = null;
  let ready: Promise<void> | undefined;

  /**
   * Recover, load, snapshot - once, and without ever rejecting.
   *
   * Each step reports rather than throws, and the notes are collected into the
   * one notice slot: a snapshot that could not be written is worth saying even
   * when the load itself was fine, because it means the next crash has no net.
   */
  async function initialize(): Promise<void> {
    const recovery = await recoverStoreFile(spec.path, files);
    const notes = recovery.note ? [recovery.note] : [];

    let loaded = true;
    try {
      await store.get(spec.loadKey);
    } catch (e) {
      // The plugin itself is unusable. Say so and return normally: every later
      // `get` and `set` will fail with its own real error, which is far more
      // useful than all of them failing with this one forever.
      loaded = false;
      notes.push(`${spec.path} could not be loaded: ${reason(e)}`);
    }

    if (loaded) {
      const snapshot = await snapshotStoreFile(spec.path, files);
      if (snapshot.note) notes.push(snapshot.note);
    }

    if (notes.length > 0) {
      notice = { found: recovery.found, recovered: recovery.recovered, note: notes.join("; ") };
    }
  }

  const settle = (): Promise<void> => (ready ??= initialize());

  let snapshotting: Promise<void> | null = null;
  let snapshotAgain = false;
  /** The snapshot failure already reported, so a burst of commits against a
   *  directory that will not take one is a burst of copies, not of toasts.
   *  Cleared by a pass that works, so a fault that comes back is said again. */
  let reportedSnapshotNote: string | null = null;

  /**
   * Add to the notice slot instead of replacing it, so a post-startup note cannot
   * discard a recovery the caller has not taken yet.
   *
   * `found: "ok"` is not a guess: reaching here means `save()` had already put the
   * primary on disk. What failed is the copy beside it.
   */
  function addNote(note: string): void {
    notice = notice
      ? { ...notice, note: notice.note ? `${notice.note}; ${note}` : note }
      : { found: "ok", recovered: false, note };
  }

  /**
   * Snapshot the file the save just produced, coalescing concurrent callers.
   *
   * One pass at a time plus one trailing pass for whatever landed during it. A
   * page of inline edits fires one commit per field the user leaves, so a burst
   * costs two file copies instead of one each - and the LAST commit is still
   * covered, which a plain "skip while busy" would not guarantee.
   *
   * A failure goes into the notice slot, deduplicated. The startup pass is NOT
   * enough to make that redundant: on a fresh profile it has no primary to copy,
   * so it returns silently with nothing to report, and the `.bak` write can then
   * fail for a reason the primary write does not share - a Windows path length the
   * extra suffix crosses, a quota hit between the two writes. Without this the
   * user is simply never told the safety net is absent.
   */
  function snapshotAfterSave(): Promise<void> {
    if (snapshotting) {
      snapshotAgain = true;
      return snapshotting;
    }
    const pass = (async () => {
      try {
        do {
          snapshotAgain = false;
          const { note } = await snapshotStoreFile(spec.path, files);
          if (!note) reportedSnapshotNote = null;
          else if (note !== reportedSnapshotNote) {
            reportedSnapshotNote = note;
            addNote(note);
          }
        } while (snapshotAgain);
      } finally {
        snapshotting = null;
      }
    })();
    snapshotting = pass;
    return pass;
  }

  function takeRecoveryNotice(): StoreRecovery | null {
    const held = notice;
    notice = null;
    return held;
  }

  return {
    enqueueWrite,
    async get<T>(key: string): Promise<T | null> {
      await settle();
      return (await store.get<T>(key)) ?? null;
    },
    async set(key: string, value: unknown): Promise<void> {
      await settle();
      await store.set(key, value);
    },
    async commit(): Promise<void> {
      // Settle first even though `set` normally got here already: `commit` is on
      // the public port, and a commit-before-any-read would `save()` a store
      // whose load was never preceded by recovery - writing empty defaults over
      // a torn but recoverable file.
      await settle();
      await store.save();
      // Broadcast after the save so a window that reloads on it sees the bytes,
      // and snapshot the file the save just produced.
      await Promise.all([broadcast.emit(spec.changedEvent), snapshotAfterSave()]);
    },
    onChanged: (cb) => broadcast.listen(spec.changedEvent, cb),
    async ensureLoaded(): Promise<StoreRecovery | null> {
      await settle();
      return takeRecoveryNotice();
    },
    takeRecoveryNotice,
  };
}
