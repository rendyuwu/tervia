import { emit, listen } from "@tauri-apps/api/event";

import { createFileKeyValueStore } from "./fileKeyValueStore";
import {
  recoverStoreFile,
  snapshotStoreFile,
  tauriStoreFileIo,
  type StoreFileIo,
  type StoreFileState,
  type StoreRecovery,
} from "./storeRecovery";

// A JSON store file with crash recovery in front of it, parameterised.
//
// The ordering is the whole content of this file, and it is the part that is easy
// to get subtly wrong once per module: recover a torn file BEFORE the store is
// touched at all (the store caches what it read, so a read that came back empty
// has already lost), force the load while the file is known good, then snapshot
// what it loaded from - and snapshot again after every save, because at first
// load there is no file to copy. `modules/vault`, `modules/hosts`,
// `modules/forwards`, `modules/workspaces` and the CLI-agents store differ only
// in a file name, a load key and an event name - so they take this rather than
// five copies of the same thirty-five lines.
//
// The default store is `./fileKeyValueStore`, not `tauri-plugin-store`: the
// plugin cannot make a two-key commit one write, and `deleteGroup` in
// `modules/hosts/store.ts` is a genuine two-key commit. See that module for what
// the whole-file port buys and what it deliberately drops.
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

/**
 * The key/value layer, narrowed to what this wrapper drives.
 *
 * Injectable because `scripts/*-verify.ts` runs under plain node with no Tauri
 * runtime, and the settle ordering above is exactly the thing worth pinning down
 * before a UI exists.
 */
export type KeyValueStore = {
  get<T>(key: string): Promise<T | undefined | null>;
  set(key: string, value: unknown): Promise<void>;
  save(): Promise<void>;
  /**
   * Drop whatever this store cached, if it caches anything.
   *
   * Optional because an injected fake usually holds its map in the open and has
   * nothing to drop. The real one - `createFileKeyValueStore` - caches the whole
   * parsed file, and that cache is per webview, so a second window's commit is
   * invisible to it until this is called.
   */
  invalidate?(): void;
};

/** Cross-window notification, injectable for the same reason. */
export type StoreBroadcast = {
  emit(event: string): Promise<void>;
  listen(event: string, cb: () => void): Promise<() => void>;
};

/** What distinguishes one store in this family from another. */
export type RecoveredStoreSpec = {
  /** Store file name, resolved against `appDataDir()`. */
  path: string;
  /** A key read once to force the first load while the file is known good.
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
   *  file with no `.bak` at all.
   *
   *  Every `set` since the last commit lands in ONE atomic file replacement, so
   *  a multi-key write is all-or-nothing. `deleteGroup` in
   *  `modules/hosts/store.ts` is why that is worth stating: it drops a group and
   *  clears `groupId` on its members together, and half of that pair is a
   *  dangling reference. */
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
   * What the recovery pass found, once it has run. Never drains anything.
   *
   * Separate from {@link RecoveredStoreIo.ensureLoaded} because the two have
   * different audiences and only one of them may consume the notice: the UI
   * tells the user once, and a store layer deciding whether it is safe to write
   * a default over the file must be able to ask the same question without
   * racing that toast away. `modules/workspaces/store.ts` is the caller - it
   * seeds a workspace when the list comes back empty, and doing that over a file
   * that was merely unreadable is how saved workspaces get blanked.
   */
  fileState(): Promise<{ found: StoreFileState; recovered: boolean }>;
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
  // `files` first: the default store is backed by it.
  const files = deps.files ?? tauriStoreFileIo;
  const store = deps.store ?? createFileKeyValueStore(spec.path, files);
  const broadcast = deps.broadcast ?? tauriStoreBroadcast;
  const enqueueWrite = createWriteQueue();

  let notice: StoreRecovery | null = null;
  let ready: Promise<void> | undefined;
  /** The recovery verdict, kept whether or not there was anything to say. The
   *  notice slot cannot serve this: it is emptied by the first taker. */
  let verdict: { found: StoreFileState; recovered: boolean } = { found: "ok", recovered: false };

  /**
   * Recover, load, snapshot - once, and without ever rejecting.
   *
   * Each step reports rather than throws, and the notes are collected into the
   * one notice slot: a snapshot that could not be written is worth saying even
   * when the load itself was fine, because it means the next crash has no net.
   */
  async function initialize(): Promise<void> {
    const recovery = await recoverStoreFile(spec.path, files);
    verdict = { found: recovery.found, recovered: recovery.recovered };
    const notes = recovery.note ? [recovery.note] : [];

    // Subscribe BEFORE the first load, so the subscription exists before
    // `settle()` resolves and therefore before any read this wrapper serves. A
    // window that commits while this one is still starting up is then seen; a
    // subscription attached later would miss it and cache the pre-commit file
    // for as long as nothing else changed.
    //
    // The listener is never removed. There is one of these per store file per
    // WEBVIEW - the settings window builds its own, so two exist for the store
    // files it touches - and each lives as long as the store it belongs to.
    try {
      await broadcast.listen(spec.changedEvent, () => store.invalidate?.());
    } catch (e) {
      // Degrade rather than reject: without this the cache simply goes stale on
      // another window's write, which is worse than it was and not fatal.
      notes.push(`${spec.path} will not see other windows' changes: ${reason(e)}`);
    }

    let loaded = true;
    try {
      await store.get(spec.loadKey);
    } catch (e) {
      // The store layer itself is unusable. Say so and return normally: every
      // later `get` and `set` will fail with its own real error, which is far
      // more useful than all of them failing with this one forever.
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
   * Snapshot the file the save just produced, coalescing CONCURRENT callers.
   *
   * One pass at a time plus one trailing pass for whatever landed during it,
   * which is what keeps the LAST commit covered where a plain "skip while busy"
   * would not.
   *
   * MEASURE BEFORE CITING THIS AS A SAVING. It coalesces only callers that
   * overlap, and no live one does: `commit` awaits this, and every store layer
   * commits inside `enqueueWrite`, so `snapshotting` is always null by the time
   * the next pass starts. A queued burst of four commits costs four snapshot
   * passes, not one. The machinery is reachable through the public port - two
   * `commit()` calls not awaited, which the `[settle]` group does exercise - so
   * it is a real guard rather than dead code, but a comment that prices a burst
   * as one pass is describing a path nothing in `src/` takes. `modules/workspaces`
   * gets the burst saving people expect here, and gets it from its own `persist`
   * coalescer instead.
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
      //
      // Tauri v2 self-delivers `emit()`, so this window's own listener fires too
      // and drops the cache the save just wrote. That costs one extra file read
      // on the next get, and it is the right price: one rule ("a change event
      // means re-read") beats a writer that trusts its own cache and a reader
      // that does not.
      await Promise.all([broadcast.emit(spec.changedEvent), snapshotAfterSave()]);
    },
    /**
     * Subscribe to another window's commit, with the cache already dropped.
     *
     * The invalidation is repeated here rather than left to the listener
     * `initialize` registers, and it is worth being exact about what that buys,
     * because it is not dispatch order: both listeners run in one synchronous
     * pass and any read a consumer's callback starts settles after that pass, so
     * the internal one has already dropped the cache whichever Tauri calls
     * first. What this covers is the internal listener not EXISTING - a `listen`
     * that rejects at startup is reported rather than fatal, and without this a
     * webview that hit one would hold a cache nothing ever invalidates while its
     * reload callbacks kept firing normally.
     */
    onChanged: (cb) =>
      broadcast.listen(spec.changedEvent, () => {
        store.invalidate?.();
        cb();
      }),
    async ensureLoaded(): Promise<StoreRecovery | null> {
      await settle();
      return takeRecoveryNotice();
    },
    async fileState(): Promise<{ found: StoreFileState; recovered: boolean }> {
      await settle();
      return verdict;
    },
    takeRecoveryNotice,
  };
}
