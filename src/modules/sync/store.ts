// Sync's own settings file: the configuration, the etag map, and the status the
// settings window renders.
//
// ITS OWN FILE, never a key inside another store's. `fileKeyValueStore.ts`
// records that a contended write eventually gives up and writes this session's
// pending keys over a stale baseline, so every key a store writes is a key it
// can clobber - and a pull writes the etag map on every run. Putting that beside
// the host list would put the host list inside the blast radius of a background
// pull.
//
// NO CREDENTIALS AND NO PASSPHRASE. This is plain JSON in the app data
// directory beside the host list; the secret half goes to the keychain under
// `SYNC_KEYRING_SERVICE`.

import type { FileKeyValueStore } from "@/lib/fileKeyValueStore";

import {
  DEFAULT_SYNC_CONFIG,
  EMPTY_SYNC_STATUS,
  SYNC_CONFIG_KEY,
  SYNC_DIRTY_KEY,
  SYNC_ETAGS_KEY,
  SYNC_STATUS_KEY,
  type SyncConfig,
  type SyncStatus,
} from "./types";

/**
 * Persistence for this module, injected.
 *
 * No crash recovery in front of it, unlike the three record stores, and that is
 * a decision rather than an omission: nothing here is user-authored. A torn
 * configuration costs the user one re-entry in settings, and a torn etag map
 * costs one full inventory download - both recoverable by doing the thing
 * again, which is what `tervia-settings.json` already accepts for the same
 * reason.
 */
export type SyncStoreIo = FileKeyValueStore;

/**
 * Every operation this module's two windows perform on that file.
 *
 * NO `invalidate` ON THIS PORT, deliberately: every method below already drops
 * the cache before it runs, so exposing one would be an invitation to call it
 * somewhere and conclude the rest did not need to.
 */
export type SyncSettingsStore = {
  readConfig(): Promise<SyncConfig>;
  /**
   * Store what the settings window collected.
   *
   * THE ONE KEY THE SETTINGS WINDOW WRITES, and `main` writes none of it - see
   * `SYNC_CONFIG_KEY` for why the four keys are separate. Two windows writing
   * one blob here would make a status write from `main` able to roll back a
   * configuration the user just typed.
   */
  writeConfig(config: SyncConfig): Promise<void>;
  /** `kind:id` to etag, as `sync_pull` returned it. */
  readEtags(): Promise<Record<string, string>>;
  writeEtags(etags: Record<string, string>): Promise<void>;
  /**
   * The `kind:id` slots this device still owes the remote.
   *
   * DURABLE, and that is not tidiness. An etag-skipped object hides this
   * device's local edit from the reconcile entirely - the pull sees the remote
   * copy has not moved and skips the local copy with it - so the dirty set is
   * the only thing carrying a local edit across a restart. In memory alone, a
   * quit inside the five-second debounce loses the edit with no error, no
   * failed request, and a pending count of zero.
   */
  readDirty(): Promise<string[]>;
  writeDirty(slots: string[]): Promise<void>;
  readStatus(): Promise<SyncStatus>;
  writeStatus(status: SyncStatus): Promise<void>;
};

/** A stored value that survived a hand edit of the file, or the default.
 *  Shape-checked rather than cast: this reads a file a user can open. */
function object<T extends object>(raw: unknown, fallback: T): T {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return fallback;
  return { ...fallback, ...(raw as Partial<T>) };
}

export function createSyncSettingsStore(io: SyncStoreIo): SyncSettingsStore {
  /**
   * Drop the cache, then do the thing.
   *
   * EVERY METHOD GOES THROUGH HERE, reads and writes alike, and it is one
   * wrapper rather than a line in each body so that a method added later cannot
   * be the one that forgets.
   *
   * On a READ it is what makes the other window's write visible: this file is
   * the only store two webviews write, and nothing broadcasts a change event
   * for it, so a cached copy is otherwise frozen at whatever the file said when
   * this webview launched.
   *
   * On a WRITE it is what stops this window putting that frozen copy back.
   * `createFileKeyValueStore` writes the whole map, built from its cache plus
   * this session's pending keys - so a status write from a background pull,
   * built on a baseline read before the user pressed Save, silently reverts the
   * configuration they just entered. Dropping the cache immediately before
   * forces the payload to be built on what the file says NOW, and the pending
   * key being written survives an invalidation by design.
   *
   * The cost is one small file read per operation, a few per minute at most. It
   * buys the correctness a cross-window change event would buy, without a
   * second event to keep in step.
   */
  async function fresh<T>(op: () => Promise<T>): Promise<T> {
    io.invalidate();
    return op();
  }

  return {
    readConfig: () => fresh(async () => object(await io.get(SYNC_CONFIG_KEY), DEFAULT_SYNC_CONFIG)),
    writeConfig: (config) =>
      fresh(async () => {
        await io.set(SYNC_CONFIG_KEY, config);
        await io.save();
      }),
    readEtags: () =>
      fresh(async () => {
        const raw = await io.get(SYNC_ETAGS_KEY);
        if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return {};
        // Every value, not just the map - a hand-edited file can hold anything,
        // and a non-string etag would be sent back as an `If-Match`.
        const out: Record<string, string> = {};
        for (const [key, value] of Object.entries(raw as Record<string, unknown>)) {
          if (typeof value === "string") out[key] = value;
        }
        return out;
      }),
    writeEtags: (etags) =>
      fresh(async () => {
        await io.set(SYNC_ETAGS_KEY, etags);
        await io.save();
      }),
    readDirty: () =>
      fresh(async () => {
        const raw = await io.get(SYNC_DIRTY_KEY);
        return Array.isArray(raw) ? raw.filter((s): s is string => typeof s === "string") : [];
      }),
    writeDirty: (slots) =>
      fresh(async () => {
        await io.set(SYNC_DIRTY_KEY, slots);
        await io.save();
      }),
    readStatus: () => fresh(async () => object(await io.get(SYNC_STATUS_KEY), EMPTY_SYNC_STATUS)),
    writeStatus: (status) =>
      fresh(async () => {
        await io.set(SYNC_STATUS_KEY, status);
        await io.save();
      }),
  };
}
