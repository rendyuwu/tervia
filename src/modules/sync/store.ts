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

import type { KeyValueStore } from "@/lib/recoveredStore";

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
export type SyncStoreIo = KeyValueStore;

export type SyncSettingsStore = {
  readConfig(): Promise<SyncConfig>;
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
  return {
    async readConfig() {
      return object(await io.get(SYNC_CONFIG_KEY), DEFAULT_SYNC_CONFIG);
    },
    async readEtags() {
      const raw = await io.get(SYNC_ETAGS_KEY);
      if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return {};
      // Every value, not just the map - a hand-edited file can hold anything,
      // and a non-string etag would be sent back as an `If-Match`.
      const out: Record<string, string> = {};
      for (const [key, value] of Object.entries(raw as Record<string, unknown>)) {
        if (typeof value === "string") out[key] = value;
      }
      return out;
    },
    async writeEtags(etags) {
      await io.set(SYNC_ETAGS_KEY, etags);
      await io.save();
    },
    async readDirty() {
      const raw = await io.get(SYNC_DIRTY_KEY);
      return Array.isArray(raw) ? raw.filter((s): s is string => typeof s === "string") : [];
    },
    async writeDirty(slots) {
      await io.set(SYNC_DIRTY_KEY, slots);
      await io.save();
    },
    async readStatus() {
      return object(await io.get(SYNC_STATUS_KEY), EMPTY_SYNC_STATUS);
    },
    async writeStatus(status) {
      await io.set(SYNC_STATUS_KEY, status);
      await io.save();
    },
  };
}
