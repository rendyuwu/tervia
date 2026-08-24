import { invoke } from "@tauri-apps/api/core";
import { emit, listen } from "@tauri-apps/api/event";
import { LazyStore } from "@tauri-apps/plugin-store";

import { recoverStoreFile, snapshotStoreFile, type StoreRecovery } from "@/lib/storeRecovery";

import { VAULT_IDENTITIES_KEY, VAULT_STORE_PATH } from "./types";

// The two things the vault store layer reaches outside itself for, behind
// interfaces.
//
// Not indirection for its own sake: `scripts/*-verify.ts` runs under plain node
// with no Tauri runtime, and everything worth pinning down in this module -
// reference integrity, the presence flags, resolution - is logic rather than IPC.
// A `LazyStore` reached directly would make all of it untestable and none of it
// clearer.

const VAULT_CHANGED_EVENT = "tervia://vault-changed";

/** Persistence for the vault, narrowed to what the store layer uses. */
export type VaultStoreIo = {
  get<T>(key: string): Promise<T | null>;
  set(key: string, value: unknown): Promise<void>;
  /** Flush and tell every window. One call because the two always happen
   *  together, and a write that skips the broadcast leaves a stale list in the
   *  other window. */
  commit(): Promise<void>;
  onChanged(cb: () => void): Promise<() => void>;
  /**
   * A crash recovery that happened on the first load, returned ONCE so a caller
   * can toast it exactly once. `src/lib` cannot import a toast, so the notice
   * travels instead of the dependency.
   */
  takeRecoveryNotice(): StoreRecovery | null;
};

/**
 * Keychain access.
 *
 * `getAll` takes a service because `secrets_get_all` does: it is
 * `(service, accounts[])`, ONE service per call. So a batch spanning host-owned
 * and vault-owned secrets is two IPC calls, not one, and a port that hid the
 * service would invite a caller to assume otherwise.
 */
export type SecretsIo = {
  getAll(service: string, accounts: string[]): Promise<(string | null)[]>;
  set(service: string, account: string, value: string): Promise<void>;
  delete(service: string, account: string): Promise<void>;
};

export type VaultIo = { store: VaultStoreIo; secrets: SecretsIo };

/**
 * The real store, with crash recovery in front of it.
 *
 * Recovery has to happen before the plugin is touched at all, and the snapshot
 * right after the load that proved the file good - see `@/lib/storeRecovery` for
 * what a torn write does otherwise.
 */
export function createTauriVaultStoreIo(): VaultStoreIo {
  const store = new LazyStore(VAULT_STORE_PATH, { defaults: {}, autoSave: 200 });
  let notice: StoreRecovery | null = null;
  let ready: Promise<void> | undefined;

  const settle = (): Promise<void> =>
    (ready ??= (async () => {
      const recovery = await recoverStoreFile(VAULT_STORE_PATH);
      if (recovery.note) notice = recovery;
      // Force the plugin's load while the file is known good, then snapshot what
      // it loaded from.
      await store.get(VAULT_IDENTITIES_KEY);
      await snapshotStoreFile(VAULT_STORE_PATH);
    })());

  return {
    async get<T>(key: string): Promise<T | null> {
      await settle();
      return (await store.get<T>(key)) ?? null;
    },
    async set(key: string, value: unknown): Promise<void> {
      await settle();
      await store.set(key, value);
    },
    async commit(): Promise<void> {
      await Promise.all([store.save(), emit(VAULT_CHANGED_EVENT)]);
    },
    onChanged: (cb) => listen(VAULT_CHANGED_EVENT, () => cb()),
    takeRecoveryNotice(): StoreRecovery | null {
      const held = notice;
      notice = null;
      return held;
    },
  };
}

export const tauriSecretsIo: SecretsIo = {
  getAll: (service, accounts) =>
    accounts.length === 0
      ? Promise.resolve([])
      : invoke<(string | null)[]>("secrets_get_all", { service, accounts }),
  set: (service, account, value) =>
    invoke<void>("secrets_set", { service, account, password: value }),
  delete: async (service, account) => {
    try {
      await invoke<void>("secrets_delete", { service, account });
    } catch {
      // Already absent.
    }
  },
};
