import { invoke } from "@tauri-apps/api/core";

import { createRecoveredStore, type RecoveredStoreIo } from "@/lib/recoveredStore";

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

/**
 * Persistence for the vault: the shared recovered-store port, unaliased in
 * behaviour and renamed only so this module's own vocabulary stays local.
 *
 * The ordering it enforces - recover, then force the load, then snapshot - is
 * the part `modules/hosts` and `modules/forwards` must not re-implement, so the
 * vault takes the shape rather than a copy of it.
 */
export type VaultStoreIo = RecoveredStoreIo;

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

/** The real vault store, with crash recovery in front of it. */
export function createTauriVaultStoreIo(): VaultStoreIo {
  return createRecoveredStore({
    path: VAULT_STORE_PATH,
    loadKey: VAULT_IDENTITIES_KEY,
    changedEvent: VAULT_CHANGED_EVENT,
  });
}

export const tauriSecretsIo: SecretsIo = {
  getAll: (service, accounts) =>
    accounts.length === 0
      ? Promise.resolve([])
      : invoke<(string | null)[]>("secrets_get_all", { service, accounts }),
  set: (service, account, value) =>
    invoke<void>("secrets_set", { service, account, password: value }),
  // Deliberately unguarded. `secrets_delete` already reports an absent account as
  // success on every platform - a `HashMap::remove` that removed nothing on
  // Linux and Windows, `keyring::Error::NoEntry` mapped to `Ok` on macOS - so
  // anything that reaches here is a REAL failure: a read-only data directory, a
  // DPAPI error, a full disk. Swallowing it would report the clear as done and
  // flip the presence flag to false with the secret still on disk, where nothing
  // would ever name it again.
  delete: (service, account) => invoke<void>("secrets_delete", { service, account }),
};
