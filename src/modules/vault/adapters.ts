import { invoke } from "@tauri-apps/api/core";

import { createRecoveredStore, type RecoveredStoreIo } from "@/lib/recoveredStore";

import { VAULT_IDENTITIES_KEY, VAULT_STORE_PATH } from "./types";

// The two things the vault store layer reaches outside itself for, behind
// interfaces.
//
// Not indirection for its own sake: `scripts/*-verify.ts` runs under plain node
// with no Tauri runtime, and everything worth pinning down in this module -
// reference integrity, the presence flags, resolution - is logic rather than IPC.
// A store file reached directly would make all of it untestable and none of it
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
 * One stored secret, addressed the way `secrets.rs` addresses it.
 *
 * Named rather than four positional strings on {@link SecretsIo.copy}, because
 * all four are a `string`: a call that transposed a service and an account, or a
 * source and a destination, would type-check and then write a secret to an
 * account nothing reads while reporting success. The other three methods stay
 * positional - two arguments in a fixed order that every other keychain call in
 * the app already uses.
 */
export type SecretEntry = { service: string; account: string };

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
  /**
   * Move one stored secret to another account, WITHOUT its value passing through
   * here.
   *
   * That is the only reason this exists rather than a `get` followed by a `set`:
   * there is no single-value read on this port at all, precisely so no caller can
   * assemble one. `secrets_copy` reads and writes in-process, so an RDP password
   * can travel with a duplicated host or into a vault identity while staying
   * inside the invariant that an RDP password never enters the webview - a
   * duplicated RDP host used to get no password for exactly this reason.
   *
   * Resolves `true` when the source held something and the destination now holds
   * it, `false` when the source was empty and NOTHING was written. A caller
   * turns that boolean straight into a presence flag, so it must never be
   * optimistic: an account holding the empty string is indistinguishable from a
   * real one to every `has*` flag in the app, and no layer above this reads a
   * secret back to notice.
   *
   * Copying `from` onto itself is a no-op that still reports what is there.
   */
  copy(from: SecretEntry, to: SecretEntry): Promise<boolean>;
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
  // camelCase on this side, `from_service` / `from_account` / `to_service` /
  // `to_account` on the Rust side: Tauri v2 maps the two itself, and getting it
  // wrong fails at runtime with "invalid args" rather than at compile time.
  // `git_file_head`'s `repoPath` and `ssh_forward_open`'s `localPort` are the
  // precedent.
  copy: (from, to) =>
    invoke<boolean>("secrets_copy", {
      fromService: from.service,
      fromAccount: from.account,
      toService: to.service,
      toAccount: to.account,
    }),
};
