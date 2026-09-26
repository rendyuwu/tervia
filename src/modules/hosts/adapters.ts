import { createRecoveredStore, type RecoveredStoreIo } from "@/lib/recoveredStore";
import { tauriStoreFileIo, type StoreFileIo } from "@/lib/storeRecovery";
import type { DirtyId } from "@/lib/tombstones";
import type { SecretsIo } from "@/modules/vault/adapters";
import type { VaultIdentity } from "@/modules/vault/types";

import { HOSTS_KEY, HOSTS_STORE_PATH, type Host } from "./types";

// The two things the host store layer reaches outside itself for, behind
// interfaces - for the same reason `modules/vault` does it: `scripts/*-verify.ts`
// runs under plain node with no Tauri runtime, and everything worth pinning down
// here (binding ownership, the reference guards, the cascades) is logic rather
// than IPC.
//
// `SecretsIo` is the vault's port, imported rather than re-declared. There is one
// `secrets_*` surface and one shape for it; a second copy here would be a second
// thing to keep in step with `secrets.rs`.

const HOSTS_CHANGED_EVENT = "tervia://hosts-changed";

/**
 * Persistence for the host store: the shared recovered-store port, renamed only
 * so this module's vocabulary stays local.
 *
 * The ordering it owns - recover a torn file, THEN force the load, then snapshot
 * - is not re-implemented here: this module passes a path, a load key and an
 * event name, and nothing else.
 */
export type HostsStoreIo = RecoveredStoreIo;

/**
 * Raw file reads, for the one thing in this module that cannot go through a
 * store at all: the legacy purge reads the two OLD store files directly, so it
 * keeps working after the modules that own them are deleted (`legacyPurge.ts`).
 *
 * Optional with the real default, the way `recoverStoreFile` and `resolveJumpHops`
 * take their ports - omitting it means "the real filesystem", never "skip a
 * guard", so there is nothing here for a caller to silently opt out of.
 */
export type HostsIo = {
  store: HostsStoreIo;
  secrets: SecretsIo;
  files?: StoreFileIo;
  /**
   * The clock every `updatedAt` and every `deletedAt` in this store is stamped
   * from. Optional with the real default, on the same terms as `files` above -
   * omitting it means the real clock, never "skip a stamp".
   *
   * It exists because the property it carries is otherwise uncheckable: two
   * awaited writes against in-memory ports routinely land in the same
   * millisecond, so "a second write produces a later stamp" would be a check
   * that fails at random rather than one that fails when the stamp is wrong. The
   * tombstone window's boundary needs the same control.
   */
  now?: () => number;
  /**
   * Told which records a committed write owes a push, after every commit.
   *
   * INJECTED and optional with a no-op default, which is the only shape that
   * keeps the dependency pointing the right way: a store that imported a
   * scheduler would put a network module behind every host edit, and every
   * suite that builds this store would have to construct one. Omitting it means
   * "nothing is listening", never "this write does not count" - what a write
   * owes is decided at the call site, by what it passes `persist`.
   */
  markDirty?: (dirty: DirtyId[]) => void;
  /**
   * Told the vault identity a successful connect authenticated as this identity,
   * after this host's own stamp has committed. Optional with a no-op default, on
   * `markDirty`'s terms: omitting it means nothing records vault recency, never
   * "skip the host stamp".
   */
  markIdentityConnected?: (identityId: string, protocol: Host["protocol"]) => Promise<void>;
  /**
   * Looked up when `upsertGroup` writes a CHANGING `defaultIdentityId`, to
   * refuse one naming nothing - on `markIdentityConnected`'s own terms:
   * optional with a no-op default, and omitting it means the existence
   * check never runs, never "the write is refused". The one production
   * wiring is `vaultStore.findIdentity`, on `markIdentityConnected`'s own
   * pattern.
   */
  findIdentity?: (id: string) => Promise<VaultIdentity | undefined>;
};

/** The file port every caller gets unless a test hands one in. */
export const defaultHostFiles: StoreFileIo = tauriStoreFileIo;

/** The real host store, with crash recovery in front of it. */
export function createTauriHostsStoreIo(): HostsStoreIo {
  return createRecoveredStore({
    path: HOSTS_STORE_PATH,
    loadKey: HOSTS_KEY,
    changedEvent: HOSTS_CHANGED_EVENT,
  });
}
