import { createRecoveredStore, type RecoveredStoreIo } from "@/lib/recoveredStore";
import type { DirtyId } from "@/lib/tombstones";

import { FORWARDS_KEY, FORWARDS_STORE_PATH } from "./types";

// The one thing the forwards store layer reaches outside itself for, behind an
// interface - and there is only one, unlike `modules/vault` and `modules/hosts`.
//
// No `SecretsIo` here, and none is coming. A forward rule holds no secret of its
// own: the credential comes from the SSH host it names, resolved through
// `resolveSshAuth` at the moment the rule is opened - the same resolution an
// ordinary connect already does. Saying so here rather than trusting it to stay
// obvious, because "a new store module" in this codebase has meant "a new
// keychain service" twice (`modules/vault`, then `modules/hosts`), and a third
// one would be a real defect: a rule's own account with nothing that ever reads
// it, since nothing here ever asks the keychain for anything.

/**
 * Persistence for the forwards store, the shared recovered-store port under this
 * module's own name. Unaliased in behaviour, per `vault/adapters.ts`'s own
 * `VaultStoreIo` - the ordering it enforces belongs to `createRecoveredStore`,
 * not to this module.
 */
export type ForwardsStoreIo = RecoveredStoreIo;

/** The real forwards store, with crash recovery in front of it. */
export function createTauriForwardsStoreIo(): ForwardsStoreIo {
  return createRecoveredStore({
    path: FORWARDS_STORE_PATH,
    loadKey: FORWARDS_KEY,
    changedEvent: "tervia://forwards-changed",
  });
}

/** `now` is the clock every `updatedAt` and `deletedAt` here is stamped from, and
 *  `markDirty` is told which records a committed write owes a push. Both optional
 *  with the real default - see `HostsIo` in `modules/hosts/adapters.ts` for why
 *  each is a port rather than an inline call. */
export type ForwardsIo = {
  store: ForwardsStoreIo;
  now?: () => number;
  markDirty?: (dirty: DirtyId[]) => void;
};
