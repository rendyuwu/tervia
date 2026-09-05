import { createRecoveredStore, type RecoveredStoreIo } from "@/lib/recoveredStore";
import { tauriStoreFileIo, type StoreFileIo } from "@/lib/storeRecovery";
import type { SecretsIo } from "@/modules/vault/adapters";

import { HOSTS_KEY, HOSTS_STORE_PATH } from "./types";

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
 * Raw file reads, for the one thing in this module that cannot go through the
 * plugin store: the legacy purge reads the two OLD store files directly, so it
 * keeps working after the modules that own them are deleted (`legacyPurge.ts`).
 *
 * Optional with the real default, the way `recoverStoreFile` and `resolveJumpHops`
 * take their ports - omitting it means "the real filesystem", never "skip a
 * guard", so there is nothing here for a caller to silently opt out of.
 */
export type HostsIo = { store: HostsStoreIo; secrets: SecretsIo; files?: StoreFileIo };

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
