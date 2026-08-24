import { createRecoveredStore, type RecoveredStoreIo } from "@/lib/recoveredStore";
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
 * - is not re-implemented here. §12.12: this module passes a path, a load key and
 * an event name, and nothing else.
 */
export type HostsStoreIo = RecoveredStoreIo;

export type HostsIo = { store: HostsStoreIo; secrets: SecretsIo };

/** The real host store, with crash recovery in front of it. */
export function createTauriHostsStoreIo(): HostsStoreIo {
  return createRecoveredStore({
    path: HOSTS_STORE_PATH,
    loadKey: HOSTS_KEY,
    changedEvent: HOSTS_CHANGED_EVENT,
  });
}
