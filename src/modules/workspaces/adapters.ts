import { createRecoveredStore, type RecoveredStoreIo } from "@/lib/recoveredStore";

// The one thing the workspaces store layer reaches outside itself for, behind an
// interface - in the shape of `modules/forwards/adapters.ts`.
//
// No `SecretsIo` here, and none is coming. A saved workspace holds a layout: a
// cwd, a path, an SSH connection id, an RDP connection id. Every credential it
// could need belongs to the host record the id names, resolved at the moment the
// leaf comes back. Saying so because two modules in this codebase acquired a
// keychain service after their store existed, and a third here would be an
// account nothing ever reads.

const WORKSPACES_STORE_PATH = "tervia-workspaces.json";

/** The saved workspace list. Also the load key, per `RecoveredStoreSpec`. */
export const KEY_LIST = "workspaces";
/** Id of the workspace that was open. Written with the list, in one commit. */
export const KEY_ACTIVE = "activeId";

/**
 * Persistence for the workspaces store, the shared recovered-store port under
 * this module's own name.
 *
 * The reason this store is in the family at all is `persist`: it writes the list
 * and the active id together, and the two disagreeing is a saved workspace set
 * whose active id names a workspace that is not in it. A commit here is one
 * atomic file write, so that pair cannot come apart.
 */
export type WorkspacesStoreIo = RecoveredStoreIo;

/** The real workspaces store, with crash recovery in front of it. */
export function createTauriWorkspacesStoreIo(): WorkspacesStoreIo {
  return createRecoveredStore({
    path: WORKSPACES_STORE_PATH,
    loadKey: KEY_LIST,
    changedEvent: "tervia://workspaces-changed",
  });
}
