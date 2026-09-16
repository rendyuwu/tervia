// The one place this module touches the running app: the real stores, the real
// commands, the real store file, and the focus event.
//
// EVERY IMPORT EDGE POINTS THIS WAY. `modules/sync` knows about `modules/hosts`,
// `modules/vault` and `modules/forwards`; none of them knows about this one.
// That is why the dirty marks arrive through `src/lib/dirtySink.ts` rather than
// through a call: a store importing a scheduler would put a network module
// behind every host edit, and every verify script that builds a store would have
// to construct one.

import { invoke } from "@tauri-apps/api/core";
import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow";
import { listen } from "@tauri-apps/api/event";

import { setDirtySink } from "@/lib/dirtySink";
import { createFileKeyValueStore } from "@/lib/fileKeyValueStore";
import { IPC_EVENTS } from "@/lib/ipc";
import { tauriStoreFileIo } from "@/lib/storeRecovery";
import { releaseRule } from "@/modules/forwards/controller";
import { forwardsStore } from "@/modules/forwards/store";
import { hostsStore } from "@/modules/hosts/store";
import { vaultStore } from "@/modules/vault/store";

import { createScheduler, type SyncScheduler } from "./scheduler";
import { createSyncSettingsStore } from "./store";
import {
  SYNC_STORE_PATH,
  type Envelope,
  type PullReport,
  type PushReport,
  type SyncCommands,
} from "./types";

/** The two registered commands, with their names spelled at the call - see
 *  `SyncCommands` for why they are not passed as variables. */
const commands: SyncCommands = {
  pull: (envelopes: Envelope[], etags: Record<string, string>) =>
    invoke<PullReport>("sync_pull", { envelopes, etags }),
  push: (envelopes: Envelope[], etags: Record<string, string>) =>
    invoke<PushReport>("sync_push", { envelopes, etags }),
};

let running: SyncScheduler | null = null;

/**
 * Start sync for this webview, and answer with how to stop it.
 *
 * SAFE IN EVERY WEBVIEW: `createScheduler` returns an inert object outside
 * `main`, so calling this from a shared entry point costs one store handle and
 * one listener that never fires anything.
 *
 * The mount is also the app-setup pull. It is here rather than emitted from
 * Rust's setup because emitting there races the frontend listener - a webview
 * that has not finished loading has nothing subscribed yet.
 */
export function startSync(): () => void {
  if (running) return () => {};
  const scheduler = createScheduler({
    label: getCurrentWebviewWindow().label,
    commands,
    settings: createSyncSettingsStore(createFileKeyValueStore(SYNC_STORE_PATH, tauriStoreFileIo)),
    stores: { hosts: hostsStore, vault: vaultStore, forwards: forwardsStore },
    // The runtime half of a landed delete. Imported here, where a Tauri surface
    // already is, and injected - see `SchedulerIo.releaseRule`.
    releaseRule,
  });
  running = scheduler;
  setDirtySink(scheduler.markDirty);

  const unlisten = listen(IPC_EVENTS.SYNC_FOCUSED, () => scheduler.onFocus());
  void scheduler.pullNow();

  return () => {
    running = null;
    setDirtySink(null);
    scheduler.dispose();
    void unlisten.then((off) => off()).catch(() => {});
  };
}
