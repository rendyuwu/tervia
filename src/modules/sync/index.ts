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
import { inspectSshKey } from "@/modules/ssh/bridge";
import { tauriSecretsIo } from "@/modules/vault/adapters";
import { SECRET_ALREADY_STORED, vaultStore } from "@/modules/vault/store";
import {
  vaultAccount,
  VAULT_KEYRING_SERVICE,
  VAULT_KEY_SECRET_FIELDS,
  type VaultKey,
} from "@/modules/vault/types";

import { createScheduler } from "./scheduler";
import { createSyncSettingsStore } from "./store";
import {
  SYNC_ACCESS_KEY_ID_ACCOUNT,
  SYNC_KEYRING_SERVICE,
  SYNC_PASSPHRASE_ACCOUNT,
  SYNC_REQUEST_EVENT,
  SYNC_SECRET_ACCESS_KEY_ACCOUNT,
  SYNC_STORE_PATH,
  type Envelope,
  type PullReport,
  type PushReport,
  type SyncCommands,
  type SyncConfig,
  type SyncConfigureArgs,
  type SyncRequest,
} from "./types";

/** The registered commands the scheduler drives, with their names spelled at
 *  the call - see `SyncCommands` for why they are not passed as variables. */
const commands: SyncCommands = {
  pull: (envelopes: Envelope[], etags: Record<string, string>) =>
    invoke<PullReport>("sync_pull", { envelopes, etags }),
  push: (envelopes: Envelope[], etags: Record<string, string>) =>
    invoke<PushReport>("sync_push", { envelopes, etags }),
};

/**
 * The configuration the Rust process currently holds a session for, as the
 * exact arguments that opened it.
 *
 * MEMOIZED, because `openSession` runs before every pass and opening one costs
 * a PBKDF2 at six hundred thousand iterations and a GET of the keyfile.
 * Comparing the ARGUMENTS rather than keeping a boolean is what makes a
 * configuration change take effect: the user editing their bucket in settings
 * has to reach the Rust side, and a boolean would say "already open" forever.
 *
 * CLEARED WHENEVER THE SETTINGS WINDOW ASKS FOR ANYTHING, because that window
 * can also close the session behind this one's back - see the request listener
 * in `startSync`.
 *
 * The passphrase and the credentials are inside the compared string, which is
 * deliberate and is also why this is a module-local and never logged: a
 * corrected passphrase has to reopen the session, and comparing only the
 * non-secret half would leave a device stuck on the wrong one until relaunch.
 */
let openedWith: string | null = null;

/**
 * Turn the stored configuration into an open session in the Rust process.
 *
 * WHERE THE PROVIDER'S OWN SHAPE IS ASSEMBLED. `SyncConfig` holds the
 * non-secret half and the keychain holds the rest, and this is the one place
 * the two are put back together - which is what keeps the credentials out of
 * the store file and out of the scheduler both.
 *
 * THE KEYCHAIN READ HAPPENS BEFORE THE MEMO CHECK, not after, because the
 * passphrase is part of what is being compared: a user correcting a mistyped
 * one changes nothing this side could see without reading it. One read per pass
 * is the price, and a pass is at most one per minute and already carries a
 * network round trip.
 */
async function openSession(config: SyncConfig): Promise<void> {
  const [passphrase, accessKeyId, secretAccessKey] = await tauriSecretsIo.getAll(
    SYNC_KEYRING_SERVICE,
    [SYNC_PASSPHRASE_ACCOUNT, SYNC_ACCESS_KEY_ID_ACCOUNT, SYNC_SECRET_ACCESS_KEY_ACCOUNT],
  );
  if (!passphrase) {
    throw new Error(
      "sync is on but no passphrase is stored for it - re-enter it in the sync settings",
    );
  }
  const args: SyncConfigureArgs = {
    provider: config.provider,
    prefix: config.prefix,
    passphrase,
    config: {
      endpoint: config.endpoint,
      region: config.region,
      bucket: config.bucket,
      cas: config.cas,
      accessKeyId: accessKeyId ?? "",
      secretAccessKey: secretAccessKey ?? "",
    },
  };
  const fingerprint = JSON.stringify(args);
  if (fingerprint === openedWith) return;
  await invoke<void>("sync_configure", { args });
  // AFTER the command resolves, never before: a configuration that failed to
  // open must be retried on the next pass, and recording it first would make
  // one wrong passphrase permanent for the session.
  openedWith = fingerprint;
}

/**
 * One vault key's stored secrets, by field name.
 *
 * ABSENT ACCOUNTS ARE LEFT OUT rather than mapped to an empty string, because
 * every caller asks "is there a body" and `""` answers that question wrongly in
 * the direction that publishes a record claiming a key it does not hold.
 */
async function readKeySecrets(id: string): Promise<Record<string, string>> {
  const fields = [...VAULT_KEY_SECRET_FIELDS];
  const values = await tauriSecretsIo.getAll(
    VAULT_KEYRING_SERVICE,
    fields.map((field) => vaultAccount(id, field)),
  );
  const out: Record<string, string> = {};
  fields.forEach((field, i) => {
    const value = values[i];
    if (value) out[field] = value;
  });
  return out;
}

/**
 * Re-state what this device holds about a key.
 *
 * `SECRET_ALREADY_STORED` rather than the body itself, and that is the whole
 * reason this wrapper exists rather than a direct call: passing the body would
 * send a private key back out through a store mutator that is about to write it
 * to the account it was just read from, and passing nothing would have
 * `upsertKey` take the presence flag off the EXISTING record - which is the
 * understated one this call is correcting.
 */
async function correctKey(key: VaultKey): Promise<void> {
  await vaultStore.upsertKey(key, { privateKey: SECRET_ALREADY_STORED });
}

/** The teardown for the scheduler currently running in this webview. */
let stop: (() => void) | null = null;

/**
 * Start sync for this webview, and answer with how to stop it.
 *
 * SAFE IN EVERY WEBVIEW: `createScheduler` returns an inert object outside
 * `main`, so calling this from a shared entry point costs one store handle and
 * one listener that never fires anything.
 *
 * A SECOND CALL ANSWERS WITH THE FIRST CALL'S TEARDOWN rather than a no-op. A
 * no-op there is the shape that leaves sync unstoppable: whoever holds it
 * believes it can stop what it started, and cannot.
 *
 * The mount is also the app-setup pull. It is here rather than emitted from
 * Rust's setup because emitting there races the frontend listener - a webview
 * that has not finished loading has nothing subscribed yet.
 */
export function startSync(): () => void {
  if (stop) return stop;
  const scheduler = createScheduler({
    label: getCurrentWebviewWindow().label,
    commands,
    settings: createSyncSettingsStore(createFileKeyValueStore(SYNC_STORE_PATH, tauriStoreFileIo)),
    stores: { hosts: hostsStore, vault: vaultStore, forwards: forwardsStore },
    // The runtime half of a landed delete. Imported here, where a Tauri surface
    // already is, and injected - see `SchedulerIo.releaseRule`.
    releaseRule,
    openSession,
    // The three halves of carrying a private key body that need a Tauri
    // surface, injected for the same reason.
    readKeySecrets,
    inspectKey: (body, passphrase) => inspectSshKey(body, passphrase),
    correctKey,
  });
  setDirtySink(scheduler.markDirty);

  // Caught at construction as well as at teardown: an unhandled rejection here
  // would surface as a console error with no owner, on a path that is allowed
  // to fail - a webview with no such event is a webview that never pulls on
  // focus, which is a degradation and not a fault.
  const unlisten = listen(IPC_EVENTS.SYNC_FOCUSED, () => scheduler.onFocus()).catch(() => () => {});
  // The settings window asking for something only `main` may do. A pull covers
  // "the configuration changed" as well, which is why saving in settings raises
  // one: a new configuration is only observable by reconciling against it.
  const unrequest = listen<SyncRequest>(SYNC_REQUEST_EVENT, (e) => {
    // THE MEMO IS DROPPED ON EVERY REQUEST, and that is not caution. The
    // settings window calls `sync_disable` itself, which empties the session in
    // the Rust process while `openedWith` here still names it - so the user's
    // own remedy, switching sync off and back on, would leave every later pull
    // answering that nothing is configured, for the life of the process, with
    // the memo skipping the one call that would fix it. Costs one extra
    // `sync_configure` per settings action, which is exactly when one is wanted.
    openedWith = null;
    if (e.payload === "push") void scheduler.pushNow();
    else void scheduler.pullNow();
  }).catch(() => () => {});
  void scheduler.pullNow();

  stop = () => {
    stop = null;
    setDirtySink(null);
    scheduler.dispose();
    void unlisten.then((off) => off());
    void unrequest.then((off) => off());
  };
  return stop;
}
