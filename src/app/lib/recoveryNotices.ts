import type { StoreRecovery } from "@/lib/storeRecovery";

/**
 * Turning a store's crash-recovery notice into something the user is told.
 *
 * Split from the hook that mounts it (`app/hooks/useStoreRecoveryNotices.ts`)
 * for the same reason `app/lib/sectionOrder.ts` is split from the right column:
 * the policy - what gets said, how loudly, and how many times each store is
 * asked - is the part worth pinning down, and it is checkable on its own only
 * while it depends on neither React nor the real stores.
 */

/** One store with a recovery pass, and the words for it. `label` is what a
 *  PERSON calls the store; the notice itself names the file, which is the detail
 *  rather than the subject. */
export type RecoverableStore = {
  label: string;
  /** Runs the recovery pass + first load and hands back the notice once. */
  ensureLoaded: () => Promise<StoreRecovery | null>;
  /** Drains the notice slot again, for a note that lands after startup. */
  takeRecoveryNotice: () => StoreRecovery | null;
  onChanged: (cb: () => void) => Promise<() => void>;
};

export type RecoveryToast = {
  message: string;
  variant: "warning" | "error";
};

/** Says a notice out loud. The hook passes the real `toast`. */
export type Say = (t: RecoveryToast) => void;

/**
 * The divergence a restore leaves behind, in the app's own words.
 *
 * Said only on the branch where a file actually WAS rolled back, because that is
 * the only branch where it is true. It states what was not done and stops: the
 * app did not reconcile anything, cannot enumerate the keychain to find out
 * (there is no `secrets_list`), and must not imply either.
 */
const KEYCHAIN_DIVERGENCE =
  "Stored passwords and keys were not rolled back with it, so a restored record " +
  "can describe material that is no longer there.";

/**
 * What to say for one notice, or null when there is nothing to say.
 *
 * Deliberately reports only what happened to the FILE. A recovered store is not
 * a safer store and must not be described as one: the snapshot is metadata from
 * the last process start while the keychain is current, so the two can come back
 * disagreeing (see the note in `lib/storeRecovery.ts`, and the entry in
 * `KNOWN-LIMITS.md` that accepts it). The notice's own `note` is passed through
 * rather than paraphrased - it names the file and the snapshot, which is what
 * anyone digging further needs, and paraphrasing it here would be a second copy
 * of wording that lives in `lib/storeRecovery.ts`.
 */
export function recoveryToast(label: string, notice: StoreRecovery): RecoveryToast | null {
  if (!notice.note) return null;
  if (notice.recovered) {
    return {
      message: `${label}: recovered from a backup copy. ${notice.note}. ${KEYCHAIN_DIVERGENCE}`,
      variant: "warning",
    };
  }
  // No recovery, but something to report: the primary could not be checked or
  // restored, or the `.bak` beside it could not be written. Each is something
  // the app could NOT do - the same split `purgeLegacySecrets` uses for its
  // "finished with notes" vs "could not finish" toasts.
  return { message: `${label}: ${notice.note}`, variant: "error" };
}

/**
 * Run one store's startup recovery pass and say whatever came back.
 *
 * Total: `ensureLoaded` is itself total (every step inside reports rather than
 * throws), and the catch here covers the case that should not happen rather than
 * letting an unhandled rejection out of a fire-and-forget call.
 *
 * Exactly ONE `ensureLoaded` per store per call, which is the whole point - the
 * notice is only deterministic at that moment. Every other store method awaits
 * the same pass, so recovery always happens, but the notice is then only seen if
 * something remembers to take it after a read has already run. That is how two
 * real `.bak` recoveries went unreported.
 */
export async function announceRecovery(store: RecoverableStore, say: Say): Promise<void> {
  let notice: StoreRecovery | null = null;
  try {
    notice = await store.ensureLoaded();
  } catch (e) {
    console.error(`${store.label}: recovery pass failed`, e);
    return;
  }
  if (!notice) return;
  const t = recoveryToast(store.label, notice);
  if (t) say(t);
}

/**
 * Drain a store's notice slot outside startup, and say anything found.
 *
 * Startup is not the only thing that fills it: a `.bak` that could not be
 * written after a save lands there too, so a UI that reads once would never
 * mention that the safety net has gone away mid-session.
 */
export function drainRecovery(store: RecoverableStore, say: Say): void {
  const notice = store.takeRecoveryNotice();
  if (!notice) return;
  const t = recoveryToast(store.label, notice);
  if (t) say(t);
}
