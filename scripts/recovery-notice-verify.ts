/**
 * Self-check: a `.bak` recovery is SAID OUT LOUD.
 * Run: `npx tsx scripts/recovery-notice-verify.ts`.
 *
 * `createRecoveredStore` has produced a recovery notice since it was written,
 * and `ensureLoaded()` / `takeRecoveryNotice()` had no caller anywhere in `src/`
 * - only in verify scripts. A tester recovered from corruption twice and was
 * told nothing either time.
 *
 * What is checked here is the policy: that the startup pass is asked exactly
 * once per store, that a notice becomes a toast naming the store and the backup,
 * that a store with nothing to report stays silent, and that the whole thing is
 * total - a rejecting store must not take the launch with it, because the caller
 * is fire-and-forget.
 *
 * NOT checked here: that `App.tsx` mounts the hook, and that the hook asks each
 * store once per LAUNCH (a `useRef` guard). Both need React. The mount is
 * asserted by source text at the end, which is exactly as strong as reading it.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import type { StoreRecovery } from "../src/lib/storeRecovery";
import {
  announceRecovery,
  drainRecovery,
  recoveryToast,
  type RecoverableStore,
  type RecoveryToast,
} from "../src/app/lib/recoveryNotices";

let failed = 0;
function check(name: string, ok: boolean, detail?: unknown): void {
  if (ok) {
    console.log(`  ok: ${name}`);
    return;
  }
  console.error(`  FAIL: ${name}`, detail === undefined ? "" : JSON.stringify(detail));
  failed++;
}

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (rel: string) => readFileSync(join(repoRoot, rel), "utf8");

/** A store whose pass returns whatever the test wants, counting the asks. */
function fakeStore(notice: StoreRecovery | null, label = "Saved machines") {
  const calls = { ensureLoaded: 0, take: 0 };
  let held = notice;
  const store: RecoverableStore = {
    label,
    ensureLoaded: async () => {
      calls.ensureLoaded++;
      const out = held;
      // The real port hands the notice out ONCE. Modelling that is what makes
      // the "asked exactly once" check below mean something.
      held = null;
      return out;
    },
    takeRecoveryNotice: () => {
      calls.take++;
      const out = held;
      held = null;
      return out;
    },
    onChanged: async () => () => {},
  };
  return { store, calls };
}

function recorder() {
  const said: RecoveryToast[] = [];
  return { said, say: (t: RecoveryToast) => void said.push(t) };
}

const RECOVERED: StoreRecovery = {
  found: "unparseable",
  recovered: true,
  note: "tervia-hosts.json was unparseable; restored from tervia-hosts.json.bak",
};
const SNAPSHOT_FAILED: StoreRecovery = {
  found: "ok",
  recovered: false,
  note: "tervia-vault.json.bak could not be written: EACCES",
};
const NOTHING_TO_SAY: StoreRecovery = { found: "ok", recovered: false };

// ---- the words ------------------------------------------------------------
console.log("[copy] a recovery names the store and says where the data came from");
{
  const t = recoveryToast("Saved machines", RECOVERED);
  check("there is something to say", t !== null);
  check("it names the store", !!t && t.message.startsWith("Saved machines:"), t?.message);
  check("it says the data came from a backup", !!t && /recovered from a backup/i.test(t.message));
  check(
    // The note is where the file names live; paraphrasing it here would be a
    // second copy of wording that belongs to `lib/storeRecovery.ts`.
    "the notice's own detail is passed through verbatim",
    !!t && t.message.includes(RECOVERED.note!),
    t?.message,
  );
  check("as a warning, not an error", t?.variant === "warning", t?.variant);
  check(
    // Nothing in this app may suggest that storing a secret here makes it safer,
    // and a restored store is not a safer store - the snapshot is metadata from
    // the last process start while the keychain is current.
    "and it claims nothing about secrets, safety or protection",
    !!t && !/secret|password|key|safe|secure|protect|encrypt/i.test(t.message),
    t?.message,
  );
}
{
  const t = recoveryToast("Vault", SNAPSHOT_FAILED);
  check("a note with no recovery is still said", t !== null);
  check("named the same way", !!t && t.message.startsWith("Vault:"), t?.message);
  check("as an error - it is something the app could NOT do", t?.variant === "error", t?.variant);
  check(
    "and it does not claim a recovery that did not happen",
    !!t && !/recovered from a backup/i.test(t.message),
    t?.message,
  );
}
check("a notice with no note says nothing at all", recoveryToast("Vault", NOTHING_TO_SAY) === null);

// ---- the startup pass ---------------------------------------------------
console.log("\n[startup] each store is asked once, and a recovery reaches the user");
{
  const { store, calls } = fakeStore(RECOVERED);
  const { said, say } = recorder();
  await announceRecovery(store, say);
  check("the recovery pass ran", calls.ensureLoaded === 1, calls);
  // Distinct from the check above, not a restatement of it: `announceRecovery`
  // goes through `ensureLoaded` alone. A version that ALSO called
  // `takeRecoveryNotice` (the drain-only method `drainRecovery` uses instead)
  // would double-drain the slot on a startup pass and this would catch it.
  check("and never separately drains via takeRecoveryNotice", calls.take === 0, calls);
  check("one toast, not none", said.length === 1, said);
  check("naming the store", said[0]?.message.startsWith("Saved machines:"), said[0]?.message);
}
{
  // The ordinary launch: nothing was wrong, so nothing is said. Without this
  // check a hook that toasted unconditionally would pass everything above.
  const { store, calls } = fakeStore(null);
  const { said, say } = recorder();
  await announceRecovery(store, say);
  check("a clean store is still asked", calls.ensureLoaded === 1, calls);
  check("and says nothing", said.length === 0, said);
}
{
  const { store } = fakeStore(NOTHING_TO_SAY);
  const { said, say } = recorder();
  await announceRecovery(store, say);
  check("a notice with no note says nothing either", said.length === 0, said);
}
{
  // Fire-and-forget: a throwing pass must not become an unhandled rejection.
  const store: RecoverableStore = {
    label: "Vault",
    ensureLoaded: () => Promise.reject(new Error("boom")),
    takeRecoveryNotice: () => null,
    onChanged: async () => () => {},
  };
  const { said, say } = recorder();
  let threw = false;
  // `announceRecovery` logs the swallowed error, which is the right thing for it
  // to do and an alarming stack trace in the middle of passing output. Muted for
  // this one call so a reader can tell a real failure from a provoked one.
  const realError = console.error;
  console.error = () => {};
  await announceRecovery(store, say).catch(() => {
    threw = true;
  });
  console.error = realError;
  check("a rejecting store is swallowed, not propagated", !threw);
  check("and says nothing", said.length === 0, said);
}

// ---- the post-startup drain --------------------------------------------
console.log("\n[later] a note that lands after startup is not lost");
{
  // A `.bak` that could not be written after a save fills the slot mid-session.
  const { store, calls } = fakeStore(SNAPSHOT_FAILED, "Vault");
  const { said, say } = recorder();
  drainRecovery(store, say);
  check("the slot is drained", calls.take === 1, calls);
  check("and the note is said", said.length === 1, said);
  drainRecovery(store, say);
  check("draining again says nothing - the notice is handed out once", said.length === 1, said);
}

// ---- the real once-per-launch guarantee (behavioural) ---------------------
// The hook's comment used to credit `startedRef` for the once-per-launch
// guarantee. A `useRef` does not survive a genuine unmount/remount of App - a
// fresh mount gets a fresh ref and would ask again - so that was never the
// real mechanism (see the corrected comment in useStoreRecoveryNotices.ts).
// What actually stops a second toast is `createRecoveredStore`'s notice slot
// being DRAINED by the first `ensureLoaded()` call. Proven directly here, at
// the layer it actually happens - `lib/recoveredStore.ts`, with injected
// ports so it runs under plain node - with no React and no `startedRef`
// anywhere in the picture.
console.log("\n[drain] the real once-per-launch guarantee: ensureLoaded() drains the slot");
{
  const { createRecoveredStore } = await import("../src/lib/recoveredStore");
  // A torn primary with a good `.bak` beside it, so the recovery pass has a
  // real notice to hand out - same shape as the [copy]/[startup] fixtures
  // above, but exercised through the real store rather than a fake `Say`.
  let primary = "not json";
  const files = {
    dir: async () => "/fake",
    read: async (path: string) =>
      path.endsWith(".bak")
        ? ({ kind: "text", content: '{"ok":true}' } as const)
        : ({ kind: "text", content: primary } as const),
    write: async (path: string, content: string) => {
      if (!path.endsWith(".bak")) primary = content;
    },
  };
  const kv = { get: async () => undefined, set: async () => {}, save: async () => {} };
  const broadcast = { emit: async () => {}, listen: async () => () => {} };
  const io = createRecoveredStore(
    { path: "fake.json", loadKey: "k", changedEvent: "fake-changed" },
    { store: kv, files, broadcast },
  );
  const first = await io.ensureLoaded();
  check(
    "first ensureLoaded() reports the recovery",
    first !== null && first.recovered === true,
    first,
  );
  const second = await io.ensureLoaded();
  check(
    // The whole guarantee, in one call: a SECOND ask - modelling a
    // StrictMode double-invoke of the hook's effect, or a genuine remount
    // asking again with no memory of the first - finds the slot already
    // drained. No ref, no React, nothing per-component involved.
    "a second ensureLoaded() finds the slot already drained",
    second === null,
    second,
  );
}

// ---- the wiring (source text only) -------------------------------------
// Honest about its strength: these read the files, they do not run them. They
// exist because the whole defect was a caller that did not exist, and nothing
// runnable here can tell a mounted hook from an unmounted one.
console.log("\n[wiring] source text: the hook exists, is mounted, and uses the real stores");
{
  const app = read("src/app/App.tsx");
  const hook = read("src/app/hooks/useStoreRecoveryNotices.ts");
  check("App imports the hook", app.includes('from "./hooks/useStoreRecoveryNotices"'));
  check("App calls it", /useStoreRecoveryNotices\(\);/.test(app));
  check(
    "the hook asks the hosts store",
    hook.includes('from "@/modules/hosts/store"') && hook.includes("ensureHostsLoaded"),
  );
  check(
    "the hook asks the vault store",
    hook.includes('from "@/modules/vault/store"') && hook.includes("ensureVaultLoaded"),
  );
  check(
    // NOT the once-per-launch guarantee itself - the [drain] check above is
    // what pins that, at the layer it actually holds. This only pins that
    // the hook still has its own same-mount guard (StrictMode double-invoke
    // of THIS effect), which is a real but much narrower property.
    "the hook guards its own effect body with startedRef",
    hook.includes("startedRef.current"),
  );
  check("and it toasts what comes back", hook.includes("toast(t.message"));
}

if (failed > 0) throw new Error(`${failed} check(s) FAILED`);
console.log("\nALL PASS");
