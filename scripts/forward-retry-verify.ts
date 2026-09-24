/**
 * Self-check for `controller.ts`'s app-launch autostart and its backoff
 * ladder: `startForwardAutostart`, the retry it schedules on a
 * transport-class failure, and the cancel points (`stopRule`, `startRule`,
 * `releaseRule`, and `pageMustStopFirst`'s own read of a pending retry) that
 * keep a stopped/edited/deleted rule from resurrecting itself. Run: `pnpm
 * verify forward-retry` (or `npx tsx scripts/forward-retry-verify.ts` to
 * iterate).
 *
 * Mirrors two existing scripts rather than inventing a third harness shape:
 * `scripts/ssh-retry-verify.ts`'s classification focus (a fixture is judged
 * by whether it LADDERS or PARKS, never by its wording), and
 * `scripts/forwards-shell-verify.ts`'s C-series `RuntimeDeps` harness (the
 * `window.__TAURI_INTERNALS__` stub `controller.ts`'s own import graph needs
 * under plain node - `ssh/tunnel.ts` -> `hosts/store.ts` reaches
 * `getCurrentWebviewWindow()` at module scope - and the fake `openForward`/
 * `closeForward`/`toast` triple). `startForwardAutostart` is called directly
 * rather than through `useForwardsAutostart.ts`: that hook is a thin
 * store-hydration-then-filter consumer with nothing left to prove once this
 * entry point is.
 *
 * Every ladder fixture below fakes `setTimeout`/`clearTimeout` before
 * importing `controller.ts`, capturing the REAL ones first for the harness's
 * own microtask `settle()` - so a five-rung ladder (over a minute of real
 * delay) runs in one event-loop tick, and each rung is fired ONE AT A TIME
 * by the fixture rather than by the clock.
 *
 * `-L` only, per the `KNOWN-LIMITS.md` entry `forwards-shell-verify.ts`
 * already carries: `-R`/`-D` dial `ssh/tunnel.ts` directly and cannot be
 * driven through `RuntimeDeps` under plain node.
 */
import {
  SshAuthRejectedError,
  SshLocalConnectError,
} from "../src/modules/terminal/lib/ssh-exit-decision";

let failed = 0;
function check(label: string, got: unknown, want: unknown): void {
  if (JSON.stringify(got) === JSON.stringify(want)) {
    console.log(`  ok: ${label}`);
  } else {
    console.error(`  FAIL: ${label} = ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
    failed++;
  }
}

// ============================================================================
// Fake timers. `setTimeout`/`clearTimeout` are replaced with a queue a fixture
// drives by hand - never real wall-clock waits, and the REAL ones are kept for
// `settle()` below (queueing a fake timer through itself would deadlock it).
// ============================================================================

const realSetTimeout = globalThis.setTimeout.bind(globalThis);

type FakeTimer = { id: number; fn: () => void; delay: number };
let timers: FakeTimer[] = [];
let nextTimerId = 1;

function fakeSetTimeout(fn: () => void, delay?: number): number {
  const id = nextTimerId++;
  timers.push({ id, fn, delay: delay ?? 0 });
  return id;
}
function fakeClearTimeout(id: number): void {
  timers = timers.filter((t) => t.id !== id);
}
(globalThis as unknown as { setTimeout: unknown }).setTimeout = fakeSetTimeout;
(globalThis as unknown as { clearTimeout: unknown }).clearTimeout = fakeClearTimeout;

/** Let queued microtasks settle, the same shape `forwards-shell-verify.ts`'s
 *  own `settle()` gives the real bridge - real timers only, captured above. */
async function settle(): Promise<void> {
  for (let i = 0; i < 8; i++) {
    await new Promise<void>((resolve) => realSetTimeout(resolve, 0));
  }
}

/** Fire the SOLE pending retry timer - every fixture below drives one rule at
 *  a time, so more than one pending is itself a bug the count assertions
 *  around each call already catch - and let its own re-attempt settle. */
async function fireRetry(): Promise<void> {
  const next = timers.shift();
  if (!next) throw new Error("forward-retry-verify: expected a pending retry timer, found none");
  next.fn();
  await settle();
}

// ============================================================================
// The Tauri stand-in `controller.ts`'s import graph needs (not called by any
// fixture below - every dial rides the fake `RuntimeDeps` instead).
// ============================================================================

(globalThis as { window?: unknown }).window = {
  __TAURI_INTERNALS__: {
    transformCallback: () => 0,
    unregisterCallback: () => {},
    invoke: (cmd: string) => {
      throw new Error(`forward-retry-verify: unexpected bridge command "${cmd}"`);
    },
  },
};

// Dynamic, not static: the module specifier is known, but LOAD ORDER is the
// constraint - `controller.ts` transitively imports `hosts/store.ts`, which
// calls `getCurrentWebviewWindow()` at MODULE SCOPE (`ssh-exit-decision.ts`'s
// own header names the same chain for `ssh-session.ts`), so the
// `window.__TAURI_INTERNALS__` stub above has to exist before this import
// runs, and a static `import` is hoisted ahead of every statement in this
// file including that one. `forwards-shell-verify.ts`'s C-series imports the
// same module the same way for the identical reason.
const { startForwardAutostart, startRule, stopRule, releaseRule, pageMustStopFirst } =
  await import("../src/modules/forwards/controller");
type RuntimeDepsType = NonNullable<Parameters<typeof startRule>[1]>;
const { useForwardRuntime } = await import("../src/modules/forwards/runtime");
const { useHostKeyPrompt } = await import("../src/modules/ssh/hostKeyPrompt");
const { useHostOwnedForwards } = await import("../src/modules/forwards/hostOwned");

function resetStores(): void {
  useForwardRuntime.setState({ byRule: {} });
  useHostKeyPrompt.setState({ queue: [] });
  useHostOwnedForwards.setState({ byRule: {} });
}

// ============================================================================
// The fake dial. One SCRIPTED OUTCOME per `openForward` call, shifted off a
// queue - an empty queue is a fixture bug (a call the fixture forgot to
// script), thrown loudly rather than hung or silently resolved. A call can
// also be PARKED instead of scripted (`parkNextOpen`), for a fixture that
// needs to land a Delete/Save or a hostOwned takeover WHILE a dial is still
// in flight, rather than only ever between dials.
// ============================================================================

type FakeForward = { sessionId: number; localPort: number; generation: number; claim: number };
type Outcome = { kind: "resolve" } | { kind: "reject"; error: unknown };
type ParkedOpen = { resolve: (f: FakeForward) => void; reject: (e: unknown) => void };

let outcomes: Outcome[] = [];
let openCallCount = 0;
let nextClaim = 1;
let parkedOpens: ParkedOpen[] = [];
let parkNextOpen = false;
let toastCalls: Array<{ message: string; variant?: string }> = [];

function resetFakes(): void {
  outcomes = [];
  openCallCount = 0;
  nextClaim = 1;
  timers = [];
  parkedOpens = [];
  parkNextOpen = false;
  toastCalls = [];
}

/** Queue `n` rejections of the same error - the common shape for a ladder
 *  fixture that fails every attempt it makes. */
function queueRejections(n: number, error: unknown): void {
  for (let i = 0; i < n; i++) outcomes.push({ kind: "reject", error });
}

const FAKE_RUNTIME = {
  openForward: (): Promise<FakeForward> => {
    openCallCount++;
    if (parkNextOpen) {
      return new Promise<FakeForward>((resolve, reject) => {
        parkedOpens.push({ resolve, reject });
      });
    }
    const outcome = outcomes.shift();
    if (!outcome) {
      return Promise.reject(
        new Error("forward-retry-verify: no scripted outcome queued for this open call"),
      );
    }
    if (outcome.kind === "reject") return Promise.reject(outcome.error);
    return Promise.resolve({
      sessionId: 1,
      localPort: 18080,
      generation: 1,
      claim: nextClaim++,
    });
  },
  closeForward: (): Promise<void> => Promise.resolve(),
  toast: (message: string, options?: { variant?: string }): void => {
    toastCalls.push({ message, variant: options?.variant });
  },
} satisfies RuntimeDepsType;

function fakeRule(id: string) {
  return {
    id,
    name: `rule-${id}`,
    hostId: "h-1",
    localPort: 18080,
    remoteHost: "10.0.0.9",
    remotePort: 5432,
    startWithHost: false,
    startWithApp: true,
    description: undefined,
  };
}

// The exact ladder `controller.ts` walks - pinned as a behavioural contract,
// not as wording: each entry is asserted against a REAL pending timer's
// delay, never read off source text.
const LADDER_MS = [1_000, 3_000, 7_000, 15_000, 30_000];

// ---------------------------------------------------------------------------
console.log("[resolve] a rule that binds on the first attempt schedules nothing");
{
  resetFakes();
  resetStores();
  const rule = fakeRule("r1");
  outcomes.push({ kind: "resolve" });
  await startForwardAutostart(rule, FAKE_RUNTIME);
  check("the row ends up running", useForwardRuntime.getState().byRule["r1"]?.status, "running");
  check("nothing was scheduled", timers.length, 0);
  check("no toast for a Start that never failed", toastCalls.length, 0);
}

// ---------------------------------------------------------------------------
console.log(
  "\n[transport] a failure that classifies transport ladders at each rung, in order, then gives up - with exactly ONE toast, on give-up, never per rung",
);
{
  resetFakes();
  resetStores();
  const rule = fakeRule("r2");
  // One initial attempt plus one retry per ladder rung - the terminal's own
  // `MAX_SSH_RECONNECT_ATTEMPTS` shape (`ssh-session.ts`), which governs
  // RECONNECTS and leaves the original attempt outside the count.
  queueRejections(LADDER_MS.length + 1, new Error("transport blip"));

  await startForwardAutostart(rule, FAKE_RUNTIME);
  check(
    "the row is failed after the first attempt",
    useForwardRuntime.getState().byRule["r2"]?.status,
    "failed",
  );
  check("exactly one open call so far", openCallCount, 1);
  check(
    "one retry pending, at the FIRST rung",
    timers.length === 1 && timers[0]?.delay,
    LADDER_MS[0],
  );
  check(
    "the row's OWN status text gains a retrying-in-Ns suffix - the toast stays silent instead",
    useForwardRuntime.getState().byRule["r2"]?.error?.endsWith(`(retrying in 1s)`),
    true,
  );
  check("no toast yet - a rung that will retry never raises one", toastCalls.length, 0);

  for (let rung = 1; rung < LADDER_MS.length; rung++) {
    await fireRetry();
    check(
      `after retry ${rung}, the next rung is queued at ${LADDER_MS[rung]}ms`,
      timers.length === 1 && timers[0]?.delay,
      LADDER_MS[rung],
    );
    check(`still no toast after retry ${rung}`, toastCalls.length, 0);
  }
  check(
    "the initial attempt plus four retries have run - the fifth rung is still pending",
    openCallCount,
    LADDER_MS.length,
  );

  // The LAST rung's own retry: fails too, and the ladder is now exhausted.
  await fireRetry();
  check("the ladder gives up - nothing further is scheduled", timers.length, 0);
  check(
    "the row stays failed with the last attempt's own error",
    useForwardRuntime.getState().byRule["r2"]?.status,
    "failed",
  );
  check("no attempt beyond the ladder's own length was made", openCallCount, LADDER_MS.length + 1);
  check("exactly ONE toast for the whole ladder, raised on give-up", toastCalls.length, 1);
  check("and it is an error toast", toastCalls[0]?.variant, "error");
}

// ---------------------------------------------------------------------------
console.log(
  "\n[local] a local-classified failure parks on the FIRST attempt - no retry at all, one toast",
);
{
  resetFakes();
  resetStores();
  const rule = fakeRule("r3");
  queueRejections(1, new SshLocalConnectError("host removed"));
  await startForwardAutostart(rule, FAKE_RUNTIME);
  check("the row is failed", useForwardRuntime.getState().byRule["r3"]?.status, "failed");
  check("nothing was scheduled - a local failure never ladders", timers.length, 0);
  check("exactly one attempt was made, ever", openCallCount, 1);
  check("exactly one toast, since this parked immediately", toastCalls.length, 1);
  check("and it is an error toast", toastCalls[0]?.variant, "error");
}

// ---------------------------------------------------------------------------
console.log(
  "\n[rejected] a rejected-classified failure (bad credential) parks the same way local does",
);
{
  resetFakes();
  resetStores();
  const rule = fakeRule("r4");
  queueRejections(1, new SshAuthRejectedError("authentication rejected"));
  await startForwardAutostart(rule, FAKE_RUNTIME);
  check("nothing was scheduled", timers.length, 0);
  check("exactly one attempt was made, ever", openCallCount, 1);
  check("exactly one toast, since this parked immediately", toastCalls.length, 1);
}

// ---------------------------------------------------------------------------
console.log("\n[start] a manual Start cancels and does not resume the old attempt count");
{
  resetFakes();
  resetStores();
  const rule = fakeRule("r6");
  queueRejections(1, new Error("transport blip"));
  await startForwardAutostart(rule, FAKE_RUNTIME);
  check("one retry is pending before the manual Start", timers.length, 1);

  outcomes.push({ kind: "resolve" });
  await startRule(rule, FAKE_RUNTIME);
  check("the old ladder's retry is gone", timers.length, 0);
  check(
    "the manual Start itself succeeded",
    useForwardRuntime.getState().byRule["r6"]?.status,
    "running",
  );

  // A LATER failure starts a fresh ladder at the FIRST rung, not wherever the
  // cancelled one left off - there is no attempt counter left to resume from,
  // since `cancelForwardRetry` deletes the whole entry.
  await stopRule(rule, FAKE_RUNTIME);
  queueRejections(1, new Error("transport blip, second lifetime"));
  await startForwardAutostart(rule, FAKE_RUNTIME);
  check(
    "a fresh ladder after the reset starts at rung 1 again",
    timers.length === 1 && timers[0]?.delay,
    LADDER_MS[0],
  );
}

// ---------------------------------------------------------------------------
// P0: the delete confirm (`ForwardsPage.tsx`) and the editor's save
// (`RuleEditorDialog.tsx`) each write the SAME two statements inline -
// `if (pageMustStopFirst(id)) await stopRule(rule)` - and neither imports
// `releaseRule` at all. Driving `releaseRule` here (as an earlier version of
// this section did) proves nothing about either UI path; this drives the
// exact statements they run.
// ---------------------------------------------------------------------------
console.log(
  "\n[confirm pattern] the delete confirm's / editor save's own `if (pageMustStopFirst(id)) await stopRule(rule)` cancels a PENDING retry on an already-failed row",
);
{
  resetFakes();
  resetStores();
  const rule = fakeRule("r5");
  queueRejections(1, new Error("transport blip"));
  await startForwardAutostart(rule, FAKE_RUNTIME);
  check(
    "the row is failed, with a retry pending",
    [useForwardRuntime.getState().byRule["r5"]?.status, timers.length],
    ["failed", 1],
  );
  check(
    "pageMustStopFirst now answers true for a failed row with a pending retry - the P0 fix",
    pageMustStopFirst(rule.id),
    true,
  );

  if (pageMustStopFirst(rule.id)) await stopRule(rule, FAKE_RUNTIME);
  check("the guard reached stopRule and the timer is gone", timers.length, 0);
  check(
    "the row reads stopped, not failed - a real stopRule ran, not a no-op",
    useForwardRuntime.getState().byRule["r5"]?.status,
    "stopped",
  );

  // Proving the timer is REALLY gone, not merely that a later read agrees:
  // settling further must never produce a second, unwanted open call - the
  // exact leak P0-1 named (a deleted/edited rule re-dialled by a retry
  // nobody cancelled).
  await settle();
  check("no second open call ever happened", openCallCount, 1);
}

// ---------------------------------------------------------------------------
console.log(
  "\n[releaseRule] the backup-apply / sync-release / host-delete caller also cancels a pending retry on an already-failed row, through the same pageMustStopFirst guard",
);
{
  resetFakes();
  resetStores();
  const rule = fakeRule("r7");
  queueRejections(1, new Error("transport blip"));
  await startForwardAutostart(rule, FAKE_RUNTIME);
  check(
    "the row is failed, with a retry pending",
    [useForwardRuntime.getState().byRule["r7"]?.status, timers.length],
    ["failed", 1],
  );

  await releaseRule(rule);
  check("the pending retry is gone", timers.length, 0);
  check(
    "the row reads stopped - releaseRule reached stopRule via pageMustStopFirst, no cancel of its own needed",
    useForwardRuntime.getState().byRule["r7"]?.status,
    "stopped",
  );
}

// ---------------------------------------------------------------------------
console.log(
  "\n[mid-dial delete] a Delete/Save landing WHILE a retry's own dial is in flight stops the Start; the dial's later (superseded) rejection must not schedule a new retry",
);
{
  resetFakes();
  resetStores();
  const rule = fakeRule("r8");
  queueRejections(1, new Error("transport blip"));
  await startForwardAutostart(rule, FAKE_RUNTIME);
  check("one retry pending after the first failure", timers.length, 1);

  // Fire the pending retry's timer, but PARK its own dial instead of
  // scripting an outcome - this is the window a Delete/Save can land in
  // while the retry itself is mid-flight, not merely while it is scheduled.
  parkNextOpen = true;
  const next = timers.shift();
  if (!next) throw new Error("forward-retry-verify: expected the pending retry's own timer");
  next.fn();
  await settle();
  parkNextOpen = false;
  check(
    "the retry's own dial is in flight - starting, with no timer pending for it",
    [useForwardRuntime.getState().byRule["r8"]?.status, timers.length],
    ["starting", 0],
  );
  check(
    "the live guard says stop, the same as it does for any starting row",
    pageMustStopFirst(rule.id),
    true,
  );

  if (pageMustStopFirst(rule.id)) await stopRule(rule, FAKE_RUNTIME);
  check(
    "stopRule ran while the dial was still in flight - row reads stopped",
    useForwardRuntime.getState().byRule["r8"]?.status,
    "stopped",
  );

  // THE DIAL FINALLY REJECTS, after the Stop already abandoned it. The
  // superseded-attempt arm in `startRule`'s own catch returns before
  // `onFailure` runs, so this ladder must never react to a dial nobody wants
  // any more.
  parkedOpens[0]?.reject(new Error("late transport blip"));
  await settle();
  check("no timer was scheduled from the superseded dial's late rejection", timers.length, 0);
  check(
    "the row is still stopped, not resurrected as failed",
    useForwardRuntime.getState().byRule["r8"]?.status,
    "stopped",
  );
}

// ---------------------------------------------------------------------------
console.log(
  "\n[mid-dial hostOwned] a terminal claiming the rule WHILE a retry's own dial is in flight yields; nothing is scheduled from that dial's own rejection",
);
{
  resetFakes();
  resetStores();
  const rule = fakeRule("r9");
  queueRejections(1, new Error("transport blip"));
  await startForwardAutostart(rule, FAKE_RUNTIME);
  check("one retry pending after the first failure", timers.length, 1);

  parkNextOpen = true;
  const next = timers.shift();
  if (!next) throw new Error("forward-retry-verify: expected the pending retry's own timer");
  next.fn();
  await settle();
  parkNextOpen = false;
  check(
    "the retry's own dial is in flight",
    useForwardRuntime.getState().byRule["r9"]?.status,
    "starting",
  );

  // A terminal claims the rule mid-dial - `autostart.ts`'s own claim-on-
  // `starting` (its own header), stood in for here the same way
  // `forwards-shell-verify.ts`'s own mid-dial fixtures write `hostOwned`
  // directly rather than driving a second real terminal session.
  useHostOwnedForwards.setState({ byRule: { r9: { sessionId: 9, boundPort: 18080 } } });
  parkedOpens[0]?.reject(new Error("EADDRINUSE"));
  await settle();
  check(
    "the row yielded to the terminal - stopped, not failed",
    useForwardRuntime.getState().byRule["r9"]?.status,
    "stopped",
  );
  check("the yield never calls onFailure, so the ladder schedules nothing", timers.length, 0);
  check(
    "the yield's own warning toast still passes through the silenced runtime - only \"error\" is dropped",
    [toastCalls.length, toastCalls[0]?.variant],
    [1, "warning"],
  );
}

if (failed > 0) throw new Error(`forward-retry-verify: ${failed} FAILED`);
console.log("\nforward-retry-verify: OK\n");
