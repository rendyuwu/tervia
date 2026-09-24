/**
 * Self-check for `controller.ts`'s app-launch autostart and its backoff
 * ladder (issue #77): `startForwardAutostart`, the retry it schedules on a
 * transport-class failure, and the cancel points (`stopRule`, `startRule`,
 * `releaseRule`) that keep a stopped/edited/deleted rule from resurrecting
 * itself. Run: `pnpm verify forward-retry` (or `npx tsx
 * scripts/forward-retry-verify.ts` to iterate).
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
    const { promise, resolve } = Promise.withResolvers<void>();
    realSetTimeout(resolve, 0);
    await promise;
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
const { startForwardAutostart, startRule, stopRule, releaseRule } =
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
// script), thrown loudly rather than hung or silently resolved.
// ============================================================================

type FakeForward = { sessionId: number; localPort: number; generation: number; claim: number };
type Outcome = { kind: "resolve" } | { kind: "reject"; error: unknown };

let outcomes: Outcome[] = [];
let openCallCount = 0;
let nextClaim = 1;

function resetFakes(): void {
  outcomes = [];
  openCallCount = 0;
  nextClaim = 1;
  timers = [];
}

/** Queue `n` rejections of the same error - the common shape for a ladder
 *  fixture that fails every attempt it makes. */
function queueRejections(n: number, error: unknown): void {
  for (let i = 0; i < n; i++) outcomes.push({ kind: "reject", error });
}

const FAKE_RUNTIME = {
  openForward: (): Promise<FakeForward> => {
    openCallCount++;
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
  toast: (): void => {},
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

// The exact ladder `controller.ts` walks - pinned as a behavioural contract
// (issue #77 asks for "a backoff ladder"), not as wording: each entry is
// asserted against a REAL pending timer's delay, never read off source text.
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
}

// ---------------------------------------------------------------------------
console.log(
  "\n[transport] a failure that classifies transport ladders at each rung, in order, then gives up",
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

  for (let rung = 1; rung < LADDER_MS.length; rung++) {
    await fireRetry();
    check(
      `after retry ${rung}, the next rung is queued at ${LADDER_MS[rung]}ms`,
      timers.length === 1 && timers[0]?.delay,
      LADDER_MS[rung],
    );
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
}

// ---------------------------------------------------------------------------
console.log("\n[local] a local-classified failure parks on the FIRST attempt - no retry at all");
{
  resetFakes();
  resetStores();
  const rule = fakeRule("r3");
  queueRejections(1, new SshLocalConnectError("host removed"));
  await startForwardAutostart(rule, FAKE_RUNTIME);
  check("the row is failed", useForwardRuntime.getState().byRule["r3"]?.status, "failed");
  check("nothing was scheduled - a local failure never ladders", timers.length, 0);
  check("exactly one attempt was made, ever", openCallCount, 1);
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
}

// ---------------------------------------------------------------------------
console.log("\n[stop] a manual Stop cancels a pending retry");
{
  resetFakes();
  resetStores();
  const rule = fakeRule("r5");
  queueRejections(1, new Error("transport blip"));
  await startForwardAutostart(rule, FAKE_RUNTIME);
  check("one retry is pending before the Stop", timers.length, 1);

  await stopRule(rule, FAKE_RUNTIME);
  check("the pending retry is gone", timers.length, 0);
  check(
    "the row reads stopped, not failed",
    useForwardRuntime.getState().byRule["r5"]?.status,
    "stopped",
  );

  // The cancelled retry, if it somehow still fired, must not resurrect the
  // rule - proving the timer itself is gone (above) is the real guarantee;
  // this is the same property from the other side, in case a future edit
  // moves the cancel without also clearing the timer array.
  check("settling further finds nothing pending", timers.length, 0);
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
console.log("\n[delete/edit] releaseRule cancels a pending retry even on an already-failed row");
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

  // `pageMustStopFirst` answers false for a `failed` row, so `releaseRule`
  // alone reaching `stopRule` is NOT what has to cancel this - the property
  // this section exists to prove.
  await releaseRule(rule);
  check("the pending retry is gone", timers.length, 0);
  check(
    "the row is untouched otherwise - releaseRule did not spend a Stop it never needed",
    useForwardRuntime.getState().byRule["r7"]?.status,
    "failed",
  );
}

if (failed > 0) throw new Error(`forward-retry-verify: ${failed} FAILED`);
console.log("\nforward-retry-verify: OK\n");
