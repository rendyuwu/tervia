/**
 * Self-check for wave 3 step 11: `startWithHost` - the terminal-owned forwards
 * map (`src/modules/forwards/hostOwned.ts`), the autostart entry point
 * (`src/modules/forwards/autostart.ts`), its call site and its two release
 * sites in `src/modules/terminal/lib/ssh-session.ts`, and the read-only
 * "Running (with host)" row in `src/modules/forwards/page/RuleCard.tsx`.
 * Run: `pnpm verify forward-autostart` (or `npx tsx
 * scripts/forward-autostart-verify.ts` to iterate).
 *
 * Sections 1-7 and 11-16 are BEHAVIOURAL: they drive the real
 * `startHostForwards` through the `AutostartDeps` seam that module exports for
 * exactly this purpose, so no Tauri IPC and no DOM is needed for the properties
 * that matter. Sections 8-10 are source pins, because a call site inside
 * `ssh-session.ts` cannot be imported at all (that file's own import graph
 * reaches `@xterm/xterm` and `@tauri-apps/plugin-os`, which throw on load
 * outside the app) and a React component's rendered text is not reachable
 * from node either. 11-15 sit AFTER the pins rather than beside 1-7 so the
 * numbering stays in file order; they are the fix round's additions and each
 * one names the blocker it closes.
 *
 * What each section pins, and why it is a bug that has already happened once
 * in this codebase or is one wrong character away:
 *
 * 1/2. THE FILTER IS BOTH HALVES. A rule with `startWithHost: false` and a
 *    rule bound to another host are the two ways a fresh session can open a
 *    forward nobody asked for - one binds a local port the user never
 *    consented to, the other binds it on the wrong machine entirely.
 *
 * 3. MUTUAL EXCLUSION (VLT-94). A rule the PAGE is running is skipped, not
 *    started a second time: two listeners for one rule means the page's Stop
 *    frees one of them and the row then lies about the other. The skip is a
 *    `continue` and never a `return`, so the rules after it still come up.
 *
 * 4. A BAD RULE IS NOT A BAD CONNECT. A rule whose bind rejects writes its
 *    banner, the NEXT rule still opens, and `startHostForwards` resolves. Its
 *    call site is fire-and-forget inside the connect path, so a rejection is
 *    an unhandled promise rejection - and a `throw` mid-loop silently drops
 *    every rule after it. Observed on the SETTLED promise with counters read
 *    after the await, against a rejection this fixture holds open until it
 *    chooses: a count taken after awaiting an ALREADY-settled promise proves
 *    nothing about who waited.
 *
 * 5. THE BANNER NAMES THE PORT THAT IS LISTENING. `openForward` resolves with
 *    the port actually bound - an auto rule asked for 0, and a pinned rule can
 *    be handed a different one. Naming the requested port is §4.10's second
 *    defect exactly, and on an auto rule it prints "localhost:0".
 *
 * 6. A TERMINAL OWNS WHAT IT OPENED, AND THE ENDING IS THE SESSION'S.
 *    `releaseSession(a)` drops exactly session a's entries; session b's
 *    forwards belong to a tab that is still open, and a release keyed on
 *    anything coarser closes the wrong tab's rows out of the page.
 *
 * 7. AN UNREADABLE STORE IS ONE BANNER, NOT A FAILED CONNECT. Same ordering
 *    claim and same deferred-rejection fixture as section 4.
 *
 * 8. THE CALL SITE AND THE TWO RELEASES. The `finishSsh` release sits ABOVE
 *    `if (s.disposed) return;`: a disposed pane's forwards are as dead as a
 *    live one's, so a release under that guard leaks every entry for every tab
 *    the user closed. Two independent `includes` are both satisfied by a
 *    release written BELOW it, so this compares indices. Position is not the
 *    whole claim, though: the call site also has to be UNCONDITIONAL (wrapped
 *    in a runtime-false guard the feature is inert for every rule and every
 *    gate in this repo passes) and the adapter-close release has to be
 *    UNDEFERRED (queued into a microtask it survives the session it is ending).
 *    Two structural assertions each, and the second of each pair is the one a
 *    reviewer generation found the first one blind to: an EXPRESSION guard
 *    (`sessionEnded && void startHostForwards(...)`) is a direct top-level
 *    statement, and `await` defers without a callback. Every one of them closes
 *    an open set of spellings that no deny-list could.
 *
 * 9. THE ROW THE TERMINAL'S FORWARD GETS. "Running (with host)", the port that
 *    is actually listening, and a disabled Start/Stop whose tooltip says where
 *    to stop it. Nothing else in the suite reads `RuleCard.tsx` for any of it.
 *
 * 10. §1.6 IN THE SECOND STORE TOO. Every `useHostOwnedForwards(` selector
 *    returns a primitive: one that builds a fresh object is never `Object.is`
 *    its own last return, and under zustand v5 that is "Maximum update depth
 *    exceeded" (research §12.7). The allow-list has to recurse on every
 *    operator whose VALUE is an operand rather than the operator's own result -
 *    `??`/`||`/`&&`, and also the comma and the assignments, which is where it
 *    had a measured hole. Its access-chain arm is rooted on the selector's own
 *    PARAMETER NAME, read off the arrow: rooted on the letter `s` it refused
 *    `(state) => state.byRule[id]?.boundPort`, and a check that reddens on a
 *    rename is a check the next reader weakens. `forwards-shell-verify.ts`
 *    carries a COPY of the same helper for `useForwardRuntime`, whose selectors
 *    were still behind the deny-list this one replaced (no `scripts/lib` exists
 *    yet - VLT-33).
 *
 * 11. TWO PANES ON ONE HOST ARE TWO OWNERS, AND THE SECOND IS REFUSED -
 *    SEQUENTIALLY AND CONCURRENTLY. The terminal dials its own session per
 *    pane, so two tabs to one host are two autostart runs; `hostOwned.ts` is
 *    keyed by rule id alone and cannot represent two owners, so `claim` used to
 *    OVERWRITE and the first tab's live listener became untracked. Reachable
 *    with no timing at all through the default rule shape, because a blank
 *    Local port binds a second port successfully. And the two runs are not
 *    serialised by anything, so the ordering that matters is BOTH STARTED
 *    BEFORE EITHER IS AWAITED - the one a pre-bind read cannot separate.
 *
 * 12. A CLAIM MUST NOT LAND AFTER THE SESSION'S RELEASE, AND A DEAD SESSION
 *    MUST NOT BIND AT ALL. Both release sites are one-shot, so an entry written
 *    after either has run is never released: the row reads "Running (with
 *    host)" for the app's whole lifetime with a disabled Stop and a note
 *    pointing at a tab that is already gone. `finishSsh` sets its flag
 *    unconditionally, so a session that ended before this run reached its first
 *    bind is a real state too - and a bind-then-check loop orphaned one
 *    listener on it before breaking.
 *
 * 13. NEVER REJECTS, AND STRUCTURALLY SO. The call site is a `void` and there
 *    is no `unhandledrejection` handler in `src/`. Before the fix the claim
 *    held only by another file's ordering.
 *
 * 14. WHOEVER RESOLVES SECOND YIELDS. The page's status was read BEFORE the
 *    bind and the claim written AFTER it with no re-check, so a Start clicked
 *    mid-bind left two live listeners (auto port) or a row whose dot, status
 *    line and button gave three different answers. The re-check yields on
 *    `running` and CLAIMS on `starting`: a page Start still dialling can fail,
 *    and both sides yielding to each other leaves the rule down on both, which
 *    is a wrong answer rather than a louder one. The page's own half of that
 *    rule lives in `controller.ts` and is checked as C10 in
 *    `forwards-shell-verify.ts`.
 *
 * 15. THE BANNER SAYS SOMETHING FOR EVERY REJECTION SHAPE. `describeError`'s
 *    raw-string arm (section 4) and `Error` arm (section 7) were covered; its
 *    `JSON.stringify` and `String(e)` fallbacks were not. Banner text only, so
 *    low stakes - but arms nothing exercises is the shape that has produced
 *    real defects against a green suite twice in this wave.
 *
 * 16. AUTOSTART NEVER WRITES THE PAGE'S STORE. The load-bearing half of VLT-94,
 *    and the one thing the `AutostartDeps` seam cannot see: `claimHostOwned` is
 *    injected, a direct `useForwardRuntime.getState().markRunning(...)` is not.
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import ts from "typescript";

import type { AutostartDeps } from "../src/modules/forwards/autostart";
import type { HostOwnedEntry } from "../src/modules/forwards/hostOwned";
import type { ForwardStatus } from "../src/modules/forwards/runtime";
import type { ForwardRule } from "../src/modules/forwards/types";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (rel: string) => readFileSync(join(repoRoot, rel), "utf8");

let failed = 0;
/**
 * HAZARD, named here rather than fixed here: this compares
 * `JSON.stringify(got) === JSON.stringify(want)`, and `JSON.stringify(undefined)`
 * is itself `undefined` - so an UNDEFINED `want` also matches every value that
 * does not serialise (a function, a symbol, `undefined` itself). Such a call
 * reads as if it proved something and is inert.
 *
 * Not rewritten, because THREE different `check()` signatures exist across this
 * verify suite - `check(label, got, want)` here and in `rdp-tunnel-verify.ts`,
 * `check(name, ok, detail?)` in `vault-shell-verify.ts:32`, `check(label, cond)`
 * in `hosts-header-narrow-verify.ts:47` - and changing one is a cross-script
 * change with no relation to this step. The rule instead: an assertion whose
 * `want` could be `undefined` uses `assert(... === undefined, ...)`, which
 * compares the value rather than its serialisation. The `[wiring]` block's
 * `hostOwnedBy` claim is the one place in this file that needed it.
 */
function check(label: string, got: unknown, want: unknown): void {
  if (JSON.stringify(got) === JSON.stringify(want)) {
    console.log(`  ok: ${label}`);
  } else {
    console.error(`  FAIL: ${label} = ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
    failed++;
  }
}
function assert(cond: boolean, msg: string, detail?: unknown): void {
  if (cond) console.log(`  ok: ${msg}`);
  else {
    console.error(`  FAIL: ${msg}`, detail === undefined ? "" : JSON.stringify(detail));
    failed++;
  }
}

// ---------------------------------------------------------------------------
// Stand-in for the Tauri IPC bridge, installed BEFORE the modules under test
// are imported - the same idiom and the same reason as
// `scripts/rdp-tunnel-verify.ts:169-179`. `autostart.ts` reaches
// `modules/forwards/store` and `modules/ssh/bridge` for its DEFAULT deps, and
// both of those touch `@tauri-apps/*` at module scope. Every section below
// injects its own deps, so nothing here should ever be called: an unexpected
// command throws rather than answering, so a section that silently fell
// through to the real bridge fails instead of passing.
// ---------------------------------------------------------------------------
(globalThis as { window?: unknown }).window = {
  __TAURI_INTERNALS__: {
    transformCallback: () => 1,
    unregisterCallback: () => true,
    invoke: (cmd: string) => {
      throw new Error(`forward-autostart-verify: nothing here should reach Tauri (got ${cmd})`);
    },
  },
};

const { defaultAutostartDeps, startHostForwards } =
  await import("../src/modules/forwards/autostart");
const { useHostOwnedForwards } = await import("../src/modules/forwards/hostOwned");
// Imported as a VALUE, not `import type`, and that is the whole of section 15:
// `autostart.ts` already holds a live reference to this store for its own
// `defaultAutostartDeps.runtimeStatus`, so a direct `markRunning` inside
// `startHostForwards` is invisible to every dep-injected assertion in this
// file. `claimHostOwned` is behind the seam; a store write is not.
const { useForwardRuntime } = await import("../src/modules/forwards/runtime");
// Imported for REFERENCE IDENTITY in the `[wiring]` block, not to be called:
// `typeof defaultAutostartDeps.openForward === "function"` is satisfied by any
// function at all, including `openForwardForConnection` - which takes a HOST id
// and DIALS if there is no session. Loadable here only because the stand-in
// above is already installed and `autostart.ts` has already pulled this module
// in for its own defaults.
const { closeSshForward, openSshForward } = await import("../src/modules/ssh/bridge");

// ---------------------------------------------------------------------------
// The fixtures.
// ---------------------------------------------------------------------------

const rule = (over: Partial<ForwardRule> = {}): ForwardRule => ({
  id: "f-1",
  name: "db tunnel",
  hostId: "h-1",
  localPort: 18080,
  remoteHost: "10.0.0.9",
  remotePort: 5432,
  startWithHost: true,
  ...over,
});

type OpenCall = { id: number; localPort: number; remoteHost: string; remotePort: number };
type CloseCall = { id: number; boundPort: number };

let nextAutoPort = 45000;

/**
 * One run's world: recorded calls, a banner sink, and the deps to drive
 * `startHostForwards` with.
 *
 * The default `openForward` answers the way `session.rs` does - a pinned port
 * is bound literally and comes back as itself, `0` means "the OS picks" and
 * comes back as whatever it chose. Returning a fresh number either way would
 * make the port ASKED FOR and the port BOUND indistinguishable, which is the
 * mock-fidelity defect `rdp-tunnel-verify.ts:151-155` names and which would
 * turn section 5 into a tautology.
 *
 * `claimHostOwned` writes to the REAL store as well as recording, and
 * `hostOwnedBy` READS the real store by default - the same pair
 * `defaultAutostartDeps` wires up. That is what lets section 12 drive two
 * sequential runs and have the second one actually see the first one's claim,
 * rather than testing a copy of the map kept in this file.
 *
 * `statusFn` exists because the page's status is read TWICE per rule now, once
 * before the bind and once after it, and the interesting case is the two reads
 * DISAGREEING (`status`, a flat record, cannot express that). `statusCalls`
 * records every read so a fixture can prove the second one happened at all.
 */
function world(over: {
  rules?: ForwardRule[];
  listRules?: () => Promise<ForwardRule[]>;
  status?: Record<string, ForwardStatus>;
  statusFn?: (ruleId: string, nth: number) => ForwardStatus;
  open?: (call: OpenCall) => Promise<number>;
  close?: (call: CloseCall) => Promise<boolean>;
  hostOwnedBy?: (ruleId: string) => number | undefined;
  stillLive?: () => boolean;
}) {
  const banners: string[] = [];
  const openCalls: OpenCall[] = [];
  const closeCalls: CloseCall[] = [];
  const statusCalls: string[] = [];
  const claims: Array<{ ruleId: string; entry: HostOwnedEntry }> = [];
  const deps: AutostartDeps = {
    listRules: over.listRules ?? (async () => over.rules ?? []),
    openForward: async (id, localPort, remoteHost, remotePort) => {
      const call = { id, localPort, remoteHost, remotePort };
      openCalls.push(call);
      return over.open ? await over.open(call) : localPort || nextAutoPort++;
    },
    closeForward: async (id, boundPort) => {
      const call = { id, boundPort };
      closeCalls.push(call);
      return over.close ? await over.close(call) : true;
    },
    runtimeStatus: (ruleId) => {
      const nth = statusCalls.filter((seen) => seen === ruleId).length;
      statusCalls.push(ruleId);
      if (over.statusFn) return over.statusFn(ruleId, nth);
      return over.status?.[ruleId] ?? "stopped";
    },
    hostOwnedBy: (ruleId) =>
      over.hostOwnedBy
        ? over.hostOwnedBy(ruleId)
        : useHostOwnedForwards.getState().byRule[ruleId]?.sessionId,
    claimHostOwned: (ruleId, entry) => {
      claims.push({ ruleId, entry });
      useHostOwnedForwards.getState().claim(ruleId, entry);
    },
    ...(over.stillLive ? { stillLive: over.stillLive } : {}),
  };
  return {
    deps,
    banners,
    openCalls,
    closeCalls,
    statusCalls,
    claims,
    writeBanner: (t: string) => banners.push(t),
  };
}

/** Empty the shared map between sections. Test-only: production has exactly
 *  two writers, `claim` and `releaseSession`. */
function resetHostOwned(): void {
  useHostOwnedForwards.setState({ byRule: {} });
}

/** Let queued microtasks run without settling anything the fixture is holding
 *  open on purpose. */
async function tick(): Promise<void> {
  for (let i = 0; i < 4; i++) await new Promise((r) => setTimeout(r, 0));
}

/** The banners, written out by value rather than imported: a check that
 *  reached for the module's own template would pass with the template
 *  rewritten. `->` is ASCII deliberately - see `autostart.ts`'s note, and
 *  `ssh-session.ts:498-501`'s existing forward banner. */
const forwardingBanner = (bound: number, target: string, name: string) =>
  `\x1b[2m[tervia] forwarding localhost:${bound} -> ${target} (${name})\x1b[0m\r\n`;
const failedBanner = (name: string, message: string) =>
  `\x1b[33m[tervia] forward "${name}" failed: ${message}\x1b[0m\r\n`;
/** Split by status on purpose. `starting` is a page Start still DIALLING, which
 *  can then fail - telling the user it was already up elsewhere is then a wrong
 *  answer, not a louder one. */
const skippedBanner = (name: string, status: "running" | "starting") =>
  status === "running"
    ? `\x1b[33m[tervia] forward "${name}" is already running from the Port Forwarding page; not starting a second one.\x1b[0m\r\n`
    : `\x1b[33m[tervia] forward "${name}" is starting from the Port Forwarding page; not starting a second one.\x1b[0m\r\n`;
const otherTerminalBanner = (name: string) =>
  `\x1b[33m[tervia] forward "${name}" is already open on another terminal for this host; not starting a second one.\x1b[0m\r\n`;
const yieldedBanner = (name: string) =>
  `\x1b[33m[tervia] forward "${name}" was started from the Port Forwarding page while this one was binding; closing the one this terminal just opened.\x1b[0m\r\n`;

// ===========================================================================
console.log("[1. startWithHost] a rule that does not start with its host is never opened");
// ===========================================================================
{
  resetHostOwned();
  const off = rule({ id: "f-off", name: "manual only", startWithHost: false, localPort: 19000 });
  const on = rule({ id: "f-on", name: "db tunnel", startWithHost: true, localPort: 18080 });
  const w = world({ rules: [off, on] });
  await startHostForwards("h-1", 7, w.writeBanner, w.deps);

  check(
    "exactly one forward was opened, and it is the startWithHost one",
    w.openCalls.map((c) => c.localPort),
    [18080],
  );
  check(
    "the manual rule was not claimed either",
    Object.keys(useHostOwnedForwards.getState().byRule),
    ["f-on"],
  );
  check("and it produced no banner of its own", w.banners, [
    forwardingBanner(18080, "10.0.0.9:5432", "db tunnel"),
  ]);
  // THE LOAD-BEARING HALF OF VLT-94, and nothing else in this suite asserts it.
  // `autostart.ts` holds a live `useForwardRuntime` reference for its own
  // default `runtimeStatus`, so `useForwardRuntime.getState().markRunning(...)`
  // inside `startHostForwards` would satisfy every dep-injected check in this
  // file. If it ever happened the page would believe it can Stop a
  // terminal-owned rule, and would spend a claim nobody took. Read here rather
  // than after a reset, because the claim is that autostart NEVER writes it.
  check(
    "autostart left the PAGE's runtime store completely untouched",
    useForwardRuntime.getState().byRule,
    {},
  );
}

// ===========================================================================
console.log("\n[2. hostId] a rule bound to another host is never opened on this session");
// ===========================================================================
{
  resetHostOwned();
  const other = rule({
    id: "f-other",
    name: "other host",
    hostId: "h-2",
    localPort: 19001,
    remoteHost: "10.9.9.9",
  });
  const mine = rule({ id: "f-mine", name: "db tunnel", hostId: "h-1", localPort: 18080 });
  const w = world({ rules: [other, mine] });
  await startHostForwards("h-1", 7, w.writeBanner, w.deps);

  check(
    "only this host's rule reached the bridge",
    w.openCalls.map((c) => [c.localPort, c.remoteHost]),
    [[18080, "10.0.0.9"]],
  );
  check(
    "and only it was claimed",
    w.claims.map((c) => c.ruleId),
    ["f-mine"],
  );
}

// ===========================================================================
console.log("\n[3. mutual exclusion] a rule the PAGE owns is skipped, and the loop carries on");
// ===========================================================================
/** The skip banner the MODULE actually wrote, per page status - kept so the two
 *  wordings can be compared against each other rather than against this file's
 *  own copy of them. */
const skipBannersWritten: Record<string, string | undefined> = {};
for (const pageStatus of ["running", "starting"] as const) {
  resetHostOwned();
  const owned = rule({ id: "f-page", name: "page rule", localPort: 18080 });
  const free = rule({ id: "f-free", name: "free rule", localPort: 18081 });
  const w = world({ rules: [owned, free], status: { "f-page": pageStatus } });
  await startHostForwards("h-1", 7, w.writeBanner, w.deps);
  skipBannersWritten[pageStatus] = w.banners[0];

  check(
    `a "${pageStatus}" rule is not opened a second time`,
    w.openCalls.map((c) => c.localPort),
    [18081],
  );
  check(
    `a "${pageStatus}" rule is not claimed`,
    w.claims.map((c) => c.ruleId),
    ["f-free"],
  );
  check(
    `a "${pageStatus}" rule is never in the terminal's map`,
    Object.keys(useHostOwnedForwards.getState().byRule),
    ["f-free"],
  );
  check(
    `the skip banner names the rule AND its status, by exact text ("${pageStatus}")`,
    w.banners[0],
    skippedBanner("page rule", pageStatus),
  );
  check(
    `and the rule AFTER the skip still came up ("${pageStatus}") - a continue, not a return`,
    w.banners[1],
    forwardingBanner(18081, "10.0.0.9:5432", "free rule"),
  );
}
{
  // The paired positive for the OTHER two statuses: a rule the page tried and
  // failed to start, and one it has stopped, are both free for the terminal to
  // take. Without this the section passes with the guard widened to "any
  // status the store knows about".
  resetHostOwned();
  const failedRule = rule({ id: "f-failed", name: "failed rule", localPort: 18080 });
  const stopped = rule({ id: "f-stopped", name: "stopped rule", localPort: 18081 });
  const w = world({
    rules: [failedRule, stopped],
    status: { "f-failed": "failed", "f-stopped": "stopped" },
  });
  await startHostForwards("h-1", 7, w.writeBanner, w.deps);
  check(
    "a failed or stopped rule is the terminal's to start",
    w.openCalls.map((c) => c.localPort),
    [18080, 18081],
  );
}
{
  // Read off what the MODULE wrote, not off this file's copy of it: a check
  // comparing `skippedBanner("x", "running")` with `skippedBanner("x",
  // "starting")` is a statement about the fixture and stays green while the
  // module answers one sentence for both.
  assert(
    skipBannersWritten["running"] !== undefined &&
      skipBannersWritten["starting"] !== undefined &&
      skipBannersWritten["running"] !== skipBannersWritten["starting"],
    'the "running" and "starting" skips are not the same sentence',
    skipBannersWritten,
  );
  assert(
    !(skipBannersWritten["starting"] ?? "").includes("is already running"),
    'a rule the page is still DIALLING is not described as "already running" - it can still fail, and a rule that is then down on BOTH sides was told it was up elsewhere',
    skipBannersWritten["starting"],
  );
}

// ===========================================================================
console.log("\n[4. a bad rule is not a bad connect] the next rule opens, and the promise RESOLVES");
// ===========================================================================
{
  resetHostOwned();
  const bad = rule({ id: "f-bad", name: "busy port", localPort: 18080 });
  const good = rule({ id: "f-good", name: "db tunnel", localPort: 18081 });

  // A deferred the fixture controls, NOT an already-rejected promise: a
  // counter read after awaiting something already settled passes whether or
  // not anybody waited for it, which is the exact fixture defect wave 2's own
  // step-9 block shipped.
  let rejectBad: (e: unknown) => void = () => {};
  const parked = new Promise<number>((_, rej) => {
    rejectBad = rej;
  });
  // The backend rejects `invoke` with a RAW STRING, which is the branch
  // `describeError`'s string arm exists for.
  const bindError = "ssh: bind 127.0.0.1:18080 failed: Address already in use (os error 98)";

  const w = world({
    rules: [bad, good],
    open: (call) => (call.localPort === 18080 ? parked : Promise.resolve(call.localPort)),
  });
  const settled = startHostForwards("h-1", 7, w.writeBanner, w.deps).then(
    () => "resolved" as const,
    (e) => `rejected: ${e instanceof Error ? e.message : String(e)}`,
  );

  await tick();
  check("the loop is parked on the first rule's bind", w.openCalls.length, 1);
  check("so the second rule has not been asked for yet", w.banners.length, 0);

  rejectBad(bindError);
  check("startHostForwards RESOLVES rather than rejecting", await settled, "resolved");
  // Counters read AFTER the await above, which is what makes them a statement
  // about ordering rather than about a race this fixture happened to win.
  check(
    "the failed rule wrote its banner, by exact text",
    w.banners[0],
    failedBanner("busy port", bindError),
  );
  check(
    "and the rule after it still opened",
    w.banners[1],
    forwardingBanner(18081, "10.0.0.9:5432", "db tunnel"),
  );
  check("two binds were attempted in all", w.openCalls.length, 2);
  check("the failed rule owns nothing", Object.keys(useHostOwnedForwards.getState().byRule), [
    "f-good",
  ]);
}

// ===========================================================================
console.log("\n[5. the bound port] the banner names what openForward RESOLVED with");
// ===========================================================================
{
  resetHostOwned();
  // An auto rule: asks for 0, and 0 is the one number that is never listening.
  const auto = rule({ id: "f-auto", name: "auto rule", localPort: 0 });
  const w = world({ rules: [auto], open: async () => 54321 });
  await startHostForwards("h-1", 7, w.writeBanner, w.deps);
  check("the bridge was asked for 0", w.openCalls[0]?.localPort, 0);
  check(
    "and the banner names the port the OS chose",
    w.banners[0],
    forwardingBanner(54321, "10.0.0.9:5432", "auto rule"),
  );
  check("as does the claim", w.claims[0]?.entry, { sessionId: 7, boundPort: 54321 });
}
{
  resetHostOwned();
  // A PINNED rule handed a different port. The backend binds what it binds;
  // the row and the banner have to say that, not what the rule asked for.
  const pinned = rule({ id: "f-pin", name: "pinned rule", localPort: 18080 });
  const w = world({ rules: [pinned], open: async () => 18099 });
  await startHostForwards("h-1", 7, w.writeBanner, w.deps);
  check("the bridge was asked for the pinned port", w.openCalls[0]?.localPort, 18080);
  check(
    "and the banner still names the port it was HANDED",
    w.banners[0],
    forwardingBanner(18099, "10.0.0.9:5432", "pinned rule"),
  );
  check("as does the claim", w.claims[0]?.entry, { sessionId: 7, boundPort: 18099 });
}

// ===========================================================================
console.log(
  "\n[6. the map] claim records the session and the bound port; release takes one session",
);
// ===========================================================================
{
  resetHostOwned();
  const a1 = rule({ id: "f-a1", name: "a one", hostId: "h-1", localPort: 18080 });
  const a2 = rule({ id: "f-a2", name: "a two", hostId: "h-1", localPort: 0 });
  const b1 = rule({ id: "f-b1", name: "b one", hostId: "h-2", localPort: 18443 });

  const wa = world({ rules: [a1, a2, b1], open: async (c) => c.localPort || 54321 });
  await startHostForwards("h-1", 11, wa.writeBanner, wa.deps);
  const wb = world({ rules: [a1, a2, b1], open: async (c) => c.localPort || 54322 });
  await startHostForwards("h-2", 22, wb.writeBanner, wb.deps);

  check(
    "every opened rule is in the map, with its session and its BOUND port",
    useHostOwnedForwards.getState().byRule,
    {
      "f-a1": { sessionId: 11, boundPort: 18080 },
      "f-a2": { sessionId: 11, boundPort: 54321 },
      "f-b1": { sessionId: 22, boundPort: 18443 },
    },
  );

  useHostOwnedForwards.getState().releaseSession(11);
  check(
    "releasing session 11 drops exactly its entries and leaves 22's standing",
    useHostOwnedForwards.getState().byRule,
    { "f-b1": { sessionId: 22, boundPort: 18443 } },
  );

  useHostOwnedForwards.getState().releaseSession(11);
  check(
    "and releasing it again is a no-op - both release sites fire without knowing about each other",
    useHostOwnedForwards.getState().byRule,
    { "f-b1": { sessionId: 22, boundPort: 18443 } },
  );

  useHostOwnedForwards.getState().releaseSession(22);
  check("the last session out leaves the map empty", useHostOwnedForwards.getState().byRule, {});
}
{
  // A reconnect: the same rule, a new session id. The claim overwrites, and
  // the OLD session's release must not take the new session's entry with it -
  // which is what a `releaseSession` keyed on the rule instead would do.
  //
  // THE RELEASE COMES FIRST, and that is the real order rather than a
  // convenience: `finishSsh` releases at the TOP of itself and only then
  // dispatches `scheduleSshReconnect`, and `runSshReconnect`'s disposed branch
  // goes through `pty.close()`, which releases too. Without a release in
  // between, the second run is now correctly REFUSED - section 11's skip - so
  // this fixture would be asserting a state the app cannot reach.
  resetHostOwned();
  const r = rule({ id: "f-re", name: "reconnecting", localPort: 18080 });
  const first = world({ rules: [r] });
  await startHostForwards("h-1", 31, first.writeBanner, first.deps);
  useHostOwnedForwards.getState().releaseSession(31);
  const second = world({ rules: [r] });
  await startHostForwards("h-1", 32, second.writeBanner, second.deps);
  check("the newer session owns the rule", useHostOwnedForwards.getState().byRule, {
    "f-re": { sessionId: 32, boundPort: 18080 },
  });
  useHostOwnedForwards.getState().releaseSession(31);
  check("and the dead session's release leaves it alone", useHostOwnedForwards.getState().byRule, {
    "f-re": { sessionId: 32, boundPort: 18080 },
  });
}

// ===========================================================================
console.log("\n[7. an unreadable store] one banner, no binds, and still RESOLVED");
// ===========================================================================
{
  resetHostOwned();
  let rejectList: (e: unknown) => void = () => {};
  const parkedList = new Promise<ForwardRule[]>((_, rej) => {
    rejectList = rej;
  });
  const w = world({ listRules: () => parkedList });
  const settled = startHostForwards("h-1", 7, w.writeBanner, w.deps).then(
    () => "resolved" as const,
    (e) => `rejected: ${e instanceof Error ? e.message : String(e)}`,
  );

  await tick();
  check("nothing is written while the read is still in flight", w.banners.length, 0);

  rejectList(new Error("forwards: store file is unreadable"));
  check("startHostForwards RESOLVES", await settled, "resolved");
  check("with one banner, naming the reason", w.banners, [
    "\x1b[33m[tervia] could not read the forward rules: forwards: store file is unreadable\x1b[0m\r\n",
  ]);
  check("and nothing was bound", w.openCalls.length, 0);
  check("nor claimed", useHostOwnedForwards.getState().byRule, {});
}

// ===========================================================================
console.log("\n[wiring] defaultAutostartDeps is complete");
// ===========================================================================
{
  // Not a behavioural claim - the real deps reach Tauri and cannot be called
  // here - but a missing key is a `TypeError: deps.openForward is not a
  // function` at the moment a session connects, on a path no other check
  // touches.
  check(
    "every dep the production caller relies on is present and callable",
    (
      [
        "listRules",
        "openForward",
        "closeForward",
        "runtimeStatus",
        "hostOwnedBy",
        "claimHostOwned",
        "stillLive",
      ] as const
    ).map((k) => typeof defaultAutostartDeps[k]),
    ["function", "function", "function", "function", "function", "function", "function"],
  );
  check(
    'runtimeStatus answers "stopped" for a rule the page has never heard of',
    defaultAutostartDeps.runtimeStatus("f-never-started"),
    "stopped",
  );
  // `assert` rather than `check`, and the reason is the hazard named at
  // `check`'s own definition: it compares `JSON.stringify(got) ===
  // JSON.stringify(want)`, `JSON.stringify(undefined)` IS `undefined`, and this
  // is the one call site in this file with an undefined WANT - so as a `check`
  // it also passed for a returned function or symbol. `=== undefined` compares
  // the value.
  assert(
    defaultAutostartDeps.hostOwnedBy("f-never-started") === undefined,
    "hostOwnedBy answers undefined (strictly, not merely unserialisable) for a rule no terminal owns",
    defaultAutostartDeps.hostOwnedBy("f-never-started"),
  );
  // Module scope knows of no session, so the DEFAULT must answer "alive": a
  // default of false would stop every autostart run on its first rule for any
  // caller that did not pass a session-scoped one.
  check(
    "the default stillLive answers true - the session-scoped one is the call site's to supply",
    defaultAutostartDeps.stillLive?.(),
    true,
  );
  // REFERENCE IDENTITY, which is the commit's headline claim and the one thing
  // `typeof === "function"` cannot see. VLT-11 and research §5.4 rest on
  // autostart calling `openSshForward` - a forward on a LIVE SESSION ID - and
  // never `openForwardForConnection`, which takes a HOST id and DIALS a
  // connection if there is none. Wired to that one, a `startWithHost` rule
  // opens an SSH connection nobody asked for, on a host with no terminal.
  // `tsc` gives partial cover because the two signatures differ, but a
  // SAME-SHAPED wrong function typechecks and passes a `typeof` check outright
  // (mutations M-W1, M-W2).
  check(
    "openForward IS ssh/bridge's openSshForward, by reference - not a same-shaped stand-in",
    defaultAutostartDeps.openForward === openSshForward,
    true,
  );
  check(
    "closeForward IS closeSshForward, by reference - the yield path closes ONE listener, not the session",
    defaultAutostartDeps.closeForward === closeSshForward,
    true,
  );
  // The control for the pair above: two identity checks against the same
  // function would both pass while the deps held one function twice.
  check(
    "and those are two different functions, so neither check above can pass by accident",
    (openSshForward as unknown) === (closeSshForward as unknown),
    false,
  );
}
{
  // And the OMITTED case, which is what the `?? true` in the loop covers: a
  // deps object with no `stillLive` key at all must behave as "alive", not stop
  // the run on its first rule.
  resetHostOwned();
  const bare = world({ rules: [rule({ id: "f-bare", localPort: 18080 })] });
  delete bare.deps.stillLive;
  await startHostForwards("h-1", 7, bare.writeBanner, bare.deps);
  check(
    "a deps object with no stillLive at all still starts rules",
    Object.keys(useHostOwnedForwards.getState().byRule),
    ["f-bare"],
  );
}

// ===========================================================================
// Source-pin helpers for sections 8-10.
// ===========================================================================

/** A line with its trailing `//` comment removed, string literals respected -
 *  quote-aware rather than a regex because a `//` inside a string is not a
 *  comment. Copied from `scripts/host-editor-verify.ts`. */
function stripLineComment(line: string): string {
  let quote = "";
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote) {
      if (c === "\\") i++;
      else if (c === quote) quote = "";
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      quote = c;
      continue;
    }
    if (c === "/" && line[i + 1] === "/") return line.slice(0, i);
  }
  return line;
}

/**
 * Comments removed, so a POSITIVE assertion runs over text a comment cannot
 * satisfy. Copied from `scripts/host-editor-verify.ts:191`, JSX branch in the
 * NEGATIVE-LOOKAHEAD form: the lazy form `\{\s*\/\*[\s\S]*?\*\/\s*\}` reads as
 * equivalent and is not - it is allowed to cross an intervening close-comment
 * marker while searching for one followed by `}`, and on a real file it
 * swallowed 50752 characters in another script, silencing a negative that then
 * ran blind over deleted text.
 */
function stripComments(src: string): string {
  const withoutJsxComments = src.replace(/\{\s*\/\*(?:(?!\*\/)[\s\S])*\*\/\s*\}/g, "");
  return withoutJsxComments
    .split("\n")
    .filter((line) => {
      const t = line.trim();
      return !(t.startsWith("//") || t.startsWith("/*") || t.startsWith("*"));
    })
    .map(stripLineComment)
    .join("\n");
}

// The mandatory two-assertion self-test for a script that strips a `.tsx`.
{
  const probe = stripComments(
    "type P = { /** c */ x: X };\nconst KEEP = 1;\nconst j = <div>{/* c */}</div>;",
  );
  assert(probe.includes("KEEP"), "stripComments self-test: KEEP survives");
  assert(
    !/\{\s*\/\*\s*c\s*\*\/\s*\}/.test(probe),
    "stripComments self-test: the JSX comment {/* c */} does not",
  );
}

/**
 * Whitespace AND a comma before a closing bracket are PRETTIER'S; everything
 * else is the claim. Both halves are needed: a legal multi-line reformat under
 * this repo's config (`trailingComma: "all"`) adds a comma that plain
 * whitespace-collapsing does not remove, which reddens a pin over a change
 * that means nothing - the M9 control below is what measures it.
 */
const norm = (s: string): string => s.replace(/\s+/g, "").replace(/,+([)\]}])/g, "$1");

function parse(rel: string, src: string): ts.SourceFile {
  return ts.createSourceFile(
    rel,
    src,
    ts.ScriptTarget.ESNext,
    true,
    rel.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS,
  );
}

/**
 * Every call whose CALLEE text is `name`, whitespace-normalised on both sides.
 *
 * NORMALISED AND NOT COMPARED RAW, and the M9 reflow control is what found it:
 * a member chain long enough to wrap - `useHostOwnedForwards.getState()
 * .releaseSession(...)`, which Prettier splits over three lines under a
 * narrower `printWidth` - has a callee whose `getText()` carries the newlines
 * and the indentation. A raw `===` then finds zero calls, and the assertion
 * rooted on it reddens over a change that means nothing. Whitespace is
 * Prettier's; everything else is the claim.
 */
function findCallsTo(root: ts.Node, sf: ts.SourceFile, name: string): ts.CallExpression[] {
  const want = norm(name);
  const out: ts.CallExpression[] = [];
  const visit = (n: ts.Node): void => {
    if (ts.isCallExpression(n) && norm(n.expression.getText(sf)) === want) out.push(n);
    ts.forEachChild(n, visit);
  };
  visit(root);
  return out;
}

/** The initializer of `const <name> = ...`, or null. */
function findConstInitializer(sf: ts.SourceFile, name: string): ts.Expression | null {
  let out: ts.Expression | null = null;
  const visit = (n: ts.Node): void => {
    if (
      ts.isVariableDeclaration(n) &&
      ts.isIdentifier(n.name) &&
      n.name.text === name &&
      n.initializer
    ) {
      out = n.initializer;
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return out;
}

function findFunctionBody(sf: ts.SourceFile, name: string): ts.Node | null {
  let out: ts.Node | null = null;
  const visit = (n: ts.Node): void => {
    if (ts.isFunctionDeclaration(n) && n.name?.text === name && n.body) out = n.body;
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return out;
}

/** Walking up from `node`, is every ancestor up to `fnBody` free of a NESTED
 *  function? Tells a direct statement of a function's own body from a call
 *  buried in a decoy arrow declared in the same scope - the count alone cannot
 *  bite that deletion (VLT-76's lesson). */
function isDirectlyInFunctionBody(node: ts.Node, fnBody: ts.Node): boolean {
  let cur: ts.Node | undefined = node.parent;
  while (cur && cur !== fnBody) {
    if (
      ts.isFunctionDeclaration(cur) ||
      ts.isFunctionExpression(cur) ||
      ts.isArrowFunction(cur) ||
      ts.isMethodDeclaration(cur)
    ) {
      return false;
    }
    cur = cur.parent;
  }
  return cur === fnBody;
}

/**
 * The `ExpressionStatement` this expression is the whole of, or null - walking
 * up, so it works for a call buried under `void <call>.catch(...)`.
 *
 * WHAT THIS ANSWERS THAT {@link isDirectlyInFunctionBody} CANNOT, and it is a
 * total-feature-loss hole this suite had twice: nesting and CONDITIONALITY are
 * different questions. `if (sessionEnded) { void startHostForwards(...) }` where
 * `sessionEnded` is `false` at that point is neither below an exit nor inside a
 * nested FUNCTION, so the positional and nesting checks both pass while the
 * statement never runs and the whole feature is inert for every rule -
 * measured, with 195/195 ok, `forwards-shell` green and `tsc --noEmit` green.
 * `allowUnreachableCode: false` does not fire either: a runtime-false guard is
 * REACHABLE code. (Measured which shapes TS7027 actually flags: `if (false)`
 * yes, `while (false)` yes, `if (0)` no, `if (someBoolean)` no.)
 *
 * Comparing this statement's own `parent` against the function BODY closes the
 * STATEMENT wrapper family at once - `if`, `try`, `for`, `switch`, a block
 * written next year - which is what a positional or nesting check never could,
 * because each of those is one more member of an open set.
 *
 * WHAT IT DOES NOT CLOSE, and the previous version of this sentence claimed
 * otherwise: the EXPRESSION family. `sessionEnded && void startHostForwards(...)`
 * is an expression statement whose parent IS the body, so this walk returns it
 * and the parent comparison passes - and with `sessionEnded` false at that point
 * the whole feature is inert for every rule again (measured: 57/57 scripts, this
 * file 219/219 ok, `tsc` and `prettier` clean). `&&`, `||`, `?:` and `??` are all
 * that shape. Section 8 closes them with a SECOND assertion, that the
 * statement's own `expression` IS the `void <call>.catch(...)` the shape checks
 * already located - not merely something inside it.
 */
function enclosingStatement(node: ts.Node): ts.ExpressionStatement | null {
  let cur: ts.Node | undefined = node;
  while (cur && !ts.isExpressionStatement(cur)) cur = cur.parent;
  return cur ? (cur as ts.ExpressionStatement) : null;
}

/**
 * The leftmost operand of a `&&`/`||` chain, parentheses unwrapped - or the
 * expression itself when it is not one.
 *
 * What turns "`hostOwned` is tested FIRST" into a claim about POSITION rather
 * than about presence. `.includes("hostOwned")` over a function body or a
 * ternary is position-blind: `starting ? … : hostOwned ? …` contains the name
 * and tests it second, and `if (hostOwned)` moved below an exhaustive `switch`
 * is dead code that typechecks under every flag this repo sets.
 */
function leftmostOperand(node: ts.Expression, sf: ts.SourceFile): string {
  let cur: ts.Expression = node;
  for (;;) {
    if (ts.isParenthesizedExpression(cur)) {
      cur = cur.expression;
      continue;
    }
    if (
      ts.isBinaryExpression(cur) &&
      (cur.operatorToken.kind === ts.SyntaxKind.BarBarToken ||
        cur.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken)
    ) {
      cur = cur.left;
      continue;
    }
    return norm(cur.getText(sf));
  }
}

/** Every conditional expression under `root`, nested ones included. */
function findConditionals(root: ts.Node): ts.ConditionalExpression[] {
  const out: ts.ConditionalExpression[] = [];
  const visit = (n: ts.Node): void => {
    if (ts.isConditionalExpression(n)) out.push(n);
    ts.forEachChild(n, visit);
  };
  visit(root);
  return out;
}

function findPropertyValue(
  obj: ts.ObjectLiteralExpression,
  name: string,
  sf: ts.SourceFile,
): ts.Expression | null {
  for (const prop of obj.properties) {
    if (ts.isPropertyAssignment(prop) && prop.name.getText(sf) === name) return prop.initializer;
  }
  return null;
}

/** Every `.ts`/`.tsx` file under `dir`, recursively. Copied from
 *  `scripts/forwards-shell-verify.ts:322-332`, for the repo-wide selector
 *  sweep section 10 needs. */
function walkSrcFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...walkSrcFiles(full));
    else if (/\.(ts|tsx)$/.test(entry)) out.push(full);
  }
  return out;
}

/** The selector arrow's own parameter name, whitespace-normalised, or `""` when
 *  it has none. What {@link primitiveSelectorBody}'s access-chain arm has to be
 *  ROOTED ON: the letter `s` is this codebase's habit and not the claim, and a
 *  check that reddens when somebody writes `(state) => state.byRule[id]?.status`
 *  is a check the next reader weakens rather than reads. Taken off the AST so
 *  the name the arm tests and the name the arrow declares cannot disagree. */
function selectorParamName(arrow: ts.ArrowFunction, sf: ts.SourceFile): string {
  const p = arrow.parameters[0];
  return p ? norm(p.name.getText(sf)) : "";
}

/**
 * Can this selector body only ever yield a PRIMITIVE?
 *
 * AN ALLOW-LIST, AND THE POLARITY IS THE CLAIM. The failure mode is "the
 * selector returns a FRESH REFERENCE", and the set of ways to produce one is
 * OPEN - an object literal, an array literal, `Object.keys(...)`,
 * `Object.values(...).map(...)`, `Object.entries(...)`, `new Set(...)`,
 * `structuredClone(...)`, `[...x]`, any helper written next year. The set of
 * shapes that can only produce a primitive is small and CLOSED. So anything not
 * named below is guilty until argued, INCLUDING EVERY CALL EXPRESSION: a fresh
 * collection is exactly what a call returns.
 *
 * What this replaced, and why the polarity had to flip rather than the list
 * grow. The deny-list here named four forms and TWO OF THEM COULD NEVER FIRE:
 * an object-literal arrow body must be parenthesised, so the node in this
 * position is a `ParenthesizedExpression` and never an
 * `ObjectLiteralExpression`; and `(s) => ...x` is a syntax error, so a
 * `SpreadElement` can never occupy this position at all. That left
 * `useHostOwnedForwards((s) => ({ a, b }))` - the exact case this section exists
 * to forbid - PASSING, alongside `Object.keys(s.byRule)`, `Object.entries(...)`,
 * `new Set(...)`, `structuredClone(s.byRule)` and bare `s.byRule`, every one of
 * them the same "Maximum update depth exceeded" failure under zustand v5
 * (research §12.7). Measured, not argued.
 *
 * Returns the REASON as well as the verdict, so a failure names the shape it
 * refused instead of only echoing the text.
 */
function primitiveSelectorBody(
  expr: ts.Expression,
  sf: ts.SourceFile,
  param: string,
): { ok: true } | { ok: false; why: string } {
  // Parentheses FIRST and to a fixed point, because parenthesising is how an
  // object-literal arrow body has to be written at all - unwrapping later would
  // leave the headline case looking like a shape nobody named.
  let cur: ts.Expression = expr;
  while (ts.isParenthesizedExpression(cur)) cur = cur.expression;

  // `!x`, `-x`, `+x`, `~x`, `typeof x`: a primitive whatever the operand is.
  if (ts.isPrefixUnaryExpression(cur) || ts.isTypeOfExpression(cur)) return { ok: true };

  if (ts.isBinaryExpression(cur)) {
    const kind = cur.operatorToken.kind;
    // `??`, `||` and `&&` PASS AN OPERAND THROUGH, so each side has to qualify
    // on its own: `s.byRule[id] ?? {}` is a fresh object on every miss.
    if (
      kind === ts.SyntaxKind.QuestionQuestionToken ||
      kind === ts.SyntaxKind.BarBarToken ||
      kind === ts.SyntaxKind.AmpersandAmpersandToken
    ) {
      const left = primitiveSelectorBody(cur.left, sf, param);
      if (!left.ok) return left;
      return primitiveSelectorBody(cur.right, sf, param);
    }
    // THE COMMA OPERATOR PASSES ITS RIGHT OPERAND THROUGH, exactly like `??`
    // three lines above, and it was the hole the "every other binary operator
    // yields a primitive" line below used to leave open. Measured with a real
    // new hook in `hostOwned.ts`:
    // `useHostOwnedForwards((s) => (s.byRule[ruleId]?.boundPort ?? 0, Object.keys(s.byRule)))`
    // came back GREEN, with this section printing three fresh PASSING
    // assertions calling it "returns a primitive" - a fresh array per store
    // read, which is the "Maximum update depth exceeded" loop the whole section
    // exists to forbid. `(0, X)` on its own is caught by TS2695; any
    // non-trivial left operand dodges that, and a return annotation cannot see
    // it either because the comma form satisfies any declared return type while
    // still handing back a fresh reference.
    //
    // The LEFT operand is evaluated and thrown away, so it cannot be what the
    // selector returns and does not need to qualify.
    if (kind === ts.SyntaxKind.CommaToken) return primitiveSelectorBody(cur.right, sf, param);
    // THE ASSIGNMENTS - `=`, `+=`, `??=`, `||=`, `&&=` and the rest - the other
    // operator class whose value is an operand: `(lastIds = Object.keys(s.byRule))`
    // measured GREEN the same way. `FirstAssignment`..`LastAssignment` is the
    // whole closed range, so no member of the family is left out by name.
    //
    // BOTH operands have to qualify, because `??=`/`||=`/`&&=` yield EITHER
    // side. In practice that refuses every assignment, since an assignment
    // TARGET is an identifier or an access chain that does not reach a
    // primitive field - and refusing is the right answer: nothing legitimate
    // assigns inside a zustand selector, and the allow-list's polarity is
    // "guilty until argued".
    if (kind >= ts.SyntaxKind.FirstAssignment && kind <= ts.SyntaxKind.LastAssignment) {
      const left = primitiveSelectorBody(cur.left, sf, param);
      if (!left.ok) return left;
      return primitiveSelectorBody(cur.right, sf, param);
    }
    // Every other binary operator - the comparisons, the arithmetic, the
    // bitwise ones - produces a primitive from any pair of operands. TRUE OF
    // WHAT IS LEFT, which is what the two arms above are for: the general
    // sentence was false for exactly the two classes whose value is an operand
    // rather than the operator's own result.
    return { ok: true };
  }

  // A ternary is its two arms, for the same reason `??` is.
  if (ts.isConditionalExpression(cur)) {
    const whenTrue = primitiveSelectorBody(cur.whenTrue, sf, param);
    if (!whenTrue.ok) return whenTrue;
    return primitiveSelectorBody(cur.whenFalse, sf, param);
  }

  if (
    ts.isNumericLiteral(cur) ||
    ts.isStringLiteral(cur) ||
    ts.isNoSubstitutionTemplateLiteral(cur) ||
    ts.isTemplateExpression(cur) ||
    cur.kind === ts.SyntaxKind.TrueKeyword ||
    cur.kind === ts.SyntaxKind.FalseKeyword ||
    cur.kind === ts.SyntaxKind.NullKeyword ||
    (ts.isIdentifier(cur) && cur.text === "undefined")
  ) {
    return { ok: true };
  }

  if (ts.isPropertyAccessExpression(cur) || ts.isElementAccessExpression(cur)) {
    // `.length` / `.size` is a number however the thing it counts was reached -
    // an array, a string, a `Map`, a `Set`, or the result of any call in front
    // of it.
    //
    // AND THIS ARM PASSES UNCONDITIONALLY ON THE NAME, which is the honest
    // description: it is a LEXICAL guess, not a typed one. `x.length` where
    // `length` is a user-defined field holding an object would be accepted, and
    // this script builds no `ts.Program`, so there is no checker here that could
    // tell the two apart. What makes the guess sound for the two stores it is
    // applied to is that neither entry type HAS such a field: `ForwardRuntimeEntry`
    // (`runtime.ts:38-48`) and `HostOwnedEntry` (`hostOwned.ts:47`) are a status
    // string plus numbers, `byRule` is a plain `Record`, and a `.length` or
    // `.size` written against any of them is a TS error rather than a selector
    // this arm would wave through. Kept as a comment rather than tightened: the
    // tightening that would actually close it is a type lookup, and refusing
    // `.length`/`.size` outright would refuse `useRunningCount`, the one real
    // selector in either store that builds a collection inside itself.
    if (
      ts.isPropertyAccessExpression(cur) &&
      (cur.name.text === "length" || cur.name.text === "size")
    ) {
      return { ok: true };
    }
    // Otherwise the chain has to reach PAST the entry, to one of its own
    // fields. `<param>.byRule` is the whole map and `<param>.byRule[id]` is the
    // whole entry; both are objects `claim` and `releaseSession` rebuild, so
    // neither is ever `Object.is` its own last return. Both entry types hold
    // only `number`/string-literal fields, which is what makes one field off
    // one entry primitive.
    //
    // ROOTED ON THE SELECTOR'S OWN PARAMETER NAME rather than on the letter
    // `s`: `(state) => state.byRule[id]?.boundPort` is the same claim spelled
    // differently, and it was REFUSED before this - a check that reddens on a
    // rename is a check the next reader weakens. The name arrives from
    // {@link selectorParamName}, off the arrow itself.
    const text = norm(cur.getText(sf));
    if (!/^[A-Za-z_$][\w$]*$/.test(param)) {
      return {
        ok: false,
        why: `the selector's parameter \`${param}\` is not a plain identifier, so no access chain can be rooted on it`,
      };
    }
    const entryField = new RegExp(`^${param}\\.byRule\\[[^\\]]+\\]\\??\\.[A-Za-z_$][\\w$]*$`);
    if (entryField.test(text)) return { ok: true };
    return {
      ok: false,
      why: `access chain \`${text}\` does not reach a primitive field off \`${param}.byRule[…]\``,
    };
  }

  return {
    ok: false,
    why: `${ts.SyntaxKind[cur.kind]} \`${norm(cur.getText(sf)).slice(0, 60)}\` is not a shape that can only yield a primitive`,
  };
}

// The allow-list's own self-test, over SYNTHETIC selectors, so its verdicts are
// pinned here rather than only by whatever `hostOwned.ts` happens to contain
// today. Without it the helper is only ever exercised on two inputs that both
// pass, and every refusal it is supposed to make is unmeasured.
{
  const probes: Array<[string, boolean, string?]> = [
    // The two real ones, plus a reordered comparison that means the same thing.
    ["s.byRule[ruleId] !== undefined", true],
    ["undefined !== s.byRule[ruleId]", true],
    ["s.byRule[ruleId]?.boundPort", true],
    ["s.byRule[ruleId]?.boundPort ?? 0", true],
    ["Object.keys(s.byRule).length", true],
    // The refusals. The first is the case the old deny-list could not see.
    ["({ a: 1, b: 2 })", false],
    ["Object.keys(s.byRule)", false],
    ["Object.entries(s.byRule)", false],
    ["Object.values(s.byRule).map((e) => e.boundPort)", false],
    ["new Set(Object.keys(s.byRule))", false],
    ["structuredClone(s.byRule)", false],
    ["s.byRule", false],
    ["s.byRule[ruleId]", false],
    ["s.byRule[ruleId] ?? {}", false],
    ["[s.byRule[ruleId]?.boundPort]", false],
    // THE TWO OPERATOR CLASSES NEITHER THIS TABLE NOR THE HELPER USED TO
    // REPRESENT, which is why the hole survived a self-test written
    // specifically to catch this shape. Both were measured passing end-to-end
    // against a real hook before the classifier was fixed.
    ["(s.byRule[ruleId]?.boundPort ?? 0, Object.keys(s.byRule))", false],
    ["(lastIds = Object.keys(s.byRule))", false],
    // And the paired controls, so each new arm is a RECURSION rather than a
    // blanket verdict on its operator. The comma one passes because its right
    // operand qualifies; the assignment one is refused even though its right
    // operand qualifies, because the target never can - deliberate, and the
    // helper's own comment says why.
    ["(s.byRule[ruleId]?.boundPort ?? 0, s.byRule[ruleId]?.boundPort)", true],
    ["(lastPort = s.byRule[ruleId]?.boundPort)", false],
    // `new Set(...)` reached through a different builder than the one above,
    // because the refusal has to come from "a call returns a fresh reference"
    // and not from a list of builder NAMES.
    ["new Set(Object.getOwnPropertyNames(s.byRule))", false],
    // THE PARAMETER NAME IS NOT THE LETTER `s`, and these three are what make
    // that a claim rather than an accident. The first is the legal selector a
    // rename produces - accepted, and REFUSED before the arm was parameterised.
    // The second proves the rename does not blanket-accept: the same refusal
    // still fires under the new name. The third proves the arm is rooted on the
    // PARAMETER and not on any identifier that happens to read `.byRule` - here
    // `s` is a free variable the selector never received.
    ["state.byRule[ruleId]?.boundPort", true, "state"],
    ["state.byRule[ruleId] ?? {}", false, "state"],
    ["s.byRule[ruleId]?.boundPort", false, "state"],
  ];
  for (const [text, want, paramName = "s"] of probes) {
    const probeSf = parse("selector-probe.ts", `useHostOwnedForwards((${paramName}) => ${text});`);
    const arg = findCallsTo(probeSf, probeSf, "useHostOwnedForwards")[0]?.arguments[0];
    const arrow = arg && ts.isArrowFunction(arg) ? arg : null;
    const body = arrow && !ts.isBlock(arrow.body) ? arrow.body : null;
    check(
      `allow-list self-test: \`${text}\` under \`(${paramName}) =>\` is ${want ? "primitive" : "REFUSED"}`,
      arrow === null || body === null
        ? "no selector body parsed"
        : primitiveSelectorBody(body, probeSf, selectorParamName(arrow, probeSf)).ok,
      want,
    );
  }
}

// ===========================================================================
console.log("\n[8. ssh-session.ts] the call site, and the two releases");
// ===========================================================================
// A source pin, because this file cannot be imported: its own graph reaches
// `@xterm/xterm` and `@tauri-apps/plugin-os`, which throw on load outside the
// app. Parsed from COMMENT-STRIPPED text - every claim below is a positive,
// and a positive over raw source is satisfied by a comment describing the code
// it wants. Each claim reads one AST NODE's own text, whitespace- and
// trailing-comma-normalised, so a legal Prettier reformat of the call site is
// invisible to it (mutation M9).
{
  const sshSessionSrc = stripComments(read("src/modules/terminal/lib/ssh-session.ts"));
  const sf = parse("ssh-session.ts", sshSessionSrc);

  const calls = findCallsTo(sf, sf, "startHostForwards");
  check("exactly one startHostForwards(...) call site", calls.length, 1);
  const call = calls[0];
  if (call) {
    // THE FOURTH ARGUMENT IS THE WIRING, and it is the only thing that catches
    // `stillLive: () => true` written here while the loop's own check stays
    // exactly as it is: every behavioural section drives its own deps, so a
    // dead flag at the production call site is invisible to all of them. Pinned
    // as the ARGUMENT NODE's whole text, not by `includes("sessionEnded")` -
    // `stillLive: () => !sessionEnded && false` would satisfy a substring.
    check(
      "it is handed the host id, the LIVE session id, a banner writer bound to this pane, and a session-scoped stillLive",
      call.arguments.map((a) => norm(a.getText(sf))),
      [
        "sshConnectionId",
        "sshSession.id",
        "(text)=>writeSshBanner(s,text)",
        "{...defaultAutostartDeps,stillLive:()=>!sessionEnded}",
      ],
    );
    // R1's second half: the file's own idiom at `:336`, `:346` and `:384`.
    // There is no `unhandledrejection` handler anywhere in `src/`, so a bare
    // `void` here rests entirely on reading another function's body.
    assert(
      call.parent !== undefined &&
        ts.isPropertyAccessExpression(call.parent) &&
        call.parent.name.text === "catch",
      "and the fire-and-forget call carries its own .catch, like every other void-ed promise in this file",
      call.parent?.getText(sf).slice(0, 120),
    );
    // THE `void` ITSELF, which nothing pinned. `openSshForSession` is `async`,
    // so `await` in place of `void` compiles, and there is NO ESLINT IN THIS
    // PROJECT AT ALL - no `eslint.config.*`, and `package.json` has only
    // `lint:imports` and `lint:rust` - so `no-floating-promises` does not
    // exist here to notice either. Measured mutation M-G: the whole suite
    // stayed green with the pane's first prompt held behind N sequential
    // binds, which is exactly what the comment above the call site says must
    // not happen and the reason the call is fire-and-forget at all.
    //
    // The shape round 1 landed is `void <call>.catch(() => {})`, so the walk
    // up from the call is: call -> `.catch` property access -> `.catch(...)`
    // call -> VoidExpression. `await` at that outermost position is an
    // AwaitExpression and reddens here.
    const catchCall = call.parent?.parent;
    const outer = catchCall?.parent;
    assert(
      catchCall !== undefined &&
        ts.isCallExpression(catchCall) &&
        outer !== undefined &&
        ts.isVoidExpression(outer),
      "and the whole `<call>.catch(...)` is VOID-ed rather than awaited - an await holds the pane's first prompt behind every bind",
      outer?.getText(sf).slice(0, 140),
    );
    // Structural position, not a count: a deletion whose decoy re-adds the
    // call inside a nested arrow keeps the count at 1 and never runs.
    const body = findFunctionBody(sf, "openSshForSession");
    check("found openSshForSession's body", body !== null, true);
    if (body) {
      assert(
        isDirectlyInFunctionBody(call, body),
        "and the call is a direct statement of openSshForSession's own body, not nested in a decoy",
      );
      // UNCONDITIONAL, which is a THIRD question and the one that closes the
      // family. `isDirectlyInFunctionBody` tests NESTING (its own docstring says
      // so) and the index comparison below tests POSITION; neither can see a
      // statement wrapped in a runtime-false guard. See
      // `enclosingStatement`'s own doc for the measurement: wrapped as
      // `if (sessionEnded) { void startHostForwards(...) }` the suite stayed at
      // 195/195 ok with `forwards-shell` and `tsc --noEmit` both green, and
      // `startWithHost` was inert for every rule. Comparing the enclosing
      // statement's PARENT against the body is what refuses every wrapper -
      // `if`, `try`, `for`, `switch` - in one assertion.
      const stmt = enclosingStatement(call);
      assert(stmt !== null, "the call sits inside an expression STATEMENT at all");
      assert(
        stmt !== null && stmt.parent === body,
        "and that statement is an UNCONDITIONAL top-level statement of openSshForSession's body - wrapped in any guard, the feature is inert for every rule and every gate in this repo still passes",
        stmt === null ? undefined : ts.SyntaxKind[stmt.parent.kind],
      );
      // AND THE STATEMENT IS NOTHING BUT THAT CALL. The parent comparison
      // above closes the STATEMENT wrapper family and leaves the EXPRESSION
      // one wide open - measured, after `prettier --write` so the formatting
      // is what a developer would actually commit:
      //
      //   sessionEnded &&
      //     void startHostForwards(sshConnectionId, sshSession.id, ..., {
      //       ...defaultAutostartDeps,
      //       stillLive: () => !sessionEnded,
      //     }).catch(() => {});
      //
      // `sessionEnded` is `false` at `:206`, so terminal autostart was inert
      // for every rule with 57/57 scripts, this file 219/219 ok, and `tsc` and
      // `prettier --check` both green. `&&`, `||`, `?:` and `??` are all this
      // shape, and each is one more member of an open set - so this compares
      // the statement's own expression against `outer`, the `void <call>.catch(...)`
      // the two assertions above already located by walking UP from the call.
      // A guard in front of it, in any spelling, makes them different nodes.
      assert(
        stmt !== null && outer !== undefined && stmt.expression === outer,
        "and the statement IS that `void <call>.catch(...)` and nothing else - `sessionEnded && void startHostForwards(...)` is a direct top-level statement too, and with that flag false the feature is inert for every rule",
        stmt === null ? undefined : norm(stmt.expression.getText(sf)).slice(0, 90),
      );
      // REACHABILITY BY POSITION. Measured mutation M-H: delete this statement
      // and re-add the identical statement AFTER the `return { ... }` below.
      // That one is now ALSO caught by `tsconfig.json`'s
      // `allowUnreachableCode: false` (TS7027), which it was not when this
      // check was written, so what is left here is the cheap belt: a statement
      // below the function's final exit.
      //
      // AGAINST THE LAST EXIT AND NOT EVERY EXIT, deliberately softened. The
      // "every exit" form reddened when a CORRECT early return was added above
      // the call site - measured - and its failure message then told the reader
      // the feature was silently inert, which was false. With the parent check
      // above covering the wrapper family and TS7027 covering real
      // unreachability, "above every exit" bought nothing and cost a
      // false-positive surface aimed at the next developer. `openSshForSession`
      // has exactly one direct-body `return` today, so the two forms are
      // identical on this file and the softening is about the exits somebody
      // adds later. The seven direct-body `throw`s are deliberately not in the
      // exit set: they all precede `sshSession`, so the call would not
      // typecheck below them anyway.
      const exits: ts.ReturnStatement[] = [];
      const visitExits = (n: ts.Node): void => {
        if (ts.isReturnStatement(n) && isDirectlyInFunctionBody(n, body)) exits.push(n);
        ts.forEachChild(n, visitExits);
      };
      visitExits(body);
      assert(exits.length > 0, "openSshForSession has an exit to sit above at all", exits.length);
      const lastExit = exits.length > 0 ? Math.max(...exits.map((r) => r.getStart(sf))) : -1;
      assert(
        exits.length > 0 && call.getStart(sf) < lastExit,
        "and it sits ABOVE the LAST exit of that body - below the final return the statement is unreachable",
        { call: call.getStart(sf), lastExit, exits: exits.length },
      );
    }
  }

  // Release 1: inside `finishSsh`, ABOVE the disposed guard. Compared by
  // INDEX - two independent `includes` are both satisfied by a release written
  // below the guard, which is the leak this half exists to catch.
  //
  // WHAT THE INDEX COMPARISON DOES NOT ESTABLISH, said here because the
  // alternative is a reader assuming it does. The claim is TEXTUAL POSITION
  // RELATIVE TO THE GUARD, and that is the claim it is right for. It cannot see
  // a DEFERRAL: measured mutation M-I wrapped this release in
  // `setTimeout(..., 5000)` while leaving it textually above the guard, and the
  // suite stayed green even though the entry then survives five seconds past
  // the session.
  //
  // THE ALLOW-LIST THAT CLOSES THAT FAMILY WAS ALREADY IN THIS FILE, which the
  // previous version of this comment missed while correctly arguing that a
  // deny-list over `setTimeout`/`queueMicrotask`/`.then` is a list over an open
  // set. Every deferral primitive there can ever be - including a scheduler
  // written next year - has to put the statement inside a NESTED FUNCTION
  // EXPRESSION, and `isDirectlyInFunctionBody` above refuses exactly that. It
  // is applied to the ADAPTER-CLOSE release below, where the deferral is the
  // live risk (measured: `queueMicrotask(() => { ...releaseSession(...) })`
  // left textually above the close kept all three gates green).
  //
  // NOT applied to this `finishSsh` twin, and the reason is that it is covered
  // by two ACCIDENTS rather than by design: deferring it while keeping
  // `resolvedSessionId` as the argument trips TS2345 inside the closure, and
  // hoisting it to a local breaks the exact-text `indexOf` below. Both hold
  // today; neither is a claim this section makes. If either stops holding, the
  // remedy is the same structural check the close half now carries.
  const finishSsh = findConstInitializer(sf, "finishSsh");
  check("found finishSsh", finishSsh !== null, true);
  if (finishSsh) {
    const body = norm((finishSsh as ts.Expression).getText(sf));
    const release = body.indexOf(
      "useHostOwnedForwards.getState().releaseSession(resolvedSessionId)",
    );
    const guard = body.indexOf("if(s.disposed)return;");
    assert(release >= 0, "finishSsh releases this session's forwards", body.slice(0, 200));
    assert(guard >= 0, "finishSsh still has its disposed guard", body.slice(0, 200));
    assert(
      release >= 0 && guard >= 0 && release < guard,
      "and the release is ABOVE that guard - a disposed pane's forwards are just as dead",
      { release, guard },
    );
    assert(
      body.includes("if(resolvedSessionId!==null)"),
      "guarded on a session id having been resolved at all",
    );
    // The `stillLive` flag, set here as well as at the adapter's close. Both
    // release sites are ONE-SHOT, so a claim landing after either has run is
    // never released - the row then reads "Running (with host)" for the rest of
    // the app's life with a disabled Stop.
    const ended = body.indexOf("sessionEnded=true");
    assert(
      ended >= 0,
      "finishSsh marks the session ENDED as well as releasing",
      body.slice(0, 240),
    );
    assert(
      ended >= 0 && ended < guard,
      "and it does so above the disposed guard too - a disposed pane's in-flight claim is just as unwanted",
      { ended, guard },
    );
    // UNCONDITIONAL, unlike the release: a session that ended before `openSsh`
    // ever resolved an id is still one an in-flight autostart must not claim
    // against.
    assert(
      release >= 0 && ended < release,
      "the flag is set BEFORE (and so outside) the resolved-session-id guard",
      { ended, release },
    );
  }

  // Release 2: the PtySession adapter's own `close`, for the ending that never
  // reaches `finishSsh` (a user-initiated disconnect, a pane closing).
  const openBody = findFunctionBody(sf, "openSshForSession");
  let closeText: string | null = null;
  let closeValue: ts.Expression | null = null;
  if (openBody) {
    const visit = (n: ts.Node): void => {
      if (
        ts.isReturnStatement(n) &&
        n.expression &&
        ts.isObjectLiteralExpression(n.expression) &&
        isDirectlyInFunctionBody(n, openBody)
      ) {
        const value = findPropertyValue(n.expression, "close", sf);
        if (value) {
          closeText = norm(value.getText(sf));
          closeValue = value;
        }
      }
      ts.forEachChild(n, visit);
    };
    visit(openBody);
  }
  assert(closeText !== null, "found the PtySession adapter's close member");
  if (closeText !== null) {
    // INDEX-COMPARED, like the `finishSsh` twin above and for the same reason.
    // Two independent `includes` are both satisfied by
    // `close: () => sshSession.close().finally(() => ...releaseSession(...))`,
    // which mentions everything this section names while moving the release
    // AFTER the close IPC resolves - and that widens exactly the window an
    // in-flight autostart claim slips through.
    const text = closeText as string;
    const release = text.indexOf("useHostOwnedForwards.getState().releaseSession(sshSession.id)");
    const closes = text.indexOf("sshSession.close()");
    const ended = text.indexOf("sessionEnded=true");
    assert(release >= 0, "the adapter's close releases this session's forwards too", text);
    assert(closes >= 0, "and still closes the session itself", text);
    assert(ended >= 0, "and marks the session ENDED, like finishSsh does", text);
    assert(
      release >= 0 && closes >= 0 && release < closes,
      "the release is ORDERED BEFORE the close IPC, not chained off its resolution",
      { release, closes },
    );
    assert(
      ended >= 0 && closes >= 0 && ended < closes,
      "as is the flag - a claim resolving during the close IPC must already see a dead session",
      { ended, closes },
    );
  }
  // AND THE RELEASE IS NOT DEFERRED, which is the half every index comparison
  // above is blind to. Measured: `queueMicrotask(() => { ...releaseSession(...)
  // })` keeps the release textually above `sshSession.close()` and every one of
  // the three index assertions passes, with `tsc` and `forwards-shell` green
  // too - and the entry then survives past the session the close is ending.
  //
  // ONE POSITIVE OVER MOST OF THE OPEN SET, and the previous version of this
  // comment claimed the whole of it. `setTimeout`, `queueMicrotask`, `.then`,
  // `.finally`, `requestIdleCallback` and whatever comes next all have to put
  // the statement inside a nested function expression, and the nesting check
  // refuses that whatever its spelling.
  //
  // `await` DOES NOT, and it is the most idiomatic deferral of the lot.
  // Measured: making `close` `async` and inserting `await Promise.resolve()`
  // above the release keeps the release a DIRECT statement of `close`'s own
  // body and textually above `sshSession.close()`, so every index comparison
  // and the nesting check all passed - 57/57 scripts, `tsc` and `prettier`
  // clean - while the entry survived the session the close was ending. So two
  // more assertions: `close` is not an async function, and no `await` sits
  // above the release. Neither is a list over an open set; both are the
  // absence of a language feature.
  if (closeValue !== null) {
    const arrow = closeValue as ts.Expression;
    const closeBody = ts.isArrowFunction(arrow) && ts.isBlock(arrow.body) ? arrow.body : null;
    assert(closeBody !== null, "the close member is an arrow with a block body to root this in");
    assert(
      ts.isArrowFunction(arrow) &&
        !(arrow.modifiers ?? []).some((m) => m.kind === ts.SyntaxKind.AsyncKeyword),
      "and close is NOT an async function - an async close can suspend before the release with the release still a direct statement of its own body",
      ts.isArrowFunction(arrow) ? norm(arrow.getText(sf)).slice(0, 60) : undefined,
    );
    if (closeBody) {
      const releases = findCallsTo(closeBody, sf, "useHostOwnedForwards.getState().releaseSession");
      check("exactly one releaseSession(...) call inside close", releases.length, 1);
      const releaseCall = releases[0];
      if (releaseCall) {
        assert(
          isDirectlyInFunctionBody(releaseCall, closeBody),
          "and it runs DIRECTLY in close's own body - not deferred into a callback, which would leave the entry alive past the session while every textual-position check above still passed",
        );
        // Every `await` anywhere under close's body, positioned against the
        // release. Not "no await at all": one BELOW the release would be
        // harmless, and refusing it would redden a correct future edit.
        const awaits: ts.AwaitExpression[] = [];
        const visitAwaits = (n: ts.Node): void => {
          if (ts.isAwaitExpression(n)) awaits.push(n);
          ts.forEachChild(n, visitAwaits);
        };
        visitAwaits(closeBody);
        const above = awaits.filter((a) => a.getStart(sf) < releaseCall.getStart(sf));
        check(
          "and NO await precedes it - a suspension point above the release defers it just as surely as a callback does, and leaves it a direct statement",
          above.map((a) => norm(a.getText(sf)).slice(0, 40)),
          [],
        );
      }
    }
  }
}

// ===========================================================================
console.log("\n[9. RuleCard.tsx] the read-only row a terminal-owned forward gets");
// ===========================================================================
{
  const ruleCardRaw = read("src/modules/forwards/page/RuleCard.tsx");
  const ruleCardStripped = stripComments(ruleCardRaw);
  const sf = parse("RuleCard.tsx", ruleCardStripped);

  // The two terminal-map reads, pinned at their OWN BINDINGS and not as a
  // substring. What the substring establishes, and the label below says only
  // this now: the text appears in CODE rather than in a comment. It does NOT
  // establish that the call is reached - `if (false) useIsHostOwned(x)`
  // satisfies `.includes` - and it says nothing at all about the value the
  // binding ends up holding. Measured mutation M-E:
  // `const hostOwned = useIsHostOwned(rule.id) && !row.hostDangling;` left the
  // substring intact, kept the whole suite green, and silently took the
  // read-only treatment off a dangling-host row - the row then offers a Start
  // for a listener the page holds no reference to.
  //
  // The previous label claimed "reachable, not merely mentioned in a comment".
  // Half of that was true. A LABEL THAT OVERCLAIMS IS WORSE THAN NO LABEL: it
  // is what stopped the next reader from looking.
  for (const hook of ["useIsHostOwned(", "useHostOwnedPort("]) {
    assert(
      ruleCardStripped.includes(hook),
      `RuleCard.tsx names ${hook} in code rather than in a comment - presence only; the binding's own initializer is pinned below`,
    );
  }
  for (const [name, want] of [
    ["hostOwned", "useIsHostOwned(rule.id)"],
    ["hostOwnedPort", "useHostOwnedPort(rule.id)"],
  ] as const) {
    const init = findConstInitializer(sf, name);
    check(`found ${name}'s own binding`, init !== null, true);
    if (init) {
      check(
        `${name} is EXACTLY ${want} - nothing ANDed, ORed or defaulted into it`,
        norm((init as ts.Expression).getText(sf)),
        want,
      );
    }
  }

  const note = findConstInitializer(sf, "HOST_OWNED_NOTE");
  check("found HOST_OWNED_NOTE", note !== null, true);
  if (note) {
    check(
      "the disabled button's tooltip says exactly where to stop it",
      (note as ts.Expression).getText(sf),
      '"Started with its terminal. Close that terminal tab to stop it."',
    );
  }

  // The status line. Pinned inside `statusText`'s own body, so a copy of the
  // string sitting unread elsewhere in the file does not satisfy it.
  const statusText = findFunctionBody(sf, "statusText");
  check("found statusText's body", statusText !== null, true);
  if (statusText) {
    assert(
      (statusText as ts.Node).getText(sf).includes('return "Running (with host)";'),
      'statusText answers "Running (with host)" for a terminal-owned rule',
    );
  }

  const dot = findFunctionBody(sf, "statusDotClass");
  check("found statusDotClass's body", dot !== null, true);
  if (dot) {
    assert(
      norm((dot as ts.Node).getText(sf)).includes('if(hostOwned)return"bg-icon-idle"'),
      "the dot is the RUNNING dot for a terminal-owned rule",
    );
  }

  // -------------------------------------------------------------------------
  // ONE PRECEDENCE ORDER: `hostOwned` FIRST, at every site that consults it.
  //
  // The row must not be able to disagree with itself: with the three orders
  // disagreeing, `hostOwned && starting` rendered a green dot, "Running (with
  // host)", a note telling the user to close a terminal tab, and a button
  // reading "Starting…" with a live spinner. A third answer about one rule, and
  // there is no owner it corresponds to.
  //
  // THAT COMBINATION IS CURRENTLY UNCONSTRUCTIBLE, and this section is pinning
  // defence in depth rather than a live defect - said plainly, because the
  // previous version of this comment claimed it was reachable and nobody could
  // build it. `controller.ts:155-161` runs the terminal-owned refusal and
  // `markStarting` with no `await` between them, so no claim lands in the gap,
  // and a terminal that reads `"starting"` after its own bind now CLAIMS rather
  // than yielding. The precedence is pinned anyway because the ROW's own
  // consistency must not rest on an argument about two other files'
  // interleavings, and the trigger that would make it reachable is a second
  // caller of `startRule`/`stopRule`.
  //
  // Every assertion below is POSITIONAL. `.includes` over a function body is
  // position-blind: moving `if (hostOwned)` below the exhaustive `switch`
  // leaves the branch dead, typechecks, and keeps every substring intact.
  // -------------------------------------------------------------------------
  for (const fn of ["statusText", "statusDotClass"] as const) {
    const fnBody = findFunctionBody(sf, fn);
    check(`found ${fn}'s body for the precedence check`, fnBody !== null, true);
    if (fnBody) {
      const body = norm((fnBody as ts.Node).getText(sf));
      const first = body.indexOf("if(hostOwned)");
      const sw = body.indexOf("switch(status)");
      assert(first >= 0, `${fn} has a hostOwned branch at all`, body.slice(0, 160));
      assert(sw >= 0, `${fn} still has its exhaustive status switch`, body.slice(0, 160));
      assert(
        first >= 0 && sw >= 0 && first < sw,
        `${fn} tests hostOwned ABOVE that switch - below it the branch is unreachable and still typechecks`,
        { first, sw },
      );
    }
  }
  {
    // The ternaries: `toggleLabel`, `toggleTooltip`, the button's `variant`,
    // its icon, and the JSX status line. Swept rather than listed, so a site
    // added later is covered without anyone remembering to add it here. `\b`
    // keeps `hostOwnedPort` out of the sweep - a different value with a
    // different question.
    //
    // WHAT THE SWEEP DOES NOT SEE: only `ConditionalExpression`s. A future
    // `hostOwned` site written as an `if` STATEMENT inside a helper is outside
    // it, and so is a `switch`. Future-facing only - every site that exists
    // today is either in this sweep or carries its own exact-text pin below -
    // but a site added as an `if` in a new helper would be uncovered, and the
    // remedy then is the same shape `statusText`/`statusDotClass` already get
    // above: an index comparison inside that helper's own body.
    const withHostOwned = findConditionals(sf).filter((c) =>
      /\bhostOwned\b/.test(norm(c.getText(sf))),
    );
    assert(
      withHostOwned.length >= 5,
      "found the hostOwned ternaries to check (label, tooltip, variant, icon, status line)",
      withHostOwned.length,
    );
    for (const cond of withHostOwned) {
      const leftmost = leftmostOperand(cond.condition, sf);
      assert(
        leftmost === "hostOwned",
        `every ternary mentioning hostOwned tests it FIRST: ${norm(cond.getText(sf)).slice(0, 80)}`,
        leftmost,
      );
    }
  }
  {
    // The click handler must AGREE WITH THE LABEL. `toggleLabel` says "Stop"
    // for a terminal-owned rule while `running` is false, so without the early
    // return the button's own handler calls `startRule` - and neither call is
    // right: the page holds no claim for such a rule, so `startRule` dials a
    // second listener and `stopRule` marks it `stopped` in the page's store,
    // which is a lie about a live listener nobody here can free. Unreachable
    // today only because `startDisabled` includes `hostOwned`, and a disabled
    // button is a rendering rather than an invariant.
    let handler: string | null = null;
    const visit = (n: ts.Node): void => {
      if (
        ts.isJsxAttribute(n) &&
        n.name.getText(sf) === "onClick" &&
        n.initializer &&
        ts.isJsxExpression(n.initializer) &&
        n.initializer.expression &&
        n.initializer.expression.getText(sf).includes("startRule")
      ) {
        handler = norm(n.initializer.expression.getText(sf));
      }
      ts.forEachChild(n, visit);
    };
    visit(sf);
    check("found the Start/Stop button's click handler", handler !== null, true);
    if (handler !== null) {
      check(
        "it returns early for a terminal-owned rule, ahead of both calls",
        handler,
        "()=>{if(hostOwned)return;if(running)voidstopRule(rule);elsevoidstartRule(rule);}",
      );
    }
  }

  // The three derived values, each read off its own binding's definition:
  // pinning the NAME would be satisfied by an alias or a rebind. TRUE OF THESE
  // THREE AND NOW ALSO OF THEIR INPUTS - `hostOwned` and `hostOwnedPort` have
  // their own initializers pinned at the top of this section, so the chain is
  // closed at both ends. Before that it was not: this sentence read as if it
  // covered the whole file while the two values everything below derives from
  // were pinned by name only (M-E).
  const cases: Array<[string, string]> = [
    ["startDisabled", "hostOwned||row.hostDangling||starting"],
    ["toggleLabel", 'hostOwned?"Stop":starting?"Starting…":running?"Stop":"Start"'],
    ["localLabel", "localPortLabel(rule,hostOwnedPort??boundPort)"],
  ];
  for (const [name, want] of cases) {
    const init = findConstInitializer(sf, name);
    check(`found ${name}`, init !== null, true);
    if (init) check(`${name} is ${want}`, norm((init as ts.Expression).getText(sf)), want);
  }
  const tooltip = findConstInitializer(sf, "toggleTooltip");
  check("found toggleTooltip", tooltip !== null, true);
  if (tooltip) {
    const text = norm((tooltip as ts.Expression).getText(sf));
    assert(
      text.startsWith("hostOwned?HOST_OWNED_NOTE:"),
      "toggleTooltip answers the host-owned note FIRST, so the const is actually reached",
      text.slice(0, 120),
    );
  }

  // `onDelete` passes BOTH flags, as two arguments and not one folded into the
  // other. `running` stays strictly the PAGE's notion: it feeds `deleteNote`,
  // whose "deleting a running rule stops it" sentence is true only of a rule
  // this page can stop (and true at all only because `ForwardsPage.tsx`'s
  // `confirmDelete` stops it first). `hostOwned` rides alongside because the
  // dialog has its own, different sentence for a terminal-owned rule - the one
  // that says deleting the record does NOT stop that forward. Folding them into
  // `running || hostOwned` is the mutation this pins: the dialog would then
  // promise a stop it cannot perform, which is the false promise in a
  // destructive confirm this round exists to remove.
  assert(
    ruleCardStripped.includes("onDelete(running, hostOwned)"),
    "onDelete passes the PAGE's notion of running AND hostOwned, as two separate arguments",
  );
}

// ===========================================================================
console.log("\n[10. §1.6 in the second store] every useHostOwnedForwards( selector is primitive");
// ===========================================================================
{
  const hostOwnedSrc = read("src/modules/forwards/hostOwned.ts");
  const sf = parse("hostOwned.ts", hostOwnedSrc);
  const calls = findCallsTo(sf, sf, "useHostOwnedForwards");
  assert(calls.length >= 2, "found the selector calls to check", calls.length);
  for (const call of calls) {
    const arg = call.arguments[0];
    const isArrow = !!arg && ts.isArrowFunction(arg);
    assert(isArrow, `${call.getText(sf)}'s argument is an arrow function`);
    if (arg && isArrow) {
      const body = (arg as ts.ArrowFunction).body;
      const expr = ts.isBlock(body) ? null : body;
      assert(expr !== null, `found ${call.getText(sf)}'s selector body`);
      if (expr) {
        const verdict = primitiveSelectorBody(
          expr,
          sf,
          selectorParamName(arg as ts.ArrowFunction, sf),
        );
        assert(
          verdict.ok,
          `${call.getText(sf)} returns a primitive`,
          verdict.ok ? undefined : verdict.why,
        );
      }
    }
  }

  // The negative, over COMMENT-STRIPPED source. Stripped because this file's
  // own note at `hostOwned.ts:85-89` explains IN PROSE why `useShallow` is
  // avoided, so a sentence there naming the module path would falsely redden a
  // raw-source regex - the same exception `forwards-shell-verify.ts:417-420`
  // already carves out for its own copy of this claim. Inconsistent with
  // sections 8 and 9, which strip, until now.
  assert(
    !/from ["']zustand\/react\/shallow["']/.test(stripComments(hostOwnedSrc)),
    "hostOwned.ts imports nothing from zustand/react/shallow (comment-stripped text)",
  );
  // And the same claim STRUCTURALLY, which is what makes it immune to both
  // polarities of the comment problem: an import declaration is a statement
  // about this module's graph, and neither a comment nor a string literal can
  // forge or hide one.
  const shallowImports = sf.statements
    .filter(ts.isImportDeclaration)
    .filter(
      (st) =>
        ts.isStringLiteral(st.moduleSpecifier) &&
        /zustand\/react\/shallow/.test(st.moduleSpecifier.text),
    );
  check("and no import DECLARATION names it either (AST, not text)", shallowImports.length, 0);

  // REPO-WIDE, and this is the half that was missing entirely: the section only
  // ever read `hostOwned.ts`, so a bad selector written in a `.tsx` sat outside
  // its parse and outside every other script's. Same shape as
  // `scripts/forwards-shell-verify.ts:431-438` uses for `useForwardRuntime(`.
  // Currently clean - the only two calls are the two above - and keeping it
  // that way is what keeps the two checks above total. Comment-stripped, so a
  // note discussing the hook is not an offender; `useHostOwnedForwards.getState()`
  // does not contain `useHostOwnedForwards(`, which is why `ssh-session.ts` and
  // `controller.ts` are not caught by it.
  const hostOwnedAbs = join(repoRoot, "src/modules/forwards/hostOwned.ts");
  const selectorOffenders = walkSrcFiles(join(repoRoot, "src")).filter(
    (f) =>
      f !== hostOwnedAbs &&
      stripComments(readFileSync(f, "utf8")).includes("useHostOwnedForwards("),
  );
  check(
    "useHostOwnedForwards( is called ONLY from hostOwned.ts - so every selector in src/ is inside this section's parse",
    selectorOffenders.map((f) => f.slice(repoRoot.length)),
    [],
  );
  assert(
    hostOwnedSrc.includes("useHostOwnedForwards("),
    "sanity: the sweep's needle does appear in hostOwned.ts itself",
  );
}

// ===========================================================================
console.log(
  "\n[11. two panes, one host] a rule another SESSION already owns is refused, not overwritten - sequentially AND concurrently",
);
// ===========================================================================
{
  resetHostOwned();
  // LOCAL PORT BLANK, which is the DEFAULT rule shape: `EMPTY_RULE_DRAFT` has
  // `localPort: ""` (`editor/draft.ts:46-54`), which saves as 0 and renders
  // "Auto". That is what makes this reachable with no timing whatsoever - the
  // second bind SUCCEEDS on a different port, so nothing fails and nothing
  // warns. A pinned port would have failed EADDRINUSE and left tab A's entry
  // standing by accident.
  const shared = rule({ id: "f-shared", name: "shared", localPort: 0 });
  let nextPort = 54321;
  const a = world({ rules: [shared], open: async () => nextPort++ });
  await startHostForwards("h-1", 41, a.writeBanner, a.deps);
  check("tab A owns the rule", useHostOwnedForwards.getState().byRule, {
    "f-shared": { sessionId: 41, boundPort: 54321 },
  });

  const b = world({ rules: [shared], open: async () => nextPort++ });
  await startHostForwards("h-1", 42, b.writeBanner, b.deps);
  check("tab B never asked the bridge for a second listener", b.openCalls.length, 0);
  check("tab B claimed nothing", b.claims.length, 0);
  check("and it says why, without claiming the PAGE owns it", b.banners, [
    otherTerminalBanner("shared"),
  ]);
  check(
    "the map still names session 41 - the live first owner was not overwritten",
    useHostOwnedForwards.getState().byRule,
    { "f-shared": { sessionId: 41, boundPort: 54321 } },
  );

  // The consequence the overwrite used to have, pinned from the other end:
  // tab B closing must not take tab A's live forward out of the page, and tab
  // A closing must still clear it (before the fix its entry had been
  // overwritten, so its own release was a no-op and the row leaked).
  useHostOwnedForwards.getState().releaseSession(42);
  check("closing tab B leaves tab A's forward standing", useHostOwnedForwards.getState().byRule, {
    "f-shared": { sessionId: 41, boundPort: 54321 },
  });
  useHostOwnedForwards.getState().releaseSession(41);
  check("and closing tab A clears it", useHostOwnedForwards.getState().byRule, {});
}
{
  // PRESENCE ALONE, and this fixture is the one that changed direction. It used
  // to pin `owner !== sessionId` - "a rule THIS session already owns is not
  // refused" - as correct behaviour. That case is UNREACHABLE in production
  // (`next_id` is a monotonic `AtomicU32` from 1,
  // `src-tauri/src/modules/ssh/mod.rs:52,59,476`), so what the fixture was
  // really pinning was the UNSAFE half of an unreachable branch: if the
  // comparison ever did fire, the same session would bind a SECOND listener and
  // overwrite its own entry, orphaning the first port for the app's lifetime.
  // `if (owner !== undefined) continue;` is the same code with a safe failure
  // mode, and a check should pin the safe one.
  resetHostOwned();
  const same = rule({ id: "f-same", name: "same session", localPort: 18080 });
  const first = world({ rules: [same] });
  await startHostForwards("h-1", 41, first.writeBanner, first.deps);
  check("the first run claims it", useHostOwnedForwards.getState().byRule, {
    "f-same": { sessionId: 41, boundPort: 18080 },
  });
  const again = world({ rules: [same] });
  await startHostForwards("h-1", 41, again.writeBanner, again.deps);
  check(
    "a rule ANY session already owns - this one included - never reaches a second bind",
    again.openCalls.length,
    0,
  );
  check("and nothing was re-claimed over the live entry", again.claims.length, 0);
  // The same sentence as the other-pane case, and correctly so: the entry it
  // refuses in favour of does name a live listener for this rule, whichever
  // session opened it.
  check("it is banner-skipped, not re-claimed", again.banners, [
    otherTerminalBanner("same session"),
  ]);
  check(
    "the entry is byte-identical to the one the first run wrote",
    useHostOwnedForwards.getState().byRule,
    {
      "f-same": { sessionId: 41, boundPort: 18080 },
    },
  );
}
{
  // ---------------------------------------------------------------------
  // THE CONCURRENT CASE, and it is the one that matters: two runs started
  // BEFORE either is awaited. This is the DEFAULT shape for two panes, not an
  // unlucky one - each pane runs its own connect and nothing serialises across
  // panes - and `localPort: 0` from `EMPTY_RULE_DRAFT` is what makes the second
  // bind SUCCEED rather than fail EADDRINUSE, so nothing fails and nothing
  // warns.
  //
  // The two blocks above cannot see it: both drive their runs with an `await`
  // between them, which is the only ordering a PRE-BIND read wins. Before the
  // post-bind `hostOwnedBy` re-read existed, this fixture's outcome was two
  // listeners, zero closes and one named - the pre-fix defect verbatim, against
  // a suite that was green.
  //
  // §4.60's second half: the suspension point is one the FIXTURE controls. Each
  // run's bind is a deferred this block resolves by hand, never an
  // already-settled promise, so every counter below is read after an ordering
  // this file chose.
  // ---------------------------------------------------------------------
  resetHostOwned();
  const shared = rule({ id: "f-race", name: "raced", localPort: 0 });
  let releaseA: (p: number) => void = () => {};
  let releaseB: (p: number) => void = () => {};
  const a = world({
    rules: [shared],
    open: () =>
      new Promise<number>((res) => {
        releaseA = res;
      }),
  });
  const b = world({
    rules: [shared],
    open: () =>
      new Promise<number>((res) => {
        releaseB = res;
      }),
  });
  // BOTH STARTED, THEN awaited. Reversing these two lines is the fixture the
  // section already had.
  const runA = startHostForwards("h-1", 41, a.writeBanner, a.deps);
  const runB = startHostForwards("h-1", 42, b.writeBanner, b.deps);
  await tick();
  check(
    "both runs passed their pre-bind reads and are parked on a bind - the pre-bind check cannot separate them",
    [a.openCalls.length, b.openCalls.length],
    [1, 1],
  );
  check("and neither has claimed anything yet", useHostOwnedForwards.getState().byRule, {});

  releaseA(54321);
  await tick();
  check("A resolves first and claims", useHostOwnedForwards.getState().byRule, {
    "f-race": { sessionId: 41, boundPort: 54321 },
  });

  releaseB(54322);
  await Promise.all([runA, runB]);
  check(
    "B's post-bind re-read finds A's claim and B CLOSES THE LISTENER IT JUST BOUND",
    b.closeCalls,
    [{ id: 42, boundPort: 54322 }],
  );
  check("B claimed nothing", b.claims.length, 0);
  check("A closed nothing - the winner keeps its listener", a.closeCalls, []);
  check(
    "the map still names session 41, with the port A actually bound",
    useHostOwnedForwards.getState().byRule,
    { "f-race": { sessionId: 41, boundPort: 54321 } },
  );
  check("A said it was forwarding", a.banners, [forwardingBanner(54321, "10.0.0.9:5432", "raced")]);
  check("B said why it did not", b.banners, [otherTerminalBanner("raced")]);
  // The leak's other end, and the assertion that used to fail: closing the tab
  // the store NAMES must clear it. With B's overwrite in place the map named
  // session 42, so releasing 41 left an entry standing for a listener nothing
  // could reach and the row read "Running (with host)" for the app's lifetime.
  useHostOwnedForwards.getState().releaseSession(41);
  check(
    "and closing the tab the store names clears it",
    useHostOwnedForwards.getState().byRule,
    {},
  );
}

// ===========================================================================
console.log(
  "\n[12. a session that ended mid-bind] no claim, and the loop STOPS - and one already dead never binds at all",
);
// ===========================================================================
{
  resetHostOwned();
  const one = rule({ id: "f-l1", name: "one", localPort: 18080 });
  const two = rule({ id: "f-l2", name: "two", localPort: 18081 });
  const three = rule({ id: "f-l3", name: "three", localPort: 18082 });

  // A deferred the FIXTURE controls, so every counter below is read after a
  // suspension point this file chose. A count taken after awaiting an
  // already-settled promise proves nothing about who waited.
  let resolveTwo: (p: number) => void = () => {};
  const parked = new Promise<number>((res) => {
    resolveTwo = res;
  });
  let live = true;
  const w = world({
    rules: [one, two, three],
    open: (call) => (call.localPort === 18081 ? parked : Promise.resolve(call.localPort)),
    stillLive: () => live,
  });
  const settled = startHostForwards("h-1", 41, w.writeBanner, w.deps).then(
    () => "resolved" as const,
    (e) => `rejected: ${e instanceof Error ? e.message : String(e)}`,
  );

  await tick();
  check("the first rule is up and the loop is parked on the second's bind", w.openCalls.length, 2);
  check("the first rule's claim is on file", useHostOwnedForwards.getState().byRule, {
    "f-l1": { sessionId: 41, boundPort: 18080 },
  });

  // The session ends while the bind is in flight. This is the REAL order:
  // `disposeSession` sets `disposed`, then `pty.close()` releases
  // SYNCHRONOUSLY, and only then issues `invoke("ssh_close")` - while this
  // loop is already parked on an `ssh_forward_open` issued earlier, which
  // takes a read lock and usually wins.
  useHostOwnedForwards.getState().releaseSession(41);
  live = false;
  resolveTwo(18081);

  check("startHostForwards still RESOLVES", await settled, "resolved");
  check(
    "the late bind claimed NOTHING - both release sites are one-shot, so an entry written now is never released",
    useHostOwnedForwards.getState().byRule,
    {},
  );
  check("nor was it recorded through the seam", w.claims.length, 1);
  check(
    "and the loop STOPPED rather than binding the third rule on a dead session",
    w.openCalls.length,
    2,
  );
  check("no banner told the user about a forward with no owner left", w.banners, [
    forwardingBanner(18080, "10.0.0.9:5432", "one"),
  ]);
}
{
  // The paired control, and it is what tells "the guard bites" from "the
  // suspension bites": the SAME parked bind, the same resolve, with the
  // session still alive. Everything proceeds.
  resetHostOwned();
  const one = rule({ id: "f-k1", name: "one", localPort: 18080 });
  const two = rule({ id: "f-k2", name: "two", localPort: 18081 });
  let resolveTwo: (p: number) => void = () => {};
  const parked = new Promise<number>((res) => {
    resolveTwo = res;
  });
  const w = world({
    rules: [one, two],
    open: (call) => (call.localPort === 18081 ? parked : Promise.resolve(call.localPort)),
    stillLive: () => true,
  });
  const settled = startHostForwards("h-1", 41, w.writeBanner, w.deps).then(() => "resolved");
  await tick();
  resolveTwo(18081);
  await settled;
  check("a live session claims both rules", useHostOwnedForwards.getState().byRule, {
    "f-k1": { sessionId: 41, boundPort: 18080 },
    "f-k2": { sessionId: 41, boundPort: 18081 },
  });
}
{
  // ALREADY DEAD BEFORE THE FIRST BIND, which the fixture above cannot reach:
  // it kills the session between bind 1 and bind 2, so it only ever exercises
  // the post-bind check. `finishSsh` sets `sessionEnded` UNCONDITIONALLY
  // (`ssh-session.ts:218`) - before `openSsh` has resolved an id - so a session
  // that ended while this run was still awaiting `listRules` is a real state,
  // and with the loop shaped bind-then-check it issued ONE bind on a dead
  // session and orphaned that listener before breaking.
  //
  // Zero opens, not "one fewer": the check is at the TOP of the loop body, so
  // the very first rule is refused too.
  resetHostOwned();
  const one = rule({ id: "f-d1", name: "one", localPort: 18080 });
  const two = rule({ id: "f-d2", name: "two", localPort: 18081 });
  const w = world({ rules: [one, two], stillLive: () => false });
  await startHostForwards("h-1", 41, w.writeBanner, w.deps);
  check("a session already dead on entry asks the bridge for NOTHING", w.openCalls.length, 0);
  check("claims nothing", useHostOwnedForwards.getState().byRule, {});
  check("and writes no banner about a forward it never opened", w.banners, []);
  // The paired control, so the zero above is the GUARD biting and not the
  // fixture failing to drive anything: the identical two rules with the session
  // alive bind both.
  const alive = world({ rules: [one, two], stillLive: () => true });
  await startHostForwards("h-1", 41, alive.writeBanner, alive.deps);
  check("the same two rules on a live session bind both", alive.openCalls.length, 2);
}

// ===========================================================================
console.log("\n[13. NEVER REJECTS, structurally] every throw site outside the per-rule try");
// ===========================================================================
// The doc comment says the function never rejects; the call site is a `void`
// and there is no `unhandledrejection` handler anywhere in `src/`. Before the
// fix that claim held only because `writeSshBanner` guards `s.disposed` and
// `s.term.dispose()` runs after that flag is set - true by another file's
// ordering rather than by construction.
//
// Every scenario is parked on a `listRules` the FIXTURE releases, so the
// resolve/reject verdict is read after a suspension point this file controls.
{
  const boom = new Error("banner: this pane is already gone");
  const throwingBanner = (): void => {
    throw boom;
  };
  const quietBanner = (): void => {};
  const t = rule({ id: "f-throw", name: "throwing", localPort: 18080 });

  type Site = {
    name: string;
    over: Parameters<typeof world>[0];
    banner: (text: string) => void;
    listFails?: boolean;
    mutate?: (deps: AutostartDeps) => void;
  };
  const sites: Site[] = [
    // The four the reviewer named.
    {
      name: "the unreadable-store banner throws",
      over: {},
      banner: throwingBanner,
      listFails: true,
    },
    {
      name: "deps.runtimeStatus throws",
      over: {
        rules: [t],
        statusFn: () => {
          throw boom;
        },
      },
      banner: quietBanner,
    },
    {
      name: "the page-skip banner throws",
      over: { rules: [t], status: { "f-throw": "running" } },
      banner: throwingBanner,
    },
    {
      name: "the failed banner throws after a rejected bind",
      over: { rules: [t], open: () => Promise.reject("ssh: bind 127.0.0.1:18080 failed") },
      banner: throwingBanner,
    },
    // And the sites this round's own fixes added.
    {
      name: "deps.hostOwnedBy throws",
      over: {
        rules: [t],
        hostOwnedBy: () => {
          throw boom;
        },
      },
      banner: quietBanner,
    },
    {
      name: "the other-terminal banner throws",
      over: { rules: [t], hostOwnedBy: () => 99 },
      banner: throwingBanner,
    },
    {
      name: "deps.stillLive throws",
      over: {
        rules: [t],
        stillLive: () => {
          throw boom;
        },
      },
      banner: quietBanner,
    },
    {
      name: "the yielding banner throws",
      over: { rules: [t], statusFn: (_id, nth) => (nth === 0 ? "stopped" : "running") },
      banner: throwingBanner,
    },
    {
      name: "deps.closeForward rejects while yielding",
      over: {
        rules: [t],
        statusFn: (_id, nth) => (nth === 0 ? "stopped" : "running"),
        close: () => Promise.reject(boom),
      },
      banner: quietBanner,
    },
    // The success banner throwing is the compound case: the per-rule catch
    // reaches for `failedBanner`, which throws again with no handler left.
    {
      name: "the success banner throws, and so does the failed banner the catch reaches for",
      over: { rules: [t] },
      banner: throwingBanner,
    },
    {
      name: "deps.claimHostOwned throws and the failed banner throws too",
      over: { rules: [t] },
      banner: throwingBanner,
      mutate: (deps) => {
        deps.claimHostOwned = () => {
          throw boom;
        };
      },
    },
  ];

  for (const site of sites) {
    resetHostOwned();
    let release: () => void = () => {};
    const parkedList = new Promise<ForwardRule[]>((res, rej) => {
      release = () =>
        site.listFails
          ? rej(new Error("forwards: store file is unreadable"))
          : res(site.over.rules ?? []);
    });
    const w = world({ ...site.over, listRules: () => parkedList });
    site.mutate?.(w.deps);
    const settled = startHostForwards("h-1", 7, site.banner, w.deps).then(
      () => "resolved" as const,
      (e) => `rejected: ${e instanceof Error ? e.message : String(e)}`,
    );
    await tick();
    check(
      `${site.name}: nothing has settled while the store read is parked`,
      w.openCalls.length,
      0,
    );
    release();
    check(`${site.name}: startHostForwards RESOLVES`, await settled, "resolved");
  }
}

// ===========================================================================
console.log(
  "\n[14. the page took it mid-bind] whoever resolves SECOND yields - so `running` yields and `starting` CLAIMS",
);
// ===========================================================================
{
  resetHostOwned();
  const r = rule({ id: "f-yield", name: "yielded", localPort: 0 });
  // THE STALE READ, which the seam could not express before this round: the
  // status is answered "stopped" on the FIRST read (before the bind) and
  // "running" on the second (after it). That is the user clicking Start while
  // this bind was in flight, and `controller.ts`'s `markStarting` is
  // synchronous, so no timing trick is needed to reach it.
  const w = world({
    rules: [r],
    statusFn: (_id, nth) => (nth === 0 ? "stopped" : "running"),
    open: async () => 54321,
  });
  await startHostForwards("h-1", 41, w.writeBanner, w.deps);

  check("the bind DID happen - the first read said stopped", w.openCalls.length, 1);
  check("and the status was re-read AFTER it, which is the whole fix", w.statusCalls, [
    "f-yield",
    "f-yield",
  ]);
  check("the just-bound listener was closed, by session and BOUND port", w.closeCalls, [
    { id: 41, boundPort: 54321 },
  ]);
  check("no claim was written - the page's forward is genuinely up", w.claims.length, 0);
  check("and the terminal's map is untouched", useHostOwnedForwards.getState().byRule, {});
  check("the banner names the rule", w.banners, [yieldedBanner("yielded")]);
}
{
  // `"starting"` IS THE INVERSE, and this fixture is written against the new
  // behaviour: the terminal CLAIMS rather than yielding. `autostart.ts:141-145`
  // already reasoned this way about the very same status for the PRE-bind
  // banner - "a page Start still dialling, which can then FAIL" - and the
  // post-bind path had not absorbed it.
  //
  // The sequence it fixes has DEFAULT step ordering, not unlucky ordering: the
  // terminal's bind wins in the backend because it arrived first, the page's
  // bind returns EADDRINUSE, the terminal's `await` resolves first and reads
  // `"starting"`. Yielding there closed the terminal's listener; then the
  // page's rejection landed and marked the row failed. No owner on either side,
  // and the row read "Failed - port 18080 is already in use" naming a port
  // nothing held.
  //
  // The page is the side that gives up its duplicate now, in `controller.ts`'s
  // post-dial read - one rule seen from two sides, checked there as C10.
  resetHostOwned();
  const r = rule({ id: "f-starting", name: "still dialling", localPort: 0 });
  const w = world({
    rules: [r],
    statusFn: (_id, nth) => (nth === 0 ? "stopped" : "starting"),
    open: async () => 54321,
  });
  await startHostForwards("h-1", 41, w.writeBanner, w.deps);

  check("the status was still re-read after the bind", w.statusCalls, ["f-starting", "f-starting"]);
  check(
    "NOTHING was closed - the terminal bound first and the page's dial may still fail",
    w.closeCalls,
    [],
  );
  check("the terminal CLAIMS", useHostOwnedForwards.getState().byRule, {
    "f-starting": { sessionId: 41, boundPort: 54321 },
  });
  check("with the ordinary forwarding banner, not a yield", w.banners, [
    forwardingBanner(54321, "10.0.0.9:5432", "still dialling"),
  ]);
}
{
  // The paired control: both reads say "stopped", so nothing is closed and the
  // claim lands. Without this the section passes with a re-check widened to
  // "always yield".
  resetHostOwned();
  const r = rule({ id: "f-keep", name: "kept", localPort: 0 });
  const w = world({ rules: [r], statusFn: () => "stopped", open: async () => 54321 });
  await startHostForwards("h-1", 41, w.writeBanner, w.deps);
  check("a rule the page never took is not closed", w.closeCalls, []);
  check("and it is claimed", useHostOwnedForwards.getState().byRule, {
    "f-keep": { sessionId: 41, boundPort: 54321 },
  });
  check("with the ordinary forwarding banner", w.banners, [
    forwardingBanner(54321, "10.0.0.9:5432", "kept"),
  ]);
}

// ===========================================================================
console.log("\n[15. describeError] the two FALLBACK arms, not only the two already covered");
// ===========================================================================
// Banner text only, so the stakes are low - but two of four arms untested is
// the §4.59 shape, and it costs two fixtures. The RAW-STRING arm is covered by
// section 4 and correctly so: a Tauri `invoke` rejects with a raw string, and
// that is how the backend's own `ssh: bind ... failed` text reaches the banner
// at all. The `Error` arm is covered by section 7. These are the other two.
{
  resetHostOwned();
  const r = rule({ id: "f-json", name: "json rule", localPort: 18080 });
  const w = world({ rules: [r], open: () => Promise.reject({ kind: "bind", port: 18080 }) });
  await startHostForwards("h-1", 7, w.writeBanner, w.deps);
  check(
    "a rejection that is neither a string nor an Error is JSON-stringified into the banner",
    w.banners,
    [failedBanner("json rule", '{"kind":"bind","port":18080}')],
  );
}
{
  resetHostOwned();
  // A CYCLE, which is what makes `JSON.stringify` itself throw and leaves the
  // `String(e)` arm as the only one left. Not contrived: a structured payload
  // carrying a back-reference is a shape an IPC rejection can have, and the
  // point of the arm is that the throw inside `describeError` must not become
  // the failed connect that section 4 exists to prevent.
  const cyclic: Record<string, unknown> = { kind: "bind" };
  cyclic.self = cyclic;
  const r = rule({ id: "f-cyclic", name: "cyclic rule", localPort: 18080 });
  const w = world({ rules: [r], open: () => Promise.reject(cyclic) });
  await startHostForwards("h-1", 7, w.writeBanner, w.deps);
  check(
    "and one JSON.stringify throws on falls through to String(e) rather than taking the run down",
    w.banners,
    [failedBanner("cyclic rule", "[object Object]")],
  );
}

// ===========================================================================
console.log("\n[16. VLT-94's load-bearing half] autostart never writes the PAGE's store");
// ===========================================================================
{
  // Read after every section above has run, with NO reset in between - the
  // claim is that `startHostForwards` never writes this store at all, on any
  // path: not the happy one, not the skip, not the yield, not the failure.
  // `claimHostOwned` is behind the `AutostartDeps` seam and every fixture
  // substitutes it; a direct `useForwardRuntime.getState().markRunning(...)`
  // is not, and `autostart.ts` already holds a live reference to that store.
  // If it ever happened the page would believe it can Stop a terminal-owned
  // rule, and would spend a claim nobody took.
  check(
    "after every run in this file, the page's runtime store is still empty",
    useForwardRuntime.getState().byRule,
    {},
  );
}

// ===========================================================================
console.log(
  "\n[17. the two halves of one yield wait the same way] every release in autostart.ts and controller.ts is awaited, and each carries its own .catch",
);
// ===========================================================================
// A CONSISTENCY CHECK AND NOTHING MORE, said plainly because the finding it
// came from claimed nothing more either. `controller.ts:188-194` and `:219-225`
// argue that a release must be awaited - "a close that landed later could land
// on a listener a subsequent Start has since bound on that port" - while
// `autostart.ts`'s two yield releases fired UN-awaited on the identical hazard.
// Nothing here was measured against the Rust side, so the claim is that the two
// frontend halves of one rule now wait in the same way, not that the race was
// observed.
//
// The `.catch(() => {})` half is what keeps the awaited close out of
// `autostart.ts`'s per-rule catch: a close that reports a failure must not
// print `failedBanner`, which would say the forward could not be opened when in
// fact it opened and was handed over. Awaiting a chain ending in `.catch`
// cannot throw, so the two properties are not in tension - and pinning both
// together is what stops the next reader from restoring the bare `void` to get
// the second one back.
//
// Source pins over COMMENT-STRIPPED text: every claim is a positive, and a
// positive over raw source is satisfied by a comment describing the code it
// wants.
{
  for (const [rel, callee, wantCatch, wantCount] of [
    // autostart.ts: the pre-claim other-terminal yield and the page-took-it
    // yield. controller.ts: the superseded-attempt release, the post-dial yield
    // and `stopRule`'s own close - THREE, and the count is asserted so a
    // release added or deleted has to be argued for rather than skipped.
    ["src/modules/forwards/autostart.ts", "deps.closeForward", true, 2],
    ["src/modules/forwards/controller.ts", "runtime.closeForward", false, 3],
  ] as const) {
    const sf = parse(rel, stripComments(read(rel)));
    const calls = findCallsTo(sf, sf, callee);
    check(`${rel}: found all ${wantCount} ${callee}(...) releases`, calls.length, wantCount);
    for (const call of calls) {
      // The AWAIT, read off the AST and walking up through the `.catch(...)`
      // wrapper when there is one: `void x.catch(...)` keeps every substring a
      // text check would look for.
      const chainTop =
        call.parent !== undefined &&
        ts.isPropertyAccessExpression(call.parent) &&
        call.parent.name.text === "catch" &&
        call.parent.parent !== undefined &&
        ts.isCallExpression(call.parent.parent)
          ? call.parent.parent
          : call;
      assert(
        chainTop.parent !== undefined && ts.isAwaitExpression(chainTop.parent),
        `${rel}: and the release is AWAITED, not fired off - the same rule ${callee === "deps.closeForward" ? "controller.ts" : "autostart.ts"} follows on the other half of this yield`,
        chainTop.parent === undefined ? undefined : ts.SyntaxKind[chainTop.parent.kind],
      );
      assert(
        wantCatch ? chainTop !== call : chainTop === call,
        wantCatch
          ? `${rel}: and it carries its own .catch(...), so the awaited close cannot reach the per-rule catch and print failedBanner`
          : `${rel}: and it carries NO .catch - a release that reported here has nowhere else to go, and this file's own stopRule uses a finally instead`,
        norm(chainTop.getText(sf)).slice(0, 70),
      );
    }
  }
}

if (failed > 0) throw new Error(`forward-autostart-verify: ${failed} FAILED`);
console.log("\nforward-autostart-verify: OK\n");

// ----------------------------------------------------------------------------
// Mutation table - fix round 3. Every mutation below was actually applied to a
// byte-identical copy of `src/` AND `scripts/` (both trees reset each time, and
// the ok-count printed on every run - a harness that silently stops asserting
// reports GREEN for everything), the three verify scripts and both `tsc`
// projects run, and the result recorded. Baseline: fa 219 ok, fs 141 ok, fp 79
// ok, both tsc green.
//
//   Id    Mutation                                       Result
//   ----  ---------------------------------------------  --------------------------
//   Y1    autostart.ts: the post-bind `hostOwnedBy`      RED, 5 checks in section
//           re-check block deleted                         11's CONCURRENT block -
//                                                          and only that block. The
//                                                          two sequential blocks
//                                                          stayed green, which is
//                                                          the whole reason the
//                                                          concurrent one exists.
//   Y2    autostart.ts: `taken === "starting"` restored  RED, 3 checks in section
//           to the post-bind yield condition               14's `starting` block
//   Y6    autostart.ts: the top-of-loop `stillLive`      RED, section 12's
//           check deleted                                  already-dead-on-entry
//                                                          check. Its paired live
//                                                          control stayed green.
//   Y7    autostart.ts: `owner !== undefined &&          RED, 1 check - section
//           owner !== sessionId` restored for the          11's second block's
//           PRE-bind read                                  "never reaches a second
//                                                          bind". Only one, and the
//                                                          reason is worth keeping:
//                                                          the new POST-bind
//                                                          presence check catches
//                                                          the same entry a moment
//                                                          later, so the damage the
//                                                          mutation still does is
//                                                          exactly one wasted bind
//                                                          plus its close. The two
//                                                          checks are layered, not
//                                                          redundant.
//   Y9    ssh-session.ts: the call site wrapped as       RED, section 8's
//           `if (sessionEnded) { void ... }`, textually    UNCONDITIONAL check.
//           unchanged otherwise                            Measured GREEN across all
//                                                          three gates before the
//                                                          parent check existed,
//                                                          with the feature inert
//                                                          for every rule.
//   Y10   hostOwned.ts: a new selector hook returning    RED, section 10's
//           `(s.byRule[id]?.boundPort ?? 0,                primitive verdict for
//           Object.keys(s.byRule))`                        that selector. Measured
//                                                          GREEN before the comma
//                                                          arm existed - the section
//                                                          printed it as "returns a
//                                                          primitive".
//   Y11   ssh-session.ts: the adapter-close release      RED, section 8's
//           wrapped in `queueMicrotask(() => ...)`,        undeferred check.
//           still textually above `sshSession.close()`     Measured GREEN across all
//                                                          three gates before it -
//                                                          every index comparison
//                                                          passed.
//   Y8    `prettier --write --print-width 60` over all   GREEN, the paired control
//           seven src files this round pins (770             - BUT ONLY AFTER
//           changed lines; at this repo's printWidth of      `findCallsTo` was
//           100 the reflow would have been a no-op, so       fixed to normalise the
//           the narrower width is what makes the            CALLEE text. On the
//           control measure anything)                       first run it reddened
//                                                          section 8's new
//                                                          releaseSession lookup,
//                                                          because Prettier splits
//                                                          `useHostOwnedForwards
//                                                          .getState()
//                                                          .releaseSession(...)`
//                                                          over three lines and the
//                                                          raw `===` on the callee
//                                                          then found zero calls.
//                                                          An exact-text pin needs
//                                                          its reformat control, and
//                                                          this is the second time
//                                                          in this wave that the
//                                                          control is what found the
//                                                          defect.
// ----------------------------------------------------------------------------
// Mutation table - FIX ROUND 4. Same discipline and the same both-trees reset;
// baseline fa 238 ok, fs 202 ok, fp 79 ok, both tsc projects and
// `prettier --check` green.
//
//   Id    Mutation                                       Result
//   ----  ---------------------------------------------  --------------------------
//   Z3    ssh-session.ts: the autostart call site        RED, fa 237/238 - the NEW
//           wrapped in an EXPRESSION guard,                `stmt.expression === outer`
//           `sessionEnded && void startHostForwards(…)`,   assertion, and nothing
//           then `prettier --write` so the formatting      else. GREEN across every
//           is what a developer would actually commit      gate before it: the
//                                                          statement's parent IS the
//                                                          body, so enclosingStatement
//                                                          returned it and the wrapper
//                                                          check passed while the whole
//                                                          feature was inert for every
//                                                          rule (`sessionEnded` is
//                                                          false at `:206`).
//   Z7    ssh-session.ts: `close: async () => {` with    RED, fa 236/238 - both new
//           `await Promise.resolve();` above the           assertions, the not-async
//           release                                        one and the no-await-above
//                                                          one. `tsc` and `prettier`
//                                                          clean, and the release
//                                                          stays a DIRECT statement of
//                                                          close's own body, which is
//                                                          why the nesting check could
//                                                          not see it.
//   Z7b   `close: async () => {` with NO await added     RED on the not-async
//                                                          assertion ALONE - so the two
//                                                          are independent rather than
//                                                          one claim written twice.
//   Z7c   `close: async () => {` with the await placed   RED on the not-async
//           BELOW the release                              assertion alone; the
//                                                          position assertion stayed
//                                                          GREEN, which is the scoping
//                                                          it was written with - an
//                                                          await after the release
//                                                          defers nothing, and
//                                                          refusing it would redden a
//                                                          correct future edit.
//   Z4    the four fresh-reference selectors, Z5 the     see forwards-shell-verify.ts's
//    Z5     rename control, Z5c the reverted               own round-4 table. Z5c
//    Z5c    parameterisation, Z8 the reflow control       reddens THIS file too (fa
//    Z8                                                   235/238): the allow-list here
//                                                          is the original that copy
//                                                          was taken from, so a rename
//                                                          breaks both.
// ----------------------------------------------------------------------------
