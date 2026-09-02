/**
 * Self-check for wave 3 step 11: `startWithHost` - the terminal-owned forwards
 * map (`src/modules/forwards/hostOwned.ts`), the autostart entry point
 * (`src/modules/forwards/autostart.ts`), its call site and its two release
 * sites in `src/modules/terminal/lib/ssh-session.ts`, and the read-only
 * "Running (with host)" row in `src/modules/forwards/page/RuleCard.tsx`.
 * Run: `pnpm verify forward-autostart` (or `npx tsx
 * scripts/forward-autostart-verify.ts` to iterate).
 *
 * Sections 1-7 are BEHAVIOURAL: they drive the real `startHostForwards`
 * through the `AutostartDeps` seam that module exports for exactly this
 * purpose, so no Tauri IPC and no DOM is needed for the properties that
 * matter. Sections 8-10 are source pins, because a call site inside
 * `ssh-session.ts` cannot be imported at all (that file's own import graph
 * reaches `@xterm/xterm` and `@tauri-apps/plugin-os`, which throw on load
 * outside the app) and a React component's rendered text is not reachable
 * from node either.
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
 *    release written BELOW it, so this compares indices.
 *
 * 9. THE ROW THE TERMINAL'S FORWARD GETS. "Running (with host)", the port that
 *    is actually listening, and a disabled Start/Stop whose tooltip says where
 *    to stop it. Nothing else in the suite reads `RuleCard.tsx` for any of it.
 *
 * 10. §1.6 IN THE SECOND STORE TOO. Every `useHostOwnedForwards(` selector
 *    returns a primitive: one that builds a fresh object is never `Object.is`
 *    its own last return, and under zustand v5 that is "Maximum update depth
 *    exceeded" (research §12.7).
 */

import { readFileSync } from "node:fs";
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
 * `claimHostOwned` writes to the REAL store as well as recording, so section 6
 * reads what the shipped `claim`/`releaseSession` actually did rather than
 * what a copy of them in this file would have done.
 */
function world(over: {
  rules?: ForwardRule[];
  listRules?: () => Promise<ForwardRule[]>;
  status?: Record<string, ForwardStatus>;
  open?: (call: OpenCall) => Promise<number>;
}) {
  const banners: string[] = [];
  const openCalls: OpenCall[] = [];
  const claims: Array<{ ruleId: string; entry: HostOwnedEntry }> = [];
  const deps: AutostartDeps = {
    listRules: over.listRules ?? (async () => over.rules ?? []),
    openForward: async (id, localPort, remoteHost, remotePort) => {
      const call = { id, localPort, remoteHost, remotePort };
      openCalls.push(call);
      return over.open ? await over.open(call) : localPort || nextAutoPort++;
    },
    runtimeStatus: (ruleId) => over.status?.[ruleId] ?? "stopped",
    claimHostOwned: (ruleId, entry) => {
      claims.push({ ruleId, entry });
      useHostOwnedForwards.getState().claim(ruleId, entry);
    },
  };
  return { deps, banners, openCalls, claims, writeBanner: (t: string) => banners.push(t) };
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

/** The three banners, written out by value rather than imported: a check that
 *  reached for the module's own template would pass with the template
 *  rewritten. `->` is ASCII deliberately - see `autostart.ts`'s note, and
 *  `ssh-session.ts:498-501`'s existing forward banner. */
const forwardingBanner = (bound: number, target: string, name: string) =>
  `\x1b[2m[tervia] forwarding localhost:${bound} -> ${target} (${name})\x1b[0m\r\n`;
const failedBanner = (name: string, message: string) =>
  `\x1b[33m[tervia] forward "${name}" failed: ${message}\x1b[0m\r\n`;
const skippedBanner = (name: string) =>
  `\x1b[33m[tervia] forward "${name}" is already running from the Port Forwarding page; not starting a second one.\x1b[0m\r\n`;

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
for (const pageStatus of ["running", "starting"] as const) {
  resetHostOwned();
  const owned = rule({ id: "f-page", name: "page rule", localPort: 18080 });
  const free = rule({ id: "f-free", name: "free rule", localPort: 18081 });
  const w = world({ rules: [owned, free], status: { "f-page": pageStatus } });
  await startHostForwards("h-1", 7, w.writeBanner, w.deps);

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
    `the skip banner names the rule, by exact text ("${pageStatus}")`,
    w.banners[0],
    skippedBanner("page rule"),
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
  resetHostOwned();
  const r = rule({ id: "f-re", name: "reconnecting", localPort: 18080 });
  const first = world({ rules: [r] });
  await startHostForwards("h-1", 31, first.writeBanner, first.deps);
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
    (["listRules", "openForward", "runtimeStatus", "claimHostOwned"] as const).map(
      (k) => typeof defaultAutostartDeps[k],
    ),
    ["function", "function", "function", "function"],
  );
  check(
    'runtimeStatus answers "stopped" for a rule the page has never heard of',
    defaultAutostartDeps.runtimeStatus("f-never-started"),
    "stopped",
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

function findCallsTo(root: ts.Node, sf: ts.SourceFile, name: string): ts.CallExpression[] {
  const out: ts.CallExpression[] = [];
  const visit = (n: ts.Node): void => {
    if (ts.isCallExpression(n) && n.expression.getText(sf) === name) out.push(n);
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
    check(
      "it is handed the host id, the LIVE session id, and a banner writer bound to this pane",
      call.arguments.map((a) => norm(a.getText(sf))),
      ["sshConnectionId", "sshSession.id", "(text)=>writeSshBanner(s,text)"],
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
    }
  }

  // Release 1: inside `finishSsh`, ABOVE the disposed guard. Compared by
  // INDEX - two independent `includes` are both satisfied by a release written
  // below the guard, which is the leak this half exists to catch.
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
  }

  // Release 2: the PtySession adapter's own `close`, for the ending that never
  // reaches `finishSsh` (a user-initiated disconnect, a pane closing).
  const openBody = findFunctionBody(sf, "openSshForSession");
  let closeText: string | null = null;
  if (openBody) {
    const visit = (n: ts.Node): void => {
      if (
        ts.isReturnStatement(n) &&
        n.expression &&
        ts.isObjectLiteralExpression(n.expression) &&
        isDirectlyInFunctionBody(n, openBody)
      ) {
        const value = findPropertyValue(n.expression, "close", sf);
        if (value) closeText = norm(value.getText(sf));
      }
      ts.forEachChild(n, visit);
    };
    visit(openBody);
  }
  assert(closeText !== null, "found the PtySession adapter's close member");
  if (closeText !== null) {
    assert(
      (closeText as string).includes(
        "useHostOwnedForwards.getState().releaseSession(sshSession.id)",
      ),
      "the adapter's close releases this session's forwards too",
      closeText,
    );
    assert(
      (closeText as string).includes("sshSession.close()"),
      "and still closes the session itself",
      closeText,
    );
  }
}

// ===========================================================================
console.log("\n[9. RuleCard.tsx] the read-only row a terminal-owned forward gets");
// ===========================================================================
{
  const ruleCardRaw = read("src/modules/forwards/page/RuleCard.tsx");
  const sf = parse("RuleCard.tsx", stripComments(ruleCardRaw));

  for (const hook of ["useIsHostOwned(", "useHostOwnedPort("]) {
    assert(
      stripComments(ruleCardRaw).includes(hook),
      `RuleCard.tsx calls ${hook}) - reachable, not merely mentioned in a comment`,
    );
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
    assert(
      norm((statusText as ts.Node).getText(sf)).includes("if(hostOwned)"),
      "on the hostOwned branch, ahead of the status switch",
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

  // The three derived values, each read off its own binding's definition:
  // pinning the NAME would be satisfied by an alias or a rebind.
  const cases: Array<[string, string]> = [
    ["startDisabled", "row.hostDangling||starting||hostOwned"],
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

  // `onDelete(running)` is deliberately UNCHANGED: it feeds `deleteNote`,
  // whose "deleting a running rule stops it" sentence is true only of a rule
  // this page can stop. Pinned so the next reader does not "fix" it.
  assert(
    stripComments(ruleCardRaw).includes("onDelete(running)"),
    "onDelete still passes the PAGE's notion of running, not hostOwned",
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
        const forbidden =
          ts.isObjectLiteralExpression(expr) ||
          ts.isArrayLiteralExpression(expr) ||
          ts.isSpreadElement(expr) ||
          // The whole entry is an OBJECT: a selector returning it is never
          // `Object.is` its own last return once `claim` rebuilds `byRule`.
          /^s\.byRule\[[^\]]+\]$/.test(norm(expr.getText(sf)));
        assert(!forbidden, `${call.getText(sf)} returns a primitive`, expr.getText(sf));
      }
    }
  }
  assert(
    !/from ["']zustand\/react\/shallow["']/.test(hostOwnedSrc),
    "hostOwned.ts imports nothing from zustand/react/shallow",
  );
}

if (failed > 0) throw new Error(`forward-autostart-verify: ${failed} FAILED`);
console.log("\nforward-autostart-verify: OK\n");
