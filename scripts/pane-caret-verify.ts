/**
 * Self-check for VLT-39 (and its RDP-side twin, VLT-64): which pane owns the
 * caret across a tab switch. Run: `npx tsx scripts/pane-caret-verify.ts`.
 *
 * TWO PREDECESSORS WERE GREEN OVER THE VERY THING THEY EXISTED TO PROTECT, for
 * the same underlying reason, so the reason is worth naming rather than the two
 * bugs:
 *
 *   - `terminal-focus-attach-verify.ts` pinned one true but insufficient
 *     property, and deleting `if (focused) s.term.focus();` - the only writer
 *     that returned the caret to a terminal on a tab switch - left it green.
 *   - This file's first draft asserted `visBody.includes("claimCaret()")`, which
 *     `if (false) claimCaret();` satisfies. Four other straight reversions were
 *     green too, including replacing the whole fix with
 *     `createCaretArbiter((run) => { run(); })`.
 *
 * The class is A POSITIVE ASSERTION THAT DEAD CODE CAN SATISFY. A substring is
 * in a file whether or not the statement holding it can ever run, and
 * `createCaretArbiter` is a factory, not the object the app claims through. Two
 * rules follow, and every check below is one or the other:
 *
 *   POSITIVES MUST BE LIVE. "X happens" is asserted against code that is
 *   statically REACHABLE - `walkLive` below refuses to descend into `if (false)`
 *   / `if (0)` / `if (null)`, anything after an unconditional `return`, the
 *   never-taken arm of a `&&`, a `while (false)` body - so a neutered call reads
 *   as absent. And where the app has one wired-up object (`paneCaret`), the
 *   assertion drives THAT object, with `requestAnimationFrame` stubbed from
 *   under it, rather than a fresh arbiter built to the test's own taste.
 *
 *   NEGATIVES MUST COVER EVERYTHING. "X never happens" is asserted over the
 *   whole subtree, dead branches included (`walkAll`): dead code is revived by
 *   deleting one word, so a `.focus()` parked behind `if (false)` is a defect
 *   already.
 *
 * What was actually broken, measured in a headless Chromium against a
 * structural copy of the tab strip: the tab strip is a Radix `Tabs`, Radix
 * changes value on MOUSEDOWN, React 19 flushes the resulting commit (layout AND
 * passive effects) synchronously inside that same mousedown, and the browser
 * then runs the mousedown's default action and focuses the tab chip - over the
 * top of whatever any pane effect had just focused. So both halves of VLT-39
 * were the same defect: the Hosts search box never kept the caret on a
 * click-through (R11.3/R11.5), and a terminal never got it back after a tab
 * round-trip (R11.6).
 *
 * The fix is a hand-over deferred by one frame, with three guards, in
 * `src/lib/paneCaret.ts`. Three things are checked here:
 *
 *   1. THE CONTRACT, EXECUTED. `createCaretArbiter` takes its scheduler and its
 *      view of the caret as parameters, so the whole decision runs in Node
 *      against a hand-cranked frame - including the property that IS the fix: a
 *      claim must not take the caret synchronously.
 *   2. THE APP'S ARBITER, EXECUTED. The `paneCaret` export, driven through a
 *      stubbed `requestAnimationFrame` and a stubbed `document`, so the frame
 *      deferral and the `OVERLAY_ROLES` selector are checked as WIRED, not as
 *      re-created.
 *   3. THE CALL SITES, PARSED. That a pane CLAIMS instead of calling `.focus()`
 *      is a shape, so it is read out of the files that must not regress -
 *      HostsPage, useTerminalSession, and (VLT-64) RdpPane, which had VLT-39's
 *      direct-focus defect verbatim until it was converted to a claim. Parsed
 *      with the TypeScript compiler rather than matched with regexes, because
 *      the question asked of each site - "can this call actually run, and under
 *      what condition" - is not a question about text.
 *
 * The executed/parsed split is counted and printed by the run itself, so no
 * comment here can claim a number the file does not have.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import ts from "typescript";

import { caretHandoff, createCaretArbiter, paneCaret, type CaretNode } from "../src/lib/paneCaret";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (rel: string) => readFileSync(join(repoRoot, rel), "utf8");

let failed = 0;
let phase: "executed" | "parsed" = "executed";
const tally = { executed: 0, parsed: 0 };
function check(name: string, ok: boolean, detail?: string | number): void {
  tally[phase]++;
  if (ok) {
    console.log(`  ok: ${name}`);
    return;
  }
  console.error(`  FAIL: ${name}`, detail === undefined ? "" : JSON.stringify(detail));
  failed++;
}

// ============================================================================
// 1. THE CONTRACT, EXECUTED
// ============================================================================

/** A stand-in for a DOM element: `contains` by membership, `closest` by role. */
function node(
  name: string,
  opts: { holds?: string[]; role?: string } = {},
): CaretNode & {
  name: string;
} {
  const self = {
    name,
    contains(other: unknown): boolean {
      const o = other as { name?: string } | null;
      return !!o?.name && (o.name === name || (opts.holds ?? []).includes(o.name));
    },
    closest(selector: string): CaretNode | null {
      // Answering the ARGUMENT, not just "am I an overlay". A fixture that says
      // yes to any selector at all leaves `OVERLAY_ROLES` unchecked: dropping
      // `[role="dialog"]` from it stays green, and every dialog loses the caret
      // a frame after it opens. Split the selector the way
      // `keybindings-terminal-verify.ts` splits its own.
      if (!opts.role) return null;
      const wanted = selector.split(",").map((s) => s.trim());
      return wanted.includes(`[role="${opts.role}"]`) ? self : null;
    },
  };
  return self;
}

/** An arbiter whose "frame" only happens when this test says so. */
function harness(caret: () => CaretNode | null) {
  const frames: (() => void)[] = [];
  const taken: string[] = [];
  const arbiter = createCaretArbiter((run) => frames.push(run), caret);
  return {
    arbiter,
    taken,
    pendingFrames: () => frames.length,
    /** Run every scheduled frame callback, once each. */
    frame() {
      const due = frames.splice(0, frames.length);
      for (const run of due) run();
    },
    claim(owner: string, opts: { pane?: CaretNode | null; onScreen?: () => boolean } = {}): void {
      arbiter.claim(owner, {
        pane: () => opts.pane ?? null,
        stillOnScreen: opts.onScreen ?? (() => true),
        take: () => taken.push(owner),
      });
    },
  };
}

console.log("[the fix] a claim is not honoured until after the gesture that caused it");
{
  // The tab chip holds the caret when the claim is made - which is exactly the
  // state the browser leaves behind after a mousedown on the tab strip.
  const h = harness(() => node("tab-chip"));
  h.claim("hosts", { pane: node("hosts-pane") });
  check(
    "nothing is focused synchronously (the mousedown default action has not run yet)",
    h.taken.length === 0,
    h.taken.join(","),
  );
  h.frame();
  check(
    "one frame later the caret is handed over",
    h.taken.join(",") === "hosts",
    h.taken.join(","),
  );
}

console.log("\n[stale claims] the world is re-read at flush time, never at claim time");
{
  // A slow attach: the leaf was on screen when it claimed and is not by the
  // time the frame runs. This is the property the previous fix (2dc40b5) added
  // and it is kept, now as a consequence of the contract rather than a
  // special case at two call sites.
  let onScreen = true;
  const h = harness(() => node("tab-chip"));
  h.claim("term", { pane: node("term-pane"), onScreen: () => onScreen });
  onScreen = false;
  h.frame();
  check(
    "a leaf that went off screen between claim and frame does not take the caret",
    h.taken.length === 0,
    h.taken.join(","),
  );
}

console.log("\n[the user always wins] focus the user placed is never overridden");
{
  // Clicking a host card / a pane header button inside the claiming pane.
  const h = harness(() => node("a-host-card"));
  h.claim("hosts", { pane: node("hosts-pane", { holds: ["a-host-card"] }) });
  h.frame();
  check(
    "the caret already inside the claimant's own pane is left alone",
    h.taken.length === 0,
    h.taken.join(","),
  );
}
{
  // A menu/dialog is portaled OUT of the pane that opened it, so the clause
  // above cannot see it. Without this one, opening "New host" in a pane that
  // was not already active yanks the caret out of the menu a frame later.
  //
  // One case PER ROLE, not one "overlay" flag: the fixture's `closest` answers
  // the selector it is handed, so a role dropped from `OVERLAY_ROLES` reddens
  // exactly the line that names it instead of hiding behind its neighbours.
  for (const role of ["menu", "dialog", "alertdialog", "listbox"]) {
    const h = harness(() => node(`${role}-content`, { role }));
    h.claim("hosts", { pane: node("hosts-pane") });
    h.frame();
    check(`a [role="${role}"] holding the caret keeps it`, h.taken.length === 0, h.taken.join(","));
  }
}
{
  // THE NEGATIVE HALF (§4.30). Not every portaled thing traps the caret - a
  // tooltip must not, or a pane that opens one can never be handed the caret
  // again. This is what keeps `OVERLAY_ROLES` from being widened to `*`.
  const h = harness(() => node("a-tooltip", { role: "tooltip" }));
  h.claim("hosts", { pane: node("hosts-pane") });
  h.frame();
  check(
    "a role that is NOT an overlay does not block the hand-over",
    h.taken.join(",") === "hosts",
    h.taken.join(","),
  );
}
{
  // The caret is in ANOTHER pane: Ctrl+] moving to the next pane has nothing
  // else to move it, so this one must NOT be treated as the user's.
  const h = harness(() => node("other-pane-body"));
  h.claim("term", { pane: node("term-pane") });
  h.frame();
  check(
    "the caret in a DIFFERENT pane is taken (Ctrl+] still works)",
    h.taken.join(",") === "term",
    h.taken.join(","),
  );
}

console.log("\n[one caret] a frame hands it to at most one pane");
{
  let hostsOnScreen = true;
  const h = harness(() => node("tab-chip"));
  h.claim("hosts", { pane: node("hosts-pane"), onScreen: () => hostsOnScreen });
  h.claim("term", { pane: node("term-pane") });
  check(
    "two claims in one commit still schedule ONE frame",
    h.pendingFrames() === 1,
    h.pendingFrames(),
  );
  hostsOnScreen = false;
  h.frame();
  check(
    "only the claim that is still on screen takes it",
    h.taken.join(",") === "term",
    h.taken.join(","),
  );
}
{
  const h = harness(() => node("tab-chip"));
  h.claim("a", { pane: node("a-pane") });
  h.claim("b", { pane: node("b-pane") });
  h.frame();
  check("two equally-valid claims do not both fire", h.taken.length === 1, h.taken.join(","));
}
{
  const h = harness(() => node("tab-chip"));
  h.claim("gone", { pane: node("gone-pane") });
  h.arbiter.release("gone");
  h.frame();
  check("a released claim (unmounted pane) never fires", h.taken.length === 0, h.taken.join(","));
}
{
  const h = harness(() => node("tab-chip"));
  h.claim("hosts", { pane: node("hosts-pane") });
  h.frame();
  h.frame();
  check("a claim fires once, not on every later frame", h.taken.length === 1, h.taken.join(","));
}

console.log("\n[exhaustive] exactly one of the eight states hands the caret over");
{
  let handovers = 0;
  for (const stillOnScreen of [false, true]) {
    for (const caretInsideOwnPane of [false, true]) {
      for (const caretInOverlay of [false, true]) {
        if (caretHandoff({ stillOnScreen, caretInsideOwnPane, caretInOverlay })) handovers++;
      }
    }
  }
  check("1 of 8, and it is on-screen + not mine + no overlay", handovers === 1, handovers);
  check(
    "that one is the tab-switch case",
    caretHandoff({ stillOnScreen: true, caretInsideOwnPane: false, caretInOverlay: false }),
  );
}

// ============================================================================
// 2. THE APP'S ARBITER, EXECUTED
// ============================================================================

/** Queue whatever the module under test asks a frame for, and hand back the
 *  drain. Returns the queue so a block can assert HOW MANY frames were asked
 *  for - `setTimeout` instead of `requestAnimationFrame` would show up as zero. */
function stubFrames(extraGlobals: Record<string, unknown> = {}) {
  const frames: (() => void)[] = [];
  Object.assign(globalThis, {
    requestAnimationFrame: (cb: FrameRequestCallback): number => frames.push(() => cb(0)),
    ...extraGlobals,
  });
  return {
    frames,
    run() {
      for (const f of frames.splice(0, frames.length)) f();
    },
    restore() {
      Reflect.deleteProperty(globalThis, "requestAnimationFrame");
      for (const key of Object.keys(extraGlobals)) Reflect.deleteProperty(globalThis, key);
    },
  };
}

console.log("\n[the app's arbiter] `paneCaret` itself, not another one built to taste");
{
  // Everything above drives `createCaretArbiter`, which is a FACTORY. Swapping
  // the app's instance for `createCaretArbiter((run) => { run(); })` - VLT-39
  // reverted whole, in one line - leaves every check above green, because none
  // of them ever touches the export the panes actually claim through.
  const rig = stubFrames();
  try {
    const taken: string[] = [];
    paneCaret.claim("probe-defer", {
      pane: () => null,
      stillOnScreen: () => true,
      take: () => void taken.push("probe-defer"),
    });
    check(
      "a claim on `paneCaret` takes nothing synchronously - the deferral IS the fix",
      taken.length === 0,
      taken.join(","),
    );
    check(
      "...and it asks for exactly one animation frame (rAF, not a timeout)",
      rig.frames.length === 1,
      rig.frames.length,
    );
    rig.run();
    check(
      "...and hands the caret over inside that frame",
      taken.join(",") === "probe-defer",
      taken.join(","),
    );
  } finally {
    rig.restore();
  }
}
{
  // The other half of the app's wiring: `domCaret`, the default `caretNow` that
  // every fixture above replaces, is what feeds a REAL element to
  // `OVERLAY_ROLES`. Stub `document` so that path runs for real too - dropping a
  // role from the selector has to redden here as well as upstairs.
  const dialog = node("open-dialog", { role: "dialog" });
  const rig = stubFrames({ document: { activeElement: dialog } });
  try {
    const taken: string[] = [];
    paneCaret.claim("probe-overlay", {
      pane: () => null,
      stillOnScreen: () => true,
      take: () => void taken.push("probe-overlay"),
    });
    rig.run();
    check(
      "a dialog holding the real `document.activeElement` keeps the caret",
      taken.length === 0,
      taken.join(","),
    );
  } finally {
    rig.restore();
  }
}

// ============================================================================
// 3. THE CALL SITES, PARSED
// ============================================================================
phase = "parsed";

function parse(rel: string): ts.SourceFile {
  return ts.createSourceFile(
    rel,
    read(rel),
    ts.ScriptTarget.ESNext,
    /* setParentNodes */ true,
    rel.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS,
  );
}

type Truth = "truthy" | "falsy" | "unknown";

/** What a condition is worth without running anything. Only literals answer;
 *  everything else is `unknown`, which keeps the walk below conservative in the
 *  safe direction (an unknown branch is treated as live). */
function staticTruth(expr: ts.Expression): Truth {
  if (expr.kind === ts.SyntaxKind.TrueKeyword) return "truthy";
  if (expr.kind === ts.SyntaxKind.FalseKeyword) return "falsy";
  if (expr.kind === ts.SyntaxKind.NullKeyword) return "falsy";
  if (ts.isIdentifier(expr) && expr.text === "undefined") return "falsy";
  if (ts.isNumericLiteral(expr)) return Number(expr.text) === 0 ? "falsy" : "truthy";
  if (ts.isStringLiteral(expr) || ts.isNoSubstitutionTemplateLiteral(expr)) {
    return expr.text === "" ? "falsy" : "truthy";
  }
  if (ts.isVoidExpression(expr)) return "falsy";
  if (ts.isParenthesizedExpression(expr)) return staticTruth(expr.expression);
  if (ts.isPrefixUnaryExpression(expr) && expr.operator === ts.SyntaxKind.ExclamationToken) {
    const inner = staticTruth(expr.operand);
    return inner === "truthy" ? "falsy" : inner === "falsy" ? "truthy" : "unknown";
  }
  return "unknown";
}

const terminates = (s: ts.Statement): boolean =>
  ts.isReturnStatement(s) ||
  ts.isThrowStatement(s) ||
  ts.isBreakStatement(s) ||
  ts.isContinueStatement(s);

/** Every node that can actually run, starting at `root`. This is what makes a
 *  positive assertion mean something: `if (false) claimCaret();`, `if (0) ...`,
 *  a call below an unconditional `return`, and the right of a `false &&` are
 *  never visited, so they read as absent rather than as present-and-fine. */
function walkLive(root: ts.Node, visit: (n: ts.Node) => void): void {
  visit(root);
  if (ts.isSourceFile(root) || ts.isBlock(root) || ts.isCaseClause(root)) {
    for (const st of root.statements) {
      walkLive(st, visit);
      if (terminates(st)) return;
    }
    return;
  }
  if (ts.isIfStatement(root)) {
    walkLive(root.expression, visit);
    const t = staticTruth(root.expression);
    if (t !== "falsy") walkLive(root.thenStatement, visit);
    if (t !== "truthy" && root.elseStatement) walkLive(root.elseStatement, visit);
    return;
  }
  if (ts.isConditionalExpression(root)) {
    walkLive(root.condition, visit);
    const t = staticTruth(root.condition);
    if (t !== "falsy") walkLive(root.whenTrue, visit);
    if (t !== "truthy") walkLive(root.whenFalse, visit);
    return;
  }
  if (
    ts.isBinaryExpression(root) &&
    (root.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken ||
      root.operatorToken.kind === ts.SyntaxKind.BarBarToken)
  ) {
    walkLive(root.left, visit);
    const isAnd = root.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken;
    const t = staticTruth(root.left);
    if (isAnd ? t !== "falsy" : t !== "truthy") walkLive(root.right, visit);
    return;
  }
  if (ts.isWhileStatement(root) && staticTruth(root.expression) === "falsy") {
    walkLive(root.expression, visit);
    return;
  }
  if (ts.isForStatement(root) && root.condition && staticTruth(root.condition) === "falsy") {
    if (root.initializer) walkLive(root.initializer, visit);
    walkLive(root.condition, visit);
    return;
  }
  ts.forEachChild(root, (c) => {
    walkLive(c, visit);
  });
}

/** Every node under `root`, dead branches included. Negative assertions use
 *  this: a `.focus()` parked behind `if (false)` is one word from being live. */
function walkAll(root: ts.Node, visit: (n: ts.Node) => void): void {
  visit(root);
  ts.forEachChild(root, (c) => {
    walkAll(c, visit);
  });
}

function liveMatches<T>(root: ts.Node, match: (n: ts.Node) => T | null): T[] {
  const out: T[] = [];
  walkLive(root, (n) => {
    const m = match(n);
    if (m !== null) out.push(m);
  });
  return out;
}

function allMatches<T>(root: ts.Node, match: (n: ts.Node) => T | null): T[] {
  const out: T[] = [];
  walkAll(root, (n) => {
    const m = match(n);
    if (m !== null) out.push(m);
  });
  return out;
}

/** `<callee>(...)`, matched on the callee's own source text. */
const callTo =
  (callee: string) =>
  (n: ts.Node): ts.CallExpression | null =>
    ts.isCallExpression(n) && n.expression.getText() === callee ? n : null;

/** Any `x.focus(...)`, however it is reached. */
const focusCall = (n: ts.Node): ts.CallExpression | null =>
  ts.isCallExpression(n) &&
  ts.isPropertyAccessExpression(n.expression) &&
  n.expression.name.text === "focus"
    ? n
    : null;

const isFunctionNode = (n: ts.Node): boolean =>
  ts.isFunctionDeclaration(n) ||
  ts.isFunctionExpression(n) ||
  ts.isArrowFunction(n) ||
  ts.isMethodDeclaration(n);

/** How many functions enclose `n`. 1 = the component/hook body itself, i.e.
 *  RENDER scope; 2+ = inside an effect, a callback, a cleanup. */
function functionDepth(n: ts.Node): number {
  let d = 0;
  for (let p: ts.Node | undefined = n.parent; p; p = p.parent) if (isFunctionNode(p)) d++;
  return d;
}

const spans = (outer: ts.Node, inner: ts.Node): boolean =>
  inner.getStart() >= outer.getStart() && inner.end <= outer.end;

/** Identifiers an expression reads. `a.b` names `a`; `{ x: 1 }` names neither. */
function identifiersIn(root: ts.Node): Set<string> {
  const out = new Set<string>();
  walkAll(root, (n) => {
    if (!ts.isIdentifier(n)) return;
    const p: ts.Node | undefined = n.parent;
    if (p && ts.isPropertyAccessExpression(p) && p.name === n) return;
    if (p && ts.isPropertyAssignment(p) && p.name === n) return;
    out.add(n.text);
  });
  return out;
}

const exitsEarly = (s: ts.Statement): boolean => {
  if (ts.isReturnStatement(s) || ts.isThrowStatement(s)) return true;
  return (
    ts.isBlock(s) && s.statements.some((x) => ts.isReturnStatement(x) || ts.isThrowStatement(x))
  );
};

/**
 * Every condition that has to hold for `n` to run, up to `stop`: each enclosing
 * `if`, each `&&`/`||` it sits to the right of, and each `if (...) return;`
 * standing above it in an enclosing block.
 *
 * Collected as expressions and asked only for their IDENTIFIERS, so the sign of
 * a guard (`focused` vs `!focused`) is deliberately not the question. The
 * question is whether the pane's own visibility still takes part in the decision
 * at all - `if (true) claimCaret();` is reachable and still wrong.
 */
function reachConditions(n: ts.Node, stop: ts.Node): ts.Expression[] {
  const out: ts.Expression[] = [];
  for (let cur: ts.Node = n; cur !== stop && cur.parent; cur = cur.parent) {
    const p: ts.Node = cur.parent;
    if (ts.isIfStatement(p) && cur !== p.expression) out.push(p.expression);
    else if (ts.isConditionalExpression(p) && cur !== p.condition) out.push(p.condition);
    else if (
      ts.isBinaryExpression(p) &&
      cur === p.right &&
      (p.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken ||
        p.operatorToken.kind === ts.SyntaxKind.BarBarToken)
    ) {
      out.push(p.left);
    } else if (ts.isBlock(p)) {
      for (const st of p.statements) {
        if (st === cur) break;
        if (ts.isIfStatement(st) && !st.elseStatement && exitsEarly(st.thenStatement)) {
          out.push(st.expression);
        }
      }
    }
  }
  return out;
}

function reachIdentifiers(n: ts.Node, stop: ts.Node): Set<string> {
  const out = new Set<string>();
  for (const cond of reachConditions(n, stop)) for (const id of identifiersIn(cond)) out.add(id);
  return out;
}

type Effect = {
  body: ts.ConciseBody;
  deps: string[];
  /** Whether a second argument was written at all. `useEffect(fn, [])` and
   *  `useEffect(fn)` both parse to `deps: []` above, but they are opposite
   *  effects: the first runs once, on mount; the second runs after EVERY
   *  render, because React only skips a re-run when it has a deps array to
   *  compare against. `deps.length === 0` alone cannot tell them apart. */
  depsArgPresent: boolean;
  /** Functions this effect returns - React runs them on cleanup. */
  cleanups: ts.Node[];
};

function cleanupsOf(fn: ts.ArrowFunction): ts.Node[] {
  const body = fn.body;
  if (!ts.isBlock(body)) {
    return ts.isArrowFunction(body) || ts.isFunctionExpression(body) ? [body] : [];
  }
  const out: ts.Node[] = [];
  walkAll(body, (n) => {
    if (!ts.isReturnStatement(n)) return;
    const e = n.expression;
    if (e && (ts.isArrowFunction(e) || ts.isFunctionExpression(e))) out.push(e);
  });
  return out;
}

/** Every `useEffect(() => ..., [...])` / `useLayoutEffect(...)` in a file. */
function effectsIn(sf: ts.SourceFile): Effect[] {
  return allMatches(sf, (n) => {
    if (!ts.isCallExpression(n) || !ts.isIdentifier(n.expression)) return null;
    const hook = n.expression.text;
    if (hook !== "useEffect" && hook !== "useLayoutEffect") return null;
    const fn = n.arguments[0];
    if (!fn || !ts.isArrowFunction(fn)) return null;
    const depsArg = n.arguments[1];
    const deps =
      depsArg && ts.isArrayLiteralExpression(depsArg)
        ? depsArg.elements.map((e) => e.getText())
        : [];
    return { body: fn.body, deps, depsArgPresent: !!depsArg, cleanups: cleanupsOf(fn) };
  });
}

const hasDeps = (e: Effect, ...names: string[]) => names.every((d) => e.deps.includes(d));

type Claim = { owner: string; props: Map<string, ts.Expression> };

/** Every REACHABLE `paneCaret.claim(owner, { ... })`. */
function claimsIn(root: ts.Node): Claim[] {
  return liveMatches(root, (n) => {
    const call = callTo("paneCaret.claim")(n);
    if (!call) return null;
    const owner = call.arguments[0];
    const obj = call.arguments[1];
    if (!owner || !obj || !ts.isObjectLiteralExpression(obj)) return null;
    const props = new Map<string, ts.Expression>();
    for (const p of obj.properties) {
      if (ts.isPropertyAssignment(p) && ts.isIdentifier(p.name))
        props.set(p.name.text, p.initializer);
    }
    return { owner: owner.getText(), props };
  });
}

/** Owners whose claim is withdrawn from an effect cleanup. */
function releasedOwners(sf: ts.SourceFile): string[] {
  const out: string[] = [];
  for (const eff of effectsIn(sf)) {
    for (const cleanup of eff.cleanups) {
      for (const call of liveMatches(cleanup, callTo("paneCaret.release"))) {
        const arg = call.arguments[0];
        if (arg) out.push(arg.getText());
      }
    }
  }
  return out;
}

/** `X.current = <rhs>` written at render scope, or null. */
function renderScopeRefWrite(
  sf: ts.SourceFile,
  ref: string,
): { any: boolean; rhs: ts.Expression | null } {
  const writes = allMatches(sf, (n) => {
    if (!ts.isBinaryExpression(n) || n.operatorToken.kind !== ts.SyntaxKind.EqualsToken)
      return null;
    return n.left.getText() === `${ref}.current` ? n : null;
  });
  const atRender = writes.filter((w) => functionDepth(w) === 1);
  return { any: writes.length > 0, rhs: atRender.length > 0 ? atRender[0].right : null };
}

/**
 * `stillOnScreen` has to READ A REF THAT IS REWRITTEN EVERY RENDER, not a value
 * closed over when the claim was made. The claim is decided a frame later, so a
 * closure is answering a question about a world that has already moved: that is
 * the stale-claim half of VLT-39, and `() => true`, `() => visible && focused`
 * (the params) and `() => onScreen` (the prop) are all the same defect written
 * three ways. Asserted as the property rather than as a spelling, so the fix
 * cannot be renamed out from under the check.
 */
function checkStillOnScreenIsLive(label: string, sf: ts.SourceFile, expr: ts.Expression): void {
  const refs = new Set<string>();
  const propsRead = new Map<string, Set<string>>();
  walkAll(expr, (n) => {
    if (!ts.isPropertyAccessExpression(n) || n.name.text !== "current") return;
    if (!ts.isIdentifier(n.expression)) return;
    const ref = n.expression.text;
    refs.add(ref);
    const parent: ts.Node | undefined = n.parent;
    if (parent && ts.isPropertyAccessExpression(parent) && parent.expression === n) {
      const bag = propsRead.get(ref) ?? new Set<string>();
      bag.add(parent.name.text);
      propsRead.set(ref, bag);
    }
  });
  check(
    `${label}: reads a ref, not a value captured when the claim was made`,
    refs.size > 0,
    expr.getText(),
  );
  for (const ref of refs) {
    const write = renderScopeRefWrite(sf, ref);
    check(`${label}: \`${ref}.current = ...\` exists`, write.any);
    check(
      `${label}: ...written at render scope (every render), not inside an effect (once, at mount)`,
      write.rhs !== null,
    );
    const wanted = propsRead.get(ref);
    if (!write.rhs || !wanted || wanted.size === 0) continue;
    // `{ visible, focused }` - each field the claim reads must actually be
    // re-supplied by that write. A write of `{ visible: true }` would keep the
    // ref alive and the answer frozen, which is the same bug with extra steps.
    const supplied = new Set<string>();
    if (ts.isObjectLiteralExpression(write.rhs)) {
      for (const p of write.rhs.properties) {
        if (ts.isShorthandPropertyAssignment(p)) supplied.add(p.name.text);
        else if (ts.isPropertyAssignment(p) && ts.isIdentifier(p.name)) {
          if (identifiersIn(p.initializer).size > 0) supplied.add(p.name.text);
        }
      }
    }
    const missing = [...wanted].filter((w) => !supplied.has(w));
    check(
      `${label}: ...and that write supplies every field the claim reads (${[...wanted].join(", ")})`,
      missing.length === 0,
      missing.join(","),
    );
  }
}

/** No `.focus()` anywhere in `root` except inside the claim's own `take:`, which
 *  is what `take:` is for. Scans DEAD code too - see the header's second rule. */
function checkNoDirectFocus(label: string, root: ts.Node): void {
  const takes = allMatches(root, (n) =>
    ts.isPropertyAssignment(n) && ts.isIdentifier(n.name) && n.name.text === "take"
      ? n.initializer
      : null,
  );
  const stray = allMatches(root, focusCall).filter((c) => !takes.some((t) => spans(t, c)));
  check(label, stray.length === 0, stray.map((c) => c.getText()).join(" | "));
}

/** The claim actually does something: `take:` has to reach a `.focus()`. */
function checkTakeFocuses(label: string, take: ts.Expression | undefined): void {
  check(label, !!take && liveMatches(take, focusCall).length > 0, take?.getText() ?? "(missing)");
}

/**
 * `pane:` has to resolve the LEAF FRAME - a live ref, then its `[data-pane-leaf]`
 * ancestor. That is what makes "the caret is already inside my pane" true for a
 * click on this pane's own header buttons, which the pane's own root element
 * does not contain. `pane: () => null` type-checks and satisfies any test that
 * only asks whether the key is present, while quietly switching that clause off:
 * the claim then yanks the caret off the header button that was just pressed,
 * one frame later. Asking for the frame is asking for the property.
 */
function checkPaneIsTheLeafFrame(label: string, pane: ts.Expression | undefined): void {
  const readsRef =
    !!pane &&
    allMatches(pane, (n) =>
      ts.isPropertyAccessExpression(n) && n.name.text === "current" ? n : null,
    ).length > 0;
  const findsFrame =
    !!pane &&
    liveMatches(pane, (n) => {
      if (!ts.isCallExpression(n)) return null;
      if (!ts.isPropertyAccessExpression(n.expression)) return null;
      if (n.expression.name.text !== "closest") return null;
      const arg = n.arguments[0];
      return arg && ts.isStringLiteral(arg) && arg.text === "[data-pane-leaf]" ? n : null;
    }).length > 0;
  check(label, readsRef && findsFrame, pane?.getText() ?? "(missing)");
}

console.log("\n[HostsPage.tsx] the page claims the caret, it does not take it");
{
  const sf = parse("src/modules/hosts/HostsPage.tsx");
  const effects = effectsIn(sf);
  const focusEffect = effects.find((e) => e.deps.length === 1 && e.deps[0] === "onScreen");
  check(
    "found the effect keyed on the on-screen prop",
    !!focusEffect,
    effects.map((e) => `[${e.deps.join(",")}]`).join(" "),
  );
  const body = focusEffect?.body;
  const claims = body ? claimsIn(body) : [];
  check("it makes exactly one REACHABLE paneCaret.claim(", claims.length === 1, claims.length);
  if (body && claims.length === 1) {
    const claim = claims[0];
    const claimCall = liveMatches(body, callTo("paneCaret.claim"))[0];
    check(
      "...reached only when the page is on screen (`if (true)` would not do)",
      reachIdentifiers(claimCall, body).has("onScreen"),
      [...reachIdentifiers(claimCall, body)].join(","),
    );
    checkStillOnScreenIsLive("stillOnScreen", sf, claim.props.get("stillOnScreen") ?? claimCall);
    checkPaneIsTheLeafFrame(
      "its pane: resolves the leaf frame it must not steal from",
      claim.props.get("pane"),
    );
    checkTakeFocuses("its take: is what focuses the search box", claim.props.get("take"));
    check(
      "and the claim is withdrawn on cleanup, for the SAME owner it was made for",
      releasedOwners(sf).includes(claim.owner),
      claim.owner,
    );
  }
  checkNoDirectFocus(
    "no .focus() outside take: in that effect - that is the shape the browser overwrites",
    body ?? sf,
  );
}

console.log("\n[useTerminalSession.ts] every terminal focus path is a claim");
{
  const sf = parse("src/modules/terminal/lib/useTerminalSession.ts");
  const effects = effectsIn(sf);

  const claims = claimsIn(sf);
  check(
    "the hook makes exactly one REACHABLE paneCaret.claim(",
    claims.length === 1,
    claims.length,
  );
  if (claims.length === 1) {
    const claim = claims[0];
    checkStillOnScreenIsLive(
      "stillOnScreen",
      sf,
      claim.props.get("stillOnScreen") ?? ts.factory.createTrue(),
    );
    checkPaneIsTheLeafFrame(
      "its pane: resolves the leaf frame it must not steal from",
      claim.props.get("pane"),
    );
    checkTakeFocuses("its take: is what focuses the terminal", claim.props.get("take"));
    check(
      "the claim is withdrawn on cleanup, for the SAME owner it was made for",
      releasedOwners(sf).includes(claim.owner),
      claim.owner,
    );
  }

  const attach = effects.find((e) => e.deps.length === 1 && e.deps[0] === "leafId");
  check(
    "found the [leafId] attach effect",
    !!attach,
    effects.map((e) => `[${e.deps.join(",")}]`).join(" "),
  );
  if (attach) {
    check(
      "both attach sites (immediate + interval fallback) reach claimCaret()",
      liveMatches(attach.body, callTo("claimCaret")).length === 2,
      liveMatches(attach.body, callTo("claimCaret")).length,
    );
    checkNoDirectFocus("no bare .focus() left in the attach effect", attach.body);
  }

  const visibility = effects.find((e) => hasDeps(e, "visible", "focused"));
  check(
    "found the visibility/focus effect",
    !!visibility,
    effects.map((e) => `[${e.deps.join(",")}]`).join(" "),
  );
  if (visibility) {
    const calls = liveMatches(visibility.body, callTo("claimCaret"));
    // R11.6 IS this call. `if (false) claimCaret();` used to satisfy the check
    // that stood here, which is why liveness is the assertion now.
    check("the tab-switch path reaches claimCaret()", calls.length === 1, calls.length);
    if (calls.length === 1) {
      const reached = reachIdentifiers(calls[0], visibility.body);
      check(
        "...only when this leaf is both visible and focused",
        reached.has("visible") && reached.has("focused"),
        [...reached].join(","),
      );
    }
    checkNoDirectFocus(
      "...and it does not call .focus() itself - R11.6 is exactly that call losing to the tab chip",
      visibility.body,
    );
  }
}

console.log("\n[RdpPane.tsx] the RDP pane claims the caret, it does not take it (VLT-64)");
{
  const sf = parse("src/modules/rdp/RdpPane.tsx");
  const effects = effectsIn(sf);

  // `leafId` disambiguates from the OTHER `[visible, focused, ...]` effect in
  // this file (the one that fires `releaseAll()`), which shares two of the three
  // deps but not this one.
  const claimEffect = effects.find((e) => hasDeps(e, "leafId", "visible", "focused"));
  check(
    "found the [leafId, visible, focused] claim effect",
    !!claimEffect,
    effects.map((e) => `[${e.deps.join(",")}]`).join(" "),
  );
  const body = claimEffect?.body;
  const claims = body ? claimsIn(body) : [];
  check("it makes exactly one REACHABLE paneCaret.claim(", claims.length === 1, claims.length);
  if (body && claims.length === 1) {
    const claim = claims[0];
    const claimCall = liveMatches(body, callTo("paneCaret.claim"))[0];
    const reached = reachIdentifiers(claimCall, body);
    check(
      "...reached only when this leaf is both visible and focused",
      reached.has("visible") && reached.has("focused"),
      [...reached].join(","),
    );
    checkStillOnScreenIsLive("stillOnScreen", sf, claim.props.get("stillOnScreen") ?? claimCall);
    checkPaneIsTheLeafFrame(
      "its pane: resolves the leaf frame it must not steal from",
      claim.props.get("pane"),
    );
    checkTakeFocuses("its take: is what focuses the RDP host element", claim.props.get("take"));
    check(
      "the claim is withdrawn on cleanup, for the SAME owner it was made for",
      releasedOwners(sf).includes(claim.owner),
      claim.owner,
    );
  }
  checkNoDirectFocus(
    "no .focus() outside take: in that effect - that is the shape the browser overwrites",
    body ?? sf,
  );
}

console.log("\n[PaneTreeView.tsx] the page is only on screen when its leaf is the active one");
{
  const sf = parse("src/modules/panes/PaneTreeView.tsx");
  /** The `attr={...}` expression on the first `<tag ...>` in the file. */
  const jsxAttr = (tag: string, attr: string): ts.Expression | null => {
    const found = allMatches(sf, (n) => {
      const open = ts.isJsxSelfClosingElement(n) ? n : ts.isJsxOpeningElement(n) ? n : null;
      if (!open || open.tagName.getText() !== tag) return null;
      for (const p of open.attributes.properties) {
        if (!ts.isJsxAttribute(p) || !ts.isIdentifier(p.name) || p.name.text !== attr) continue;
        const init = p.initializer;
        if (init && ts.isJsxExpression(init) && init.expression) return init.expression;
      }
      return null;
    });
    return found.length > 0 ? found[0] : null;
  };

  // R11.6's other half: without `focused` in this signal, switching to a tab
  // that splits Hosts beside a terminal would hand the caret to the page.
  const onScreen = jsxAttr("PageLeafBody", "onScreen");
  check("PageLeafBody is given an onScreen expression", !!onScreen, "(missing)");
  if (onScreen) {
    const ids = identifiersIn(onScreen);
    check(
      "...and it is `tabVisible && focused`, both of them",
      ts.isBinaryExpression(onScreen) &&
        onScreen.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken &&
        ids.has("tabVisible") &&
        ids.has("focused"),
      onScreen.getText(),
    );
  }
  const forwarded = jsxAttr("HostsPage", "onScreen");
  check(
    "...and forwards it to HostsPage as onScreen",
    !!forwarded && identifiersIn(forwarded).has("onScreen"),
    forwarded?.getText() ?? "(missing)",
  );
}

console.log("\n[VaultPage.tsx] the rail view claims the caret, and mount is its on-screen signal");
{
  const sf = parse("src/modules/vault/VaultPage.tsx");
  const effects = effectsIn(sf);

  // A rail view is UNMOUNTED when it is not showing (`WorkspaceArea.tsx:142`),
  // so mount IS the visibility transition and the claim effect has no deps.
  // That is the opposite of HostsPage's `[onScreen]` above, and the reason the
  // two differ is the reason this section exists at all rather than reusing
  // that one.
  //
  // `depsArgPresent` as well as `deps.length === 0`: an ABSENT second argument
  // parses to the same `deps: []` as a literal `[]`, but it is the opposite
  // effect - `useEffect(fn)` with no deps array re-runs after every render,
  // which would claim and release the caret continuously instead of once on
  // mount. `hasDeps`/`e.deps.length === 1` elsewhere in this file never asks
  // "is this effect mount-only", so this is the only site that needs the
  // distinction, and the field means nothing to the other three sections.
  const mountEffects = effects.filter((e) => e.deps.length === 0 && e.depsArgPresent);
  check(
    "found exactly one mount-only effect to look in",
    mountEffects.length === 1,
    effects.map((e) => `[${e.deps.join(",")}]`).join(" "),
  );
  const body = mountEffects.length === 1 ? mountEffects[0].body : undefined;
  const claims = body ? claimsIn(body) : [];
  check("it makes exactly one REACHABLE paneCaret.claim(", claims.length === 1, claims.length);
  if (body && claims.length === 1) {
    const claim = claims[0];
    const claimCall = liveMatches(body, callTo("paneCaret.claim"))[0];

    checkStillOnScreenIsLive("stillOnScreen", sf, claim.props.get("stillOnScreen") ?? claimCall);

    // NOT checkPaneIsTheLeafFrame: this surface has no `[data-pane-leaf]`
    // ancestor - it is rendered outside PaneStack - so asking for one would
    // resolve null and switch the "the caret is already inside my own box"
    // clause OFF, which is what stops the claim yanking the caret out of
    // something the user just clicked in here. The property is the same
    // (`pane:` reads a LIVE ref, because `pane: () => null` type-checks and
    // silently disables the clause); the element it resolves is not.
    const pane = claim.props.get("pane");
    const paneReadsRef =
      !!pane &&
      allMatches(pane, (n) =>
        ts.isPropertyAccessExpression(n) && n.name.text === "current" ? n : null,
      ).length > 0;
    check(
      "its pane: reads a live ref rather than resolving to null",
      paneReadsRef,
      pane?.getText() ?? "(missing)",
    );
    check(
      "...and does not ask for a leaf frame this surface has never had",
      !!pane && !pane.getText().includes("data-pane-leaf"),
      pane?.getText() ?? "(missing)",
    );

    checkTakeFocuses("its take: is what focuses the search box", claim.props.get("take"));
    check(
      "the claim is withdrawn on cleanup, for the SAME owner it was made for",
      releasedOwners(sf).includes(claim.owner),
      claim.owner,
    );

    // The half a mount-only surface needs that a leaf does not: the cleanup
    // has to falsify the on-screen ref as well as release the claim, or a
    // claim already handed to the arbiter in the same frame as an unmount is
    // decided against a ref that still says "showing".
    const refName = (claim.props.get("stillOnScreen")?.getText() ?? "").match(
      /(\w+)\.current/,
    )?.[1];
    check("stillOnScreen names a ref we can look for", !!refName, refName ?? "(none)");
    const falsified = mountEffects[0].cleanups.some(
      (c) =>
        allMatches(c, (n) =>
          ts.isBinaryExpression(n) &&
          n.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
          n.left.getText() === `${refName}.current` &&
          n.right.kind === ts.SyntaxKind.FalseKeyword
            ? n
            : null,
        ).length > 0,
    );
    check("...and the cleanup sets it false as well as releasing the claim", falsified);
  }
  checkNoDirectFocus(
    "no .focus() outside take: in that effect - that is the shape the browser overwrites",
    body ?? sf,
  );

  // A prop could only ever carry the literal `true` here (RailViewArea's own
  // `case "vault":` is the only mount point), and a restated literal cannot
  // fail. Pinned so a future wave does not "fix" the ref by adding one.
  //
  // `getFullText()`, not `getText()`: this negative is over the WHOLE FILE,
  // comments included - a future wave drafting the prop in the header doc
  // comment above and forgetting to remove it should still redden this. Node
  // `getText()` skips a node's leading trivia, and for a `SourceFile` that
  // trivia is the entire leading doc comment; only `getFullText()` returns the
  // raw source `readFileSync` read.
  check("the page declares no onScreen prop", !sf.getFullText().includes("onScreen:"));
}

console.log(`\n${tally.executed} executed / ${tally.parsed} parsed-source checks`);
console.log(failed === 0 ? "ALL PASS" : `${failed} FAILED`);
process.exit(failed === 0 ? 0 : 1);
