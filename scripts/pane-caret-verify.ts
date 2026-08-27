/**
 * Self-check for VLT-39 (and its RDP-side twin, VLT-64): which pane owns the
 * caret across a tab switch. Run: `npx tsx scripts/pane-caret-verify.ts`.
 *
 * Replaces `terminal-focus-attach-verify.ts`, which was green over the exact
 * implementation the hand test rejected. That check pinned one true but
 * insufficient property (the async attach reads live focus state, not
 * mount-time state) and could not see the defect at all: deleting
 * `if (focused) s.term.focus();` - the ONLY writer that returns the caret to a
 * terminal on a tab switch - left it fully green. It was rewritten rather than
 * extended because the property it pinned is not the property that was broken.
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
 * `src/lib/paneCaret.ts`. Two halves are checked here:
 *
 *   1. THE CONTRACT, EXECUTED. `createCaretArbiter` takes its scheduler and its
 *      view of the caret as parameters, so the whole decision runs in Node
 *      against a hand-cranked frame - including the property that IS the fix:
 *      a claim must not take the caret synchronously.
 *   2. THE CALL SITES, as source text. That a pane CLAIMS instead of calling
 *      `.focus()` is a shape, not a value, so it is read out of the files
 *      that must not regress - HostsPage, useTerminalSession, and (VLT-64)
 *      RdpPane, which had VLT-39's direct-focus defect verbatim until it was
 *      converted to a claim here. Weaker than (1), and said plainly rather
 *      than dressed up - but it reddens on the exact edit that would
 *      reintroduce the bug.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { caretHandoff, createCaretArbiter, type CaretNode } from "../src/lib/paneCaret";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (rel: string) => readFileSync(join(repoRoot, rel), "utf8");

let failed = 0;
function check(name: string, ok: boolean, detail?: unknown): void {
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

/** A stand-in for a DOM element: `contains` by membership, `closest` by flag. */
function node(
  name: string,
  opts: { holds?: string[]; overlay?: boolean } = {},
): CaretNode & {
  name: string;
} {
  const self = {
    name,
    contains(other: unknown): boolean {
      const o = other as { name?: string } | null;
      return !!o?.name && (o.name === name || (opts.holds ?? []).includes(o.name));
    },
    closest(_selector: string): CaretNode | null {
      return opts.overlay ? self : null;
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
    h.taken,
  );
  h.frame();
  check("one frame later the caret is handed over", h.taken.join(",") === "hosts", h.taken);
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
    h.taken,
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
    h.taken,
  );
}
{
  // A menu/dialog is portaled OUT of the pane that opened it, so the clause
  // above cannot see it. Without this one, opening "New host" in a pane that
  // was not already active yanks the caret out of the menu a frame later.
  const h = harness(() => node("menu-item", { overlay: true }));
  h.claim("hosts", { pane: node("hosts-pane") });
  h.frame();
  check("a menu/dialog/listbox holding the caret keeps it", h.taken.length === 0, h.taken);
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
    h.taken,
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
  check("only the claim that is still on screen takes it", h.taken.join(",") === "term", h.taken);
}
{
  const h = harness(() => node("tab-chip"));
  h.claim("a", { pane: node("a-pane") });
  h.claim("b", { pane: node("b-pane") });
  h.frame();
  check("two equally-valid claims do not both fire", h.taken.length === 1, h.taken);
}
{
  const h = harness(() => node("tab-chip"));
  h.claim("gone", { pane: node("gone-pane") });
  h.arbiter.release("gone");
  h.frame();
  check("a released claim (unmounted pane) never fires", h.taken.length === 0, h.taken);
}
{
  const h = harness(() => node("tab-chip"));
  h.claim("hosts", { pane: node("hosts-pane") });
  h.frame();
  h.frame();
  check("a claim fires once, not on every later frame", h.taken.length === 1, h.taken);
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
// 2. THE CALL SITES, AS SOURCE TEXT
// ============================================================================

/** Comment-stripped, quote-aware - same convention as host-editor-verify.ts /
 *  ssh-exit-verify.ts, so a docblock describing the bug in prose (this file's
 *  own header does, at length) can never be mistaken for the code checked. */
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
function stripComments(src: string): string {
  return src
    .split("\n")
    .filter((line) => {
      const t = line.trim();
      return !(t.startsWith("//") || t.startsWith("/*") || t.startsWith("*"));
    })
    .map(stripLineComment)
    .join("\n");
}

/** Index of the `}` matching the `{` at `openIdx`, or -1. */
function matchingBrace(src: string, openIdx: number): number {
  let depth = 0;
  for (let i = openIdx; i < src.length; i++) {
    if (src[i] === "{") depth++;
    else if (src[i] === "}") {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

type EffectSpan = { start: number; end: number; body: string; deps: string };

/** Every `useEffect(() => {...}, [...])` / `useLayoutEffect(...)` in `src`,
 *  brace-matched so a nested callback (a `setInterval`, a `.then()`) cannot end
 *  the scan early. */
function effectSpans(src: string): EffectSpan[] {
  const spans: EffectSpan[] = [];
  const re = /use(?:Layout)?Effect\(\(\)\s*=>\s*\{/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(src))) {
    const openBrace = src.indexOf("{", m.index);
    const close = matchingBrace(src, openBrace);
    if (close === -1) continue;
    const depsMatch = /^\s*,\s*\[([^\]]*)\]\s*,?\s*\)/.exec(src.slice(close + 1, close + 200));
    spans.push({
      start: m.index,
      end: close,
      body: src.slice(m.index, close),
      deps: depsMatch?.[1] ?? "",
    });
  }
  return spans;
}

/** Is `idx` inside any effect body? The two `*.current = ...` lines below must
 *  sit at RENDER scope: moved inside an effect they freeze at mount, which is
 *  the same class of bug one level removed. */
const insideAnyEffect = (spans: EffectSpan[], idx: number) =>
  spans.some((s) => idx > s.start && idx < s.end);

/** The claim's own `take:` callback is allowed to call `.focus()` - that is what
 *  it is for. Everything else in an effect body calling `.focus()` is the shape
 *  the browser overwrites, so it is stripped before the assertion. */
const withoutTakeCallback = (body: string) =>
  body
    .split("\n")
    .filter((l) => !l.includes("take:"))
    .join("\n");

const dep = (s: EffectSpan, name: string) =>
  s.deps
    .split(",")
    .map((d) => d.trim())
    .includes(name);

console.log("\n[HostsPage.tsx] the page claims the caret, it does not take it");
{
  const src = stripComments(read("src/modules/hosts/HostsPage.tsx"));
  const spans = effectSpans(src);
  const focusEffect = spans.find((s) => s.deps.trim() === "onScreen");
  check(
    "found the effect keyed on the on-screen prop",
    !!focusEffect,
    spans.map((s) => s.deps),
  );
  const body = focusEffect?.body ?? "";
  check("it goes through paneCaret.claim(", body.includes("paneCaret.claim("), body);
  check(
    "it does NOT focus the search box directly (that is the shape the browser overwrites)",
    !/\.focus\(\)/.test(withoutTakeCallback(body)),
    body,
  );
  check("and it withdraws the claim on cleanup", body.includes("paneCaret.release("), body);
  // The live read the deferred claim depends on: a ref written on every render,
  // not a value captured when the effect ran.
  const assign = /onScreenRef\.current\s*=\s*onScreen\s*;/.exec(src);
  check("`onScreenRef.current = onScreen;` exists", !!assign, null);
  check(
    "...at render scope, so the claim re-reads it a frame later",
    !!assign && !insideAnyEffect(spans, assign.index),
    null,
  );
}

console.log("\n[useTerminalSession.ts] every terminal focus path is a claim");
{
  const src = stripComments(read("src/modules/terminal/lib/useTerminalSession.ts"));
  const spans = effectSpans(src);

  const attach = spans.find((s) => s.deps.trim() === "leafId");
  check(
    "found the [leafId] attach effect",
    !!attach,
    spans.map((s) => s.deps),
  );
  const attachBody = attach?.body ?? "";
  check(
    "both attach sites (immediate + interval fallback) claim",
    (attachBody.match(/claimCaret\(\)/g) ?? []).length === 2,
    (attachBody.match(/claimCaret\(\)/g) ?? []).length,
  );
  check(
    "no bare term.focus() left in the attach effect",
    !/\.term\.focus\(\)/.test(withoutTakeCallback(attachBody)),
    null,
  );

  const visibility = spans.find((s) => dep(s, "visible") && dep(s, "focused"));
  check(
    "found the visibility/focus effect",
    !!visibility,
    spans.map((s) => s.deps),
  );
  const visBody = visibility?.body ?? "";
  check("the tab-switch path claims", visBody.includes("claimCaret()"), visBody);
  check(
    "...and does not call term.focus() itself - R11.6 is exactly that call losing to the tab chip",
    !/\.term\.focus\(\)/.test(withoutTakeCallback(visBody)),
    visBody,
  );

  check(
    "the claim's stillOnScreen reads liveFocus.current (live), not the closed-over params",
    /stillOnScreen:\s*\(\)\s*=>\s*liveFocus\.current\.visible\s*&&\s*liveFocus\.current\.focused/.test(
      src,
    ),
    null,
  );
  const assign = /liveFocus\.current\s*=\s*\{\s*visible\s*,\s*focused\s*\}\s*;/.exec(src);
  check("`liveFocus.current = { visible, focused };` exists", !!assign, null);
  check(
    "...at render scope (every render), not inside an effect (once, at mount)",
    !!assign && !insideAnyEffect(spans, assign.index),
    null,
  );
  check(
    "the pending claim is released when the leaf unmounts",
    /paneCaret\.release\(leafId\)/.test(src),
    null,
  );
}

console.log("\n[RdpPane.tsx] the RDP pane claims the caret, it does not take it (VLT-64)");
{
  const src = stripComments(read("src/modules/rdp/RdpPane.tsx"));
  const spans = effectSpans(src);

  // `dep(s, "leafId")` disambiguates from the OTHER `[visible, focused, ...]`
  // effect in this file (the one that fires `releaseAll()`), which shares two
  // of the three deps but not this one.
  const claimEffect = spans.find((s) => dep(s, "leafId") && dep(s, "visible") && dep(s, "focused"));
  check(
    "found the [leafId, visible, focused] claim effect",
    !!claimEffect,
    spans.map((s) => s.deps),
  );
  const body = claimEffect?.body ?? "";
  check("the tab-switch path claims", body.includes("paneCaret.claim("), body);
  check(
    "...and does not focus the host element directly - that is the shape the browser overwrites",
    !/\.focus\(/.test(withoutTakeCallback(body)),
    body,
  );

  check(
    "the claim's stillOnScreen reads liveFocus.current (live), not the closed-over params",
    /stillOnScreen:\s*\(\)\s*=>\s*liveFocus\.current\.visible\s*&&\s*liveFocus\.current\.focused/.test(
      src,
    ),
    null,
  );
  const assign = /liveFocus\.current\s*=\s*\{\s*visible\s*,\s*focused\s*\}\s*;/.exec(src);
  check("`liveFocus.current = { visible, focused };` exists", !!assign, null);
  check(
    "...at render scope (every render), not inside an effect (once, at mount)",
    !!assign && !insideAnyEffect(spans, assign.index),
    null,
  );
  check(
    "the pending claim is released when the leaf unmounts",
    /paneCaret\.release\(leafId\)/.test(src),
    null,
  );
}

console.log("\n[PaneTreeView.tsx] the page is only on screen when its leaf is the active one");
{
  const src = stripComments(read("src/modules/panes/PaneTreeView.tsx"));
  // R11.6's other half: without `focused` in this signal, switching to a tab
  // that splits Hosts beside a terminal would hand the caret to the page.
  check(
    "PageLeafBody gets `tabVisible && focused`",
    /onScreen=\{tabVisible\s*&&\s*focused\}/.test(src),
    null,
  );
  check("...and forwards it to HostsPage as onScreen", /onScreen=\{onScreen\}/.test(src), null);
}

console.log(failed === 0 ? "\nALL PASS" : `\n${failed} FAILED`);
process.exit(failed === 0 ? 0 : 1);
