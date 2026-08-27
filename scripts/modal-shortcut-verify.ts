/**
 * Self-check for VLT-30: global shortcuts must not fire through an open
 * Dialog/AlertDialog (repro: Ctrl+W closed the tab out from under the open
 * host editor and silently discarded the in-progress edit).
 *
 * Run: `npx tsx scripts/modal-shortcut-verify.ts` (registered as
 * `*-verify.ts`, so `pnpm verify` picks it up automatically).
 *
 * Two kinds of check, deliberately kept apart:
 *
 *   BEHAVIOURAL - imports the real `modalRegistry.ts` and drives its actual
 *   `openModal`/`isModalOpen` functions through open/close, nesting, and
 *   double-release. This is real code under test, not a description of it.
 *
 *   SOURCE-TEXT - the registry counting logic can be exercised in isolation,
 *   but the WIRING that makes it matter (the early-return gate in
 *   useGlobalShortcuts' keydown listener, and the two primitives calling
 *   `openModal()`) lives inside a React effect / DOM keydown handler. This
 *   repo has no jsdom or React test renderer (checked: neither is a
 *   dependency), and adding one is out of scope for a single check. So the
 *   wiring is verified by reading the source for the specific lines that
 *   must exist. This is a weaker guarantee than a real keydown-through-a-
 *   mounted-dialog test, and is called out as such rather than dressed up as
 *   behavioural - a source check that only re-states the code it's reading
 *   is worthless, so each pattern below is anchored to the exact mechanism
 *   (an early `return` before the SHORTCUTS loop; a `useEffect` gated on
 *   `open` that calls `openModal()`), not just "the string exists somewhere".
 *
 * Also enumerates every Dialog/AlertDialog consumer under src/ and re-checks
 * for any hand-rolled modal (fixed full-screen overlay, `role="dialog"`,
 * `createPortal`) that bypasses both shared primitives - that gap is exactly
 * how a previous suppression fix left dialogs uncovered.
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, relative } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (p: string) => readFileSync(join(root, p), "utf8");

let failed = 0;
function check(name: string, ok: boolean, detail?: unknown): void {
  if (ok) {
    console.log(`  ok: ${name}`);
    return;
  }
  console.error(`  FAIL: ${name}`, detail === undefined ? "" : JSON.stringify(detail));
  failed++;
}

/** Index of the `)` matching the `(` at `openIdx`, or -1. Counts nesting so a
 *  paren inside the call's own arguments (an arrow function, a condition)
 *  doesn't end the scan early. */
function matchingParen(src: string, openIdx: number): number {
  let depth = 0;
  for (let i = openIdx; i < src.length; i++) {
    if (src[i] === "(") depth++;
    else if (src[i] === ")") {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

/**
 * Attribute text of every JSX opening tag named exactly `tagName` - e.g.
 * `Dialog` matches `<Dialog ...>` but not `<DialogTrigger ...>` or
 * `<DialogContent ...>`, via the lookahead that refuses a following
 * identifier character. Captured from just past the tag name up to the
 * tag's OWN closing `>`, found by counting `{`/`}` so a `>` inside an
 * attribute expression - `onOpenChange={(open) => { ... }}` has one in its
 * arrow - is never mistaken for the end of the tag. Neither primitive here
 * is ever used self-closing (both always wrap children), so that form isn't
 * handled.
 */
function jsxOpenTagAttrs(src: string, tagName: string): string[] {
  const out: string[] = [];
  const nameRe = new RegExp(`<${tagName}(?![A-Za-z0-9])`, "g");
  let m: RegExpExecArray | null;
  while ((m = nameRe.exec(src))) {
    const attrsStart = m.index + m[0].length;
    let depth = 0;
    let end = -1;
    for (let i = attrsStart; i < src.length; i++) {
      const c = src[i];
      if (c === "{") depth++;
      else if (c === "}") depth--;
      else if (depth === 0 && c === ">") {
        end = i;
        break;
      }
    }
    if (end !== -1) out.push(src.slice(attrsStart, end));
  }
  return out;
}

function walk(dir: string, match: RegExp, out: string[] = []): string[] {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return out;
  }
  for (const name of entries) {
    if (name === "node_modules" || name === ".git" || name === "dist") continue;
    const full = join(dir, name);
    if (statSync(full).isDirectory()) walk(full, match, out);
    else if (match.test(name)) out.push(full);
  }
  return out;
}

// ============================================================================
// BEHAVIOURAL - the registry itself
// ============================================================================
console.log("[behavioural] modalRegistry counting");
const { openModal, isModalOpen, __resetModalRegistryForTest } =
  await import("../src/modules/shortcuts/lib/modalRegistry");

__resetModalRegistryForTest();
check("starts closed", isModalOpen() === false);

{
  const release = openModal();
  check("one open -> open", isModalOpen() === true);
  release();
  check("released -> closed", isModalOpen() === false);
}

console.log("[behavioural] nesting: a COUNT, not a boolean (§ VLT-30 req 4)");
{
  const releaseOuter = openModal();
  const releaseInner = openModal();
  check("two open -> open", isModalOpen() === true);
  releaseInner();
  check(
    "inner closes first -> STILL open (outer must not be un-suppressed)",
    isModalOpen() === true,
  );
  releaseOuter();
  check("outer closes -> closed", isModalOpen() === false);
}

console.log("[behavioural] idempotent release: leak-safety building block");
{
  const release = openModal();
  release();
  release(); // second call must be a no-op, not an extra decrement
  const releaseAgain = openModal();
  check("count did not go negative from the double-release", isModalOpen() === true);
  releaseAgain();
  check("clean after", isModalOpen() === false);
}

// ============================================================================
// SOURCE-TEXT - the wiring the behavioural test above can't reach
// ============================================================================
console.log("[source-text] useGlobalShortcuts gates on isModalOpen() before dispatch");
const useGlobalShortcuts = read("src/modules/shortcuts/lib/useGlobalShortcuts.ts");
check(
  "imports isModalOpen from the registry",
  /import\s*\{\s*isModalOpen\s*\}\s*from\s*"\.\/modalRegistry"/.test(useGlobalShortcuts),
);
{
  // Item 1 (palette toggle chord): the gate is scoped to the MATCHED
  // shortcut rather than a blanket pre-loop return, because it now needs to
  // know WHICH id matched before it can decide whether the one documented
  // exemption (MODAL_GATE_EXEMPT) applies. So the gate must sit AFTER
  // "no match, continue" and BEFORE the handler runs - a gate that runs
  // before a match is known, or after the handler already fired, would not
  // suppress anything for a non-exempt id.
  const onKeyMatch = useGlobalShortcuts.match(
    /const onKey = \(e: KeyboardEvent\) => \{([\s\S]*?)\n {4}\};/,
  );
  check("found the onKey handler body", onKeyMatch !== null);
  const onKeyBody = onKeyMatch?.[1] ?? "";
  const continueIdx = onKeyBody.indexOf("if (!isMatch) continue;");
  const gateMatch =
    /if\s*\(\s*isModalOpen\(\)\s*&&\s*!MODAL_GATE_EXEMPT\.has\(s\.id\)\s*\)\s*return\s*;/.exec(
      onKeyBody,
    );
  const handlerCallIdx = onKeyBody.indexOf("h(e);");
  check("onKey checks isMatch before deciding anything else", continueIdx !== -1);
  check(
    "onKey has an `if (isModalOpen() && !MODAL_GATE_EXEMPT.has(s.id)) return;` gate",
    gateMatch !== null,
    { onKeyBody: onKeyBody.slice(0, 160) },
  );
  check(
    "the gate runs AFTER the match is known and BEFORE the handler fires",
    continueIdx !== -1 &&
      gateMatch !== null &&
      handlerCallIdx !== -1 &&
      continueIdx < gateMatch.index &&
      gateMatch.index < handlerCallIdx,
  );
}

console.log("[source-text] MODAL_GATE_EXEMPT holds exactly the one documented exception");
{
  // Pinned deliberately, not a restatement: item 1's whole safety argument is
  // that this set stays a single pure-toggle id (see the comment above it in
  // useGlobalShortcuts.ts). A silent addition here IS the "hole" that
  // comment warns against, so growing the set - even by one id - must show
  // up as a reddened check here, not slip through as an unreviewed one-line
  // diff.
  const exemptMatch = useGlobalShortcuts.match(
    /MODAL_GATE_EXEMPT:\s*ReadonlySet<ShortcutId>\s*=\s*new Set\(\[([^\]]*)\]\)/,
  );
  check("found the MODAL_GATE_EXEMPT declaration", exemptMatch !== null);
  const exemptIds = (exemptMatch?.[1] ?? "")
    .split(",")
    .map((s) => s.trim().replace(/^["']|["']$/g, ""))
    .filter(Boolean);
  check(
    "it holds exactly one id, commandPalette.open, and nothing else",
    exemptIds.length === 1 && exemptIds[0] === "commandPalette.open",
    exemptIds,
  );
}

console.log("[source-text] the two primitives register on open, release on close/unmount");
for (const [file, comp] of [
  ["src/components/ui/dialog.tsx", "Dialog"],
  ["src/components/ui/alert-dialog.tsx", "AlertDialog"],
] as const) {
  const text = read(file);
  check(`${comp}: imports openModal`, /import\s*\{\s*openModal\s*\}/.test(text));
  // Must be a useEffect keyed on `open` that RETURNS the release (so React
  // runs it as the cleanup on close AND on unmount - the leak-safety path).
  //
  // Anchored on the mechanism (a `React.useEffect(` call, paren-balanced so
  // its own internals can't fool the scan) rather than on exact source text:
  // the previous version of this check pinned whitespace byte-for-byte,
  // which meant a Prettier reflow of this file would redden it for no
  // behavioural reason at all - the opposite failure mode from a vacuous
  // check, but still not what a check should cost.
  const callIdx = text.indexOf("React.useEffect(");
  check(`${comp}: has a React.useEffect(...) call`, callIdx !== -1);
  if (callIdx !== -1) {
    const openParenIdx = callIdx + "React.useEffect".length;
    const closeParenIdx = matchingParen(text, openParenIdx);
    check(`${comp}: the useEffect(...) call's parens balance`, closeParenIdx !== -1);
    const call = closeParenIdx !== -1 ? text.slice(openParenIdx, closeParenIdx + 1) : "";
    const guardAt = call.search(/if\s*\(\s*!open\s*\)\s*return\s*;/);
    const registerAt = call.search(/return\s+openModal\(\)\s*;/);
    check(`${comp}: the effect guards on !open before registering`, guardAt !== -1);
    check(`${comp}: the effect returns openModal() as its cleanup`, registerAt !== -1);
    check(
      `${comp}: the guard runs BEFORE the registration, not after`,
      guardAt !== -1 && registerAt !== -1 && guardAt < registerAt,
    );
    // Trailing comma optional: this repo's Prettier config is
    // `trailingComma: "all"`, so a hard-wrapped call gets one after the last
    // argument - a real reflow this check must not mistake for a change in
    // the deps array itself.
    check(`${comp}: keyed on exactly [open]`, /,\s*\[\s*open\s*\]\s*,?\s*\)\s*$/.test(call));
  }
}

// ============================================================================
// COVERAGE - every dialog/modal under src/ goes through one of the two
// primitives, or is called out here as NOT COVERED
// ============================================================================
console.log("[coverage] every Dialog/AlertDialog consumer, and no bypass");
const srcFiles = walk(join(root, "src"), /\.tsx?$/);

const dialogConsumers = srcFiles.filter(
  (f) =>
    !f.endsWith("components/ui/dialog.tsx") &&
    /from ["']@\/components\/ui\/dialog["']/.test(read(relative(root, f))),
);
const alertDialogConsumers = srcFiles.filter(
  (f) =>
    !f.endsWith("components/ui/alert-dialog.tsx") &&
    /from ["']@\/components\/ui\/alert-dialog["']/.test(read(relative(root, f))),
);
console.log(
  `  Dialog consumers (${dialogConsumers.length}):`,
  dialogConsumers.map((f) => relative(root, f)).join(", "),
);
console.log(
  `  AlertDialog consumers (${alertDialogConsumers.length}):`,
  alertDialogConsumers.map((f) => relative(root, f)).join(", "),
);
// Anchor for the loop below, not a claim about coverage on its own - a repo
// with zero consumers would make that loop vacuously pass, so this has to
// hold first. (It is realistically never the thing that catches a
// regression: see the real coverage check right after it.)
check(
  "found at least one real consumer of each primitive to check",
  dialogConsumers.length > 0 && alertDialogConsumers.length > 0,
);

// The gap the checks above leave: importing `Dialog`/`AlertDialog` says
// nothing about whether the JSX actually controls `open`. A dialog built as
// `<Dialog><DialogTrigger>...</DialogTrigger><DialogContent>...</DialogContent></Dialog>`
// - open only via the Trigger's own internal state, no `open` prop at all -
// imports the primitive, renders it, and would pass every check above while
// being exactly the shape VLT-30's registration effect does not cover (see
// the "future fully-uncontrolled dialog" line in both primitives' own
// comments). So: every root tag must show SOME form of control - a literal
// `open=` attribute, the direct form every consumer but one uses, or a
// `{...spread}` that plausibly threads it through (how `CommandDialog` in
// command.tsx passes its own `open` prop into `Dialog`). The spread form is
// trusted rather than traced into the spreading component's own prop list -
// this file does no JSX/prop-flow analysis - so it is weaker than the direct
// form, but it still catches the one thing this check exists for: a root tag
// with NEITHER, which is exactly what a Trigger-only dialog leaves behind.
console.log("[coverage] every Dialog/AlertDialog root passes a controlled `open`");
for (const [consumers, tagName] of [
  [dialogConsumers, "Dialog"],
  [alertDialogConsumers, "AlertDialog"],
] as const) {
  for (const f of consumers) {
    const rel = relative(root, f);
    const tags = jsxOpenTagAttrs(read(rel), tagName);
    check(`${rel}: renders a <${tagName}> root tag`, tags.length > 0, { found: tags.length });
    const controlled = tags.some((t) => /\bopen\s*=/.test(t) || /\{\s*\.\.\./.test(t));
    check(
      `${rel}: at least one <${tagName}> root is controlled (open= or {...spread})`,
      controlled,
      {
        tags,
      },
    );
  }
}

// Bypass detection: a hand-rolled modal wouldn't import either primitive, so
// scan for the tell-tale patterns of one instead - a full-viewport fixed
// overlay, an explicit ARIA dialog role, or a manual portal - outside the ui/
// primitives themselves. Any hit is a NOT COVERED finding to report, not to
// silently fix here.
const bypassCandidates: string[] = [];
for (const f of srcFiles) {
  const rel = relative(root, f);
  if (rel.startsWith("src/components/ui/")) continue; // the primitives themselves
  const text = read(rel);
  if (/role=["']dialog["']/.test(text)) bypassCandidates.push(`${rel}: role="dialog"`);
  if (/createPortal/.test(text)) bypassCandidates.push(`${rel}: createPortal`);
  if (/fixed inset-0/.test(text)) bypassCandidates.push(`${rel}: "fixed inset-0"`);
}
check(
  "no hand-rolled modal bypassing Dialog/AlertDialog found under src/",
  bypassCandidates.length === 0,
  bypassCandidates,
);

console.log(failed === 0 ? "\nALL PASS" : `\n${failed} FAILED`);
process.exit(failed === 0 ? 0 : 1);
