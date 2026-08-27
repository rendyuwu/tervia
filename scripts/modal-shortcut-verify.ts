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

/**
 * A line with its trailing `//` comment removed, string literals respected.
 *
 * VLT-33; canonical copy in `scripts/host-editor-verify.ts`, duplicated here on
 * purpose (no shared module between these scripts, and no `scripts/lib`). A
 * character scan rather than a regex: a `//` inside a string is not a comment,
 * and a regex alternation over string literals desyncs on the first unbalanced
 * quote and then eats real code. This loses the strip for that one line -
 * failing towards KEEPING text.
 */
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

/**
 * Every source-text check in this file is POSITIVE - "this expression is
 * present" - which is exactly the shape a comment satisfies (VLT-33). This file
 * read raw text until now, so `return openModal(modalName);` deleted and left
 * behind as `// return openModal(modalName);` would have passed every wiring
 * check below.
 *
 * The coverage and bypass scans further down read through the same stripper on
 * purpose: a commented-out `createPortal` or `<Dialog>` is not a modal, and
 * reporting one as an uncovered bypass is a false finding somebody then has to
 * chase.
 */
const read = (p: string) => stripComments(readFileSync(join(root, p), "utf8"));

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
const { openModal, isModalOpen, isTopModal, COMMAND_PALETTE_MODAL, __resetModalRegistryForTest } =
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

console.log("[behavioural] which modal is on TOP (VLT-59: the palette exemption)");
{
  __resetModalRegistryForTest();
  check(
    // Nothing open is NOT an exemption: the gate asks isModalOpen() first, and
    // this must not answer "yes, the palette" to a stack with nothing in it.
    "with nothing open, no name is on top",
    !isTopModal(COMMAND_PALETTE_MODAL),
  );

  // The repro, in the order the user performs it: the host editor is up, then
  // Mod+Shift+P. The palette is not open, so it is not on top, so the chord is
  // gated - which is the whole fix. Keyed by chord identity this returned
  // "exempt" and the palette opened over the editor.
  const releaseEditor = openModal();
  check(
    "host editor open -> the palette is not the topmost modal",
    !isTopModal(COMMAND_PALETTE_MODAL),
  );
  check("and something IS open, so the gate applies", isModalOpen());

  // THE NEGATIVE HALF (§4.30): the case the exemption exists for must still
  // work, or this is just the suppression with extra steps.
  releaseEditor();
  const releasePalette = openModal(COMMAND_PALETTE_MODAL);
  check(
    "palette alone -> it IS topmost, so its own chord still closes it",
    isTopModal(COMMAND_PALETTE_MODAL),
  );

  // A confirm stacked OVER the palette: the palette is still open, but it is no
  // longer what the user is looking at, so the chord must not reach past the
  // thing on top of it. "Open" and "topmost" are different questions and this
  // is the fixture where they disagree.
  const releaseConfirm = openModal();
  check("a dialog stacked over it -> no longer topmost", !isTopModal(COMMAND_PALETTE_MODAL));
  releaseConfirm();
  check("that dialog closing gives the palette the top back", isTopModal(COMMAND_PALETTE_MODAL));

  // Out-of-order close: a modal BELOW the top going away first (a form
  // force-unmounted while its confirm is up) must remove its own entry, not pop
  // whatever happens to be last.
  const releaseUnder = openModal("under");
  const releaseOver = openModal("over");
  releaseUnder();
  check("closing a modal below the top leaves the top alone", isTopModal("over"));
  releaseOver();
  check("and the palette is back on top once both are gone", isTopModal(COMMAND_PALETTE_MODAL));
  releasePalette();
  check("everything released -> closed", isModalOpen() === false);
  check("and nothing is on top", !isTopModal(COMMAND_PALETTE_MODAL));
}

// ============================================================================
// SOURCE-TEXT - the wiring the behavioural test above can't reach
// ============================================================================
console.log("[source-text] useGlobalShortcuts gates on isModalOpen() before dispatch");
const useGlobalShortcuts = read("src/modules/shortcuts/lib/useGlobalShortcuts.ts");
check(
  "imports isModalOpen and isTopModal from the registry",
  /import\s*\{[^}]*\bisModalOpen\b[^}]*\}\s*from\s*"\.\/modalRegistry"/.test(useGlobalShortcuts) &&
    /import\s*\{[^}]*\bisTopModal\b[^}]*\}\s*from\s*"\.\/modalRegistry"/.test(useGlobalShortcuts),
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
  // The gate now asks the modal STACK, not the chord's identity: `isModalOpen()`
  // decides whether it applies at all, and the exempt chord gets through only
  // while the modal it names is the topmost one. A gate that still reads
  // `MODAL_GATE_EXEMPT.has(...)` is VLT-59(b) back again, so the shape is
  // pinned rather than merely "isModalOpen appears somewhere".
  const gateMatch =
    /if\s*\(\s*isModalOpen\(\)\s*&&\s*\(\s*mayActOn === undefined\s*\|\|\s*!isTopModal\(mayActOn\)\s*\)\s*\)\s*return\s*;/.exec(
      onKeyBody,
    );
  const handlerCallIdx = onKeyBody.indexOf("h(e);");
  check("onKey checks isMatch before deciding anything else", continueIdx !== -1);
  check(
    "onKey gates on isModalOpen() plus the matched chord's topmost target",
    gateMatch !== null,
    { onKeyBody: onKeyBody.slice(0, 160) },
  );
  check(
    // The straight revert of the fix: exempting by membership means exempting
    // the chord wherever it is pressed, which is what opened the palette over
    // the host editor.
    "the gate does NOT exempt by chord identity alone",
    !/MODAL_GATE_EXEMPT\.has\(/.test(onKeyBody),
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
  // Pinned deliberately, not a restatement: the whole safety argument is that
  // this map stays a single pure-toggle id pointing at its OWN dialog (see the
  // comment above it in useGlobalShortcuts.ts). A silent addition here IS the
  // "hole" that comment warns against, so growing it - even by one id - must
  // show up as a reddened check, not slip through as an unreviewed one-line
  // diff. The VALUE is checked too: an entry naming some other modal would
  // exempt the chord over a dialog it does not own, which is the same defect
  // with a different spelling.
  const exemptMatch = useGlobalShortcuts.match(
    /MODAL_GATE_EXEMPT:\s*ReadonlyMap<ShortcutId,\s*string>\s*=\s*new Map\(\[([\s\S]*?)\]\)/,
  );
  check("found the MODAL_GATE_EXEMPT declaration, as a Map of id -> modal", exemptMatch !== null);
  const entries = [
    ...(exemptMatch?.[1] ?? "").matchAll(/\[\s*"([^"]+)"\s*,\s*([A-Za-z_$][\w$]*)/g),
  ];
  check(
    "it holds exactly one entry, commandPalette.open",
    entries.length === 1 && entries[0][1] === "commandPalette.open",
    entries.map((m) => m[1]),
  );
  check(
    "and it names the palette's own modal, by the shared constant",
    entries.length === 1 && entries[0][2] === "COMMAND_PALETTE_MODAL",
    entries.map((m) => m[2]),
  );
}

console.log("[source-text] the palette registers under the name the gate asks for");
{
  // The two ends of the name. A gate that asks about "commandPalette" while the
  // dialog registers anonymously is a gate that suppresses the palette's own
  // toggle again - and it would fail silently, since Escape still closes it.
  const dialog = read("src/components/ui/dialog.tsx");
  check(
    "Dialog takes a modalName and passes it to openModal",
    /modalName\?:\s*string/.test(dialog) && /openModal\(modalName\)/.test(dialog),
  );
  check(
    // Radix has no such prop; forwarding it would put an unknown attribute on
    // the DOM node.
    "and destructures it out rather than spreading it into Radix",
    /function Dialog\(\{[\s\S]*?modalName,[\s\S]*?\.\.\.props/.test(dialog),
  );
  const palette = read("src/modules/commandPalette/CommandPalette.tsx");
  check(
    "the palette passes modalName={COMMAND_PALETTE_MODAL}",
    /modalName=\{COMMAND_PALETTE_MODAL\}/.test(palette),
  );
  check(
    "imported from the shortcuts module, not spelled out again",
    /COMMAND_PALETTE_MODAL[\s\S]*?from "@\/modules\/shortcuts"/.test(palette),
  );
  const registry = read("src/modules/shortcuts/lib/modalRegistry.ts");
  check(
    // A pop would drop the wrong entry when a modal below the top closes first.
    "the registry removes an entry by identity, not by popping",
    /stack\.splice\(at, 1\)/.test(registry) && !/stack\.pop\(\)/.test(registry),
  );
}

console.log("[source-text] the two primitives register on open, release on close/unmount");
// `Dialog` alone can be handed a name to register under (VLT-59), so it calls
// `openModal(modalName)` and carries that in its dep array. Spelled out per
// primitive rather than as one loose pattern: a check that accepted "any
// argument, any deps" would stop noticing the mechanism it is here to pin.
for (const [file, comp, arg, deps] of [
  ["src/components/ui/dialog.tsx", "Dialog", "modalName", "open, modalName"],
  ["src/components/ui/alert-dialog.tsx", "AlertDialog", "", "open"],
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
    const registerAt = call.search(new RegExp(`return\\s+openModal\\(${arg}\\)\\s*;`));
    check(`${comp}: the effect guards on !open before registering`, guardAt !== -1);
    check(`${comp}: the effect returns openModal(${arg}) as its cleanup`, registerAt !== -1);
    check(
      `${comp}: the guard runs BEFORE the registration, not after`,
      guardAt !== -1 && registerAt !== -1 && guardAt < registerAt,
    );
    // Trailing comma optional: this repo's Prettier config is
    // `trailingComma: "all"`, so a hard-wrapped call gets one after the last
    // argument - a real reflow this check must not mistake for a change in
    // the deps array itself.
    const depsRe = new RegExp(
      `,\\s*\\[\\s*${deps.replace(/,\s*/g, ",\\s*")}\\s*\\]\\s*,?\\s*\\)\\s*$`,
    );
    check(`${comp}: keyed on exactly [${deps}]`, depsRe.test(call), { call: call.slice(-80) });
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
const ROLE_DIALOG_TELL = /(?:^|[^[])role=["']dialog["']/;
{
  // The tell, self-tested against both directions before it is trusted on real
  // files. Narrowing it to exclude a bracketed selector is only safe if it
  // still catches the thing it is for; a tell that has been quietly relaxed
  // into never matching reports "no bypass found" forever.
  console.log("[coverage] the hand-rolled-modal tell, against its own fixtures");
  check('fires on a JSX role="dialog" attribute', ROLE_DIALOG_TELL.test('  <div role="dialog">'));
  check(
    "fires on one at the very start of the text too",
    ROLE_DIALOG_TELL.test('role="dialog" className="x"'),
  );
  check(
    "does NOT fire on a CSS attribute selector asking about someone else's dialog",
    !ROLE_DIALOG_TELL.test('const S = \'[role="menu"],[role="dialog"]\';'),
  );
  check("nor on an alertdialog selector", !ROLE_DIALOG_TELL.test("'[role=\"alertdialog\"]'"));
}
const bypassCandidates: string[] = [];
for (const f of srcFiles) {
  const rel = relative(root, f);
  if (rel.startsWith("src/components/ui/")) continue; // the primitives themselves
  const text = read(rel);
  // A JSX attribute, not a CSS attribute SELECTOR. `'[role="dialog"]'` inside a
  // query string is code asking about somebody else's dialog, which is the
  // opposite of hand-rolling one - and the bare substring reported every such
  // selector as a bypass. The `[` is what tells them apart; see the fixtures
  // above.
  if (ROLE_DIALOG_TELL.test(text)) bypassCandidates.push(`${rel}: role="dialog"`);
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
