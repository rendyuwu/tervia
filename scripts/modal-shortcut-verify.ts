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
  // The gate must be an early `return` that runs BEFORE the SHORTCUTS loop -
  // a call to isModalOpen() that doesn't early-return (e.g. only logged, or
  // checked after a shortcut already ran) would not suppress anything.
  const onKeyMatch = useGlobalShortcuts.match(
    /const onKey = \(e: KeyboardEvent\) => \{([\s\S]*?)\n {4}\};/,
  );
  check("found the onKey handler body", onKeyMatch !== null);
  const onKeyBody = onKeyMatch?.[1] ?? "";
  const gateIdx = onKeyBody.search(/if\s*\(\s*isModalOpen\(\)\s*\)\s*return\s*;/);
  const loopIdx = onKeyBody.indexOf("for (const s of SHORTCUTS)");
  check("onKey has an `if (isModalOpen()) return;` gate", gateIdx !== -1, {
    onKeyBody: onKeyBody.slice(0, 80),
  });
  check(
    "the gate runs BEFORE the SHORTCUTS loop, not after",
    gateIdx !== -1 && loopIdx !== -1 && gateIdx < loopIdx,
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
  const effectMatch = text.match(
    /React\.useEffect\(\(\) => \{\s*if \(!open\) return;\s*return openModal\(\);\s*\}, \[open\]\);/,
  );
  check(`${comp}: useEffect([open]) registers and returns the release as cleanup`, !!effectMatch);
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
check(
  "at least one real consumer of each primitive exists",
  dialogConsumers.length > 0 && alertDialogConsumers.length > 0,
);

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
