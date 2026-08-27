/**
 * Self-check for VLT-47: the jump-host / RDP-tunnel / desktop-size picker's
 * wheel fix uses `stopPropagation()`, not an unconditional `scrollTop +=`
 * write.
 * Run: `pnpm verify hosts-combobox-wheel` (or `npx tsx
 * scripts/hosts-combobox-wheel-verify.ts` to iterate).
 *
 * SOURCE-TEXT: there is no DOM/layout engine in this repo's check suite (see
 * `hosts-header-narrow-verify.ts`), and this bug was never reproducible from
 * a render anyway - it needs an actual native `wheel` event colliding with
 * `react-remove-scroll`'s document-level listener, which nothing in this
 * suite can dispatch. What CAN be checked from the source is the property
 * the fix depends on staying true: `Combobox.tsx`'s `<CommandList>` reaches
 * for `e.stopPropagation()`, not `e.currentTarget.scrollTop += e.deltaY`.
 *
 * Why the second form specifically must never come back (see the comment on
 * this element in `Combobox.tsx` for the full derivation): an unconditional
 * `scrollTop += deltaY` is correct only INSIDE a modal `Dialog`, where the
 * lock's own `preventDefault()` suppresses the browser's native scroll and
 * the imperative write is the only one that lands. `Combobox` is shared by
 * three pickers today and is the documented reuse target for 6e's vault
 * entry picker - the moment ANY caller mounts this component with no modal
 * Dialog above it, an unconditional `scrollTop +=` write runs ALONGSIDE the
 * browser's now-unsuppressed native scroll, and the list scrolls twice per
 * wheel notch. `stopPropagation()` has no such failure mode: with no
 * `RemoveScroll` mounted there is no document listener to stop propagation
 * to, so it is a no-op and native scroll runs once, exactly as expected.
 * This file is what stops that regression from being silently reintroduced.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (p: string) => readFileSync(join(root, p), "utf8");

let failed = 0;
function check(label: string, cond: boolean): void {
  if (cond) console.log(`  ok: ${label}`);
  else {
    console.error(`  FAIL: ${label}`);
    failed++;
  }
}

const src = read("src/modules/hosts/editor/Combobox.tsx");

/** Prose is not code. This file's own comment on the fix TALKS ABOUT the
 *  rejected `scrollTop +=` form by name (to explain why it was replaced),
 *  which would trip a naive `!/scrollTop/` check on the raw source - same
 *  trap `scrollbar-consistency-verify.ts` strips comments for, and for the
 *  same reason: a mention is not a use. */
const stripComments = (text: string) =>
  text.replace(/\/\/.*$/gm, "").replace(/\/\*[\s\S]*?\*\//g, "");

const code = stripComments(src);

// Anchored on the `<CommandList` opening tag through its closing `>`, so the
// extracted block is exactly this element's props - not the whole file, which
// would let an unrelated `scrollTop` or `stopPropagation` elsewhere in the
// component satisfy these checks for the wrong reason.
const commandListMatch = /<CommandList\b[\s\S]*?\n\s*>/.exec(code);
check("anchor found: <CommandList ...> opening tag (comments stripped)", commandListMatch !== null);
const commandListProps = commandListMatch?.[0] ?? "";

check(
  "CommandList's onWheel calls e.stopPropagation()",
  /onWheel=\{\(e\) => \{\s*e\.stopPropagation\(\);\s*\}\}/.test(commandListProps),
);
check(
  "CommandList's onWheel does NOT write scrollTop (the double-scroll-outside-a-modal trap)",
  !/scrollTop/.test(commandListProps),
);
// Belt and suspenders: even outside the anchored block, the pattern that
// caused the double-scroll risk must not exist anywhere in this file's CODE
// (comments already stripped) - a second, redundant handler added elsewhere
// would reintroduce the same bug.
check("no scrollTop write anywhere in Combobox.tsx's code", !/\.scrollTop\s*\+=/.test(code));

console.log(
  failed === 0 ? "\nAll hosts-combobox-wheel checks passed." : `\n${failed} check(s) FAILED.`,
);
process.exit(failed === 0 ? 0 : 1);
