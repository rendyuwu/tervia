/**
 * Self-check for VLT-39: the async terminal attach must not focus a pane on
 * MOUNT-TIME visibility/focus, only on the LATEST render's.
 * Run: `npx tsx scripts/terminal-focus-attach-verify.ts`.
 *
 * The bug: `useTerminalSession`'s attach effect is keyed on `[leafId]`, so
 * everything it closes over is frozen at mount - but `tryAttach` can land
 * seconds later (it waits on the container ref, then polls). A leaf that was
 * `visible: true, focused: true` at mount and has since been switched away
 * from would still steal focus back when it finally attached, because the
 * effect's own `visible`/`focused` closure never saw the switch. The fix
 * (`liveFocus`, a ref updated every render) makes both attach sites read the
 * LATEST values instead of the mount-time ones.
 *
 * The regression this bug reintroduces is not a runtime value that can be
 * asserted against - it is a RACE against real font-loading and real
 * `requestAnimationFrame` timing, which this repo has no way to force
 * deterministically (no jsdom/fake timers harness - same gap
 * modal-shortcut-verify.ts's wiring section already lives with). What IS a
 * fixed, checkable property is the shape of the fix itself: does the attach
 * code read `liveFocus.current` (a ref, mutated on every render, so it is
 * never stale) instead of the closed-over `visible`/`focused` parameters (frozen
 * at mount by the `[leafId]` dep array)? So, honestly, THIS is source text,
 * not execution - weaker than a real DOM/timing test, but it pins the exact
 * property that broke and reddens on both the straightforward revert and the
 * most likely "fix that looks right" (moving the ref's own update inside the
 * effect, which would refreeze it at mount just like before).
 *
 * `src/modules/terminal/lib/useTerminalSession.ts` is owned by another agent
 * this round - read here, never written.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

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

/** Comment-stripped, quote-aware - same convention as host-editor-verify.ts /
 *  rdp-lifetime-verify.ts / ssh-exit-verify.ts, so a docblock describing the
 *  bug in prose (this file's own header does, at length) can never be
 *  mistaken for the code being checked. */
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

type EffectSpan = { start: number; end: number; deps: string };

/** Every `useEffect(() => {...}, [...])` / `useLayoutEffect(...)` span in
 *  `src`, found by brace-matching so a nested callback's own braces (a
 *  `setInterval`, a `.then()`) can't end the scan early. */
function effectSpans(src: string): EffectSpan[] {
  const spans: EffectSpan[] = [];
  const re = /use(?:Layout)?Effect\(\(\)\s*=>\s*\{/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(src))) {
    const openBrace = src.indexOf("{", m.index);
    const close = matchingBrace(src, openBrace);
    if (close === -1) continue;
    const depsMatch = /^\s*,\s*\[([^\]]*)\]\s*,?\s*\)/.exec(src.slice(close + 1, close + 200));
    spans.push({ start: m.index, end: close, deps: depsMatch?.[1] ?? "" });
  }
  return spans;
}

/**
 * The property under test, run against arbitrary (real or synthetic) source
 * text: does the `[leafId]`-only effect's body read `liveFocus.current` at
 * both attach sites and never the bare closed-over form, and does the ref's
 * own update sit outside every effect (render scope)?
 */
function checkFocusOnAttach(rawSrc: string) {
  const src = stripComments(rawSrc);
  const spans = effectSpans(src);
  const leafIdEffect = spans.find((s) => s.deps.trim() === "leafId");

  const guardRe = /if\s*\(\s*liveFocus\.current\.visible\s*&&\s*liveFocus\.current\.focused\s*\)/g;
  const bareRe = /if\s*\(\s*visible\s*&&\s*focused\s*\)/g;
  const body = leafIdEffect ? src.slice(leafIdEffect.start, leafIdEffect.end) : "";
  const guardMatches = leafIdEffect ? [...body.matchAll(guardRe)] : [];
  const bareMatches = leafIdEffect ? [...body.matchAll(bareRe)] : [];

  const assignRe = /liveFocus\.current\s*=\s*\{\s*visible\s*,\s*focused\s*\}\s*;/;
  const assignMatch = assignRe.exec(src);
  const assignInsideEffect = assignMatch
    ? spans.some((s) => assignMatch.index > s.start && assignMatch.index < s.end)
    : null;

  return {
    foundLeafIdEffect: !!leafIdEffect,
    guardCount: guardMatches.length,
    bareCount: bareMatches.length,
    foundAssign: !!assignMatch,
    assignAtRenderScope: assignMatch ? !assignInsideEffect : null,
  };
}

// ============================================================================
// SELF-TEST: prove the extraction above actually distinguishes the fixed
// shape from the bug, on synthetic fixtures - before trusting it against the
// real (unmodifiable-by-this-agent) file. Handoff §5.17/§5.18: a check that
// only re-states the code it reads is worthless, so this is the "watch it
// redden" step, done on fixtures because the real file can't be mutated.
// ============================================================================
console.log("[self-test] the extraction distinguishes fixed / reverted / half-fixed shapes");

const FIXED_FIXTURE = `
export function useTerminalSession({ leafId, visible, focused = true }: Options) {
  const liveFocus = useRef({ visible, focused });
  liveFocus.current = { visible, focused };

  useEffect(() => {
    const tryAttach = (framesLeft: number) => {
      if (container.current) {
        attachSession(leafId, container.current, callbacks);
        if (liveFocus.current.visible && liveFocus.current.focused) s.term.focus();
        return;
      }
      attachIntervalId = setInterval(() => {
        attachSession(leafId, container.current, callbacks);
        if (liveFocus.current.visible && liveFocus.current.focused) s.term.focus();
      }, 250);
    };
  }, [leafId]);

  useLayoutEffect(() => {
    if (focused) s.term.focus();
  }, [leafId, visible, focused]);
}
`;

const REVERTED_FIXTURE = FIXED_FIXTURE.replaceAll(
  "if (liveFocus.current.visible && liveFocus.current.focused) s.term.focus();",
  "if (visible && focused) s.term.focus();",
).replace(
  "const liveFocus = useRef({ visible, focused });\n  liveFocus.current = { visible, focused };\n\n",
  "",
);

const REFROZEN_FIXTURE = FIXED_FIXTURE.replace(
  "const liveFocus = useRef({ visible, focused });\n  liveFocus.current = { visible, focused };\n\n  useEffect(() => {",
  "const liveFocus = useRef({ visible, focused });\n\n  useEffect(() => {\n    liveFocus.current = { visible, focused };",
);

{
  const r = checkFocusOnAttach(FIXED_FIXTURE);
  check("fixture[fixed]: finds the [leafId] effect", r.foundLeafIdEffect, r);
  check("fixture[fixed]: both attach sites read liveFocus.current", r.guardCount === 2, r);
  check("fixture[fixed]: the bare frozen form is absent", r.bareCount === 0, r);
  check(
    "fixture[fixed]: the assignment is found, at render scope",
    r.assignAtRenderScope === true,
    r,
  );
}
{
  // Straight revert: back to reading the closed-over params directly.
  const r = checkFocusOnAttach(REVERTED_FIXTURE);
  check(
    "fixture[reverted]: no longer finds liveFocus.current at either site (reddens)",
    r.guardCount === 0,
    r,
  );
  check("fixture[reverted]: the bare frozen form is present (reddens)", r.bareCount === 2, r);
}
{
  // The likely "fix that looks right": ref exists and is read correctly at
  // both attach sites, but its OWN update moved inside the [leafId] effect -
  // which reintroduces the freeze this bug is about, one level removed.
  const r = checkFocusOnAttach(REFROZEN_FIXTURE);
  check(
    "fixture[refrozen]: attach sites still look right (would false-pass a shallower check)",
    r.guardCount === 2,
    r,
  );
  check(
    "fixture[refrozen]: but the assignment is now INSIDE the effect (reddens)",
    r.assignAtRenderScope === false,
    r,
  );
}

// ============================================================================
// THE PIN: run the same extraction against the real file.
// ============================================================================
console.log("\n[useTerminalSession.ts] the async attach reads live, not mount-time, focus state");
{
  const r = checkFocusOnAttach(read("src/modules/terminal/lib/useTerminalSession.ts"));
  check("found the [leafId] attach effect", r.foundLeafIdEffect, r);
  check(
    "both attach sites (immediate + interval-fallback) read liveFocus.current.visible && .focused",
    r.guardCount === 2,
    r,
  );
  check(
    "the bare, mount-frozen `if (visible && focused)` form does not appear in that effect",
    r.bareCount === 0,
    r,
  );
  check("found `liveFocus.current = { visible, focused };`", r.foundAssign, r);
  check(
    "...and it sits at RENDER scope (every render), not inside the [leafId] effect (once, at mount)",
    r.assignAtRenderScope === true,
    r,
  );
}

console.log(failed === 0 ? "\nALL PASS" : `\n${failed} FAILED`);
process.exit(failed === 0 ? 0 : 1);
