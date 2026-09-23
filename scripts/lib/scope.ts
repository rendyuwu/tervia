/**
 * A brace scanner over comment-stripped source text, for the checks that ask
 * which statement list a position sits in.
 *
 * Text rather than the compiler API on purpose: the callers walk out from a
 * NEEDLE they already found by index — a field of an argument object, a call
 * inside a template — and want the enclosing block's text back so they can read
 * the guard in front of it. Going through a `ts.SourceFile` for that means
 * mapping the index to a node first, which is the step these checks exist
 * without. Everything here assumes comments are already gone; a `{` inside a
 * comment is a `{` to this scanner.
 */

/**
 * Does the `{` at `brace` open a statement list, or an object literal?
 *
 * `) {` is an `if`/`for`/`while`/function, `> {` is an arrow body, and
 * `;`/`{`/`}` mean the brace follows a statement. `(`, `,`, `:`, `=`, `[` and
 * `$` all introduce a VALUE, so the brace opens a literal and anything inside
 * it is an argument rather than a statement. The distinction is what lets a
 * check name a field of an argument object (`kind: "keyDown"`) and still be
 * told which BLOCK the call it belongs to sits in.
 */
export function opensABlock(src: string, brace: number): boolean {
  let i = brace - 1;
  while (i >= 0 && /\s/.test(src[i])) i--;
  if (i < 0) return true;
  const prev = src[i];
  if (")>;{}".includes(prev)) return true;
  const word = /(\w+)$/.exec(src.slice(0, i + 1))?.[1] ?? "";
  return word === "else" || word === "try" || word === "do" || word === "finally";
}

/**
 * Does the `}` at `brace` close a statement list?
 *
 * Its partner is found first, because right-to-left a closing brace says
 * nothing about what it closes: `focus({ ok: true });` and `if (a) { other(); }`
 * end the same way, and only one of them ends a STATEMENT. Called only at depth
 * 0, where the answer changes an outcome.
 */
export function closesABlock(src: string, brace: number): boolean {
  let depth = 0;
  for (let i = brace; i >= 0; i--) {
    if (src[i] === "}") depth++;
    else if (src[i] === "{") {
      depth--;
      if (depth === 0) return opensABlock(src, i);
    }
  }
  return false;
}

/**
 * The innermost statement list containing `at`: where its block opens (-1 at
 * module scope), and the text of the list up to `at` with nested groups elided
 * and a `;` standing where a nested BLOCK closed.
 *
 * Walking out over object-literal braces is what makes a needle inside an
 * ARGUMENT report the block its call sits in. Eliding nested groups, and
 * standing a `;` where a nested block closed, is what stops
 * `if (a) { record(); }\nsend(…)` from reading as though `send` were inside
 * that `if`.
 */
export function scopeOf(src: string, at: number): { block: number; before: string } {
  let before = "";
  let depth = 0;
  for (let i = at - 1; i >= 0; i--) {
    const c = src[i];
    if (c === "}") {
      if (depth === 0 && closesABlock(src, i)) before = ";" + before;
      depth++;
      continue;
    }
    if (c === "{") {
      if (depth > 0) {
        depth--;
        continue;
      }
      if (opensABlock(src, i)) return { block: i, before };
      continue;
    }
    if (depth === 0) before = c + before;
  }
  return { block: -1, before };
}

/**
 * The condition of the innermost `if` that controls the statement at `start`,
 * or "" when none does. A `start` of -1 (a needle `indexOf` did not find)
 * answers "" rather than throwing.
 *
 * Walks OUT through statement-list braces while the text in front of `start`
 * in each list is empty, so a write that is the second statement inside a
 * guard still reports that guard and the INNERMOST guard wins. It stops at any
 * other statement head (a `for`, an arrow declaration, a call whose argument
 * list `start` sits in) and at a `;` or a closed nested block, so a write that
 * follows a guarded statement borrows nothing.
 *
 * Walking out is only safe because every caller compares the condition it gets
 * against the exact one that has to be there: a guard from further out than
 * intended is not that string and fails. Asking merely whether SOME guard
 * exists is the unsound way to use this.
 *
 * `start` must sit at a STATEMENT (`setTest({`, not `kind: "ok"`), or the
 * statement text read back is a fragment of an argument list.
 */
export function guardAt(src: string, start: number): string {
  let at = start;
  if (at < 0) return "";
  // Bounded rather than `for (;;)`: eight levels of nesting is already more than
  // any caller's source has, and a bound cannot spin on a source it does not expect.
  for (let level = 0; level < 8; level++) {
    const { block, before } = scopeOf(src, at);
    const parts = before.split(";");
    const stmt = (parts[parts.length - 1] ?? "")
      .trim()
      // A statement may open with an operator keyword before the call a check
      // names (`void pinFingerprint(…)`), and that is still the same statement.
      // Dropped only at the END, so it cannot swallow a guard.
      .replace(/\b(?:void|await|return)$/, "")
      .trim();
    const own = /^if \((.*)\)$/s.exec(stmt);
    if (own) return own[1];
    // Some other statement head: not a guard, and not something to look past.
    if (stmt.length > 0 || block < 0) return "";
    at = block;
  }
  return "";
}

/**
 * The probes `guardAtSelfTest` runs, as `[label, source, expected]`, all with
 * `writeIt()` as the needle. They keep out two failures: a fixed lookback's
 * false PASS, which saw the previous statement's guard and called an ungated
 * write gated, and a one-hop walk's false alarm, which reported a correctly
 * guarded SECOND statement as ungated.
 */
const GUARD_PROBES: Array<[string, string, string]> = [
  ["reads a block-bodied guard", "if (a === b) {\n  writeIt();\n}\n", "a === b"],
  ["and a single-statement guard", "if (a === b) writeIt();\n", "a === b"],
  ["and a guard whose body opens with void", "if (a === b) {\n  void writeIt();\n}\n", "a === b"],
  [
    "an unguarded write does not borrow the guard of the statement above it",
    "if (a === b) other();\nwriteIt();\n",
    "",
  ],
  ["not even when that write opens with void", "if (a === b) other();\nvoid writeIt();\n", ""],
  [
    "a write that IS the second statement inside a guard still reports it",
    "if (a === b) {\n  other();\n  void writeIt();\n}\n",
    "a === b",
  ],
  [
    "one AFTER that guard's block closes does not",
    "if (a === b) {\n  other();\n}\nwriteIt();\n",
    "",
  ],
  [
    "nor one inside a block the guard does not control",
    "if (a === b) {\n  other();\n}\nfor (const x of xs) {\n  writeIt();\n}\n",
    "",
  ],
  [
    "the INNERMOST guard is reported, not the outermost",
    "if (a) {\n  if (b === c) {\n    writeIt();\n  }\n}\n",
    "b === c",
  ],
  ["an unguarded write in a bare block reports nothing", "{\n  writeIt();\n}\n", ""],
  ["a missing needle reports nothing rather than throwing", "x();\n", ""],
];

/**
 * The assertions every caller of {@link guardAt} must run, as `{ label, ok }`
 * pairs that each script feeds to its own `check`/`assert`, for the same reason
 * as `stripperSelfTest`: the suite has no single `check` signature, and a check
 * at library scope would be counted by nobody.
 */
export function guardAtSelfTest(): Array<{ label: string; ok: boolean }> {
  return GUARD_PROBES.map(([label, src, want]) => ({
    label: `guardAt self-test: ${label}`,
    ok: guardAt(src, src.indexOf("writeIt()")) === want,
  }));
}
