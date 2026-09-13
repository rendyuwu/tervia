/**
 * A brace scanner over comment-stripped source text, for the checks that ask
 * which statement list a position sits in.
 *
 * Text rather than the compiler API on purpose: the callers walk out from a
 * NEEDLE they already found by index — a field of an argument object, a call
 * inside a template — and want the enclosing block's text back so they can read
 * the guard in front of it. Going through a `ts.SourceFile` for that means
 * mapping the index to a node first, which is the step these two checks exist
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
