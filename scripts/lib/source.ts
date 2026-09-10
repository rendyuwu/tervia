/**
 * Source-text helpers shared by the `*-verify.ts` suite.
 *
 * Nothing in `scripts/lib/` runs as a check: `verify-all.mjs` globs `scripts/`
 * non-recursively for `*-verify.ts`, so this directory is typechecked and
 * formatted but never executed on its own. That is deliberate — a helper with
 * no caller is a `noUnusedLocals` failure in the importer, not a silently
 * passing script here.
 *
 * There are three strippers rather than one, because the scripts do not all
 * want the same thing and collapsing them would have quietly changed what four
 * of them check:
 *
 *   `stripComments`       whole-line, trailing AND JSX-expression comments.
 *                         The form every POSITIVE check over a `.tsx` needs.
 *   `stripCommentsNoJsx`  the same minus the JSX branch, for callers whose
 *                         input is `.ts` or Rust, where a brace wrapping a
 *                         block comment is an object literal or a type literal
 *                         and deleting it would eat real code.
 *   `stripBlockComments`  block comments only, for CSS, where the quote-aware
 *                         `//` scan would truncate at the `//` in a `url()`.
 */

/**
 * `line` with any `//` comment removed, respecting string and template quoting.
 *
 * A naive `line.split("//")[0]` truncates at the `//` inside a URL or inside a
 * quoted `"a // b"`, which silently shortens the very region a check is about
 * to search. This walks the line instead, skipping escaped characters inside an
 * open quote, so only a `//` at top level ends the code. A line with an
 * unclosed quote loses its strip entirely, which fails towards KEEPING text —
 * the safe direction, because the failure this exists to prevent is a positive
 * check going green off a `// was: <deleted code>`.
 *
 * `quotes` is the set of characters that open a string. It is a parameter for
 * the Rust callers: Rust's `'a` lifetime is not a quote, and treating it as one
 * opens a state that never closes and swallows the rest of the line.
 */
export function stripLineComment(line: string, quotes = "\"'`"): string {
  let quote = "";
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote) {
      if (c === "\\") i++;
      else if (c === quote) quote = "";
      continue;
    }
    if (quotes.includes(c)) {
      quote = c;
      continue;
    }
    if (c === "/" && line[i + 1] === "/") return line.slice(0, i);
  }
  return line;
}

/**
 * The same source with whole-line and trailing comments removed, and nothing
 * else.
 *
 * Every check that searches source text for a literal runs on a stripped copy
 * rather than on the raw file: the prose in a script's own docblock names the
 * calls it checks for by their literal text, so a positive search over raw
 * source can be satisfied by a comment alone. Deleting a guarded call and
 * leaving a trailing `// was: ...` behind it must fail, and stripping first is
 * what makes it fail.
 *
 * Use this one only when the input cannot be JSX. See `stripComments`.
 */
export function stripCommentsNoJsx(src: string, quotes = "\"'`"): string {
  return src
    .split("\n")
    .filter((line) => {
      const t = line.trim();
      return !(t.startsWith("//") || t.startsWith("/*") || t.startsWith("*"));
    })
    .map((line) => stripLineComment(line, quotes))
    .join("\n");
}

/**
 * `stripCommentsNoJsx` plus the one comment syntax that is legal INSIDE JSX
 * children: a brace wrapping a block comment.
 *
 * A bare `//` there renders as literal text, so the line filter never had a
 * reason to know about it, and it does not match a line starting `{` either.
 * Required by every positive check over a `.tsx` file: a deleted guarded call
 * left behind inside one of those would otherwise pass every one of them.
 *
 * The inner group must NOT be allowed to cross a comment terminator while
 * hunting for one followed by `}` — a lazy `[\s\S]*?` is still permitted to do
 * that, and a type literal opening with a doc comment then swallows
 * everything up to some later, unrelated terminator. The negative lookahead
 * forbids it: the first terminator is final, either a real JSX comment
 * expression or the match fails right there. `stripperSelfTest` is the
 * two-direction proof of exactly that, and the reason it is mandatory for any
 * caller of this function.
 */
export function stripComments(src: string): string {
  return stripCommentsNoJsx(src.replace(/\{\s*\/\*(?:(?!\*\/)[\s\S])*\*\/\s*\}/g, ""));
}

/**
 * `text` with block comments removed and line comments left alone.
 *
 * For CSS, and for the one caller that scans stylesheets alongside components:
 * a stylesheet's `url(http://…)` contains a `//` that is not a comment, and
 * `stripLineComment` would truncate the declaration at it — which for a scan
 * looking for forbidden properties hides an offender rather than revealing one.
 * Block comments are the only comment syntax plain CSS has.
 */
export function stripBlockComments(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, "");
}

/**
 * The probe `stripperSelfTest` runs `stripComments` over.
 *
 * Both halves matter. `KEEP` sits on its own line after a type literal whose
 * doc comment the stripper must not swallow — that is the case the lazy version
 * of the JSX regex got wrong, pairing that comment's terminator with the JSX
 * comment's `}` two lines later and deleting everything between. The last line
 * carries the JSX comment expression the line filter cannot see.
 */
const STRIPPER_PROBE =
  "type P = { /** c */ x: X };\nconst KEEP = 1;\nconst j = <div>{/* c */}</div>;";

/**
 * The two assertions every caller of `stripComments` must run, as
 * `{ label, ok }` pairs rather than as `check(...)` calls.
 *
 * The suite has no single `check` signature — the scripts spell it
 * `(label, cond)`, `(label, got, want)`, `(name, ok, detail?)` and `(cond, msg)`
 * — and a `check` called at this module's scope would be counted by nobody,
 * because each script tallies its own failures and exits on its own count. So
 * this returns the verdicts and each caller feeds them to its own `check`,
 * which keeps one definition of the probe data while leaving the `ok:` lines in
 * the scripts where they are read.
 */
export function stripperSelfTest(): Array<{ label: string; ok: boolean }> {
  const probe = stripComments(STRIPPER_PROBE);
  return [
    { label: "stripComments self-test: KEEP survives", ok: probe.includes("KEEP") },
    {
      label: "stripComments self-test: the JSX comment {/* c */} does not survive",
      ok: !probe.includes("{/*"),
    },
  ];
}
