/**
 * Comment EXTRACTION shared by the `*-verify.ts` suite.
 *
 * The inverse of `source.ts`, which is the whole reason this lives beside it
 * rather than inside a script. The three strippers there delete comments so a
 * positive check over source text cannot be satisfied by prose; this returns
 * only the comments, so a check can assert something about the prose itself.
 * Both directions turn on the same property, that a `//` inside a string is not
 * a comment, and neither direction may guess at it.
 *
 * For TypeScript the answer comes out of the parse rather than out of a
 * quote-aware walk. `parseSource` already decided where every string, template
 * part, regex literal and JSX text run begins and ends, so a scan that skips
 * exactly those spans and treats every remaining `//` or block opener as a
 * comment is exact rather than approximate. Outside a literal, `//` is always a
 * comment in JavaScript, and a `/` followed by `*` always opens one: there is no
 * prefix `*` operator, so the alternative reading of `a / *b` is not a program.
 *
 * Rust gets a hand-written scan, because nothing here parses Rust. It carries
 * the three shapes a naive quote walk gets wrong:
 *
 *   - `'a` is a lifetime, not an opening quote. Treating it as one opens a state
 *     that never closes and swallows the rest of the line, which is the same
 *     trap `stripLineComment` takes its `quotes` parameter for. A `'` here only
 *     opens a literal when a whole char literal closes it.
 *   - a raw string takes no escapes and ends only at a quote followed by the
 *     matching run of hashes, so `r#"a\"#` ends at the hash and not at the
 *     backslashed quote.
 *   - a block comment NESTS, unlike JavaScript's, so the first terminator is not
 *     necessarily the last.
 *
 * CSS gets block comments only, for the reason `stripBlockComments` exists: a
 * stylesheet's `url(http://…)` carries a `//` that is not a comment, and there
 * is no line-comment syntax in plain CSS for it to be confused with.
 *
 * `commentScannerSelfTest` is the two-direction proof, and running it is
 * mandatory for every caller for the reason `stripperSelfTest` is: an extractor
 * that silently returns nothing turns every check built on it green.
 */
import ts from "typescript";

import { parseSource } from "./ast";

export type CommentRange = {
  /** Offset of the first character of the opening delimiter. */
  readonly pos: number;
  /** Offset one past the comment's last character. */
  readonly end: number;
  /** The comment's own text, delimiters included. */
  readonly text: string;
  /**
   * The 1-based line the comment's OPENING DELIMITER sits on.
   *
   * Named for the delimiter and not `line`, because the obvious shorter name is
   * a trap and it has already been walked into. A caller reporting where
   * something it found INSIDE a multi-line comment lives must not use this: for
   * every block comment it points at the `/*` or `/**` and not at the text, so a
   * report built on it lands on comment filler. That is exactly the class of
   * defect a citation check exists to catch, so an instrument emitting it is
   * worse than none. Take the match's own offset instead, add it to `pos`, and
   * map it with {@link lineNumbersFor}.
   */
  readonly openLine: number;
};

/** Extensions `commentRangesOf` reads through the TypeScript parse. */
const TS_EXTENSIONS = [".ts", ".tsx", ".mts", ".cts", ".mjs", ".cjs", ".js"];

/**
 * Is `rel` a file `commentRangesOf` knows how to read?
 *
 * Exported so a caller walking a tree can SKIP rather than guess. An unknown
 * extension answering "no comments" would be indistinguishable from a clean
 * file, which is the failure mode this module's self-test exists to refuse.
 */
export function hasKnownCommentSyntax(rel: string): boolean {
  return rel.endsWith(".rs") || rel.endsWith(".css") || TS_EXTENSIONS.some((e) => rel.endsWith(e));
}

/**
 * Every comment in `src`, in source order, with the syntax chosen from `rel`'s
 * extension.
 *
 * Throws on an extension it does not know, rather than returning `[]`. See
 * {@link hasKnownCommentSyntax}.
 */
export function commentRangesOf(rel: string, src: string): CommentRange[] {
  if (rel.endsWith(".rs")) return rustCommentRanges(src);
  if (rel.endsWith(".css")) return cssCommentRanges(src);
  if (TS_EXTENSIONS.some((e) => rel.endsWith(e))) return tsCommentRanges(rel, src);
  throw new Error(`commentRangesOf: no comment syntax known for ${rel}`);
}

/** The offsets of every line start in `src`. */
function lineStarts(src: string): number[] {
  const starts = [0];
  for (let i = 0; i < src.length; i++) if (src[i] === "\n") starts.push(i + 1);
  return starts;
}

/** The 1-based line `pos` sits on, by binary search over `starts`. */
function lineAt(starts: number[], pos: number): number {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid] <= pos) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1;
}

/**
 * A lookup from an absolute offset in `src` to its 1-based line.
 *
 * What a caller needs to report WHERE inside a comment it found something, and
 * the reason it is exported rather than left private: the alternative on offer
 * is {@link CommentRange.openLine}, which is right only for a single-line
 * comment and silently wrong for every block one.
 *
 * A factory rather than a `lineOf(src, pos)` call, because the table costs a
 * pass over the file and a caller with many matches would otherwise pay for it
 * per match. One table per file, then a binary search each.
 *
 * Language-neutral on purpose. The TypeScript compiler offers
 * `getLineAndCharacterOfPosition`, but only for a `ts.SourceFile`, and the Rust
 * and CSS scans here have no such object; one lookup used by all four keeps a
 * single definition of what a line number means rather than two that could
 * disagree about a trailing newline or a lone carriage return.
 */
export function lineNumbersFor(src: string): (pos: number) => number {
  const starts = lineStarts(src);
  return (pos: number): number => lineAt(starts, pos);
}

/**
 * The node kinds whose text is literal content rather than code.
 *
 * The template parts are listed one by one because a template expression's
 * quoted regions are three different kinds: the head runs from the backtick to
 * the first `${`, each middle from a `}` to the next `${`, and the tail from the
 * last `}` to the closing backtick. Miss one and a `//` written inside a
 * multi-part template reads as a comment.
 */
const LITERAL_KINDS: ReadonlySet<ts.SyntaxKind> = new Set([
  ts.SyntaxKind.StringLiteral,
  ts.SyntaxKind.NoSubstitutionTemplateLiteral,
  ts.SyntaxKind.TemplateHead,
  ts.SyntaxKind.TemplateMiddle,
  ts.SyntaxKind.TemplateTail,
  ts.SyntaxKind.JsxText,
  ts.SyntaxKind.RegularExpressionLiteral,
]);

/**
 * Where every literal's text begins and ends in `sf`, sorted by start.
 *
 * `getStart` and not `pos`: a node's `pos` includes its leading trivia, so
 * `f(/* c *\/ "x")` would report the string as beginning before the comment and
 * the comment would be skipped as literal content. JSX text is the one kind
 * taken at `pos` instead, because it has no leading trivia at all and its
 * `getStart` deliberately stops AT a comment, which would move the span's start
 * past whitespace that is part of the run.
 */
function literalSpans(sf: ts.SourceFile): Array<{ from: number; to: number }> {
  const spans: Array<{ from: number; to: number }> = [];
  const visit = (n: ts.Node): void => {
    if (LITERAL_KINDS.has(n.kind)) {
      spans.push({ from: n.kind === ts.SyntaxKind.JsxText ? n.pos : n.getStart(sf), to: n.end });
      return;
    }
    ts.forEachChild(n, visit);
  };
  ts.forEachChild(sf, visit);
  return spans.sort((a, b) => a.from - b.from);
}

/** Every comment in a TypeScript, TSX or JavaScript source text. */
function tsCommentRanges(rel: string, src: string): CommentRange[] {
  const spans = literalSpans(parseSource(rel, src));
  const starts = lineStarts(src);
  const out: CommentRange[] = [];
  let s = 0;
  let i = 0;
  while (i < src.length) {
    // The spans are sorted and disjoint, so one forward cursor is enough.
    while (s < spans.length && spans[s].to <= i) s++;
    if (s < spans.length && spans[s].from <= i) {
      // `Math.max` and not a bare assignment: a zero-width or overlapping span
      // would otherwise leave the cursor where it was and spin here forever.
      i = Math.max(i + 1, spans[s].to);
      continue;
    }
    if (src[i] === "/" && src[i + 1] === "/") {
      const nl = src.indexOf("\n", i);
      const end = nl < 0 ? src.length : nl;
      out.push({ pos: i, end, text: src.slice(i, end), openLine: lineAt(starts, i) });
      i = end;
      continue;
    }
    if (src[i] === "/" && src[i + 1] === "*") {
      const close = src.indexOf("*/", i + 2);
      const end = close < 0 ? src.length : close + 2;
      out.push({ pos: i, end, text: src.slice(i, end), openLine: lineAt(starts, i) });
      i = end;
      continue;
    }
    i++;
  }
  return out;
}

/** Characters that continue an identifier, for the raw-string prefix guard. */
const IDENT = /[A-Za-z0-9_]/;

/**
 * A complete Rust char literal at the scan position, or no match.
 *
 * The escape arm is spelled out ahead of the catch-all `.` so a hex or unicode
 * escape is consumed whole; the catch-all covers `\n`, `\'`, `\\` and the rest.
 * Anything this does not match leaves the `'` as ordinary punctuation, which is
 * how a lifetime and a loop label survive the scan.
 */
const RUST_CHAR = /^'(?:\\(?:x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f]{1,6}\}|[\s\S])|[^\\'\n])'/;

/** A raw-string opener, with its hash run captured so the closer can match it. */
const RUST_RAW_OPEN = /^(?:b|c)?r(#*)"/;

/** Every comment in a Rust source text, line and (nesting) block alike. */
export function rustCommentRanges(src: string): CommentRange[] {
  const starts = lineStarts(src);
  const out: CommentRange[] = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (c === "/" && src[i + 1] === "/") {
      const nl = src.indexOf("\n", i);
      const end = nl < 0 ? src.length : nl;
      out.push({ pos: i, end, text: src.slice(i, end), openLine: lineAt(starts, i) });
      i = end;
      continue;
    }
    if (c === "/" && src[i + 1] === "*") {
      let depth = 0;
      let j = i;
      while (j < src.length) {
        if (src[j] === "/" && src[j + 1] === "*") {
          depth++;
          j += 2;
          continue;
        }
        if (src[j] === "*" && src[j + 1] === "/") {
          depth--;
          j += 2;
          if (depth === 0) break;
          continue;
        }
        j++;
      }
      out.push({ pos: i, end: j, text: src.slice(i, j), openLine: lineAt(starts, i) });
      i = j;
      continue;
    }
    // A raw string before a plain one, because `br#"` opens a raw string whose
    // interior backslashes and quotes mean nothing.
    if ((c === "r" || c === "b" || c === "c") && !IDENT.test(src[i - 1] ?? "")) {
      const open = RUST_RAW_OPEN.exec(src.slice(i));
      if (open !== null) {
        const closer = `"${open[1]}`;
        const from = i + open[0].length;
        const at = src.indexOf(closer, from);
        i = at < 0 ? src.length : at + closer.length;
        continue;
      }
    }
    if (c === '"') {
      let j = i + 1;
      while (j < src.length) {
        if (src[j] === "\\") {
          j += 2;
          continue;
        }
        if (src[j] === '"') {
          j++;
          break;
        }
        j++;
      }
      i = j;
      continue;
    }
    if (c === "'") {
      const char = RUST_CHAR.exec(src.slice(i));
      i += char === null ? 1 : char[0].length;
      continue;
    }
    i++;
  }
  return out;
}

/** Every block comment in a stylesheet, which is all the comment syntax CSS has. */
function cssCommentRanges(src: string): CommentRange[] {
  const starts = lineStarts(src);
  const out: CommentRange[] = [];
  for (let i = 0; i < src.length;) {
    if (src[i] === "/" && src[i + 1] === "*") {
      const close = src.indexOf("*/", i + 2);
      const end = close < 0 ? src.length : close + 2;
      out.push({ pos: i, end, text: src.slice(i, end), openLine: lineAt(starts, i) });
      i = end;
      continue;
    }
    i++;
  }
  return out;
}

/**
 * The probes `commentScannerSelfTest` runs, one per language.
 *
 * `NEEDLE` is the marker in every one of them, and each probe places it BOTH
 * where a comment scan must find it and where the same characters must be
 * invisible, so a single probe proves both directions at once. A scanner that
 * returned every occurrence, and one that returned none, fail different halves.
 */
const NEEDLE = "NEEDLE";

/** `.ts`: a comment, a plain string, a template part, and a regex literal. */
const TS_PROBE = [
  `// keep ${NEEDLE} one`,
  `const s = "// ${NEEDLE} not a comment";`,
  `const t = \`head // ${NEEDLE} \${s} tail // ${NEEDLE}\`;`,
  `const r = /\\/\\/ ${NEEDLE}/;`,
  `/* keep ${NEEDLE} two */`,
].join("\n");

/** `.tsx`: JSX text that looks like a comment, beside the one that is one. */
const TSX_PROBE = [
  `const a = <div>// ${NEEDLE} is text here</div>;`,
  `const b = <div>{/* keep ${NEEDLE} one */}</div>;`,
  `const c = <p title="// ${NEEDLE} not a comment">x</p>;`,
].join("\n");

/**
 * `.rs`: the lifetime, the raw string and the nested block comment.
 *
 * The lifetime line is the load-bearing one. A scanner that reads `'a` as an
 * opening quote never closes it and loses the comment at the end of that line,
 * and every comment after it in the file.
 */
const RS_PROBE = [
  `fn f<'a>(x: &'a str) -> &'a str { x } // keep ${NEEDLE} one`,
  `let s = "// ${NEEDLE} not a comment";`,
  `let r = r#"// ${NEEDLE} not a comment either \\"#;`,
  `let c = '\\'';  // keep ${NEEDLE} two`,
  `/* outer /* inner */ keep ${NEEDLE} three */`,
  `let after = 1; // keep ${NEEDLE} four`,
].join("\n");

/** `.css`: a `url()` whose `//` is not a comment. */
const CSS_PROBE = [
  `.a { background: url(http://x/${NEEDLE}.png); }`,
  `/* keep ${NEEDLE} one */`,
].join("\n");

/**
 * The assertions every caller of {@link commentRangesOf} must run, as
 * `{ label, ok }` pairs rather than as `check(...)` calls.
 *
 * Pairs and not calls for the reason `stripperSelfTest` returns them: the suite
 * has no single `check` signature, and a `check` called at this module's scope
 * would be tallied by nobody, because each script counts its own failures and
 * exits on its own count.
 *
 * Every probe is asserted in BOTH directions, by counting the marker inside the
 * extracted comments and comparing against its count in the whole text. A
 * one-directional assertion passes for an extractor that returns the file.
 */
export function commentScannerSelfTest(): Array<{ label: string; ok: boolean }> {
  const occurrences = (text: string): number => text.split(NEEDLE).length - 1;
  const commentsOf = (rel: string, src: string): string =>
    commentRangesOf(rel, src)
      .map((c) => c.text)
      .join("\n");

  /**
   * One probe, asserted in both directions at once.
   *
   * `found` names every marker that must be inside a comment, so a scanner that
   * returns nothing fails; `total` is the marker count in the whole probe text,
   * so a scanner that returns the file fails on the same line. Neither half is
   * sufficient alone, which is the property the two instruments this pattern
   * comes from were missing.
   */
  const probe = (
    label: string,
    rel: string,
    src: string,
    found: string[],
    total: number,
  ): { label: string; ok: boolean } => {
    const text = commentsOf(rel, src);
    return {
      label,
      ok:
        found.every((f) => text.includes(f)) &&
        occurrences(text) === found.length &&
        occurrences(src) === total,
    };
  };

  return [
    probe(
      "comment scan: .ts keeps 2 comment markers of 6, and hides the string, template and regex ones",
      "p.ts",
      TS_PROBE,
      [`keep ${NEEDLE} one`, `keep ${NEEDLE} two`],
      6,
    ),
    probe(
      "comment scan: .tsx reads JSX text as text and an attribute as a string, not as comments",
      "p.tsx",
      TSX_PROBE,
      [`keep ${NEEDLE} one`],
      3,
    ),
    probe(
      "comment scan: .rs survives a lifetime, a raw string and a nested block comment",
      "p.rs",
      RS_PROBE,
      [`keep ${NEEDLE} one`, `keep ${NEEDLE} two`, `keep ${NEEDLE} three`, `keep ${NEEDLE} four`],
      6,
    ),
    probe(
      "comment scan: .css leaves the // inside a url() alone",
      "p.css",
      CSS_PROBE,
      [`keep ${NEEDLE} one`],
      2,
    ),
    {
      label: "comment scan: an unknown extension throws rather than reporting no comments",
      ok: (() => {
        try {
          commentRangesOf("p.zig", `// ${NEEDLE}`);
          return false;
        } catch {
          return true;
        }
      })(),
    },
  ];
}
