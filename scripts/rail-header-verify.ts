/**
 * Self-check for D-UI1b: a rail view says which page it is.
 * Run: `pnpm verify rail-header`.
 *
 * Hosts named itself and Vault / Port Forwarding did not, and the asymmetry was
 * never a decision: a Hosts TAB is a page leaf, so it inherits the per-pane
 * header every leaf gets (`PaneTreeView.tsx:703`), while a rail view is
 * deliberately NOT a leaf (`RailViewArea.tsx`) and so inherited nothing. The
 * header therefore had to be written, and this pins the four things about it
 * that a later edit can quietly undo.
 *
 * Source text, for the reason `rail-views-verify.ts` gives about `App.tsx`:
 * this is JSX inside a React component, and there is no renderer in this suite
 * to mount it in. What is checkable without one is which markup EXISTS and
 * where - which is exactly what each item below is.
 *
 *  1. ONE HEADER, NOT ONE PER PAGE. It is written once in the rail-view
 *     container, above `<RailViewArea/>`, so both pages get the same bar from
 *     the same lines. The rejected shape - a bar added inside `VaultPage` and
 *     again inside `ForwardsPage` - is DCR-5's failure mode: two copies of the
 *     same chrome, kept in sync by whoever remembers. So the checks count
 *     occurrences rather than merely finding one.
 *  2. THE NAME IS SAID ONCE, IN ONE PLACE, AND COMES FROM `PAGE_LABELS`. The
 *     region is labelled with `aria-labelledby` pointing AT the heading rather
 *     than with an `aria-label` repeating the string, and the heading's text is
 *     `PAGE_LABELS[railView]` rather than a literal - `panes.ts:179` exists so
 *     the rail button, the tab strip and the page cannot drift into calling one
 *     page two things, and a literal here would be the fourth name.
 *  3. THE PANE HEADER'S TYPOGRAPHY, NONE OF ITS CONTROLS. A rail view cannot be
 *     dragged, split, floated or closed as a leaf, so a grip / close / split /
 *     float on this bar would be a control that does nothing when pressed -
 *     D-NAV1's complaint in another costume. The negatives below are what stop
 *     the next edit reaching for the pane header wholesale.
 *
 * VLT-83: every check here is a POSITIVE over a `.tsx` file, so `stripComments`
 * carries the JSX-comment branch. Without it a `{/* … *\/}` left behind by a
 * deletion satisfies the positives above - the header could be commented out
 * and this script would still report it present.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

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

/**
 * A line with its trailing `//` comment removed, string literals respected.
 *
 * The third copy of this pair in the suite (VLT-33); canonical copy lives in
 * `scripts/host-editor-verify.ts`, duplicated rather than shared because these
 * scripts have no common module. Quote-aware and a character scan rather than a
 * regex: a `//` inside a string is not a comment, and an apostrophe in unquoted
 * JSX text opens a quote state that never closes - which loses the strip for
 * that one line, i.e. fails towards KEEPING text rather than towards deleting
 * code.
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

/**
 * The same source with comments removed - the form every check below reads.
 *
 * The JSX branch is not optional here (VLT-83). `{/* … *\/}` is the only comment
 * syntax legal inside JSX children, the line filter underneath recognises none
 * of it, and every check in this file is a positive: comment the header out and
 * the positives would still match the header inside the comment. The prose in
 * `WorkspaceArea.tsx` also names `PAGE_LABELS[railView]` and `PAGE_ICONS` while
 * explaining them, which is a sentence that satisfies two of the checks below on
 * its own.
 *
 * The regex is the FIXED, non-lazy form from `host-editor-verify.ts:216`, not
 * the lazy `\{\s*\/\*[\s\S]*?\*\/\s*\}` it replaced: lazy still ALLOWS the inner
 * run to cross an intervening `*\/` while hunting for one followed by `}`, which
 * measurably ate 50KB of a file. The negative lookahead forbids that crossing,
 * so the first `*\/` found is final.
 */
function stripComments(src: string): string {
  const withoutJsxComments = src.replace(/\{\s*\/\*(?:(?!\*\/)[\s\S])*\*\/\s*\}/g, "");
  return withoutJsxComments
    .split("\n")
    .filter((line) => {
      const t = line.trim();
      return !(t.startsWith("//") || t.startsWith("/*") || t.startsWith("*"));
    })
    .map(stripLineComment)
    .join("\n");
}

/**
 * The source between two anchors, or "" if either is missing. Anchored on code
 * rather than on line numbers so an edit above does not move a region - and
 * every region is checked for having been FOUND, because a renamed anchor
 * otherwise turns every check over the empty string into a pass.
 */
function between(src: string, from: string, to: string): string {
  const start = src.indexOf(from);
  if (start < 0) return "";
  const end = src.indexOf(to, start + from.length);
  if (end < 0) return "";
  return src.slice(start, end);
}

/** How many times `needle` occurs. Counting is the whole point of section [1]:
 *  "the header exists" is satisfied by two of them. */
function countOf(src: string, needle: string): number {
  return src.split(needle).length - 1;
}

const src = stripComments(read("src/app/components/WorkspaceArea.tsx"));

// The rail-view block: the container, its header, and the page body. Bounded at
// the panel's closing tag rather than at a counted brace, so the region holds
// nothing from the PaneStack half of the file - which legitimately passes
// `onCloseLeafRequest` and would fail every negative in section [3].
const railBlock = between(src, "railView !== null && (", "</ResizablePanel>");
// Everything ABOVE the page body. Being able to cut here IS the ordering check:
// anything found in this region renders above `<RailViewArea/>`, i.e. as a
// header rather than as something floating over the page.
const header = between(railBlock, "railView !== null && (", "<RailViewArea");
// The container's own opening tag, where the region role and its label live.
// A JSX opening tag holds no `>` of its own until it ends - the attributes here
// are a class string, a role, and one brace expression.
const containerTag = between(header, "<div", ">");

console.log("[found] the rail-view container, its header and its opening tag parsed");
check("the rail-view block was located", railBlock.length > 0);
check("the header region above RailViewArea was located", header.length > 0);
check("and the container's opening tag", containerTag.length > 0, containerTag.slice(0, 80));
check(
  // Non-vacuity of the cut above: if `<RailViewArea` moved above the container
  // the header region would be a few characters of nothing and sections [2] and
  // [3] would pass by having found no markup at all.
  "the header region actually contains the header, not a sliver of the container",
  header.includes("<h2"),
  header.length,
);

// ---- 1. one header, serving both pages ----------------------------------
console.log("\n[once] the header is written once, in the container, not once per page");
check("exactly one heading in the file", countOf(src, "<h2") === 1, countOf(src, "<h2"));
const HEADER_BAR = "border-border/60 bg-card flex h-7";
check(
  // The bar's own vocabulary, taken from `PaneTreeView.tsx:707`. Two of these is
  // the DCR-5 shape arriving by copy-paste.
  //
  // The pane header's `@container` is deliberately NOT in this literal, because
  // it is deliberately not on the bar: it is there so the pane header's per-file
  // cluster can shed itself on a narrow pane (`PaneTreeView.tsx:705-706`) and
  // this bar has no `@[…]` descendant to shed. Pinning it here would have made a
  // dead class unremovable without a red check - a pin's job is to hold what is
  // load-bearing, so this one stops at the border, the card background and the
  // 28px height, and section [4] below pins the `shrink-0` beside them.
  "exactly one header bar",
  countOf(src, HEADER_BAR) === 1,
  countOf(src, HEADER_BAR),
);
check(
  "the page name is read from PAGE_LABELS exactly once",
  countOf(src, "PAGE_LABELS[railView]") === 1,
  countOf(src, "PAGE_LABELS[railView]"),
);
check("and the page body is still rendered once", countOf(src, "<RailViewArea") === 1);

// ---- 2. the name: one source, one place, said once ----------------------
console.log("\n[name] the region is labelled BY the heading, and the heading reads PAGE_LABELS");
const labelledBy = /aria-labelledby=\{([^}]*)\}/.exec(containerTag);
check("the region carries aria-labelledby", labelledBy !== null, containerTag);
check(
  // `aria-label=` with the `=` required: `aria-label` is a PREFIX of
  // `aria-labelledby`, so the bare substring matches the attribute this check
  // exists to forbid the alternative to, and the check would be unfailable.
  "and NOT an aria-label duplicating the name it already has",
  !/aria-label=/.test(containerTag),
  containerTag,
);
check("the region is still a region", /role="region"/.test(containerTag));
// The heading's own opening tag, read the same way the container's was, so the
// check does not depend on which attribute prettier decided to put first or on
// whether it wrapped the tag across lines at all.
const headingTag = between(header, "<h2", ">");
const headingId = /\bid=\{([^}]*)\}/.exec(headingTag);
check("the heading carries an id", headingId !== null, headingTag);
check(
  // The EXPRESSIONS, not a pinned string: the id is generated by `useId()` at
  // runtime, so there is no literal to compare against - and the failure this
  // guards is the two drifting apart, which two expressions show and two
  // literals could not.
  "and it is the id aria-labelledby names, not a second one",
  labelledBy !== null && headingId !== null && labelledBy[1].trim() === headingId[1].trim(),
  { labelledBy: labelledBy?.[1], headingId: headingId?.[1] },
);
check(
  // `useId`, because a module constant is unique only while exactly one
  // WorkspaceArea is mounted, and a duplicate id resolves to the FIRST element
  // carrying it - i.e. the other workspace's heading.
  "the id is generated per instance rather than being a module constant",
  /useId\(\)/.test(src) && /from "react"/.test(src),
);
const h2 = between(header, "<h2", "</h2>");
check("the heading's text is PAGE_LABELS[railView]", h2.includes("{PAGE_LABELS[railView]}"), h2);
check(
  // The other half of the same rule, and the one a mutation actually trips:
  // `PAGE_LABELS` staying in the file while the heading renders "Vault" would
  // satisfy the positive above if the positive were file-wide.
  "and not a literal page name, which would be a fourth place to rename",
  !/Vault|Port Forwarding|Hosts/.test(header),
  header,
);

// ---- 3. the pane header's typography, none of its controls --------------
console.log("\n[chrome] the header borrows the pane header's look and none of its affordances");
const iconBinding = /const (\w+) = PAGE_ICONS\[railView\];/.exec(header);
check(
  // The same glyph the rail button the user just pressed shows - `PAGE_ICONS` is
  // the single source `LeafIcon.tsx:42` documents, and three copies of a glyph
  // map is the drift it was written to end.
  "the icon comes from PAGE_ICONS[railView]",
  iconBinding !== null,
  header,
);
check(
  // Bound and RENDERED. `PAGE_ICONS` is a map of components, so a binding nobody
  // uses is a header with no glyph that still matches the check above.
  "and that binding is what the header renders",
  iconBinding !== null && header.includes(`<${iconBinding[1]}`),
  iconBinding?.[1],
);
check(
  "sized and tinted like the pane header's LeafIcon",
  /size=\{13\}/.test(header) && /text-muted-foreground\/80/.test(header),
  header,
);
check(
  "the label span's typography is the pane header's",
  /min-w-0 flex-1 truncate text-xs/.test(header) && /text-muted-foreground/.test(header),
);
for (const control of [
  "GripVertical",
  "onCloseLeafRequest",
  "onSplit",
  "floatPane",
  "onToggleMdPreview",
]) {
  check(
    `the header carries no ${control} - a rail view has nothing for it to act on`,
    !header.includes(control),
    control,
  );
}
check(
  // Spelled as three shapes rather than one, because "a close button" is a
  // behaviour and not an identifier: the X glyph, the accessible name a close
  // control has to carry, and the handler prop it would be wired to.
  "nor a close button in any of its three spellings",
  !/<X\b/.test(header) && !/aria-label="Close/.test(header) && !/onClose/.test(header),
  header,
);

// ---- 4. the box the header now shares with the page ---------------------
// The non-obvious half of the change, and the one with no visual trace until a
// list is long: the container is `absolute inset-0`, so the header eats 28px out
// of the same fixed box each page's own `min-h-0 flex-1 overflow-y-auto` scroll
// area sizes against. Both pages' roots are `flex h-full`, and `h-full` against
// a parent with no definite height is `auto` - so without the two classes below
// the page sizes to the WHOLE container and its scroll area ends up that much
// off the bottom of the card.
console.log("\n[box] the page below the header still has a definite height to scroll inside");
check(
  "the container is a column, so the header and the page divide its height",
  /flex flex-col/.test(containerTag),
  containerTag,
);
check("and it is still the absolute, bordered card it was", /absolute inset-0/.test(containerTag));
const bodyWrapper = between(railBlock, "</h2>", "<RailViewArea");
check(
  "the page body is wrapped in a min-h-0 flex-1 box of its own",
  bodyWrapper.length > 0 && /min-h-0 flex-1/.test(bodyWrapper),
  bodyWrapper,
);
check(
  // `min-h-0` without `flex-1` is a box with no height; `flex-1` without
  // `min-h-0` is a box a long list can grow past, which scrolls the whole card
  // instead of the list. Named separately so a half-removal fails by name.
  "the header itself does not grow or shrink with it",
  /h-7 shrink-0/.test(header),
  header,
);

if (failed > 0) throw new Error(`${failed} check(s) FAILED`);
console.log("\nALL PASS");
