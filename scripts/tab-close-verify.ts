/**
 * Self-check for the close rule: WHICH leaves and tabs may be closed.
 * Run: `npx tsx scripts/tab-close-verify.ts`.
 *
 * The bug this pins down (VLT-43) is not "Hosts is unclosable" - it is that the
 * three close paths disagreed about it. The tab-strip X was gated on the entry
 * COUNT (`totalEntries > 1`), so with a terminal open beside it the X appeared on
 * Hosts and closed it. The pane-header X routed a single-pane tab through
 * `closeTab`, which only ever refused the LAST tab, so it closed Hosts too.
 * `closePaneByLeaf` refused only the last entry. Nothing anywhere knew that a
 * page leaf is permanent.
 *
 * So the checks below are about a single predicate answering for every path, and
 * about the third case in particular: a predicate hardwired to `false` satisfies
 * "Hosts is refused" and "the last entry is refused" while breaking the app
 * completely, so "an ordinary leaf beside another entry IS closable" is what
 * makes the other two mean anything.
 *
 * The claim was re-checked against RDP panes and needed a fifth section
 * (VLT-62). `closable.ts` was fine - it asks only whether the leaf is a page and
 * whether it is the last entry, so it has always answered for an `rdp` leaf
 * exactly as for a `terminal` one, and both X buttons closed an RDP tab
 * happily. What disagreed was `Ctrl+Shift+X`, which carried its OWN kind test
 * in `app/lib/shortcutHandlers.ts` in FRONT of the arbiter and silently dropped
 * the chord for anything that was not a terminal. So "one predicate, all three
 * paths agree" needed both halves checking: the predicate treats RDP like any
 * other session leaf ([iv]), and no path re-decides in front of it ([v]).
 *
 * Sections [vi] and [vii] are the SECOND question a close has to answer - not
 * "may this happen" but "may it happen silently" - which was still in the state
 * the first one was in before VLT-43: one copy per path, and the copies
 * disagreed. `requestCloseLeaf` confirmed only on a busy terminal, so a dirty
 * editor was discarded without a word by three of the five affordances that
 * funnel through it, while `handleClose` prompted for the same file. Every
 * fixture in this suite was clean (`editorLeaf` hardcoded `dirty: false`), so
 * nothing here could see it.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  canCloseLeaf,
  canCloseTab,
  leafCloseConfirmReason,
  leafCloseRefusal,
  tabCloseConfirmReason,
  tabCloseRefusal,
} from "../src/modules/tabs/lib/closable";
import { buildEntries, countTabEntries } from "../src/modules/tabs/lib/entries";
import type { Tab } from "../src/modules/tabs/lib/tabTypes";
import type { PaneNode } from "../src/modules/terminal/lib/panes";

/**
 * A line with its trailing `//` comment removed, string literals respected.
 *
 * VLT-33, and this is the fourth copy of this pair in the suite - duplicated
 * on purpose, because these scripts share no module and `scripts/lib` is not a
 * thing we want. The canonical copy is in `scripts/host-editor-verify.ts`; keep
 * them the same shape.
 *
 * A character scan rather than a regex, because a `//` inside a string is not a
 * comment and a regex alternation desyncs on the first unbalanced quote. An
 * apostrophe in unquoted JSX text opens a quote state that never closes, which
 * loses the strip for that one line - it fails towards KEEPING text, never
 * towards deleting code, which is the direction that matters: a positive check
 * must never be satisfied by a comment, and must never be reddened by prose it
 * accidentally ate.
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

// VLT-83: no JSX-comment branch here, deliberately. Every file this stripper
// runs over is a `.ts` module - `shortcutHandlers.ts`, `shortcuts.ts`,
// `useTabActions.ts` - and a `{/* ... */}` is only meaningful inside JSX
// children, so a `.ts` source can never contain one that would hide code from
// a positive check the way it did in `host-editor-verify.ts` (fixed at
// `host-editor-verify.ts:191` - copy the branch from there, and not the lazy
// form `\{\s*\/\*[\s\S]*?\*\/\s*\}`, which is not a substitute: it can still
// cross an intervening `*/` while hunting for one followed by `}`) and
// `vault-editor-verify.ts:101`. If this file is ever pointed at a `.tsx`
// file, that branch has to be added first.
/** The same source with whole-line and trailing comments removed. */
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

let failed = 0;
function check(name: string, ok: boolean, detail?: unknown): void {
  if (ok) {
    console.log(`  ok: ${name}`);
    return;
  }
  console.error(`  FAIL: ${name}`, detail === undefined ? "" : JSON.stringify(detail));
  failed++;
}

// ---- fixtures -------------------------------------------------------------
// Ids are hand-assigned and unique across every tab in a case, exactly as the
// live allocator guarantees.

function hostsLeaf(id: number): PaneNode {
  return { kind: "leaf", id, leafKind: "page", page: "hosts" };
}
function termLeaf(id: number, cwd = "/w"): PaneNode {
  return { kind: "leaf", id, leafKind: "terminal", cwd };
}
// `dirty` is a PARAMETER, not the hardcoded `false` it was. Every fixture here
// was clean, so the whole suite ran past the one input the confirmation rule
// turns on - see [vi].
function editorLeaf(id: number, path = "/w/a.ts", dirty = false): PaneNode {
  return { kind: "leaf", id, leafKind: "editor", path, dirty, preview: false };
}
function rdpLeaf(id: number, rdpConnectionId = "conn-1"): PaneNode {
  return { kind: "leaf", id, leafKind: "rdp", rdpConnectionId, sizeMode: "preset" };
}
function split(id: number, children: PaneNode[]): PaneNode {
  return { kind: "split", id, dir: "row", children };
}
function tab(id: number, paneTree: PaneNode, activeLeafId: number): Tab {
  return { id, kind: "pane", title: "t", paneTree, activeLeafId };
}

const HOSTS_ONLY: Tab[] = [tab(1, hostsLeaf(2), 2)];
const HOSTS_AND_TERMINAL: Tab[] = [tab(1, hostsLeaf(2), 2), tab(3, termLeaf(4), 4)];
const TERMINAL_ONLY: Tab[] = [tab(3, termLeaf(4), 4)];
const HOSTS_SPLIT_WITH_TERMINAL: Tab[] = [tab(1, split(5, [hostsLeaf(2), termLeaf(6)]), 2)];
const THREE_TABS: Tab[] = [
  tab(1, hostsLeaf(2), 2),
  tab(3, termLeaf(4), 4),
  tab(7, editorLeaf(8), 8),
];
// One tab, two panes: `countTabEntries` is 2 here but `tabs.length` is 1 - the
// one fixture that can tell `tabCloseRefusal`'s "last entry" gate apart from
// `leafCloseRefusal`'s. See [ii-tab] below.
const ONE_TAB_TWO_PANES: Tab[] = [tab(1, split(5, [termLeaf(2), termLeaf(6)]), 2)];
// The VLT-62 shape: Hosts plus an RDP tab, which is what the hand test had open
// when Ctrl+Shift+X did nothing and both X buttons worked.
const HOSTS_AND_RDP: Tab[] = [tab(1, hostsLeaf(2), 2), tab(3, rdpLeaf(4), 4)];
const RDP_ONLY: Tab[] = [tab(3, rdpLeaf(4), 4)];
const RDP_SPLIT_WITH_TERMINAL: Tab[] = [tab(3, split(5, [rdpLeaf(4), termLeaf(6)]), 4)];
// The [vi] shapes. Hosts sits beside each one so the close is LEGAL and the
// only question left is whether it happens silently.
const HOSTS_AND_DIRTY_EDITOR: Tab[] = [
  tab(1, hostsLeaf(2), 2),
  tab(3, editorLeaf(4, "/w/a.ts", true), 4),
];
const HOSTS_AND_CLEAN_EDITOR: Tab[] = [tab(1, hostsLeaf(2), 2), tab(3, editorLeaf(4), 4)];
// A split whose unsaved editor is NOT the active leaf. `syncPaneMirror` copies
// `dirty` from the active leaf alone, so this is the shape a tab-level answer
// read off `tab.dirty` gets wrong.
const SPLIT_DIRTY_EDITOR_BEHIND: Tab[] = [
  tab(1, hostsLeaf(2), 2),
  tab(3, split(5, [termLeaf(6), editorLeaf(7, "/w/b.ts", true)]), 6),
];

// ---- (i) a Hosts page leaf is never closable ------------------------------
console.log("[i] a page leaf is permanent, on every path and in every arrangement");
check(
  "alone in the workspace: refused",
  leafCloseRefusal(HOSTS_ONLY, 2) === "permanent-page",
  leafCloseRefusal(HOSTS_ONLY, 2),
);
check(
  // The exact regression: two entries exist, so the old count-based gate
  // rendered the strip X and `closeTab` allowed it.
  "beside a terminal tab: still refused, and for being a page rather than for being last",
  leafCloseRefusal(HOSTS_AND_TERMINAL, 2) === "permanent-page",
  leafCloseRefusal(HOSTS_AND_TERMINAL, 2),
);
check(
  "sharing a split with a terminal: still refused",
  leafCloseRefusal(HOSTS_SPLIT_WITH_TERMINAL, 2) === "permanent-page",
  leafCloseRefusal(HOSTS_SPLIT_WITH_TERMINAL, 2),
);
check(
  "with two other tabs open: still refused",
  leafCloseRefusal(THREE_TABS, 2) === "permanent-page",
  leafCloseRefusal(THREE_TABS, 2),
);
check(
  // `Ctrl+W` on a single-pane Hosts tab, and the pane-header X on the last pane
  // in its tab, both ask the TAB question. Refusing the leaf but allowing the
  // tab is exactly how the pane header used to close Hosts.
  "the whole Hosts TAB is refused too, even with other tabs open",
  tabCloseRefusal(HOSTS_AND_TERMINAL, 1) === "permanent-page",
  tabCloseRefusal(HOSTS_AND_TERMINAL, 1),
);
check("and the Hosts tab of a three-tab workspace is refused", !canCloseTab(THREE_TABS, 1));
check(
  "a tab that merely CONTAINS a page leaf is refused, split or not",
  tabCloseRefusal(HOSTS_SPLIT_WITH_TERMINAL, 1) === "permanent-page",
  tabCloseRefusal(HOSTS_SPLIT_WITH_TERMINAL, 1),
);

// ---- (ii) the last entry is not closable ---------------------------------
console.log("\n[ii] the last thing on screen is permanent, whatever it is");
check(
  "a lone terminal is refused, so the window cannot be emptied",
  leafCloseRefusal(TERMINAL_ONLY, 4) === "last-entry",
  leafCloseRefusal(TERMINAL_ONLY, 4),
);
check("countTabEntries agrees it is the only entry", countTabEntries(TERMINAL_ONLY) === 1);
check(
  // `closeTab`'s historical guard, restated at the tab level.
  "and closing that lone tab is refused",
  tabCloseRefusal(TERMINAL_ONLY, 3) === "last-entry",
  tabCloseRefusal(TERMINAL_ONLY, 3),
);
check(
  "an id no tab holds is refused rather than reported closable",
  leafCloseRefusal(TERMINAL_ONLY, 999) === "unknown-leaf",
  leafCloseRefusal(TERMINAL_ONLY, 999),
);
check(
  // Tightened to match the leaf-level equivalent two checks up: `!== null`
  // also accepts "last-entry" or "permanent-page", which an implementation
  // that checks the tab COUNT before even looking up the id would satisfy
  // just as well - it would refuse for the wrong reason and this would not
  // notice.
  "a tab id no workspace holds likewise",
  tabCloseRefusal(TERMINAL_ONLY, 999) === "unknown-leaf",
  tabCloseRefusal(TERMINAL_ONLY, 999),
);

// ---- (ii-tab) the last TAB is permanent, regardless of how many panes it
// holds -----------------------------------------------------------------
// The case `tabCloseRefusal`'s two candidate gates - `tabs.length <= 1` (the
// real one: is this the only TAB) and `countTabEntries(tabs) <= 1` (wrong:
// counts panes, not tabs) - disagree on. `ONE_TAB_TWO_PANES` has
// `tabs.length === 1` but `countTabEntries` of 2, so only the real gate
// refuses it. Get this backwards and `closeTab` would filter the workspace's
// only tab out from under itself, leaving `tabs = []` for whatever reads
// `.id` off the (now empty) array next - see `useTabs.ts:396` and VLT-43.
console.log("\n[ii-tab] the only tab is refused even though it holds two panes, not one");
check(
  "closing the workspace's one tab is refused as last-entry, not allowed for holding 2 panes",
  tabCloseRefusal(ONE_TAB_TWO_PANES, 1) === "last-entry",
  tabCloseRefusal(ONE_TAB_TWO_PANES, 1),
);
check("canCloseTab agrees", !canCloseTab(ONE_TAB_TWO_PANES, 1));

// ---- (iii) an ordinary leaf beside another entry IS closable --------------
// Without this the two checks above pass for a predicate that refuses
// everything, which would leave the app with no way to close anything at all.
console.log("\n[iii] and an ordinary leaf beside another entry IS closable");
check(
  "the terminal tab next to Hosts closes",
  leafCloseRefusal(HOSTS_AND_TERMINAL, 4) === null,
  leafCloseRefusal(HOSTS_AND_TERMINAL, 4),
);
check("canCloseLeaf agrees", canCloseLeaf(HOSTS_AND_TERMINAL, 4));
check(
  "so does closing that whole tab",
  tabCloseRefusal(HOSTS_AND_TERMINAL, 3) === null,
  tabCloseRefusal(HOSTS_AND_TERMINAL, 3),
);
check(
  "a terminal sharing a split with Hosts closes - the split is not a shield",
  canCloseLeaf(HOSTS_SPLIT_WITH_TERMINAL, 6),
);
check("an editor leaf among three tabs closes", canCloseLeaf(THREE_TABS, 8));
check("and so does its tab", canCloseTab(THREE_TABS, 7));
check(
  // Two panes in one tab: dropping one leaves the other, so it is not the last
  // entry even though the TAB count is 1. Same fixture the [ii-tab] block
  // above uses to pin the opposite question - the TAB itself is still
  // refused even though a PANE within it is fine to close.
  "one of two panes in the only tab closes",
  canCloseLeaf(ONE_TAB_TWO_PANES, 2),
);

// ---- the strip asks the same question -----------------------------------
// The tab strip builds its close-X set by running this predicate over the very
// entries `buildEntries` produces, so the two cannot drift. What is worth
// pinning is that the entry list and the predicate agree about which leaf is
// which - a page entry is the one refused, and it is not the only entry there.
console.log("\n[strip] every entry the strip renders resolves through the same predicate");
{
  const entries = buildEntries(THREE_TABS, new Map());
  const closable = entries.filter(
    (e) => e.kind === "pane-leaf" && canCloseLeaf(THREE_TABS, e.leafId),
  );
  const refused = entries.filter(
    (e) => e.kind === "pane-leaf" && !canCloseLeaf(THREE_TABS, e.leafId),
  );
  check("three entries, one per leaf", entries.length === 3, entries.length);
  check("two of them get an X", closable.length === 2, closable.length);
  check(
    "the one refused is the page entry",
    refused.length === 1 && refused[0].kind === "pane-leaf" && refused[0].leafKind === "page",
    refused.map((e) => (e.kind === "pane-leaf" ? e.leafKind : e.kind)),
  );
}
{
  // The single-tab case the old gate got right by accident: no X anywhere.
  const entries = buildEntries(HOSTS_ONLY, new Map());
  check(
    "a Hosts-only workspace renders no close X at all",
    entries.every((e) => e.kind !== "pane-leaf" || !canCloseLeaf(HOSTS_ONLY, e.leafId)),
  );
}

// ---- (iv) an RDP leaf is a session leaf like any other -------------------
// VLT-62. Checked as its own section rather than assumed from "terminal works",
// because the whole item was somebody assuming exactly that: `closable.ts`
// never names a leaf kind except `page`, so RDP was always fine here - and the
// chord that quoted it as the single arbiter was refusing what it allows.
console.log("\n[iv] an RDP pane closes on the same predicate a terminal does");
check(
  "an RDP tab beside Hosts closes",
  leafCloseRefusal(HOSTS_AND_RDP, 4) === null,
  leafCloseRefusal(HOSTS_AND_RDP, 4),
);
check("and so does the whole RDP tab", tabCloseRefusal(HOSTS_AND_RDP, 3) === null);
check(
  // Same answer a lone terminal gets: the rule is about the workspace being
  // emptied, not about what kind of session is in the way.
  "a lone RDP pane is refused as the last entry, not for being RDP",
  leafCloseRefusal(RDP_ONLY, 4) === "last-entry",
  leafCloseRefusal(RDP_ONLY, 4),
);
check(
  "an RDP pane sharing a split with a terminal closes",
  canCloseLeaf(RDP_SPLIT_WITH_TERMINAL, 4),
);
check("and the terminal beside it closes too", canCloseLeaf(RDP_SPLIT_WITH_TERMINAL, 6));
{
  // The strip's own answer, through `buildEntries` - the affordance half of
  // "all three paths agree". Both entries get an X, which is what the hand test
  // saw and the chord did not match.
  const entries = buildEntries(HOSTS_AND_RDP, new Map());
  const refused = entries.filter(
    (e) => e.kind === "pane-leaf" && !canCloseLeaf(HOSTS_AND_RDP, e.leafId),
  );
  check(
    "the strip refuses only the page entry, not the RDP one",
    refused.length === 1 && refused[0].kind === "pane-leaf" && refused[0].leafKind === "page",
    refused.map((e) => (e.kind === "pane-leaf" ? e.leafKind : e.kind)),
  );
}

// ---- (v) and no close path re-decides in front of the arbiter ------------
// Source-text, because `shortcutHandlers.ts` imports through the `@/` alias and
// this suite has no bundler to resolve it. The behavioural checks above cannot
// see a caller that stops asking - which is exactly the defect: every fixture in
// [iv] passed for the whole life of VLT-62.
console.log("\n[v] Ctrl+Shift+X and Ctrl+W ask the arbiter rather than a leaf kind");
{
  const root = join(dirname(fileURLToPath(import.meta.url)), "..");
  // Comments stripped first (VLT-33): every assertion below is POSITIVE - "this
  // expression is present" - and a positive check is exactly the kind a comment
  // satisfies. Deleting the guard and leaving `// if (coveredByRailView())
  // return;` behind must fail, and stripping is what makes it fail.
  const src = stripComments(readFileSync(join(root, "src/app/lib/shortcutHandlers.ts"), "utf8"));
  /** The body of the `"<id>": () => { ... }` handler, or null. */
  const handlerBody = (id: string): string | null => {
    const at = src.indexOf(`"${id}": `);
    if (at === -1) return null;
    const open = src.indexOf("{", at);
    if (open === -1) return null;
    let depth = 0;
    for (let i = open; i < src.length; i++) {
      if (src[i] === "{") depth++;
      else if (src[i] === "}") {
        depth--;
        if (depth === 0) return src.slice(open, i + 1);
      }
    }
    return null;
  };
  const close = handlerBody("terminal.close");
  check("found the terminal.close handler", close !== null);
  check(
    // The exact line that dropped the chord for RDP.
    "it no longer gates on the active leaf KIND",
    close !== null && !/activeLeafKindCurrent/.test(close),
    close,
  );
  check(
    "it routes the close through requestCloseLeaf, the funnel that asks canCloseLeaf",
    close !== null && /requestCloseLeaf\(activeLeafIdInTab\)/.test(close),
  );
  check(
    // The one guard it keeps, and the only one: no focused leaf, nothing to
    // close. Not a refusal - a missing argument.
    "and keeps only the no-focused-leaf guard",
    close !== null && /activeLeafIdInTab === null/.test(close),
  );
  const tabClose = handlerBody("tab.close");
  check("found the tab.close handler", tabClose !== null);
  check(
    "it routes through handleCloseTabOrPane, which asks canCloseTab / canCloseLeaf",
    tabClose !== null && /handleCloseTabOrPane\(\)/.test(tabClose),
  );
  check(
    "and it decides nothing about leaf kinds either",
    tabClose !== null && !/activeLeafKindCurrent/.test(tabClose),
    tabClose,
  );
  // The catalogue entry names what it now does, so Settings > Shortcuts and the
  // Command Palette do not still say "terminal" for a chord that closes any
  // pane. The id is deliberately unchanged: a user's rebinding is stored under
  // it.
  const catalogue = stripComments(
    readFileSync(join(root, "src/modules/shortcuts/shortcuts.ts"), "utf8"),
  );
  const entry = /id: "terminal\.close",\s*label: "([^"]+)",\s*group: "([^"]+)",/.exec(catalogue);
  check("the catalogue still carries the terminal.close id", entry !== null);
  check("labelled for a pane, not a terminal", entry?.[1] === "Close focused pane", entry?.[1]);
  check("and grouped with the other pane chords", entry?.[2] === "Panes", entry?.[2]);
}

// ---- (vi) a legal close still has to ask before discarding work -----------
// The sections above are all about which closes are LEGAL. This one is about
// which of the legal ones may happen SILENTLY, and it exists because that
// second question was in the same state the first one was in before VLT-43:
// one copy per path, and the copies disagreed. `handleClose` prompted on a
// dirty editor; `requestCloseLeaf` prompted only on a busy terminal. So for a
// single-pane tab holding an unsaved editor the pane-header X and `Ctrl+W`
// asked, and `Ctrl+Shift+X`, the tab-strip leaf X and the split pane-header X
// discarded the buffer without a word.
//
// Removing the chord's leaf-kind test (VLT-62) is only what made it reachable
// FROM THE CHORD - the other two paths had been losing buffers all along, which
// is why the fix is at the funnel and why this section is behavioural over
// `closable.ts` rather than a source-text check on the chord.
console.log("\n[vi] and a legal close asks first when it would discard work");
/** No pane has a foreground command. The default for an editor fixture. */
const noProcess = () => false;
/** Every pane claims one - only terminal leaves may act on it. */
const everyProcess = () => true;
check(
  // THE defect: `Ctrl+Shift+X` on this tab used to close it in silence.
  "an unsaved editor leaf must be confirmed before it is dropped",
  leafCloseConfirmReason(HOSTS_AND_DIRTY_EDITOR, 4, noProcess) === "unsaved",
  leafCloseConfirmReason(HOSTS_AND_DIRTY_EDITOR, 4, noProcess),
);
check(
  // The negative half, and the one that makes the check above mean something:
  // "confirm everything" satisfies every positive assertion here while turning
  // each of the five close affordances into a two-click action.
  "a SAVED editor leaf still closes silently",
  leafCloseConfirmReason(HOSTS_AND_CLEAN_EDITOR, 4, noProcess) === null,
  leafCloseConfirmReason(HOSTS_AND_CLEAN_EDITOR, 4, noProcess),
);
check(
  "a busy terminal leaf is confirmed, and for being busy",
  leafCloseConfirmReason(HOSTS_AND_TERMINAL, 4, everyProcess) === "running",
  leafCloseConfirmReason(HOSTS_AND_TERMINAL, 4, everyProcess),
);
check(
  "an idle terminal leaf closes silently",
  leafCloseConfirmReason(HOSTS_AND_TERMINAL, 4, noProcess) === null,
  leafCloseConfirmReason(HOSTS_AND_TERMINAL, 4, noProcess),
);
check(
  // VLT-62's pane must keep closing on one keystroke. Only terminal panes
  // register a handle, so a predicate that answered `true` for everything was
  // never asked about an RDP leaf by accident - state it as a rule instead.
  "an RDP leaf is never confirmed, even when the process probe says yes",
  leafCloseConfirmReason(HOSTS_AND_RDP, 4, everyProcess) === null,
  leafCloseConfirmReason(HOSTS_AND_RDP, 4, everyProcess),
);
check(
  "and nor is a leaf no tab holds - the refusal already stopped that close",
  leafCloseConfirmReason(HOSTS_AND_TERMINAL, 999, everyProcess) === null,
);
check(
  // Unrecoverable beats recoverable: a killed process can be re-run.
  "unsaved wins over running for a tab that is both",
  tabCloseConfirmReason(SPLIT_DIRTY_EDITOR_BEHIND, 3, everyProcess) === "unsaved",
  tabCloseConfirmReason(SPLIT_DIRTY_EDITOR_BEHIND, 3, everyProcess),
);
check(
  // Read off `tab.dirty` this is `false`, because the mirror follows the ACTIVE
  // leaf and the active leaf here is the terminal.
  "an unsaved editor in a BACKGROUND pane still stops the tab closing silently",
  tabCloseConfirmReason(SPLIT_DIRTY_EDITOR_BEHIND, 3, noProcess) === "unsaved",
  tabCloseConfirmReason(SPLIT_DIRTY_EDITOR_BEHIND, 3, noProcess),
);
check(
  "the same editor, closed as a pane rather than a tab, gets the same answer",
  leafCloseConfirmReason(SPLIT_DIRTY_EDITOR_BEHIND, 7, noProcess) === "unsaved",
);
check(
  "while the idle terminal sharing its split closes silently",
  leafCloseConfirmReason(SPLIT_DIRTY_EDITOR_BEHIND, 6, noProcess) === null,
);
check(
  // The agreement itself, for the exact shape that was reported: a single-pane
  // tab holding a dirty editor. The pane-header X routes it to the TAB question
  // (`handleClose`), the chord and the strip X to the LEAF question
  // (`requestCloseLeaf`). Same answer or somebody loses a buffer.
  "on a single-pane dirty editor the tab question and the leaf question agree",
  tabCloseConfirmReason(HOSTS_AND_DIRTY_EDITOR, 3, noProcess) ===
    leafCloseConfirmReason(HOSTS_AND_DIRTY_EDITOR, 4, noProcess),
  [
    tabCloseConfirmReason(HOSTS_AND_DIRTY_EDITOR, 3, noProcess),
    leafCloseConfirmReason(HOSTS_AND_DIRTY_EDITOR, 4, noProcess),
  ],
);
check(
  "a clean single-pane editor agrees the other way too",
  tabCloseConfirmReason(HOSTS_AND_CLEAN_EDITOR, 3, noProcess) === null &&
    leafCloseConfirmReason(HOSTS_AND_CLEAN_EDITOR, 4, noProcess) === null,
);

// ---- (vii) and both close paths ask it, rather than re-deciding -----------
// Source-text over `useTabActions.ts`, for the same reason [v] is: the hook
// cannot be rendered here. The behavioural section above cannot see a caller
// that stopped asking - which is the whole defect, twice over now.
console.log("\n[vii] handleClose and requestCloseLeaf both route through closable.ts");
{
  const root = join(dirname(fileURLToPath(import.meta.url)), "..");
  const src = stripComments(readFileSync(join(root, "src/app/hooks/useTabActions.ts"), "utf8"));
  /**
   * Each hook-level `const NAME = useCallback(...)` body, keyed by name. The
   * chunk runs to the next hook-level declaration; the two-space indent is what
   * keeps a `const` nested inside a callback from cutting its body in half.
   */
  const bodies = (() => {
    const marks: { name: string; at: number }[] = [];
    const re = /\n {2}const (\w+) = useCallback\(/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(src)) !== null) marks.push({ name: m[1], at: m.index });
    const out = new Map<string, string>();
    for (let i = 0; i < marks.length; i++) {
      out.set(
        marks[i].name,
        src.slice(marks[i].at, i + 1 < marks.length ? marks[i + 1].at : src.length),
      );
    }
    return out;
  })();
  const leafClose = bodies.get("requestCloseLeaf");
  const tabClose = bodies.get("handleClose");
  check("found requestCloseLeaf", leafClose !== undefined, [...bodies.keys()]);
  check("found handleClose", tabClose !== undefined, [...bodies.keys()]);
  check(
    "requestCloseLeaf asks closable.ts whether the close needs confirming",
    leafClose !== undefined && /leafCloseConfirmReason\(/.test(leafClose),
    leafClose,
  );
  check(
    // The exact line that lost the buffer: it probed the terminal handle and
    // treated "not running" as "close it". Passing the probe as an ARGUMENT is
    // not a call, so this stays green for the fixed shape and reddens the
    // moment the decision moves back in here.
    "and does not re-decide from the process probe on its own",
    leafClose !== undefined && !/leafHasRunningProcess\(/.test(leafClose),
    leafClose,
  );
  check(
    "handleClose asks the tab-level question from the same module",
    tabClose !== undefined && /tabCloseConfirmReason\(/.test(tabClose),
    tabClose,
  );
  check(
    // `t.dirty` is the mirror of the ACTIVE leaf, which is why the tab question
    // had to stop being asked of it - see SPLIT_DIRTY_EDITOR_BEHIND above.
    "and no longer reads the tab's dirty mirror",
    tabClose !== undefined && !/\.dirty/.test(tabClose),
    tabClose,
  );
  for (const [name, body] of [
    ["requestCloseLeaf", leafClose],
    ["handleClose", tabClose],
  ] as const) {
    check(
      // A hardcoded reason would satisfy "it calls the predicate" while
      // throwing the answer away.
      `${name} passes the answer through rather than naming a reason itself`,
      body !== undefined && /reason,/.test(body) && !/reason: "(?:unsaved|running)"/.test(body),
      body,
    );
    check(
      // Order, not just presence: `closable.ts` says the refusal comes first,
      // because prompting for a close that is then refused is worse than the
      // silent no-op it replaces.
      `${name} still asks the refusal first, so it never prompts for a close it will refuse`,
      body !== undefined &&
        /canClose(?:Leaf|Tab)\(/.test(body) &&
        body.includes("ConfirmReason") &&
        body.indexOf("canClose") < body.indexOf("ConfirmReason"),
    );
  }
}

if (failed > 0) throw new Error(`${failed} check(s) FAILED`);
console.log("\nALL PASS");
