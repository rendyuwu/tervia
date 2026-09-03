/**
 * Self-check for DCR-1: Vault and Port Forwarding are rail VIEWS, not tabs.
 * Run: `pnpm verify rail-views` (or `npx tsx scripts/rail-views-verify.ts`).
 *
 * Four things worth pinning down, and the last two are the ones that bit:
 *
 *  1. The page union is PARTITIONED. Every `PageKind` is either the one page that
 *     may be a tab leaf or a rail view - never both, never neither. Adding a
 *     fourth page without saying which it is fails here rather than producing a
 *     rail button that opens nothing.
 *  2. MIGRATION. A workspace snapshotted before this change can hold a `vault`
 *     or `forwards` page leaf, and every arrangement of one has to come back
 *     sensibly: the leaf dropped, the tab dropped if that empties it, a split
 *     collapsed around it, the whole workspace falling back to Hosts if nothing
 *     survives, and the restored active TAB and LEAF indices re-based onto what
 *     is left - otherwise restore focuses something the user was not looking at,
 *     or the strip shows a Vault tab that the rail, `openPageTab` and
 *     `PageLeafBody` have all stopped believing in. A page value this build does
 *     NOT recognise goes down the same drop path: rewriting it into Hosts minted
 *     a second Hosts tab, and a page leaf is permanent, so neither could be
 *     closed again.
 *  3. RE-BASING IS TESTED THROUGH THE CONSUMER. `restoredActiveTabIndex` was
 *     asserted directly and passed, while two of its three call sites clamped
 *     the RAW saved index instead of calling it - so the checks below go through
 *     `restoreWorkspaceEntry` and `savedToTab`, which is where the answer is
 *     actually decided. The fixtures pick indices where a clamp gives a
 *     DIFFERENT tab, not merely an equal one (§5.18: the old leaf fixture had 2
 *     leaves and a saved index of 1, so clamping rescued the wrong answer).
 *  4. THE WAY BACK OUT. A rail view covers the tab area, so every route INTO
 *     that area has to leave it. That is one state write (`tabs/lib/tabView.ts`)
 *     rather than a rule ten callers remember - nine of eleven did not - so the
 *     checks are the transition itself, plus a source-text sweep proving every
 *     `activeId` write in `useTabs` / `useAuxTabs` goes through the funnel.
 *  5. AND THE ROUTE THAT NEVER REACHED IT (D-NAV1, section 9). The funnel was
 *     right and the tab strip's own chip never called it: Radix suppresses
 *     `onValueChange` when the clicked trigger's value already equals the
 *     current one, which under a rail view is exactly the covered tab. Sections
 *     4 and 7 could not see that, because a check on a transition cannot notice
 *     a caller that stops asking for it - the same lesson as 3, one layer up.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  isRailViewKind,
  isTabPageKind,
  RAIL_VIEW_KINDS,
  TAB_PAGE_KIND,
  type RailViewKind,
} from "../src/modules/tabs/lib/pages";
import {
  focusTabView,
  INITIAL_TAB_VIEW,
  rehomeTabView,
  showTabsIn,
  toggleRailViewIn,
} from "../src/modules/tabs/lib/tabView";
// Type-only, so tsx never has to resolve the hook at runtime (it pulls in
// `@xterm/xterm`, which Node cannot resolve outside a bundler - see
// `serialize.ts`'s note). The probe below is checked by `pnpm typecheck:scripts`.
import type { Tab, useTabs } from "../src/modules/tabs/lib/useTabs";
// A VALUE import, and it can be one only because `selectEntry.ts` is a leaf: its
// single import is `import type { Entry }`, which is erased. Section 9 executes
// the click route rather than pinning a substring of it, which is the half a
// source-text sweep cannot do. The entry types beside it stay type-only -
// `entries.ts` reaches `@/`-aliased modules this script has no bundler for.
import {
  entrySelectHandlers,
  entrySelectTarget,
  type SelectEntry,
} from "../src/modules/tabs/lib/selectEntry";
import type { Entry, PaneEntry } from "../src/modules/tabs/lib/entries";
import {
  isPageKind,
  PAGE_KINDS,
  leaves,
  type PageKind,
  type PageLeafState,
} from "../src/modules/terminal/lib/panes";
import {
  countSavedTabEntries,
  defaultHostsTab,
  isUnrestorablePageLeaf,
  restoreSavedTabs,
  restoreWorkspaceEntry,
  restoredActiveLeafIndex,
  restoredActiveTabIndex,
  savedToTab,
  serializeTabs,
} from "../src/modules/workspaces/serialize";
import type { SavedPaneNode, SavedTab } from "../src/modules/workspaces/store";

/**
 * The narrowing itself, checked by the COMPILER rather than at runtime: a pane
 * leaf's `page` must be assignable to nothing wider than the one tab page. This
 * is the load-bearing half of "make the bad state unrepresentable" - every
 * runtime check below is about the migration, and none of them would notice
 * `PageLeafState.page` quietly widening back to `PageKind`.
 *
 * An assignability probe rather than `@ts-expect-error` on a bad literal: this
 * fails at exactly this line if the type widens, instead of reporting that an
 * expected error went missing somewhere else.
 */
const LEAF_PAGE_IS_NARROW: PageLeafState["page"] extends "hosts" ? true : false = true;

/**
 * `setActiveId` takes an ID, not a `SetStateAction`. Also compiler-checked, and
 * the reason it matters is behavioural: the functional form is what the two
 * CLOSE paths used to write this state with, and a removal re-pointing
 * `activeId` reads identically to a focus while meaning the opposite (a focus
 * leaves the rail view, a removal must not). Widening it back makes the tuple
 * stop extending `number` and fails right here.
 */
type ActiveIdArg = Parameters<ReturnType<typeof useTabs>["setActiveId"]>[0];
const SET_ACTIVE_ID_TAKES_AN_ID: [ActiveIdArg] extends [number] ? true : false = true;

let failed = 0;
function check(name: string, ok: boolean, detail?: unknown): void {
  if (ok) {
    console.log(`  ok: ${name}`);
    return;
  }
  console.error(`  FAIL: ${name}`, detail === undefined ? "" : JSON.stringify(detail));
  failed++;
}

// ---- source-text helpers --------------------------------------------------
// Shared by sections 8 and 9. At module scope rather than inside section 8's
// block because section 9 needs the SAME scanner over `.tsx` files; a fourth
// copy of it in this one file would be the way the two drift apart. Section 8
// keeps calling `stripComments`, unchanged, so nothing about its behaviour
// moves with them.
const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (p: string) => readFileSync(join(root, p), "utf8");

/**
 * Comments stripped so a doc comment naming a call is not read AS one. (The
 * third copy of this pair in the suite - VLT-33. Canonical copy lives in
 * `scripts/host-editor-verify.ts`; keep them the same shape. Duplicated
 * rather than shared, because these scripts have no common module.)
 *
 * QUOTE-AWARE, and a character scan rather than a regex: a `//` inside a
 * string is not a comment, and a regex alternation over string literals
 * desyncs on the first unbalanced quote - after which it eats real code. The
 * scan loses the strip for a line with an unclosed quote instead, which fails
 * towards KEEPING text. That is the safe direction: the failure this exists
 * to prevent is a positive check going green off `// was: <deleted code>`.
 */
const stripLineComment = (line: string): string => {
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
};
// VLT-83: no JSX-comment branch in THIS one, and that is deliberate rather
// than an oversight. It does run over `.tsx` files (section 8 reads
// `src/app/App.tsx`), so a `{/* ... */}` left behind by a deletion survives
// it - but every check section 8 makes over a `.tsx` file is a NEGATIVE
// (`!/setRailView/`, `!/useState<RailViewKind/`, `!/openPageTabInTabs/`), and
// an un-stripped JSX comment there can only cause a FALSE FAILURE (the
// forbidden text still present, inertly, inside a comment), never a silenced
// pass - the unsafe direction this bug is about. Section 9 writes POSITIVE
// checks over `.tsx` files, where the direction reverses, so it uses
// `stripTsxComments` below. Section 8 is left on this one so its behaviour is
// unchanged by that addition.
const stripComments = (src: string): string =>
  src
    .split("\n")
    .filter((line) => {
      const t = line.trim();
      return !(t.startsWith("//") || t.startsWith("/*") || t.startsWith("*"));
    })
    .map(stripLineComment)
    .join("\n");

// The same, plus the one comment syntax that is legal INSIDE JSX children:
// a `{/* ... */}` expression. A bare `//` there renders as literal text, so
// the line-based filter above never had a reason to know about it - and it
// does not match a line starting `{` either. Required by every POSITIVE check
// over a `.tsx` file: without this, deleting the trigger's select spread and
// leaving `{/* ...entrySelectHandlers(e, onSelectEntry) */}` behind still
// satisfies section 9(ii), which is the exact failure VLT-83 is about.
//
// The regex is the FIXED one from `scripts/host-editor-verify.ts` (around
// `:216`), NOT the lazy `\{\s*\/\*[\s\S]*?\*\/\s*\}` that
// `vault-editor-verify.ts` carries. Lazy is not a substitute: it is still
// ALLOWED to skip over an intervening `*/` while hunting for one that happens
// to be followed by `}`, and a type literal opening `{ /** null = closed. */
// target: ... }` is exactly that shape - measured over there to eat 50KB of
// file between the two. The negative lookahead forbids the inner group from
// crossing a `*/` at all, so the first one found is final: either `}` follows
// it and this is a real JSX comment, or the match fails HERE rather than
// searching on for a luckier closer.
const stripTsxComments = (src: string): string =>
  stripComments(src.replace(/\{\s*\/\*(?:(?!\*\/)[\s\S])*\*\/\s*\}/g, ""));

// ---- fixtures -------------------------------------------------------------

function savedPage(page: PageKind): SavedPaneNode {
  return { kind: "leaf", leafKind: "page", page };
}
/**
 * A saved page leaf naming a page THIS build does not know: a newer build's
 * page, or a hand-edited state file. Cast, because the whole point of the fixture
 * is a value outside `PageKind` - which is exactly what a state file can hold and
 * the type cannot.
 */
function savedUnknownPage(page = "snippets"): SavedPaneNode {
  return { kind: "leaf", leafKind: "page", page: page as PageKind };
}
function savedTerm(cwd = "/w"): SavedPaneNode {
  return { kind: "leaf", leafKind: "terminal", cwd };
}
function savedSplit(children: SavedPaneNode[], sizes?: number[]): SavedPaneNode {
  return { kind: "split", dir: "row", children, ...(sizes ? { sizes } : {}) };
}
function savedTab(paneTree: SavedPaneNode, activeLeafIndex = 0): SavedTab {
  return { kind: "pane", paneTree, activeLeafIndex };
}

let nextId = 1;
const allocId = () => nextId++;
/**
 * The cwd of a restored tab's ACTIVE leaf, or null when there is none. How the
 * focus fixtures tell one restored pane from another: the ids are freshly
 * allocated, the cwds are the fixture's own labels.
 */
function activeLeafCwdOf(tab: Tab | null | undefined): string | null {
  if (!tab || tab.kind !== "pane") return null;
  const leaf = leaves(tab.paneTree).find((l) => l.id === tab.activeLeafId);
  return leaf && leaf.leafKind === "terminal" ? (leaf.cwd ?? null) : null;
}

/** Every leaf kind in a restored tab list, depth-first. */
function leafKinds(tabs: ReturnType<typeof restoreSavedTabs>): string[] {
  return tabs.flatMap((t) =>
    t.kind === "pane"
      ? leaves(t.paneTree).map((l) => (l.leafKind === "page" ? `page:${l.page}` : l.leafKind))
      : [t.kind],
  );
}

// ---- 1. the union is partitioned -----------------------------------------
console.log("[union] every page is a tab page or a rail view, and exactly one of them");
for (const page of PAGE_KINDS) {
  const asTab = isTabPageKind(page);
  const asView = isRailViewKind(page);
  check(`${page}: classified exactly once`, asTab !== asView, { page, asTab, asView });
}
check("Hosts is the tab page", isTabPageKind(TAB_PAGE_KIND) && TAB_PAGE_KIND === "hosts");
check(
  "the rail views are Vault and Port Forwarding, in that order",
  RAIL_VIEW_KINDS.join(",") === "vault,forwards",
  RAIL_VIEW_KINDS,
);
check(
  "and they account for every page that is not the tab page",
  RAIL_VIEW_KINDS.length === PAGE_KINDS.length - 1,
  { views: RAIL_VIEW_KINDS.length, pages: PAGE_KINDS.length },
);
check("the tab page is not a rail view", !isRailViewKind(TAB_PAGE_KIND));
check("an unrecognised string is neither", !isTabPageKind("kitchen") && !isRailViewKind("kitchen"));
check(
  // Checked by the compiler at `LEAF_PAGE_IS_NARROW` above; asserted here too so
  // a reader of the output sees the invariant stated rather than inferring it
  // from a type alias they cannot run.
  "a pane leaf's page type is narrowed to the tab page, not the whole union",
  LEAF_PAGE_IS_NARROW,
);
check(
  "isPageKind still recognises every rail page",
  PAGE_KINDS.every((p) => isPageKind(p)),
);
check("and rejects a value from no build", !isPageKind("snippets"));
check(
  // The migration asks `!isTabPageKind`, NOT `isRailViewKind`, so that an
  // unrecognised page is dropped rather than falling through to Hosts.
  "a page from no build is not the tab page either",
  !isTabPageKind("snippets"),
);

// ---- 2. which saved leaves restore ---------------------------------------
console.log("\n[saved] a page leaf that is not Hosts does not come back as a tab");
check("a saved vault leaf is unrestorable", isUnrestorablePageLeaf(savedPage("vault")));
check("a saved forwards leaf is unrestorable", isUnrestorablePageLeaf(savedPage("forwards")));
check(
  // The case a two-name enumeration missed: not a rail view, not Hosts, and
  // turning it INTO Hosts is what minted the second permanent Hosts tab.
  "and so is a page value this build has never heard of",
  isUnrestorablePageLeaf(savedUnknownPage()),
);
check("a saved hosts leaf is NOT", !isUnrestorablePageLeaf(savedPage("hosts")));
check("nor is a terminal leaf", !isUnrestorablePageLeaf(savedTerm()));
check("nor is a split", !isUnrestorablePageLeaf(savedSplit([savedTerm(), savedTerm()])));

// ---- 3. migration on restore --------------------------------------------
console.log("\n[migrate] a pre-DCR-1 snapshot restores without a Vault tab in the strip");
{
  // The realistic shape: Hosts, a terminal, and the Vault tab the user left open.
  const saved: SavedTab[] = [
    savedTab(savedPage("hosts")),
    savedTab(savedTerm("/a")),
    savedTab(savedPage("vault")),
  ];
  const tabs = restoreSavedTabs(saved, allocId);
  check("the Vault tab is gone", tabs.length === 2, leafKinds(tabs));
  check(
    "Hosts and the terminal are untouched",
    leafKinds(tabs).join(",") === "page:hosts,terminal",
    leafKinds(tabs),
  );
  check(
    "no rail-view leaf survives anywhere",
    !leafKinds(tabs).some((k) => k.startsWith("page:v")),
  );
}
{
  // A split the user made by dragging Vault next to a shell: the leaf goes, the
  // split collapses into its lone survivor rather than restoring as a one-child
  // split (which is not a valid pane tree).
  const saved: SavedTab[] = [
    savedTab(savedSplit([savedTerm("/a"), savedPage("forwards")], [60, 40]), 1),
  ];
  const tabs = restoreSavedTabs(saved, allocId);
  check("the tab survives on its terminal", tabs.length === 1, leafKinds(tabs));
  check("collapsed to a single leaf, not a one-child split", tabs[0].paneTree.kind === "leaf");
  check("and that leaf is the terminal", leafKinds(tabs).join(",") === "terminal", leafKinds(tabs));
  check(
    // The saved index pointed at the dropped leaf; it must land on a real one.
    "the active leaf is one the tab actually has",
    tabs[0].kind === "pane" && leaves(tabs[0].paneTree).some((l) => l.id === tabs[0].activeLeafId),
  );
}
{
  // Three panes, one of them a rail view: the split stays a split, and the saved
  // divider sizes are dropped because pruning invalidated the ratios.
  const saved: SavedTab[] = [
    savedTab(savedSplit([savedTerm("/a"), savedPage("vault"), savedTerm("/b")], [30, 30, 40])),
  ];
  const tabs = restoreSavedTabs(saved, allocId);
  check("two panes left", leafKinds(tabs).join(",") === "terminal,terminal", leafKinds(tabs));
  check("still a split", tabs[0].paneTree.kind === "split");
  check(
    "the stale 3-way sizes are not applied to 2 children",
    tabs[0].paneTree.kind === "split" && tabs[0].paneTree.sizes === undefined,
    tabs[0].paneTree.kind === "split" ? tabs[0].paneTree.sizes : null,
  );
}
{
  // Everything the workspace had was a rail view. An empty window is not an
  // option, so it lands where a fresh profile does.
  const saved: SavedTab[] = [savedTab(savedPage("vault")), savedTab(savedPage("forwards"))];
  const tabs = restoreSavedTabs(saved, allocId);
  check("falls back to a single tab", tabs.length === 1, leafKinds(tabs));
  check("and it is the Hosts page", leafKinds(tabs).join(",") === "page:hosts", leafKinds(tabs));
}
{
  // A single saved tab that does not survive: `savedToTab` says so rather than
  // returning an empty tab for the caller to notice later.
  check(
    "savedToTab returns null for a Vault-only tab",
    savedToTab(savedTab(savedPage("vault")), allocId) === null,
  );
  check(
    "and a real tab for a Hosts one",
    savedToTab(savedTab(savedPage("hosts")), allocId) !== null,
  );
}
{
  // Nothing saved at all: unchanged behaviour, stated here because the fallback
  // above shares its implementation.
  const tabs = restoreSavedTabs([], allocId);
  check("an empty snapshot still lands on Hosts", leafKinds(tabs).join(",") === "page:hosts");
}
{
  // An unrecognised page beside a real Hosts tab. It used to be REWRITTEN into
  // Hosts, so this restored as two Hosts tabs - both permanent (`closable.ts`
  // invariant 1), so the workspace could not be got back to one.
  const saved: SavedTab[] = [savedTab(savedPage("hosts")), savedTab(savedUnknownPage())];
  const tabs = restoreSavedTabs(saved, allocId);
  check("the unrecognised page's tab is gone", tabs.length === 1, leafKinds(tabs));
  check(
    "exactly one Hosts page survives, not two",
    leafKinds(tabs).filter((k) => k === "page:hosts").length === 1,
    leafKinds(tabs),
  );
  check(
    "and nothing was restored under the unrecognised page name",
    !leafKinds(tabs).includes("page:snippets"),
    leafKinds(tabs),
  );
  check(
    "savedToTab returns null for an unrecognised-page-only tab",
    savedToTab(savedTab(savedUnknownPage()), allocId) === null,
  );
  check(
    "the cold badge does not count it either",
    countSavedTabEntries(saved) === 1,
    countSavedTabEntries(saved),
  );
}
{
  // Split around one: same collapse a rail-view leaf gets, so the sibling
  // terminal keeps its pane rather than losing the tab to a page nothing here
  // can render.
  const saved: SavedTab[] = [savedTab(savedSplit([savedTerm("/a"), savedUnknownPage()], [60, 40]))];
  const tabs = restoreSavedTabs(saved, allocId);
  check("the sibling terminal survives", leafKinds(tabs).join(",") === "terminal", leafKinds(tabs));
  check("collapsed, not a one-child split", tabs[0].paneTree.kind === "leaf");
}

// ---- 4. the restored active index ---------------------------------------
console.log("\n[focus] the active tab index is re-based onto the tabs that survived");
{
  const saved: SavedTab[] = [
    savedTab(savedPage("hosts")), // 0 -> 0
    savedTab(savedPage("vault")), // 1 -> dropped
    savedTab(savedTerm("/a")), // 2 -> 1
    savedTab(savedTerm("/b")), // 3 -> 2
  ];
  check("a tab before the drop keeps its index", restoredActiveTabIndex(saved, 0) === 0);
  check(
    "a tab after the drop shifts down by one",
    restoredActiveTabIndex(saved, 2) === 1,
    restoredActiveTabIndex(saved, 2),
  );
  check("and so does the next one", restoredActiveTabIndex(saved, 3) === 2);
  check(
    // The dropped tab was the active one. Its neighbour is the only sensible
    // landing, and it must be in range.
    "the dropped tab's own index lands on its neighbour",
    restoredActiveTabIndex(saved, 1) === 1,
    restoredActiveTabIndex(saved, 1),
  );
  const tabs = restoreSavedTabs(saved, allocId);
  check(
    "every re-based index is in range for the restored list",
    [0, 1, 2, 3].every((i) => restoredActiveTabIndex(saved, i) < tabs.length),
    { count: tabs.length },
  );
}
{
  // THE CONSUMER, not the helper. Every check above asks `restoredActiveTabIndex`
  // directly, and it was always right - while two of its three call sites never
  // called it, clamping the raw saved index against the restored array instead.
  // Index 2 with one dropped tab before it: re-basing gives termA, clamping
  // gives termB, so the two answers DIFFER (a fixture where they agree proves
  // nothing - §5.18).
  const entry = {
    tabs: [
      savedTab(savedPage("hosts")), // 0
      savedTab(savedPage("vault")), // 1 -> dropped
      savedTab(savedTerm("/a")), // 2 -> 1, and the one that was active
      savedTab(savedTerm("/b")), // 3 -> 2
    ],
    activeTabIndex: 2,
  };
  const restored = restoreWorkspaceEntry(entry, allocId);
  const active = restored.tabs.find((t) => t.id === restored.activeId) ?? null;
  const activeCwd = activeLeafCwdOf(active);
  check("the Vault tab is gone from the restored list", restored.tabs.length === 3, {
    kinds: leafKinds(restored.tabs),
  });
  check("the focused tab is one the list actually holds", active !== undefined, {
    activeId: restored.activeId,
  });
  check(
    "and it is the terminal the workspace was saved on, not its neighbour",
    activeCwd === "/a",
    { activeCwd },
  );
  check(
    // The whole point of returning an id: a caller cannot re-derive it from an
    // index computed against a different list.
    "restoreWorkspaceEntry hands back an id, not an index",
    typeof restored.activeId === "number" && restored.tabs.some((t) => t.id === restored.activeId),
  );
}
{
  // The last tab, saved active, with a drop before it: the clamp and the
  // re-basing also differ here, and this is the case where clamping runs off the
  // end of the shorter list rather than merely one row late.
  const entry = {
    tabs: [
      savedTab(savedPage("vault")), // dropped
      savedTab(savedTerm("/a")),
      savedTab(savedTerm("/b")),
    ],
    activeTabIndex: 2,
  };
  const restored = restoreWorkspaceEntry(entry, allocId);
  const activeCwd = activeLeafCwdOf(restored.tabs.find((t) => t.id === restored.activeId) ?? null);
  check("two tabs restored", restored.tabs.length === 2, leafKinds(restored.tabs));
  check("focus lands on the saved terminal", activeCwd === "/b", { activeCwd });
}
{
  // A workspace with nothing restorable in it: the Hosts fallback is what to
  // focus, and there has to BE something to focus.
  const restored = restoreWorkspaceEntry(
    { tabs: [savedTab(savedPage("vault"))], activeTabIndex: 0 },
    allocId,
  );
  check("falls back to one Hosts tab", leafKinds(restored.tabs).join(",") === "page:hosts");
  check(
    "and focuses it rather than nothing",
    restored.activeId !== null && restored.tabs[0].id === restored.activeId,
  );
}

// ---- 4b. the restored active LEAF index ----------------------------------
console.log("\n[focus-leaf] the active leaf index is re-based onto the leaves that survived");
{
  // Four panes, the Vault one at index 1, saved active leaf at index 2 (termB).
  // Survivors are [termA, termB, termC], so the answer is 1. Clamping the raw
  // index gives 2 = termC - a DIFFERENT leaf, which is what the old 2-leaf
  // fixture could not show, because there clamping happened to land right.
  const tree = savedSplit([savedTerm("/a"), savedPage("vault"), savedTerm("/b"), savedTerm("/c")]);
  check("a leaf before the drop keeps its index", restoredActiveLeafIndex(tree, 0) === 0);
  check(
    "a leaf after the drop shifts down by one",
    restoredActiveLeafIndex(tree, 2) === 1,
    restoredActiveLeafIndex(tree, 2),
  );
  check("and so does the next one", restoredActiveLeafIndex(tree, 3) === 2);
  check(
    "the dropped leaf's own index lands on its neighbour",
    restoredActiveLeafIndex(tree, 1) === 1,
    restoredActiveLeafIndex(tree, 1),
  );
  // And through the consumer, which is where it was never asked.
  const tab = savedToTab(savedTab(tree, 2), allocId);
  const activeLeafCwd = activeLeafCwdOf(tab);
  check("three panes survive", tab?.kind === "pane" && leaves(tab.paneTree).length === 3, {
    kinds: tab === null ? null : leafKinds([tab]),
  });
  check("savedToTab focuses the saved leaf, not the one after it", activeLeafCwd === "/b", {
    activeLeafCwd,
  });
}
{
  // An unrecognised page inside a split shifts the leaves after it exactly like
  // a rail view does - the drop rule is one predicate, so the re-basing follows
  // it for free.
  const tree = savedSplit([savedTerm("/a"), savedUnknownPage(), savedTerm("/b"), savedTerm("/c")]);
  const activeLeafCwd = activeLeafCwdOf(savedToTab(savedTab(tree, 3), allocId));
  check("focus follows the shift past an unrecognised page", activeLeafCwd === "/c", {
    activeLeafCwd,
  });
}
{
  // No drops at all: re-basing must be the identity, or it would break every
  // ordinary restore to fix the pruned one.
  const tree = savedSplit([savedTerm("/a"), savedTerm("/b"), savedTerm("/c")]);
  check(
    "with nothing dropped, every index is unchanged",
    [0, 1, 2].every((i) => restoredActiveLeafIndex(tree, i) === i),
  );
  const activeLeafCwd = activeLeafCwdOf(savedToTab(savedTab(tree, 2), allocId));
  check("and the consumer still focuses the saved leaf", activeLeafCwd === "/c", { activeLeafCwd });
}
{
  // Round trip: serialize a live split, restore it, and land on the same pane.
  // Guards the direction of the mirror - `tabToSaved`'s `kept.findIndex` and
  // `restoredActiveLeafIndex` have to compose to the identity.
  const live = restoreSavedTabs(
    [savedTab(savedSplit([savedTerm("/a"), savedTerm("/b"), savedTerm("/c")]), 1)],
    allocId,
  );
  const cwd = activeLeafCwdOf(restoreSavedTabs(serializeTabs(live), allocId)[0]);
  check("a split round-trips onto the same active pane", cwd === "/b", { cwd });
}

// ---- 5. the cold-workspace badge ----------------------------------------
console.log("\n[badge] a cold workspace counts the entries opening it would produce");
{
  const saved: SavedTab[] = [
    savedTab(savedPage("hosts")),
    savedTab(savedSplit([savedTerm("/a"), savedPage("vault")])),
  ];
  check(
    "the rail-view leaf is not counted",
    countSavedTabEntries(saved) === 2,
    countSavedTabEntries(saved),
  );
  check(
    "which is exactly what restoring produces",
    countSavedTabEntries(saved) === leafKinds(restoreSavedTabs(saved, allocId)).length,
  );
}

// ---- 6. round trip ------------------------------------------------------
console.log("\n[round-trip] a Hosts tab still survives save and restore untouched");
{
  const saved = serializeTabs([defaultHostsTab(allocId)]);
  check("one saved tab", saved.length === 1);
  const tabs = restoreSavedTabs(saved, allocId);
  check("restored as the Hosts page", leafKinds(tabs).join(",") === "page:hosts", leafKinds(tabs));
}

// ---- 7. the way back out of a rail view ---------------------------------
console.log("\n[exit] activating a tab leaves the rail view, and a removal does not");
{
  // Built from `RAIL_VIEW_KINDS`, not a copy of the union: a third rail view is
  // then covered by these rows the moment it is declared.
  const RAIL: (RailViewKind | null)[] = [null, ...RAIL_VIEW_KINDS];
  check(
    // §4.18: driving the table off `RAIL_VIEW_KINDS` is what keeps it current,
    // and is also the way it could quietly become vacuous - an empty list would
    // leave only the `null` row, so every "over a view" assertion below would
    // run exclusively against "no view" and pass while testing nothing. The
    // compiler catches the specific way that happens today (narrow `PageKind`
    // back to `"hosts"` and `RailViewKind` becomes `never`, so the literals in
    // this section stop type-checking), but a compiler error is not a check,
    // and `RAIL_VIEW_KINDS` could equally be emptied without changing the type.
    "there is at least one rail view for the table below to test",
    RAIL_VIEW_KINDS.length > 0 && RAIL.length === RAIL_VIEW_KINDS.length + 1,
    { views: RAIL_VIEW_KINDS, rows: RAIL.length },
  );
  // A table, not one case: "clears it when the id changed" is the subtle version
  // of the same bug, and only the same-id row shows it. Ctrl+1 on the tab that is
  // ALREADY active is precisely the case where the user is asking to be shown a
  // tab the Vault is covering.
  for (const railView of RAIL) {
    for (const from of [1, 2]) {
      for (const to of [1, 2, 3]) {
        const next = focusTabView({ activeId: from, railView }, to);
        check(
          `focus ${from}->${to} over ${railView ?? "no view"}: the tabs are showing`,
          next.railView === null,
          next,
        );
        check(
          `focus ${from}->${to} over ${railView ?? "no view"}: the tab is active`,
          next.activeId === to,
          next,
        );
      }
    }
  }
  const settled = { activeId: 7, railView: null };
  check(
    // No churn when there is nothing to do: `useTabs` holds this in state, so a
    // fresh object on every focus would re-render the whole workspace area.
    "re-focusing the active tab with no view returns the same object",
    focusTabView(settled, 7) === settled,
  );
  for (const railView of RAIL) {
    const from = { activeId: 5, railView };
    check(
      `rehome 5->6 over ${railView ?? "no view"}: the view is untouched`,
      rehomeTabView(from, 6).railView === railView,
      rehomeTabView(from, 6),
    );
    check(
      `rehome 5->6 over ${railView ?? "no view"}: the active id moved`,
      rehomeTabView(from, 6).activeId === 6,
    );
  }
  const same = { activeId: 5, railView: "vault" as const };
  check("rehome to the same id changes nothing", rehomeTabView(same, 5) === same);
  check(
    "showTabsIn clears the view",
    showTabsIn({ activeId: 3, railView: "vault" }).railView === null,
  );
  check("and keeps the active tab", showTabsIn({ activeId: 3, railView: "vault" }).activeId === 3);
  const showing = { activeId: 3, railView: null };
  check("showTabsIn on the tabs is a no-op", showTabsIn(showing) === showing);
  check(
    "the rail button lights a view",
    toggleRailViewIn({ activeId: 1, railView: null }, "vault").railView === "vault",
  );
  check(
    "clicking the lit one goes back to the tabs",
    toggleRailViewIn({ activeId: 1, railView: "vault" }, "vault").railView === null,
  );
  check(
    "and clicking the other switches view rather than closing",
    toggleRailViewIn({ activeId: 1, railView: "vault" }, "forwards").railView === "forwards",
  );
  check(
    "toggling never moves focus",
    toggleRailViewIn({ activeId: 9, railView: null }, "vault").activeId === 9,
  );
  check(
    "the mount state is no tab and no view",
    INITIAL_TAB_VIEW.activeId === 0 && INITIAL_TAB_VIEW.railView === null,
    INITIAL_TAB_VIEW,
  );
  check("the compiler pins setActiveId to an id", SET_ACTIVE_ID_TAKES_AN_ID);
}

// ---- 8. every activeId write goes through the funnel --------------------
// SOURCE-TEXT, because the rule is about which writes EXIST, not about what one
// of them returns - and the state lives in a React hook this suite cannot run
// (no renderer here; §5.26's lesson is to enumerate by the mutation, so this
// enumerates them). The pure transition above is the behaviour; this is the
// proof that nothing writes `activeId` around it.
console.log("\n[funnel] no route into the tab area writes activeId on its own");
{
  const stripQuotesAwareComments = stripComments;
  /**
   * Each top-level declaration body, keyed by name. The chunk runs to the next
   * such declaration, which is enough here: both files are one flat list of a
   * hook's callbacks.
   *
   * NOT `const NAME = useCallback(` any more. That shape is a convention, not a
   * rule, and every closure below is only a closure over the declarations this
   * function returns - so a writer declared as a plain `const NAME = (id) => {}`
   * was in the file, in the api, and in none of the buckets, silently. The marks
   * are now any `const` / `function` at module level or at the hook's own
   * indent.
   *
   * The indent is load-bearing and is why this is `{0,2}` rather than `\s*`: a
   * `const` nested inside a callback would otherwise be a mark, cutting that
   * callback's body off at its first local variable and hiding everything after
   * it. Destructuring (`const { a, b } = ...`) is deliberately not matched -
   * there is no single name to key it by, and the [return] check at the end of
   * the sweep is what covers a callback that arrives that way.
   */
  const callbackBodies = (src: string): Map<string, string> => {
    const marks: { name: string; at: number }[] = [];
    const re = /\n {0,2}(?:export )?(?:const|function) (\w+)\b/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(src)) !== null) marks.push({ name: m[1], at: m.index });
    const out = new Map<string, string>();
    for (let i = 0; i < marks.length; i++) {
      const end = i + 1 < marks.length ? marks[i + 1].at : src.length;
      out.set(marks[i].name, src.slice(marks[i].at, end));
    }
    return out;
  };

  /** The four funnels. Only these may touch the view state. */
  const FUNNELS = ["setActiveId", "rehomeActiveId", "showTabs", "toggleRailView"];
  /**
   * Every mutation in `useTabs` that activates a tab, mints one, moves focus
   * inside one, or REARRANGES the panes of one - i.e. every route INTO the tab
   * area. Each must funnel; the closure check below then proves the list is
   * complete, because a new mutation that writes `activeId` and is not named
   * here fails.
   *
   * The last three arrived with §4.29: this list originally stopped at "moves
   * focus", which is why a rotate or a reorder driven from the header - a
   * surface a rail view does not cover - reshaped panes nobody could see. See
   * the [sweep] section below, which enumerates from the pane-tree write rather
   * than from what the mutation is called.
   */
  const ROUTES_IN: Record<string, string[]> = {
    "src/modules/tabs/lib/useTabs.ts": [
      "newTab",
      "newPaneGroupTab",
      "newSshTab",
      "openFileTab",
      "selectByIndex",
      "replaceAllTabs",
      "moveLeafToTab",
      "moveLeafToNewTab",
      "splitActivePane",
      "focusPane",
      "focusNextPaneInTab",
      "rotateLeafSplit",
      "reorderLeafInGroup",
      "movePaneLeafToEdge",
    ],
    "src/modules/tabs/lib/useAuxTabs.ts": ["openBoardTab", "newRdpTab", "openPageTab"],
  };
  /** The removals. They re-point `activeId` and must NOT leave the rail view. */
  const REMOVALS = ["closeTab", "closePaneByLeaf"];

  for (const [file, routes] of Object.entries(ROUTES_IN)) {
    const bodies = callbackBodies(stripComments(read(file)));
    for (const name of routes) {
      const body = bodies.get(name);
      check(`${name} is still a callback in ${file.split("/").pop()}`, body !== undefined, [
        ...bodies.keys(),
      ]);
      check(
        `${name} routes into the tab area through the funnel`,
        body !== undefined && (/\bsetActiveId\(/.test(body) || /\bshowTabs\(/.test(body)),
      );
    }
    // Closure: the set of `activeId` writers is exactly what is enumerated here.
    const declared = new Set([...routes, ...REMOVALS, ...FUNNELS]);
    const writers = [...bodies.entries()]
      .filter(([, b]) => /\bsetActiveId\(|\brehomeActiveId\(|\bshowTabs\(/.test(b))
      .map(([n]) => n);
    check(
      `no unlisted mutation in ${file.split("/").pop()} writes activeId`,
      writers.every((n) => declared.has(n)),
      writers.filter((n) => !declared.has(n)),
    );
  }

  const tabsSrc = stripComments(read("src/modules/tabs/lib/useTabs.ts"));
  const tabsBodies = callbackBodies(tabsSrc);
  for (const name of REMOVALS) {
    const body = tabsBodies.get(name);
    check(`${name} re-homes activeId`, body !== undefined && /\brehomeActiveId\(/.test(body));
    check(
      // The distinction the old code could not express: it wrote the same setter
      // with a functional updater, so a removal read as a focus.
      `${name} does NOT focus, so the rail view survives closing a tab`,
      body !== undefined && !/\bsetActiveId\(/.test(body),
    );
  }
  for (const name of REMOVALS) {
    const body = tabsBodies.get(name) ?? "";
    check(
      // Defence in depth, and the only kind available for a state this suite
      // cannot run: `next[...].id` on an emptied list is a TypeError thrown
      // INSIDE a `setTabs` reducer - an unhandled render crash, not a misplaced
      // focus. `closable.ts` refuses the last entry, so it is unreachable today;
      // a rule enforced two layers up should not be the only thing between a
      // typo in that predicate and a white window.
      `${name} does not read .id off a blind index into the tab list`,
      !/next\[[^\]]*\]\.id/.test(body),
    );
    check(
      `${name} falls back to "no tab active" when nothing is left`,
      /\?\?\s*0\)/.test(body) && /\?\?\s*next\[0\]/.test(body),
    );
  }

  // ---- 8b. every PANE-TREE write, not just every activeId write ----------
  // §4.29: the fix for this rule inherited the blind spot of the enumeration
  // that scoped it. The list above is "routes that ACTIVATE A TAB", so it could
  // never have covered a chord that rearranges the tab already active - Ctrl+D
  // splitting a pane behind the Vault, the header's Rotate/reorder doing the
  // same from a menu the view does not cover. Those write the PANE TREE, which
  // is the other half of "what the workspace area is showing".
  //
  // So this enumerates from the mutation instead: every callback whose body
  // reshapes a pane tree or moves focus inside one. Each must land in exactly
  // one of three named buckets, and the closure check at the end fails on any
  // that lands in none - which is what makes a NEW pane-tree mutation a red
  // check rather than the next round's defect report.
  //
  // THE CLOSURE WAS ITSELF A HARDCODED LIST, once (§4.29 one level up). "Which
  // calls count as a pane-tree write" was seven names transcribed into a regex,
  // out of the twenty-one `useTabs` imports from `panes.ts` - so `buildPaneTree`
  // and `cloneLeafState` were imported, in use, and invisible to it, and a new
  // callback that rebuilt a whole tree through `buildPaneTree` passed. The
  // classification is now driven off the import statement itself: every name a
  // swept file imports from `panes.ts` must appear in exactly one of the three
  // lists below, so the next import lands as a red check by name rather than as
  // a hole in a regex nobody re-reads.
  console.log("\n[sweep] every write of a pane tree leaves the rail view, or says why not");
  {
    /**
     * `panes.ts` exports that PRODUCE OR RESHAPE a tree. A callback that calls
     * one is rearranging what the workspace area shows.
     *
     * `cloneLeafState` is a read on its own and is listed here anyway: it exists
     * only to lift a leaf's state out of one tree so it can be planted in
     * another, so every call site is half of a move. `setSplitSizesInTree` is
     * here for the opposite reason - so its exemption below has to be argued
     * rather than obtained by leaving it out.
     */
    const RESHAPES_A_TREE = [
      "buildPaneTree",
      "cloneLeafState",
      "movePaneLeafToEdgeInTree",
      "normalizePaneTree",
      "removeLeaf",
      "reorderLeafInTree",
      "rotateLeafWithNeighbor",
      "setSplitSizesInTree",
      "splitLeaf",
    ];
    /**
     * Write a FIELD of one leaf and nothing else. None of them changes which
     * panes exist or which one is focused, so none is a route into the tab area:
     * the pane is already on screen or already is not. They are also the ones
     * driven by the session rather than by the user - an OSC 7 cwd, a PTY id, an
     * editor going dirty - so making them show the tabs would let a background
     * terminal yank someone out of the Vault by printing a prompt.
     */
    const WRITES_A_LEAF_FIELD = [
      "setLeafActiveToolInTree",
      "setLeafCustomTitleInTree",
      "setLeafCwdInTree",
      "setLeafPtyIdInTree",
      "setLeafTerminalThemeInTree",
      "updateEditorLeaf",
    ];
    /** Read nothing into the tree at all - lookups, id arithmetic, a label map. */
    const READS_ONLY = [
      "findLeaf",
      "hasLeaf",
      "leafIds",
      "leaves",
      "nextLeafId",
      "PAGE_LABELS",
      "siblingLeafOf",
    ];
    const CLASSIFIED = new Set([...RESHAPES_A_TREE, ...WRITES_A_LEAF_FIELD, ...READS_ONLY]);

    /**
     * The LOCAL names a file imports from `panes.ts`, types dropped. Local,
     * because `movePaneLeafToEdge as movePaneLeafToEdgeInTree` is what a body
     * actually calls, and the alias is the name that has to be in the regex.
     */
    const panesImports = (src: string): string[] => {
      // `[^}]` rather than `[\s\S]*?`: a lazy any-character run starts matching
      // at the file's FIRST `import {` and happily swallows every import between
      // it and the panes one, so the "list" came back holding `useCallback`.
      const m = /import \{([^}]*)\} from "@\/modules\/terminal\/lib\/panes";/.exec(src);
      if (!m) return [];
      return m[1]
        .split(",")
        .map((s) => s.trim())
        .filter((s) => s !== "" && !s.startsWith("type "))
        .map((s) => (s.includes(" as ") ? s.slice(s.indexOf(" as ") + 4).trim() : s));
    };

    /**
     * A pane-tree write, DERIVED from what this file imports rather than
     * transcribed. The two structural clauses are what catch a tree built from
     * object literals with no helper at all - which is exactly how all three of
     * `useAuxTabs`' openers mint theirs - and `activeLeafId:` is a write of
     * WHICH PANE IS SHOWING even when the tree itself is untouched.
     */
    const treeWriteFor = (imports: string[]): RegExp => {
      const named = imports.filter((n) => RESHAPES_A_TREE.includes(n));
      const clauses = ["activeLeafId:", "paneTree:"];
      if (named.length > 0) clauses.unshift(`\\b(?:${named.join("|")})\\(`);
      return new RegExp(clauses.join("|"));
    };

    /** Leaves the view, because its whole result is inside the covered area. */
    const SHOWS_TABS: Record<string, string[]> = {
      "src/modules/tabs/lib/useTabs.ts": [
        "newTab",
        "newPaneGroupTab",
        "newSshTab",
        "openFileTab",
        "replaceAllTabs",
        "splitActivePane",
        "focusPane",
        "focusNextPaneInTab",
        "moveLeafToTab",
        "moveLeafToNewTab",
        // The three the chord-shaped enumeration missed. All three are reached
        // from the header, which stays on screen above a rail view.
        "rotateLeafSplit",
        "reorderLeafInGroup",
        "movePaneLeafToEdge",
      ],
      // Swept for the first time here. `useAuxTabs` writes pane trees - three
      // openers, each minting a single-leaf tree from an object literal - and
      // the sweep read `useTabs` alone, while TERVIA.md claimed the guarantee
      // covered both. They pass today; that they pass is now checked.
      "src/modules/tabs/lib/useAuxTabs.ts": ["openBoardTab", "newRdpTab", "openPageTab"],
    };
    /** Removals. They re-point `activeId` and must KEEP the view - closing a
     *  background tab from the strip X is not a request to leave the Vault
     *  (decision in force). Already asserted in full below. */
    const KEEPS_VIEW = ["closePaneByLeaf"];
    /**
     * Writes a tree and deliberately does NOT show the tabs, with the reason.
     * One entry, and it has to earn it: `setSplitSizes` persists the ratio a
     * divider drag just produced. It changes no membership and no focus, so
     * there is no new thing for showing the tabs to reveal - the drag that
     * caused it was the user watching the result happen. And it is echoed, not
     * commanded: `onLayoutChanged` fires on any relayout the panel library
     * performs, so a write that cleared the view would hand every stray echo the
     * power to close the Vault. The exemption rests on those two, NOT on the
     * divider being unreachable under a view - `movePaneLeafToEdge` above gave
     * up exactly that argument, because §4.26b says an unreachability claim is
     * only ever as good as the enumeration of affordances behind it.
     */
    const NOT_A_ROUTE_IN = ["setSplitSizes"];

    const declared = new Set([
      ...Object.values(SHOWS_TABS).flat(),
      ...KEEPS_VIEW,
      ...NOT_A_ROUTE_IN,
    ]);
    /** Every declaration name the scan found, across both swept files. */
    const swept = new Map<string, Map<string, string>>();
    const allImports = new Set<string>();
    for (const file of Object.keys(SHOWS_TABS)) {
      const short = file.split("/").pop();
      const src = stripComments(read(file));
      const bodies = callbackBodies(src);
      swept.set(file, bodies);
      const imports = panesImports(src);
      for (const n of imports) allImports.add(n);
      check(
        // Non-vacuity: a parse that finds nothing classifies nothing, and the
        // derived regex below would fall back to its two structural clauses
        // without a word. Both files import from `panes.ts` today.
        `the panes.ts import list in ${short} parsed`,
        imports.length > 0,
        imports,
      );
      check(
        // THE fix for the hardcoded regex: an import nobody classified is a call
        // the sweep cannot see. Fails by name, so the answer is "add it to a
        // list", not "notice it".
        `every panes.ts import in ${short} is classified as a tree write or not`,
        imports.every((n) => CLASSIFIED.has(n)),
        imports.filter((n) => !CLASSIFIED.has(n)),
      );
      const TREE_WRITE = treeWriteFor(imports);
      for (const name of SHOWS_TABS[file]) {
        const body = bodies.get(name);
        check(`${name} is still declared in ${short}`, body !== undefined, [...bodies.keys()]);
        check(
          `${name} writes a pane tree - the reason it is on this list`,
          body !== undefined && TREE_WRITE.test(body),
        );
        check(
          `${name} shows the tabs, so its result is not applied behind a rail view`,
          body !== undefined && (/\bsetActiveId\(/.test(body) || /\bshowTabs\(/.test(body)),
        );
      }
      // THE CLOSURE. Every pane-tree writer must be spoken for; a new one that
      // is not fails here by name. This is the check the round before this one
      // did not have, and its absence is the whole of §4.29.
      const treeWriters = [...bodies.entries()]
        .filter(([, b]) => TREE_WRITE.test(b))
        .map(([n]) => n);
      check(
        `the scan of ${short} found its known pane-tree writers, so it is not empty`,
        treeWriters.length >= SHOWS_TABS[file].length,
        treeWriters,
      );
      check(
        `no pane-tree write in ${short} is unaccounted for`,
        treeWriters.every((n) => declared.has(n)),
        treeWriters.filter((n) => !declared.has(n)),
      );
    }
    check(
      // And the other direction, so the three lists cannot rot into a museum of
      // names `panes.ts` no longer exports. A stale entry is worse than a
      // missing one: it reads as coverage while covering a call that no longer
      // happens, and it is the only way the classification can drift now that
      // the import list drives it.
      "every name the three lists classify is actually imported by a swept file",
      [...CLASSIFIED].every((n) => allImports.has(n)),
      [...CLASSIFIED].filter((n) => !allImports.has(n)),
    );
    const tabsOnlyBodies =
      swept.get("src/modules/tabs/lib/useTabs.ts") ?? new Map<string, string>();
    const TABS_TREE_WRITE = treeWriteFor(panesImports(tabsSrc));
    for (const name of NOT_A_ROUTE_IN) {
      const body = tabsOnlyBodies.get(name);
      check(`${name} is still declared in useTabs`, body !== undefined);
      check(`${name} writes a pane tree`, body !== undefined && TABS_TREE_WRITE.test(body));
      check(
        `${name} deliberately does NOT show the tabs`,
        body !== undefined && !/\bsetActiveId\(/.test(body) && !/\bshowTabs\(/.test(body),
      );
    }
    // ONE MORE WAY OUT, and it is the reason `useAuxTabs` is swept rather than
    // argued about: a writer that `useTabs` returns but does not DECLARE. The
    // scan above reads declarations, and `const { openBoardTab, newRdpTab,
    // openPageTab } = useAuxTabs(...)` declares none of them - so those three
    // were returned from the same api, wrote pane trees, and appeared in no
    // sweep at all. Every key the hook returns must therefore be a name found in
    // one of the swept files, or one of the three pieces of STATE it returns.
    const RETURNED_STATE = ["tabs", "activeId", "railView"];
    const returned = (() => {
      const at = tabsSrc.lastIndexOf("\n  return {");
      if (at === -1) return [];
      return [...tabsSrc.slice(at).matchAll(/\n {4}(\w+),/g)].map((m) => m[1]);
    })();
    const found = new Set([...swept.values()].flatMap((b) => [...b.keys()]));
    check("found the useTabs return object to scan", returned.length > 20, returned.length);
    check(
      "every callback useTabs returns was declared in a file this sweep reads",
      returned.every((n) => found.has(n) || RETURNED_STATE.includes(n)),
      returned.filter((n) => !found.has(n) && !RETURNED_STATE.includes(n)),
    );
  }

  // ---- 8c. the two CLOSING chords refuse while a view is up --------------
  // The one place the rule is enforced at the chord rather than at the
  // mutation, and it has to be: `closeTab` / `closePaneByLeaf` are shared with
  // the tab-strip X, which names the tab it closes, is on screen, and must keep
  // leaving the user in the view. A chord names "the active tab", which is
  // exactly what the view has taken off screen - so it does nothing instead of
  // ending a session with no feedback.
  //
  // Source-text: `shortcutHandlers.ts` imports through the `@/` alias, which
  // this suite has no bundler to resolve. Weaker than driving the handler.
  console.log("\n[chords] a closing chord does nothing while a rail view covers the tabs");
  {
    const src = stripQuotesAwareComments(read("src/app/lib/shortcutHandlers.ts"));
    /** The body of the `"<id>": ...` entry, up to the next handler key. */
    const handlerBody = (id: string): string | null => {
      const at = src.indexOf(`"${id}": `);
      if (at === -1) return null;
      const rest = src.slice(at);
      const next = /\n\s{4}(?:\/|"[a-zA-Z]+\.)/.exec(rest.slice(1));
      return next ? rest.slice(0, next.index + 1) : rest;
    };
    /**
     * FUNCTION NAMES WHOSE CALL ENDS A SESSION - not "the deps the two close
     * chords happen to take". That is what this was, and the difference is the
     * whole value of the closure below: a new chord wired straight to
     * `closePaneByLeaf` rather than to `requestCloseLeaf` destroys exactly the
     * same pane and matched nothing here, so it passed.
     *
     * So: the two App-side close funnels, plus the three mutations underneath
     * them. A chord may reach any of the five - through App or by taking the
     * `useTabs` api directly - and each ends something a rail view has taken off
     * screen, which is the property the guard is about.
     */
    const DESTRUCTIVE = [
      "handleCloseTabOrPane",
      "requestCloseLeaf",
      "handleClose",
      "closePaneByLeaf",
      "closeTab",
      "disposeTab",
    ];
    const CLOSING_CHORDS = ["tab.close", "terminal.close"];
    for (const id of CLOSING_CHORDS) {
      const body = handlerBody(id);
      check(`found the ${id} handler`, body !== null);
      check(
        `${id} asks whether a rail view is covering the tabs`,
        body !== null && /coveredByRailView\(\)/.test(body),
        body,
      );
      check(
        `${id} returns on that answer rather than closing anyway`,
        body !== null && /if \(coveredByRailView\(\)\) return;/.test(body),
      );
      check(
        `${id} still calls its close dep when it is not covered`,
        body !== null && DESTRUCTIVE.some((d) => new RegExp(`\\b${d}\\(`).test(body)),
      );
    }
    check(
      "the refusal reads the railView dep, so it cannot be a constant",
      /railView !== null/.test(src) && /railView,/.test(src),
    );
    // Closure: no OTHER chord may reach a destructive dep without the guard.
    // Written as a scan of the whole handler map rather than a list of the two
    // ids, so a third closing chord added later fails here.
    const guarded = new Set(CLOSING_CHORDS);
    const handlerIds = [...src.matchAll(/\n\s{4}"([a-zA-Z]+\.[a-zA-Z]+)":/g)].map((m) => m[1]);
    check("found the handler map to scan", handlerIds.length > 10, handlerIds.length);
    const unguarded = handlerIds.filter((id) => {
      if (guarded.has(id)) return false;
      const body = handlerBody(id) ?? "";
      return DESTRUCTIVE.some((d) => new RegExp(`\\b${d}\\(`).test(body));
    });
    check(
      "no other chord calls a close dep without the rail-view guard",
      unguarded.length === 0,
      unguarded,
    );
    // And the constructive chords must NOT carry it: they leave the view
    // through `useTabs` and show the user their own result, so a guard here
    // would turn Ctrl+T back into the "does nothing at all" this item opened
    // with. The negative half of the refusal (§4.30).
    for (const id of ["tab.new", "pane.splitRight", "pane.splitDown", "pane.focusNext"]) {
      const body = handlerBody(id);
      check(`found the ${id} handler`, body !== null);
      check(
        `${id} does NOT refuse under a rail view - it clears it instead`,
        body !== null && !/coveredByRailView/.test(body),
        body,
      );
    }
  }

  const setViewWriters = [...tabsBodies.entries()]
    .filter(([, b]) => /\bsetView\(/.test(b))
    .map(([n]) => n);
  check(
    "the raw view setter is written only by the four funnels",
    setViewWriters.length === FUNNELS.length && setViewWriters.every((n) => FUNNELS.includes(n)),
    setViewWriters,
  );
  check(
    "the view is one piece of state, so a tab cannot activate behind it",
    /useState<TabView>\(/.test(tabsSrc),
  );
  check(
    "and the aux openers get the funnel, not a raw setter",
    !/\bsetView\(/.test(stripComments(read("src/modules/tabs/lib/useAuxTabs.ts"))),
  );

  // App must no longer own it: as component state, clearing it was the caller's
  // job, and that is the bug.
  const appSrc = stripComments(read("src/app/App.tsx"));
  check("App holds no rail-view state of its own", !/setRailView/.test(appSrc));
  check("nor a useState for it", !/useState<RailViewKind/.test(appSrc));
  check(
    "and no tab action is wrapped to clear it by hand",
    !/openPageTabInTabs/.test(appSrc) && !/showTabs\(\);/.test(appSrc),
  );

  // The three cold-restore call sites. Also source-text, and for the same reason
  // §5.26 gives: the index defect was never in the helper - the helper was right
  // and two of its three callers did the arithmetic themselves. A behavioural
  // check on `restoreWorkspaceEntry` cannot see a caller that stops asking it.
  const switching = stripComments(read("src/app/hooks/useWorkspaceSwitching.ts"));
  const persistence = stripComments(read("src/app/hooks/useWorkspacePersistence.ts"));
  const calls = (s: string) => (s.match(/restoreWorkspaceEntry\(/g) ?? []).length;
  check(
    "the switch path and the close path both restore through one call",
    calls(switching) === 2,
    calls(switching),
  );
  check("and so does the startup hydrate", calls(persistence) === 1, calls(persistence));
  check(
    "no cold-restore caller reads the raw saved index any more",
    !/\.activeTabIndex/.test(switching) && !/\.activeTabIndex/.test(persistence),
  );
  check(
    "nor clamps an index against the restored tab list",
    !/Math\.min\(/.test(switching) && !/Math\.min\(/.test(persistence),
  );
}

// ---- 9. the chip's own click route --------------------------------------
// D-NAV1, and the reason this section exists at all: the table in section 7
// proves the funnel's ARITHMETIC, and a table cannot see a route that never
// calls it. It did not. With a rail view up, `activeKey` still names the tab
// underneath, so clicking that tab's own chip is not a value CHANGE - and the
// controlled Radix `Tabs` in `TabBar` only activates a trigger when
// `value !== context.value`. `focusTabView` was correct, unconditional in the
// id, and simply never reached. Clicking the HOSTS chip first worked, and only
// then did the terminal's chip respond.
//
// Two halves, because one alone would have passed before the fix. The click
// route is EXECUTED (§5 decision 17: pin the expression, not the name) and then
// fed through the real `focusTabView`; and the wiring - which is the part that
// was missing, and which no behavioural check on a leaf module can see - is
// pinned in the source of the two components that carry it.
console.log("\n[chip] a chip selects its own entry, even when it is already the active one");
{
  // Same idiom as section 7, and non-vacuity is pinned there: an emptied
  // `RAIL_VIEW_KINDS` would leave only the `null` row here too.
  const RAIL: (RailViewKind | null)[] = [null, ...RAIL_VIEW_KINDS];

  // ---- 9(i) executed: the handler, then the funnel it hands off to -------
  // A terminal leaf whose key is exactly what `TabBar`'s `activeKey` computes
  // for the active pane tab (`leaf-${activeLeafId}`). That is the fixture the
  // defect lives in: every OTHER chip always worked, because for those the
  // value genuinely changed.
  const leafEntry: PaneEntry = {
    kind: "pane-leaf",
    key: "leaf-42",
    tabId: 7,
    leafId: 42,
    leafKind: "terminal",
    label: "zsh",
    renameSeed: "zsh",
  };
  const activeKey = `leaf-${leafEntry.leafId}`;
  check(
    // Non-vacuity, and it is the whole point of the fixture: if this stopped
    // being the active chip, every assertion below would run against the case
    // that never broke.
    "the fixture chip is the one activeKey already names",
    leafEntry.key === activeKey,
    { key: leafEntry.key, activeKey },
  );

  const calls: { tabId: number; leafId: number | null }[] = [];
  const spy: SelectEntry = (tabId, leafId) => {
    calls.push({ tabId, leafId });
  };
  entrySelectHandlers(leafEntry, spy).onClick();
  check("clicking it calls onSelectEntry exactly once", calls.length === 1, calls);
  check("with its own tab id", calls[0]?.tabId === leafEntry.tabId, calls[0]);
  check("and its own leaf id", calls[0]?.leafId === leafEntry.leafId, calls[0]);
  const leafTarget = entrySelectTarget(leafEntry);
  check(
    // ONE expression for both routes. Asserted rather than assumed, because the
    // pair was hand-written at each call site before, which is how they were
    // free to drift.
    "and the pair it passed is the one entrySelectTarget names",
    calls[0]?.tabId === leafTarget.tabId && calls[0]?.leafId === leafTarget.leafId,
    { click: calls[0], target: leafTarget },
  );
  // `?? -1` so a handler that never fired fails the rows below rather than
  // throwing a TypeError out of the whole section - which would take 9(ii),
  // the source-text half, down with it and report nothing about the wiring.
  const clickedTabId = calls[0]?.tabId ?? -1;
  for (const railView of RAIL) {
    // The spied id, through the REAL funnel: the click is only a fix if what it
    // reaches leaves the view. `activeId` starts as the chip's own tab, which is
    // the state the defect happened in.
    const next = focusTabView({ activeId: leafEntry.tabId, railView }, clickedTabId);
    check(
      `chip click over ${railView ?? "no view"}: the tabs are showing`,
      next.railView === null,
      next,
    );
    check(
      `chip click over ${railView ?? "no view"}: its own tab is active`,
      next.activeId === leafEntry.tabId,
      next,
    );
  }

  // The standalone arm, so `leafId` cannot come back 0 or undefined for a tab
  // that has no leaves - `onCloseEntry` and `onSelectEntry` both read `null` as
  // "the whole tab".
  const boardEntry: Entry = { kind: "board", key: "tab-9", tabId: 9, label: "Board" };
  const boardCalls: { tabId: number; leafId: number | null }[] = [];
  entrySelectHandlers(boardEntry, (tabId, leafId) => {
    boardCalls.push({ tabId, leafId });
  }).onClick();
  check("a standalone chip selects its tab", boardCalls[0]?.tabId === boardEntry.tabId, boardCalls);
  check("with no leaf at all, not leaf 0", boardCalls[0]?.leafId === null, boardCalls);
  check("and entrySelectTarget agrees", entrySelectTarget(boardEntry).leafId === null);

  // ---- 9(ii) source text: the wiring is what was missing -----------------
  // VLT-83: these are POSITIVE checks over `.tsx` files, so they run on
  // `stripTsxComments` - the line-based stripper would let a deletion pass by
  // leaving the code behind as a JSX comment expression.
  const bodySrc = stripTsxComments(read("src/modules/tabs/components/renderEntryBody.tsx"));
  const barSrc = stripTsxComments(read("src/modules/tabs/TabBar.tsx"));

  /**
   * The text of `<Tag ...>`'s OPENING TAG, brace- and quote-aware.
   *
   * Not "up to the first `>`": every arrow function in a prop
   * (`onDoubleClick={() => {`) contains one, and the tag would be cut off before
   * the props this section is about. The depth counter matters for the ORDER
   * check below too - the assertion is about where inside the tag the spread
   * sits, so the slice has to be the whole tag and nothing after it.
   */
  const openingTag = (src: string, tag: string): string | null => {
    const at = src.indexOf(`<${tag}`);
    if (at === -1) return null;
    let depth = 0;
    let quote = "";
    for (let i = at; i < src.length; i++) {
      const c = src[i];
      if (quote) {
        if (c === "\\") i++;
        else if (c === quote) quote = "";
        continue;
      }
      if (c === '"' || c === "'" || c === "`") quote = c;
      else if (c === "{") depth++;
      else if (c === "}") depth--;
      else if (c === ">" && depth === 0) return src.slice(at, i + 1);
    }
    return null;
  };

  /** The braced value of prop `name`, brace-matched and quote-aware. */
  const propValue = (src: string, name: string): string | null => {
    const start = src.indexOf(`${name}={`) === -1 ? -1 : src.indexOf("{", src.indexOf(`${name}={`));
    if (start === -1) return null;
    let depth = 0;
    let quote = "";
    for (let i = start; i < src.length; i++) {
      const c = src[i];
      if (quote) {
        if (c === "\\") i++;
        else if (c === quote) quote = "";
        continue;
      }
      if (c === '"' || c === "'" || c === "`") quote = c;
      else if (c === "{") depth++;
      else if (c === "}" && --depth === 0) return src.slice(start, i + 1);
    }
    return null;
  };

  const triggerTag = openingTag(bodySrc, "TabsTrigger");
  check(
    // Non-vacuity: a slice that found nothing satisfies no positive below by
    // failing them all, but a slice that found the WRONG element would.
    "found the TabsTrigger opening tag to scan",
    triggerTag !== null && /value=\{e\.key\}/.test(triggerTag),
    triggerTag === null ? null : triggerTag.slice(0, 80),
  );
  const spreadAt = triggerTag === null ? -1 : triggerTag.indexOf("entrySelectHandlers(");
  check("the trigger spreads entrySelectHandlers", spreadAt >= 0, triggerTag);
  check(
    // A BARE spread. The fix is only a fix if it is unconditional: wrapped in
    // `renaming ? ... :` or `isDragging && ...` it goes back to being a chip
    // that sometimes does nothing, which is the defect.
    "as a bare spread, with no condition in front of it",
    spreadAt > 0 && /\{\s*\.\.\.\s*$/.test(triggerTag!.slice(0, spreadAt)),
    triggerTag === null ? null : triggerTag.slice(Math.max(0, spreadAt - 60), spreadAt),
  );
  check(
    // Exactly one, so a guarded second copy cannot sit beside the bare one and
    // satisfy the check above while shadowing it.
    "and exactly once in the tag",
    (triggerTag?.match(/entrySelectHandlers/g) ?? []).length === 1,
    triggerTag,
  );
  const dragAttrsAt = triggerTag === null ? -1 : triggerTag.indexOf("...(dragAttrs");
  const dragListenersAt = triggerTag === null ? -1 : triggerTag.indexOf("...(dragListeners");
  check("the two drag spreads are still on the trigger", dragAttrsAt >= 0 && dragListenersAt >= 0, {
    dragAttrsAt,
    dragListenersAt,
  });
  check(
    // dnd-kit's attributes are a plain object. Spread AFTER this handler, one of
    // them silently overwrites `onClick` and the chip is inert again - with
    // every behavioural check in 9(i) still green, because the leaf module is
    // untouched.
    "and the select handler is spread after both, so neither can clobber it",
    spreadAt > dragAttrsAt && spreadAt > dragListenersAt,
    { dragAttrsAt, dragListenersAt, spreadAt },
  );

  const renameSpan = (() => {
    const at = bodySrc.indexOf("<InlineInput");
    if (at === -1) return null;
    const open = bodySrc.lastIndexOf("<span", at);
    return open === -1 ? null : bodySrc.slice(open, at);
  })();
  check(
    "found the inline rename field's wrapper span",
    renameSpan !== null && /onPointerDown=\{\(ev\) => ev\.stopPropagation\(\)\}/.test(renameSpan),
    renameSpan,
  );
  check(
    // The one place an unconditional trigger handler is wrong, and it is fixed
    // at the field rather than in the handler: clicking into the rename field
    // must not activate the tab and throw the user out of the rail view they
    // opened the rename from.
    "which stops the click too, so renaming does not navigate",
    renameSpan !== null && /onClick=\{\(ev\) => ev\.stopPropagation\(\)\}/.test(renameSpan),
    renameSpan,
  );

  const groupTag = openingTag(barSrc, "SortableTabGroup");
  check(
    "found the SortableTabGroup element to scan",
    groupTag !== null && /entries=\{group\.entries\}/.test(groupTag),
    groupTag === null ? null : groupTag.slice(0, 80),
  );
  check(
    // The thread. Without it the leaf module is correct, imported, and reaches
    // no chip.
    "TabBar hands onSelectEntry to every group, so the chips have a route of their own",
    groupTag !== null && /onSelectEntry=\{onSelectEntry\}/.test(groupTag),
    groupTag,
  );

  const onValueChange = propValue(barSrc, "onValueChange");
  check(
    "found TabBar's onValueChange to scan",
    onValueChange !== null && /entries\.find\(/.test(onValueChange),
    onValueChange,
  );
  check(
    // Both routes through one expression. Radix's route survives for the
    // keyboard, so a second hand-written `entry.kind === "pane-leaf" ? ... :
    // null` here is a second place to get a standalone tab's `null` wrong.
    "onValueChange resolves its target through entrySelectTarget",
    onValueChange !== null && /entrySelectTarget\(/.test(onValueChange),
    onValueChange,
  );
  check(
    "and keeps none of its own kind test, so the two routes cannot drift",
    onValueChange !== null && !/pane-leaf/.test(onValueChange),
    onValueChange,
  );
  check(
    "and still bails on a key no entry has",
    onValueChange !== null && /if \(!entry\) return;/.test(onValueChange),
    onValueChange,
  );
}

if (failed > 0) throw new Error(`${failed} check(s) FAILED`);
console.log("\nALL PASS");
