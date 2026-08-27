/**
 * Self-check for DCR-1: Vault and Port Forwarding are rail VIEWS, not tabs.
 * Run: `npx tsx scripts/rail-views-verify.ts`.
 *
 * Two things worth pinning down, and the second is the one that bites:
 *
 *  1. The page union is PARTITIONED. Every `PageKind` is either the one page that
 *     may be a tab leaf or a rail view - never both, never neither. Adding a
 *     fourth page without saying which it is fails here rather than producing a
 *     rail button that opens nothing.
 *  2. MIGRATION. A workspace snapshotted before this change can hold a `vault`
 *     or `forwards` page leaf, and every arrangement of one has to come back
 *     sensibly: the leaf dropped, the tab dropped if that empties it, a split
 *     collapsed around it, the whole workspace falling back to Hosts if nothing
 *     survives, and the restored active-tab index re-based onto what is left -
 *     otherwise restore focuses a tab the user was not looking at, or the strip
 *     shows a Vault tab that the rail, `openPageTab` and `PageLeafBody` have all
 *     stopped believing in.
 */
import {
  isRailViewKind,
  isTabPageKind,
  RAIL_VIEW_KINDS,
  TAB_PAGE_KIND,
} from "../src/modules/tabs/lib/pages";
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
  isRailViewLeaf,
  restoreSavedTabs,
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

function savedPage(page: PageKind): SavedPaneNode {
  return { kind: "leaf", leafKind: "page", page };
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

// ---- 2. which saved leaves restore ---------------------------------------
console.log("\n[saved] a rail-view page leaf is recognised, a Hosts one is not");
check("a saved vault leaf is a rail-view leaf", isRailViewLeaf(savedPage("vault")));
check("a saved forwards leaf is a rail-view leaf", isRailViewLeaf(savedPage("forwards")));
check("a saved hosts leaf is NOT", !isRailViewLeaf(savedPage("hosts")));
check("nor is a terminal leaf", !isRailViewLeaf(savedTerm()));
check("nor is a split", !isRailViewLeaf(savedSplit([savedTerm(), savedTerm()])));

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

if (failed > 0) throw new Error(`${failed} check(s) FAILED`);
console.log("\nALL PASS");
