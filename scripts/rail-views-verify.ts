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
  const root = join(dirname(fileURLToPath(import.meta.url)), "..");
  const read = (p: string) => readFileSync(join(root, p), "utf8");
  /** Comments stripped so a doc comment naming a call is not read AS one. (The
   *  third copy of this helper in the suite - VLT-33.) */
  const stripComments = (s: string) =>
    s.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
  /**
   * Each `const NAME = useCallback(...)` body, keyed by name. The chunk runs to
   * the next such declaration, which is enough here: both files are one flat
   * list of a hook's top-level callbacks.
   */
  const callbackBodies = (src: string): Map<string, string> => {
    const marks: { name: string; at: number }[] = [];
    const re = /\n\s*const (\w+) = useCallback\(/g;
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
   * Every mutation in `useTabs` that activates a tab, mints one, or moves focus
   * inside one - i.e. every route INTO the tab area. Each must funnel; the
   * closure check below then proves the list is complete, because a new mutation
   * that writes `activeId` and is not named here fails.
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

if (failed > 0) throw new Error(`${failed} check(s) FAILED`);
console.log("\nALL PASS");
