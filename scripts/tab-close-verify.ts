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
 */
import {
  canCloseLeaf,
  canCloseTab,
  leafCloseRefusal,
  tabCloseRefusal,
} from "../src/modules/tabs/lib/closable";
import { buildEntries, countTabEntries } from "../src/modules/tabs/lib/entries";
import type { Tab } from "../src/modules/tabs/lib/tabTypes";
import type { PaneNode } from "../src/modules/terminal/lib/panes";

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
function editorLeaf(id: number, path = "/w/a.ts"): PaneNode {
  return { kind: "leaf", id, leafKind: "editor", path, dirty: false, preview: false };
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

if (failed > 0) throw new Error(`${failed} check(s) FAILED`);
console.log("\nALL PASS");
