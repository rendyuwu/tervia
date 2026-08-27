import { findLeaf, leaves, type PaneLeaf } from "@/modules/terminal/lib/panes";
import { countTabEntries } from "./entries";
import { type Tab } from "./tabTypes";

/**
 * WHETHER A LEAF MAY BE CLOSED - the whole rule, in one place.
 *
 * Two invariants, and they are separate reasons that happen to share a gate:
 *
 *  1. A PAGE LEAF IS PERMANENT. Hosts is the only page that is a tab (see
 *     `./pages.ts`), it is the workspace's entry point, and it holds no session
 *     that closing would end - so there is nothing to gain by closing it and a
 *     dead end to reach if you do. It is refused regardless of what else is
 *     open, which is the part a "last entry" rule alone does not give: with a
 *     terminal beside it, the tab-strip X used to close Hosts quite happily.
 *  2. THE LAST ENTRY IS PERMANENT. Closing the only thing on screen would leave
 *     an empty window. This mirrors what `closePaneByLeaf` has always refused;
 *     it is stated here so every close path asks the same question instead of
 *     one path blocking what another allows.
 *
 * Three close paths must consult this and refuse identically - the tab-strip X,
 * the pane-header X, and `Ctrl+Shift+X` - and a refusal has to be VISIBLE where
 * a button exists: both X buttons are not rendered rather than rendered dead.
 * The chord may no-op silently only because the buttons for the same close are
 * absent, so the user is never told two different things.
 *
 * Enforced twice on purpose: the render gates above keep the affordance honest,
 * and `useTabs`' `closePaneByLeaf` / `closeTab` re-check at the mutation itself,
 * so a caller that never looked cannot bypass the rule.
 */
export type CloseRefusal =
  /** No leaf with that id. Nothing to close, so nothing is offered. */
  | "unknown-leaf"
  /** A page leaf (Hosts). Invariant 1. */
  | "permanent-page"
  /** The only entry left in the workspace. Invariant 2. */
  | "last-entry";

/** The owning tab's leaf, or null when no tab holds `leafId`. */
function leafInTabs(tabs: Tab[], leafId: number): PaneLeaf | null {
  for (const t of tabs) {
    if (t.kind !== "pane") continue;
    const leaf = findLeaf(t.paneTree, leafId);
    if (leaf) return leaf;
  }
  return null;
}

/** Why closing `leafId` is refused, or `null` when it is allowed. */
export function leafCloseRefusal(tabs: Tab[], leafId: number): CloseRefusal | null {
  const leaf = leafInTabs(tabs, leafId);
  if (!leaf) return "unknown-leaf";
  // Every page leaf, not "the leaf whose page is hosts": Hosts is the only page
  // that can BE a leaf, so the two are the same set, and asking by leafKind
  // keeps this from silently permitting a leaf a future page kind introduces.
  if (leaf.leafKind === "page") return "permanent-page";
  if (countTabEntries(tabs) <= 1) return "last-entry";
  return null;
}

export function canCloseLeaf(tabs: Tab[], leafId: number): boolean {
  return leafCloseRefusal(tabs, leafId) === null;
}

/**
 * Why closing the WHOLE tab `tabId` is refused, or `null` when it is allowed.
 *
 * A tab close takes every leaf in it, so it is refused when any one of them is
 * permanent - closing the tab is not a way around invariant 1. `Ctrl+W` on a
 * single-pane tab and the pane-header X on the last pane in its tab both land
 * here rather than on `leafCloseRefusal`, which is exactly how the Hosts tab
 * used to be closable from the pane header while the strip hid its X.
 */
export function tabCloseRefusal(tabs: Tab[], tabId: number): CloseRefusal | null {
  const tab = tabs.find((t) => t.id === tabId);
  if (!tab) return "unknown-leaf";
  if (tab.kind === "pane" && leaves(tab.paneTree).some((l) => l.leafKind === "page")) {
    return "permanent-page";
  }
  if (tabs.length <= 1) return "last-entry";
  return null;
}

export function canCloseTab(tabs: Tab[], tabId: number): boolean {
  return tabCloseRefusal(tabs, tabId) === null;
}
