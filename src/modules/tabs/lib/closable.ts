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

/**
 * WHETHER A LEGAL CLOSE MUST BE CONFIRMED FIRST - the other half of the rule.
 *
 * The refusals above answer whether a close MAY happen. These answer whether it
 * may happen SILENTLY, and the two are asked in that order on every path:
 * prompting "close the running terminal?" for a close that will then be refused
 * is worse than the silent no-op it replaces.
 *
 * They live here, beside the refusals, because the same thing went wrong twice.
 * `closable.ts` exists because three close paths each carried their own copy of
 * "may this close" and answered differently; the confirmation was left behind in
 * exactly that state. `handleClose` asked about unsaved work AND a running
 * process. `requestCloseLeaf` asked only about the process and said so in a
 * comment - "Editor leaves always close without a prompt". So a dirty editor
 * prompted from the pane-header X of a single-pane tab and was discarded without
 * a word by the tab-strip leaf X, by that same header X on a split, and by
 * `Ctrl+Shift+X`. The chord is only how it was reported: removing its leaf-kind
 * test let it reach an editor for the first time, which surfaced a
 * disagreement the other two paths had been carrying all along.
 *
 * `isProcessRunning` is a parameter rather than something read here: whether a
 * terminal has a foreground command lives in the pane's imperative handle, not
 * in the tab state. Keeping it out is what leaves these pure, so the close
 * checks can run them over fixtures instead of asserting on source text.
 */
export type CloseConfirmReason =
  /** An editor leaf with unsaved edits. Closing it discards them - unrecoverable. */
  | "unsaved"
  /** A terminal leaf with a foreground process. Closing it kills the process. */
  | "running";

/** Holds work that closing would discard. */
function leafIsDirty(leaf: PaneLeaf): boolean {
  return leaf.leafKind === "editor" && leaf.dirty;
}

/** Has a foreground command in flight. */
function leafIsBusy(leaf: PaneLeaf, isProcessRunning: (leafId: number) => boolean): boolean {
  // The kind test is what makes this honest rather than accidental: only
  // terminal panes register a handle, so asking about any other leaf has always
  // answered `false` - by absence, not by rule.
  return leaf.leafKind === "terminal" && isProcessRunning(leaf.id);
}

/**
 * Why closing leaf `leafId` must be confirmed first, or `null` to close silently.
 *
 * Unsaved beats running for a leaf that is somehow both: discarding an edit
 * cannot be undone, and killing a process can be redone.
 */
export function leafCloseConfirmReason(
  tabs: Tab[],
  leafId: number,
  isProcessRunning: (leafId: number) => boolean,
): CloseConfirmReason | null {
  const leaf = leafInTabs(tabs, leafId);
  if (!leaf) return null;
  if (leafIsDirty(leaf)) return "unsaved";
  if (leafIsBusy(leaf, isProcessRunning)) return "running";
  return null;
}

/**
 * Why closing the WHOLE tab `tabId` must be confirmed first, or `null`.
 *
 * Asked of every leaf in the tab, exactly as `tabCloseRefusal` is and for the
 * same reason: a tab close takes all of them. The running half already swept the
 * tree; the unsaved half was read off `tab.dirty`, which `syncPaneMirror` copies
 * from the ACTIVE leaf alone - so a split whose unsaved editor was not the pane
 * you were looking at closed without a prompt.
 */
export function tabCloseConfirmReason(
  tabs: Tab[],
  tabId: number,
  isProcessRunning: (leafId: number) => boolean,
): CloseConfirmReason | null {
  const tab = tabs.find((t) => t.id === tabId);
  if (!tab || tab.kind !== "pane") return null;
  const all = leaves(tab.paneTree);
  if (all.some(leafIsDirty)) return "unsaved";
  if (all.some((l) => leafIsBusy(l, isProcessRunning))) return "running";
  return null;
}
