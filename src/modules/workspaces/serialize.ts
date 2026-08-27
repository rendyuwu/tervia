import { isTabPageKind, TAB_PAGE_KIND, type PaneTab, type Tab } from "@/modules/tabs";
import type { PaneLeaf, PaneNode } from "@/modules/terminal/lib/panes";
import { leaves, PAGE_LABELS } from "@/modules/terminal/lib/panes";
import { useTerminalTitles } from "@/modules/terminal/lib/terminalTitles";
import type { SavedPaneNode, SavedTab } from "./store";

/** Count terminal leaves in a serialised pane tree. Used to tally
 *  terminals across inactive workspaces without rehydrating them into
 *  live `Tab[]` objects. */
export function countSavedTerminalLeaves(node: SavedPaneNode): number {
  if (node.kind === "leaf") {
    return node.leafKind === "terminal" ? 1 : 0;
  }
  let n = 0;
  for (const child of node.children) n += countSavedTerminalLeaves(child);
  return n;
}

/** Tab-strip entry count for a serialised (unvisited) workspace: every leaf of
 *  each pane tab plus one per standalone (preview) tab. Mirrors the live
 *  `countTabEntries` so the badge stays consistent once the workspace is
 *  opened - a multi-pane group tab counts as its panes, not 1, and a rail-view
 *  page leaf from an older snapshot counts as none, because opening the
 *  workspace drops it (see {@link isUnrestorablePageLeaf}). */
export function countSavedTabEntries(tabs: SavedTab[]): number {
  let n = 0;
  for (const t of tabs) n += t.kind === "pane" ? countRestorableLeaves(t.paneTree) : 1;
  return n;
}

// live -> saved

function leafToSaved(leaf: PaneLeaf): SavedPaneNode {
  if (leaf.leafKind === "terminal") {
    // Capture the live program title (OSC 0/2) so an inactive workspace still
    // shows it next to the folder name. Read straight from the singleton title
    // store (same store the live rows use).
    const title = useTerminalTitles.getState().titles[leaf.id];
    return {
      kind: "leaf",
      leafKind: "terminal",
      cwd: leaf.cwd,
      sshConnectionId: leaf.sshConnectionId,
      terminalOrdinal: leaf.terminalOrdinal,
      ...(leaf.customTitle ? { customTitle: leaf.customTitle } : {}),
      ...(leaf.terminalThemeId ? { terminalThemeId: leaf.terminalThemeId } : {}),
      ...(title ? { title } : {}),
      // Only local PTYs use the daemon backend; SSH leaves carry their
      // remote session id separately and aren't restored via pty_attach.
      ...(leaf.ptyId && !leaf.sshConnectionId ? { ptyId: leaf.ptyId } : {}),
      // Persist the running agent kind only for reattachable local leaves
      // (same gate as ptyId). On restore it pre-activates the detector so a
      // still-running agent's badge survives.
      ...(leaf.activeTool && leaf.ptyId && !leaf.sshConnectionId
        ? { activeTool: leaf.activeTool }
        : {}),
    };
  }
  if (leaf.leafKind === "editor") {
    return {
      kind: "leaf",
      leafKind: "editor",
      path: leaf.path,
      // Only the STABLE half of a remote binding is persisted. `sshSessionId`
      // is deliberately dropped: see `isUnrestorableEditorLeaf`.
      ...(leaf.sshConnectionId ? { sshConnectionId: leaf.sshConnectionId } : {}),
      ...(leaf.sshConnectionId && leaf.sshHostLabel ? { sshHostLabel: leaf.sshHostLabel } : {}),
      ...(leaf.customTitle ? { customTitle: leaf.customTitle } : {}),
    };
  }
  if (leaf.leafKind === "rdp") {
    // A reference and a size mode, nothing else. There is no live session id to
    // persist: an RDP session cannot be reattached, so the restored leaf dials
    // again - the same UX a restored SSH leaf has, for the same reason.
    return {
      kind: "leaf",
      leafKind: "rdp",
      rdpConnectionId: leaf.rdpConnectionId,
      sizeMode: leaf.sizeMode,
      ...(leaf.customTitle ? { customTitle: leaf.customTitle } : {}),
    };
  }
  if (leaf.leafKind === "board") {
    // Board: restorable from nothing but its own existence, since the columns
    // are rebuilt from the live tab tree.
    return {
      kind: "leaf",
      leafKind: "board",
      ...(leaf.customTitle ? { customTitle: leaf.customTitle } : {}),
    };
  }
  // Page: restorable from nothing but which page it is - same as Board.
  if (leaf.leafKind === "page") {
    return {
      kind: "leaf",
      leafKind: "page",
      page: leaf.page,
      ...(leaf.customTitle ? { customTitle: leaf.customTitle } : {}),
    };
  }
  // Unreachable through the types - every live leaf kind is handled above - but
  // this used to be where the `page` branch sat, unguarded, so a leaf kind from a
  // build whose union was WIDER (the `browser` pane up to v0.4.22, reached by a
  // downgrade or a hand-edited file) was saved as a page leaf with no page. That
  // is the one thing it must not become: restore drops a page value it cannot
  // render, and before that it restored the leaf as a permanent, unclosable Hosts
  // tab nothing had asked for. Saved as a terminal instead - what RESTORE turns an
  // unrecognised SAVED leaf into - so the tree's shape and the user's name for the
  // pane both survive.
  const unknown = leaf as PaneLeaf;
  return {
    kind: "leaf",
    leafKind: "terminal",
    ...(unknown.customTitle ? { customTitle: unknown.customTitle } : {}),
  };
}

/**
 * True for a remote editor leaf that has nothing stable to come back as: an
 * AD-HOC connection, identified only by a LIVE russh session number that is
 * dead in a later launch (and, since the counter restarts at 1, may then name a
 * different host entirely). There is no saved profile to reconnect to, so the
 * leaf is dropped and its siblings kept.
 *
 * A leaf carrying `sshConnectionId` round-trips instead: the connection id is
 * stable across restarts and the pane re-resolves it to a live session, holding
 * the file unread until then. What must never happen is a remote leaf restored
 * as a LOCAL one, which is what a naive persist did: `useDocument` routed
 * through SFTP only while a session id was set, so the remote path was read
 * from, and on the next save written to, the local filesystem.
 */
function isUnrestorableEditorLeaf(leaf: PaneLeaf): boolean {
  return (
    leaf.leafKind === "editor" &&
    leaf.sshSessionId !== undefined &&
    leaf.sshConnectionId === undefined
  );
}

/** Serialises a pane subtree, pruning leaves that cannot be restored.
 *  Returns null when nothing in this subtree survives. */
function nodeToSaved(node: PaneNode): SavedPaneNode | null {
  if (node.kind === "leaf") return isUnrestorableEditorLeaf(node) ? null : leafToSaved(node);
  const children: SavedPaneNode[] = [];
  for (const c of node.children) {
    const s = nodeToSaved(c);
    if (s !== null) children.push(s);
  }
  if (children.length === 0) return null;
  // A lone survivor collapses into its parent: a one-child split is not a
  // valid pane tree.
  if (children.length === 1) return children[0];
  // Only persist sizes that still match the child count (a split/close can
  // leave a stale-length array, and pruning above invalidates the ratios);
  // a mismatch restores as an equal split.
  const pruned = children.length !== node.children.length;
  return {
    kind: "split",
    dir: node.dir,
    children,
    ...(!pruned && node.sizes && node.sizes.length === children.length
      ? { sizes: node.sizes }
      : {}),
  };
}

/**
 * True for exactly the tabs `tabToSaved` emits. A pane tab whose every leaf is
 * an ad-hoc remote editor has nothing left to save.
 *
 * Single source of truth for "which tabs are saved", shared by `tabToSaved`
 * and `savedActiveTabIndex` so the saved active-index can't drift from the
 * saved array.
 */
function isPersistedTab(tab: Tab): tab is PaneTab {
  if (tab.kind !== "pane") return false;
  return leaves(tab.paneTree).some((l) => !isUnrestorableEditorLeaf(l));
}

function tabToSaved(tab: Tab): SavedTab | null {
  if (!isPersistedTab(tab)) return null;
  const paneTree = nodeToSaved(tab.paneTree);
  // isPersistedTab already proved at least one leaf survives; this narrows.
  if (paneTree === null) return null;
  // Index within the leaves that were actually SAVED, not the live ones: a
  // pruned remote editor shifts every later leaf. A dropped active leaf lands
  // on the first survivor via the Math.max below.
  const kept = leaves(tab.paneTree).filter((l) => !isUnrestorableEditorLeaf(l));
  const idx = kept.findIndex((l) => l.id === tab.activeLeafId);
  return {
    kind: "pane",
    title: tab.title,
    paneTree,
    activeLeafIndex: Math.max(0, idx),
  };
}

/**
 * Index of the active tab within the serialized tab list (`serializeTabs`),
 * used to restore focus. Counts only persisted tabs preceding the active one,
 * so it stays aligned with the saved array even when a session-only
 * (ai-diff / git-diff / scm / ext) tab sits before the active tab. The former
 * per-call loops skipped only `ai-diff`, which mis-focused the restored
 * workspace whenever another session-only kind preceded the active tab.
 */
export function savedActiveTabIndex(tabs: Tab[], activeId: number): number {
  let idx = 0;
  for (const t of tabs) {
    if (t.id === activeId) break;
    if (isPersistedTab(t)) idx++;
  }
  return idx;
}

export function serializeTabs(tabs: Tab[]): SavedTab[] {
  const out: SavedTab[] = [];
  for (const t of tabs) {
    const s = tabToSaved(t);
    if (s !== null) out.push(s);
  }
  return out;
}

// saved -> live

/**
 * True for a saved page leaf that must NOT come back as a tab - which is every
 * page but Hosts, asked as "is it the tab page?" rather than "is it one of the
 * two rail views?".
 *
 * Two cases, and the second is why the question is put that way round:
 *
 *  - A `vault` or `forwards` leaf, which a snapshot from before DCR-1 can hold.
 *    Those pages are now views the rail shows over the tab area, so there is no
 *    such thing as a tab for one. Restoring it as a page leaf would put a tab in
 *    the strip that the rail's pressed state, `openPageTab` and `PageLeafBody`
 *    have all stopped believing in.
 *  - A page value THIS build does not recognise: a newer build's page, or a
 *    hand-edited state file. It used to be rewritten INTO Hosts, which silently
 *    minted a SECOND Hosts tab - and a page leaf is permanent (`closable.ts`
 *    invariant 1), so neither could then be closed. Enumerating the two known
 *    rail views left that case on the fallback path; naming the one page that
 *    may be a tab puts it on the drop path, where a page nothing in this build
 *    can render belongs.
 *
 * Dropped exactly like an unrestorable remote editor leaf: the leaf goes, its
 * siblings are kept, the tab goes with it if that empties it, and a workspace
 * emptied that way falls back to Hosts. Nothing is silently reinterpreted as a
 * page it never was.
 */
export function isUnrestorablePageLeaf(node: SavedPaneNode): boolean {
  return node.kind === "leaf" && node.leafKind === "page" && !isTabPageKind(node.page);
}

/** Restores a pane subtree, dropping leaves that must not come back (see
 *  {@link isUnrestorablePageLeaf}). Returns null when nothing in this subtree
 *  survives. Mirrors `nodeToSaved`'s pruning on the way out, collapse included. */
function savedToNode(
  node: SavedPaneNode,
  allocId: () => number,
  outLeafIds: number[],
): PaneNode | null {
  if (node.kind === "leaf") {
    if (isUnrestorablePageLeaf(node)) return null;
    const id = allocId();
    outLeafIds.push(id);
    if (node.leafKind === "terminal") {
      return {
        kind: "leaf",
        id,
        leafKind: "terminal",
        cwd: node.cwd,
        sshConnectionId: node.sshConnectionId,
        terminalOrdinal: node.terminalOrdinal,
        ...(node.terminalThemeId ? { terminalThemeId: node.terminalThemeId } : {}),
        // `savedPtyId` is the signal for `useTerminalSession.attachSession`
        // to attempt `reattachPty` before falling back to `openPty`. The
        // hot `ptyId` field is populated by the session itself on attach.
        ...(node.ptyId ? { savedPtyId: node.ptyId } : {}),
        // Pre-activate the detector for a still-running agent on reattach.
        ...(node.activeTool ? { activeTool: node.activeTool } : {}),
        ...(node.customTitle ? { customTitle: node.customTitle } : {}),
      };
    }
    if (node.leafKind === "editor") {
      return {
        kind: "leaf",
        id,
        leafKind: "editor",
        path: node.path,
        dirty: false,
        preview: false,
        // Remote leaves come back bound to the saved PROFILE only. No
        // `sshSessionId`: the pane resolves one from whichever session for this
        // connection is live, and shows a reconnect prompt until then, so an
        // unbound remote path can never reach the local filesystem.
        ...(node.sshConnectionId ? { sshConnectionId: node.sshConnectionId } : {}),
        ...(node.sshHostLabel ? { sshHostLabel: node.sshHostLabel } : {}),
        ...(node.customTitle ? { customTitle: node.customTitle } : {}),
      };
    }
    if (node.leafKind === "rdp") {
      // Reconnects fresh. There is nothing to reattach to, so the pane dials
      // the saved connection on mount - the same thing a restored SSH leaf
      // does, and the reason no session id was persisted.
      return {
        kind: "leaf",
        id,
        leafKind: "rdp",
        rdpConnectionId: node.rdpConnectionId,
        // Older snapshots cannot exist (the field shipped with the kind), but
        // a hand-edited or downgraded file can still be missing it, and the
        // fallback is the only mode there is.
        sizeMode: node.sizeMode ?? "preset",
        ...(node.customTitle ? { customTitle: node.customTitle } : {}),
      };
    }
    if (node.leafKind === "board") {
      return {
        kind: "leaf",
        id,
        leafKind: "board",
        ...(node.customTitle ? { customTitle: node.customTitle } : {}),
      };
    }
    if (node.leafKind === "page") {
      return {
        kind: "leaf",
        id,
        leafKind: "page",
        // Hosts, and only Hosts - and now that is a narrowing rather than a
        // rewrite: `isUnrestorablePageLeaf` dropped every page but this one
        // above, so `node.page` IS the tab page by the time control gets here.
        // It used to be written unconditionally over whatever the file said,
        // which turned an unrecognised page into a second permanent Hosts tab.
        page: TAB_PAGE_KIND,
        ...(node.customTitle ? { customTitle: node.customTitle } : {}),
      };
    }
    // Unknown leafKind, including the `browser` leaves saved by builds up to
    // v0.4.22. Restore it as an empty terminal rather than dropping the node:
    // the tree's shape (and the split sizes saved alongside it) stays valid,
    // and the user gets a usable pane where the browser tab used to be.
    return {
      kind: "leaf",
      id,
      leafKind: "terminal",
    };
  }
  const children: PaneNode[] = [];
  for (const c of node.children) {
    const restored = savedToNode(c, allocId, outLeafIds);
    if (restored !== null) children.push(restored);
  }
  if (children.length === 0) return null;
  // A lone survivor collapses into its parent: a one-child split is not a valid
  // pane tree. Same rule `nodeToSaved` applies when it prunes on the way out.
  if (children.length === 1) return children[0];
  return {
    kind: "split",
    id: allocId(),
    dir: node.dir,
    children,
    // Restore divider positions only when the saved sizes still line up with
    // the child count; otherwise fall back to an equal split. A pruned child
    // invalidates the ratios, which is exactly what the length compare catches.
    ...(node.sizes && node.sizes.length === children.length ? { sizes: node.sizes } : {}),
  };
}

/**
 * One saved tab, restored - or `null` when nothing in it survives restore.
 *
 * `null` is the DCR-1 migration's "drop the tab if dropping its leaves empties
 * it" case: a workspace with a Vault tab in it comes back with that tab gone,
 * not with an empty one. Prefer {@link restoreSavedTabs}, which handles the
 * dropping and the fall back to Hosts when a whole workspace empties out.
 */
export function savedToTab(saved: SavedTab, allocId: () => number): Tab | null {
  if (saved.kind === "preview") {
    // Legacy standalone browser ("preview") tab, from a build that still had an
    // embedded browser. Restore it as an empty terminal pane so the tab (and
    // whatever the user named it) survives instead of vanishing on upgrade.
    const tabId = allocId();
    const leafId = allocId();
    const leaf: PaneNode = { kind: "leaf", id: leafId, leafKind: "terminal" };
    return {
      id: tabId,
      kind: "pane",
      title: saved.title ?? saved.url,
      paneTree: leaf,
      activeLeafId: leafId,
    };
  }
  const id = allocId();
  const leafIds: number[] = [];
  const paneTree = savedToNode(saved.paneTree, allocId, leafIds);
  if (paneTree === null) return null;
  // Re-based, not clamped: `leafIds` holds the SURVIVORS, `saved.activeLeafIndex`
  // indexes the saved list, and a dropped leaf shifts every later one. Clamping
  // the raw index focused the wrong pane whenever the drop was BEFORE it - a
  // saved `[termA, vault, termB, termC]` on termB (index 2) came back on termC.
  // The outbound side has always done this (`tabToSaved`'s `kept.findIndex`);
  // this is its counterpart, one level below `restoredActiveTabIndex`.
  const wanted = restoredActiveLeafIndex(saved.paneTree, saved.activeLeafIndex);
  const activeLeafId = leafIds[Math.min(Math.max(0, wanted), leafIds.length - 1)] ?? leafIds[0];
  const tab: PaneTab = {
    id,
    kind: "pane",
    title: saved.title ?? "",
    paneTree,
    activeLeafId,
  };
  return tab;
}

/**
 * Startup fallback tab (decision 9): one pane tab holding a Hosts page leaf,
 * used by `useWorkspacePersistence` in place of a local shell when there is
 * nothing to restore - first run, an empty workspace, or a dev session that
 * skips restore entirely.
 */
export function defaultHostsTab(allocId: () => number): Tab {
  const leafId = allocId();
  return {
    id: allocId(),
    kind: "pane",
    title: PAGE_LABELS.hosts,
    paneTree: {
      kind: "leaf",
      id: leafId,
      leafKind: "page",
      page: TAB_PAGE_KIND,
    },
    activeLeafId: leafId,
  };
}

/**
 * Every saved tab restored, with DCR-1's migration applied: a `vault` or
 * `forwards` page leaf is dropped, the tab goes with it if that empties it, and
 * a workspace emptied that way falls back to the Hosts page rather than to a
 * window with no tabs at all.
 *
 * THE restore entry point. `savedToTab` is still exported for the cold-workspace
 * row builder and the verify scripts, but every path that produces the live tab
 * list goes through here, so a snapshot taken before rail views existed cannot
 * put a Vault tab back in the strip.
 */
export function restoreSavedTabs(saved: SavedTab[], allocId: () => number): Tab[] {
  const out: Tab[] = [];
  for (const s of saved) {
    const tab = savedToTab(s, allocId);
    if (tab !== null) out.push(tab);
  }
  return out.length === 0 ? [defaultHostsTab(allocId)] : out;
}

/**
 * The saved active-tab index, re-based onto what {@link restoreSavedTabs}
 * actually produced. Dropping a tab shifts every later one, so the raw saved
 * index would land on a tab the user was not looking at - or, for the last tab,
 * past the end.
 *
 * Counts the surviving tabs BEFORE the saved index, which is the same shape as
 * `savedActiveTabIndex` on the way out; a dropped active tab lands on its
 * neighbour. Restore is destructive to nothing, so this only ever reads the
 * saved array - it needs no ids and allocates none.
 */
export function restoredActiveTabIndex(saved: SavedTab[], activeIndex: number): number {
  let idx = 0;
  for (let i = 0; i < saved.length && i < activeIndex; i++) {
    if (survivesRestore(saved[i])) idx++;
  }
  return idx;
}

/**
 * The saved active-LEAF index, re-based onto the leaves that survived restore.
 * {@link restoredActiveTabIndex} one level down, and the mirror of
 * `tabToSaved`'s `kept.findIndex` on the way out.
 *
 * Counts the surviving leaves BEFORE the saved index, in the same depth-first
 * order `savedToNode` pushes ids in, so the result indexes the id array it is
 * used against. A dropped active leaf lands on its neighbour.
 */
export function restoredActiveLeafIndex(tree: SavedPaneNode, activeLeafIndex: number): number {
  const survives: boolean[] = [];
  collectLeafSurvival(tree, survives);
  let idx = 0;
  for (let i = 0; i < survives.length && i < activeLeafIndex; i++) {
    if (survives[i]) idx++;
  }
  return idx;
}

/** Whether each leaf of a saved subtree restores, depth-first. */
function collectLeafSurvival(node: SavedPaneNode, out: boolean[]): void {
  if (node.kind === "leaf") {
    out.push(!isUnrestorablePageLeaf(node));
    return;
  }
  for (const child of node.children) collectLeafSurvival(child, out);
}

/** True for exactly the tabs {@link restoreSavedTabs} keeps. Decided without
 *  allocating ids so {@link restoredActiveTabIndex} can ask it too. */
function survivesRestore(saved: SavedTab): boolean {
  if (saved.kind === "preview") return true;
  return countRestorableLeaves(saved.paneTree) > 0;
}

/** Leaves of a saved subtree that restore, i.e. all of them minus the rail-view
 *  page leaves DCR-1 dropped. */
function countRestorableLeaves(node: SavedPaneNode): number {
  if (node.kind === "leaf") return isUnrestorablePageLeaf(node) ? 0 : 1;
  let n = 0;
  for (const child of node.children) n += countRestorableLeaves(child);
  return n;
}

/**
 * Live tabs for a workspace with no cached live-tab entry (i.e. it hasn't been
 * visited yet this session): its saved tabs restored, or - if it has none - the
 * Hosts page. The runtime counterpart of decision 9's startup fallback in
 * `useWorkspacePersistence`, so switching to (or creating) an empty workspace
 * lands on the same screen a fresh profile does instead of a local shell.
 *
 * Lives here rather than beside its `useWorkspaceSwitching` callers because it
 * needs nothing from that hook, and here it is reachable from
 * `workspace-serialize-verify` - which cannot import the hook, whose module
 * pulls in `@xterm/xterm` (no `exports` map, so Node can't resolve `Terminal`
 * outside a bundler). Only `tabs` is read; callers pass a whole workspace.
 */
export function tabsForWorkspaceEntry(entry: { tabs: SavedTab[] }, allocId: () => number): Tab[] {
  // `restoreSavedTabs` already falls back to Hosts on an empty result, which
  // covers both "no saved tabs" and "every saved tab was a rail view".
  return restoreSavedTabs(entry.tabs, allocId);
}

/**
 * A cold workspace's live tabs AND the tab to focus, from ONE call, so the index
 * and the array it indexes cannot be computed from different lists.
 *
 * The three callers - workspace switch, workspace close (the neighbour it falls
 * back to), and the startup hydrate - got this right once between them. The
 * other two clamped the RAW saved index against the RESTORED array, which lands
 * on the wrong tab whenever a dropped tab sat before it: a workspace saved as
 * `[Hosts, Vault, termA, termB]` focused on termA came back focused on termB.
 * Handing back an id rather than an index is what makes that unexpressible.
 *
 * `activeId` is null only when there is no tab to focus, which
 * {@link restoreSavedTabs}' Hosts fallback means cannot happen today; the
 * signature keeps saying so rather than asserting it.
 */
export function restoreWorkspaceEntry(
  entry: { tabs: SavedTab[]; activeTabIndex: number },
  allocId: () => number,
): { tabs: Tab[]; activeId: number | null } {
  const tabs = tabsForWorkspaceEntry(entry, allocId);
  const wanted = restoredActiveTabIndex(entry.tabs, entry.activeTabIndex);
  const target = tabs[Math.min(Math.max(0, wanted), tabs.length - 1)] ?? tabs[0];
  return { tabs, activeId: target?.id ?? null };
}
