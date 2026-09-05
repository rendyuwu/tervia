import { toast } from "@/components/ui/toast";
import {
  activeLeaf,
  canCloseLeaf,
  canCloseTab,
  leafCloseConfirmReason,
  MAX_PANES_PER_TAB,
  tabCloseConfirmReason,
  type Tab,
} from "@/modules/tabs";
import {
  agentToolKind,
  MAX_AGENT_SPAWN,
  useCliAgentsStore,
  type CliAgent,
} from "@/modules/terminal/lib/cliAgents";
import { hasLeaf, leafIds, type PaneLayout, type TerminalPaneHandle } from "@/modules/terminal";
import { useCallback, useState, type Dispatch, type RefObject, type SetStateAction } from "react";
import { type TabsApi } from "./tabsApi";

type Params = {
  tabs: Tab[];
  activeId: number;
  tabsRef: RefObject<Tab[]>;
  terminalRefs: RefObject<Map<number, TerminalPaneHandle>>;
  activeLeafIdInTab: number | null;
  activeLeafKindCurrent: "terminal" | "editor" | "rdp" | null;
  /** True when the active leaf is a connected SSH terminal. A breadcrumb `cd`
   *  then targets the remote shell only; it must NOT repoint the local
   *  workspace root at a remote path (which breaks the local explorer and
   *  persists across reloads). */
  activeLeafIsSsh: boolean;
  explorerRoot: string | null;
  inheritedCwdForNewTab: () => string | undefined;
  setPickedRoot: Dispatch<SetStateAction<string | null>>;
  disposeTab: (id: number) => void;
} & Pick<
  TabsApi,
  | "setActiveId"
  | "newTab"
  | "newPaneGroupTab"
  | "setLeafCwd"
  | "splitActivePane"
  | "moveLeafToTab"
  | "closePaneByLeaf"
>;

/**
 * A close pending the user's confirmation. Drives the close-confirmation
 * AlertDialog in `AppDialogs`.
 */
export type PendingClose = {
  /** What to dispose once the user confirms. */
  target: { kind: "tab"; tabId: number } | { kind: "leaf"; leafId: number };
  /** Why we're asking - drives the modal copy. */
  reason: "unsaved" | "running";
  /** Tab title for the prompt, when known. */
  title?: string;
};

/**
 * Tab/pane-level user actions: open / close / cd / split / move plus the
 * close-confirmation state (`pendingClose`). A close is confirmed first when
 * the tab/pane has unsaved editor changes or a terminal running a process;
 * otherwise it disposes immediately. `disposeTab` is threaded in because it
 * stays in App (the dispose-effect and `handlePathDeleted` also share it).
 */
export function useTabActions({
  tabs,
  activeId,
  tabsRef,
  terminalRefs,
  activeLeafIdInTab,
  activeLeafKindCurrent,
  activeLeafIsSsh,
  explorerRoot,
  inheritedCwdForNewTab,
  setPickedRoot,
  disposeTab,
  setActiveId,
  newTab,
  newPaneGroupTab,
  setLeafCwd,
  splitActivePane,
  moveLeafToTab,
  closePaneByLeaf,
}: Params): {
  pendingClose: PendingClose | null;
  handleClose: (id: number) => void;
  requestCloseLeaf: (leafId: number) => void;
  confirmClose: () => void;
  cancelClose: () => void;
  cycleTab: (delta: 1 | -1) => void;
  openNewTab: () => void;
  sendCd: (path: string) => void;
  cdInNewTab: (path: string) => void;
  spawnAgents: (agentIds: string[], layout?: PaneLayout) => void;
  splitActivePaneInActiveTab: (dir: "row" | "col", kind?: "terminal" | "editor") => void;
  moveLeafToGroup: (leafId: number, targetTabId: number) => void;
  handleCloseTabOrPane: () => void;
} {
  const [pendingClose, setPendingClose] = useState<PendingClose | null>(null);

  // A terminal leaf is "busy" only when a foreground command is genuinely
  // running - a full-screen TUI on the alt-screen, or an in-flight OSC 133
  // command (with Enter-synthesis for pwsh). This is prompt-text independent,
  // so an idle terminal (even with a custom oh-my-posh/starship prompt) never
  // triggers the confirmation. Non-terminal leaves have no handle in
  // terminalRefs, so they never read busy.
  const leafHasRunningProcess = useCallback((leafId: number): boolean => {
    const term = terminalRefs.current.get(leafId);
    return term ? term.isProcessRunning() : false;
  }, []);

  // Whole-tab close. Confirms first on unsaved editor changes or a running
  // terminal process; otherwise disposes immediately.
  //
  // The close rule (`tabs/lib/closable.ts`) is asked BEFORE the confirmation,
  // not after: prompting "close the running terminal?" for a close that will
  // then be refused is worse than the silent no-op it replaces. Nothing is said
  // here because nothing offered the action - the tab strip and pane header do
  // not render an X for a tab this refuses, and `Ctrl+W` is the only way in.
  //
  // WHETHER to confirm is asked of `closable.ts` too, and both close paths ask
  // the same pair of functions. Hand-rolling the question here is how the two
  // came to disagree about a dirty editor - see `leafCloseConfirmReason`.
  const handleClose = useCallback(
    (id: number) => {
      if (!canCloseTab(tabs, id)) return;
      const reason = tabCloseConfirmReason(tabs, id, leafHasRunningProcess);
      if (reason !== null) {
        const t = tabs.find((x) => x.id === id);
        setPendingClose({
          target: { kind: "tab", tabId: id },
          reason,
          title: t?.kind === "pane" ? t.title : undefined,
        });
        return;
      }
      disposeTab(id);
    },
    [tabs, disposeTab, leafHasRunningProcess],
  );

  // Single-pane close (tab-strip leaf X, pane-header X on a split, Ctrl+W on a
  // multi-pane tab, Ctrl+Shift+X, "Close Tabs to the Right"). Confirms on an
  // unsaved editor or a busy terminal; otherwise drops the pane immediately.
  const requestCloseLeaf = useCallback(
    (leafId: number) => {
      // Same two questions as `handleClose`, in the same order, from the same
      // module - which is the point. This is the funnel for five affordances, so
      // a question it answers differently is one the user gets a different
      // answer to depending on which of them they used. It used to prompt only
      // on a busy terminal and drop a dirty editor buffer without a word, while
      // the pane-header X of a single-pane tab (which routes to `handleClose`)
      // prompted for the same file.
      if (!canCloseLeaf(tabsRef.current, leafId)) return;
      const reason = leafCloseConfirmReason(tabsRef.current, leafId, leafHasRunningProcess);
      if (reason !== null) {
        const tab = tabsRef.current.find((x) => x.kind === "pane" && hasLeaf(x.paneTree, leafId));
        setPendingClose({
          target: { kind: "leaf", leafId },
          reason,
          title: tab?.kind === "pane" ? tab.title : undefined,
        });
        return;
      }
      closePaneByLeaf(leafId);
    },
    [leafHasRunningProcess, closePaneByLeaf],
  );

  const confirmClose = useCallback(() => {
    if (!pendingClose) return;
    const { target } = pendingClose;
    if (target.kind === "tab") disposeTab(target.tabId);
    else closePaneByLeaf(target.leafId);
    setPendingClose(null);
  }, [pendingClose, disposeTab, closePaneByLeaf]);

  const cancelClose = useCallback(() => {
    setPendingClose(null);
  }, []);

  const cycleTab = useCallback(
    (delta: 1 | -1) => {
      if (tabs.length < 2) return;
      const idx = tabs.findIndex((t) => t.id === activeId);
      const nextIdx = (idx + delta + tabs.length) % tabs.length;
      setActiveId(tabs[nextIdx].id);
    },
    [tabs, activeId, setActiveId],
  );

  const openNewTab = useCallback(() => {
    // Ctrl+T opens the new shell in the explorer's root so the tab matches
    // the folder being browsed.
    newTab(explorerRoot ?? inheritedCwdForNewTab());
  }, [newTab, inheritedCwdForNewTab, explorerRoot]);

  const sendCd = useCallback(
    (path: string) => {
      // Breadcrumb click = open this folder. Updates the workspace root so
      // the explorer, AI workspace context, and inherited cwd follow.
      // Persisted across reloads.
      const normalized = path.replace(/\\/g, "/");
      // Under SSH the breadcrumb path is REMOTE: pointing the local workspace
      // root at it makes the local explorer read a non-existent local path
      // ("the system cannot find the path") and persists that across reloads.
      // Skip the local-root mutation entirely; only the remote `cd` below runs.
      if (!activeLeafIsSsh) {
        setPickedRoot(normalized);
        try {
          localStorage.setItem("tervia.workspaceRoot", normalized);
        } catch {
          // Storage unavailable. Skip persistence.
        }
      }
      // If the active leaf is a terminal, cd it too so the shell tracks
      // the new workspace - but ONLY while it's sitting idle at a prompt.
      // Writing `cd "…"` into a busy shell (a command running, output
      // streaming, or a TUI owning the alt-screen) lands the keystrokes in
      // that program's stdin instead of changing directory, garbling
      // whatever is in flight. When busy we skip the shell write entirely;
      // the explorer / AI workspace context above still follow the click,
      // and the next breadcrumb click once the command finishes cds for
      // real. Mirrors the `run_in_terminal` isAtPrompt() guard so the AI and
      // the breadcrumb refuse to disrupt a working terminal the same way.
      // Double quotes work across pwsh/bash/zsh/cmd for paths without shell
      // metacharacters (segmentsFromCwd outputs never contain any). React
      // state updates the cwd optimistically so the breadcrumb reflects the
      // click immediately. Shells with OSC 7 reconcile after, shells without
      // it still show the target.
      if (activeLeafIdInTab !== null && activeLeafKindCurrent === "terminal") {
        const term = terminalRefs.current.get(activeLeafIdInTab);
        if (term && term.isAtPrompt()) {
          setLeafCwd(activeLeafIdInTab, normalized);
          term.write(`cd "${normalized}"\r`);
          term.focus();
        }
      }
    },
    [activeLeafIdInTab, activeLeafKindCurrent, activeLeafIsSsh, setLeafCwd, setPickedRoot],
  );

  const cdInNewTab = useCallback(
    (path: string) => {
      const tabId = newTab(path);
      setTimeout(() => {
        const tab = tabsRef.current.find((x) => x.id === tabId);
        if (!tab || tab.kind !== "pane") return;
        const leaf = activeLeaf(tab);
        if (!leaf || leaf.leafKind !== "terminal") return;
        const t = terminalRefs.current.get(leaf.id);
        if (!t) return;
        const quoted = path.includes(" ") ? `'${path.replace(/'/g, `'\\''`)}'` : path;
        t.write(`cd ${quoted}\r`);
        t.focus();
      }, 80);
    },
    [newTab],
  );

  /**
   * `+` -> Agent: one tab holding a terminal per picked agent, arranged by
   * `layout`, each auto-running that agent's CLI.
   *
   * The whole pane group is built in one shot (`newPaneGroupTab`) rather than by
   * chaining splits, because a grid is not reachable by repeatedly splitting the
   * active pane, and because every leaf must exist before we start typing into
   * them.
   *
   * The CLI is typed into the shell rather than spawned as the PTY's program, so
   * the pane falls back to a normal shell when the agent exits. `launchAgent`
   * (not `write`) does the typing because it also tags the pane with the agent's
   * detector kind - the status badge would otherwise stay dark, since the
   * command bypasses xterm's `onData` and a renamed launcher (`claude-start`)
   * matches no detector pattern anyway.
   */
  const spawnAgents = useCallback(
    (agentIds: string[], layout: PaneLayout = "row") => {
      const roster = useCliAgentsStore.getState().all();
      const picked: CliAgent[] = [];
      for (const id of agentIds.slice(0, MAX_AGENT_SPAWN)) {
        const agent = roster.find((a) => a.id === id);
        if (agent && agent.command.trim() !== "") picked.push(agent);
      }
      if (picked.length === 0) return;
      const cwd = explorerRoot ?? inheritedCwdForNewTab();
      const title = picked.length === 1 ? picked[0].name : `${picked.length} agents`;
      const tabId = newPaneGroupTab(picked.length, layout, cwd, title);
      // Panes mount and spawn their PTY asynchronously; wait for the shell to
      // reach a prompt before typing, else the keystrokes land in a shell that
      // is not reading stdin yet. Give up after ~6s rather than typing blind.
      const launch = (leafId: number, agent: CliAgent, tries: number) => {
        const term = terminalRefs.current.get(leafId);
        if (term?.isAtPrompt()) {
          term.launchAgent(agent.command.trim(), agentToolKind(agent));
          return;
        }
        if (tries <= 0) return;
        setTimeout(() => launch(leafId, agent, tries - 1), 150);
      };
      setTimeout(() => {
        const tab = tabsRef.current.find((x) => x.id === tabId);
        if (!tab || tab.kind !== "pane") return;
        leafIds(tab.paneTree).forEach((leafId, i) => {
          const agent = picked[i];
          if (agent) launch(leafId, agent, 40);
        });
      }, 120);
    },
    [newPaneGroupTab, explorerRoot, inheritedCwdForNewTab],
  );

  /**
   * Ctrl+D / Ctrl+Shift+D: splits the active pane in the active tab.
   * "row" puts the new pane to the right, "col" puts it below. The new
   * leaf becomes active. Capped at `MAX_PANES_PER_TAB`.
   */
  const splitActivePaneInActiveTab = useCallback(
    (dir: "row" | "col", kind?: "terminal" | "editor") => {
      const t = tabsRef.current.find((x) => x.id === activeId);
      if (!t || t.kind !== "pane") return;
      splitActivePane(activeId, dir, kind, explorerRoot ?? undefined);
    },
    [activeId, splitActivePane, explorerRoot],
  );

  /**
   * Moves a leaf into `targetTabId` as a horizontal split. The leaf's id
   * is preserved so its PTY / editor session survives. Resolves the
   * target title before the move so the toast can name it if the source
   * tab is dropped.
   */
  const moveLeafToGroup = useCallback(
    (leafId: number, targetTabId: number) => {
      const target = tabsRef.current.find((x) => x.id === targetTabId);
      if (!target || target.kind !== "pane") return;
      const targetTitle = target.title;
      const result = moveLeafToTab(leafId, targetTabId);
      if (result === "full") {
        toast(`Group "${targetTitle}" is full (${MAX_PANES_PER_TAB} panes max).`, {
          variant: "warning",
        });
      }
    },
    [moveLeafToTab],
  );

  const handleCloseTabOrPane = useCallback(() => {
    const t = tabsRef.current.find((x) => x.id === activeId);
    // Multi-pane tab → close just the focused pane. Single-pane tab → close
    // the whole tab. Both routes confirm first when a terminal is busy.
    if (t?.kind === "pane" && leafIds(t.paneTree).length > 1) {
      requestCloseLeaf(t.activeLeafId);
      return;
    }
    handleClose(activeId);
  }, [activeId, requestCloseLeaf, handleClose]);

  return {
    pendingClose,
    handleClose,
    requestCloseLeaf,
    confirmClose,
    cancelClose,
    cycleTab,
    openNewTab,
    sendCd,
    cdInNewTab,
    spawnAgents,
    splitActivePaneInActiveTab,
    moveLeafToGroup,
    handleCloseTabOrPane,
  };
}
