/**
 * App.tsx - the main-window top-level COORDINATOR (not a feature dump).
 *
 * App's job is to own the shared runtime state (the per-leaf handle maps, the
 * workspace live-tab cache) and to compose
 * the domain hooks + layout components that implement each behavior. Features
 * themselves live in src/modules/<area>/; the wiring lives in the domain hooks
 * under src/app/hooks/ and the render tree in src/app/components/.
 *
 * Where behaviors are set up (each is its own hook unless noted):
 *   - useWorkspaceRoot         - home / picked root + `tervia <path>` CLI targets
 *   - useWorkspacePersistence  - hydrate + auto-snapshot workspaces
 *   - useQuitGuard             - pre-quit snapshot flush + busy-terminal prompt
 *   - useWorkspaceSwitching    - switch / create / close orchestration
 *   - useRightPanelExclusion   - closes a docked right-slot panel when its pref flips off
 *   - useActiveLeafSurface     - active leaf search addon / URL / editor handle
 *   - useSessionDisposal       - PTY/xterm teardown by pane tree
 *   - useChromeDerivations     - Header/StatusBar derived values
 *   - useTabSideEffects        - live per-workspace tab counts
 * Layout: AppSidebar / WorkspaceArea / AppRightSlot / AppDialogs.
 *
 * See ARCHITECTURE.md for the two-process model and TEDI.md for full detail.
 */
import { pathToFileUrl } from "@/lib/path";
import { openUrl } from "@tauri-apps/plugin-opener";
import { ResizableHandle, ResizablePanelGroup } from "@/components/ui/resizable";
import { Toaster } from "@/components/ui/toast";
import { TooltipProvider } from "@/components/ui/tooltip";
import { type EditorPaneHandle } from "@/modules/editor";
import { Header, type SearchInlineHandle } from "@/modules/header";
import { usePreferencesStore } from "@/modules/settings/preferences";
import { useSshRightPanelStore } from "@/modules/ssh/sshRightPanelStore";
import {
  isTerminalControlChord,
  isTerminalMetaChord,
  useGlobalShortcuts,
  type ShortcutHandlers,
} from "@/modules/shortcuts";
import { StatusBar } from "@/modules/statusbar";
import {
  activeLeafKind,
  isEditorLikeTab,
  isTerminalLikeTab,
  useTabs,
  useWorkspaceCwd,
  type Tab,
} from "@/modules/tabs";
import {
  acknowledgeAiCli,
  ensureFsDragListener,
  useTerminalFileDrop,
  type TerminalPaneHandle,
} from "@/modules/terminal";
import { useCliAgentsStore } from "@/modules/terminal/lib/cliAgents";
import { ThemeProvider } from "@/modules/theme";
import { type SshConnection } from "@/modules/ssh/connections";
import { useWorkspacesStore } from "@/modules/workspaces";
import type { SearchAddon } from "@xterm/addon-search";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { PanelImperativeHandle } from "react-resizable-panels";
import { buildShortcutHandlers } from "./lib/shortcutHandlers";
import { useApplyZoom } from "./hooks/useApplyZoom";
import { useRightPanelExclusion } from "./hooks/useRightPanelExclusion";
import { useRightColumnStore } from "@/modules/rightPanel";
import { useDockedSectionAutoOpen } from "./hooks/useDockedSectionAutoOpen";
import { useWorkspaceSwitching } from "./hooks/useWorkspaceSwitching";
import { useSshLeafState } from "./hooks/useSshLeafState";
import { usePaneHandles } from "./hooks/usePaneHandles";
import { useEditorFileDrop } from "./hooks/useEditorFileDrop";
import { useTabActions } from "./hooks/useTabActions";
import { useFileActions } from "./hooks/useFileActions";
import { useHeaderActions } from "./hooks/useHeaderActions";
import { useWorkspaceRoot } from "./hooks/useWorkspaceRoot";
import { useQuitGuard } from "./hooks/useQuitGuard";
import { useWorkspacePersistence } from "./hooks/useWorkspacePersistence";
import { useSessionDisposal } from "./hooks/useSessionDisposal";
import { useAdoptDaemonSessions } from "./hooks/useAdoptDaemonSessions";
import { useActiveLeafSurface } from "./hooks/useActiveLeafSurface";
import { useProjectUrl } from "./hooks/useProjectUrl";
import { useChromeDerivations } from "./hooks/useChromeDerivations";
import { useTabSideEffects } from "./hooks/useTabSideEffects";
import { CommandPalette } from "@/modules/commandPalette";
import { AppDialogs } from "./components/AppDialogs";
import { AppSidebar } from "./components/AppSidebar";
import { WorkspaceArea } from "./components/WorkspaceArea";
import { AppRightSlot } from "./components/AppRightSlot";

export default function App() {
  const isDevSession = import.meta.env.DEV;
  const {
    tabs,
    activeId,
    setActiveId,
    newTab,
    newPaneGroupTab,
    newSshTab,
    openFileTab,
    pinTab,
    openBoardTab,
    closeTab,
    selectByIndex,
    setLeafCwd,
    setLeafPtyId,
    setLeafActiveTool,
    setSplitSizes,
    setEditorLeafDirty,
    setEditorLeafPath,
    focusPane,
    focusNextPaneInTab,
    closePaneByLeaf,
    splitActivePane,
    moveLeafToTab,
    moveLeafToNewTab,
    rotateLeafSplit,
    replaceAllTabs,
    allocId,
    reorderTabs,
    reorderLeafInGroup,
    movePaneLeafToEdge,
    renameLeaf,
    setLeafTerminalTheme,
  } = useTabs();

  // Drop a file from the OS file manager onto a terminal pane to paste its
  // shell-quoted path. Tauri captures OS drops globally, so one listener
  // at the app root hit-tests the cursor.
  useTerminalFileDrop();

  // HTML5 drags from `[data-fs-path]` elements (the sidebar tree) populate
  // dataTransfer at a document-level capture listener. Bypasses React's
  // per-root delegation so drag sources from separate `createRoot` trees still
  // work. Module guard prevents double-attach.
  useEffect(() => {
    ensureFsDragListener();
  }, []);

  // Mirror `tabs` into a ref so deferred callbacks (e.g. cdInNewTab) read
  // the latest state instead of a stale closure.
  const tabsRef = useRef(tabs);
  tabsRef.current = tabs;

  const activeTab = useMemo(() => tabs.find((t) => t.id === activeId), [tabs, activeId]);
  const activePaneTab = activeTab?.kind === "pane" ? activeTab : null;
  const isTerminalLike = activeTab ? isTerminalLikeTab(activeTab) : false;
  const isEditorLike = activeTab ? isEditorLikeTab(activeTab) : false;

  // Lazy-mount the ext stack. The chunk only loads once a tab of that kind
  // exists.

  // Active leaf says what's focused in the current tab. Drives Search,
  // CWD wiring, etc.
  const activeLeafIdInTab = activePaneTab?.activeLeafId ?? null;
  const activeLeafKindCurrent = activeTab ? activeLeafKind(activeTab) : null;

  // -------- shared runtime handles & state owned by the coordinator --------
  // These are read/written by several domain hooks and the layout components,
  // so they stay here and are threaded in. Single-consumer state lives inside
  // its owning hook instead (e.g. pendingClose in useTabActions).
  const searchAddons = useRef<Map<number, SearchAddon>>(undefined!);
  if (!searchAddons.current) searchAddons.current = new Map();
  const terminalRefs = useRef<Map<number, TerminalPaneHandle>>(undefined!);
  if (!terminalRefs.current) terminalRefs.current = new Map();
  const editorRefs = useRef<Map<number, EditorPaneHandle>>(undefined!);
  if (!editorRefs.current) editorRefs.current = new Map();
  const detectedUrls = useRef<Map<number, string>>(undefined!);
  if (!detectedUrls.current) detectedUrls.current = new Map();
  const [activeSearchAddon, setActiveSearchAddon] = useState<SearchAddon | null>(null);
  const [activeEditorHandle, setActiveEditorHandle] = useState<EditorPaneHandle | null>(null);
  const searchInlineRef = useRef<SearchInlineHandle | null>(null);

  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);

  const [editingSshConn, setEditingSshConn] = useState<SshConnection | null>(null);
  const [sshEditorOpen, setSshEditorOpen] = useState(false);
  // Latches the first time each lazy dialog opens. Stays true; see the
  // dialog mount sites for why.
  const [sshEditorMounted, setSshEditorMounted] = useState(false);
  useEffect(() => {
    if (sshEditorOpen) setSshEditorMounted(true);
  }, [sshEditorOpen]);

  // `+` -> Agent...: the CLI-agent picker. Mount-once like the editor dialog so
  // the chunk loads on first open and Radix's exit animation still plays.
  const [agentDialogOpen, setAgentDialogOpen] = useState(false);
  const [agentDialogMounted, setAgentDialogMounted] = useState(false);
  const [newEditorOpen, setNewEditorOpen] = useState(false);
  const [newEditorMounted, setNewEditorMounted] = useState(false);
  useEffect(() => {
    if (agentDialogOpen) setAgentDialogMounted(true);
  }, [agentDialogOpen]);
  useEffect(() => {
    if (newEditorOpen) setNewEditorMounted(true);
  }, [newEditorOpen]);

  /**
   * Editor leaves currently shown as markdown preview instead of source.
   * Keyed by leaf id so split panes toggle independently. Stale entries
   * for closed leaves are harmless.
   */
  const [mdPreviewLeafIds, setMdPreviewLeafIds] = useState<ReadonlySet<number>>(() => new Set());
  const toggleMdPreviewForLeaf = useCallback((leafId: number) => {
    setMdPreviewLeafIds((curr) => {
      const next = new Set(curr);
      if (next.has(leafId)) next.delete(leafId);
      else next.add(leafId);
      return next;
    });
  }, []);

  const sidebarRef = useRef<PanelImperativeHandle | null>(null);
  const toggleSidebar = useCallback(() => {
    const p = sidebarRef.current;
    if (!p) return;
    if (p.getSize().asPercentage <= 0) p.expand();
    else p.collapse();
  }, []);

  // When the active workspace is closed, activeId is reassigned to a
  // neighbor. Skip the auto-snapshot for that transition so it doesn't
  // overwrite the neighbor's saved tabs with the closing workspace's
  // live tabs (still in `useTabs` until we rehydrate below). Shared by
  // useWorkspacePersistence (sets the skip) and useWorkspaceSwitching.
  const skipNextSnapshotRef = useRef(false);
  // In-memory cache of each workspace's live Tab[] (with leaf ids) so a
  // switch back restores the same terminal leaf ids and keeps PTY/xterm
  // sessions alive. `serializeTabs` still writes to disk for crash
  // recovery, but live state wins on switch. Shared by useWorkspaceSwitching
  // (writes) and useSessionDisposal (reads to keep cached leaves alive).
  const liveTabsByWorkspace = useRef<Map<string, { tabs: Tab[]; activeId: number | null }>>(
    undefined!,
  );
  if (!liveTabsByWorkspace.current) liveTabsByWorkspace.current = new Map();

  // -------- home / picked root + CLI targets --------
  const { home, pickedRoot, setPickedRoot, openWorkspaceFolder } = useWorkspaceRoot({
    tabs,
    activePaneTab,
    newTab,
    openFileTab,
  });

  // -------- Preferences boot --------
  const initPrefs = usePreferencesStore((s) => s.init);
  useEffect(() => {
    void initPrefs();
  }, [initPrefs]);

  // Preferences used by the chrome / layout.
  const sshInRightPanel = usePreferencesStore((s) => s.sshInRightPanel);
  const contentZoom = usePreferencesStore((s) => s.contentZoom);
  // UI zoom scales the chrome only (header / tabs, sidebar, side panels, status
  // bar) plus portaled overlays, which mount on `document.body` outside `#root`.
  // The workspace pane counter-zooms back to 1 (see WorkspaceArea) so terminal /
  // editor / preview keep native resolution and their own `--content-zoom`.
  const uiZoom = usePreferencesStore((s) => s.uiZoom);
  // Apply --content-zoom (CSS var) and body.zoom from the prefs values.
  useApplyZoom(contentZoom, uiZoom);

  const sshRightOpen = useSshRightPanelStore((s) => s.open);
  const closeSshRight = useSshRightPanelStore((s) => s.closePanel);

  // Docked sidebar sections and the SSH right panel all live in the right column
  // TOGETHER, stacked like the left sidebar's sections (see AppRightSlot). This
  // is the list of docked sections that are currently open.
  const rightSections = useRightColumnStore((s) => s.open);
  // Re-open a sidebar section docked to the right slot on boot (else it would
  // vanish: gone from the left sidebar, closed in the right).
  useDockedSectionAutoOpen();

  // CLI-agent roster for the `+` -> Agent submenu. Hydrated here (not in the
  // menu) so a Settings edit broadcast arrives even while the menu is closed.
  const hydrateCliAgents = useCliAgentsStore((s) => s.hydrate);
  useEffect(() => {
    void hydrateCliAgents();
  }, [hydrateCliAgents]);

  // -------- workspaces wiring --------
  const wsHydrate = useWorkspacesStore((s) => s.hydrate);
  const wsHydrated = useWorkspacesStore((s) => s.hydrated);
  const wsList = useWorkspacesStore((s) => s.workspaces);
  const wsActiveId = useWorkspacesStore((s) => s.activeId);
  const wsSetActive = useWorkspacesStore((s) => s.setActiveId);
  const wsCreate = useWorkspacesStore((s) => s.createWorkspace);
  const wsRemove = useWorkspacesStore((s) => s.removeWorkspace);
  const wsSaveTabs = useWorkspacesStore((s) => s.saveWorkspaceTabs);
  const wsFlush = useWorkspacesStore((s) => s.flush);

  useWorkspacePersistence({
    wsHydrate,
    wsHydrated,
    restoreTabsOnHydrate: !isDevSession,
    persistTabsSnapshot: !isDevSession,
    wsList,
    wsActiveId,
    wsSaveTabs,
    tabs,
    activeId,
    allocId,
    replaceAllTabs,
    skipNextSnapshotRef,
  });

  // Flushes the workspace snapshot before the window goes away, and prompts
  // (keep terminals running / close them all) when a terminal is still busy.
  const quitGuard = useQuitGuard(wsFlush, !isDevSession);

  const { switchToWorkspace, createNewWorkspace, closeWorkspace } = useWorkspaceSwitching({
    wsActiveId,
    wsList,
    tabs,
    activeId,
    wsSaveTabs,
    wsSetActive,
    wsCreate,
    wsRemove,
    allocId,
    home,
    replaceAllTabs,
    liveTabsByWorkspace,
    skipNextSnapshotRef,
  });

  const { liveTabCounts } = useTabSideEffects({ tabs, wsActiveId });

  const { explorerRoot, inheritedCwdForNewTab } = useWorkspaceCwd(
    activeTab,
    tabs,
    home,
    pickedRoot,
  );

  // Persist the live workspace root so the Settings window (separate webview,
  // shared localStorage) can target/scan the open project for AI skills. This
  // mirrors exactly what the agent scans (explorerRoot ?? home), so a skill
  // installed "to this project" lands where the agent actually looks.
  useEffect(() => {
    try {
      localStorage.setItem("tervia.liveWorkspaceRoot", explorerRoot ?? home ?? "");
    } catch {
      /* storage unavailable */
    }
  }, [explorerRoot, home]);

  const {
    sshStatuses,
    setSshStatuses,
    aiCliStatuses,
    setAiCliStatuses,
    handleSshStatus,
    handleAiCliStatus,
    activeSshContext,
    sshBindingByConnection,
    hasAnySshLeaf,
  } = useSshLeafState({ activePaneTab, tabs });

  // "Reconnect" on a remote editor pane with no live session (typically a
  // restored workspace whose SSH terminal was closed). Opens a normal SSH tab
  // for the saved profile, so host-key prompts and jump hosts run through the
  // usual terminal flow; the editor pane rebinds itself once the session lands,
  // since it resolves by connection id rather than holding a session number.
  const handleReconnectSshForEditor = useCallback(
    (connectionId: string, title: string) => {
      newSshTab(connectionId, title);
    },
    [newSshTab],
  );

  // Besides the live toast/beep + status map that `handleAiCliStatus` drives,
  // stamp the detected agent kind onto the leaf so the serializer persists it.
  // On the next launch a still-running (reattached) agent resumes its badge
  // instead of going dark until the user types a command. Only the tool
  // identity is written; the frequent working<->idle flips are no-op-guarded
  // inside `setLeafActiveTool`.
  const handleAiCliStatusAndPersist: typeof handleAiCliStatus = useCallback(
    (leafId, status) => {
      handleAiCliStatus(leafId, status);
      setLeafActiveTool(leafId, status?.tool ?? null);
    },
    [handleAiCliStatus, setLeafActiveTool],
  );

  // Hide the local-OS status badge while the active pane IS a live SSH session:
  // the status bar's cwd breadcrumb shows the REMOTE path, so "Windows" would
  // misrepresent the shell the user is actually in. Keyed off the active leaf's
  // own connected status (not hasAnySshLeaf), so a background SSH session while
  // you're in a local tab still shows the correct local badge.
  const activeLeafIsSsh =
    activeLeafIdInTab != null && sshStatuses.get(activeLeafIdInTab)?.kind === "connected";

  // The focused terminal's "done" badge decays back to idle: done is an
  // attention glance for panes you're NOT looking at. `aiCliStatuses` is in the
  // deps so this also fires when the ACTIVE pane transitions into done while
  // already focused (a single pane you're watching finish) - not only when you
  // switch TO a done pane. acknowledgeAiCli is a no-op unless the leaf is done,
  // so the extra runs are cheap. Typing clears it too (detector pushInput). The
  // "<tool> finished" toast still fires first (working->done edge in
  // useSshLeafState), so you don't miss the completion signal.
  useEffect(() => {
    if (activeLeafIdInTab != null) acknowledgeAiCli(activeLeafIdInTab);
  }, [activeLeafIdInTab, aiCliStatuses]);

  // Right-column housekeeping (close a docked panel when its enabling pref flips
  // off). Declared here (not up with the other store reads) because it needs
  // hasAnySshLeaf from useSshLeafState.
  useRightPanelExclusion(sshRightOpen, sshInRightPanel, hasAnySshLeaf, closeSshRight);

  const disposeTab = useCallback(
    (id: number) => {
      // Per-leaf maps are pruned by useSessionDisposal's [tabs] effect.
      closeTab(id);
    },
    [closeTab],
  );

  // Disposes sessions by pane tree, not React lifecycle, and prunes the
  // per-leaf handle maps + ssh/ai-cli status state for dead leaves.
  useSessionDisposal({
    tabs,
    liveTabsByWorkspace,
    terminalRefs,
    searchAddons,
    detectedUrls,
    editorRefs,
    setSshStatuses,
    setAiCliStatuses,
  });

  // Adopt daemon PTY sessions created by another client (the remote-access
  // agent, when the browser hits "+") as real terminal tabs, and let the
  // daemon's Exit event (e.g. a browser-initiated close) tear the tab down.
  // Reuses the workspace-restore reattach machinery via newTab({ savedPtyId }).
  // Safe to re-enable: the launch hang was git commands on the UI thread (fixed
  // in 0.3.50), not this hook, and the adopt poll's pty_list_sessions is now
  // async so a slow daemon can't freeze the UI.
  useAdoptDaemonSessions({
    tabsRef,
    liveTabsByWorkspace,
    newTab,
    restoreDone: wsHydrated,
    enabled: !isDevSession,
  });

  const {
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
  } = useTabActions({
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
  });

  // On active leaf/tab change, surface the focused leaf's search addon,
  // editor handle, and detected URL to the chrome; track browser-pane titles.
  const { handleSearchReady, handleDetectedLocalUrl, handleProjectUrl, detectedBrowserUrl } =
    useActiveLeafSurface({
      searchAddons,
      editorRefs,
      detectedUrls,
      activeId,
      activeLeafIdInTab,
      activeLeafKindCurrent,
      isTerminalLike,
      setActiveSearchAddon,
      setActiveEditorHandle,
    });

  // The other half of the open-in-browser pill: finds a server the terminal
  // never saw start by reading the url the project declares for itself.
  useProjectUrl(explorerRoot, handleProjectUrl);

  const { handleOpenFile, handleOpenRemoteFile, handlePathRenamed, handlePathDeleted } =
    useFileActions({
      tabs,
      disposeTab,
      openFileTab,
      setEditorLeafPath,
      sshBindingByConnection,
    });

  // Drop a file onto an editor pane or the tab strip to open it, VSCode-style —
  // works for any absolute path, even outside the current workspace root. A
  // dropped folder opens a terminal tab rooted there instead. Routed through
  // `handleOpenFile` (not `openFileTab`) so a dropped PDF goes to the OS handler
  // exactly like one clicked in the explorer. Declared here rather than
  // beside the other drop listeners because it needs `handleOpenFile`.
  useEditorFileDrop({ openFile: handleOpenFile, newTerminalTab: newTab });

  // Explorer "Preview in Browser" (HTML files): hand the file:// URL to the OS
  // browser.
  const handlePreviewFileInBrowser = useCallback((path: string) => {
    const url = pathToFileUrl(path);
    if (url) void openUrl(url).catch(console.error);
  }, []);

  const { searchTarget, activeCwd, activeFilePath } = useChromeDerivations({
    isTerminalLike,
    isEditorLike,
    activeSearchAddon,
    activeEditorHandle,
    activeLeafIdInTab,
    activePaneTab,
    activeTab,
    terminalRefs,
    explorerRoot: explorerRoot ?? null,
  });

  const commandPaletteHandler = useCallback(() => {
    setCommandPaletteOpen((prev) => !prev);
  }, []);

  const shortcutHandlers = useMemo<ShortcutHandlers>(
    () =>
      buildShortcutHandlers({
        openNewTab,
        handleCloseTabOrPane,
        cycleTab,
        selectByIndex,
        splitActivePaneInActiveTab,
        focusNextPaneInTab,
        toggleSidebar,
        requestCloseLeaf,
        setNewEditorOpen,
        setAgentDialogOpen,
        searchInlineRef,
        editorRefs,
        terminalRefs,
        tabsRef,
        activeId,
        activeLeafIdInTab,
        activeLeafKindCurrent,
        commandPaletteOpen: commandPaletteHandler,
      }),
    [
      activeId,
      activeLeafIdInTab,
      activeLeafKindCurrent,
      requestCloseLeaf,
      cycleTab,
      handleCloseTabOrPane,
      openNewTab,
      selectByIndex,
      splitActivePaneInActiveTab,
      focusNextPaneInTab,
      toggleSidebar,
      commandPaletteHandler,
    ],
  );

  // The options object is read fresh each keydown (see useGlobalShortcuts), so
  // closing over activeLeafKindCurrent without a dep array is fine.
  useGlobalShortcuts(shortcutHandlers, {
    isDisabled: (id, e) =>
      // A focused terminal owns every bare-Ctrl control code (Ctrl+E, Ctrl+W,
      // Ctrl+K, Ctrl+L, Ctrl+[ Esc, Ctrl+I Tab, the tmux/screen prefix, …) and
      // every bare-Alt meta sequence (readline M-b / M-f / M-d / M-1..9). On
      // Win/Linux `Mod`=Ctrl, so those chords otherwise fire app actions (close
      // tab, word-wrap, …) and the byte never reaches the shell. Let them fall
      // through. Exception: pane.splitRight (Ctrl+D) always fires;
      // pane.splitDown already passes because it carries Shift. Terminal-safe
      // app chords keep Shift/Meta or add a second modifier (Ctrl+Shift+C copy,
      // Ctrl+Shift+X close, Ctrl+Alt+P, Shift+Alt+F) and stay active; Ctrl+Tab /
      // Ctrl+digit / zoom are not control codes either.
      id !== "pane.splitRight" &&
      activeLeafKindCurrent === "terminal" &&
      (isTerminalControlChord(e) || isTerminalMetaChord(e)),
  });

  const paneHandles = usePaneHandles({
    terminalRefs,
    editorRefs,
    tabsRef,
    activeLeafIdInTab,
    setActiveEditorHandle,
    handleClose,
    requestCloseLeaf,
    setLeafCwd,
    setLeafPtyId,
    focusPane,
    closePaneByLeaf,
    openFileTab,
    splitActivePane,
    newTab,
    setEditorLeafDirty,
  });

  const {
    handleOpenDetectedPreview,
    handleHeaderSelectEntry,
    handleHeaderCloseEntry,
    handleHeaderPinLeaf,
    handleHeaderOpenSettings,
    handleHeaderConnectSsh,
    headerCanSplit,
  } = useHeaderActions({
    activePaneTab,
    detectedBrowserUrl,
    handleClose,
    requestCloseLeaf,
    setActiveId,
    focusPane,
    pinTab,
    newSshTab,
  });

  // Activate a tab and focus a specific leaf inside it. Backs the Workspaces
  // panel's terminal list (jump straight to a running terminal).
  const focusLeafInTab = useCallback(
    (tabId: number, leafId: number) => {
      setActiveId(tabId);
      focusPane(tabId, leafId);
    },
    [setActiveId, focusPane],
  );

  const shell = (
    <ThemeProvider>
      <TooltipProvider>
        <div className="bg-background text-foreground relative flex h-screen flex-col overflow-hidden">
          <Header
            tabs={tabs}
            activeId={activeId}
            onSelectEntry={handleHeaderSelectEntry}
            onCloseEntry={handleHeaderCloseEntry}
            onNewTerminal={openNewTab}
            onRenameLeaf={renameLeaf}
            onOpenAgents={() => setAgentDialogOpen(true)}
            onPinLeaf={handleHeaderPinLeaf}
            onReorderTabs={reorderTabs}
            onReorderLeafInGroup={reorderLeafInGroup}
            onToggleSidebar={toggleSidebar}
            onOpenFolder={openWorkspaceFolder}
            onSplit={splitActivePaneInActiveTab}
            canSplit={headerCanSplit}
            onOpenSettings={handleHeaderOpenSettings}
            onConnectSsh={handleHeaderConnectSsh}
            onMoveLeafToGroup={moveLeafToGroup}
            onMoveLeafToNewTab={moveLeafToNewTab}
            onRotateLeafSplit={rotateLeafSplit}
            sshStatuses={sshStatuses}
            aiCliStatuses={aiCliStatuses}
            searchTarget={searchTarget}
            searchRef={searchInlineRef}
          />

          {/* Bento tray: the deep `bg-sidebar` well holds the three body columns
              as separate 1px-bordered cards, inset from the header/status bar and
              gapped from each other (`p-1.5` + `gap-1.5`). Under glass the gaps
              reveal the wallpaper, matching the floating-panels look. */}
          <main className="bg-sidebar flex min-h-0 flex-1 flex-col">
            <ResizablePanelGroup orientation="horizontal" className="min-h-0 flex-1 gap-1.5 p-1.5">
              <AppSidebar
                sidebarRef={sidebarRef}
                explorerRoot={explorerRoot}
                hasAnySshLeaf={hasAnySshLeaf}
                onOpenFile={handleOpenFile}
                onPathRenamed={handlePathRenamed}
                onPathDeleted={handlePathDeleted}
                onRevealInTerminal={cdInNewTab}
                onPreviewInBrowser={handlePreviewFileInBrowser}
                activeFilePath={activeFilePath}
                activeSshContext={activeSshContext}
                onOpenRemoteFile={handleOpenRemoteFile}
                sshInRightPanel={sshInRightPanel}
                onSwitchWorkspace={switchToWorkspace}
                onCreateWorkspace={createNewWorkspace}
                onCloseWorkspace={closeWorkspace}
                tabCounts={liveTabCounts}
                liveTabs={tabs}
                cachedTabsByWorkspace={liveTabsByWorkspace}
                onFocusLeaf={focusLeafInTab}
                onRenameLeaf={renameLeaf}
                onCloseEntry={handleHeaderCloseEntry}
                activeLeafId={activePaneTab?.activeLeafId ?? null}
                sshStatuses={sshStatuses}
                openBoardTab={openBoardTab}
              />
              <ResizableHandle withHandle />
              <WorkspaceArea
                tabs={tabs}
                activeId={activeId}
                activePaneTab={activePaneTab}
                uiZoom={uiZoom}
                paneHandles={paneHandles}
                onSearchReady={handleSearchReady}
                onDetectedLocalUrl={handleDetectedLocalUrl}
                onSshStatus={handleSshStatus}
                onAiCliStatus={handleAiCliStatusAndPersist}
                sshStatuses={sshStatuses}
                aiCliStatuses={aiCliStatuses}
                sshBindingByConnection={sshBindingByConnection}
                onReconnectSsh={handleReconnectSshForEditor}
                mdPreviewLeafIds={mdPreviewLeafIds}
                onToggleMdPreview={toggleMdPreviewForLeaf}
                detectedBrowserUrl={detectedBrowserUrl}
                onOpenPreview={handleOpenDetectedPreview}
                movePaneLeafToEdge={movePaneLeafToEdge}
                setLeafTerminalTheme={setLeafTerminalTheme}
                onSplitSizes={setSplitSizes}
              />
              <AppRightSlot
                rightSections={rightSections}
                sshRightOpen={sshRightOpen}
                explorerRoot={explorerRoot}
                onPathDeleted={handlePathDeleted}
                closeSshRight={closeSshRight}
                activeSshContext={activeSshContext}
                onOpenRemoteFile={handleOpenRemoteFile}
                filesSection={{
                  onOpenFile: handleOpenFile,
                  onPathRenamed: handlePathRenamed,
                  onRevealInTerminal: cdInNewTab,
                  onPreviewInBrowser: handlePreviewFileInBrowser,
                  activeFilePath,
                }}
                workspacesSection={{
                  onSwitch: switchToWorkspace,
                  onCreate: createNewWorkspace,
                  onCloseWorkspace: closeWorkspace,
                  tabCounts: liveTabCounts,
                  liveTabs: tabs,
                  cachedTabsByWorkspace: liveTabsByWorkspace,
                  onFocusLeaf: focusLeafInTab,
                  onRenameLeaf: renameLeaf,
                  onCloseEntry: handleHeaderCloseEntry,
                  activeLeafId: activePaneTab?.activeLeafId ?? null,
                  sshStatuses,
                }}
                openBoardTab={openBoardTab}
              />
            </ResizablePanelGroup>
          </main>

          <StatusBar
            cwd={activeCwd}
            filePath={activeFilePath}
            home={home}
            onCd={sendCd}
            hasAnySshLeaf={hasAnySshLeaf}
            activeIsSsh={activeLeafIsSsh}
            sshSessionId={activeLeafIsSsh ? activeSshContext.sessionId : null}
            sshRoute={
              activeLeafIdInTab != null ? sshStatuses.get(activeLeafIdInTab)?.route : undefined
            }
          />

          <Toaster />

          <CommandPalette
            open={commandPaletteOpen}
            onOpenChange={setCommandPaletteOpen}
            explorerRoot={explorerRoot ?? null}
            onOpenFile={handleOpenFile}
          />

          <AppDialogs
            agentDialogMounted={agentDialogMounted}
            agentDialogOpen={agentDialogOpen}
            setAgentDialogOpen={setAgentDialogOpen}
            onSpawnAgents={spawnAgents}
            newEditorMounted={newEditorMounted}
            newEditorOpen={newEditorOpen}
            setNewEditorOpen={setNewEditorOpen}
            explorerRoot={explorerRoot}
            home={home}
            openFileTab={openFileTab}
            sshEditorMounted={sshEditorMounted}
            sshEditorOpen={sshEditorOpen}
            setSshEditorOpen={setSshEditorOpen}
            editingSshConn={editingSshConn}
            setEditingSshConn={setEditingSshConn}
            pendingClose={pendingClose}
            cancelClose={cancelClose}
            confirmClose={confirmClose}
            quitGuard={quitGuard}
          />
        </div>
      </TooltipProvider>
    </ThemeProvider>
  );

  return shell;
}
