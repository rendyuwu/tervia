import { type EditorPaneHandle } from "@/modules/editor";
import { activeLeaf, type Tab } from "@/modules/tabs";
import { isLastEntryInWorkspace } from "@/modules/tabs/lib/entries";
import {
  hasLeaf,
  leafIds,
  leaves,
  respawnSession,
  type TerminalPaneHandle,
  type TerviaOpenInput,
  type TerviaSpawnTabInput,
} from "@/modules/terminal";
import { useCallback, useRef, type Dispatch, type RefObject, type SetStateAction } from "react";
import { isQuitting } from "./useQuitGuard";
import { type TabsApi } from "./tabsApi";

type Params = {
  terminalRefs: RefObject<Map<number, TerminalPaneHandle>>;
  editorRefs: RefObject<Map<number, EditorPaneHandle>>;
  tabsRef: RefObject<Tab[]>;
  activeLeafIdInTab: number | null;
  setActiveEditorHandle: Dispatch<SetStateAction<EditorPaneHandle | null>>;
  handleClose: (id: number) => void;
  requestCloseLeaf: (leafId: number) => void;
} & Pick<
  TabsApi,
  | "setLeafCwd"
  | "setLeafPtyId"
  | "focusPane"
  | "closePaneByLeaf"
  | "openFileTab"
  | "splitActivePane"
  | "newTab"
  | "setEditorLeafDirty"
>;

/**
 * The PaneStack wiring: handle registration plus the per-leaf lifecycle
 * callbacks (cwd / ptyId / focus / exit / dirty / close). Moved verbatim from
 * App with identical dependency arrays. `handleClose` is threaded in from
 * `useTabActions` because the editor/pane-header close paths share it.
 */
export function usePaneHandles({
  terminalRefs,
  editorRefs,
  tabsRef,
  activeLeafIdInTab,
  setActiveEditorHandle,
  setLeafCwd,
  setLeafPtyId,
  focusPane,
  closePaneByLeaf,
  openFileTab,
  splitActivePane,
  newTab,
  setEditorLeafDirty,
  handleClose,
  requestCloseLeaf,
}: Params): {
  registerTerminalHandle: (leafId: number, h: TerminalPaneHandle | null) => void;
  registerEditorHandle: (leafId: number, h: EditorPaneHandle | null) => void;
  handleTerminalCwd: (leafId: number, cwd: string) => void;
  handlePtyId: (leafId: number, ptyId: string) => void;
  handleFocusLeaf: (tabId: number, leafId: number) => void;
  handleLeafExit: (leafId: number, _code: number) => void;
  handleTerviaOpen: (_leafId: number, input: TerviaOpenInput) => void;
  handleTerviaSpawnTab: (_leafId: number, input: TerviaSpawnTabInput) => void;
  handleEditorDirty: (leafId: number, dirty: boolean) => void;
  handleEditorCloseLeaf: (leafId: number) => void;
  handlePaneHeaderClose: (leafId: number) => void;
} {
  const registerTerminalHandle = useCallback((leafId: number, h: TerminalPaneHandle | null) => {
    if (h) terminalRefs.current.set(leafId, h);
    else terminalRefs.current.delete(leafId);
  }, []);

  const registerEditorHandle = useCallback(
    (leafId: number, h: EditorPaneHandle | null) => {
      if (h) editorRefs.current.set(leafId, h);
      else editorRefs.current.delete(leafId);
      if (leafId === activeLeafIdInTab) setActiveEditorHandle(h);
    },
    [activeLeafIdInTab],
  );

  const handleTerminalCwd = useCallback(
    (leafId: number, cwd: string) => setLeafCwd(leafId, cwd),
    [setLeafCwd],
  );

  // Fires once whenever a terminal leaf acquires a daemon-side PTY UUID.
  // Stamping it onto the leaf lets the workspace serializer persist it
  // so the next launch can `pty_attach` instead of spawning fresh.
  const handlePtyId = useCallback(
    (leafId: number, ptyId: string) => setLeafPtyId(leafId, ptyId),
    [setLeafPtyId],
  );

  const handleFocusLeaf = useCallback(
    (tabId: number, leafId: number) => focusPane(tabId, leafId),
    [focusPane],
  );

  const handleLeafExit = useCallback(
    (leafId: number, _code: number) => {
      // Quitting: the shells are being killed on purpose (force quit), so every
      // Exit here is our own doing. Reshaping the layout now would persist a
      // torn-down workspace over the user's real one - and the respawn branch
      // below would spawn a FRESH shell that then outlives the GUI, which is
      // the exact opposite of "close all terminals".
      if (isQuitting()) return;
      const all = tabsRef.current;
      const tab = all.find((t) => t.kind === "pane" && hasLeaf(t.paneTree, leafId));
      if (!tab || tab.kind !== "pane") return;
      // Respawn only to keep the window from going empty - i.e. when this pane
      // is the last thing on screen. Anything else, including the only terminal
      // in a workspace whose other tab is a Hosts page, just closes.
      const targetLeaf = leaves(tab.paneTree).find((l) => l.id === leafId);
      const cwd = targetLeaf?.leafKind === "terminal" ? targetLeaf.cwd : undefined;
      if (isLastEntryInWorkspace(all, leafId)) {
        void respawnSession(leafId, cwd);
      } else {
        closePaneByLeaf(leafId);
      }
    },
    [closePaneByLeaf],
  );

  const handleTerviaOpen = useCallback(
    (_leafId: number, input: TerviaOpenInput) => {
      openFileTab(input.file);
    },
    [openFileTab],
  );

  // OSC 8889: shell asks Tervia to open a new terminal tab at `cwd` and run
  // `cmd`. Used by tools like Laravel's `php artisan dev:serve` to keep
  // dev processes inside Tervia instead of spawning cmd.exe windows.
  //
  // If `split` is set, splits the last spawned pane in the same tab
  // instead of opening a new tab. Lets `dev:serve` cluster
  // Vite/Reverb/Queue into one tab with horizontal splits.
  const lastSpawnedTabIdRef = useRef<number | null>(null);
  const handleTerviaSpawnTab = useCallback(
    (_leafId: number, input: TerviaSpawnTabInput) => {
      const cwd = input.cwd;
      const cmd = input.cmd;

      const writeIntoLeaf = (leafId: number) => {
        if (!cmd) return;
        setTimeout(() => {
          const t = terminalRefs.current.get(leafId);
          if (!t) return;
          t.write(`${cmd}\r`);
          t.focus();
        }, 120);
      };

      // Split path requires a previous spawned tab still alive.
      if (input.split) {
        const lastTabId = lastSpawnedTabIdRef.current;
        const lastTab = lastTabId !== null ? tabsRef.current.find((x) => x.id === lastTabId) : null;
        if (lastTab && lastTab.kind === "pane") {
          const newLeafId = splitActivePane(lastTabId!, input.split);
          if (newLeafId !== null) {
            writeIntoLeaf(newLeafId);
            return;
          }
          // Split refused (e.g. MAX_PANES_PER_TAB). Fall through to new tab.
        }
      }

      const tabId = newTab(cwd);
      lastSpawnedTabIdRef.current = tabId;
      if (!cmd) return;
      // Wait for the new PTY to be ready before injecting the command.
      setTimeout(() => {
        const tab = tabsRef.current.find((x) => x.id === tabId);
        if (!tab || tab.kind !== "pane") return;
        const leaf = activeLeaf(tab);
        if (!leaf || leaf.leafKind !== "terminal") return;
        const t = terminalRefs.current.get(leaf.id);
        if (!t) return;
        t.write(`${cmd}\r`);
        t.focus();
      }, 120);
    },
    [newTab, splitActivePane],
  );

  const handleEditorDirty = useCallback(
    (leafId: number, dirty: boolean) => setEditorLeafDirty(leafId, dirty),
    [setEditorLeafDirty],
  );

  const handleEditorCloseLeaf = useCallback(
    (leafId: number) => {
      // `:q` in a split pane should close only that pane.
      const tab = tabsRef.current.find((t) => t.kind === "pane" && hasLeaf(t.paneTree, leafId));
      if (!tab || tab.kind !== "pane") return;
      if (leafIds(tab.paneTree).length > 1) {
        closePaneByLeaf(leafId);
      } else {
        handleClose(tab.id);
      }
    },
    [closePaneByLeaf, handleClose],
  );

  // Pane header close button: drop the leaf when it shares a tab, otherwise
  // close the whole tab (mirrors the tab-strip leaf close semantics). Both
  // routes confirm first when a terminal is running a process.
  const handlePaneHeaderClose = useCallback(
    (leafId: number) => {
      const tab = tabsRef.current.find((t) => t.kind === "pane" && hasLeaf(t.paneTree, leafId));
      if (!tab || tab.kind !== "pane") return;
      if (leafIds(tab.paneTree).length > 1) {
        requestCloseLeaf(leafId);
      } else {
        handleClose(tab.id);
      }
    },
    [requestCloseLeaf, handleClose],
  );

  return {
    registerTerminalHandle,
    registerEditorHandle,
    handleTerminalCwd,
    handlePtyId,
    handleFocusLeaf,
    handleLeafExit,
    handleTerviaOpen,
    handleTerviaSpawnTab,
    handleEditorDirty,
    handleEditorCloseLeaf,
    handlePaneHeaderClose,
  };
}
