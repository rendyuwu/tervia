import { type RefObject } from "react";
import { readClipboardText } from "@/lib/clipboard";
import { openSettingsWindow } from "@/modules/settings/openSettingsWindow";
import { usePreferencesStore } from "@/modules/settings/preferences";
import {
  setContentZoom,
  setLineWrap,
  CONTENT_ZOOM_DEFAULT,
  CONTENT_ZOOM_MAX,
  CONTENT_ZOOM_MIN,
  CONTENT_ZOOM_STEP,
} from "@/modules/settings/store";
import { type ShortcutHandlers } from "@/modules/shortcuts";
import { type TerminalPaneHandle } from "@/modules/terminal";
import { type EditorPaneHandle } from "@/modules/editor";
import { type SearchInlineHandle } from "@/modules/header";
import { type RailViewKind, type TabPageKind } from "@/modules/tabs";

/**
 * Component-local identifiers from App that the keyboard-shortcut handler
 * map closes over. Module-level dependencies (stores, constants,
 * openSettingsWindow) are imported directly above and are NOT threaded
 * through here. See App.tsx for the call site and its memo dep array.
 */
export interface ShortcutHandlerDeps {
  openNewTab: () => void;
  handleCloseTabOrPane: () => void;
  cycleTab: (delta: 1 | -1) => void;
  selectByIndex: (idx: number) => void;
  splitActivePaneInActiveTab: (dir: "row" | "col", kind?: "terminal" | "editor") => void;
  focusNextPaneInTab: (tabId: number, delta: 1 | -1) => void;
  toggleSidebar: () => void;
  requestCloseLeaf: (leafId: number) => void;
  setNewEditorOpen: (open: boolean) => void;
  setAgentDialogOpen: (open: boolean) => void;
  /** Open a page tab, and leave any rail view that is covering the tab area.
   *  Backs `rdp.connect` below, repointed at the Hosts page now that connecting
   *  lives there instead of behind the RDP dropdown. */
  openPageTab: (page: TabPageKind) => void;
  searchInlineRef: RefObject<SearchInlineHandle | null>;
  editorRefs: RefObject<Map<number, EditorPaneHandle>>;
  terminalRefs: RefObject<Map<number, TerminalPaneHandle>>;
  activeId: number;
  activeLeafIdInTab: number | null;
  activeLeafKindCurrent: "terminal" | "editor" | "rdp" | null;
  /**
   * The rail view covering the tab area, or null when the tabs are showing.
   *
   * Only the two CLOSING chords read it, and they read it HERE rather than at
   * the mutation, which is the one place in the rail-view rule where those two
   * differ. Every other route into the tab area leaves the view inside
   * `useTabs` (`tabs/lib/tabView.ts`), so no caller can forget - but the close
   * paths are shared with the tab-strip X, and the decision in force is that
   * clicking a background tab's X while the Vault is up leaves you in the
   * Vault. That X names the tab it closes and is on screen; a chord names "the
   * active tab", which is exactly what a rail view has taken off screen. So the
   * refusal belongs to the chord, not to `closeTab` / `closePaneByLeaf`.
   */
  railView: RailViewKind | null;
  commandPaletteOpen: () => void;
}

export function buildShortcutHandlers(deps: ShortcutHandlerDeps): ShortcutHandlers {
  const {
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
    openPageTab,
    searchInlineRef,
    editorRefs,
    terminalRefs,
    activeId,
    activeLeafIdInTab,
    activeLeafKindCurrent,
    railView,
    commandPaletteOpen,
  } = deps;
  /**
   * A rail view is covering the tab area, so there is nothing on screen for a
   * closing chord to be aimed at. Both close chords ask this and do nothing -
   * they are the only two chords here that DESTROY: everything else either
   * mints something (Ctrl+T, Ctrl+D) or moves focus (Ctrl+], Ctrl+1..9), and
   * those all leave the view through `useTabs` and show the user their own
   * result. A close cannot show its result - the thing it did is gone - so a
   * chord that fires it against an unseen tab would end a session with no
   * feedback at all. See `ShortcutHandlerDeps.railView` for why this is not
   * enforced at the mutation.
   */
  const coveredByRailView = () => railView !== null;
  return {
    "commandPalette.open": commandPaletteOpen,
    "tab.new": openNewTab,
    "tab.newEditor": () => setNewEditorOpen(true),
    "tab.newAgent": () => setAgentDialogOpen(true),
    // Used to raise the RDP dropdown; connecting now lives on the Hosts page.
    "rdp.connect": () => openPageTab("hosts"),
    "tab.close": () => {
      if (coveredByRailView()) return;
      handleCloseTabOrPane();
    },
    "tab.next": () => cycleTab(1),
    "tab.prev": () => cycleTab(-1),
    "tab.selectByIndex": (e) => selectByIndex(parseInt(e.key, 10) - 1),
    // Ctrl+D: horizontal split (new pane beside focus).
    // Ctrl+Shift+D: vertical split (new pane below focus).
    "pane.splitRight": () => splitActivePaneInActiveTab("row"),
    "pane.splitDown": () => splitActivePaneInActiveTab("col"),
    "pane.focusNext": () => focusNextPaneInTab(activeId, 1),
    "pane.focusPrev": () => focusNextPaneInTab(activeId, -1),
    "search.focus": () => searchInlineRef.current?.focus(),
    "editor.findReplace": () => {
      // VSCode-style Ctrl+H opens the find/replace overlay inside the
      // active editor. Falls through silently when the focused leaf isn't
      // an editor; the global shortcut still consumes the key to match
      // VSCode's behavior of preventing the browser's history palette.
      if (activeLeafKindCurrent !== "editor" || activeLeafIdInTab === null) return;
      const handle = editorRefs.current.get(activeLeafIdInTab);
      handle?.openFindReplace();
    },
    "shortcuts.open": () => void openSettingsWindow("shortcuts"),
    "settings.open": () => void openSettingsWindow(),
    "sidebar.toggle": toggleSidebar,
    "view.zoomIn": () => {
      const current = usePreferencesStore.getState().contentZoom;
      const next = Math.min(
        CONTENT_ZOOM_MAX,
        Math.round((current + CONTENT_ZOOM_STEP) * 100) / 100,
      );
      if (next !== current) void setContentZoom(next);
    },
    "view.zoomOut": () => {
      const current = usePreferencesStore.getState().contentZoom;
      const next = Math.max(
        CONTENT_ZOOM_MIN,
        Math.round((current - CONTENT_ZOOM_STEP) * 100) / 100,
      );
      if (next !== current) void setContentZoom(next);
    },
    "view.zoomReset": () => {
      if (usePreferencesStore.getState().contentZoom !== CONTENT_ZOOM_DEFAULT) {
        void setContentZoom(CONTENT_ZOOM_DEFAULT);
      }
    },
    "editor.toggleWordWrap": () => {
      void setLineWrap(!usePreferencesStore.getState().lineWrap);
    },
    "editor.formatDocument": () => {
      // Falls through silently when the focused leaf isn't an editor —
      // matches VSCode's behaviour of consuming the chord regardless so
      // the OS / browser default never fires.
      if (activeLeafKindCurrent !== "editor" || activeLeafIdInTab === null) return;
      void editorRefs.current.get(activeLeafIdInTab)?.formatDocument();
    },
    // Copy terminal selection. Defaults: Cmd+C on macOS, Ctrl+Shift+C
    // elsewhere (see shortcuts.ts). No-op when nothing is selected.
    // useGlobalShortcuts preventDefaults the event so xterm never sees
    // it. Bare Ctrl+C falls through to xterm and sends SIGINT.
    "terminal.copy": () => {
      if (activeLeafIdInTab === null || activeLeafKindCurrent !== "terminal") return;
      const term = terminalRefs.current.get(activeLeafIdInTab);
      const sel = term?.getSelection();
      if (!sel) return;
      // Clipboard WRITES work through the webview API on every OS (they ride
      // the keystroke's user gesture); only reads need the host process, see
      // `readClipboardText`. Fire-and-forget; the usual failure is the document
      // not yet focused (window-switch race) and the user can retry.
      void navigator.clipboard.writeText(sel).catch((e) => {
        console.warn("terminal.copy: clipboard write failed:", e);
      });
    },
    // Paste clipboard via term.paste so the shell gets a bracketed
    // paste (multi-line snippets don't auto-execute line by line under
    // bash/zsh). Defaults: Cmd+V on macOS, Ctrl+Shift+V or Shift+Insert
    // elsewhere (see shortcuts.ts).
    "terminal.paste": () => {
      if (activeLeafIdInTab === null || activeLeafKindCurrent !== "terminal") return;
      const term = terminalRefs.current.get(activeLeafIdInTab);
      if (!term) return;
      void readClipboardText().then((text) => {
        if (text) term.paste(text);
      });
    },
    // Ctrl+Shift+X: close the focused pane, through `requestCloseLeaf` so a busy
    // terminal confirms before being killed. Deliberately carries no count of
    // its own: `tabs/lib/closable.ts` is the single arbiter of whether a close
    // is legal and `requestCloseLeaf` asks it, which is what keeps this chord
    // agreeing with the pane-header and tab-strip X buttons rather than refusing
    // what they allow - or, as it did, allowing what they refuse.
    //
    // IT HAD A SECOND GATE. `activeLeafKindCurrent !== "terminal"`
    // dropped the chord for an RDP pane, whose leaf kind is `"rdp"` - so both X
    // buttons closed an RDP tab and the chord silently did nothing, which is the
    // exact disagreement the single-arbiter argument above claims cannot happen.
    // The arbiter itself was never the problem: `closable.ts` asks only whether
    // the leaf is a page and whether it is the last entry, so it has always
    // treated an RDP leaf exactly like a terminal one. What made the claim false
    // was a kind test standing IN FRONT of it, in the chord that quoted it. So
    // the kind test is gone and `canCloseLeaf` is genuinely the only thing
    // deciding - which is also what makes the label "Close focused pane"
    // honest, and why the id keeps its `terminal.` prefix (a user's rebinding
    // is stored under it).
    //
    // With no kind test, the chord can now reach a page leaf; `leafCloseRefusal`
    // refuses it as permanent, and both X buttons are absent there, so its
    // silence still never contradicts a visible affordance.
    //
    // It also reaches an EDITOR leaf for the first time, and `requestCloseLeaf`
    // used to confirm only on a busy terminal - so this chord discarded an
    // unsaved buffer that the pane-header X and `Ctrl+W` both prompt for. The
    // fix is at the funnel, not here: `leafCloseConfirmReason` in `closable.ts`
    // now answers "must this be confirmed" for every close path, the same way
    // `leafCloseRefusal` answers "may it happen". Adding the check here would
    // have left the tab-strip X and the split pane-header X still dropping it.
    "terminal.close": () => {
      if (coveredByRailView()) return;
      if (activeLeafIdInTab === null) return;
      requestCloseLeaf(activeLeafIdInTab);
    },
  };
}
