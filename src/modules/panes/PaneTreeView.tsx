import {
  createContext,
  Fragment,
  lazy,
  memo,
  Suspense,
  use,
  useCallback,
  useMemo,
  useRef,
  useState,
  type RefObject,
} from "react";
import {
  DndContext,
  DragOverlay,
  PointerSensor,
  pointerWithin,
  useDraggable,
  useDroppable,
  useSensor,
  useSensors,
  type DragEndEvent,
  type DragMoveEvent,
  type DragStartEvent,
} from "@dnd-kit/core";
import { ResizableHandle, ResizablePanel, ResizablePanelGroup } from "@/components/ui/resizable";
import { basename } from "@/lib/path";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { TERMINAL_PRESETS, type TerminalPalette } from "@/modules/settings/terminalPalette";
import { usePreferencesStore } from "@/modules/settings/preferences";
import { setLineWrap } from "@/modules/settings/store";
import { shortcutHint } from "@/modules/shortcuts/shortcuts";
import { IconTooltip } from "@/components/ui/icon-tooltip";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { LeafIcon, type LeafIconInfo } from "@/components/LeafIcon";
import { cn } from "@/lib/utils";
import { type EditorPaneHandle } from "@/modules/editor";
import { useExplorerIconsReady } from "@/modules/explorer/lib/iconResolver";
import { WorkspaceBoard } from "@/modules/workspaces/WorkspaceBoard";
import { RdpPane } from "@/modules/rdp/RdpPane";
import { fireRdpPaneAction } from "@/modules/rdp/paneActions";
import { TerminalPane, type TerminalPaneHandle } from "@/modules/terminal";
import type { SearchAddon } from "@xterm/addon-search";
import type { PaneEdge, PaneLeaf, PaneNode, TabPageKind } from "@/modules/terminal/lib/panes";
import { editorPaneSession, isRemoteEditorLeaf, leaves } from "@/modules/terminal/lib/panes";
import type {
  TerviaOpenInput,
  TerviaSpawnTabInput,
} from "@/modules/terminal/lib/useTerminalSession";
import { statusLabelClass, type SshConnectionBinding, type SshStatus } from "@/modules/ssh/status";
import { type PaneEntry } from "@/modules/tabs/lib/entries";
import type { Tab } from "@/modules/tabs";
import { leafLabel } from "@/modules/tabs/lib/tabHelpers";
import { HostsPage } from "@/modules/hosts/HostsPage";
import type { Host } from "@/modules/hosts/types";
import { type AiCliStatus } from "@/modules/terminal/lib/aiCliStatus";
import { useTerminalTitles } from "@/modules/terminal/lib/terminalTitles";
import { closeFloat, floatPane, pushBoardCards } from "./floatHost";
import { useFloatStore } from "./floatStore";
import type { FloatLeafParams } from "./floatProtocol";
import {
  BookOpen,
  Cloud,
  FileCode,
  Globe,
  GripVertical,
  Keyboard,
  Settings,
  SquareArrowOutUpRight,
  WrapText,
  X,
} from "lucide-react";

// Lazy so the ~1.5MB editor stack (CodeMirror + streamdown + markdown + katex)
// is only fetched+parsed when an editor leaf actually renders, not on every
// launch. PaneTreeView is on the boot render tree but the default/most common
// tab is a terminal, so this keeps the editor bundle off first paint. The
// separate float.html entry (FloatApp) still imports EditorPane directly.
const EditorPane = lazy(() => import("@/modules/editor").then((m) => ({ default: m.EditorPane })));

/** Leaf kinds that can be floated into their own window. Terminals mirror live
 *  over Tauri events (the primary "watch an agent while working" case); an SSH
 *  pane is a terminal leaf so it floats through the same path. Editor float is a
 *  deliberate follow-up, not a bootstrap problem: EditorPane is self-contained
 *  (file IO by path, cross-window-safe) and FloatApp already renders it, but
 *  it hands off: the main pane unmounts its editor while floating (so two live
 *  CodeMirror views can't race and save-stomp the same file) and saves before
 *  float + on dock-back. Remote/SFTP editors depend on the main window's russh
 *  session, so those are gated out. NOTE: float windows only run on a real Tauri
 *  build, so this path is build-green but needs a manual smoke test. */
function floatParamsFor(node: PaneLeaf, title: string): FloatLeafParams | null {
  if (node.leafKind === "terminal")
    return {
      leafId: node.id,
      kind: "terminal",
      title,
      remotePty: node.sshConnectionId !== undefined,
    };
  if (node.leafKind === "editor" && !isRemoteEditorLeaf(node))
    return {
      leafId: node.id,
      kind: "editor",
      title,
      path: node.path,
    };
  // A board mirrors like a terminal rather than handing off: it is a list, so
  // the main-window pane stays mounted (it owns the tab tree the float has no
  // copy of) and pushes its cards over.
  if (node.leafKind === "board") return { leafId: node.id, kind: "board", title };
  // RDP is deliberately not floatable, and `rdp` is deliberately absent from
  // `FloatKind`. Neither of the two float strategies fits: it cannot MIRROR
  // (that would fan every frame batch to a second webview, and one batch can be
  // a whole framebuffer), and it cannot HAND OFF (a session belongs to the
  // channel that opened it, so the float would have to dial its own - a second
  // login on the same desktop, which is not what popping a pane out means).
  // Returning null here hides the float button; adding a `FloatKind` member
  // without a `floatPane` branch is what would crash.
  return null;
}

export type LeafBundle = {
  // terminal-only
  setTerminalRef: (h: TerminalPaneHandle | null) => void;
  onSearchReady: (addon: SearchAddon) => void;
  onCwd: (cwd: string) => void;
  onDetectedLocalUrl: (url: string) => void;
  onExit: (code: number) => void;
  onTerviaOpen: (input: TerviaOpenInput) => void;
  onTerviaSpawnTab: (input: TerviaSpawnTabInput) => void;
  onSshStatus: (status: SshStatus) => void;
  onAiCliStatus: (status: AiCliStatus) => void;
  onPtyId: (ptyId: string) => void;
  // editor-only
  setEditorRef: (h: EditorPaneHandle | null) => void;
  onDirtyChange: (dirty: boolean) => void;
  onCloseLeaf: () => void;
};

type Props = {
  node: PaneNode;
  tabVisible: boolean;
  activeLeafId: number;
  onFocusLeaf: (leafId: number) => void;
  getBundle: (leafId: number) => LeafBundle;
  /** Editor leaf ids currently rendered in markdown preview. */
  mdPreviewLeafIds: ReadonlySet<number>;
  /** Drag-and-drop: drop `sourceLeafId` onto an `edge` of `targetLeafId`. */
  onMovePaneLeaf?: (sourceLeafId: number, targetLeafId: number, edge: PaneEdge) => void;
  /** Close button in a pane header. Hidden when omitted. */
  onCloseLeaf?: (leafId: number) => void;
  /** Whether this leaf's close is allowed, from the one close predicate
   *  (`tabs/lib/closable.ts`). Threaded in rather than derived here because the
   *  answer depends on the whole workspace, which a pane tree does not know.
   *  Omitted means "no gate", the default a caller without a tab list gets. */
  canCloseLeaf?: (leafId: number) => boolean;
  /** Set (or clear, with `null`) a terminal leaf's per-pane theme override.
   *  `themeId` is a `TERMINAL_PRESETS` id. Backs the header "Terminal theme" menu. */
  onSetTerminalTheme?: (leafId: number, themeId: string | null) => void;
  /** Flip a markdown editor leaf between source and preview. Backs the pane
   *  header's book/code toggle (it used to live in the app toolbar). */
  onToggleMdPreview?: (leafId: number) => void;
  /** Detected local URL for the "open preview" globe, already resolved against
   *  the *active* leaf. Shown on the focused pane's header (it used to sit in
   *  the app toolbar); `null` hides it. */
  detectedBrowserUrl?: string | null;
  onOpenPreview?: () => void;
  /** Persist a split node's per-child size percentages after a divider drag. */
  onSplitSizes?: (splitId: number, sizes: number[]) => void;
  /** Saved hosts, keyed by id. Resolves a leaf's `ssh:<host>` / `rdp:<host>` label. */
  hosts?: Map<string, Host>;
  /** Live SSH status per terminal leaf id. Colors the SSH header label. */
  sshStatuses?: Map<number, SshStatus>;
  /** Live AI CLI status per terminal leaf id. Tints the header icon (idle/working/blocking). */
  aiCliStatuses?: Map<number, AiCliStatus>;
  /** Live session per saved SSH connection, for remote editor leaves. */
  sshBindingByConnection?: Map<string, SshConnectionBinding>;
  /** Open an SSH session for a saved connection (remote editor reconnect). */
  onReconnectSsh?: (connectionId: string, title: string) => void;
  /** Every tab in the workspace, for a board leaf. */
  boardTabs?: Tab[];
  /** Focus any leaf in any tab, for a board leaf's cards. */
  onFocusEntry?: (tabId: number, leafId: number) => void;
  /** Connect a saved host through App's connect path, routed by
   *  `host.protocol`. Backs the Hosts page leaf body's connect action (6d). */
  onConnectHost?: (host: Host) => void;
};

type PaneDragState = {
  sourceLeafId: number | null;
  overLeafId: number | null;
  edge: PaneEdge | null;
};

type PaneDndValue = {
  drag: PaneDragState;
  leafCount: number;
  onCloseLeaf?: (leafId: number) => void;
  canCloseLeaf?: (leafId: number) => boolean;
  onSetTerminalTheme?: (leafId: number, themeId: string | null) => void;
  onToggleMdPreview?: (leafId: number) => void;
  detectedBrowserUrl?: string | null;
  onOpenPreview?: () => void;
};

const PaneDndContext = createContext<PaneDndValue>({
  drag: { sourceLeafId: null, overLeafId: null, edge: null },
  leafCount: 1,
});

/** Radio value for "follow the global terminal theme" (clears the override). */
const FOLLOW_GLOBAL_THEME = "__follow_global__";

/** Compact palette chip for a terminal-theme menu row. */
function ThemeSwatch({ palette }: { palette: TerminalPalette }) {
  const dots = [palette.ansi.red, palette.ansi.green, palette.ansi.blue, palette.ansi.yellow];
  return (
    <span
      aria-hidden
      className="border-border/40 flex h-3.5 w-7 shrink-0 items-center gap-[2px] overflow-hidden rounded-[3px] border px-1"
      style={{ background: palette.background }}
    >
      {dots.map((c, i) => (
        <span key={i} className="size-1.5 rounded-full" style={{ background: c }} />
      ))}
    </span>
  );
}

type PaneMetaValue = {
  hosts?: Map<string, Host>;
  sshStatuses?: Map<number, SshStatus>;
  aiCliStatuses?: Map<number, AiCliStatus>;
  sshBindingByConnection?: Map<string, SshConnectionBinding>;
  onReconnectSsh?: (connectionId: string, title: string) => void;
  /** Every tab in the workspace, for a board leaf - the only leaf kind whose
   *  content is the OTHER leaves. Rides this context rather than `LeafBundle`
   *  because a bundle is per-leaf and this is workspace-wide. */
  boardTabs?: Tab[];
  /** Focus any leaf in any tab. A board leaf's cards address panes outside
   *  their own tab, which the per-tab `onFocusLeaf` cannot express. */
  onFocusEntry?: (tabId: number, leafId: number) => void;
  /** Connect a saved host through App's connect path, routed by
   *  `host.protocol`. Read by `PageLeafBody`'s Hosts case (6d); it rides this
   *  context rather than a prop on `PageLeafBody` alone because App's connect
   *  handlers are workspace-wide, same reasoning as `onFocusEntry` above. */
  onConnectHost?: (host: Host) => void;
};

// SSH host/status lives in its own context so status pushes re-render only the
// leaf headers (not the memoized split tree or xterm/CodeMirror bodies).
const PaneMetaContext = createContext<PaneMetaValue>({});

/**
 * A board leaf's body. Its own component, and deliberately NOT part of the
 * memoized `LeafBody`: it is the one leaf that must re-render on every AI status
 * push, and subscribing `LeafBody` to that context would drag every xterm and
 * CodeMirror in the workspace along with it.
 */
function BoardLeafBody({ leafId }: { leafId: number }) {
  const { boardTabs, sshStatuses, aiCliStatuses, onFocusEntry } = use(PaneMetaContext);
  // Feed the float window. Stable so the board's mirror effect isn't re-run by
  // this callback's identity alone.
  const mirrorToFloat = useCallback(
    (cards: PaneEntry[], titles: Record<number, string>) =>
      pushBoardCards(leafId, { entries: cards, titles }),
    [leafId],
  );
  return (
    <WorkspaceBoard
      tabs={boardTabs ?? []}
      sshStatuses={sshStatuses}
      aiCliStatuses={aiCliStatuses}
      onFocusLeaf={onFocusEntry}
      mirrorToFloat={mirrorToFloat}
    />
  );
}

/**
 * A page leaf's body. Hosts is the only case there is: DCR-1 made Vault and Port
 * Forwarding rail VIEWS rather than tabs, and `PageLeafState.page` is
 * `TabPageKind`, so no other page can reach here.
 *
 * A `switch` rather than an `if`, so widening `TabPageKind` later fails to
 * compile here instead of silently rendering nothing.
 */
function PageLeafBody({ page, onScreen }: { page: TabPageKind; onScreen: boolean }) {
  const { onConnectHost } = use(PaneMetaContext);
  switch (page) {
    case "hosts":
      return (
        <HostsPage
          // `onConnectHost` is optional only because `PaneMetaContext`'s default
          // value (`{}`) has to type-check; App always supplies the real
          // dispatcher, so this fallback is never a state a real user reaches -
          // it exists for the context default, not as a supported no-op path.
          onConnect={onConnectHost ?? (() => {})}
          // "The user is looking at this page": its tab is on screen AND it is
          // the focused pane. `PaneStack` keeps an inactive tab's leaves mounted
          // (hidden via `visibility:hidden`, which a focus() call cannot reach),
          // so the page's own mount-only focus effect would fire once - while it
          // was not even visible - and never again for a tab restored into the
          // background. Forwarded so it can re-fire on becoming visible.
          //
          // `focused` is in the signal, not just tab visibility: in a tab that
          // splits Hosts beside a terminal, switching to that tab would
          // otherwise pull the caret out of the terminal and into this page's
          // search box. Single-leaf Hosts tabs - the ordinary case - are always
          // the focused pane, so nothing changes for them.
          //
          // The prop is still named `tabVisible` on `HostsPage`; renaming it
          // there is cosmetic and that file is held by another agent.
          tabVisible={onScreen}
        />
      );
  }
}

const DRAG_PREFIX = "pane-drag:";
const DROP_PREFIX = "pane-drop:";

function parsePaneId(id: string | number, prefix: string): number | null {
  const s = String(id);
  if (!s.startsWith(prefix)) return null;
  const n = Number(s.slice(prefix.length));
  return Number.isFinite(n) ? n : null;
}

/** Diagonal-quadrant hit test: which edge of `rect` the pointer is closest to. */
function computeEdge(
  rect: { left: number; top: number; width: number; height: number },
  x: number,
  y: number,
): PaneEdge {
  const cx = rect.left + rect.width / 2;
  const cy = rect.top + rect.height / 2;
  const nx = rect.width ? (x - cx) / (rect.width / 2) : 0;
  const ny = rect.height ? (y - cy) / (rect.height / 2) : 0;
  if (Math.abs(nx) >= Math.abs(ny)) return nx < 0 ? "left" : "right";
  return ny < 0 ? "top" : "bottom";
}

/** Build the shared {@link LeafIconInfo} for a pane leaf so the header and the
 *  drag overlay render the exact icon the tab strip shows for the same leaf. */
function leafIconInfo(node: PaneLeaf, aiCliStatuses?: Map<number, AiCliStatus>): LeafIconInfo {
  return {
    leafKind: node.leafKind,
    isSsh: node.leafKind === "terminal" && !!node.sshConnectionId,
    editorFileName: node.leafKind === "editor" ? basename(node.path) : undefined,
    editorRemote: isRemoteEditorLeaf(node),
    aiCliStatus: node.leafKind === "terminal" ? (aiCliStatuses?.get(node.id) ?? null) : null,
    page: node.leafKind === "page" ? node.page : undefined,
  };
}

/** One remote editor leaf resolved against the live SSH sessions, for the
 *  current render. Undefined on local leaves. */
type RemoteEditorBinding = {
  /** Session to read and write through. Undefined while nothing is connected. */
  sessionId: number | undefined;
  /** A terminal for this host is on its way up, so wait rather than prompt. */
  connecting: boolean;
  hostLabel: string;
  /** Absent for ad-hoc connections: there is no saved profile to reopen. */
  onReconnect?: () => void;
};

/**
 * Waiting room for a remote editor leaf with no live SSH session: shown after a
 * restart, before any terminal for its host has connected. The editor is
 * deliberately NOT mounted here, so a remote path can never be read from (or
 * saved to) the local disk while unbound.
 */
function RemoteEditorPending({
  fileName,
  hostLabel,
  connecting,
  onReconnect,
}: {
  fileName: string;
  hostLabel: string;
  connecting: boolean;
  onReconnect?: () => void;
}) {
  return (
    <div className="bg-background text-muted-foreground flex h-full w-full flex-col items-center justify-center gap-3 p-6 text-center text-[11px]">
      <Cloud size={22} strokeWidth={1.5} className="opacity-50" />
      <span className="max-w-72 leading-relaxed">
        <span className="text-foreground">{fileName}</span> lives on{" "}
        <span className="text-foreground">{hostLabel}</span>.{" "}
        {connecting ? "Connecting…" : "Not connected."}
      </span>
      {!connecting && onReconnect && (
        <button
          type="button"
          onClick={onReconnect}
          className="hover:bg-muted hover:text-foreground border-border rounded-md border px-2 py-1 transition-colors"
        >
          Reconnect
        </button>
      )}
    </div>
  );
}

/** Heavy leaf content. Memoized so pointer-move re-renders during a drag don't churn xterm/CodeMirror. */
const LeafBody = memo(function LeafBody({
  node,
  tabVisible,
  isFloating,
  editorHandleRef,
  focused,
  b,
  mdPreview,
  remoteSession,
}: {
  node: PaneLeaf;
  tabVisible: boolean;
  /** True while this leaf is popped out into a float window. */
  isFloating: boolean;
  /** Captures the editor handle so the frame can save before floating. */
  editorHandleRef: RefObject<EditorPaneHandle | null>;
  focused: boolean;
  b: LeafBundle;
  mdPreview: boolean;
  /** Resolution of a remote editor leaf against the live SSH sessions.
   *  Undefined for local leaves. */
  remoteSession?: RemoteEditorBinding;
}) {
  // Register the editor handle both with the parent bundle (find/replace etc.)
  // and the frame's own ref (save-before-float). Stable so EditorPane doesn't
  // re-register each render.
  const setEditorRef = useCallback(
    (h: EditorPaneHandle | null) => {
      b.setEditorRef(h);
      editorHandleRef.current = h;
    },
    [b, editorHandleRef],
  );
  // Last session this leaf actually bound to. Losing the session (Disconnect, a
  // dropped link) must NOT swap a live editor for the reconnect panel: that
  // unmounts CodeMirror and takes any unsaved edits with it. Keep the editor on
  // the old session instead - saving fails against a dead one, exactly as it did
  // before - until a reconnect resolves a fresh session and it heals itself.
  const boundSessionRef = useRef<number | undefined>(undefined);
  if (remoteSession?.sessionId !== undefined) boundSessionRef.current = remoteSession.sessionId;
  if (node.leafKind === "terminal") {
    return (
      <ErrorBoundary label="terminal pane" resetKeys={[node.id]}>
        <div className="h-full w-full p-1.5">
          <TerminalPane
            leafId={node.id}
            visible={tabVisible}
            focused={focused}
            initialCwd={node.cwd}
            sshConnectionId={node.sshConnectionId}
            savedPtyId={node.savedPtyId}
            savedActiveTool={node.activeTool}
            terminalThemeId={node.terminalThemeId}
            ref={b.setTerminalRef}
            onSearchReady={(_id, addon) => b.onSearchReady(addon)}
            onCwd={(_id, cwd) => b.onCwd(cwd)}
            onDetectedLocalUrl={(_id, url) => b.onDetectedLocalUrl(url)}
            onExit={(_id, code) => b.onExit(code)}
            onTerviaOpen={(_id, input) => b.onTerviaOpen(input)}
            onTerviaSpawnTab={(_id, input) => b.onTerviaSpawnTab(input)}
            onSshStatus={(_id, status) => b.onSshStatus(status)}
            onAiCliStatus={(_id, status) => b.onAiCliStatus(status)}
            onPtyId={(_id, ptyId) => b.onPtyId(ptyId)}
          />
        </div>
      </ErrorBoundary>
    );
  }
  if (node.leafKind === "board") {
    return (
      <ErrorBoundary label="board pane" resetKeys={[node.id]}>
        <BoardLeafBody leafId={node.id} />
      </ErrorBoundary>
    );
  }
  if (node.leafKind === "rdp") {
    // `resetKeys` on the connection id as well as the leaf id: re-pointing a
    // leaf at another host is a new session, so a boundary tripped by the old
    // one must not hold the new one hostage.
    return (
      <ErrorBoundary label="rdp pane" resetKeys={[node.id, node.rdpConnectionId]}>
        <RdpPane
          leafId={node.id}
          connectionId={node.rdpConnectionId}
          visible={tabVisible}
          focused={focused}
        />
      </ErrorBoundary>
    );
  }
  if (node.leafKind === "page") {
    return (
      <ErrorBoundary label="page pane" resetKeys={[node.id, node.page]}>
        <PageLeafBody page={node.page} onScreen={tabVisible && focused} />
      </ErrorBoundary>
    );
  }
  // Editor - while floating it's handed off to the float window; unmount here so
  // two live CodeMirror views can't race and save-stomp the same file (the parent
  // overlays a "floating" indicator in its place).
  if (isFloating) return null;
  // Remote file with nothing to read it through yet (typically a workspace
  // restored before its SSH terminal came up). Hold the pane closed rather than
  // mount an editor that would fall back to the LOCAL filesystem.
  const sshSessionId = editorPaneSession(node, remoteSession?.sessionId, boundSessionRef.current);
  if (sshSessionId === "blocked") {
    return (
      <RemoteEditorPending
        fileName={basename(node.path)}
        hostLabel={remoteSession?.hostLabel ?? node.sshHostLabel ?? "remote"}
        connecting={remoteSession?.connecting ?? false}
        onReconnect={remoteSession?.onReconnect}
      />
    );
  }
  return (
    <ErrorBoundary label="editor pane" resetKeys={[node.id, node.path]}>
      {/* fallback={null}: the editor chunk loads on first editor render; the
          brief gap is unnoticeable and only on the first editor of a session. */}
      <Suspense fallback={null}>
        <EditorPane
          ref={setEditorRef}
          path={node.path}
          onDirtyChange={b.onDirtyChange}
          onClose={b.onCloseLeaf}
          mdPreview={mdPreview}
          sshSessionId={sshSessionId}
        />
      </Suspense>
    </ErrorBoundary>
  );
});

function DropIndicator({ edge }: { edge: PaneEdge }) {
  const pos =
    edge === "left"
      ? "inset-y-0 left-0 w-1/2"
      : edge === "right"
        ? "inset-y-0 right-0 w-1/2"
        : edge === "top"
          ? "inset-x-0 top-0 h-1/2"
          : "inset-x-0 bottom-0 h-1/2";
  return (
    <div
      className={cn(
        "border-primary/70 bg-primary/20 pointer-events-none absolute z-20 rounded-md border-2",
        pos,
      )}
    />
  );
}

function PaneLeafFrame({
  node,
  tabVisible,
  focused,
  b,
  mdPreview,
  onFocusLeaf,
}: {
  node: PaneLeaf;
  tabVisible: boolean;
  focused: boolean;
  b: LeafBundle;
  mdPreview: boolean;
  onFocusLeaf: (leafId: number) => void;
}) {
  const {
    drag,
    leafCount,
    onCloseLeaf,
    canCloseLeaf,
    onSetTerminalTheme,
    onToggleMdPreview,
    detectedBrowserUrl,
    onOpenPreview,
  } = use(PaneDndContext);
  const {
    hosts,
    sshStatuses,
    aiCliStatuses,
    sshBindingByConnection,
    onReconnectSsh,
    onFocusEntry,
  } = use(PaneMetaContext);
  const draggable = leafCount > 1;
  const {
    listeners,
    attributes,
    setNodeRef: setDragRef,
  } = useDraggable({
    id: `${DRAG_PREFIX}${node.id}`,
    disabled: !draggable,
  });
  const { setNodeRef: setDropRef } = useDroppable({ id: `${DROP_PREFIX}${node.id}` });

  // Re-render the header once the catppuccin file-icon set lands so editor
  // leaves swap from the pencil fallback to the real file-type glyph.
  useExplorerIconsReady();

  // Word wrap is a global preference, so every editor pane shows the same
  // switch and toggles the same value - no need to know which one is focused.
  const lineWrap = usePreferencesStore((s) => s.lineWrap);
  const userShortcuts = usePreferencesStore((s) => s.shortcuts);

  // Header buttons that act on whatever leaf is *active* (the detected-URL
  // globe) must render exactly once. Every
  // pane tab keeps a focused leaf even while hidden, so `focused` alone would
  // mount one copy per background tab.
  const onlyHere = tabVisible && focused;

  const isSource = drag.sourceLeafId === node.id;
  const isOver = drag.overLeafId === node.id && drag.sourceLeafId !== node.id && drag.edge !== null;
  const isSsh = node.leafKind === "terminal" && !!node.sshConnectionId;
  const sshStatus = isSsh ? sshStatuses?.get(node.id) : undefined;
  // Program-set terminal title (OSC 2), e.g. a running agent's task. Appended to
  // the folder label so the pane header reads identically to the Workspaces
  // panel's terminal list for the same leaf.
  const termTitle = useTerminalTitles((s) =>
    node.leafKind === "terminal" ? s.titles[node.id] : undefined,
  );
  const baseLabel = leafLabel(node, hosts, undefined);
  const showTitle =
    node.leafKind === "terminal" &&
    !!termTitle &&
    termTitle !== baseLabel &&
    termTitle !== node.cwd;

  // Resolve a remote editor leaf to a live session on every render, rather than
  // stamping one onto the leaf: a saved profile outlives any session, so a
  // reconnect (which mints a new session id) is followed automatically and a
  // restored leaf simply waits until its host is up.
  const remoteSession = useMemo<RemoteEditorBinding | undefined>(() => {
    if (node.leafKind !== "editor" || !isRemoteEditorLeaf(node)) return undefined;
    const connId = node.sshConnectionId;
    const conn = connId ? hosts?.get(connId) : undefined;
    const hostLabel = conn?.name.trim() || node.sshHostLabel || "remote";
    // Ad-hoc connection: no profile to re-resolve or reopen, so the session it
    // was opened with is all this leaf will ever have.
    if (!connId) return { sessionId: node.sshSessionId, connecting: false, hostLabel };
    const binding = sshBindingByConnection?.get(connId);
    return {
      sessionId: binding?.sessionId,
      connecting: binding?.connecting ?? false,
      hostLabel,
      onReconnect: onReconnectSsh ? () => onReconnectSsh(connId, hostLabel) : undefined,
    };
  }, [node, hosts, sshBindingByConnection, onReconnectSsh]);

  // Float the pane into its own always-on-top window (terminals mirror live via
  // Tauri events; editors open the file).
  const floatParams = floatParamsFor(node, baseLabel);
  const frameRef = useRef<HTMLDivElement>(null);
  const editorHandleRef = useRef<EditorPaneHandle | null>(null);
  const isFloating = useFloatStore((s) => s.floating.has(node.id));
  const doFloat = async () => {
    if (!floatParams) return;
    const r = frameRef.current?.getBoundingClientRect();
    // Editor hand-off: persist the buffer first so the float (which reads the file
    // by path) opens the live content and the main editor's unmount can't drop
    // unsaved edits. No-op when clean; skipped when already floating (ref is null).
    if (floatParams.kind === "editor") await editorHandleRef.current?.save();
    void floatPane(floatParams, { w: r?.width ?? 720, h: r?.height ?? 480 }, onFocusEntry);
  };

  return (
    <div
      ref={(el) => {
        setDropRef(el);
        frameRef.current = el;
      }}
      onMouseDownCapture={() => {
        if (!focused) onFocusLeaf(node.id);
      }}
      onFocus={() => {
        if (!focused) onFocusLeaf(node.id);
      }}
      data-pane-leaf={node.id}
      className={cn(
        "bg-background relative flex h-full w-full flex-col overflow-hidden rounded-md border shadow-sm transition-colors",
        focused ? "border-primary/60 ring-primary/30 ring-1" : "border-border",
        isSource && "opacity-60",
      )}
    >
      {/* Per-pane navigation header (drag handle + label + float + terminal-theme
          gear + close). A terminal leaf's per-pane theme is a gear-icon dropdown
          placed between the float + close buttons. */}
      {(() => {
        const headerBar = (
          // `@container` so the per-file cluster below can shed itself on a
          // narrow pane instead of pushing the close button out of the frame.
          <div className="border-border/60 bg-card @container flex h-7 shrink-0 items-center gap-1 border-b px-1 select-none">
            {(() => {
              const dragHandle = (
                <button
                  type="button"
                  ref={setDragRef}
                  {...listeners}
                  {...attributes}
                  disabled={!draggable}
                  aria-label="Drag to move pane"
                  className={cn(
                    "flex size-5 shrink-0 items-center justify-center rounded transition-colors",
                    draggable
                      ? "text-muted-foreground/70 hover:bg-muted hover:text-foreground cursor-grab active:cursor-grabbing"
                      : "text-muted-foreground/40 cursor-default",
                  )}
                >
                  <GripVertical size={14} strokeWidth={2} />
                </button>
              );
              // The grip only earns its place (and a tooltip) when the pane can
              // actually move - i.e. it shares the tab with another pane. A lone
              // pane has nothing to reorder, so hide the grip entirely instead of
              // showing a dead disabled button.
              return draggable ? (
                <IconTooltip label="Drag to move pane" side="bottom">
                  {dragHandle}
                </IconTooltip>
              ) : null;
            })()}
            {/* Same glyph the tab strip + drag overlay show for this leaf. The
            muted default tint is overridden by the AI CLI status when active. */}
            <LeafIcon
              info={leafIconInfo(node, aiCliStatuses)}
              size={13}
              className="text-muted-foreground/80"
            />
            <span
              className={cn(
                "min-w-0 flex-1 truncate text-xs",
                "text-muted-foreground",
                node.leafKind === "editor" && node.preview && "italic",
                // SSH status colors the label, matching the tab strip.
                isSsh && statusLabelClass(sshStatus),
              )}
            >
              {baseLabel}
              {showTitle ? <span className="opacity-60"> · {termTitle}</span> : null}
            </span>
            {node.leafKind === "editor" && node.dirty && (
              <span className="bg-foreground/60 size-1.5 shrink-0 rounded-full" />
            )}
            {/* Everything this pane's *content* can do (view mode, wrap,
                format), fenced off by a rule from the three
                that act on the pane itself (float / theme / close).
                `empty:hidden` retires the rule with the group: only some leaf
                kinds fill it. Under ~17rem the label has
                nothing left to give, so the whole group steps aside rather than
                shove the close button off the frame. */}
            <div className="border-border flex shrink-0 items-center gap-1 border-r pr-1 empty:hidden @max-[17rem]:hidden">
              {/* Markdown source/preview toggle. Lives here rather than in the app
                toolbar so it sits on the pane it acts on - with a split, the
                toolbar version could only ever address the focused one. */}
              {node.leafKind === "editor" &&
                onToggleMdPreview &&
                /\.(md|markdown|mdx)$/i.test(node.path) && (
                  <IconTooltip label={mdPreview ? "Show source" : "Preview markdown"} side="bottom">
                    <button
                      type="button"
                      aria-label={mdPreview ? "Show source" : "Preview markdown"}
                      aria-pressed={mdPreview}
                      onClick={(e) => {
                        e.stopPropagation();
                        onToggleMdPreview(node.id);
                      }}
                      className={cn(
                        "flex size-5 shrink-0 items-center justify-center rounded transition-colors",
                        mdPreview
                          ? "text-primary hover:bg-muted"
                          : "text-muted-foreground/70 hover:bg-muted hover:text-foreground",
                      )}
                    >
                      {mdPreview ? (
                        <FileCode size={12} strokeWidth={2} />
                      ) : (
                        <BookOpen size={12} strokeWidth={2} />
                      )}
                    </button>
                  </IconTooltip>
                )}
              {/* Word wrap. Same reasoning as the markdown toggle: it belongs on
                the editor it wraps, and the toolbar copy could only ever
                address the focused pane. Hidden in markdown preview (nothing
                to wrap). */}
              {node.leafKind === "editor" && !mdPreview && (
                <IconTooltip
                  label={(() => {
                    const t = shortcutHint("editor.toggleWordWrap", userShortcuts);
                    return `${lineWrap ? "Disable" : "Enable"} word wrap${t ? ` (${t})` : ""}`;
                  })()}
                  side="bottom"
                >
                  <button
                    type="button"
                    aria-label={lineWrap ? "Disable word wrap" : "Enable word wrap"}
                    aria-pressed={lineWrap}
                    onClick={(e) => {
                      e.stopPropagation();
                      void setLineWrap(!lineWrap);
                    }}
                    className={cn(
                      "flex size-5 shrink-0 items-center justify-center rounded transition-colors",
                      lineWrap
                        ? "text-primary hover:bg-muted"
                        : "text-muted-foreground/70 hover:bg-muted hover:text-foreground",
                    )}
                  >
                    <WrapText size={12} strokeWidth={2} />
                  </button>
                </IconTooltip>
              )}
              {/* Hand a detected local URL (a printed dev-server address, or a
                running port found from the project's config) to the OS browser.
                `detectedBrowserUrl` is already resolved against the active
                leaf, so it rides the focused pane. */}
              {onlyHere && detectedBrowserUrl && onOpenPreview && (
                <IconTooltip label={`Open ${detectedBrowserUrl} in your browser`} side="bottom">
                  <button
                    type="button"
                    aria-label={`Open ${detectedBrowserUrl} in your browser`}
                    onClick={(e) => {
                      e.stopPropagation();
                      onOpenPreview();
                    }}
                    className="text-muted-foreground/70 hover:bg-muted hover:text-foreground flex size-5 shrink-0 items-center justify-center rounded transition-colors"
                  >
                    <Globe size={12} strokeWidth={2} />
                  </button>
                </IconTooltip>
              )}
            </div>
            {floatParams && (
              <IconTooltip
                label={
                  isFloating
                    ? "Floating, click to focus its window"
                    : "Float pane in its own window"
                }
                side="bottom"
              >
                <button
                  type="button"
                  aria-label={
                    isFloating ? "Focus the floating window" : "Float pane in its own window"
                  }
                  onClick={(e) => {
                    e.stopPropagation();
                    doFloat();
                  }}
                  className={cn(
                    "flex size-5 shrink-0 items-center justify-center rounded transition-colors",
                    isFloating
                      ? "text-primary hover:bg-muted"
                      : "text-muted-foreground/70 hover:bg-muted hover:text-foreground",
                  )}
                >
                  <SquareArrowOutUpRight size={12} strokeWidth={2} />
                </button>
              </IconTooltip>
            )}
            {/* Ctrl+Alt+Del, as a button, because the real chord never arrives:
                on Windows it is a Secure Attention Sequence the OS consumes
                before any application sees it, and elsewhere the browser does
                not report it either. Without this there is no way to reach the
                lock screen or Task Manager on the remote desktop, which is
                most of what an RDP session is opened for. */}
            {node.leafKind === "rdp" && (
              <IconTooltip label="Send Ctrl+Alt+Del" side="bottom">
                <button
                  type="button"
                  aria-label="Send Ctrl+Alt+Del to the remote desktop"
                  onClick={(e) => {
                    e.stopPropagation();
                    fireRdpPaneAction(node.id, "ctrlAltDel");
                  }}
                  className="text-muted-foreground/70 hover:bg-muted hover:text-foreground flex size-5 shrink-0 items-center justify-center rounded transition-colors"
                >
                  <Keyboard size={12} strokeWidth={2} />
                </button>
              </IconTooltip>
            )}
            {/* Per-pane terminal theme, moved out of the right-click menu into a
                gear dropdown that sits between the float + close buttons. */}
            {node.leafKind === "terminal" && onSetTerminalTheme && (
              <DropdownMenu>
                <IconTooltip label="Terminal theme" side="bottom">
                  <DropdownMenuTrigger asChild>
                    <button
                      type="button"
                      aria-label="Terminal theme"
                      onClick={(e) => e.stopPropagation()}
                      className="text-muted-foreground/70 hover:bg-muted hover:text-foreground flex size-5 shrink-0 items-center justify-center rounded transition-colors"
                    >
                      <Settings size={12} strokeWidth={2} />
                    </button>
                  </DropdownMenuTrigger>
                </IconTooltip>
                <DropdownMenuContent
                  align="end"
                  className="max-h-[60vh] overflow-x-hidden overflow-y-auto"
                >
                  <DropdownMenuRadioGroup
                    value={node.terminalThemeId ?? FOLLOW_GLOBAL_THEME}
                    onValueChange={(v) =>
                      onSetTerminalTheme(node.id, v === FOLLOW_GLOBAL_THEME ? null : v)
                    }
                  >
                    <DropdownMenuRadioItem value={FOLLOW_GLOBAL_THEME}>
                      Default (follow global)
                    </DropdownMenuRadioItem>
                    <DropdownMenuSeparator />
                    {TERMINAL_PRESETS.map((p) => (
                      <DropdownMenuRadioItem key={p.id} value={p.id}>
                        <ThemeSwatch palette={p.palette} />
                        <span className="truncate">{p.palette.name}</span>
                      </DropdownMenuRadioItem>
                    ))}
                  </DropdownMenuRadioGroup>
                </DropdownMenuContent>
              </DropdownMenu>
            )}
            {/* Not rendered when the close would be refused, rather than
                rendered and dead: the tab strip already hides its X the same
                way, and a permanent pane with a live-looking X is the one
                outcome the close rule must not produce. */}
            {onCloseLeaf && (canCloseLeaf?.(node.id) ?? true) && (
              <IconTooltip label="Close pane" side="bottom">
                <button
                  type="button"
                  aria-label="Close pane"
                  onClick={(e) => {
                    e.stopPropagation();
                    onCloseLeaf(node.id);
                  }}
                  className="text-muted-foreground/70 hover:bg-muted hover:text-foreground flex size-5 shrink-0 items-center justify-center rounded transition-colors"
                >
                  <X size={12} strokeWidth={2} />
                </button>
              </IconTooltip>
            )}
          </div>
        );

        // The per-pane terminal theme moved to the header gear button (between
        // float + close), so the header carries no right-click menu of its own.
        return headerBar;
      })()}
      {/* While floating, an independent window mirrors this leaf, so the pane
          hides its now-redundant terminal (kept mounted so the PTY + mirror tap
          stay alive) and shows an indicator instead. */}
      <div className="relative min-h-0 flex-1">
        <LeafBody
          node={node}
          tabVisible={tabVisible && !isFloating}
          isFloating={isFloating}
          editorHandleRef={editorHandleRef}
          focused={focused}
          b={b}
          mdPreview={mdPreview}
          remoteSession={remoteSession}
        />
        {isFloating && (
          <div className="bg-background text-muted-foreground absolute inset-0 flex flex-col items-center justify-center gap-3 text-center text-[11px]">
            <SquareArrowOutUpRight size={22} strokeWidth={1.5} className="opacity-50" />
            <span className="max-w-56 leading-relaxed">
              This pane is open in a floating window.
            </span>
            <span className="flex items-center gap-2">
              <button
                type="button"
                onClick={doFloat}
                className="hover:bg-muted hover:text-foreground border-border rounded-md border px-2 py-1 transition-colors"
              >
                Focus window
              </button>
              <button
                type="button"
                onClick={() => closeFloat(node.id)}
                className="hover:bg-muted hover:text-foreground border-border rounded-md border px-2 py-1 transition-colors"
              >
                Dock back
              </button>
            </span>
          </div>
        )}
      </div>
      {isOver && drag.edge && <DropIndicator edge={drag.edge} />}
    </div>
  );
}

type NodesProps = {
  node: PaneNode;
  tabVisible: boolean;
  activeLeafId: number;
  onFocusLeaf: (leafId: number) => void;
  getBundle: (leafId: number) => LeafBundle;
  mdPreviewLeafIds: ReadonlySet<number>;
  onSplitSizes?: (splitId: number, sizes: number[]) => void;
};

const PaneNodes = memo(function PaneNodes({
  node,
  tabVisible,
  activeLeafId,
  onFocusLeaf,
  getBundle,
  mdPreviewLeafIds,
  onSplitSizes,
}: NodesProps) {
  if (node.kind === "leaf") {
    return (
      <PaneLeafFrame
        node={node}
        tabVisible={tabVisible}
        focused={node.id === activeLeafId}
        b={getBundle(node.id)}
        mdPreview={mdPreviewLeafIds.has(node.id)}
        onFocusLeaf={onFocusLeaf}
      />
    );
  }

  // Restore saved divider positions only when the stored ratios still line up
  // with the current children (a split/close leaves a stale-length array);
  // otherwise fall back to an equal split.
  const savedSizes = node.sizes && node.sizes.length === node.children.length ? node.sizes : null;

  return (
    <ResizablePanelGroup
      orientation={node.dir === "row" ? "horizontal" : "vertical"}
      className="gap-1.5"
      // `onLayoutChanged` fires once the layout settles (no debounce needed);
      // `isUserInteraction` isolates a genuine drag/keyboard resize from mount,
      // container-resize, and programmatic layouts so only real user intent is
      // persisted. `layout` is keyed by panel id -> percentage; map it back to
      // child order for the tree.
      onLayoutChanged={(layout, meta) => {
        if (!meta.isUserInteraction || !onSplitSizes) return;
        const sizes = node.children.map((c) => layout[`pane-${c.id}`]);
        if (sizes.some((s) => typeof s !== "number")) return;
        onSplitSizes(node.id, sizes);
      }}
    >
      {node.children.map((child, i) => (
        <Fragment key={child.id}>
          {i > 0 && <ResizableHandle withHandle />}
          {/* Numeric sizes would be read as pixels; a "%"-string keeps them
              as percentages of the group. */}
          <ResizablePanel
            id={`pane-${child.id}`}
            minSize="10%"
            defaultSize={savedSizes ? `${savedSizes[i]}%` : undefined}
          >
            <PaneNodes
              node={child}
              tabVisible={tabVisible}
              activeLeafId={activeLeafId}
              onFocusLeaf={onFocusLeaf}
              getBundle={getBundle}
              mdPreviewLeafIds={mdPreviewLeafIds}
              onSplitSizes={onSplitSizes}
            />
          </ResizablePanel>
        </Fragment>
      ))}
    </ResizablePanelGroup>
  );
});

export function PaneTreeView({
  node,
  tabVisible,
  activeLeafId,
  onFocusLeaf,
  getBundle,
  mdPreviewLeafIds,
  onMovePaneLeaf,
  onCloseLeaf,
  canCloseLeaf,
  onSetTerminalTheme,
  onToggleMdPreview,
  detectedBrowserUrl,
  onOpenPreview,
  onSplitSizes,
  hosts,
  sshStatuses,
  aiCliStatuses,
  sshBindingByConnection,
  onReconnectSsh,
  boardTabs,
  onFocusEntry,
  onConnectHost,
}: Props) {
  const leafList = useMemo(() => leaves(node), [node]);
  const leafCount = leafList.length;

  const [drag, setDrag] = useState<PaneDragState>({
    sourceLeafId: null,
    overLeafId: null,
    edge: null,
  });
  // Latest resolved drop target. Kept in a ref so `onDragEnd` reads it without
  // closing over stale `drag` state.
  const latestRef = useRef<{ over: number | null; edge: PaneEdge | null }>({
    over: null,
    edge: null,
  });

  const sensors = useSensors(useSensor(PointerSensor, { activationConstraint: { distance: 6 } }));

  const clearOver = () => {
    if (latestRef.current.over === null && latestRef.current.edge === null) return;
    latestRef.current = { over: null, edge: null };
    setDrag((d) => ({ ...d, overLeafId: null, edge: null }));
  };

  const reset = () => {
    latestRef.current = { over: null, edge: null };
    setDrag({ sourceLeafId: null, overLeafId: null, edge: null });
  };

  const handleDragStart = (ev: DragStartEvent) => {
    latestRef.current = { over: null, edge: null };
    setDrag({ sourceLeafId: parsePaneId(ev.active.id, DRAG_PREFIX), overLeafId: null, edge: null });
  };

  const handleDragMove = (ev: DragMoveEvent) => {
    const sourceId = parsePaneId(ev.active.id, DRAG_PREFIX);
    if (!ev.over) {
      clearOver();
      return;
    }
    const overId = parsePaneId(ev.over.id, DROP_PREFIX);
    if (overId === null || overId === sourceId) {
      clearOver();
      return;
    }
    const ae = ev.activatorEvent as PointerEvent;
    const x = ae.clientX + ev.delta.x;
    const y = ae.clientY + ev.delta.y;
    const edge = computeEdge(ev.over.rect, x, y);
    if (latestRef.current.over === overId && latestRef.current.edge === edge) return;
    latestRef.current = { over: overId, edge };
    setDrag((d) => ({ ...d, overLeafId: overId, edge }));
  };

  const handleDragEnd = (ev: DragEndEvent) => {
    const sourceId = parsePaneId(ev.active.id, DRAG_PREFIX);
    const { over, edge } = latestRef.current;
    reset();
    if (sourceId !== null && over !== null && edge !== null && over !== sourceId) {
      onMovePaneLeaf?.(sourceId, over, edge);
    }
  };

  const ctxValue = useMemo<PaneDndValue>(
    () => ({
      drag,
      leafCount,
      onCloseLeaf,
      canCloseLeaf,
      onSetTerminalTheme,
      onToggleMdPreview,
      detectedBrowserUrl,
      onOpenPreview,
    }),
    [
      drag,
      leafCount,
      onCloseLeaf,
      canCloseLeaf,
      onSetTerminalTheme,
      onToggleMdPreview,
      detectedBrowserUrl,
      onOpenPreview,
    ],
  );
  const metaValue = useMemo<PaneMetaValue>(
    () => ({
      hosts,
      sshStatuses,
      aiCliStatuses,
      sshBindingByConnection,
      onReconnectSsh,
      boardTabs,
      onFocusEntry,
      onConnectHost,
    }),
    [
      hosts,
      sshStatuses,
      aiCliStatuses,
      sshBindingByConnection,
      onReconnectSsh,
      boardTabs,
      onFocusEntry,
      onConnectHost,
    ],
  );

  // Re-render the overlay once the file-icon set lands so a dragged editor leaf
  // shows its file-type glyph rather than the pencil fallback.
  useExplorerIconsReady();

  const draggedLeaf =
    drag.sourceLeafId !== null ? (leafList.find((l) => l.id === drag.sourceLeafId) ?? null) : null;

  return (
    <DndContext
      sensors={sensors}
      collisionDetection={pointerWithin}
      onDragStart={handleDragStart}
      onDragMove={handleDragMove}
      onDragEnd={handleDragEnd}
      onDragCancel={reset}
    >
      <PaneMetaContext.Provider value={metaValue}>
        <PaneDndContext.Provider value={ctxValue}>
          <PaneNodes
            node={node}
            tabVisible={tabVisible}
            activeLeafId={activeLeafId}
            onFocusLeaf={onFocusLeaf}
            getBundle={getBundle}
            mdPreviewLeafIds={mdPreviewLeafIds}
            onSplitSizes={onSplitSizes}
          />
        </PaneDndContext.Provider>
      </PaneMetaContext.Provider>
      <DragOverlay dropAnimation={null}>
        {draggedLeaf && (
          // Fixed 1:1 (28x28) chip with the leaf's own icon centered (file-type
          // glyph for editors, terminal/cloud for shells). The pane drag handle
          // is tiny, so a centered
          // icon-only square reads cleaner than an icon+label pill clipped to the
          // handle's width.
          <div className="bg-accent text-accent-foreground ring-border flex size-7 items-center justify-center shadow-lg ring-1">
            <LeafIcon info={leafIconInfo(draggedLeaf, aiCliStatuses)} size={14} />
          </div>
        )}
      </DragOverlay>
    </DndContext>
  );
}
