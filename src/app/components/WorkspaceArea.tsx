import { ResizablePanel } from "@/components/ui/resizable";
import { cn } from "@/lib/utils";
import { PaneStack } from "@/modules/panes";
import { type AiCliStatus } from "@/modules/terminal/lib/aiCliStatus";
import { type SshConnectionBinding, type SshStatus } from "@/modules/ssh/status";
import { type PaneTab, type RailViewKind, type Tab } from "@/modules/tabs";
import { PAGE_LABELS } from "@/modules/terminal/lib/panes";
import type { Host } from "@/modules/hosts/types";
import type { SearchAddon } from "@xterm/addon-search";
import { type TabsApi } from "../hooks/tabsApi";
import { type usePaneHandles } from "../hooks/usePaneHandles";
import { RailViewArea } from "./RailViewArea";

type PaneHandles = ReturnType<typeof usePaneHandles>;

type Props = {
  tabs: Tab[];
  activeId: number;
  activePaneTab: PaneTab | null;
  uiZoom: number;
  paneHandles: PaneHandles;
  onSearchReady: (leafId: number, addon: SearchAddon) => void;
  onDetectedLocalUrl: (leafId: number, url: string) => void;
  onSshStatus: (leafId: number, status: SshStatus) => void;
  onAiCliStatus: (leafId: number, status: AiCliStatus) => void;
  sshStatuses: Map<number, SshStatus>;
  aiCliStatuses: Map<number, AiCliStatus>;
  /** Live session per saved SSH connection; a remote editor pane binds through it. */
  sshBindingByConnection: Map<string, SshConnectionBinding>;
  /** Open an SSH session for a saved connection (remote editor reconnect). */
  onReconnectSsh: (connectionId: string, title: string) => void;
  /** Connect a saved host through App's connect path, routed by
   *  `host.protocol`. Passed straight through to `PaneStack`; a page leaf
   *  body is the first consumer, not this file. */
  onConnectHost?: (host: Host) => void;
  mdPreviewLeafIds: ReadonlySet<number>;
  /** Flip a markdown editor leaf between source and preview, from its pane header. */
  onToggleMdPreview: (leafId: number) => void;
  /** Detected local URL for the focused pane header's "open preview" globe. */
  detectedBrowserUrl: string | null;
  onOpenPreview: () => void;
  /** Persist a split node's per-child size percentages after a divider drag. */
  onSplitSizes: (splitId: number, sizes: number[]) => void;
  /** The rail view covering the tab area, or null when the tabs are showing
   *  (DCR-1). Vault and Port Forwarding arrive here instead of as tabs. */
  railView: RailViewKind | null;
} & Pick<TabsApi, "movePaneLeafToEdge" | "setLeafTerminalTheme">;

/**
 * The center workspace column. Renders the live PaneStack.
 * Lifted out of App verbatim; the per-leaf handlers arrive bundled as
 * `paneHandles`, with the chrome/ssh/tabs-api handlers threaded in alongside.
 */
export function WorkspaceArea({
  tabs,
  activeId,
  activePaneTab,
  uiZoom,
  paneHandles,
  onSearchReady,
  onDetectedLocalUrl,
  onSshStatus,
  onAiCliStatus,
  sshStatuses,
  aiCliStatuses,
  sshBindingByConnection,
  onReconnectSsh,
  onConnectHost,
  mdPreviewLeafIds,
  onToggleMdPreview,
  detectedBrowserUrl,
  onOpenPreview,
  onSplitSizes,
  movePaneLeafToEdge,
  setLeafTerminalTheme,
  railView,
}: Props) {
  return (
    <ResizablePanel id="workspace" defaultSize="58%" minSize="25%">
      {/* Counter the body-level UI zoom so the panes (terminal,
          editor, preview, diffs) render at their native scale.
          Net effective zoom here is uiZoom * (1 / uiZoom) = 1. */}
      <div
        className="flex h-full min-h-0 flex-col"
        style={uiZoom === 1 ? undefined : { zoom: 1 / uiZoom }}
      >
        {/* Transparent to the bento tray (`bg-sidebar`, owned by App's <main>):
            each pane is its own `bg-background` bordered card that floats on the
            tray, butting the uniform tray gutter like the sidebar / right cards. */}
        <div className="relative min-h-0 flex-1">
          {/* A rail view HIDES the panes rather than unmounting them: a Vault
              detour must not kill the PTYs behind it, exactly as a tab switch
              doesn't. Same treatment the no-pane-tab case already gets. */}
          <div
            className={cn(
              "absolute inset-0",
              (!activePaneTab || railView !== null) && "pointer-events-none invisible",
            )}
            aria-hidden={activePaneTab && railView === null ? "false" : "true"}
          >
            <PaneStack
              tabs={tabs}
              activeId={activeId}
              // A rail view on top means no pane is on screen, so no terminal
              // should be holding a WebGL context or the caret behind it. Coming
              // back is the same visibility flip as a tab switch.
              visible={railView === null}
              registerTerminalHandle={paneHandles.registerTerminalHandle}
              onSearchReady={onSearchReady}
              onCwd={paneHandles.handleTerminalCwd}
              onDetectedLocalUrl={onDetectedLocalUrl}
              onExit={paneHandles.handleLeafExit}
              onTerviaOpen={paneHandles.handleTerviaOpen}
              onTerviaSpawnTab={paneHandles.handleTerviaSpawnTab}
              onSshStatus={onSshStatus}
              onAiCliStatus={onAiCliStatus}
              onPtyId={paneHandles.handlePtyId}
              registerEditorHandle={paneHandles.registerEditorHandle}
              onDirtyChange={paneHandles.handleEditorDirty}
              onCloseLeaf={paneHandles.handleEditorCloseLeaf}
              mdPreviewLeafIds={mdPreviewLeafIds}
              onToggleMdPreview={onToggleMdPreview}
              detectedBrowserUrl={detectedBrowserUrl}
              onOpenPreview={onOpenPreview}
              onFocusLeaf={paneHandles.handleFocusLeaf}
              onMovePaneLeaf={movePaneLeafToEdge}
              onCloseLeafRequest={paneHandles.handlePaneHeaderClose}
              onSetTerminalTheme={setLeafTerminalTheme}
              onSplitSizes={onSplitSizes}
              sshStatuses={sshStatuses}
              aiCliStatuses={aiCliStatuses}
              sshBindingByConnection={sshBindingByConnection}
              onReconnectSsh={onReconnectSsh}
              onConnectHost={onConnectHost}
            />
          </div>
          {/* The Board is a pane LEAF, not an overlay surface: it renders
              inside PaneStack above, with the same header every other pane has.
              A rail view is the opposite - not a leaf, so it mounts only while
              shown and takes the whole workspace card, with the tab strip still
              visible above it to click back to. */}
          {railView !== null && (
            <div
              className="bg-background absolute inset-0 overflow-hidden rounded-md border shadow-sm"
              role="region"
              aria-label={PAGE_LABELS[railView]}
            >
              <RailViewArea view={railView} />
            </div>
          )}
        </div>
      </div>
    </ResizablePanel>
  );
}
