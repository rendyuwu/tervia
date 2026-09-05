import { PAGE_ICONS } from "@/components/LeafIcon";
import { ResizablePanel } from "@/components/ui/resizable";
import { cn } from "@/lib/utils";
import { PaneStack } from "@/modules/panes";
import { type AiCliStatus } from "@/modules/terminal/lib/aiCliStatus";
import { type SshConnectionBinding, type SshStatus } from "@/modules/ssh/status";
import { type PaneTab, type RailViewKind, type Tab } from "@/modules/tabs";
import { PAGE_LABELS } from "@/modules/terminal/lib/panes";
import type { Host } from "@/modules/hosts/types";
import type { SearchAddon } from "@xterm/addon-search";
import { useId } from "react";
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
  /** The rail view covering the tab area, or null when the tabs are showing.
   *  Vault and Port Forwarding arrive here instead of as tabs. */
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
  // The rail view's heading, named by its region's `aria-labelledby` below.
  // `useId()` rather than a module constant because a constant is only unique
  // while exactly one WorkspaceArea is mounted, and a future split workspace
  // would mount two - both labelling their region with the same id, and
  // `aria-labelledby` resolves a duplicate id to whichever element comes first
  // in the document, i.e. the OTHER workspace's heading.
  //
  // NOT about a second WINDOW, which is the tempting second example and is not
  // one: each Tauri window is its own document with its own root
  // (`main.tsx:42`, `settings/main.tsx:20`, `float/main.tsx:30` are three
  // separate `createRoot` calls), so ids cannot collide across them at all.
  // And the case that IS left - two roots inside ONE document - `useId()` does
  // not solve either: React numbers ids per ROOT, so two roots rendering the
  // same shape hand out the same ones unless each is given `createRoot`'s
  // `identifierPrefix`, which nothing here sets.
  const railHeadingId = useId();
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
              className="bg-background absolute inset-0 flex flex-col overflow-hidden rounded-md border shadow-sm"
              role="region"
              // Labelled BY the heading rather than by an `aria-label` repeating
              // the same string: the name is then one thing on screen and in the
              // accessibility tree, so it cannot be renamed in one and not the
              // other, and a screen reader announces the region with the title
              // the user can actually see.
              aria-labelledby={railHeadingId}
            >
              {/* The page says its own name. Hosts already did - not by anyone's
                  design, but because a Hosts TAB is a page leaf, so it inherits
                  the per-pane header every leaf gets (`PaneTreeView.tsx:703`).
                  A rail view is deliberately not a leaf, so it inherited
                  nothing and Vault / Port Forwarding arrived nameless.

                  Written ONCE, here in the container, rather than as a bar
                  added inside `VaultPage` and `ForwardsPage`, which would be two
                  copies of the same chrome to keep in sync by hand.

                  The pane header's TYPOGRAPHY, and none of its controls: no
                  grip, close, split, float or gear. A rail view cannot be
                  dragged, split or closed as a leaf, and a control that does
                  nothing when pressed is a dead affordance.

                  Its `@container` is the one token of that bar NOT copied:
                  the pane header carries it so the per-file cluster inside it
                  can shed itself on a narrow pane (`PaneTreeView.tsx:705-706`),
                  and this bar has no `@[…]` descendant to shed - an icon and a
                  truncating heading, both of which already fit at any width. A
                  container query with nothing querying it is dead weight that
                  reads like a rule someone forgot to write. */}
              <div className="border-border/60 bg-card flex h-7 shrink-0 items-center gap-1 border-b px-1 select-none">
                {(() => {
                  // `PAGE_ICONS` is a map of components, and a computed member
                  // expression is not valid JSX, so the glyph has to be bound to
                  // a capitalised local first - the same IIFE shape the pane
                  // header uses for its own conditional pieces. Sized and tinted
                  // like that header's `LeafIcon`, and it is the same glyph the
                  // rail button the user just pressed shows (`ActivityRail.tsx`).
                  const PageIcon = PAGE_ICONS[railView];
                  return (
                    <PageIcon
                      size={13}
                      strokeWidth={2}
                      className="text-muted-foreground/80 shrink-0"
                    />
                  );
                })()}
                {/* A real heading, not a styled span: it is the only title on
                    this surface, so it is what "jump to the next heading" and
                    the region label above both need to find. */}
                <h2
                  id={railHeadingId}
                  className="text-muted-foreground min-w-0 flex-1 truncate text-xs"
                >
                  {PAGE_LABELS[railView]}
                </h2>
              </div>
              {/* The container is `absolute inset-0`, so it is a fixed box that
                  the header now takes 28px out of - and the page below has to be
                  told about that rather than left to size itself against the
                  whole box. `flex flex-col` here plus `min-h-0 flex-1` on this
                  wrapper is what gives each page's root `h-full` a definite
                  height to resolve against, so `VaultPage`'s and
                  `ForwardsPage`'s own `min-h-0 flex-1 overflow-y-auto` list
                  still scrolls INSIDE the card instead of running off the bottom
                  of it. `min-h-0` is the load-bearing half: a flex item's
                  default `min-height: auto` lets a long list grow the item past
                  its parent, which is a page that scrolls the whole card at a
                  narrow width rather than scrolling its list. */}
              <div className="min-h-0 flex-1">
                <RailViewArea view={railView} />
              </div>
            </div>
          )}
        </div>
      </div>
    </ResizablePanel>
  );
}
