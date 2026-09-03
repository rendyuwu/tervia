import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuSub,
  ContextMenuSubContent,
  ContextMenuSubTrigger,
  ContextMenuTrigger,
} from "@/components/ui/context-menu";
import { TabsTrigger } from "@/components/ui/tabs";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import { MAX_PANES_PER_TAB } from "../lib/useTabs";
import { isSshHost, type Host } from "@/modules/hosts/types";
import { hopDotClass, sshHopDetail, statusLabel } from "@/modules/ssh/status";
import { aiCliLabel } from "@/modules/terminal/lib/aiCliStatus";
import { X } from "lucide-react";
import { useSortable } from "@dnd-kit/sortable";
import { Fragment } from "react";
import type { ReactNode } from "react";
import { type Entry, type PaneEntry, entryLabelClass, tabAccentClass } from "../lib/entries";
import { type SelectEntry, entrySelectHandlers } from "../lib/selectEntry";
import { InlineInput } from "@/modules/explorer/InlineInput";
import { EntryIcon } from "./EntryIcon";
import { TrailingIconButton } from "./TrailingIconButton";

export type PaneGroupForMove = {
  id: number;
  title: string;
  count: number;
  full: boolean;
};

/** Shared render args. Kept as one object to avoid 15-arg signatures. */
export type RenderEntryArgs = {
  entry: Entry;
  idx: number;
  isSplit: boolean;
  totalEntries: number;
  activeKey: string | null;
  lastEntryKey: string | null;
  compact?: boolean;
  /** Whether THIS entry may be closed, decided by the one close predicate
   *  (`lib/closable.ts`) and resolved by the caller. False renders no X at all
   *  rather than a dead one - see the invariants in that file. */
  canClose: boolean;
  /** dnd-kit attributes for the trigger as drag handle. */
  dragAttrs?: ReturnType<typeof useSortable>["attributes"];
  dragListeners?: ReturnType<typeof useSortable>["listeners"];
  /** Per-leaf sortable ref and style. Undefined for group-level drag (uses the outer wrapper). */
  dragRef?: (node: HTMLElement | null) => void;
  dragStyle?: React.CSSProperties;
  /** True when this entry is being dragged. Drives ghost opacity. */
  selfDragging?: boolean;
  /** Activate this entry. Required, not optional: the trigger's own click route
   *  (`lib/selectEntry.ts`) is the ONLY thing that reaches a chip whose key is
   *  already the active one, so an entry rendered without it would be the exact
   *  chip D-NAV1 was about - inert under a rail view. Every caller has one. */
  onSelectEntry: SelectEntry;
  onPinLeaf: (tabId: number, leafId: number) => void;
  onCloseEntry: (tabId: number, leafId: number | null) => void;
  onCloseEntriesAfter: (entry: Entry) => void;
  hosts: Map<string, Host>;
  onMoveLeafToGroup?: (leafId: number, targetTabId: number) => void;
  onMoveLeafToNewTab?: (leafId: number) => "ok" | "invalid";
  onRotateLeafSplit?: (leafId: number) => void;
  paneGroupsForMove: PaneGroupForMove[];
  /** Leaf currently being renamed inline, or null. Owned by the caller because
   *  this is a plain render function, not a component, so it holds no state. */
  renamingLeafId?: number | null;
  /** Enter (leafId) or leave (null) inline rename. */
  onSetRenaming?: (leafId: number | null) => void;
  /** Commit a new tab name, or `null` to drop back to the derived one. */
  onRename?: (leafId: number, title: string | null) => void;
};

/** Render one entry. Extracted so both group-level and leaf-level drag share the same JSX. */
export function renderEntryBody(args: RenderEntryArgs): ReactNode {
  const {
    entry: e,
    idx,
    isSplit,
    totalEntries,
    activeKey,
    lastEntryKey,
    compact,
    canClose,
    dragAttrs,
    dragListeners,
    dragRef,
    dragStyle,
    selfDragging,
    onSelectEntry,
    onPinLeaf,
    onCloseEntry,
    onCloseEntriesAfter,
    hosts,
    onMoveLeafToGroup,
    onMoveLeafToNewTab,
    onRotateLeafSplit,
    paneGroupsForMove,
    renamingLeafId,
    onSetRenaming,
    onRename,
  } = args;
  const sshHostCandidate =
    e.kind === "pane-leaf" && e.sshConnectionId ? hosts.get(e.sshConnectionId) : undefined;
  const sshHost = sshHostCandidate && isSshHost(sshHostCandidate) ? sshHostCandidate : undefined;
  const isPaneLeaf = e.kind === "pane-leaf";
  // Declared before the trigger JSX below, which reads `renaming` to swap the
  // label for an edit field. Keeping them with the other right-click flags
  // further down would be a use-before-init at render time.
  const canRename = isPaneLeaf && !!onRename && !!onSetRenaming;
  const renaming = isPaneLeaf && e.kind === "pane-leaf" && renamingLeafId === e.leafId;
  const trigger = (
    <TabsTrigger
      key={e.key}
      ref={dragRef}
      value={e.key}
      data-entry-key={e.key}
      data-tab-id={e.tabId}
      data-tauri-drag-region="false"
      onDoubleClick={() => {
        if (e.kind === "pane-leaf" && e.italic) {
          onPinLeaf(e.tabId, e.leafId);
        }
      }}
      // Drag attrs/listeners supplied by caller. Nullish spreads preserve default click semantics when absent.
      {...(dragAttrs ?? {})}
      {...(dragListeners ?? {})}
      // D-NAV1: the chip's own click route, and it must sit AFTER the two drag
      // spreads - dnd-kit's attributes are a plain object, so a later spread of
      // one would silently clobber this `onClick` and put the defect back.
      //
      // Unconditional, on purpose. Radix skips `onValueChange` when the clicked
      // trigger's value already equals the current one, which under a rail view
      // is precisely the covered tab the user is asking to see again; see
      // `lib/selectEntry.ts` for why this is a click handler rather than a
      // `value` the rail view unsets. The drag hazard is already handled by
      // dnd-kit (a capture-phase `click` listener on `document` swallows the
      // click that ends an activated drag), so no `isDragging` guard belongs
      // here - it would be dead code.
      {...entrySelectHandlers(e, onSelectEntry)}
      // Inline style set by per-leaf sortables. Undefined for non-leaf paths (wrapper carries the transform).
      // eslint-disable-next-line react/forbid-dom-props
      style={dragStyle}
      className={cn(
        // Active state uses the brand --accent surface. `h-full!` overrides
        // the primitive's calc so trigger height stays an even integer.
        "group bg-muted/30 text-muted-foreground/80 hover:bg-muted/60 hover:text-foreground/80 relative h-full! shrink-0 justify-between gap-1.5 text-xs transition-[background-color,color] duration-150",
        "data-[state=active]:bg-accent data-[state=active]:text-accent-foreground data-[state=active]:font-semibold",
        // Inside a split cluster, entries are flat; outside they keep the pill look.
        isSplit ? "rounded-none" : "rounded-md",
        compact ? "px-2!" : totalEntries === 1 ? "px-2.5!" : "ps-2.5! pe-1.5!",
        // Divider on every entry except the first in a split group.
        isSplit &&
          idx > 0 &&
          "before:bg-border/70 before:absolute before:top-1 before:bottom-1 before:left-0 before:w-px before:content-[''] data-[state=active]:before:opacity-0",
        // Fade the dragged entry so the overlay chip reads as the real thing.
        selfDragging && "opacity-30",
        // Grab cursor on leaves in a split group; non-split tabs inherit it from the wrapper.
        dragListeners && isSplit && "cursor-grab active:cursor-grabbing",
      )}
    >
      {/* Accent stripe, painted only on the active entry. Computed in JS to
          avoid Tailwind variant collisions with the primitive's `::after`. */}
      {e.key === activeKey && (
        <span
          aria-hidden
          className={cn(
            "pointer-events-none absolute top-1/2 left-1 h-4 w-[3px] -translate-y-1/2",
            tabAccentClass(e),
          )}
        />
      )}
      <span
        className={cn(
          // No `truncate` here; its `overflow:hidden` would clip the ordinal
          // badge. `min-w-0` keeps flex-shrink so the inner label can ellipsize.
          "flex min-w-0 items-center gap-1.5",
          // Cap tab width so long page titles (browser panes) don't make tabs
          // huge; the inner label `truncate`s with an ellipsis past this.
          compact ? "max-w-32" : "max-w-44",
        )}
      >
        <EntryIcon entry={e} />
        {renaming && e.kind === "pane-leaf" ? (
          // `stopPropagation` on pointerdown so a drag-to-reorder gesture cannot
          // start from inside the field: the drag listeners live on the trigger
          // this input sits in, and text selection would otherwise reorder tabs.
          // And on click for the same reason, one layer up: the trigger's select
          // handler is unconditional, so clicking or selecting text INSIDE the
          // rename field would otherwise activate the tab and throw the user out
          // of the rail view they opened the rename from. Stopped here rather
          // than by teaching the trigger's handler about `renaming` - that
          // handler stays unconditional, which is the whole of the D-NAV1 fix.
          // InlineInput is the explorer's rename field, reused here because it
          // already survives the hazard this flow creates - the context menu's
          // Radix portal steals focus as it unmounts, and it re-focuses through
          // that instead of committing an empty name.
          <span
            className="flex min-w-0 flex-1"
            onPointerDown={(ev) => ev.stopPropagation()}
            onClick={(ev) => ev.stopPropagation()}
          >
            <InlineInput
              // The kind tag ("ssh", "SQL", "API") is core's, not the user's;
              // it is re-applied around whatever they type.
              initial={e.renameSeed}
              placeholder="Tab name"
              onCommit={(value) => {
                onSetRenaming?.(null);
                // Blank means "back to the derived name", not an empty tab.
                onRename?.(e.leafId, value.trim() ? value : null);
              }}
              onCancel={() => onSetRenaming?.(null)}
            />
          </span>
        ) : (
          <span
            className={cn(
              "truncate",
              e.italic && "italic",
              // SSH status tone. Shared with the Workspaces panel so the same
              // entry is the same colour in both.
              entryLabelClass(e),
            )}
          >
            {e.label}
          </span>
        )}
        {e.dirty ? (
          <span
            aria-label="Unsaved changes"
            className="bg-foreground/60 size-1.5 shrink-0 rounded-full"
          />
        ) : null}
      </span>
      {/* Trailing close button. Rotate-split and move-to-group are in the right-click menu.
          Hidden while renaming: it crowds the field, and clicking it mid-rename would
          close the very tab being named. */}
      <span className="ms-1.5 flex shrink-0 items-center gap-0.5">
        {canClose && !renaming && (
          <TrailingIconButton
            icon={X}
            label="Close"
            variant="danger"
            onClick={() => onCloseEntry(e.tabId, e.kind === "pane-leaf" ? e.leafId : null)}
          />
        )}
      </span>
    </TabsTrigger>
  );

  // Right-click actions: rotate split, leave group, join group, close right.
  // Rotate/leave-group only for leaves inside a split. Move-to-group needs another tab.
  const moveTargets =
    isPaneLeaf && onMoveLeafToGroup ? paneGroupsForMove.filter((g) => g.id !== e.tabId) : [];
  const canRotate = isPaneLeaf && isSplit && !!onRotateLeafSplit;
  const canLeaveGroup = isPaneLeaf && isSplit && !!onMoveLeafToNewTab;
  const canMove = moveTargets.length > 0;
  const canCloseToRight = lastEntryKey !== null && e.key !== lastEntryKey;
  const hasContextActions = canRename || canRotate || canLeaveGroup || canMove || canCloseToRight;
  const hasLeafActions = canRename || canRotate || canLeaveGroup || canMove;
  const tooltipMode: "ssh" | "ai" | null = sshHost
    ? "ssh"
    : isPaneLeaf && e.aiCliStatus
      ? "ai"
      : null;

  // Build innermost-out. TabsTrigger must be the DOM child of every asChild
  // trigger so Radix' Slot can merge handlers. Tooltip is a Provider, not a
  // DOM element, so wrapping it first would drop the context-menu handler.
  let inner: ReactNode = trigger;
  if (tooltipMode) inner = <TooltipTrigger asChild>{inner}</TooltipTrigger>;
  if (hasContextActions) inner = <ContextMenuTrigger asChild>{inner}</ContextMenuTrigger>;

  let wrapped: ReactNode = inner;
  if (hasContextActions) {
    wrapped = (
      <ContextMenu>
        {wrapped}
        <ContextMenuContent className="min-w-44">
          {canRename && (
            <ContextMenuItem
              onSelect={() => {
                if (e.kind === "pane-leaf") onSetRenaming!(e.leafId);
              }}
            >
              Rename
            </ContextMenuItem>
          )}
          {canRename && e.kind === "pane-leaf" && e.renamed && (
            <ContextMenuItem
              onSelect={() => {
                if (e.kind === "pane-leaf") onRename!(e.leafId, null);
              }}
            >
              Reset Name
            </ContextMenuItem>
          )}
          {canRotate && (
            <ContextMenuItem onSelect={() => onRotateLeafSplit!(e.leafId)}>
              Toggle Split Orientation
            </ContextMenuItem>
          )}
          {canLeaveGroup && (
            <ContextMenuItem
              onSelect={() => {
                if (e.kind === "pane-leaf") onMoveLeafToNewTab!(e.leafId);
              }}
            >
              Move to New Tab
            </ContextMenuItem>
          )}
          {canMove && (
            <ContextMenuSub>
              <ContextMenuSubTrigger>Join Group</ContextMenuSubTrigger>
              <ContextMenuSubContent className="max-w-52">
                {moveTargets.map((g) => (
                  <ContextMenuItem
                    key={g.id}
                    disabled={g.full}
                    onSelect={() => {
                      if (e.kind === "pane-leaf") onMoveLeafToGroup!(e.leafId, g.id);
                    }}
                  >
                    {/* min-w-0 lets the long page title ellipsize instead of
                        stretching the menu; the count stays pinned. */}
                    <span className="min-w-0 flex-1 truncate">{g.title}</span>
                    <span className="text-muted-foreground ml-2 shrink-0 text-xs">
                      {g.full ? "Full" : `${g.count}/${MAX_PANES_PER_TAB}`}
                    </span>
                  </ContextMenuItem>
                ))}
              </ContextMenuSubContent>
            </ContextMenuSub>
          )}
          {canCloseToRight && hasLeafActions && <ContextMenuSeparator />}
          {canCloseToRight && (
            <ContextMenuItem onSelect={() => onCloseEntriesAfter(e)}>
              Close Tabs to the Right
            </ContextMenuItem>
          )}
        </ContextMenuContent>
      </ContextMenu>
    );
  }
  if (tooltipMode === "ssh") {
    const sshStatus = isPaneLeaf ? e.sshStatus : undefined;
    const ai = isPaneLeaf ? e.aiCliStatus : undefined;
    wrapped = (
      <Tooltip>
        {wrapped}
        <TooltipContent side="bottom">
          <div className="flex flex-col gap-0.5 text-[11px]">
            <span>
              SSH · {sshHost!.credential.kind === "inline" ? `${sshHost!.credential.user}@` : ""}
              {sshHost!.host}:{sshHost!.port}
            </span>
            {sshStatus ? (
              <span className="text-muted-foreground">{statusLabel(sshStatus)}</span>
            ) : null}
            {/* The jump chain, when there is one. A tab labelled "prod-db"
                otherwise gives no hint that it is reached through a bastion,
                and the status bar only ever shows the ACTIVE pane's route. */}
            {sshStatus?.route?.length ? (
              <span className="text-muted-foreground flex flex-col gap-0.5 pt-0.5">
                {sshStatus.route.map((hop, i) => (
                  <span key={`${hop.host}-${i}`} className="flex items-center gap-1.5">
                    <span
                      aria-hidden
                      className={cn("size-1.5 shrink-0 rounded-full", hopDotClass(hop.state))}
                    />
                    <span className="font-mono">{sshHopDetail(hop)}</span>
                    <span>{hop.isTarget ? "· target" : "· jump"}</span>
                  </span>
                ))}
              </span>
            ) : null}
            {ai ? <span className="text-muted-foreground">{aiCliLabel(ai)}</span> : null}
          </div>
        </TooltipContent>
      </Tooltip>
    );
  } else if (tooltipMode === "ai") {
    const ai = (e as PaneEntry).aiCliStatus!;
    wrapped = (
      <Tooltip>
        {wrapped}
        <TooltipContent side="bottom">
          <div className="flex flex-col gap-0.5 text-[11px]">
            <span>{aiCliLabel(ai)}</span>
          </div>
        </TooltipContent>
      </Tooltip>
    );
  }

  return <Fragment key={e.key}>{wrapped}</Fragment>;
}
