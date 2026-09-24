/**
 * The Hosts page's group filter strip: All / Ungrouped chips, then the group
 * list as a depth-indented tree - create, rename, reparent ("Move to…") and
 * delete, plus a sub-group under any group. Pure presentation over the counts
 * and callbacks the page hands it - no store access of its own.
 */
import { IconActionButton } from "@/components/IconActionButton";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { IconTooltip } from "@/components/ui/icon-tooltip";
import { toast } from "@/components/ui/toast";
import { cn } from "@/lib/utils";
import { InlineInput } from "@/modules/explorer/InlineInput";
import {
  TRAILING_BTN_BASE,
  TRAILING_BTN_VARIANT,
  TRAILING_ICON_SIZE,
} from "@/modules/tabs/components/TrailingIconButton";
import { ChevronRight, FolderInput, MoreHorizontal, Pencil, Plus, Trash2 } from "lucide-react";
import { useMemo, useState, type ReactNode } from "react";
import { buildGroupTree, descendantIds, type GroupNode } from "../groupTree";
import type { HostGroup } from "../types";
// One definition, in the module that computes it - a second one here would let
// the chips and the counts drift apart without `tsc` noticing.
import type { GroupCounts } from "./derive";

export type GroupStripProps = {
  groups: HostGroup[];
  counts: GroupCounts;
  /** null = "All". The string "ungrouped" is not a group id - use the dedicated chip. */
  selectedGroupId: string | null;
  ungroupedSelected: boolean;
  onSelectAll: () => void;
  onSelectUngrouped: () => void;
  onSelectGroup: (groupId: string) => void;
  /** `parentId` is the sub-group's direct parent, or `undefined` for a root
   *  group - "New group" on the strip and "New sub-group" on a chip's menu are
   *  the same call with a different second argument. */
  onCreateGroup: (name: string, parentId?: string) => void | Promise<void>;
  onRenameGroup: (id: string, name: string) => void | Promise<void>;
  /** "Move to…": `parentId` is the chosen new parent, or `undefined` for root. */
  onMoveGroup: (id: string, parentId: string | undefined) => void | Promise<void>;
  onDeleteGroup: (id: string) => void | Promise<void>;
};

/** The one cascade in the host model that is correct: a group is a label, not
 *  an owner, so deleting it only clears `groupId` on its members and hands its
 *  own child groups up to ITS parent, rather than deleting either. Said
 *  plainly here because the failure mode runs both ways - read as "delete
 *  these hosts" and a user who should confirm won't, read the other way when
 *  it really would delete them and a user who confirms loses data. */
function deleteDescription(hostCount: number, childGroupCount: number): string {
  // The empty case gets its own sentence rather than reading "The 0 hosts in
  // this group are not deleted", which is true and unreadable.
  const hostSentence =
    hostCount === 0
      ? "This group has no hosts, so nothing else changes."
      : `The ${hostCount} ${hostCount === 1 ? "host" : "hosts"} in this group ${hostCount === 1 ? "is" : "are"} not deleted - they become ungrouped.`;
  const childSentence =
    childGroupCount === 0
      ? ""
      : ` Its ${childGroupCount} sub-${childGroupCount === 1 ? "group" : "groups"} ${childGroupCount === 1 ? "moves" : "move"} up to take its place.`;
  return `${hostSentence}${childSentence} This cannot be undone.`;
}

/**
 * Where a group can move to: Root, plus every group that is not itself or one
 * of its own descendants - reparenting into either would be a cycle
 * `store.ts`'s `groupChain` refuses anyway, so this list never offers one.
 * Depth-first over the SAME tree the strip renders, so the order a user reads
 * in the submenu matches the order the rows above it appear in, and each
 * label is indented to show where in the tree it sits.
 */
function moveTargetsFor(
  groupId: string,
  groups: readonly HostGroup[],
): { parentId: string | undefined; label: string }[] {
  const excluded = descendantIds(groupId, groups);
  const options: { parentId: string | undefined; label: string }[] = [
    { parentId: undefined, label: "Root" },
  ];
  function walk(nodes: readonly GroupNode[], depth: number): void {
    for (const node of nodes) {
      if (excluded.has(node.group.id)) continue;
      options.push({
        parentId: node.group.id,
        label: "\u00a0\u00a0".repeat(depth) + node.group.name,
      });
      walk(node.children, depth + 1);
    }
  }
  walk(buildGroupTree(groups), 0);
  return options;
}

export function GroupStrip({
  groups,
  counts,
  selectedGroupId,
  ungroupedSelected,
  onSelectAll,
  onSelectUngrouped,
  onSelectGroup,
  onCreateGroup,
  onRenameGroup,
  onMoveGroup,
  onDeleteGroup,
}: GroupStripProps): ReactNode {
  const tree = useMemo(() => buildGroupTree(groups), [groups]);
  // Collapsed ids, not expanded ones - so a flat install (every group a root
  // with no children) has an empty Set, no chevron anywhere, and looks exactly
  // like the strip did before this - the "existing flat groups behave exactly
  // as before" line, made true by the default rather than asserted about it.
  const [collapsedIds, setCollapsedIds] = useState<Set<string>>(() => new Set());
  const [renamingId, setRenamingId] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<HostGroup | null>(null);
  const [creatingUnder, setCreatingUnder] = useState<{ parentId: string | undefined } | null>(null);

  // Every one of the mutations can be refused by the store. Surface the
  // rejection here instead of letting it reach the console unhandled.
  //
  // This used to be its own persistent inline `error` state with no
  // dismiss control at all - cleared only implicitly, at the top of the NEXT
  // `runMutation` call, so a rename refused five minutes ago could sit under
  // the strip until the user happened to try another create/rename/delete.
  // `toast()` (see `HostsPage.tsx`'s header-error comment for the fuller
  // reasoning, applied identically across all three of this page's error
  // surfaces) both expires on its own and - new on this surface - gets an
  // actual dismiss `×` for the first time.
  const runMutation = async (action: () => void | Promise<void>) => {
    try {
      await action();
    } catch (e) {
      toast(e instanceof Error ? e.message : String(e), { variant: "error" });
    }
  };

  const toggleExpand = (id: string) =>
    setCollapsedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const rowProps: GroupTreeRowProps = {
    groups,
    counts,
    selectedGroupId,
    collapsedIds,
    onToggleExpand: toggleExpand,
    onSelect: onSelectGroup,
    renamingId,
    onStartRename: setRenamingId,
    onCommitRename: (id, name, previousName) => {
      setRenamingId(null);
      if (!name || name === previousName) return;
      void runMutation(() => onRenameGroup(id, name));
    },
    onCancelRename: () => setRenamingId(null),
    creatingUnder,
    onStartCreateChild: (parentId) => setCreatingUnder({ parentId }),
    onCommitCreate: (parentId, name) => {
      setCreatingUnder(null);
      if (!name) return;
      void runMutation(() => onCreateGroup(name, parentId));
    },
    onCancelCreate: () => setCreatingUnder(null),
    onDelete: setDeleting,
    onMove: (id, parentId) => void runMutation(() => onMoveGroup(id, parentId)),
  };

  return (
    <div className="flex flex-col gap-1.5">
      <div className="flex flex-wrap items-center gap-1.5">
        <Chip
          label="All"
          count={counts.total}
          selected={selectedGroupId === null && !ungroupedSelected}
          onClick={onSelectAll}
        />
        <Chip
          label="Ungrouped"
          count={counts.ungrouped}
          selected={ungroupedSelected}
          onClick={onSelectUngrouped}
        />
      </div>

      <div className="flex flex-col gap-0.5">
        {tree.map((node) => (
          <GroupTreeRow key={node.group.id} node={node} depth={0} {...rowProps} />
        ))}
        {creatingUnder && creatingUnder.parentId === undefined ? (
          <InlineInput
            initial=""
            placeholder="Group name"
            onCommit={(value) => {
              setCreatingUnder(null);
              const trimmed = value.trim();
              if (!trimmed) return;
              void runMutation(() => onCreateGroup(trimmed));
            }}
            onCancel={() => setCreatingUnder(null)}
          />
        ) : (
          <Button
            type="button"
            variant="ghost"
            size="xs"
            onClick={() => setCreatingUnder({ parentId: undefined })}
            className="w-fit gap-1"
          >
            <Plus size={12} strokeWidth={2} />
            New group
          </Button>
        )}
      </div>

      <AlertDialog open={deleting !== null} onOpenChange={(open) => !open && setDeleting(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete group &quot;{deleting?.name}&quot;?</AlertDialogTitle>
            <AlertDialogDescription>
              {deleteDescription(
                deleting ? (counts.byGroup[deleting.id] ?? 0) : 0,
                deleting ? groups.filter((g) => g.parentId === deleting.id).length : 0,
              )}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              onClick={() => {
                const target = deleting;
                setDeleting(null);
                if (target) void runMutation(() => onDeleteGroup(target.id));
              }}
            >
              Delete group
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

/** Everything one {@link GroupTreeRow} needs beside its own `node`/`depth` -
 *  bundled so the recursion threads one object down instead of a dozen
 *  positional props, on `FileTreeNode.tsx`'s `depth`+`tree` threading. */
type GroupTreeRowProps = {
  groups: HostGroup[];
  counts: GroupCounts;
  selectedGroupId: string | null;
  collapsedIds: ReadonlySet<string>;
  onToggleExpand: (id: string) => void;
  onSelect: (id: string) => void;
  renamingId: string | null;
  onStartRename: (id: string) => void;
  onCommitRename: (id: string, name: string, previousName: string) => void;
  onCancelRename: () => void;
  creatingUnder: { parentId: string | undefined } | null;
  onStartCreateChild: (parentId: string) => void;
  onCommitCreate: (parentId: string, name: string) => void;
  onCancelCreate: () => void;
  onDelete: (group: HostGroup) => void;
  onMove: (id: string, parentId: string | undefined) => void;
};

function GroupTreeRow({
  node,
  depth,
  ...actions
}: GroupTreeRowProps & { node: GroupNode; depth: number }): ReactNode {
  const {
    groups,
    counts,
    selectedGroupId,
    collapsedIds,
    onToggleExpand,
    onSelect,
    renamingId,
    onStartRename,
    onCommitRename,
    onCancelRename,
    creatingUnder,
    onStartCreateChild,
    onCommitCreate,
    onCancelCreate,
    onDelete,
    onMove,
  } = actions;
  const { group, children } = node;
  const hasChildren = children.length > 0;
  const expanded = !collapsedIds.has(group.id);
  const creatingHere = creatingUnder?.parentId === group.id;

  return (
    <div>
      <div className="flex items-center gap-0.5" style={{ paddingLeft: depth * 16 }}>
        {hasChildren ? (
          <button
            type="button"
            aria-expanded={expanded}
            aria-label={expanded ? `Collapse ${group.name}` : `Expand ${group.name}`}
            onClick={() => onToggleExpand(group.id)}
            className="text-muted-foreground flex size-4 shrink-0 items-center justify-center"
          >
            <ChevronRight
              size={12}
              strokeWidth={2.25}
              className={cn("transition-transform", expanded && "rotate-90")}
            />
          </button>
        ) : (
          <span className="size-4 shrink-0" />
        )}
        {renamingId === group.id ? (
          <InlineInput
            initial={group.name}
            placeholder="Group name"
            onCommit={(value) => onCommitRename(group.id, value.trim(), group.name)}
            onCancel={onCancelRename}
          />
        ) : (
          <GroupChip
            group={group}
            count={counts.byGroup[group.id] ?? 0}
            selected={selectedGroupId === group.id}
            onSelect={() => onSelect(group.id)}
            onRename={() => onStartRename(group.id)}
            onDelete={() => onDelete(group)}
            onCreateChild={() => onStartCreateChild(group.id)}
            moveOptions={moveTargetsFor(group.id, groups)}
            onMove={(parentId) => onMove(group.id, parentId)}
          />
        )}
      </div>
      {creatingHere ? (
        <div style={{ paddingLeft: (depth + 1) * 16 + 18 }}>
          <InlineInput
            initial=""
            placeholder="Sub-group name"
            onCommit={(value) => onCommitCreate(group.id, value.trim())}
            onCancel={onCancelCreate}
          />
        </div>
      ) : null}
      {expanded &&
        children.map((child) => (
          <GroupTreeRow key={child.group.id} node={child} depth={depth + 1} {...actions} />
        ))}
    </div>
  );
}

/**
 * A pill toggle: label, an optional tabular-nums count, pressed state.
 *
 * Exported because `HostsPage`'s protocol filter is the same control - narrow
 * the grid by clicking a pill - with no count to show. `count` is optional
 * rather than that page passing a fake one, so a caller with nothing to count
 * doesn't have to lie about it.
 */
export function Chip({
  label,
  count,
  selected,
  onClick,
}: {
  label: string;
  count?: number;
  selected: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      aria-pressed={selected}
      onClick={onClick}
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium transition-colors",
        selected
          ? "bg-accent text-accent-foreground border-transparent"
          : "border-border text-muted-foreground hover:bg-muted/50",
      )}
    >
      {label}
      {count !== undefined ? (
        <span className={cn("tabular-nums", selected ? "opacity-80" : "text-muted-foreground/70")}>
          {count}
        </span>
      ) : null}
    </button>
  );
}

function GroupChip({
  group,
  count,
  selected,
  onSelect,
  onRename,
  onDelete,
  onCreateChild,
  moveOptions,
  onMove,
}: {
  group: HostGroup;
  count: number;
  selected: boolean;
  onSelect: () => void;
  onRename: () => void;
  onDelete: () => void;
  onCreateChild: () => void;
  moveOptions: { parentId: string | undefined; label: string }[];
  onMove: (parentId: string | undefined) => void;
}) {
  return (
    // Plain "group" (not a named group) so IconActionButton's own
    // `group-hover:` and `group-focus-within:` reveals - written for a single
    // level of nesting - key off this element without needing a matching named
    // variant here. Both, not just hover: focus the label button or either icon
    // and the pair appears, which is what makes a control that is ALREADY
    // keyboard-reachable visible to a keyboard user. Reachable is the element's
    // job - these are real `<button>`s, so they are in the tab order natively -
    // and the reveal only decides whether you can see what you have focused.
    <div
      className={cn(
        "group inline-flex items-center gap-0.5 rounded-full border py-1 pr-1 pl-2.5 text-xs font-medium transition-colors",
        selected
          ? "bg-accent text-accent-foreground border-transparent"
          : "border-border text-muted-foreground hover:bg-muted/50",
      )}
    >
      <button
        type="button"
        aria-pressed={selected}
        onClick={onSelect}
        className="flex items-center gap-1.5"
      >
        {group.name}
        <span className={cn("tabular-nums", selected ? "opacity-80" : "text-muted-foreground/70")}>
          {count}
        </span>
      </button>
      <IconActionButton icon={Plus} label="New sub-group" onClick={onCreateChild} />
      <DropdownMenu>
        <IconTooltip label="More group actions" side="bottom">
          <DropdownMenuTrigger asChild>
            <button
              type="button"
              aria-label="More group actions"
              className={cn(TRAILING_BTN_BASE, TRAILING_BTN_VARIANT.default)}
            >
              <MoreHorizontal size={TRAILING_ICON_SIZE} strokeWidth={2} />
            </button>
          </DropdownMenuTrigger>
        </IconTooltip>
        <DropdownMenuContent align="start">
          <DropdownMenuItem onSelect={onRename}>
            <Pencil size={14} strokeWidth={1.75} />
            Rename
          </DropdownMenuItem>
          <DropdownMenuSub>
            <DropdownMenuSubTrigger>
              <FolderInput size={14} strokeWidth={1.75} />
              Move to…
            </DropdownMenuSubTrigger>
            <DropdownMenuSubContent>
              {moveOptions.map((opt) => (
                <DropdownMenuItem key={opt.parentId ?? ""} onSelect={() => onMove(opt.parentId)}>
                  {opt.label}
                </DropdownMenuItem>
              ))}
            </DropdownMenuSubContent>
          </DropdownMenuSub>
          <DropdownMenuItem variant="destructive" onSelect={onDelete}>
            <Trash2 size={14} strokeWidth={1.75} />
            Delete
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  );
}
