/**
 * The Hosts page's group filter strip: All / Ungrouped / one chip per
 * `HostGroup`, plus create, rename and delete. Pure presentation over the
 * counts and callbacks the page hands it - no store access of its own.
 */
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
import { toast } from "@/components/ui/toast";
import { cn } from "@/lib/utils";
import { InlineInput } from "@/modules/explorer/InlineInput";
import { TrailingIconButton } from "@/modules/tabs/components/TrailingIconButton";
import { Pencil, Plus, Trash2 } from "lucide-react";
import { useMemo, useState, type ReactNode } from "react";
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
  onCreateGroup: (name: string) => void | Promise<void>;
  onRenameGroup: (id: string, name: string) => void | Promise<void>;
  onDeleteGroup: (id: string) => void | Promise<void>;
};

/** Ordered groups first (by `order`, ascending), then unordered ones by name.
 *  Stable regardless of the array's incoming order, so the strip does not
 *  reshuffle between renders. */
function sortGroups(groups: HostGroup[]): HostGroup[] {
  return [...groups].sort((a, b) => {
    if (a.order !== undefined && b.order !== undefined) return a.order - b.order;
    if (a.order !== undefined) return -1;
    if (b.order !== undefined) return 1;
    return a.name.localeCompare(b.name);
  });
}

/** The one cascade in the host model that is correct: a group is a label, not
 *  an owner, so deleting it only clears `groupId` on its members. Said plainly
 *  here because the failure mode runs both ways - read as "delete these
 *  hosts" and a user who should confirm won't, read the other way when it
 *  really would delete them and a user who confirms loses data. */
function deleteDescription(hostCount: number): string {
  // The empty case gets its own sentence rather than reading "The 0 hosts in
  // this group are not deleted", which is true and unreadable.
  if (hostCount === 0) {
    return "This group has no hosts, so nothing else changes. This cannot be undone.";
  }
  const noun = hostCount === 1 ? "host" : "hosts";
  const verb = hostCount === 1 ? "is" : "are";
  return `The ${hostCount} ${noun} in this group ${verb} not deleted - they become ungrouped. This cannot be undone.`;
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
  onDeleteGroup,
}: GroupStripProps): ReactNode {
  const sorted = useMemo(() => sortGroups(groups), [groups]);
  const [creating, setCreating] = useState(false);
  const [renamingId, setRenamingId] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<HostGroup | null>(null);

  // Every one of the three mutations can be refused by the store. Surface the
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

        {sorted.map((group) =>
          renamingId === group.id ? (
            <InlineInput
              key={group.id}
              initial={group.name}
              placeholder="Group name"
              onCommit={(value) => {
                setRenamingId(null);
                const trimmed = value.trim();
                if (!trimmed || trimmed === group.name) return;
                void runMutation(() => onRenameGroup(group.id, trimmed));
              }}
              onCancel={() => setRenamingId(null)}
            />
          ) : (
            <GroupChip
              key={group.id}
              group={group}
              count={counts.byGroup[group.id] ?? 0}
              selected={selectedGroupId === group.id}
              onSelect={() => onSelectGroup(group.id)}
              onRename={() => setRenamingId(group.id)}
              onDelete={() => setDeleting(group)}
            />
          ),
        )}

        {creating ? (
          <InlineInput
            initial=""
            placeholder="Group name"
            onCommit={(value) => {
              setCreating(false);
              const trimmed = value.trim();
              if (!trimmed) return;
              void runMutation(() => onCreateGroup(trimmed));
            }}
            onCancel={() => setCreating(false)}
          />
        ) : (
          <Button
            type="button"
            variant="ghost"
            size="xs"
            onClick={() => setCreating(true)}
            className="gap-1"
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
              {deleteDescription(deleting ? (counts.byGroup[deleting.id] ?? 0) : 0)}
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
}: {
  group: HostGroup;
  count: number;
  selected: boolean;
  onSelect: () => void;
  onRename: () => void;
  onDelete: () => void;
}) {
  return (
    // Plain "group" (not a named group) so TrailingIconButton's own
    // `group-hover:opacity-60` - written for a single level of nesting - keys
    // off this element without needing a matching named variant here.
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
      <TrailingIconButton icon={Pencil} label="Rename group" onClick={onRename} />
      <TrailingIconButton icon={Trash2} label="Delete group" onClick={onDelete} variant="danger" />
    </div>
  );
}
