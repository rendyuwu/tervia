/**
 * Status-bar toggle buttons for the sidebar sections the user has docked to the
 * right column. Mirrors `SshRightOpenButton`: an icon-only button that
 * opens/closes the section in the column, shown while its placement is "right"
 * (never removed, so the row doesn't reflow). The open state reads active.
 */
import { IconTooltip } from "@/components/ui/icon-tooltip";
import { cn } from "@/lib/utils";
import { FolderTree, LayoutDashboard, type LucideIcon } from "lucide-react";

import { MOVABLE_SECTIONS, useSidebarPlacementStore, type RightSectionId } from "./placement";
import { isRightSectionOpen, useRightColumnStore } from "./store";

const ICONS: Record<RightSectionId, LucideIcon> = {
  files: FolderTree,
  workspaces: LayoutDashboard,
};

export function RightSectionToggles() {
  const placement = useSidebarPlacementStore((s) => s.placement);
  const open = useRightColumnStore((s) => s.open);
  const toggle = useRightColumnStore((s) => s.toggleSection);

  const moved = MOVABLE_SECTIONS.filter((s) => placement[s.id] === "right");
  if (moved.length === 0) return null;

  return (
    <div className="flex items-center gap-1.5">
      {moved.map(({ id, title }) => {
        const Icon = ICONS[id];
        const isOpen = isRightSectionOpen(open, id);
        return (
          <IconTooltip key={id} label={`${isOpen ? "Close" : "Open"} ${title}`} side="top">
            <button
              type="button"
              onClick={() => toggle(id)}
              aria-label={`${isOpen ? "Close" : "Open"} ${title}`}
              aria-pressed={isOpen}
              className={cn(
                "flex size-6 cursor-pointer items-center justify-center rounded-md transition-colors",
                isOpen
                  ? "text-foreground bg-accent/60"
                  : "text-muted-foreground hover:text-foreground",
              )}
            >
              <Icon size={16} strokeWidth={1.75} className="shrink-0" />
            </button>
          </IconTooltip>
        );
      })}
    </div>
  );
}
