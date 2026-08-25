import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { IconTooltip } from "@/components/ui/icon-tooltip";
import { leaves, PAGE_LABELS, type PageKind } from "@/modules/terminal/lib/panes";
import { type Tab } from "@/modules/tabs";
import { ArrowLeftRight, Router, Vault, type LucideIcon } from "lucide-react";

const RAIL_ITEMS: { page: PageKind; icon: LucideIcon }[] = [
  { page: "hosts", icon: Router },
  { page: "vault", icon: Vault },
  { page: "forwards", icon: ArrowLeftRight },
];

type Props = {
  /** The current tab. "Active" means THIS tab holds the page leaf, not any
   *  tab in the workspace - two Hosts tabs can't exist (§5.1), but the rail
   *  still shouldn't light up for one sitting in a background tab. */
  activeTab: Tab | undefined;
  onOpenPage: (page: PageKind) => void;
};

/**
 * Fixed-width icon strip left of the sidebar. Holds no selection state of its
 * own - "active" is derived from the live tab list every render - and, unlike
 * the sidebar, is never collapsible (§9.6/§12.10).
 */
export function ActivityRail({ activeTab, onOpenPage }: Props) {
  const activePage: PageKind | null =
    activeTab?.kind === "pane"
      ? (leaves(activeTab.paneTree).find((l) => l.leafKind === "page")?.page ?? null)
      : null;

  return (
    <div className="bg-background tervia-glass-panel flex w-12 shrink-0 flex-col items-center gap-1 rounded-md border py-1.5">
      {RAIL_ITEMS.map(({ page, icon: Icon }) => (
        <IconTooltip key={page} label={PAGE_LABELS[page]} side="right">
          <Button
            onClick={() => onOpenPage(page)}
            aria-label={PAGE_LABELS[page]}
            aria-pressed={activePage === page}
            variant="ghost"
            size="icon"
            className={cn(
              "size-8 rounded-md",
              activePage === page
                ? "bg-accent text-accent-foreground"
                : "text-muted-foreground hover:text-foreground",
            )}
          >
            <Icon size={16} strokeWidth={2} />
          </Button>
        </IconTooltip>
      ))}
    </div>
  );
}
