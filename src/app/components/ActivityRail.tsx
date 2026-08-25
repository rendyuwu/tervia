import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { IconTooltip } from "@/components/ui/icon-tooltip";
import { PAGE_ICONS } from "@/components/LeafIcon";
import { leaves, PAGE_LABELS, type PageKind } from "@/modules/terminal/lib/panes";
import { type Tab } from "@/modules/tabs";

/** Rail order, top to bottom. The glyphs come from the shared `PAGE_ICONS`. */
const RAIL_PAGES: PageKind[] = ["hosts", "vault", "forwards"];

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
  // EVERY page in the active tab, not just the first: splitting Hosts and Vault
  // into one tab puts both on screen, and a rail button that stays unpressed
  // while its page is visible is the same lie as one pressed while it isn't.
  const activePages = new Set<PageKind>();
  if (activeTab?.kind === "pane") {
    for (const l of leaves(activeTab.paneTree)) {
      if (l.leafKind === "page") activePages.add(l.page);
    }
  }

  return (
    <div className="bg-background tervia-glass-panel flex w-12 shrink-0 flex-col items-center gap-1 rounded-md border py-1.5">
      {RAIL_PAGES.map((page) => {
        const Icon = PAGE_ICONS[page];
        const active = activePages.has(page);
        return (
          <IconTooltip key={page} label={PAGE_LABELS[page]} side="right">
            <Button
              onClick={() => onOpenPage(page)}
              aria-label={PAGE_LABELS[page]}
              aria-pressed={active}
              variant="ghost"
              size="icon"
              className={cn(
                "size-8 rounded-md",
                active
                  ? "bg-accent text-accent-foreground"
                  : "text-muted-foreground hover:text-foreground",
              )}
            >
              <Icon size={16} strokeWidth={2} />
            </Button>
          </IconTooltip>
        );
      })}
    </div>
  );
}
