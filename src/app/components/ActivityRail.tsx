import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { IconTooltip } from "@/components/ui/icon-tooltip";
import { PAGE_ICONS } from "@/components/LeafIcon";
import { leaves, PAGE_LABELS, type PageKind } from "@/modules/terminal/lib/panes";
import {
  RAIL_VIEW_KINDS,
  TAB_PAGE_KIND,
  type RailViewKind,
  type TabPageKind,
  type Tab,
} from "@/modules/tabs";

type Props = {
  /** The current tab. "Active" means THIS tab holds the page leaf, not any
   *  tab in the workspace - two Hosts tabs can't exist, but the rail
   *  still shouldn't light up for one sitting in a background tab. */
  activeTab: Tab | undefined;
  /** Open (or focus) the Hosts tab and return to the tab area. */
  onOpenPage: (page: TabPageKind) => void;
  /** The rail view currently covering the tab area, or null when the tabs are
   *  showing. Not persisted: a relaunch comes up on the tabs. */
  railView: RailViewKind | null;
  /** Show this rail view, or - when it is the one already showing - go back to
   *  the tabs. The same button both ways, so the lit button is never a dead one. */
  onToggleRailView: (view: RailViewKind) => void;
};

/**
 * Fixed-width icon strip left of the sidebar. Holds no selection state of its
 * own - "active" is derived from the live tab list and the current rail view on
 * every render - and, unlike the sidebar, is never collapsible.
 *
 * Two kinds of button, which is the whole shape (see `tabs/lib/pages.ts`):
 * Hosts activates a TAB, because it is where connections come from and belongs
 * in the strip of them; Vault and Port Forwarding are views shown OVER the tab
 * area, because they are not connections and were only ever taking up room in a
 * strip that is for them.
 */
export function ActivityRail({ activeTab, onOpenPage, railView, onToggleRailView }: Props) {
  // EVERY page in the active tab, not just the first: splitting Hosts and a
  // terminal into one tab puts both on screen, and a rail button that stays
  // unpressed while its page is visible is the same lie as one pressed while it
  // isn't. A rail view covering the tab area means none of them is visible.
  const activePages = new Set<PageKind>();
  if (railView === null && activeTab?.kind === "pane") {
    for (const l of leaves(activeTab.paneTree)) {
      if (l.leafKind === "page") activePages.add(l.page);
    }
  }

  return (
    <div className="bg-background tervia-glass-panel flex w-12 shrink-0 flex-col items-center gap-1 rounded-md border py-1.5">
      <RailButton
        page={TAB_PAGE_KIND}
        active={activePages.has(TAB_PAGE_KIND)}
        onClick={() => onOpenPage(TAB_PAGE_KIND)}
      />
      {RAIL_VIEW_KINDS.map((view) => (
        <RailButton
          key={view}
          page={view}
          active={railView === view}
          onClick={() => onToggleRailView(view)}
        />
      ))}
    </div>
  );
}

/** One rail button. Same glyph, label and pressed treatment either side of the
 *  tab/view split, so the strip reads as one control rather than two. */
function RailButton({
  page,
  active,
  onClick,
}: {
  page: PageKind;
  active: boolean;
  onClick: () => void;
}) {
  const Icon = PAGE_ICONS[page];
  return (
    <IconTooltip label={PAGE_LABELS[page]} side="right">
      <Button
        onClick={onClick}
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
}
