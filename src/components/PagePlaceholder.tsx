import { PAGE_ICONS } from "@/components/LeafIcon";
import { PAGE_LABELS, type PageKind } from "@/modules/terminal/lib/panes";

/**
 * The "not built yet" body for a rail page, so the two places that can show one
 * - a rail view (`app/components/RailViewArea.tsx`) and the page-leaf body in
 * `panes/PaneTreeView.tsx` - say it identically instead of each keeping a copy.
 *
 * Both Vault and Port Forwarding have real UI now, each in its own branch of
 * `RailViewArea`; replacing a branch was all either one took, because the rail,
 * its labels and its pressed state are driven by `PageKind` rather than by what
 * is rendered inside.
 */
export function PagePlaceholder({ page }: { page: PageKind }) {
  const Icon = PAGE_ICONS[page];
  return (
    <div className="bg-background text-muted-foreground flex h-full w-full flex-col items-center justify-center gap-3 p-6 text-center">
      <Icon size={28} strokeWidth={1.5} className="opacity-50" />
      <span className="text-foreground text-sm font-medium">{PAGE_LABELS[page]}</span>
      <span className="max-w-72 text-[11px] leading-relaxed opacity-70">Coming soon.</span>
    </div>
  );
}
