import { type PageKind, type TabPageKind } from "@/modules/terminal/lib/panes";

/**
 * Which of the rail's pages may live in the connection tab strip, and which are
 * views of their own.
 *
 * DCR-1: the tab strip is for connections. Hosts earns a place there because it
 * is where connections come FROM - it is the workspace's default tab and the one
 * surface that is always reachable. Vault and Port Forwarding are neither
 * connections nor entry points to one, so they stopped being tabs: the rail
 * shows them over the tab area and clicking a tab (or the lit rail button again)
 * comes back.
 *
 * Splitting the union is what keeps that a rule rather than a habit. `PageKind`
 * still names all three - the rail, its labels and its glyphs are indexed by it -
 * but `PageLeafState.page` is `TabPageKind`, so "open Vault as a tab" is a type
 * error rather than a thing a caller can say. The two leaf constructors are
 * `useAuxTabs.openPageTab` and the workspace restore path in
 * `workspaces/serialize.ts`; both take that type, and restore drops a
 * `vault`/`forwards` leaf saved by an older build.
 *
 * `TabPageKind` itself is declared next to the leaf it constrains, in
 * `terminal/lib/panes.ts`, and re-exported here so the two halves of the split
 * read together.
 */
export type { TabPageKind };

/** A page the rail shows as a view instead of a tab. */
export type RailViewKind = Exclude<PageKind, TabPageKind>;

/** Rail order, top to bottom, below the Hosts button. */
export const RAIL_VIEW_KINDS: readonly RailViewKind[] = ["vault", "forwards"];

/** The one page that is a tab. Named so the leaf constructors read as the rule
 *  rather than as a hardcoded string that happens to be right. */
export const TAB_PAGE_KIND: TabPageKind = "hosts";

export function isTabPageKind(value: string): value is TabPageKind {
  return value === TAB_PAGE_KIND;
}

/** True for a page that must NOT be restored as a pane leaf. Read by the
 *  workspace migration, which drops such a leaf from a pre-DCR-1 snapshot. */
export function isRailViewKind(value: string): value is RailViewKind {
  return (RAIL_VIEW_KINDS as readonly string[]).includes(value);
}
