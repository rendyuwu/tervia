import { useCallback, type Dispatch, type RefObject, type SetStateAction } from "react";
import { leaves, PAGE_LABELS, type PageKind, type PaneLeaf } from "@/modules/terminal/lib/panes";
import { type Tab } from "./tabTypes";
import { syncPaneMirror } from "./tabHelpers";

/**
 * Shared mutable handles `useTabs` threads into the aux-tab sub-hook. These
 * are the exact `setTabs` / `setActiveId` setters, id counter, and live-tabs
 * ref owned by `useTabs`; the callbacks below close over them verbatim.
 */
type AuxTabsDeps = {
  setTabs: Dispatch<SetStateAction<Tab[]>>;
  setActiveId: Dispatch<SetStateAction<number>>;
  nextIdRef: RefObject<number>;
  tabsRef: RefObject<Tab[]>;
};

/**
 * The non-terminal tab openers. `useTabs` spreads the returned callbacks into
 * its return object.
 */
export function useAuxTabs({ setTabs, setActiveId, nextIdRef, tabsRef }: AuxTabsDeps) {
  /**
   * Open (or focus) the workspace Board. A board is a pane LEAF, not a
   * standalone tab, so it arrives as a pane tab holding one - which is what
   * gives it the ordinary pane header (drag, close, split) rather than a second
   * hand-rolled copy of it. Single-instance dedup: two boards would chart the
   * same workspace twice.
   */
  const openBoardTab = useCallback(() => {
    const existing = tabsRef.current.find(
      (t) => t.kind === "pane" && leaves(t.paneTree).some((l) => l.leafKind === "board"),
    );
    if (existing) {
      setActiveId(existing.id);
      return existing.id;
    }
    const tabId = nextIdRef.current++;
    const leafId = nextIdRef.current++;
    const leaf: PaneLeaf = { kind: "leaf", id: leafId, leafKind: "board" };
    setTabs((curr) => [
      ...curr,
      syncPaneMirror({
        id: tabId,
        kind: "pane",
        title: "Board",
        paneTree: leaf,
        activeLeafId: leafId,
      }),
    ]);
    setActiveId(tabId);
    return tabId;
  }, []);

  /**
   * Open a saved RDP host in a new pane tab.
   *
   * An RDP session is a pane LEAF like a terminal or an editor, so an "RDP tab"
   * is a pane tab whose tree is a single rdp leaf - splittable, draggable, and
   * carrying the ordinary pane header rather than a second hand-rolled copy of
   * it. Mirrors `newSshTab`.
   *
   * Deliberately NOT single-instance: two panes onto the same host are two
   * separate RDP logins, which is a thing people do (one for a console, one for
   * a tool), and unlike the Board there is no shared state for them to fight
   * over. `title` is only the interim tab name - `syncPaneMirror` immediately
   * recomputes it through `leafLabel`, which resolves the connection properly.
   */
  const newRdpTab = useCallback((rdpConnectionId: string, title: string) => {
    const tabId = nextIdRef.current++;
    const leafId = nextIdRef.current++;
    const leaf: PaneLeaf = {
      kind: "leaf",
      id: leafId,
      leafKind: "rdp",
      rdpConnectionId,
      sizeMode: "preset",
    };
    setTabs((curr) => [
      ...curr,
      syncPaneMirror({
        id: tabId,
        kind: "pane",
        title,
        paneTree: leaf,
        activeLeafId: leafId,
      }),
    ]);
    setActiveId(tabId);
    return tabId;
  }, []);

  /**
   * Open (or focus) a rail page. Single-instance PER PAGE KIND: two Hosts
   * lists would be two copies of one store subscription fighting over the
   * same selection state, with no upside - unlike `newRdpTab` below, which is
   * deliberately not single-instance because two RDP panes are two genuine
   * logins with nothing to fight over.
   */
  const openPageTab = useCallback((page: PageKind) => {
    const existing = (() => {
      for (const t of tabsRef.current) {
        if (t.kind !== "pane") continue;
        const leaf = leaves(t.paneTree).find((l) => l.leafKind === "page" && l.page === page);
        if (leaf) return { tabId: t.id, leafId: leaf.id };
      }
      return null;
    })();
    if (existing) {
      // Focus the page LEAF, not just its tab. The rail button carries a pressed
      // state, so when the page shares a tab with a focused terminal, activating
      // the tab alone would leave the button reading as engaged with the caret
      // still in the terminal - a dead click on a permanent affordance.
      setActiveId(existing.tabId);
      setTabs((curr) =>
        curr.map((t) =>
          t.id === existing.tabId && t.kind === "pane" && t.activeLeafId !== existing.leafId
            ? syncPaneMirror({ ...t, activeLeafId: existing.leafId })
            : t,
        ),
      );
      return existing.tabId;
    }
    const tabId = nextIdRef.current++;
    const leafId = nextIdRef.current++;
    const leaf: PaneLeaf = { kind: "leaf", id: leafId, leafKind: "page", page };
    setTabs((curr) => [
      ...curr,
      syncPaneMirror({
        id: tabId,
        kind: "pane",
        title: PAGE_LABELS[page],
        paneTree: leaf,
        activeLeafId: leafId,
      }),
    ]);
    setActiveId(tabId);
    return tabId;
  }, []);

  return { openBoardTab, newRdpTab, openPageTab };
}
