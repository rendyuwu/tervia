import { countTabEntries, type Tab } from "@/modules/tabs";
import { useWorkspacesStore } from "@/modules/workspaces";
import { useEffect, useMemo, useState } from "react";

type Params = {
  tabs: Tab[];
  wsActiveId: string | null;
};

/**
 * Live tab counts per workspace: tracks the active workspace's real tab-entry
 * total so the sidebar badge matches the tab strip exactly. `liveTabCounts` is
 * returned for the WorkspacesPanel badge.
 */
export function useTabSideEffects({ tabs, wsActiveId }: Params): {
  liveTabCounts: Record<string, number>;
} {
  // Live tab counts per workspace, keyed by id. The active workspace's entry
  // tracks the real open-tab total (every kind, including the session-only
  // diff / scm / extension tabs the persisted snapshot drops), so the sidebar
  // badge matches the tab strip exactly. Workspaces visited this session keep
  // their last live count while inactive (no jump on switch-away); never-yet-
  // visited ones fall back to the persisted `tabs.length` in WorkspacesPanel.
  const [liveTabCounts, setLiveTabCounts] = useState<Record<string, number>>({});
  // Count tab-strip entries (one per pane leaf, so a split "group" tab counts
  // its panes, not 1) rather than tabs.length, and key the effect on it so a
  // split/unsplit that leaves tabs.length unchanged still updates the badge.
  const tabEntryCount = useMemo(() => countTabEntries(tabs), [tabs]);
  useEffect(() => {
    if (!wsActiveId) return;
    setLiveTabCounts((m) =>
      m[wsActiveId] === tabEntryCount ? m : { ...m, [wsActiveId]: tabEntryCount },
    );
  }, [tabEntryCount, wsActiveId]);

  // Drop entries for workspaces that have been closed so the map stays bounded
  // (it otherwise keeps a count for every workspace ever activated).
  const workspaceIds = useWorkspacesStore((s) => s.workspaces.map((w) => w.id).join("\x1f"));
  useEffect(() => {
    const live = new Set(workspaceIds ? workspaceIds.split("\x1f") : []);
    setLiveTabCounts((m) => {
      const stale = Object.keys(m).filter((id) => !live.has(id));
      if (stale.length === 0) return m;
      const next = { ...m };
      for (const id of stale) delete next[id];
      return next;
    });
  }, [workspaceIds]);

  return { liveTabCounts };
}
