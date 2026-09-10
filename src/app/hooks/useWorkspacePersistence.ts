import { type Tab } from "@/modules/tabs";
import {
  defaultHostsTab,
  savedActiveTabIndex,
  serializeTabs,
  useWorkspacesStore,
} from "@/modules/workspaces";
// Deep import, like `useWorkspaceSwitching`: `restoreWorkspaceEntry` lives beside
// the serializer so the verify scripts can execute it (see its doc comment).
import { restoreWorkspaceEntry } from "@/modules/workspaces/serialize";
import { useEffect, useRef, type RefObject } from "react";

type Workspace = ReturnType<typeof useWorkspacesStore.getState>["workspaces"][number];

type Params = {
  wsHydrate: () => void;
  wsHydrated: boolean;
  restoreTabsOnHydrate?: boolean;
  persistTabsSnapshot?: boolean;
  wsList: Workspace[];
  wsActiveId: string | null;
  wsSaveTabs: (
    workspaceId: string,
    saved: ReturnType<typeof serializeTabs>,
    activeTabIndex: number,
    liveTabCount?: number,
  ) => void;
  tabs: Tab[];
  activeId: number;
  allocId: () => number;
  replaceAllTabs: (tabs: Tab[], activeId: number | null) => void;
  skipNextSnapshotRef: RefObject<boolean>;
};

/**
 * Workspace persistence side of the workspaces wiring: hydrate the store on
 * mount, load the active workspace's saved tabs into live state once, and
 * auto-snapshot live tabs back to the store on every change.
 *
 * The disk snapshot (`serializeTabs` -> `wsSaveTabs`) is NOT debounced, and a
 * comment here said for a long time that it was: `persist` in
 * `modules/workspaces/store.ts` commits immediately, so every `saveWorkspaceTabs`
 * that changes anything is a whole write of the workspace file.
 * `skipNextSnapshotRef` is shared
 * with `useWorkspaceSwitching` (a workspace close sets it so the closing
 * workspace's live tabs don't clobber the neighbor's saved tabs), so it lives
 * in App and is passed in. `hydratedWorkspaceRef` is local. Effects are moved
 * verbatim with identical dependency arrays.
 */
export function useWorkspacePersistence({
  wsHydrate,
  wsHydrated,
  restoreTabsOnHydrate = true,
  persistTabsSnapshot = true,
  wsList,
  wsActiveId,
  wsSaveTabs,
  tabs,
  activeId,
  allocId,
  replaceAllTabs,
  skipNextSnapshotRef,
}: Params): void {
  useEffect(() => {
    void wsHydrate();
  }, [wsHydrate]);

  // Once the workspace store hydrates, load the active workspace's saved
  // tabs into live state - or land on the Hosts page when
  // there is nothing to restore (first run, an empty workspace, or a dev
  // session that skips restore below). `useTabs`' own initial state is an
  // empty tab list precisely so this effect is the only place that decides;
  // it runs exactly once (`hydratedWorkspaceRef`), synchronously within the
  // render where `wsHydrated` first turns true, so nothing downstream (the
  // daemon-session adopt poll, gated on the same flag) can observe the gap
  // between "hydrated" and "tabs decided".
  const hydratedWorkspaceRef = useRef(false);
  useEffect(() => {
    if (!wsHydrated || hydratedWorkspaceRef.current) return;
    hydratedWorkspaceRef.current = true;

    const openHostsFallback = () => {
      const tab = defaultHostsTab(allocId);
      replaceAllTabs([tab], tab.id);
    };

    if (!restoreTabsOnHydrate) {
      openHostsFallback();
      return;
    }
    const active = wsList.find((w) => w.id === wsActiveId);
    if (!active || active.tabs.length === 0) {
      openHostsFallback();
      return;
    }
    // `restoreWorkspaceEntry` applies the rail-view migration (a page leaf this
    // build will not restore as a tab is dropped, and so is a tab that empties
    // out),
    // falls back to Hosts if that leaves nothing, and re-bases the saved active
    // index onto the tabs that survived - a dropped tab shifts every later one.
    // The three callers used to each do the last part themselves, and two of
    // them clamped the raw index instead.
    const restored = restoreWorkspaceEntry(active, allocId);
    replaceAllTabs(restored.tabs, restored.activeId);
  }, [wsHydrated, wsList, wsActiveId, replaceAllTabs, allocId]);

  // Auto-snapshot tabs whenever they change. Not debounced anywhere: the store's
  // `persist` writes the file on every change that gets this far.
  useEffect(() => {
    if (!persistTabsSnapshot) return;
    if (!wsHydrated || !wsActiveId || !hydratedWorkspaceRef.current) return;
    if (skipNextSnapshotRef.current) {
      skipNextSnapshotRef.current = false;
      return;
    }
    const saved = serializeTabs(tabs);
    // Pass the live tab count so the store's anti-wipe guard can tell a
    // legitimate all-session-only emptying (tabs.length > 0, serialize empty)
    // from a transient truly-empty state (tabs.length 0).
    wsSaveTabs(wsActiveId, saved, savedActiveTabIndex(tabs, activeId), tabs.length);
  }, [tabs, activeId, wsHydrated, wsActiveId, wsSaveTabs]);
}
