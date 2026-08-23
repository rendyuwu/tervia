import { openSettingsWindow } from "@/modules/settings/openSettingsWindow";
import { type SshConnection } from "@/modules/ssh/connections";
import { MAX_PANES_PER_TAB, type PaneTab } from "@/modules/tabs";
import { leafIds } from "@/modules/terminal";
import { openUrl } from "@tauri-apps/plugin-opener";
import { useCallback, useMemo } from "react";
import { type TabsApi } from "./tabsApi";

type Params = {
  activePaneTab: PaneTab | null;
  detectedBrowserUrl: string | null;
  handleClose: (id: number) => void;
  requestCloseLeaf: (leafId: number) => void;
} & Pick<TabsApi, "setActiveId" | "focusPane" | "pinTab" | "newSshTab">;

/**
 * Stable handlers for the memoised `<Header/>`. Each was previously an inline
 * arrow in the JSX, so the memo wrapper saw a fresh prop identity on every App
 * re-render. Bundled here verbatim with identical dependency arrays;
 * `handleClose` / `detectedBrowserUrl` are threaded in from
 * App.
 */
export function useHeaderActions({
  activePaneTab,
  detectedBrowserUrl,
  handleClose,
  requestCloseLeaf,
  setActiveId,
  focusPane,
  pinTab,
  newSshTab,
}: Params): {
  handleOpenDetectedPreview: () => void;
  handleHeaderSelectEntry: (tabId: number, leafId: number | null) => void;
  handleHeaderCloseEntry: (tabId: number, leafId: number | null) => void;
  handleHeaderPinLeaf: (tabId: number, leafId: number) => void;
  handleHeaderOpenSettings: () => void;
  handleHeaderConnectSsh: (conn: SshConnection, opts?: { private?: boolean }) => void;
  headerCanSplit: boolean;
} {
  // The pane header's globe pill: hand the detected dev-server url to the OS
  // browser. There is no in-app browser to open it in any more.
  const handleOpenDetectedPreview = useCallback(() => {
    if (detectedBrowserUrl) void openUrl(detectedBrowserUrl).catch(console.error);
  }, [detectedBrowserUrl]);

  const handleHeaderSelectEntry = useCallback(
    (tabId: number, leafId: number | null) => {
      setActiveId(tabId);
      if (leafId !== null) focusPane(tabId, leafId);
    },
    [setActiveId, focusPane],
  );
  const handleHeaderCloseEntry = useCallback(
    (tabId: number, leafId: number | null) => {
      if (leafId !== null) {
        requestCloseLeaf(leafId);
      } else {
        handleClose(tabId);
      }
    },
    [requestCloseLeaf, handleClose],
  );
  const handleHeaderPinLeaf = useCallback(
    (tabId: number, leafId: number) => {
      focusPane(tabId, leafId);
      pinTab(tabId);
    },
    [focusPane, pinTab],
  );
  const handleHeaderOpenSettings = useCallback(() => void openSettingsWindow(), []);
  const handleHeaderConnectSsh = useCallback(
    (conn: SshConnection, opts?: { private?: boolean }) => newSshTab(conn.id, conn.name, opts),
    [newSshTab],
  );
  const headerCanSplit = useMemo(
    () => activePaneTab !== null && leafIds(activePaneTab.paneTree).length < MAX_PANES_PER_TAB,
    [activePaneTab],
  );

  return {
    handleOpenDetectedPreview,
    handleHeaderSelectEntry,
    handleHeaderCloseEntry,
    handleHeaderPinLeaf,
    handleHeaderOpenSettings,
    handleHeaderConnectSsh,
    headerCanSplit,
  };
}
