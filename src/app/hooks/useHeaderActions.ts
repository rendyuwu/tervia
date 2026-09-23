import { openSettingsWindow } from "@/modules/settings/openSettingsWindow";
import { type RdpHost, type SshHost } from "@/modules/hosts/types";
import { MAX_PANES_PER_TAB, type PaneTab } from "@/modules/tabs";
import { leafIds } from "@/modules/terminal";
import { openUrl } from "@tauri-apps/plugin-opener";
import { useCallback, useMemo } from "react";
import { type TabsApi } from "./tabsApi";

type Params = {
  activePaneTab: PaneTab | null;
  detectedBrowserUrl: string | null;
} & Pick<TabsApi, "setActiveId" | "focusPane" | "pinTab" | "newSshTab" | "newRdpTab">;

/**
 * Stable handlers for the memoised `<Header/>`. Each was previously an inline
 * arrow in the JSX, so the memo wrapper saw a fresh prop identity on every App
 * re-render. Bundled here verbatim with identical dependency arrays;
 * `detectedBrowserUrl` is threaded in from App.
 */
export function useHeaderActions({
  activePaneTab,
  detectedBrowserUrl,
  setActiveId,
  focusPane,
  pinTab,
  newSshTab,
  newRdpTab,
}: Params): {
  handleOpenDetectedPreview: () => void;
  handleHeaderSelectEntry: (tabId: number, leafId: number) => void;
  handleHeaderPinLeaf: (tabId: number, leafId: number) => void;
  handleHeaderOpenSettings: () => void;
  handleHeaderConnectSsh: (conn: SshHost) => void;
  handleHeaderConnectRdp: (conn: RdpHost) => void;
  headerCanSplit: boolean;
} {
  // The pane header's globe pill: hand the detected dev-server url to the OS
  // browser. There is no in-app browser to open it in any more.
  const handleOpenDetectedPreview = useCallback(() => {
    if (detectedBrowserUrl) void openUrl(detectedBrowserUrl).catch(console.error);
  }, [detectedBrowserUrl]);

  const handleHeaderSelectEntry = useCallback(
    (tabId: number, leafId: number) => {
      setActiveId(tabId);
      focusPane(tabId, leafId);
    },
    [setActiveId, focusPane],
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
    (conn: SshHost) => newSshTab(conn.id, conn.name),
    [newSshTab],
  );
  // The name is only the interim tab title: `syncPaneMirror` recomputes it
  // through `leafLabel`, which resolves the connection to `rdp:<name>` and
  // keeps following it across a rename.
  const handleHeaderConnectRdp = useCallback(
    (conn: RdpHost) => newRdpTab(conn.id, conn.name),
    [newRdpTab],
  );
  const headerCanSplit = useMemo(
    () => activePaneTab !== null && leafIds(activePaneTab.paneTree).length < MAX_PANES_PER_TAB,
    [activePaneTab],
  );

  return {
    handleOpenDetectedPreview,
    handleHeaderSelectEntry,
    handleHeaderPinLeaf,
    handleHeaderOpenSettings,
    handleHeaderConnectSsh,
    handleHeaderConnectRdp,
    headerCanSplit,
  };
}
