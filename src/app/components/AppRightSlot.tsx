import { ResizableHandle, ResizablePanel } from "@/components/ui/resizable";
import {
  isMovableSection,
  useRightColumnStore,
  useSidebarPlacementStore,
  type RightSectionId,
} from "@/modules/rightPanel";
import { FileExplorer } from "@/modules/explorer";
import { WorkspacesPanel } from "@/modules/workspaces";
import { type SshStatus } from "@/modules/ssh/status";
import { type Tab } from "@/modules/tabs";
import { Suspense, type RefObject } from "react";
import { type TabsApi } from "../hooks/tabsApi";
import { SshFileExplorer } from "./lazyPanels";
import { SectionStack, type StackSection } from "./SectionStack";

type Props = {
  rightSections: RightSectionId[];
  sshRightOpen: boolean;
  explorerRoot: string | null;
  onPathDeleted: (path: string) => void;
  closeSshRight: () => void;
  /** SSH context for the right-slot Remote explorer (same source the sidebar uses). */
  activeSshContext: {
    sessionId: number | null;
    hostLabel: string | null;
    cwd: string | null;
    fromActiveLeaf: boolean;
  };
  onOpenRemoteFile: (path: string, sessionId: number, hostLabel: string | null) => void;
  /** Files-section props, so a right-docked Files section renders in the column
   *  (same values App passes to AppSidebar). */
  filesSection: {
    onOpenFile: (path: string, pin?: boolean) => void;
    onPathRenamed: (from: string, to: string) => void;
    onRevealInTerminal: (path: string) => void;
    onPreviewInBrowser: (path: string) => void;
    activeFilePath: string | null;
  };
  /** Workspaces-section props, for a right-docked Workspaces section. */
  workspacesSection: {
    onSwitch: (id: string) => void;
    onCreate: () => void;
    onCloseWorkspace: (id: string) => void;
    tabCounts: Record<string, number>;
    liveTabs: Tab[];
    cachedTabsByWorkspace: RefObject<Map<string, { tabs: Tab[]; activeId: number | null }>>;
    onFocusLeaf: (tabId: number, leafId: number) => void;
    onRenameLeaf: (leafId: number, title: string | null) => void;
    onCloseEntry: (tabId: number, leafId: number | null) => void;
    activeLeafId: number | null;
    sshStatuses: Map<number, SshStatus>;
  };
} & Pick<TabsApi, "openBoardTab">;

// Persisted in localStorage, alongside the left sidebar's own order key.
const ORDER_LS_KEY = "tervia:right:sectionOrder";
// Sections start compact; the group normalizes for whatever is actually open.
const PANEL_DEFAULT_SIZE = "25%";

/** Move a docked section back to the left sidebar (undocks) vs just closing it
 *  (keeps the dock; the status-bar toggle reopens it) - mirrors SSH. Module
 *  scope because it reads both stores imperatively and closes over nothing. */
function dockLeft(key: RightSectionId): void {
  useSidebarPlacementStore.getState().moveLeft(key);
  useRightColumnStore.getState().closeSection(key);
}

/**
 * The right column: Remote plus the right-docked sidebar sections, STACKED
 * rather than mutually exclusive.
 *
 * It renders through the same `SectionStack` as the left sidebar, so every
 * surface here is resizable against its neighbours, minimizable to its header,
 * and drag-reorderable by the grip in that header. Each surface already draws
 * its own bento card, hence `chrome={false}`. Renders nothing when the column
 * is empty.
 */
export function AppRightSlot({
  rightSections,
  sshRightOpen,
  explorerRoot,
  onPathDeleted,
  closeSshRight,
  activeSshContext,
  onOpenRemoteFile,
  filesSection,
  workspacesSection,
  openBoardTab,
}: Props) {
  const sections: StackSection[] = [];

  if (sshRightOpen) {
    sections.push({
      key: "ssh",
      title: "Remote",
      defaultSize: PANEL_DEFAULT_SIZE,
      render: (controls, collapsed) => (
        <div className="border-border/60 bg-background tervia-glass-panel flex h-full min-h-0 flex-col overflow-hidden rounded-md border">
          <Suspense fallback={null}>
            <SshFileExplorer
              sessionId={activeSshContext.sessionId}
              hostLabel={activeSshContext.hostLabel}
              currentCwd={activeSshContext.cwd}
              onOpenFile={onOpenRemoteFile}
              onClose={closeSshRight}
              dragHandle={controls}
              collapsed={collapsed}
            />
          </Suspense>
        </div>
      ),
    });
  }

  for (const docked of rightSections) {
    if (docked === "files") {
      sections.push({
        key: "files",
        title: "Files",
        defaultSize: PANEL_DEFAULT_SIZE,
        render: (controls, collapsed) => (
          <div className="border-border/60 bg-background tervia-glass-panel flex h-full min-h-0 flex-col overflow-hidden rounded-md border">
            <FileExplorer
              rootPath={explorerRoot}
              onOpenFile={filesSection.onOpenFile}
              onPathRenamed={filesSection.onPathRenamed}
              onPathDeleted={onPathDeleted}
              onRevealInTerminal={filesSection.onRevealInTerminal}
              onPreviewInBrowser={filesSection.onPreviewInBrowser}
              activeFilePath={filesSection.activeFilePath}
              dragHandle={controls}
              collapsed={collapsed}
              onMoveToLeft={() => dockLeft("files")}
              onClose={() => useRightColumnStore.getState().closeSection("files")}
              hideSort
            />
          </div>
        ),
      });
      continue;
    }
    if (docked === "workspaces") {
      sections.push({
        key: "workspaces",
        title: "Workspaces",
        defaultSize: PANEL_DEFAULT_SIZE,
        render: (controls) => (
          <div className="border-border/60 bg-background tervia-glass-panel flex h-full min-h-0 flex-col overflow-hidden rounded-md border">
            <WorkspacesPanel
              onSwitch={workspacesSection.onSwitch}
              onCreate={workspacesSection.onCreate}
              onClose={workspacesSection.onCloseWorkspace}
              tabCounts={workspacesSection.tabCounts}
              liveTabs={workspacesSection.liveTabs}
              cachedTabsByWorkspace={workspacesSection.cachedTabsByWorkspace}
              onFocusLeaf={workspacesSection.onFocusLeaf}
              onRenameLeaf={workspacesSection.onRenameLeaf}
              onCloseEntry={workspacesSection.onCloseEntry}
              onOpenBoard={openBoardTab}
              activeLeafId={workspacesSection.activeLeafId}
              sshStatuses={workspacesSection.sshStatuses}
              dragHandle={controls}
              onMoveToLeft={() => dockLeft("workspaces")}
              onClosePanel={() => useRightColumnStore.getState().closeSection("workspaces")}
            />
          </div>
        ),
      });
    }
  }

  if (sections.length === 0) return null;

  return (
    <>
      <ResizableHandle withHandle />
      <ResizablePanel id="right-slot" defaultSize="22%" minSize="18%" maxSize="50%">
        <div data-section-column="right" className="flex h-full flex-col">
          <SectionStack
            sections={sections}
            orderStorageKey={ORDER_LS_KEY}
            idPrefix="right"
            chrome={false}
            column="right"
            canMoveColumn={isMovableSection}
            onMoveColumn={(key) => {
              if (isMovableSection(key)) dockLeft(key);
            }}
          />
        </div>
      </ResizablePanel>
    </>
  );
}
