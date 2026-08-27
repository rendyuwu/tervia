export { TabBar } from "./TabBar";
export {
  MAX_PANES_PER_TAB,
  useTabs,
  activeLeaf,
  activeLeafKind,
  isEditorLikeTab,
  isTerminalLikeTab,
  type Tab,
  type PaneTab,
} from "./lib/useTabs";
export { useWorkspaceCwd } from "./lib/useWorkspaceCwd";
export { countTabEntries } from "./lib/entries";
export {
  canCloseLeaf,
  canCloseTab,
  leafCloseConfirmReason,
  leafCloseRefusal,
  tabCloseConfirmReason,
  tabCloseRefusal,
  type CloseConfirmReason,
  type CloseRefusal,
} from "./lib/closable";
export {
  isRailViewKind,
  isTabPageKind,
  RAIL_VIEW_KINDS,
  TAB_PAGE_KIND,
  type RailViewKind,
  type TabPageKind,
} from "./lib/pages";
