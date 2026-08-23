import { type PaneNode } from "@/modules/terminal/lib/panes";

/**
 * A pane tab holds a tmux-style pane tree of terminal or editor leaves.
 * Splitting (Ctrl+D / Ctrl+Shift+D) adds a new leaf next to the focused one.
 * Trees can mix horizontal and vertical orientations.
 * `title` / `cwd` / `path` / `dirty` / `preview` mirror the active leaf and
 * resync whenever the tree or active leaf changes.
 */
export type PaneTab = {
  id: number;
  kind: "pane";
  title: string;
  paneTree: PaneNode;
  activeLeafId: number;
  // Mirrors of the active leaf, populated by `syncPaneMirror`.
  cwd?: string;
  path?: string;
  dirty?: boolean;
  preview?: boolean;
};

/** Tabs are pane tabs. The alias is kept because the app talks about `Tab`
 *  everywhere and the tab layer used to carry other kinds. */
export type Tab = PaneTab;
