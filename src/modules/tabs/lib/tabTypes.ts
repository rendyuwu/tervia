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

/**
 * Lifecycle hint an extension can attach to its tab so the title text
 * colour reflects connection / job state. Mirrors the SSH tab palette so
 * "remote-ish" extensions read consistently next to terminal tabs:
 * `connecting`/`reconnecting` → pulsing yellow, `connected` → green,
 * `disconnected`/`error` → red, `idle`/undefined → default.
 */
export type ExtensionTabState =
  | "idle"
  | "connecting"
  | "reconnecting"
  | "connected"
  | "disconnected"
  | "error";

/**
 * Extension-owned tab. The content is mounted by `ExtensionTabStack`
 * which calls the renderer registered by `ctx.registerPanelRenderer`.
 * Opened via `ctx.tabs.openExtensionTab({ extensionId, panelId, title })`.
 */
export type ExtensionTab = {
  id: number;
  kind: "ext";
  title: string;
  extensionId: string;
  panelId: string;
  /** Optional icon path relative to the extension root (or `data:` URL). */
  icon?: string;
  /** Caller-supplied stable id for dedup (so re-opening focuses the
   *  existing tab instead of pushing a new one). */
  reuseKey?: string;
  /** Optional lifecycle tone for the tab title text. Updated by the
   *  extension via `ctx.tabs.setExtensionTabState(...)`. */
  state?: ExtensionTabState;
};

export type Tab = PaneTab | ExtensionTab;
