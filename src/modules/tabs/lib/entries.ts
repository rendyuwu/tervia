import { cn } from "@/lib/utils";
import { type PaneLeaf, isRemoteEditorLeaf, leaves } from "@/modules/terminal/lib/panes";
import { type SshConnection } from "@/modules/ssh/connections";
import { statusLabelClass, type SshStatus } from "@/modules/ssh/status";
import { type AiCliStatus } from "@/modules/terminal/lib/aiCliStatus";
import type { Tab } from "./useTabs";
import { leafLabel, leafRenameSeed } from "./tabHelpers";

/**
 * Tab strip entries: one per pane for pane tabs, one per tab otherwise.
 * Clicking a pane entry focuses that pane; clicking a standalone entry
 * activates that tab.
 */
type EntryBase = {
  /** Composite key like "tab-3" or "leaf-7". */
  key: string;
  /** Owning tab id. */
  tabId: number;
  /** Display label. */
  label: string;
  /** Italic for preview/transient. */
  italic?: boolean;
  /** Yellow dot for unsaved edits. */
  dirty?: boolean;
};

export type PaneEntry = EntryBase & {
  kind: "pane-leaf";
  leafId: number;
  leafKind: "terminal" | "editor" | "board";
  /** 1-based FIFO badge number for terminal leaves - the same identifier the
   *  AI sees in `<env>`. */
  ordinal?: number;
  /** Working directory of a terminal leaf. Only consumed by hover surfaces (the
   *  Workspaces panel's tooltip); the label itself is already derived. */
  cwd?: string;
  /** Set on terminal leaves bound to a saved SSH host. */
  sshConnectionId?: string;
  /** Latest SSH session status. Drives the colored dot. */
  sshStatus?: SshStatus;
  /** Latest AI CLI status for terminal leaves. Null when no AI CLI is active. */
  aiCliStatus?: AiCliStatus;
  /** Set on editor leaves backed by SFTP. Flips the file icon to a remote variant. */
  remoteHost?: string;
  /** Inherited from the owning tab. Drives the red badge + lock icon. */
  isPrivate?: boolean;
  /** True when `label` is a name the user typed rather than a derived one. Only
   *  drives whether the right-click menu offers "Reset name". */
  renamed?: boolean;
  /** What an inline rename field starts with: `label` minus the kind tag core
   *  re-applies, so committing it unchanged cannot yield "ssh:ssh:prod". */
  renameSeed: string;
};

type StandaloneEntry = EntryBase & {
  kind: "board";
};

export type Entry = PaneEntry | StandaloneEntry;

/**
 * Background color for the per-tab accent stripe. Emerald for local shell,
 * sky for SSH, brand blue for editor, cyan for preview. Rendered as a `<span>` (not `::after`) because the
 * primitive `TabsTrigger` already uses `::after` with equal specificity.
 * Keep strings as full literals for Tailwind's JIT.
 */
export function tabAccentClass(e: Entry): string {
  if (e.kind === "pane-leaf") {
    // Private tabs win the accent regardless of leaf kind so the red stripe
    // is the dominant signal. AI cannot see this tab. Uses the `destructive`
    // (danger) token, matching the private LABEL text elsewhere, rather than
    // the AI-CLI `icon-blocked` status color.
    if (e.isPrivate) return "bg-destructive";
    if (e.leafKind === "terminal") {
      return e.sshConnectionId
        ? "bg-[color:var(--tedi-tab-ssh)]"
        : "bg-[color:var(--tedi-tab-terminal)]";
    }
    return "bg-[color:var(--tedi-tab-editor)]";
  }
  // Board: reuses the violet accent rather than adding a token of its own to
  // all 20 theme presets.
  return "bg-[color:var(--tedi-tab-ai-diff)]";
}

/**
 * Tailwind `text-*` tone for an entry's LABEL: SSH session state, then private,
 * which wins because "not persisted" outranks any liveness colour.
 *
 * Shared by the tab strip and the Workspaces panel so one connected host is
 * green in both places instead of green in the strip and grey in the panel.
 */
export function entryLabelClass(e: Entry): string {
  return cn(
    // Pulse yellow while connecting, emerald when connected, red on
    // disconnect/error. The icon stays sky so the two signals don't collide.
    e.kind === "pane-leaf" && e.sshConnectionId ? statusLabelClass(e.sshStatus) : null,
    // Private leaves carry the red on the label (not the icon) so the icon
    // colour stays free for AI CLI status. Last = wins.
    e.kind === "pane-leaf" && e.isPrivate === true && "text-destructive",
  );
}

export function buildEntries(
  tabs: Tab[],
  sshHosts: Map<string, SshConnection>,
  sshStatuses?: Map<number, SshStatus>,
  aiCliStatuses?: Map<number, AiCliStatus>,
): Entry[] {
  const out: Entry[] = [];
  for (const t of tabs) {
    if (t.kind === "pane") {
      for (const leaf of leaves(t.paneTree)) {
        const label = leafLabel(leaf, sshHosts, t.cwd);
        const sshConnectionId = leaf.leafKind === "terminal" ? leaf.sshConnectionId : undefined;
        // FIFO ordinal assigned at leaf creation. Preserved through drag,
        // reorder, move-to-group, and workspace restarts. It is the same
        // number the AI sees in the per-turn `<env>` block.
        const ord =
          leaf.leafKind === "terminal" && typeof leaf.terminalOrdinal === "number"
            ? leaf.terminalOrdinal
            : undefined;
        const remoteHost =
          leaf.leafKind === "editor" && isRemoteEditorLeaf(leaf)
            ? (leaf.sshHostLabel ?? "remote")
            : undefined;
        out.push({
          kind: "pane-leaf",
          key: `leaf-${leaf.id}`,
          tabId: t.id,
          leafId: leaf.id,
          leafKind: leaf.leafKind,
          cwd: leaf.leafKind === "terminal" ? leaf.cwd : undefined,
          label,
          ordinal: ord,
          italic:
            leaf.leafKind === "editor" &&
            (leaf as PaneLeaf & { preview?: boolean }).preview === true,
          dirty:
            leaf.leafKind === "editor" && (leaf as PaneLeaf & { dirty?: boolean }).dirty === true,
          sshConnectionId,
          sshStatus: sshConnectionId ? sshStatuses?.get(leaf.id) : undefined,
          // AI CLI status on SSH leaves too. Detector runs on the byte stream regardless of PTY locality.
          aiCliStatus: leaf.leafKind === "terminal" ? aiCliStatuses?.get(leaf.id) : undefined,
          remoteHost,
          isPrivate: leaf.private === true,
          renamed: leaf.customTitle !== undefined,
          renameSeed: leafRenameSeed(leaf, sshHosts, t.cwd),
        });
      }
    }
  }
  return out;
}

/**
 * Number of tab-strip entries `buildEntries` would produce, without building
 * them: every leaf of a pane tab (so a split "group" tab contributes all its
 * panes, not 1) plus one for each standalone/extension tab. The workspace
 * badge counts this so it matches the strip exactly instead of treating a
 * multi-pane group as a single tab.
 */
export function countTabEntries(tabs: Tab[]): number {
  let n = 0;
  for (const t of tabs) n += t.kind === "pane" ? leaves(t.paneTree).length : 1;
  return n;
}
