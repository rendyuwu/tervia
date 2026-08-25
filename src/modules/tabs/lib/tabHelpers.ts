import { basename } from "@/lib/path";
import { findLeaf, type PaneLeaf } from "@/modules/terminal/lib/panes";
import { type Host } from "@/modules/hosts/types";
import { type PaneTab, type Tab } from "./tabTypes";

/**
 * The KIND tag that stays in front of a tab's name, or null when the kind needs
 * no word (a terminal, an editor - their names already read as what they are).
 *
 * Renaming replaces the NAME, never this. An SSH pane called "prod" is still
 * `ssh:prod`, in the strip AND in the Workspaces panel.
 */
export function leafKindTag(leaf: PaneLeaf): string | null {
  if (leaf.leafKind === "terminal" && leaf.sshConnectionId) return "ssh";
  // Same reasoning as `ssh`: the name is a machine, and which protocol you are
  // holding it open with is not something a rename should be able to drop.
  if (leaf.leafKind === "rdp") return "rdp";
  return null;
}

/**
 * What the inline rename field starts with: the current name WITHOUT the kind
 * tag. Both rename surfaces seeded their input with the full label, so keeping
 * an SSH tab's name and pressing Enter stored "ssh:prod" as the name and the
 * tab read `ssh:ssh:prod`.
 */
export function leafRenameSeed(
  leaf: PaneLeaf,
  hosts?: Map<string, Host>,
  fallbackCwd?: string,
): string {
  if (leaf.customTitle) return leaf.customTitle;
  const tag = leafKindTag(leaf);
  const label = leafLabel(leaf, hosts, fallbackCwd);
  if (!tag) return label;
  // A leaf whose connection was deleted reads as a bare "ssh": that is all tag
  // and no name, so seed it empty rather than handing back the tag to be
  // committed as one ("ssh" -> "ssh:ssh").
  if (label === tag) return "";
  return label.startsWith(`${tag}:`) ? label.slice(tag.length + 1) : label;
}

/**
 * THE display label for a pane leaf. Single source for every surface that names
 * one: the tab strip (`buildEntries`), the pane header, `tab.title` (which the
 * "Join Group" submenu and friends read), and the Workspaces panel's terminal
 * list. They all have to agree, or a renamed tab keeps showing its old folder
 * name somewhere.
 *
 * `hosts` resolves an SSH or RDP leaf to `ssh:<name>` / `rdp:<name>`; a caller
 * with no host map (`tab.title`, which is recomputed before the map is even
 * loaded) gets the bare "ssh"/"rdp" interim label. `fallbackCwd` is the owning
 * tab's cwd, used only when the leaf itself carries none.
 */
export function leafLabel(leaf: PaneLeaf, hosts?: Map<string, Host>, fallbackCwd?: string): string {
  // A user-set name wins over every derived one. Renaming exists precisely
  // because "the folder this opened in" is often not what the tab should say,
  // so nothing below may override it - except the KIND tag, which is not a
  // name and is not the user's to drop (see leafKindTag).
  if (leaf.customTitle) {
    const tag = leafKindTag(leaf);
    return tag ? `${tag}:${leaf.customTitle}` : leaf.customTitle;
  }
  if (leaf.leafKind === "editor") return basename(leaf.path);
  if (leaf.leafKind === "board") return "Board";
  // RDP leaves: `rdp:<name>` off the saved connection, falling back to its
  // host, then to a bare "rdp" for a deleted connection or a caller with no
  // map. Exactly the SSH ladder, because the failure modes are the same.
  if (leaf.leafKind === "rdp") {
    const host = hosts?.get(leaf.rdpConnectionId);
    if (!host) return "rdp";
    return `rdp:${host.name.trim() || host.host}`;
  }
  // SSH leaves: show "ssh:<name>" when the saved connection has a name, else
  // fall back to the host/IP. Bare "ssh" if the connection was deleted.
  if (leaf.sshConnectionId) {
    const host = hosts?.get(leaf.sshConnectionId);
    if (!host) return "ssh";
    return `ssh:${host.name.trim() || host.host}`;
  }
  for (const cwd of [leaf.cwd, fallbackCwd]) {
    const b = cwd ? basename(cwd) : "";
    if (b) return b;
  }
  return "shell";
}

/** Recompute the top-level mirrors from the active leaf. */
export function syncPaneMirror(tab: PaneTab): PaneTab {
  const leaf = findLeaf(tab.paneTree, tab.activeLeafId);
  if (!leaf) return tab;
  const next: PaneTab = {
    ...tab,
    title: leafLabel(leaf),
  };
  if (leaf.leafKind === "terminal") {
    next.cwd = leaf.cwd;
    delete next.path;
    delete next.dirty;
    delete next.preview;
  } else if (leaf.leafKind === "editor") {
    delete next.cwd;
    next.path = leaf.path;
    next.dirty = leaf.dirty;
    next.preview = leaf.preview;
  } else {
    // RDP or board leaf: neither has a cwd or a file, so the top-level mirrors
    // are cleared rather than left holding the previous active leaf's.
    delete next.cwd;
    delete next.path;
    delete next.dirty;
    delete next.preview;
  }
  return next;
}

/** Helpers for discriminating on the active leaf kind. */
export function activeLeaf(tab: Tab): PaneLeaf | null {
  if (tab.kind !== "pane") return null;
  return findLeaf(tab.paneTree, tab.activeLeafId);
}

export function activeLeafKind(tab: Tab): "terminal" | "editor" | "rdp" | null {
  const leaf = activeLeaf(tab);
  if (!leaf) return null;
  // Board leaves aren't one of the kinds the chrome derivations branch on;
  // report null so callers fall to their defaults instead of every one having to
  // special-case them.
  //
  // RDP is reported, unlike board, for one reason: a focused RDP pane owns the
  // keyboard the way a focused terminal does, and App's shortcut `isDisabled`
  // gate needs to know that or every bare-Ctrl chord would fire an app action
  // instead of reaching the remote desktop.
  return leaf.leafKind === "board" ? null : leaf.leafKind;
}

export function isTerminalLikeTab(tab: Tab): boolean {
  return tab.kind === "pane" && activeLeafKind(tab) === "terminal";
}

export function isEditorLikeTab(tab: Tab): boolean {
  return tab.kind === "pane" && activeLeafKind(tab) === "editor";
}
