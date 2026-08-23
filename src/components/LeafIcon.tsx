import { cn } from "@/lib/utils";
import { CliAgentIcon } from "./CliAgentIcon";
import { fileIconUrl } from "@/modules/explorer/lib/iconResolver";
import { aiCliIconClass, type AiCliStatus } from "@/modules/terminal/lib/aiCliStatus";
import { Lock, Server, SquarePen, SquareTerminal } from "lucide-react";

/** Normalized description of one pane leaf, enough to pick its icon. Built from
 *  a tab-strip `Entry` or a `PaneLeaf` so both feed the same renderer. */
export type LeafIconInfo = {
  leafKind: "terminal" | "editor" | "board";
  /** Private leaf (AI cannot read it): forces a lock glyph over kind/ssh. */
  isPrivate?: boolean;
  /** Terminal bound to a saved SSH host: cloud glyph instead of local terminal. */
  isSsh?: boolean;
  /** Editor filename. Drives the catppuccin file-type icon. */
  editorFileName?: string;
  /** Editor backed by SFTP: recolor the file icon (remote variant). */
  editorRemote?: boolean;
  /** Terminal AI CLI status: tints the glyph idle/working/blocking. */
  aiCliStatus?: AiCliStatus | null;
};

/**
 * The icon for a single pane leaf. Shared by the tab strip (EntryIcon), the
 * per-pane header, and the pane drag overlay so a leaf reads identically
 * everywhere it appears - the shape the user grabs is the shape shown in the
 * strip and the header.
 *
 * Precedence (matches every surface): private (lock) > editor file-type icon /
 * SSH cloud / local terminal. The AI CLI status tints the
 * glyph; `className` carries the default (non-AI) colour and the AI tint wins
 * via tailwind-merge when present. The terminal FIFO ordinal badge is NOT
 * rendered here - it stays specific to the tab strip.
 */
export function LeafIcon({
  info,
  size = 14,
  className,
}: {
  info: LeafIconInfo;
  size?: number;
  className?: string;
}) {
  const aiTint = info.aiCliStatus ? aiCliIconClass(info.aiCliStatus) : null;

  if (info.isPrivate) {
    return <Lock size={size} strokeWidth={2} className={cn("shrink-0", className, aiTint)} />;
  }

  if (info.leafKind === "editor") {
    const url = info.editorFileName ? fileIconUrl(info.editorFileName) : "";
    // Empty while the catppuccin set is still loading, or for an unknown file
    // type: fall back to the pencil so an editor leaf is never icon-less.
    if (!url) {
      return <SquarePen size={size} strokeWidth={2} className={cn("shrink-0", className)} />;
    }
    if (info.editorRemote) {
      // Remote (SFTP) files reuse the file-type shape recolored sky-blue via a
      // CSS mask. Trade-off: loses per-language colour, gains a remote cue.
      return (
        <span
          aria-hidden
          className={cn("bg-info shrink-0", className)}
          style={{
            width: size,
            height: size,
            mask: `url("${url}") center / contain no-repeat`,
            WebkitMask: `url("${url}") center / contain no-repeat`,
          }}
        />
      );
    }
    return (
      <img
        src={url}
        alt=""
        width={size}
        height={size}
        draggable={false}
        className={cn("shrink-0", className)}
      />
    );
  }

  // A running agent replaces the terminal shape with its own vendor mark, so a
  // wall of terminals is readable at a glance: which one is Claude, which is
  // Codex, which is Gemini. It outranks the SSH cloud - "remote" is already
  // carried by the `ssh:<host>` label and its status colour, while WHICH agent
  // is running has nowhere else to show. The status tint still applies, so the
  // mark keeps breathing green/yellow/red exactly as the terminal glyph did.
  if (info.aiCliStatus) {
    return (
      <CliAgentIcon
        agentId={info.aiCliStatus.tool}
        size={size}
        className={cn("shrink-0", className, aiTint)}
      />
    );
  }

  // Terminal: cloud for SSH, local terminal otherwise.
  return info.isSsh ? (
    <Server size={size} strokeWidth={2} className={cn("shrink-0", className)} />
  ) : (
    <SquareTerminal size={size} strokeWidth={2} className={cn("shrink-0", className)} />
  );
}
