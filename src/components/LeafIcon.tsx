import { cn } from "@/lib/utils";
import { CliAgentIcon } from "./CliAgentIcon";
import { fileIconUrl } from "@/modules/explorer/lib/iconResolver";
import { aiCliIconClass, type AiCliStatus } from "@/modules/terminal/lib/aiCliStatus";
import type { PageKind } from "@/modules/terminal/lib/panes";
import {
  ArrowLeftRight,
  Monitor,
  Router,
  Server,
  SquarePen,
  SquareTerminal,
  Vault,
  type LucideIcon,
} from "lucide-react";

/** Normalized description of one pane leaf, enough to pick its icon. Built from
 *  a tab-strip `Entry` or a `PaneLeaf` so both feed the same renderer. */
export type LeafIconInfo = {
  leafKind: "terminal" | "editor" | "rdp" | "board" | "page";
  /** Terminal bound to a saved SSH host: cloud glyph instead of local terminal. */
  isSsh?: boolean;
  /** Editor filename. Drives the catppuccin file-type icon. */
  editorFileName?: string;
  /** Editor backed by SFTP: recolor the file icon (remote variant). */
  editorRemote?: boolean;
  /** Terminal AI CLI status: tints the glyph idle/working/blocking. */
  aiCliStatus?: AiCliStatus | null;
  /** Which rail page, for a `page` leaf. Picks the glyph below. */
  page?: PageKind;
};

/**
 * One glyph per rail page. Single source of truth, read by the activity rail,
 * the tab strip / pane header (via `LeafIcon` below) and the page body itself -
 * `Record<PageKind, …>` catches a MISSING page but nothing catches a divergent
 * one, so three copies meant re-marking Vault in the rail and silently leaving
 * the strip on the old glyph. Lives here rather than in `terminal/lib/panes.ts`
 * beside `PAGE_LABELS` because no file under a `lib/` directory imports
 * `lucide-react`, and this file already does.
 */
export const PAGE_ICONS: Record<PageKind, LucideIcon> = {
  hosts: Router,
  vault: Vault,
  forwards: ArrowLeftRight,
};

/**
 * The icon for a single pane leaf. Shared by the tab strip (EntryIcon), the
 * per-pane header, and the pane drag overlay so a leaf reads identically
 * everywhere it appears - the shape the user grabs is the shape shown in the
 * strip and the header.
 *
 * Precedence (matches every surface): editor file-type icon / RDP monitor / SSH
 * cloud / local terminal. The AI CLI status tints the
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

  // RDP: a monitor, ABOVE the AI-CLI branch below because that branch is about
  // what is running in a terminal and an RDP leaf has no terminal to run it in
  // (and no `aiCliStatus`, so the branch could not fire - but leaving the order
  // to that coincidence is how a later change silently repaints these).
  if (info.leafKind === "rdp") {
    return <Monitor size={size} strokeWidth={2} className={cn("shrink-0", className)} />;
  }

  // Page: one glyph per rail page, so a Hosts/Vault/Forwards tab reads as
  // what it is rather than all sharing one generic "page" shape.
  if (info.leafKind === "page") {
    const PageIcon = info.page ? PAGE_ICONS[info.page] : Router;
    return <PageIcon size={size} strokeWidth={2} className={cn("shrink-0", className)} />;
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
