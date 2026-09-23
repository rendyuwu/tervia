import { cn } from "@/lib/utils";
import { LeafIcon } from "@/components/LeafIcon";
import type { Entry } from "../lib/entries";

/**
 * Pill badge stamped next to terminal entries ("Terminal 3"). Uses the muted
 * palette so the emerald/yellow/red palette stays reserved for the AI CLI icon
 * tint.
 */
function OrdinalBadge({ ordinal }: { ordinal: number }) {
  const label = `Terminal ${ordinal}`;
  return (
    <span
      aria-label={label}
      className={cn(
        "inline-flex shrink-0 items-center self-center rounded px-1.5 py-[3px] font-mono text-[10px] leading-none font-semibold tabular-nums",
        "bg-muted text-muted-foreground",
      )}
    >
      {ordinal}
    </span>
  );
}

export function EntryIcon({ entry }: { entry: Entry }) {
  // The leaf glyph is shared with the pane header + drag overlay (see
  // `LeafIcon`) so a leaf reads identically in every surface. The tab strip
  // adds the FIFO ordinal badge on terminals on top of that glyph.
  const glyph = (
    <LeafIcon
      info={{
        leafKind: entry.leafKind,
        isSsh: !!entry.sshConnectionId,
        editorFileName: entry.leafKind === "editor" ? entry.label : undefined,
        editorRemote: !!entry.remoteHost,
        aiCliStatus: entry.aiCliStatus,
        page: entry.page,
      }}
      size={14}
    />
  );
  const ordinal = entry.leafKind === "terminal" ? entry.ordinal : undefined;
  if (ordinal) {
    return (
      <span className="inline-flex shrink-0 items-center gap-1">
        {glyph}
        <OrdinalBadge ordinal={ordinal} />
      </span>
    );
  }
  return glyph;
}
