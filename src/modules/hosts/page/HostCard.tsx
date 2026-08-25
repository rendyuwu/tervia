/**
 * One host in the Hosts page grid. Pure presentation: every value it shows and
 * every action it exposes arrives as a prop, so the page owns the data (the
 * merged host list, the vault lookup, the missing-secret check) and this file
 * only owns the rendering.
 */
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { IconTooltip } from "@/components/ui/icon-tooltip";
import { DESTRUCTIVE_ACTION } from "@/lib/toolbarButton";
import { cn } from "@/lib/utils";
import { CircleAlert, Copy, Pencil, Play, Trash2, type LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import { isSshHost, type Host } from "../types";

export type HostCardProps = {
  host: Host;
  /** The vault identity's name when the binding is `{kind:"identity"}`; undefined
   *  for an inline binding. The page resolves it; the card never looks it up. */
  identityName?: string;
  groupName?: string;
  /** The record claims a credential the keychain does not hold, or an auth mode
   *  whose secret is absent. Renders as a warning pip. */
  missingSecret?: boolean;
  selected?: boolean;
  /** Single click. Optional, so a surface with no selection model can omit it. */
  onSelect?: () => void;
  onConnect: () => void;
  onEdit: () => void;
  onDuplicate: () => void;
  onDelete: () => void;
};

/** `user@host:port`, or bare `host:port` for a vault-bound host - its username
 *  lives on the vault identity, which this card never resolves. */
function connectionDetail(host: Host): string {
  const address = `${host.host}:${host.port}`;
  if (isSshHost(host)) {
    return host.credential.kind === "inline" ? `${host.credential.user}@${address}` : address;
  }
  // Host is SshHost | RdpHost, so failing isSshHost narrows this to RdpHost -
  // no cast needed to reach the RDP-only `username` field below.
  return host.credential.kind === "inline" ? `${host.credential.username}@${address}` : address;
}

export function HostCard({
  host,
  identityName,
  groupName,
  missingSecret,
  selected,
  onSelect,
  onConnect,
  onEdit,
  onDuplicate,
  onDelete,
}: HostCardProps): ReactNode {
  const detail = connectionDetail(host);
  const credentialLabel = missingSecret ? "Missing secret" : (identityName ?? "Inline");

  return (
    <div
      tabIndex={0}
      role="group"
      aria-label={`${host.name}, ${host.protocol.toUpperCase()} host`}
      onClick={onSelect}
      onDoubleClick={onConnect}
      onKeyDown={(e) => {
        // Only an Enter that lands on the card itself connects. Enter on a
        // nested action button is that button's own activation, and the
        // keydown still bubbles here - without this guard it would ALSO fire
        // onConnect on top of whatever the button just did.
        if (e.key === "Enter" && e.target === e.currentTarget) {
          e.preventDefault();
          onConnect();
        }
      }}
      className={cn(
        "group flex cursor-default flex-col gap-2 rounded-lg border p-3 text-left transition-colors outline-none",
        "focus-visible:ring-ring/50 focus-visible:ring-2",
        selected ? "border-primary bg-accent/30" : "border-border hover:bg-muted/30",
        // ~100px: p-3 padding (24) + name/pip row (20) + detail row (16) +
        // group/actions row (24) + two 8px gaps (16). content-visibility:auto
        // skips layout/paint for off-screen cards (search-first keeps the
        // steady-state DOM small, this covers the unfiltered case); without
        // contain-intrinsic-size an off-screen card lays out at 0px and the
        // scrollbar jumps while the user scrolls - it looks like dead weight
        // and is load-bearing.
        "[contain-intrinsic-size:auto_100px] [content-visibility:auto]",
      )}
    >
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <span className="min-w-0 flex-1 truncate text-sm font-medium">{host.name}</span>
        <Badge
          variant={missingSecret ? "destructive" : identityName ? "secondary" : "outline"}
          className="shrink-0"
        >
          {missingSecret && <CircleAlert size={11} strokeWidth={2} />}
          {credentialLabel}
        </Badge>
      </div>

      <div className="text-muted-foreground truncate text-xs">
        {host.protocol.toUpperCase()} · {detail}
      </div>

      <div className="flex min-h-6 flex-wrap items-center justify-between gap-x-2 gap-y-1">
        {groupName ? (
          <span className="text-muted-foreground min-w-0 truncate text-xs">{groupName}</span>
        ) : (
          <span />
        )}
        <div
          className="flex shrink-0 items-center gap-0.5 opacity-0 transition-opacity group-focus-within:opacity-100 group-hover:opacity-100"
          // Row actions live inside the card's own click/dblclick handlers, so
          // both must be stopped here - otherwise double-clicking Edit would
          // also fire the card's onConnect as the dblclick bubbles past it.
          onClick={(e) => e.stopPropagation()}
          onDoubleClick={(e) => e.stopPropagation()}
        >
          <CardAction icon={Play} label="Connect" onClick={onConnect} />
          <CardAction icon={Pencil} label="Edit" onClick={onEdit} />
          <CardAction icon={Copy} label="Duplicate" onClick={onDuplicate} />
          <CardAction icon={Trash2} label="Delete" onClick={onDelete} destructive />
        </div>
      </div>
    </div>
  );
}

/** One row-action icon button. Local to this file - the four calls are its
 *  only callers. */
function CardAction({
  icon: Icon,
  label,
  onClick,
  destructive,
}: {
  icon: LucideIcon;
  label: string;
  onClick: () => void;
  destructive?: boolean;
}) {
  return (
    <IconTooltip label={label}>
      <Button
        type="button"
        variant="ghost"
        size="icon-xs"
        aria-label={label}
        onClick={onClick}
        className={cn(destructive && DESTRUCTIVE_ACTION)}
      >
        <Icon size={12} strokeWidth={1.75} />
      </Button>
    </IconTooltip>
  );
}
