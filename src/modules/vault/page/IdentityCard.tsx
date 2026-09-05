/**
 * One vault identity in the Vault page list. Pure presentation: every value it
 * shows arrives as a prop, exactly as `hosts/page/HostCard.tsx` does it, so the
 * page owns the data (the row builder, the reference counts, the missing-secret
 * answer) and this file owns only the rendering.
 *
 * Edit opens the identity editor. There is no selection, no connect
 * action and no card-level `onClick`: this card is a static row, not the
 * interactive surface `HostCard` is, and giving it one for no caller would be a
 * dead affordance of the kind this app has shipped before (a header drag that
 * silently does nothing under a rail view). Delete is here because
 * the refusal behind it is real code today.
 *
 * Nothing here says anything about how well a secret is protected, because
 * nothing about the vault protects one better than it was protected before:
 * what it buys is FEWER COPIES of one secret.
 */
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { IconTooltip } from "@/components/ui/icon-tooltip";
import { DESTRUCTIVE_ACTION } from "@/lib/toolbarButton";
import { cn } from "@/lib/utils";
import { CircleAlert, KeyRound, Pencil, Trash2 } from "lucide-react";
import type { ReactNode } from "react";

import type { VaultAuthMode, VaultIdentity } from "../types";

export type IdentityCardProps = {
  identity: VaultIdentity;
  /** The bound key's NAME, or the page's unknown-key label for a `keyId` the
   *  vault cannot resolve. The page's row builder resolves it; this card never
   *  looks a key up. */
  keyName?: string;
  /** `keyId` names a key the vault does not have. Colours the KEY CHIP and
   *  nothing else: for `authMode: "key"` the row is already destructive through
   *  `missingSecret`, so a second destructive mark would be one fact said
   *  twice, and for any other mode a stale `keyId` does not stop the identity
   *  working - a destructive row badge there would be a false alarm about a
   *  record that connects fine. */
  keyDangling?: boolean;
  /** How many hosts bind to this identity. A count, not a list: the names are
   *  what the delete refusal carries, and the page reads them from
   *  `hostsUsingIdentity` when it needs them. */
  hostCount: number;
  /** The record names a secret it does not have. Renders as a warning pip. */
  missingSecret?: boolean;
  /** Open the editor for this record. Required, not optional: no surface lists
   *  these rows without being able to edit one, and an optional callback would
   *  let a future caller render a card whose Edit button does nothing. */
  onEdit: () => void;
  onDelete: () => void;
};

const AUTH_LABEL: Record<VaultAuthMode, string> = {
  password: "Password",
  key: "Key",
  agent: "Agent",
};

/** `user`, or `DOMAIN\user` when the identity carries a domain (RDP only - see
 *  `VaultIdentity.domain`). */
function accountDetail(identity: VaultIdentity): string {
  return identity.domain ? `${identity.domain}\\${identity.username}` : identity.username;
}

/** "3 hosts" / "1 host" / the honest zero. A row nothing uses is the row a
 *  delete succeeds on, so saying so is useful rather than noise. */
function usageDetail(hostCount: number): string {
  if (hostCount === 0) return "No hosts";
  return hostCount === 1 ? "1 host" : `${hostCount} hosts`;
}

export function IdentityCard({
  identity,
  keyName,
  keyDangling,
  hostCount,
  missingSecret,
  onEdit,
  onDelete,
}: IdentityCardProps): ReactNode {
  return (
    <div
      role="group"
      aria-label={`${identity.name}, vault identity`}
      className={cn(
        "group border-border hover:bg-muted/30 flex flex-col gap-2 rounded-lg border p-3 text-left transition-colors",
        // ~100px, the same reasoning as HostCard's: content-visibility skips
        // layout and paint for off-screen rows (search-first keeps the
        // steady-state DOM small, this covers the unfiltered case), and
        // WITHOUT contain-intrinsic-size an off-screen row lays out at 0px and
        // the scrollbar jumps while the user scrolls. The pair is load-bearing;
        // neither half works alone.
        "[contain-intrinsic-size:auto_100px] [content-visibility:auto]",
      )}
    >
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <span className="min-w-0 flex-1 truncate text-sm font-medium">{identity.name}</span>
        <Badge variant={missingSecret ? "destructive" : "outline"} className="shrink-0">
          {missingSecret && <CircleAlert size={11} strokeWidth={2} />}
          {missingSecret ? "Missing secret" : AUTH_LABEL[identity.authMode]}
        </Badge>
      </div>

      <div className="text-muted-foreground truncate text-xs">{accountDetail(identity)}</div>

      <div className="flex min-h-6 flex-wrap items-center justify-between gap-x-2 gap-y-1">
        <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1 text-xs">
          <span className="text-muted-foreground truncate">{usageDetail(hostCount)}</span>
          {keyName !== undefined ? (
            <span
              className={cn(
                "inline-flex min-w-0 items-center gap-1",
                keyDangling ? "text-destructive" : "text-muted-foreground",
              )}
              title={keyDangling ? "This identity names a key the vault does not have" : undefined}
            >
              <KeyRound size={11} strokeWidth={2} className="shrink-0" />
              <span className="truncate">{keyName}</span>
            </span>
          ) : null}
        </div>
        <div className="flex shrink-0 items-center gap-0.5 opacity-0 transition-opacity group-focus-within:opacity-100 group-hover:opacity-100">
          <IconTooltip label="Edit">
            <Button
              type="button"
              variant="ghost"
              size="icon-xs"
              aria-label={`Edit ${identity.name}`}
              onClick={onEdit}
            >
              <Pencil size={12} strokeWidth={1.75} />
            </Button>
          </IconTooltip>
          <IconTooltip label="Delete">
            <Button
              type="button"
              variant="ghost"
              size="icon-xs"
              aria-label={`Delete ${identity.name}`}
              onClick={onDelete}
              className={DESTRUCTIVE_ACTION}
            >
              <Trash2 size={12} strokeWidth={1.75} />
            </Button>
          </IconTooltip>
        </div>
      </div>
    </div>
  );
}
