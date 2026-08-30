/**
 * One vault key in the Vault page list. Pure presentation, same contract as
 * `IdentityCard` next door: the page's row builder resolves every value.
 *
 * The record arrives as `vaultKey` because `key` is React's reserved prop - a
 * prop named `key` never reaches the component at all, and the list key the
 * page must also supply is a different thing entirely.
 */
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { IconTooltip } from "@/components/ui/icon-tooltip";
import { DESTRUCTIVE_ACTION } from "@/lib/toolbarButton";
import { cn } from "@/lib/utils";
import { CircleAlert, Trash2 } from "lucide-react";
import type { ReactNode } from "react";

import type { VaultKey } from "../types";

export type KeyCardProps = {
  vaultKey: VaultKey;
  /** How many identities name this key. */
  identityCount: number;
  /** The record claims a private key the store does not hold. */
  missingPrivateKey?: boolean;
  onDelete: () => void;
};

/** "2 identities" / "1 identity" / the honest zero. */
function usageDetail(identityCount: number): string {
  if (identityCount === 0) return "No identities";
  return identityCount === 1 ? "1 identity" : `${identityCount} identities`;
}

export function KeyCard({
  vaultKey,
  identityCount,
  missingPrivateKey,
  onDelete,
}: KeyCardProps): ReactNode {
  return (
    <div
      role="group"
      aria-label={`${vaultKey.name}, vault key`}
      className={cn(
        "group border-border hover:bg-muted/30 flex flex-col gap-2 rounded-lg border p-3 text-left transition-colors",
        "[contain-intrinsic-size:auto_100px] [content-visibility:auto]",
      )}
    >
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <span className="min-w-0 flex-1 truncate text-sm font-medium">{vaultKey.name}</span>
        <Badge variant={missingPrivateKey ? "destructive" : "outline"} className="shrink-0">
          {missingPrivateKey && <CircleAlert size={11} strokeWidth={2} />}
          {missingPrivateKey
            ? "Missing private key"
            : vaultKey.keyType !== undefined
              ? vaultKey.keyType.toUpperCase()
              : "Unknown type"}
        </Badge>
      </div>

      {/* The fingerprint identifies the KEY YOU HOLD. `font-mono` and the full
          string, truncated by the box rather than shortened in code, because a
          fingerprint a user compares against has to be comparable. The host
          editor's "Recorded server key" row is the other fingerprint in this
          app and identifies a MACHINE - the two must never read as the same
          thing, which is why this one sits under a key's own name. */}
      <div className="text-muted-foreground truncate font-mono text-[11px]">
        {vaultKey.fingerprint ?? "No fingerprint recorded"}
      </div>

      <div className="flex min-h-6 flex-wrap items-center justify-between gap-x-2 gap-y-1">
        <span className="text-muted-foreground min-w-0 truncate text-xs">
          {usageDetail(identityCount)}
        </span>
        <div className="flex shrink-0 items-center gap-0.5 opacity-0 transition-opacity group-focus-within:opacity-100 group-hover:opacity-100">
          <IconTooltip label="Delete">
            <Button
              type="button"
              variant="ghost"
              size="icon-xs"
              aria-label={`Delete ${vaultKey.name}`}
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
