/**
 * One vault key in the Vault page list. Pure presentation, same contract as
 * `IdentityCard` next door: the page's row builder resolves every value.
 *
 * The record arrives as `vaultKey` because `key` is React's reserved prop - a
 * prop named `key` never reaches the component at all, and the list key the
 * page must also supply is a different thing entirely.
 *
 * Edit opens the key editor. There is no selection and no card-level
 * `onClick`: this card is a static row, not the interactive surface `HostCard`
 * is, and giving it one for no caller would be a dead affordance of the kind
 * this app has shipped before (a header drag that silently does nothing under a
 * rail view).
 *
 * ONE EXCEPTION to "the row builder resolves every value", and it is called out
 * rather than left to be noticed: the needs-a-passphrase line below is derived
 * HERE, by calling `keyNeedsPassphrase` on the record this card already holds,
 * instead of arriving as a prop like `missingPrivateKey` does. It is the same
 * shape of question, off the same record, through the same shared predicate
 * module - so the two cannot disagree - and it costs no new prop on a row
 * builder that would only be forwarding a pure function of `vaultKey`.
 */
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { IconTooltip } from "@/components/ui/icon-tooltip";
import { DESTRUCTIVE_ACTION } from "@/lib/toolbarButton";
import { cn } from "@/lib/utils";
import { CircleAlert, Pencil, Trash2 } from "lucide-react";
import type { ReactNode } from "react";

import { keyNeedsPassphrase } from "../refs";
import type { VaultKey } from "../types";

export type KeyCardProps = {
  vaultKey: VaultKey;
  /** How many identities name this key. */
  identityCount: number;
  /** The record claims a private key the store does not hold. */
  missingPrivateKey?: boolean;
  /** Open the editor for this record. Required, not optional: no surface lists
   *  these rows without being able to edit one, and an optional callback would
   *  let a future caller render a card whose Edit button does nothing. */
  onEdit: () => void;
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
  onEdit,
  onDelete,
}: KeyCardProps): ReactNode {
  const needsPassphrase = keyNeedsPassphrase(vaultKey);
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

      {/* The one state the badge above cannot carry, because the badge holds the
          key type and there is exactly one of it. Said in full rather than as a
          second chip: "encrypted" alone is not the problem - an encrypted key
          with its passphrase stored is the ordinary, better case - so the line
          has to name what is MISSING, and there is no shorter true version of
          that. Not wrapped in the truncating classes the fingerprint uses: a
          sentence clipped mid-clause is worse than a taller row, and this row
          is rare. */}
      {needsPassphrase && (
        <div className="text-destructive flex items-start gap-1.5 text-xs">
          <CircleAlert size={12} strokeWidth={2} className="mt-px shrink-0" />
          <span className="min-w-0">
            Recorded as passphrase-encrypted with no passphrase stored, so it fails every connect
            until its passphrase is entered in the editor.
          </span>
        </div>
      )}

      <div className="flex min-h-6 flex-wrap items-center justify-between gap-x-2 gap-y-1">
        <span className="text-muted-foreground min-w-0 truncate text-xs">
          {usageDetail(identityCount)}
        </span>
        <div className="flex shrink-0 items-center gap-0.5 opacity-0 transition-opacity group-focus-within:opacity-100 group-hover:opacity-100">
          <IconTooltip label="Edit">
            <Button
              type="button"
              variant="ghost"
              size="icon-xs"
              aria-label={`Edit ${vaultKey.name}`}
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
