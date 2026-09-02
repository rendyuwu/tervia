/**
 * One forward rule in the Port Forwarding page list. Pure presentation for
 * everything EXCEPT Start/Stop: `HostCard.tsx` and `IdentityCard.tsx` both
 * take every value as a prop and own only the rendering, but this row is
 * also the ONE place `startRule`/`stopRule` (`../controller`, step 9) are
 * called from a component - the page hands over `row` and two callbacks for
 * Edit and Delete, and this file reads the rule's live status for itself
 * through the three primitive selectors `../runtime` exports (§1.6: one
 * selector per primitive, never one object selector).
 *
 * A LIST ROW, not a grid cell - one per line, full width. So this file adds
 * no responsive grid className of its own; `ForwardsPage.tsx` stacks these in
 * a plain `flex flex-col` list.
 */
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { IconTooltip } from "@/components/ui/icon-tooltip";
import { Spinner } from "@/components/ui/spinner";
import { DESTRUCTIVE_ACTION } from "@/lib/toolbarButton";
import { cn } from "@/lib/utils";
import { CircleAlert, Pencil, Play, SquareStop, Trash2 } from "lucide-react";
import type { ReactNode } from "react";

import { startRule, stopRule } from "../controller";
import { useForwardBoundPort, useForwardError, useForwardStatus } from "../runtime";
import { localPortLabel, stopNote, type ForwardRuleRow } from "./derive";

export type RuleCardProps = {
  row: ForwardRuleRow;
  /** Open the editor for this rule. Required, the same reason
   *  `IdentityCardProps.onEdit` (`vault/page/IdentityCard.tsx:47-50`) is: no
   *  surface lists these rows without being able to edit one. */
  onEdit: () => void;
  /**
   * Ask the page to confirm a delete. Takes `running` rather than nothing,
   * because the page's confirm dialog needs it for `deleteNote`
   * (`../page/derive.ts`) and this card is the only place that already holds
   * it - through its own `useForwardStatus` selector, not a second lookup the
   * page would have to make.
   */
  onDelete: (running: boolean) => void;
};

/** What the status dot renders as, sharing `ssh/status.ts`'s tone vocabulary
 *  (`bg-icon-working` amber-pulse / `bg-icon-idle` green / `bg-icon-blocked`
 *  red) so "in progress / good / bad" reads the same colour everywhere this
 *  app shows a connection state - "stopped" is the one status that vocabulary
 *  has no tone for, because it is not a hop's outcome, it is the rule simply
 *  not running, so it gets the neutral dot instead of borrowing one of the
 *  other three. */
function statusDotClass(status: ReturnType<typeof useForwardStatus>): string {
  switch (status) {
    case "starting":
      return "bg-icon-working animate-pulse";
    case "running":
      return "bg-icon-idle";
    case "failed":
      return "bg-icon-blocked";
    case "stopped":
      return "bg-muted-foreground/40";
  }
}

function statusText(status: ReturnType<typeof useForwardStatus>): string {
  switch (status) {
    case "starting":
      return "Starting…";
    case "running":
      return "Running";
    case "failed":
      return "Failed";
    case "stopped":
      return "Stopped";
  }
}

export function RuleCard({ row, onEdit, onDelete }: RuleCardProps): ReactNode {
  const { rule } = row;
  const status = useForwardStatus(rule.id);
  const boundPort = useForwardBoundPort(rule.id);
  const error = useForwardError(rule.id);

  const running = status === "running";
  const starting = status === "starting";
  const localLabel = localPortLabel(rule, boundPort);

  // A dangling row's host is gone, so there is no credential and no route left
  // to dial - Start is refused at the UI rather than left to fail at
  // `startRule`, and the reason rides the tooltip rather than a second toast.
  const startDisabled = row.hostDangling || starting;
  const toggleLabel = starting ? "Starting…" : running ? "Stop" : "Start";
  const toggleTooltip = row.hostDangling
    ? `${row.hostName} no longer exists. Edit this rule to pick another host before starting it.`
    : running
      ? stopNote()
      : toggleLabel;

  return (
    <div
      role="group"
      aria-label={`${rule.name}, forward rule`}
      className={cn(
        "group border-border hover:bg-muted/30 flex flex-col gap-2 rounded-lg border p-3 text-left transition-colors",
        // Same reasoning as `HostCard.tsx`/`IdentityCard.tsx`: content-visibility
        // skips layout and paint for an off-screen row (search-first keeps the
        // steady-state DOM small, this covers the unfiltered case), and WITHOUT
        // contain-intrinsic-size an off-screen row lays out at 0px and the
        // scrollbar jumps while the user scrolls. The pair is load-bearing;
        // neither half works alone. This is the fourth root that carries it.
        "[contain-intrinsic-size:auto_100px] [content-visibility:auto]",
      )}
    >
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <span
          className={cn("size-2 shrink-0 rounded-full", statusDotClass(status))}
          aria-hidden="true"
        />
        <span className="min-w-0 flex-1 truncate text-sm font-medium">{rule.name}</span>
        {row.hostDangling && (
          <Badge variant="destructive" className="shrink-0">
            <CircleAlert size={11} strokeWidth={2} />
            Host missing
          </Badge>
        )}
        <span className="text-muted-foreground shrink-0 text-xs tabular-nums">{localLabel}</span>
      </div>

      <div className="text-muted-foreground truncate text-xs">{row.route}</div>

      {/* The row's own status line - `useForwardError` for a failed bind, or
          `stopNote()` for a running one, never a third error surface of its
          own (VLT-36 is untouched by this wave: failures already reach
          `toast()` through `startRule`/`stopRule` themselves). */}
      {error ? (
        <div className="text-destructive text-xs">{error}</div>
      ) : running ? (
        <div className="text-muted-foreground text-[11px] leading-relaxed opacity-70">
          {stopNote()}
        </div>
      ) : null}

      <div className="flex min-h-6 flex-wrap items-center justify-between gap-x-2 gap-y-1">
        <span className="text-muted-foreground text-xs">{statusText(status)}</span>
        <div className="flex shrink-0 items-center gap-1">
          <IconTooltip label={toggleTooltip}>
            <span>
              <Button
                type="button"
                variant={running ? "outline" : "default"}
                size="sm"
                className="gap-1.5"
                disabled={startDisabled}
                aria-label={`${toggleLabel} ${rule.name}`}
                onClick={() => {
                  if (running) void stopRule(rule);
                  else void startRule(rule);
                }}
              >
                {starting ? (
                  <Spinner className="size-3.5" />
                ) : running ? (
                  <SquareStop size={13} strokeWidth={2} />
                ) : (
                  <Play size={13} strokeWidth={2} />
                )}
                {toggleLabel}
              </Button>
            </span>
          </IconTooltip>
          <div
            className="flex items-center gap-0.5 opacity-0 transition-opacity group-focus-within:opacity-100 group-hover:opacity-100"
            onClick={(e) => e.stopPropagation()}
          >
            <IconTooltip label="Edit">
              <Button
                type="button"
                variant="ghost"
                size="icon-xs"
                aria-label={`Edit ${rule.name}`}
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
                aria-label={`Delete ${rule.name}`}
                onClick={() => onDelete(running)}
                className={DESTRUCTIVE_ACTION}
              >
                <Trash2 size={12} strokeWidth={1.75} />
              </Button>
            </IconTooltip>
          </div>
        </div>
      </div>
    </div>
  );
}
