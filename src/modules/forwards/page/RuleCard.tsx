/**
 * One forward rule in the Port Forwarding page list. Pure presentation for
 * everything EXCEPT Start/Stop: `HostCard.tsx` and `IdentityCard.tsx` both
 * take every value as a prop and own only the rendering, but this row is
 * also the ONE place `startRule`/`stopRule` (`../controller`, step 9) are
 * called from a component - the page hands over `row` and two callbacks for
 * Edit and Delete, and this file reads the rule's live status for itself
 * through the three primitive selectors `../runtime` exports plus the two
 * `../hostOwned` exports (§1.6: one selector per primitive, never one object
 * selector).
 *
 * TWO OWNERS, ONE ROW. A rule started from this page lives in `../runtime`; a
 * rule the terminal started for itself lives in `../hostOwned` and is
 * READ-ONLY here - shown as "Running (with host)" with Start/Stop disabled,
 * because its lifetime belongs to the tab that opened it. The two maps are
 * mutually exclusive by construction (`../hostOwned.ts`'s header), so this
 * file never has to reconcile them, only render whichever one has the rule.
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
import { useHostOwnedPort, useIsHostOwned } from "../hostOwned";
import { useForwardBoundPort, useForwardError, useForwardStatus } from "../runtime";
import { localPortLabel, stopNote, type ForwardRuleRow } from "./derive";

/** What the Start/Stop button says about a forward this page did not start and
 *  cannot stop - the terminal that opened it owns it, and it dies with that
 *  tab. See `../hostOwned.ts`: a Stop here would spend a reference nobody on
 *  this page ever took. */
const HOST_OWNED_NOTE = "Started with its terminal. Close that terminal tab to stop it.";

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
function statusDotClass(status: ReturnType<typeof useForwardStatus>, hostOwned: boolean): string {
  // A terminal-owned forward IS running, it is simply running somewhere this
  // store cannot see (`../hostOwned.ts`), so it gets the running tone. Checked
  // ahead of `status`, which for such a rule reads "stopped" - the page's
  // runtime store never hears about a forward the terminal opened.
  if (hostOwned) return "bg-icon-idle";
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

function statusText(status: ReturnType<typeof useForwardStatus>, hostOwned: boolean): string {
  // Named as its own state rather than a bare "Running": the difference is
  // what the user can DO about it, and the disabled button below is only
  // legible next to a status line that says who owns the forward.
  if (hostOwned) return "Running (with host)";
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
  // The terminal's own map, read-only from here (`../hostOwned.ts`). Two more
  // primitive selectors beside the three above, per §1.6 - never one object
  // selector for the pair.
  const hostOwned = useIsHostOwned(rule.id);
  const hostOwnedPort = useHostOwnedPort(rule.id);

  // `running` stays the PAGE's notion of running - `onDelete(running)` below
  // feeds `deleteNote`, whose "deleting a running rule stops it" sentence is
  // true only of a rule this page can stop. A terminal-owned rule is stopped
  // there, and the dialog correctly says only that it will no longer start
  // automatically with its host.
  const running = status === "running";
  const starting = status === "starting";
  // The port that is ACTUALLY LISTENING, whichever owner bound it. The two are
  // mutually exclusive by construction (`../hostOwned.ts`), so this is a
  // two-way choice and not a precedence rule.
  const localLabel = localPortLabel(rule, hostOwnedPort ?? boundPort);

  // A dangling row's host is gone, so there is no credential and no route left
  // to dial - Start is refused at the UI rather than left to fail at
  // `startRule`, and the reason rides the tooltip rather than a second toast.
  // A terminal-owned rule is refused for the opposite reason: it is already up,
  // and stopping it is the terminal tab's to do.
  const startDisabled = row.hostDangling || starting || hostOwned;
  const toggleLabel = starting ? "Starting…" : running || hostOwned ? "Stop" : "Start";
  // `hostOwned` first: for a rule whose host record was deleted mid-session
  // both facts are true, and the one worth saying is why the live forward
  // cannot be stopped from here - the dangling note is advice about EDITING,
  // which the Edit button beside it still offers.
  const toggleTooltip = hostOwned
    ? HOST_OWNED_NOTE
    : row.hostDangling
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
          className={cn("size-2 shrink-0 rounded-full", statusDotClass(status, hostOwned))}
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
          `toast()` through `startRule`/`stopRule` themselves).

          `hostOwned` is checked FIRST and suppresses `error`: that error is
          this page's last failed Start, and a rule the terminal has since
          brought up is running whatever that attempt did. A red line under
          "Running (with host)" would be two contradictory answers about one
          rule. The note itself is shared with the button's tooltip, the same
          way `stopNote()` already is - one sentence, two places. */}
      {hostOwned ? (
        <div className="text-muted-foreground text-[11px] leading-relaxed opacity-70">
          {HOST_OWNED_NOTE}
        </div>
      ) : error ? (
        <div className="text-destructive text-xs">{error}</div>
      ) : running ? (
        <div className="text-muted-foreground text-[11px] leading-relaxed opacity-70">
          {stopNote()}
        </div>
      ) : null}

      <div className="flex min-h-6 flex-wrap items-center justify-between gap-x-2 gap-y-1">
        <span className="text-muted-foreground text-xs">{statusText(status, hostOwned)}</span>
        <div className="flex shrink-0 items-center gap-1">
          <IconTooltip label={toggleTooltip}>
            <span>
              <Button
                type="button"
                variant={running || hostOwned ? "outline" : "default"}
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
                ) : running || hostOwned ? (
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
