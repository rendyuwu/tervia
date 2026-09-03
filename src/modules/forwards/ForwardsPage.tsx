/**
 * The Port Forwarding page: a header with its own search box, then one card
 * grid of saved forward rules (mirrors `modules/vault/VaultPage.tsx` in shape
 * and purpose, down to the caret claim, the delete-confirmation pattern and
 * the grid literal itself - see that file's header for the fuller reasoning
 * behind the first two, and the grid's own comment below for the third).
 *
 * A RAIL VIEW, not a pane leaf. `app/components/WorkspaceArea.tsx:160-238`'s
 * `railView !== null` branch mounts this only while the rail's Port Forwarding
 * button is pressed and unmounts it on the way out - there is no `onScreen`
 * prop to take (mount IS the transition), and the caret claim's effect below
 * is keyed on `[]`, as `VaultPage.tsx:120-135` is and for the same reason.
 *
 * Everything it draws lives somewhere else: `RuleCard` is its own component
 * and reads its own live status (`../runtime`), and every derived value that
 * is NOT live status comes from `page/derive.ts` as a pure function over
 * plain data. What is left here is the wiring and the two bits of state a
 * shell has - the query, and which delete is awaiting confirmation.
 *
 * One editor dialog is mounted here, one instance for the whole page: both
 * the New rule button and every row's own Edit button set the same
 * `editorTarget` state this file owns, and the dialog itself owns its own
 * load and its own save - the same one-instance pattern `VaultPage.tsx`'s
 * last header paragraph explains for its two editors.
 */
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { InputGroup, InputGroupAddon, InputGroupInput } from "@/components/ui/input-group";
import { toast } from "@/components/ui/toast";
import { paneCaret } from "@/lib/paneCaret";
import { useHosts } from "@/modules/hosts/useHosts";
import { Plus, Search, X } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";

import { pageMustStopFirst, stopRule } from "./controller";
import { RuleEditorDialog, type RuleEditorTarget } from "./editor/RuleEditorDialog";
import { RuleCard } from "./page/RuleCard";
import { deleteNote, rankRules, ruleRows } from "./page/derive";
import { deleteRule } from "./store";
import type { ForwardRule } from "./types";
import { useForwards } from "./useForwards";

/**
 * Which delete is awaiting confirmation. The WHOLE `ForwardRule` is carried
 * alongside the two runtime flags, for the same reason `VaultPage.tsx`'s
 * `PendingDelete` carries its own record fields: the confirm dialog's title
 * needs the name, and the record may be gone from the store by the time
 * either renders, so nothing here is looked up a second time.
 *
 * THE WHOLE RECORD AND NOT JUST `id`/`name`, because `confirmDelete` below
 * has to be able to STOP a page-running rule before deleting it, and
 * `stopRule` needs the host and both endpoints to name the entry it is
 * releasing (`controller.ts`'s note on `closeForwardForConnection`'s
 * arguments). A rule looked up again at confirm time is exactly the record
 * that may already be gone.
 *
 * `pageStops` and `hostOwned` are captured from `RuleCard`'s own
 * `useForwardStatus` and `useIsHostOwned` selectors, at the moment the row's
 * Delete button was clicked. `pageStops` is `running || starting`, not
 * `running` - `RuleCard`'s own note on that binding says why, and
 * `DeleteNoteSubject.pageStops` carries the full reasoning.
 *
 * BOTH ARE FOR `deleteNote` AND FOR NOTHING ELSE, and the next reader should
 * not "fix" that to match `confirmDelete` below. The dialog's sentence is a
 * claim about what the user was TOLD when they opened it, so captured is what
 * makes it correct; the DECISION to stop the forward is a claim about now, so
 * `confirmDelete` re-reads both owners live through `pageMustStopFirst`
 * (`./controller`) instead of trusting either field. The page still reads
 * neither store during a RENDER (§1.6: the card is the one place that needs
 * them, and it already has them) - that live read is inside an event handler
 * and goes through `getState()`, the idiom `controller.ts` and `runtime.ts`
 * both spell out.
 *
 * SEPARATE, BUT NOT FREE TO DISAGREE ABOUT WHICH STATUSES COUNT. Captured and
 * live answer about different MOMENTS, which is the split; they answer the same
 * QUESTION, so `pageStops` and `pageMustStopFirst` name the same two statuses.
 * A `pageStops` that had stayed at `running` alone would have the dialog say
 * "Deleting it changes nothing else." while the confirm below closed a bind.
 */
type PendingDelete = { rule: ForwardRule; pageStops: boolean; hostOwned: boolean };

export function ForwardsPage(): ReactNode {
  const forwardsById = useForwards();
  const hostsById = useHosts();

  const [query, setQuery] = useState("");
  const [pendingDelete, setPendingDelete] = useState<PendingDelete | null>(null);
  const [editorTarget, setEditorTarget] = useState<RuleEditorTarget | null>(null);

  const searchRef = useRef<HTMLInputElement>(null);
  const pageRef = useRef<HTMLDivElement>(null);

  // See `VaultPage.tsx:93-101` for why this is written at RENDER scope and
  // falsified only in the effect cleanup below.
  const onScreenRef = useRef(true);
  onScreenRef.current = true;

  // Caret claim, keyed on `[]` - see `VaultPage.tsx:103-135` for the full
  // reasoning this is adapted from: a rail view is unmounted, not hidden,
  // whenever it is not shown, so mount is the only on-screen transition
  // there is, and `pane: () => pageRef.current` (NOT
  // `closest("[data-pane-leaf]")`) is what that makes correct - a rail view
  // has no leaf frame above it, and asking for one would resolve `null` and
  // silently switch off the "the caret is already inside my own box" clause.
  useEffect(() => {
    paneCaret.claim(searchRef, {
      pane: () => pageRef.current,
      stillOnScreen: () => onScreenRef.current,
      take: () => searchRef.current?.focus(),
    });
    return () => {
      onScreenRef.current = false;
      paneCaret.release(searchRef);
    };
  }, []);

  // `ruleRows` and `rankRules` both return a FRESH array per call, so both
  // live in a memo and neither is ever called inside a store selector - see
  // `VaultPage.tsx:137-155` for the full reasoning (zustand v5 matches
  // `Object.is`, and a selector returning a fresh array re-subscribes
  // forever). `useForwards()` and `useHosts()` hand back references that are
  // stable BETWEEN renders, which is what stops the loop; `hostsById` is
  // handed to `ruleRows` directly (it looks hosts up by id, so it wants the
  // Map itself, unlike `identityRows`, which wants an array).
  const rules = useMemo(() => Array.from(forwardsById.values()), [forwardsById]);
  // Unfiltered, on purpose - the editor's SSH host picker must not follow
  // this page's search box, the same reason `VaultPage.tsx`'s `keyRowList`
  // prop is unfiltered for the identity editor's key picker.
  const hosts = useMemo(() => Array.from(hostsById.values()), [hostsById]);

  const ruleRowList = useMemo(() => ruleRows(rules, hostsById), [rules, hostsById]);
  const visibleRules = useMemo(() => rankRules(ruleRowList, query), [ruleRowList, query]);

  const confirmDelete = useCallback((target: PendingDelete) => {
    setPendingDelete(null);
    void (async () => {
      try {
        // STOPPED BEFORE IT IS DELETED, and this is what makes
        // `deleteNote`'s "deleting a running rule stops it" sentence TRUE
        // rather than a false promise in a destructive confirm. Deleting the
        // record alone leaves `runtime.ts`'s entry naming a rule no row
        // renders, so no Stop is ever offered again; `ssh/tunnel.ts`'s entry
        // keeps `refs: 1`, so the SSH session never closes for the rest of
        // the app's life; the local port stays bound, and re-creating a rule
        // on the same pinned port then fails EADDRINUSE with no in-app
        // recovery.
        //
        // GUARDED ON LIVE STATE AND NEVER ON `target.pageStops`, which is a
        // flag captured when the trash icon was clicked. The row is on
        // screen as `starting` for the whole dial and the Delete button is
        // not disabled during it (`page/RuleCard.tsx`'s `startDisabled`
        // gates the toggle only), so Start, Delete, dial-resolves, confirm
        // is the ORDINARY ordering rather than the unlucky one - and on it
        // the captured flag is about a moment that has passed.
        // `pageMustStopFirst` (`./controller`) is that read, both owners and
        // in the order every other site uses; its own doc carries the full
        // reasoning and the cost of getting it wrong.
        //
        // AND IT ANSWERS FOR A ROW STILL DIALLING, which is the other
        // ordering of the same two clicks: the confirm can land BEFORE the
        // dial resolves just as easily as after it, and a guard that only
        // said `running` let the record go while the bind was in flight -
        // `startAttempts` was never cleared, so the dial that landed
        // afterwards marked a deleted rule running and left the port bound.
        // Stopping a mid-dial rule is the same release path a Stop clicked
        // mid-dial takes: the attempt is superseded and hands its reference
        // straight back.
        //
        // Still guarded rather than unconditional, because the guard now
        // answers about NOW: a Stop for a rule that is genuinely not running
        // would be harmless (`controller.ts`: a Stop with no claim recorded
        // closes nothing and still marks the rule stopped) but it would also
        // be a Stop nobody asked for, and a terminal-owned rule's forward is
        // not this page's to stop at all - `deleteNote` says so instead of
        // promising otherwise.
        if (pageMustStopFirst(target.rule.id)) await stopRule(target.rule);
      } finally {
        // THE DELETE THE USER CONFIRMED HAPPENS EITHER WAY. A `stopRule`
        // that rejected must not swallow the delete - the user would be left
        // with the rule they asked to remove AND the forward they asked to
        // stop. Nothing reaches this today (`closeForwardForConnection`'s
        // chain ends in `.catch(() => {})` and `markStopped` is a
        // synchronous store write), which is exactly why it is a `finally`
        // rather than an argument about another module's ordering.
        //
        // `deleteRule` refuses nothing (`store.ts`'s own comment on the
        // export) - nothing references a rule the way a host references an
        // identity - but the write can still fail (an I/O error, a torn
        // store), so a rejection from either half lands on the one `toast()`
        // below rather than being dropped.
        await deleteRule(target.rule.id);
      }
    })().catch((e: unknown) =>
      toast(e instanceof Error ? e.message : String(e), { variant: "error" }),
    );
  }, []);

  const filtering = query.trim().length > 0;

  // Radix keeps `AlertDialogContent` mounted for its exit animation - see
  // `VaultPage.tsx:197-216` for the full reasoning this `lastDeleteRef` /
  // `shownDelete` pair is adapted from.
  const lastDeleteRef = useRef<PendingDelete | null>(null);
  if (pendingDelete) lastDeleteRef.current = pendingDelete;
  const shownDelete = pendingDelete ?? lastDeleteRef.current;

  return (
    <div ref={pageRef} className="bg-background @container flex h-full w-full min-w-0 flex-col">
      <div className="flex flex-col gap-2 border-b p-3">
        <div className="flex flex-wrap items-center gap-2">
          <Button
            size="sm"
            className="gap-1.5"
            aria-label="New rule"
            onClick={() => setEditorTarget({ mode: "create" })}
          >
            <Plus size={13} strokeWidth={2} />
            <span className="@max-[420px]:hidden">New rule</span>
          </Button>
          {/* Byte-identical to `VaultPage.tsx:269` / `HostsPage.tsx:401` -
              `hosts-header-narrow-verify.ts` asserts the equality. */}
          <InputGroup className="min-w-0 flex-1 @max-[420px]:min-w-40 @max-[420px]:basis-full @[480px]:min-w-40">
            <InputGroupAddon>
              <Search />
            </InputGroupAddon>
            <InputGroupInput
              ref={searchRef}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search forward rules…"
              aria-label="Search forward rules"
              spellCheck={false}
              autoComplete="off"
            />
            {query.length > 0 ? (
              <InputGroupAddon align="inline-end">
                <button
                  type="button"
                  aria-label="Clear search"
                  onClick={() => {
                    setQuery("");
                    searchRef.current?.focus();
                  }}
                  className="hover:text-foreground transition-colors"
                >
                  <X size={13} strokeWidth={2} />
                </button>
              </InputGroupAddon>
            ) : null}
          </InputGroup>
        </div>
      </div>

      {/* No transform and no fixed row height between here and a card:
          either one defeats the card's `content-visibility: auto`, which is
          what stands in for virtualization. */}
      <div className="min-h-0 flex-1 overflow-y-auto p-3">
        {visibleRules.length === 0 ? (
          <SectionEmpty
            filtering={filtering}
            hasAny={ruleRowList.length > 0}
            nothingYet="No saved forward rules yet."
            nothingYetHint="A forward rule binds a port on this machine and tunnels it to a machine the SSH host can reach."
            noMatch="No rules match."
          />
        ) : (
          // THE SAME GRID LITERAL `HostsPage.tsx:490` and `VaultPage.tsx`'s two
          // sections carry, byte for byte - see HostsPage's own comment there
          // for why the thresholds are `@[…]` container widths and not
          // `sm:`/`xl:` viewport ones, and why `@container` sits on the page
          // root above rather than here. This page listed one full-width row
          // per rule until now: three sibling surfaces showing records as a
          // card grid and this one showing them as a column was a difference
          // the user had to learn per page, not a difference about forwards.
          //
          // A NARROWER BREAKPOINT SET WAS THE TEMPTING COMPROMISE and it is
          // rejected: a rule's route is the longest string any of these four
          // card types renders, so stopping at two columns would have bought
          // that one line its room by giving up the parity this change is
          // for. Finding the room is `page/RuleCard.tsx`'s job instead, and
          // its header says where it found it.
          //
          // `vault-shell-verify.ts` section 16 pins this string across all
          // four sites, so a divergence is a red check rather than a page
          // that quietly drifts out of the set.
          <div className="grid grid-cols-1 gap-2 @[580px]:grid-cols-2 @[860px]:grid-cols-3 @[1140px]:grid-cols-4">
            {visibleRules.map((row) => (
              <RuleCard
                key={row.rule.id}
                row={row}
                onEdit={() => setEditorTarget({ mode: "edit", ruleId: row.rule.id })}
                onDelete={(pageStops, hostOwned) =>
                  setPendingDelete({ rule: row.rule, pageStops, hostOwned })
                }
              />
            ))}
          </div>
        )}
      </div>

      <RuleEditorDialog target={editorTarget} onClose={() => setEditorTarget(null)} hosts={hosts} />

      <AlertDialog
        open={pendingDelete !== null}
        onOpenChange={(open) => !open && setPendingDelete(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete rule &quot;{shownDelete?.rule.name}&quot;?</AlertDialogTitle>
            <AlertDialogDescription>
              {/* The three `deleteNote` inputs spelled out rather than
                  `deleteNote(shownDelete)`: `startWithHost` lives on the
                  captured RULE and the other two are the runtime flags the
                  row handed over, so one source of truth per field and no
                  copy of `startWithHost` kept beside the record it came
                  from. */}
              {shownDelete
                ? deleteNote({
                    pageStops: shownDelete.pageStops,
                    hostOwned: shownDelete.hostOwned,
                    startWithHost: shownDelete.rule.startWithHost,
                  })
                : null}{" "}
              This cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              onClick={() => {
                if (pendingDelete) confirmDelete(pendingDelete);
              }}
            >
              Delete rule
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

/** Nothing to show, said in whichever of the two ways is true - adapted from
 *  `VaultPage.tsx:458-483`; see that file for the full reasoning
 *  (`matching = hasAny && filtering`, VLT-72: `hasAny` is fed from the
 *  UNFILTERED row list, which is what makes a query against an empty store
 *  still say "No saved forward rules yet." rather than the lie "No rules
 *  match."). */
function SectionEmpty({
  filtering,
  hasAny,
  nothingYet,
  nothingYetHint,
  noMatch,
}: {
  filtering: boolean;
  hasAny: boolean;
  nothingYet: string;
  nothingYetHint: string;
  noMatch: string;
}): ReactNode {
  const matching = hasAny && filtering;
  return (
    <div className="text-muted-foreground flex flex-col gap-1 rounded-lg border border-dashed p-6 text-center">
      <span className="text-foreground text-sm font-medium">{matching ? noMatch : nothingYet}</span>
      <span className="mx-auto max-w-72 text-[11px] leading-relaxed opacity-70">
        {matching ? "Clear the search box to see everything." : nothingYetHint}
      </span>
    </div>
  );
}
