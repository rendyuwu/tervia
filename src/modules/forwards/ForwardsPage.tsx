/**
 * The Port Forwarding page: a header with its own search box, then one list
 * of saved forward rules (mirrors `modules/vault/VaultPage.tsx` in shape and
 * purpose, down to the caret claim and the delete-confirmation pattern - see
 * that file's header for the fuller reasoning behind both).
 *
 * A RAIL VIEW, not a pane leaf. `app/components/WorkspaceArea.tsx:142-150`
 * mounts this only while the rail's Port Forwarding button is pressed and
 * unmounts it on the way out - there is no `onScreen` prop to take (mount IS
 * the transition), and the caret claim's effect below is therefore keyed on
 * `[]`, exactly as `VaultPage.tsx:120-135` is and for the same reason.
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

import { RuleEditorDialog, type RuleEditorTarget } from "./editor/RuleEditorDialog";
import { RuleCard } from "./page/RuleCard";
import { deleteNote, rankRules, ruleRows } from "./page/derive";
import { deleteRule } from "./store";
import { useForwards } from "./useForwards";

/**
 * Which delete is awaiting confirmation. `id` and `name` are carried
 * alongside the two `deleteNote` inputs for the same reason
 * `VaultPage.tsx`'s `PendingDelete` carries its own record fields: the
 * confirm dialog's title needs `name`, and the record may be gone from the
 * store by the time either renders, so nothing here is looked up a second
 * time. `running` is captured from `RuleCard`'s own `useForwardStatus`
 * selector, at the moment the row's Delete button was clicked - this page
 * never reads runtime status itself (§1.6: the card is the one place that
 * needs it, and it already has it).
 */
type PendingDelete = { id: string; name: string; running: boolean; startWithHost: boolean };

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
    // `deleteRule` refuses nothing (`store.ts`'s own comment on the export)
    // - nothing references a rule the way a host references an identity -
    // but the write can still fail (an I/O error, a torn store), so this
    // still routes a rejection to `toast()` rather than dropping it.
    void deleteRule(target.id).catch((e: unknown) =>
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
          <div className="flex flex-col gap-2">
            {visibleRules.map((row) => (
              <RuleCard
                key={row.rule.id}
                row={row}
                onEdit={() => setEditorTarget({ mode: "edit", ruleId: row.rule.id })}
                onDelete={(running) =>
                  setPendingDelete({
                    id: row.rule.id,
                    name: row.rule.name,
                    running,
                    startWithHost: row.rule.startWithHost,
                  })
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
            <AlertDialogTitle>Delete rule &quot;{shownDelete?.name}&quot;?</AlertDialogTitle>
            <AlertDialogDescription>
              {shownDelete ? deleteNote(shownDelete) : null} This cannot be undone.
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
