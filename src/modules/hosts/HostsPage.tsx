/**
 * The Hosts page: a header row, the group strip, then the host grid (research
 * §5.5).
 *
 * This file is assembly and page-level state. Everything it draws lives
 * somewhere else - the cards, the strip, the backup buttons and the editor are
 * each their own component, and every derived value comes from `page/derive.ts`
 * as a pure function over plain data. What is left here is the wiring and the
 * five bits of state a page has: the query, the two filters, which row is
 * selected, and which dialog is open.
 *
 * Two things it deliberately does NOT do. It never reads a secret to decide what
 * a card shows - the `has*` flags on the record are what the pips come from
 * (§5.2), because a hundred rows must not cost three keychain reads each. And it
 * does not open tabs: `onConnect` arrives as a prop because opening a tab needs
 * `setTabs` and `nextIdRef` from `useTabs`, which a pane leaf body cannot reach.
 *
 * Nothing here makes a secret safer. On Linux a private key sits in a mode-0600
 * JSON file before and after this work, and SSH still round-trips plaintext
 * through the webview on every connect. What a vault binding buys - and what the
 * identity pip on a card is telling you about - is FEWER COPIES of one secret.
 */
import { Button } from "@/components/ui/button";
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
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { InputGroup, InputGroupAddon, InputGroupInput } from "@/components/ui/input-group";
import { VaultInUseError } from "@/modules/vault/types";
import { useVault } from "@/modules/vault/useVault";
import { ChevronDown, Monitor, Plus, Search, SquareTerminal, X } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";

import { HostEditorDialog } from "./HostEditorDialog";
import { Chip, GroupStrip } from "./page/GroupStrip";
import { HostCard } from "./page/HostCard";
import { HostsBackupActions } from "./page/HostsBackupActions";
import {
  filterAndRank,
  groupCounts,
  identityName,
  missingSecret,
  searchRows,
  type GroupFilter,
  type ProtocolFilter,
} from "./page/derive";
import {
  clearHostEditorRequest,
  useHostEditorRequest,
  type HostEditorTarget,
} from "./pendingEditor";
import {
  deleteGroup,
  deleteHost,
  duplicateHost,
  newGroupId,
  noForwardRules,
  upsertGroup,
} from "./store";
import type { Host } from "./types";
import { useHostGroups, useHosts } from "./useHosts";

export type HostsPageProps = {
  /** Open a tab for this host. A prop rather than something the page reaches
   *  for: a leaf body cannot call `useTabs`, so the callback arrives from the
   *  pane instead. */
  onConnect: (host: Host) => void;
  /** Whether this page's tab is the one currently on screen. `PaneStack`
   *  keeps an inactive tab's leaves mounted but `visibility:hidden`, which a
   *  `.focus()` call cannot reach - so the search-input focus below has to
   *  re-fire on becoming visible, not just once at mount. */
  tabVisible: boolean;
};

// Module constants so their IDENTITY is stable. Both are `useMemo` dependencies
// below, and a filter object rebuilt per render would re-derive the whole visible
// list on every keystroke anywhere on the page.
const ALL_GROUPS: GroupFilter = { kind: "all" };
const UNGROUPED: GroupFilter = { kind: "ungrouped" };

const PROTOCOL_FILTERS: ReadonlyArray<{ value: ProtocolFilter; label: string }> = [
  { value: "all", label: "All" },
  { value: "ssh", label: "SSH" },
  { value: "rdp", label: "RDP" },
];

function errorText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/**
 * A refused delete, said in terms of what the user has to go and fix.
 *
 * `VaultInUseError` already carries a perfectly good message, and it is not the
 * one to show: it says "still used by 2 hosts", which reads as a tidiness
 * complaint. It is not. Research §5.2 - deleting this row would turn a machine
 * deliberately confined to a bastion into a direct dial, with a pinned
 * fingerprint that still matches and so nothing at all on screen to notice. So
 * the copy names the ROUTE and names the rows, because those are the rows that
 * would silently change.
 */
function deleteRefusalText(host: Host, e: unknown): string {
  if (!(e instanceof VaultInUseError)) return errorText(e);
  const names = e.holders.map((h) => h.name || h.id).join(", ");
  const one = e.holders.length === 1;
  return (
    `Cannot delete "${host.name}": ${e.holders.length} ${one ? "host" : "hosts"} still ` +
    `${one ? "routes" : "route"} through it (${names}). Clear the jump host or tunnel on ` +
    `${one ? "it" : "each of them"} first.`
  );
}

/**
 * What the confirm dialog says about the keychain, branched on whether this
 * row owns its own secrets.
 *
 * `secretFieldsFor` in `store.ts` returns `[]` for an `identity` binding, so
 * `deleteHost` deletes nothing from the keychain in that case - the shared
 * identity, and any other host bound to it, is untouched. Saying "removed
 * from the keychain too" regardless would read as a promise that a
 * shared-identity delete also wipes the credential, in the one direction
 * that matters: a user could believe it is gone when it is not.
 */
function deleteKeychainNote(host: Host): string {
  return host.credential.kind === "identity"
    ? "Its shared vault identity is not affected - other hosts bound to it keep working."
    : "Its saved credentials are removed from the keychain too.";
}

export function HostsPage({ onConnect, tabVisible }: HostsPageProps): ReactNode {
  const hostsById = useHosts();
  const groups = useHostGroups();
  const vault = useVault();

  const [query, setQuery] = useState("");
  const [protocol, setProtocol] = useState<ProtocolFilter>("all");
  const [group, setGroup] = useState<GroupFilter>(ALL_GROUPS);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [editorTarget, setEditorTarget] = useState<HostEditorTarget | null>(null);
  const [pendingDelete, setPendingDelete] = useState<Host | null>(null);
  /** The last refused or failed row action. Cleared by the next one. */
  const [actionError, setActionError] = useState<string | null>(null);

  const searchRef = useRef<HTMLInputElement>(null);
  // §5.5: search is the primary navigation at 100 hosts, so the page opens with
  // the caret already in it. That is also the first half of the no-virtualization
  // plan (§12.6): search-first keeps the steady-state DOM a filtered handful, and
  // the card's own `content-visibility` covers the unfiltered case.
  //
  // Keyed on `tabVisible`, not `[]`: `PaneStack` keeps a backgrounded tab's
  // leaves mounted (`visibility:hidden`), so a mount-only effect fires once,
  // while the tab is not even visible yet, and never again - a Hosts tab
  // restored into the background loses this focus for good. Re-running on
  // every true transition covers both the fresh-open case (already visible at
  // mount) and every later switch back to an already-mounted tab.
  useEffect(() => {
    if (tabVisible) searchRef.current?.focus();
  }, [tabVisible]);

  const hosts = useMemo(() => Array.from(hostsById.values()), [hostsById]);
  const knownGroupIds = useMemo(() => new Set(groups.map((g) => g.id)), [groups]);
  const rows = useMemo(() => searchRows(hosts, groups, vault), [hosts, groups, vault]);
  const counts = useMemo(() => groupCounts(hosts, groups), [hosts, groups]);
  const visible = useMemo(
    () => filterAndRank({ rows, protocol, group, knownGroupIds, query }),
    [rows, protocol, group, knownGroupIds, query],
  );

  // A group deleted in another window (or by the strip below) leaves the filter
  // naming an id nothing has, which shows an empty grid with no way back to it -
  // the chip that would clear the filter is gone too.
  useEffect(() => {
    if (group.kind === "group" && !knownGroupIds.has(group.groupId)) setGroup(ALL_GROUPS);
  }, [group, knownGroupIds]);

  // The header's quick-connect opens the Hosts tab and then asks for the editor,
  // so the request may predate this mount - see `pendingEditor.ts`.
  const requested = useHostEditorRequest();
  useEffect(() => {
    if (requested) setEditorTarget(requested);
  }, [requested]);

  // Closing the Hosts TAB (Ctrl+W) unmounts this page directly - there is no
  // dialog `onClose` in that path, so `closeEditor` below never runs and the
  // pending request stays set. Reopening Hosts later remounts this component,
  // re-reads that same stale request through the effect above, and pops the
  // editor back open with whatever it was prefilled with. This is the other
  // place the request has to be cleared, not a duplicate of `closeEditor`.
  useEffect(() => {
    return () => clearHostEditorRequest();
  }, []);

  const closeEditor = useCallback(() => {
    setEditorTarget(null);
    // The request is sticky: leaving it set means the effect above reopens the
    // dialog the user just closed, forever.
    clearHostEditorRequest();
  }, []);

  const duplicate = useCallback((host: Host) => {
    setActionError(null);
    void duplicateHost(host.id)
      .then((copy) => {
        // `null` is not a failure - the row was deleted between this render and
        // the click, in this window or another. Still worth saying, because a
        // click that produces no new card and no message looks swallowed.
        if (!copy) setActionError(`"${host.name}" no longer exists, so there was nothing to copy.`);
      })
      // `duplicateHost` returns THROUGH `upsertHost`, whose guards refuse rather
      // than ignore (handoff §5.11). A call site handling only `null` gets an
      // unhandled rejection.
      .catch((e: unknown) => setActionError(errorText(e)));
  }, []);

  const confirmDelete = useCallback((host: Host) => {
    setPendingDelete(null);
    setActionError(null);
    // `noForwardRules` is passed by NAME, never as an inline `() => {}`, so 6f
    // finds every call site with one grep when `modules/forwards` lands.
    void deleteHost(host.id, noForwardRules).catch((e: unknown) =>
      setActionError(deleteRefusalText(host, e)),
    );
  }, []);

  const createGroup = useCallback(async (name: string): Promise<void> => {
    await upsertGroup({ id: newGroupId(), name });
  }, []);

  const renameGroup = useCallback(
    async (id: string, name: string): Promise<void> => {
      const existing = groups.find((g) => g.id === id);
      if (!existing) return;
      // Spread, so `order` survives a rename.
      await upsertGroup({ ...existing, name });
    },
    [groups],
  );

  const removeGroup = useCallback(async (id: string): Promise<void> => {
    await deleteGroup(id);
  }, []);

  const filtering = query.trim().length > 0 || protocol !== "all" || group.kind !== "all";

  return (
    // `@container`: this page renders inside an independently resizable pane
    // (the sidebar split, at minimum window width, can leave it well under
    // 100px), not the viewport - so the header row and the grid below both
    // size off THIS box, not `sm:`/`xl:` viewport breakpoints. See the header
    // row and grid comments below for what that buys each of them.
    <div className="bg-background @container flex h-full w-full min-w-0 flex-col">
      <div className="flex flex-col gap-2 border-b p-3">
        {/* Every control below either has no hard-minimum floor, or collapses
            past one on its own `@container` threshold, and the protocol group
            wraps internally - so no single item here can be wider than the
            box `flex-wrap` is trying to fit it into. `HostsBackupActions`'
            two labelled buttons are the one exception this page cannot fix
            from the outside (its own file, not wrapped/collapsible here); the
            `overflow-x-auto` wrapper below contains THAT overflow to its own
            strip instead of dragging the whole pane into a horizontal
            scrollbar. */}
        <div className="flex flex-wrap items-center gap-2">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button size="sm" className="gap-1.5" aria-label="New host">
                <Plus size={13} strokeWidth={2} />
                <span className="@max-[420px]:hidden">New host</span>
                <ChevronDown size={13} strokeWidth={2} className="opacity-70 @max-[420px]:hidden" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="start">
              <DropdownMenuItem
                onSelect={() => setEditorTarget({ mode: "create", protocol: "ssh" })}
              >
                <SquareTerminal size={14} strokeWidth={1.75} />
                SSH host
              </DropdownMenuItem>
              <DropdownMenuItem
                onSelect={() => setEditorTarget({ mode: "create", protocol: "rdp" })}
              >
                <Monitor size={14} strokeWidth={1.75} />
                RDP host
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>

          {/* `flex-wrap` + `min-w-0`: three chips read ~134px on one line with
              no room to shrink (buttons don't shrink below their text), which
              is wider than this page's box can go. Wrapping them onto their
              own line(s) bounds this group by its WIDEST SINGLE chip
              (~45px), not their sum - `Chip` is GroupStrip's, reused rather
              than re-typed here (see the P2 note there). */}
          <div
            className="flex min-w-0 flex-wrap items-center gap-1.5"
            role="group"
            aria-label="Protocol"
          >
            {PROTOCOL_FILTERS.map((option) => (
              <Chip
                key={option.value}
                label={option.label}
                selected={protocol === option.value}
                onClick={() => setProtocol(option.value)}
              />
            ))}
          </div>

          {/* No unconditional floor: `min-w-40` was a 160px minimum this box
              cannot always afford. `min-w-0` lets it shrink to whatever
              `flex-1` leaves it (still typeable at any width), and the
              160px comfort floor comes back only once the box has room to
              spare for it. */}
          <InputGroup className="min-w-0 flex-1 @[480px]:min-w-40">
            <InputGroupAddon>
              <Search />
            </InputGroupAddon>
            <InputGroupInput
              ref={searchRef}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search hosts…"
              aria-label="Search hosts"
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

          {/* `min-w-0` lets this shrink below its content's width (a plain
              flex child otherwise floors at its min-content size); `overflow-
              x-auto` is what a shrunk-past-content box then does with the
              overflow - scrolls it locally instead of forcing this DIV wider,
              which is what was dragging the whole pane's scrollbar out with
              it. `HostsBackupActions` owns its own two buttons and neither
              shrinks nor wraps them - out of this page's reach - so this is
              the fix available from outside that file. */}
          <div className="min-w-0 overflow-x-auto">
            <HostsBackupActions />
          </div>
        </div>

        {/* Above the scroll container on purpose: a refused delete names rows the
            user now has to go and find, and a message that scrolls out of the
            grid is a message they will not see. */}
        {actionError ? (
          <div className="text-destructive flex items-start gap-2 text-[11px]">
            <span className="flex-1">{actionError}</span>
            <button
              type="button"
              aria-label="Dismiss"
              onClick={() => setActionError(null)}
              className="shrink-0 opacity-70 hover:opacity-100"
            >
              <X size={12} strokeWidth={2} />
            </button>
          </div>
        ) : null}

        <GroupStrip
          groups={groups}
          counts={counts}
          selectedGroupId={group.kind === "group" ? group.groupId : null}
          ungroupedSelected={group.kind === "ungrouped"}
          onSelectAll={() => setGroup(ALL_GROUPS)}
          onSelectUngrouped={() => setGroup(UNGROUPED)}
          onSelectGroup={(groupId) => setGroup({ kind: "group", groupId })}
          onCreateGroup={createGroup}
          onRenameGroup={renameGroup}
          onDeleteGroup={removeGroup}
        />
      </div>

      {/* No transform and no fixed row height anywhere between here and the
          card: either one defeats the card's `content-visibility: auto`, which is
          the only thing standing in for virtualization (§12.6). */}
      <div className="min-h-0 flex-1 overflow-y-auto p-3">
        {visible.length === 0 ? (
          <EmptyState filtering={filtering} hasHosts={hosts.length > 0} />
        ) : (
          // `@[…]` container thresholds, not `sm:`/`xl:`/`2xl:` viewport ones -
          // this grid's width comes from the sidebar drag and the pane split,
          // not the window, so a wide window with a narrow pane used to render
          // 3-4 columns at a few dozen px each (PaneTreeView.tsx:694 and
          // ExplorerGrep.tsx:356 already do the same for the same reason).
          // Thresholds are `columns * ~280px card + gaps`, not a copy of the
          // old viewport numbers - those measured the wrong box. Applying
          // `@container` on the page root above, not here, is what makes these
          // resolve against the pane's own width rather than needing a second
          // container ancestor of their own; it does not add containment to
          // `HostCard` itself, so its own `content-visibility: auto` /
          // `contain-intrinsic-size` (HostCard.tsx) are untouched.
          <div className="grid grid-cols-1 gap-2 @[580px]:grid-cols-2 @[860px]:grid-cols-3 @[1140px]:grid-cols-4">
            {visible.map(({ host, groupName }) => (
              <HostCard
                key={host.id}
                host={host}
                identityName={identityName(host, vault.identities)}
                groupName={groupName}
                missingSecret={missingSecret(host, vault)}
                selected={host.id === selectedId}
                onSelect={() => setSelectedId(host.id)}
                onConnect={() => onConnect(host)}
                onEdit={() => setEditorTarget({ mode: "edit", hostId: host.id })}
                onDuplicate={() => duplicate(host)}
                onDelete={() => setPendingDelete(host)}
              />
            ))}
          </div>
        )}
      </div>

      <HostEditorDialog
        target={editorTarget}
        onClose={closeEditor}
        // Selected but not un-filtered: if the saved row is hidden, it is hidden
        // by a query the user typed, and clearing it out from under them is worse
        // than the row not being on screen.
        onSaved={(host) => setSelectedId(host.id)}
      />

      <AlertDialog
        open={pendingDelete !== null}
        onOpenChange={(open) => !open && setPendingDelete(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete host &quot;{pendingDelete?.name}&quot;?</AlertDialogTitle>
            <AlertDialogDescription>
              {pendingDelete ? deleteKeychainNote(pendingDelete) : null} This cannot be undone.
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
              Delete host
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

/** Nothing to show, said in whichever of the two ways is true - "add one" and
 *  "your filters exclude everything" need different next steps. */
function EmptyState({ filtering, hasHosts }: { filtering: boolean; hasHosts: boolean }): ReactNode {
  return (
    <div className="text-muted-foreground flex h-full flex-col items-center justify-center gap-2 p-6 text-center">
      <span className="text-foreground text-sm font-medium">
        {hasHosts ? "No hosts match" : "No saved hosts yet"}
      </span>
      <span className="max-w-72 text-[11px] leading-relaxed opacity-70">
        {hasHosts && filtering
          ? "Clear the search box or widen the protocol and group filters."
          : "Use New host to save an SSH or RDP machine, or Import to bring one over."}
      </span>
    </div>
  );
}
