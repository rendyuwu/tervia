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
import { cn } from "@/lib/utils";
import { VaultInUseError } from "@/modules/vault/types";
import { useVault } from "@/modules/vault/useVault";
import { ChevronDown, Monitor, Plus, Search, SquareTerminal, X } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";

import { HostEditorDialog } from "./HostEditorDialog";
import { GroupStrip } from "./page/GroupStrip";
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

export function HostsPage({ onConnect }: HostsPageProps): ReactNode {
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
  useEffect(() => {
    searchRef.current?.focus();
  }, []);

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
    <div className="bg-background flex h-full w-full min-w-0 flex-col">
      <div className="flex flex-col gap-2 border-b p-3">
        <div className="flex flex-wrap items-center gap-2">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button size="sm" className="gap-1.5">
                <Plus size={13} strokeWidth={2} />
                New host
                <ChevronDown size={13} strokeWidth={2} className="opacity-70" />
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

          <div className="flex items-center gap-1.5" role="group" aria-label="Protocol">
            {PROTOCOL_FILTERS.map((option) => (
              <button
                key={option.value}
                type="button"
                aria-pressed={protocol === option.value}
                onClick={() => setProtocol(option.value)}
                // Deliberately the group strip's chip vocabulary rather than a
                // second one: the two rows sit against each other and both mean
                // "narrow the grid", so they should not look like different kinds
                // of control.
                className={cn(
                  "rounded-full border px-2.5 py-1 text-xs font-medium transition-colors",
                  protocol === option.value
                    ? "bg-accent text-accent-foreground border-transparent"
                    : "border-border text-muted-foreground hover:bg-muted/50",
                )}
              >
                {option.label}
              </button>
            ))}
          </div>

          <InputGroup className="min-w-40 flex-1 basis-40">
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

          <HostsBackupActions />
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
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4">
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
              Its saved credentials are removed from the keychain too. This cannot be undone.
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
