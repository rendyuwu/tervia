/**
 * The Vault page: a header with its own search box, then two sections -
 * Identities and Keys (research §5.6).
 *
 * A RAIL VIEW, not a pane leaf. `app/components/WorkspaceArea.tsx:142-150`
 * mounts this only while the rail's Vault button is pressed and unmounts it on
 * the way out, which is the opposite of a page leaf: `PaneStack` keeps a
 * background tab's leaves mounted behind `visibility:hidden`. Two consequences
 * run through this file, both marked where they land - there is no `onScreen`
 * prop to take (mount IS the transition), and the caret claim's effect is
 * therefore keyed on `[]`, which is exactly what `HostsPage.tsx:170-175` warns
 * against for a leaf.
 *
 * Everything it draws lives somewhere else: the two cards are their own
 * components, and every derived value comes from `page/derive.ts` as a pure
 * function over plain data. What is left here is the wiring and the two bits of
 * state a shell has - the query, and which delete is awaiting confirmation.
 *
 * It never reads a secret to decide what a row shows. The `has*` flags on the
 * records are what the pips come from (research §5.2), and nothing here
 * protects a secret better than it was protected before: on Linux a private
 * key sits in a mode-0600 plaintext file before and after this work. What a
 * shared identity buys is FEWER COPIES of one secret.
 *
 * The two editor dialogs are mounted here, one instance of each for the whole
 * page: every affordance that opens one - both New buttons and both cards'
 * Edit button - sets the same `identityTarget`/`keyTarget` state this file
 * owns, and the dialog itself owns its own load and its own save. Wave 4 adds
 * convert-to-vault and the identity picker that binds a host to one of these
 * records.
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
import { identityHostRefs } from "@/modules/hosts/store";
import { useHosts } from "@/modules/hosts/useHosts";
import { KeyRound, Plus, Search, X } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";

import { IdentityEditorDialog, type IdentityEditorTarget } from "./editor/IdentityEditorDialog";
import { KeyEditorDialog, type KeyEditorTarget } from "./editor/KeyEditorDialog";
import { IdentityCard } from "./page/IdentityCard";
import { KeyCard } from "./page/KeyCard";
import {
  deleteNote,
  deleteRefusalText,
  identityRows,
  keyRows,
  rankIdentities,
  rankKeys,
} from "./page/derive";
import { deleteIdentity, deleteKey } from "./store";
import type { VaultAuthMode } from "./types";
import { useVault } from "./useVault";

/**
 * Which delete is awaiting confirmation. `id` and `name` are carried
 * alongside `kind` because the refusal message and the dialog title both need
 * them, and the record may be gone from the store by the time either renders.
 * `hasPassword`/`authMode` (identity) and `hasPassphrase` (key) are carried
 * for the same reason, one level down: `deleteNote` (`page/derive.ts`)
 * decides what the description honestly says from these fields, and it must
 * decide from the values captured AT THE MOMENT the delete was requested, not
 * from a second lookup into a store the record may have already left.
 */
type PendingDelete =
  | { kind: "identity"; id: string; name: string; hasPassword: boolean; authMode: VaultAuthMode }
  | { kind: "key"; id: string; name: string; hasPassphrase: boolean };

export function VaultPage(): ReactNode {
  const vault = useVault();
  const hostsById = useHosts();

  const [query, setQuery] = useState("");
  const [pendingDelete, setPendingDelete] = useState<PendingDelete | null>(null);
  const [identityTarget, setIdentityTarget] = useState<IdentityEditorTarget | null>(null);
  const [keyTarget, setKeyTarget] = useState<KeyEditorTarget | null>(null);

  const searchRef = useRef<HTMLInputElement>(null);
  const pageRef = useRef<HTMLDivElement>(null);

  // "Still on screen" for a rail view means "still mounted", because
  // `WorkspaceArea.tsx:142` renders this only while the Vault view is the one
  // showing. Written at RENDER scope and falsified in the effect cleanup below,
  // so the claim - which is decided one animation frame after it is made - can
  // never act on a world that has already moved. A closure over a value, or a
  // literal `() => true`, is the stale-claim half of VLT-39 written a different
  // way.
  const onScreenRef = useRef(true);
  onScreenRef.current = true;

  // The page opens with the caret already in the search box, because search is
  // the primary navigation here exactly as it is on the Hosts page.
  //
  // It CLAIMS the caret rather than taking it. A pane (or a view) that focuses
  // itself on a visibility transition loses: the gesture that caused the
  // transition runs its own default action afterwards and focuses whatever was
  // clicked, over the top of anything set during the commit.
  // `@/lib/paneCaret` has the measured sequence and hands the caret over one
  // frame later, once that is done - and it stands down if an overlay holds the
  // caret, or if the caret is already inside this view.
  //
  // Keyed on `[]`, and that is the OPPOSITE of `HostsPage.tsx:198`'s
  // `[onScreen]` for a reason that is worth reading twice before "fixing" it: a
  // page LEAF stays mounted while its tab is in the background, so a mount-only
  // effect there fires once while invisible and never again. This is a rail
  // view - it is not mounted at all when it is not shown, so mount is the only
  // on-screen transition there is, and there is no prop that could carry one.
  useEffect(() => {
    paneCaret.claim(searchRef, {
      // The page root, NOT `closest("[data-pane-leaf]")`: a rail view is
      // rendered outside `PaneStack` and has no leaf frame above it, so asking
      // for one would resolve `null` and switch off the "the caret is already
      // in my own box" clause - which is what stops this yanking the caret out
      // of something the user just clicked in here.
      pane: () => pageRef.current,
      stillOnScreen: () => onScreenRef.current,
      take: () => searchRef.current?.focus(),
    });
    return () => {
      onScreenRef.current = false;
      paneCaret.release(searchRef);
    };
  }, []);

  // The row builders return a FRESH array per call - they end in `.map`. They
  // must therefore be called in a memo and never inside a store selector:
  // zustand v5 dropped the equality-function overload and matches React's
  // `Object.is`, so a selector building a fresh array re-subscribes forever and
  // throws "Maximum update depth exceeded". `useVault()` and `useHosts()` hand
  // back references that are stable BETWEEN RENDERS - straight out of
  // `useState`, not rebuilt by a render this component did not cause - and
  // that is what stops the loop. They are NOT stable across a BROADCAST:
  // `useHosts.ts:19` and `useVault.ts:38,54` each build a fresh `Map` on every
  // `onHostsChanged`/`onVaultChanged`, identical data or not, so this page
  // re-derives every row on every store change, not only a change that
  // actually touches what it shows - free at this scale, worth knowing the
  // day it is not.
  //
  // The two `[...map.values()]` spreads live HERE, inside the memos, for the
  // same reason: the row builders take arrays for the collections they iterate
  // and a Map for the one they look up by id, and spreading at the call site
  // inside a memo costs nothing. Spreading inside a selector is the mistake
  // this comment exists to prevent.
  const hosts = useMemo(() => Array.from(hostsById.values()), [hostsById]);
  const identities = useMemo(() => Array.from(vault.identities.values()), [vault.identities]);
  const keys = useMemo(() => Array.from(vault.keys.values()), [vault.keys]);

  const identityRowList = useMemo(
    () => identityRows(identities, vault.keys, hosts),
    [identities, vault.keys, hosts],
  );
  const keyRowList = useMemo(() => keyRows(keys, identities), [keys, identities]);

  const visibleIdentities = useMemo(
    () => rankIdentities(identityRowList, query),
    [identityRowList, query],
  );
  const visibleKeys = useMemo(() => rankKeys(keyRowList, query), [keyRowList, query]);

  const confirmDelete = useCallback((target: PendingDelete) => {
    setPendingDelete(null);
    // `identityHostRefs` is passed by NAME, never as an inline closure, so the
    // one place that answers "which hosts bind this identity" stays greppable -
    // and it is the store's REQUIRED parameter precisely so no caller can skip
    // the guard by omitting it. A key needs no equivalent: a key is only ever
    // referenced by an identity, so `deleteKey` finds its holders in-store.
    const done =
      target.kind === "identity"
        ? deleteIdentity(target.id, identityHostRefs)
        : deleteKey(target.id);
    void done.catch((e: unknown) =>
      toast(
        deleteRefusalText(
          `${target.kind} "${target.name}"`,
          target.kind === "identity" ? "host" : "identity",
          e,
        ),
        { variant: "error" },
      ),
    );
  }, []);

  const filtering = query.trim().length > 0;

  // Radix keeps `AlertDialogContent`/`AlertDialogOverlay` MOUNTED for their
  // `data-closed:animate-out … duration-100` exit animation
  // (`components/ui/alert-dialog.tsx:39,64`), so the dialog re-renders with
  // `pendingDelete === null` for ~100ms on every close path - Cancel, Esc,
  // outside-click, the X, and the Delete button itself, which nulls it as its
  // OWN first statement in `confirmDelete` above. Reading `pendingDelete`
  // directly in the title, description or action label would render
  // `Delete ""?` on the way out, and - worse - the description would fall
  // through to whichever `deleteNote` arm a `kind` of `undefined` happens to
  // hit.
  //
  // `shownDelete` is the same record, held past the moment `pendingDelete` is
  // cleared, and exists ONLY to answer "what does the dialog show" - the
  // `open` prop below and `confirmDelete`'s own argument still key off
  // `pendingDelete` itself, never this, so a click during the exit animation
  // (already impossible - `open` is false) could not act on stale data even
  // if it landed.
  const lastDeleteRef = useRef<PendingDelete | null>(null);
  if (pendingDelete) lastDeleteRef.current = pendingDelete;
  const shownDelete = pendingDelete ?? lastDeleteRef.current;

  return (
    // `@container`, not viewport breakpoints: this page renders inside the
    // workspace column, whose width comes from the sidebar drag and the right
    // slot, not from the window. Every size floor between here and the window
    // edge is a PERCENTAGE (`WorkspaceArea.tsx:79` 25%, `AppSidebar.tsx:215`
    // 8%, `AppRightSlot.tsx:178` 18%), and a percentage floor shrinks with the
    // window - so the narrow rules below are reachable only by shrinking the
    // window itself toward `tauri.conf.json`'s `minWidth: 420`, and
    // `scripts/hosts-header-narrow-verify.ts` forces the width directly
    // instead of relying on a hand test that cannot get there.
    <div ref={pageRef} className="bg-background @container flex h-full w-full min-w-0 flex-col">
      <div className="flex flex-col gap-2 border-b p-3">
        {/* The same wrapping header row the Hosts page uses, with one child
            today. `flex-wrap` and the search box's `basis-full` rule are
            anticipatory in this wave - a single child has nothing to wrap
            against - and they are here rather than in wave 3 because the wrap
            rule and the min-width floor are one decision: `flex-1` alone gives
            `flex-basis: 0%`, so the input contributes no intrinsic size and
            CLIPS in place instead of wrapping when wave 3's New buttons arrive
            beside it. The floor is what bites today. */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Both labels collapse at the same `@container` threshold the Hosts
              page's New host button and the two backup buttons use
              (`HostsPage.tsx:337`, `page/HostsBackupActions.tsx:134,144`), so
              each button floors at icon + padding instead of icon-plus-text -
              and the search box's `@max-[420px]:basis-full` rule, anticipatory
              until now, becomes the thing that keeps it off their row.
              `aria-label` is SEPARATE from the span for the reason
              `HostsBackupActions.tsx:107-113` gives: a hidden span still has an
              accessible name via the DOM, but relying on that makes the
              collapsed button's name track whatever text the span happens to
              hold. */}
          <Button
            size="sm"
            className="gap-1.5"
            aria-label="New identity"
            onClick={() => setIdentityTarget({ mode: "create" })}
          >
            <Plus size={13} strokeWidth={2} />
            <span className="@max-[420px]:hidden">New identity</span>
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="gap-1.5"
            aria-label="New key"
            onClick={() => setKeyTarget({ mode: "create" })}
          >
            <KeyRound size={13} strokeWidth={2} />
            <span className="@max-[420px]:hidden">New key</span>
          </Button>
          <InputGroup className="min-w-0 flex-1 @max-[420px]:min-w-40 @max-[420px]:basis-full @[480px]:min-w-40">
            <InputGroupAddon>
              <Search />
            </InputGroupAddon>
            <InputGroupInput
              ref={searchRef}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search vault…"
              aria-label="Search vault"
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

      {/* One scroll area over both sections, so a query that matches an
          identity by the name of the key it uses shows both halves of that
          answer at once. No transform and no fixed row height between here and
          a card: either one defeats the card's `content-visibility: auto`,
          which is what stands in for virtualization. */}
      <div className="min-h-0 flex-1 space-y-4 overflow-y-auto p-3">
        <VaultSection
          title="Identities"
          shown={visibleIdentities.length}
          total={identityRowList.length}
        >
          {visibleIdentities.length === 0 ? (
            <SectionEmpty
              filtering={filtering}
              hasAny={identityRowList.length > 0}
              nothingYet="No saved identities yet."
              nothingYetHint="An identity is one account - a username and its credential - that any number of hosts can share."
              noMatch="No identities match."
            />
          ) : (
            <div className="grid grid-cols-1 gap-2 @[580px]:grid-cols-2 @[860px]:grid-cols-3 @[1140px]:grid-cols-4">
              {visibleIdentities.map((row) => (
                <IdentityCard
                  key={row.identity.id}
                  identity={row.identity}
                  keyName={row.keyName}
                  keyDangling={row.keyDangling}
                  hostCount={row.hostCount}
                  missingSecret={row.missingSecret}
                  onEdit={() => setIdentityTarget({ mode: "edit", identityId: row.identity.id })}
                  onDelete={() =>
                    setPendingDelete({
                      kind: "identity",
                      id: row.identity.id,
                      name: row.identity.name,
                      hasPassword: row.identity.hasPassword,
                      authMode: row.identity.authMode,
                    })
                  }
                />
              ))}
            </div>
          )}
        </VaultSection>

        <VaultSection title="Keys" shown={visibleKeys.length} total={keyRowList.length}>
          {visibleKeys.length === 0 ? (
            <SectionEmpty
              filtering={filtering}
              hasAny={keyRowList.length > 0}
              nothingYet="No saved keys yet."
              nothingYetHint="A key is stored once and shared by every identity that uses it."
              noMatch="No keys match."
            />
          ) : (
            <div className="grid grid-cols-1 gap-2 @[580px]:grid-cols-2 @[860px]:grid-cols-3 @[1140px]:grid-cols-4">
              {visibleKeys.map((row) => (
                <KeyCard
                  key={row.key.id}
                  vaultKey={row.key}
                  identityCount={row.identityCount}
                  missingPrivateKey={row.missingPrivateKey}
                  onEdit={() => setKeyTarget({ mode: "edit", keyId: row.key.id })}
                  onDelete={() =>
                    setPendingDelete({
                      kind: "key",
                      id: row.key.id,
                      name: row.key.name,
                      hasPassphrase: row.key.hasPassphrase,
                    })
                  }
                />
              ))}
            </div>
          )}
        </VaultSection>
      </div>

      {/* The page owns which editor is open; each dialog owns its own load and
          its own save. `keyRowList` is the UNFILTERED list on purpose - the
          picker inside the identity editor must not follow this page's search
          box - and it is the same array the Keys section ranks, so the picker
          and the list cannot disagree about what a key is called. */}
      <IdentityEditorDialog
        target={identityTarget}
        onClose={() => setIdentityTarget(null)}
        keyRows={keyRowList}
      />
      <KeyEditorDialog target={keyTarget} onClose={() => setKeyTarget(null)} />

      <AlertDialog
        open={pendingDelete !== null}
        onOpenChange={(open) => !open && setPendingDelete(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              Delete {shownDelete?.kind} &quot;{shownDelete?.name}&quot;?
            </AlertDialogTitle>
            {/* What is actually deleted for THIS record, not a blanket claim
                keyed on `kind` alone - `deleteNote` branches on the record's
                own fields (`hasPassword`, `authMode`, `hasPassphrase`)
                because two identities on the same `authMode` can differ on
                what they actually have stored. Nothing here says how well a
                secret was kept: the store deletes this record's own secrets
                and refuses outright while anything still references it, so
                there is no cascade to warn about either. Guarded on
                `shownDelete`, not read unconditionally, for the same reason
                the title reads `shownDelete` rather than `pendingDelete`. */}
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
              Delete {shownDelete?.kind}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

/** One titled section with its count. `shown` and `total` are both here so a
 *  filtered list says "3 of 12" rather than quietly looking like the whole
 *  vault. */
function VaultSection({
  title,
  shown,
  total,
  children,
}: {
  title: string;
  shown: number;
  total: number;
  children: ReactNode;
}): ReactNode {
  return (
    <section className="flex flex-col gap-2">
      <div className="flex items-center gap-2">
        <h2 className="text-xs font-semibold tracking-wide uppercase">{title}</h2>
        <span className="text-muted-foreground text-xs tabular-nums">
          {shown === total ? total : `${shown} of ${total}`}
        </span>
      </div>
      {children}
    </section>
  );
}

/** Nothing to show, said in whichever of the two ways is true - "there is
 *  nothing here" and "your query excludes everything" need different next
 *  steps, and conflating them is how an empty grid reads as a broken page. */
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
