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
 * Wave 3 adds the two editors and the New buttons; wave 4 adds
 * convert-to-vault. This wave deliberately ships no affordance that opens
 * nothing.
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
import { InputGroup, InputGroupAddon, InputGroupInput } from "@/components/ui/input-group";
import { toast } from "@/components/ui/toast";
import { paneCaret } from "@/lib/paneCaret";
import { identityHostRefs } from "@/modules/hosts/store";
import { useHosts } from "@/modules/hosts/useHosts";
import { Search, X } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";

import { IdentityCard } from "./page/IdentityCard";
import { KeyCard } from "./page/KeyCard";
import { deleteRefusalText, identityRows, keyRows, rankIdentities, rankKeys } from "./page/derive";
import { deleteIdentity, deleteKey } from "./store";
import { useVault } from "./useVault";

/** Which delete is awaiting confirmation. The NAME is carried alongside the id
 *  because the refusal message and the dialog title both need it, and the
 *  record may be gone from the store by the time either renders. */
type PendingDelete = { kind: "identity" | "key"; id: string; name: string };

export function VaultPage(): ReactNode {
  const vault = useVault();
  const hostsById = useHosts();

  const [query, setQuery] = useState("");
  const [pendingDelete, setPendingDelete] = useState<PendingDelete | null>(null);

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
  // back references that only change when the data does, so a memo keyed on
  // them is correct.
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
                  onDelete={() =>
                    setPendingDelete({
                      kind: "identity",
                      id: row.identity.id,
                      name: row.identity.name,
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
                  onDelete={() =>
                    setPendingDelete({ kind: "key", id: row.key.id, name: row.key.name })
                  }
                />
              ))}
            </div>
          )}
        </VaultSection>
      </div>

      <AlertDialog
        open={pendingDelete !== null}
        onOpenChange={(open) => !open && setPendingDelete(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              Delete {pendingDelete?.kind} &quot;{pendingDelete?.name}&quot;?
            </AlertDialogTitle>
            {/* What is deleted, and nothing about how well it was kept. The
                store deletes this record's own secrets and refuses outright
                while anything still references it, so there is no cascade to
                warn about - and no claim to make about where the value was
                sitting. */}
            <AlertDialogDescription>
              {pendingDelete?.kind === "key"
                ? "Its stored private key and passphrase are deleted too."
                : "Its stored password is deleted too."}{" "}
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
              Delete {pendingDelete?.kind}
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
