import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Combobox, type ComboboxOption } from "@/modules/hosts/editor/Combobox";
import { Field, ToggleButton } from "@/modules/hosts/editor/FormControls";
import { SECRET_STORE_LOCATIONS } from "@/modules/hosts/editor/secretStoreCopy";
import type { ReactNode } from "react";
import { useEffect, useMemo, useRef, useState } from "react";

import type { KeyRow } from "../page/derive";
import { findIdentity, newIdentityId, upsertIdentity } from "../store";
import {
  VAULT_STAMP_ABSENT,
  VaultRecordChangedError,
  vaultIdentityStamp,
  type VaultIdentity,
} from "../types";
import {
  EMPTY_IDENTITY_DRAFT,
  identityDraftFrom,
  identityPasswordHelp,
  identityRecordFrom,
  identitySecretsForSave,
  type IdentityDraft,
  validateIdentityDraft,
} from "./draft";

// The identity editor. Shares its shell with `KeyEditorDialog` - the same
// token/load/ready/saving/error mechanics `HostEditorDialog.tsx` established -
// but there is no keychain SEED here at all: `editor/draft.ts`'s file header is
// the reason, and it is why this file carries no `touched`/`seeded` pair. The
// password field is only ever filled by the user, so `ready` gates nothing but
// the identity record's own load.
//
// `identityRecordFrom` (`./draft.ts`) is where `keyId` gets normalised away from
// a non-key auth mode - not here. This file keeps the picked key in the
// DRAFT across a toggle so a sitting that flips password -> key -> password does
// not lose the selection; only the write drops it. Adding a second normalisation
// in the toggle handler below would be a second implementation of one rule, and
// that is how the two drift.

export type IdentityEditorTarget = { mode: "create" } | { mode: "edit"; identityId: string };

export type IdentityEditorDialogProps = {
  target: IdentityEditorTarget | null;
  onClose: () => void;
  /**
   * Every key in the vault, as the page's own row builder produced them.
   *
   * A PROP, not a fresh read of the vault's own key list, and that is the point
   * rather than a saving: `identityRows`/`keyRows` in `../page/derive.ts` are THE row
   * builders every surface that lists vault records must call, because the
   * Hosts page and the header quick-connect once disagreed about which hosts a
   * query matched while both calling one shared ranking function - each built
   * its own rows in its own loop (`../page/derive.ts:91-121`). A picker that
   * mapped `vault.keys` itself would be that mistake again, one wave later.
   * The page hands over its UNFILTERED `keyRowList`: this list must not follow
   * the page's search box.
   */
  keyRows: readonly KeyRow[];
};

/** A token for "the row the form is showing right now" - see
 *  `HostEditorDialog.tsx`'s own `tokenFor` for the two jobs this does. */
function tokenFor(target: IdentityEditorTarget | null): string | null {
  if (!target) return null;
  if (target.mode === "edit") return `edit:${target.identityId}`;
  return "create";
}

export function IdentityEditorDialog({
  target,
  onClose,
  keyRows,
}: IdentityEditorDialogProps): ReactNode {
  const [mode, setMode] = useState<"create" | "edit">("create");
  const [draft, setDraft] = useState<IdentityDraft>(EMPTY_IDENTITY_DRAFT);
  /** The stored record being edited, or null in create mode. Read for
   *  `identityPasswordHelp` below - the draft's own password field is always
   *  blank, so whether a password is already stored has to come from here. */
  const [existing, setExisting] = useState<VaultIdentity | null>(null);
  const [ready, setReady] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const token = tokenFor(target);
  /** The token whose load has been applied - see `HostEditorDialog.tsx`'s
   *  `applied` for why this is a ref and not state. */
  const applied = useRef<string | null>(null);

  // Reset and populate whenever the editor is pointed at a different row.
  // Closing deliberately leaves the draft alone: the next open resets it, and
  // wiping it here would empty every field behind the dialog's own close
  // animation.
  useEffect(() => {
    if (applied.current === token) return;
    applied.current = token;
    if (!target || !token) return;

    setError(null);
    setSaving(false);
    setExisting(null);
    setReady(false);
    setMode(target.mode);

    const stale = () => applied.current !== token;

    const load = async () => {
      if (target.mode === "create") {
        setDraft(EMPTY_IDENTITY_DRAFT);
        setReady(true);
        return;
      }
      let identity: VaultIdentity | undefined;
      try {
        identity = await findIdentity(target.identityId);
      } catch (e) {
        if (!stale()) setError(e instanceof Error ? e.message : String(e));
        return;
      }
      if (stale()) return;
      if (!identity) {
        setError("That identity no longer exists - it was deleted in another window.");
        return;
      }
      setExisting(identity);
      setDraft(identityDraftFrom(identity));
      setReady(true);
    };

    void load();
  }, [target, token]);

  const patch = (p: Partial<IdentityDraft>) => setDraft((d) => ({ ...d, ...p }));

  const keyOptions: ComboboxOption[] = useMemo(
    () => [
      // "" is a legitimate Combobox value meaning "none" and is an option like
      // any other (`Combobox.tsx:21-23`). It is offered so the trigger has a
      // label before a key is chosen rather than rendering an empty button;
      // choosing it back is refused by `validateIdentityDraft` with a message
      // that says what to do about it.
      { value: "", label: "Select a key…", search: "none select choose key" },
      ...keyRows.map((row) => ({
        value: row.key.id,
        label: row.key.name,
        hint: row.key.fingerprint,
        // The id is in `search` for the reason `Combobox.tsx:27-29` gives: two
        // like-named keys must never collapse into one entry.
        search: `${row.key.name} ${row.key.id} ${row.key.fingerprint ?? ""} ${row.key.keyType ?? ""}`,
      })),
    ],
    [keyRows],
  );
  /** The row for the key currently chosen, so the field below can say what is
   *  wrong with it without asking the vault a second question. */
  const chosenKey = keyRows.find((row) => row.key.id === draft.keyId);

  const save = async () => {
    setError(null);
    const invalid = validateIdentityDraft(draft);
    if (invalid) {
      setError(invalid);
      return;
    }
    setSaving(true);
    try {
      const id = existing?.id ?? newIdentityId();
      // `upsertIdentity` REFUSES key auth that names no key and a `keyId` naming
      // a key that does not exist (`../store.ts`'s own `upsertIdentity`) - as
      // rejected promises. The second is reachable here only by a key deleted in
      // another window between opening this form and pressing Save, and it lands
      // in the error line below rather than the console.
      // The third argument is the secret material this form LOADED, handed to
      // the store so it can refuse a save whose record has moved underneath.
      // Always passed, including in create mode - see `KeyEditorDialog`'s twin
      // of this call for why that needs no `mode` branch.
      await upsertIdentity(
        identityRecordFrom(id, draft),
        identitySecretsForSave(draft),
        vaultIdentityStamp(existing),
      );
      onClose();
    } catch (e) {
      if (e instanceof VaultRecordChangedError) {
        // Rendered so the user can act on it, and NO recovery is offered - see
        // `KeyEditorDialog`'s twin of this arm for why a second press cannot
        // help and neither message may invite one.
        setError(
          e.actual === VAULT_STAMP_ABSENT
            ? `${e.message} Close this editor - pressing Save again will not help: this form ` +
                `still names the deleted record, so the write is refused the same way every time.`
            : `${e.message} Close and reopen this identity to edit it against what is stored ` +
                `now; anything typed here has to be entered again.`,
        );
        return;
      }
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  };

  const busy = saving || !ready;
  const title = mode === "create" ? "New identity" : "Edit identity";

  return (
    <Dialog
      open={target !== null}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>
            The password is stored outside Tervia&apos;s settings file: {SECRET_STORE_LOCATIONS}.
          </DialogDescription>
        </DialogHeader>

        {/* DialogContent caps at calc(100dvh-2rem). min-h-0 lets the inner stack
            shrink so the form scrolls inside the dialog instead of top fields
            sliding off-screen. -mr-2/pr-2 keeps the scrollbar off the content
            edge - same reasoning as `HostEditorDialog.tsx`. */}
        <div className="-mr-2 flex min-h-0 flex-col gap-3 overflow-y-auto pr-2">
          {!ready && !error ? <p className="text-muted-foreground text-[11px]">Loading…</p> : null}
          {ready ? (
            <>
              <Field label="Name">
                <Input
                  value={draft.name}
                  onChange={(e) => patch({ name: e.target.value })}
                  placeholder="root @ prod"
                  spellCheck={false}
                  className="h-8 text-[12px]"
                />
              </Field>

              <Field label="Username">
                <Input
                  value={draft.username}
                  onChange={(e) => patch({ username: e.target.value })}
                  spellCheck={false}
                  className="h-8 font-mono text-[12px]"
                />
              </Field>

              <Field label="Domain (optional)">
                <Input
                  value={draft.domain}
                  onChange={(e) => patch({ domain: e.target.value })}
                  spellCheck={false}
                  className="h-8 font-mono text-[12px]"
                />
                <span className="text-muted-foreground text-[10.5px]">
                  NetBIOS or DNS domain, RDP only. Leave blank for a local account or a UPN
                  username.
                </span>
              </Field>

              <Field label="Authentication">
                <div className="flex gap-1">
                  <ToggleButton
                    active={draft.authMode === "password"}
                    onClick={() => patch({ authMode: "password" })}
                  >
                    Password
                  </ToggleButton>
                  <ToggleButton
                    active={draft.authMode === "key"}
                    onClick={() => patch({ authMode: "key" })}
                  >
                    Private key
                  </ToggleButton>
                  <ToggleButton
                    active={draft.authMode === "agent"}
                    onClick={() => patch({ authMode: "agent" })}
                  >
                    SSH agent
                  </ToggleButton>
                </div>
                <span className="text-muted-foreground text-[10.5px]">
                  How this identity proves who it is over SSH. RDP always uses the password below,
                  whichever mode is chosen here - one account can be a key over SSH and the same
                  account&apos;s password over RDP, which is what sharing an identity across
                  protocols is for.
                </span>
              </Field>

              {/* Rendered in EVERY auth mode, not only "password" - this is not a
                  bug. `VaultIdentity.hasPassword` is independent of `authMode` by
                  design (`../types.ts:99-106`) and `resolveRdpAuth` deliberately
                  never consults the mode (`../resolve.ts:284-288`): hiding this
                  field under key or agent auth would make the RDP half of a
                  shared identity unreachable, which is the state that split
                  exists to permit. */}
              <Field label="Password">
                <Input
                  type="password"
                  value={draft.password}
                  onChange={(e) => patch({ password: e.target.value })}
                  placeholder="••••••••"
                  spellCheck={false}
                  className="h-8 text-[12px]"
                />
                <span className="text-muted-foreground text-[10.5px]">
                  {identityPasswordHelp(existing?.hasPassword === true)}
                </span>
              </Field>

              {draft.authMode === "key" ? (
                <Field label="Key">
                  {keyRows.length === 0 ? (
                    <span className="text-muted-foreground text-[10.5px]">
                      No keys saved yet. Close this and use New key first - an identity that signs
                      with a key has to name one, and the save is refused without it.
                    </span>
                  ) : (
                    <>
                      <Combobox
                        options={keyOptions}
                        value={draft.keyId}
                        onChange={(keyId) => patch({ keyId })}
                        searchPlaceholder="Search keys…"
                        emptyLabel="No key found."
                      />
                      {chosenKey?.missingPrivateKey ? (
                        <span className="text-destructive text-[10.5px]">
                          This key has no private key body stored, so a connect using it is refused
                          before it dials.
                        </span>
                      ) : (
                        <span className="text-muted-foreground text-[10.5px]">
                          The key is a separate record, shared by every identity that names it.
                          Deleting this identity does not delete it.
                        </span>
                      )}
                    </>
                  )}
                </Field>
              ) : null}

              <Field label="Description (optional)">
                <Textarea
                  value={draft.description}
                  onChange={(e) => patch({ description: e.target.value })}
                  placeholder="What this identity is for"
                  spellCheck={false}
                  className="h-16 text-[12px]"
                />
              </Field>
            </>
          ) : null}

          {error ? <p className="text-destructive text-[11px]">{error}</p> : null}
        </div>

        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline" size="sm">
              Cancel
            </Button>
          </DialogClose>
          <Button size="sm" onClick={() => void save()} disabled={busy}>
            {saving ? "Saving…" : mode === "edit" ? "Save" : "Create"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
