/**
 * Create or edit one vault key: a private key stored once and shared by every
 * identity that names it.
 *
 * Modelled on `@/modules/hosts/HostEditorDialog` - the same target token, the
 * same per-target load effect, the same inline error line, the same footer.
 * What it deliberately does NOT copy is that editor's keychain seed and its
 * `touched`/`seeded` pair: the vault store exposes no secret read at all
 * (`../store.ts:39-71`), and `SecretsIo` has no single-value read by design
 * (`../adapters.ts:52-61`), so a secret field here is only ever filled by the
 * user. Blank therefore means "leave the stored value alone", unambiguously,
 * and `./draft.ts` is where that rule is decided and checked.
 *
 * The record is built at SAVE from a FRESH inspection of the two fields as they
 * stand, not from the panel below: the panel describes whichever
 * (body, passphrase) pair the last Check key ran on, and a record built from it
 * would inherit that question one level deeper. One answer, one moment. It also
 * means a public key pasted by mistake, a DSA key or a mistyped passphrase is
 * refused at save with the backend's own sentence instead of being stored.
 *
 * Nothing here changes how a stored secret is kept: on Linux a private key sits
 * in a mode-0600 plaintext file before and after. What one shared key buys is
 * FEWER COPIES of the same private key.
 */
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
import { toast } from "@/components/ui/toast";
import type { FsReadResult } from "@/lib/ipc";
import { Field } from "@/modules/hosts/editor/FormControls";
import { SECRET_STORE_LOCATIONS } from "@/modules/hosts/editor/secretStoreCopy";
import { inspectSshKey } from "@/modules/ssh/bridge";
import { invoke } from "@tauri-apps/api/core";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import { useEffect, useRef, useState, type ReactNode } from "react";

import {
  describeKeyError,
  describeKeyInfo,
  vaultKeyFactsFrom,
  type KeyInspectState,
  type VaultKeyFacts,
} from "../keyInspect";
import { findKey, newKeyId, upsertKey } from "../store";
import type { VaultKey } from "../types";
import {
  EMPTY_KEY_DRAFT,
  keyDraftFrom,
  keyRecordFrom,
  keySecretsForSave,
  passphraseHelp,
  privateKeyHelp,
  validateKeyDraft,
  type KeyDraft,
} from "./draft";

/** null = closed. */
export type KeyEditorTarget = { mode: "create" } | { mode: "edit"; keyId: string };

export type KeyEditorDialogProps = {
  target: KeyEditorTarget | null;
  onClose: () => void;
};

/** Local to this file, and the same shape `SshCredentialSection.tsx:37-38`
 *  declares: the picked file's path, or why it could not be used. */
type ImportState =
  { kind: "idle" } | { kind: "loaded"; path: string } | { kind: "error"; message: string };

/**
 * A token for "the row this form is showing RIGHT NOW", stable across
 * re-renders and different for every distinct target - the same job it does at
 * `HostEditorDialog.tsx:122-126`, so a parent that builds `target` inline does
 * not restart the load on every one of its own renders.
 */
function tokenFor(target: KeyEditorTarget | null): string | null {
  if (!target) return null;
  return target.mode === "edit" ? `edit:${target.keyId}` : "create";
}

export function KeyEditorDialog({ target, onClose }: KeyEditorDialogProps): ReactNode {
  const [draft, setDraft] = useState<KeyDraft>(EMPTY_KEY_DRAFT);
  // Taken from the target when one is applied rather than read off `target` on
  // every render, because `target` goes null the moment the dialog starts
  // closing and the title would flip to "New key" behind the fade - the same
  // reason `HostEditorDialog.tsx:134` holds its own copy.
  const [mode, setMode] = useState<"create" | "edit">("create");
  const [existing, setExisting] = useState<VaultKey | null>(null);
  const [ready, setReady] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [inspected, setInspected] = useState<KeyInspectState>({ kind: "idle" });
  const [imported, setImported] = useState<ImportState>({ kind: "idle" });
  // What `inspected` currently describes: the (body, passphrase) pair as of the
  // last `checkKey` call still allowed to write to it. Bumped by `checkKey`
  // itself, so a second call outruns a first still in flight; by
  // `invalidateInspection`, so an edit to either input does the same; and by
  // the load effect, so an inspection started for the PREVIOUS key can never
  // repaint over this one. A response may repaint only while it still names the
  // generation it was asked to answer for.
  const inspectGeneration = useRef(0);

  const token = tokenFor(target);
  /** The token whose load has been applied. A ref rather than state because the
   *  effect reads it without wanting a render. */
  const applied = useRef<string | null>(null);

  // Reset and populate whenever the editor is pointed at a different key.
  // Closing deliberately leaves the draft alone: the next open resets it, and
  // wiping it here would empty every field behind the dialog's close animation.
  useEffect(() => {
    if (applied.current === token) return;
    applied.current = token;
    if (!target || !token) return;

    setError(null);
    setSaving(false);
    setInspected({ kind: "idle" });
    setImported({ kind: "idle" });
    inspectGeneration.current += 1;
    setExisting(null);
    setReady(false);
    setMode(target.mode);

    if (target.mode === "create") {
      setDraft(EMPTY_KEY_DRAFT);
      setReady(true);
      return;
    }

    const stale = () => applied.current !== token;
    void findKey(target.keyId)
      .then((key) => {
        if (stale()) return;
        if (!key) {
          setError("That key no longer exists - it was deleted in another window.");
          return;
        }
        setExisting(key);
        setDraft(keyDraftFrom(key));
        setReady(true);
      })
      .catch((e: unknown) => {
        if (!stale()) setError(e instanceof Error ? e.message : String(e));
      });
  }, [target, token]);

  const patch = (next: Partial<KeyDraft>) => setDraft((d) => ({ ...d, ...next }));

  /**
   * Ask the backend what this key text is, without dialing anything.
   *
   * Explicit rather than on every keystroke, for the reason
   * `SshCredentialSection.tsx:162-175` gives: this is an IPC round trip that
   * runs bcrypt-pbkdf for an encrypted key, at a round count the key file's own
   * header chooses.
   */
  const checkKey = async (pem: string, passphrase: string) => {
    // Claimed BEFORE the first await, so a call already in flight for an older
    // pair cannot win a race against this one.
    const generation = ++inspectGeneration.current;
    if (!pem.trim()) {
      setInspected({ kind: "idle" });
      return;
    }
    setInspected({ kind: "checking" });
    try {
      const result = describeKeyInfo(await inspectSshKey(pem, passphrase || undefined));
      // Discard rather than render if a newer call - or an edit to either
      // input - has since moved the generation on. Discarding, not aborting, so
      // the panel is never left stuck on "checking".
      if (inspectGeneration.current === generation) setInspected(result);
    } catch (e) {
      const result = describeKeyError(e);
      if (inspectGeneration.current === generation) setInspected(result);
    }
  };

  /**
   * What every edit to either input `checkKey` consumed must do to the panel it
   * produced. Bumping the generation here, not only inside `checkKey`, is what
   * closes the passphrase side: clearing or correcting the passphrase after a
   * successful check has no new call to race against, so without this the
   * answer already delivered would simply sit there, unretracted, describing a
   * passphrase the field no longer holds.
   */
  const invalidateInspection = () => {
    inspectGeneration.current += 1;
    setInspected({ kind: "idle" });
  };

  const pickKeyFile = async () => {
    setImported({ kind: "idle" });
    try {
      const picked = await openDialog({
        multiple: false,
        directory: false,
        title: "Pick SSH private key",
        filters: [
          // `.pub` is absent for the reason `SshCredentialSection.tsx:220-227`
          // gives: russh has no branch that reads a public key as a private
          // one, so offering it invites a single unhelpful failure. `.ppk`
          // stays - the fork's `ppk` feature is on unconditionally.
          { name: "Private key (.pem, .key, .ppk)", extensions: ["pem", "key", "ppk"] },
          { name: "All files", extensions: ["*"] },
        ],
      });
      if (typeof picked !== "string") return;
      const result = await invoke<FsReadResult>("fs_read_file", { path: picked });
      if (result.kind !== "text") {
        setImported({
          kind: "error",
          message:
            result.kind === "toolarge"
              ? "File too large to import"
              : "Picked file is not a text key",
        });
        return;
      }
      // A freshly picked file is a DIFFERENT key from whatever was in the field
      // before it, so a passphrase left over from that one must not be carried
      // into a check of this one - it would report a wrong-passphrase error
      // against a key it was never meant to unlock.
      patch({ privateKey: result.content, passphrase: "" });
      if (!result.content.trim()) {
        // `checkKey`'s own guard sets the panel back to idle for a blank body,
        // so without this branch the status line would say "Loaded <path>"
        // beside a panel showing nothing.
        setImported({ kind: "error", message: "Picked file is empty" });
        invalidateInspection();
        return;
      }
      setImported({ kind: "loaded", path: picked });
      await checkKey(result.content, "");
    } catch (e) {
      setImported({ kind: "error", message: e instanceof Error ? e.message : String(e) });
    }
  };

  const save = async () => {
    setError(null);
    const invalid = validateKeyDraft(draft, mode);
    if (invalid) {
      setError(invalid);
      return;
    }
    setSaving(true);
    try {
      // Inspected HERE rather than read off `inspected`: this reads both fields
      // at the moment the record is built, so there is no generation to compare
      // and no way for the stored facts to describe a pair the form has moved
      // on from. A blank body means the stored key is not being replaced, so
      // there is nothing to inspect and `keyRecordFrom` keeps the facts the
      // record already has.
      let facts: VaultKeyFacts | null = null;
      if (draft.privateKey.trim() !== "") {
        facts = vaultKeyFactsFrom(
          await inspectSshKey(draft.privateKey, draft.passphrase || undefined),
        );
      }
      const id = existing?.id ?? newKeyId();
      // `upsertKey` REFUSES a nameless key and rolls both accounts back for a
      // key it has never seen if either secret write throws (`../store.ts:238-272`).
      // Caught below so the reason lands in the form instead of the console.
      const { warning } = await upsertKey(
        keyRecordFrom(id, draft, existing, facts),
        keySecretsForSave(draft),
      );
      // A duplicate NAME is warned about, not refused - the store's own call
      // (`../store.ts:252-256`), because the name is not an identifier and it is
      // the user's file. It goes to `toast()` rather than into this form,
      // because the form is about to close and an inline warning would vanish
      // with it.
      if (warning) toast(warning, { variant: "warning" });
      onClose();
    } catch (e) {
      // `describeKeyError` strips a leading `ssh: ` and leaves everything else
      // alone (`../keyInspect.ts:73-77`), which is right for both sources here:
      // an inspection failure carries that prefix and a store refusal
      // ("vault: ...") does not. Its return type is the full `KeyInspectState`
      // union rather than just the error arm, so the `kind` check below is a
      // type narrowing `describeKeyError` itself never fails to satisfy - not a
      // real branch this code can reach.
      const described = describeKeyError(e);
      setError(described.kind === "error" ? described.message : String(e));
    } finally {
      setSaving(false);
    }
  };

  const busy = saving || !ready;
  const replacingBody = draft.privateKey.trim() !== "";

  return (
    <Dialog
      open={target !== null}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{mode === "create" ? "New key" : "Edit key"}</DialogTitle>
          <DialogDescription>
            {`The private key is stored outside Tervia's settings file: ${SECRET_STORE_LOCATIONS}.`}
          </DialogDescription>
        </DialogHeader>

        {/* DialogContent caps at calc(100dvh-2rem); min-h-0 lets this stack
            shrink so the form scrolls inside the dialog instead of the top
            fields sliding off screen. -mr-2/pr-2 keeps the scrollbar off the
            content edge. Copied from `HostEditorDialog.tsx:858-862`. */}
        <div className="-mr-2 flex min-h-0 flex-col gap-3 overflow-y-auto pr-2">
          {!ready && !error ? <p className="text-muted-foreground text-[11px]">Loading…</p> : null}
          {ready ? (
            <>
              <Field label="Name">
                <Input
                  value={draft.name}
                  onChange={(e) => patch({ name: e.target.value })}
                  placeholder="id_ed25519"
                  spellCheck={false}
                  className="h-8 text-[12px]"
                />
                <span className="text-muted-foreground text-[10.5px]">
                  How this key is listed and picked from an identity. Renaming it does not move
                  anything: the id it is stored under never changes.
                </span>
              </Field>

              <Field label="Private key (PEM / OpenSSH)">
                <div className="flex flex-col gap-1">
                  <Textarea
                    value={draft.privateKey}
                    onChange={(e) => {
                      patch({ privateKey: e.target.value });
                      // A stale panel must not sit under a body that has since
                      // been edited - what it shows would describe the old text.
                      invalidateInspection();
                    }}
                    placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                    spellCheck={false}
                    className="h-32 font-mono text-[11px]"
                  />
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-1.5">
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        className="h-7 px-2 text-[11px]"
                        onClick={() => void pickKeyFile()}
                      >
                        Import from file…
                      </Button>
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        className="h-7 px-2 text-[11px]"
                        onClick={() => void checkKey(draft.privateKey, draft.passphrase)}
                        disabled={inspected.kind === "checking" || !replacingBody}
                      >
                        Check key
                      </Button>
                    </div>
                    {imported.kind === "loaded" ? (
                      <span className="text-muted-foreground truncate text-[10.5px]">
                        Loaded {imported.path}
                      </span>
                    ) : imported.kind === "error" ? (
                      <span className="text-destructive truncate text-[10.5px]">
                        {imported.message}
                      </span>
                    ) : (
                      <span className="text-muted-foreground text-[10.5px]">
                        Paste, or import a .pem / key file
                      </span>
                    )}
                  </div>
                  <KeyInspectPanel state={inspected} />
                </div>
                <span className="text-muted-foreground text-[10.5px]">{privateKeyHelp(mode)}</span>
              </Field>

              <Field label="Key passphrase (optional)">
                <Input
                  type="password"
                  value={draft.passphrase}
                  onChange={(e) => {
                    patch({ passphrase: e.target.value });
                    // The panel's "ok" and "locked" results, and any error
                    // naming a wrong passphrase, all describe the passphrase
                    // that was IN this field at check time.
                    invalidateInspection();
                  }}
                  className="h-8 font-mono text-[12px]"
                />
                <span className="text-muted-foreground text-[10.5px]">
                  {passphraseHelp(replacingBody)}
                </span>
              </Field>

              <Field label="Description (optional)">
                <Textarea
                  value={draft.description}
                  onChange={(e) => patch({ description: e.target.value })}
                  placeholder="Which machines this key opens"
                  spellCheck={false}
                  className="h-16 text-[12px]"
                />
              </Field>

              {mode === "edit" && existing ? <StoredKeyRow vaultKey={existing} /> : null}
            </>
          ) : null}

          {error ? <p className="text-destructive text-[11px]">{error}</p> : null}
        </div>

        {/* Override DialogFooter's flex-col-reverse so Cancel stays on the left
            at any width - the same override `HostEditorDialog.tsx:1019` uses. */}
        <DialogFooter className="flex-row items-center justify-end gap-2 sm:justify-end sm:[&>button]:flex-none">
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

/**
 * What the STORE already records about this key, on an edit.
 *
 * Read-only, and separate from the panel above on purpose: the panel describes
 * whatever is in the textarea right now, and this describes what is stored. The
 * public half is here rather than hidden because it is not a secret and is
 * meant to be copied straight into `authorized_keys` (`../types.ts:126-127`) -
 * it is rendered whole, in a selectable box, because a value someone pastes
 * elsewhere has to be pasteable.
 */
function StoredKeyRow({ vaultKey }: { vaultKey: VaultKey }): ReactNode {
  return (
    <Field label="Stored key">
      {/* Same box as the read-only status blocks in the host editor. */}
      <div className="border-border/60 bg-muted/30 flex flex-col gap-1 rounded-md border px-2 py-1.5">
        <span className="text-[11px]">
          {vaultKey.keyType !== undefined ? vaultKey.keyType.toUpperCase() : "Unknown type"}
          {vaultKey.hasPassphrase ? " · passphrase stored" : ""}
        </span>
        <span className="text-muted-foreground truncate font-mono text-[10.5px]">
          {vaultKey.fingerprint ?? "No fingerprint recorded"}
        </span>
        {vaultKey.publicKey ? (
          <span className="text-muted-foreground font-mono text-[10px] break-all">
            {vaultKey.publicKey}
          </span>
        ) : null}
      </div>
    </Field>
  );
}

/**
 * What `checkKey` found, rendered under the textarea.
 *
 * Reports what the key IS and nothing more. A near-copy of
 * `SshCredentialSection.tsx:502-548`, and deliberately a copy: that one is a
 * private function inside a file `scripts/key-inspect-verify.ts` section 5
 * anchors on, including a wording rule scoped to its own body, so lifting it
 * out is a change to a checked host-editor file for a vault feature. The
 * duplication is reported instead - see the plan's §1.9.
 */
function KeyInspectPanel({ state }: { state: KeyInspectState }): ReactNode {
  if (state.kind === "idle") return null;
  if (state.kind === "checking") {
    return <span className="text-muted-foreground text-[10.5px]">Reading key…</span>;
  }
  if (state.kind === "locked") {
    return (
      <span className="text-muted-foreground text-[10.5px]">
        This key is encrypted and hides its details. Enter the key passphrase below and press Check
        key. Saving without it stores the key with no type or fingerprint recorded.
      </span>
    );
  }
  if (state.kind === "error") {
    return <span className="text-destructive text-[10.5px]">{state.message}</span>;
  }
  return (
    <div className="border-border/60 bg-muted/30 flex flex-col gap-1 rounded-md border px-2 py-1.5">
      <div className="flex items-center gap-2 text-[11px]">
        <span>{state.keyType}</span>
        {state.encrypted ? (
          <span className="text-muted-foreground">Key file is passphrase-encrypted</span>
        ) : null}
      </div>
      <div className="flex min-w-0 items-center gap-1.5 font-mono text-[10.5px]">
        <span className="text-muted-foreground shrink-0">Key fingerprint</span>
        <span className="truncate" title={state.fingerprint}>
          {state.fingerprint}
        </span>
      </div>
      {state.comment ? (
        <span className="text-muted-foreground truncate text-[10.5px]" title={state.comment}>
          {state.comment}
        </span>
      ) : null}
    </div>
  );
}
