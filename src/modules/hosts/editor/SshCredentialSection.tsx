import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import type { FsReadResult } from "@/lib/ipc";
import { inspectSshKey, listSshAgentKeys, type SshAgentKey } from "@/modules/ssh/bridge";
import {
  describeKeyError,
  describeKeyInfo,
  type KeyInspectState,
} from "@/modules/vault/keyInspect";
import { invoke } from "@tauri-apps/api/core";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import { useCallback, useEffect, useRef, useState } from "react";

import { forgetKeyNote, forgetKeyRowLabel } from "./credentialChoice";
import { Field, ToggleButton } from "./FormControls";
import type { SshCredentialDraft } from "./types";

// The SSH credential region, lifted out of `SshConnectionDialog` as it stood.
//
// Deliberately NOT merged with the RDP one and deliberately not tidied: the
// three-state secret convention and the auth-mode branching are the part of these
// two dialogs that costs a lost credential when it is got wrong, so the merge
// moved them and changed nothing else. Factoring the two sections together is
// separate work with its own review.
//
// What the plumbing did force: this component no longer owns the draft (the
// dialog does, because the save path needs every field), so each write goes out
// as a PATCH - which is also what tells the dialog that the user, rather than the
// secret load, touched a field.

/** What the local ssh-agent answered. Agent auth has no field to fill in, so
 *  this IS the form validation for that mode: it says up front whether an agent
 *  is running and holding a key, instead of failing at dial time. */
type AgentState =
  { kind: "checking" } | { kind: "ok"; keys: SshAgentKey[] } | { kind: "error"; message: string };

type ImportState =
  { kind: "idle" } | { kind: "loaded"; path: string } | { kind: "error"; message: string };

export type SshCredentialSectionProps = {
  /** The identity this host is bound to, or null when it owns its credentials
   *  inline. A bound row shows a read-only panel and nothing editable. */
  boundIdentity: string | null;
  /** `boundIdentity`'s NAME, resolved by the dialog from the `identityRows`
   *  prop it already holds - this component does no vault read of its own.
   *  `undefined` renders the id alone, which covers a dangling binding. */
  identityName?: string;
  value: SshCredentialDraft;
  onChange: (patch: Partial<SshCredentialDraft>) => void;
  /**
   * Whether the STORED record claims a password, which is what a blank field
   * means the opposite of. Blank on a host with nothing stored saves a host
   * without a password; blank on a host that has one means the keychain read has
   * not landed and the save leaves it alone. Same prop, same reason, as the RDP
   * section's - see {@link passwordHelp}.
   */
  hasStoredPassword: boolean;
  /**
   * Whether the STORED record holds a private key BODY, which is what a blank
   * textarea means the opposite of. Same prop, same shape and same reason as
   * `hasStoredPassword` above, with one difference that is the whole of why this
   * one is worth its own doc: under key auth this textarea is also the ROUTE
   * that deletes a stored key, so what it decides is copy on a delete path. See
   * {@link keyBodyHelp}.
   *
   * `hasPrivateKey` ALONE, deliberately not `hasPrivateKey || hasKeyPassphrase`.
   * This line is about the field under it, and that field is seeded from,
   * cleared into and deleted through the key body account and no other. A record
   * holding a key passphrase and no body is a real state - `forgetKeyNote` is a
   * function of the flags precisely because of it - and on that record the
   * stored arm would be wrong twice: there is no key body to keep, and the
   * removal route it names never fires, because a field the seed never filled is
   * not `seeded` and clearing it sends nothing. That orphan is
   * `hostKeySecretNames`'s subject rather than this one's: it unions the two
   * accounts because the row it feeds offers to delete both, and it is gated on
   * things this line is not.
   */
  hasStoredPrivateKey: boolean;
  /**
   * The dialog's save-time refusal for the key body, or null.
   *
   * A prop rather than state of this component's own because the inspection it
   * comes from happens in `save()`, which reads every field at the moment the
   * record is built - and it is DISTINCT from the dialog's bottom `error` line,
   * which carries store refusals and keychain errors. This one names the key
   * field and tells the user to enter the passphrase below it, so it renders as
   * the last child of that field with the passphrase input directly under it.
   * The same split, for the same reason, as the vault key editor's.
   */
  keyRefusal: string | null;
  /**
   * The key material the STORED record still holds and this row may offer to
   * delete, by name - `hostKeySecretNames` in `credentialChoice.ts`, already
   * gated by the dialog on this row being the only surface promising anything
   * about those two accounts.
   *
   * An empty list means no row, and it is the ONE gate on that: the dialog
   * answers `[]` for a create-mode form, for a vault-bound row (which owns no
   * accounts of its own) and while a credential change is pending (which already
   * deletes or moves the same accounts). Passed in rather than derived here
   * because this component never sees the stored record - it holds the draft,
   * whose key body is an open-time snapshot that says nothing about what is
   * stored.
   */
  forgettableKeySecrets: readonly string[];
  /** Whether Forget has been pressed in this sitting. The dialog's state,
   *  applied by Save and discarded by Cancel - see `forgetSshKey` there. */
  forgetKey: boolean;
  onForgetKey: () => void;
};

/**
 * The credential half of the form's validation, kept beside the fields it is
 * about. The shared half lives in the dialog.
 */
export function validateSshCredential(
  draft: SshCredentialDraft,
  boundIdentity: string | null,
): string | null {
  // A vault-bound row has no user and no credential of its own to validate:
  // both belong to the identity, and the form does not show either.
  if (boundIdentity) return null;
  // Still required, and not by symmetry with the password below: `user` has no
  // presence flag, no indicator and no path that fills it later. A row saved
  // without one dials with `user: ""` and fails the handshake with a message that
  // names nothing the card could show, so a blank user is a MALFORMED record
  // rather than an incomplete one.
  if (!draft.user.trim()) return "User is required";
  // A BLANK SECRET IS DELIBERATELY ALLOWED - the password AND, since the key
  // body joined it, the private key - and the missing rules here are the fix
  // rather than an omission. `hasPassword: false` and `hasPrivateKey: false` on
  // an inline row are states the store persists and the Hosts page renders: the
  // card shows "Missing secret" and reads the stored flag, not the keychain, and
  // `../page/derive.ts` asks about exactly the one field the auth mode uses. So
  // refusing either made the one state that indicator exists for unreachable
  // from the UI, while leaving no way to save a host now and store its secret
  // later.
  //
  // What a connect then does, stated correctly because the earlier version of this
  // comment claimed the wrong thing: it never reaches the server. `resolve.ts` maps
  // an empty secret to `undefined`, and `session.rs`'s `connect` pre-flights that -
  // `ssh: no credentials: set use_agent, password, or private_key` - before any
  // socket is opened. Better than the authentication failure this used to promise,
  // since nothing is sent and nothing looks like a rejected login, but it is a
  // different message and the reasoning here should name the one that happens.
  //
  // What replaced the key-body rule is a REAL check rather than nothing, and the
  // trade is the point: the rule caught the one key-auth state that is honest on
  // the card, and caught none of the states that are not. The dialog's save now
  // inspects a non-blank body and refuses an encrypted key saved without its
  // passphrase, and lets the backend refuse a public key, a DSA key, a SEC1 key
  // and a wrong passphrase - each of which used to store a complete-looking
  // record whose every connect fails, with nothing on the card to say so. That
  // inspection cannot live here: it is an IPC round trip and this function is
  // synchronous.
  //
  // The RDP password is NOT relaxed with either of them, and the asymmetry is
  // deliberate rather than an oversight: `RdpPane` declines to connect at all
  // without a password, so an RDP row saved without one has no reachable outcome
  // but a failure. See `validateRdpCredential`.
  //
  // Agent mode has nothing to require here on purpose: the agent may be started
  // (or the key added) after this host is saved, so a down agent must not block
  // saving. The panel reports its state, and a connect attempt fails with the
  // backend's message naming what to start.
  return null;
}

/**
 * What leaving the password field blank actually does, which is the OPPOSITE thing
 * on the two sides of `hasStoredPassword`.
 *
 * One string served both until a review found what that costs. On a host that has
 * no password, blank saves a host without one, and saying so is the point of the
 * text. On a host that HAS one, the field is blank for the whole of the keychain
 * read - the form is interactive before the secrets arrive, deliberately - and it
 * stays blank if that read yielded to a keystroke. Telling the user "leave blank to
 * save the host without one" at that moment describes a destruction the save
 * refuses to perform, and confirms the mental model that makes them try.
 *
 * The delete path is described with its precondition attached, because that is the
 * rule `sshSecretsForSave` enforces: emptying this field removes the stored
 * password only once the stored password has been loaded into it.
 */
function passwordHelp(hasStoredPassword: boolean): string {
  if (hasStoredPassword) {
    return "A password is already stored for this host, and blank does not remove it: blank means leave it exactly as it is. To remove it, wait for the stored password to load into this field, clear it, and save.";
  }
  return "Leave blank to save the host without one. It is listed with a missing-secret warning until a password is entered, and a connect is then refused before it dials - the host process reports that it has no credentials rather than failing a login.";
}

/**
 * What leaving the KEY BODY blank actually does, which is the OPPOSITE thing on
 * the two sides of `hasStoredPrivateKey`.
 *
 * The same split as {@link passwordHelp}, and it carries more here: this
 * textarea is not only a field whose blank saves nothing, it is the ONE route
 * that removes a stored private key. `sshSecretsForSave` turns a cleared field
 * that was seeded into the store's delete instruction, so this is copy on a
 * delete path rather than copy about a value, and the wrong half of it shown at
 * the wrong moment describes a destruction and invites the user to try it.
 *
 * THE RULE HAS THREE STATES AND THIS FUNCTION HAS TWO ARMS, which is a split
 * rather than a simplification. `sshSecretsForSave` decides per field on
 * (touched, seeded): a blank body that WAS seeded deletes the stored key, a
 * blank body that was not is omitted - the keychain read had not landed, so
 * there was never a value on screen to delete - and an untouched field is
 * omitted too. The two arms split on what is STORED, which is the question this
 * component cannot answer from the draft, and the third state is exactly what
 * the stored arm's precondition clause is for: the field is blank for the whole
 * of that read, deliberately, and "wait for the stored key to load into this
 * field" is what tells a user who has a key and is looking at an empty box which
 * of the two blanks they are looking at.
 *
 * The Forget button is not named here on purpose, and its absence is not an
 * omission: that row renders only in the auth modes with no key field at all, so
 * naming it from under the textarea would be the second surface promising one
 * deletion that its placement rule exists to prevent.
 */
function keyBodyHelp(hasStoredPrivateKey: boolean): string {
  if (hasStoredPrivateKey) {
    return "A private key is already stored for this host, and blank does not remove it: blank means leave it exactly as it is. To remove it, wait for the stored key to load into this field, clear it, and save.";
  }
  return "Leave blank to save the host without a private key. It is listed with a missing-secret warning until a key is entered, and a connect is then refused before it dials - the host process reports that it has no credentials rather than failing a login.";
}

export function SshCredentialSection({
  boundIdentity,
  identityName,
  value,
  onChange,
  hasStoredPassword,
  hasStoredPrivateKey,
  keyRefusal,
  forgettableKeySecrets,
  forgetKey,
  onForgetKey,
}: SshCredentialSectionProps) {
  const [agent, setAgent] = useState<AgentState>({ kind: "checking" });
  const [imported, setImported] = useState<ImportState>({ kind: "idle" });
  const [inspected, setInspected] = useState<KeyInspectState>({ kind: "idle" });
  // What `inspected` currently describes: the (pem, passphrase) pair as of the
  // last `checkKey` call that is still allowed to write to `inspected`. Bumped
  // by `checkKey` itself, so a second call outruns and discards a first one
  // still in flight, and by `invalidateInspection`, so an edit to either input
  // does the same to a call already in flight over the text before the edit.
  // A response may only ever repaint the panel while it still names the
  // generation it was asked to answer for.
  const inspectGeneration = useRef(0);

  // Ask the agent what it holds whenever this mode is on screen. Cheap enough to
  // re-run on every open and every switch into the tab, which is also what makes
  // "start the agent, then come back" show the right answer.
  const checkAgent = useCallback(async () => {
    setAgent({ kind: "checking" });
    try {
      setAgent({ kind: "ok", keys: await listSshAgentKeys() });
    } catch (e) {
      setAgent({ kind: "error", message: e instanceof Error ? e.message : String(e) });
    }
  }, []);

  // The old dialog gated this on its own `open` prop. It no longer needs one: the
  // dialog unmounts its content when it closes, so being mounted IS being open,
  // and the reset that used to happen on open is now this component's own mount.
  useEffect(() => {
    if (value.authMode !== "agent") return;
    void checkAgent();
  }, [value.authMode, checkAgent]);

  /**
   * Ask the backend what this key text is, without dialing anything.
   *
   * Explicit rather than on every keystroke: this is an IPC round trip that runs
   * bcrypt-pbkdf for an encrypted key, at a round count the key file's own header
   * chooses, so firing it per character would freeze the form on a hand-edited
   * key. A file import calls it once, and a pasted key gets a button.
   *
   * The passphrase is passed because an OpenSSH container answers type,
   * fingerprint and public half WITHOUT it but seals the comment away, and every
   * other container seals the lot - and because verifying the passphrase here is
   * the whole reason a wrong one stops being something the user discovers at the
   * first connect.
   */
  const checkKey = async (pem: string, passphrase: string) => {
    // Claim this generation before the first await, so a call already in
    // flight for an older (pem, passphrase) pair can no longer win a race
    // against this one - see `inspectGeneration`.
    const generation = ++inspectGeneration.current;
    if (!pem.trim()) {
      setInspected({ kind: "idle" });
      return;
    }
    setInspected({ kind: "checking" });
    try {
      const result = describeKeyInfo(await inspectSshKey(pem, passphrase || undefined));
      // Discard rather than render if a newer call - or an edit to either
      // input, via `invalidateInspection` - has since moved the generation on.
      if (inspectGeneration.current === generation) setInspected(result);
    } catch (e) {
      const result = describeKeyError(e);
      if (inspectGeneration.current === generation) setInspected(result);
    }
  };

  /**
   * What every edit to either input `checkKey` consumed must do to the panel
   * it produced: the panel names an algorithm, a fingerprint and a comment
   * that describe ONE (pem, passphrase) pair, and neither input may change
   * out from under it while it still claims to describe them. Bumping the
   * generation here, not only inside `checkKey`, is what closes the passphrase
   * side of that: clearing or editing the passphrase after a successful check
   * has no new `checkKey` call to race against, so without this the response
   * already delivered would simply sit there, unretracted.
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
          {
            // `.pub` is gone from this list: it is a PUBLIC key and russh has no
            // branch that can ever read one as a private key, so offering it was
            // an invitation to the single unhelpful "Could not read key". `.ppk`
            // stays - russh enables the fork's `ppk` feature unconditionally and
            // handles PuTTY v2 and v3.
            name: "Private key (.pem, .key, .ppk)",
            extensions: ["pem", "key", "ppk"],
          },
          // OpenSSH keys (id_rsa, id_ed25519, …) have no extension, so keep an
          // all-files fallback the user can switch to.
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
      // A freshly picked file is a different key from whatever was in the
      // field before it, so a passphrase left over from that one must not be
      // carried into a check of this one: it would report a wrong-passphrase
      // error against a key it was never meant to unlock.
      onChange({ privateKey: result.content, keyPassphrase: "" });
      if (!result.content.trim()) {
        // The one unusable key `checkKey`'s own guard says nothing about: a
        // blank `pem` makes it set `inspected` back to idle, so without this
        // branch the status line would claim "Loaded <path>" beside a panel
        // showing nothing - a silent success for the one file that has none.
        // `validateSshCredential` still catches this at save time regardless.
        setImported({ kind: "error", message: "Picked file is empty" });
        invalidateInspection();
        return;
      }
      setImported({ kind: "loaded", path: picked });
      await checkKey(result.content, "");
    } catch (e) {
      setImported({
        kind: "error",
        message: e instanceof Error ? e.message : String(e),
      });
    }
  };

  // The user and the credential are one block, because a vault binding owns
  // both: an identity carries the username as well as the secret, so showing a
  // user field for a bound row would offer to edit half of something this dialog
  // cannot edit at all.
  if (boundIdentity) {
    return <VaultBindingPanel identityId={boundIdentity} identityName={identityName} />;
  }

  return (
    <>
      <Field label="User">
        <Input
          value={value.user}
          onChange={(e) => onChange({ user: e.target.value })}
          placeholder="users"
          spellCheck={false}
          className="h-8 font-mono text-[12px]"
        />
      </Field>

      <Field label="Authentication">
        <div className="flex gap-1">
          <ToggleButton
            active={value.authMode === "password"}
            onClick={() => onChange({ authMode: "password" })}
          >
            Password
          </ToggleButton>
          <ToggleButton
            active={value.authMode === "key"}
            onClick={() => onChange({ authMode: "key" })}
          >
            Private key
          </ToggleButton>
          <ToggleButton
            active={value.authMode === "agent"}
            onClick={() => onChange({ authMode: "agent" })}
          >
            SSH agent
          </ToggleButton>
        </div>
      </Field>

      {value.authMode === "agent" ? (
        <AgentPanel state={agent} onRecheck={() => void checkAgent()} />
      ) : value.authMode === "password" ? (
        <Field label="Password">
          <Input
            type="password"
            value={value.password}
            onChange={(e) => onChange({ password: e.target.value })}
            className="h-8 font-mono text-[12px]"
          />
          {/* Saving with this blank is allowed - see `validateSshCredential` - so
              the form says what that produces rather than leaving the user to
              discover it at the first connect. Which of the two things it produces
              depends on the stored record, not on this draft: see
              `passwordHelp`. */}
          <span className="text-muted-foreground text-[10.5px]">
            {passwordHelp(hasStoredPassword)}
          </span>
        </Field>
      ) : (
        <>
          <Field label="Private key (PEM / OpenSSH)">
            <div className="flex flex-col gap-1">
              <Textarea
                value={value.privateKey}
                onChange={(e) => {
                  onChange({ privateKey: e.target.value });
                  // A stale "ok" panel must not sit under a key that has since
                  // been edited - the fields it shows would describe the OLD text.
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
                    onClick={() => void checkKey(value.privateKey, value.keyPassphrase)}
                    disabled={inspected.kind === "checking" || value.privateKey.trim() === ""}
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
            {/* Saving with this blank is allowed - see `validateSshCredential` -
                and unlike the password field, blank here is also how a stored key
                is REMOVED, so what blank does is the one thing this field has to
                say out loud. Which of the two things it does depends on the
                stored record and not on this draft: see `keyBodyHelp`.

                A direct child of the `Field` rather than of the control cluster
                above, so it reads as being about the field rather than about the
                inspect panel it would otherwise hang off, and ABOVE the refusal,
                which stays last for the reason its own comment gives. The status
                span in the button row is deliberately left alone: it is the
                import slot, truncated and replaced by a path or an error, so a
                sentence about what Save does would vanish at the moment a file is
                imported. */}
            <span className="text-muted-foreground text-[10.5px]">
              {keyBodyHelp(hasStoredPrivateKey)}
            </span>
            {/* The save-time refusal, and the LAST child of this field on
                purpose: its sentence says to enter the passphrase below, and
                the passphrase input is the next field down. It is not the
                dialog's bottom `error` line and must not move there - that
                line carries store refusals and keychain errors, which are
                about the form rather than about this one input. */}
            {keyRefusal ? <p className="text-destructive text-[10.5px]">{keyRefusal}</p> : null}
          </Field>
          <Field label="Key passphrase (optional)">
            <Input
              type="password"
              value={value.keyPassphrase}
              onChange={(e) => {
                onChange({ keyPassphrase: e.target.value });
                // The panel's "ok" and "locked" results, and any error naming
                // a wrong passphrase, all describe the passphrase that was
                // IN this field at check time. Editing it - correcting it,
                // clearing it, or mistyping over a correct one - makes that
                // description stale in exactly the way editing the key body
                // already does above.
                invalidateInspection();
              }}
              className="h-8 font-mono text-[12px]"
            />
          </Field>
        </>
      )}

      {/* AFTER the auth-mode ternary and gated on the mode itself, rather than
          added to the two non-key arms above: one render site, one gate, and
          the gate is the claim - the key textarea IS the route to clearing a
          stored key, so this row exists only where that textarea does not.
          Under key auth it must not appear at all: the field the user is
          looking at is the thing that removes the key, and a second surface
          promising the same deletion is how the two come to say different
          things.

          WHAT THE GATE COSTS is in `KNOWN-LIMITS.md`, and it is this row's
          placement that carries it: the textarea route can strand a key
          passphrase behind a deleted body, and this is the only surface that
          offers to remove one - so the user has to leave key auth before
          anything does. Accepted, not overlooked; widening the gate retires
          that entry. */}
      {value.authMode !== "key" && forgettableKeySecrets.length > 0 ? (
        <ForgetKeyRow
          keySecrets={forgettableKeySecrets}
          forgetting={forgetKey}
          onForget={onForgetKey}
        />
      ) : null}
    </>
  );
}

/**
 * The key material a host still stores under an auth mode that cannot use it,
 * with its Forget action.
 *
 * The shape is `PinnedKeyRow`'s in `HostEditorDialog.tsx` - a `Field`, a bordered
 * row naming what is held, a small outline button, a footnote saying when it
 * applies - and deliberately a SIBLING of it rather than the two sharing a shell.
 * They hold different content (a fingerprint against a list of accounts) and have
 * different empty states, and a shared card shell was priced and declined.
 * `KNOWN-LIMITS.md` carries that as an accepted duplication, and records that
 * only this copy of the shape is pinned by a verify script; a THIRD card wanting
 * it is what re-runs the calculus, and retires the entry either way.
 *
 * Forget records an INTENT, which is the whole design and not an ordering
 * preference: the same button wrote its deletion straight to the store for the
 * pinned key, and Cancel then reverted the visible field while nothing reverted
 * the deletion. So the button disappears once pressed and the note says what Save
 * will do - the press is visible, and nothing has happened yet.
 *
 * Every string here comes from `credentialChoice.ts`, where it can be exercised by
 * value: the note has to read correctly for a stored passphrase with no stored
 * body, which is a case no fixed sentence covers.
 */
function ForgetKeyRow({
  keySecrets,
  forgetting,
  onForget,
}: {
  keySecrets: readonly string[];
  forgetting: boolean;
  onForget: () => void;
}) {
  return (
    <Field label="Stored key material">
      {/* Same box as the read-only status blocks in this editor. */}
      <div className="border-border/60 bg-muted/30 flex items-center justify-between gap-2 rounded-md border px-2 py-1">
        <span className="truncate text-[10.5px]">{forgetKeyRowLabel(keySecrets)}</span>
        {forgetting ? null : (
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="h-6 shrink-0 px-2 text-[10.5px]"
            onClick={onForget}
          >
            Forget
          </Button>
        )}
      </div>
      <span className="text-muted-foreground text-[10.5px]">
        {forgetKeyNote(keySecrets, forgetting)}
      </span>
    </Field>
  );
}

/**
 * What stands in for the user and credential fields when the row is bound to a
 * shared vault identity.
 *
 * Read-only on purpose, and it says which parts of the form still work: the
 * alternative was refusing to open the dialog at all, which would leave an
 * imported host unable to be renamed or re-pointed at all. The identity used to
 * be named by id alone because resolving the name meant a vault read this dialog
 * had no reason to do - it no longer does:
 * `HostEditorDialog` holds `identityRows` for its own credential picker and
 * passes the resolved name down, so the id is now a footnote under it rather
 * than the only thing on screen, kept for the one case a name cannot cover - a
 * binding naming an identity that no longer exists.
 */
function VaultBindingPanel({
  identityId,
  identityName,
}: {
  identityId: string;
  identityName?: string;
}) {
  return (
    <Field label="Credential">
      {/* Same box as the two other read-only status blocks in this editor. */}
      <div className="border-border/60 bg-muted/30 flex flex-col gap-1 rounded-md border px-2 py-1.5">
        <span className="text-[11px]">
          This host uses the shared vault identity{identityName ? ` "${identityName}"` : ""}.
        </span>
        <span className="text-muted-foreground truncate font-mono text-[10.5px]" title={identityId}>
          {identityId}
        </span>
      </div>
      <span className="text-muted-foreground text-[10.5px]">
        The user and the credential belong to the identity, so neither is editable here and Test
        cannot run. The binding is changed with the Credential picker above; everything else on this
        form can still be edited.
      </span>
    </Field>
  );
}

/**
 * The whole of the agent auth "form": there is nothing to type, so the panel
 * answers the only question that matters - is an agent running and does it hold
 * a key. The error text comes from the backend, which names the exact service to
 * start per platform.
 */
function AgentPanel({ state, onRecheck }: { state: AgentState; onRecheck: () => void }) {
  return (
    <Field label="SSH agent">
      {/* Same box and same secondary button as "Recorded server key", so the
          read-only status blocks in this editor look like one thing. */}
      <div className="border-border/60 bg-muted/30 flex flex-col gap-1.5 rounded-md border px-2 py-1.5">
        <div className="flex items-center justify-between gap-2">
          {state.kind === "checking" ? (
            <span className="text-muted-foreground text-[11px]">Checking ssh-agent…</span>
          ) : state.kind === "error" ? (
            <span className="text-destructive text-[11px]">{state.message}</span>
          ) : state.keys.length === 0 ? (
            <span className="text-[11px]">
              Agent is running but holds no key. Add one with{" "}
              <span className="font-mono">ssh-add</span>.
            </span>
          ) : (
            <span className="text-[11px]">
              {state.keys.length} key{state.keys.length === 1 ? "" : "s"} available
            </span>
          )}
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="h-6 shrink-0 px-2 text-[10.5px]"
            onClick={onRecheck}
            disabled={state.kind === "checking"}
          >
            Recheck
          </Button>
        </div>
        {state.kind === "ok" && state.keys.length > 0 ? (
          <ul className="flex flex-col gap-0.5">
            {state.keys.map((k) => (
              <li
                key={k.fingerprint}
                className="flex min-w-0 items-center gap-2 font-mono text-[10.5px]"
                title={k.fingerprint}
              >
                <span className="text-muted-foreground shrink-0">{k.algorithm}</span>
                <span className="truncate">{k.comment || k.fingerprint}</span>
              </li>
            ))}
          </ul>
        ) : null}
      </div>
      <span className="text-muted-foreground text-[10.5px]">
        The key never leaves the agent: Tervia asks it to sign each handshake and stores nothing ·
        the server must already have the matching public key · Windows uses the OpenSSH
        Authentication Agent service or Pageant, elsewhere{" "}
        <span className="font-mono">SSH_AUTH_SOCK</span>.
      </span>
    </Field>
  );
}

/**
 * What `checkKey` found, rendered under the key textarea.
 *
 * Reports what the key IS, and nothing more: no wording here may say a key is
 * "verified" or "safe" - that is not a question this panel, or the vault, answers.
 * A missing `comment` is not shown as a gap: it is normal for an encrypted
 * `openssh-key-v1` key inspected without its passphrase (see `keyInspect.ts`).
 */
function KeyInspectPanel({ state }: { state: KeyInspectState }) {
  if (state.kind === "idle") return null;
  if (state.kind === "checking") {
    return <span className="text-muted-foreground text-[10.5px]">Reading key…</span>;
  }
  if (state.kind === "locked") {
    return (
      <span className="text-muted-foreground text-[10.5px]">
        This key is encrypted and hides its details. Enter the key passphrase below and press Check
        key.
      </span>
    );
  }
  if (state.kind === "error") {
    return <span className="text-destructive text-[10.5px]">{state.message}</span>;
  }
  return (
    // Same box as the two other read-only status blocks in this editor.
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
