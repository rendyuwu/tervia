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
  // A BLANK PASSWORD IS DELIBERATELY ALLOWED, and the missing rule here is the
  // fix rather than an omission. `hasPassword: false` on an inline password-auth
  // row is a state the store persists and the Hosts page renders - the card shows
  // "Missing secret" and reads the stored flag, not the keychain - so refusing it
  // made the one state that indicator exists for unreachable from the UI, while
  // leaving no way to save a host now and store its password later.
  //
  // What a connect then does, stated correctly because the earlier version of this
  // comment claimed the wrong thing: it never reaches the server. `resolve.ts` maps
  // an empty secret to `undefined`, and `session.rs`'s `connect` pre-flights that -
  // `ssh: no credentials: set use_agent, password, or private_key` - before any
  // socket is opened. Better than the authentication failure this used to promise,
  // since nothing is sent and nothing looks like a rejected login, but it is a
  // different message and the reasoning here should name the one that happens.
  //
  // Key auth is NOT relaxed with it. `hasPrivateKey: false` renders the same pip,
  // so this is a scope boundary and not a correctness one: it is a second
  // behaviour change, it needs its own hand test of what the connect reports for
  // an empty key body, and the reported defect (test C8) is about password auth.
  if (draft.authMode === "key" && !draft.privateKey.trim())
    return "Private key body is required for key auth";
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

export function SshCredentialSection({
  boundIdentity,
  value,
  onChange,
  hasStoredPassword,
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
  if (boundIdentity) return <VaultBindingPanel identityId={boundIdentity} />;

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
    </>
  );
}

/**
 * What stands in for the user and credential fields when the row is bound to a
 * shared vault identity.
 *
 * Read-only on purpose, and it says which parts of the form still work: the
 * alternative was refusing to open the dialog at all, which would leave an
 * imported host unable to be renamed or re-pointed until the identity picker
 * ships. The identity is named by id rather than by name because resolving the
 * name means a vault read, and a dialog that cannot edit the binding does not
 * need to load it.
 */
function VaultBindingPanel({ identityId }: { identityId: string }) {
  return (
    <Field label="Credential">
      {/* Same box as the two other read-only status blocks in this editor. */}
      <div className="border-border/60 bg-muted/30 flex flex-col gap-1 rounded-md border px-2 py-1.5">
        <span className="text-[11px]">This host uses a shared vault identity.</span>
        <span className="text-muted-foreground truncate font-mono text-[10.5px]" title={identityId}>
          {identityId}
        </span>
      </div>
      <span className="text-muted-foreground text-[10.5px]">
        The user and the credential belong to the identity, so neither is editable here and Test
        cannot run - choosing or changing an identity arrives with the Vault page. Everything else
        on this form is editable, and saving leaves the binding exactly as it is.
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
