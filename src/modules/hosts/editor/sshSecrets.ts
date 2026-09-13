import type { HostSecretInput } from "../store";
import type { SshCredentialDraft, SshSecretTouched } from "./types";

// The SSH half of the editor's three-state secret convention, lifted out of
// `HostEditorDialog.tsx` so it can be exercised directly rather than described by
// a regex. It is a pure function over three records, and it decides whether a
// stored secret survives a save - which makes a truth table the only honest test
// of it (`scripts/host-editor-verify.ts` section [2]).

/**
 * Which SSH secret fields the keychain seed put a value the user can SEE into.
 *
 * NOT a second copy of {@link SshSecretTouched}, and the distinction is the whole
 * of the rule below. `touched` says the user edited the field; this says the field
 * was showing a stored value when they did. An empty field can mean either "there
 * is nothing stored" or "the read has not landed yet" - and only the first of
 * those makes emptying it an instruction to delete anything.
 *
 * Set by `seedSshSecrets` in `HostEditorDialog.tsx`, every time a keychain read
 * resolves for the row still on screen. There are two such reads, not one: the
 * editor's load for an inline row, and again once a detach has copied an
 * identity's secrets onto this host's own accounts - so a sitting that binds or
 * converts and then detaches sets this twice. A read that throws sets nothing,
 * and neither does one whose row has moved on.
 *
 * REPLACED rather than merged on that second read, which is the safe direction:
 * all three are re-derived from the touched record as it stands then, so a field
 * the user typed into after the first read comes back NOT seeded - and a touched,
 * blank, unseeded field is omitted from the save rather than clearing anything.
 *
 * Always from what that read actually applied: a field the seed YIELDED to
 * (because the user was already typing in it) is not seeded, whatever the
 * keychain returned, because the stored value never reached the screen.
 */
export type SshSecretSeeded = {
  password: boolean;
  privateKey: boolean;
  keyPassphrase: boolean;
};

export const NOTHING_SEEDED: SshSecretSeeded = {
  password: false,
  privateKey: false,
  keyPassphrase: false,
};

/**
 * Whether this field's value is the store's CLEAR instruction rather than a value.
 *
 * Trimmed, because `writeSecret` in the store trims before it decides: a field
 * holding one space deletes the account exactly as an empty one does. Judging
 * emptiness any other way here would leave a space-bar keystroke as a way to reach
 * the delete branch past the rule below.
 */
export function clearsSecret(value: string): boolean {
  return value.trim() === "";
}

/**
 * The SSH secrets to write, three-state per field.
 *
 * THE rule this function exists for: an UNTOUCHED field is `undefined`, which is
 * the store's "leave whatever is stored alone" instruction. The form seeds these
 * three from the keychain, so a save that echoed the seed back would send `""` for
 * any field whose read had not resolved yet - and `""` is the store's CLEAR
 * instruction, not a no-op. An edit that only renamed a host would take its
 * password with it.
 *
 * THE SECOND RULE, and the reason `seeded` is a parameter: **emptying a field is a
 * CLEAR only when the user emptied a value they could see.** `touched` alone
 * cannot say that. It is set by any patch carrying the key, so `onChange({
 * password: "" })` - one character typed and backspaced, a Ctrl+Z after a paste -
 * marks the field touched while it is empty, and the seed may not have landed yet.
 * Sending that `""` deletes the keychain account of a host whose password the user
 * never saw and never meant to touch, and the save reports success. So an empty
 * touched field is only forwarded when the seed put a non-empty value there first;
 * otherwise it is omitted, which is the same "leave it alone" the RDP arm gets for
 * a blank password field.
 *
 * The deliberate clear is untouched by that: open a host, let the seed land, select
 * the password and delete it, and `seeded.password` is true, so `""` goes down and
 * the account is deleted. What is refused is a clear of something that was never
 * on screen.
 *
 * THE KEY BODY NOW LEANS ON THAT RULE THE SAME WAY THE PASSWORD DOES, and it did
 * not before. `validateSshCredential` used to refuse a key-auth save with a blank
 * body, so the blank-and-touched case never reached this function under key auth
 * at all; that rule is gone, for the reason stated there, and this is what stands
 * behind it. Nothing here changed to accommodate that: the rule is per field and
 * was always applied to all three. A body emptied before the seed landed is still
 * omitted, so the stored key survives; a seeded body the user selected and deleted
 * still goes down as `""`, so the key is removed and the card says so.
 *
 * A field the current auth mode does not use is left ALONE rather than cleared,
 * which is the one place this differs from the dialog it came from. Nothing goes
 * unreachable by it: an inline SSH record NAMES all three accounts whatever its
 * auth mode, so the store still releases them when the credential moves to the
 * vault and still deletes them with the host. What it buys is that switching to
 * password auth and back does not cost the user the key they had.
 *
 * `forgetKey` IS THE ONE OVERRIDE OF ALL OF THE ABOVE, and it exists because the
 * route the rules describe DISAPPEARS at exactly the moment it is wanted. Clearing
 * the key textarea and saving works: the field is touched and was seeded, so `""`
 * goes down and the account is deleted. But the textarea is rendered only under
 * key auth, so a host that has moved to a password can no longer reach it - the
 * key stays in the secret store for good and travels in every export. Under this
 * flag both key fields are forced to `""` whatever `touched` and `seeded` say,
 * which is the whole point: the field cannot be touched when it is not on screen.
 *
 * AN EXPLICIT PARAMETER, not a caller that marks the two fields touched and
 * seeded and blanks the draft. Those two records carry a stated meaning - what the
 * user typed, and what the store actually put on screen - and the rule above is
 * the only thing standing between an ordinary save and a deleted password. A
 * caller that lies to them to reach this branch breaks the invariant that
 * licenses every OTHER clear.
 *
 * BOTH KEY FIELDS GO DOWN TOGETHER. A key passphrase with no key body opens
 * nothing and cannot be reached by any field in this editor, so leaving one
 * behind would leave an account no screen names and nothing removes - the same
 * argument the vault's own `keySecretsForSave` makes for the same pair, where a
 * replaced body takes its passphrase with it.
 *
 * THAT RULE IS THE OVERRIDE'S, NOT THIS FUNCTION'S, and the difference is
 * recorded rather than hidden: on the ordinary textarea route a cleared body
 * goes down as `""` while an untouched passphrase is omitted, so the passphrase
 * account survives its key. `KNOWN-LIMITS.md` carries that as an accepted state.
 * Making the two fields travel together HERE, outside `forgetKey`, resolves it -
 * retire the entry in the same change rather than leaving it describing a state
 * the code no longer reaches.
 *
 * IT DOES NOT TOUCH THE PASSWORD. That is the credential the host has moved TO,
 * and it is still decided by `touched`/`seeded` above: a password typed in the
 * same sitting is still sent, and an untouched one is still left alone.
 */
export function sshSecretsForSave(
  cred: SshCredentialDraft,
  touched: SshSecretTouched,
  seeded: SshSecretSeeded,
  forgetKey: boolean,
): HostSecretInput {
  const send = (field: keyof SshSecretSeeded): boolean =>
    touched[field] && (!clearsSecret(cred[field]) || seeded[field]);
  const out: HostSecretInput = {};
  if (send("password")) out.password = cred.password;
  if (forgetKey) {
    out.privateKey = "";
    out.keyPassphrase = "";
    return out;
  }
  if (send("privateKey")) out.privateKey = cred.privateKey;
  if (send("keyPassphrase")) out.keyPassphrase = cred.keyPassphrase;
  return out;
}
