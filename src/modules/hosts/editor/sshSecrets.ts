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
 * Set once, when the seed resolves, from what the seed actually applied: a field
 * the seed YIELDED to (because the user was already typing in it) is not seeded,
 * whatever the keychain returned, because the stored value never reached the
 * screen.
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
 * A field the current auth mode does not use is left ALONE rather than cleared,
 * which is the one place this differs from the dialog it came from. Nothing goes
 * unreachable by it: an inline SSH record NAMES all three accounts whatever its
 * auth mode, so the store still releases them when the credential moves to the
 * vault and still deletes them with the host. What it buys is that switching to
 * password auth and back does not cost the user the key they had.
 */
export function sshSecretsForSave(
  cred: SshCredentialDraft,
  touched: SshSecretTouched,
  seeded: SshSecretSeeded,
): HostSecretInput {
  const send = (field: keyof SshSecretSeeded): boolean =>
    touched[field] && (!clearsSecret(cred[field]) || seeded[field]);
  const out: HostSecretInput = {};
  if (send("password")) out.password = cred.password;
  if (send("privateKey")) out.privateKey = cred.privateKey;
  if (send("keyPassphrase")) out.keyPassphrase = cred.keyPassphrase;
  return out;
}
