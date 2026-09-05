import { HOST_RDP_SECRET_FIELDS, HOST_SSH_SECRET_FIELDS, type Host } from "../types";
import {
  HOST_RDP_PASSWORD_FIELD,
  HOST_SSH_KEY_PASSPHRASE_FIELD,
  HOST_SSH_PASSWORD_FIELD,
  HOST_SSH_PRIVATE_KEY_FIELD,
  type RdpInlineCredentials,
  type SshInlineCredentials,
} from "@/modules/vault/types";

// The credential picker's own vocabulary, pure: what its value MEANS against a
// stored record, and what pressing "Change credential" would then do.
//
// No React, no store, no Tauri, so `scripts/credential-move-verify.ts`
// exercises every string here BY VALUE, the same discipline
// `vault/page/derive.ts` and `vault/editor/draft.ts` are held to.
//
// CREATE MODE: binding a NEW host to an identity is
// an immediate, unconfirmed pick - there is no stored credential to destroy,
// so `credentialChangeFor(null, choice)` never returns anything but
// `{kind:"none"}`. What a create-mode dialog actually does with the picker's
// value is read `identityIdFromChoice` directly at Save; see that function's
// own comment for the two callers.

/** The picker's value for "this host keeps its own credentials". */
export const CREDENTIAL_CHOICE_INLINE = "";

/** The picker's value for "move these credentials into a new shared identity". */
export const CREDENTIAL_CHOICE_NEW_IDENTITY = "new";

const IDENTITY_CHOICE_PREFIX = "identity:";

/**
 * The picker's value for one identity. Prefixed so it cannot collide with the
 * two sentinels above - an identity id is opaque (`../../vault/store.ts:74-76`)
 * and nothing stops one being the string "new".
 */
export function identityChoice(identityId: string): string {
  return `${IDENTITY_CHOICE_PREFIX}${identityId}`;
}

/**
 * The identity id one picker value names, or `null` for either sentinel.
 *
 * Two callers. The picker's own change handler turns a selection back into an
 * id; `HostEditorDialog`'s `boundIdentity`, in CREATE MODE ONLY, reads this
 * straight off the draft picker value at Save - a `null`
 * return there is what makes an unbound new host build an inline credential
 * instead of a binding, with no separate "create mode" branch anywhere in
 * this file.
 */
export function identityIdFromChoice(choice: string): string | null {
  return choice.startsWith(IDENTITY_CHOICE_PREFIX)
    ? choice.slice(IDENTITY_CHOICE_PREFIX.length)
    : null;
}

/** What the picker shows as selected for the record as it stands. `null` (no
 *  record yet, i.e. create mode) and an inline record both read as "own
 *  credentials". */
export function currentCredentialChoice(host: Host | null): string {
  if (!host) return CREDENTIAL_CHOICE_INLINE;
  return host.credential.kind === "identity"
    ? identityChoice(host.credential.identityId)
    : CREDENTIAL_CHOICE_INLINE;
}

export type CredentialChange =
  | { kind: "none" }
  | { kind: "convert" }
  | { kind: "bind"; identityId: string }
  | { kind: "detach"; identityId: string };

/**
 * What pressing "Change credential" would do, from the STORED record and the
 * picker's value. `{kind:"none"}` when the picker is on what is already true,
 * and for every combination the UI must not offer.
 *
 * `host === null` is create mode, and it always answers `{kind:"none"}`:
 * there is no stored credential to convert, destroy or bind
 * away from immediately, so the picker's value takes effect only at Save,
 * read directly through {@link identityIdFromChoice}.
 */
export function credentialChangeFor(host: Host | null, choice: string): CredentialChange {
  if (!host) return { kind: "none" };

  const current = currentCredentialChoice(host);
  if (choice === current) return { kind: "none" };

  const boundTo = host.credential.kind === "identity" ? host.credential.identityId : null;

  if (choice === CREDENTIAL_CHOICE_NEW_IDENTITY) {
    // A bound host owns nothing to move - convert only makes sense from
    // inline, and an inline record's `current` is already
    // CREDENTIAL_CHOICE_INLINE, never this branch's `choice`.
    return boundTo ? { kind: "none" } : { kind: "convert" };
  }
  if (choice === CREDENTIAL_CHOICE_INLINE) {
    // Only reached with `boundTo` set: an inline record's `current` IS this
    // value, so it would already have matched `current` above.
    return boundTo ? { kind: "detach", identityId: boundTo } : { kind: "none" };
  }
  const identityId = identityIdFromChoice(choice);
  return identityId ? { kind: "bind", identityId } : { kind: "none" };
}

/** The user-facing word for one keychain field, in the order it is enumerated. */
function secretFieldWord(field: string): string {
  switch (field) {
    case HOST_SSH_PASSWORD_FIELD:
      return "password";
    case HOST_SSH_PRIVATE_KEY_FIELD:
      return "private key";
    case HOST_SSH_KEY_PASSPHRASE_FIELD:
      return "key passphrase";
    default:
      return field;
  }
}

function sshOwnedFlag(credential: SshInlineCredentials, field: string): boolean {
  if (field === HOST_SSH_PASSWORD_FIELD) return credential.hasPassword;
  if (field === HOST_SSH_PRIVATE_KEY_FIELD) return credential.hasPrivateKey;
  return credential.hasKeyPassphrase;
}

function rdpOwnedFlag(credential: RdpInlineCredentials, field: string): boolean {
  return field === HOST_RDP_PASSWORD_FIELD && credential.hasPassword;
}

/**
 * Every account the stored record owns, by name, for the bind confirmation to
 * enumerate. Empty for a vault-bound host, which owns none.
 *
 * Enumerated from {@link HOST_SSH_SECRET_FIELDS} / {@link HOST_RDP_SECRET_FIELDS}
 * rather than listing the three flags by hand, so a field added to either list
 * is picked up here for free.
 */
export function hostOwnedSecretNames(host: Host): string[] {
  if (host.credential.kind !== "inline") return [];
  if (host.protocol === "rdp") {
    const credential = host.credential;
    return HOST_RDP_SECRET_FIELDS.filter((f) => rdpOwnedFlag(credential, f)).map(secretFieldWord);
  }
  const credential = host.credential;
  return HOST_SSH_SECRET_FIELDS.filter((f) => sshOwnedFlag(credential, f)).map(secretFieldWord);
}

/**
 * The KEY MATERIAL a stored record still holds, by name, in the order
 * {@link HOST_SSH_SECRET_FIELDS} enumerates it.
 *
 * Read off the STORED record's own flags, which is what the row this feeds must
 * be a function of: the editor's draft holds a key body seeded at open time, and
 * a draft that is blank because the read has not landed says nothing at all about
 * whether an account exists.
 *
 * Empty for every record that must not be offered a Forget, and each arm is one
 * of those cases rather than a belt: a vault-bound host owns no accounts of its
 * own (`bind` deleted them and said so), and an RDP host owns one password field
 * and never held key material. An SSH host with neither flag set has nothing to
 * forget, so the same empty list covers it.
 *
 * The two fields are named POSITIVELY and then ordered through
 * {@link HOST_SSH_SECRET_FIELDS}, rather than filtering the password out of that
 * list: a fourth SSH secret added later is not key material by default, and
 * having it appear in a row that offers to delete it would be the wrong
 * direction to fail in.
 */
export function hostKeySecretNames(host: Host): string[] {
  if (host.protocol !== "ssh" || host.credential.kind !== "inline") return [];
  const credential = host.credential;
  const keyFields: readonly string[] = [HOST_SSH_PRIVATE_KEY_FIELD, HOST_SSH_KEY_PASSPHRASE_FIELD];
  return HOST_SSH_SECRET_FIELDS.filter(
    (f) => keyFields.includes(f) && sshOwnedFlag(credential, f),
  ).map(secretFieldWord);
}

export function credentialChangeTitle(change: CredentialChange): string {
  switch (change.kind) {
    case "convert":
      return "Move this host's credentials into a new identity?";
    case "bind":
      return "Switch to a shared identity?";
    case "detach":
      return "Stop using this shared identity?";
    case "none":
      return "";
  }
}

/** "a" / "a and b" / "a, b, and c", plus the verb that agrees with the count -
 *  a shared comma-join reads as correct for two items and silently wrong for
 *  three or for one, which is exactly the property
 *  `scripts/credential-move-verify.ts` checks by value. */
function joinWithVerb(names: readonly string[]): { list: string; verb: string } {
  if (names.length === 0) return { list: "credentials", verb: "are" };
  if (names.length === 1) return { list: names[0], verb: "is" };
  if (names.length === 2) return { list: `${names[0]} and ${names[1]}`, verb: "are" };
  const last = names[names.length - 1];
  const head = names.slice(0, names.length - 1);
  return { list: `${head.join(", ")}, and ${last}`, verb: "are" };
}

/** `identityName`, or the id when the name is not known (an identity found by
 *  id alone, with no record loaded to read a name off). */
function identityLabel(identityName: string | undefined, identityId: string): string {
  return identityName ?? identityId;
}

/**
 * The confirmation body. One string per outcome, each naming exactly what
 * happens and what does not, because the three outcomes differ in what is
 * destroyed and a shared sentence would be wrong for two of them.
 *
 * CONVERT SAYS THE DRAFT IS NOT INVOLVED, out loud and in its own sentence. What
 * travels is the host's stored keychain accounts, so a private key typed into
 * the editor and not yet saved goes nowhere - and the editor cannot show it
 * going nowhere either, because a converted row is bound and renders no key
 * field at all. The word "stores" carried that on its own before, which is one
 * word doing the work of a promise.
 */
export function credentialChangeNote(
  change: CredentialChange,
  identityName: string | undefined,
  ownedSecrets: readonly string[],
): string {
  switch (change.kind) {
    case "convert":
      return "The credentials this host stores move into a new shared identity, and the host stops owning them. What moves is what is saved for this host, so a key body typed into the form and not yet saved is not moved, and is discarded. Nothing here is deleted until the move has succeeded. This happens as soon as you confirm - cancelling the editor afterwards does not undo it, and what it buys is fewer copies of one credential, nothing else.";
    case "bind": {
      const identity = identityLabel(identityName, change.identityId);
      const { list, verb } = joinWithVerb(ownedSecrets);
      return `This host stops using its own stored credentials and authenticates as "${identity}" instead. Its own stored ${list} ${verb} deleted and cannot be brought back from here. This happens as soon as you confirm - cancelling the editor afterwards does not undo it.`;
    }
    case "detach": {
      const identity = identityLabel(identityName, change.identityId);
      return `This host stops using "${identity}" and takes its own copy of that identity's stored secrets. The identity itself is not changed and every other host bound to it keeps working. This happens as soon as you confirm - cancelling the editor afterwards does not undo it.`;
    }
    case "none":
      return "";
  }
}

/**
 * What the forget-key row holds, as its own one-line label - the counterpart of
 * the fingerprint the recorded-key row shows.
 *
 * Through {@link joinWithVerb} rather than a comma-join of its own, because a
 * list of one and a list of two are the two cases this row actually has and a
 * shared join reads as correct for one of them and silently wrong for the other.
 */
export function forgetKeyRowLabel(keySecrets: readonly string[]): string {
  return `Stored ${joinWithVerb(keySecrets).list}`;
}

/**
 * What the forget-key row says, on both sides of the button having been pressed.
 *
 * A function of the FLAGS rather than one fixed sentence, for the reason the row
 * exists at all: a stored key passphrase with no stored key body is the same
 * orphan and gets the same row, and a sentence naming a private key would be
 * describing something that is not there.
 *
 * Three things, in both arms. WHAT IS STORED, because this row is the only place
 * it is said. That this host does not authenticate with it - true by PLACEMENT
 * rather than by anything passed in here: the row renders only in the auth modes
 * that have no key field at all, which is what `scripts/host-editor-verify.ts`
 * pins structurally. And that SAVE is what deletes it, which is the whole
 * difference between this and a button that writes as it is pressed: the press
 * records an intent in the editor, and cancelling the editor discards it.
 */
export function forgetKeyNote(keySecrets: readonly string[], forgetting: boolean): string {
  const { list, verb } = joinWithVerb(keySecrets);
  if (forgetting) {
    return `The stored ${list} ${verb} deleted when you save, and nothing in Tervia undoes that deletion. Cancelling this editor instead leaves the stored ${list} alone.`;
  }
  return `This host does not authenticate with a key, so the stored ${list} ${verb} never read. Forget deletes the stored ${list} when you save, and nothing in Tervia undoes that deletion.`;
}
