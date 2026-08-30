import type { VaultKeyFacts } from "../keyInspect";
import type { VaultAuthMode, VaultIdentity, VaultKey } from "../types";

// What the two vault editors edit, and the pure functions that turn a draft
// into the record and the secrets the store is handed.
//
// Pure - no React, no store, no Tauri - for the same reason `page/derive.ts`
// is: `scripts/vault-draft-verify.ts` exercises every rule below BY VALUE under
// plain node. The dialogs own the fields and the IPC; every decision about what
// gets written lives here, where it can be checked without a DOM.
//
// THE RULE THE WHOLE FILE IS BUILT ON: a blank secret field means "leave
// whatever is stored alone", never "delete it". `writeSecret` (`../store.ts:118-133`)
// reads `undefined` as leave-alone and a blank string as DELETE, so the
// distance between the two is one `if` - and getting it wrong costs a private
// key nobody can put back, because no layer above the keychain ever reads a
// secret and so none of them holds a previous value.
//
// Unlike the host editor there is no keychain SEED here and therefore no
// `touched`/`seeded` pair (`../../hosts/editor/sshSecrets.ts:81-93`): the vault
// store exposes no secret read at all (`../store.ts:39-71`) and `SecretsIo` has
// no single-value read by design (`../adapters.ts:52-61`), so a secret field is
// only ever filled by the user. Blank is unambiguous here in a way it is not
// there.
//
// There is exactly ONE place a blank field is forwarded as a delete, and it is
// argued for at {@link keySecretsForSave}.

/**
 * The identity editor's fields.
 *
 * `password` is the only secret, and it is never seeded - see the file header.
 * `keyId` is `""` when no key is chosen and is kept ACROSS an auth-mode toggle
 * on purpose: flipping key -> password -> key inside one sitting must not lose
 * the key the user picked. What stops that reaching the store is
 * {@link identityRecordFrom}, not this type.
 */
export type IdentityDraft = {
  name: string;
  username: string;
  domain: string;
  authMode: VaultAuthMode;
  password: string;
  keyId: string;
  description: string;
};

/** Always replaced, never mutated in place - the same discipline
 *  `NO_SSH_SECRETS_TOUCHED` (`../../hosts/editor/types.ts:60-64`) is held to. */
export const EMPTY_IDENTITY_DRAFT: IdentityDraft = {
  name: "",
  username: "",
  domain: "",
  authMode: "password",
  password: "",
  keyId: "",
  description: "",
};

/** A stored identity, opened for editing. `password` is deliberately blank and
 *  there is no path that fills it: the vault has no secret read, so blank here
 *  means "leave the stored password alone" and the form says so through
 *  {@link identityPasswordHelp}. */
export function identityDraftFrom(identity: VaultIdentity): IdentityDraft {
  return {
    name: identity.name,
    username: identity.username,
    domain: identity.domain ?? "",
    authMode: identity.authMode,
    password: "",
    keyId: identity.keyId ?? "",
    description: identity.description ?? "",
  };
}

/**
 * The identity form's validation, or `null` when it passes.
 *
 * `name` and `username` are required and the password is not, which is the same
 * split the host editor settled at `SshCredentialSection.tsx:60-99`: a row
 * without a username is MALFORMED - it has no presence flag, no indicator and
 * no path that fills it later - while a row without a password is merely
 * incomplete, is a state the store persists, and is exactly what the Vault
 * page's "Missing secret" badge exists to show (`page/IdentityCard.tsx:92-95`).
 * Refusing it would make that badge unreachable from the UI, which is the
 * present-correct-and-dead shape.
 *
 * `name` is required here and NOT at the store (`../store.ts:197-236` requires
 * only that key auth names a key), so this function is the only guard on it.
 * That asymmetry is admitted rather than hidden: a blank name renders an empty
 * card title and makes the delete refusal fall back to an opaque id
 * (`page/derive.ts:352`).
 */
export function validateIdentityDraft(draft: IdentityDraft): string | null {
  if (!draft.name.trim()) return "Name is required";
  if (!draft.username.trim()) return "Username is required";
  if (draft.authMode === "key" && !draft.keyId) return "Choose a key for key authentication";
  return null;
}

/**
 * The record `upsertIdentity` is handed.
 *
 * `keyId` IS THE POINT OF THIS FUNCTION (VLT-73). `VaultIdentity.keyId`'s doc
 * says "Set when `authMode === 'key'`" (`../types.ts:107-108`) and nothing
 * enforced it: the store refuses key auth with no key and refuses a `keyId`
 * naming a key that does not exist (`../store.ts:208-213`), but it accepts a
 * RESOLVABLE `keyId` on a password identity - which then renders a grey key
 * chip on a row that authenticates with a password
 * (`page/derive.ts:130-134` sets `keyName` from `keyId` alone;
 * `page/IdentityCard.tsx:103` renders the chip from `keyName`). It reads as
 * "this identity signs with that key". It does not.
 *
 * So the mode decides, here, at the write. Nothing is destroyed by it: the
 * `VaultKey` is a separate record (`../types.ts:116`), which is what
 * `deleteNote` already tells the user about a key-auth identity
 * (`page/derive.ts:409-411`). The DRAFT keeps the selection so a toggle inside
 * one sitting costs nothing.
 *
 * `hasPassword` is a placeholder, not a claim: `upsertIdentity` overwrites it
 * with what it actually stored (`../store.ts:218-227`), the same way
 * `HostEditorDialog.tsx:739-741` hands the host store three `false`s.
 */
export function identityRecordFrom(id: string, draft: IdentityDraft): VaultIdentity {
  return {
    id,
    name: draft.name.trim(),
    username: draft.username.trim(),
    domain: draft.domain.trim() || undefined,
    authMode: draft.authMode,
    hasPassword: false,
    keyId: draft.authMode === "key" ? draft.keyId : undefined,
    description: draft.description.trim() || undefined,
  };
}

/**
 * The identity secrets `upsertIdentity` is handed.
 *
 * A blank field is OMITTED, so the store is never given the empty string it
 * reads as a delete. This editor therefore cannot remove a stored password at
 * all, which is a real gap and an old one - VLT-28 - and it is the cautious
 * direction: the alternative is a form where a backspace over a field that was
 * never filled deletes a credential and reports success.
 *
 * Untrimmed on the way out. `writeSecret` trims before it decides
 * (`../store.ts:126`), so trimming again here would only move the decision.
 */
export function identitySecretsForSave(draft: IdentityDraft): { password?: string } {
  return draft.password.trim() === "" ? {} : { password: draft.password };
}

/**
 * The key editor's fields.
 *
 * `privateKey` blank means "leave the stored key alone" on an edit and is
 * refused on a create - {@link validateKeyDraft} says why. The stored body is
 * never read back into this field, for the reason in the file header.
 */
export type KeyDraft = {
  name: string;
  privateKey: string;
  passphrase: string;
  description: string;
};

export const EMPTY_KEY_DRAFT: KeyDraft = {
  name: "",
  privateKey: "",
  passphrase: "",
  description: "",
};

/** A stored key, opened for editing. Both secret fields start blank and nothing
 *  fills them: blank means "leave the stored value alone". */
export function keyDraftFrom(key: VaultKey): KeyDraft {
  return {
    name: key.name,
    privateKey: "",
    passphrase: "",
    description: key.description ?? "",
  };
}

/**
 * The key form's validation, or `null` when it passes.
 *
 * A NAME is required at the store too (`../store.ts:247`) and is repeated here
 * so the message arrives in the form instead of as a rejected promise.
 *
 * A BODY is required only when CREATING, and the asymmetry is the whole rule.
 * On a create, a key with no private key body has no reachable outcome but a
 * failed connect and nothing outside this editor ever fills one in - the same
 * argument the owner upheld twice for the RDP password (VLT-50). On an EDIT,
 * blank is the only way to say "keep the stored key", so it must be allowed;
 * refusing it would mean retyping a PEM to rename a key.
 *
 * Consequence, stated rather than discovered: `missingPrivateKey: true` on a
 * key row stays unreachable from the UI after this wave. It is covered
 * behaviourally in `scripts/vault-page-verify.ts` section 15 and reachable from
 * a hand-written `tervia-vault.json`; 6g's import is the next thing that can
 * produce one.
 */
export function validateKeyDraft(draft: KeyDraft, mode: "create" | "edit"): string | null {
  if (!draft.name.trim()) return "Name is required";
  if (mode === "create" && !draft.privateKey.trim()) return "Paste or import a private key";
  return null;
}

/**
 * The record `upsertKey` is handed.
 *
 * `facts` is `null` when the body was left blank - nothing about the stored key
 * is being replaced, so the three things recorded about it are still true and
 * are carried across unchanged.
 *
 * When `facts` is present the three are replaced WHOLESALE, and that includes
 * being replaced with nothing: `vaultKeyFactsFrom` returns `{}` for a sealed
 * container, and the base record below names none of the three, so they end up
 * absent. Merging the old values under the new ones is the failure this shape
 * exists to prevent - a fingerprint that outlives the key body it described
 * names a key the record no longer holds, and the Vault page would show it next
 * to the new key's name without anything looking wrong.
 *
 * `hasPrivateKey` and `hasPassphrase` are placeholders: `upsertKey` overwrites
 * both with what it actually stored (`../store.ts:158-180`).
 */
export function keyRecordFrom(
  id: string,
  draft: KeyDraft,
  existing: VaultKey | null,
  facts: VaultKeyFacts | null,
): VaultKey {
  const base: VaultKey = {
    id,
    name: draft.name.trim(),
    description: draft.description.trim() || undefined,
    hasPrivateKey: false,
    hasPassphrase: false,
  };
  if (facts === null) {
    return {
      ...base,
      keyType: existing?.keyType,
      fingerprint: existing?.fingerprint,
      publicKey: existing?.publicKey,
    };
  }
  return { ...base, ...facts };
}

/**
 * The key secrets `upsertKey` is handed.
 *
 * THE ONE PLACE THIS EDITOR SENDS A DELETE, and it is deliberate. A passphrase
 * unlocks one particular key body; replacing the body and keeping the old
 * passphrase leaves `hasPassphrase: true` describing a secret that belongs to a
 * key the record no longer holds - the same stale-projection failure
 * {@link keyRecordFrom} refuses for the fingerprint, and worse, because
 * `deleteNote` would then promise to delete a passphrase this key never had
 * (`page/derive.ts:402-406`). So: when the body is replaced, the passphrase
 * field goes down with it, blank included, and blank is the store's clear.
 *
 * When the body is NOT replaced, neither secret is: a blank passphrase leaves
 * the stored one alone, and a typed one replaces it. There is therefore no way
 * to remove a passphrase without replacing the key - VLT-28 again, and the same
 * cautious direction the identity password takes.
 */
export function keySecretsForSave(draft: KeyDraft): {
  privateKey?: string;
  passphrase?: string;
} {
  if (draft.privateKey.trim() === "") {
    return draft.passphrase.trim() === "" ? {} : { passphrase: draft.passphrase };
  }
  return { privateKey: draft.privateKey, passphrase: draft.passphrase };
}

/**
 * What leaving the identity password blank actually does, which is the OPPOSITE
 * thing on the two sides of `hasStoredPassword`.
 *
 * The same split, for the same reason, as `passwordHelp` in
 * `../../hosts/editor/SshCredentialSection.tsx:117-122`: on an identity that
 * has no password, blank saves an identity without one and saying so is the
 * point; on one that HAS a password, blank means the stored value is left
 * exactly as it is, and telling the user "leave blank to save without one"
 * there describes something the save refuses to do.
 */
export function identityPasswordHelp(hasStoredPassword: boolean): string {
  if (hasStoredPassword) {
    return "A password is already stored for this identity, and blank does not remove it: blank means leave it exactly as it is.";
  }
  return "Leave blank to save the identity without one. It is listed with a missing-secret warning until a password is entered.";
}

/** What the private key field does on each side of create/edit. Blank is
 *  required to mean two different things, so it is said twice. */
export function privateKeyHelp(mode: "create" | "edit"): string {
  if (mode === "create") {
    return "Required. A key with no private key body cannot authenticate anything, and nothing outside this editor fills one in later.";
  }
  return "Leave blank to keep the key that is already stored. Pasting or importing a key replaces it, and replaces its passphrase along with it.";
}

/** What the passphrase field does, branched on whether the body above is being
 *  replaced in this same save - the rule {@link keySecretsForSave} enforces,
 *  said in the form rather than left for the user to discover. */
export function passphraseHelp(replacingBody: boolean): string {
  if (replacingBody) {
    return "This passphrase belongs to the key body above. Leaving it blank records this key as having none.";
  }
  return "Leave blank to keep whatever is already stored. Typing here replaces it.";
}
