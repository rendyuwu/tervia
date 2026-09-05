import type { Host } from "@/modules/hosts/types";

import type { VaultIdentity, VaultKey, VaultRef } from "./types";

// Who references what, as pure functions over plain data.
//
// These are the SINGLE definitions of three questions that already have, or are
// about to have, two callers each: the delete guard that refuses to remove an
// identity a host still binds to, and the Vault page that has to say WHICH hosts
// those are; the delete guard that refuses to remove a key an identity still
// names, and the page's usage list; and the presence question a credential pip
// asks, which the Hosts page already asks and the Vault page is about to.
//
// One definition per question, because a shared answer that each caller derives
// separately is not shared at all - a delete refused for reasons the page does not
// list, or a page listing holders a delete does not refuse for, is worse than
// either alone.
//
// `keyNeedsPassphrase` is a FOURTH question and does not yet have two callers -
// the key card is the only surface that asks it. It lives here anyway because it
// is the same KIND of question as the pip beside it, read off the same record's
// flags, and because the next surface that needs it (the editors' recovery copy)
// must not answer it a second, differently-worded way.
//
// The `Host` import is TYPE-ONLY and must stay that way: `modules/hosts` imports
// the binding union from `modules/vault/types`, so a value import here would close
// a runtime cycle. A type import is erased and closes nothing.

/** A record named well enough for a refusal to be actionable rather than merely
 *  correct. */
export function toVaultRef(record: { id: string; name: string }): VaultRef {
  return { id: record.id, name: record.name };
}

/**
 * Every host bound to one identity, across both protocols.
 *
 * The predicate is `credential.kind === "identity"` and a matching `identityId`,
 * which is the same test on an SSH row and an RDP row - the binding union is
 * shared even though the inline arms are not.
 */
export function hostsUsingIdentity(hosts: readonly Host[], identityId: string): VaultRef[] {
  return hosts
    .filter((h) => h.credential.kind === "identity" && h.credential.identityId === identityId)
    .map(toVaultRef);
}

/** Every identity that names one key. A key is only ever referenced by an
 *  identity, never by a host directly. */
export function identitiesUsingKey(
  identities: readonly VaultIdentity[],
  keyId: string,
): VaultRef[] {
  return identities.filter((i) => i.keyId === keyId).map(toVaultRef);
}

/**
 * Does this key name a private half it does not have?
 *
 * One line, and extracted anyway, because two surfaces ask it: the Vault page's
 * key row shows a pip for it, and {@link identityMissingSecret} below asks the
 * same question of whichever key an identity names. Two implementations of one
 * question is how a delete refused for reasons a page does not show gets
 * shipped - and here it would be worse than inconsistent, because the two pips
 * sit on the same screen, one row above the other.
 *
 * From the `has*` flag on the record and NEVER from a keychain read, for the
 * reason {@link identityMissingSecret} gives.
 *
 * `hasPassphrase` is deliberately not part of the answer: a key with no
 * passphrase is a key with no passphrase, not a key that is missing one.
 */
export function keyMissingSecret(key: VaultKey): boolean {
  return !key.hasPrivateKey;
}

/**
 * Does this key record an ENCRYPTED body with no passphrase stored?
 *
 * A SIBLING of {@link keyMissingSecret}, deliberately not a widening of it.
 * That one feeds {@link identityMissingSecret}, and an encrypted key whose
 * passphrase is missing is not a key with no private half - it has one. Folding
 * this in there would replace one false statement about the record with a
 * different one.
 *
 * THE PRIVATE HALF IS A CONJUNCT, not an assumption, because a record with
 * `encrypted: true` and NO stored body is reachable: an import whose secret did
 * not land keeps the file's `encrypted` while forcing both presence flags false
 * (`sanitizeKey` in `modules/backup/file.ts`), and a hand-written
 * `tervia-vault.json` can say the same. That row has no passphrase question to
 * answer - there is no body a passphrase could unlock - and
 * {@link keyMissingSecret} is what speaks for it, correctly and already.
 * Without the conjunct both predicates fire on it at once and the key card's
 * remedy is FALSE: it tells the user the key fails every connect until its
 * passphrase is entered, and entering one stores it, turns this predicate
 * `false` and takes the warning away while the row still cannot authenticate.
 * So exactly one of the two speaks for any given row.
 *
 * Asked THROUGH {@link keyMissingSecret} rather than off the presence flag a
 * second time, for the reason the `key` arm of {@link identityMissingSecret}
 * delegates to it: the private-half question has one definition in this module,
 * and a second direct read is how two answers to it come to disagree. It also
 * makes the sentence above structural rather than a coincidence of two reads -
 * this predicate is false wherever that one is true, by construction.
 *
 * A record in this state fails every connect until the passphrase is stored.
 * That IS recoverable - `keySecretsForSave` in `editor/draft.ts` forwards a lone
 * passphrase, so the key editor can add one to a stored key without replacing
 * the body - and this predicate is what makes it findable: nothing else on a
 * saved record distinguishes the row that needs that from a key that simply has
 * no passphrase. `encryptedKeyRefusal` in the same file blocks the two EDITOR
 * routes into the state. An IMPORT cannot be gated the same way because it
 * inspects nothing at all (`sanitizeKey` again, which reads a file). A
 * HOST-TO-VAULT CONVERSION can, on ONE of its arms: `applyCredentialChange` in
 * `modules/hosts/HostEditorDialog.tsx` inspects the stored body for the facts it
 * mints onto the new key - but only while the key field still holds that body
 * unedited - with the host's own stored passphrase seeded beside it, so there it
 * could refuse and deliberately does not: the host already holds that encrypted
 * body with no passphrase, so the convert MOVES the state rather than creating
 * it. On THAT arm this predicate is what makes not refusing safe: the minted
 * record carries `encrypted: true` with `hasPassphrase: false`, and the key card
 * reports it. On the arms where the inspection is skipped - the field was
 * touched, which one keystroke does - or throws, the mint gets no facts at all,
 * so the record carries no `encrypted`, this predicate answers `false` for it,
 * and nothing reports the state. Absent is the honest answer there, because
 * nobody inspected the material that travelled; what is missing is a report, not
 * a refusal. `scripts/vault-draft-verify.ts` section 10 holds both arms.
 *
 * `encrypted === true`, never a truthiness test: {@link VaultKey.encrypted} is
 * three-state, absent means no inspection ever answered, and the store reads
 * `tervia-vault.json` without re-validating it, so a hand-edited file can put a
 * non-boolean there. Absent and a non-boolean both answer `false` here - the
 * honest answer, since nothing has established the body is encrypted. The same
 * `=== true` is what `vaultKeyStamp` in `./types.ts` tests for its third flag
 * character, so the stamp and this predicate cannot read one field by two rules.
 */
export function keyNeedsPassphrase(key: VaultKey): boolean {
  return !keyMissingSecret(key) && key.encrypted === true && !key.hasPassphrase;
}

/**
 * Does this identity name a secret it does not have?
 *
 * Answered from the `has*` flags on the records and NEVER from a keychain read.
 * That is what the flags are for: a page rendering a hundred rows must not issue a
 * secret read per row, and a pip computed from a read-back would also be wrong more
 * often, not less - it would report "fine" for a keychain that happens to be
 * unlocked and "missing" for one that is not.
 *
 * The `never` default is the same guarantee `resolve.ts` gives itself: a fourth
 * auth mode stops this compiling until it is handled, rather than falling off the
 * end and quietly reporting "nothing missing".
 */
export function identityMissingSecret(
  identity: VaultIdentity,
  keys: ReadonlyMap<string, VaultKey>,
): boolean {
  switch (identity.authMode) {
    case "agent":
      // Never missing, and not a shortcut: the local ssh-agent holds the key and
      // signs the handshake, so there is no secret for this record to be missing.
      return false;
    case "password":
      return !identity.hasPassword;
    case "key": {
      if (!identity.keyId) return true;
      const key = keys.get(identity.keyId);
      // Through the shared leaf, so the pip on an identity row and the pip on
      // the key row it points at cannot disagree.
      return !key || keyMissingSecret(key);
    }
    default: {
      const unhandled: never = identity.authMode;
      throw new Error(`vault: unhandled auth mode ${String(unhandled)}`);
    }
  }
}
