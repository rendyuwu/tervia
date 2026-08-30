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
