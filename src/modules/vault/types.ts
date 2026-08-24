// The vault: named credentials, owned by nobody and referenced by hosts.
//
// Two records in one store file. A VaultIdentity is "who I log in as"; a VaultKey
// is a private key, stored ONCE and shared by every identity that uses it.
//
// What this buys is FEWER COPIES of the same secret, not a stronger secret. On
// Linux a private key sits in a mode-0600 JSON file before and after this work,
// and the SSH connect path still round-trips plaintext through JS on every
// connect and every ProxyJump hop (issues/11). Nothing here changes either.

export const VAULT_STORE_PATH = "tervia-vault.json";
export const VAULT_IDENTITIES_KEY = "identities";
export const VAULT_KEYS_KEY = "keys";

/** Secret service for everything the vault owns. */
export const VAULT_KEYRING_SERVICE = "tervia-vault";

/**
 * Secret service for credentials a HOST owns itself (an inline binding).
 *
 * Declared here rather than in the host module because `resolve.ts` owns the
 * binding union and is the thing that dereferences these accounts; the host store
 * imports the constant from here so there is exactly one spelling of it.
 */
export const HOST_KEYRING_SERVICE = "tervia-hosts";

/** Vault-owned fields. */
export const IDENTITY_PASSWORD_FIELD = "password";
export const KEY_PRIVATE_KEY_FIELD = "privateKey";
export const KEY_PASSPHRASE_FIELD = "passphrase";

/**
 * Host-owned SSH fields. Note the passphrase: `keyPassphrase` here, plain
 * `passphrase` on a vault key.
 *
 * The two differ on purpose: an account is named after the presence flag that
 * tracks it, so `hasKeyPassphrase` -> `keyPassphrase` on a host and
 * `hasPassphrase` -> `passphrase` on a key. That keeps the mapping mechanical on
 * both sides instead of memorable on one.
 */
export const HOST_SSH_PASSWORD_FIELD = "password";
export const HOST_SSH_PRIVATE_KEY_FIELD = "privateKey";
export const HOST_SSH_KEY_PASSPHRASE_FIELD = "keyPassphrase";

/**
 * Host-owned RDP password field. Same VALUE as the SSH one today, and a separate
 * constant because a merged host row can carry both protocols: if it ever turns
 * out that one machine needs a different password per protocol, this is the one
 * line that changes rather than every call site.
 */
export const HOST_RDP_PASSWORD_FIELD = "password";

/**
 * Every keychain field one identity can own, and every field one key can own,
 * each in one list so a caller that has to enumerate them cannot miss one. Same
 * reason `SSH_SECRET_FIELDS` exists, and the same caller will need these: an
 * export builds a keychain reference per field, and a field left out simply does
 * not travel.
 */
export const VAULT_IDENTITY_SECRET_FIELDS = [IDENTITY_PASSWORD_FIELD] as const;
export const VAULT_KEY_SECRET_FIELDS = [KEY_PRIVATE_KEY_FIELD, KEY_PASSPHRASE_FIELD] as const;

/**
 * `<id>::<field>`, the app-wide keychain account shape. Exported because
 * `resolve.ts` hands the RDP path a REFERENCE instead of a value, so the string
 * itself travels; `secrets_get_all` batching also depends on nothing more than
 * the account list being enumerable.
 */
export function vaultAccount(id: string, field: string): string {
  return `${id}::${field}`;
}

/**
 * How an identity proves who it is.
 *
 * The same three modes the SSH connection store names, and kept in step BY HAND:
 * nothing here imports from `modules/ssh` and nothing there imports from here, so
 * NO compiler check spans the two. Claiming one would be worse than admitting
 * there isn't one.
 *
 * What is checked is narrower and entirely local: every switch over this union in
 * `resolve.ts` ends in a `never` assignment, so adding a mode HERE fails to
 * compile until each mapping handles it. A mode added on the SSH side alone is
 * invisible to `tsc` and has to be caught in review.
 *
 * RDP only ever uses a password.
 */
export type VaultAuthMode = "password" | "key" | "agent";

/** A named way of proving who you are. Referenced by hosts, never owned by one. */
export type VaultIdentity = {
  id: string;
  /** Shown wherever a host names its credential ("root @ prod", "rendy (admin)"). */
  name: string;
  username: string;
  /** NetBIOS/DNS domain. RDP only; absent for a local account or a UPN username. */
  domain?: string;
  authMode: VaultAuthMode;
  /**
   * Password at `tervia-vault :: <id>::password`.
   *
   * Independent of `authMode` on purpose: one identity can be a key over SSH and
   * the same account's password over RDP, which is the whole point of sharing it
   * across protocols.
   */
  hasPassword: boolean;
  /** Set when `authMode === "key"`. Names a {@link VaultKey}. */
  keyId?: string;
  description?: string;
};

/** What `ssh_key_inspect` reports. Display only. */
export type VaultKeyType = "rsa" | "ed25519" | "ecdsa" | "unknown";

/** A private key, stored once and shared by every identity that uses it. */
export type VaultKey = {
  id: string;
  /** Referenced by NAME across many hosts, so a duplicate is a real usability
   *  failure - see the collision warning in `store.ts`. */
  name: string;
  keyType?: VaultKeyType;
  /** `SHA256:<base64, unpadded>` of the public half. Display, and duplicate
   *  detection at import. */
  fingerprint?: string;
  /** Non-secret, so it lives in the store: shown, copyable, pasteable straight
   *  into `authorized_keys`. */
  publicKey?: string;
  /** Private key at `tervia-vault :: <id>::privateKey`. */
  hasPrivateKey: boolean;
  /** Passphrase at `tervia-vault :: <id>::passphrase`. */
  hasPassphrase: boolean;
  description?: string;
};

/** A reference to a shared vault identity. */
export type VaultIdentityBinding = { kind: "identity"; identityId: string };

/**
 * SSH credentials one host owns alone. Flags only - the secrets themselves live
 * under `tervia-hosts :: <hostId>::<field>`.
 *
 * `hostId` is part of the binding rather than a second argument alongside it,
 * which removes the RESOLVE-time mismatch entirely: no call site can hand the
 * resolver one host's binding and another host's id.
 *
 * It does NOT remove the mismatch, it moves it to write time, where nothing in
 * the type system catches it. The live hazard is a spread copy: a duplicate-host
 * action written as `{ ...source, id: newId() }` carries `hostId` verbatim, so the
 * copy's binding names the SOURCE host. Resolution then reads the source's
 * accounts while the copy's own secrets sit under the new id, unread - rotating
 * the source's password changes the copy's, and deleting the source deletes what
 * the copy authenticates with. No error anywhere.
 *
 * So the pair is enforced on WRITE, by the host store, which must call
 * {@link assertBindingOwner} on every upsert; a duplicate must rewrite `hostId`
 * alongside `id`. This type is not the enforcement and cannot be.
 */
export type SshInlineCredentials = {
  kind: "inline";
  /** The host these accounts belong to. See the note above. */
  hostId: string;
  user: string;
  authMode: VaultAuthMode;
  hasPassword: boolean;
  hasPrivateKey: boolean;
  hasKeyPassphrase: boolean;
};

/** RDP credentials one host owns alone. Carries its `hostId` for the same reason
 *  {@link SshInlineCredentials} does. */
export type RdpInlineCredentials = {
  kind: "inline";
  hostId: string;
  username: string;
  domain?: string;
  hasPassword: boolean;
};

/**
 * How a host proves who it is: a shared identity, or credentials it owns itself.
 *
 * These live HERE, not in the host module, and the host module imports them:
 * `resolve.ts` is what turns one of these into something the connect path can use,
 * so it owns them. The inline arm is protocol-specific because the two protocols
 * have genuinely different invariants - SSH needs an auth mode, RDP needs a domain.
 *
 * Two unions, and deliberately NO third one combining them: both inline arms carry
 * `kind: "inline"`, so a combined union does not narrow - a `kind === "inline"`
 * guard over it leaves `SshInlineCredentials | RdpInlineCredentials`, where `user`
 * and `username` are each a type error. A host record holds one of each instead.
 */
export type SshCredentialBinding = VaultIdentityBinding | SshInlineCredentials;
export type RdpCredentialBinding = VaultIdentityBinding | RdpInlineCredentials;

/**
 * Refuse a binding whose `hostId` names a host other than the one storing it.
 *
 * The write-time half of the invariant {@link SshInlineCredentials} describes, and
 * the only half there is: call this on EVERY host upsert, for every binding the
 * record carries. Nothing else can catch a spread copy that took `hostId` along.
 *
 * `ownerId` is a required parameter for the reason {@link IdentityHostRefs} is:
 * a caller allowed to omit it would skip the guard silently, and the guard is the
 * only thing standing between a duplicated host and secrets it shares with the
 * original without saying so. Both ids must be present - `"" === ""` would
 * otherwise pass a half-built record straight through.
 */
export function assertBindingOwner(
  binding: SshCredentialBinding | RdpCredentialBinding,
  ownerId: string,
): void {
  if (binding.kind !== "inline") return;
  if (!ownerId || !binding.hostId) {
    throw new Error("vault: inline credentials need a host id on both sides to be checked");
  }
  if (binding.hostId !== ownerId) {
    throw new Error(
      `vault: inline credentials belong to host ${binding.hostId} but are being stored on ` +
        `host ${ownerId} - a copy that did not rewrite hostId reads the ORIGINAL host's secrets`,
    );
  }
}

/** Something that holds a reference, named well enough for a refusal to be
 *  actionable rather than merely correct. */
export type VaultRef = { id: string; name: string };

/**
 * The hosts that reference one identity.
 *
 * INJECTED, never imported. The host store does not exist yet, and once it does it
 * will import {@link SshCredentialBinding} and {@link RdpCredentialBinding} from
 * this module - so a vault -> hosts import would close a cycle. The wiring is
 * `(id) => listHosts().then((hosts) => hosts.filter(usesIdentity(id)).map(toRef))`.
 *
 * Required, never optional: a caller allowed to pass nothing would silently skip
 * the guard, and the guard is the only thing between one confirmed delete and a
 * host that can no longer connect.
 */
export type IdentityHostRefs = (identityId: string) => VaultRef[] | Promise<VaultRef[]>;

/**
 * A delete refused because something still points at the record, naming what.
 *
 * Refuse, never cascade. Cascading turns one confirmed delete into silent
 * breakage of hosts the user was not looking at, and re-entering a credential
 * costs far more than clearing the references first.
 */
export class VaultInUseError extends Error {
  readonly holders: VaultRef[];

  constructor(subject: string, holderKind: "identity" | "host", holders: VaultRef[]) {
    const noun =
      holders.length === 1 ? holderKind : holderKind === "identity" ? "identities" : "hosts";
    const named = holders.map((h) => h.name || h.id).join(", ");
    super(`cannot delete ${subject}: still used by ${holders.length} ${noun} (${named})`);
    this.name = "VaultInUseError";
    this.holders = holders;
  }
}
