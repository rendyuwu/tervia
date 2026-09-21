import { vaultStore } from "./store";
import {
  HOST_KEYRING_SERVICE,
  HOST_RDP_PASSWORD_FIELD,
  HOST_SSH_KEY_PASSPHRASE_FIELD,
  HOST_SSH_PASSWORD_FIELD,
  HOST_SSH_PRIVATE_KEY_FIELD,
  IDENTITY_PASSWORD_FIELD,
  KEY_PASSPHRASE_FIELD,
  KEY_PRIVATE_KEY_FIELD,
  VAULT_KEYRING_SERVICE,
  vaultAccount,
  type RdpCredentialBinding,
  type SshCredentialBinding,
  type VaultAuthMode,
  type VaultIdentity,
  type VaultKey,
} from "./types";

// One module, one job: turn a credential binding into what the connect path
// needs.
//
// Both protocols get REFERENCES. `rdp_open` and `ssh_open` take a keychain
// service/account and the host process reads the plaintext itself, so no saved
// credential enters the webview on a connect. That is preserved BY
// CONSTRUCTION here: this module makes no keychain read at all - it imports no
// secrets port and has nowhere to put one.
//
// This module deliberately imports NOTHING from another feature module. The
// dependency direction is vault <- hosts: `modules/hosts` imports the binding
// unions and the two output types from here, never the reverse. So the SSH
// credential shape and the auth-mode mapping that fills it are DECLARED here
// rather than borrowed from a connection store, which is also what lets them
// outlive one.

/**
 * Exactly the keychain reference `rdp_open` accepts, and deliberately NOT
 * `rdp/bridge.ts`'s wider `RdpCredential`: that union also has an `inline`
 * variant carrying a plaintext password, and leaving it out means no later edit
 * to this file can put one in the webview without changing this type first.
 */
export type KeychainRef = { kind: "keychain"; service: string; account: string };

/**
 * Where one secret comes from, as `ssh_open` accepts it: a reference the host
 * process dereferences itself, or a plaintext the caller is holding. The
 * inline arm exists for ONE case - the host editor's Test button, where the
 * user has just typed a credential that is not saved anywhere yet - and is
 * never reachable from a saved binding: neither producer below emits one.
 */
export type SecretSource = KeychainRef | { kind: "inline"; value: string };

/**
 * What the RDP connect path needs. `username` and `domain` are VALUES because
 * `rdp_open` takes them as separate arguments alongside the credential; only the
 * password is a reference.
 */
export type ResolvedRdpAuth = {
  username: string;
  domain?: string;
  credential: KeychainRef;
};

/**
 * Secrets as they come out of the keychain, before an auth mode decides which of
 * them the handshake is actually given.
 */
export type SshSecretValues = {
  password?: string | null;
  privateKey?: string | null;
  keyPassphrase?: string | null;
};

/**
 * The credential half of an `openSsh` input.
 *
 * Owned here, and exported, because this is the one place that knows how a
 * binding becomes a credential; every consumer imports the shape rather than
 * re-spelling it. Spelling it out per call site is what this replaces: a new auth
 * mode then means finding every one of them, and any that is missed silently
 * connects with no credentials at all.
 */
export type SshCredentials = {
  useAgent?: boolean;
  password?: SecretSource;
  privateKey?: SecretSource;
  privateKeyPassphrase?: SecretSource;
};

/** What the SSH connect path needs: the credential half plus the user to send it
 *  as, so a caller never has to branch on the binding kind again. */
export type ResolvedSshAuth = SshCredentials & { user: string };

/**
 * One auth mode's credentials from a typed draft, as INLINE sources.
 *
 * Exported for the one caller holding secrets that are not saved anywhere yet
 * - the host editor's Test probe - so it maps them the same way a resolved
 * binding does instead of assembling the fields by hand. Every saved
 * connection goes through {@link sshKeychainCredentials} instead and sends
 * references.
 *
 * Everything empty becomes `undefined` rather than `""`, so a missing secret
 * fails the backend's explicit "no credentials" guard instead of attempting an
 * empty password or an unparseable key.
 *
 * The `never` default is the guarantee {@link VaultAuthMode} points at: a fourth
 * mode added to that union stops this file compiling until it is handled here,
 * rather than falling off the end and returning `undefined`.
 */
export function sshInlineCredentials(
  authMode: VaultAuthMode,
  secrets: SshSecretValues,
): SshCredentials {
  const inline = (v: string | null | undefined): SecretSource | undefined =>
    v ? { kind: "inline", value: v } : undefined;
  switch (authMode) {
    case "agent":
      // The local ssh-agent signs the handshake. Tervia never sees, stores or
      // backs up the key, so there is nothing here to leak: one copy, in the agent.
      return { useAgent: true };
    case "key":
      return {
        privateKey: inline(secrets.privateKey),
        privateKeyPassphrase: inline(secrets.keyPassphrase),
      };
    case "password":
      return { password: inline(secrets.password) };
    default: {
      const unhandled: never = authMode;
      throw new Error(`vault: unhandled auth mode ${String(unhandled)}`);
    }
  }
}

/**
 * The two lookups resolution needs. A subset of `VaultStore`, so the real store
 * satisfies it as-is and a test can pass two maps.
 */
export type VaultLookup = {
  findIdentity(id: string): Promise<VaultIdentity | undefined>;
  findKey(id: string): Promise<VaultKey | undefined>;
};

export type ResolveDeps = { vault: VaultLookup };

export const defaultResolveDeps: ResolveDeps = { vault: vaultStore };

/** The three SSH field names on each side. They differ only in the passphrase -
 *  see the constants for why. Exported so `credentialMove.ts` builds every
 *  keychain account from these two maps instead of a second spelling of the
 *  field names. */
export const HOST_SSH_FIELDS = {
  password: HOST_SSH_PASSWORD_FIELD,
  privateKey: HOST_SSH_PRIVATE_KEY_FIELD,
  keyPassphrase: HOST_SSH_KEY_PASSPHRASE_FIELD,
} as const;

export const VAULT_SSH_FIELDS = {
  password: IDENTITY_PASSWORD_FIELD,
  privateKey: KEY_PRIVATE_KEY_FIELD,
  keyPassphrase: KEY_PASSPHRASE_FIELD,
} as const;

type SshFields = typeof HOST_SSH_FIELDS | typeof VAULT_SSH_FIELDS;

/**
 * Who owns the accounts one resolution reads.
 *
 * Two ids because in the vault case they are two records: the password belongs to
 * the identity, the key material to the shared `VaultKey`. `key` is optional
 * because a `password` or `agent` identity names no key at all - and an id that
 * is merely NOT A KEY must not be passed in its place, which is how a resolution
 * ends up reading `<identityId>::privateKey` and finding nothing.
 */
type SshAccountOwner = { password: string; key?: string };

/**
 * The keychain references an auth mode authenticates with. Makes no read: the
 * host process dereferences these itself, so no SSH secret enters the webview
 * on the connect path.
 *
 * `agent` references none: the local ssh-agent signs the handshake, so there
 * is no secret to name.
 */
function sshKeychainCredentials(
  mode: VaultAuthMode,
  fields: SshFields,
  service: string,
  owner: SshAccountOwner,
): SshCredentials {
  switch (mode) {
    case "agent":
      return { useAgent: true };
    case "password":
      return {
        password: {
          kind: "keychain",
          service,
          account: vaultAccount(owner.password, fields.password),
        },
      };
    case "key":
      if (!owner.key) {
        // Refuse rather than build `undefined::privateKey`, which reads back as
        // "no key stored" and fails the handshake talking about credentials the
        // user did enter.
        throw new Error("vault: key auth resolved with no key to read it from");
      }
      return {
        privateKey: {
          kind: "keychain",
          service,
          account: vaultAccount(owner.key, fields.privateKey),
        },
        privateKeyPassphrase: {
          kind: "keychain",
          service,
          account: vaultAccount(owner.key, fields.keyPassphrase),
        },
      };
    default: {
      const unhandled: never = mode;
      throw new Error(`vault: unhandled auth mode ${String(unhandled)}`);
    }
  }
}

/**
 * Resolve an identity, refusing the states that would fail at the handshake with
 * a message about something the user never touched.
 *
 * `keyId` is absent for any mode that does not use one. It is deliberately not
 * filled with the identity's own id: that reads like a key id at every call site
 * downstream, and the day one of them uses it, it points at the wrong record.
 */
async function resolveIdentity(
  deps: ResolveDeps,
  identityId: string,
): Promise<{ identity: VaultIdentity; keyId?: string }> {
  const identity = await deps.vault.findIdentity(identityId);
  if (!identity) throw new Error(`vault: identity ${identityId} no longer exists`);
  if (identity.authMode !== "key") return { identity };
  if (!identity.keyId) {
    throw new Error(`vault: identity "${identity.name}" uses key auth but names no key`);
  }
  const key = await deps.vault.findKey(identity.keyId);
  if (!key) {
    throw new Error(`vault: identity "${identity.name}" names a key that no longer exists`);
  }
  return { identity, keyId: key.id };
}

export async function resolveSshAuth(
  binding: SshCredentialBinding,
  deps: ResolveDeps = defaultResolveDeps,
): Promise<ResolvedSshAuth> {
  if (binding.kind === "inline") {
    return {
      user: binding.user,
      ...sshKeychainCredentials(binding.authMode, HOST_SSH_FIELDS, HOST_KEYRING_SERVICE, {
        password: binding.hostId,
        key: binding.hostId,
      }),
    };
  }

  const { identity, keyId } = await resolveIdentity(deps, binding.identityId);
  return {
    user: identity.username,
    ...sshKeychainCredentials(identity.authMode, VAULT_SSH_FIELDS, VAULT_KEYRING_SERVICE, {
      password: identity.id,
      key: keyId,
    }),
  };
}

/**
 * The RDP half, on the same terms as the SSH half above: a reference out, no
 * keychain read here, so there is no code path in this module that reads an
 * RDP password into a JS value.
 *
 * An identity's `authMode` is deliberately NOT checked. `hasPassword` is
 * independent of it, so a key identity holding a password is a legitimate row -
 * that is exactly the "one account, key over SSH and password over RDP" case
 * sharing an identity across protocols exists for.
 */
export async function resolveRdpAuth(
  binding: RdpCredentialBinding,
  deps: ResolveDeps = defaultResolveDeps,
): Promise<ResolvedRdpAuth> {
  if (binding.kind === "inline") {
    return {
      username: binding.username,
      ...(binding.domain ? { domain: binding.domain } : {}),
      credential: {
        kind: "keychain",
        service: HOST_KEYRING_SERVICE,
        account: vaultAccount(binding.hostId, HOST_RDP_PASSWORD_FIELD),
      },
    };
  }

  const identity = await deps.vault.findIdentity(binding.identityId);
  if (!identity) throw new Error(`vault: identity ${binding.identityId} no longer exists`);
  return {
    username: identity.username,
    ...(identity.domain ? { domain: identity.domain } : {}),
    credential: {
      kind: "keychain",
      service: VAULT_KEYRING_SERVICE,
      account: vaultAccount(identity.id, IDENTITY_PASSWORD_FIELD),
    },
  };
}
