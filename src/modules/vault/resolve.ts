import { tauriSecretsIo, type SecretsIo } from "./adapters";
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

// One module, one job: turn a `CredentialBinding` into what the connect path
// needs.
//
// Two output shapes, because the two protocols have genuinely different
// invariants, and the asymmetry is worth stating plainly rather than hiding
// behind a common type:
//
//   RDP gets a REFERENCE. `rdp_open` takes a keychain service/account and the
//   host process reads the plaintext itself, so an RDP password never enters the
//   webview. That is a Phase 5 invariant, and here it is preserved BY
//   CONSTRUCTION: `resolveRdpAuth` makes no keychain read at all.
//
//   SSH gets VALUES, because that is what `openSsh` takes today. This is a
//   pre-existing defect (issues/11), not one the vault introduces: SSH
//   round-trips plaintext through JS on every connect and every ProxyJump hop,
//   bound to a vault identity or not.
//
// This module deliberately imports NOTHING from another feature module. The
// dependency direction is vault <- hosts: `modules/hosts` imports the binding
// union and the two output types from here, never the reverse. So the SSH
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
export type SshCredentialValues = {
  useAgent?: boolean;
  password?: string;
  privateKey?: string;
  privateKeyPassphrase?: string;
};

/** What the SSH connect path needs: the credential half plus the user to send it
 *  as, so a caller never has to branch on the binding kind again. */
export type ResolvedSshAuth = SshCredentialValues & { user: string };

/**
 * One auth mode's credentials, from whatever the keychain returned.
 *
 * Exported so a caller holding secrets that are not in the vault at all - a
 * dialog's unsaved draft, an ad-hoc connection - maps them the same way a
 * resolved binding does, instead of assembling the fields by hand.
 *
 * Everything empty becomes `undefined` rather than `""`, so a missing secret
 * fails the backend's explicit "no credentials" guard instead of attempting an
 * empty password or an unparseable key.
 *
 * The `never` default is the guarantee {@link VaultAuthMode} points at: a fourth
 * mode added to that union stops this file compiling until it is handled here,
 * rather than falling off the end and returning `undefined`.
 */
export function sshCredentialValues(
  authMode: VaultAuthMode,
  secrets: SshSecretValues,
): SshCredentialValues {
  switch (authMode) {
    case "agent":
      // The local ssh-agent signs the handshake. Tervia never sees, stores or
      // backs up the key, so there is nothing here to leak: one copy, in the agent.
      return { useAgent: true };
    case "key":
      return {
        privateKey: secrets.privateKey || undefined,
        privateKeyPassphrase: secrets.keyPassphrase || undefined,
      };
    case "password":
      return { password: secrets.password || undefined };
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

export type ResolveDeps = { vault: VaultLookup; secrets: SecretsIo };

export const defaultResolveDeps: ResolveDeps = { vault: vaultStore, secrets: tauriSecretsIo };

/** The three SSH field names on each side. They differ only in the passphrase -
 *  see the constants for why. */
const HOST_SSH_FIELDS = {
  password: HOST_SSH_PASSWORD_FIELD,
  privateKey: HOST_SSH_PRIVATE_KEY_FIELD,
  keyPassphrase: HOST_SSH_KEY_PASSPHRASE_FIELD,
} as const;

const VAULT_SSH_FIELDS = {
  password: IDENTITY_PASSWORD_FIELD,
  privateKey: KEY_PRIVATE_KEY_FIELD,
  keyPassphrase: KEY_PASSPHRASE_FIELD,
} as const;

type SshFields = typeof HOST_SSH_FIELDS | typeof VAULT_SSH_FIELDS;

/** Accounts an auth mode actually uses, keyed by the `SshSecretValues` field they
 *  fill. Empty for `agent`. */
type SshAccounts = Partial<Record<keyof SshSecretValues, string>>;

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
 * Which accounts one auth mode reads.
 *
 * `agent` reads none: the local ssh-agent signs the handshake, so there is no
 * secret to fetch and no IPC to spend.
 */
function sshAccountsFor(
  mode: VaultAuthMode,
  fields: SshFields,
  owner: SshAccountOwner,
): SshAccounts {
  switch (mode) {
    case "agent":
      return {};
    case "password":
      return { password: vaultAccount(owner.password, fields.password) };
    case "key":
      if (!owner.key) {
        // Refuse rather than build `undefined::privateKey`, which reads back as
        // "no key stored" and fails the handshake talking about credentials the
        // user did enter.
        throw new Error("vault: key auth resolved with no key to read it from");
      }
      return {
        privateKey: vaultAccount(owner.key, fields.privateKey),
        keyPassphrase: vaultAccount(owner.key, fields.keyPassphrase),
      };
    default: {
      const unhandled: never = mode;
      throw new Error(`vault: unhandled auth mode ${String(unhandled)}`);
    }
  }
}

/**
 * The one keychain read a resolution makes: only the accounts the auth mode uses,
 * in a single `secrets_get_all` against a single SERVICE. A batch spanning
 * host-owned and vault-owned accounts would be two calls, and no resolution needs
 * one - a binding is either inline or by identity, never half of each.
 */
async function readSshSecrets(
  secrets: SecretsIo,
  service: string,
  accounts: SshAccounts,
): Promise<SshSecretValues> {
  const fields = Object.keys(accounts) as (keyof SshSecretValues)[];
  if (fields.length === 0) return {};
  const values = await secrets.getAll(
    service,
    fields.map((f) => accounts[f] as string),
  );
  const out: SshSecretValues = {};
  fields.forEach((field, i) => {
    out[field] = values[i] ?? null;
  });
  return out;
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
    const accounts = sshAccountsFor(binding.authMode, HOST_SSH_FIELDS, {
      password: binding.hostId,
      key: binding.hostId,
    });
    const secrets = await readSshSecrets(deps.secrets, HOST_KEYRING_SERVICE, accounts);
    return { user: binding.user, ...sshCredentialValues(binding.authMode, secrets) };
  }

  const { identity, keyId } = await resolveIdentity(deps, binding.identityId);
  const accounts = sshAccountsFor(identity.authMode, VAULT_SSH_FIELDS, {
    password: identity.id,
    key: keyId,
  });
  const secrets = await readSshSecrets(deps.secrets, VAULT_KEYRING_SERVICE, accounts);
  return { user: identity.username, ...sshCredentialValues(identity.authMode, secrets) };
}

/**
 * The RDP half. Note what is missing: `deps.secrets` is never touched, so there
 * is no code path here that reads an RDP password into a JS value.
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
