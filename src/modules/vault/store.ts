import type { StoreRecovery } from "@/lib/storeRecovery";

import { createTauriVaultStoreIo, tauriSecretsIo, type SecretsIo, type VaultIo } from "./adapters";
import {
  IDENTITY_PASSWORD_FIELD,
  KEY_PASSPHRASE_FIELD,
  KEY_PRIVATE_KEY_FIELD,
  VAULT_IDENTITIES_KEY,
  VAULT_IDENTITY_SECRET_FIELDS,
  VAULT_KEYRING_SERVICE,
  VAULT_KEYS_KEY,
  VAULT_KEY_SECRET_FIELDS,
  VaultInUseError,
  vaultAccount,
  type IdentityHostRefs,
  type VaultIdentity,
  type VaultKey,
  type VaultRef,
} from "./types";

// The vault store: metadata and presence flags here, secrets in the keychain.
//
// Reference integrity is enforced in THIS layer rather than in a dialog, for the
// same reason the presence flags are maintained here: a second caller (an import,
// a command-palette action, the next window) would otherwise have to remember the
// rule, and the failure of forgetting is a host that can no longer connect.

/** What an upsert wrote, plus anything the caller should surface. */
export type VaultUpsert<T> = {
  record: T;
  /** Advisory only - the write has already happened. */
  warning?: string;
};

/** Three-state secret input: a string writes (or clears when blank), `undefined`
 *  leaves whatever is stored alone. */
export type SecretInput = string | null | undefined;

export type VaultStore = {
  listIdentities(): Promise<VaultIdentity[]>;
  listKeys(): Promise<VaultKey[]>;
  findIdentity(id: string): Promise<VaultIdentity | undefined>;
  findKey(id: string): Promise<VaultKey | undefined>;
  newIdentityId(): string;
  newKeyId(): string;
  upsertIdentity(
    identity: VaultIdentity,
    secrets: { password?: SecretInput },
  ): Promise<VaultUpsert<VaultIdentity>>;
  upsertKey(
    key: VaultKey,
    secrets: { privateKey?: SecretInput; passphrase?: SecretInput },
  ): Promise<VaultUpsert<VaultKey>>;
  deleteIdentity(id: string, hostRefs: IdentityHostRefs): Promise<void>;
  deleteKey(id: string): Promise<void>;
  onVaultChanged(cb: () => void): Promise<() => void>;
  /**
   * Run the store's crash-recovery pass and first load, then hand back whatever
   * the user should be told - once.
   *
   * The startup entry point, and the ONLY one that makes the notice
   * deterministic: every other method awaits the same pass, so recovery always
   * happens, but the notice is then only seen if something remembers to take it
   * after a read has already occurred. That is how a `.bak` restore goes
   * unreported.
   */
  ensureLoaded(): Promise<StoreRecovery | null>;
  /** The recovery notice if a read has already triggered the pass. Prefer
   *  {@link VaultStore.ensureLoaded}. */
  takeRecoveryNotice(): StoreRecovery | null;
};

/** Opaque id. Stays stable across renames so keychain accounts don't drift. */
function newId(prefix: string): string {
  return `${prefix}-${Math.random().toString(36).slice(2, 10)}${Date.now().toString(36)}`;
}

function toRef(record: { id: string; name: string }): VaultRef {
  return { id: record.id, name: record.name };
}

/** Key names are compared the way a person reads them, so `" id_rsa"` and
 *  `"ID_rsa"` are the collision they look like. */
function sameName(a: string, b: string): boolean {
  return a.trim().toLowerCase() === b.trim().toLowerCase();
}

export function createVaultStore(io: VaultIo): VaultStore {
  // Serialize every mutation through one chain so concurrent callers cannot
  // interleave a read-modify-write and lose an update. Same reasoning as the SSH
  // and RDP stores, and the vault makes the race easy to hit: a page with inline
  // edits fires one of these per field the user leaves.
  let writeQueue: Promise<unknown> = Promise.resolve();
  function enqueueWrite<T>(op: () => Promise<T>): Promise<T> {
    const run = writeQueue.then(op, op);
    // Keep the chain alive regardless of any single op's outcome.
    writeQueue = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  async function listIdentities(): Promise<VaultIdentity[]> {
    const raw = await io.store.get<VaultIdentity[]>(VAULT_IDENTITIES_KEY);
    return Array.isArray(raw) ? raw : [];
  }

  async function listKeys(): Promise<VaultKey[]> {
    const raw = await io.store.get<VaultKey[]>(VAULT_KEYS_KEY);
    return Array.isArray(raw) ? raw : [];
  }

  /** Every mutation lands through here. The commit is also what takes the `.bak`
   *  snapshot, which is why the session that CREATES the vault has one: at first
   *  load there is no file to snapshot yet, so the first successful write is the
   *  earliest moment a private key can be protected at all. */
  async function persist(storeKey: string, list: unknown[]): Promise<void> {
    await io.store.set(storeKey, list);
    await io.store.commit();
  }

  /**
   * Write one secret and report the presence flag that now belongs in the record.
   *
   * `undefined` means "leave the stored secret alone", the app-wide three-state
   * convention: an edit that never touched a password field cannot wipe it. The
   * flag then comes from the EXISTING RECORD rather than from a keychain
   * read-back, and that part is deliberate - the flags exist so a list screen
   * never costs one `secrets_get` per row, and a no-change write reading the
   * secret back would spend exactly what they were added to save.
   */
  async function writeSecret(
    secrets: SecretsIo,
    id: string,
    field: string,
    value: SecretInput,
    current: boolean,
  ): Promise<boolean> {
    if (value === undefined) return current;
    const trimmed = value?.trim() ?? "";
    if (!trimmed) {
      await secrets.delete(VAULT_KEYRING_SERVICE, vaultAccount(id, field));
      return false;
    }
    await secrets.set(VAULT_KEYRING_SERVICE, vaultAccount(id, field), trimmed);
    return true;
  }

  async function upsertIdentity(
    identity: VaultIdentity,
    secrets: { password?: SecretInput },
  ): Promise<VaultUpsert<VaultIdentity>> {
    return enqueueWrite(async () => {
      const [identities, keys] = await Promise.all([listIdentities(), listKeys()]);

      // A `keyId` may never dangle. The delete guard below exists to keep that
      // true from one side; refusing here keeps it true from the other, and
      // without both the guard only makes the bad state harder to reach rather
      // than unreachable.
      if (identity.authMode === "key" && !identity.keyId) {
        throw new Error(`vault: identity "${identity.name}" uses key auth but names no key`);
      }
      if (identity.keyId && !keys.some((k) => k.id === identity.keyId)) {
        throw new Error(`vault: identity "${identity.name}" names a key that does not exist`);
      }

      const existing = identities.find((i) => i.id === identity.id);
      const record: VaultIdentity = {
        ...identity,
        hasPassword: await writeSecret(
          io.secrets,
          identity.id,
          IDENTITY_PASSWORD_FIELD,
          secrets.password,
          existing?.hasPassword ?? false,
        ),
      };

      const next = [...identities];
      const idx = next.findIndex((i) => i.id === identity.id);
      if (idx >= 0) next[idx] = record;
      else next.push(record);
      await persist(VAULT_IDENTITIES_KEY, next);
      return { record };
    });
  }

  async function upsertKey(
    key: VaultKey,
    secrets: { privateKey?: SecretInput; passphrase?: SecretInput },
  ): Promise<VaultUpsert<VaultKey>> {
    return enqueueWrite(async () => {
      // Required, unlike an identity's name: a key is chosen by name from a
      // dropdown in every host that uses it, so a blank one is unpickable. The
      // collision warning below also degenerates without it - two nameless keys
      // "collide" with `another key is already named ""`.
      if (!key.name.trim()) throw new Error("vault: a key needs a name");

      const keys = await listKeys();
      const existing = keys.find((k) => k.id === key.id);

      // Warned, not refused: a key is referenced by name across many hosts, so a
      // duplicate is a real usability failure - but it is the user's file and the
      // name is not an identifier, so refusing would be the app arguing with them.
      const clash = keys.find((k) => k.id !== key.id && sameName(k.name, key.name));
      const warning = clash ? `another key is already named "${clash.name}"` : undefined;

      const record: VaultKey = {
        ...key,
        hasPrivateKey: await writeSecret(
          io.secrets,
          key.id,
          KEY_PRIVATE_KEY_FIELD,
          secrets.privateKey,
          existing?.hasPrivateKey ?? false,
        ),
        hasPassphrase: await writeSecret(
          io.secrets,
          key.id,
          KEY_PASSPHRASE_FIELD,
          secrets.passphrase,
          existing?.hasPassphrase ?? false,
        ),
      };

      const next = [...keys];
      const idx = next.findIndex((k) => k.id === key.id);
      if (idx >= 0) next[idx] = record;
      else next.push(record);
      await persist(VAULT_KEYS_KEY, next);
      return warning ? { record, warning } : { record };
    });
  }

  /** Refused while any host still binds to it - see {@link IdentityHostRefs} for
   *  why the lookup arrives as an argument. */
  async function deleteIdentity(id: string, hostRefs: IdentityHostRefs): Promise<void> {
    return enqueueWrite(async () => {
      const identities = await listIdentities();
      const identity = identities.find((i) => i.id === id);
      if (!identity) return;

      const holders = await hostRefs(id);
      if (holders.length > 0) {
        throw new VaultInUseError(`identity "${identity.name}"`, "host", holders);
      }

      await Promise.all(
        VAULT_IDENTITY_SECRET_FIELDS.map((field) =>
          io.secrets.delete(VAULT_KEYRING_SERVICE, vaultAccount(id, field)),
        ),
      );
      await persist(
        VAULT_IDENTITIES_KEY,
        identities.filter((i) => i.id !== id),
      );
    });
  }

  /** Refused while any identity still names it. Holders are found in-store: a key
   *  is only ever referenced by an identity, never by a host directly. */
  async function deleteKey(id: string): Promise<void> {
    return enqueueWrite(async () => {
      const [keys, identities] = await Promise.all([listKeys(), listIdentities()]);
      const key = keys.find((k) => k.id === id);
      if (!key) return;

      const holders = identities.filter((i) => i.keyId === id).map(toRef);
      if (holders.length > 0) {
        throw new VaultInUseError(`key "${key.name}"`, "identity", holders);
      }

      await Promise.all(
        VAULT_KEY_SECRET_FIELDS.map((field) =>
          io.secrets.delete(VAULT_KEYRING_SERVICE, vaultAccount(id, field)),
        ),
      );
      await persist(
        VAULT_KEYS_KEY,
        keys.filter((k) => k.id !== id),
      );
    });
  }

  return {
    listIdentities,
    listKeys,
    findIdentity: async (id) => (await listIdentities()).find((i) => i.id === id),
    findKey: async (id) => (await listKeys()).find((k) => k.id === id),
    newIdentityId: () => newId("i"),
    newKeyId: () => newId("k"),
    upsertIdentity,
    upsertKey,
    deleteIdentity,
    deleteKey,
    onVaultChanged: (cb) => io.store.onChanged(cb),
    ensureLoaded: () => io.store.ensureLoaded(),
    takeRecoveryNotice: () => io.store.takeRecoveryNotice(),
  };
}

/** The app's vault. One instance, so one write queue. */
export const vaultStore = createVaultStore({
  store: createTauriVaultStoreIo(),
  secrets: tauriSecretsIo,
});

export const {
  listIdentities,
  listKeys,
  findIdentity,
  findKey,
  newIdentityId,
  newKeyId,
  upsertIdentity,
  upsertKey,
  deleteIdentity,
  deleteKey,
  onVaultChanged,
  ensureLoaded,
  takeRecoveryNotice,
} = vaultStore;
