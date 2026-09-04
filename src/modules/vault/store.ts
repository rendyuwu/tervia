import type { StoreRecovery } from "@/lib/storeRecovery";

import { createTauriVaultStoreIo, tauriSecretsIo, type SecretsIo, type VaultIo } from "./adapters";
import { identitiesUsingKey } from "./refs";
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
  VaultRecordChangedError,
  vaultAccount,
  vaultIdentityStamp,
  vaultKeyStamp,
  type IdentityHostRefs,
  type VaultIdentity,
  type VaultKey,
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

/**
 * The secret is ALREADY at this account: record it as present and write nothing.
 *
 * The fourth state, and it is a `Symbol` rather than a sentinel string for the
 * reason the host store's copy of this doc gives: `JSON.parse` cannot produce
 * one, so no imported file, no store row and no IPC payload can reach this
 * branch by carrying the right characters - and the caller that would hand one
 * over is the one parsing an untrusted backup. Do not simplify it to a string.
 *
 * Two callers, one of them not written yet. `credentialMove.ts` copies a host's
 * secret onto a vault account with `secrets_copy`, which never returns the value,
 * so the record it then writes has no other way to claim the secret honestly.
 * 6g's import is the second: `backup_apply_secrets` writes from Rust and hands
 * JS a `boolean[]`.
 *
 * Declared HERE rather than in `modules/hosts`, and re-exported from there, so
 * there is exactly ONE of it: two symbols with the same description are not
 * `===`, and the branch would silently never be taken.
 */
export const SECRET_ALREADY_STORED = Symbol("secretAlreadyStored");

/** {@link SecretInput} plus {@link SECRET_ALREADY_STORED}. */
export type VaultSecretValue = SecretInput | typeof SECRET_ALREADY_STORED;

export type VaultStore = {
  listIdentities(): Promise<VaultIdentity[]>;
  listKeys(): Promise<VaultKey[]>;
  findIdentity(id: string): Promise<VaultIdentity | undefined>;
  findKey(id: string): Promise<VaultKey | undefined>;
  newIdentityId(): string;
  newKeyId(): string;
  /**
   * `expect` is the stamp the caller loaded, from {@link vaultIdentityStamp}.
   * Supplied, the write is refused unless the stored record still carries that
   * secret material; omitted, the write is unconditional.
   *
   * Optional, and that is a statement rather than an oversight: an import holds
   * no earlier snapshot of the record, so a required parameter would only make
   * it invent one - the v3 import route passes two arguments deliberately. The
   * caller that DOES hold a snapshot is an editor, and
   * `scripts/vault-editor-verify.ts` is what proves it still passes one.
   */
  upsertIdentity(
    identity: VaultIdentity,
    secrets: { password?: VaultSecretValue },
    expect?: string,
  ): Promise<VaultUpsert<VaultIdentity>>;
  /** `expect` is the stamp from {@link vaultKeyStamp} - see
   *  {@link VaultStore.upsertIdentity} for why it is optional. */
  upsertKey(
    key: VaultKey,
    secrets: { privateKey?: VaultSecretValue; passphrase?: VaultSecretValue },
    expect?: string,
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

/** Key names are compared the way a person reads them, so `" id_rsa"` and
 *  `"ID_rsa"` are the collision they look like. */
function sameName(a: string, b: string): boolean {
  return a.trim().toLowerCase() === b.trim().toLowerCase();
}

export function createVaultStore(io: VaultIo): VaultStore {
  // Every mutation is serialized by the store port, not here: the queue only means
  // anything if there is one of it per store FILE, so it belongs beside the file.
  const enqueueWrite = <T>(op: () => Promise<T>): Promise<T> => io.store.enqueueWrite(op);

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
   *
   * {@link SECRET_ALREADY_STORED} is the one input that reports `true` without
   * touching the keychain at all - no set, no delete, and no read either. The
   * caller has already put the value at this account.
   */
  async function writeSecret(
    secrets: SecretsIo,
    id: string,
    field: string,
    value: VaultSecretValue,
    current: boolean,
  ): Promise<boolean> {
    if (value === SECRET_ALREADY_STORED) return true;
    if (value === undefined) return current;
    const trimmed = value?.trim() ?? "";
    if (!trimmed) {
      await secrets.delete(VAULT_KEYRING_SERVICE, vaultAccount(id, field));
      return false;
    }
    await secrets.set(VAULT_KEYRING_SERVICE, vaultAccount(id, field), trimmed);
    return true;
  }

  /**
   * A key's two secrets, with both accounts cleared again if either write throws.
   *
   * The hole this closes: `privateKey` lands, `passphrase` throws, and the PEM
   * then sits at `<key.id>::privateKey` with no record naming it - the "bytes no
   * code path can enumerate or delete" case the module header opens with, and
   * literally unenumerable, since there is no `secrets_list` command. The required
   * key name closed the blank-name route into that hole; this closes the failure
   * route.
   *
   * Rolled back only for a record that did not exist before, which is what makes
   * it safe: for an id the store has never seen there was nothing at these
   * accounts to lose, and `secrets_delete` reports an absent account as success.
   * For a record that DOES exist the accounts stay reachable through `deleteKey`,
   * and clearing them would destroy a stored secret this layer cannot put back -
   * it never reads one, so it holds no previous value. That case is metadata
   * drift, already registered as VLT-22, not an orphan.
   *
   * A failing rollback is swallowed - the only swallow in this module. The caller
   * is already rethrowing the write's own error, which is the one the user can act
   * on, and a keychain that refused the write usually refuses this too. What
   * survives that is VLT-23.
   *
   * {@link SECRET_ALREADY_STORED} does not change this arm. A caller passing it
   * for `privateKey` and a real string for `passphrase` that then throws has the
   * rollback delete the private key it never wrote here - and that is correct,
   * not a bug: both accounts were populated by THIS operation, under an id
   * nothing else names, so there is nothing pre-existing for the rollback to
   * destroy.
   */
  async function writeKeySecrets(
    key: VaultKey,
    secrets: { privateKey?: VaultSecretValue; passphrase?: VaultSecretValue },
    existing: VaultKey | undefined,
  ): Promise<VaultKey> {
    try {
      return {
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
    } catch (e) {
      if (!existing) {
        try {
          await Promise.all(
            VAULT_KEY_SECRET_FIELDS.map((field) =>
              io.secrets.delete(VAULT_KEYRING_SERVICE, vaultAccount(key.id, field)),
            ),
          );
        } catch {
          // See above: replacing the real error with this one hides the reason.
        }
      }
      throw e;
    }
  }

  async function upsertIdentity(
    identity: VaultIdentity,
    secrets: { password?: VaultSecretValue },
    expect?: string,
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

      // INSIDE the write queue, and before any secret is written - the placement
      // `upsertKey`'s own copy of this block explains in full.
      if (expect !== undefined) {
        const current = vaultIdentityStamp(existing);
        if (current !== expect) {
          throw new VaultRecordChangedError(
            "identity",
            identity.id,
            identity.name,
            expect,
            current,
          );
        }
      }

      // No rollback here, and none needed: an identity owns ONE secret, so a write
      // that throws wrote nothing. The multi-write hole is `upsertKey`'s alone.
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
    secrets: { privateKey?: VaultSecretValue; passphrase?: VaultSecretValue },
    expect?: string,
  ): Promise<VaultUpsert<VaultKey>> {
    return enqueueWrite(async () => {
      // Required, unlike an identity's name: a key is chosen by name from a
      // dropdown in every host that uses it, so a blank one is unpickable. The
      // collision warning below also degenerates without it - two nameless keys
      // "collide" with `another key is already named ""`.
      if (!key.name.trim()) throw new Error("vault: a key needs a name");

      const keys = await listKeys();
      const existing = keys.find((k) => k.id === key.id);

      // INSIDE the write queue, and BEFORE any secret is written. Both halves are
      // load-bearing. Inside, because a check the caller ran before calling has a
      // window between its read and this write that another writer fits into -
      // this body runs as one queue entry, so the record read here is the record
      // about to be replaced, with nothing able to land in between. Before,
      // because a refusal must leave the keychain exactly as it was:
      // `writeKeySecrets` below writes up to two accounts, and a refusal after
      // that has already mutated the thing it was refusing to touch.
      if (expect !== undefined) {
        const current = vaultKeyStamp(existing);
        if (current !== expect) {
          throw new VaultRecordChangedError("key", key.id, key.name, expect, current);
        }
      }

      // Warned, not refused: a key is referenced by name across many hosts, so a
      // duplicate is a real usability failure - but it is the user's file and the
      // name is not an identifier, so refusing would be the app arguing with them.
      const clash = keys.find((k) => k.id !== key.id && sameName(k.name, key.name));
      const warning = clash ? `another key is already named "${clash.name}"` : undefined;

      const record = await writeKeySecrets(key, secrets, existing);

      const next = [...keys];
      const idx = next.findIndex((k) => k.id === key.id);
      if (idx >= 0) next[idx] = record;
      else next.push(record);
      // A `persist` that throws is deliberately NOT rolled back. `LazyStore` runs
      // with `autoSave`, so the record is already in the plugin's cache with a
      // debounced retry behind it - deleting the secrets here would race that into
      // a record whose flags name material that is gone, permanently, since the
      // flags are never read back. Orphaned on a failure that never clears: VLT-23.
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

      const holders = identitiesUsingKey(identities, id);
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
