import { describeError } from "@/lib/describeError";
import { markDirty } from "@/lib/dirtySink";
import type { StoreFileState, StoreRecovery } from "@/lib/storeRecovery";
import {
  landedTombstones,
  landingRefusal,
  livingTombstones,
  TOMBSTONES_KEY,
  withoutTombstone,
  withTombstone,
  type DirtyId,
  type RemoteLanding,
  type RemoteLandingRefusal,
  type Tombstone,
} from "@/lib/tombstones";

import { createTauriVaultStoreIo, tauriSecretsIo, type SecretsIo, type VaultIo } from "./adapters";
import { identitiesUsingKey } from "./refs";
import {
  IDENTITY_PASSWORD_FIELD,
  IDENTITY_TOMBSTONE_KIND,
  KEY_PASSPHRASE_FIELD,
  KEY_TOMBSTONE_KIND,
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
 * Two callers. `credentialMove.ts` copies a host's secret onto a vault account
 * with `secrets_copy`, which never returns the value, so the record it then
 * writes has no other way to claim the secret honestly. `backup/apply.ts` is the
 * second: `backup_apply_secrets` writes from Rust and hands JS a `boolean[]`.
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
  /**
   * A successful connect authenticated as this identity: stamp its `lastConnectedAt`,
   * and its key's when the connect was SSH under key auth - the one case
   * `resolveSshAuth` hands the handshake the key (`resolveRdpAuth` never reads it).
   *
   * DOES NOT STAMP `updatedAt` AND MARKS NOTHING DIRTY, for the reason `patchHost`
   * in `src/modules/hosts/store.ts` gives: per-machine history is not record content
   * and does not sync. A missing identity writes nothing; a `keyId` naming no key
   * stamps the identity alone - both are a record deleted or re-pointed mid-connect.
   */
  markIdentityConnected(identityId: string, protocol: "ssh" | "rdp"): Promise<void>;
  /**
   * Land already-merged identities and keys, and their tombstones, at their
   * REMOTE timestamps in ONE commit, and report the ones that were not applied.
   *
   * The one writer here that does not originate what it writes, which is why it
   * does not stamp: every mutator but this one and `markIdentityConnected` (whose
   * write is device-local history, not record content) overwrites its caller's
   * `updatedAt`, and doing that to a pulled record would have it outrank the copy
   * it came from, while a locally-stamped `deletedAt` restarts the expiry window
   * on every device that receives the delete.
   *
   * BOTH KINDS IN ONE CALL and one commit, because both live in one file: two
   * calls would be two commits, and the second could tear against a write from
   * another window in between.
   *
   * A TOMBSTONE LANDING RELEASES THE KEYCHAIN, the same accounts `deleteKey` and
   * `deleteIdentity` clear. A body left at an account no record names is not
   * untidy: nothing reaches it again but the Vault page's unreferenced-entry
   * sweep, which the user has to go and run.
   *
   * REFUSALS COME BACK, nothing throws - see `landingRefusal` in
   * `src/lib/tombstones.ts` for the five conditions, and for why the reference
   * guards `upsertIdentity` runs are deliberately outside them: an identity may
   * legitimately arrive before the key it names, since the order within one pull
   * is an artifact of a listing rather than of what the other device holds.
   *
   * A LANDED DELETE RUNS NEITHER IN-USE REFUSAL. `deleteKey` refuses while an
   * identity still names the key and `deleteIdentity` refuses while a host still
   * binds it; a landing does neither, so a key body can be released here while a
   * local-only identity still names it. Accepted, with the reasoning and the
   * trigger in `KNOWN-LIMITS.md`.
   *
   * A LOCAL DELETE MADE AFTER THE MERGE WINS over a record landing for the same
   * id - see `applyRemote` in `modules/hosts/store.ts` for why only this function
   * can make that comparison.
   */
  applyRemote(
    identities: RemoteLanding<VaultIdentity>[],
    keys: RemoteLanding<VaultKey>[],
  ): Promise<RemoteLandingRefusal[]>;
  /**
   * What this store's deletes have left behind, already pruned to the window.
   *
   * ONE list for both record kinds, because both live in one file and `kind` is
   * what tells them apart. See `livingTombstones` in `src/lib/tombstones.ts` for
   * why an expired row in the file is never observable here.
   */
  listTombstones(): Promise<Tombstone[]>;
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
  /** How this store's file looked on disk. Neither draining the notice slot nor
   *  competing for it - see {@link HostsStore.fileState} in
   *  `src/modules/hosts/store.ts` for the caller and why it must not use
   *  {@link VaultStore.ensureLoaded} instead. */
  fileState(): Promise<{ found: StoreFileState; recovered: boolean }>;
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

  // Read ONCE per mutator and reused - see the same line in `hosts/store.ts` for
  // why separate reads of an injected constant clock are indistinguishable from
  // one, and what that hides. This store's own clock in every mutator, never a
  // caller's value - `applyRemote` is the one exception, and takes the remote
  // timestamp beside the record it lands.
  const now = io.now ?? Date.now;

  async function listIdentities(): Promise<VaultIdentity[]> {
    const raw = await io.store.get<VaultIdentity[]>(VAULT_IDENTITIES_KEY);
    return Array.isArray(raw) ? raw : [];
  }

  async function listKeys(): Promise<VaultKey[]> {
    const raw = await io.store.get<VaultKey[]>(VAULT_KEYS_KEY);
    return Array.isArray(raw) ? raw : [];
  }

  /**
   * Every mutation lands through here. The commit is also what takes the `.bak`
   * snapshot, which is why the session that CREATES the vault has one: at first
   * load there is no file to snapshot yet, so the first successful write is the
   * earliest moment a private key can be protected at all.
   *
   * ENTRIES rather than one key, the shape `hosts/store.ts`'s copy already has,
   * because a delete now writes two: the record list and the tombstone. Split
   * into two commits there would be a window where the record is gone and
   * nothing records that it was deleted, and a device pulling into that window
   * pushes the record straight back. A `set` reaches the store's cache only and
   * the `commit` writes the whole file in one `atomic_write`, so either both keys
   * land or neither does.
   *
   * DIRTY IS REQUIRED, and per RECORD - `hosts/store.ts`'s copy of this doc
   * carries the full reasoning; it is the same parameter for the same reasons.
   * `[]` is what `applyRemote` passes, because a landing is what the remote
   * already holds, and what `markIdentityConnected` passes, because connect
   * history does not sync.
   */
  async function persist(entries: [string, unknown][], dirty: DirtyId[]): Promise<void> {
    for (const [key, value] of entries) await io.store.set(key, value);
    await io.store.commit();
    io.markDirty?.(dirty);
  }

  /** Both the public read and every write's baseline, so no caller can reason
   *  about an expired row. `at` is the mutator's own single clock read. */
  async function readTombstones(at = now()): Promise<Tombstone[]> {
    return livingTombstones(await io.store.get(TOMBSTONES_KEY), at);
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
   * code path can enumerate or delete" case the module header opens with. Only
   * the Vault page's unreferenced-entry sweep would ever name it, and that is a
   * screen somebody has to visit rather than anything this write can rely on. The
   * required key name closed the blank-name route into that hole; this closes the
   * failure route.
   *
   * Rolled back only for a record that did not exist before, which is what makes
   * it safe: for an id the store has never seen there was nothing at these
   * accounts to lose, and `secrets_delete` reports an absent account as success.
   * For a record that DOES exist the accounts stay reachable through `deleteKey`,
   * and clearing them would destroy a stored secret this layer cannot put back -
   * it never reads one, so it holds no previous value. That case is metadata
   * drift, not an orphan.
   *
   * A failing rollback is swallowed - the only swallow in this module. The caller
   * is already rethrowing the write's own error, which is the one the user can act
   * on, and a keychain that refused the write usually refuses this too. What
   * survives that is bytes at a vault account no record names, and nothing can
   * sweep them: `secrets.rs` exposes `get`, `get_all`, `set`, `delete` and
   * `copy`, and no command that lists accounts.
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
      //
      // `updatedAt` is stamped from this layer's clock and overwrites whatever
      // the caller supplied - an editor round-trips the record it loaded, so
      // honouring that value would mean a save never bumps the stamp.
      const at = now();
      // `lastConnectedAt` is carried from the STORED record, never the caller's: it is
      // this device's connect history and `markIdentityConnected` is its only writer.
      // An editor builds from a draft without it, a backup describes the exporting
      // machine, a landing arrives stripped of it - written through, each would erase
      // or forge it. The same last property closes `upsertKey` and both `applyRemote`
      // branches.
      const record: VaultIdentity = {
        ...identity,
        hasPassword: await writeSecret(
          io.secrets,
          identity.id,
          IDENTITY_PASSWORD_FIELD,
          secrets.password,
          existing?.hasPassword ?? false,
        ),
        updatedAt: at,
        lastConnectedAt: existing?.lastConnectedAt,
      };

      const next = [...identities];
      const idx = next.findIndex((i) => i.id === identity.id);
      if (idx >= 0) next[idx] = record;
      else next.push(record);
      // Any tombstone naming this id goes in the same commit, so a backup restore
      // of a record deleted earlier is not deleted again by the first sync pull.
      // The key is carried only when something changed - see `withoutTombstone`.
      const entries: [string, unknown][] = [[VAULT_IDENTITIES_KEY, next]];
      const graves = withoutTombstone(await readTombstones(at), [identity.id], at);
      if (graves) entries.push([TOMBSTONES_KEY, graves]);
      await persist(entries, [{ kind: IDENTITY_TOMBSTONE_KIND, id: identity.id }]);
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

      // Stamped onto what `writeKeySecrets` returns, not onto `key`, so the flags
      // it just computed are not discarded. Same clock rule as `upsertIdentity`.
      const at = now();
      const record: VaultKey = {
        ...(await writeKeySecrets(key, secrets, existing)),
        updatedAt: at,
        lastConnectedAt: existing?.lastConnectedAt,
      };

      const next = [...keys];
      const idx = next.findIndex((k) => k.id === key.id);
      if (idx >= 0) next[idx] = record;
      else next.push(record);
      // A `persist` that throws is deliberately NOT rolled back. There is no
      // retry behind it any more - the store writes the whole file on `commit`
      // and nothing re-attempts a write that failed - and the decision is
      // unchanged, for the reason underneath the old one: `persist` sets the
      // record into the store's cache BEFORE the write, so this session goes on
      // reading a list that names these accounts and the next commit that
      // succeeds puts it on disk. Deleting the secrets here would leave that
      // live record naming material that is gone, permanently, since the flags
      // are never read back. Orphaned on a failure that never clears, and
      // unreachable afterwards: nothing enumerates keychain accounts.
      const entries: [string, unknown][] = [[VAULT_KEYS_KEY, next]];
      const graves = withoutTombstone(await readTombstones(at), [key.id], at);
      if (graves) entries.push([TOMBSTONES_KEY, graves]);
      await persist(entries, [{ kind: KEY_TOMBSTONE_KIND, id: key.id }]);
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

      await releaseAccounts(id, VAULT_IDENTITY_SECRET_FIELDS);
      // The record drop and its tombstone in ONE commit, after the accounts are
      // cleared - the ordering is unchanged, only the second key is new. The
      // `if (!identity) return` above keeps a missing id from minting a tombstone
      // for a record that never existed, which another device could not tell from
      // a real delete.
      const at = now();
      const graves = await readTombstones(at);
      await persist(
        [
          [VAULT_IDENTITIES_KEY, identities.filter((i) => i.id !== id)],
          [
            TOMBSTONES_KEY,
            withTombstone(graves, [{ id, kind: IDENTITY_TOMBSTONE_KIND, deletedAt: at }], at),
          ],
        ],
        [{ kind: IDENTITY_TOMBSTONE_KIND, id }],
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

      await releaseAccounts(id, VAULT_KEY_SECRET_FIELDS);
      // One commit, after the accounts are cleared - see `deleteIdentity`.
      const at = now();
      const graves = await readTombstones(at);
      await persist(
        [
          [VAULT_KEYS_KEY, keys.filter((k) => k.id !== id)],
          [
            TOMBSTONES_KEY,
            withTombstone(graves, [{ id, kind: KEY_TOMBSTONE_KIND, deletedAt: at }], at),
          ],
        ],
        [{ kind: KEY_TOMBSTONE_KIND, id }],
      );
    });
  }

  async function markIdentityConnected(identityId: string, protocol: "ssh" | "rdp"): Promise<void> {
    return enqueueWrite(async () => {
      const at = now();
      const identities = await listIdentities();
      const idx = identities.findIndex((i) => i.id === identityId);
      if (idx < 0) return;
      const identity = identities[idx];
      const nextIdentities = [...identities];
      nextIdentities[idx] = { ...identity, lastConnectedAt: at };
      const entries: [string, unknown][] = [[VAULT_IDENTITIES_KEY, nextIdentities]];
      if (protocol === "ssh" && identity.authMode === "key" && identity.keyId) {
        const keys = await listKeys();
        const k = keys.findIndex((x) => x.id === identity.keyId);
        if (k >= 0) {
          const nextKeys = [...keys];
          nextKeys[k] = { ...keys[k], lastConnectedAt: at };
          entries.push([VAULT_KEYS_KEY, nextKeys]);
        }
      }
      // Nothing is owed a push - see the doc on `VaultStore.markIdentityConnected`.
      await persist(entries, []);
    });
  }

  /**
   * Clear every account one dropped record owned - the keychain half of every
   * delete in this module, local or landed.
   *
   * A landed delete re-runs it rather than trusting the origin device's: that
   * device cleared ITS keychain, and a body left behind here is named by no record
   * on this machine, so nothing reaches it again but the Vault page's
   * unreferenced-entry sweep.
   */
  async function releaseAccounts(id: string, fields: readonly string[]): Promise<void> {
    await Promise.all(
      fields.map((field) => io.secrets.delete(VAULT_KEYRING_SERVICE, vaultAccount(id, field))),
    );
  }

  /**
   * Store the private-key body a landing carried, and report the presence flags
   * it earns.
   *
   * ONLY THE TWO KEY FIELDS. A landing naming anything else is a device running
   * a newer build, or a remote that has been tampered with; either way this
   * store has no account for it and writing one would put bytes at an address
   * nothing on this machine can ever enumerate, since no registered command
   * lists accounts.
   *
   * A BLANK VALUE IS SKIPPED rather than written or deleted. The delete reading
   * is the destructive one and it is not what an empty string from another
   * device means; the write reading would store an empty secret behind a `true`
   * flag, which is the record lying about what it holds.
   *
   * No rollback, unlike `writeKeySecrets`. Its rollback exists for a record the
   * store has never seen, where the accounts held nothing to lose; here the
   * record either already exists or is arriving with its body, and clearing an
   * account on a partial failure would destroy a secret this layer never read
   * and cannot put back. A half-landed pair leaves the other field's flag
   * false, so the next pull carrying the body lands it again.
   */
  async function landKeySecrets(
    id: string,
    secrets: Record<string, string>,
  ): Promise<Record<string, boolean>> {
    const flags: Record<string, boolean> = {};
    for (const field of VAULT_KEY_SECRET_FIELDS) {
      const value = secrets[field]?.trim();
      if (!value) continue;
      await io.secrets.set(VAULT_KEYRING_SERVICE, vaultAccount(id, field), value);
      flags[field === KEY_PRIVATE_KEY_FIELD ? "hasPrivateKey" : "hasPassphrase"] = true;
    }
    return flags;
  }

  async function applyRemote(
    identityLandings: RemoteLanding<VaultIdentity>[],
    keyLandings: RemoteLanding<VaultKey>[],
  ): Promise<RemoteLandingRefusal[]> {
    return enqueueWrite(async () => {
      // ONE clock read for the whole set, and it stamps nothing: it is the window
      // boundary every tombstone read and write here is filtered against, so one
      // apply judges every landing in it against one instant.
      const at = now();
      const refusals: RemoteLandingRefusal[] = [];
      const [identities, keys] = await Promise.all([listIdentities(), listKeys()]);
      const nextIdentities = [...identities];
      const nextKeys = [...keys];
      const graves = await readTombstones(at);
      const buried: Tombstone[] = [];
      const revived: string[] = [];
      let identitiesTouched = false;
      let keysTouched = false;

      for (const landing of identityLandings) {
        const refusal = landingRefusal(landing, IDENTITY_TOMBSTONE_KIND);
        if (refusal) {
          refusals.push(refusal);
          continue;
        }
        if (landing.deleted) {
          const idx = nextIdentities.findIndex((i) => i.id === landing.tombstone.id);
          if (idx >= 0) {
            // A keychain that refuses becomes a REFUSAL, not a throw: this is the
            // only await in the loop that can reject, and letting it out would
            // lose every other landing in the set. The record stays, so a partial
            // release leaves accounts `deleteIdentity` can still reach.
            try {
              await releaseAccounts(landing.tombstone.id, VAULT_IDENTITY_SECRET_FIELDS);
            } catch (e) {
              refusals.push({
                kind: IDENTITY_TOMBSTONE_KIND,
                id: landing.tombstone.id,
                reason: `the keychain refused to release this identity's accounts: ${describeError(e)}`,
              });
              continue;
            }
            nextIdentities.splice(idx, 1);
            identitiesTouched = true;
          }
          const revivedIdx = revived.indexOf(landing.tombstone.id);
          if (revivedIdx >= 0) revived.splice(revivedIdx, 1);
          // Filed even with no local record to drop: another device deleted it,
          // and a device that has not pulled since would push its own copy back.
          buried.push(landing.tombstone);
          continue;
        }
        // A local delete made after the merge outranks the landing - see the same
        // comparison in `applyRemote` in `modules/hosts/store.ts` for why only
        // this function can make it.
        const superseding = graves.find(
          (t) => t.id === landing.id && t.kind === IDENTITY_TOMBSTONE_KIND,
        );
        if (superseding && superseding.deletedAt > landing.updatedAt) continue;
        // AN IDENTITY'S `secrets` IS NEVER LANDED, and that is not an omission
        // the key branch below forgot to copy. The carry toggle is an opt-in to
        // holding a PRIVATE KEY BODY, which is what `README.md` publishes; an
        // account password is not one, so nothing attaches one on the way out
        // and nothing accepts one on the way in. The record's own `hasPassword`
        // is applied as the merge decided it.
        const idx = nextIdentities.findIndex((i) => i.id === landing.id);
        const record: VaultIdentity = {
          ...landing.record,
          updatedAt: landing.updatedAt,
          lastConnectedAt: idx >= 0 ? nextIdentities[idx].lastConnectedAt : undefined,
        };
        if (idx >= 0) nextIdentities[idx] = record;
        else nextIdentities.push(record);
        const buriedIdx = buried.findIndex((t) => t.id === landing.id);
        if (buriedIdx >= 0) buried.splice(buriedIdx, 1);
        revived.push(landing.id);
        identitiesTouched = true;
      }

      for (const landing of keyLandings) {
        const refusal = landingRefusal(landing, KEY_TOMBSTONE_KIND);
        if (refusal) {
          refusals.push(refusal);
          continue;
        }
        if (landing.deleted) {
          const idx = nextKeys.findIndex((k) => k.id === landing.tombstone.id);
          if (idx >= 0) {
            try {
              await releaseAccounts(landing.tombstone.id, VAULT_KEY_SECRET_FIELDS);
            } catch (e) {
              refusals.push({
                kind: KEY_TOMBSTONE_KIND,
                id: landing.tombstone.id,
                reason: `the keychain refused to release this key's accounts: ${describeError(e)}`,
              });
              continue;
            }
            nextKeys.splice(idx, 1);
            keysTouched = true;
          }
          const revivedIdx = revived.indexOf(landing.tombstone.id);
          if (revivedIdx >= 0) revived.splice(revivedIdx, 1);
          buried.push(landing.tombstone);
          continue;
        }
        const superseding = graves.find(
          (t) => t.id === landing.id && t.kind === KEY_TOMBSTONE_KIND,
        );
        if (superseding && superseding.deletedAt > landing.updatedAt) continue;
        // THE CARRIED BODY, when the pull decided one should land. Written in
        // THIS mutator and before the commit, so a key record and the secret it
        // claims can never be committed apart.
        //
        // ABSENT SECRETS MEANS NO INFORMATION, NEVER "DELETE THE BODY". `merge`
        // discards the loser's secrets, absent included, so a device that does
        // not carry bodies wins every merge with `secrets` unset - against a
        // local body that is perfectly good. Reading that as a reconcile would
        // destroy a private key the user still holds, on an ordinary background
        // pull. So this writes a body when one arrives and deletes none when
        // none did.
        //
        // THE GATE IS NOT HERE. Whether a body is allowed onto this device at
        // all is the carry toggle's question, and the scheduler answers it by
        // dropping `secrets` off the landing before this function sees it -
        // which is also what keeps the two sides of the pull's
        // `secretsChanged` comparison symmetric.
        let landed: Record<string, boolean> = {};
        if (landing.secrets) {
          try {
            landed = await landKeySecrets(landing.id, landing.secrets);
          } catch (e) {
            refusals.push({
              kind: KEY_TOMBSTONE_KIND,
              id: landing.id,
              reason: `the keychain refused to store this key's body: ${describeError(e)}`,
            });
            continue;
          }
        }
        // The presence flags are raised PER FIELD ACTUALLY WRITTEN rather than
        // per landing: a landing carrying only a passphrase must not have the
        // record claim a private key nobody sent.
        const idx = nextKeys.findIndex((k) => k.id === landing.id);
        const record: VaultKey = {
          ...landing.record,
          ...landed,
          updatedAt: landing.updatedAt,
          lastConnectedAt: idx >= 0 ? nextKeys[idx].lastConnectedAt : undefined,
        };
        if (idx >= 0) nextKeys[idx] = record;
        else nextKeys.push(record);
        const buriedIdx = buried.findIndex((t) => t.id === landing.id);
        if (buriedIdx >= 0) buried.splice(buriedIdx, 1);
        revived.push(landing.id);
        keysTouched = true;
      }

      const entries: [string, unknown][] = [];
      if (identitiesTouched) entries.push([VAULT_IDENTITIES_KEY, nextIdentities]);
      if (keysTouched) entries.push([VAULT_KEYS_KEY, nextKeys]);
      const next = landedTombstones(graves, revived, buried, at);
      if (next) entries.push([TOMBSTONES_KEY, next]);
      // An apply with nothing to write costs no commit, which is what keeps a
      // pull that landed nothing - the ordinary case once two devices agree -
      // from rewriting the file anyway.
      if (entries.length > 0) await persist(entries, []);
      return refusals;
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
    markIdentityConnected,
    applyRemote,
    listTombstones: () => readTombstones(),
    onVaultChanged: (cb) => io.store.onChanged(cb),
    ensureLoaded: () => io.store.ensureLoaded(),
    fileState: () => io.store.fileState(),
    takeRecoveryNotice: () => io.store.takeRecoveryNotice(),
  };
}

/** The app's vault. One instance, so one write queue. */
export const vaultStore = createVaultStore({
  store: createTauriVaultStoreIo(),
  secrets: tauriSecretsIo,
  // See the same line in `modules/hosts/store.ts`, and `src/lib/dirtySink.ts`
  // for why the marks travel through a sink rather than a direct call.
  markDirty,
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
  applyRemote,
  listTombstones,
  onVaultChanged,
  ensureLoaded,
  fileState,
  takeRecoveryNotice,
} = vaultStore;
