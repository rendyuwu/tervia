import type { StoreRecovery } from "@/lib/storeRecovery";
import { tauriSecretsIo } from "@/modules/vault/adapters";
import type { SshSecretValues } from "@/modules/vault/resolve";
import type { SecretInput } from "@/modules/vault/store";
import {
  assertBindingOwner,
  HOST_KEYRING_SERVICE,
  HOST_RDP_PASSWORD_FIELD,
  HOST_SSH_KEY_PASSPHRASE_FIELD,
  HOST_SSH_PASSWORD_FIELD,
  HOST_SSH_PRIVATE_KEY_FIELD,
  vaultAccount,
  type IdentityHostRefs,
  type RdpCredentialBinding,
  type RdpInlineCredentials,
  type SshCredentialBinding,
  type SshInlineCredentials,
  type VaultRef,
} from "@/modules/vault/types";

import { createTauriHostsStoreIo, type HostsIo } from "./adapters";
import {
  HOSTS_KEY,
  HOST_GROUPS_KEY,
  HOST_RDP_SECRET_FIELDS,
  HOST_SSH_SECRET_FIELDS,
  hostFingerprint,
  type Host,
  type HostGroup,
  type RdpHost,
  type SshHost,
} from "./types";

// The unified host store: metadata and presence flags here, secrets in the
// keychain under `tervia-hosts :: <hostId>::<field>`.
//
// Every integrity rule lives in THIS layer rather than in a dialog, because a
// dialog is never the only writer: an import, a duplicate action, a
// command-palette entry and the next window each would otherwise have to
// remember the rule. Three of the rules cost something specific when forgotten:
//
//   BINDING OWNERSHIP. A duplicate written as `{ ...source, id: newId() }` is
//   well-typed and carries the source's `hostId` inside its credential, after
//   which the copy authenticates with the SOURCE's secrets - rotating one
//   password changes both, and deleting the source breaks the copy. Silently, in
//   every case. `assertBindingOwner` on every upsert is the only thing that
//   catches it.
//
//   A JUMP OR TUNNEL HOST IS AN SSH HOST. The two old stores could not express an
//   RDP jump host. One merged store can, and it is meaningless.
//
//   NO ACCOUNT OUTLIVES THE RECORD NAMING IT. There is no `secrets_list`
//   command, so an account nothing references is not merely untidy, it is
//   unreachable (§9.7). A delete clears the host's accounts, and an upsert clears
//   the ones the new record can no longer name.

/**
 * Secrets to write alongside one host. Three-state per field, the app-wide
 * convention: a string writes it (or clears the account when blank), and
 * `undefined` leaves whatever is stored alone - so an edit that never touched the
 * password field cannot wipe it.
 *
 * ONE shape for both protocols rather than a union, because a union of
 * all-optional objects does not narrow: `{ password }` satisfies both arms, so a
 * guard over it would prove nothing. The protocol decides which fields are legal
 * instead, and {@link HostsStore.upsertHost} REFUSES the rest rather than
 * ignoring it - a private key written against an RDP row lands at an account no
 * code path will ever read or delete.
 */
export type HostSecretInput = {
  password?: SecretInput;
  privateKey?: SecretInput;
  keyPassphrase?: SecretInput;
};

/**
 * Drop every forward rule that rides one host.
 *
 * INJECTED, never imported, for the reason {@link IdentityHostRefs} is:
 * `modules/forwards` does not exist until 6f, and when it does it will import
 * {@link Host} from here - so a hosts -> forwards import would close a cycle.
 *
 * Required, never optional. A caller allowed to pass nothing would skip it
 * silently, and a rule left behind names a host id that resolves to nothing,
 * which fails when the rule is next started - on a page the user was not looking
 * at when they deleted.
 *
 * Fails CLOSED: {@link HostsStore.deleteHost} awaits this before it touches the
 * keychain or the store, so a cleanup that throws leaves both sides intact
 * instead of leaving rules pointing at a host that is gone.
 */
export type ForwardRuleCleanup = (hostId: string) => void | Promise<void>;

/**
 * The stand-in until `modules/forwards` exists.
 *
 * Named rather than an inline `() => {}` at each call site so 6f finds every one
 * of them with a single grep, and so "no rules were cleaned up here" is a
 * deliberate statement rather than an omission.
 */
export const noForwardRules: ForwardRuleCleanup = () => {};

export type HostsStore = {
  listHosts(): Promise<Host[]>;
  listGroups(): Promise<HostGroup[]>;
  findHost(id: string): Promise<Host | undefined>;
  findGroup(id: string): Promise<HostGroup | undefined>;
  newHostId(): string;
  newGroupId(): string;
  upsertHost(host: Host, secrets?: HostSecretInput): Promise<Host>;
  upsertGroup(group: HostGroup): Promise<HostGroup>;
  duplicateHost(id: string): Promise<Host | null>;
  deleteHost(id: string, forwards: ForwardRuleCleanup): Promise<void>;
  deleteGroup(id: string): Promise<void>;
  getHostSshSecrets(id: string): Promise<SshSecretValues>;
  markConnected(id: string, fingerprint: string): Promise<void>;
  pinFingerprint(id: string, fingerprint: string): Promise<void>;
  clearFingerprint(id: string): Promise<void>;
  /**
   * The hosts bound to one vault identity, in the shape `deleteIdentity` refuses
   * with. This is the wiring {@link IdentityHostRefs} describes, and it lives
   * here because this is the only module that knows how a host names an identity.
   */
  identityHostRefs: IdentityHostRefs;
  onHostsChanged(cb: () => void): Promise<() => void>;
  /** Run the crash-recovery pass and first load, then hand back whatever the
   *  user should be told - once. The startup entry point. */
  ensureLoaded(): Promise<StoreRecovery | null>;
  /** The recovery notice if a read already triggered the pass. Prefer
   *  {@link HostsStore.ensureLoaded}. */
  takeRecoveryNotice(): StoreRecovery | null;
};

/** Opaque id. Stays stable across renames, because both the keychain accounts and
 *  the pinned server key are derived from it. */
function newId(prefix: string): string {
  return `${prefix}-${Math.random().toString(36).slice(2, 10)}${Date.now().toString(36)}`;
}

/** The accounts one host can own, which is a function of its protocol. Empty for
 *  a vault-bound host: it owns none. */
function secretFieldsFor(host: Host): readonly string[] {
  if (host.credential.kind !== "inline") return [];
  return host.protocol === "ssh" ? HOST_SSH_SECRET_FIELDS : HOST_RDP_SECRET_FIELDS;
}

/**
 * The same binding, owned by a different host.
 *
 * The one rewrite a duplicate MUST make. Without it the copy's binding names the
 * source, and `assertBindingOwner` refuses the write - which is the point: the
 * refusal is what turns a silent shared-secret bug into a failed save.
 */
function rebound(binding: SshCredentialBinding, hostId: string): SshCredentialBinding;
function rebound(binding: RdpCredentialBinding, hostId: string): RdpCredentialBinding;
function rebound(
  binding: SshCredentialBinding | RdpCredentialBinding,
  hostId: string,
): SshCredentialBinding | RdpCredentialBinding {
  return binding.kind === "inline" ? { ...binding, hostId } : binding;
}

/** The stored inline arm, or `undefined` when the stored record had none. The
 *  protocol check matters: an edit may change it, and flags read off the wrong
 *  arm would claim secrets that are not there. */
function storedSshInline(existing: Host | undefined): SshInlineCredentials | undefined {
  if (!existing || existing.protocol !== "ssh") return undefined;
  return existing.credential.kind === "inline" ? existing.credential : undefined;
}

function storedRdpInline(existing: Host | undefined): RdpInlineCredentials | undefined {
  if (!existing || existing.protocol !== "rdp") return undefined;
  return existing.credential.kind === "inline" ? existing.credential : undefined;
}

/** One host with its pin replaced, whichever field this protocol keeps it in. */
function withFingerprint(host: Host, fingerprint: string | undefined): Host {
  if (host.protocol === "ssh") return { ...host, lastFingerprint: fingerprint };
  return { ...host, certFingerprint: fingerprint };
}

function hostRef(host: Host): VaultRef {
  return { id: host.id, name: host.name };
}

/** Group names are compared the way a person reads them, so `" prod"` and
 *  `"PROD"` are the collision they look like. */
function sameName(a: string, b: string): boolean {
  return a.trim().toLowerCase() === b.trim().toLowerCase();
}

export function createHostsStore(io: HostsIo): HostsStore {
  // Serialized by the store port, not here: the queue only means anything if
  // there is one of it per store FILE, so it belongs beside the file. A chained
  // connect fires `markConnected` once per hop plus once for the target, so
  // concurrent read-modify-writes are the ordinary case, not the exotic one.
  const enqueueWrite = <T>(op: () => Promise<T>): Promise<T> => io.store.enqueueWrite(op);

  async function listHosts(): Promise<Host[]> {
    const raw = await io.store.get<Host[]>(HOSTS_KEY);
    return Array.isArray(raw) ? raw : [];
  }

  async function listGroups(): Promise<HostGroup[]> {
    const raw = await io.store.get<HostGroup[]>(HOST_GROUPS_KEY);
    return Array.isArray(raw) ? raw : [];
  }

  /** Every mutation lands through here. The commit is also what takes the `.bak`
   *  snapshot, which is why the session that CREATES the file has one: at first
   *  load there is nothing to copy, so the first successful write is the earliest
   *  moment the host list is protected at all. */
  async function persist(entries: [string, unknown][]): Promise<void> {
    for (const [key, value] of entries) await io.store.set(key, value);
    await io.store.commit();
  }

  function account(hostId: string, field: string): string {
    return vaultAccount(hostId, field);
  }

  /**
   * Write one secret and report the presence flag that now belongs in the record.
   *
   * `undefined` leaves the stored secret alone, and the flag then comes from the
   * STORED RECORD rather than from a keychain read-back. That part is deliberate:
   * the flags exist so a list of a hundred hosts costs zero `secrets_get` calls,
   * and a no-change write reading the secret back would spend exactly what they
   * were added to save.
   */
  async function writeSecret(
    hostId: string,
    field: string,
    value: SecretInput,
    current: boolean,
  ): Promise<boolean> {
    if (value === undefined) return current;
    const trimmed = value?.trim() ?? "";
    if (!trimmed) {
      await io.secrets.delete(HOST_KEYRING_SERVICE, account(hostId, field));
      return false;
    }
    await io.secrets.set(HOST_KEYRING_SERVICE, account(hostId, field), trimmed);
    return true;
  }

  /**
   * The three SSH accounts one host owns, read in one batch.
   *
   * The destructure follows {@link HOST_SSH_SECRET_FIELDS}, which is also the
   * order the accounts were requested in.
   */
  async function readSshSecrets(hostId: string): Promise<SshSecretValues> {
    const [password, privateKey, keyPassphrase] = await io.secrets.getAll(
      HOST_KEYRING_SERVICE,
      HOST_SSH_SECRET_FIELDS.map((f) => account(hostId, f)),
    );
    return { password, privateKey, keyPassphrase };
  }

  /** A vault-bound host owns no accounts, so a secret handed in with one would
   *  land where nothing reads it. Refused rather than dropped: the caller thinks
   *  it saved a password. */
  function assertNoHostSecrets(host: Host, secrets: HostSecretInput): void {
    const named = Object.entries(secrets)
      .filter(([, v]) => v !== undefined)
      .map(([k]) => k);
    if (named.length === 0) return;
    throw new Error(
      `hosts: "${host.name}" binds a vault identity and owns no accounts, so ` +
        `${named.join(", ")} cannot be stored on it - write it on the identity instead`,
    );
  }

  /**
   * Clear the host-owned accounts the new record can no longer name.
   *
   * Covers a credential moving inline -> vault, and a row changing protocol.
   * Without it those accounts are not merely stale: nothing enumerates them
   * again, and there is no `secrets_list` command, so "unreferenced" means
   * unreachable.
   *
   * Only what the STORED record owned is touched, so a convert-to-vault following
   * §5.3's order - copy the secrets to the vault FIRST, then rewrite the binding -
   * loses nothing. A converter that rewrote the binding first would.
   */
  async function releaseStaleAccounts(host: Host, existing: Host | undefined): Promise<void> {
    if (!existing) return;
    const keeps = new Set(secretFieldsFor(host));
    const stale = secretFieldsFor(existing).filter((f) => !keeps.has(f));
    if (stale.length === 0) return;
    await Promise.all(
      stale.map((f) => io.secrets.delete(HOST_KEYRING_SERVICE, account(host.id, f))),
    );
  }

  /**
   * Every account this host owns, cleared again after a write that threw partway.
   *
   * The hole this closes: `password` lands, `privateKey` throws, and the password
   * then sits at an account no record names. Rolled back only for a host that did
   * not exist before, which is what makes it safe - for an id the store has never
   * seen there was nothing at these accounts to lose, and `secrets_delete` reports
   * an absent account as success. For a host that DOES exist the accounts stay
   * reachable through `deleteHost`, and clearing them would destroy a stored
   * secret this layer cannot put back.
   *
   * A failing rollback is swallowed: the caller is already rethrowing the write's
   * own error, which is the one the user can act on.
   */
  async function rollbackNewHost(host: Host): Promise<void> {
    try {
      await Promise.all(
        secretFieldsFor(host).map((f) =>
          io.secrets.delete(HOST_KEYRING_SERVICE, account(host.id, f)),
        ),
      );
    } catch {
      // Replacing the real error with this one hides the reason.
    }
  }

  async function nextSshCredential(
    host: SshHost,
    secrets: HostSecretInput,
    existing: Host | undefined,
  ): Promise<SshCredentialBinding> {
    const binding = host.credential;
    if (binding.kind !== "inline") {
      assertNoHostSecrets(host, secrets);
      return binding;
    }
    const stored = storedSshInline(existing);
    try {
      return {
        ...binding,
        hasPassword: await writeSecret(
          host.id,
          HOST_SSH_PASSWORD_FIELD,
          secrets.password,
          stored?.hasPassword ?? false,
        ),
        hasPrivateKey: await writeSecret(
          host.id,
          HOST_SSH_PRIVATE_KEY_FIELD,
          secrets.privateKey,
          stored?.hasPrivateKey ?? false,
        ),
        hasKeyPassphrase: await writeSecret(
          host.id,
          HOST_SSH_KEY_PASSPHRASE_FIELD,
          secrets.keyPassphrase,
          stored?.hasKeyPassphrase ?? false,
        ),
      };
    } catch (e) {
      if (!existing) await rollbackNewHost(host);
      throw e;
    }
  }

  async function nextRdpCredential(
    host: RdpHost,
    secrets: HostSecretInput,
    existing: Host | undefined,
  ): Promise<RdpCredentialBinding> {
    const binding = host.credential;
    if (binding.kind !== "inline") {
      assertNoHostSecrets(host, secrets);
      return binding;
    }
    // An RDP row owns exactly one account, so key material handed in here has
    // nowhere to go. Refused rather than dropped, for the same reason as above.
    if (secrets.privateKey !== undefined || secrets.keyPassphrase !== undefined) {
      throw new Error(`hosts: "${host.name}" is an RDP host and stores no key material`);
    }
    return {
      ...binding,
      hasPassword: await writeSecret(
        host.id,
        HOST_RDP_PASSWORD_FIELD,
        secrets.password,
        storedRdpInline(existing)?.hasPassword ?? false,
      ),
    };
  }

  /**
   * Refuse a jump or tunnel target that is missing, is this host itself, or is not
   * an SSH host.
   *
   * The last one is the new rule. `resolveJumpHops` checks it too, and both are
   * needed: refusing at the connect alone leaves a saved row that can never
   * connect, and refusing at the write alone says nothing about a row an import
   * or another window put there.
   */
  function assertSshTarget(host: Host, targetId: string, hosts: Host[], role: string): void {
    if (targetId === host.id) {
      throw new Error(`hosts: "${host.name}" cannot be its own ${role}`);
    }
    const target = hosts.find((h) => h.id === targetId);
    if (!target) {
      throw new Error(`hosts: "${host.name}" names a ${role} that does not exist`);
    }
    if (target.protocol !== "ssh") {
      throw new Error(`hosts: "${target.name}" is an RDP host and cannot be a ${role}`);
    }
  }

  /**
   * `groupId` is deliberately NOT checked here. A group that has gone away leaves
   * its member rendering as ungrouped, which is visible and recoverable, so
   * refusing the whole save would lose a real edit over a label.
   */
  function assertReferences(host: Host, hosts: Host[]): void {
    if (host.protocol === "ssh") {
      // Falsy is "no jump host", matching `resolveJumpHops`.
      if (host.proxyJumpId) assertSshTarget(host, host.proxyJumpId, hosts, "jump host");
      return;
    }
    if (!host.tunnel) return;
    if (!host.tunnel.sshHostId) {
      throw new Error(`hosts: "${host.name}" has a tunnel that names no SSH host`);
    }
    assertSshTarget(host, host.tunnel.sshHostId, hosts, "tunnel host");
  }

  async function upsertHost(host: Host, secrets: HostSecretInput = {}): Promise<Host> {
    return enqueueWrite(async () => {
      // The write-time half of the binding invariant, and the only half there is.
      assertBindingOwner(host.credential, host.id);

      const hosts = await listHosts();
      assertReferences(host, hosts);
      const existing = hosts.find((h) => h.id === host.id);
      await releaseStaleAccounts(host, existing);

      const record: Host =
        host.protocol === "ssh"
          ? { ...host, credential: await nextSshCredential(host, secrets, existing) }
          : { ...host, credential: await nextRdpCredential(host, secrets, existing) };

      const next = [...hosts];
      const idx = next.findIndex((h) => h.id === host.id);
      if (idx >= 0) next[idx] = record;
      else next.push(record);
      // A `persist` that throws is deliberately NOT rolled back: `LazyStore` runs
      // with autoSave, so the record is already in the plugin's cache with a
      // debounced retry behind it, and clearing the secrets here would race that
      // into a record whose flags name material that is gone.
      await persist([[HOSTS_KEY, next]]);
      return record;
    });
  }

  async function upsertGroup(group: HostGroup): Promise<HostGroup> {
    return enqueueWrite(async () => {
      // Required, because a group is chosen by name from a dropdown: a blank one
      // is unpickable, and the collision warning below degenerates without it.
      if (!group.name.trim()) throw new Error("hosts: a group needs a name");
      const groups = await listGroups();
      if (groups.some((g) => g.id !== group.id && sameName(g.name, group.name))) {
        throw new Error(`hosts: a group is already named "${group.name.trim()}"`);
      }
      const next = [...groups];
      const idx = next.findIndex((g) => g.id === group.id);
      if (idx >= 0) next[idx] = group;
      else next.push(group);
      await persist([[HOST_GROUPS_KEY, next]]);
      return group;
    });
  }

  /**
   * Copy a saved host under a new id, for the case it exists for: the same
   * credential against a different address, without retyping anything.
   *
   * Three things the copy does NOT inherit.
   *
   * The BINDING'S OWNER: `rebound` points it at the copy's own id. Skipping that
   * is the spread-copy bug, and `assertBindingOwner` in `upsertHost` is what
   * turns it into a refused save rather than two hosts quietly sharing secrets.
   *
   * The PINNED SERVER KEY: it belongs to the machine that presented it, and a
   * copy exists to be pointed somewhere else. Carrying it over would fail the
   * next connect as a key MISMATCH, which reads as an attack rather than as a
   * copy. The copy takes one first-connect prompt instead.
   *
   * An RDP PASSWORD: there is no `secrets_copy` command, so duplicating one would
   * mean reading it into the webview, which is exactly the Phase 5 invariant. The
   * copy is saved with `hasPassword: false` and the password is re-entered once.
   * SSH secrets do travel, because SSH plaintext already round-trips through JS on
   * every connect (issues/11) - the copy adds no exposure that a connect does not.
   *
   * Deliberately NOT wrapped in `enqueueWrite`: it awaits `upsertHost`, which
   * enqueues, and an op waiting on a later entry in a serial queue never resolves.
   */
  async function duplicateHost(id: string): Promise<Host | null> {
    const source = (await listHosts()).find((h) => h.id === id);
    if (!source) return null;
    const copyId = newId("h");
    const name = `${source.name} (copy)`;

    if (source.protocol === "ssh") {
      const copy: SshHost = {
        ...source,
        id: copyId,
        name,
        credential: rebound(source.credential, copyId),
        lastConnectedAt: undefined,
        lastFingerprint: undefined,
      };
      const secrets =
        source.credential.kind === "inline" ? await readSshSecrets(source.id) : undefined;
      return upsertHost(copy, secrets);
    }

    const copy: RdpHost = {
      ...source,
      id: copyId,
      name,
      credential: rebound(source.credential, copyId),
      lastConnectedAt: undefined,
      certFingerprint: undefined,
    };
    return upsertHost(copy);
  }

  async function deleteHost(id: string, forwards: ForwardRuleCleanup): Promise<void> {
    return enqueueWrite(async () => {
      const hosts = await listHosts();
      const host = hosts.find((h) => h.id === id);
      if (!host) return;

      // First, and awaited: a throw here leaves the host and its rules both
      // intact, which is recoverable. The other order leaves rules naming a host
      // that no longer exists.
      await forwards(id);

      await Promise.all(
        secretFieldsFor(host).map((f) => io.secrets.delete(HOST_KEYRING_SERVICE, account(id, f))),
      );

      // Clear what pointed at this host, so a delete cannot leave another row
      // failing every connect with "a jump host in the chain no longer exists".
      const next = hosts
        .filter((h) => h.id !== id)
        .map((h) => {
          if (h.protocol === "ssh") {
            return h.proxyJumpId === id ? { ...h, proxyJumpId: undefined } : h;
          }
          return h.tunnel?.sshHostId === id ? { ...h, tunnel: undefined } : h;
        });
      await persist([[HOSTS_KEY, next]]);
    });
  }

  async function deleteGroup(id: string): Promise<void> {
    return enqueueWrite(async () => {
      const [groups, hosts] = await Promise.all([listGroups(), listHosts()]);
      if (!groups.some((g) => g.id === id)) return;
      // The one place a cascade is right: a group is a label, not an owner, so its
      // members lose the label and go on existing.
      await persist([
        [HOST_GROUPS_KEY, groups.filter((g) => g.id !== id)],
        [HOSTS_KEY, hosts.map((h) => (h.groupId === id ? { ...h, groupId: undefined } : h))],
      ]);
    });
  }

  /**
   * The three SSH secrets one host owns, in plaintext, for the host editor
   * prefilling a draft.
   *
   * Reading a secret back into JS is the PRE-EXISTING SSH defect (issues/11), not
   * one this store introduces: `resolveSshAuth` does the same on every connect and
   * every ProxyJump hop. It is SSH-only and there is deliberately no RDP
   * counterpart - an RDP password reaches the backend as a keychain reference and
   * must never enter the webview.
   *
   * Empty for a vault-bound host, which owns no accounts to read.
   */
  async function getHostSshSecrets(id: string): Promise<SshSecretValues> {
    const host = (await listHosts()).find((h) => h.id === id);
    if (!host || host.protocol !== "ssh" || host.credential.kind !== "inline") return {};
    return readSshSecrets(id);
  }

  /**
   * Read-modify-write one host through the serialized queue. `patch` returns the
   * next record, or null to write nothing. A missing id is a no-op: the host was
   * deleted mid-connect.
   */
  async function patchHost(id: string, patch: (current: Host) => Host | null): Promise<void> {
    return enqueueWrite(async () => {
      const hosts = await listHosts();
      const idx = hosts.findIndex((h) => h.id === id);
      if (idx < 0) return;
      const next = patch(hosts[idx]);
      if (!next) return;
      const list = [...hosts];
      list[idx] = next;
      await persist([[HOSTS_KEY, list]]);
    });
  }

  /** Marks a successful connect: the timestamp, and the key or certificate the
   *  server actually presented. */
  async function markConnected(id: string, fingerprint: string): Promise<void> {
    const at = Date.now();
    return patchHost(id, (h) =>
      h.protocol === "ssh"
        ? { ...h, lastConnectedAt: at, lastFingerprint: fingerprint || h.lastFingerprint }
        : { ...h, lastConnectedAt: at, certFingerprint: fingerprint || h.certFingerprint },
    );
  }

  /**
   * Records a server key or certificate the user just accepted in the
   * first-connect dialog.
   *
   * Separate from {@link markConnected} because trusting a key and connecting are
   * two different steps and only the first has happened: `openssh` writes
   * `known_hosts` the moment you answer yes, and the RDP backend pauses inside the
   * TLS handshake, both before any credential is sent. Pinning only on a fully
   * successful connect meant a wrong password re-asked the question on every
   * retry. `lastConnectedAt` is deliberately untouched: nothing has connected.
   */
  async function pinFingerprint(id: string, fingerprint: string): Promise<void> {
    if (!fingerprint) return;
    return patchHost(id, (h) =>
      hostFingerprint(h) === fingerprint ? null : withFingerprint(h, fingerprint),
    );
  }

  /** Clears the pinned key so the next connect re-pins via TOFU. Use after
   *  verifying a legitimate rotation - which for RDP is routine, since a
   *  self-signed certificate is regenerated on some reinstalls. */
  async function clearFingerprint(id: string): Promise<void> {
    return patchHost(id, (h) => withFingerprint(h, undefined));
  }

  const identityHostRefs: IdentityHostRefs = async (identityId) =>
    (await listHosts())
      .filter((h) => h.credential.kind === "identity" && h.credential.identityId === identityId)
      .map(hostRef);

  return {
    listHosts,
    listGroups,
    findHost: async (id) => (await listHosts()).find((h) => h.id === id),
    findGroup: async (id) => (await listGroups()).find((g) => g.id === id),
    newHostId: () => newId("h"),
    newGroupId: () => newId("g"),
    upsertHost,
    upsertGroup,
    duplicateHost,
    deleteHost,
    deleteGroup,
    getHostSshSecrets,
    markConnected,
    pinFingerprint,
    clearFingerprint,
    identityHostRefs,
    onHostsChanged: (cb) => io.store.onChanged(cb),
    ensureLoaded: () => io.store.ensureLoaded(),
    takeRecoveryNotice: () => io.store.takeRecoveryNotice(),
  };
}

/** The app's host list. One instance, so one write queue. */
export const hostsStore = createHostsStore({
  store: createTauriHostsStoreIo(),
  secrets: tauriSecretsIo,
});

export const {
  listHosts,
  listGroups,
  findHost,
  findGroup,
  newHostId,
  newGroupId,
  upsertHost,
  upsertGroup,
  duplicateHost,
  deleteHost,
  deleteGroup,
  getHostSshSecrets,
  markConnected,
  pinFingerprint,
  clearFingerprint,
  identityHostRefs,
  onHostsChanged,
  ensureLoaded,
  takeRecoveryNotice,
} = hostsStore;
