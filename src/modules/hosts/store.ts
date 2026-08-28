import type { StoreRecovery } from "@/lib/storeRecovery";
import { tauriSecretsIo } from "@/modules/vault/adapters";
import { hostsUsingIdentity } from "@/modules/vault/refs";
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
  VaultInUseError,
  type IdentityHostRefs,
  type RdpCredentialBinding,
  type RdpInlineCredentials,
  type SshCredentialBinding,
  type SshInlineCredentials,
  type VaultRef,
} from "@/modules/vault/types";

import { createTauriHostsStoreIo, defaultHostFiles, type HostsIo } from "./adapters";
import { jumpChain } from "./jumps";
import { purgeLegacySecrets as runLegacyPurge, type LegacyPurgeResult } from "./legacyPurge";
import {
  credentialStamp,
  HOSTS_KEY,
  HOST_GROUPS_KEY,
  HOST_RDP_SECRET_FIELDS,
  HOST_SSH_SECRET_FIELDS,
  HostBindingChangedError,
  hostFingerprint,
  hostPins,
  type Host,
  type HostGroup,
  type HostPins,
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
//   A JUMP OR TUNNEL HOST IS AN SSH HOST, AND THE CHAIN DOES NOT LOOP. The two
//   old stores could not express an RDP jump host. One merged store can, and it is
//   meaningless. The whole chain is walked, not just the first hop: a 2-cycle used
//   to save on both sides and then fail every connect to either host.
//
//   NO ACCOUNT OUTLIVES THE RECORD NAMING IT, AND NO RECORD OUTLIVES ITS ACCOUNT.
//   There is no `secrets_list` command, so an account nothing references is not
//   merely untidy, it is unreachable (§9.7). A delete clears the host's accounts,
//   and an upsert clears the ones the new record can no longer name - AFTER the
//   new record is on disk, never before, because nothing here can read a secret
//   back to undo a release that a failed write leaves unjustified. `legacyPurge.ts`
//   is the same rule pointed at the two old connection stores.

/**
 * The secret is ALREADY at this host's account: record it as present and write
 * nothing.
 *
 * The fourth state, and it exists for exactly one caller. A backup import has
 * `backup_apply_secrets` write the credential to the keychain from Rust and get
 * back only a `boolean[]` - the value never reaches JS, which for an RDP password
 * is a Phase 5 invariant rather than a preference. Without this, the import can
 * only pass `undefined`, and a host the store has never seen then takes its flags
 * from an absent record: every flag false over a live secret. SSH survives that
 * (`resolveSshAuth` resolves by auth mode and never reads a flag) but RDP does
 * not - `RdpPane` pre-flights `hasPassword` and refuses to connect.
 *
 * A `Symbol` rather than a sentinel string, and that is the point rather than
 * taste: `JSON.parse` cannot produce one, so no imported file, no store row and
 * no IPC payload can reach this branch by carrying the right characters. A
 * `"__already_stored"` could, and the caller that would hand it over is the one
 * parsing an untrusted backup. Do not simplify it to a string.
 */
export const SECRET_ALREADY_STORED = Symbol("hosts.secretAlreadyStored");

/** One field of {@link HostSecretInput}: the three-state convention plus
 *  {@link SECRET_ALREADY_STORED}. */
export type HostSecretValue = SecretInput | typeof SECRET_ALREADY_STORED;

/**
 * Secrets to write alongside one host. Three-state per field, the app-wide
 * convention: a string writes it (or clears the account when blank), and
 * `undefined` leaves whatever is stored alone - so an edit that never touched the
 * password field cannot wipe it. {@link SECRET_ALREADY_STORED} is the fourth
 * state, for a caller that put the secret there without holding it.
 *
 * ONE shape for both protocols rather than a union, because a union of
 * all-optional objects does not narrow: `{ password }` satisfies both arms, so a
 * guard over it would prove nothing. The protocol decides which fields are legal
 * instead, and {@link HostsStore.upsertHost} REFUSES the rest rather than
 * ignoring it - a private key written against an RDP row lands at an account no
 * code path will ever read or delete.
 */
export type HostSecretInput = {
  password?: HostSecretValue;
  privateKey?: HostSecretValue;
  keyPassphrase?: HostSecretValue;
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
  /**
   * `expect` is the credential stamp the caller loaded, from
   * {@link credentialStamp}. Supplied, the write is refused unless the stored
   * record still carries that binding; omitted, the write is unconditional.
   *
   * Optional, and that is a statement rather than an oversight: an import and a
   * duplicate hold no earlier snapshot of the record, so a required parameter
   * would only make them invent one. The caller that DOES hold one is the editor,
   * and `scripts/host-editor-verify.ts` is what proves it still passes it.
   */
  upsertHost(host: Host, secrets?: HostSecretInput, expect?: string): Promise<Host>;
  upsertGroup(group: HostGroup): Promise<HostGroup>;
  duplicateHost(id: string): Promise<Host | null>;
  deleteHost(id: string, forwards: ForwardRuleCleanup): Promise<void>;
  deleteGroup(id: string): Promise<void>;
  getHostSshSecrets(id: string): Promise<SshSecretValues>;
  markConnected(id: string, fingerprint: string): Promise<void>;
  pinFingerprint(id: string, fingerprint: string): Promise<void>;
  // No `clearFingerprint`. It existed for the editor's Forget button, which now
  // records the intent in the DRAFT and lets Save apply it - because a Forget that
  // wrote straight through left a cancelled dialog having silently put the host
  // back on TOFU, with the pin unrecoverable since only that machine can present
  // it. Nothing else ever cleared a pin, so keeping the method would have left a
  // store write reachable that no UI path is allowed to make.
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
  /**
   * Clear the keychain accounts the two OLD connection stores left behind, once.
   *
   * On the store's surface because the marker that makes it one-shot lives in the
   * hosts store file, so it shares this store's queue rather than racing it. Safe
   * on every launch, and it never rejects - see `legacyPurge.ts`.
   */
  purgeLegacySecrets(): Promise<LegacyPurgeResult>;
  /** The recovery notice if a read already triggered the pass. Prefer
   *  {@link HostsStore.ensureLoaded}. */
  takeRecoveryNotice(): StoreRecovery | null;
};

/** Opaque id. Stays stable across renames, because both the keychain accounts and
 *  the pinned server key are derived from it. */
function newId(prefix: string): string {
  return `${prefix}-${Math.random().toString(36).slice(2, 10)}${Date.now().toString(36)}`;
}

/**
 * One field of {@link HostSecretInput}, which is also the name of the keychain
 * account that field writes to - an account is named after the presence flag
 * tracking it, so the mapping is mechanical rather than memorised.
 */
type HostSecretField = keyof HostSecretInput;

/** The accounts one host can own, which is a function of its protocol. Empty for
 *  a vault-bound host: it owns none. */
function secretFieldsFor(host: Host): readonly HostSecretField[] {
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

/** The stored inline arm, or `undefined` when the stored record had none. */
function storedSshInline(existing: Host | undefined): SshInlineCredentials | undefined {
  if (!existing || existing.protocol !== "ssh") return undefined;
  return existing.credential.kind === "inline" ? existing.credential : undefined;
}

function storedRdpInline(existing: Host | undefined): RdpInlineCredentials | undefined {
  if (!existing || existing.protocol !== "rdp") return undefined;
  return existing.credential.kind === "inline" ? existing.credential : undefined;
}

/**
 * What the STORED record says about ONE ACCOUNT, which is the only thing an
 * untouched field may take its flag from.
 *
 * Keyed on the account FIELD rather than on the stored arm, because a field
 * outlives a protocol change: `HOST_SSH_PASSWORD_FIELD` and
 * `HOST_RDP_PASSWORD_FIELD` are both `"password"`, so a host flipped SSH -> RDP
 * keeps the secret already sitting at `<hostId>::password` - see
 * `releaseStaleAccounts`, which by design releases only what the new record
 * cannot NAME.
 *
 * Reading the flag off the new protocol's arm alone is what made that a real
 * hazard rather than untidiness: the stored arm was SSH, so an RDP row came back
 * `hasPassword: false` while the password was still in the keychain - and
 * `resolveRdpAuth` hands `rdp_open` that account reference UNCONDITIONALLY, so the
 * backend authenticated with a secret the record denied. The record then warns
 * "no secret" over a live one, and an export keyed on the flag omits a credential
 * in use. The reverse flip is the same defect through `sshAccountsFor`, which
 * also resolves by auth mode and never consults a flag.
 *
 * So the flag follows the ACCOUNT. `false` for a field the stored record did not
 * own - a vault binding owns none, and an RDP row never owned key material, which
 * is exactly when the account was released.
 */
function storedFlag(existing: Host | undefined, field: string): boolean {
  if (!existing) return false;
  if (existing.protocol === "rdp") {
    return field === HOST_RDP_PASSWORD_FIELD && (storedRdpInline(existing)?.hasPassword ?? false);
  }
  const stored = storedSshInline(existing);
  if (!stored) return false;
  switch (field) {
    case HOST_SSH_PASSWORD_FIELD:
      return stored.hasPassword;
    case HOST_SSH_PRIVATE_KEY_FIELD:
      return stored.hasPrivateKey;
    case HOST_SSH_KEY_PASSPHRASE_FIELD:
      return stored.hasKeyPassphrase;
    default:
      return false;
  }
}

/**
 * One host carrying `pins`, with the flat pin field PROJECTED from it - the only
 * shape this store persists, and the reason nothing outside this module has to
 * know pins are keyed at all.
 *
 * `ssh-session.ts`, `tunnel.ts`, `jumps.ts` and `rdp/dial.ts` each read the flat
 * field and hand it to the backend as the fingerprint to expect. So the flat field
 * has to be the pin for the address the record names and nothing else: a pin left
 * over from a previous address would be compared against a different machine and
 * abort the connect as a MISMATCH, which is the failure this keying exists to
 * remove rather than relocate.
 *
 * An empty map is stored as ABSENT, so a row that never pinned anything does not
 * grow a key. {@link hostPins} reads the two the same way round.
 */
function withPins(host: Host, pins: HostPins): Host {
  const keyed = Object.keys(pins).length > 0 ? pins : undefined;
  const flat = pins[host.host];
  if (host.protocol === "ssh") return { ...host, pins: keyed, lastFingerprint: flat };
  return { ...host, pins: keyed, certFingerprint: flat };
}

/**
 * The keyed pins to persist for an incoming record, which is the one place a flat
 * pin with no map has to be given an address.
 *
 * Three readings of that record, and the STORED record is what tells them apart.
 *
 * A MAP was handed over: the caller has said which address each key belongs to, so
 * there is nothing to infer and nothing else is consulted. That is every save from
 * the editor - and every row an import writes, because `carryPins` in
 * `ssh/backupFile.ts` builds the map there rather than leaving it to be guessed
 * here.
 *
 * NO MAP AND NO STORED RECORD - a first save: the flat pin can only mean this
 * record's own address, because there is no earlier address for it to have come
 * from.
 *
 * NO MAP AND THE ADDRESS HAS CHANGED: the flat pin is filed under the address the
 * STORED record named, never moved onto the new machine - that is the
 * mis-attribution the old `keepPin` existed to prevent, and a pin compared against
 * the wrong machine aborts the next connect as an attack. Not dropped either:
 * re-pointing back finds it again. This is the branch a `{ ...stored, host: next }`
 * spread in 6e or 6f lands in, and it is correct without that caller knowing pins
 * exist.
 *
 * AND IT ONLY FILES INTO AN EMPTY SLOT, which is the one thing this cannot take on
 * trust. The branch's premise is that the flat pin was read off the stored row, and
 * that is not checkable from here: for a spread it holds, because the flat field IS
 * this store's projection of `carried` at the stored address - so the write is a
 * no-op and `carried[existing.host]` is exactly the pin being handed back. A caller
 * whose flat pin came from anywhere else, with no map and a changed address, cannot
 * be identified, and the two ways of being wrong about it are not symmetric.
 * OVERWRITING puts a different machine's key at an address the user may return to,
 * and that connect aborts as a MISMATCH - which reads as an attack (§5.16), out of
 * a save that was about something else. DROPPING leaves that address exactly as
 * fail-open as it was before the pin existed. Both leave the new address unpinned;
 * only overwriting manufactures a false alarm. So a key already keyed at the stored
 * address wins, and the unattributable pin is discarded rather than filed over it.
 *
 * A file WAS that caller - same inputs, opposite correct answer - which is why the
 * disambiguation belongs at the call site: `carryPins` in `ssh/backupFile.ts` builds
 * the map from the FILE's own address, so no import reaches this branch at all.
 */
function nextPins(host: Host, existing: Host | undefined): HostPins {
  if (host.pins) return host.pins;
  const carried = existing ? hostPins(existing) : {};
  const flat = hostFingerprint(host);
  if (!flat) return carried;
  if (!existing || existing.host === host.host) return { ...carried, [host.host]: flat };
  // A blank pin is never stored - `withFingerprint` deletes the key rather than
  // keying an empty string, and `pinsOf` drops one at the import boundary - so
  // presence and truthiness are the same question here.
  return carried[existing.host] ? carried : { ...carried, [existing.host]: flat };
}

/**
 * One host with the pin for the address it CURRENTLY NAMES replaced.
 *
 * The address comes from the record rather than from the caller, and that is what
 * lets {@link HostsStore.pinFingerprint} keep a two-argument signature: the connect
 * that was presented this key dialled the address the record names, so the record
 * is the only place the key can belong. A caller that wanted to pin some other
 * address would be describing a machine this host is not pointed at.
 *
 * Only ever called with a record read from THIS store - both callers come through
 * `patchHost` - which is what makes {@link hostPins}'s adoption of an unkeyed pin
 * safe here: a stored record's flat pin is the pin for its own address by
 * construction. An incoming record from a caller goes through {@link nextPins}
 * instead, which does not assume that.
 */
function withFingerprint(host: Host, fingerprint: string | undefined): Host {
  const pins: Record<string, string> = { ...hostPins(host) };
  if (fingerprint) pins[host.host] = fingerprint;
  else delete pins[host.host];
  return withPins(host, pins);
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

  /**
   * Every mutation lands through here. The commit is also what takes the `.bak`
   * snapshot, which is why the session that CREATES the file has one: at first
   * load there is nothing to copy, so the first successful write is the earliest
   * moment the host list is protected at all.
   *
   * NOT atomic across keys, and one caller passes two. `deleteGroup` sets the group
   * list and the host list before this commits, so a throw on the second `set`
   * leaves the first in the plugin's cache with the 200 ms autosave still behind it
   * - persisting the group removal without clearing `groupId` on its members.
   * Benign by design (a dangling `groupId` renders as ungrouped, which is what
   * deleting the group was for) and named here because it is the one place the
   * multi-key contract is weaker than it reads. A real fix is VLT-19's atomic store
   * write, not a second commit here.
   */
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
   *
   * {@link SECRET_ALREADY_STORED} is the one input that reports `true` without
   * touching the keychain at all - no set, no delete, and no read either, which is
   * what keeps it inside the no-read-back rule above rather than an exception to
   * it. The caller has already put the value at this account.
   */
  async function writeSecret(
    hostId: string,
    field: string,
    value: HostSecretValue,
    current: boolean,
  ): Promise<boolean> {
    if (value === SECRET_ALREADY_STORED) return true;
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

  /**
   * Copy every account the SOURCE owns onto the accounts `copyId` will own, and
   * report what actually arrived.
   *
   * The report is the point, and it is why this returns write instructions rather
   * than nothing. A copy's `has*` flags may only describe what `secrets_copy`
   * found: the source record's flags arrive for free through the `rebound` spread,
   * and if the source claims a secret the keychain no longer holds, propagating
   * that claim writes a flag that is wrong forever - this layer never reads a
   * secret back, so nothing can ever correct it. §5.4 is the same failure with a
   * different cause. So a field that copied comes back as
   * {@link SECRET_ALREADY_STORED} - present, nothing left to write - and a field
   * that did not is OMITTED, which for an id the store has never seen resolves to
   * `false` with no further IPC.
   *
   * NO VALUE PASSES THROUGH HERE. `secrets_copy` reads and writes in-process,
   * which is what lets an RDP password travel at all: the old code could only
   * read SSH secrets back through JS, so the RDP half of a duplicate silently got
   * no password.
   *
   * SEQUENTIAL, which is now what every account fan-out in this file does - see
   * `deleteAccounts`. On Linux and Windows one write is a read-modify-write of the
   * whole secrets file, and the delete fan-outs this comment used to contrast
   * itself against are exactly what broke SSH host delete. A vault-bound source
   * owns no accounts, so this is an empty loop and no IPC.
   */
  async function copyHostSecrets(source: Host, copyId: string): Promise<HostSecretInput> {
    const out: HostSecretInput = {};
    for (const field of secretFieldsFor(source)) {
      const copied = await io.secrets.copy(
        { service: HOST_KEYRING_SERVICE, account: account(source.id, field) },
        { service: HOST_KEYRING_SERVICE, account: account(copyId, field) },
      );
      if (copied) out[field] = SECRET_ALREADY_STORED;
    }
    return out;
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
   * Clear a list of this host's accounts, ONE AT A TIME.
   *
   * Sequential, and that is the point rather than a style choice. Every
   * `secrets_delete` on Linux and Windows is a read-modify-write of the whole
   * secrets file, and each one stages through the temp path `atomic_write` derives
   * from that file - so three at once, which is what an SSH host owns, had two of
   * them renaming a temp the third had already consumed. `os error 2`, and SSH
   * host delete never completed while RDP host delete, owning one account, always
   * did. `secrets.rs` holds its cache lock across the write now and
   * `fs/atomic.rs` serializes per target, so this is no longer load-bearing for
   * correctness - it is kept because rewriting one file three times over is work
   * nobody asked for, and because a fan-out that only works thanks to a lock two
   * layers down is a thing the next reader has to go and check.
   *
   * The one behavioural difference from the `Promise.all` this replaces: a throw
   * stops the run, so the accounts after it are not attempted. `rollbackNewHost`
   * does not care - it swallows the error either way. `releaseStaleAccounts` does,
   * because it names the unreachable accounts in a message, so it calls this one
   * field at a time and counts.
   */
  async function deleteAccounts(hostId: string, fields: readonly HostSecretField[]): Promise<void> {
    for (const field of fields) {
      await io.secrets.delete(HOST_KEYRING_SERVICE, account(hostId, field));
    }
  }

  /**
   * Clear the host-owned accounts the new record can no longer NAME.
   *
   * Covers a credential moving inline -> vault, and a row changing protocol.
   * Without it those accounts are not merely stale: nothing enumerates them
   * again, and there is no `secrets_list` command, so "unreferenced" means
   * unreachable.
   *
   * Only what the STORED record owned is touched, so a convert-to-vault following
   * §5.3's order - copy the secrets to the vault FIRST, then rewrite the binding -
   * loses nothing. A converter that rewrote the binding first would.
   *
   * A field BOTH protocols own survives a protocol change, and that is the
   * behaviour rather than an oversight: nothing has been copied anywhere, so
   * deleting it would destroy the only copy of a secret this layer cannot read
   * back. `storedFlag` is what makes it honest, by carrying the flag across with
   * the account.
   *
   * MUST run after the record is persisted - see the call site.
   */
  async function releaseStaleAccounts(host: Host, existing: Host | undefined): Promise<void> {
    if (!existing) return;
    const keeps = new Set(secretFieldsFor(host));
    const stale = secretFieldsFor(existing).filter((f) => !keeps.has(f));
    if (stale.length === 0) return;
    // One field at a time and COUNTED, because the message below names what is
    // unreachable and has to be true. `deleteAccounts` stops at the first throw,
    // so the fields after it were never attempted while the ones before it are
    // already gone - and naming the whole list would send the user looking for
    // bytes that are not there, in a message whose whole job is saying where they
    // are. `secrets_delete` reports an absent account as success, so a cleared
    // field is cleared.
    let cleared = 0;
    try {
      for (const field of stale) {
        await deleteAccounts(host.id, [field]);
        cleared++;
      }
    } catch (e) {
      // Re-worded rather than rethrown, because the record IS saved and is
      // accurate about what it owns: reporting the keychain's error alone would
      // read as "your edit was not saved". Not swallowed either - what is left is
      // bytes at an account nothing names, and no `secrets_list` can find them.
      const why = e instanceof Error ? e.message : String(e);
      const left = stale.slice(cleared);
      throw new Error(
        `hosts: "${host.name}" was saved, but ${left.join(", ")} could not be cleared ` +
          `from the keychain and is now unreachable: ${why}`,
      );
    }
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
      await deleteAccounts(host.id, secretFieldsFor(host));
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
    try {
      return {
        ...binding,
        hasPassword: await writeSecret(
          host.id,
          HOST_SSH_PASSWORD_FIELD,
          secrets.password,
          storedFlag(existing, HOST_SSH_PASSWORD_FIELD),
        ),
        hasPrivateKey: await writeSecret(
          host.id,
          HOST_SSH_PRIVATE_KEY_FIELD,
          secrets.privateKey,
          storedFlag(existing, HOST_SSH_PRIVATE_KEY_FIELD),
        ),
        hasKeyPassphrase: await writeSecret(
          host.id,
          HOST_SSH_KEY_PASSPHRASE_FIELD,
          secrets.keyPassphrase,
          storedFlag(existing, HOST_SSH_KEY_PASSPHRASE_FIELD),
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
        storedFlag(existing, HOST_RDP_PASSWORD_FIELD),
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
      if (host.proxyJumpId) {
        assertSshTarget(host, host.proxyJumpId, hosts, "jump host");
        // The TRANSITIVE half. `assertSshTarget` catches the 1-cycle and the
        // dangling id; only the walk catches A -> B -> A, which otherwise saves
        // on both sides and then fails every connect to EITHER host with this
        // same error - the asymmetry with the dangling-id refusal is what reads
        // as a bug. Walked from the incoming record's own start id, so the row
        // is judged by what it is about to become.
        jumpChain(host.proxyJumpId, host.id, hosts);
      }
      return;
    }
    if (!host.tunnel) return;
    if (!host.tunnel.sshHostId) {
      throw new Error(`hosts: "${host.name}" has a tunnel that names no SSH host`);
    }
    assertSshTarget(host, host.tunnel.sshHostId, hosts, "tunnel host");
    // A tunnel host carries its own jump chain, resolved on the same connect, so
    // the same walk applies. An RDP host has no `proxyJumpId` and cannot appear
    // in a chain, so seeding the walk with its id only ever helps.
    jumpChain(host.tunnel.sshHostId, host.id, hosts);
  }

  async function upsertHost(
    host: Host,
    secrets: HostSecretInput = {},
    expect?: string,
  ): Promise<Host> {
    return enqueueWrite(() => writeHost(host, secrets, expect));
  }

  /**
   * The body of {@link upsertHost}, WITHOUT the queue.
   *
   * Private, and called un-queued from exactly one place: `duplicateHost`, which
   * has to read the source and write the copy inside ONE queue entry or another
   * window's rotation lands between the two. Nothing else may call it - a write
   * outside the queue is the lost-update this store exists to prevent.
   */
  async function writeHost(host: Host, secrets: HostSecretInput, expect?: string): Promise<Host> {
    // The write-time half of the binding invariant, and the only half there is.
    assertBindingOwner(host.credential, host.id);

    const hosts = await listHosts();
    assertReferences(host, hosts);
    const existing = hosts.find((h) => h.id === host.id);

    // INSIDE the queue, and before any secret is written. Inside, because a check
    // the caller ran before calling has a window between its read and this write
    // that another writer fits in - `writeHost` runs as one queue entry, so the
    // record read here is the record about to be replaced, with nothing able to
    // land in between. Before, because a refusal must leave the keychain exactly
    // as it was: `nextSshCredential` below writes up to three accounts, and a
    // refusal after that has already mutated the thing it was refusing to touch.
    if (expect !== undefined) {
      const current = credentialStamp(existing);
      if (current !== expect) {
        throw new HostBindingChangedError(host.id, host.name, expect, current);
      }
    }

    const credentialed: Host =
      host.protocol === "ssh"
        ? { ...host, credential: await nextSshCredential(host, secrets, existing) }
        : { ...host, credential: await nextRdpCredential(host, secrets, existing) };
    // Pins resolved and projected HERE rather than trusted from the caller,
    // because this is the layer every writer goes through and the flat field is
    // what every CONSUMER reads. A record arriving with a pin for an address it no
    // longer names must not have that pin projected onto the new address, and this
    // is what makes that structural instead of remembered by each writer. Nothing
    // is discarded: the pin stays in the map under the address it belongs to.
    const record: Host = withPins(credentialed, nextPins(credentialed, existing));

    const next = [...hosts];
    const idx = next.findIndex((h) => h.id === host.id);
    if (idx >= 0) next[idx] = record;
    else next.push(record);
    // A `persist` that throws is deliberately NOT rolled back: `LazyStore` runs
    // with autoSave, so the record is already in the plugin's cache with a
    // debounced retry behind it, and clearing the secrets here would race that
    // into a record whose flags name material that is gone.
    await persist([[HOSTS_KEY, next]]);

    // AFTER the rewrite, never before, which is §5.3's ordering: every step up to
    // the rewrite is additive, so a `persist` that throws leaves the old record
    // still naming secrets that are still there. Releasing first is the "step 5
    // before step 4" the spec calls out - and a protocol change has NO copy step,
    // so nothing preserves the secret anywhere and a throw at `persist` costs the
    // user their only copy of a key while the stored record still claims it. What
    // is left instead is the lesser evil the spec ranks below it: an orphan
    // account after a good write.
    await releaseStaleAccounts(host, existing);
    return record;
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
   * Two things the copy does NOT inherit.
   *
   * The BINDING'S OWNER: `rebound` points it at the copy's own id. Skipping that
   * is the spread-copy bug, and `assertBindingOwner` in `upsertHost` is what
   * turns it into a refused save rather than two hosts quietly sharing secrets.
   *
   * THE PINNED SERVER KEYS: they belong to the machines that presented them, and
   * a copy exists to be pointed somewhere else. Carrying them over would fail the
   * next connect as a key MISMATCH, which reads as an attack rather than as a
   * copy. The copy takes one first-connect prompt instead. The keyed map goes with
   * the flat field, and dropping the map is the load-bearing half now: the flat
   * field is a projection, so clearing it alone would have the store put it
   * straight back from `pins` at the copy's (identical) address.
   *
   * The SECRETS DO travel, both protocols, and never through JS: `secrets_copy`
   * moves each account in-process. An RDP password used to be the exception -
   * there was no such command, so copying one would have meant reading it into
   * the webview, and the copy was saved with `hasPassword: false` instead. A
   * VAULT-BOUND source owns no accounts, so there is nothing to copy and the
   * binding is SHARED rather than duplicated, which is the point of a vault entry.
   *
   * ONE queue entry covers the read AND the write, through the un-queued
   * `writeHost`. Calling `upsertHost` from inside the queue would deadlock - an op
   * waiting on a later entry in a serial queue never resolves - but reading
   * outside it was its own bug: another window rotating the source's password
   * between the read and the write left the copy holding the pre-rotation value
   * and claiming `hasPassword: true`.
   */
  async function duplicateHost(id: string): Promise<Host | null> {
    return enqueueWrite(async () => {
      const source = (await listHosts()).find((h) => h.id === id);
      if (!source) return null;
      const copyId = newId("h");
      const name = `${source.name} (copy)`;
      const copy: Host =
        source.protocol === "ssh"
          ? {
              ...source,
              id: copyId,
              name,
              credential: rebound(source.credential, copyId),
              lastConnectedAt: undefined,
              pins: {},
              lastFingerprint: undefined,
            }
          : {
              ...source,
              id: copyId,
              name,
              credential: rebound(source.credential, copyId),
              lastConnectedAt: undefined,
              pins: {},
              certFingerprint: undefined,
            };

      // SECRETS FIRST, RECORD SECOND, and the order is not interchangeable.
      // Copying is additive: it touches only accounts under an id no record names
      // yet, so a failure between here and `persist` leaves bytes at an
      // unreferenced account - VLT-23's orphan class, and nothing that is WRONG,
      // just unreachable. The other order leaves a saved record claiming secrets
      // that are not there, which this layer can never correct because it never
      // reads one back. `rollbackNewHost` clears what a partial copy did land,
      // which is safe for exactly one reason: `copyId` is brand new, so there was
      // nothing at these accounts to lose.
      let secrets: HostSecretInput;
      try {
        secrets = await copyHostSecrets(source, copyId);
      } catch (e) {
        await rollbackNewHost(copy);
        throw e;
      }
      return writeHost(copy, secrets);
    });
  }

  async function deleteHost(id: string, forwards: ForwardRuleCleanup): Promise<void> {
    return enqueueWrite(async () => {
      const hosts = await listHosts();
      const host = hosts.find((h) => h.id === id);

      // Refuse rather than cascade - the same discipline `modules/vault` applies
      // to an in-use identity, and for the same reason: a cascade turns one
      // confirmed delete into a silent change to a host the user was not looking
      // at.
      //
      // Both kinds of holder, an RDP `tunnel.sshHostId` and an SSH
      // `proxyJumpId`, because the consequence is the same one: the host that
      // rode this one goes on connecting and changes ROUTE, with nothing on
      // screen changing at all. An RDP row confined to this bastion becomes a
      // direct dial to `host:3389` with CredSSP; an SSH row that reached its
      // target through it becomes a direct dial to `host:22`. What makes the SSH
      // half silent rather than merely quiet is the pin: it is keyed by the
      // address the ROW NAMES, and removing a bastion changes the route rather
      // than the address - so the same machine reached directly presents the same
      // host key, matches the pin the row already had, and raises no TOFU
      // question whatsoever. A row that never connected has no pin, and the
      // first-connect prompt it gets instead names `row.host` and reads as
      // entirely normal.
      //
      // ONE refusal listing every holder, not a tunnel check and then a jump
      // check: a user who clears the tunnels and is then refused a second time
      // about jump hosts reads the first refusal as a lie about what was in the
      // way.
      //
      // Checked before ANYTHING below is touched - including the forward-rule
      // cleanup - so a refusal leaves the host, its secrets and every referencing
      // row exactly as they were.
      if (host) {
        const holders = hosts
          .filter((h) => (h.protocol === "rdp" ? h.tunnel?.sshHostId === id : h.proxyJumpId === id))
          .map(hostRef);
        if (holders.length > 0) {
          throw new VaultInUseError(`host "${host.name}"`, "host", holders);
        }
      }

      // First, awaited, and UNCONDITIONAL. A throw here leaves the host and its
      // rules both intact, which is recoverable; the other order leaves rules
      // naming a host that no longer exists. Unconditional because a rule can name
      // an id that is already gone - deleted in another window, or lost with a torn
      // store file - and orphaning those rules is this sub-phase's job. Skipping
      // the call for a missing host is what left exactly those rules behind, and it
      // costs one no-op.
      await forwards(id);
      if (!host) return;

      // One at a time. Three concurrent deletes - which is what an SSH host's
      // three accounts produced - is what reported `os error 2` and left the row
      // on screen after a confirmed delete. See `deleteAccounts`.
      await deleteAccounts(id, secretFieldsFor(host));

      // Drop the row and nothing else. No surviving row can be naming `id`: both
      // kinds of reference were refused above, so there is nothing left here to
      // rewrite. Anything that rewrote a neighbour at this point would be
      // reintroducing the cascade the refusal replaced.
      await persist([[HOSTS_KEY, hosts.filter((h) => h.id !== id)]]);
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
   *
   * PRIVATE, and that is the constraint rather than an implementation detail.
   * `patch` is an arbitrary `(Host) => Host | null`, so a fourth caller written as
   * `patchHost(id, (h) => ({ ...h, name }))` would be well-typed, would look like
   * the cheap path next to a full `upsertHost`, and would skip `assertReferences`
   * and the stale-account release entirely. The three callbacks that exist touch
   * only `lastConnectedAt`, `lastFingerprint` and `certFingerprint`, which is why
   * no credential is addressable through here today - a fact about those three
   * closures, not about this signature.
   *
   * `assertBindingOwner` on what `patch` returns makes the credential half of that
   * enforced rather than remembered, and costs nothing: every pin path hands back a
   * byte-identical credential.
   */
  async function patchHost(id: string, patch: (current: Host) => Host | null): Promise<void> {
    return enqueueWrite(async () => {
      const hosts = await listHosts();
      const idx = hosts.findIndex((h) => h.id === id);
      if (idx < 0) return;
      const next = patch(hosts[idx]);
      if (!next) return;
      // Against `id`, not `next.id`: a patch that rewrote both would otherwise
      // agree with itself while landing at this index.
      assertBindingOwner(next.credential, id);
      const list = [...hosts];
      list[idx] = next;
      await persist([[HOSTS_KEY, list]]);
    });
  }

  /** Marks a successful connect: the timestamp, and the key or certificate the
   *  server actually presented, recorded against the address that record names. */
  async function markConnected(id: string, fingerprint: string): Promise<void> {
    const at = Date.now();
    // An empty fingerprint leaves the pin alone rather than clearing it: a
    // reconnect that could not report one must not discard the key an earlier
    // connect recorded.
    return patchHost(id, (h) => ({
      ...withFingerprint(h, fingerprint || hostPins(h)[h.host]),
      lastConnectedAt: at,
    }));
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
   *
   * TWO ARGUMENTS, and the address is deliberately not one of them. The key came
   * from the machine a connect had just dialled, and that connect read its address
   * off this very record, so the record is the only place the key can belong -
   * `withFingerprint` derives it there. Taking an address from the caller would
   * let a stale one in and would have meant editing `ssh-session.ts`,
   * `tunnel.ts` and `RdpPane.tsx` to pass something they already agree about.
   */
  async function pinFingerprint(id: string, fingerprint: string): Promise<void> {
    if (!fingerprint) return;
    // Against the pin for THIS record's address, so an unchanged key writes
    // nothing - including the file rewrite a no-op patch would still cost.
    return patchHost(id, (h) =>
      hostPins(h)[h.host] === fingerprint ? null : withFingerprint(h, fingerprint),
    );
  }

  // Through the shared lookup, so the hosts this refuses a delete over are exactly
  // the hosts the Vault page lists as holders. Two implementations of one question
  // is how a delete refused for reasons a page does not show gets shipped.
  const identityHostRefs: IdentityHostRefs = async (identityId) =>
    hostsUsingIdentity(await listHosts(), identityId);

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
    identityHostRefs,
    onHostsChanged: (cb) => io.store.onChanged(cb),
    ensureLoaded: () => io.store.ensureLoaded(),
    takeRecoveryNotice: () => io.store.takeRecoveryNotice(),
    purgeLegacySecrets: () =>
      runLegacyPurge({
        store: io.store,
        secrets: io.secrets,
        files: io.files ?? defaultHostFiles,
      }),
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
  identityHostRefs,
  onHostsChanged,
  ensureLoaded,
  takeRecoveryNotice,
  purgeLegacySecrets,
} = hostsStore;
