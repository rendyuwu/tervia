// When sync runs, and what it does with what comes back.
//
// ONE WEBVIEW, AND IT IS `main`. `vite.config.ts` builds three, and
// `fileKeyValueStore.ts` records that a contended write eventually gives up and
// writes over a stale baseline, "LOSING another window's update". An apply lands
// N records at once, on every focus - so two windows doing it would make that
// loss routine rather than rare. Outside `main` every entry point below is a
// no-op, and it is a no-op by CONSTRUCTION: the constructor returns a different
// object, so there is no branch inside a hot path for a later edit to forget.
//
// THE TWO TRIGGERS. A local edit marks records dirty and a debounce collects the
// burst; the window regaining focus pulls, behind a rate limit. Neither is a
// poll - `CONTRIBUTING.md` rejects that shape, and the rate limit is what keeps
// the focus trigger from becoming one under alt-tabbing.
//
// WHAT RUNS WHERE. Every decision - the merge, the prune, the etag skip - is in
// `src-tauri/src/modules/sync/engine.rs`. Everything this file does with the
// answer goes through a store's `applyRemote`, because `KNOWN-LIMITS.md` records
// that every integrity rule lives in the store layer and a pull has to go
// through it.

import { type DirtyId, type RemoteLanding, type RemoteLandingRefusal } from "@/lib/tombstones";
import type { ForwardRule } from "@/modules/forwards/types";
import type { Host, HostGroup } from "@/modules/hosts/types";
import type { VaultIdentity, VaultKey } from "@/modules/vault/types";
import { GROUP_TOMBSTONE_KIND, HOST_TOMBSTONE_KIND } from "@/modules/hosts/types";
import { RULE_TOMBSTONE_KIND } from "@/modules/forwards/types";
import {
  IDENTITY_TOMBSTONE_KIND,
  KEY_PASSPHRASE_FIELD,
  KEY_PRIVATE_KEY_FIELD,
  KEY_TOMBSTONE_KIND,
} from "@/modules/vault/types";
import { vaultKeyFactsFrom, type KeyInspectResult } from "@/modules/vault/keyInspect";

import { landingOf, recordEnvelope, tombstoneEnvelope } from "./envelope";
import type { SyncSettingsStore } from "./store";
import {
  etagSlot,
  EMPTY_SYNC_STATUS,
  FOCUS_INTERVAL_MS,
  PUSH_DEBOUNCE_MS,
  type Envelope,
  type PushFailure,
  type Reconciled,
  type SyncCommands,
  type SyncConfig,
  type SyncStatus,
} from "./types";

/**
 * The three record stores, as this module needs them.
 *
 * STRUCTURAL rather than the exported store types, so the verify script builds
 * a fake by writing the four methods it uses instead of a whole store - and so
 * this file gains no import edge on three store MODULES, only on their types.
 */
export type SyncStores = {
  hosts: {
    listHosts(): Promise<Host[]>;
    listGroups(): Promise<HostGroup[]>;
    listTombstones(): Promise<{ id: string; kind: string; deletedAt: number }[]>;
    applyRemote(
      hosts: RemoteLanding<Host>[],
      groups: RemoteLanding<HostGroup>[],
    ): Promise<RemoteLandingRefusal[]>;
  };
  vault: {
    listIdentities(): Promise<VaultIdentity[]>;
    listKeys(): Promise<VaultKey[]>;
    listTombstones(): Promise<{ id: string; kind: string; deletedAt: number }[]>;
    applyRemote(
      identities: RemoteLanding<VaultIdentity>[],
      keys: RemoteLanding<VaultKey>[],
    ): Promise<RemoteLandingRefusal[]>;
  };
  forwards: {
    listRules(): Promise<ForwardRule[]>;
    listTombstones(): Promise<{ id: string; kind: string; deletedAt: number }[]>;
    applyRemote(rules: RemoteLanding<ForwardRule>[]): Promise<RemoteLandingRefusal[]>;
  };
};

/**
 * The keychain and the key inspector, as the two paths that carry a private key
 * body need them.
 *
 * SEPARATE FROM {@link SyncStores} and both optional, because a scheduler built
 * without them is a scheduler that never carries a body and never corrects a
 * record - which is the whole behaviour of a device with the carry toggle off,
 * and therefore has to be constructible.
 */
export type SyncKeyBodies = {
  /**
   * This device's stored secrets for one vault key, by field name.
   *
   * INJECTED RATHER THAN A PORT OBJECT: the accounts a vault key's secrets sit
   * at are the vault store's vocabulary, and a second spelling of them here is
   * how a body comes to be published under a name nothing reads back.
   */
  readKeySecrets?: (id: string) => Promise<Record<string, string>>;
  /**
   * What a private key body says about itself.
   *
   * The derivation is the registered inspect command and nothing in TypeScript
   * computes a fingerprint. Injected because the module holding that command
   * imports a Tauri surface at the top level, and this file is loaded under
   * plain node by its own check.
   */
  inspectKey?: (body: string, passphrase?: string) => Promise<KeyInspectResult>;
  /**
   * Re-state what this device holds about a key, after a landing understated
   * it.
   *
   * A REAL LOCAL EDIT, stamped and published like any other - not a quiet
   * repair. The device holding the body is the only one that can know the
   * record is wrong, so the correction has to reach the remote or the next pull
   * lands the same understatement again, forever.
   */
  correctKey?: (key: VaultKey) => Promise<void>;
};

export type SchedulerIo = SyncKeyBodies & {
  /** This webview's label. Everything is a no-op unless it is `main`. */
  label: string;
  commands: SyncCommands;
  settings: SyncSettingsStore;
  /**
   * Stop a running forward before its rule record is landed away.
   *
   * INJECTED, not imported: `modules/forwards/controller.ts` is the runtime and
   * it imports the forwards store, so a direct import here would pull a Tauri
   * surface into a module the verify script loads under plain node.
   *
   * Sequenced AHEAD of the apply for the reason `releaseRulesForHost`'s own doc
   * gives: dropping the record releases nothing, and once the record is gone
   * nothing can name the entry - the SSH session stays at one reference and the
   * local port stays bound for the rest of the app's life. `KNOWN-LIMITS.md`
   * named this pull as the trigger that would have to sequence it.
   */
  releaseRule?: (rule: ForwardRule) => Promise<void>;
  /**
   * Open a session in the Rust process for this configuration.
   *
   * CALLED BEFORE EVERY PASS, and that is not belt-and-braces: the Rust state
   * is empty on every launch, so a configuration the settings window stored
   * last week opens nothing until `main` asks for it. Settings stores the
   * configuration; `main` is what turns it into a session.
   *
   * INJECTED because opening one means reading the passphrase and the provider
   * credentials out of the keychain, which is a Tauri surface - and because the
   * shape a provider's own configuration takes is not this file's business.
   * Expected to be cheap when nothing changed: a keychain read, and no key
   * derivation and no network unless the configuration actually moved.
   */
  openSession?: (config: SyncConfig) => Promise<void>;
  stores: SyncStores;
  now?: () => number;
  /** Injected so a check can fire the debounce without waiting five real
   *  seconds, and so a disposed scheduler's timer is cancellable. */
  setTimer?: (fn: () => void, ms: number) => unknown;
  clearTimer?: (handle: unknown) => void;
};

export type SyncScheduler = {
  /** What a store's committed write owes a push. Never throws - see
   *  `markDirty` in `src/lib/dirtySink.ts`. */
  markDirty(dirty: DirtyId[]): void;
  /** Reconcile now, then publish what the remote turned out to be missing. */
  pullNow(): Promise<void>;
  /** Publish everything marked dirty since the last push, now. */
  pushNow(): Promise<void>;
  /** The window regained focus. Rate limited. */
  onFocus(): void;
  /** Drop the pending debounce. */
  dispose(): void;
};

/** Every entry point, doing nothing. What a non-`main` webview gets. */
const INERT: SyncScheduler = {
  markDirty: () => {},
  pullNow: async () => {},
  pushNow: async () => {},
  onFocus: () => {},
  dispose: () => {},
};

/** Landings sorted into the arrays the three `applyRemote` calls take. */
type Sorted = {
  hosts: RemoteLanding<Host>[];
  groups: RemoteLanding<HostGroup>[];
  identities: RemoteLanding<VaultIdentity>[];
  keys: RemoteLanding<VaultKey>[];
  rules: RemoteLanding<ForwardRule>[];
};

export function createScheduler(io: SchedulerIo): SyncScheduler {
  if (io.label !== "main") return INERT;

  const now = io.now ?? Date.now;
  const setTimer = io.setTimer ?? ((fn, ms) => setTimeout(fn, ms));
  const clearTimer = io.clearTimer ?? ((handle) => clearTimeout(handle as never));

  /** Record slots (`kind:id`) this device owes the remote. Mirrored into the
   *  sync store file on every change - see `markDirty` for why in memory alone
   *  loses an edit. */
  const dirty = new Set<string>();
  let pending: unknown = null;
  /** The pass in flight, so a second entry point queues behind it rather than
   *  interleaving two read-modify-writes of the etag map. */
  let running: Promise<void> | null = null;
  /** The one-time read that folds the last session's dirty set into this one's.
   *  See {@link hydrate}. */
  let loaded: Promise<void> | null = null;
  /** `-Infinity` so the app-setup pull is never rate limited away. */
  let lastPull = -Infinity;
  let status: SyncStatus = { ...EMPTY_SYNC_STATUS };
  /** What went wrong ALONGSIDE this pull's apply rather than inside it - a
   *  forward that would not close, a key body that would not re-derive. Held
   *  rather than written at once, because the pull's own status write comes
   *  after and would put a `null` over it. */
  let applyError: string | null = null;

  /**
   * The private key body one outbound key record carries, or nothing.
   *
   * THE ONLY PLACE A BODY IS READ FOR PUBLICATION, and the toggle is checked
   * first so that a device with carrying off makes no keychain call at all -
   * not a call whose result is then discarded. That matters beyond tidiness:
   * on Linux and Windows a keychain read is a read of the whole secrets file,
   * once per key, on every pull and every push.
   *
   * ONLY KEYS, never identities and never hosts. An account password is not a
   * private key body, and the toggle is published as an opt-in to carrying the
   * latter.
   */
  async function outboundSecrets(
    config: SyncConfig,
    key: VaultKey,
  ): Promise<Record<string, string> | undefined> {
    const read = io.readKeySecrets;
    if (!config.carrySecrets || !read) return undefined;
    if (!key.hasPrivateKey && !key.hasPassphrase) return undefined;
    const found = await read(key.id);
    const carried: Record<string, string> = {};
    for (const field of [KEY_PRIVATE_KEY_FIELD, KEY_PASSPHRASE_FIELD]) {
      const value = found[field];
      if (value) carried[field] = value;
    }
    return Object.keys(carried).length > 0 ? carried : undefined;
  }

  /**
   * Every local record and living tombstone, as envelopes.
   *
   * `wanted` names the slots the caller is going to keep, and it gates ONLY the
   * keychain reads - the envelope list is built whole either way, because a
   * pull's reconcile needs every local record to pair against. Without it a
   * push of one renamed host would read every stored key body out of the
   * keychain to build envelopes it then throws away, which on two of the three
   * platforms is one whole-file read per key.
   *
   * THE PULL PASSES NONE, deliberately, and pays that cost on every pass with
   * carrying on. It has to: `secretsChanged` is a comparison against the local
   * body, so an envelope built without one would answer that the remote's body
   * differs from nothing at all, on every key, forever.
   */
  async function localEnvelopes(config: SyncConfig, wanted?: Set<string>): Promise<Envelope[]> {
    const [hosts, groups, hostGraves, identities, keys, vaultGraves, rules, ruleGraves] =
      await Promise.all([
        io.stores.hosts.listHosts(),
        io.stores.hosts.listGroups(),
        io.stores.hosts.listTombstones(),
        io.stores.vault.listIdentities(),
        io.stores.vault.listKeys(),
        io.stores.vault.listTombstones(),
        io.stores.forwards.listRules(),
        io.stores.forwards.listTombstones(),
      ]);
    // SEQUENTIAL over the keys, not `Promise.all`. Each iteration is a keychain
    // read, and on two of the three platforms those serialize behind one file
    // lock anyway - so the parallel spelling would buy nothing and make a burst
    // of simultaneous reads the shape a future change has to reason about.
    const keyEnvelopes: Envelope[] = [];
    for (const k of keys) {
      const carried =
        wanted && !wanted.has(etagSlot(KEY_TOMBSTONE_KIND, k.id))
          ? undefined
          : await outboundSecrets(config, k);
      keyEnvelopes.push(recordEnvelope(KEY_TOMBSTONE_KIND, k, carried));
    }
    return [
      ...hosts.map((h) => recordEnvelope(HOST_TOMBSTONE_KIND, h)),
      ...groups.map((g) => recordEnvelope(GROUP_TOMBSTONE_KIND, g)),
      ...identities.map((i) => recordEnvelope(IDENTITY_TOMBSTONE_KIND, i)),
      ...keyEnvelopes,
      ...rules.map((r) => recordEnvelope(RULE_TOMBSTONE_KIND, r)),
      // LIVING TOMBSTONES ARE PART OF THE LOCAL SET, not an afterthought: a
      // local delete has to pair with its remote counterpart and resolve
      // through the merge, or a record deleted here reads as remote-only and
      // lands again on the device that deleted it.
      ...[...hostGraves, ...vaultGraves, ...ruleGraves].map(tombstoneEnvelope),
    ];
  }

  /**
   * Sort one pull's landings by the store that owns each kind.
   *
   * `dropped` is the half that is easy to forget and expensive to get wrong: a
   * landing this function DISCARDS has not been applied, so its etag must not
   * advance either - otherwise the pull etag-skips that object from now on and
   * the landing never happens again, silently, for the life of the object.
   * Refusals from `applyRemote` and discards from here go into the same set.
   */
  function sort(
    records: Reconciled[],
    config: SyncConfig,
  ): { sorted: Sorted; dropped: RemoteLandingRefusal[] } {
    const out: Sorted = { hosts: [], groups: [], identities: [], keys: [], rules: [] };
    const dropped: RemoteLandingRefusal[] = [];
    for (const record of records) {
      // THE CARRY TOGGLE, BOTH DIRECTIONS, and it is computed FIRST because the
      // landing below is gated on it as well as filtered by it. A device with
      // the toggle off drops the body here and the store never sees one.
      //
      // WHY THE GATE AND THE FILTER MUST BE THE SAME EXPRESSION. `ordering_key`
      // in `src-tauri/src/modules/sync/model.rs` includes `secrets`, and an
      // absent one sorts below a present one - so a device that does not carry
      // bodies gets `secretsChanged: true` against every remote object that DOES
      // carry one, on every pull, forever. That is not an exotic fleet: it is
      // exactly what this app's own settings produce the moment one device turns
      // carrying off. Landing on `secretsChanged` alone would then rewrite the
      // whole vault file and take a fresh snapshot on every single pull, for a
      // body this device is about to discard anyway.
      //
      // A MERGE THAT DID NOT MOVE THE BODY IS ALSO NOT CARRIED, even with the
      // toggle on: the winner's envelope carries its `secrets` whether or not
      // they differ from this device's, and landing them unconditionally would
      // rewrite the keychain on every pull for a body already at the account.
      const withSecrets =
        config.carrySecrets &&
        (record.outcome === "remoteOnly" || (record.outcome === "merged" && record.secretsChanged));
      // A merge that changed NEITHER destination writes nothing: that is the
      // steady state of two devices that agree, so applying it would rewrite
      // every store file on every focus for no new information. `withSecrets`
      // is the second destination, and a body arriving for a record whose
      // fields already agree is exactly the `changed: false` shape - so keying
      // the landing off `changed` alone would make a body that travelled
      // correctly unlandable, silently, for as long as the two records stayed
      // equal.
      const envelope =
        record.outcome === "remoteOnly"
          ? record.envelope
          : record.outcome === "merged" && (record.changed || withSecrets)
            ? record.envelope
            : null;
      if (!envelope) continue;
      const landing = landingOf(envelope, withSecrets);
      if (!landing) {
        dropped.push({
          kind: record.kind,
          id: record.id,
          reason: "the tombstone carries no usable deletedAt",
        });
        continue;
      }
      switch (record.kind) {
        case HOST_TOMBSTONE_KIND:
          out.hosts.push(landing as RemoteLanding<Host>);
          break;
        case GROUP_TOMBSTONE_KIND:
          out.groups.push(landing as RemoteLanding<HostGroup>);
          break;
        case IDENTITY_TOMBSTONE_KIND:
          out.identities.push(landing as RemoteLanding<VaultIdentity>);
          break;
        case KEY_TOMBSTONE_KIND:
          out.keys.push(landing as RemoteLanding<VaultKey>);
          break;
        case RULE_TOMBSTONE_KIND:
          out.rules.push(landing as RemoteLanding<ForwardRule>);
          break;
        default:
          // A kind no store here owns, from a device running a newer build.
          // Reported as a drop rather than ignored, so its etag stays out of
          // the map and a build that DOES own the kind reads the object when
          // it arrives.
          dropped.push({
            kind: record.kind,
            id: record.id,
            reason: `no store on this device owns a ${record.kind}`,
          });
      }
    }
    return { sorted: out, dropped };
  }

  /**
   * Apply one pull's landings, dependency first.
   *
   * Vault before hosts before forwards, because that is the direction the
   * references point. It buys only the ordinary case - the reference guards are
   * deliberately skipped on this path, so a landing whose referent has not
   * arrived is applied with the reference dangling either way.
   */
  async function apply(sorted: Sorted): Promise<RemoteLandingRefusal[]> {
    const refusals: RemoteLandingRefusal[] = [];
    if (sorted.identities.length > 0 || sorted.keys.length > 0) {
      refusals.push(...(await io.stores.vault.applyRemote(sorted.identities, sorted.keys)));
    }
    if (sorted.hosts.length > 0 || sorted.groups.length > 0) {
      refusals.push(...(await io.stores.hosts.applyRemote(sorted.hosts, sorted.groups)));
    }
    if (sorted.rules.length > 0) {
      await release(sorted.rules);
      refusals.push(...(await io.stores.forwards.applyRemote(sorted.rules)));
    }
    return refusals;
  }

  /**
   * Stop the forwards a landed delete is about to remove the record for.
   *
   * ONE FAILURE DOES NOT ABORT THE PASS, unlike `deleteHost`'s use of the same
   * call. There a rejecting close leaves the host and its rules both intact,
   * which is recoverable; here the apply is ONE queued write over every landing
   * in the pull, so a throw would lose all of them - the failure the whole
   * refusal design exists to prevent, arriving through a different door. The
   * close is reported instead, and the record still lands.
   *
   * A LANDED EDIT IS NOT RELEASED, only a landed delete: a remote rename would
   * otherwise drop a tunnel the user is working over. Carried in
   * `KNOWN-LIMITS.md`.
   */
  /**
   * Correct a landed key record against the body this device actually holds.
   *
   * WHY A LANDING CAN UNDERSTATE. The merge drops `fingerprint` whenever the
   * winner's own record claims no private key, and never copies one off the
   * loser - correctly, because that layer has no keychain and a fingerprint it
   * carried forward could describe a body nobody has. A device that holds the
   * body is then the only place the truth exists, and this is where it is put
   * back.
   *
   * WHY IT PUBLISHES. `correctKey` stamps and marks the record like any local
   * edit, and that is load bearing rather than incidental: a correction kept
   * local would lose the next merge to the remote copy still claiming no body,
   * land the same understatement again, and be re-derived again - a store write
   * per pull, for the life of the record. Published, both devices agree after
   * one round.
   *
   * WHAT IT COSTS TO SKIP THE CHEAP CASE. The keychain is read only for a key
   * the landing left incomplete, so a device whose records already agree with
   * its keychain makes no call at all.
   *
   * A LEGACY PEM BODY CANNOT BE INSPECTED WITHOUT ITS PASSPHRASE, so its
   * fingerprint stays dropped until the key is next opened. The presence flag
   * is still corrected, because that one is known from the body existing rather
   * than from reading it. Carried in `KNOWN-LIMITS.md`.
   *
   * ONE BAD KEY DOES NOT STOP THE REST: a refusing keychain, an unparseable
   * body and a name collision inside `correctKey` are all per record, and the
   * first of them taking the whole pass would be the failure the refusal design
   * exists to prevent arriving through a different door.
   */
  async function rederive(landings: RemoteLanding<VaultKey>[]): Promise<void> {
    const read = io.readKeySecrets;
    const inspect = io.inspectKey;
    const correct = io.correctKey;
    if (!read || !inspect || !correct) return;
    const landed = landings.filter((l) => !l.deleted).map((l) => l.id);
    if (landed.length === 0) return;
    const stored = await io.stores.vault.listKeys();
    for (const id of landed) {
      const key = stored.find((k) => k.id === id);
      // Read from the STORE rather than from the landing, so a landing the
      // apply refused - or one a local delete superseded - is never corrected
      // into existence. A `hardware` key is skipped outright: it never has a
      // body to read at all (`VaultKeyKind` in `src/modules/vault/types.ts`),
      // so the read below would always come back empty and the loop would
      // still hit its own `if (!body) continue` - this just skips the
      // pointless keychain call to get there.
      if (!key || key.kind === "hardware" || (key.hasPrivateKey && key.fingerprint)) continue;
      try {
        const secrets = await read(id);
        const body = secrets[KEY_PRIVATE_KEY_FIELD];
        if (!body) continue;
        const facts = vaultKeyFactsFrom(await inspect(body, secrets[KEY_PASSPHRASE_FIELD]));
        // `hasPrivateKey` is stated here rather than taken from the inspection,
        // which answers about the body's CONTENT and says nothing about whether
        // this machine stores one. Reading it back out of the account is what
        // just happened, so the flag is known.
        const next: VaultKey = { ...key, hasPrivateKey: true };
        // FIELD BY FIELD, and `undefined` is skipped rather than spread. An
        // inspection that could not answer must not erase what the record
        // already knew - the sealed-container branch answers `encrypted` alone,
        // so spreading it wholesale would blank a fingerprint and a public half
        // that were perfectly good.
        if (facts.keyType !== undefined) next.keyType = facts.keyType;
        if (facts.fingerprint !== undefined) next.fingerprint = facts.fingerprint;
        if (facts.publicKey !== undefined) next.publicKey = facts.publicKey;
        if (facts.encrypted !== undefined) next.encrypted = facts.encrypted;
        // NOTHING TO SAY, SO NOTHING IS SAID - and this comparison is what makes
        // the whole pass terminate, rather than the guard above. A body that
        // cannot be inspected without its passphrase leaves `fingerprint`
        // undefined FOREVER, so the guard can never fire for it; without this
        // line `correctKey` would stamp a fresh `updatedAt` and mark the record
        // dirty on every pull, two devices holding such a body would land each
        // other's restamp and restamp back, and the exchange would never settle
        // - one vault write, one snapshot and one remote object per pull, per
        // device, for the life of the record.
        if (JSON.stringify(next) === JSON.stringify(key)) continue;
        await correct(next);
      } catch (e) {
        applyError = e instanceof Error ? e.message : String(e);
      }
    }
  }

  async function release(landings: RemoteLanding<ForwardRule>[]): Promise<void> {
    const releaseRule = io.releaseRule;
    if (!releaseRule) return;
    const dropped = new Set(landings.filter((l) => l.deleted).map((l) => l.tombstone.id));
    if (dropped.size === 0) return;
    for (const rule of await io.stores.forwards.listRules()) {
      if (!dropped.has(rule.id)) continue;
      try {
        await releaseRule(rule);
      } catch (e) {
        applyError = e instanceof Error ? e.message : String(e);
      }
    }
  }

  async function writeStatus(next: Partial<SyncStatus>): Promise<void> {
    // Hydrated first, or this merges over an empty object rather than over what
    // the last session left - see {@link hydrate}. It is also what makes the
    // floor below complete: `hydrate` folds the last session's dirty set into
    // this one's, so `dirty.size` is the whole of what this device owes.
    await hydrate();
    status = { ...status, ...next };
    // THE COUNT IS A FLOOR, and the dirty set is the half the reconcile cannot
    // see. `pending` is what the remote was missing as of the last SUCCESSFUL
    // pull, so during an outage - the one moment a user goes looking for it -
    // it reads zero while edits sit unpublished. A slot that is both dirty and
    // remote-missing is counted once, so this never double counts; two disjoint
    // sets report the larger, which is why the field says "at least".
    status.pending = Math.max(status.pending, dirty.size);
    await io.settings.writeStatus(status);
  }

  /**
   * Publish `envelopes` and fold the etags the remote answered with back into
   * the map.
   *
   * A SLOT THAT FAILED LOSES ITS ETAG, rather than merely keeping the old one.
   * The two are not the same: the pull has already recorded the remote object's
   * current etag, so leaving it there means the next pull etag-skips the object
   * AND skips this device's local copy with it - no disposition, `pending: 0`,
   * and a status that reads "in sync" while a delete this device made never
   * propagates. Dropping the etag makes the next pull fetch the object and see
   * the divergence again.
   *
   * Returns the slots that did not land, so the caller can put their dirty
   * marks back.
   */
  async function publish(envelopes: Envelope[]): Promise<PushFailure[]> {
    if (envelopes.length === 0) return [];
    const etags = await io.settings.readEtags();
    const report = await io.commands.push(envelopes, etags);
    const next = { ...etags, ...report.etags };
    for (const failure of report.failed) delete next[etagSlot(failure.kind, failure.id)];
    await io.settings.writeEtags(next);
    return report.failed;
  }

  async function runPull(): Promise<void> {
    // FRESH FROM DISK, not from a cache this webview filled at launch. The
    // settings window is the other writer of that file and nothing broadcasts a
    // change event for it - `SyncSettingsStore` drops its cache on every call
    // for that reason, so nothing is needed here beyond reading it each pass.
    const config = await io.settings.readConfig();
    if (!config.enabled) return;
    // Stamped here as well as in `onFocus`, so a pull from any other entry
    // point also costs the rate limit rather than leaving the next focus free
    // to start a second one on top of it.
    lastPull = now();
    // INSIDE THE RATE LIMIT AND OUTSIDE THE TRY, in that order: a configuration
    // that cannot be opened - a wrong passphrase, an endpoint that is gone -
    // must still cost the limit, or every alt-tab retries it; and its error
    // belongs in the same status write as everything else below rather than
    // thrown out of a background pass.
    applyError = null;
    let error: string | null = null;
    /**
     * What the reconcile FOUND, or nothing when it never got that far.
     *
     * Held as one value rather than three initialized fields, because three
     * fields initialized to "healthy" and written unconditionally is how a
     * failed pull comes to report zero pending, nothing quarantined and a last
     * pull just now - the settings window reading its healthiest exactly when
     * sync is broken.
     */
    let found: Pick<SyncStatus, "lastPullAt" | "pending" | "quarantine" | "stale"> | null = null;
    try {
      await io.openSession?.(config);
      const [envelopes, etags] = await Promise.all([
        localEnvelopes(config),
        io.settings.readEtags(),
      ]);
      const report = await io.commands.pull(envelopes, etags);
      const { sorted, dropped } = sort(report.records, config);
      const refusals = [...dropped, ...(await apply(sorted))];
      // AFTER the apply and OUTSIDE it: the correction is a local edit through
      // the ordinary mutator, so it stamps its own clock and marks the record
      // dirty - neither of which an apply is allowed to do.
      await rederive(sorted.keys);

      // THE MAP ADVANCES MINUS THE REFUSED, never frozen wholesale. Freezing on
      // any refusal would leave one unresolvable landing degrading every later
      // pull to a full inventory download, forever and silently. A refusal
      // names `{kind, id}`, which is exactly the map's key - and `dropped` is in
      // here too, because a landing nothing applied is a landing that did not
      // happen whichever layer declined it.
      const refused = new Set(refusals.map((r) => etagSlot(r.kind, r.id)));
      const next: Record<string, string> = {};
      for (const [slot, etag] of Object.entries(report.etags)) {
        if (!refused.has(slot)) next[slot] = etag;
      }
      // WRITTEN AFTER THE APPLY RESOLVES. A crash between the two costs one
      // redundant, idempotent re-apply; the other order costs the landing.
      await io.settings.writeEtags(next);

      // What the reconcile found the remote is missing. A record the apply
      // refused is left out: this device does not hold what it would publish.
      const bySlot = new Map(envelopes.map((e) => [etagSlot(e.kind, e.id), e]));
      const owed: Envelope[] = [];
      for (const record of report.records) {
        const slot = etagSlot(record.kind, record.id);
        if (refused.has(slot)) continue;
        if (record.outcome === "merged" && record.republish) owed.push(record.envelope);
        if (record.outcome === "localOnly" && !record.stale) {
          const mine = bySlot.get(slot);
          if (mine) owed.push(mine);
        }
      }
      const failed = await publish(owed);
      // A record the reconcile says the remote is missing and the push did not
      // place is still owed, so it goes back on the dirty set - which is
      // durable, so it also survives the window closing.
      for (const failure of failed) dirty.add(etagSlot(failure.kind, failure.id));
      found = {
        lastPullAt: now(),
        // COUNTED AFTER THE PUSH, not before: the remote is missing what the
        // reconcile found minus what this pass just gave it, and reporting the
        // pre-push number leaves the settings window showing work that is
        // already done until the next pull.
        pending: Math.max(0, report.pending - (owed.length - failed.length)),
        quarantine: report.quarantined,
        stale: report.records
          .filter((r) => r.outcome === "localOnly" && r.stale)
          .map((r) => ({ kind: r.kind, id: r.id })),
      };
      error = failed[0]?.reason ?? applyError;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
    // THE PULL IS ALSO THE FLUSH, and it runs BEFORE the one status write: a
    // dirty mark that survived the last quit has nothing else that would notice
    // it, because an etag-skipped object hides this device's local edit from the
    // reconcile entirely. Its error folds into the same write rather than
    // arriving in a second one that would put a `null` over this one.
    const pushError = await runPush();
    // A PULL THAT FAILED REPORTS ONLY THAT. Leaving the previous pull's counts
    // in place is the honest reading - they are the last thing this device
    // actually learned - and stamping a fresh `lastPullAt` over them would say
    // the opposite.
    await writeStatus({ ...found, lastError: error ?? pushError });
  }

  /**
   * Publish everything marked since the last push.
   *
   * Returns what to report, so the caller writes status ONCE: a pull ends by
   * calling this, and a second status write here would put its own `null` over
   * the error the pull just recorded.
   */
  async function runPush(): Promise<string | null> {
    // EVERYTHING THAT TOUCHES THE SET IS INSIDE THE TRY, including the write
    // that records the removal. The removal happens in memory first, so a
    // throw between it and the write would leave those slots gone from memory
    // while `hydrate` never reads the key again - and the next successful
    // write would then put a set without them over the disk copy that still
    // had them. The catch below is what puts them back.
    const taken = new Set<string>();
    try {
      // FRESH FROM DISK, not from a cache this webview filled at launch. The
      // settings window is the other writer of that file and nothing broadcasts a
      // change event for it - `SyncSettingsStore` drops its cache on every call
      // for that reason, so nothing is needed here beyond reading it each pass.
      const config = await io.settings.readConfig();
      await hydrate();
      // SNAPSHOT AND REMOVE WITH NO AWAIT BETWEEN THEM. `hydrate` has already
      // folded what was on disk into this set, so there is no second read here
      // - and that is the point: a read at this line would spread `dirty`
      // before its own await was evaluated, and a mark made while it was in
      // flight would land in neither the snapshot nor the set afterwards. Gone
      // from memory and disk both, with no error and a pending count of zero.
      for (const slot of dirty) taken.add(slot);
      for (const slot of taken) dirty.delete(slot);
      // Taken whether or not sync is on: marks accumulated while it was off
      // describe an inventory the remote has never seen, and the pull that
      // follows enabling it publishes the whole of it anyway.
      await persistDirty();
      if (!config.enabled || taken.size === 0) return null;
      // A push can be the FIRST thing a session does - a pull that returned
      // early, then an edit - so it opens the session too rather than assuming
      // the pull already did.
      await io.openSession?.(config);

      // ONE OBJECT PER EDIT, not the inventory. The whole reason `persist`
      // takes record ids: a hook that could only say "this store changed" would
      // push every host every time one was renamed.
      const envelopes = (await localEnvelopes(config, taken)).filter((e) =>
        taken.has(etagSlot(e.kind, e.id)),
      );
      const failed = await publish(envelopes);
      for (const failure of failed) dirty.add(etagSlot(failure.kind, failure.id));
      await persistDirty();
      // Counted down by what this pass placed, the way the pull's own figure
      // is - without it the floor in `writeStatus` can only ever rise.
      await writeStatus({
        lastPushAt: now(),
        pending: Math.max(0, status.pending - (taken.size - failed.length)),
      });
      return failed[0]?.reason ?? null;
    } catch (e) {
      // The edit is not lost: the marks go back and the next trigger retries.
      // A slot re-marked meanwhile costs one redundant push, which is the safe
      // direction. The write itself may be what failed, so it cannot be the
      // thing that decides whether this reports.
      for (const slot of taken) dirty.add(slot);
      await persistDirty().catch(() => {});
      const reason = e instanceof Error ? e.message : String(e);
      // A DEBOUNCED PUSH IS THE ONLY THING THAT RAN, so it is the only thing
      // that can report: both entry points that reach here drop the returned
      // string. Swallowed rather than thrown on - the edit is already safe on
      // the dirty set, and a failed status write must not replace the reason.
      await writeStatus({ lastError: reason }).catch(() => {});
      return reason;
    }
  }

  /**
   * Run `op` after whatever is already running.
   *
   * SERIAL, because both entry points are read-modify-write over one etag map
   * and the read-to-write window is a whole network round trip. Two overlapping
   * passes put a refused slot's etag back into the map, and once there the etag
   * skip guarantees nothing ever looks at that object again.
   *
   * Queued rather than dropped: a push carries edits, and discarding one would
   * lose them until the next mutation.
   */
  function serialize(op: () => Promise<unknown>): Promise<void> {
    // NOTHING THAT COMES OUT OF HERE REJECTS. Every caller is `void
    // serialize(...)` or a fire-and-forget event handler, and the store file
    // being unwritable would otherwise surface as an unhandled rejection with
    // no owner - on a background path that is allowed to fail.
    const next = (running ?? Promise.resolve()).then(op, op).then(
      () => {},
      (e: unknown) => {
        console.error("sync: a pass failed", e);
      },
    );
    running = next;
    return next;
  }

  /**
   * Fold what the last session left on disk into the in-memory set, ONCE.
   *
   * Every write of the set is `[...dirty]`, so memory has to be a superset of
   * disk before the first one - otherwise the first mark of a session writes
   * its one slot over everything the previous session was still owed, which is
   * the lost edit the durable set exists to prevent, reintroduced by the thing
   * that makes it durable.
   *
   * After this runs, memory is authoritative and nothing reads the key again.
   */
  function hydrate(): Promise<void> {
    loaded ??= Promise.all([io.settings.readDirty(), io.settings.readStatus()])
      .then(([slots, stored]) => {
        for (const slot of slots) dirty.add(slot);
        // THE STATUS COMES BACK TOO, for the reason the pull's own write gives:
        // what is reported is "the last thing this device actually learned",
        // and that is a claim about the DEVICE, so it holds across a relaunch.
        // Without this, `writeStatus` merges over an empty object and the first
        // failed pull of a new session - launch offline and it is the first
        // pull - writes zero pending and no last pull over what the previous
        // session had found.
        status = stored;
      })
      // RESET ON FAILURE, or one rejection is permanent for the session: every
      // later `persistDirty` would reject on the memoized promise and the set
      // would never be written again. `createFileKeyValueStore` memoizes an
      // in-flight read the same way one layer down and resets for the same
      // reason. NOT `finally` - on success memory is authoritative, and a
      // second read would re-add slots a flush has already published.
      .catch((e: unknown) => {
        loaded = null;
        throw e;
      });
    return loaded;
  }

  /** The dirty set, written where a quit can no longer take it.
   *
   *  `[...dirty]` is read at the moment of the write rather than snapshotted by
   *  the caller, so two writers racing both write current state. */
  async function persistDirty(): Promise<void> {
    await hydrate();
    await io.settings.writeDirty([...dirty]);
  }

  function schedule(): void {
    if (pending !== null) return;
    // The window opens at the FIRST edit of a burst rather than sliding with
    // each one, so a long stream of edits still publishes every five seconds
    // instead of never.
    pending = setTimer(() => {
      pending = null;
      void serialize(runPush);
    }, PUSH_DEBOUNCE_MS);
  }

  return {
    markDirty(ids) {
      if (ids.length === 0) return;
      for (const id of ids) dirty.add(etagSlot(id.kind, id.id));
      // WRITTEN BEFORE THE DEBOUNCE, not after it. The debounce is five
      // seconds; quitting inside it used to lose the edit outright, because the
      // next pull etag-skips an unmoved remote object and skips this device's
      // local copy with it - so nothing would have noticed, and `pending` would
      // have said zero.
      //
      // Caught rather than left floating: this runs at the end of a queued
      // STORE write, so an unhandled rejection here would attach itself to a
      // record the user did save.
      void persistDirty().catch((e: unknown) => {
        console.error("sync: the dirty set could not be written", e);
      });
      schedule();
    },
    pullNow: () => serialize(runPull),
    pushNow: () => serialize(runPush),
    onFocus() {
      const at = now();
      if (at - lastPull < FOCUS_INTERVAL_MS) return;
      // Stamped BEFORE the pull rather than after it, so a pull that fails or
      // hangs still costs the rate limit - otherwise a broken endpoint is
      // retried on every alt-tab.
      lastPull = at;
      void serialize(runPull);
    },
    dispose() {
      if (pending !== null) clearTimer(pending);
      pending = null;
    },
  };
}
