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
import { IDENTITY_TOMBSTONE_KIND, KEY_TOMBSTONE_KIND } from "@/modules/vault/types";

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

export type SchedulerIo = {
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
  /** A close that reported during this pull's apply. Held rather than written
   *  at once, because the pull's own status write comes after and would put a
   *  `null` over it. */
  let closeError: string | null = null;

  async function localEnvelopes(): Promise<Envelope[]> {
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
    return [
      ...hosts.map((h) => recordEnvelope(HOST_TOMBSTONE_KIND, h)),
      ...groups.map((g) => recordEnvelope(GROUP_TOMBSTONE_KIND, g)),
      ...identities.map((i) => recordEnvelope(IDENTITY_TOMBSTONE_KIND, i)),
      ...keys.map((k) => recordEnvelope(KEY_TOMBSTONE_KIND, k)),
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
  function sort(records: Reconciled[]): { sorted: Sorted; dropped: RemoteLandingRefusal[] } {
    const out: Sorted = { hosts: [], groups: [], identities: [], keys: [], rules: [] };
    const dropped: RemoteLandingRefusal[] = [];
    for (const record of records) {
      // A `changed: false` merge writes NOTHING. It is the steady state of two
      // devices that agree, so applying it would rewrite every store file on
      // every focus for no new information.
      const envelope =
        record.outcome === "remoteOnly"
          ? record.envelope
          : record.outcome === "merged" && record.changed
            ? record.envelope
            : null;
      if (!envelope) continue;
      const landing = landingOf(envelope);
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
        closeError = e instanceof Error ? e.message : String(e);
      }
    }
  }

  async function writeStatus(next: Partial<SyncStatus>): Promise<void> {
    // Hydrated first, or this merges over an empty object rather than over what
    // the last session left - see {@link hydrate}.
    await hydrate();
    status = { ...status, ...next };
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
    const config = await io.settings.readConfig();
    if (!config.enabled) return;
    // Stamped here as well as in `onFocus`, so a pull from any other entry
    // point also costs the rate limit rather than leaving the next focus free
    // to start a second one on top of it.
    lastPull = now();
    closeError = null;
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
      const [envelopes, etags] = await Promise.all([localEnvelopes(), io.settings.readEtags()]);
      const report = await io.commands.pull(envelopes, etags);
      const { sorted, dropped } = sort(report.records);
      const refusals = [...dropped, ...(await apply(sorted))];

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
      // COUNTED AFTER THE PUSH, not before: the remote is missing what the
      // reconcile found minus what this pass just gave it, and reporting the
      // pre-push number leaves the settings window showing work that is
      // already done until the next pull.
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
      error = failed[0]?.reason ?? closeError;
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

      // ONE OBJECT PER EDIT, not the inventory. The whole reason `persist`
      // takes record ids: a hook that could only say "this store changed" would
      // push every host every time one was renamed.
      const envelopes = (await localEnvelopes()).filter((e) => taken.has(etagSlot(e.kind, e.id)));
      const failed = await publish(envelopes);
      for (const failure of failed) dirty.add(etagSlot(failure.kind, failure.id));
      await persistDirty();
      await writeStatus({ lastPushAt: now() });
      return failed[0]?.reason ?? null;
    } catch (e) {
      // The edit is not lost: the marks go back and the next trigger retries.
      // A slot re-marked meanwhile costs one redundant push, which is the safe
      // direction. The write itself may be what failed, so it cannot be the
      // thing that decides whether this reports.
      for (const slot of taken) dirty.add(slot);
      await persistDirty().catch(() => {});
      return e instanceof Error ? e.message : String(e);
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
