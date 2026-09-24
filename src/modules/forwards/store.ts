import { markDirty } from "@/lib/dirtySink";
import type { StoreRecovery } from "@/lib/storeRecovery";
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
import type { Host } from "@/modules/hosts/types";

import { createTauriForwardsStoreIo, type ForwardsIo } from "./adapters";
import { FORWARDS_KEY, RULE_TOMBSTONE_KIND, type ForwardRule } from "./types";

// The forwards store: one record per saved rule, modelled on `vault/store.ts`'s
// shape and its `enqueueWrite` one-liner.
//
// `hosts` arrives on `upsertRule` as a REQUIRED INJECTED LOOKUP, never an
// import. `modules/hosts/store.ts`'s own comment on `ForwardRuleCleanup`
// explains the direction: `modules/forwards` will always want to
// import `Host` from `modules/hosts` (a type-only import, and the only one this
// file makes across modules), so a `modules/hosts` -> `modules/forwards` import
// closes the cycle. `ForwardRuleCleanup` is the wiring in the other direction -
// `deleteHost` calls into this module without importing it either.
//
// `dropRulesForHost` is the callee behind that wiring, and it deliberately does
// NOT consult the host lookup at all: it runs from inside `deleteHost`'s own
// write queue (`deleteHost` in `hosts/store.ts`), awaited before that queue touches the
// keychain or the host list, and a rule may legitimately name a host id that is
// already gone - deleted in another window, or lost with a torn store file. A
// lookup here would either re-enter a queue that is already mid-entry (a
// deadlock, the same one `duplicateHost` avoids by calling `writeHost` directly)
// or read a host list that has not been rewritten yet and see the very host
// this call exists to react to. Group 4 of `scripts/forward-rules-verify.ts`
// is what proves it: a lookup that throws must not stop the drop.

/** Resolves a saved host by id, or `undefined` when there is none. Injected so
 *  this module never imports `modules/hosts/store` - see the header above. */
export type HostLookup = (hostId: string) => Promise<Host | undefined>;

export type ForwardsStore = {
  listRules(): Promise<ForwardRule[]>;
  findRule(id: string): Promise<ForwardRule | undefined>;
  newRuleId(): string;
  /**
   * Refuses a blank `name` and a `hostId` that does not name a saved SSH
   * host, for every type. The port/host refusals are TYPE-CONDITIONAL - see
   * `types.ts`'s doc on each `ForwardRule` field for which type uses which:
   * `-L` (type absent) refuses a blank `remoteHost`, a `localPort` outside
   * `0`/`1-65535` and a `remotePort` outside `1-65535`; `-D` refuses only a
   * `localPort` (its SOCKS port) outside `0`/`1-65535`; `-R` refuses a blank
   * `remoteHost` (its local target), a `remotePort` outside `1-65535`, and -
   * only when present - a `bindPort` outside `0`/`1-65535`. Each refusal
   * names both the rule and the id or value it is refusing.
   */
  upsertRule(rule: ForwardRule, hosts: HostLookup): Promise<ForwardRule>;
  /** Refuses nothing, in the sense every other delete in this codebase refuses:
   *  a rule references a host; nothing references a rule, so there is no holder
   *  to check. It does check that the rule EXISTS, which is a different question
   *  - see the guard inside `deleteRule` for why a delete of an id that is not
   *  there must stay a no-op. */
  deleteRule(id: string): Promise<void>;
  /**
   * Drop every rule naming `hostId`. Idempotent, and a no-op for a host with no
   * rules or a host id that was never saved. It does NOT consult a host lookup -
   * see the header above for why that omission is load bearing rather than a
   * shortcut, which is the only sense in which it is unconditional.
   */
  dropRulesForHost(hostId: string): Promise<void>;
  /**
   * Land already-merged rules and rule tombstones at their REMOTE timestamps, in
   * one commit, and report the ones that were not applied.
   *
   * The one writer in this module that does not originate what it writes, which
   * is why it is the one that does not stamp: every other mutator overwrites its
   * caller's `updatedAt`, and doing that here would have a pulled rule outrank
   * the copy it came from and a pulled tombstone restart its expiry window on
   * every device that receives it.
   *
   * REFUSALS COME BACK, nothing throws - see `landingRefusal` in
   * `src/lib/tombstones.ts` for the five conditions and for why the reference
   * guard `upsertRule` runs is deliberately not among them. A rule whose host
   * has not landed yet is applied with a `hostId` that dangles until the host
   * arrives, on the same terms `assertReferences` in `modules/hosts/store.ts`
   * already accepts for a missing group.
   *
   * A LANDED DELETE DROPS A RULE WITHOUT STOPPING IT. The runtime that would
   * release a running forward lives in `controller.ts`, which imports this
   * module, so this store cannot reach it without closing the cycle every port
   * here exists to keep open - the caller sequences the release ahead of the
   * apply, the way `HostsPage.tsx` sequences `deleteHost`'s. Carried in
   * `KNOWN-LIMITS.md` with the pinned member set in
   * `scripts/forwards-shell-verify.ts`.
   *
   * A LOCAL DELETE MADE AFTER THE MERGE WINS over a record landing for the same
   * id - see `applyRemote` in `modules/hosts/store.ts` for why only this function
   * can make that comparison.
   */
  applyRemote(rules: RemoteLanding<ForwardRule>[]): Promise<RemoteLandingRefusal[]>;
  /** What this store's deletes have left behind, already pruned to the window -
   *  see `livingTombstones` in `src/lib/tombstones.ts`. */
  listTombstones(): Promise<Tombstone[]>;
  onForwardsChanged(cb: () => void): Promise<() => void>;
  ensureLoaded(): Promise<StoreRecovery | null>;
  takeRecoveryNotice(): StoreRecovery | null;
};

/** Opaque id. Same shape as `vault/store.ts`'s and `hosts/store.ts`'s `newId`,
 *  just with this module's own prefix. */
function newId(prefix: string): string {
  return `${prefix}-${Math.random().toString(36).slice(2, 10)}${Date.now().toString(36)}`;
}

function isValidLocalPort(port: number): boolean {
  return port === 0 || (Number.isInteger(port) && port >= 1 && port <= 65535);
}

function isValidRemotePort(port: number): boolean {
  return Number.isInteger(port) && port >= 1 && port <= 65535;
}

export function createForwardStore(io: ForwardsIo): ForwardsStore {
  // Serialized by the store port, not here - see `enqueueWrite` in
  // `vault/store.ts`'s identical one-liner for why the queue belongs beside
  // the file rather than in this layer.
  const enqueueWrite = <T>(op: () => Promise<T>): Promise<T> => io.store.enqueueWrite(op);

  // Read ONCE per mutator and reused - `dropRulesForHost` stamps one `deletedAt`
  // per rule it drops, and those stamps describe one operation. See the same line
  // in `hosts/store.ts`. This store's own clock in every mutator, never a
  // caller's value - `applyRemote` is the one exception, and takes the remote
  // timestamp beside the record it lands.
  const now = io.now ?? Date.now;

  async function listRules(): Promise<ForwardRule[]> {
    const raw = await io.store.get<ForwardRule[]>(FORWARDS_KEY);
    return Array.isArray(raw) ? raw : [];
  }

  /**
   * Every mutation lands through here, same shape as `vault/store.ts`'s
   * `persist`: the commit is also what takes the `.bak` snapshot.
   *
   * ENTRIES rather than one key, because a delete now writes the rule list and
   * the tombstone together. Split into two commits there would be a window where
   * the rule is gone and nothing records that it was deleted, and a device
   * pulling into that window pushes the rule straight back.
   *
   * DIRTY IS REQUIRED, and per RECORD - `hosts/store.ts`'s copy of this doc
   * carries the full reasoning; it is the same parameter for the same reasons.
   * `[]` is what `applyRemote` passes: a landing is what the remote already
   * holds.
   */
  async function persist(entries: [string, unknown][], dirty: DirtyId[]): Promise<void> {
    for (const [key, value] of entries) await io.store.set(key, value);
    await io.store.commit();
    io.markDirty?.(dirty);
  }

  /** Every rule dirty mark this store makes, since a rule is the only record it
   *  owns. */
  const dirtyRules = (ids: string[]): DirtyId[] =>
    ids.map((id) => ({ kind: RULE_TOMBSTONE_KIND, id }));

  /** Both the public read and every write's baseline, so no caller can reason
   *  about an expired row. `at` is the mutator's own single clock read. */
  async function readTombstones(at = now()): Promise<Tombstone[]> {
    return livingTombstones(await io.store.get(TOMBSTONES_KEY), at);
  }

  async function upsertRule(rule: ForwardRule, hosts: HostLookup): Promise<ForwardRule> {
    return enqueueWrite(async () => {
      if (!rule.name.trim()) {
        throw new Error("forwards: a rule needs a name");
      }
      // Every port/host refusal below is TYPE-CONDITIONAL: `-D` only binds a
      // local SOCKS5 port and has no dial target at all; `-R` dials its
      // target LOCALLY (so `targetHost`/`targetPort` are refused, its own
      // fields rather than `-L`'s `remoteHost`/`remotePort`) but binds its
      // listener on the SERVER (`bindPort`, which may legally be 0 - the
      // opposite of `-L`'s `remotePort`). See `types.ts`'s field-by-field doc
      // on `ForwardRule` for the mapping.
      if (rule.type === "dynamic") {
        if (!isValidLocalPort(rule.localPort)) {
          throw new Error(
            `forwards: "${rule.name}" has an invalid SOCKS port ${rule.localPort} - must be 0, or 1-65535`,
          );
        }
      } else if (rule.type === "remote") {
        if (!rule.targetHost?.trim()) {
          throw new Error(`forwards: "${rule.name}" needs a local target host`);
        }
        if (rule.targetPort === undefined || !isValidRemotePort(rule.targetPort)) {
          throw new Error(
            `forwards: "${rule.name}" has an invalid target port ${rule.targetPort} - must be 1-65535`,
          );
        }
        if (rule.bindPort !== undefined && !isValidLocalPort(rule.bindPort)) {
          throw new Error(
            `forwards: "${rule.name}" has an invalid bind port ${rule.bindPort} - must be 0, or 1-65535`,
          );
        }
      } else {
        if (!rule.remoteHost.trim()) {
          throw new Error(`forwards: "${rule.name}" needs a remote host`);
        }
        if (!isValidLocalPort(rule.localPort)) {
          throw new Error(
            `forwards: "${rule.name}" has an invalid local port ${rule.localPort} - must be 0, or 1-65535`,
          );
        }
        if (!isValidRemotePort(rule.remotePort)) {
          throw new Error(
            `forwards: "${rule.name}" has an invalid remote port ${rule.remotePort} - must be 1-65535`,
          );
        }
      }

      const host = await hosts(rule.hostId);
      if (!host) {
        throw new Error(
          `forwards: "${rule.name}" names a host (${rule.hostId}) that does not exist`,
        );
      }
      if (host.protocol !== "ssh") {
        throw new Error(
          `forwards: "${rule.name}" names a host (${rule.hostId}) that is an RDP host and cannot carry a forward`,
        );
      }

      const rules = await listRules();
      // Stamped from this layer's clock, overwriting whatever the caller
      // supplied: an editor round-trips the record it loaded, so honouring that
      // value would mean a save never bumps the stamp.
      const at = now();
      const record: ForwardRule = { ...rule, updatedAt: at };
      const next = [...rules];
      const idx = next.findIndex((r) => r.id === rule.id);
      if (idx >= 0) next[idx] = record;
      else next.push(record);
      // Any tombstone naming this id goes in the same commit, so a backup restore
      // is not deleted again by the first sync pull. The key is carried only when
      // something changed - see `withoutTombstone`.
      const entries: [string, unknown][] = [[FORWARDS_KEY, next]];
      const graves = withoutTombstone(await readTombstones(at), [rule.id], at);
      if (graves) entries.push([TOMBSTONES_KEY, graves]);
      await persist(entries, dirtyRules([rule.id]));
      return record;
    });
  }

  async function deleteRule(id: string): Promise<void> {
    return enqueueWrite(async () => {
      const rules = await listRules();
      // An existence guard, which this function did not have and did not need
      // while the write was a filter over a list: rewriting the same rules was a
      // harmless no-op. It is not harmless now. `deleteRule` on an id that was
      // never saved would publish a tombstone for a record that never existed,
      // and on another device that tombstone is indistinguishable from a real
      // delete - so it would delete a rule someone else had just created under a
      // colliding id, or simply resurrect nothing forever. The other deletes in
      // this codebase all return early on a missing id already.
      if (!rules.some((r) => r.id === id)) return;
      const at = now();
      const graves = await readTombstones(at);
      await persist(
        [
          [FORWARDS_KEY, rules.filter((r) => r.id !== id)],
          [
            TOMBSTONES_KEY,
            withTombstone(graves, [{ id, kind: RULE_TOMBSTONE_KIND, deletedAt: at }], at),
          ],
        ],
        dirtyRules([id]),
      );
    });
  }

  async function dropRulesForHost(hostId: string): Promise<void> {
    return enqueueWrite(async () => {
      const rules = await listRules();
      // ONE TOMBSTONE PER RULE DROPPED, never one for the host: what this call
      // deletes is rules, and the host's own tombstone is the hosts store's
      // business.
      //
      // Computed first so a host with no rules stays the no-op it has always
      // been - the same guard `deleteRule` gained and for the same reason. A
      // `hostId` with no rules is not the "id not in the store" case either: a
      // rules store holds no host ids at all, so nothing else here covers it.
      const dropped = rules.filter((r) => r.hostId === hostId);
      if (dropped.length === 0) return;
      const at = now();
      const graves = await readTombstones(at);
      await persist(
        [
          [FORWARDS_KEY, rules.filter((r) => r.hostId !== hostId)],
          [
            TOMBSTONES_KEY,
            withTombstone(
              graves,
              dropped.map((r) => ({ id: r.id, kind: RULE_TOMBSTONE_KIND, deletedAt: at })),
              at,
            ),
          ],
        ],
        // One mark per rule dropped, matching the tombstones: this call deletes
        // rules, and the host's own record is the hosts store's business.
        dirtyRules(dropped.map((r) => r.id)),
      );
    });
  }

  async function applyRemote(
    landings: RemoteLanding<ForwardRule>[],
  ): Promise<RemoteLandingRefusal[]> {
    return enqueueWrite(async () => {
      // ONE clock read for the whole set, and it stamps nothing: it is the
      // window boundary the tombstone reads and writes are filtered against, so
      // every landing in one apply is judged against one instant.
      const at = now();
      const refusals: RemoteLandingRefusal[] = [];
      const rules = [...(await listRules())];
      const graves = await readTombstones(at);
      const buried: Tombstone[] = [];
      const revived: string[] = [];
      let touched = false;

      for (const landing of landings) {
        const refusal = landingRefusal(landing, RULE_TOMBSTONE_KIND);
        if (refusal) {
          refusals.push(refusal);
          continue;
        }
        if (landing.deleted) {
          const idx = rules.findIndex((r) => r.id === landing.tombstone.id);
          if (idx >= 0) {
            rules.splice(idx, 1);
            touched = true;
          }
          const revivedIdx = revived.indexOf(landing.tombstone.id);
          if (revivedIdx >= 0) revived.splice(revivedIdx, 1);
          // Filed even when no local rule matched: another device deleted it, and
          // a device that has not pulled since would otherwise push its own copy
          // back the moment this one lands.
          buried.push(landing.tombstone);
          continue;
        }
        // A local delete made after the merge outranks the landing - see the same
        // comparison in `applyRemote` in `modules/hosts/store.ts` for why only
        // this function can make it.
        const superseding = graves.find(
          (t) => t.id === landing.id && t.kind === RULE_TOMBSTONE_KIND,
        );
        if (superseding && superseding.deletedAt > landing.updatedAt) continue;
        const record: ForwardRule = { ...landing.record, updatedAt: landing.updatedAt };
        const idx = rules.findIndex((r) => r.id === landing.id);
        if (idx >= 0) rules[idx] = record;
        else rules.push(record);
        const buriedIdx = buried.findIndex((t) => t.id === landing.id);
        if (buriedIdx >= 0) buried.splice(buriedIdx, 1);
        revived.push(landing.id);
        touched = true;
      }

      const entries: [string, unknown][] = [];
      if (touched) entries.push([FORWARDS_KEY, rules]);
      const next = landedTombstones(graves, revived, buried, at);
      if (next) entries.push([TOMBSTONES_KEY, next]);
      // An apply with nothing to write costs no commit at all, which is what
      // keeps a pull that landed nothing - the ordinary case once two devices
      // agree - from rewriting the file on every focus.
      if (entries.length > 0) await persist(entries, []);
      return refusals;
    });
  }

  return {
    listRules,
    findRule: async (id) => (await listRules()).find((r) => r.id === id),
    newRuleId: () => newId("f"),
    upsertRule,
    deleteRule,
    dropRulesForHost,
    applyRemote,
    listTombstones: () => readTombstones(),
    onForwardsChanged: (cb) => io.store.onChanged(cb),
    ensureLoaded: () => io.store.ensureLoaded(),
    takeRecoveryNotice: () => io.store.takeRecoveryNotice(),
  };
}

/** The app's forward rules. One instance, so one write queue. */
export const forwardsStore = createForwardStore({
  store: createTauriForwardsStoreIo(),
  // See the same line in `modules/hosts/store.ts`, and `src/lib/dirtySink.ts`
  // for why the marks travel through a sink rather than a direct call.
  markDirty,
});

export const {
  listRules,
  findRule,
  newRuleId,
  upsertRule,
  deleteRule,
  dropRulesForHost,
  applyRemote,
  listTombstones,
  onForwardsChanged,
  ensureLoaded,
  takeRecoveryNotice,
} = forwardsStore;
