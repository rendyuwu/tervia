import type { StoreRecovery } from "@/lib/storeRecovery";
import {
  livingTombstones,
  TOMBSTONES_KEY,
  withoutTombstone,
  withTombstone,
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
   * Refuses a `hostId` that does not name a saved SSH host, a `localPort`
   * outside `0` or `1-65535`, a `remotePort` outside `1-65535`, a blank `name`,
   * or a blank `remoteHost`. Each refusal names both the rule and the id or
   * value it is refusing.
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
  // in `hosts/store.ts`. Always this store's own clock, never a caller's value:
  // accepted and deferred in `KNOWN-LIMITS.md`.
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
   */
  async function persist(entries: [string, unknown][]): Promise<void> {
    for (const [key, value] of entries) await io.store.set(key, value);
    await io.store.commit();
  }

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
      await persist(entries);
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
      await persist([
        [FORWARDS_KEY, rules.filter((r) => r.id !== id)],
        [
          TOMBSTONES_KEY,
          withTombstone(graves, [{ id, kind: RULE_TOMBSTONE_KIND, deletedAt: at }], at),
        ],
      ]);
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
      await persist([
        [FORWARDS_KEY, rules.filter((r) => r.hostId !== hostId)],
        [
          TOMBSTONES_KEY,
          withTombstone(
            graves,
            dropped.map((r) => ({ id: r.id, kind: RULE_TOMBSTONE_KIND, deletedAt: at })),
            at,
          ),
        ],
      ]);
    });
  }

  return {
    listRules,
    findRule: async (id) => (await listRules()).find((r) => r.id === id),
    newRuleId: () => newId("f"),
    upsertRule,
    deleteRule,
    dropRulesForHost,
    listTombstones: () => readTombstones(),
    onForwardsChanged: (cb) => io.store.onChanged(cb),
    ensureLoaded: () => io.store.ensureLoaded(),
    takeRecoveryNotice: () => io.store.takeRecoveryNotice(),
  };
}

/** The app's forward rules. One instance, so one write queue. */
export const forwardsStore = createForwardStore({ store: createTauriForwardsStoreIo() });

export const {
  listRules,
  findRule,
  newRuleId,
  upsertRule,
  deleteRule,
  dropRulesForHost,
  listTombstones,
  onForwardsChanged,
  ensureLoaded,
  takeRecoveryNotice,
} = forwardsStore;
