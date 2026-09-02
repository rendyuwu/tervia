import type { StoreRecovery } from "@/lib/storeRecovery";
import type { Host } from "@/modules/hosts/types";

import { createTauriForwardsStoreIo, type ForwardsIo } from "./adapters";
import { FORWARDS_KEY, type ForwardRule } from "./types";

// The forwards store: one record per saved rule, modelled on `vault/store.ts`'s
// shape and its `enqueueWrite` one-liner.
//
// `hosts` arrives on `upsertRule` as a REQUIRED INJECTED LOOKUP, never an
// import. `modules/hosts/store.ts`'s own comment on `ForwardRuleCleanup`
// (:112-114) explains the direction: `modules/forwards` will always want to
// import `Host` from `modules/hosts` (a type-only import, and the only one this
// file makes across modules), so a `modules/hosts` -> `modules/forwards` import
// closes the cycle. `ForwardRuleCleanup` is the wiring in the other direction -
// `deleteHost` calls into this module without importing it either.
//
// `dropRulesForHost` is the callee behind that wiring, and it deliberately does
// NOT consult the host lookup at all: it runs from inside `deleteHost`'s own
// write queue (`hosts/store.ts`:954-961), awaited before that queue touches the
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
   * or a blank `remoteHost`. See the six named checks in the plan's step body -
   * each refusal names both the rule and the id or value it is refusing.
   */
  upsertRule(rule: ForwardRule, hosts: HostLookup): Promise<ForwardRule>;
  /** Refuses nothing. A rule references a host; nothing references a rule, so
   *  there is no holder to check - unlike every other delete in this codebase,
   *  which is exactly why this comment exists: the next reader will go looking
   *  for the guard here and should stop instead. */
  deleteRule(id: string): Promise<void>;
  /**
   * Drop every rule naming `hostId`. Unconditional and idempotent: a no-op for a
   * host with no rules and for a host id that was never saved, and it does NOT
   * consult a host lookup - see the header above for why that omission is load
   * bearing rather than a shortcut.
   */
  dropRulesForHost(hostId: string): Promise<void>;
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
  // Serialized by the store port, not here - see `vault/store.ts:111`'s
  // identical one-liner for why the queue belongs beside the file rather than
  // in this layer.
  const enqueueWrite = <T>(op: () => Promise<T>): Promise<T> => io.store.enqueueWrite(op);

  async function listRules(): Promise<ForwardRule[]> {
    const raw = await io.store.get<ForwardRule[]>(FORWARDS_KEY);
    return Array.isArray(raw) ? raw : [];
  }

  /** Every mutation lands through here, same shape as `vault/store.ts`'s
   *  `persist`: the commit is also what takes the `.bak` snapshot. */
  async function persist(list: ForwardRule[]): Promise<void> {
    await io.store.set(FORWARDS_KEY, list);
    await io.store.commit();
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
      const next = [...rules];
      const idx = next.findIndex((r) => r.id === rule.id);
      if (idx >= 0) next[idx] = rule;
      else next.push(rule);
      await persist(next);
      return rule;
    });
  }

  async function deleteRule(id: string): Promise<void> {
    return enqueueWrite(async () => {
      const rules = await listRules();
      await persist(rules.filter((r) => r.id !== id));
    });
  }

  async function dropRulesForHost(hostId: string): Promise<void> {
    return enqueueWrite(async () => {
      const rules = await listRules();
      await persist(rules.filter((r) => r.hostId !== hostId));
    });
  }

  return {
    listRules,
    findRule: async (id) => (await listRules()).find((r) => r.id === id),
    newRuleId: () => newId("f"),
    upsertRule,
    deleteRule,
    dropRulesForHost,
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
  onForwardsChanged,
  ensureLoaded,
  takeRecoveryNotice,
} = forwardsStore;
