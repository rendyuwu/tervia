/**
 * Self-check for the sync scheduler: when a pull and a push happen, what they
 * carry, and what the etag map is allowed to record afterwards.
 * Run: `npx tsx scripts/sync-scheduler-verify.ts`.
 *
 * SPLIT BY THE LANGUAGE THE BEHAVIOUR IS IN. The merge, the prune and the etag
 * skip are in `src-tauri/src/modules/sync/engine.rs` and are checked by
 * `cargo test` against a fake provider; a copy of them here would be a fake
 * asserting against a fake. What is here is what only TypeScript decides: the
 * triggers, which store a landing goes to, and the map write.
 *
 * REAL STORES, NOT FAKES. Every check below that involves a dirty mark drives
 * `createHostsStore` and friends with in-memory ports and the scheduler wired in
 * as their live `markDirty`. That is the whole reason B5 can fail here and could
 * not in `sync-apply-verify.ts`: there, "`applyRemote` marks nothing" is true by
 * construction because nothing consumes marks; here there is a consumer and a
 * regression would push a record this device merely received.
 *
 * What fails silently without these:
 *
 * 1. A SCHEDULER THAT RUNS WITH SYNC OFF. "Off means no network" is the whole
 *    opt-in, and it is asserted as a MEASURED ZERO on a counting command port -
 *    not as a consequence of nothing calling, which would pass in a tree where
 *    the call was simply deleted.
 *
 * 2. A PUSH PER EDIT, OR A PUSH OF THE WHOLE INVENTORY. Both are invisible
 *    locally: the store is right either way, and the cost lands on the user's
 *    storage bill and on every other device's next pull.
 *
 * 3. A CONNECT THAT PUSHES. `markConnected` and `pinFingerprint` write
 *    device-local fields that never travel. A mark there means a machine that
 *    merely reconnected republishes its copy over a real edit made elsewhere.
 *
 * 4. AN APPLY THAT PUSHES BACK. A landed record is what the remote already
 *    holds; marking it dirty is a loop between two devices, neither of them
 *    wrong.
 *
 * 5. AN ETAG MAP THAT RECORDS A LANDING THAT NEVER HAPPENED. A refused record
 *    whose etag advanced is skipped by every later pull - so the refusal is
 *    permanent and silent. The mirror failure is freezing the whole map on any
 *    refusal, which degrades every pull to a full inventory download forever.
 *
 * 6. A FOCUS TRIGGER WITH NO FLOOR. Event-driven in name and a poll loop in
 *    substance: one LIST against the user's storage per alt-tab.
 *
 * 7. TWO WINDOWS APPLYING AT ONCE. `fileKeyValueStore.ts` gives up after a few
 *    contended attempts and writes over a stale baseline, losing the other
 *    window's update.
 *
 * 8. TWO SPELLINGS OF ONE CONSTANT DRIFTING. The device-local field list and the
 *    tombstone window each exist in Rust and in TypeScript, and each pair has to
 *    agree or the symptom is a store rewritten on every pull, or remote objects
 *    removed while devices still compare against them. Both are read out of the
 *    Rust source as text, because `tsc` cannot see across that boundary.
 */
/// <reference types="node" />
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  createWriteQueue,
  type KeyValueStore,
  type RecoveredStoreIo,
} from "../src/lib/recoveredStore";
import { TOMBSTONE_TTL_MS, TOMBSTONES_KEY, type Tombstone } from "../src/lib/tombstones";
import { createForwardStore } from "../src/modules/forwards/store";
import { FORWARDS_KEY, RULE_TOMBSTONE_KIND, type ForwardRule } from "../src/modules/forwards/types";
import { createHostsStore } from "../src/modules/hosts/store";
import {
  HOSTS_KEY,
  HOST_GROUPS_KEY,
  HOST_TOMBSTONE_KIND,
  type Host,
  type HostGroup,
  type SshHost,
} from "../src/modules/hosts/types";
import { DEVICE_LOCAL_FIELDS } from "../src/modules/sync/envelope";
import { createScheduler } from "../src/modules/sync/scheduler";
import { createSyncSettingsStore, type SyncSettingsStore } from "../src/modules/sync/store";
import {
  DEFAULT_SYNC_CONFIG,
  SYNC_CONFIG_KEY,
  SYNC_DIRTY_KEY,
  SYNC_ETAGS_KEY,
  WIRE_VERSION,
  type Envelope,
  type PullReport,
  type PushReport,
  type Reconciled,
  type SyncCommands,
  type SyncStatus,
} from "../src/modules/sync/types";
import type { SecretsIo } from "../src/modules/vault/adapters";
import { createVaultStore } from "../src/modules/vault/store";
import {
  IDENTITY_TOMBSTONE_KIND,
  KEY_TOMBSTONE_KIND,
  VAULT_IDENTITIES_KEY,
  VAULT_KEYS_KEY,
  type VaultIdentity,
  type VaultKey,
} from "../src/modules/vault/types";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));

let failed = 0;

/**
 * Everything the scheduler LOGGED instead of throwing.
 *
 * `serialize` swallows every rejection, which is right - each of its four
 * callers is a `void` or an event handler, and an unhandled rejection there has
 * no owner. The cost is that a check awaiting `pullNow()` sees a clean resolve
 * on a pass that failed outside its own try, so the whole of that blind spot is
 * invisible to an assertion. Counting the log is what closes it.
 *
 * `check` writes its own failures through the captured writer, so a FAIL is not
 * also counted here.
 */
const logged: string[] = [];
const write = console.error.bind(console);
console.error = (...args: unknown[]): void => {
  if (typeof args[0] === "string" && args[0].startsWith("sync:")) logged.push(args[0]);
  write(...args);
};

function check(label: string, got: unknown, want: unknown): void {
  const found = JSON.stringify(got) ?? String(got);
  const wanted = JSON.stringify(want) ?? String(want);
  if (found === wanted) {
    console.log(`  ok: ${label}`);
  } else {
    write(`  FAIL: ${label} = ${found}, want ${wanted}`);
    failed++;
  }
}

/** Far enough from the epoch that a stamp a hundred days earlier is positive. */
const START = 1_800_000_000_000;

/**
 * Drain the microtask queue.
 *
 * Every await in the scheduler and in the three stores resolves on a microtask -
 * the write queue included - so nothing here needs a real timer, which is also
 * why the debounce is fired by hand rather than waited out.
 */
async function settle(): Promise<void> {
  for (let i = 0; i < 50; i++) await Promise.resolve();
}

// ---------------------------------------------------------------------------
// Ports
// ---------------------------------------------------------------------------

/** A shared step counter, so "the map was written AFTER the apply resolved" is
 *  an ordering question a check can actually ask. */
let step = 0;
const trace: string[] = [];
function mark(what: string): void {
  step++;
  trace.push(`${step} ${what}`);
}

function port(seed: Record<string, unknown>, label: string): RecoveredStoreIo {
  const data: Record<string, unknown> = { ...seed };
  let pending: Record<string, unknown> = {};
  return {
    async get<T>(key: string): Promise<T | null> {
      return ((key in pending ? pending[key] : data[key]) as T | undefined) ?? null;
    },
    async set(key: string, value: unknown): Promise<void> {
      pending[key] = value;
    },
    async commit(): Promise<void> {
      mark(`commit:${label}`);
      Object.assign(data, pending);
      pending = {};
    },
    enqueueWrite: createWriteQueue(),
    async onChanged(): Promise<() => void> {
      return () => {};
    },
    ensureLoaded: async () => null,
    takeRecoveryNotice: () => null,
    fileState: async () => ({ found: "ok" as const, recovered: false }),
  };
}

/** The sync settings file, in memory, saving straight through. */
function settingsPort(seed: Record<string, unknown>): KeyValueStore {
  const data: Record<string, unknown> = { ...seed };
  let pending: Record<string, unknown> = {};
  return {
    async get<T>(key: string): Promise<T | null> {
      return ((key in pending ? pending[key] : data[key]) as T | undefined) ?? null;
    },
    async set(key: string, value: unknown): Promise<void> {
      pending[key] = value;
    },
    async save(): Promise<void> {
      if (SYNC_ETAGS_KEY in pending) mark("writeEtags");
      Object.assign(data, pending);
      pending = {};
    },
  };
}

const noSecrets: SecretsIo = {
  async getAll(_service, accounts) {
    return accounts.map(() => null);
  },
  async set() {},
  async delete() {},
  async copy() {
    return false;
  },
};

function harness(
  seed: {
    enabled?: boolean;
    label?: string;
    hosts?: Host[];
    groups?: HostGroup[];
    hostGraves?: Tombstone[];
    identities?: VaultIdentity[];
    vaultKeys?: VaultKey[];
    rules?: ForwardRule[];
    etags?: Record<string, string>;
    pull?: PullReport;
    push?: PushReport;
    dirty?: string[];
    park?: boolean;
    parkDirty?: boolean;
    releaseThrows?: boolean;
  } = {},
) {
  const now = () => START;
  const hostsData = port(
    {
      [HOSTS_KEY]: seed.hosts ?? [],
      [HOST_GROUPS_KEY]: seed.groups ?? [],
      ...(seed.hostGraves ? { [TOMBSTONES_KEY]: seed.hostGraves } : {}),
    },
    "hosts",
  );
  const vaultData = port(
    { [VAULT_IDENTITIES_KEY]: seed.identities ?? [], [VAULT_KEYS_KEY]: seed.vaultKeys ?? [] },
    "vault",
  );
  const forwardsData = port({ [FORWARDS_KEY]: seed.rules ?? [] }, "forwards");

  const settingsData = settingsPort({
    [SYNC_CONFIG_KEY]: { ...DEFAULT_SYNC_CONFIG, enabled: seed.enabled ?? true },
    [SYNC_ETAGS_KEY]: seed.etags ?? {},
    ...(seed.dirty ? { [SYNC_DIRTY_KEY]: seed.dirty } : {}),
  });
  // A `readDirty` that can be parked mid-flight, which is the only way to
  // construct a mark made DURING a flush - the window the spread order in
  // `runPush` decides.
  let releaseDirty = (): void => {};
  const dirtyParked = new Promise<void>((r) => {
    releaseDirty = r;
  });
  const base = createSyncSettingsStore(settingsData);
  const settings: SyncSettingsStore = {
    ...base,
    async readDirty() {
      if (seed.parkDirty) await dirtyParked;
      return base.readDirty();
    },
  };

  // A pull that can be parked mid-flight, which is the only way to construct
  // the interleaving B17 is about: a real pull's read-to-write window is a LIST
  // plus N GETs, and here every fake resolves on the next microtask.
  let release = (): void => {};
  const parked = new Promise<void>((r) => {
    release = r;
  });
  /** Set by a check to make the next pull command reject. */
  let failPull: string | null = null;
  const calls = { pull: 0, push: 0 };
  const pulled: { envelopes: Envelope[]; etags: Record<string, string> }[] = [];
  const pushed: { envelopes: Envelope[]; etags: Record<string, string> }[] = [];
  const commands: SyncCommands = {
    async pull(envelopes, etags) {
      calls.pull++;
      pulled.push({ envelopes, etags });
      if (seed.park) await parked;
      if (failPull) throw new Error(failPull);
      return seed.pull ?? { records: [], etags: {}, quarantined: [], pruned: 0, pending: 0 };
    },
    async push(envelopes, etags) {
      calls.push++;
      pushed.push({ envelopes, etags });
      return seed.push ?? { etags: {}, failed: [] };
    },
  };

  const timers: (() => void)[] = [];

  const hosts = createHostsStore({
    store: hostsData,
    secrets: noSecrets,
    now,
    markDirty: (d) => scheduler.markDirty(d),
  });
  const vault = createVaultStore({
    store: vaultData,
    secrets: noSecrets,
    now,
    markDirty: (d) => scheduler.markDirty(d),
  });
  const forwards = createForwardStore({
    store: forwardsData,
    now,
    markDirty: (d) => scheduler.markDirty(d),
  });

  const released: string[] = [];
  const scheduler = createScheduler({
    label: seed.label ?? "main",
    commands,
    settings,
    stores: { hosts, vault, forwards },
    async releaseRule(rule) {
      mark(`release:${rule.id}`);
      released.push(rule.id);
      if (seed.releaseThrows) throw new Error("forwards: the close reported");
    },
    now,
    setTimer: (fn) => {
      timers.push(fn);
      return timers.length;
    },
    clearTimer: () => {},
  });

  return {
    scheduler,
    hosts,
    vault,
    forwards,
    released,
    release: (): void => release(),
    releaseDirty: (): void => releaseDirty(),
    failPull: (reason: string | null): void => {
      failPull = reason;
    },
    settings,
    settingsData,
    dirty: (): Promise<string[]> => settings.readDirty(),
    calls,
    pulled,
    pushed,
    timers,
    async fire(): Promise<void> {
      const due = timers.splice(0, timers.length);
      for (const fn of due) fn();
      await settle();
    },
    status: async (): Promise<SyncStatus> => settings.readStatus(),
  };
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** An SSH host that references nothing, so `upsertHost` accepts it without a
 *  vault identity or a jump host having to exist. */
const host = (id: string, over: Partial<SshHost> = {}): SshHost => ({
  id,
  name: `host ${id}`,
  host: "10.0.0.1",
  port: 22,
  protocol: "ssh",
  credential: {
    kind: "inline",
    hostId: id,
    user: "root",
    authMode: "password",
    hasPassword: false,
    hasPrivateKey: false,
    hasKeyPassphrase: false,
  },
  updatedAt: START - 5000,
  ...over,
});

/** A landing straight off the wire: stamped OLDER than the harness clock, so a
 *  store that stamped its own would answer `START` instead. */
const REMOTE = START - 9000;

function merged(
  kind: string,
  id: string,
  record: unknown,
  over: { changed?: boolean; republish?: boolean } = {},
): Reconciled {
  return {
    kind,
    id,
    outcome: "merged",
    envelope: {
      v: WIRE_VERSION,
      kind,
      id,
      updatedAt: REMOTE,
      device: "dev-b",
      deleted: false,
      record,
    },
    changed: over.changed ?? true,
    secretsChanged: false,
    republish: over.republish ?? false,
  };
}

function remoteOnly(kind: string, id: string, record: unknown): Reconciled {
  return {
    kind,
    id,
    outcome: "remoteOnly",
    envelope: {
      v: WIRE_VERSION,
      kind,
      id,
      updatedAt: REMOTE,
      device: "dev-b",
      deleted: false,
      record,
    },
  };
}

const localOnly = (kind: string, id: string, stale: boolean): Reconciled => ({
  kind,
  id,
  outcome: "localOnly",
  stale,
});

// ---------------------------------------------------------------------------
// The checks
// ---------------------------------------------------------------------------

async function b1(): Promise<void> {
  console.log("\nB1 - with sync off, nothing is invoked");
  const h = harness({ enabled: false, hosts: [host("h-1")] });
  await h.scheduler.pullNow();
  await h.hosts.upsertGroup({ id: "g-1", name: "prod" });
  await h.fire();
  h.scheduler.onFocus();
  await settle();
  // A MEASURED ZERO on the port itself, not an absence of call sites.
  check("off: no pull and no push", h.calls, { pull: 0, push: 0 });
  // And the marks accumulated while it was off are dropped rather than held
  // forever: turning sync on publishes the whole inventory anyway, so a set
  // that grew for months would only make that first push describe itself twice.
  check("off: the dirty set is cleared, not hoarded", await h.dirty(), []);
}

async function b2b3b4(): Promise<void> {
  console.log("\nB2, B3, B4 - the debounce, and what one edit carries");

  const one = harness({ hosts: [host("h-1"), host("h-2"), host("h-3")] });
  await one.hosts.upsertGroup({ id: "g-1", name: "prod" });
  check("B2: one mutation arms exactly one timer", one.timers.length, 1);
  await one.fire();
  check("B2: one push after the debounce", one.calls.push, 1);

  const five = harness({ hosts: [host("h-1")] });
  for (const id of ["g-1", "g-2", "g-3", "g-4", "g-5"]) {
    await five.hosts.upsertGroup({ id, name: id });
  }
  check("B3: five mutations inside the window arm one timer", five.timers.length, 1);
  await five.fire();
  check("B3: and produce one push, not five", five.calls.push, 1);
  check("B3: carrying all five records", five.pushed[0]?.envelopes.map((e) => e.id).sort(), [
    "g-1",
    "g-2",
    "g-3",
    "g-4",
    "g-5",
  ]);

  const edit = harness({ hosts: [host("h-1"), host("h-2"), host("h-3")] });
  await edit.hosts.upsertHost(host("h-2", { name: "renamed" }));
  await edit.fire();
  // The property `persist(entries, dirty)` exists for: a hook that could only
  // say "this store changed" would publish all three.
  check(
    "B4: one host edit pushes one object",
    edit.pushed[0]?.envelopes.map((e) => `${e.kind}:${e.id}`),
    ["host:h-2"],
  );
  check(
    "B4: and no device-local field rides with it",
    DEVICE_LOCAL_FIELDS.filter(
      (f) => (edit.pushed[0]?.envelopes[0]?.record as Record<string, unknown>)[f] !== undefined,
    ),
    [],
  );
  check("B4: and this side names no device", edit.pushed[0]?.envelopes[0]?.device ?? null, null);
}

async function b5(): Promise<void> {
  console.log("\nB5 - what must NOT schedule a push");

  const h = harness({ hosts: [host("h-1")] });
  await h.hosts.markConnected("h-1", "SHA256:aaa");
  await h.hosts.pinFingerprint("h-1", "SHA256:aaa");
  check("markConnected and pinFingerprint arm no timer", h.timers.length, 0);

  // The one a live consumer can fail and a construction-only argument cannot:
  // a landed record is what the remote already holds, so marking it dirty is a
  // push loop between two devices.
  const applied = harness({ hosts: [host("h-1")] });
  await applied.hosts.applyRemote(
    [{ deleted: false, id: "h-9", record: host("h-9"), updatedAt: REMOTE }],
    [],
  );
  check("applyRemote arms no timer", applied.timers.length, 0);
  await applied.fire();
  check("applyRemote pushes nothing", applied.calls.push, 0);
}

async function b6(): Promise<void> {
  console.log("\nB6 - the focus rate limit");
  const h = harness();
  h.scheduler.onFocus();
  h.scheduler.onFocus();
  await settle();
  // One clock value for both events, which is the shape of an alt-tab burst.
  check("two focus events inside the window produce one pull", h.calls.pull, 1);
}

async function b7(): Promise<void> {
  console.log("\nB7 - a merge only writes when it changed something");

  const unchanged = harness({
    hosts: [host("h-1")],
    pull: {
      records: [merged(HOST_TOMBSTONE_KIND, "h-1", host("h-1"), { changed: false })],
      etags: { "host:h-1": "e1" },
      quarantined: [],
      pruned: 0,
      pending: 0,
    },
  });
  const before = trace.length;
  await unchanged.scheduler.pullNow();
  await settle();
  check(
    "changed: false commits nothing to the hosts store",
    trace.slice(before).filter((t) => t.endsWith("commit:hosts")).length,
    0,
  );

  const changed = harness({
    hosts: [host("h-1")],
    pull: {
      records: [merged(HOST_TOMBSTONE_KIND, "h-1", host("h-1", { name: "from the remote" }))],
      etags: { "host:h-1": "e1" },
      quarantined: [],
      pruned: 0,
      pending: 0,
    },
  });
  await changed.scheduler.pullNow();
  await settle();
  check(
    "changed: true lands the record at the REMOTE stamp",
    (await changed.hosts.listHosts()).map((h) => [h.name, h.updatedAt]),
    [["from the remote", REMOTE]],
  );
}

async function b8(): Promise<void> {
  console.log("\nB8 - the three dispositions");
  const h = harness({
    hosts: [host("h-1"), host("h-2")],
    pull: {
      records: [
        remoteOnly(HOST_TOMBSTONE_KIND, "h-9", host("h-9", { name: "landed" })),
        localOnly(HOST_TOMBSTONE_KIND, "h-1", false),
        localOnly(HOST_TOMBSTONE_KIND, "h-2", true),
      ],
      etags: {},
      quarantined: [],
      pruned: 1,
      pending: 1,
    },
  });
  await h.scheduler.pullNow();
  await settle();

  check("RemoteOnly lands", (await h.hosts.listHosts()).map((x) => x.id).sort(), [
    "h-1",
    "h-2",
    "h-9",
  ]);
  check(
    "recent LocalOnly is pushed and stale LocalOnly is not",
    h.pushed[0]?.envelopes.map((e) => e.id),
    ["h-1"],
  );
  // The whole reason the stale arm is not a delete: a listing gap is an
  // inference, and a truncated page presents exactly the same way.
  check("stale LocalOnly is still in the store", (await h.hosts.findHost("h-2"))?.id, "h-2");
  const status = await h.status();
  check("stale LocalOnly is reported", status.stale, [{ kind: "host", id: "h-2" }]);
  // COUNTED AFTER THE PUSH. The reconcile said one record was missing from the
  // remote, and the push in the same pass placed it, so nothing is pending -
  // reporting the pre-push number would leave the settings window showing work
  // that was already done until the next pull. B15 is the other direction: a
  // push that FAILS leaves its record counted.
  check("the pending count is what the push left behind", status.pending, 0);
  check("and it reaches the store file", (await h.settings.readStatus()).pending, 0);
}

async function b9(): Promise<void> {
  console.log("\nB9 - no scheduler outside the main webview");
  for (const label of ["settings", "float"]) {
    const h = harness({ label, hosts: [host("h-1")] });
    h.scheduler.markDirty([{ kind: HOST_TOMBSTONE_KIND, id: "h-1" }]);
    await h.scheduler.pullNow();
    await h.scheduler.pushNow();
    h.scheduler.onFocus();
    await settle();
    check(
      `${label}: nothing is invoked and nothing is armed`,
      {
        ...h.calls,
        timers: h.timers.length,
      },
      { pull: 0, push: 0, timers: 0 },
    );
  }
}

async function b10(): Promise<void> {
  console.log("\nB10 - the etag map advances minus the refused");
  // The refusal is the id disagreement, which is one of the five conditions
  // `landingRefusal` owns - and NOT a reference guard, which this path skips.
  const h = harness({
    hosts: [host("h-1")],
    pull: {
      records: [
        {
          ...merged(HOST_TOMBSTONE_KIND, "h-bad", host("h-other")),
        },
        merged(HOST_TOMBSTONE_KIND, "h-good", host("h-good")),
      ],
      etags: { "host:h-bad": "e1", "host:h-good": "e2" },
      quarantined: [],
      pruned: 0,
      pending: 0,
    },
  });
  const before = trace.length;
  await h.scheduler.pullNow();
  await settle();

  check("the refused id is dropped and the applied one is kept", await h.settings.readEtags(), {
    "host:h-good": "e2",
  });
  // Order, not just content: writing the map first costs the landing on a
  // crash, and writing it after costs one idempotent re-apply.
  const after = trace.slice(before);
  const commit = after.findIndex((t) => t.endsWith("commit:hosts"));
  const write = after.findIndex((t) => t.endsWith("writeEtags"));
  check("the map is written after the apply resolved", commit >= 0 && write > commit, true);
  // And the good landing still landed, in the same pass that refused the bad
  // one - a refusal must not cost the rest of the inventory.
  check("the good landing applied anyway", (await h.hosts.findHost("h-good"))?.id, "h-good");
}

async function b11(): Promise<void> {
  console.log("\nB11 - the two constants that exist in both languages");

  const model = readFileSync(resolve(ROOT, "src-tauri/src/modules/sync/model.rs"), "utf8");
  const listed = /const DEVICE_LOCAL_FIELDS: \[&str; \d+\] = \[([\s\S]*?)\];/.exec(model);
  const rustFields = [...(listed?.[1] ?? "").matchAll(/"([^"]+)"/g)].map((m) => m[1]);
  check(
    "the device-local field list agrees with the Rust one",
    [...DEVICE_LOCAL_FIELDS],
    rustFields,
  );
  // A negative assertion passes for free against an empty list, so the list
  // being non-empty is part of the claim.
  check("and it is not empty", rustFields.length > 0, true);

  const engine = readFileSync(resolve(ROOT, "src-tauri/src/modules/sync/engine.rs"), "utf8");
  const ttl = /const TOMBSTONE_TTL_MS: u64 = ([0-9 *_]+);/.exec(engine);
  const factors = (ttl?.[1] ?? "").split("*").map((part) => Number(part.replace(/[\s_]/g, "")));
  const rustTtl = factors.every((n) => Number.isFinite(n) && n > 0)
    ? factors.reduce((a, b) => a * b, 1)
    : NaN;
  // The prune window and the local expiry window are the same window seen from
  // two sides: a drift either strands objects nobody reads or removes objects
  // devices still compare against.
  check("the tombstone window agrees with the Rust one", rustTtl, TOMBSTONE_TTL_MS);
}

async function b12(): Promise<void> {
  console.log("\nB12 - the local set is records plus living tombstones");
  const h = harness({
    hosts: [host("h-1")],
    hostGraves: [{ id: "h-7", kind: HOST_TOMBSTONE_KIND, deletedAt: START - 1000 }],
    identities: [{ id: "i-1", name: "root", updatedAt: START - 1000 } as VaultIdentity],
    vaultKeys: [{ id: "k-1", name: "id_ed25519", updatedAt: START - 1000 } as VaultKey],
    rules: [
      {
        id: "f-1",
        name: "web",
        hostId: "h-1",
        localPort: 8080,
        remoteHost: "127.0.0.1",
        remotePort: 80,
        startWithHost: false,
        updatedAt: START - 1000,
      },
    ],
  });
  await h.scheduler.pullNow();
  await settle();
  // Without the tombstone the delete reads as remote-only and lands again on
  // the device that made it.
  check(
    "every kind, and the tombstone, reach the pull",
    h.pulled[0]?.envelopes.map((e) => `${e.kind}:${e.id}${e.deleted ? " (deleted)" : ""}`).sort(),
    [
      `${HOST_TOMBSTONE_KIND}:h-1`,
      `${HOST_TOMBSTONE_KIND}:h-7 (deleted)`,
      `${IDENTITY_TOMBSTONE_KIND}:i-1`,
      `${KEY_TOMBSTONE_KIND}:k-1`,
      `${RULE_TOMBSTONE_KIND}:f-1`,
    ],
  );
  check(
    "a tombstone travels at its own deletedAt",
    h.pulled[0]?.envelopes.find((e) => e.deleted)?.updatedAt,
    START - 1000,
  );
}

/** One rule, running, that another device deletes. */
function runningRule(): ForwardRule {
  return {
    id: "f-1",
    name: "web",
    hostId: "h-1",
    localPort: 8080,
    remoteHost: "127.0.0.1",
    remotePort: 80,
    startWithHost: false,
    updatedAt: START - 5000,
  };
}

/** A landed delete for the rule above, as the pull hands it over. */
const droppedRule: Reconciled = {
  kind: RULE_TOMBSTONE_KIND,
  id: "f-1",
  outcome: "remoteOnly",
  envelope: {
    v: WIRE_VERSION,
    kind: RULE_TOMBSTONE_KIND,
    id: "f-1",
    updatedAt: REMOTE,
    device: "dev-b",
    deleted: true,
    record: null,
  },
};

async function b13(): Promise<void> {
  console.log("\nB13 - a landed delete releases the forward before dropping the rule");
  const pull: PullReport = {
    records: [droppedRule],
    etags: { "rule:f-1": "e1" },
    quarantined: [],
    pruned: 0,
    pending: 0,
  };

  const h = harness({ rules: [runningRule()], pull });
  const before = trace.length;
  await h.scheduler.pullNow();
  await settle();
  check("the running forward is released", h.released, ["f-1"]);
  // ORDER IS THE PROPERTY. Dropping the record first releases nothing: the
  // record carries the host and both endpoints a stop needs to NAME the entry,
  // and once it is gone nothing can name it.
  const after = trace.slice(before);
  const releasedAt = after.findIndex((t) => t.endsWith("release:f-1"));
  const droppedAt = after.findIndex((t) => t.endsWith("commit:forwards"));
  check("released before the record is dropped", releasedAt >= 0 && droppedAt > releasedAt, true);
  check("and the rule is gone", (await h.forwards.listRules()).length, 0);

  // A REJECTING CLOSE DOES NOT ABORT THE PASS. The apply is one queued write
  // over every landing in the pull, so a throw would lose all of them.
  //
  // THE FIXTURE CARRIES A REPUBLISH, deliberately: with nothing to publish the
  // pull's push path never runs, and a status write there that overwrote the
  // close error would go unnoticed. This is the arrangement that can fail.
  const noisy = harness({
    hosts: [host("h-1")],
    rules: [runningRule()],
    pull: {
      ...pull,
      records: [
        ...pull.records,
        merged(HOST_TOMBSTONE_KIND, "h-1", host("h-1"), { changed: false, republish: true }),
      ],
    },
    releaseThrows: true,
  });
  await noisy.scheduler.pullNow();
  await settle();
  check("a rejecting close still lands the delete", (await noisy.forwards.listRules()).length, 0);
  check("and the pull still published what it owed", noisy.calls.push, 1);
  check(
    "and the close is reported rather than swallowed",
    (await noisy.status()).lastError,
    "forwards: the close reported",
  );
}

async function b14(): Promise<void> {
  console.log("\nB14 - a landing nothing applied does not advance the etag map");

  // Arm one: a kind no store on this device owns, which is what a record type
  // added by a newer build looks like from here.
  const unknown = harness({
    pull: {
      records: [
        remoteOnly("workspace", "w-1", { id: "w-1" }),
        remoteOnly(HOST_TOMBSTONE_KIND, "h-9", host("h-9")),
      ],
      etags: { "workspace:w-1": "e1", "host:h-9": "e2" },
      quarantined: [],
      pruned: 0,
      pending: 0,
    },
  });
  await unknown.scheduler.pullNow();
  await settle();
  // Without this the object is etag-skipped on every later pull, so the build
  // that DOES own the kind never sees it.
  check("an unownable kind keeps its etag out of the map", await unknown.settings.readEtags(), {
    "host:h-9": "e2",
  });

  // Arm two: a tombstone with no `deletedAt`. `livingTombstones` requires a
  // number, so landing it would write a row that every read then filters out -
  // the delete lost here while the map says it was applied.
  const stampless = harness({
    pull: {
      records: [
        {
          kind: HOST_TOMBSTONE_KIND,
          id: "h-7",
          outcome: "remoteOnly",
          envelope: {
            v: WIRE_VERSION,
            kind: HOST_TOMBSTONE_KIND,
            id: "h-7",
            device: "dev-b",
            deleted: true,
            record: null,
          },
        },
        remoteOnly(HOST_TOMBSTONE_KIND, "h-9", host("h-9")),
      ],
      etags: { "host:h-7": "e1", "host:h-9": "e2" },
      quarantined: [],
      pruned: 0,
      pending: 0,
    },
  });
  await stampless.scheduler.pullNow();
  await settle();
  check(
    "an unstamped tombstone keeps its etag out of the map",
    await stampless.settings.readEtags(),
    { "host:h-9": "e2" },
  );
  check(
    "and the good landing in the same set still landed",
    (await stampless.hosts.listHosts()).map((x) => x.id),
    ["h-9"],
  );
}

async function b15(): Promise<void> {
  console.log("\nB15 - a failed push loses its etag and keeps its dirty mark");
  // The worst shape: a local delete that must overwrite a live remote record.
  // If the failed slot keeps the etag the pull already recorded, the next pull
  // etag-skips the object AND skips the local tombstone with it - no
  // disposition, pending 0, and the delete never propagates.
  const h = harness({
    hosts: [host("h-1")],
    etags: { "host:h-1": "e0" },
    pull: {
      records: [merged(HOST_TOMBSTONE_KIND, "h-1", host("h-1"), { republish: true })],
      etags: { "host:h-1": "e1" },
      quarantined: [],
      pruned: 0,
      pending: 1,
    },
    push: { etags: {}, failed: [{ kind: "host", id: "h-1", reason: "the remote answered 500" }] },
  });
  await h.scheduler.pullNow();
  await settle();

  check("the failed slot is gone from the map", await h.settings.readEtags(), {});
  check("it is still owed, durably", await h.dirty(), ["host:h-1"]);
  check("and the failure is reported", (await h.status()).lastError, "the remote answered 500");
  // Pending counts what the remote is still missing AFTER the push, and the
  // push placed nothing.
  check("pending still counts it", (await h.status()).pending, 1);
}

async function b16(): Promise<void> {
  console.log("\nB16 - the dirty set survives a quit inside the debounce");
  const edit = harness({ hosts: [host("h-1")] });
  await edit.hosts.upsertHost(host("h-1", { name: "renamed" }));
  await settle();
  // Written at the mark, not at the flush: the debounce is five seconds, and a
  // quit inside it used to lose the edit outright with no error anywhere.
  check("the mark is durable before the debounce fires", await edit.dirty(), ["host:h-1"]);
  edit.scheduler.dispose();

  // What the next launch sees: a fresh scheduler, the same store file.
  const relaunch = harness({ hosts: [host("h-1", { name: "renamed" })], dirty: ["host:h-1"] });
  await relaunch.scheduler.pullNow();
  await settle();
  check(
    "and the next launch publishes it",
    relaunch.pushed[relaunch.pushed.length - 1]?.envelopes.map((e) => `${e.kind}:${e.id}`),
    ["host:h-1"],
  );
  check("then clears it", await relaunch.dirty(), []);
}

async function b17(): Promise<void> {
  console.log("\nB17 - two passes never interleave over the etag map");
  // The interleaving this guards: a pull reads the map, its apply refuses a
  // slot, the debounce fires a push that read the OLD map, the pull writes the
  // map without the refused slot, and the push writes it back in. After that
  // the refused object is etag-skipped forever.
  const h = harness({
    hosts: [host("h-1")],
    etags: { "host:h-bad": "e1" },
    park: true,
    pull: {
      records: [merged(HOST_TOMBSTONE_KIND, "h-bad", host("h-other"))],
      etags: { "host:h-bad": "e1" },
      quarantined: [],
      pruned: 0,
      pending: 0,
    },
  });
  const pulling = h.scheduler.pullNow();
  await settle();
  // Edit and fire the debounce while the pull is parked mid-flight. Five
  // seconds inside a LIST plus N GETs is not a stretch.
  await h.hosts.upsertGroup({ id: "g-1", name: "prod" });
  await h.fire();
  // THE PROPERTY, asserted directly rather than through its consequence: the
  // push has not started. An unserialized push would read the map here - still
  // holding the refused slot - and write it back after the pull removed it.
  check("a push fired mid-pull waits for it", h.calls.push, 0);

  h.release();
  await pulling;
  await settle();
  check("so the refused slot stays out of the map", await h.settings.readEtags(), {});
  check("and the push that waited still ran", h.calls.push, 1);
}

async function b18(): Promise<void> {
  console.log("\nB18 - a mark made during a flush is not eaten by it");
  // `[...dirty, ...(await readDirty())]` spreads the SET before the await is
  // evaluated, so a mark made while that read is in flight lands in neither the
  // snapshot nor the set afterwards - and the `writeDirty([])` that follows
  // puts an empty list over it on disk too. Gone from memory and disk both,
  // with no error and a pending count of zero.
  const h = harness({ hosts: [host("h-1"), host("h-2")], dirty: ["host:h-1"], parkDirty: true });
  const flushing = h.scheduler.pushNow();
  await settle();
  // The flush is parked inside its own `readDirty`. Edit now.
  await h.hosts.upsertHost(host("h-2", { name: "edited mid-flush" }));
  await settle();
  h.releaseDirty();
  await flushing;
  await settle();

  // NEITHER IS LOST. The mid-flush mark joins the one the last session left
  // behind, because the read that folds disk into memory is the SAME read the
  // flush is parked in - so the mark waits for it rather than racing it.
  check(
    "the flush publishes both the persisted mark and the mid-flush one",
    h.pushed[0]?.envelopes.map((e) => `${e.kind}:${e.id}`).sort(),
    ["host:h-1", "host:h-2"],
  );
  check("and nothing is left owed", await h.dirty(), []);
}

async function b19(): Promise<void> {
  console.log("\nB19 - one status write per pass, and the pull's error wins");
  // A pull that fails and a flush that succeeds used to produce two status
  // writes, the second of which put `null` over the first's error - so the
  // settings window reported "no error" on a pull that did not happen.
  const h = harness({ hosts: [host("h-1")], dirty: ["host:h-1"] });
  h.failPull("the remote answered 503");
  await h.scheduler.pullNow();
  await settle();
  check("the flush ran", h.calls.push, 1);
  check(
    "and the pull's error survived it",
    (await h.status()).lastError,
    "the remote answered 503",
  );

  // A FAILED PULL MUST NOT REPORT A HEALTHY RECONCILE. Fields initialized to
  // "nothing found" and written unconditionally make the settings window read
  // its healthiest - zero pending, nothing quarantined, last pull just now -
  // exactly when sync is broken. A run that succeeded FIRST and then failed is
  // the arrangement that can tell "left alone" from "written as empty".
  const after = harness({
    hosts: [host("h-1"), host("h-2")],
    pull: {
      records: [localOnly(HOST_TOMBSTONE_KIND, "h-2", true)],
      etags: {},
      quarantined: [{ name: "deadbeef", reason: "unreadable" }],
      pruned: 0,
      pending: 3,
    },
  });
  await after.scheduler.pullNow();
  await settle();
  const healthy = await after.status();
  check("a good pull records what it found", [healthy.pending, healthy.quarantine.length], [3, 1]);

  after.failPull("the remote answered 503");
  await after.scheduler.pullNow();
  await settle();
  const broken = await after.status();
  check(
    "a failed pull leaves those counts alone rather than zeroing them",
    [broken.pending, broken.quarantine.length, broken.stale.length],
    [3, 1, 1],
  );
  check("and does not stamp a fresh lastPullAt", broken.lastPullAt, healthy.lastPullAt);
  check("while reporting the failure", broken.lastError, "the remote answered 503");
}

async function main(): Promise<void> {
  await b1();
  await b2b3b4();
  await b5();
  await b6();
  await b7();
  await b8();
  await b9();
  await b10();
  await b11();
  await b12();
  await b13();
  await b14();
  await b15();
  await b16();
  await b17();
  await b18();
  await b19();

  // A pass that failed where no assertion could see it. Asserted last so the
  // group that produced it has already printed.
  check("nothing was swallowed into a log line", logged, []);

  if (failed > 0) throw new Error(`sync-scheduler-verify: ${failed} FAILED`);
  console.log("\nsync-scheduler-verify: OK\n");
}

await main();
