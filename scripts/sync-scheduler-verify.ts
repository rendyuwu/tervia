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
 * WHICH IS WHY THE NUMBERING BELOW SKIPS C5, rather than a check having been
 * deleted. C5 is the purge that removes key bodies already published, and the
 * purge is Rust: it is a pass over the stored objects in
 * `src-tauri/src/modules/sync/engine.rs` and it is checked by `cargo test`
 * there, for the same reason the merge is. Nothing in this file could assert it
 * without faking the provider it walks.
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
 *
 * 9. A CARRY TOGGLE THAT WORKS IN ONE DIRECTION ONLY. Off has to stop a body
 *    leaving AND stop one arriving, and the outbound half is asserted as a
 *    MEASURED ZERO on a counting keychain fake - a port left absent would make
 *    that zero a property of the harness. The inbound mirror is worse than
 *    silent: an envelope with no `secrets` read as "delete the body" destroys a
 *    private key the user still holds, on an ordinary background pull.
 *
 * 10. A CORRECTION THAT RUNS ON EVERY LANDING. Re-deriving a key record the
 *     merge understated costs one keychain read, one store write and one
 *     republish; doing it for a record that was already complete costs those
 *     three PER PULL, forever, and nothing local looks wrong while it happens.
 *
 * TWO CHECKS READ SOURCE TEXT, AND THAT IS THE ONLY READING AVAILABLE. There is
 * no DOM in this suite - every `scripts/*-verify.ts` runs under plain `tsx`, and
 * nothing in `devDependencies` can render a component - so a claim about what
 * the sync tab SHOWS is made the way `scripts/hosts-header-narrow-verify.ts`
 * makes its own: anchored regex against the actual source of
 * `src/settings/sections/SyncSection.tsx`, with comments stripped first. The
 * stripping is load bearing rather than tidy: that file argues in its comments
 * about the very wording one of these checks requires to be ABSENT.
 */
/// <reference types="node" />
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import type { FileKeyValueStore } from "../src/lib/fileKeyValueStore";
import { createWriteQueue, type RecoveredStoreIo } from "../src/lib/recoveredStore";
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
  EMPTY_SYNC_STATUS,
  SYNC_CONFIG_KEY,
  SYNC_DIRTY_KEY,
  SYNC_ETAGS_KEY,
  SYNC_STATUS_KEY,
  WIRE_VERSION,
  namesTheSameRemote,
  type Envelope,
  type PullReport,
  type PushReport,
  type Reconciled,
  type SyncCommands,
  type SyncStatus,
} from "../src/modules/sync/types";
import type { SecretsIo } from "../src/modules/vault/adapters";
import type { KeyInspectResult } from "../src/modules/vault/keyInspect";
import { createVaultStore } from "../src/modules/vault/store";
import {
  IDENTITY_TOMBSTONE_KIND,
  KEY_PRIVATE_KEY_FIELD,
  KEY_TOMBSTONE_KIND,
  VAULT_IDENTITIES_KEY,
  VAULT_KEYRING_SERVICE,
  VAULT_KEYS_KEY,
  VAULT_KEY_SECRET_FIELDS,
  vaultAccount,
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

/**
 * The sync settings file, WITH THE CACHE THE REAL ONE HOLDS.
 *
 * NOT A STRAIGHT-THROUGH MAP, and the difference is the whole of C10. The real
 * store keeps a per-webview copy of the file, serves reads out of it, and builds
 * every `save` payload from that copy plus this session's pending keys - so a
 * cache filled before the settings window wrote is how this webview comes to put
 * an older configuration back over the user's, permanently, with nothing to see
 * until the pass after. A straight-through map cannot express that at all: it
 * has nothing to go stale, so a check driving it would pass whether or not the
 * cache was ever dropped.
 *
 * `file` is what a second webview writes to, behind this one's back. Handed back
 * so a check can play the settings window and then read what actually landed,
 * rather than counting calls and calling that an ordering.
 *
 * Every operation is also marked, `invalidate` included, so the sweep in C10 can
 * ask the narrower question the two behavioural halves cannot: that no method
 * AT ALL skips the drop, including the ones no scenario here drives. One mark
 * per operation, so "the drop came immediately before" is a question about
 * adjacent entries. `writeEtags` is a second, narrower mark that B10's ordering
 * check keys on, and it is emitted after the operation's own.
 */
function settingsPort(seed: Record<string, unknown>) {
  const file: Record<string, unknown> = { ...seed };
  let cache: Record<string, unknown> = {};
  let pending: Record<string, unknown> = {};
  let loaded = false;
  function load(): void {
    if (loaded) return;
    cache = { ...file };
    loaded = true;
  }
  const io: FileKeyValueStore = {
    async get<T>(key: string): Promise<T | null> {
      mark("settings:get");
      if (key in pending) return (pending[key] as T | undefined) ?? null;
      load();
      return (cache[key] as T | undefined) ?? null;
    },
    async set(key: string, value: unknown): Promise<void> {
      pending[key] = value;
    },
    async save(): Promise<void> {
      mark("settings:save");
      if (SYNC_ETAGS_KEY in pending) mark("writeEtags");
      // READ WHOLE, WRITTEN WHOLE, from the cache plus what this session set.
      // A key the other window added that this cache never saw is not in the
      // payload, so it is gone - which is the loss, stated as code.
      load();
      const payload = { ...cache, ...pending };
      for (const key of Object.keys(file)) delete file[key];
      Object.assign(file, payload);
      Object.assign(cache, pending);
      pending = {};
    },
    invalidate(): void {
      mark("invalidate");
      loaded = false;
      cache = {};
    },
  };
  return { io, file };
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
    /** One report per pull, in order, for a check that needs two consecutive
     *  passes to differ. Falls through to `pull` once the list is spent. */
    pulls?: PullReport[];
    push?: PushReport;
    dirty?: string[];
    status?: SyncStatus;
    park?: boolean;
    parkDirty?: boolean;
    releaseThrows?: boolean;
    carrySecrets?: boolean;
    /** The vault store's keychain. Defaults to one that holds nothing. */
    secrets?: SecretsIo;
    readKeySecrets?: (id: string) => Promise<Record<string, string>>;
    inspectKey?: (body: string, passphrase?: string) => Promise<KeyInspectResult>;
    correctKey?: (key: VaultKey) => Promise<void>;
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
    [SYNC_CONFIG_KEY]: {
      ...DEFAULT_SYNC_CONFIG,
      enabled: seed.enabled ?? true,
      carrySecrets: seed.carrySecrets ?? false,
    },
    [SYNC_ETAGS_KEY]: seed.etags ?? {},
    ...(seed.dirty ? { [SYNC_DIRTY_KEY]: seed.dirty } : {}),
    ...(seed.status ? { [SYNC_STATUS_KEY]: seed.status } : {}),
  });
  // A `readDirty` that can be parked mid-flight, which is the only way to
  // construct a mark made DURING a flush - the window the spread order in
  // `runPush` decides.
  let releaseDirty = (): void => {};
  const dirtyParked = new Promise<void>((r) => {
    releaseDirty = r;
  });
  const base = createSyncSettingsStore(settingsData.io);
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
  /** The same for the push command. A per-record `failed` entry is the other
   *  shape and B15 covers it; this one is the endpoint being gone, which is
   *  what a mid-session outage actually looks like. */
  let failPush: string | null = null;
  const calls = { pull: 0, push: 0 };
  const pulled: { envelopes: Envelope[]; etags: Record<string, string> }[] = [];
  const pushed: { envelopes: Envelope[]; etags: Record<string, string> }[] = [];
  const commands: SyncCommands = {
    async pull(envelopes, etags) {
      calls.pull++;
      pulled.push({ envelopes, etags });
      if (seed.park) await parked;
      if (failPull) throw new Error(failPull);
      return (
        seed.pulls?.shift() ??
        seed.pull ?? { records: [], etags: {}, quarantined: [], pruned: 0, pending: 0 }
      );
    },
    async push(envelopes, etags) {
      calls.push++;
      pushed.push({ envelopes, etags });
      if (failPush) throw new Error(failPush);
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
    secrets: seed.secrets ?? noSecrets,
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
    readKeySecrets: seed.readKeySecrets,
    inspectKey: seed.inspectKey,
    correctKey: seed.correctKey,
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
    failPush: (reason: string | null): void => {
      failPush = reason;
    },
    settings,
    /** The bytes on disk, for a check that has to play the other webview. */
    settingsFile: settingsData.file,
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
  over: {
    changed?: boolean;
    secretsChanged?: boolean;
    republish?: boolean;
    secrets?: Record<string, string>;
  } = {},
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
      ...(over.secrets ? { secrets: over.secrets } : {}),
    },
    changed: over.changed ?? true,
    secretsChanged: over.secretsChanged ?? false,
    republish: over.republish ?? false,
  };
}

/** `secrets` is the carried key body, absent unless a check is about one - which
 *  is the ordinary case, since only a key envelope ever has one. */
function remoteOnly(
  kind: string,
  id: string,
  record: unknown,
  secrets?: Record<string, string>,
): Reconciled {
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
      ...(secrets ? { secrets } : {}),
    },
  };
}

const localOnly = (kind: string, id: string, stale: boolean): Reconciled => ({
  kind,
  id,
  outcome: "localOnly",
  stale,
});

/** One pull report carrying `records` and nothing else: no etags, nothing
 *  quarantined, nothing pruned, nothing pending. */
const reportOf = (records: Reconciled[]): PullReport => ({
  records,
  etags: {},
  quarantined: [],
  pruned: 0,
  pending: 0,
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
  // `null` rather than an index straight into the record: with no envelope to
  // read, the cast fed `undefined` to a subscript and the whole run died on a
  // TypeError - taking every later check with it, so a regression that stopped
  // pushes reported one crash instead of its own failures. Reported as a miss
  // instead, which fails this line loudly and lets the rest of the suite speak.
  const carried = (edit.pushed[0]?.envelopes[0]?.record ?? null) as Record<string, unknown> | null;
  check(
    "B4: and no device-local field rides with it",
    carried && DEVICE_LOCAL_FIELDS.filter((f) => carried[f] !== undefined),
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

  // ACROSS A RELAUNCH TOO. "The last thing this device actually learned" is a
  // claim about the DEVICE, so a fresh session that fails its first pull -
  // launching offline is exactly that - must not write an empty status over
  // what the previous session found.
  const relaunched = harness({ status: { ...broken } });
  relaunched.failPull("still offline");
  await relaunched.scheduler.pullNow();
  await settle();
  const carried = await relaunched.status();
  check(
    "a new session's failed first pull keeps the last session's counts",
    [carried.pending, carried.quarantine.length, carried.lastPullAt],
    [broken.pending, broken.quarantine.length, broken.lastPullAt],
  );
  check("and reports its own failure", carried.lastError, "still offline");
}

/** The sync tab's source, which two checks below read instead of rendering. */
const SYNC_SECTION = "src/settings/sections/SyncSection.tsx";

/**
 * `source` with its block comments and its whole-line `//` comments gone.
 *
 * SHARED BY C1 AND C4, and load bearing for both directions. C1 asserts that a
 * phrasing is ABSENT from what the user reads, and the file's own comments argue
 * at length about why it is absent - so an unstripped scan would fail on the
 * paragraph explaining the property. C4 asserts that markup is PRESENT, and an
 * unstripped scan would be satisfied by a comment describing markup nobody
 * wrote.
 *
 * Only whole-line `//` is stripped, so a `//` inside a string literal survives.
 */
function withoutComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^[ \t]*\/\/.*$/gm, "");
}

async function b20(): Promise<void> {
  console.log("\nB20 - the pending count is a floor, and an outage cannot read zero");
  // D2 from the cross-device sync hand test: the server was stopped mid-session, two records
  // were edited, and "Waiting to be pushed" read 0 throughout - because the
  // number is the RECONCILE's, which is what the remote was missing as of the
  // last SUCCESSFUL pull, and a failed pull leaves it alone by design. The
  // dirty set is the half that holds unpushed local edits, and it was never in
  // the number.

  // A. A pull that fails and a push that fails, which is one dead endpoint.
  const outage = harness({ hosts: [host("h-1"), host("h-2")] });
  outage.failPull("the remote could not be reached");
  outage.failPush("the remote could not be reached");
  await outage.hosts.upsertHost(host("h-1", { name: "edited in the dark" }));
  await outage.hosts.upsertHost(host("h-2", { name: "edited too" }));
  await settle();
  await outage.scheduler.pullNow();
  await settle();
  const dark = await outage.status();
  check("the two edits are still owed", (await outage.dirty()).sort(), ["host:h-1", "host:h-2"]);
  check("and the count says so rather than zero", dark.pending, 2);
  check("it reaches the store file", (await outage.settings.readStatus()).pending, 2);
  check("with the outage still reported", dark.lastError, "the remote could not be reached");

  // B. THE DEBOUNCED PUSH ALONE, with no pull anywhere near it. Both entry
  // points that reach `runPush` drop its returned string, so a flush into a
  // dead endpoint used to write no status at all - the settings window sat on
  // the last pull's healthy figures until a focus cleared the rate limit.
  const flush = harness({ hosts: [host("h-1")] });
  flush.failPush("the remote answered 503");
  await flush.hosts.upsertHost(host("h-1", { name: "renamed" }));
  await settle();
  check("nothing has been written yet", (await flush.status()).lastError, null);
  await flush.fire();
  const flushed = await flush.status();
  check("the failed flush reports itself", flushed.lastError, "the remote answered 503");
  check("and its edit is counted", flushed.pending, 1);

  // C. THE OTHER DIRECTION, or the floor is a ratchet: a reconcile figure that
  // no push can lower leaves the window reporting work that is done.
  const settled = harness({
    hosts: [host("h-1")],
    status: { ...EMPTY_SYNC_STATUS, pending: 1 },
  });
  await settled.hosts.upsertHost(host("h-1", { name: "renamed" }));
  await settle();
  await settled.fire();
  check("a push that lands clears the count", (await settled.status()).pending, 0);
  check("and nothing is left owed", await settled.dirty(), []);
}

async function c1(): Promise<void> {
  console.log("\nC1 - the conditional-write warning is about the setting, not a probe");
  const source = readFileSync(resolve(ROOT, SYNC_SECTION), "utf8");
  // THE GATING EXPRESSION, not the string. A warning that exists somewhere in
  // the file and is never reached from the toggle is the same as no warning, and
  // a check that searched the whole file for the sentence would pass on one.
  const block = /\{!config\.cas \? \(([\s\S]*?)\n\s*\) : null\}/.exec(source);
  check("the warning is reached from the cas toggle being off", block !== null, true);
  // Comments out, then tags out: what is left is what a reader sees.
  const warning = withoutComments(block?.[1] ?? "")
    .replace(/<[^>]*>/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  // ANTI-VACUITY for the absence below, which passes for free against the empty
  // string a failed match leaves: the block has to have been found AND still say
  // whose choice the fact came from.
  check("and it names the setting as the user's own choice", /which you chose/.test(warning), true);
  // THE PROPERTY. Nothing in the app probes the endpoint, so a warning phrased
  // as a finding would be a claim no code backs - and a check asserting only
  // that the sentence is present would pass against exactly that warning.
  check(
    "and no phrasing claims this device tested the endpoint",
    warning.match(/detect|probe|does not support|doesn't support|we found|unsupported/gi) ?? [],
    [],
  );
}

/**
 * A private key body, as a fixture. Inert everywhere: nothing here parses one.
 *
 * NO TRAILING NEWLINE, unlike a real PEM file, because `landKeySecrets` in
 * `src/modules/vault/store.ts` trims what it lands - so a fixture carrying one
 * would make C3's round trip assert that trim rather than the carry it is about.
 */
const KEY_BODY = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjE";

async function c2(): Promise<void> {
  console.log("\nC2 - with the carry toggle off, no key body leaves the machine");
  const key = (): VaultKey => ({
    id: "k-1",
    name: "id_ed25519",
    hasPrivateKey: true,
    hasPassphrase: false,
    updatedAt: START - 1000,
  });
  const slot = `${KEY_TOMBSTONE_KIND}:k-1`;

  let offReads = 0;
  const off = harness({
    vaultKeys: [key()],
    dirty: [slot],
    carrySecrets: false,
    // A REAL FAKE, present and counting. Leaving the port off would make the
    // zero below a property of this harness rather than of the toggle - which is
    // the whole failure the measured-zero rule exists for.
    readKeySecrets: async () => {
      offReads++;
      return { [KEY_PRIVATE_KEY_FIELD]: KEY_BODY };
    },
  });
  await off.scheduler.pushNow();
  await settle();
  check("off: the keychain is not read at all", offReads, 0);
  check(
    "off: and no envelope carries a body",
    off.pushed[0]?.envelopes.filter((e) => e.secrets !== undefined).map((e) => e.id),
    [],
  );

  // ANTI-VACUITY, REQUIRED: without this arm the check above passes in a tree
  // where carrying was deleted outright rather than gated.
  let onReads = 0;
  const on = harness({
    vaultKeys: [key()],
    dirty: [slot],
    carrySecrets: true,
    readKeySecrets: async () => {
      onReads++;
      return { [KEY_PRIVATE_KEY_FIELD]: KEY_BODY };
    },
  });
  await on.scheduler.pushNow();
  await settle();
  check("on: the keychain is read, once for the one key", onReads, 1);
  check(
    "on: and the key's envelope carries the body",
    on.pushed[0]?.envelopes.find((e) => e.kind === KEY_TOMBSTONE_KIND)?.secrets,
    { [KEY_PRIVATE_KEY_FIELD]: KEY_BODY },
  );
}

/** A keychain that holds what it is given and records every write, so "nothing
 *  was written" and "nothing was deleted" are both measurable. */
function recordingSecrets(seed: Record<string, string> = {}) {
  const held: Record<string, string> = { ...seed };
  const sets: { service: string; account: string; value: string }[] = [];
  const deletes: { service: string; account: string }[] = [];
  const io: SecretsIo = {
    async getAll(_service, accounts) {
      return accounts.map((a) => held[a] ?? null);
    },
    async set(service, account, value) {
      sets.push({ service, account, value });
      held[account] = value;
    },
    async delete(service, account) {
      deletes.push({ service, account });
      delete held[account];
    },
    async copy() {
      return false;
    },
  };
  return { io, sets, deletes };
}

async function c3(): Promise<void> {
  console.log("\nC3 - the inbound body: carried, refused, and absent");
  const landedKey = (over: Partial<VaultKey> = {}): VaultKey => ({
    id: "k-1",
    name: "id_ed25519",
    hasPrivateKey: false,
    hasPassphrase: false,
    ...over,
  });
  const account = vaultAccount("k-1", KEY_PRIVATE_KEY_FIELD);
  const mine = new Set<string>(VAULT_KEY_SECRET_FIELDS.map((f) => vaultAccount("k-1", f)));
  const arriving = (secrets?: Record<string, string>): PullReport => ({
    records: [remoteOnly(KEY_TOMBSTONE_KIND, "k-1", landedKey(), secrets)],
    etags: {},
    quarantined: [],
    pruned: 0,
    pending: 0,
  });

  // 1. CARRY ON, A BODY ARRIVES. The whole point of the toggle being on.
  const on = recordingSecrets();
  const carried = harness({
    carrySecrets: true,
    secrets: on.io,
    pull: arriving({ [KEY_PRIVATE_KEY_FIELD]: KEY_BODY }),
  });
  await carried.scheduler.pullNow();
  await settle();
  check("on: the body is written at this key's private-key account", on.sets, [
    { service: VAULT_KEYRING_SERVICE, account, value: KEY_BODY },
  ]);
  check(
    "on: and the stored record now claims one",
    (await carried.vault.listKeys()).find((k) => k.id === "k-1")?.hasPrivateKey,
    true,
  );

  // 2. CARRY OFF, THE SAME BODY ARRIVES. ONE TOGGLE, BOTH DIRECTIONS: a device
  // that opted out of publishing bodies has equally opted out of receiving them,
  // and the drop happens before the store is handed the landing at all.
  const off = recordingSecrets();
  const refused = harness({
    carrySecrets: false,
    secrets: off.io,
    pull: arriving({ [KEY_PRIVATE_KEY_FIELD]: KEY_BODY }),
  });
  await refused.scheduler.pullNow();
  await settle();
  check(
    "off: nothing is written to this key's accounts",
    off.sets.filter((s) => mine.has(s.account)),
    [],
  );

  // 3. CARRY ON, NO BODY ARRIVES, A LOCAL BODY EXISTS. An absent `secrets` is no
  // information and must never read as "delete the body": a device that carries
  // nothing wins an ordinary merge with `secrets` unset, so the delete reading
  // would destroy a private key the user still holds on a background pull. This
  // is why the check has three cases and not one.
  const kept = recordingSecrets({ [account]: KEY_BODY });
  const quiet = harness({
    carrySecrets: true,
    secrets: kept.io,
    vaultKeys: [landedKey({ hasPrivateKey: true, updatedAt: START - 1000 })],
    pull: {
      records: [
        merged(KEY_TOMBSTONE_KIND, "k-1", landedKey({ hasPrivateKey: true, name: "renamed" })),
      ],
      etags: {},
      quarantined: [],
      pruned: 0,
      pending: 0,
    },
  });
  await quiet.scheduler.pullNow();
  await settle();
  check(
    "absent: no delete reaches this key's accounts",
    kept.deletes.filter((d) => mine.has(d.account)),
    [],
  );
  check(
    "absent: and the body is still readable afterwards",
    (await kept.io.getAll(VAULT_KEYRING_SERVICE, [account]))[0],
    KEY_BODY,
  );
}

async function c4(): Promise<void> {
  console.log("\nC4 - the stale list, and the control that settles it");
  const source = withoutComments(readFileSync(resolve(ROOT, SYNC_SECTION), "utf8"));
  // ANCHORED ON JSX AND IDENTIFIER SYNTAX over comment-stripped source, never a
  // substring search for a word: "stale" appears in this file's prose, and a
  // check a comment can satisfy is a check that survives the markup being
  // deleted.
  check("the section is still the component", /export function SyncSection\(\)/.test(source), true);
  check(
    "the stale list is rendered off the status it loaded",
    /\{status\.stale\.length > 0 \? \(/.test(source),
    true,
  );
  check("one row per entry", /\{status\.stale\.map\(\(s\) => \(/.test(source), true);
  // THE LOOKBEHIND IS THE CHECK. Each row's `key` prop is a template literal
  // holding both fields, so a pattern without it is satisfied by React
  // bookkeeping the user never sees - measured: deleting the rendered kind left
  // the naive pattern green.
  check(
    "each carrying its kind and its id, rendered rather than keyed",
    [/(?<!\$)\{s\.kind\}/.test(source), /(?<!\$)\{s\.id\}/.test(source)],
    [true, true],
  );

  // AND THE RESOLUTION PATH, PINNED TO THE LIST THAT NEEDS IT. A stale list with
  // nothing that settles it is a report the user cannot act on.
  //
  // THE CONTROL IS NOT INSIDE THE BLOCK, so this cannot anchor on markup there:
  // the block names a control that lives in the group above it. What is pinned
  // instead is the pairing that DOES exist - the label the block tells the user
  // to press, and the button carrying exactly that label and the handler. Those
  // two drifting apart is the real failure: an instruction naming a control
  // nobody can find reads as a bug in the sync itself. An assertion that merely
  // found the handler somewhere in the file would pass in a tree where the list
  // rendered with no route out of it at all, which is what this replaced.
  const block = /\{status\.stale\.length > 0 \? \(([\s\S]*?)\n\s*\) : null\}/.exec(source);
  check("the stale block is there to read", block !== null, true);
  check(
    "and it names the two things that settle it",
    /edit one to send it to the remote again, or\s+delete it here/.test(block?.[1] ?? ""),
    true,
  );
  // AND DOES NOT PROMISE THE ONE THING THAT DOES NOT WORK. A stale record is
  // exactly what the pull declines to publish, so telling the user to press
  // Pull now sends them round a loop that cannot end - the instruction this
  // replaced, and the reason D1 read as the remote's fault.
  check(
    "without telling the user a pull republishes them",
    /Pull now/.test(block?.[1] ?? ""),
    false,
  );
  check(
    "a request is emitted as the sync event",
    /void emit\(SYNC_REQUEST_EVENT, what\)/.test(source),
    true,
  );
  check(
    "and the control under that exact label asks for the pass",
    /onClick=\{\(\) => request\("pull"\)\}\s*>\s*Pull now\s*</.test(source),
    true,
  );
}

/** What a body that parsed says about itself. */
const PARSED: KeyInspectResult = {
  parsed: true,
  encrypted: false,
  keyType: "ed25519",
  fingerprint: "SHA256:from-the-inspector",
  publicKey: "ssh-ed25519 AAAA",
  comment: null,
};

/**
 * What a SEALED CONTAINER says: nothing at all.
 *
 * A legacy PEM or PuTTY body cannot be inspected without its passphrase, and
 * `vaultKeyFactsFrom` answers `encrypted` alone for it - so `fingerprint` stays
 * undefined for such a key forever. That is the whole reason C7 and C8 exist:
 * every guard keyed on a fingerprint being present can never fire here.
 */
const SEALED: KeyInspectResult = {
  parsed: false,
  encrypted: true,
  keyType: null,
  fingerprint: null,
  publicKey: null,
  comment: null,
};

/**
 * A body that PARSED and still answered no fingerprint and no public half.
 *
 * THE SHAPE THAT CAN ERASE, and it is NOT the sealed one. `vaultKeyFactsFrom`
 * short-circuits for a container it could not open and answers `encrypted`
 * alone, so spreading THAT wholesale overwrites nothing and a check built on it
 * proves nothing. For a body it did open, the two fields come back as explicit
 * `undefined` properties when they were empty - and a spread writes those
 * straight over a fingerprint the record already held. Measured: C8 passed
 * against the wholesale spread until this fixture replaced the sealed one.
 */
const PARSED_BLANK: KeyInspectResult = {
  parsed: true,
  encrypted: false,
  keyType: "ed25519",
  fingerprint: null,
  publicKey: null,
  comment: null,
};

/**
 * A scheduler whose key ports are fakes that record what they were asked.
 *
 * A FAKE INSPECTOR, never the real bridge: the derivation is a registered
 * command, nothing in TypeScript computes a fingerprint, and the module holding
 * that command imports a Tauri surface at the top level. Shared by C6, C7 and
 * C8, which differ only in what the inspector answers and what the pulls land.
 */
function correcting(pulls: PullReport[], answer: KeyInspectResult, stored?: VaultKey[]) {
  const inspected: string[] = [];
  const corrected: VaultKey[] = [];
  const h = harness({
    pulls,
    ...(stored ? { vaultKeys: stored } : {}),
    readKeySecrets: async () => ({ [KEY_PRIVATE_KEY_FIELD]: KEY_BODY }),
    inspectKey: async (body) => {
      inspected.push(body);
      return answer;
    },
    correctKey: async (key) => {
      corrected.push(key);
    },
  });
  return { h, inspected, corrected };
}

/** A key record as a landing hands it over, understated by default. */
const keyRecord = (over: Partial<VaultKey> = {}): VaultKey => ({
  id: "k-1",
  name: "id_ed25519",
  hasPrivateKey: false,
  hasPassphrase: false,
  ...over,
});

/** One pull landing one key record. */
const landsKey = (record: VaultKey): PullReport =>
  reportOf([remoteOnly(KEY_TOMBSTONE_KIND, "k-1", record)]);

async function c6(): Promise<void> {
  console.log("\nC6 - a landed key record is corrected from the local body");

  // A. The merge drops a fingerprint whenever the winner claims no private key,
  // so the device that HOLDS the body is the only place the truth exists.
  const understated = correcting([landsKey(keyRecord())], PARSED);
  await understated.h.scheduler.pullNow();
  await settle();
  check("A: the inspector is handed the stored body", understated.inspected, [KEY_BODY]);
  check(
    "A: and the correction carries the body and the inspector's fingerprint",
    understated.corrected.map((k) => [k.hasPrivateKey, k.fingerprint]),
    [[true, PARSED.fingerprint]],
  );

  // B, ANTI-VACUITY AND REQUIRED: without it, a correction that ran on every
  // landing - a keychain read, a store write and a republish per pull, forever -
  // would pass A and be invisible everywhere else.
  const complete = correcting(
    [landsKey(keyRecord({ hasPrivateKey: true, fingerprint: "SHA256:already-known" }))],
    PARSED,
  );
  await complete.h.scheduler.pullNow();
  await settle();
  check("B: a landing that needs nothing inspects nothing", complete.inspected, []);
  check("B: and corrects nothing", complete.corrected.length, 0);
}

async function c7(): Promise<void> {
  console.log("\nC7 - a body that cannot be inspected still settles after one correction");
  // TWO CONSECUTIVE PULLS, and the second is the check. A sealed container
  // leaves `fingerprint` undefined forever, so the guard keyed on it can never
  // fire for this key - the only thing that stops a second correction is the
  // comparison of the corrected record against the stored one. `correctKey`
  // stamps `updatedAt` and marks the record dirty unconditionally, and the Rust
  // record includes that stamp, so two devices both holding a sealed body would
  // land each other's restamp and restamp back: one vault write, one snapshot
  // and one remote object per pull, per device, for the life of the record.
  //
  // ANTI-VACUITY: one pull alone passes against the broken code, which is why
  // this check is two. The second pull lands the record in the state the FIRST
  // correction produces - the shape a peer's restamp arrives in - so the pass
  // cannot be saved by the landing looking incomplete.
  const sealed = correcting(
    [landsKey(keyRecord()), landsKey(keyRecord({ hasPrivateKey: true, encrypted: true }))],
    SEALED,
  );
  await sealed.h.scheduler.pullNow();
  await settle();
  check("the first pull corrects the record once", sealed.corrected.length, 1);
  check(
    "carrying the body it found and the one fact the inspection could answer",
    sealed.corrected.map((k) => [k.hasPrivateKey, k.encrypted, k.fingerprint ?? null]),
    [[true, true, null]],
  );

  await sealed.h.scheduler.pullNow();
  await settle();
  // THE WHOLE CHECK. The inspection runs again - nothing skips it - and the
  // correction does not, because there is nothing left to say.
  check("and the second pull corrects nothing more", sealed.corrected.length, 1);
  check("though it did look again", sealed.inspected.length, 2);
}

async function c8(): Promise<void> {
  console.log("\nC8 - a correction never erases what the record already knew");
  const known = keyRecord({
    fingerprint: "SHA256:already-on-the-record",
    publicKey: "ssh-ed25519 ALREADY",
  });

  // An inspection that opened the body and still answered neither field hands
  // back two explicit `undefined` properties, and spreading them wholesale
  // blanks a fingerprint and a public half that were perfectly good - on a
  // record the correction was only ever meant to ADD a presence flag to.
  const blank = correcting([landsKey(known)], PARSED_BLANK);
  await blank.h.scheduler.pullNow();
  await settle();
  check(
    "an answer with neither field leaves the stored fingerprint and public half alone",
    blank.corrected.map((k) => [k.fingerprint ?? null, k.publicKey ?? null]),
    [["SHA256:already-on-the-record", "ssh-ed25519 ALREADY"]],
  );

  // ANTI-VACUITY, REQUIRED: a correction that copied NOTHING would pass the
  // check above. An inspection that really answered has to land, fingerprint
  // included, and the answer here disagrees with the record on purpose.
  const answered = correcting([landsKey(known)], PARSED);
  await answered.h.scheduler.pullNow();
  await settle();
  check(
    "and a real answer replaces both",
    answered.corrected.map((k) => [k.fingerprint ?? null, k.publicKey ?? null]),
    [[PARSED.fingerprint, PARSED.publicKey]],
  );
}

async function c9(): Promise<void> {
  console.log("\nC9 - a carry-off device lands nothing for a body it would discard");
  // THE SHAPE C3 CANNOT REACH. `ordering_key` in
  // `src-tauri/src/modules/sync/model.rs` includes `secrets`, and an absent one
  // sorts below a present one - so a device with carrying off gets
  // `secretsChanged: true` against every remote object that DOES carry a body,
  // on every pull, forever. That is not an exotic fleet: it is what this app's
  // own settings produce the moment one device turns carrying off. A `merged`
  // disposition is required here, because C3's `remoteOnly` never reaches the
  // expression this is about, which is exactly why the defect survived it.
  const landing = (): PullReport =>
    reportOf([
      merged(KEY_TOMBSTONE_KIND, "k-1", keyRecord({ hasPrivateKey: true }), {
        changed: false,
        secretsChanged: true,
        secrets: { [KEY_PRIVATE_KEY_FIELD]: KEY_BODY },
      }),
    ]);

  const off = recordingSecrets();
  const discarding = harness({
    carrySecrets: false,
    secrets: off.io,
    vaultKeys: [keyRecord({ hasPrivateKey: true, updatedAt: START - 1000 })],
    pull: landing(),
  });
  const before = trace.length;
  await discarding.scheduler.pullNow();
  await settle();
  // ON THE COMMIT COUNT, not on the record. The record would be written back
  // identical, so a content assertion could not tell a write from no write -
  // and the cost being guarded is the write itself: the whole vault file
  // rewritten and a fresh snapshot taken, on every pull, forever.
  check(
    "off: the vault store is not written at all",
    trace.slice(before).filter((t) => t.endsWith("commit:vault")).length,
    0,
  );

  // ANTI-VACUITY, REQUIRED: the same disposition with carrying ON must land,
  // and must reach the keychain. Otherwise a tree that dropped every merged
  // body would pass the arm above.
  const on = recordingSecrets();
  const accepting = harness({
    carrySecrets: true,
    secrets: on.io,
    vaultKeys: [keyRecord({ hasPrivateKey: true, updatedAt: START - 1000 })],
    pull: landing(),
  });
  const at = trace.length;
  await accepting.scheduler.pullNow();
  await settle();
  check(
    "on: the same landing is applied",
    trace.slice(at).filter((t) => t.endsWith("commit:vault")).length,
    1,
  );
  check("on: and the body reaches the keychain", on.sets, [
    {
      service: VAULT_KEYRING_SERVICE,
      account: vaultAccount("k-1", KEY_PRIVATE_KEY_FIELD),
      value: KEY_BODY,
    },
  ]);
}

async function c10(): Promise<void> {
  console.log("\nC10 - the two cross-webview guards");
  // THE SETTINGS FILE IS WRITTEN BY TWO WEBVIEWS and nothing broadcasts a change
  // event for it, so a cached copy is frozen at whatever the file said when this
  // one last read it. Both halves below are OBSERVABLE IN WHAT LANDS, against a
  // port that models the real cache - not counted off a call log, which would
  // pass against a drop made at the wrong moment.
  //
  // MEASURED RATHER THAN READ OFF THE SOURCE, because the drop has already moved
  // once: it was two calls at the top of the two passes and is now one wrapper
  // inside the settings store, so an assertion naming either call site would pin
  // a shape instead of the property.

  // THE READ HALF. The settings window stores a configuration after this webview
  // has cached the file. Without the drop the cached copy answers forever: the
  // user turns sync on, gets a confirmation, and gets no sync until they
  // relaunch. The first pass is what fills the cache, so it is part of the
  // arrangement rather than a warm-up.
  const reading = harness({ enabled: false });
  await reading.scheduler.pullNow();
  await settle();
  check("a pass with sync off invokes nothing, and caches the file", reading.calls.pull, 0);
  reading.settingsFile[SYNC_CONFIG_KEY] = { ...DEFAULT_SYNC_CONFIG, enabled: true };
  await reading.scheduler.pullNow();
  await settle();
  check("and the next pass reads what the settings window stored", reading.calls.pull, 1);

  // THE WRITE HALF, which is the one that loses data and the one no source-text
  // check could see. Every `save` writes the whole map built from this webview's
  // cache, so a cache filled before the user pressed Save carries that older
  // configuration back over theirs - silently, permanently, and invisible until
  // the pass after.
  const writing = harness({ hosts: [host("h-1")] });
  await writing.scheduler.pullNow();
  await settle();
  const saved = { ...DEFAULT_SYNC_CONFIG, enabled: true, bucket: "the one the user typed" };
  writing.settingsFile[SYNC_CONFIG_KEY] = saved;
  // An edit and its flush: the dirty set, the etag map and the status are three
  // writes through the same wrapper, and any one of them carrying a stale
  // baseline is enough to lose the configuration.
  await writing.hosts.upsertHost(host("h-1", { name: "renamed" }));
  await writing.fire();
  check(
    "a pass's own writes do not carry a stale configuration back over the user's",
    writing.settingsFile[SYNC_CONFIG_KEY],
    saved,
  );
  // ANTI-VACUITY for the arm above: the writes have to have actually happened,
  // or "the configuration survived" is a statement about a pass that did nothing.
  check("while still writing what it owed", writing.calls.push, 1);

  // AND THE SWEEP, which is the narrower question the two halves cannot ask:
  // that NO method skips the drop, including the ones neither scenario drives.
  // The store's own reason for being one wrapper rather than a line per body is
  // that a method added later cannot be the one that forgets - this is that
  // claim, asserted.
  const pass = async (run: (h: ReturnType<typeof harness>) => Promise<void>) => {
    const h = harness({ hosts: [host("h-1")], dirty: [`${HOST_TOMBSTONE_KIND}:h-1`] });
    const before = trace.length;
    await run(h);
    await settle();
    const marks = trace.slice(before).map((t) => t.split(" ")[1]);
    return {
      operations: marks.filter((m) => m.startsWith("settings:")).length,
      unpaired: marks.filter((m, i) => m.startsWith("settings:") && marks[i - 1] !== "invalidate"),
    };
  };

  // ANTI-VACUITY for both arms: a pass that performed no settings operation at
  // all would have an empty unpaired list and say nothing.
  const pulled = await pass((h) => h.scheduler.pullNow());
  check("a pull touches the settings file", pulled.operations > 0, true);
  check("and every operation in it drops the cache first", pulled.unpaired, []);

  const pushed = await pass((h) => h.scheduler.pushNow());
  check("a push touches the settings file", pushed.operations > 0, true);
  check("and every operation in it drops the cache first", pushed.unpaired, []);

  // THE SECOND GUARD, as source text: `src/modules/sync/index.ts` imports a
  // Tauri surface at the top level, so this suite cannot load it. The settings
  // window invokes `sync_disable` itself, which empties the session in the Rust
  // process while this module's memo still names it - so switching sync off and
  // back on, which is the remedy a user reaches for, would otherwise leave every
  // later pull answering that nothing is configured for the life of the process.
  const index = withoutComments(readFileSync(resolve(ROOT, "src/modules/sync/index.ts"), "utf8"));
  const listener = /listen<SyncRequest>\(SYNC_REQUEST_EVENT, \(e\) => \{([\s\S]*?)\n {2}\}\)/.exec(
    index,
  );
  check("the sync-request listener is there to read", listener !== null, true);
  check(
    "and it drops the memo of what the session was opened with",
    /openedWith = null;/.test(listener?.[1] ?? ""),
    true,
  );
}

async function c11(): Promise<void> {
  console.log("\nC11 - a different remote is a different etag map");
  // The map is keyed `kind:id`, not by object name, so it survives a change of
  // provider or prefix and reads as current against a remote that has never
  // held any of those objects - see `namesTheSameRemote`.
  const at = (over: Partial<typeof DEFAULT_SYNC_CONFIG>) => ({ ...DEFAULT_SYNC_CONFIG, ...over });
  const s3 = at({ provider: "s3", endpoint: "http://one:9000", bucket: "b", prefix: "p" });
  check("the same four fields are the same remote", namesTheSameRemote(s3, { ...s3 }), true);
  check(
    "and region, cas and the carry toggle are not part of the address",
    namesTheSameRemote(s3, { ...s3, region: "eu-west-1", cas: true, carrySecrets: true }),
    true,
  );
  for (const [field, value] of [
    ["provider", "webdav"],
    ["endpoint", "http://two:9000"],
    ["bucket", "other"],
    ["prefix", "dav1"],
  ] as const) {
    check(
      `a new ${field} is a new remote`,
      namesTheSameRemote(s3, { ...s3, [field]: value }),
      false,
    );
  }

  // AND THE SETTINGS WINDOW ACTS ON IT, before it stores the configuration that
  // renames the remote: the pull that Save requests must not be able to start
  // on the old map.
  const source = withoutComments(readFileSync(resolve(ROOT, SYNC_SECTION), "utf8"));
  check(
    "the map is emptied under the guard, before the new address is stored",
    /namesTheSameRemote\([\s\S]*?\)\s*\)\s*\{\s*await settings\.writeEtags\(\{\}\);\s*\}\s*await settings\.writeConfig\(config\);/.test(
      source,
    ),
    true,
  );
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
  await b20();
  await c1();
  await c2();
  await c3();
  await c4();
  await c6();
  await c7();
  await c8();
  await c9();
  await c10();
  await c11();

  // A pass that failed where no assertion could see it. Asserted last so the
  // group that produced it has already printed.
  check("nothing was swallowed into a log line", logged, []);

  if (failed > 0) throw new Error(`sync-scheduler-verify: ${failed} FAILED`);
  console.log("\nsync-scheduler-verify: OK\n");
}

await main();
