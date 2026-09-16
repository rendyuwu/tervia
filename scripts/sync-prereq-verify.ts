/**
 * Self-check for the two things a last-write-wins merge cannot be built without:
 * every synced record able to say WHEN it changed, and every delete leaving
 * something behind. Run: `npx tsx scripts/sync-prereq-verify.ts`.
 *
 * One suite for three stores rather than three additions to three suites,
 * because this is ONE shape repeated: in `modules/hosts`, `modules/vault` and
 * `modules/forwards` every mutator a user reaches stamps `updatedAt` from its
 * own store's clock, and each files a tombstone in the same key through the same
 * helpers in `src/lib/tombstones.ts`. The one writer that does NOT stamp is
 * `applyRemote`, which lands another device's record at the remote's timestamp;
 * nothing here exercises it, and `sync-apply-verify.ts` is where it is pinned.
 * There is no vault store suite to extend in any case - `createVaultStore` is
 * only built inside suites that declare a different subject.
 *
 * Every property here fails SILENTLY, which is why they are pinned before any
 * sync code exists:
 *
 * 1. THE STORE STAMPS, NOT THE CALLER, in every mutator below. An editor
 *    round-trips the record it
 *    loaded, so a store that honoured a caller-supplied `updatedAt` would carry
 *    the OLD stamp forward on every save and a real edit would never win a
 *    merge. Every stamp check here feeds a deliberately wrong value in, because
 *    handing the previous record back cannot tell "the store stamped" from "the
 *    store echoed its caller".
 *
 * 2. ABSENT IS NOT ZERO. A record written before this field existed has no
 *    stamp, and backfilling one on read would have every legacy record claim it
 *    changed just now and win every merge it takes part in. A read must also
 *    cost no commit, or the first launch after an upgrade rewrites the file.
 *
 * 3. A DELETE LEAVES EXACTLY ONE TOMBSTONE, IN ONE COMMIT. Two commits leave a
 *    window where the record is gone and nothing records that it was deleted,
 *    and a device pulling into that window pushes the record straight back. The
 *    commit COUNT is the only thing that sees this, which is why it is asserted
 *    rather than the end state.
 *
 * 4. A DELETE OF SOMETHING THAT WAS NOT THERE PUBLISHES NOTHING. On another
 *    device a spurious tombstone is indistinguishable from a real delete.
 *    `deleteRule` and `dropRulesForHost` needed a new guard to hold this; the
 *    other four already returned early.
 *
 * 5. AN UPSERT THAT CLEARS NO TOMBSTONE DOES NOT WRITE THE KEY AT ALL. Every key
 *    a write `set`s is a key a contended save can write over a stale baseline,
 *    so the tombstones key must not ride along on a write that changes nothing
 *    there.
 *
 * 6. PRUNING IS FILTER-ON-READ PLUS PRUNE-ON-WRITE. There is no load pass, so
 *    both surfaces are checked: the helper directly at its boundary, and the
 *    store's own `listTombstones`, which takes no argument and can only be
 *    reached through a seeded file plus the injected clock.
 *
 * THE CLOCK IS INJECTED, and that is not harness convenience. Two awaited writes
 * against in-memory ports routinely land in the same millisecond, so "a second
 * write produces a later stamp" driven by the real clock would be a check that
 * fails at random rather than one that fails when the stamp is wrong. The
 * 89-day and 91-day cases need the same control.
 *
 * THE FAKE STORE BUFFERS `set`, which is the one thing NOT to copy from the
 * other suites in this directory. They all write `async set(key, value) {
 * data[key] = value }`, but `createFileKeyValueStore` in
 * `src/lib/fileKeyValueStore.ts` only fills a pending map and the `commit` is
 * what folds it onto disk. The sections that depend on it are the ones that ask
 * WHAT A COMMIT CARRIED - the one-commit checks and the clobber checks - because
 * the answer is `Object.keys(pending)` at commit time and there is no such
 * question to ask of a fake that assigns straight into its data map. The pruning
 * section leans on it too, since it asserts on committed data rather than on a
 * return value.
 *
 * What buffering does NOT buy, so nobody adds a check expecting it: `get` reads
 * pending over committed, exactly as the real store does, so a tombstone that
 * was `set` and never committed reads back as present under either shape. The
 * tombstone-presence sections are insensitive to this, and the commit COUNT is
 * too - it moves inside `commit` either way.
 */
import { createWriteQueue, type RecoveredStoreIo } from "../src/lib/recoveredStore";
import {
  livingTombstones,
  TOMBSTONES_KEY,
  TOMBSTONE_TTL_MS,
  type Tombstone,
} from "../src/lib/tombstones";
import { createForwardStore, type HostLookup } from "../src/modules/forwards/store";
import { FORWARDS_KEY, RULE_TOMBSTONE_KIND, type ForwardRule } from "../src/modules/forwards/types";
import { createHostsStore, noForwardRules } from "../src/modules/hosts/store";
import {
  GROUP_TOMBSTONE_KIND,
  HOSTS_KEY,
  HOST_GROUPS_KEY,
  HOST_TOMBSTONE_KIND,
  type Host,
  type HostGroup,
  type SshHost,
} from "../src/modules/hosts/types";
import type { SecretsIo } from "../src/modules/vault/adapters";
import { createVaultStore } from "../src/modules/vault/store";
import {
  IDENTITY_TOMBSTONE_KIND,
  KEY_TOMBSTONE_KIND,
  VAULT_IDENTITIES_KEY,
  VAULT_KEYS_KEY,
  type IdentityHostRefs,
  type VaultIdentity,
  type VaultKey,
} from "../src/modules/vault/types";

let failed = 0;
function check(label: string, got: unknown, want: unknown): void {
  // `JSON.stringify` answers `undefined` for an absent value, which is exactly
  // the answer several checks here are about, so the two are compared as text.
  const found = JSON.stringify(got) ?? String(got);
  const wanted = JSON.stringify(want) ?? String(want);
  if (found === wanted) {
    console.log(`  ok: ${label}`);
  } else {
    console.error(`  FAIL: ${label} = ${found}, want ${wanted}`);
    failed++;
  }
}

const DAY_MS = 24 * 60 * 60 * 1000;
/** Far enough from the epoch that a 91-day-old `deletedAt` is still positive. */
const START = 1_800_000_000_000;

// ---------------------------------------------------------------------------
// In-memory ports. The REAL write queue (`createWriteQueue`), so every check
// below exercises the shipped serialization rather than a copy of it living in
// this file.
// ---------------------------------------------------------------------------

type Port = {
  store: RecoveredStoreIo;
  /** What has been COMMITTED. A pending `set` is deliberately not here. */
  data: Record<string, unknown>;
  commits: () => number;
  /** The keys each commit actually carried, in order. Without this, "the
   *  tombstones key was absent from this commit" is unreachable: `data` retains
   *  it from any earlier delete in the same fixture. */
  keyLog: () => string[][];
};

function port(seed: Record<string, unknown>): Port {
  const data: Record<string, unknown> = { ...seed };
  let pending: Record<string, unknown> = {};
  const keyLog: string[][] = [];
  const listeners = new Set<() => void>();
  let commits = 0;

  const store: RecoveredStoreIo = {
    async get<T>(key: string): Promise<T | null> {
      // Pending over committed, exactly as the real store reads.
      return ((key in pending ? pending[key] : data[key]) as T | undefined) ?? null;
    },
    async set(key: string, value: unknown): Promise<void> {
      pending[key] = value;
    },
    async commit(): Promise<void> {
      keyLog.push(Object.keys(pending));
      Object.assign(data, pending);
      pending = {};
      commits++;
      for (const l of listeners) l();
    },
    enqueueWrite: createWriteQueue(),
    async onChanged(cb: () => void): Promise<() => void> {
      listeners.add(cb);
      return () => void listeners.delete(cb);
    },
    ensureLoaded: async () => null,
    takeRecoveryNotice: () => null,
    // Nothing here drives the anti-blank guard in `modules/workspaces/store.ts`,
    // which is the only caller: a good file is the honest answer for a fixture
    // with no file behind it at all.
    fileState: async () => ({ found: "ok" as const, recovered: false }),
  };

  return { store, data, commits: () => commits, keyLog: () => keyLog };
}

/** No secret in this suite is ever read back, so the keychain port only has to
 *  exist. `hosts-store-verify.ts` is where the flags themselves are pinned. */
const secrets: SecretsIo = {
  async getAll(_service: string, accounts: string[]) {
    return accounts.map(() => null);
  },
  async set() {},
  async delete() {},
  async copy() {
    return false;
  },
};

const noHolders: IdentityHostRefs = async () => [];

function harness(
  seed: {
    hosts?: Host[];
    groups?: HostGroup[];
    hostGraves?: Tombstone[];
    identities?: VaultIdentity[];
    vaultKeys?: VaultKey[];
    vaultGraves?: Tombstone[];
    rules?: ForwardRule[];
    ruleGraves?: Tombstone[];
    /** A clock that moves on EVERY read, so a mutator that reads it twice stamps
     *  two different instants. The only way to see that at all: against the
     *  frozen clock every other section uses, one read and two are identical. */
    ticking?: boolean;
  } = {},
) {
  let clock = START;
  const now = () => (seed.ticking ? clock++ : clock);

  const hostsPort = port({
    [HOSTS_KEY]: seed.hosts ?? [],
    [HOST_GROUPS_KEY]: seed.groups ?? [],
    ...(seed.hostGraves ? { [TOMBSTONES_KEY]: seed.hostGraves } : {}),
  });
  const vaultPort = port({
    [VAULT_IDENTITIES_KEY]: seed.identities ?? [],
    [VAULT_KEYS_KEY]: seed.vaultKeys ?? [],
    ...(seed.vaultGraves ? { [TOMBSTONES_KEY]: seed.vaultGraves } : {}),
  });
  const forwardsPort = port({
    [FORWARDS_KEY]: seed.rules ?? [],
    ...(seed.ruleGraves ? { [TOMBSTONES_KEY]: seed.ruleGraves } : {}),
  });

  return {
    hosts: createHostsStore({ store: hostsPort.store, secrets, now }),
    vault: createVaultStore({ store: vaultPort.store, secrets, now }),
    forwards: createForwardStore({ store: forwardsPort.store, now }),
    hostsPort,
    vaultPort,
    forwardsPort,
    advance(ms: number): void {
      clock += ms;
    },
    at: (): number => clock,
  };
}

// Every fixture carries a deliberately WRONG `updatedAt`, so no stamp check can
// pass by the store handing its caller's value straight back.
const WRONG = 1;

const host = (over: Partial<SshHost> = {}): SshHost => ({
  id: "h-1",
  name: "bastion",
  host: "10.0.0.1",
  port: 22,
  protocol: "ssh",
  credential: { kind: "identity", identityId: "i-1" },
  updatedAt: WRONG,
  ...over,
});

const group = (over: Partial<HostGroup> = {}): HostGroup => ({
  id: "g-1",
  name: "prod",
  updatedAt: WRONG,
  ...over,
});

const identity = (over: Partial<VaultIdentity> = {}): VaultIdentity => ({
  id: "i-1",
  name: "root @ prod",
  username: "root",
  authMode: "password",
  hasPassword: false,
  updatedAt: WRONG,
  ...over,
});

const vaultKey = (over: Partial<VaultKey> = {}): VaultKey => ({
  id: "k-1",
  name: "id_ed25519",
  hasPrivateKey: false,
  hasPassphrase: false,
  updatedAt: WRONG,
  ...over,
});

const rule = (over: Partial<ForwardRule> = {}): ForwardRule => ({
  id: "f-1",
  name: "web tunnel",
  hostId: "h-1",
  localPort: 8080,
  remoteHost: "127.0.0.1",
  remotePort: 80,
  startWithHost: false,
  updatedAt: WRONG,
  ...over,
});

/** The forwards store's required host lookup. Always answers with an SSH host,
 *  since nothing here is about the reference guard. */
const anySshHost: HostLookup = async (hostId) => host({ id: hostId });

const graves = (p: Port): Tombstone[] => (p.data[TOMBSTONES_KEY] as Tombstone[] | undefined) ?? [];
const lastKeys = (p: Port): string[] => p.keyLog()[p.keyLog().length - 1] ?? [];

// ---------------------------------------------------------------------------
// 1. Every mutator stamps `updatedAt` from the store's own clock
// ---------------------------------------------------------------------------
{
  console.log("\n[stamps] every mutator a user reaches stamps updatedAt, overwriting the caller");
  const h = harness();

  const saved = await h.hosts.upsertHost(host());
  check("upsertHost returns the store's stamp, not the caller's", saved.updatedAt, h.at());
  check("upsertHost persists it", (await h.hosts.listHosts())[0].updatedAt, h.at());

  const savedGroup = await h.hosts.upsertGroup(group());
  check("upsertGroup returns the store's stamp", savedGroup.updatedAt, h.at());
  check("upsertGroup persists it", (await h.hosts.listGroups())[0].updatedAt, h.at());

  // A copy is a brand new record, so it takes the clock at the moment it was
  // made - not the source's stamp, which the spread would otherwise carry over.
  h.advance(1000);
  const copy = await h.hosts.duplicateHost("h-1");
  check("duplicateHost stamps the copy at the copy's own moment", copy?.updatedAt, h.at());

  const id = await h.vault.upsertIdentity(identity(), {});
  check("upsertIdentity returns the store's stamp", id.record.updatedAt, h.at());
  check("upsertIdentity persists it", (await h.vault.listIdentities())[0].updatedAt, h.at());

  // The flag is fed in WRONG, so this discriminates: no secret is written, so
  // `writeKeySecrets` computes `false`, and a stamp spread over `key` rather than
  // over what that function returned would hand the caller's `true` straight
  // back.
  const k = await h.vault.upsertKey(vaultKey({ hasPrivateKey: true }), {});
  check("upsertKey returns the store's stamp", k.record.updatedAt, h.at());
  check("upsertKey persists it", (await h.vault.listKeys())[0].updatedAt, h.at());
  check(
    "upsertKey stamps what writeKeySecrets returned, flags and all",
    k.record.hasPrivateKey,
    false,
  );

  const r = await h.forwards.upsertRule(rule(), anySshHost);
  check("upsertRule returns the store's stamp", r.updatedAt, h.at());
  check("upsertRule persists it", (await h.forwards.listRules())[0].updatedAt, h.at());
}

// ---------------------------------------------------------------------------
// 2. A second write advances the stamp
// ---------------------------------------------------------------------------
{
  console.log("\n[stamps] a second write of the same record takes the advanced clock");
  const h = harness();
  await h.hosts.upsertHost(host());
  await h.hosts.upsertGroup(group());
  await h.vault.upsertIdentity(identity(), {});
  await h.vault.upsertKey(vaultKey(), {});
  await h.forwards.upsertRule(rule(), anySshHost);
  const first = h.at();

  h.advance(5000);
  // Round-tripping the STORED record, which is what an editor does: the value
  // being fed back in is now the store's own previous stamp rather than `WRONG`,
  // and it must still be overwritten.
  const again = await h.hosts.upsertHost((await h.hosts.listHosts())[0]);
  check("upsertHost bumps the stamp", again.updatedAt, h.at());
  check("and the advanced stamp is not the first one", again.updatedAt === first, false);

  const groupAgain = await h.hosts.upsertGroup((await h.hosts.listGroups())[0]);
  check("upsertGroup bumps the stamp", groupAgain.updatedAt, h.at());
  const idAgain = await h.vault.upsertIdentity((await h.vault.listIdentities())[0], {});
  check("upsertIdentity bumps the stamp", idAgain.record.updatedAt, h.at());
  const keyAgain = await h.vault.upsertKey((await h.vault.listKeys())[0], {});
  check("upsertKey bumps the stamp", keyAgain.record.updatedAt, h.at());
  const ruleAgain = await h.forwards.upsertRule((await h.forwards.listRules())[0], anySshHost);
  check("upsertRule bumps the stamp", ruleAgain.updatedAt, h.at());
}

// ---------------------------------------------------------------------------
// 3. A record written before the field existed comes back WITHOUT one
// ---------------------------------------------------------------------------
{
  console.log("\n[legacy] a record with no updatedAt keeps none, and reading costs no commit");
  // Through JSON, so these are files a previous build could really have written
  // rather than objects with the key deleted by hand.
  const legacy = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;
  const h = harness({
    hosts: [legacy({ ...host(), updatedAt: undefined })],
    groups: [legacy({ ...group(), updatedAt: undefined })],
    identities: [legacy({ ...identity(), updatedAt: undefined })],
    vaultKeys: [legacy({ ...vaultKey(), updatedAt: undefined })],
    rules: [legacy({ ...rule(), updatedAt: undefined })],
  });

  check("host has no updatedAt", "updatedAt" in (await h.hosts.listHosts())[0], false);
  check("group has no updatedAt", "updatedAt" in (await h.hosts.listGroups())[0], false);
  check("identity has no updatedAt", "updatedAt" in (await h.vault.listIdentities())[0], false);
  check("key has no updatedAt", "updatedAt" in (await h.vault.listKeys())[0], false);
  check("rule has no updatedAt", "updatedAt" in (await h.forwards.listRules())[0], false);

  check("reading the hosts file rewrites nothing", h.hostsPort.commits(), 0);
  check("reading the vault file rewrites nothing", h.vaultPort.commits(), 0);
  check("reading the forwards file rewrites nothing", h.forwardsPort.commits(), 0);
}

// ---------------------------------------------------------------------------
// 4. Every delete leaves exactly one tombstone, with the right kind
// ---------------------------------------------------------------------------
{
  console.log("\n[tombstones] each delete leaves one tombstone naming what it dropped");

  const deleted = harness({ hosts: [host()] });
  await deleted.hosts.deleteHost("h-1", noForwardRules);
  check("deleteHost", await deleted.hosts.listTombstones(), [
    { id: "h-1", kind: HOST_TOMBSTONE_KIND, deletedAt: deleted.at() },
  ]);

  const grouped = harness({ groups: [group()] });
  await grouped.hosts.deleteGroup("g-1");
  check("deleteGroup", await grouped.hosts.listTombstones(), [
    { id: "g-1", kind: GROUP_TOMBSTONE_KIND, deletedAt: grouped.at() },
  ]);

  const ident = harness({ identities: [identity()] });
  await ident.vault.deleteIdentity("i-1", noHolders);
  check("deleteIdentity", await ident.vault.listTombstones(), [
    { id: "i-1", kind: IDENTITY_TOMBSTONE_KIND, deletedAt: ident.at() },
  ]);

  const keyed = harness({ vaultKeys: [vaultKey()] });
  await keyed.vault.deleteKey("k-1");
  check("deleteKey", await keyed.vault.listTombstones(), [
    { id: "k-1", kind: KEY_TOMBSTONE_KIND, deletedAt: keyed.at() },
  ]);

  const ruled = harness({ rules: [rule()] });
  await ruled.forwards.deleteRule("f-1");
  check("deleteRule", await ruled.forwards.listTombstones(), [
    { id: "f-1", kind: RULE_TOMBSTONE_KIND, deletedAt: ruled.at() },
  ]);

  // One per RULE dropped, never one for the host: what this call deletes is
  // rules, and the host's own tombstone belongs to the hosts store.
  const swept = harness({
    rules: [rule(), rule({ id: "f-2" }), rule({ id: "f-3", hostId: "h-other" })],
  });
  await swept.forwards.dropRulesForHost("h-1");
  check(
    "dropRulesForHost leaves one tombstone per rule dropped",
    await swept.forwards.listTombstones(),
    [
      { id: "f-1", kind: RULE_TOMBSTONE_KIND, deletedAt: swept.at() },
      { id: "f-2", kind: RULE_TOMBSTONE_KIND, deletedAt: swept.at() },
    ],
  );
  check(
    "and the rule riding another host survives",
    (await swept.forwards.listRules()).map((r) => r.id),
    ["f-3"],
  );

  // A host with no rules is NOT the "id not in the store" case - a rules store
  // holds no host ids at all - so it needs its own check.
  const bare = harness({ rules: [rule({ id: "f-9", hostId: "h-other" })] });
  await bare.forwards.dropRulesForHost("h-1");
  check(
    "dropRulesForHost over a host with no rules leaves none",
    await bare.forwards.listTombstones(),
    [],
  );
  check("and costs no commit", bare.forwardsPort.commits(), 0);
}

// ---------------------------------------------------------------------------
// 5. A delete of an id that is not there publishes nothing
// ---------------------------------------------------------------------------
{
  console.log("\n[tombstones] a delete of an absent id mints no tombstone and costs no commit");
  const h = harness();

  await h.hosts.deleteHost("h-nope", noForwardRules);
  await h.hosts.deleteGroup("g-nope");
  check("hosts store: no tombstone", await h.hosts.listTombstones(), []);
  check("hosts store: no commit", h.hostsPort.commits(), 0);

  await h.vault.deleteIdentity("i-nope", noHolders);
  await h.vault.deleteKey("k-nope");
  check("vault store: no tombstone", await h.vault.listTombstones(), []);
  check("vault store: no commit", h.vaultPort.commits(), 0);

  await h.forwards.deleteRule("f-nope");
  await h.forwards.dropRulesForHost("h-nope");
  check("forwards store: no tombstone", await h.forwards.listTombstones(), []);
  check("forwards store: no commit", h.forwardsPort.commits(), 0);
}

// ---------------------------------------------------------------------------
// 6. The record and its tombstone land in ONE commit
// ---------------------------------------------------------------------------
{
  console.log("\n[atomicity] a delete drops the record and files the tombstone in one commit");

  const h = harness({
    hosts: [host()],
    groups: [group()],
    identities: [identity()],
    vaultKeys: [vaultKey()],
    rules: [rule(), rule({ id: "f-2" })],
  });

  await h.hosts.deleteHost("h-1", noForwardRules);
  check("deleteHost costs one commit", h.hostsPort.commits(), 1);
  check(
    "carrying both keys",
    [...lastKeys(h.hostsPort)].sort(),
    [HOSTS_KEY, TOMBSTONES_KEY].sort(),
  );

  await h.hosts.deleteGroup("g-1");
  check("deleteGroup costs one more commit", h.hostsPort.commits(), 2);
  check(
    "carrying all three keys",
    [...lastKeys(h.hostsPort)].sort(),
    [HOST_GROUPS_KEY, HOSTS_KEY, TOMBSTONES_KEY].sort(),
  );

  await h.vault.deleteIdentity("i-1", noHolders);
  check("deleteIdentity costs one commit", h.vaultPort.commits(), 1);
  check(
    "carrying both keys",
    [...lastKeys(h.vaultPort)].sort(),
    [TOMBSTONES_KEY, VAULT_IDENTITIES_KEY].sort(),
  );

  await h.vault.deleteKey("k-1");
  check("deleteKey costs one more commit", h.vaultPort.commits(), 2);
  check(
    "carrying both keys",
    [...lastKeys(h.vaultPort)].sort(),
    [TOMBSTONES_KEY, VAULT_KEYS_KEY].sort(),
  );

  await h.forwards.deleteRule("f-1");
  check("deleteRule costs one commit", h.forwardsPort.commits(), 1);
  check(
    "carrying both keys",
    [...lastKeys(h.forwardsPort)].sort(),
    [FORWARDS_KEY, TOMBSTONES_KEY].sort(),
  );

  await h.forwards.dropRulesForHost("h-1");
  check("dropRulesForHost costs one more commit", h.forwardsPort.commits(), 2);
  check(
    "carrying both keys",
    [...lastKeys(h.forwardsPort)].sort(),
    [FORWARDS_KEY, TOMBSTONES_KEY].sort(),
  );
}

// ---------------------------------------------------------------------------
// 7. `deleteGroup` bumps the members it rewrites, and only those
// ---------------------------------------------------------------------------
{
  console.log("\n[cascade] deleteGroup stamps the members whose groupId it cleared");
  const h = harness();
  await h.hosts.upsertGroup(group());
  await h.hosts.upsertHost(host({ id: "h-member", groupId: "g-1" }));
  await h.hosts.upsertHost(host({ id: "h-loner" }));
  const before = h.at();

  h.advance(7000);
  await h.hosts.deleteGroup("g-1");
  const hosts = await h.hosts.listHosts();
  const member = hosts.find((x) => x.id === "h-member");
  const loner = hosts.find((x) => x.id === "h-loner");

  check("the member's groupId is cleared", member?.groupId, undefined);
  check("and its updatedAt moves with the clear", member?.updatedAt, h.at());
  check("the non-member is left exactly as it was", loner?.updatedAt, before);
}

// ---------------------------------------------------------------------------
// 8. Pruning, at both surfaces
// ---------------------------------------------------------------------------
{
  console.log("\n[pruning] the 90-day window, through the helper and through a store");

  const at = (days: number): Tombstone => ({
    id: `t-${days}`,
    kind: HOST_TOMBSTONE_KIND,
    deletedAt: START - days * DAY_MS,
  });

  check(
    "livingTombstones keeps 89 days and drops 91",
    livingTombstones([at(89), at(91)], START).map((t) => t.id),
    ["t-89"],
  );
  check(
    "and the window is the constant, not a number spelled twice",
    livingTombstones([{ id: "edge", kind: "host", deletedAt: START - TOMBSTONE_TTL_MS }], START),
    [],
  );
  check(
    "a file holding something that is not a list reads as empty",
    livingTombstones("nonsense"),
    [],
  );
  check(
    "and a row missing deletedAt is dropped rather than read as the epoch",
    livingTombstones([{ id: "x", kind: "host" }], START),
    [],
  );

  // `listTombstones` takes no argument, so the only way to reach its filter is a
  // seeded file plus the injected clock.
  const seeded = harness({ hostGraves: [at(89), at(91)] });
  check(
    "listTombstones filters on read",
    (await seeded.hosts.listTombstones()).map((t) => t.id),
    ["t-89"],
  );
  check("and reading does not rewrite the file", seeded.hostsPort.commits(), 0);

  // Prune-on-write: the delete was happening anyway, so the expired row goes
  // with it. Asserted on what was COMMITTED, not on a return value.
  const swept = harness({ hosts: [host()], hostGraves: [at(89), at(91)] });
  await swept.hosts.deleteHost("h-1", noForwardRules);
  check(
    "a tombstone write persists the filtered list",
    graves(swept.hostsPort).map((t) => t.id),
    ["t-89", "h-1"],
  );

  // The upsert path, for the case where a named id DID match: the same write
  // that clears one tombstone also drops the expired one.
  const restored = harness({ hosts: [], hostGraves: [at(89), at(91)] });
  await restored.hosts.upsertHost(host({ id: "t-89" }));
  check(
    "an upsert that clears a tombstone persists the filtered list too",
    graves(restored.hostsPort).map((t) => t.id),
    [],
  );
}

// ---------------------------------------------------------------------------
// 9. Resurrection: an upsert clears the tombstone naming its id
// ---------------------------------------------------------------------------
{
  console.log("\n[resurrection] an upsert of a deleted id clears its tombstone");
  const h = harness({
    hosts: [host()],
    groups: [group()],
    identities: [identity()],
    vaultKeys: [vaultKey()],
    rules: [rule()],
  });

  await h.hosts.deleteHost("h-1", noForwardRules);
  await h.hosts.deleteGroup("g-1");
  await h.vault.deleteIdentity("i-1", noHolders);
  await h.vault.deleteKey("k-1");
  await h.forwards.deleteRule("f-1");

  h.advance(1000);
  await h.hosts.upsertHost(host());
  await h.hosts.upsertGroup(group());
  await h.vault.upsertIdentity(identity(), {});
  await h.vault.upsertKey(vaultKey(), {});
  await h.forwards.upsertRule(rule(), anySshHost);

  check("the hosts store names neither id", await h.hosts.listTombstones(), []);
  check("the vault store names neither id", await h.vault.listTombstones(), []);
  check("the forwards store names none", await h.forwards.listTombstones(), []);
}

// ---------------------------------------------------------------------------
// 10. An upsert that clears nothing does not write the tombstones key
// ---------------------------------------------------------------------------
{
  console.log("\n[clobber] an upsert clearing no tombstone leaves the key out of its commit");

  // With an UNRELATED tombstone expired in EVERY store, which is the case that
  // used to rewrite the key anyway. Seeded in all three, not just the hosts one:
  // against an absent key the check still catches an unconditional `set`, but it
  // cannot catch "an expiry forces the write", which is the half that matters.
  // Asserted against the per-commit key log rather than `data`, which still holds
  // the key from the delete below.
  const expired = (id: string, kind: string): Tombstone[] => [
    { id, kind, deletedAt: START - 91 * DAY_MS },
  ];
  const h = harness({
    hostGraves: expired("t-old", HOST_TOMBSTONE_KIND),
    vaultGraves: expired("i-old", IDENTITY_TOMBSTONE_KIND),
    ruleGraves: expired("f-old", RULE_TOMBSTONE_KIND),
  });

  await h.hosts.upsertHost(host());
  check("upsertHost carries the record list alone", lastKeys(h.hostsPort), [HOSTS_KEY]);
  await h.hosts.upsertGroup(group());
  check("upsertGroup carries the group list alone", lastKeys(h.hostsPort), [HOST_GROUPS_KEY]);

  await h.vault.upsertIdentity(identity(), {});
  check("upsertIdentity carries the identity list alone", lastKeys(h.vaultPort), [
    VAULT_IDENTITIES_KEY,
  ]);
  await h.vault.upsertKey(vaultKey(), {});
  check("upsertKey carries the key list alone", lastKeys(h.vaultPort), [VAULT_KEYS_KEY]);

  await h.forwards.upsertRule(rule(), anySshHost);
  check("upsertRule carries the rule list alone", lastKeys(h.forwardsPort), [FORWARDS_KEY]);

  // And the key IS carried once there is something to clear, so the check above
  // is not passing because nothing ever writes it.
  await h.hosts.deleteHost("h-1", noForwardRules);
  await h.hosts.upsertHost(host());
  check(
    "but an upsert that does clear one carries it",
    [...lastKeys(h.hostsPort)].sort(),
    [HOSTS_KEY, TOMBSTONES_KEY].sort(),
  );
}

// ---------------------------------------------------------------------------
// 11. A connect and a pin are not content changes
// ---------------------------------------------------------------------------
{
  console.log("\n[per-machine] markConnected and pinFingerprint leave updatedAt alone");
  const h = harness();
  await h.hosts.upsertHost(host());
  const stamped = h.at();

  h.advance(9000);
  await h.hosts.markConnected("h-1", "SHA256:aaa");
  check("markConnected leaves the stamp", (await h.hosts.listHosts())[0].updatedAt, stamped);

  await h.hosts.pinFingerprint("h-1", "SHA256:bbb");
  check("pinFingerprint leaves the stamp", (await h.hosts.listHosts())[0].updatedAt, stamped);
  check(
    "and the pin really was recorded, so the check above is not vacuous",
    (await h.hosts.listHosts())[0].pins?.["10.0.0.1"],
    "SHA256:bbb",
  );
}

// ---------------------------------------------------------------------------
// 12. Stamps that describe ONE operation are one instant
// ---------------------------------------------------------------------------
{
  console.log("\n[one-clock] a mutator reads its clock once, so its stamps do not drift");
  // Against a TICKING clock, which is the only thing that can see this: every
  // other section freezes the clock, and against a frozen one a mutator that
  // called `now()` twice is indistinguishable from one that called it once. In
  // production those two reads are two real instants, and two stamps that are
  // meant to describe the same operation would disagree.
  const h = harness({
    ticking: true,
    groups: [group()],
    hosts: [host({ groupId: "g-1" })],
    rules: [rule(), rule({ id: "f-2" })],
  });

  await h.hosts.deleteGroup("g-1");
  const groupGrave = (await h.hosts.listTombstones())[0];
  const member = (await h.hosts.listHosts())[0];
  check(
    "deleteGroup's tombstone and its member bump are the same instant",
    {
      same: groupGrave.deletedAt === member.updatedAt,
    },
    { same: true },
  );

  await h.forwards.dropRulesForHost("h-1");
  const ruleGraves = await h.forwards.listTombstones();
  check(
    "dropRulesForHost stamps every rule it drops at one instant",
    {
      count: ruleGraves.length,
      same: ruleGraves[0].deletedAt === ruleGraves[1].deletedAt,
    },
    { count: 2, same: true },
  );
}

if (failed > 0) throw new Error(`sync-prereq-verify: ${failed} FAILED`);
console.log("\nsync-prereq-verify: OK\n");
