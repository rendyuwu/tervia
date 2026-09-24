/**
 * Self-check for the apply path: the one writer in each store that does not
 * originate what it writes, and the record-level dirty mark every other writer
 * now leaves behind. Run: `npx tsx scripts/sync-apply-verify.ts`.
 *
 * One suite for three stores, on the same grounds as `sync-prereq-verify.ts`:
 * this is ONE shape repeated, and the three `applyRemote` implementations differ
 * only in which arrays they own and which accounts a delete releases.
 *
 * What fails silently without these:
 *
 * 1. A LANDING STAMPED FROM THE LOCAL CLOCK. Every other mutator overwrites the
 *    caller's `updatedAt`, which is right for an editor round-tripping the
 *    record it loaded. Here it inverts the merge: the pulled copy outranks the
 *    copy it came from, and the two devices push at each other forever. Every
 *    stamp check below feeds a timestamp DELIBERATELY OLDER than the injected
 *    clock, because a landing stamped locally and a landing stamped correctly
 *    are indistinguishable when the fixture's stamp is the current time.
 *
 * 2. A LANDING THAT ERASES THE DEVICE-LOCAL FIELDS. The publishing side strips
 *    `pins`, the flat fingerprint and `lastConnectedAt`, so a wholesale write
 *    does not stale them, it DELETES this device's trust pins - and the next
 *    connect asks a first-connect question it already has the answer to. The
 *    fixture carries none of the four, which is what the wire guarantees.
 *
 * 3. A TOMBSTONE LANDING THAT STRANDS A SECRET. A body at an account whose
 *    record is gone is named by nothing on this machine, so the only thing that
 *    reaches it again is the Vault page's unreferenced-entry sweep - a screen the
 *    user has to visit, not a release. Three fixtures, not one: hosts, vault keys
 *    and vault identities all fan out a delete, and covering only the first would
 *    leave the two that hold private key material unproven.
 *
 * 4. A REFUSAL THAT THROWS. Every apply runs as ONE queued write, so a throw
 *    from the middle of the loop loses every other landing in the set - the good
 *    ones included. Each bad landing below is followed by a good one in the same
 *    set, which is the only arrangement that can tell "refused" from "aborted".
 *
 * 5. A WRITE THAT MARKS THE WRONG THING DIRTY, OR NOTHING AT ALL. `persist`
 *    takes whole arrays, so the mark has to name records; and a connect or a
 *    first-connect prompt must mark nothing, or a machine that merely reconnects
 *    pushes over a real edit made elsewhere.
 *
 * 6. A LANDING THAT NAMES NO ID. `livingTombstones` requires a string id, so a
 *    tombstone landed with anything else is written to the file and filtered out
 *    of every read of it afterwards - the delete lost on this device while the
 *    caller records the object as applied and never lands it again.
 *
 * 7. A KEYCHAIN FAILURE THAT ESCAPES THE LOOP. The account release is the only
 *    await inside an apply that can reject, and a rejection out of a queued write
 *    takes every other landing in the set with it - which is the failure the
 *    returned refusal exists to prevent, arriving through the one path left open.
 *
 * 8. A LANDING THAT UNDOES A DELETE MADE AFTER THE MERGE. The merge runs outside
 *    the write queue and the apply runs inside it, so a local delete can land
 *    between the two, and only the apply can see it. The fixtures run BOTH
 *    directions: a newer local delete wins, an older one loses.
 *
 * 9. A CONNECT THAT PUBLISHES, OR AN EDIT OR LANDING THAT ERASES, VAULT RECENCY.
 *    A vault identity's and key's `lastConnectedAt` is this device's history on
 *    the host's terms: a connect writes it without a stamp or a dirty mark, and
 *    no upsert or landing may overwrite it with the caller's value or none.
 *
 * THE CLOCK IS INJECTED and the fake store BUFFERS `set` - both for the reasons
 * `sync-prereq-verify.ts` states at length. The commit COUNT and the keys a
 * commit carried are questions only a buffering fake can answer, and half the
 * checks here are exactly those two questions.
 */
import { createWriteQueue, type RecoveredStoreIo } from "../src/lib/recoveredStore";
import {
  TOMBSTONES_KEY,
  type DirtyId,
  type RemoteLanding,
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
  type RdpHost,
  type SshHost,
} from "../src/modules/hosts/types";
import type { SecretsIo } from "../src/modules/vault/adapters";
import { createVaultStore } from "../src/modules/vault/store";
import {
  HOST_KEYRING_SERVICE,
  IDENTITY_TOMBSTONE_KIND,
  KEY_TOMBSTONE_KIND,
  VAULT_IDENTITIES_KEY,
  VAULT_KEYRING_SERVICE,
  VAULT_KEYS_KEY,
  type IdentityHostRefs,
  type VaultIdentity,
  type VaultKey,
} from "../src/modules/vault/types";

let failed = 0;
function check(label: string, got: unknown, want: unknown): void {
  // `JSON.stringify` answers `undefined` for an absent value, which several
  // checks here are about, so the two are compared as text.
  const found = JSON.stringify(got) ?? String(got);
  const wanted = JSON.stringify(want) ?? String(want);
  if (found === wanted) {
    console.log(`  ok: ${label}`);
  } else {
    console.error(`  FAIL: ${label} = ${found}, want ${wanted}`);
    failed++;
  }
}

/** Far enough from the epoch that a landing stamped well before it is still
 *  positive. */
const START = 1_800_000_000_000;
/** Every landing's remote stamp, deliberately OLDER than the injected clock: a
 *  store that stamped its own clock would answer `START` instead. */
const REMOTE = START - 5000;

// ---------------------------------------------------------------------------
// In-memory ports, with the REAL write queue, a per-commit key log, and a
// recording keychain and dirty sink.
// ---------------------------------------------------------------------------

type Port = {
  store: RecoveredStoreIo;
  data: Record<string, unknown>;
  commits: () => number;
  keyLog: () => string[][];
};

function port(seed: Record<string, unknown>): Port {
  const data: Record<string, unknown> = { ...seed };
  let pending: Record<string, unknown> = {};
  const keyLog: string[][] = [];
  let commits = 0;

  const store: RecoveredStoreIo = {
    async get<T>(key: string): Promise<T | null> {
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
    },
    enqueueWrite: createWriteQueue(),
    async onChanged(): Promise<() => void> {
      return () => {};
    },
    ensureLoaded: async () => null,
    takeRecoveryNotice: () => null,
    fileState: async () => ({ found: "ok" as const, recovered: false }),
  };

  return { store, data, commits: () => commits, keyLog: () => keyLog };
}

/** Every account this suite's deletes cleared, in order, spelled the way
 *  `secrets.rs` addresses one. */
function recordingSecrets(): { io: SecretsIo; deleted: string[] } {
  const deleted: string[] = [];
  return {
    deleted,
    io: {
      async getAll(_service: string, accounts: string[]) {
        return accounts.map(() => null);
      },
      async set() {},
      async delete(service: string, account: string) {
        deleted.push(`${service}::${account}`);
      },
      async copy() {
        return false;
      },
    },
  };
}

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
  } = {},
) {
  const clock = START;
  const now = () => clock;

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

  const hostSecrets = recordingSecrets();
  const vaultSecrets = recordingSecrets();
  // One array per store, appended to on every commit - so "received `[]`" and
  // "was never called" are different answers rather than the same one.
  const dirty: { hosts: DirtyId[][]; vault: DirtyId[][]; forwards: DirtyId[][] } = {
    hosts: [],
    vault: [],
    forwards: [],
  };

  const vault = createVaultStore({
    store: vaultPort.store,
    secrets: vaultSecrets.io,
    now,
    markDirty: (d) => dirty.vault.push(d),
  });

  return {
    hosts: createHostsStore({
      store: hostsPort.store,
      secrets: hostSecrets.io,
      now,
      markDirty: (d) => dirty.hosts.push(d),
      markIdentityConnected: vault.markIdentityConnected,
    }),
    vault,
    forwards: createForwardStore({
      store: forwardsPort.store,
      now,
      markDirty: (d) => dirty.forwards.push(d),
    }),
    hostsPort,
    vaultPort,
    forwardsPort,
    hostSecrets,
    vaultSecrets,
    dirty,
    at: (): number => clock,
  };
}

/** A stored record's `updatedAt` is never what a landing asserts, so every
 *  fixture carries a value no check expects to survive. */
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

/** A host that OWNS its three accounts, which is what makes the keychain release
 *  observable: a vault-bound host owns none and would release nothing. */
const inlineHost = (over: Partial<SshHost> = {}): SshHost =>
  host({
    credential: {
      kind: "inline",
      hostId: over.id ?? "h-1",
      user: "root",
      authMode: "password",
      hasPassword: true,
      hasPrivateKey: true,
      hasKeyPassphrase: true,
    },
    ...over,
  });

/** The other protocol arm, which reads the other flat pin field. Without a
 *  fixture on this side, `withPins`'s RDP branch is never executed by this suite
 *  at all and a rewrite of it would pass every check here. */
const rdpHost = (over: Partial<RdpHost> = {}): RdpHost => ({
  id: "r-1",
  name: "desktop",
  host: "10.0.0.9",
  port: 3389,
  protocol: "rdp",
  credential: { kind: "identity", identityId: "i-1" },
  desktopWidth: 1920,
  desktopHeight: 1080,
  sizeMode: "preset",
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

const anySshHost: HostLookup = async (hostId) => host({ id: hostId });

/** A record landing at the remote stamp. */
function landed<T extends { id: string }>(record: T, updatedAt = REMOTE): RemoteLanding<T> {
  return { deleted: false, id: record.id, record, updatedAt };
}

/** A tombstone landing at the remote stamp. */
function buried<T>(id: string, kind: string, deletedAt = REMOTE): RemoteLanding<T> {
  return { deleted: true, tombstone: { id, kind, deletedAt } };
}

const lastKeys = (p: Port): string[] => p.keyLog()[p.keyLog().length - 1] ?? [];

// ---------------------------------------------------------------------------
// A1. A landed record carries the LANDING's updatedAt
// ---------------------------------------------------------------------------
{
  console.log("\n[A1] a landed record keeps the remote stamp, not this store's clock");
  const h = harness({ hosts: [host()], identities: [identity()], rules: [rule()] });

  await h.hosts.applyRemote([landed(host({ name: "renamed" }))], [landed(group())]);
  const landedHost = (await h.hosts.listHosts())[0];
  check("host takes the landing's stamp", landedHost.updatedAt, REMOTE);
  check("and is not the store's clock", landedHost.updatedAt === h.at(), false);
  check("the record content landed too", landedHost.name, "renamed");
  check("group takes the landing's stamp", (await h.hosts.listGroups())[0].updatedAt, REMOTE);

  await h.vault.applyRemote([landed(identity({ name: "renamed" }))], [landed(vaultKey())]);
  check("identity takes it", (await h.vault.listIdentities())[0].updatedAt, REMOTE);
  check("key takes it", (await h.vault.listKeys())[0].updatedAt, REMOTE);

  await h.forwards.applyRemote([landed(rule({ name: "renamed" }))]);
  check("rule takes it", (await h.forwards.listRules())[0].updatedAt, REMOTE);

  // The landing's own stamp wins over the one inside the record, which is the
  // half a spread would silently get backwards: the two disagree here on purpose.
  const disagreeing = harness();
  await disagreeing.hosts.applyRemote([landed(host({ updatedAt: WRONG }), REMOTE)], []);
  check(
    "the landing's stamp beats the one inside the record",
    (await disagreeing.hosts.listHosts())[0].updatedAt,
    REMOTE,
  );
}

// ---------------------------------------------------------------------------
// A2. A landed tombstone carries the LANDING's deletedAt
// ---------------------------------------------------------------------------
{
  console.log(
    "\n[A2] a landed tombstone keeps the remote deletedAt, so the window does not restart",
  );
  const h = harness({
    hosts: [host()],
    groups: [group()],
    identities: [identity()],
    vaultKeys: [vaultKey()],
    rules: [rule()],
  });

  await h.hosts.applyRemote(
    [buried<Host>("h-1", HOST_TOMBSTONE_KIND)],
    [buried<HostGroup>("g-1", GROUP_TOMBSTONE_KIND)],
  );
  check("hosts store files both at the remote stamp", await h.hosts.listTombstones(), [
    { id: "h-1", kind: HOST_TOMBSTONE_KIND, deletedAt: REMOTE },
    { id: "g-1", kind: GROUP_TOMBSTONE_KIND, deletedAt: REMOTE },
  ]);
  check("and the record is gone", await h.hosts.listHosts(), []);
  check("and so is the group", await h.hosts.listGroups(), []);

  await h.vault.applyRemote(
    [buried<VaultIdentity>("i-1", IDENTITY_TOMBSTONE_KIND)],
    [buried<VaultKey>("k-1", KEY_TOMBSTONE_KIND)],
  );
  check("vault store files both at the remote stamp", await h.vault.listTombstones(), [
    { id: "i-1", kind: IDENTITY_TOMBSTONE_KIND, deletedAt: REMOTE },
    { id: "k-1", kind: KEY_TOMBSTONE_KIND, deletedAt: REMOTE },
  ]);

  await h.forwards.applyRemote([buried<ForwardRule>("f-1", RULE_TOMBSTONE_KIND)]);
  check("forwards store files it at the remote stamp", await h.forwards.listTombstones(), [
    { id: "f-1", kind: RULE_TOMBSTONE_KIND, deletedAt: REMOTE },
  ]);

  // A delete whose local record is already gone still has to be recorded, or a
  // device that has not pulled since pushes its own copy straight back.
  const absent = harness();
  await absent.hosts.applyRemote([buried<Host>("h-gone", HOST_TOMBSTONE_KIND)], []);
  check(
    "a tombstone for a record this device never held is still filed",
    await absent.hosts.listTombstones(),
    [{ id: "h-gone", kind: HOST_TOMBSTONE_KIND, deletedAt: REMOTE }],
  );
}

// ---------------------------------------------------------------------------
// A3. A landed host keeps this device's pins, fingerprint and connect history
// ---------------------------------------------------------------------------
{
  console.log("\n[A3] a landing carries none of the four device-local fields, and erases none");
  const stored = host({
    pins: { "10.0.0.1": "SHA256:local" },
    lastFingerprint: "SHA256:local",
    lastConnectedAt: 1_700_000_000_000,
  });
  const h = harness({ hosts: [stored] });

  // The landing carries NONE of the four, which is what the publishing side
  // guarantees: it strips all of them before an envelope is sealed.
  await h.hosts.applyRemote([landed(host({ name: "renamed" }))], []);
  const after = (await h.hosts.listHosts())[0] as SshHost;
  check("pins survive", after.pins, { "10.0.0.1": "SHA256:local" });
  check("the flat fingerprint survives", after.lastFingerprint, "SHA256:local");
  check("lastConnectedAt survives", after.lastConnectedAt, 1_700_000_000_000);
  check("and the landing's own content did land", after.name, "renamed");

  // The other direction, which no stripped fixture can see: a landing that DOES
  // carry pins must not file them - they describe another machine's trust.
  const foreign = harness({ hosts: [stored] });
  await foreign.hosts.applyRemote(
    [
      landed(
        host({
          pins: { "10.0.0.1": "SHA256:theirs" },
          lastFingerprint: "SHA256:theirs",
          lastConnectedAt: 9,
        }),
      ),
    ],
    [],
  );
  const kept = (await foreign.hosts.listHosts())[0] as SshHost;
  check("a carried pin does not overwrite this device's", kept.pins, {
    "10.0.0.1": "SHA256:local",
  });
  check("nor the flat projection of it", kept.lastFingerprint, "SHA256:local");
  check("nor this device's connect history", kept.lastConnectedAt, 1_700_000_000_000);

  // The RDP arm, which reads the OTHER flat field. Without this the suite never
  // executes that branch of `withPins` at all.
  const desktop = harness({
    hosts: [
      rdpHost({
        pins: { "10.0.0.9": "SHA256:cert" },
        certFingerprint: "SHA256:cert",
        lastConnectedAt: 1_700_000_000_001,
      }),
    ],
  });
  await desktop.hosts.applyRemote([landed(rdpHost({ name: "renamed" }))], []);
  const desk = (await desktop.hosts.listHosts())[0] as RdpHost;
  check("an RDP landing keeps the stored cert pin", desk.certFingerprint, "SHA256:cert");
  check("and the pin map behind it", desk.pins, { "10.0.0.9": "SHA256:cert" });
  check("and its connect history", desk.lastConnectedAt, 1_700_000_000_001);
  check("and the landing's content landed", desk.name, "renamed");

  // An unpinned host must not grow a pin out of nothing.
  const fresh = harness();
  await fresh.hosts.applyRemote([landed(host({ id: "h-new" }))], []);
  const first = (await fresh.hosts.listHosts())[0] as SshHost;
  check("a host with no stored pins lands unpinned", first.pins, undefined);
  check("and with no flat fingerprint", first.lastFingerprint, undefined);

  // The vault half: an identity and a key keep this device's connect history
  // across a landing, whether the landing carries none (the stripped wire) or a
  // foreign one.
  const vh = harness({
    identities: [identity({ lastConnectedAt: 1_700_000_000_000 })],
    vaultKeys: [vaultKey({ lastConnectedAt: 1_700_000_000_002 })],
  });
  await vh.vault.applyRemote(
    [landed(identity({ name: "renamed" }))],
    [landed(vaultKey({ name: "renamed", lastConnectedAt: 9 }))],
  );
  const landedIdentity = (await vh.vault.listIdentities())[0];
  const landedKey = (await vh.vault.listKeys())[0];
  check(
    "a landed identity keeps 1_700_000_000_000",
    landedIdentity.lastConnectedAt,
    1_700_000_000_000,
  );
  check("and its content landed", landedIdentity.name, "renamed");
  check(
    "a landed key keeps 1_700_000_000_002, not the carried 9",
    landedKey.lastConnectedAt,
    1_700_000_000_002,
  );
  check("and its content landed", landedKey.name, "renamed");

  const vfresh = harness();
  await vfresh.vault.applyRemote(
    [landed(identity({ id: "i-new", lastConnectedAt: 9 }))],
    [landed(vaultKey({ id: "k-new", lastConnectedAt: 9 }))],
  );
  check(
    "a new identity does not take a carried stamp",
    (await vfresh.vault.findIdentity("i-new"))?.lastConnectedAt,
    undefined,
  );
  check("nor does a new key", (await vfresh.vault.findKey("k-new"))?.lastConnectedAt, undefined);
}

// ---------------------------------------------------------------------------
// A4. A record landing clears a living tombstone naming its id, same commit
// ---------------------------------------------------------------------------
{
  console.log("\n[A4] a landed record clears the tombstone naming it, in the same commit");
  // The local delete is OLDER than the landing, which is the resurrection case:
  // the record was deleted here and then edited on another device. A newer local
  // delete is the other way round and wins - that is A12.
  const h = harness({
    hostGraves: [{ id: "h-1", kind: HOST_TOMBSTONE_KIND, deletedAt: REMOTE - 1000 }],
  });

  await h.hosts.applyRemote([landed(host())], []);
  check("the tombstone is gone", await h.hosts.listTombstones(), []);
  check("the record is there", (await h.hosts.listHosts()).length, 1);
  check("one commit", h.hostsPort.commits(), 1);
  check(
    "carrying both keys",
    [...lastKeys(h.hostsPort)].sort(),
    [HOSTS_KEY, TOMBSTONES_KEY].sort(),
  );

  // And a landing that clears nothing leaves the key out, which is the clobber
  // discipline every upsert in these stores already follows.
  const clean = harness();
  await clean.hosts.applyRemote([landed(host())], []);
  check(
    "a landing with no tombstone to clear writes the record list alone",
    lastKeys(clean.hostsPort),
    [HOSTS_KEY],
  );

  // A re-landed delete REPLACES the stored tombstone rather than joining it: one
  // delete recorded twice would expire at two different times.
  const twice = harness({
    hostGraves: [{ id: "h-1", kind: HOST_TOMBSTONE_KIND, deletedAt: REMOTE - 1000 }],
  });
  await twice.hosts.applyRemote([buried<Host>("h-1", HOST_TOMBSTONE_KIND)], []);
  check("a re-landed delete leaves exactly one tombstone", await twice.hosts.listTombstones(), [
    { id: "h-1", kind: HOST_TOMBSTONE_KIND, deletedAt: REMOTE },
  ]);
}

// ---------------------------------------------------------------------------
// A5. A mixed landing set is exactly ONE commit
// ---------------------------------------------------------------------------
{
  console.log("\n[A5] records, tombstones and both record kinds land in one commit");
  const h = harness({
    hosts: [host(), host({ id: "h-2" })],
    groups: [group(), group({ id: "g-2" })],
    identities: [identity()],
    vaultKeys: [vaultKey()],
    rules: [rule(), rule({ id: "f-2" })],
  });

  await h.hosts.applyRemote(
    [landed(host({ name: "renamed" })), buried<Host>("h-2", HOST_TOMBSTONE_KIND)],
    [landed(group({ name: "staging" })), buried<HostGroup>("g-2", GROUP_TOMBSTONE_KIND)],
  );
  check("four host-store landings cost one commit", h.hostsPort.commits(), 1);
  check(
    "carrying all three keys",
    [...lastKeys(h.hostsPort)].sort(),
    [HOSTS_KEY, HOST_GROUPS_KEY, TOMBSTONES_KEY].sort(),
  );

  await h.vault.applyRemote(
    [landed(identity({ name: "renamed" }))],
    [buried<VaultKey>("k-1", KEY_TOMBSTONE_KIND)],
  );
  check("both vault kinds cost one commit", h.vaultPort.commits(), 1);
  check(
    "carrying all three keys",
    [...lastKeys(h.vaultPort)].sort(),
    [TOMBSTONES_KEY, VAULT_IDENTITIES_KEY, VAULT_KEYS_KEY].sort(),
  );

  await h.forwards.applyRemote([
    landed(rule({ name: "renamed" })),
    buried<ForwardRule>("f-2", RULE_TOMBSTONE_KIND),
  ]);
  check("both forwards landings cost one commit", h.forwardsPort.commits(), 1);
}

// ---------------------------------------------------------------------------
// A6. An empty landing set writes nothing at all
// ---------------------------------------------------------------------------
{
  console.log("\n[A6] an apply with nothing to land costs no commit and no key");
  const h = harness({ hosts: [host()], identities: [identity()], rules: [rule()] });

  check("hosts refuses nothing", await h.hosts.applyRemote([], []), []);
  check("vault refuses nothing", await h.vault.applyRemote([], []), []);
  check("forwards refuses nothing", await h.forwards.applyRemote([]), []);
  check("hosts store: no commit", h.hostsPort.commits(), 0);
  check("vault store: no commit", h.vaultPort.commits(), 0);
  check("forwards store: no commit", h.forwardsPort.commits(), 0);
  check("and nothing was marked dirty either", h.dirty, {
    hosts: [],
    vault: [],
    forwards: [],
  });
}

// ---------------------------------------------------------------------------
// A7. A tombstone landing releases the keychain - hosts AND vault
// ---------------------------------------------------------------------------
{
  console.log("\n[A7] a landed delete clears the accounts its record owned");

  const hostFixture = harness({ hosts: [inlineHost()] });
  await hostFixture.hosts.applyRemote([buried<Host>("h-1", HOST_TOMBSTONE_KIND)], []);
  check("an SSH host releases all three of its accounts", hostFixture.hostSecrets.deleted, [
    `${HOST_KEYRING_SERVICE}::h-1::password`,
    `${HOST_KEYRING_SERVICE}::h-1::privateKey`,
    `${HOST_KEYRING_SERVICE}::h-1::keyPassphrase`,
  ]);

  const keyFixture = harness({ vaultKeys: [vaultKey({ hasPrivateKey: true })] });
  await keyFixture.vault.applyRemote([], [buried<VaultKey>("k-1", KEY_TOMBSTONE_KIND)]);
  check("a vault key releases the body and its passphrase", keyFixture.vaultSecrets.deleted, [
    `${VAULT_KEYRING_SERVICE}::k-1::privateKey`,
    `${VAULT_KEYRING_SERVICE}::k-1::passphrase`,
  ]);

  const identityFixture = harness({ identities: [identity({ hasPassword: true })] });
  await identityFixture.vault.applyRemote(
    [buried<VaultIdentity>("i-1", IDENTITY_TOMBSTONE_KIND)],
    [],
  );
  check("a vault identity releases its password", identityFixture.vaultSecrets.deleted, [
    `${VAULT_KEYRING_SERVICE}::i-1::password`,
  ]);

  // A vault-bound host owns no accounts, so nothing is released - which is what
  // keeps the three checks above from passing on an unconditional fan-out.
  const bound = harness({ hosts: [host()] });
  await bound.hosts.applyRemote([buried<Host>("h-1", HOST_TOMBSTONE_KIND)], []);
  check("a vault-bound host releases nothing", bound.hostSecrets.deleted, []);

  // And a landed delete does NOT re-run the forward-rule cleanup: the origin
  // device already published a tombstone per rule, so minting a second set here
  // would record one user delete twice, at two times.
  const rules = harness({ hosts: [host()], rules: [rule()] });
  await rules.hosts.applyRemote([buried<Host>("h-1", HOST_TOMBSTONE_KIND)], []);
  check(
    "the rules riding a landed-deleted host are left to their own landings",
    (await rules.forwards.listRules()).map((r) => r.id),
    ["f-1"],
  );
}

// ---------------------------------------------------------------------------
// A8. Every refusal comes back, and the rest of the set still lands
// ---------------------------------------------------------------------------
{
  console.log("\n[A8] each of the four refusal conditions returns, and nothing else is lost");
  const h = harness();

  const refusals = await h.hosts.applyRemote(
    [
      // 1. the record names an id the landing does not.
      { deleted: false, id: "h-bad", record: host({ id: "h-other" }), updatedAt: REMOTE },
      // 2. no record object at all - a file or a wire can produce this, and the
      //    type cannot exclude it.
      { deleted: false, id: "h-null", record: null as unknown as Host, updatedAt: REMOTE },
      // 3. a tombstone with no usable deletedAt, which would otherwise compare as
      //    deleted at the epoch forever.
      { deleted: true, tombstone: { id: "h-nan", kind: HOST_TOMBSTONE_KIND, deletedAt: NaN } },
      // 4. a tombstone of a kind this store does not own, routed into the wrong
      //    array: applied, it would delete whatever local host shared its id.
      { deleted: true, tombstone: { id: "h-1", kind: RULE_TOMBSTONE_KIND, deletedAt: REMOTE } },
      // The good landing comes LAST on purpose: a throw at any of the four above
      // would take it with them, and the refusal list alone cannot tell the two
      // apart.
      landed(host({ id: "h-good" })),
    ],
    [],
  );

  check(
    "four refusals, each naming what it refused",
    refusals.map((r) => `${r.kind}/${r.id}`),
    ["host/h-bad", "host/h-null", "host/h-nan", "rule/h-1"],
  );
  check(
    "every refusal carries a reason",
    refusals.every((r) => r.reason.length > 0),
    true,
  );
  check(
    "the good landing in the same set still landed",
    (await h.hosts.listHosts()).map((x) => x.id),
    ["h-good"],
  );
  check("in one commit", h.hostsPort.commits(), 1);
  check("and no refused id was filed as a tombstone", await h.hosts.listTombstones(), []);

  // A set that is refused ENTIRELY writes nothing: there is nothing to commit,
  // and a commit here would rewrite the file for a pull that landed nothing.
  const allBad = harness();
  const every = await allBad.hosts.applyRemote(
    [{ deleted: false, id: "h-x", record: null as unknown as Host, updatedAt: REMOTE }],
    [],
  );
  check("an entirely refused set still reports", every.length, 1);
  check("and costs no commit", allBad.hostsPort.commits(), 0);

  // The other two stores validate through the same function, so one landing each
  // is enough to prove they call it at all.
  const vaultRefusals = await h.vault.applyRemote(
    [{ deleted: false, id: "i-bad", record: identity({ id: "i-other" }), updatedAt: REMOTE }],
    [{ deleted: true, tombstone: { id: "k-1", kind: HOST_TOMBSTONE_KIND, deletedAt: REMOTE } }],
  );
  check(
    "the vault store refuses on the same four conditions",
    vaultRefusals.map((r) => `${r.kind}/${r.id}`),
    ["identity/i-bad", "host/k-1"],
  );
  const ruleRefusals = await h.forwards.applyRemote([
    { deleted: false, id: "f-bad", record: rule({ id: "f-other" }), updatedAt: REMOTE },
  ]);
  check(
    "and so does the forwards store",
    ruleRefusals.map((r) => `${r.kind}/${r.id}`),
    ["rule/f-bad"],
  );
}

// ---------------------------------------------------------------------------
// A9. What every write marks dirty
// ---------------------------------------------------------------------------
{
  console.log("\n[A9] every committed write names the records it owes a push");
  const h = harness({ groups: [group()], hosts: [host({ id: "h-member", groupId: "g-1" })] });

  await h.hosts.upsertHost(host());
  await h.hosts.upsertGroup(group({ id: "g-2", name: "staging" }));
  await h.hosts.deleteHost("h-1", noForwardRules);
  await h.hosts.deleteGroup("g-1");
  check("the four hosts-store mutators mark their own records", h.dirty.hosts, [
    [{ kind: HOST_TOMBSTONE_KIND, id: "h-1" }],
    [{ kind: GROUP_TOMBSTONE_KIND, id: "g-2" }],
    [{ kind: HOST_TOMBSTONE_KIND, id: "h-1" }],
    // The group AND the member whose `groupId` the cascade cleared: that clear is
    // real content under a new stamp, so it owes a push of its own.
    [
      { kind: GROUP_TOMBSTONE_KIND, id: "g-1" },
      { kind: HOST_TOMBSTONE_KIND, id: "h-member" },
    ],
  ]);

  // A connect and a first-connect prompt mark NOTHING, which is the statement
  // `patchHost` makes by passing `[]` - and the only place a live consumer could
  // see the difference between "marked nothing" and "was not called".
  const pinned = harness({ hosts: [host()] });
  await pinned.hosts.markConnected("h-1", "SHA256:aaa");
  await pinned.hosts.pinFingerprint("h-1", "SHA256:bbb");
  check("markConnected and pinFingerprint mark nothing", pinned.dirty.hosts, [[], []]);
  check(
    "and both really did write, so the check above is not vacuous",
    pinned.hostsPort.commits(),
    2,
  );

  const v = harness({ identities: [identity()], vaultKeys: [vaultKey()] });
  await v.vault.upsertIdentity(identity({ id: "i-2" }), {});
  await v.vault.upsertKey(vaultKey({ id: "k-2" }), {});
  await v.vault.deleteIdentity("i-1", noHolders);
  await v.vault.deleteKey("k-1");
  check("the four vault mutators mark their own records", v.dirty.vault, [
    [{ kind: IDENTITY_TOMBSTONE_KIND, id: "i-2" }],
    [{ kind: KEY_TOMBSTONE_KIND, id: "k-2" }],
    [{ kind: IDENTITY_TOMBSTONE_KIND, id: "i-1" }],
    [{ kind: KEY_TOMBSTONE_KIND, id: "k-1" }],
  ]);

  const f = harness({ rules: [rule(), rule({ id: "f-2" }), rule({ id: "f-3" })] });
  await f.forwards.upsertRule(rule({ id: "f-4", hostId: "h-9" }), anySshHost);
  await f.forwards.deleteRule("f-1");
  await f.forwards.dropRulesForHost("h-1");
  check("the three forwards mutators mark their own records", f.dirty.forwards, [
    [{ kind: RULE_TOMBSTONE_KIND, id: "f-4" }],
    [{ kind: RULE_TOMBSTONE_KIND, id: "f-1" }],
    // One per rule dropped, matching the tombstones the same call files.
    [
      { kind: RULE_TOMBSTONE_KIND, id: "f-2" },
      { kind: RULE_TOMBSTONE_KIND, id: "f-3" },
    ],
  ]);

  // And the apply path owes nothing, in all three stores: a landing is what the
  // remote already holds, so a mark here is a push straight back at the device
  // that just sent it.
  const applied = harness({ hosts: [host()], identities: [identity()], rules: [rule()] });
  await applied.hosts.applyRemote([landed(host({ name: "renamed" }))], [landed(group())]);
  await applied.vault.applyRemote([landed(identity({ name: "renamed" }))], []);
  await applied.forwards.applyRemote([landed(rule({ name: "renamed" }))]);
  check("applyRemote marks nothing", applied.dirty, {
    hosts: [[]],
    vault: [[]],
    forwards: [[]],
  });
  check(
    "and each of the three really did commit",
    [applied.hostsPort.commits(), applied.vaultPort.commits(), applied.forwardsPort.commits()],
    [1, 1, 1],
  );
}

// ---------------------------------------------------------------------------
// A10. A landing that names no id is refused, in both arms
// ---------------------------------------------------------------------------
{
  console.log(
    "\n[A10] an unnamed landing is refused rather than written where nothing can read it",
  );
  const h = harness();

  // A tombstone whose id is not a string is the dangerous one: `livingTombstones`
  // requires a string, so the row would be written to the file and then filtered
  // out of every read of it forever - the delete lost on this device, silently,
  // while the caller records the object as applied and never lands it again.
  const numbered = await h.hosts.applyRemote(
    [
      {
        deleted: true,
        tombstone: { id: 7 as unknown as string, kind: HOST_TOMBSTONE_KIND, deletedAt: REMOTE },
      },
    ],
    [],
  );
  check("a tombstone with a non-string id is refused", numbered.length, 1);
  check("and nothing was written", h.hostsPort.commits(), 0);
  check("so the file holds no unreadable row", await h.hosts.listTombstones(), []);

  const unnamed = await h.hosts.applyRemote(
    [{ deleted: false, id: undefined as unknown as string, record: {} as Host, updatedAt: REMOTE }],
    [],
  );
  check("a record landing with no id is refused", unnamed.length, 1);
  check("and no id-less row reached the host list", await h.hosts.listHosts(), []);
  check("still no commit", h.hostsPort.commits(), 0);
}

// ---------------------------------------------------------------------------
// A11. A keychain that refuses is a refusal, not a lost landing set
// ---------------------------------------------------------------------------
{
  console.log("\n[A11] a keychain failure refuses that landing and keeps the rest of the set");
  const h = harness({ hosts: [inlineHost(), host({ id: "h-2" })] });
  h.hostSecrets.io.delete = async () => {
    throw new Error("keyring locked");
  };

  // The delete comes FIRST and the good landing after it, which is the only
  // arrangement that can tell a refusal from an abort.
  const refusals = await h.hosts.applyRemote(
    [buried<Host>("h-1", HOST_TOMBSTONE_KIND), landed(host({ id: "h-2", name: "renamed" }))],
    [],
  );
  check("the failing release comes back as a refusal", refusals.length, 1);
  check("naming the host it could not release", refusals[0]?.id, "h-1");
  check(
    "the host whose accounts would not clear is still there",
    (await h.hosts.listHosts()).some((x) => x.id === "h-1"),
    true,
  );
  check(
    "and the good landing in the same set still landed",
    (await h.hosts.listHosts()).find((x) => x.id === "h-2")?.name,
    "renamed",
  );
  check("no tombstone was filed for the refused delete", await h.hosts.listTombstones(), []);

  const v = harness({ vaultKeys: [vaultKey({ hasPrivateKey: true })], identities: [identity()] });
  v.vaultSecrets.io.delete = async () => {
    throw new Error("keyring locked");
  };
  const vaultRefusals = await v.vault.applyRemote(
    [landed(identity({ name: "renamed" }))],
    [buried<VaultKey>("k-1", KEY_TOMBSTONE_KIND)],
  );
  check(
    "the vault store refuses the same way",
    vaultRefusals.map((r) => r.id),
    ["k-1"],
  );
  check("and its other landing survived", (await v.vault.listIdentities())[0]?.name, "renamed");
}

// ---------------------------------------------------------------------------
// A12. A local delete made after the merge outranks a record landing
// ---------------------------------------------------------------------------
{
  console.log("\n[A12] a newer local delete wins over the landing that did not know about it");
  const h = harness({
    // Deleted AFTER the stamp the landing carries, which is what the merge could
    // not have seen: it read this device's state before the delete happened.
    hostGraves: [{ id: "h-1", kind: HOST_TOMBSTONE_KIND, deletedAt: REMOTE + 1000 }],
  });

  const refusals = await h.hosts.applyRemote([landed(host())], []);
  check("the landing is skipped, not refused", refusals, []);
  check("the record does not come back", await h.hosts.listHosts(), []);
  check("the local delete still stands", (await h.hosts.listTombstones()).length, 1);
  check("and nothing was written at all", h.hostsPort.commits(), 0);

  // The other direction, so the check above is not passing because a record
  // landing never clears a tombstone: a delete OLDER than the landing loses.
  const older = harness({
    hostGraves: [{ id: "h-1", kind: HOST_TOMBSTONE_KIND, deletedAt: REMOTE - 1000 }],
  });
  await older.hosts.applyRemote([landed(host())], []);
  check("an older local delete loses to the landing", (await older.hosts.listHosts()).length, 1);
  check("and its tombstone is cleared", await older.hosts.listTombstones(), []);
}

// ---------------------------------------------------------------------------
// A13. The tombstone key is left out of a commit that would not change it
// ---------------------------------------------------------------------------
{
  console.log("\n[A13] a delete that landed before does not rewrite the key on every pull");
  const already: Tombstone = { id: "h-1", kind: HOST_TOMBSTONE_KIND, deletedAt: REMOTE };
  const h = harness({ hostGraves: [already] });

  await h.hosts.applyRemote([buried<Host>("h-1", HOST_TOMBSTONE_KIND)], []);
  check("the same delete arriving twice costs no commit", h.hostsPort.commits(), 0);
  check("and the list is unchanged", await h.hosts.listTombstones(), [already]);

  // Two landings of one id in one set leave ONE row, not two.
  const twice = harness();
  await twice.hosts.applyRemote(
    [buried<Host>("h-9", HOST_TOMBSTONE_KIND), buried<Host>("h-9", HOST_TOMBSTONE_KIND)],
    [],
  );
  check("a repeated id inside one set files one tombstone", await twice.hosts.listTombstones(), [
    { id: "h-9", kind: HOST_TOMBSTONE_KIND, deletedAt: REMOTE },
  ]);

  // A tombstone and a record for one id in one set leave the two lists agreeing,
  // whichever order they arrive in. One id carries one disposition out of a
  // merge, so this is a malformed set - but the state it would otherwise leave is
  // a live record with deleted accounts and a tombstone naming it.
  const after = harness({ hosts: [inlineHost()] });
  await after.hosts.applyRemote([buried<Host>("h-1", HOST_TOMBSTONE_KIND), landed(host())], []);
  check(
    "record after tombstone: the record is live and no tombstone names it",
    {
      hosts: (await after.hosts.listHosts()).map((x) => x.id),
      graves: await after.hosts.listTombstones(),
    },
    { hosts: ["h-1"], graves: [] },
  );

  const before = harness({ hosts: [inlineHost()] });
  await before.hosts.applyRemote([landed(host()), buried<Host>("h-1", HOST_TOMBSTONE_KIND)], []);
  check(
    "tombstone after record: the record is gone and one tombstone names it",
    {
      hosts: (await before.hosts.listHosts()).map((x) => x.id),
      graves: (await before.hosts.listTombstones()).map((t) => t.id),
    },
    { hosts: [], graves: ["h-1"] },
  );
}

// ---------------------------------------------------------------------------
// A14. A connect stamps the vault identity it authenticated as
// ---------------------------------------------------------------------------
{
  console.log(
    "\n[A14] a connect stamps the vault identity it authenticated as, and its key only over SSH key auth",
  );
  const h = harness({
    hosts: [
      host(),
      rdpHost(),
      host({ id: "h-pw", credential: { kind: "identity", identityId: "i-pw" } }),
    ],
    // `i-pw` holds a stale `keyId` under password auth, which is legal: `keyId` is
    // independent of `authMode`, and password auth never hands the key over.
    identities: [
      identity({ authMode: "key", keyId: "k-1" }),
      identity({ id: "i-pw", authMode: "password", keyId: "k-1" }),
    ],
    vaultKeys: [vaultKey()],
  });
  const identityAt = async (id: string) => (await h.vault.findIdentity(id))?.lastConnectedAt;
  const keyAt = async () => (await h.vault.findKey("k-1"))?.lastConnectedAt;

  await h.hosts.markConnected("r-1", "SHA256:cert");
  check("an RDP connect stamps its identity", await identityAt("i-1"), START);
  check("but not the key, which RDP never reads", await keyAt(), undefined);

  await h.hosts.markConnected("h-pw", "SHA256:pw");
  check("a password-auth SSH connect stamps its identity", await identityAt("i-pw"), START);
  check("but not the key its stale keyId names", await keyAt(), undefined);

  await h.hosts.markConnected("h-1", "SHA256:aaa");
  check("a key-auth SSH connect stamps the key", await keyAt(), START);

  // In its own harness, because the RDP connect above already left `i-1` at the
  // same constant clock: a key branch that REPLACED the identity write instead of
  // adding to it would pass every row above.
  const keyAuth = harness({
    hosts: [host()],
    identities: [identity({ authMode: "key", keyId: "k-1" })],
    vaultKeys: [vaultKey()],
  });
  await keyAuth.hosts.markConnected("h-1", "SHA256:aaa");
  check(
    "a key-auth SSH connect alone stamps both the identity and the key",
    [
      (await keyAuth.vault.findIdentity("i-1"))?.lastConnectedAt,
      (await keyAuth.vault.findKey("k-1"))?.lastConnectedAt,
    ],
    [START, START],
  );
  check("in one commit", keyAuth.vaultPort.commits(), 1);

  check(
    "no connect moved either record's updatedAt",
    [(await h.vault.findIdentity("i-1"))?.updatedAt, (await h.vault.findKey("k-1"))?.updatedAt],
    [WRONG, WRONG],
  );
  check("and none marked anything dirty", h.dirty.vault, [[], [], []]);
  check("while each really did commit", h.vaultPort.commits(), 3);

  await h.vault.markIdentityConnected("i-gone", "ssh");
  check("a missing identity writes nothing", h.vaultPort.commits(), 3);

  // An editor saves a record built from a draft that has no stamp, or one
  // carrying a stale or foreign value: the stored stamp wins either way.
  await h.vault.upsertIdentity(identity({ authMode: "key", keyId: "k-1", name: "renamed" }), {});
  check("an identity edit keeps the stamp", await identityAt("i-1"), START);
  await h.vault.upsertKey(vaultKey({ name: "renamed", lastConnectedAt: 9 }), {});
  check("a key edit keeps the stamp, not the caller's 9", await keyAt(), START);
  await h.vault.upsertIdentity(identity({ id: "i-new", lastConnectedAt: 9 }), {});
  check("a new identity does not take the caller's stamp", await identityAt("i-new"), undefined);
}

if (failed > 0) throw new Error(`sync-apply-verify: ${failed} FAILED`);
console.log("\nsync-apply-verify: OK\n");
