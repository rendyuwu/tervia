/**
 * Self-check for the unified host store. Run: `npx tsx scripts/hosts-store-verify.ts`.
 *
 * Every property here is one whose failure is SILENT, which is why they are
 * pinned before any UI exists:
 *
 * 1. AN INLINE BINDING NAMES THE HOST STORING IT. Carrying `hostId` inside the
 *    binding removes the resolve-time mismatch and MOVES it to write time, where
 *    nothing in the type system catches it. A duplicate written as
 *    `{ ...source, id: newId() }` is well-typed and keeps the source's `hostId`,
 *    after which the copy authenticates with the source's secrets: rotating one
 *    password changes both, and deleting the source breaks the copy. No error
 *    anywhere. `assertBindingOwner` on every upsert is the only thing that
 *    catches it.
 *
 * 2. A JUMP OR TUNNEL HOST IS AN SSH HOST, AND THE CHAIN DOES NOT LOOP. Two
 *    stores could not express an RDP jump host; one merged store can, and there is
 *    nothing to jump through. Checked on the WRITE and again at RESOLVE, because
 *    neither covers the other: refusing only at the connect leaves a saved row
 *    that can never connect, and refusing only at the write says nothing about a
 *    row an import put there. The write guard walks the WHOLE chain for the same
 *    reason it refuses a dangling id - a 2-cycle that saves on both sides then
 *    fails every connect to either host.
 *
 * 3. A DUPLICATE DOES NOT INHERIT THE PINNED SERVER KEY. It belongs to the
 *    machine that presented it, and a copy exists to be pointed somewhere else.
 *    Carried over, the next connect fails as a key MISMATCH - which reads to the
 *    user as an attack rather than as a copy.
 *
 * 4. DELETING A HOST CLEARS WHAT POINTED AT IT. A dangling `proxyJumpId` fails
 *    every later connect with "a jump host in the chain no longer exists", on a
 *    host the user was not looking at when they deleted. A dangling
 *    `tunnel.sshHostId` is the same failure for RDP. Forward rules go the same
 *    way, through an injected cleanup that FAILS CLOSED.
 *
 * 5. DELETING A GROUP DOES NOT DELETE ITS MEMBERS. The one place a cascade is
 *    right is the label, not the rows: a group is not an owner.
 *
 * 6. PRESENCE FLAGS TRACK WRITES, and are never computed by reading a secret
 *    back. They exist so a hundred-host list costs zero `secrets_get` calls, and
 *    the three-state convention (`undefined` = leave it alone) is what stops an
 *    edit that never touched a password field from wiping it. Every check here
 *    feeds the flags in DELIBERATELY WRONG, because handing the previous record
 *    straight back cannot tell "the store read what is stored" from "the store
 *    echoed its caller". A FLAG FOLLOWS ITS ACCOUNT, including across a protocol
 *    change: `password` is the same account on both arms, and a record claiming
 *    otherwise is a secret `resolveRdpAuth` hands the backend regardless.
 *
 * 7. NO ACCOUNT OUTLIVES THE RECORD NAMING IT, AND NO RECORD OUTLIVES ITS
 *    ACCOUNT. There is no `secrets_list` command, so an account nothing
 *    references is unreachable, not merely untidy. A delete clears the host's
 *    accounts; an upsert clears the ones the new record can no longer name, but
 *    only AFTER the new record is on disk (§5.3), because a protocol change has no
 *    copy step and this layer cannot put a secret back; a partial write on a
 *    brand-new host rolls back. The two OLD connection stores' accounts are swept
 *    once by `legacyPurge.ts`, which is the only thing that can ever name them
 *    after those modules are deleted.
 *
 * 8. AN RDP PASSWORD NEVER ENTERS THE WEBVIEW. There is no read-back for one -
 *    not for the editor, and not for a duplicate, which is why a duplicated RDP
 *    host is saved with `hasPassword: false` and the password re-entered once.
 *
 * 9. THE UNION NARROWS ON `protocol`. `credential` sits on each arm rather than
 *    on the base precisely so one guard narrows both, and `user` (SSH) against
 *    `username` (RDP) is what a shared binding union would break.
 *
 * 10. CONCURRENT READ-MODIFY-WRITES DO NOT LOSE AN UPDATE. A chained connect
 *     fires `markConnected` once per hop plus once for the target, so this is the
 *     ordinary case: a lost write silently reverts a freshly pinned key to a TOFU
 *     prompt on the next connect. `duplicateHost` reads its source inside the same
 *     queue entry that writes the copy, or a rotation landing between the two
 *     gives the copy a password nobody has any more.
 *
 * The store, secrets, files and event bus are injectable ports, so all of this
 * runs under plain node with no Tauri runtime and no mocking library.
 */
import { createWriteQueue } from "../src/lib/recoveredStore";
import type { StoreFileIo, StoreFileRead, StoreRecovery } from "../src/lib/storeRecovery";
import type { HostsStoreIo } from "../src/modules/hosts/adapters";
import { MAX_JUMP_HOPS, resolveJumpHops } from "../src/modules/hosts/jumps";
import {
  createHostsStore,
  noForwardRules,
  SECRET_ALREADY_STORED,
} from "../src/modules/hosts/store";
import {
  hostFingerprint,
  isRdpHost,
  isSshHost,
  HOSTS_KEY,
  HOST_GROUPS_KEY,
  LEGACY_PURGE_KEY,
  presetById,
  presetIdFor,
  type Host,
  type HostGroup,
  type RdpHost,
  type SshHost,
} from "../src/modules/hosts/types";
import type { SecretsIo } from "../src/modules/vault/adapters";
import type { ResolveDeps } from "../src/modules/vault/resolve";
import type { VaultIdentity, VaultKey } from "../src/modules/vault/types";

let failed = 0;
function check(label: string, got: unknown, want: unknown): void {
  if (JSON.stringify(got) === JSON.stringify(want)) {
    console.log(`  ok: ${label}`);
  } else {
    console.error(`  FAIL: ${label} = ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
    failed++;
  }
}
function assert(cond: boolean, label: string): void {
  if (cond) console.log(`  ok: ${label}`);
  else {
    console.error(`  FAIL: ${label}`);
    failed++;
  }
}
async function rejects(
  label: string,
  fn: () => Promise<unknown>,
  needles: string[],
): Promise<void> {
  try {
    await fn();
    console.error(`  FAIL: ${label} did not reject`);
    failed++;
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    const missing = needles.filter((n) => !msg.toLowerCase().includes(n.toLowerCase()));
    if (missing.length === 0) console.log(`  ok: ${label}`);
    else {
      console.error(`  FAIL: ${label} threw "${msg}", missing ${JSON.stringify(missing)}`);
      failed++;
    }
  }
}

// ---------------------------------------------------------------------------
// In-memory ports. `SecretsIo` has no single-value read at all, so the store
// layer CANNOT compute a presence flag by reading a secret back; the call log is
// what proves it does not batch-read one either.
// ---------------------------------------------------------------------------

type SecretCall = { op: "getAll" | "set" | "delete"; service: string; accounts: string[] };

/** A step that throws, to reach the partial-failure paths. */
type Fail = { setAccount?: string; deleteAccount?: string; commit?: string; dir?: string };

/** Extra microtask ticks inside `secrets.set`, so a read racing a write has a
 *  DETERMINISTIC loser. Used only by the duplicate-inside-the-queue check: an
 *  un-queued read is indistinguishable from a queued one when both resolve in the
 *  same tick. */
const SLOW_SET_TICKS = 8;

function harness(
  seed: {
    hosts?: Host[];
    groups?: HostGroup[];
    identities?: VaultIdentity[];
    keys?: VaultKey[];
    kept?: Record<string, string>;
    notice?: StoreRecovery;
    fail?: Fail;
    /** The OLD connection store files, by file name, as the file port sees them. */
    legacy?: Record<string, StoreFileRead>;
    slowSet?: boolean;
  } = {},
) {
  const data: Record<string, unknown> = {
    [HOSTS_KEY]: seed.hosts ?? [],
    [HOST_GROUPS_KEY]: seed.groups ?? [],
  };
  const kept = new Map<string, string>(Object.entries(seed.kept ?? {}));
  const calls: SecretCall[] = [];
  const listeners = new Set<() => void>();
  let commits = 0;
  let notice = seed.notice ?? null;

  const takeNotice = (): StoreRecovery | null => {
    const held = notice;
    notice = null;
    return held;
  };

  const store: HostsStoreIo = {
    async get<T>(key: string): Promise<T | null> {
      return (data[key] as T | undefined) ?? null;
    },
    async set(key: string, value: unknown): Promise<void> {
      data[key] = value;
    },
    async commit(): Promise<void> {
      if (seed.fail?.commit) throw new Error(seed.fail.commit);
      commits++;
      for (const l of listeners) l();
    },
    // The REAL queue, so the serialization check below exercises the shipped one
    // rather than a copy of it living in this file.
    enqueueWrite: createWriteQueue(),
    async onChanged(cb: () => void): Promise<() => void> {
      listeners.add(cb);
      return () => void listeners.delete(cb);
    },
    ensureLoaded: async () => takeNotice(),
    takeRecoveryNotice: takeNotice,
  };

  const secrets: SecretsIo = {
    async getAll(service, accounts) {
      calls.push({ op: "getAll", service, accounts });
      return accounts.map((a) => kept.get(`${service}::${a}`) ?? null);
    },
    async set(service, account, value) {
      calls.push({ op: "set", service, accounts: [account] });
      if (seed.fail?.setAccount === account) throw new Error(`keychain refused ${account}`);
      if (seed.slowSet) {
        for (let i = 0; i < SLOW_SET_TICKS; i++) await Promise.resolve();
      }
      kept.set(`${service}::${account}`, value);
    },
    async delete(service, account) {
      calls.push({ op: "delete", service, accounts: [account] });
      if (seed.fail?.deleteAccount === account) {
        throw new Error(`keychain refused to delete ${account}`);
      }
      kept.delete(`${service}::${account}`);
    },
  };

  // The two OLD store files, read straight off the filesystem by the legacy
  // purge. `write` throws: the purge must never touch a store file, only the
  // keychain accounts those files name.
  const fileReads: string[] = [];
  const files: StoreFileIo = {
    async dir() {
      if (seed.fail?.dir) throw new Error(seed.fail.dir);
      return "/data";
    },
    async read(path) {
      fileReads.push(path);
      return seed.legacy?.[path.slice(path.lastIndexOf("/") + 1)] ?? { kind: "missing" };
    },
    async write(path) {
      throw new Error(`hosts-store-verify: nothing here may write ${path}`);
    },
  };

  const hosts = createHostsStore({ store, secrets, files });
  // Just enough of a vault for `resolveSshAuth` to dereference an identity
  // binding. The real store satisfies the same two-method shape.
  const deps: ResolveDeps = {
    vault: {
      findIdentity: async (id) => (seed.identities ?? []).find((i) => i.id === id),
      findKey: async (id) => (seed.keys ?? []).find((k) => k.id === id),
    },
    secrets,
  };
  return {
    hosts,
    secrets,
    deps,
    kept,
    calls,
    data,
    fileReads,
    commits: () => commits,
    reads: () => calls.filter((c) => c.op === "getAll"),
    deletes: () => calls.filter((c) => c.op === "delete").map((c) => c.accounts[0]),
    rows: () => data[HOSTS_KEY] as Host[],
    groupRows: () => data[HOST_GROUPS_KEY] as HostGroup[],
  };
}

const sshHost = (over: Partial<SshHost> = {}): SshHost => ({
  id: over.id ?? "h-ssh",
  name: "prod",
  host: "prod.example",
  port: 22,
  protocol: "ssh",
  credential: {
    kind: "inline",
    hostId: over.id ?? "h-ssh",
    user: "root",
    authMode: "password",
    hasPassword: false,
    hasPrivateKey: false,
    hasKeyPassphrase: false,
  },
  ...over,
});

const rdpHost = (over: Partial<RdpHost> = {}): RdpHost => ({
  id: over.id ?? "h-rdp",
  name: "vps",
  host: "vps.example",
  port: 3389,
  protocol: "rdp",
  credential: { kind: "inline", hostId: over.id ?? "h-rdp", username: "admin", hasPassword: false },
  desktopWidth: 1600,
  desktopHeight: 900,
  sizeMode: "preset",
  ...over,
});

const HOSTS_SERVICE = "tervia-hosts";
const at = (hostId: string, field: string): string => `${HOSTS_SERVICE}::${hostId}::${field}`;

/** An agent-auth SSH host, which reads no keychain accounts at all - so a chain
 *  of them keeps `resolveJumpHops` about the walk rather than about secrets. */
const agentHop = (id: string, jump?: string): SshHost =>
  sshHost({
    id,
    name: id,
    host: `${id}.example`,
    credential: {
      kind: "inline",
      hostId: id,
      user: "hop",
      authMode: "agent",
      hasPassword: false,
      hasPrivateKey: false,
      hasKeyPassphrase: false,
    },
    ...(jump ? { proxyJumpId: jump } : {}),
  });

/**
 * The narrowing the union exists for, exercised rather than asserted.
 *
 * This function does not compile if `credential` lives on `HostBase`: the RDP
 * guard would leave the binding a two-protocol union, where `username` and `user`
 * are each a type error. Everything it reads - `desktopWidth`, `sizeMode`,
 * `proxyJumpId` - is reachable only through the `protocol` guard.
 */
function describe(host: Host): string {
  if (host.protocol === "rdp") {
    const who =
      host.credential.kind === "inline" ? host.credential.username : host.credential.identityId;
    return `rdp ${host.desktopWidth}x${host.desktopHeight}/${host.sizeMode} as ${who}`;
  }
  const who = host.credential.kind === "inline" ? host.credential.user : host.credential.identityId;
  return `ssh via ${host.proxyJumpId ?? "direct"} as ${who}`;
}

// ---------------------------------------------------------------------------
console.log("\n[ids] a new record gets an opaque, prefixed id");
{
  const h = harness();
  assert(/^h-[a-z0-9]{8,}$/.test(h.hosts.newHostId()), "host ids are h-prefixed");
  assert(/^g-[a-z0-9]{8,}$/.test(h.hosts.newGroupId()), "group ids are g-prefixed");
  assert(h.hosts.newHostId() !== h.hosts.newHostId(), "two ids differ");
}

// ---------------------------------------------------------------------------
console.log("\n[narrowing] one `protocol` guard narrows the record AND its credential");
{
  const h = harness();
  const ssh = await h.hosts.upsertHost(sshHost({ id: "h-1" }));
  const rdp = await h.hosts.upsertHost(rdpHost({ id: "h-2" }));

  check(
    "the RDP guard reaches the desktop fields and the RDP arm",
    describe(rdp),
    "rdp 1600x900/preset as admin",
  );
  check(
    "the SSH guard reaches proxyJumpId and the SSH arm",
    describe(ssh),
    "ssh via direct as root",
  );
  check(
    "an identity binding narrows through the same guard",
    describe(rdpHost({ id: "h-3", credential: { kind: "identity", identityId: "i-7" } })),
    "rdp 1600x900/preset as i-7",
  );
  assert(isSshHost(ssh) && !isRdpHost(ssh), "isSshHost / isRdpHost agree on an SSH row");
  assert(isRdpHost(rdp) && !isSshHost(rdp), "and on an RDP row");
  check("presets round-trip", presetIdFor(1600, 900), "1600x900");
  check("a size no preset offers is not invented", presetIdFor(1234, 567), "");
  check("presetById resolves the default", presetById("1600x900")?.height, 900);
}

// ---------------------------------------------------------------------------
console.log("\n[binding] an inline credential must name the host storing it");
{
  const h = harness();
  const source = await h.hosts.upsertHost(sshHost({ id: "h-1" }), { password: "hunter2" });

  // The live hazard, verbatim: a duplicate action written as a spread copy. It is
  // well-typed, and its binding still names h-1.
  await rejects(
    "a spread-copy duplicate is refused on write",
    () => h.hosts.upsertHost({ ...source, id: "h-copy" }),
    ["h-1", "h-copy", "original"],
  );
  check("and nothing was persisted for it", await h.hosts.findHost("h-copy"), undefined);
  check(
    "so the source's password is still the source's alone",
    h.kept.get(at("h-1", "password")),
    "hunter2",
  );

  await rejects(
    "the same refusal on the RDP arm",
    () => h.hosts.upsertHost({ ...rdpHost({ id: "h-2" }), id: "h-2b" }),
    ["h-2", "h-2b"],
  );
  await rejects(
    "a half-built record with no host id on either side is refused, not passed through",
    () =>
      h.hosts.upsertHost(
        sshHost({
          id: "",
          credential: {
            kind: "inline",
            hostId: "",
            user: "root",
            authMode: "agent",
            hasPassword: false,
            hasPrivateKey: false,
            hasKeyPassphrase: false,
          },
        }),
      ),
    ["host id on both sides"],
  );
  // The builder derives the binding's `hostId` from the row's own id, which is
  // what a correctly written duplicate does by hand.
  check(
    "a correctly rebound copy saves",
    (await h.hosts.upsertHost(sshHost({ id: "h-ok" }))).id,
    "h-ok",
  );
}

// ---------------------------------------------------------------------------
console.log("\n[duplicate] a copy owns its own secrets and inherits no pin");
{
  const h = harness();
  await h.hosts.upsertHost(
    sshHost({
      id: "h-1",
      lastFingerprint: "SHA256:AAA",
      lastConnectedAt: 1_700_000_000_000,
      description: "the bastion",
    }),
    { password: "hunter2", keyPassphrase: "letmein" },
  );

  const copy = await h.hosts.duplicateHost("h-1");
  assert(copy !== null && copy.id !== "h-1", "the copy gets a new id");
  if (copy === null || copy.protocol !== "ssh") {
    throw new Error("hosts-store-verify: the SSH duplicate came back as the wrong shape");
  }
  check("named as a copy", copy.name, "prod (copy)");
  check("carrying the fields that describe the machine", copy.description, "the bastion");
  check(
    "its binding names ITSELF, not the source",
    copy.credential.kind === "inline" ? copy.credential.hostId : null,
    copy.id,
  );
  check("the pinned server key is NOT inherited", hostFingerprint(copy), undefined);
  check("nor is the last-connected stamp", copy.lastConnectedAt, undefined);
  check(
    "the SSH secrets travelled to the copy's OWN accounts",
    [h.kept.get(at(copy.id, "password")), h.kept.get(at(copy.id, "keyPassphrase"))],
    ["hunter2", "letmein"],
  );
  check(
    "with the flags to match",
    copy.credential.kind === "inline"
      ? [
          copy.credential.hasPassword,
          copy.credential.hasKeyPassphrase,
          copy.credential.hasPrivateKey,
        ]
      : null,
    [true, true, false],
  );
  check("and the source's accounts untouched", h.kept.get(at("h-1", "password")), "hunter2");

  // Rotating one must not rotate the other - the whole point of rebinding.
  await h.hosts.upsertHost(copy, { password: "rotated" });
  check("rotating the copy leaves the source alone", h.kept.get(at("h-1", "password")), "hunter2");
  check("and changes the copy", h.kept.get(at(copy.id, "password")), "rotated");

  check("nothing was duplicated by accident", (await h.hosts.listHosts()).length, 2);
}

// ---------------------------------------------------------------------------
console.log("\n[duplicate] an RDP password does not travel, and no read-back exists for one");
{
  const h = harness();
  await h.hosts.upsertHost(rdpHost({ id: "h-2", certFingerprint: "SHA256:CERT" }), {
    password: "s3cret",
  });
  const before = h.reads().length;

  const copy = await h.hosts.duplicateHost("h-2");
  if (copy === null || copy.protocol !== "rdp") {
    throw new Error("hosts-store-verify: RDP duplicate returned the wrong shape");
  }
  check("the pinned certificate is not inherited", copy.certFingerprint, undefined);
  check(
    "the copy claims no password",
    copy.credential.kind === "inline" ? copy.credential.hasPassword : null,
    false,
  );
  check("and none was stored for it", h.kept.has(at(copy.id, "password")), false);
  check("the source keeps its own", h.kept.get(at("h-2", "password")), "s3cret");
  check("no keychain read happened to duplicate it", h.reads().length, before);
  check("and the editor path offers none either", await h.hosts.getHostSshSecrets("h-2"), {});
  check("still no read", h.reads().length, before);
}

// ---------------------------------------------------------------------------
console.log("\n[duplicate] a copy of a secret-less host writes nothing to the keychain");
{
  // `secrets_get_all` reports an absent account as `null`, and `null` is the CLEAR
  // instruction - so passing the batch straight through issued three
  // `secrets_delete` calls against accounts the copy never had.
  const h = harness({ hosts: [sshHost({ id: "h-1" })] });
  const copy = await h.hosts.duplicateHost("h-1");
  check("the copy saved", copy?.id !== "h-1" && copy !== null, true);
  check("with no delete issued for it", h.deletes(), []);
  check("and no write either", h.calls.filter((c) => c.op === "set").length, 0);
  check(
    "so its flags are all false, from the store rather than from a read-back",
    copy?.credential.kind === "inline" && copy.protocol === "ssh"
      ? [
          copy.credential.hasPassword,
          copy.credential.hasPrivateKey,
          copy.credential.hasKeyPassphrase,
        ]
      : null,
    [false, false, false],
  );
}

// ---------------------------------------------------------------------------
console.log("\n[duplicate] a vault-bound copy shares the identity instead of the secrets");
{
  const h = harness();
  await h.hosts.upsertHost(
    sshHost({ id: "h-1", credential: { kind: "identity", identityId: "i-1" } }),
  );
  const copy = await h.hosts.duplicateHost("h-1");
  check("the binding is carried as-is", copy?.credential, { kind: "identity", identityId: "i-1" });
  check("and no host account was written", h.kept.size, 0);
  check("nor read", h.reads().length, 0);
}

// ---------------------------------------------------------------------------
console.log("\n[refs] a jump or tunnel host must exist, must be SSH, and must not be self");
{
  const h = harness();
  await h.hosts.upsertHost(sshHost({ id: "h-ssh" }));
  await h.hosts.upsertHost(rdpHost({ id: "h-rdp" }));

  await rejects(
    "an RDP host is refused as a proxyJumpId",
    () => h.hosts.upsertHost(sshHost({ id: "h-3", proxyJumpId: "h-rdp" })),
    ["rdp host", "jump host"],
  );
  await rejects(
    "an RDP host is refused as a tunnel.sshHostId",
    () => h.hosts.upsertHost(rdpHost({ id: "h-4", tunnel: { sshHostId: "h-rdp" } })),
    ["rdp host", "tunnel host"],
  );
  await rejects(
    "a jump host that does not exist is refused",
    () => h.hosts.upsertHost(sshHost({ id: "h-5", proxyJumpId: "h-gone" })),
    ["does not exist"],
  );
  await rejects(
    "a host cannot be its own jump host",
    () => h.hosts.upsertHost(sshHost({ id: "h-6", proxyJumpId: "h-6" })),
    ["its own jump host"],
  );
  await rejects(
    "a tunnel naming nothing is refused",
    () => h.hosts.upsertHost(rdpHost({ id: "h-7", tunnel: { sshHostId: "" } })),
    ["names no ssh host"],
  );
  check(
    "an SSH jump host is accepted",
    (await h.hosts.upsertHost(sshHost({ id: "h-8", proxyJumpId: "h-ssh" }))).id,
    "h-8",
  );
  check(
    "and an SSH tunnel host is too",
    (await h.hosts.upsertHost(rdpHost({ id: "h-9", tunnel: { sshHostId: "h-ssh" } }))).id,
    "h-9",
  );
  check("only the accepted rows landed", (await h.hosts.listHosts()).length, 4);
}

// ---------------------------------------------------------------------------
console.log("\n[jumps] the chain resolves in connect order, once per hop");
{
  const identity: VaultIdentity = {
    id: "i-1",
    name: "root @ prod",
    username: "vaulted",
    authMode: "password",
    hasPassword: true,
  };
  const h = harness({
    hosts: [
      agentHop("j-entry"),
      { ...agentHop("j-mid", "j-entry"), credential: { kind: "identity", identityId: "i-1" } },
      sshHost({ id: "h-target", proxyJumpId: "j-mid" }),
    ],
    identities: [identity],
    kept: { "tervia-vault::i-1::password": "from-the-vault" },
  });

  const all = await h.hosts.listHosts();
  const hops = await resolveJumpHops("j-mid", "h-target", all, h.deps);
  check(
    "hops come back entry-host first",
    hops.map((x) => x.connectionId),
    ["j-entry", "j-mid"],
  );
  check("an agent hop is built with no credential in it at all", hops[0], {
    connectionId: "j-entry",
    host: "j-entry.example",
    port: 22,
    user: "hop",
    useAgent: true,
  });
  check("a vault-bound hop resolves through the identity, not the host accounts", hops[1], {
    connectionId: "j-mid",
    host: "j-mid.example",
    port: 22,
    user: "vaulted",
    password: "from-the-vault",
  });
  // The call LOG, not the hop shape: the agent hop's empty credential is what the
  // check above proves, and this is what proves it cost no IPC. One read for the
  // whole chain, against the vault, for the one hop that has an identity.
  check(
    "the only keychain read in the whole chain is the vault identity's",
    h.reads().flatMap((c) => c.accounts.map((a) => `${c.service}::${a}`)),
    ["tervia-vault::i-1::password"],
  );
  check("no jump host is no hops", await resolveJumpHops(undefined, "h-target", all, h.deps), []);
}

// ---------------------------------------------------------------------------
console.log("\n[refs] a jump chain that closes a cycle is refused at WRITE time");
{
  // `assertSshTarget` catches the 1-cycle and the dangling id. Only the walk
  // catches A -> B -> A, which otherwise saved on both sides and then failed every
  // connect to EITHER host - the asymmetry with the dangling-id refusal is the bug.
  const h = harness();
  await h.hosts.upsertHost(agentHop("a"));
  await h.hosts.upsertHost(agentHop("b", "a"));
  await rejects(
    "editing A to jump through B closes a 2-cycle and is refused",
    () => h.hosts.upsertHost(agentHop("a", "b")),
    ["cycle"],
  );
  const a = await h.hosts.findHost("a");
  check(
    "so A is still stored with no jump host",
    a?.protocol === "ssh" ? a.proxyJumpId : "?",
    undefined,
  );

  await h.hosts.upsertHost(agentHop("c", "b"));
  await rejects("a three-host cycle is refused too", () => h.hosts.upsertHost(agentHop("a", "c")), [
    "cycle",
  ]);
  check(
    "while a longer straight chain still saves",
    (await h.hosts.upsertHost(agentHop("d", "c"))).id,
    "d",
  );

  // A cycle can no longer be CREATED, so the only way to meet one is a row an
  // import or another window put there - which is why the resolve-time check stays
  // as well. Seeded past the guard, the way an import would.
  const imported = harness({ hosts: [agentHop("a", "b"), agentHop("b", "a")] });
  await rejects(
    "a jump into an already-cyclic chain is refused",
    () => imported.hosts.upsertHost(sshHost({ id: "h-new", proxyJumpId: "a" })),
    ["cycle"],
  );
  await rejects(
    "and so is an RDP tunnel into one, which resolves the same chain",
    () => imported.hosts.upsertHost(rdpHost({ id: "h-r", tunnel: { sshHostId: "a" } })),
    ["cycle"],
  );
  check("neither row landed", imported.rows().length, 2);
}

// ---------------------------------------------------------------------------
console.log("\n[jumps] a cycle, a gap, an RDP hop and an over-long chain all throw");
{
  const cyclic = harness({
    hosts: [agentHop("a", "b"), agentHop("b", "a"), sshHost({ id: "h-t", proxyJumpId: "a" })],
  });
  const all = await cyclic.hosts.listHosts();
  await rejects(
    "a two-host cycle throws instead of looping",
    () => resolveJumpHops("a", "h-t", all, cyclic.deps),
    ["cycle"],
  );
  await rejects(
    "a host that jumps through itself throws",
    () => resolveJumpHops("h-self", "h-self", [agentHop("h-self", "h-self")], cyclic.deps),
    ["cycle"],
  );
  await rejects(
    "a deleted hop throws rather than silently dialling direct",
    () => resolveJumpHops("h-gone", "h-t", all, cyclic.deps),
    ["no longer exists"],
  );

  const mixed = harness({ hosts: [rdpHost({ id: "h-rdp" }), sshHost({ id: "h-t" })] });
  const mixedAll = await mixed.hosts.listHosts();
  await rejects(
    "an RDP host is refused as a hop at resolve time too",
    () => resolveJumpHops("h-rdp", "h-t", mixedAll, mixed.deps),
    ["rdp host", "jump host"],
  );

  // The cap counts hops, so a chain of exactly MAX is legal and MAX+1 is not.
  const chain = (n: number): SshHost[] =>
    Array.from({ length: n }, (_, i) => agentHop(`j-${i}`, i + 1 < n ? `j-${i + 1}` : undefined));
  const capped = harness({ hosts: chain(MAX_JUMP_HOPS) });
  check(
    `a chain of exactly ${MAX_JUMP_HOPS} hops resolves`,
    (await resolveJumpHops("j-0", "h-t", await capped.hosts.listHosts(), capped.deps)).length,
    MAX_JUMP_HOPS,
  );
  const over = harness({ hosts: chain(MAX_JUMP_HOPS + 1) });
  const overAll = await over.hosts.listHosts();
  await rejects(
    `a chain of ${MAX_JUMP_HOPS + 1} throws`,
    () => resolveJumpHops("j-0", "h-t", overAll, over.deps),
    ["too long"],
  );
}

// ---------------------------------------------------------------------------
console.log("\n[flags] presence flags track writes, and never read a secret back");
{
  const h = harness();
  const created = await h.hosts.upsertHost(sshHost({ id: "h-1" }), {
    password: "hunter2",
    privateKey: "PEM-BODY",
  });
  const flags = (host: Host | undefined): unknown =>
    host && host.protocol === "ssh" && host.credential.kind === "inline"
      ? [
          host.credential.hasPassword,
          host.credential.hasPrivateKey,
          host.credential.hasKeyPassphrase,
        ]
      : null;

  check("a written password and key set their flags", flags(created), [true, true, false]);
  check("they landed on the hosts service", h.kept.get(at("h-1", "privateKey")), "PEM-BODY");
  check("no secret was read to decide any flag", h.reads().length, 0);

  // The three-state convention. The input carries every flag deliberately WRONG,
  // so this can tell reading the stored record from echoing the caller.
  const renamed = await h.hosts.upsertHost(
    sshHost({
      id: "h-1",
      name: "renamed",
      credential: {
        kind: "inline",
        hostId: "h-1",
        user: "root",
        authMode: "password",
        hasPassword: false,
        hasPrivateKey: false,
        hasKeyPassphrase: true,
      },
    }),
  );
  check("an edit that skips the fields takes the flags from the STORE", flags(renamed), [
    true,
    true,
    false,
  ]);
  check("and that is what got persisted", flags(await h.hosts.findHost("h-1")), [
    true,
    true,
    false,
  ]);
  check("the secrets are still there", h.kept.get(at("h-1", "password")), "hunter2");
  check("and still nothing was read back", h.reads().length, 0);

  const cleared = await h.hosts.upsertHost(renamed, { password: "  " });
  check("a whitespace-only password clears the flag", flags(cleared), [false, true, false]);
  check("and removes the entry", h.kept.has(at("h-1", "password")), false);
  check("without disturbing the key", h.kept.get(at("h-1", "privateKey")), "PEM-BODY");

  // A brand-new record starts from what is STORED, not from the flags it carries.
  const fresh = await h.hosts.upsertHost(
    sshHost({
      id: "h-2",
      credential: {
        kind: "inline",
        hostId: "h-2",
        user: "root",
        authMode: "key",
        hasPassword: true,
        hasPrivateKey: true,
        hasKeyPassphrase: true,
      },
    }),
  );
  check("a new host claiming secrets it has none of is forced to all-false", flags(fresh), [
    false,
    false,
    false,
  ]);
  check("still no read-back", h.reads().length, 0);
}

// ---------------------------------------------------------------------------
console.log("\n[flags] an RDP row owns one account and refuses key material");
{
  const h = harness();
  const created = await h.hosts.upsertHost(rdpHost({ id: "h-2" }), { password: "s3cret" });
  check(
    "the password flag tracks the write",
    created.credential.kind === "inline" ? created.credential.hasPassword : null,
    true,
  );
  await rejects(
    "a private key against an RDP row is refused, not dropped",
    () => h.hosts.upsertHost(created, { privateKey: "PEM-BODY" }),
    ["rdp host", "no key material"],
  );
  check(
    "so nothing landed at an account nothing reads",
    h.kept.has(at("h-2", "privateKey")),
    false,
  );
  check("and the password survived the refusal", h.kept.get(at("h-2", "password")), "s3cret");
}

// ---------------------------------------------------------------------------
console.log("\n[accounts] no secret outlives the record naming it");
{
  // A partial write on a BRAND-NEW host rolls back, or the first secret sits at an
  // account no record names - and there is no `secrets_list` to find it with.
  const broken = harness({ fail: { setAccount: "h-1::privateKey" } });
  await rejects(
    "a write that throws partway is reported",
    () => broken.hosts.upsertHost(sshHost({ id: "h-1" }), { password: "hunter2", privateKey: "X" }),
    ["keychain refused"],
  );
  check("and the secret that DID land is cleared again", broken.kept.size, 0);
  check("with no half-written row persisted", (await broken.hosts.listHosts()).length, 0);

  // For a host that already exists the accounts stay reachable through
  // `deleteHost`, so clearing them would destroy a secret this layer cannot
  // restore - it never reads one.
  const existing = harness();
  await existing.hosts.upsertHost(sshHost({ id: "h-1" }), { password: "keepme" });
  const h2 = harness({
    hosts: await existing.hosts.listHosts(),
    kept: { [at("h-1", "password")]: "keepme" },
    fail: { setAccount: "h-1::privateKey" },
  });
  await rejects(
    "the same failure against an existing host is reported",
    () => h2.hosts.upsertHost(sshHost({ id: "h-1" }), { privateKey: "X" }),
    ["keychain refused"],
  );
  check("but its stored password is NOT rolled back", h2.kept.get(at("h-1", "password")), "keepme");

  // Moving a credential into the vault releases the accounts the host used to
  // own, which nothing would ever name again.
  const moved = harness();
  await moved.hosts.upsertHost(sshHost({ id: "h-1" }), {
    password: "hunter2",
    privateKey: "PEM",
    keyPassphrase: "pp",
  });
  check("three accounts to start with", moved.kept.size, 3);
  await moved.hosts.upsertHost(
    sshHost({ id: "h-1", credential: { kind: "identity", identityId: "i-1" } }),
  );
  check("binding to an identity releases all three", moved.kept.size, 0);
  check(
    "and each was deleted by name",
    moved
      .deletes()
      .filter((a) => a.startsWith("h-1::"))
      .sort(),
    ["h-1::keyPassphrase", "h-1::password", "h-1::privateKey"],
  );

  // A protocol change releases only what the new arm cannot NAME. `password` has
  // the same account name on both, so it stays - and the FLAG has to stay with it.
  // Reading the flag off the new arm alone reported `hasPassword: false` over a
  // password still in the keychain, which `resolveRdpAuth` hands `rdp_open`
  // UNCONDITIONALLY: the backend authenticates with a secret the record denies.
  const flipped = harness();
  await flipped.hosts.upsertHost(sshHost({ id: "h-1" }), { password: "pw", privateKey: "PEM" });
  const asRdp = await flipped.hosts.upsertHost(rdpHost({ id: "h-1" }));
  const rdpFlag = (host: Host | undefined): unknown =>
    host && host.protocol === "rdp" && host.credential.kind === "inline"
      ? host.credential.hasPassword
      : null;
  check("the key material is released", flipped.kept.has(at("h-1", "privateKey")), false);
  check("the password is kept", flipped.kept.get(at("h-1", "password")), "pw");
  check(
    "and the flag AGREES with the keychain, on the record and as returned",
    [
      rdpFlag(asRdp),
      rdpFlag(await flipped.hosts.findHost("h-1")),
      flipped.kept.has(at("h-1", "password")),
    ],
    [true, true, true],
  );

  // The reverse flip is the same defect through `sshAccountsFor`, which resolves
  // by auth mode and never consults a flag either. The input carries every flag
  // deliberately wrong, so this cannot be the caller's own values echoed back.
  const asSsh = await flipped.hosts.upsertHost(sshHost({ id: "h-1" }));
  const sshFlags = (host: Host | undefined): unknown =>
    host && host.protocol === "ssh" && host.credential.kind === "inline"
      ? [
          host.credential.hasPassword,
          host.credential.hasPrivateKey,
          host.credential.hasKeyPassphrase,
        ]
      : null;
  check("flipping back keeps the password and its flag", sshFlags(asSsh), [true, false, false]);
  check("which is still what is stored", flipped.kept.get(at("h-1", "password")), "pw");
  check(
    "and it claims no key material, which really is gone",
    [flipped.kept.has(at("h-1", "privateKey")), flipped.kept.has(at("h-1", "keyPassphrase"))],
    [false, false],
  );
  check("no flag was decided by reading a secret back", flipped.reads().length, 0);

  // A binding moving to the vault DOES release `password`, so the flag it comes
  // back with must be false - the "carry it across" rule is about the account
  // surviving, not about the field name.
  const vaulted = harness();
  await vaulted.hosts.upsertHost(sshHost({ id: "h-1" }), { password: "pw" });
  await vaulted.hosts.upsertHost(
    sshHost({ id: "h-1", credential: { kind: "identity", identityId: "i-1" } }),
  );
  const detached = await vaulted.hosts.upsertHost(rdpHost({ id: "h-1" }));
  check(
    "a vault round-trip leaves no account and no flag",
    [
      vaulted.kept.size,
      detached.credential.kind === "inline" ? detached.credential.hasPassword : null,
    ],
    [0, false],
  );
}

// ---------------------------------------------------------------------------
console.log("\n[accounts] the release happens AFTER the record is written, never before");
{
  // The order is the whole point (§5.3). A protocol change has no copy step, so
  // releasing first and then failing to persist destroys the user's only copy of a
  // key while the stored record still claims it - and this layer never reads a
  // secret, so it cannot put one back.
  const torn = harness({
    hosts: [
      sshHost({
        id: "h-1",
        credential: {
          kind: "inline",
          hostId: "h-1",
          user: "root",
          authMode: "key",
          hasPassword: false,
          hasPrivateKey: true,
          hasKeyPassphrase: true,
        },
      }),
    ],
    kept: { [at("h-1", "privateKey")]: "PEM-ONLY-COPY", [at("h-1", "keyPassphrase")]: "pp" },
    fail: { commit: "the data directory is read-only" },
  });
  await rejects(
    "a persist that throws on a protocol change is reported",
    () => torn.hosts.upsertHost(rdpHost({ id: "h-1" })),
    ["read-only"],
  );
  check(
    "and the key material the stored record still names is untouched",
    [torn.kept.get(at("h-1", "privateKey")), torn.kept.get(at("h-1", "keyPassphrase"))],
    ["PEM-ONLY-COPY", "pp"],
  );
  check("no delete was even attempted", torn.deletes().length, 0);

  // The residual worst case, which §5.3 ranks as the lesser evil: a good write
  // followed by a release that fails. It must say the record WAS saved, or the
  // user re-enters an edit that already landed.
  const orphan = harness({
    hosts: [
      sshHost({
        id: "h-1",
        credential: {
          kind: "inline",
          hostId: "h-1",
          user: "root",
          authMode: "key",
          hasPassword: false,
          hasPrivateKey: true,
          hasKeyPassphrase: false,
        },
      }),
    ],
    kept: { [at("h-1", "privateKey")]: "PEM" },
    fail: { deleteAccount: "h-1::privateKey" },
  });
  await rejects(
    "a release that fails after a good write names the orphan, not a failed save",
    () => orphan.hosts.upsertHost(rdpHost({ id: "h-1" })),
    ["was saved", "privateKey", "unreachable"],
  );
  check(
    "and the record on disk is the NEW one",
    (await orphan.hosts.findHost("h-1"))?.protocol,
    "rdp",
  );
}

// ---------------------------------------------------------------------------
console.log("\n[vault] a vault-bound host owns no accounts");
{
  const h = harness();
  await rejects(
    "a secret handed to a vault-bound host is refused, not written where nothing reads it",
    () =>
      h.hosts.upsertHost(
        sshHost({ id: "h-1", credential: { kind: "identity", identityId: "i-1" } }),
        {
          password: "hunter2",
        },
      ),
    ["vault identity", "password"],
  );
  check("nothing was stored", h.kept.size, 0);

  await h.hosts.upsertHost(
    sshHost({ id: "h-1", credential: { kind: "identity", identityId: "i-1" } }),
  );
  await h.hosts.upsertHost(
    rdpHost({ id: "h-2", credential: { kind: "identity", identityId: "i-1" } }),
  );
  await h.hosts.upsertHost(
    sshHost({ id: "h-3", credential: { kind: "identity", identityId: "i-2" } }),
  );
  await h.hosts.upsertHost(sshHost({ id: "h-4" }));

  check(
    "identityHostRefs names every host bound to one identity, across protocols",
    await h.hosts.identityHostRefs("i-1"),
    [
      { id: "h-1", name: "prod" },
      { id: "h-2", name: "vps" },
    ],
  );
  check("an unused identity has no holders", await h.hosts.identityHostRefs("i-9"), []);
}

// ---------------------------------------------------------------------------
console.log("\n[delete] a deleted host takes its accounts and every reference to it");
{
  const h = harness();
  await h.hosts.upsertHost(sshHost({ id: "h-jump" }), { password: "jumppw" });
  await h.hosts.upsertHost(sshHost({ id: "h-via", proxyJumpId: "h-jump" }));
  await h.hosts.upsertHost(rdpHost({ id: "h-tun", tunnel: { sshHostId: "h-jump" } }));
  await h.hosts.upsertHost(sshHost({ id: "h-other", proxyJumpId: "h-via" }));

  const cleaned: string[] = [];
  await h.hosts.deleteHost("h-jump", (hostId) => void cleaned.push(hostId));

  check("the row is gone", await h.hosts.findHost("h-jump"), undefined);
  check("its account is gone", h.kept.has(at("h-jump", "password")), false);
  const via = await h.hosts.findHost("h-via");
  check(
    "the host that jumped through it is cleared, not deleted",
    [via?.id, via?.protocol === "ssh" ? via.proxyJumpId : "?"],
    ["h-via", undefined],
  );
  const tun = await h.hosts.findHost("h-tun");
  check(
    "the RDP host that tunnelled through it is cleared, not deleted",
    [tun?.id, tun?.protocol === "rdp" ? tun.tunnel : "?"],
    ["h-tun", undefined],
  );
  const other = await h.hosts.findHost("h-other");
  check(
    "a reference to a DIFFERENT host is left alone",
    other?.protocol === "ssh" ? other.proxyJumpId : "?",
    "h-via",
  );
  check("the forward-rule cleanup was told which host went", cleaned, ["h-jump"]);
  check("three hosts remain", (await h.hosts.listHosts()).length, 3);

  // Fail closed: the rules and the host must not come apart.
  await h.hosts.upsertHost(sshHost({ id: "h-keep" }), { password: "keeppw" });
  await rejects(
    "a cleanup that throws aborts the delete",
    () =>
      h.hosts.deleteHost("h-keep", () => {
        throw new Error("forwards: the rule store is unreadable");
      }),
    ["rule store is unreadable"],
  );
  assert((await h.hosts.findHost("h-keep")) !== undefined, "the host is still there");
  check("and so is its account", h.kept.get(at("h-keep", "password")), "keeppw");

  // A `Promise<void>` resolving to `undefined` is `void`'s definition, so the only
  // thing worth asserting about a no-op is that the store did not move.
  const rowsBefore = JSON.stringify(h.rows());
  const callsBefore = h.calls.length;
  const alsoCleaned: string[] = [];
  await h.hosts.deleteHost("h-nope", (hostId) => void alsoCleaned.push(hostId));
  check(
    "deleting a host that is already gone changes no row",
    JSON.stringify(h.rows()),
    rowsBefore,
  );
  check("and touches no keychain account", h.calls.length, callsBefore);
  // Unconditional on purpose: a forward rule can name an id that is already gone,
  // and orphaning those rules is this sub-phase's job.
  check("but the forward-rule cleanup still runs for the id", alsoCleaned, ["h-nope"]);
  // The named stand-in is the only legal way to say "there are no rules here yet".
  await h.hosts.deleteHost("h-nope", noForwardRules);
  check("and the no-op stand-in is accepted", JSON.stringify(h.rows()), rowsBefore);
}

// ---------------------------------------------------------------------------
console.log("\n[groups] deleting a group clears the label and keeps the rows");
{
  const h = harness();
  await h.hosts.upsertGroup({ id: "g-1", name: "Production", order: 0 });
  await h.hosts.upsertGroup({ id: "g-2", name: "Staging" });
  await h.hosts.upsertHost(sshHost({ id: "h-1", groupId: "g-1" }), { password: "pw" });
  await h.hosts.upsertHost(rdpHost({ id: "h-2", groupId: "g-1" }));
  await h.hosts.upsertHost(sshHost({ id: "h-3", groupId: "g-2" }));

  // Against a LITERAL, not against what `upsertGroup` returned - that is the very
  // object the store persisted, so comparing the two proves persistence happened
  // and could not notice a mangled field.
  check("a group round-trips field for field", await h.hosts.findGroup("g-1"), {
    id: "g-1",
    name: "Production",
    order: 0,
  });
  await rejects("a group needs a name", () => h.hosts.upsertGroup({ id: "g-3", name: "  " }), [
    "needs a name",
  ]);
  await rejects(
    "and a name a person would read as taken is refused",
    () => h.hosts.upsertGroup({ id: "g-3", name: " production " }),
    ["already named"],
  );

  await h.hosts.deleteGroup("g-1");
  check("the group is gone", await h.hosts.findGroup("g-1"), undefined);
  check("its members are NOT", (await h.hosts.listHosts()).length, 3);
  check(
    "they lost only the label",
    (await h.hosts.listHosts()).map((x) => [x.id, x.groupId]),
    [
      ["h-1", undefined],
      ["h-2", undefined],
      ["h-3", "g-2"],
    ],
  );
  check("and kept their secrets", h.kept.get(at("h-1", "password")), "pw");
  check(
    "the other group is untouched",
    (await h.hosts.listGroups()).map((g) => g.id),
    ["g-2"],
  );
  const groupsBefore = JSON.stringify(h.groupRows());
  const rowsBefore = JSON.stringify(h.rows());
  await h.hosts.deleteGroup("g-1");
  check(
    "deleting a group that is gone leaves the group list alone",
    JSON.stringify(h.groupRows()),
    groupsBefore,
  );
  check("and the host list with it", JSON.stringify(h.rows()), rowsBefore);
}

// ---------------------------------------------------------------------------
console.log("\n[pins] one pin per host, in whichever field the protocol keeps it");
{
  // h-3 is reserved for the credential-stability check at the end of this block:
  // it must reach that check having been through no pin at all, or the baseline it
  // captures already carries whatever a broken pin path did to h-1.
  const h = harness({
    hosts: [sshHost({ id: "h-1" }), rdpHost({ id: "h-2" }), sshHost({ id: "h-3" })],
  });
  const pin = async (id: string): Promise<string | undefined> => {
    const host = await h.hosts.findHost(id);
    if (!host) return "MISSING";
    return hostFingerprint(host);
  };

  await h.hosts.pinFingerprint("h-1", "SHA256:KEY");
  await h.hosts.pinFingerprint("h-2", "SHA256:CERT");
  check("the SSH pin lands in lastFingerprint", await pin("h-1"), "SHA256:KEY");
  check("the RDP pin lands in certFingerprint", await pin("h-2"), "SHA256:CERT");
  check(
    "pinning does not claim a connect happened",
    (await h.hosts.findHost("h-1"))?.lastConnectedAt,
    undefined,
  );
  check(
    "the SSH pin did NOT land in the RDP field",
    (await h.hosts.listHosts()).map((x) => (x.protocol === "rdp" ? x.certFingerprint : null)),
    [null, "SHA256:CERT", null],
  );

  await h.hosts.markConnected("h-1", "");
  const marked = await h.hosts.findHost("h-1");
  check("a connect with no fingerprint keeps the pin", await pin("h-1"), "SHA256:KEY");
  assert((marked?.lastConnectedAt ?? 0) > 0, "and stamps the connect");

  await h.hosts.clearFingerprint("h-2");
  check("clearing drops the RDP pin", await pin("h-2"), undefined);
  check("without dropping anything else", (await h.hosts.findHost("h-2"))?.protocol, "rdp");
  const rowsBefore = JSON.stringify(h.rows());
  const callsBefore = h.calls.length;
  await h.hosts.pinFingerprint("h-x", "SHA256:Z");
  await h.hosts.markConnected("h-x", "SHA256:Z");
  await h.hosts.clearFingerprint("h-x");
  check("pinning a host that is gone writes no row", JSON.stringify(h.rows()), rowsBefore);
  check("and makes no keychain call", h.calls.length, callsBefore);

  // `assertBindingOwner` is called on ONE path, `upsertHost`. That is only
  // sufficient while the pin paths cannot change a credential, so that is checked
  // rather than asserted in a comment.
  //
  // Snapshotted as a STRING, not held as an object: `withFingerprint` spreads the
  // record, so the pinned copy shares the credential's object identity with the
  // original, and comparing the two live values passes even when one of them was
  // replaced. That aliasing is what made an earlier version of this check vacuous.
  const bindingOf = async (id: string): Promise<string> =>
    JSON.stringify((await h.hosts.findHost(id))?.credential ?? null);
  const ownerOf = async (id: string): Promise<string> => {
    const host = await h.hosts.findHost(id);
    if (!host) return "MISSING";
    return host.credential.kind === "inline" ? host.credential.hostId : "NOT-INLINE";
  };

  const beforePins = await bindingOf("h-3");
  await h.hosts.pinFingerprint("h-3", "SHA256:ROTATED");
  await h.hosts.markConnected("h-3", "SHA256:ROTATED");
  await h.hosts.clearFingerprint("h-3");
  check(
    "no pin path rewrites the credential, so upsertHost is the only guarded write",
    await bindingOf("h-3"),
    beforePins,
  );
  check("and the binding still names its own host", await ownerOf("h-3"), "h-3");
}

// ---------------------------------------------------------------------------
console.log("\n[queue] concurrent read-modify-writes do not lose an update");
{
  const h = harness({ hosts: [sshHost({ id: "h-1" }), agentHop("h-2"), rdpHost({ id: "h-3" })] });
  // A chained connect fires these near-simultaneously, one per hop plus the
  // target. Without one queue per store file, the last write wins and the others
  // silently revert to a TOFU prompt.
  await Promise.all([
    h.hosts.markConnected("h-1", "SHA256:ONE"),
    h.hosts.markConnected("h-2", "SHA256:TWO"),
    h.hosts.markConnected("h-3", "SHA256:THREE"),
  ]);
  check(
    "every pin survived",
    (await h.hosts.listHosts()).map((x) => hostFingerprint(x)),
    ["SHA256:ONE", "SHA256:TWO", "SHA256:THREE"],
  );

  // A rejection must not take the writes behind it with it.
  const results = await Promise.allSettled([
    h.hosts.upsertHost(sshHost({ id: "h-4", proxyJumpId: "h-rdp-gone" })),
    h.hosts.upsertHost(sshHost({ id: "h-5" })),
  ]);
  check(
    "a refused write does not kill the queue",
    results.map((r) => r.status),
    ["rejected", "fulfilled"],
  );
  assert((await h.hosts.findHost("h-5")) !== undefined, "the write behind it landed");
}

// ---------------------------------------------------------------------------
console.log("\n[queue] duplicateHost reads the source INSIDE the queue");
{
  // The read used to sit outside it, so another window rotating the source's
  // password between the read and the write left the copy holding the
  // pre-rotation value while claiming `hasPassword: true` - a copy that
  // authenticates with a password nobody has any more. `slowSet` makes the race
  // deterministic: an un-queued read resolves while the rotation's `secrets_set`
  // is still in flight.
  const h = harness({ hosts: [sshHost({ id: "h-1" })], slowSet: true });
  await h.hosts.upsertHost(sshHost({ id: "h-1" }), { password: "before" });

  const rotate = h.hosts.upsertHost(sshHost({ id: "h-1" }), { password: "after" });
  const dup = h.hosts.duplicateHost("h-1");
  const [, copy] = await Promise.all([rotate, dup]);
  if (copy === null) throw new Error("hosts-store-verify: the duplicate came back null");

  check("the source holds the rotated value", h.kept.get(at("h-1", "password")), "after");
  check(
    "and the copy carries THAT, not the value the rotation replaced",
    h.kept.get(at(copy.id, "password")),
    "after",
  );
  check(
    "with a flag that matches what it actually stored",
    copy.credential.kind === "inline" ? copy.credential.hasPassword : null,
    true,
  );
}

// ---------------------------------------------------------------------------
console.log("\n[recovery] the store layer hands the startup notice through");
{
  const h = harness({
    notice: { found: "empty", recovered: true, note: "restored from the snapshot" },
  });
  check(
    "ensureLoaded reaches the port",
    (await h.hosts.ensureLoaded())?.note,
    "restored from the snapshot",
  );
  check("and only fires once", await h.hosts.ensureLoaded(), null);
  check("sharing one slot with takeRecoveryNotice", h.hosts.takeRecoveryNotice(), null);

  let changes = 0;
  const stop = await h.hosts.onHostsChanged(() => changes++);
  await h.hosts.upsertHost(sshHost({ id: "h-1" }));
  check("a commit tells the other windows", changes, 1);
  stop();
  await h.hosts.upsertHost(sshHost({ id: "h-2" }));
  check("and stops when unsubscribed", changes, 1);
}

// ---------------------------------------------------------------------------
console.log("\n[purge] the two old connection stores' secrets are cleared once, by name only");
{
  const sshFile = (ids: string[]): StoreFileRead => ({
    kind: "text",
    content: JSON.stringify({ connections: ids.map((id) => ({ id, name: id, host: "x" })) }),
  });
  const legacy = (ssh: StoreFileRead, rdp: StoreFileRead): Record<string, StoreFileRead> => ({
    "tervia-ssh-connections.json": ssh,
    "tervia-rdp-connections.json": rdp,
  });

  // What makes this worth building at all: once the old modules are gone there is
  // no `secrets_list`, so `tervia-ssh :: <id>::privateKey` is a private key with no
  // delete button anywhere in the app, forever.
  const h = harness({
    legacy: legacy(sshFile(["c-1", "c-2"]), sshFile(["r-1"])),
    kept: {
      "tervia-ssh::c-1::password": "old-pw",
      "tervia-ssh::c-1::privateKey": "old-PEM",
      "tervia-ssh::c-1::keyPassphrase": "old-pp",
      "tervia-rdp::r-1::password": "old-rdp-pw",
      [at("h-1", "password")]: "current",
    },
  });
  const swept = await h.hosts.purgeLegacySecrets();
  check("both files were read, from the store directory", h.fileReads, [
    "/data/tervia-ssh-connections.json",
    "/data/tervia-rdp-connections.json",
  ]);
  check("every account either old service could own is cleared", swept.cleared.slice().sort(), [
    "tervia-rdp::r-1::password",
    "tervia-ssh::c-1::keyPassphrase",
    "tervia-ssh::c-1::password",
    "tervia-ssh::c-1::privateKey",
    "tervia-ssh::c-2::keyPassphrase",
    "tervia-ssh::c-2::password",
    "tervia-ssh::c-2::privateKey",
  ]);
  check("nothing failed", swept.failed, []);
  check(
    "the legacy secrets are gone",
    [
      h.kept.has("tervia-ssh::c-1::privateKey"),
      h.kept.has("tervia-ssh::c-1::password"),
      h.kept.has("tervia-rdp::r-1::password"),
    ],
    [false, false, false],
  );
  check("and a live host account is untouched", h.kept.get(at("h-1", "password")), "current");
  // The invariant that matters most here: it deletes by ACCOUNT NAME and never
  // learns a value, so no RDP password enters the webview even on the way out.
  check("no secret value was read", h.reads().length, 0);
  check(
    "and nothing but deletes reached either old service",
    h.calls
      .filter((c) => c.service === "tervia-ssh" || c.service === "tervia-rdp")
      .every((c) => c.op === "delete"),
    true,
  );

  const callsBefore = h.calls.length;
  const readsBefore = h.fileReads.length;
  const again = await h.hosts.purgeLegacySecrets();
  check("a second run is skipped by the marker", [again.skipped, again.cleared.length], [true, 0]);
  check("so the files are not re-read forever", h.fileReads.length, readsBefore);
  check("and the keychain is not touched again", h.calls.length, callsBefore);
}

// ---------------------------------------------------------------------------
console.log("\n[purge] a missing, empty, torn or unparseable file is nothing to do");
{
  // Every one of these is an ordinary launch, not an error: the app runs this on
  // every start, and a throw would take startup with it.
  const cases: [string, StoreFileRead, StoreFileRead][] = [
    ["missing", { kind: "missing" }, { kind: "missing" }],
    ["empty", { kind: "text", content: "" }, { kind: "text", content: "   \n" }],
    ["torn", { kind: "binary" }, { kind: "text", content: '{"connections":[{"id":"c-1"' }],
    [
      "unparseable",
      { kind: "text", content: '{"connections":"not a list"}' },
      { kind: "toolarge" },
    ],
  ];
  for (const [label, ssh, rdp] of cases) {
    const h = harness({
      legacy: {
        "tervia-ssh-connections.json": ssh,
        "tervia-rdp-connections.json": rdp,
      },
    });
    const result = await h.hosts.purgeLegacySecrets();
    check(
      `a file that is ${label} clears nothing and fails nothing`,
      [result.cleared, result.failed, h.calls.length],
      [[], [], 0],
    );
    check(`and one that is ${label} still records the pass`, h.data[LEGACY_PURGE_KEY], true);
  }

  // A row without a usable id is skipped rather than turned into `undefined::field`.
  const junk = harness({
    legacy: {
      "tervia-ssh-connections.json": {
        kind: "text",
        content: JSON.stringify({ connections: [null, 7, { id: "" }, { id: "c-1" }] }),
      },
      "tervia-rdp-connections.json": { kind: "missing" },
    },
  });
  const result = await junk.hosts.purgeLegacySecrets();
  check("only the rows that name an id are swept", result.cleared.slice().sort(), [
    "tervia-ssh::c-1::keyPassphrase",
    "tervia-ssh::c-1::password",
    "tervia-ssh::c-1::privateKey",
  ]);

  // No data directory means no way to know whether there was anything to purge.
  const nowhere = harness({ fail: { dir: "the app data directory is unreachable" } });
  const blind = await nowhere.hosts.purgeLegacySecrets();
  check(
    "an unreachable data directory is not success",
    [blind.cleared, blind.failed.length],
    [[], 1],
  );
  check("and leaves no marker", nowhere.data[LEGACY_PURGE_KEY], undefined);
}

// ---------------------------------------------------------------------------
console.log("\n[purge] one failed delete does not abort the sweep, and is not success");
{
  const h = harness({
    legacy: {
      "tervia-ssh-connections.json": {
        kind: "text",
        content: JSON.stringify({ connections: [{ id: "c-1" }, { id: "c-2" }] }),
      },
      "tervia-rdp-connections.json": {
        kind: "text",
        content: JSON.stringify({ connections: [{ id: "r-1" }] }),
      },
    },
    kept: { "tervia-ssh::c-1::privateKey": "stuck-PEM", "tervia-rdp::r-1::password": "old-rdp-pw" },
    fail: { deleteAccount: "c-1::privateKey" },
  });
  const result = await h.hosts.purgeLegacySecrets();
  check("the refusal is named", result.failed.length, 1);
  check(
    "every OTHER account is still cleared - the same id's, and the other file's",
    result.cleared.slice().sort(),
    [
      "tervia-rdp::r-1::password",
      "tervia-ssh::c-1::keyPassphrase",
      "tervia-ssh::c-1::password",
      "tervia-ssh::c-2::keyPassphrase",
      "tervia-ssh::c-2::password",
      "tervia-ssh::c-2::privateKey",
    ],
  );
  check(
    "the one it could not clear is still there",
    h.kept.get("tervia-ssh::c-1::privateKey"),
    "stuck-PEM",
  );
  // Reporting a partial purge as done is how a private key becomes permanently
  // unreachable: `secrets_delete` already treats an absent account as success, so
  // anything that throws is a real failure.
  check("a partial purge is NOT recorded as done", h.data[LEGACY_PURGE_KEY], undefined);
  const retry = await h.hosts.purgeLegacySecrets();
  check("so the next launch tries again", retry.skipped, false);
  check("and it is still not marked done", h.data[LEGACY_PURGE_KEY], undefined);
}

/** The three SSH presence flags, read off a record rather than asserted about
 *  one, so a check can compare a fresh read against what `upsertHost` returned. */
const sshFlags = (host: Host | undefined): unknown =>
  host && host.protocol === "ssh" && host.credential.kind === "inline"
    ? [host.credential.hasPassword, host.credential.hasPrivateKey, host.credential.hasKeyPassphrase]
    : null;

// ---------------------------------------------------------------------------
console.log("\n[flags] SECRET_ALREADY_STORED records presence and writes nothing");
{
  // The backup import's exact state: `backup_apply_secrets` put the value at the
  // account from Rust and handed JS a boolean, so this layer has a flag to set and
  // no value to set it with. Passing `undefined` instead takes the flag from a
  // record that does not exist yet - all false, over a live secret.
  const h = harness({ kept: { [at("h-imp", "password")]: "written-by-rust" } });
  const created = await h.hosts.upsertHost(
    sshHost({
      id: "h-imp",
      credential: {
        kind: "inline",
        hostId: "h-imp",
        user: "root",
        authMode: "password",
        // Fed in deliberately WRONG, so a pass here cannot be the store echoing
        // its caller: the answer must come from the sentinel and from the absence
        // of the other two, not from these.
        hasPassword: false,
        hasPrivateKey: true,
        hasKeyPassphrase: true,
      },
    }),
    { password: SECRET_ALREADY_STORED },
  );

  // Per FIELD, not per host: the declared one is true and the two silent ones are
  // false. A per-host answer would claim a private key that is not there.
  check("only the declared field's flag is set", sshFlags(created), [true, false, false]);
  // Off a FRESH read, never off what `upsertHost` handed back - a check that reads
  // the returned object cannot tell a persisted flag from an echoed one.
  check("and that is what got PERSISTED", sshFlags(await h.hosts.findHost("h-imp")), [
    true,
    false,
    false,
  ]);
  // The whole point of the sentinel: no set, no delete, and no READ either, so it
  // stays inside the no-read-back rule rather than becoming an exception to it.
  check("the keychain was not touched at all", h.calls, []);
  check(
    "and the value Rust wrote is exactly as it was",
    h.kept.get(at("h-imp", "password")),
    "written-by-rust",
  );
}

// ---------------------------------------------------------------------------
console.log("\n[flags] the sentinel sits alongside a real value and a left-alone field");
{
  const h = harness();
  const first = await h.hosts.upsertHost(sshHost({ id: "h-mix" }), { keyPassphrase: "pp" });
  check("the passphrase is the only flag so far", sshFlags(first), [false, false, true]);

  // Rust writes the private key straight to the account, the way the import does.
  h.kept.set(at("h-mix", "privateKey"), "PEM-FROM-RUST");
  const before = h.calls.length;
  const mixed = await h.hosts.upsertHost(first, {
    password: "typed-here",
    privateKey: SECRET_ALREADY_STORED,
    // keyPassphrase omitted: leave whatever is stored alone.
  });
  check("a value writes, a sentinel declares, an omission keeps", sshFlags(mixed), [
    true,
    true,
    true,
  ]);
  check("and all three survive a fresh read", sshFlags(await h.hosts.findHost("h-mix")), [
    true,
    true,
    true,
  ]);
  check("exactly one keychain call, for the one field that had a value", h.calls.slice(before), [
    { op: "set", service: HOSTS_SERVICE, accounts: ["h-mix::password"] },
  ]);
  check(
    "the sentinel's account is untouched",
    h.kept.get(at("h-mix", "privateKey")),
    "PEM-FROM-RUST",
  );
  check("and so is the omitted one", h.kept.get(at("h-mix", "keyPassphrase")), "pp");
}

// ---------------------------------------------------------------------------
console.log("\n[flags] an imported RDP host stays connectable - what the sentinel is for");
{
  // The bug this closes. `RdpPane` pre-flights the record before dialling:
  // `credential.kind === "inline" && !credential.hasPassword` refuses with "No
  // password is stored for X". Under `undefined` an import left that flag false
  // over a password sitting in the keychain, so every imported inline RDP host was
  // unconnectable while its credential was right there - the whole RDP half of a
  // backup import.
  const h = harness({ kept: { [at("h-win", "password")]: "written-by-rust" } });
  await h.hosts.upsertHost(rdpHost({ id: "h-win" }), { password: SECRET_ALREADY_STORED });
  const imported = await h.hosts.findHost("h-win");
  const refused =
    !imported || (imported.credential.kind === "inline" && !imported.credential.hasPassword);
  assert(!refused, "RdpPane's pre-flight does not refuse the imported host");
  check(
    "because the PERSISTED record says the password is there",
    imported && imported.credential.kind === "inline" ? imported.credential.hasPassword : null,
    true,
  );
  check(
    "the keychain still holds what Rust put there",
    h.kept.get(at("h-win", "password")),
    "written-by-rust",
  );
  check("and this layer made no keychain call to find out", h.calls, []);
}

// ---------------------------------------------------------------------------
console.log("\n[flags] the sentinel is still refused where there is no account for it");
{
  const h = harness();
  // A vault-bound host owns no accounts, so "it is already at this host's account"
  // is not a claim that can be true. Refused rather than accepted quietly, or the
  // record would advertise a secret that lives on another service entirely.
  await rejects(
    "a vault-bound host refuses it, like any other secret",
    () =>
      h.hosts.upsertHost(
        sshHost({ id: "h-v", credential: { kind: "identity", identityId: "i-1" } }),
        { password: SECRET_ALREADY_STORED },
      ),
    ["owns no accounts", "password"],
  );
  await rejects(
    "and an RDP row refuses key material whether it carries a value or the sentinel",
    () => h.hosts.upsertHost(rdpHost({ id: "h-r" }), { privateKey: SECRET_ALREADY_STORED }),
    ["rdp host", "no key material"],
  );
  check("neither refusal touched the keychain", h.calls, []);
}

if (failed > 0) throw new Error(`hosts-store-verify: ${failed} FAILED`);
console.log("\nhosts-store-verify: OK\n");
