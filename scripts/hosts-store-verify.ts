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
 * 4. DELETING A HOST IS REFUSED WHILE ANOTHER HOST RIDES IT, never cascaded, and
 *    a `proxyJumpId` counts exactly as much as a `tunnel.sshHostId`. Cleared
 *    silently, the referencing host goes on connecting and changes ROUTE with
 *    nothing on screen changing: the pin is keyed per host id, so the same
 *    machine reached directly presents the same host key and raises no TOFU
 *    question at all. ONE refusal lists every holder, because a user who clears
 *    the tunnels and is then refused again about jump hosts reads the first
 *    refusal as a lie. Forward rules are the exception and are cleaned up, through
 *    an injected cleanup that FAILS CLOSED.
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
 *    only AFTER the new record is on disk, because a protocol change has no
 *    copy step and this layer cannot put a secret back; a partial write on a
 *    brand-new host rolls back. The two OLD connection stores' accounts are swept
 *    once by `legacyPurge.ts`, which is the only thing that can ever name them
 *    after those modules are deleted.
 *
 * 8. AN RDP PASSWORD NEVER ENTERS THE WEBVIEW. There is no read-back for one, not
 *    even for the editor. A DUPLICATE still carries it, because `secrets_copy`
 *    moves it account-to-account in-process - and the copy's flags then describe
 *    what the copy reported, never what the source record claimed, since a claim
 *    over an account the keychain no longer holds is wrong forever on a layer
 *    that never reads one back.
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
  credentialStamp,
  CREDENTIAL_STAMP_ABSENT,
  CREDENTIAL_STAMP_INLINE,
  hostFingerprint,
  HostBindingChangedError,
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
// The import's own passes, so the pin block below can exercise the COMPOSITION
// this store sits at the end of. Both are Tauri-free by design - `file.ts`
// is kept that way so `backup-verify.ts` can run under plain node - and
// nothing here reaches `apply.ts`, which does `invoke`.
import { carryPins, sanitizePayload } from "../src/modules/backup/file";
import type { SecretsIo } from "../src/modules/vault/adapters";
import type { ResolveDeps } from "../src/modules/vault/resolve";
import { VaultInUseError, type VaultIdentity, type VaultKey } from "../src/modules/vault/types";

let failed = 0;

/**
 * A canonical rendering of a value, used to compare AND to report - so what a
 * failure prints is what was actually compared.
 *
 * Deliberately not `JSON.stringify`, which is one of the comparison shapes that
 * has passed against implementations it existed to reject. Two reasons, and the pin
 * assertions below are exposed to both.
 *
 * It DROPS `undefined` properties, so `{ pins: undefined }` and `{}` serialize
 * identically - and the whole of `hostPins` turns on `pins` being absent versus
 * being an empty object versus being keyed. Here `undefined` is rendered, so a key
 * that is present and empty is not the same as a key that is gone.
 *
 * It is KEY-ORDER-SENSITIVE, so a pin map built by spreading in a different order
 * failed a check about which pins survived rather than about their order. Keys are
 * sorted here. That leaves key order unasserted, which is correct for every use in
 * this file: where order IS the contract - a list of accounts deleted in sequence -
 * the assertion is on an ARRAY, whose order this preserves.
 */
function shape(v: unknown): string {
  if (v === undefined) return "undefined";
  if (v === null) return "null";
  if (Array.isArray(v)) return `[${v.map(shape).join(",")}]`;
  if (typeof v === "object") {
    const o = v as Record<string, unknown>;
    const keys = Object.keys(o).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${shape(o[k])}`).join(",")}}`;
  }
  // A number, string or boolean; `String` covers the ones `JSON.stringify`
  // answers `undefined` for rather than rendering them as a missing value.
  return JSON.stringify(v) ?? String(v);
}

function check(label: string, got: unknown, want: unknown): void {
  const found = shape(got);
  const wanted = shape(want);
  if (found === wanted) {
    console.log(`  ok: ${label}`);
  } else {
    console.error(`  FAIL: ${label} = ${found}, want ${wanted}`);
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

type SecretCall = {
  op: "getAll" | "set" | "delete" | "copy";
  service: string;
  accounts: string[];
  /** `copy` only, and separate because a copy can CROSS services: moving a host
   *  password onto `tervia-vault` does. */
  toService?: string;
};

/** A step that throws, to reach the partial-failure paths. */
type Fail = {
  setAccount?: string;
  deleteAccount?: string;
  copyAccount?: string;
  commit?: string;
  dir?: string;
};

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
    // A REAL copy against `kept`, and deliberately NOT a stub that answers
    // `true`. Every duplicate check below asserts that the copy's flags describe
    // what actually arrived, and a fake that reported success without moving a
    // byte would make all of them vacuous. A missing source writes NOTHING -
    // not the empty string, which every `has*` flag in the app reads as a real
    // secret.
    async copy(from, to) {
      calls.push({
        op: "copy",
        service: from.service,
        accounts: [from.account, to.account],
        toService: to.service,
      });
      if (seed.fail?.copyAccount === from.account) {
        throw new Error(`keychain refused to copy ${from.account}`);
      }
      const value = kept.get(`${from.service}::${from.account}`);
      if (value === undefined) return false;
      kept.set(`${to.service}::${to.account}`, value);
      return true;
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
    /** Every copy, FULLY QUALIFIED on both sides - a copy landing on the wrong
     *  service is the failure `same_entry` in `secrets.rs` guards against. */
    copies: () =>
      calls
        .filter((c) => c.op === "copy")
        .map((c) => `${c.service}::${c.accounts[0]} -> ${c.toService}::${c.accounts[1]}`),
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

  const before = h.calls.length;
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

  // HOW they travelled, not just that they did. Every account the source owns is
  // attempted, on the same service both ways, by `secrets_copy` - which reads and
  // writes in-process, so no value passes through here. The old code did a
  // `secrets_get_all` on the source instead, and that read is what a duplicate
  // must no longer cost: the RDP half could not do it at all, and got no password.
  check("each account moved by name, in field order", h.copies(), [
    `${HOSTS_SERVICE}::h-1::password -> ${HOSTS_SERVICE}::${copy.id}::password`,
    `${HOSTS_SERVICE}::h-1::privateKey -> ${HOSTS_SERVICE}::${copy.id}::privateKey`,
    `${HOSTS_SERVICE}::h-1::keyPassphrase -> ${HOSTS_SERVICE}::${copy.id}::keyPassphrase`,
  ]);
  check(
    "and a copy is the ONLY thing the duplicate asked the keychain for - no read, no set",
    h.calls.slice(before).map((c) => c.op),
    ["copy", "copy", "copy"],
  );

  // Rotating one must not rotate the other - the whole point of rebinding.
  await h.hosts.upsertHost(copy, { password: "rotated" });
  check("rotating the copy leaves the source alone", h.kept.get(at("h-1", "password")), "hunter2");
  check("and changes the copy", h.kept.get(at(copy.id, "password")), "rotated");

  check("nothing was duplicated by accident", (await h.hosts.listHosts()).length, 2);
}

// ---------------------------------------------------------------------------
console.log("\n[duplicate] an RDP password DOES travel, still without a read-back");
{
  // There was no `secrets_copy` when this was written, so carrying an RDP
  // password would have meant reading it into the webview - which an RDP
  // password must never enter - and the copy was saved with
  // `hasPassword: false` instead.
  // `RdpPane` pre-flights that flag and refuses to connect, so a duplicated RDP
  // host was unconnectable until the password was re-entered by hand.
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
    "the password reached the copy's OWN account",
    h.kept.get(at(copy.id, "password")),
    "s3cret",
  );
  check(
    "the copy claims it",
    copy.credential.kind === "inline" ? copy.credential.hasPassword : null,
    true,
  );
  // Off a FRESH read: a check that reads what `duplicateHost` returned cannot
  // tell a persisted flag from an echoed one.
  const stored = await h.hosts.findHost(copy.id);
  check(
    "and that is what got PERSISTED, so RdpPane's pre-flight lets it dial",
    stored && stored.credential.kind === "inline" ? stored.credential.hasPassword : null,
    true,
  );
  check("the source keeps its own", h.kept.get(at("h-2", "password")), "s3cret");
  // An RDP row owns exactly ONE account, so exactly one copy - key material has
  // no account on this arm to copy from or to.
  check("it moved by account name, and only the one account exists", h.copies(), [
    `${HOSTS_SERVICE}::h-2::password -> ${HOSTS_SERVICE}::${copy.id}::password`,
  ]);
  check("no keychain read happened to duplicate it", h.reads().length, before);
  check("and the editor path offers none either", await h.hosts.getHostSshSecrets("h-2"), {});
  check("still no read", h.reads().length, before);

  // Rebinding is what keeps the two apart afterwards: rotating one must not
  // rotate the other, which is the whole reason the copy owns its own account
  // rather than sharing the source's.
  await h.hosts.upsertHost(copy, { password: "rotated" });
  check("rotating the copy leaves the source alone", h.kept.get(at("h-2", "password")), "s3cret");
  check("and changes the copy", h.kept.get(at(copy.id, "password")), "rotated");
}

// ---------------------------------------------------------------------------
console.log("\n[duplicate] a copy of a secret-less host writes nothing to the keychain");
{
  // A field that copied nothing must be OMITTED from the write instructions, not
  // handed on as a value: the CLEAR instruction is a blank string, and mapping
  // "found nothing" onto it would issue three `secrets_delete` calls against
  // accounts the copy has never had. (The same shape as the old defect here,
  // where `secrets_get_all` reported an absent account as `null` and `null` is
  // the clear instruction.)
  const h = harness({ hosts: [sshHost({ id: "h-1" })] });
  const copy = await h.hosts.duplicateHost("h-1");
  check("the copy saved", copy?.id !== "h-1" && copy !== null, true);
  check("every account was still ATTEMPTED, so none is missed by accident", h.copies().length, 3);
  check("with no delete issued for it", h.deletes(), []);
  check("and no write either", h.calls.filter((c) => c.op === "set").length, 0);
  check("nor anything landing in the keychain", h.kept.size, 0);
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
  // Not "a copy that found nothing" - a copy that was never attempted. A
  // vault-bound host owns no accounts, so the identity's secrets stay in ONE
  // place and both hosts dereference it. Copying them onto host accounts is the
  // opposite of what a vault entry is for.
  check("and nothing was copied - the identity is SHARED, not duplicated", h.copies(), []);
}

// ---------------------------------------------------------------------------
console.log("\n[duplicate] a copy's flags describe what the COPY got, not what the source claimed");
{
  // The source's record claims a password its account no longer holds - a `.bak`
  // restore rolling metadata back over a rotation while `secrets.rs` stayed
  // current. The source's flags arrive on the copy for
  // free through the `rebound` spread, and propagating that claim writes a flag
  // that is wrong FOREVER: this layer never reads a secret back, so nothing can
  // correct it, and `RdpPane`'s pre-flight and every export key on it.
  const flags = (host: Host | undefined): unknown =>
    host && host.protocol === "ssh" && host.credential.kind === "inline"
      ? [
          host.credential.hasPassword,
          host.credential.hasPrivateKey,
          host.credential.hasKeyPassphrase,
        ]
      : null;
  const h = harness({
    hosts: [
      sshHost({
        id: "h-1",
        credential: {
          kind: "inline",
          hostId: "h-1",
          user: "root",
          authMode: "password",
          // Claimed, and only ONE of the two is really there.
          hasPassword: true,
          hasPrivateKey: true,
          hasKeyPassphrase: false,
        },
      }),
    ],
    kept: { [at("h-1", "privateKey")]: "PEM" },
  });

  const copy = await h.hosts.duplicateHost("h-1");
  if (copy === null) throw new Error("hosts-store-verify: the duplicate came back null");
  check("the claim the keychain could not honour comes back FALSE", flags(copy), [
    false,
    true,
    false,
  ]);
  check("and that is what got PERSISTED", flags(await h.hosts.findHost(copy.id)), [
    false,
    true,
    false,
  ]);
  check(
    "nothing was invented at the empty account - not even a blank string",
    h.kept.has(at(copy.id, "password")),
    false,
  );
  check("while the key that WAS there travelled", h.kept.get(at(copy.id, "privateKey")), "PEM");
  // The copy is what gets fixed, not the source: this operation has no business
  // rewriting a record the user did not ask it to touch, and doing so would need a
  // read-back to be honest about anyway.
  check(
    "the source's own wrong claim is left exactly as it was",
    flags(await h.hosts.findHost("h-1")),
    [true, true, false],
  );
  check("and no flag was decided by reading a secret", h.reads(), []);
}

// ---------------------------------------------------------------------------
console.log("\n[duplicate] a copy that cannot carry a secret writes no record at all");
{
  // Secrets FIRST, record SECOND, and the order is not interchangeable. Copying
  // is additive - it touches only accounts under an id no record names yet - so a
  // failure here leaves bytes at an unreferenced account, which is an orphan
  // and nothing that is WRONG, just unreachable. The other order
  // leaves a saved record claiming secrets that are not there, permanently.
  const h = harness({
    hosts: [
      sshHost({
        id: "h-1",
        credential: {
          kind: "inline",
          hostId: "h-1",
          user: "root",
          authMode: "key",
          hasPassword: true,
          hasPrivateKey: true,
          hasKeyPassphrase: false,
        },
      }),
    ],
    kept: { [at("h-1", "password")]: "pw", [at("h-1", "privateKey")]: "PEM" },
    fail: { copyAccount: "h-1::privateKey" },
  });

  await rejects(
    "a copy the keychain refuses is reported, not swallowed",
    () => h.hosts.duplicateHost("h-1"),
    ["refused to copy", "privateKey"],
  );
  check(
    "and NO record was written for the copy",
    (await h.hosts.listHosts()).map((x) => x.id),
    ["h-1"],
  );
  // The partial copy is rolled back, which is safe for exactly one reason: the
  // copy's id is brand new, so there was nothing at these accounts to lose. There
  // is no `secrets_list`, so anything left here is unreachable rather than untidy.
  check(
    "the account that DID copy is cleared again, leaving only the source's two",
    [...h.kept.keys()].sort(),
    [at("h-1", "password"), at("h-1", "privateKey")].sort(),
  );
  check(
    "and the source is byte-for-byte untouched",
    [h.kept.get(at("h-1", "password")), h.kept.get(at("h-1", "privateKey"))],
    ["pw", "PEM"],
  );
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
  // `expectedFingerprint: undefined` is spelled out on both, because `check` now
  // renders an explicit `undefined` rather than dropping it: the hop spec always
  // carries the key, and an unpinned hop carrying it as `undefined` is the shape
  // the backend is handed. Omitting it here made that unobservable.
  check("an agent hop is built with no credential in it at all", hops[0], {
    connectionId: "j-entry",
    host: "j-entry.example",
    port: 22,
    user: "hop",
    useAgent: true,
    expectedFingerprint: undefined,
  });
  check("a vault-bound hop resolves through the identity, not the host accounts", hops[1], {
    connectionId: "j-mid",
    host: "j-mid.example",
    port: 22,
    user: "vaulted",
    password: "from-the-vault",
    expectedFingerprint: undefined,
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
  // The order is the whole point. A protocol change has no copy step, so
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

  // The residual worst case, and the lesser evil of the two: a good write
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

  // The fan-out is sequential, so a throw part-way leaves some accounts cleared and
  // some untouched - and the message has to name only what is actually left behind.
  // Naming the whole stale list sends the user looking for bytes that are gone, in
  // the one message whose job is saying where they are. `keyPassphrase` is the
  // SECOND of the two fields an SSH -> RDP change makes stale, so the first one
  // really is cleared before the failure.
  const partial = harness({
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
    kept: { [at("h-1", "privateKey")]: "PEM", [at("h-1", "keyPassphrase")]: "pp" },
    fail: { deleteAccount: "h-1::keyPassphrase" },
  });
  let said = "";
  try {
    await partial.hosts.upsertHost(rdpHost({ id: "h-1" }));
  } catch (e) {
    said = e instanceof Error ? e.message : String(e);
  }
  assert(said.includes("keyPassphrase"), "the message names the account that was left behind");
  assert(
    !said.includes("privateKey"),
    "and NOT the one it cleared on the way, which is not unreachable at all",
  );
  check(
    "the cleared account really is gone, and the failed one really is still there",
    [partial.kept.get(at("h-1", "privateKey")), partial.kept.get(at("h-1", "keyPassphrase"))],
    [undefined, "pp"],
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
console.log("\n[delete] an unreferenced host takes its accounts with it");
{
  // What is left of a delete once both cascades are refusals. Nothing rides
  // `h-gone`, so it goes, and every account it owned goes by NAME - there is no
  // `secrets_list`, so an account left behind is unreachable rather than untidy.
  // The two refusal cases are the next two blocks.
  const h = harness();
  await h.hosts.upsertHost(sshHost({ id: "h-keep" }), { password: "keeppw" });
  await h.hosts.upsertHost(sshHost({ id: "h-gone" }), { password: "gonepw", privateKey: "PEM" });
  await h.hosts.upsertHost(sshHost({ id: "h-via", proxyJumpId: "h-keep" }));

  const cleaned: string[] = [];
  await h.hosts.deleteHost("h-gone", (hostId) => void cleaned.push(hostId));

  check("the row is gone", await h.hosts.findHost("h-gone"), undefined);
  check(
    "and so is every account it owned",
    [h.kept.has(at("h-gone", "password")), h.kept.has(at("h-gone", "privateKey"))],
    [false, false],
  );
  check(
    "each one cleared by name, including the field it never filled",
    h
      .deletes()
      .filter((a) => a.startsWith("h-gone::"))
      .sort(),
    ["h-gone::keyPassphrase", "h-gone::password", "h-gone::privateKey"],
  );
  const via = await h.hosts.findHost("h-via");
  check(
    "a reference to a DIFFERENT host is left alone",
    via?.protocol === "ssh" ? via.proxyJumpId : "?",
    "h-keep",
  );
  check("and that host keeps its own secret", h.kept.get(at("h-keep", "password")), "keeppw");
  check("the forward-rule cleanup was told which host went", cleaned, ["h-gone"]);
  check("two hosts remain", (await h.hosts.listHosts()).length, 2);

  // Fail closed: the rules and the host must not come apart. `h-closed` is
  // deliberately unreferenced, or the refusal below would be the reference guard
  // firing first and this check would prove nothing about the cleanup.
  await h.hosts.upsertHost(sshHost({ id: "h-closed" }), { password: "closedpw" });
  await rejects(
    "a cleanup that throws aborts the delete",
    () =>
      h.hosts.deleteHost("h-closed", () => {
        throw new Error("forwards: the rule store is unreadable");
      }),
    ["rule store is unreadable"],
  );
  assert((await h.hosts.findHost("h-closed")) !== undefined, "the host is still there");
  check("and so is its account", h.kept.get(at("h-closed", "password")), "closedpw");

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
console.log("\n[delete] refused while an RDP host tunnels through it, not cascaded");
{
  // The cascade this replaces: left to clear silently, an RDP host confined to
  // this bastion becomes a DIRECT DIAL to `host:3389` with CredSSP the instant
  // the bastion is gone. Bounded where the row has a pinned certificate - a
  // wrong machine fails the pin before the password is sent - but a row that
  // has never connected has no pin, and the first-connect prompt it gets
  // instead names `row.host` and reads as entirely normal. Refuse, the same
  // discipline `modules/vault` applies to an in-use identity.
  const h = harness();
  await h.hosts.upsertHost(sshHost({ id: "h-bastion", name: "the bastion" }), {
    password: "bastionpw",
  });
  await h.hosts.upsertHost(
    rdpHost({ id: "h-rdp-1", name: "office desktop", tunnel: { sshHostId: "h-bastion" } }),
  );

  const cleaned: string[] = [];
  await rejects(
    "deleting a host an RDP tunnel names is refused",
    () => h.hosts.deleteHost("h-bastion", (hostId) => void cleaned.push(hostId)),
    ["cannot delete", "the bastion", "1 host", "office desktop"],
  );
  check("the forward-rule cleanup never ran - the refusal comes before anything else", cleaned, []);
  check("the host is still there", (await h.hosts.findHost("h-bastion"))?.id, "h-bastion");
  check("its secret account is still there", h.kept.get(at("h-bastion", "password")), "bastionpw");
  const stillTunnelled = await h.hosts.findHost("h-rdp-1");
  check(
    "the RDP host's tunnel is untouched",
    stillTunnelled?.protocol === "rdp" ? stillTunnelled.tunnel : "?",
    { sshHostId: "h-bastion" },
  );

  // The typed error carries the holders, so a dialog can offer to open them -
  // the same shape `deleteIdentity` and `deleteKey` already refuse with.
  try {
    await h.hosts.deleteHost("h-bastion", noForwardRules);
    assert(false, "the delete above should have thrown");
  } catch (e) {
    assert(e instanceof VaultInUseError, "the refusal is a VaultInUseError");
    check("carrying the holder", (e as VaultInUseError).holders, [
      { id: "h-rdp-1", name: "office desktop" },
    ]);
  }

  // A second RDP host tunnelling through the same bastion - the refusal must
  // name BOTH holders, not just the first one found.
  await h.hosts.upsertHost(
    rdpHost({ id: "h-rdp-2", name: "lab workstation", tunnel: { sshHostId: "h-bastion" } }),
  );
  await rejects(
    "the refusal names every holder, not just one",
    () => h.hosts.deleteHost("h-bastion", noForwardRules),
    ["2 hosts", "office desktop", "lab workstation"],
  );

  // Clearing the tunnels first is how the user gets what a cascade used to do
  // silently: an explicit, visible choice instead of one made for them.
  await h.hosts.upsertHost(rdpHost({ id: "h-rdp-1", name: "office desktop" }));
  await h.hosts.upsertHost(rdpHost({ id: "h-rdp-2", name: "lab workstation" }));
  await h.hosts.deleteHost("h-bastion", noForwardRules);
  check(
    "the delete succeeds once every tunnel naming it is cleared",
    await h.hosts.findHost("h-bastion"),
    undefined,
  );
  check("and its account goes with it", h.kept.has(at("h-bastion", "password")), false);
}

// ---------------------------------------------------------------------------
console.log("\n[delete] refused while another host JUMPS through it, not cascaded");
{
  // Reversing what `deleteConnection` did before the two stores merged.
  // A cleared `proxyJumpId` is a SILENT DIRECT DIAL: the row goes on
  // connecting and changes ROUTE, and the pin is what makes it silent rather than
  // merely quiet - `lastFingerprint` is keyed per HOST ID, so the same machine
  // reached directly presents the same host key, matches the pin the row already
  // had, and raises no TOFU question at all. Nothing on screen changes. Traffic
  // that was confined to a bastion now crosses whatever is between here and there.
  const h = harness();
  await h.hosts.upsertHost(sshHost({ id: "h-bastion", name: "the bastion" }), {
    password: "bastionpw",
    privateKey: "bastion-PEM",
  });
  await h.hosts.upsertHost(
    sshHost({
      id: "h-behind",
      name: "db behind it",
      proxyJumpId: "h-bastion",
      lastFingerprint: "SHA256:UNCHANGED",
    }),
  );

  const cleaned: string[] = [];
  await rejects(
    "deleting a host another host jumps through is refused",
    () => h.hosts.deleteHost("h-bastion", (hostId) => void cleaned.push(hostId)),
    ["cannot delete", "the bastion", "1 host", "db behind it"],
  );
  check("the forward-rule cleanup never ran - the refusal comes before anything else", cleaned, []);

  // A refusal must leave every side exactly as it was, which for the keychain
  // half means not even an attempt: the store cannot put a secret back.
  check("the host is still there", (await h.hosts.findHost("h-bastion"))?.id, "h-bastion");
  check(
    "with every one of its accounts intact",
    [h.kept.get(at("h-bastion", "password")), h.kept.get(at("h-bastion", "privateKey"))],
    ["bastionpw", "bastion-PEM"],
  );
  check("and no delete was even attempted", h.deletes(), []);
  const behind = await h.hosts.findHost("h-behind");
  check(
    "the referencing row keeps BOTH its jump host and the pin that would have gone quiet",
    behind?.protocol === "ssh" ? [behind.proxyJumpId, behind.lastFingerprint] : "?",
    ["h-bastion", "SHA256:UNCHANGED"],
  );

  // The typed error, so a dialog can offer to open the holders - the same shape
  // `deleteIdentity` and `deleteKey` already refuse with.
  try {
    await h.hosts.deleteHost("h-bastion", noForwardRules);
    assert(false, "the delete above should have thrown");
  } catch (e) {
    assert(e instanceof VaultInUseError, "the refusal is a VaultInUseError");
    check("carrying the holder", (e as VaultInUseError).holders, [
      { id: "h-behind", name: "db behind it" },
    ]);
  }

  // Clearing the jump first is how the user gets what the cascade used to do for
  // them: an explicit, visible choice instead of one made silently.
  await h.hosts.upsertHost(sshHost({ id: "h-behind", name: "db behind it" }));
  await h.hosts.deleteHost("h-bastion", noForwardRules);
  check(
    "the delete succeeds once the jump is cleared",
    await h.hosts.findHost("h-bastion"),
    undefined,
  );
  check("taking its accounts with it", h.kept.size, 0);
}

// ---------------------------------------------------------------------------
console.log("\n[delete] a jump holder and a tunnel holder are ONE refusal, not two");
{
  // Two checks in sequence would be worse than one: a user who clears the
  // tunnels, hits a second refusal about jump hosts, and has to go round again
  // reads the FIRST refusal as a lie about what was in the way. One check, one
  // message, every holder named.
  const h = harness();
  await h.hosts.upsertHost(sshHost({ id: "h-bastion", name: "the bastion" }), { password: "pw" });
  await h.hosts.upsertHost(
    sshHost({ id: "h-jumper", name: "db behind it", proxyJumpId: "h-bastion" }),
  );
  await h.hosts.upsertHost(
    rdpHost({ id: "h-tunneller", name: "office desktop", tunnel: { sshHostId: "h-bastion" } }),
  );

  await rejects(
    "one refusal names both kinds of holder",
    () => h.hosts.deleteHost("h-bastion", noForwardRules),
    ["cannot delete", "the bastion", "2 hosts", "db behind it", "office desktop"],
  );
  // The needles above cannot prove there were only two, or that a second call
  // says the same thing. `holders` can.
  try {
    await h.hosts.deleteHost("h-bastion", noForwardRules);
    assert(false, "the delete above should have thrown");
  } catch (e) {
    check("and carries exactly those two, in row order", (e as VaultInUseError).holders, [
      { id: "h-jumper", name: "db behind it" },
      { id: "h-tunneller", name: "office desktop" },
    ]);
  }

  // The half-cleared state is where a two-check version misleads: clearing the
  // tunnel must still refuse, and must now name only what is actually left.
  await h.hosts.upsertHost(rdpHost({ id: "h-tunneller", name: "office desktop" }));
  try {
    await h.hosts.deleteHost("h-bastion", noForwardRules);
    assert(false, "clearing only the tunnel should still refuse");
  } catch (e) {
    check(
      "clearing the tunnel alone leaves the jump holder, and only that",
      (e as VaultInUseError).holders,
      [{ id: "h-jumper", name: "db behind it" }],
    );
  }
  check("the host survived both refusals", (await h.hosts.findHost("h-bastion"))?.id, "h-bastion");
  check("and so did its secret", h.kept.get(at("h-bastion", "password")), "pw");

  await h.hosts.upsertHost(sshHost({ id: "h-jumper", name: "db behind it" }));
  await h.hosts.deleteHost("h-bastion", noForwardRules);
  check(
    "clearing the second one is what finally lets it go",
    await h.hosts.findHost("h-bastion"),
    undefined,
  );
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
console.log("\n[pins] one pin per (host, address), in whichever field the protocol keeps it");
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
  /** The keyed map as PERSISTED, so a projection that agreed with itself in memory
   *  but wrote nothing would not pass. */
  const keys = (id: string): Record<string, string> | "MISSING" =>
    h.rows().find((x) => x.id === id)?.pins ?? "MISSING";

  await h.hosts.pinFingerprint("h-1", "SHA256:KEY");
  await h.hosts.pinFingerprint("h-2", "SHA256:CERT");
  check("the SSH pin lands in lastFingerprint", await pin("h-1"), "SHA256:KEY");
  check("the RDP pin lands in certFingerprint", await pin("h-2"), "SHA256:CERT");
  // The keying itself: the address comes off the RECORD, which is what lets
  // `pinFingerprint(id, fingerprint)` stay a two-argument call.
  check("and is filed under the address that record names", keys("h-1"), {
    "prod.example": "SHA256:KEY",
  });
  check("the RDP one under its own", keys("h-2"), { "vps.example": "SHA256:CERT" });
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
  check("and keeps it keyed rather than re-filing it", keys("h-1"), {
    "prod.example": "SHA256:KEY",
  });
  assert((marked?.lastConnectedAt ?? 0) > 0, "and stamps the connect");

  // Re-pinning the same key is a no-op, not a rewrite: `pinFingerprint` compares
  // against the pin for THIS address before it patches anything.
  const beforeSame = JSON.stringify(h.rows());
  await h.hosts.pinFingerprint("h-1", "SHA256:KEY");
  check("re-pinning the same key writes nothing", JSON.stringify(h.rows()), beforeSame);

  const rowsBefore = JSON.stringify(h.rows());
  const callsBefore = h.calls.length;
  await h.hosts.pinFingerprint("h-x", "SHA256:Z");
  await h.hosts.markConnected("h-x", "SHA256:Z");
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
  check(
    "no pin path rewrites the credential, so upsertHost is the only guarded write",
    await bindingOf("h-3"),
    beforePins,
  );
  check("and the binding still names its own host", await ownerOf("h-3"), "h-3");
}

// ---------------------------------------------------------------------------
// Gaps 15 and 20 - the pair the hand test found, and the reason this section is
// long. `Forget` used to write the pin deletion straight to the store, OUTSIDE the
// dialog transaction, and `Test` verified against the pin of the machine the saved
// record still named - so testing a new address required Forget first, and Cancel
// then reverted the address while nothing reverted the pin. The host was left with
// no pinned key at all, silently on TOFU, accepting whatever the next connect was
// presented. It failed OPEN, which is why the inverse (a foreign fingerprint
// persisted by a cancelled dialog, failing closed as a MISMATCH) got fixed first.
//
// The store's half of that fix is keying, and its contract is exactly two things:
// the flat field is the pin for the address the record names AND NOTHING ELSE, and
// no pin is thrown away when the address changes. Every check below is one of
// those two.
console.log("\n[pins] a re-pointed host never compares against another machine's key");
{
  const h = harness({ hosts: [sshHost({ id: "h-1", host: "a.example" })] });
  const row = () => h.rows().find((x) => x.id === "h-1");
  const saved = async (): Promise<Host> => {
    const found = await h.hosts.findHost("h-1");
    if (!found) throw new Error("h-1 vanished");
    return found;
  };

  await h.hosts.pinFingerprint("h-1", "SHA256:A");
  check("the pin is filed under the address it was presented at", row()?.pins, {
    "a.example": "SHA256:A",
  });

  // What a save from the editor looks like after the user re-points the host and
  // accepts the NEW machine's key during Test: the draft map carries both, keyed.
  await h.hosts.upsertHost({
    ...(await saved()),
    host: "b.example",
    pins: { "a.example": "SHA256:A", "b.example": "SHA256:B" },
  });
  check("re-pointing projects the NEW address's pin", hostFingerprint(await saved()), "SHA256:B");
  check("and keeps the old one under its own key", row()?.pins, {
    "a.example": "SHA256:A",
    "b.example": "SHA256:B",
  });

  // The behaviour the old `keepPin` could not express: a key accepted for the new
  // address survives the save that moves the host there. Under `keepPin` the
  // address had changed, so this pin was discarded and the next connect re-asked.
  await h.hosts.upsertHost({ ...(await saved()), host: "a.example" });
  check(
    "re-pointing BACK finds the original pin rather than re-asking TOFU",
    hostFingerprint(await saved()),
    "SHA256:A",
  );

  // Forget, applied by Save: the address's key is dropped and nothing else is.
  await h.hosts.upsertHost({ ...(await saved()), pins: { "b.example": "SHA256:B" } });
  check("a map without this address projects no pin", hostFingerprint(await saved()), undefined);
  check("and the other address keeps its key", row()?.pins, { "b.example": "SHA256:B" });

  // Defence behind the dialog's own gate on `onTrusted`. Even an UNGATED
  // `pinFingerprint` cannot forge a pin for a machine this record does not name,
  // because the address comes off the record rather than from the caller - which is
  // also what lets that call keep a two-argument signature. So the worst a stray
  // call can do is re-pin the machine the row already points at: it can neither
  // destroy another address's key nor invent one.
  await h.hosts.upsertHost({
    ...(await saved()),
    host: "a.example",
    pins: { "a.example": "SHA256:A", "b.example": "SHA256:B" },
  });
  await h.hosts.pinFingerprint("h-1", "SHA256:STRAY");
  check("a pin write lands on the record's own address and no other", row()?.pins, {
    "a.example": "SHA256:STRAY",
    "b.example": "SHA256:B",
  });

  // Forget every address: the map is stored as ABSENT rather than as `{}`, so a row
  // with no pins does not carry an empty object around - and `hostPins` must not
  // read that absence as "adopt the flat pin", because there is none to adopt.
  await h.hosts.upsertHost({ ...(await saved()), pins: {} });
  check("forgetting every pin leaves no map at all", row()?.pins, undefined);
  check("and no flat pin", hostFingerprint(await saved()), undefined);
}

// ---------------------------------------------------------------------------
console.log("\n[pins] an unkeyed pin is attributed rather than dropped or moved");
{
  // The migration. Every host here is written the way a pre-keying build left it:
  // `lastFingerprint` set, no `pins`. Nothing may lose a pin, and nothing may
  // attribute one to a machine that never presented it.
  const h = harness({
    hosts: [
      sshHost({ id: "h-old", host: "a.example", lastFingerprint: "SHA256:OLD" }),
      sshHost({ id: "h-move", host: "a.example", lastFingerprint: "SHA256:OLD" }),
      rdpHost({ id: "h-rdp", host: "r.example", certFingerprint: "SHA256:CERT" }),
      // The two rows here that are NOT pre-keying, and they exist because a
      // pre-keying row cannot tell the two halves of the changed-address branch
      // apart: its flat pin IS its map's only entry, so both halves are the same
      // no-op on it.
      //
      // `h-keyed` has a key AT the address it names, so a flat pin arriving with a
      // changed address has something it could overwrite.
      sshHost({
        id: "h-keyed",
        host: "b.example",
        pins: { "b.example": "SHA256:B" },
        lastFingerprint: "SHA256:B",
      }),
      // `h-gap` has a key at some OTHER address and none at its own - a row
      // re-pointed to `b.example` that never trusted anything there. So the same
      // arrival has nothing to overwrite. No flat pin, which is what the store's own
      // projection of this map at `b.example` comes to.
      sshHost({ id: "h-gap", host: "b.example", pins: { "a.example": "SHA256:A" } }),
    ],
  });
  const row = (id: string) => h.rows().find((x) => x.id === id);
  const get = async (id: string): Promise<Host> => {
    const found = await h.hosts.findHost(id);
    if (!found) throw new Error(`${id} vanished`);
    return found;
  };

  // Read-side: the pin is FOUND. This is what the editor seeds its draft from, and
  // what a connect keeps comparing against in the meantime.
  check("an unkeyed row still reports its pin", hostFingerprint(await get("h-old")), "SHA256:OLD");
  check("and has not been rewritten just by being read", row("h-old")?.pins, undefined);

  // Written for an unrelated reason - a rename - and the map appears, keyed onto the
  // address the row named. Nothing was lost and no launch had to rewrite the file.
  await h.hosts.upsertHost({ ...(await get("h-old")), name: "renamed" });
  check("a write for any other reason files it under that address", row("h-old")?.pins, {
    "a.example": "SHA256:OLD",
  });
  check("and the flat pin is unchanged", hostFingerprint(await get("h-old")), "SHA256:OLD");

  // THE MIS-ATTRIBUTION CASE, and the one this branch exists for. A caller that
  // spreads an unkeyed stored record and changes the address - which is what
  // `{ ...stored, host: next }` in a later sub-phase will look like - hands over a
  // flat pin belonging to the OLD machine with the NEW address beside it. Moving it
  // onto the new address would fail that machine's next connect as a MISMATCH,
  // which reads as an attack; dropping it would put the old machine back on TOFU.
  await h.hosts.upsertHost({ ...(await get("h-move")), host: "b.example" });
  check(
    "an unkeyed pin is NOT moved onto the address the caller changed to",
    hostFingerprint(await get("h-move")),
    undefined,
  );
  check("it is filed under the address it was actually recorded at", row("h-move")?.pins, {
    "a.example": "SHA256:OLD",
  });

  // THE UNATTRIBUTABLE ARRIVAL, which the case above cannot express: there the flat
  // pin handed over is the store's own projection of the map's only entry, so
  // whatever the branch does with it writes back what is already there.
  //
  // Here the stored record has a key at the address it names, and the caller hands
  // over a flat pin that did NOT come off it - no map, changed address. The branch's
  // premise ("the flat pin came off the row as it was") is false, and nothing here
  // can tell that from a caller for which it is true. So the key already keyed there
  // wins and the arriving pin is DROPPED: overwriting would put a different
  // machine's key at an address the user may return to, and that connect aborts as a
  // MISMATCH, which reads as an attack out of a save about something else.
  // Dropping leaves that address exactly as fail-open as it was before the pin
  // existed. Both leave the new address unpinned; only overwriting invents a false
  // alarm.
  const keyed = await get("h-keyed");
  if (!isSshHost(keyed)) throw new Error("h-keyed came back on the wrong arm");
  await h.hosts.upsertHost({
    ...keyed,
    host: "c.example",
    lastFingerprint: "SHA256:C",
    // Explicit, because the stored record HAS a map: clearing it is what makes this
    // the no-map branch rather than the believed-caller one.
    pins: undefined,
  });
  check(
    "a flat pin that cannot be attributed does NOT replace the key already keyed there",
    row("h-keyed")?.pins,
    { "b.example": "SHA256:B" },
  );
  check(
    "and the address the caller moved to is left unpinned rather than given that key",
    hostFingerprint(await get("h-keyed")),
    undefined,
  );

  // The other half of the same branch: nothing is keyed at the stored address, so
  // keeping the arriving pin destroys nothing and is the only claim anyone has made
  // about that address. Filed there, not on the address the caller moved to - which
  // is the mis-attribution the whole branch exists to prevent. For the spread caller
  // this is the no-op it always was; it is reachable at all only for a caller that
  // sets a flat pin the stored row did not carry, so it is a guard on a future
  // caller rather than a live path today.
  const gap = await get("h-gap");
  if (!isSshHost(gap)) throw new Error("h-gap came back on the wrong arm");
  await h.hosts.upsertHost({
    ...gap,
    host: "c.example",
    lastFingerprint: "SHA256:X",
    pins: undefined,
  });
  check("with nothing keyed there, the pin is kept rather than discarded", row("h-gap")?.pins, {
    "a.example": "SHA256:A",
    "b.example": "SHA256:X",
  });
  check(
    "still at the STORED address, never at the one the caller moved to",
    hostFingerprint(await get("h-gap")),
    undefined,
  );

  // A FIRST SAVE of an id this store has never seen, carrying a flat pin and no
  // map. There is no earlier address it could have come from, so its own is the only
  // reading - and dropping it would make a restored host re-ask.
  await h.hosts.upsertHost(
    sshHost({ id: "h-new", host: "i.example", lastFingerprint: "SHA256:FIRST" }),
  );
  check("a flat pin on a new row is kept", hostFingerprint(await get("h-new")), "SHA256:FIRST");
  check("keyed onto the address it arrived with", row("h-new")?.pins, {
    "i.example": "SHA256:FIRST",
  });

  // Both protocols through the same code, since the flat field's NAME is the only
  // thing that differs and a projection written for one arm would silently do
  // nothing for the other.
  await h.hosts.upsertHost({ ...(await get("h-rdp")), name: "renamed" });
  check("the RDP arm is keyed the same way", row("h-rdp")?.pins, { "r.example": "SHA256:CERT" });
  check("and projects into certFingerprint", hostFingerprint(await get("h-rdp")), "SHA256:CERT");
}

// ---------------------------------------------------------------------------
console.log("\n[pins] an IMPORT keys the file's pin onto the address the FILE names");
{
  // THE COMPOSITION, because neither half fails on its own. `sanitizePayload` is
  // the import's trust boundary, `upsertHost` is what persists, and between them
  // sits `carryPins` - whose only job is that the store never has to infer which
  // machine an imported pin came off. `nextPins`'s inference is written for a
  // `{ ...stored, host: next }` spread, and a file's row is not one; the block above
  // pins what that inference does when it is handed a pin it cannot attribute.
  //
  // The fixture is the case `ImportCounts.replaced` exists for: the same host id is
  // saved here at `b.example` and named `c.example` by the file. Inferring from the
  // stored record files `c.example`'s key at `b.example` - so every later connect to
  // `b.example` aborts as a MISMATCH and can never TOFU past it - and leaves
  // `c.example`, the address about to be dialled, silently unpinned even though the
  // file carried a verified anchor for it.
  const h = harness({
    hosts: [
      sshHost({
        id: "h-1",
        host: "b.example",
        pins: { "b.example": "SHA256:B" },
        lastFingerprint: "SHA256:B",
      }),
    ],
  });
  const row = (from: () => Host[]) => from().find((x) => x.id === "h-1");
  /** The flat projection off the PERSISTED row, which is the field every connect
   *  reads. `"MISSING"` rather than `undefined`, so a vanished row cannot pass a
   *  check that expects no pin. */
  const flat = (from: () => Host[]): string | undefined => {
    const found = row(from);
    return found ? hostFingerprint(found) : "MISSING";
  };
  // A decrypted v2 payload, as raw as `applyV2` gets it: one row, at an address
  // this machine does not have for that id, carrying only the flat pin a pre-keying
  // export wrote.
  const file = sanitizePayload({
    hosts: [
      {
        id: "h-1",
        protocol: "ssh",
        name: "prod",
        host: "c.example",
        port: 22,
        credential: { kind: "inline", hostId: "h-1", user: "root", authMode: "password" },
        lastFingerprint: "SHA256:C",
      },
    ],
  });
  check("the row survived the boundary", file.hosts.length, 1);
  for (const incoming of carryPins(file.hosts, await h.hosts.listHosts())) {
    await h.hosts.upsertHost(incoming);
  }
  check("the file's pin is filed under the address the FILE named", row(h.rows)?.pins, {
    "b.example": "SHA256:B",
    "c.example": "SHA256:C",
  });
  check(
    "so the address about to be dialled is pinned rather than downgraded to TOFU",
    flat(h.rows),
    "SHA256:C",
  );

  // A ROUND TRIP, through the same serialization `buildBackup` performs: an export
  // ships whole records, so the file carries every address the host has trusted
  // rather than only the one it currently names. `h-1` now has two. Both have to
  // arrive on the far machine, or "returning to a reassigned old address aborts
  // instead of TOFU-accepting" is true only on the machine that wrote the file.
  const far = harness();
  const shipped = sanitizePayload(JSON.parse(JSON.stringify({ hosts: h.rows() })));
  for (const incoming of carryPins(shipped.hosts, await far.hosts.listHosts())) {
    await far.hosts.upsertHost(incoming);
  }
  check("a round trip carries the HISTORICAL address too", row(far.rows)?.pins, {
    "b.example": "SHA256:B",
    "c.example": "SHA256:C",
  });
  check(
    "and the flat projection still names the address the record carries",
    flat(far.rows),
    "SHA256:C",
  );
}

// ---------------------------------------------------------------------------
console.log("\n[pins] a duplicate inherits no pin, keyed or flat");
{
  // The flat field is a PROJECTION now, so clearing it alone is not enough: the
  // store would put it straight back from the map, at the copy's identical address.
  // Both fields, because that is what a STORED row looks like: the map is the
  // record and the flat field is the store's projection of it.
  const h = harness({
    hosts: [
      sshHost({
        id: "h-1",
        host: "a.example",
        pins: { "a.example": "SHA256:A" },
        lastFingerprint: "SHA256:A",
      }),
      rdpHost({
        id: "h-2",
        host: "r.example",
        pins: { "r.example": "SHA256:CERT" },
        certFingerprint: "SHA256:CERT",
      }),
    ],
  });
  const copy = await h.hosts.duplicateHost("h-1");
  assert(copy !== null, "the SSH host was duplicated");
  check("the copy has no flat pin", copy ? hostFingerprint(copy) : "MISSING", undefined);
  check("and no keyed pin either", copy?.pins, undefined);
  check(
    "while the source keeps its own",
    hostFingerprint((await h.hosts.listHosts()).filter(isSshHost)[0]),
    "SHA256:A",
  );

  const rdpCopy = await h.hosts.duplicateHost("h-2");
  check(
    "the RDP copy has no certificate pin",
    rdpCopy ? hostFingerprint(rdpCopy) : "MISSING",
    undefined,
  );
  check("and no keyed pin either", rdpCopy?.pins, undefined);
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

// ---------------------------------------------------------------------------
console.log("\n[concurrency] a save is refused when the binding moved under the caller");
{
  const h = harness();
  const loaded = await h.hosts.upsertHost(sshHost({ id: "h-1" }), { password: "hunter2" });
  const stamp = credentialStamp(loaded);
  check("what the caller loaded", stamp, CREDENTIAL_STAMP_INLINE);

  // Another writer converts it to a vault binding. No expectation passed, so this
  // one is unconditional - which is what an import or a convert action is.
  await h.hosts.upsertHost({ ...loaded, credential: { kind: "identity", identityId: "i-1" } });

  h.calls.length = 0;
  await rejects(
    "the stale caller's save is refused, naming both states",
    () => h.hosts.upsertHost(sshHost({ id: "h-1", name: "renamed" }), { password: "x" }, stamp),
    ["changed while this editor was open", "credentials of its own", "vault identity"],
  );
  check("and the refusal touched no keychain account at all", h.calls, []);
  const after = await h.hosts.findHost("h-1");
  check(
    "the vault binding survived the refused save",
    after && after.credential.kind === "identity" ? after.credential.identityId : null,
    "i-1",
  );
  check("and the name the stale save proposed did not land", after?.name, "prod");
}

// ---------------------------------------------------------------------------
console.log("\n[concurrency] the same expectation permits the save when nothing moved");
{
  const h = harness();
  const loaded = await h.hosts.upsertHost(sshHost({ id: "h-1" }), { password: "hunter2" });
  const saved = await h.hosts.upsertHost(
    sshHost({ id: "h-1", name: "renamed" }),
    {},
    credentialStamp(loaded),
  );
  check("an unchanged binding saves normally", saved.name, "renamed");
  check("and the untouched password is still there", h.kept.get(at("h-1", "password")), "hunter2");
}

// ---------------------------------------------------------------------------
console.log("\n[concurrency] a record deleted under the caller is refused, not recreated");
{
  const h = harness();
  const loaded = await h.hosts.upsertHost(sshHost({ id: "h-1" }));
  await h.hosts.deleteHost("h-1", noForwardRules);
  await rejects(
    "a save against a deleted record is refused and says so",
    () => h.hosts.upsertHost(sshHost({ id: "h-1" }), {}, credentialStamp(loaded)),
    ["deleted"],
  );
  check("and nothing was put back", await h.hosts.findHost("h-1"), undefined);
}

// ---------------------------------------------------------------------------
console.log("\n[concurrency] re-binding between two identities is a change, not a no-op");
{
  const h = harness();
  const loaded = await h.hosts.upsertHost(
    sshHost({ id: "h-1", credential: { kind: "identity", identityId: "i-1" } }),
  );
  await h.hosts.upsertHost({ ...loaded, credential: { kind: "identity", identityId: "i-2" } });
  await rejects(
    "identity:i-1 does not satisfy identity:i-2",
    () =>
      h.hosts.upsertHost(
        sshHost({ id: "h-1", credential: { kind: "identity", identityId: "i-1" } }),
        {},
        credentialStamp(loaded),
      ),
    ["vault identity"],
  );
}

// ---------------------------------------------------------------------------
console.log("\n[concurrency] no expectation means no check, for the callers that hold none");
{
  const h = harness();
  const loaded = await h.hosts.upsertHost(sshHost({ id: "h-1" }));
  await h.hosts.upsertHost({ ...loaded, credential: { kind: "identity", identityId: "i-1" } });
  const forced = await h.hosts.upsertHost(sshHost({ id: "h-1", name: "by import" }));
  check("an import with no expectation still writes", forced.name, "by import");
}

// ---------------------------------------------------------------------------
console.log(
  "\n[concurrency] create mode's call - expect ABSENT - is enforced too, not waved through",
);
{
  // The editor never special-cases create mode: `existing` is null there, so it
  // passes `credentialStamp(null)`, which is `CREDENTIAL_STAMP_ABSENT`, on every
  // create. Every OTHER section in this file either passes `undefined` or a
  // stamp read off a record that IS present - none of them passes
  // `expect === CREDENTIAL_STAMP_ABSENT` against an id another writer has since
  // claimed, so a guard silently rewritten to skip the check whenever
  // `expect === "absent"` - on the theory that "absent" means "no expectation" -
  // would leave every one of those sections green. This is the section that
  // closes it: the id a create-mode caller mints for itself is exactly the kind
  // of id someone else can also have raced to use first.
  const h = harness();
  await h.hosts.upsertHost(sshHost({ id: "h-1", name: "someone else's host" }));
  await rejects(
    "a stale create is refused, not silently overwritten",
    () =>
      h.hosts.upsertHost(sshHost({ id: "h-1", name: "my new host" }), {}, CREDENTIAL_STAMP_ABSENT),
    ["changed while this editor was open"],
  );
  const after = await h.hosts.findHost("h-1");
  check("the id's actual owner survived the refused create", after?.name, "someone else's host");
}

// ---------------------------------------------------------------------------
console.log(
  "\n[concurrency] the refusal is a HostBindingChangedError, not just a matching message",
);
{
  // Nothing above this line ever inspects the THROWN VALUE - `rejects` only
  // reads `e.message` - so a store that stopped constructing this class, or
  // built one with the wrong fields, passes every check above it while the
  // editor's `e instanceof HostBindingChangedError` / `e.actual` / `e.hostId`
  // reads silently break. Checked directly here instead.
  const h = harness();
  const loaded = await h.hosts.upsertHost(sshHost({ id: "h-1" }), { password: "hunter2" });
  const stamp = credentialStamp(loaded);
  await h.hosts.upsertHost({ ...loaded, credential: { kind: "identity", identityId: "i-1" } });

  let caught: unknown;
  try {
    await h.hosts.upsertHost(sshHost({ id: "h-1", name: "renamed" }), { password: "x" }, stamp);
  } catch (e) {
    caught = e;
  }
  assert(
    caught instanceof HostBindingChangedError,
    "the refusal is an instance of HostBindingChangedError, not a lookalike Error",
  );
  const err = caught as HostBindingChangedError;
  check("it carries the id of the host it was refused against", err?.hostId, "h-1");
  check("it carries what the caller expected", err?.expected, stamp);
  check("it carries what is actually stored now", err?.actual, "identity:i-1");
}

if (failed > 0) throw new Error(`hosts-store-verify: ${failed} FAILED`);
console.log("\nhosts-store-verify: OK\n");
