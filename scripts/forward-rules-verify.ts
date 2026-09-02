/**
 * Self-check for the forwards store: the record shape, the six write-time
 * refusals, and the `deleteHost` cleanup hook. Run:
 * `npx tsx scripts/forward-rules-verify.ts` (or `node scripts/verify-all.mjs
 * forward-rules`, which every other `*-verify.ts` in this suite runs under -
 * see that script's own comment for why it is `tsx` and not plain node: the
 * imports here, like every other script in the suite, are extensionless).
 *
 * Modelled on `scripts/vault-resolve-verify.ts`'s harness shape and its
 * `check(label, got, want)` signature (`vault-resolve-verify.ts:97`).
 *
 * Every property here is one whose failure is SILENT:
 *
 * 1. ROUND-TRIP. An upsert against a known id must REPLACE the stored rule, not
 *    append beside it - the same class of bug `vault/store.ts`'s own round-trip
 *    check guards, and here it would silently double every edit into two rows.
 *
 * 2. THE SIX REFUSALS, each pinned by its MESSAGE rather than by "it threw":
 *    `upsertRule` refuses a `hostId` that does not name a saved host, one that
 *    names an RDP host, a `localPort` outside `0` or `1-65535`, a `remotePort`
 *    outside `1-65535`, a blank `name`, and a blank `remoteHost`. The first two
 *    share one failure mode - both throw - so a substring-only check ("it threw
 *    and mentioned the host") would still pass with their messages swapped;
 *    pinning the exact text (`rejectsWith`, below) is what catches it.
 *
 * 3. `dropRulesForHost` REMOVES EXACTLY THE RIGHT ROWS, leaves the rest in
 *    order, and is a no-op for a host with no rules and for a host id that was
 *    never saved - the shape `deleteHost` needs when it is called for a host
 *    with zero forwards riding it, which is the common case.
 *
 * 4. `dropRulesForHost` NEVER CONSULTS A HOST LOOKUP. It runs from inside
 *    `hosts/store.ts`'s `deleteHost`, awaited before that queue touches the
 *    keychain or the host list (`hosts/store.ts:954-961`), so the host it is
 *    reacting to may already be gone. A version that cached the last
 *    `HostLookup` seen by `upsertRule` and consulted it here would work in
 *    every ordinary test and fail exactly there - which is why this section
 *    seeds that cache with a THROWING lookup before calling the drop.
 *
 * 5. `newRuleId()` IS OPAQUE AND UNIQUE, with the `f-` prefix every other
 *    accessor and every keychain-free assumption in this module rests on.
 *
 * The store's only ever port is the recovered-store file; there is no
 * `SecretsIo` for this script to inject, because a forward rule holds no secret
 * of its own - see `modules/forwards/adapters.ts`'s header.
 */
import { createWriteQueue } from "../src/lib/recoveredStore";
import type { ForwardsStoreIo } from "../src/modules/forwards/adapters";
import { createForwardStore, type HostLookup } from "../src/modules/forwards/store";
import type { ForwardRule } from "../src/modules/forwards/types";
import type { Host, RdpHost, SshHost } from "../src/modules/hosts/types";

let failed = 0;
function check(label: string, got: unknown, want: unknown): void {
  if (JSON.stringify(got) === JSON.stringify(want)) {
    console.log(`  ok: ${label}`);
  } else {
    console.error(`  FAIL: ${label} = ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
    failed++;
  }
}
/** Pins a refusal's message BY VALUE - the whole string, not a substring - per
 *  property 2's "not found" / "RDP" pair, which share a throw but must not
 *  share a message. */
async function rejectsWith(label: string, fn: () => Promise<unknown>, want: string): Promise<void> {
  try {
    await fn();
    console.error(`  FAIL: ${label} did not reject`);
    failed++;
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    check(label, msg, want);
  }
}

// ---------------------------------------------------------------------------
// In-memory port. The REAL write queue (`createWriteQueue`), so the round-trip
// and drop checks below exercise the shipped serialization rather than a copy
// of it living in this file - the same reasoning `vault-resolve-verify.ts`
// gives for doing the same with `enqueueWrite`.
// ---------------------------------------------------------------------------

function harness(seed: { rules?: ForwardRule[] } = {}) {
  const data: Record<string, unknown> = { rules: seed.rules ?? [] };
  const listeners = new Set<() => void>();
  let commits = 0;

  const store: ForwardsStoreIo = {
    async get<T>(key: string): Promise<T | null> {
      return (data[key] as T | undefined) ?? null;
    },
    async set(key: string, value: unknown): Promise<void> {
      data[key] = value;
    },
    async commit(): Promise<void> {
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
  };

  const forwards = createForwardStore({ store });
  return { forwards, data, commits: () => commits };
}

const rule = (over: Partial<ForwardRule> = {}): ForwardRule => ({
  id: "f-1",
  name: "web tunnel",
  hostId: "h-ssh",
  localPort: 8080,
  remoteHost: "127.0.0.1",
  remotePort: 80,
  startWithHost: false,
  ...over,
});

const sshHost = (over: Partial<SshHost> = {}): SshHost => ({
  id: "h-ssh",
  name: "bastion",
  host: "10.0.0.1",
  port: 22,
  protocol: "ssh",
  credential: { kind: "identity", identityId: "i-1" },
  ...over,
});

const rdpHost = (over: Partial<RdpHost> = {}): RdpHost => ({
  id: "h-rdp",
  name: "jump-desktop",
  host: "10.0.0.2",
  port: 3389,
  protocol: "rdp",
  credential: { kind: "identity", identityId: "i-1" },
  desktopWidth: 1920,
  desktopHeight: 1080,
  sizeMode: "preset",
  ...over,
});

/** A `HostLookup` over a fixed list, the shape the real host store's
 *  `findHost` gives `upsertRule`. */
function hostsOf(list: Host[]): HostLookup {
  return async (id) => list.find((h) => h.id === id);
}

// ---------------------------------------------------------------------------
console.log("\n[round-trip] upsert, list, find, and a repeat upsert replaces");
{
  const h = harness();
  const hosts = hostsOf([sshHost()]);

  const created = await h.forwards.upsertRule(rule(), hosts);
  check("upsert returns the rule as written", created, rule());
  check("listRules sees exactly it", await h.forwards.listRules(), [rule()]);
  check("findRule finds it by id", await h.forwards.findRule("f-1"), rule());
  check("finding an unknown id is undefined", await h.forwards.findRule("f-gone"), undefined);

  const replaced = rule({ name: "renamed", localPort: 9090 });
  await h.forwards.upsertRule(replaced, hosts);
  check(
    "a second upsert against the same id REPLACES rather than appends",
    (await h.forwards.listRules()).length,
    1,
  );
  check("and the replacement is what is stored", await h.forwards.findRule("f-1"), replaced);
}

// ---------------------------------------------------------------------------
console.log("\n[refusals] a hostId must name a saved SSH host");
{
  const h = harness();
  const hosts = hostsOf([sshHost(), rdpHost()]);

  await rejectsWith(
    "a hostId naming nothing saved is refused, by exact message",
    () => h.forwards.upsertRule(rule({ hostId: "h-ghost" }), hosts),
    'forwards: "web tunnel" names a host (h-ghost) that does not exist',
  );
  await rejectsWith(
    "a hostId naming an RDP host is refused, by a DIFFERENT exact message",
    () => h.forwards.upsertRule(rule({ hostId: "h-rdp" }), hosts),
    'forwards: "web tunnel" names a host (h-rdp) that is an RDP host and cannot carry a forward',
  );
  check("neither refusal wrote anything", (h.data.rules as ForwardRule[]).length, 0);

  const ok = await h.forwards.upsertRule(rule(), hosts);
  check("the paired positive: a valid SSH host is accepted", ok.hostId, "h-ssh");
}

// ---------------------------------------------------------------------------
console.log("\n[refusals] localPort is 0 or 1-65535; remotePort is 1-65535");
{
  const h = harness();
  const hosts = hostsOf([sshHost()]);

  await rejectsWith(
    "a negative localPort is refused",
    () => h.forwards.upsertRule(rule({ localPort: -1 }), hosts),
    'forwards: "web tunnel" has an invalid local port -1 - must be 0, or 1-65535',
  );
  await rejectsWith(
    "a localPort past 65535 is refused",
    () => h.forwards.upsertRule(rule({ localPort: 65536 }), hosts),
    'forwards: "web tunnel" has an invalid local port 65536 - must be 0, or 1-65535',
  );
  await rejectsWith(
    "remotePort 0 is refused - unlike localPort, 0 has no meaning here",
    () => h.forwards.upsertRule(rule({ remotePort: 0 }), hosts),
    'forwards: "web tunnel" has an invalid remote port 0 - must be 1-65535',
  );
  await rejectsWith(
    "a remotePort past 65535 is refused",
    () => h.forwards.upsertRule(rule({ remotePort: 65536 }), hosts),
    'forwards: "web tunnel" has an invalid remote port 65536 - must be 1-65535',
  );
  check("none of the four refusals wrote anything", (h.data.rules as ForwardRule[]).length, 0);

  const zero = await h.forwards.upsertRule(rule({ id: "f-a", localPort: 0 }), hosts);
  check("the paired positive: localPort 0 (let the OS pick) is accepted", zero.localPort, 0);
  const max = await h.forwards.upsertRule(rule({ id: "f-b", localPort: 65535 }), hosts);
  check("the paired positive: localPort 65535 is accepted", max.localPort, 65535);
}

// ---------------------------------------------------------------------------
console.log("\n[refusals] name and remoteHost may not be blank");
{
  const h = harness();
  const hosts = hostsOf([sshHost()]);

  await rejectsWith(
    "a blank name is refused",
    () => h.forwards.upsertRule(rule({ name: "  " }), hosts),
    "forwards: a rule needs a name",
  );
  await rejectsWith(
    "a blank remoteHost is refused",
    () => h.forwards.upsertRule(rule({ remoteHost: " " }), hosts),
    'forwards: "web tunnel" needs a remote host',
  );
  check("neither refusal wrote anything", (h.data.rules as ForwardRule[]).length, 0);
}

// ---------------------------------------------------------------------------
console.log("\n[dropRulesForHost] removes exactly the rules naming that host, in order");
{
  const h = harness();
  const hosts = hostsOf([sshHost({ id: "h-1" }), sshHost({ id: "h-2", name: "other" })]);

  await h.forwards.upsertRule(rule({ id: "f-1", hostId: "h-1", name: "a" }), hosts);
  await h.forwards.upsertRule(rule({ id: "f-2", hostId: "h-2", name: "b" }), hosts);
  await h.forwards.upsertRule(rule({ id: "f-3", hostId: "h-1", name: "c" }), hosts);
  await h.forwards.upsertRule(rule({ id: "f-4", hostId: "h-2", name: "d" }), hosts);

  await h.forwards.dropRulesForHost("h-1");
  check(
    "every rule naming h-1 is gone, and h-2's rules survive IN ORDER",
    (await h.forwards.listRules()).map((r) => r.id),
    ["f-2", "f-4"],
  );

  const before = await h.forwards.listRules();
  await h.forwards.dropRulesForHost("h-2-has-no-rules-of-its-own-yet-because-h-2-does");
  check("a host id with no rules at all is a no-op", await h.forwards.listRules(), before);

  await h.forwards.dropRulesForHost("h-never-saved");
  check("a host id that was never saved is a no-op too", await h.forwards.listRules(), before);
}

// ---------------------------------------------------------------------------
console.log("\n[dropRulesForHost] never consults a host lookup");
{
  // The property this exists to prove: `dropRulesForHost` runs from inside
  // `deleteHost`'s write queue, BEFORE that queue touches the host list, so the
  // host it is reacting to may already be gone (`hosts/store.ts:954-961`). A
  // version that cached the last `HostLookup` seen by `upsertRule` and
  // consulted it here would pass every check above and fail only here.
  const h = harness();
  const throwingHosts: HostLookup = () => {
    throw new Error("forwards: a host lookup must never be reachable from a drop");
  };

  // Seed the rule to be dropped with a WORKING lookup first...
  const goodHosts = hostsOf([sshHost({ id: "h-1" })]);
  await h.forwards.upsertRule(rule({ id: "f-1", hostId: "h-1" }), goodHosts);

  // ...then make the throwing lookup the MOST RECENT one `upsertRule` was
  // handed, immediately before the drop. This is what a cache-the-last-one
  // mutant would be left holding: the upsert it is attached to must fail on
  // its own (not a claim about WHY it throws, only about what gets left
  // behind), and the drop that follows must still succeed - if
  // `dropRulesForHost` reached for the cached lookup at all, THIS is the call
  // that would surface it, and swapping the seed/probe order back would let
  // this section pass for the wrong reason (found live: swapping them made
  // the S6 mutation below pass instead of fail).
  await rejectsWith(
    "(setup) an upsert against a throwing lookup fails on its own",
    () => h.forwards.upsertRule(rule({ id: "f-99", hostId: "h-1" }), throwingHosts),
    "forwards: a host lookup must never be reachable from a drop",
  );
  check(
    "the failed setup wrote nothing beyond the seed",
    (h.data.rules as ForwardRule[]).length,
    1,
  );

  // A clean check rather than a bare `await`, so a mutant that DOES reach for
  // the cached lookup reports as one FAIL line here instead of crashing the
  // process and hiding every check after it.
  let dropError: unknown;
  try {
    await h.forwards.dropRulesForHost("h-1");
  } catch (e) {
    dropError = e;
  }
  check("the drop did not reject even with a throwing lookup cached", dropError, undefined);
  check(
    "and it removed the rule, proving it ran rather than short-circuiting",
    await h.forwards.listRules(),
    [],
  );
}

// ---------------------------------------------------------------------------
console.log("\n[delete] deleteRule refuses nothing - nothing references a rule");
{
  const h = harness();
  const hosts = hostsOf([sshHost()]);
  await h.forwards.upsertRule(rule(), hosts);
  await h.forwards.deleteRule("f-1");
  check("the rule is gone", await h.forwards.listRules(), []);
  await h.forwards.deleteRule("f-gone");
  console.log("  ok: deleting an id that is already gone is a no-op, not a throw");
}

// ---------------------------------------------------------------------------
console.log("\n[ids] newRuleId returns distinct, f-prefixed ids");
{
  const h = harness();
  const a = h.forwards.newRuleId();
  const b = h.forwards.newRuleId();
  check("both are f-prefixed", [/^f-/.test(a), /^f-/.test(b)], [true, true]);
  check("and distinct", a !== b, true);
}

if (failed > 0) throw new Error(`forward-rules-verify: ${failed} FAILED`);
console.log("\nforward-rules-verify: OK\n");
