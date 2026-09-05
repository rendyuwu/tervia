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
 *    keychain or the host list (`deleteHost`'s own `await forwards(id)` runs
 *    ahead of both `deleteAccounts` and the row drop), so the host it is
 *    reacting to may already be gone. A version that cached the last
 *    `HostLookup` seen by `upsertRule` and consulted it here would work in
 *    every ordinary test and fail exactly there - which is why this section
 *    seeds that cache with a THROWING lookup before calling the drop.
 *
 * 5. `newRuleId()` IS OPAQUE AND UNIQUE, with the `f-` prefix every other
 *    accessor and every keychain-free assumption in this module rests on.
 *
 * 6. `HostsPage.tsx`'s `confirmDelete` WIRES THIS MODULE IN: `deleteHost`'s
 *    second argument is the bare `releaseRulesForHost` identifier, passed by
 *    name, not a wrapper that could silently un-await it -
 *    `hosts/store.ts`'s `deleteHost` awaits it FIRST and unconditionally (its
 *    own `await forwards(id)`, ahead of `deleteAccounts` and the row drop),
 *    and a wrapper that swallows the promise defeats that ordering without
 *    failing `tsc`. Source-text over `HostsPage.tsx`, because nothing about
 *    this store changes here; the property is about the caller.
 *
 *    THE PROPERTY IS UNCHANGED AND ONLY THE IDENTIFIER MOVED. The page used
 *    to hand over this module's own `dropRulesForHost`; it now hands over
 *    `modules/forwards/controller.ts`'s `releaseRulesForHost`, which awaits a
 *    release for every rule riding the host and only then calls the drop. It
 *    reaches this module through that function rather than around it, and the
 *    reason is that dropping the RECORDS releases nothing: each rule the page
 *    had running would be left with `ssh/tunnel.ts`'s entry at `refs: 1`, its
 *    SSH session never closing for the rest of the app's life, and its local
 *    port still bound.
 *
 *    TWO SCRIPTS PIN THIS ONE CALL SITE, DELIBERATELY, AND THE OVERLAP IS NOT
 *    SYMMETRIC - measured rather than assumed, because "they prove different
 *    things" is the kind of claim that reads true and is not. This check pins
 *    the SECOND ARGUMENT'S OWN EXPRESSION TEXT. Section 11b of
 *    `scripts/forwards-shell-verify.ts` pins the WHOLE argument list AND the
 *    page's import set, so at this call site it reddens on everything this
 *    check reddens on and on one thing more: the page importing
 *    `dropRulesForHost` again while still handing the release over by name,
 *    which leaves this check GREEN.
 *
 *    So this one is kept for INDEPENDENCE, not for coverage. They are separate
 *    scripts with separate file maps and separate parsers, so a regression in
 *    one script's own machinery - a `stripComments` bug, a stale path, a
 *    module-load error taking a script dark rather than red - does not silence
 *    the other. Delete either and the call site is pinned by one process.
 *
 * The store's only ever port is the recovered-store file; there is no
 * `SecretsIo` for this script to inject, because a forward rule holds no secret
 * of its own - see `modules/forwards/adapters.ts`'s header.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import ts from "typescript";

import { createWriteQueue } from "../src/lib/recoveredStore";
import type { ForwardsStoreIo } from "../src/modules/forwards/adapters";
import { createForwardStore, type HostLookup } from "../src/modules/forwards/store";
import type { ForwardRule } from "../src/modules/forwards/types";
import type { Host, RdpHost, SshHost } from "../src/modules/hosts/types";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (p: string) => readFileSync(join(root, p), "utf8");

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

/** A line with its trailing `//` comment removed, string literals respected -
 *  quote-aware rather than a regex because a `//` inside a string is not a
 *  comment. Copied from `scripts/host-editor-verify.ts`. */
function stripLineComment(line: string): string {
  let quote = "";
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote) {
      if (c === "\\") i++;
      else if (c === quote) quote = "";
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      quote = c;
      continue;
    }
    if (c === "/" && line[i + 1] === "/") return line.slice(0, i);
  }
  return line;
}

/**
 * The same source with comments removed, for the POSITIVE half of property 6
 * below - a positive over raw source is satisfied by a comment that merely
 * CLAIMS the wiring, so it must run over text a comment cannot survive.
 *
 * Copied from `scripts/host-editor-verify.ts:191`, including its JSX branch:
 * a JSX comment expression is the only comment syntax legal INSIDE JSX
 * children, and the negative-lookahead form below is deliberate - the lazy
 * form `\{\s*\/\*[\s\S]*?\*\/\s*\}` reads as equivalent but is allowed to
 * cross an intervening close-comment marker while searching for one followed
 * by `}`, and on a real file it swallowed 50752 characters between two
 * unrelated comments, silencing a negative check that then ran blind over
 * deleted text. The negative lookahead forbids the inner group from ever
 * crossing a close-comment marker at all, so the first one found is final.
 */
function stripComments(src: string): string {
  const withoutJsxComments = src.replace(/\{\s*\/\*(?:(?!\*\/)[\s\S])*\*\/\s*\}/g, "");
  return withoutJsxComments
    .split("\n")
    .filter((line) => {
      const t = line.trim();
      return !(t.startsWith("//") || t.startsWith("/*") || t.startsWith("*"));
    })
    .map(stripLineComment)
    .join("\n");
}

/** Every `CallExpression` whose callee's own text is one of `calleeNames`,
 *  found by walking the whole tree - the same shape `vault-editor-verify.ts`'s
 *  `findCalls` uses for the same reason: "is this the call I mean" is a
 *  question about the parsed callee, not about a substring of the file. */
function findCalls(root: ts.Node, sf: ts.SourceFile, calleeNames: string[]): ts.CallExpression[] {
  const out: ts.CallExpression[] = [];
  const visit = (n: ts.Node): void => {
    if (ts.isCallExpression(n) && calleeNames.includes(n.expression.getText(sf))) out.push(n);
    ts.forEachChild(n, visit);
  };
  visit(root);
  return out;
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
    // Nothing here drives the anti-blank guard in `modules/workspaces/store.ts`,
    // which is the only caller: a good file is the honest answer for a fixture
    // with no file behind it at all.
    fileState: async () => ({ found: "ok" as const, recovered: false }),
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

// ---------------------------------------------------------------------------
console.log(
  "\n[cascade wiring] HostsPage.confirmDelete passes releaseRulesForHost by name - not noForwardRules, and not a wrapper",
);
{
  // Self-test for `stripComments`: a comment that
  // is NOT a JSX comment expression (a plain block comment mid-line, inside a
  // type literal) must survive, and code that follows it must too; a JSX
  // comment expression must not.
  const probe = stripComments(
    "type P = { /** c */ x: X };\nconst KEEP = 1;\nconst j = <div>{/* c */}</div>;",
  );
  check(
    "stripComments self-test: code after a non-JSX comment survives",
    probe.includes("KEEP"),
    true,
  );
  check(
    "stripComments self-test: the JSX comment expression is gone",
    probe.includes("{/* c */}"),
    false,
  );

  const hostsPageRaw = read("src/modules/hosts/HostsPage.tsx");

  // NEGATIVE, over RAW source: a negative over raw source is what catches a
  // comment that still CLAIMS the old wiring even after the call site itself
  // was fixed - stripping comments first would blind this half to exactly
  // that. `noForwardRules` stays exported from `hosts/store.ts`
  // and stays in `hosts-store-verify.ts`'s fixtures; this checks only that
  // `HostsPage.tsx` no longer names it, anywhere.
  check(
    "HostsPage.tsx contains no reference to noForwardRules at all",
    hostsPageRaw.includes("noForwardRules"),
    false,
  );

  // POSITIVE, over COMMENT-STRIPPED source and the PARSED call: a positive
  // over raw source is satisfied by a comment that merely claims the wiring
  // is right, and a substring check on top of that
  // (`src.includes("releaseRulesForHost")`) is satisfied by
  // `(id) => { releaseRulesForHost(id); return; }` - one line, compiles, and
  // silently un-awaits the cleanup, so the fail-closed ordering
  // `deleteHost`'s own `await forwards(id)` gives it is gone. Reading the
  // second argument's own expression text off the AST, whitespace-normalised
  // only, is what refuses that shape: a wrapper is an arrow function and not a
  // bare identifier, whatever it wraps and whatever it is named.
  //
  // THE IDENTIFIER MOVED AND THE PROPERTY DID NOT. The page now reaches this
  // module's `dropRulesForHost` through `forwards/controller.ts`'s
  // `releaseRulesForHost`, which awaits a release for every rule riding the
  // host first - dropping the records alone releases nothing. What is asserted
  // here is still "by name, never a wrapper", and it is the SECOND ARGUMENT'S
  // OWN EXPRESSION TEXT that is asserted. `forwards-shell-verify.ts`'s section
  // 11b pins the same call site more tightly - the whole argument list plus the
  // page's import set - so it reddens on everything this reddens on and on the
  // page importing the store's drop again, which this leaves green. Kept for
  // INDEPENDENCE rather than coverage: two scripts, two parsers, so one going
  // dark does not leave the call site unpinned. See this file's header item 6.
  const stripped = stripComments(hostsPageRaw);
  const sf = ts.createSourceFile(
    "HostsPage.tsx",
    stripped,
    ts.ScriptTarget.ESNext,
    true,
    ts.ScriptKind.TSX,
  );
  const deleteHostCalls = findCalls(sf, sf, ["deleteHost"]);
  check("exactly one deleteHost(...) call site in HostsPage.tsx", deleteHostCalls.length, 1);

  const call = deleteHostCalls[0];
  const secondArgText =
    call && call.arguments.length >= 2
      ? call.arguments[1].getText(sf).replace(/\s+/g, "")
      : "<deleteHost call or its second argument is missing>";
  check(
    "deleteHost's second argument is the bare identifier releaseRulesForHost, whitespace-normalised",
    secondArgText,
    "releaseRulesForHost",
  );
}

if (failed > 0) throw new Error(`forward-rules-verify: ${failed} FAILED`);
console.log("\nforward-rules-verify: OK\n");
