/**
 * Self-check for the host search ranking shared by the Hosts page search box
 * and the header quick-connect (research §5.5, §5.8, §12.11).
 * Run: `pnpm verify` (or `npx tsx scripts/hosts-search-verify.ts` to iterate).
 *
 * The whole point of ONE ranking function with two mount points is that the
 * page and the header can never show a different "top match" for the same
 * query. That guarantee has two halves, and the tier checks are neither of them:
 *
 *   The tie-break chain is TOTAL, so a shuffled input produces the identical
 *   output order every time. [totality] below.
 *
 *   Both mount points build their ROWS the same way. They did not - the header
 *   resolved a username inline and the page resolved it through the vault - which
 *   is the whole of [two surfaces] below and the reason `searchRows` moved into
 *   `search.ts`. Sharing `rankHosts` alone was never enough: it cannot see a
 *   difference in what it was handed.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  inlineUsername,
  parseAdHocTarget,
  rankHosts,
  searchRows,
  type HostSearchRow,
} from "../src/modules/hosts/search";
import type { HostGroup, RdpHost, SshHost } from "../src/modules/hosts/types";
import type { VaultIdentity } from "../src/modules/vault/types";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (p: string) => readFileSync(join(root, p), "utf8");

let failed = 0;

/**
 * JSON with object keys SORTED, and `undefined` values kept.
 *
 * `JSON.stringify` was doing two things wrong here. It is key-ORDER sensitive,
 * so reordering the fields of a returned object failed a check that no behaviour
 * had changed. And it DROPS keys whose value is `undefined`, so comparing
 * `parseAdHocTarget("host")` against `{ host: "host" }` left `user` and `port`
 * completely unconstrained - the check passed whatever they were, including
 * absent, which is the opposite of what `search.ts` promises.
 *
 * So: field order is deliberately NOT part of what `check` compares. Where key
 * order genuinely is the contract - `parseAdHocTarget`'s fixed shape - the check
 * asserts `Object.keys` directly instead of hoping a string comparison notices.
 *
 * ARRAY order is preserved, and that is the point of the distinction: for a
 * ranked list the order IS the contract, and canonicalising it away would delete
 * most of this file's content.
 */
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (typeof value === "object" && value !== null) {
    const body = Object.entries(value as Record<string, unknown>)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`)
      .join(",");
    return `{${body}}`;
  }
  return value === undefined ? "undefined" : JSON.stringify(value);
}

function check(label: string, got: unknown, want: unknown): void {
  const g = canonical(got);
  const w = canonical(want);
  if (g === w) {
    console.log(`  ok: ${label}`);
  } else {
    console.error(`  FAIL: ${label} = ${g}, want ${w}`);
    failed++;
  }
}
function ok(label: string, cond: boolean): void {
  if (cond) console.log(`  ok: ${label}`);
  else {
    console.error(`  FAIL: ${label}`);
    failed++;
  }
}

// --- fixtures -----------------------------------------------------------

function ssh(
  id: string,
  name: string,
  host: string,
  opts: { lastConnectedAt?: number; identity?: boolean; user?: string } = {},
): SshHost {
  return {
    id,
    name,
    host,
    port: 22,
    protocol: "ssh",
    lastConnectedAt: opts.lastConnectedAt,
    credential: opts.identity
      ? { kind: "identity", identityId: "vault-1" }
      : {
          kind: "inline",
          hostId: id,
          user: opts.user ?? "root",
          authMode: "password",
          hasPassword: true,
          hasPrivateKey: false,
          hasKeyPassphrase: false,
        },
  };
}

function rdp(id: string, name: string, host: string, opts: { user?: string } = {}): RdpHost {
  return {
    id,
    name,
    host,
    port: 3389,
    protocol: "rdp",
    desktopWidth: 1920,
    desktopHeight: 1080,
    sizeMode: "preset",
    credential: {
      kind: "inline",
      hostId: id,
      username: opts.user ?? "administrator",
      hasPassword: true,
    },
  };
}

function row(host: SshHost | RdpHost, extra: Partial<HostSearchRow> = {}): HostSearchRow {
  return { host, username: inlineUsername(host), groupName: undefined, ...extra };
}

const names = (rows: HostSearchRow[]) => rows.map((r) => r.host.name);

// --- tier 1: exact name match beats everything else ---------------------

console.log("[tier 1] exact name match outranks a prefix, word-boundary or substring match");
{
  const exact = ssh("h-1", "db", "10.0.0.1");
  const prefix = ssh("h-2", "db-prod", "10.0.0.2");
  const boundary = ssh("h-3", "prod-db", "10.0.0.3");
  const substring = ssh("h-4", "adbox", "10.0.0.4");
  const result = rankHosts([row(prefix), row(substring), row(boundary), row(exact)], "db");
  check("order is exact, prefix, word-boundary, substring", names(result), [
    "db",
    "db-prod",
    "prod-db",
    "adbox",
  ]);
}

// --- tier 2: name prefix beats host prefix ------------------------------

console.log("\n[tier 2] name-prefix outranks host-prefix and word-boundary matches");
{
  const namePrefix = ssh("h-1", "webapp", "10.0.0.1");
  const hostPrefix = ssh("h-2", "app", "webserver.internal");
  const boundary = ssh("h-3", "prod-web", "10.0.0.3");
  const result = rankHosts([row(hostPrefix), row(boundary), row(namePrefix)], "web");
  check("order is name-prefix, host-prefix, word-boundary", names(result), [
    "webapp",
    "app",
    "prod-web",
  ]);
}

// --- tier 3: host prefix beats word-boundary and substring --------------

console.log("\n[tier 3] host-prefix outranks word-boundary and substring matches");
{
  const hostPrefix = ssh("h-1", "gateway", "app.internal");
  const boundary = ssh("h-2", "backend", "prod-app-1");
  // "app" is buried mid-word here (no delimiter before it), so this can only
  // land in tier 5, never tier 4 - the fixture that actually isolates tier 3.
  const substring = ssh("h-3", "myapplication", "10.0.0.9");
  const result = rankHosts([row(substring), row(boundary), row(hostPrefix)], "app");
  check("order is host-prefix, word-boundary, substring", names(result), [
    "gateway",
    "backend",
    "myapplication",
  ]);
}

// --- tier 4: word-boundary beats plain substring -------------------------

console.log("\n[tier 4] a word-boundary hit outranks a bare substring hit");
{
  const boundary = ssh("h-1", "prod-db-01", "10.0.0.1"); // "db" starts a word
  const substring = ssh("h-2", "adbox", "10.0.0.2"); // "db" is buried mid-word
  const result = rankHosts([row(substring), row(boundary)], "db");
  check("word-boundary match comes first", names(result), ["prod-db-01", "adbox"]);
}
{
  const dot = ssh("h-1", "x.mail", "h");
  const dash = ssh("h-2", "x-mail", "h");
  const underscore = ssh("h-3", "x_mail", "h");
  const spaced = ssh("h-4", "x mail", "h");
  const noBoundary = ssh("h-5", "xmail", "h"); // "mail" is not word-initial here
  const result = rankHosts(
    [row(noBoundary), row(dot), row(dash), row(underscore), row(spaced)],
    "mail",
  );
  // The four boundary forms tie with each other on tier (all 4) and are only
  // ordered between themselves by the name tie-break, which is not what this
  // check is about - so compare them as a set, and check the no-boundary form
  // separately, ranked strictly last.
  const top4 = names(result).slice(0, 4).sort();
  check(
    "'.', '-', '_' and space all count as word boundaries",
    top4,
    ["x mail", "x-mail", "x.mail", "x_mail"].sort(),
  );
  check("the no-boundary (tier 5) form ranks after all four", names(result)[4], "xmail");
}

// --- tier 5: substring in username or group name, and dropped non-matches -

console.log("\n[tier 5] a match found only via username or only via group name still ranks");
{
  const viaUser = row(ssh("h-1", "box-one", "10.0.0.1", { user: "deploy" }));
  const viaGroup = row(ssh("h-2", "box-two", "10.0.0.2"), { groupName: "deploy-team" });
  const noMatch = row(ssh("h-3", "box-three", "10.0.0.3"));
  const result = rankHosts([noMatch, viaUser, viaGroup], "deploy");
  check("both match, the non-match is dropped (not sorted to the bottom)", names(result).sort(), [
    "box-one",
    "box-two",
  ]);
}
// A vault-bound row carries no inline username. The version of this that was
// here asserted `.length === 1` over a SINGLE-row input, which passes for any
// implementation that does not drop every row - a `matchTier` hardwired to 5
// passed it - and it never said that the absent username was what forced the
// name match. Both halves are now stated against a list with a non-match and a
// control in it.
{
  const bound = row(ssh("h-1", "identity-box", "10.0.0.1", { identity: true }));
  const carries = row(ssh("h-2", "other-box", "10.0.0.2", { user: "svcacct" }));
  const noMatch = row(ssh("h-3", "unrelated", "10.0.0.9"));
  ok("a vault-bound row really has no inline username to match on", bound.username === undefined);
  check(
    "it still matches on its NAME, and only it does",
    names(rankHosts([bound, carries, noMatch], "identity")),
    ["identity-box"],
  );
  check(
    "and a username-only query reaches the row that carries one, not this one",
    names(rankHosts([bound, carries, noMatch], "svcacct")),
    ["other-box"],
  );
}

// --- case folding, in both directions ------------------------------------
//
// Every query in the tier blocks above is already lowercase, and `matchTier`
// lowercases the fields itself - so `rankHosts`'s own `query.trim().toLowerCase()`
// was removable with ZERO failures, and so were `matchTier`'s folds on `username`
// and `groupName`, which nothing above ever fed a capital letter to. Each check
// below is written to die if exactly one of those five folds is dropped: an
// uppercase query against a lowercase field kills the query fold, a lowercase
// query against a mixed-case field kills that field's fold, and each list carries
// a non-matching row so a `matchTier` that stopped discriminating fails too.

console.log("\n[case folding] an uppercase query and an uppercase field both fold");
{
  const noise = row(ssh("h-9", "unrelated", "10.0.0.9"));

  // Uppercase QUERY, lowercase fields: only `rankHosts`'s own fold can match.
  const lower = ssh("h-1", "prod-db", "10.0.0.1");
  check(
    "an UPPERCASE query matches a lowercase name",
    names(rankHosts([row(lower), noise], "PROD-DB")),
    ["prod-db"],
  );
  check("a MiXeD-case query matches it too", names(rankHosts([row(lower), noise], "Prod-Db")), [
    "prod-db",
  ]);

  // Lowercase query, mixed-case NAME: only `matchTier`'s name fold can match.
  const upperName = ssh("h-2", "ProdDB", "10.0.0.2");
  check(
    "a lowercase query matches a mixed-case name exactly (tier 1)",
    names(rankHosts([row(upperName), noise], "proddb")),
    ["ProdDB"],
  );

  // Mixed-case HOST, with a name that cannot match at all - isolates the host fold.
  const upperHost = ssh("h-3", "gateway", "Prod.Example.COM");
  check(
    "a lowercase query matches a mixed-case host prefix (tier 3)",
    names(rankHosts([row(upperHost), noise], "prod")),
    ["gateway"],
  );
  check(
    "and a mixed-case host's later word (tier 4)",
    names(rankHosts([row(upperHost), noise], "example")),
    ["gateway"],
  );

  // The two folds nothing above exercised at all.
  const upperUser = row(ssh("h-4", "box-four", "10.0.0.4", { user: "Deploy" }));
  const upperGroup = row(ssh("h-5", "box-five", "10.0.0.5"), { groupName: "Deploy-Team" });
  check(
    "a lowercase query matches a mixed-case USERNAME",
    names(rankHosts([upperUser, noise], "deploy")),
    ["box-four"],
  );
  check(
    "a lowercase query matches a mixed-case GROUP NAME",
    names(rankHosts([upperGroup, noise], "deploy")),
    ["box-five"],
  );
  // Both ends at once, which needs the query fold and the field fold together.
  check(
    "an uppercase query matches a mixed-case username",
    names(rankHosts([upperUser, noise], "DEPLOY")),
    ["box-four"],
  );
  check(
    "an uppercase query matches a mixed-case group name",
    names(rankHosts([upperGroup, noise], "DEPLOY")),
    ["box-five"],
  );
}

// --- full tie-break chain, including the id tail ------------------------

console.log("\n[tie-break] lastConnectedAt desc, then name, then id - in that order");
{
  const newer = ssh("h-2", "srv", "10.0.0.1", { lastConnectedAt: 2000 });
  const older = ssh("h-1", "srv", "10.0.0.1", { lastConnectedAt: 1000 });
  const never = ssh("h-3", "srv", "10.0.0.1");
  // Query matches all three identically (same tier), so only the tie-break
  // chain can be deciding the order.
  const result = rankHosts([row(never), row(older), row(newer)], "srv");
  check(
    "ids in the right order for the lastConnectedAt tier",
    result.map((r) => r.host.id),
    ["h-2", "h-1", "h-3"],
  );
}
{
  // Same name, same (absent) lastConnectedAt: only `id` can break the tie.
  const b = ssh("h-b", "twin", "10.0.0.1");
  const a = ssh("h-a", "twin", "10.0.0.1");
  const result = rankHosts([row(b), row(a)], "twin");
  check(
    "id is the final, total tie-break",
    result.map((r) => r.host.id),
    ["h-a", "h-b"],
  );
}
{
  // Same lastConnectedAt: name (case-insensitive) breaks the tie next.
  const upper = ssh("h-1", "Zebra", "10.0.0.1", { lastConnectedAt: 500 });
  const lower = ssh("h-2", "apple", "10.0.0.2", { lastConnectedAt: 500 });
  const result = rankHosts([row(upper), row(lower)], "");
  check("name breaks a lastConnectedAt tie, case-insensitively", names(result), ["apple", "Zebra"]);
}

// --- totality: a shuffled input produces an identical output order ------

console.log("\n[totality] the ordering does not depend on input order");
{
  const pool: SshHost[] = [
    ssh("h-1", "alpha-db", "10.0.0.1", { lastConnectedAt: 300 }),
    ssh("h-2", "alpha-db", "10.0.0.1"),
    ssh("h-3", "beta-db", "10.0.0.2", { lastConnectedAt: 100 }),
    ssh("h-4", "beta-db", "10.0.0.3", { lastConnectedAt: 100 }),
    ssh("h-5", "gamma", "db.internal"),
    ssh("h-6", "unrelated", "10.0.0.9"),
  ];
  const rows = pool.map((h) => row(h));
  // Compare by ID, not name: h-3 and h-4 share the name "beta-db" on purpose
  // (that pair is what proves the id tail actually runs), so a names-only
  // comparison here would not notice their relative order flipping.
  const ids = (rs: HostSearchRow[]) => rs.map((r) => r.host.id);
  const baseline = ids(rankHosts(rows, "db"));
  // Hand-picked rather than a random shuffle, so a failure here is reproducible
  // without a fixed seed. The IDENTITY permutation [0,1,2,3,4,5] was in this set
  // and has been removed: it re-runs the baseline against itself, so it passes
  // for every possible implementation and made a set of three real permutations
  // read as four.
  const permutations = [
    [5, 4, 3, 2, 1, 0],
    [2, 0, 4, 1, 5, 3],
    [3, 1, 4, 0, 5, 2],
    [1, 0, 3, 2, 5, 4],
  ];
  // Guards the guard. Re-adding an identity permutation would quietly make one
  // of these vacuous again, and nothing else in the file would notice.
  ok(
    "no permutation is the identity",
    permutations.every((order) => order.some((from, to) => from !== to)),
  );
  let allMatch = true;
  for (const order of permutations) {
    const shuffled = order.map((i) => rows[i]);
    const got = ids(rankHosts(shuffled, "db"));
    if (JSON.stringify(got) !== JSON.stringify(baseline)) {
      allMatch = false;
      console.error(`  FAIL: order ${JSON.stringify(order)} gave ${JSON.stringify(got)}`);
    }
  }
  ok("every permutation ranks identically to the baseline", allMatch);
  // h-6 "unrelated" matches nothing and is dropped. h-5 "gamma" matches only
  // via its host ("db.internal" is a host-prefix hit, tier 3). The rest match
  // via a word-boundary hit on their name ("alpha-db"/"beta-db", tier 4) and
  // are ordered within that tier by lastConnectedAt (h-1:300, h-3&h-4:100 tied
  // then broken by id, h-2: absent, last).
  check("baseline itself is the expected order", baseline, ["h-5", "h-1", "h-3", "h-4", "h-2"]);
}

// --- empty query: the default order, via the SAME comparator ------------

console.log("\n[empty query] default order is lastConnectedAt desc, then name, then id");
{
  const a = ssh("h-1", "bravo", "10.0.0.1", { lastConnectedAt: 100 });
  const b = ssh("h-2", "alpha", "10.0.0.2", { lastConnectedAt: 200 });
  const c = ssh("h-3", "charlie", "10.0.0.3");
  check("blank query keeps every row", names(rankHosts([row(a), row(b), row(c)], "")).length, 3);
  check("blank query default order", names(rankHosts([row(a), row(b), row(c)], "")), [
    "alpha",
    "bravo",
    "charlie",
  ]);
  check(
    "whitespace-only query behaves the same as empty",
    names(rankHosts([row(a), row(b), row(c)], "   ")),
    names(rankHosts([row(a), row(b), row(c)], "")),
  );
}

// --- inlineUsername, all three bindings ---------------------------------

console.log("\n[inlineUsername] SSH inline, RDP inline, and vault-bound");
check("SSH inline binding reads credential.user", inlineUsername(ssh("h-1", "n", "h")), "root");
check(
  "RDP inline binding reads credential.username",
  inlineUsername(rdp("h-2", "n", "h", { user: "svc" })),
  "svc",
);
check(
  "SSH identity binding has no inline username",
  inlineUsername(ssh("h-3", "n", "h", { identity: true })),
  undefined,
);
{
  const rdpIdentity: RdpHost = {
    ...rdp("h-4", "n", "h"),
    credential: { kind: "identity", identityId: "vault-1" },
  };
  check("RDP identity binding has no inline username", inlineUsername(rdpIdentity), undefined);
}

// --- parseAdHocTarget: acceptance ---------------------------------------

// Every absent field is spelled out as `undefined` rather than omitted. Omitting
// it constrained nothing: the old comparison went through `JSON.stringify`, which
// drops `undefined` keys, so `{host: "prod.example.com"}` accepted any `user` and
// any `port` at all. `canonical` above keeps them, so they have to be stated.
console.log("\n[parseAdHocTarget] accepted shapes");
check("bare host", parseAdHocTarget("prod.example.com"), {
  user: undefined,
  host: "prod.example.com",
  port: undefined,
});
check("user@host", parseAdHocTarget("root@10.0.0.5"), {
  user: "root",
  host: "10.0.0.5",
  port: undefined,
});
check("user@host:port", parseAdHocTarget("root@10.0.0.5:2222"), {
  user: "root",
  host: "10.0.0.5",
  port: 2222,
});
check("host:port with no user", parseAdHocTarget("10.0.0.5:22"), {
  user: undefined,
  host: "10.0.0.5",
  port: 22,
});
check("surrounding whitespace is trimmed", parseAdHocTarget("  root@host  "), {
  user: "root",
  host: "host",
  port: undefined,
});
check("port at the low boundary", parseAdHocTarget("host:1"), {
  user: undefined,
  host: "host",
  port: 1,
});
check("port at the high boundary", parseAdHocTarget("host:65535"), {
  user: undefined,
  host: "host",
  port: 65535,
});

// `search.ts:159` builds the result with `user` and `port` always assigned so
// that the key order is fixed "for a caller that JSON-compares the result". This
// script is that caller, and it is the only one - so if the property is not
// asserted here it is asserted nowhere. `canonical` sorts keys on purpose, which
// means it CANNOT see this; `Object.keys` is what can.
console.log("\n[parseAdHocTarget] the key order is fixed, whichever branch ran");
{
  const branches = [
    parseAdHocTarget("prod.example.com"), // no user, no port
    parseAdHocTarget("root@10.0.0.5"), // user, no port
    parseAdHocTarget("10.0.0.5:22"), // no user, port
    parseAdHocTarget("root@10.0.0.5:2222"), // both
  ];
  check(
    "all four branches return the same keys in the same order",
    branches.map((r) => Object.keys(r ?? {})),
    [
      ["user", "host", "port"],
      ["user", "host", "port"],
      ["user", "host", "port"],
      ["user", "host", "port"],
    ],
  );
  // Present-but-undefined, not absent - the distinction `JSON.stringify` erased.
  const bare = parseAdHocTarget("prod.example.com");
  ok("a bare host has a `user` key holding undefined", bare !== null && "user" in bare);
  ok("and a `port` key holding undefined", bare !== null && "port" in bare);
}

// --- parseAdHocTarget: every rejection case ------------------------------

console.log("\n[parseAdHocTarget] every rejection case");
check("empty string", parseAdHocTarget(""), null);
check("whitespace only", parseAdHocTarget("   "), null);
check("empty host after @", parseAdHocTarget("root@"), null);
check("empty host, bare colon-port", parseAdHocTarget(":22"), null);
check("empty user before @", parseAdHocTarget("@host"), null);
check("more than one @", parseAdHocTarget("a@b@c"), null);
check("whitespace inside", parseAdHocTarget("root@my host"), null);
check("port is not an integer (letters)", parseAdHocTarget("host:abc"), null);
check("port is not an integer (decimal)", parseAdHocTarget("host:22.5"), null);
check("port is negative", parseAdHocTarget("host:-1"), null);
check("port is zero", parseAdHocTarget("host:0"), null);
check("port past 65535", parseAdHocTarget("host:65536"), null);
check("more than one colon (unbracketed IPv6-shaped)", parseAdHocTarget("::1"), null);
check("bracketed IPv6 is out of scope, rejected not mangled", parseAdHocTarget("[::1]:22"), null);
check("bracketed IPv6 with user", parseAdHocTarget("root@[::1]:22"), null);
// This one isolates the bracket check specifically: exactly one colon (the
// port separator), so the colon-count guard alone would let it through and
// parse "[abc]" as a host - it is the bracket check's job to catch it.
check("brackets with only a single colon", parseAdHocTarget("[abc]:22"), null);

// --- the two surfaces build rows the SAME way ---------------------------
//
// This is the check the module's own opening comment claimed was structural and
// was not. `rankHosts` was shared; the ROW BUILDING was not. The page resolved a
// vault-bound host's username through the identity and the header used
// `inlineUsername`, which is `undefined` for exactly those hosts - so a host
// bound to an identity whose username is "deploy" matched on the page, matched
// nothing in the header, and the header's empty state then offered to CREATE it,
// because `parseAdHocTarget("deploy")` succeeds. A duplicate of a host the other
// surface could see, one keystroke away.

console.log("\n[two surfaces] one row builder, so the page and the header cannot disagree");
{
  const bound = ssh("h-1", "box-one", "10.0.0.1", { identity: true });
  const identities = new Map<string, VaultIdentity>([
    [
      "vault-1",
      {
        id: "vault-1",
        name: "Deploy account",
        username: "deploy",
        authMode: "password",
        hasPassword: true,
      },
    ],
  ]);
  check(
    "searchRows resolves a bound host's username off its identity",
    searchRows([bound], [], { identities }).map((r) => r.username),
    ["deploy"],
  );
  check(
    "so the identity's username is a query that FINDS the host",
    names(rankHosts(searchRows([bound], [], { identities }), "deploy")),
    ["box-one"],
  );
  // The old header behaviour, kept as an executable statement of the bug: rows
  // built from `inlineUsername` cannot match, and the query parses, so the empty
  // state offered a create.
  ok(
    "rows built from inlineUsername alone find nothing - the defect, stated",
    rankHosts([{ host: bound, username: inlineUsername(bound), groupName: undefined }], "deploy")
      .length === 0,
  );
  ok(
    "and 'deploy' parses as an ad-hoc target, which is what made that a create offer",
    parseAdHocTarget("deploy") !== null,
  );
  // The other divergence the two loops had: the header tested `groupId` for
  // truthiness and the page for `!== undefined`, so an empty-string group id
  // resolved differently in each. One builder means one answer, and this pins
  // which one.
  const blankGroup: HostGroup = { id: "", name: "Blank" };
  check(
    "an empty-string groupId is looked up, not treated as absent",
    searchRows([{ ...ssh("h-2", "box-two", "10.0.0.2"), groupId: "" }], [blankGroup], {
      identities,
    }).map((r) => r.groupName),
    ["Blank"],
  );
}

// The structural half. A behavioural check cannot see which builder a React
// component calls - this script has no DOM and `HeaderQuickConnect.tsx` cannot be
// imported under plain node - so it is asserted against the source text, the same
// workaround handoff §5.12 records for `workspace-serialize-verify.ts`.
console.log("\n[two surfaces] neither mount point assembles its own rows");
{
  const header = read("src/modules/header/HeaderQuickConnect.tsx");
  const page = read("src/modules/hosts/HostsPage.tsx");
  const derive = read("src/modules/hosts/page/derive.ts");
  const search = read("src/modules/hosts/search.ts");
  ok("the header builds its rows with searchRows", /\bsearchRows\(/.test(header));
  ok("the Hosts page builds its rows with searchRows", /\bsearchRows\(/.test(page));
  // A CALL, not the identifier: the comment in that file names `inlineUsername`
  // when it explains the bug, and a check that cannot tell prose from code would
  // fail on the explanation.
  ok("the header never calls inlineUsername", !/\binlineUsername\s*\(/.test(header));
  ok(
    "searchRows and hostUsername are defined in search.ts",
    /export function searchRows\(/.test(search) && /export function hostUsername\(/.test(search),
  );
  // derive.ts re-exports them for the page's single import site. A second
  // DEFINITION there is how the two copies came back last time.
  ok(
    "page/derive.ts re-exports them rather than defining a second copy",
    /export \{ hostUsername, searchRows \} from "\.\.\/search";/.test(derive) &&
      !/export function (searchRows|hostUsername)\(/.test(derive),
  );
}

// The header's Enter path depends on one invariant: while the input has focus,
// the list is open. `PopoverAnchor` with no `PopoverTrigger` leaves Radix's
// `triggerRef` null, so a click on the input itself counted as an interaction
// OUTSIDE and dismissed the list - focused, closed, non-empty query - and Enter
// then did nothing, because `handleKeyDown` hands the key to cmdk whose list has
// unmounted. Source-text again, for the same reason as above.
console.log("\n[header] a click on the input cannot close the input's own list");
{
  const header = read("src/modules/header/HeaderQuickConnect.tsx");
  ok("the anchor element is captured in a ref", /ref=\{anchorRef\}/.test(header));
  ok(
    "and onInteractOutside treats a target inside it as inside",
    /onInteractOutside=\{/.test(header) && /anchorRef\.current\?\.contains\(target\)/.test(header),
  );
}

// --- gate: break the implementation and watch each check actually fail --
//
// Handoff §5.12: a check that has not been watched fail is not a check. This is
// the record for the checks added or repaired in THIS pass, and only those. It is
// NOT a record for every check in the file - the original pass's mutation table
// was never committed anywhere, and the comment that used to sit here promised a
// table it did not contain, which is §5.12's own anti-pattern wearing §5.12's
// clothes. Each row was run by editing the named file, running this script, and
// restoring from a byte-exact copy verified with `diff`.
//
//   Mutation                                       Check it killed
//   ------------------------------------------     -----------------------------
//   search.ts rankHosts: drop `.toLowerCase()`     "an UPPERCASE query matches a
//     from the trimmed query                        lowercase name" (+3 more)
//   search.ts matchTier: drop `.toLowerCase()`     "a lowercase query matches a
//     from `name`                                   mixed-case name exactly"
//   search.ts matchTier: drop `.toLowerCase()`     "a lowercase query matches a
//     from `host`                                   mixed-case host prefix" (+1)
//   search.ts matchTier: drop `?.toLowerCase()`    "a lowercase query matches a
//     from `username`                               mixed-case USERNAME" (+1)
//   search.ts matchTier: drop `?.toLowerCase()`    "a lowercase query matches a
//     from `groupName`                              mixed-case GROUP NAME" (+1)
//   search.ts matchTier: `return 5` for every      "it still matches on its NAME,
//     row (stop discriminating entirely)            and only it does" - the
//                                                  `.length === 1` version of
//                                                  that check PASSED under this
//                                                  mutation, which is why it was
//                                                  replaced
//   search.ts parseAdHocTarget: build the          "all four branches return the
//     result conditionally (`{host}`, then          same keys in the same order",
//     assign `user`/`port` if defined)              plus all seven accepted-shape
//                                                  checks. Under the old
//                                                  `JSON.stringify` comparison
//                                                  this mutation was invisible
//   search.ts searchRows: resolve with             "searchRows resolves a bound
//     `inlineUsername(host)` - the P1 defect        host's username off its
//                                                  identity" (+1)
//   search.ts searchRows: `host.groupId ? ... :    "an empty-string groupId is
//     undefined` - the header's old loop            looked up, not treated as
//                                                  absent"
//   search.ts compareRows: `return 0` instead      "every permutation ranks
//     of the `id` tie-break                         identically to the baseline"
//                                                  fails while "no permutation is
//                                                  the identity" still passes -
//                                                  the identity permutation had
//                                                  nothing to say about this
//   HeaderQuickConnect: revert to its own          "the header builds its rows
//     row-building loop                             with searchRows" and "the
//                                                  header never calls
//                                                  inlineUsername"
//   HeaderQuickConnect: delete the                 "and onInteractOutside treats a
//     `onInteractOutside` guard                     target inside it as inside"
//   HeaderQuickConnect: delete `ref={anchorRef}`   "the anchor element is captured
//     from the anchor                               in a ref"
//   page/derive.ts: re-add a local `searchRows`    "page/derive.ts re-exports them
//     definition beside the re-export               rather than defining a second
//                                                  copy"
//
// Not run: "the Hosts page builds its rows with searchRows" would mean editing
// `HostsPage.tsx`, which this pass does not own. The regex is the same one the
// header check uses, against the same string, so it fails the same way.

console.log(failed === 0 ? "\nAll hosts-search checks passed." : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
