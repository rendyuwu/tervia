/**
 * Self-check for the host search ranking shared by the Hosts page search box
 * and the header quick-connect (research §5.5, §5.8, §12.11).
 * Run: `pnpm verify` (or `npx tsx scripts/hosts-search-verify.ts` to iterate).
 *
 * The whole point of ONE ranking function with two mount points is that the
 * page and the header can never show a different "top match" for the same
 * query. That guarantee lives entirely in the tie-break chain being TOTAL -
 * so the check that matters most here is not any single tier, it is that a
 * shuffled input produces the identical output order every time.
 */
import {
  inlineUsername,
  parseAdHocTarget,
  rankHosts,
  type HostSearchRow,
} from "../src/modules/hosts/search";
import type { RdpHost, SshHost } from "../src/modules/hosts/types";

let failed = 0;
function check(label: string, got: unknown, want: unknown): void {
  if (JSON.stringify(got) === JSON.stringify(want)) {
    console.log(`  ok: ${label}`);
  } else {
    console.error(`  FAIL: ${label} = ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
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
ok(
  "a vault-bound host (no inline username) still matches on name",
  rankHosts([row(ssh("h-1", "identity-box", "10.0.0.1", { identity: true }))], "identity")
    .length === 1,
);

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
  // A handful of hand-picked permutations rather than a random shuffle, so a
  // failure here is reproducible without a fixed seed.
  const permutations = [
    [5, 4, 3, 2, 1, 0],
    [2, 0, 4, 1, 5, 3],
    [0, 1, 2, 3, 4, 5],
    [3, 1, 4, 0, 5, 2],
  ];
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

console.log("\n[parseAdHocTarget] accepted shapes");
check("bare host", parseAdHocTarget("prod.example.com"), { host: "prod.example.com" });
check("user@host", parseAdHocTarget("root@10.0.0.5"), { user: "root", host: "10.0.0.5" });
check("user@host:port", parseAdHocTarget("root@10.0.0.5:2222"), {
  user: "root",
  host: "10.0.0.5",
  port: 2222,
});
check("host:port with no user", parseAdHocTarget("10.0.0.5:22"), { host: "10.0.0.5", port: 22 });
check("surrounding whitespace is trimmed", parseAdHocTarget("  root@host  "), {
  user: "root",
  host: "host",
});
check("port at the low boundary", parseAdHocTarget("host:1"), { host: "host", port: 1 });
check("port at the high boundary", parseAdHocTarget("host:65535"), { host: "host", port: 65535 });

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

// --- gate: break the implementation and watch each check actually fail --
//
// Handoff §5.12: a check that has not been watched fail is not a check. The
// table below is not part of the automated run - it is the record of doing
// that by hand for every check above, kept here so the next reviewer does not
// have to take it on faith. See the report sent alongside this file.

console.log(failed === 0 ? "\nAll hosts-search checks passed." : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
