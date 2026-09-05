/**
 * Self-check for the pure Port Forwarding page derivation layer.
 * Run: `pnpm verify` (or `npx tsx scripts/forwards-page-verify.ts`
 * to iterate).
 *
 * `modules/forwards/page/derive.ts` is pure - no React, no store, no Tauri -
 * which is the only reason this file can exist. Modelled on
 * `scripts/vault-page-verify.ts`: same `canonical()` (JSON is key-order
 * sensitive and drops `undefined` keys, and both matter here), same
 * `check`/`ok` pair, fixtures, numbered sections, and a mutation table at the
 * tail recording every mutation actually run against this file.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  bindFailureText,
  deleteNote,
  localPortLabel,
  privilegedPortWarning,
  rankRules,
  ruleRows,
  stopNote,
  UNKNOWN_HOST_LABEL,
  type DeleteNoteSubject,
  type ForwardRuleRow,
} from "../src/modules/forwards/page/derive";
import type { ForwardRule } from "../src/modules/forwards/types";
import type { Host, SshHost } from "../src/modules/hosts/types";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

let failed = 0;

/**
 * JSON with object keys SORTED, and `undefined` values kept. See
 * `vault-page-verify.ts`'s helper of the same name for the full reasoning.
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
//
// Every builder returns a FRESH record, the same discipline
// `vault-page-verify.ts` follows and for the same reason: no check here can
// be reading a fixture an earlier one mutated.

function rule(id: string, over: Partial<ForwardRule> = {}): ForwardRule {
  return {
    id,
    name: `Rule ${id}`,
    hostId: `h-${id}`,
    localPort: 8080,
    remoteHost: `remote-${id}`,
    remotePort: 5432,
    startWithHost: false,
    ...over,
  };
}

function sshHost(id: string, over: Partial<SshHost> = {}): SshHost {
  return {
    id,
    name: `host ${id}`,
    host: `${id}.internal`,
    port: 22,
    protocol: "ssh",
    credential: {
      kind: "inline",
      hostId: id,
      user: "root",
      authMode: "password",
      hasPassword: true,
      hasPrivateKey: false,
      hasKeyPassphrase: false,
    },
    ...over,
  };
}

function row(over: Partial<ForwardRuleRow> = {}): ForwardRuleRow {
  return {
    rule: rule("r-x"),
    hostName: "zz",
    hostDangling: false,
    route: "",
    ...over,
  };
}

// --- 1. ruleRows: hostName/hostDangling resolution, and the label trap ------

console.log("[1] ruleRows: hostName and hostDangling resolve independently, route is built right");
{
  const bastion = sshHost("h-bastion", { name: "bastion", host: "bastion.internal" });
  // A host genuinely named "Unknown host" (D1's fixture): the label this host
  // legitimately shows is byte-identical to what a DANGLING reference shows,
  // so only a structural flag - never a label comparison - can tell them
  // apart.
  const namedUnknown = sshHost("h-named-unknown", { name: UNKNOWN_HOST_LABEL });
  const hosts = new Map<string, Host>([
    [bastion.id, bastion],
    [namedUnknown.id, namedUnknown],
  ]);

  const boundRule = rule("r-1", {
    hostId: "h-bastion",
    localPort: 18080,
    remoteHost: "10.0.0.9",
    remotePort: 5432,
  });
  const danglingRule = rule("r-2", { hostId: "h-gone" });
  const namedUnknownRule = rule("r-3", { hostId: "h-named-unknown" });

  const rows = ruleRows([boundRule, danglingRule, namedUnknownRule], hosts);

  check(
    "hostName: live host's name, UNKNOWN_HOST_LABEL for a dangling hostId",
    rows.map((r) => r.hostName),
    ["bastion", UNKNOWN_HOST_LABEL, UNKNOWN_HOST_LABEL],
  );
  // D1: hostDangling must come from whether the host was FOUND, not from
  // comparing the label to UNKNOWN_HOST_LABEL - r-3's host is real and merely
  // happens to be named that.
  check(
    "hostDangling: literal per row - only the truly dangling reference is true",
    rows.map((r) => r.hostDangling),
    [false, true, false],
  );
  // The doc example, verbatim: a pinned local port, a real host, a real
  // remote endpoint.
  check(
    "route: localhost:<localPort> -> hostName -> remoteHost:remotePort",
    rows[0].route,
    "localhost:18080 → bastion → 10.0.0.9:5432",
  );
  check(
    "route for an auto local port shows Auto, not localhost:0",
    ruleRows(
      [
        rule("r-auto", {
          hostId: "h-bastion",
          localPort: 0,
          remoteHost: "10.0.0.9",
          remotePort: 5432,
        }),
      ],
      hosts,
    )[0].route,
    "Auto → bastion → 10.0.0.9:5432",
  );

  // N2: `hostDangling` must never mean "the hosts have not loaded yet".
  // `useForwards()` and `useHosts()` are two INDEPENDENT async loads that both
  // start from an empty `Map`, so there is a render on EVERY MOUNT where the
  // rules have arrived and the hosts have not - and reporting `hostDangling`
  // there rendered a self-contradicting row that was reachable every single
  // time: "Running" + a green dot + a red "Host missing" badge + a note telling
  // the user to stop it + a DISABLED Stop whose tooltip said to edit the rule
  // before starting it. Four wrong answers about one rule, on the first frame.
  //
  // Pre-existing rather than a regression from the hostOwned work - the flag
  // itself was always `host === undefined` - but on the hand-test path, which
  // is why it is fixed here.
  {
    const orphan = rule("r-preload", { hostId: "h-not-loaded-yet" });
    check(
      "an EMPTY host map is the pre-load state, not a dangling row",
      ruleRows([orphan], new Map<string, Host>()).map((r) => r.hostDangling),
      [false],
    );
    // The paired positive, and it is what stops the fix from being an
    // off-switch: with the hosts KNOWN, a rule naming one that is not among
    // them is dangling exactly as before.
    check(
      "with the hosts known, a rule naming a missing one is still dangling",
      ruleRows([orphan], hosts).map((r) => r.hostDangling),
      [true],
    );
    // And the label is unchanged either way: `hostName` has always been
    // "Unknown host" for a host this map does not hold, and during the pre-load
    // frame that is the only honest thing it can say. What the fix removes is
    // the destructive badge and the disabled buttons, not the label.
    check(
      "the label is UNKNOWN_HOST_LABEL in both cases - only the structural flag changed",
      [
        ruleRows([orphan], new Map<string, Host>())[0].hostName,
        ruleRows([orphan], hosts)[0].hostName,
      ],
      [UNKNOWN_HOST_LABEL, UNKNOWN_HOST_LABEL],
    );
  }
}

// --- 2. rankRules: five tiers, one row per tier, and the drop rule ----------

console.log("\n[2] rankRules: tiers, drops, empty and whitespace queries");
{
  // Six rows, all matched against the query "db", chosen so the DEFAULT order
  // (name, then id) is a genuine permutation of the tier order below - not
  // the tier-order permutation - so a comparator that returned the input
  // unsorted (D2), or a filter that never ran, would still fail this section.
  //
  //   name           remoteHost   tier for "db"
  //   -------------  -----------  -------------------------------------------
  //   "db"           "zz"         1 - exact name
  //   "db-prod"      "zz"         2 - name prefix (also word-boundary, but
  //                               tier 2 is checked first and wins)
  //   "prod-db-01"   "zz"         3 - name word boundary, NOT a name prefix
  //   "zzzzzz"       "db-admin"   4 - remoteHost prefix (name matches nothing)
  //   "adbox"        "zz"         5 - plain substring, no boundary either side
  //   "nothing"      "nope"       no tier - dropped
  const alpha = row({ rule: rule("r-alpha", { name: "adbox", remoteHost: "zz" }) });
  const bravo = row({ rule: rule("r-bravo", { name: "db-prod", remoteHost: "zz" }) });
  const charlie = row({ rule: rule("r-charlie", { name: "db", remoteHost: "zz" }) });
  const delta = row({ rule: rule("r-delta", { name: "prod-db-01", remoteHost: "zz" }) });
  const echo = row({ rule: rule("r-echo", { name: "zzzzzz", remoteHost: "db-admin" }) });
  const foxtrot = row({ rule: rule("r-foxtrot", { name: "nothing", remoteHost: "nope" }) });

  const rows = [alpha, bravo, charlie, delta, echo, foxtrot];

  // Default order by name: adbox, db, db-prod, nothing, prod-db-01, zzzzzz.
  check(
    "empty query returns every row in default (name, then id) order",
    rankRules(rows, "").map((r) => r.rule.id),
    ["r-alpha", "r-charlie", "r-bravo", "r-foxtrot", "r-delta", "r-echo"],
  );
  check(
    "whitespace-only query behaves as empty",
    rankRules(rows, "   ").map((r) => r.rule.id),
    ["r-alpha", "r-charlie", "r-bravo", "r-foxtrot", "r-delta", "r-echo"],
  );
  check(
    "query 'db': exact beats name-prefix beats word-boundary beats remoteHost-prefix beats substring; no-tier dropped",
    rankRules(rows, "db").map((r) => r.rule.id),
    ["r-charlie", "r-bravo", "r-delta", "r-echo", "r-alpha"],
  );
  ok(
    "the non-matching row is dropped, not sorted to the bottom",
    !rankRules(rows, "db")
      .map((r) => r.rule.id)
      .includes("r-foxtrot"),
  );
  check(
    "how many hits is the array length: 5 of 6 rows match 'db'",
    rankRules(rows, "db").length,
    5,
  );

  // hostName reaches tier 5, the same way vault's keyName reaches its own
  // tier 5: a user searching for the host a rule rides should find it even
  // though the query matches neither name nor remoteHost. Paired with a
  // tier-2 name-prefix competitor so the tier is observable - a one-row list
  // can only prove "matched", not "matched at tier 5".
  const hostNameOnly = row({
    rule: rule("r-hostname-only", { name: "zzzzzz", remoteHost: "zz" }),
    hostName: "deploy-box",
  });
  const namePrefixCompetitor = row({
    rule: rule("r-name-competitor", { name: "deploy-service", remoteHost: "zz" }),
    hostName: "zz",
  });
  check(
    "hostName participates at tier 5: ranks behind a tier-2 name-prefix match, not ahead or tied",
    rankRules([hostNameOnly, namePrefixCompetitor], "deploy").map((r) => r.rule.id),
    ["r-name-competitor", "r-hostname-only"],
  );
}

// --- 3. Ports are matched as strings, substring tier ONLY (D7) --------------

console.log(
  "\n[3] rankRules: localPort and remotePort are substring-tier matches only, never a prefix tier",
);
{
  // A tier-2 name-prefix competitor for query "1" - it must ALWAYS rank
  // first, no matter how many rules merely have a "1" somewhere in a port.
  const competitor = row({
    rule: rule("r-competitor", {
      name: "1x-deploy",
      remoteHost: "zz",
      localPort: 9999,
      remotePort: 9999,
    }),
  });
  // Three rows that match "1" ONLY via a port digit, at three different
  // positions in the number, none of them a leading digit shared by all three
  // - proving the match is a genuine substring test, not one prefix check in
  // disguise. Every field a stronger tier reads is deliberately a "1"-free
  // "zz"-shaped value.
  const portRow1 = row({
    rule: rule("r-port-1", {
      name: "zzzzzzq",
      remoteHost: "zzq",
      localPort: 100,
      remotePort: 6000,
    }),
  });
  const portRow2 = row({
    rule: rule("r-port-2", {
      name: "zzzzzzr",
      remoteHost: "zzr",
      localPort: 18080,
      remotePort: 6001,
    }),
  });
  const portRow3 = row({
    rule: rule("r-port-3", {
      name: "zzzzzzs",
      remoteHost: "zzs",
      localPort: 6002,
      remotePort: 1194,
    }),
  });
  // A row whose ports genuinely have no "1" in them at all: must be dropped.
  const noMatch = row({
    rule: rule("r-no-match", {
      name: "zzzzzzt",
      remoteHost: "zzt",
      localPort: 6003,
      remotePort: 6004,
    }),
  });

  const rows = [competitor, portRow1, portRow2, portRow3, noMatch];
  const ranked = rankRules(rows, "1").map((r) => r.rule.id);

  check(
    "the tier-2 name-prefix competitor outranks every port-only match, and the port-only rows sort by name behind it",
    ranked,
    ["r-competitor", "r-port-1", "r-port-2", "r-port-3"],
  );
  ok("the row with no '1' anywhere is dropped", !ranked.includes("r-no-match"));

  // A single-row-per-port check that a prefix mutation cannot fake: query "6"
  // is a PREFIX of 6000/6001/6002/6003/6004 but is NOT a prefix of 100,
  // 18080 or 1194 - if `rankRules` ever promoted a port to a prefix tier,
  // querying "6" would still only reach it through remotePort's substring
  // test here, at the same weak tier as everything else. This mainly pins
  // that remotePort participates too, not just localPort.
  const remotePortOnly = row({
    rule: rule("r-remoteport-only", {
      name: "zzzzzzu",
      remoteHost: "zzu",
      localPort: 100,
      remotePort: 60005,
    }),
  });
  ok(
    "remotePort participates in the substring tier too",
    rankRules([remotePortOnly], "60005")
      .map((r) => r.rule.id)
      .includes("r-remoteport-only"),
  );

  // The check above (order-only, against a tier-2 competitor) does NOT catch
  // every prefix-tier mutation: a `localPort.startsWith(query)` clause added
  // to the tier-4 test was run here first and came back GREEN, because it
  // only promotes port-only rows from tier 5 to tier 4 - still weaker than
  // the tier-2 competitor, so the competitor still sorts first and the
  // promoted rows still happen to sort among themselves by name exactly as
  // they did at tier 5. An order check that never has two ports racing each
  // other at DIFFERENT tiers cannot see a promotion that does not change the
  // final order.
  //
  // This pair isolates the tier directly: `nameFirst`'s name sorts BEFORE
  // `namePortMatch`'s alphabetically, so at equal tiers (both tier 5, the
  // correct behaviour) `nameFirst` must rank first on the name tie-break.
  // `namePortMatch`'s localPort is a QUERY PREFIX ("18" prefixes "1800");
  // `nameFirst`'s localPort contains the query only as a non-leading
  // substring ("91800" is not prefixed by "18"). A prefix-tier mutation
  // promotes ONLY `namePortMatch`, which flips the order; the correct
  // substring-only behaviour never does.
  const nameFirst = row({
    rule: rule("r-a-name-first", {
      name: "zzzzzzp1",
      remoteHost: "zzp1",
      localPort: 91800,
      remotePort: 6006,
    }),
  });
  const namePortMatch = row({
    rule: rule("r-b-name-second", {
      name: "zzzzzzp2",
      remoteHost: "zzp2",
      localPort: 1800,
      remotePort: 6007,
    }),
  });
  check(
    "a query-prefixed port and a query-substring port tie at the SAME tier - name order wins, a prefix promotion would flip it",
    rankRules([namePortMatch, nameFirst], "18").map((r) => r.rule.id),
    ["r-a-name-first", "r-b-name-second"],
  );
}

// --- 4. The comparator is total ---------------------------------------------

console.log("\n[4] two rows equal on name break the tie on id, both input orders");
{
  const a = row({ rule: rule("r-b", { name: "same" }) });
  const b = row({ rule: rule("r-a", { name: "same" }) });
  check(
    "forward input order: id order wins the tie",
    rankRules([a, b], "").map((r) => r.rule.id),
    ["r-a", "r-b"],
  );
  check(
    "reversed input order: same result",
    rankRules([b, a], "").map((r) => r.rule.id),
    ["r-a", "r-b"],
  );
}

// --- 5. Case folding is load-bearing -----------------------------------------

console.log("\n[5] mixed-case name vs lowercase query, and the reverse, both fold");
{
  const mixedName = row({ rule: rule("r-1", { name: "ProdBox" }) });
  check(
    "mixed-case name matches a lowercase query",
    rankRules([mixedName], "prodbox").map((r) => r.rule.id),
    ["r-1"],
  );
  const lowerName = row({ rule: rule("r-2", { name: "prodbox" }) });
  check(
    "lowercase name matches a mixed-case query",
    rankRules([lowerName], "ProdBox").map((r) => r.rule.id),
    ["r-2"],
  );
}

// --- 6. localPortLabel: auto/pinned/bound, and never the requested port -----

console.log("\n[6] localPortLabel: auto, pinned, bound, and the pinned-vs-bound-differ case (D4)");
{
  check(
    "localPort 0, not bound: Auto",
    localPortLabel(rule("r-1", { localPort: 0 }), undefined),
    "Auto",
  );
  check(
    "localPort 0, bound: localhost:<bound>",
    localPortLabel(rule("r-2", { localPort: 0 }), 54321),
    "localhost:54321",
  );
  check(
    "pinned, not bound: localhost:<localPort>",
    localPortLabel(rule("r-3", { localPort: 8080 }), undefined),
    "localhost:8080",
  );
  // D4: must show the BOUND port, never the requested one, when they differ -
  // the exact defect that naming the requested port instead produces.
  check(
    "pinned and bound differ: shows the bound port, never the requested one",
    localPortLabel(rule("r-4", { localPort: 8080 }), 9090),
    "localhost:9090",
  );
}

// --- 7. bindFailureText: the four-way table, and the fallback that matters --

console.log(
  "\n[7] bindFailureText: the four failure cases, fallback passes the raw message through",
);
{
  check(
    "EACCES on a privileged port: administrator-rights sentence",
    bindFailureText("ssh: bind 127.0.0.1:80 failed: bind: EACCES", 80),
    "Port 80 needs administrator rights. Pick a port above 1024.",
  );
  check(
    "'permission denied' on a privileged port: same sentence, matched on the io text not the code",
    bindFailureText("ssh: bind 127.0.0.1:443 failed: bind: permission denied", 443),
    "Port 443 needs administrator rights. Pick a port above 1024.",
  );
  check(
    "permission denied on a NON-privileged port falls through to the raw message - the port guard is real",
    bindFailureText("ssh: bind 127.0.0.1:8080 failed: bind: permission denied (unexpected)", 8080),
    "ssh: bind 127.0.0.1:8080 failed: bind: permission denied (unexpected)",
  );
  check(
    "Windows error 10013: the Hyper-V/WSL2 sentence, independent of port",
    bindFailureText(
      "ssh: bind 0.0.0.0:3389 failed: bind: An attempt was made to access a socket (os error 10013)",
      3389,
    ),
    "Windows reserves some port ranges for Hyper-V and WSL2, and they do not appear in netstat. " +
      "Run netsh interface ipv4 show excludedportrange protocol=tcp to see them.",
  );
  check(
    "WSAEACCES spelling: the same Hyper-V/WSL2 sentence",
    bindFailureText("ssh: bind 0.0.0.0:22 failed: bind: WSAEACCES", 22),
    "Windows reserves some port ranges for Hyper-V and WSL2, and they do not appear in netstat. " +
      "Run netsh interface ipv4 show excludedportrange protocol=tcp to see them.",
  );
  check(
    "EADDRINUSE: the already-in-use sentence",
    bindFailureText("ssh: bind 127.0.0.1:5432 failed: bind: EADDRINUSE", 5432),
    "Port 5432 is already in use on this machine.",
  );
  check(
    "'address in use' spelling: same sentence",
    bindFailureText("ssh: bind 127.0.0.1:5432 failed: bind: address in use", 5432),
    "Port 5432 is already in use on this machine.",
  );
  // The REAL messages, which the needle spellings above do not carry. What
  // the backend sends is `std::io::Error`'s Display, not an errno name:
  // `src-tauri/src/modules/ssh/session.rs:443` is
  // `format!("ssh: bind 127.0.0.1:{local_port} failed: {e}")`. So every needle
  // above is a spelling nothing in the pipeline emits today, and these five
  // fixtures are the ones that decide whether a user ever sees the sentence.
  check(
    "REAL Linux EADDRINUSE - note 'already' splits the phrase 'address in use'",
    bindFailureText(
      "ssh: bind 127.0.0.1:18080 failed: Address already in use (os error 98)",
      18080,
    ),
    "Port 18080 is already in use on this machine.",
  );
  check(
    "REAL macOS EADDRINUSE - same text, different errno",
    bindFailureText(
      "ssh: bind 127.0.0.1:18080 failed: Address already in use (os error 48)",
      18080,
    ),
    "Port 18080 is already in use on this machine.",
  );
  check(
    "REAL Windows EADDRINUSE - shares none of the words the other two use",
    bindFailureText(
      "ssh: bind 127.0.0.1:18080 failed: Only one usage of each socket address " +
        "(protocol/network address/port) is normally permitted. (os error 10048)",
      18080,
    ),
    "Port 18080 is already in use on this machine.",
  );
  check(
    "REAL Linux EACCES on a privileged port - capital P, so a case-sensitive match would miss it",
    bindFailureText("ssh: bind 127.0.0.1:80 failed: Permission denied (os error 13)", 80),
    "Port 80 needs administrator rights. Pick a port above 1024.",
  );
  check(
    "REAL Windows WSAEACCES - and it must NOT take the permission-denied arm, whose words it contains",
    bindFailureText(
      "ssh: bind 127.0.0.1:50000 failed: An attempt was made to access a socket in a way " +
        "forbidden by its access permissions. (os error 10013)",
      50000,
    ),
    "Windows reserves some port ranges for Hyper-V and WSL2, and they do not appear in netstat. " +
      "Run netsh interface ipv4 show excludedportrange protocol=tcp to see them.",
  );
  // The reason the port-number needles are `os error`-qualified: a rule pinned
  // to 10048 must not read its own port number out of its own failure message.
  const pinnedTo10048 = "ssh: bind 127.0.0.1:10048 failed: Cannot assign requested address";
  check(
    "a rule pinned to port 10048 does not mistake its own port for an error code",
    bindFailureText(pinnedTo10048, 10048),
    pinnedTo10048,
  );

  // An AUTO-PORT rule (`localPort: 0`) must never be told about "Port 0". Both
  // sentences that name the port are guarded on the requested port being a real
  // one, and 0 is not: nothing is listening on it and "pick a port above 1024"
  // is advice a rule that asked for any port has already taken. The honest
  // answer for an auto rule is the raw message, since the port the OS actually
  // picked is not knowable from a bind that bound nothing.
  const autoInUse = "ssh: bind 127.0.0.1:0 failed: Address already in use (os error 98)";
  check(
    "an auto-port rule in-use failure falls through, never 'Port 0 is already in use'",
    bindFailureText(autoInUse, 0),
    autoInUse,
  );
  const autoDenied = "ssh: bind 127.0.0.1:0 failed: Permission denied (os error 13)";
  check(
    "an auto-port rule permission failure falls through, never 'Port 0 needs administrator rights'",
    bindFailureText(autoDenied, 0),
    autoDenied,
  );
  // And the paired positive, so the guards are a RANGE check and not an
  // off-switch: port 1 is the smallest real privileged port and still gets the
  // sentence.
  check(
    "port 1 still gets the administrator-rights sentence - the guard is a range, not an off-switch",
    bindFailureText("ssh: bind 127.0.0.1:1 failed: Permission denied (os error 13)", 1),
    "Port 1 needs administrator rights. Pick a port above 1024.",
  );

  // D5: the fallback is the important arm - an io error this table has never
  // seen must reach the reader UNCHANGED, not behind a generic "could not
  // bind".
  const neverSeen =
    "ssh: bind 127.0.0.1:2222 failed: bind: a message this table has never catalogued (errno 999)";
  check(
    "an unrecognised io error passes through verbatim",
    bindFailureText(neverSeen, 2222),
    neverSeen,
  );
}

// --- 8. privilegedPortWarning: 1-1023 only, 0 warns for nothing (D6) --------

console.log("\n[8] privilegedPortWarning: warns for 1-1023, undefined for 0 and for 1024+");
{
  check("port 0 (auto): no warning", privilegedPortWarning(0), undefined);
  check(
    "port 1: warns",
    privilegedPortWarning(1),
    "Port 1 needs administrator rights. Pick a port above 1024.",
  );
  check(
    "port 1023: warns",
    privilegedPortWarning(1023),
    "Port 1023 needs administrator rights. Pick a port above 1024.",
  );
  check("port 1024: no warning", privilegedPortWarning(1024), undefined);
  check("port 8080: no warning", privilegedPortWarning(8080), undefined);
}

// --- 9. stopNote: exact, one function for both the tooltip and the row -----

console.log("\n[9] stopNote: exact two-sentence copy");
{
  check(
    "the exact Stop copy",
    stopNote(),
    "No new connections; connections already open keep running until one side closes. " +
      "The SSH session stays up while anything else is using it.",
  );
}

// --- 10. deleteNote: pageStops/startWithHost/hostOwned, all eight (D8) ------

console.log(
  "\n[10] deleteNote: pageStops, startWithHost and hostOwned are independent facts; hostOwned takes precedence over pageStops",
);
// `pageStops` AND NOT `running`, moved with the field. It means "this delete
// stops a forward the PAGE holds", which is `running` OR still mid-dial as
// `starting` - `DeleteNoteSubject.pageStops` carries the reasoning, and the
// short version is that the trash button is not disabled while a row dials, so
// a mid-dial delete is an ordinary sequence and the confirm DOES stop that
// bind (`pageMustStopFirst` answers `true` for `starting`).
//
// WHAT THIS SECTION CAN AND CANNOT SEE, said here so the next reader does not
// assume the wider half is covered by these eight cells. `deleteNote` is a pure
// function of an already-decided boolean, so the WIDENING itself - `RuleCard`
// computing `running || starting` rather than `running` - is invisible from
// here whatever this table says. That half is pinned at its own binding in
// `forwards-shell-verify.ts`'s section 11.
{
  const STOPPING = "Stopping it first is not required — deleting a running rule stops it.";
  const HOST_OWNED =
    "Deleting the rule does not stop its forward — that one dies with the terminal tab that opened it.";
  const START = "It will no longer start automatically with its host.";
  const FALLBACK = "Deleting it changes nothing else.";

  const subject = (over: Partial<DeleteNoteSubject> = {}): DeleteNoteSubject => ({
    pageStops: false,
    startWithHost: false,
    hostOwned: false,
    ...over,
  });

  // ALL EIGHT COMBINATIONS, exhaustively rather than the four the two-flag
  // version needed - three independent booleans, and the interesting cell is
  // the one where two of them are true at once.
  const pageStopsOnly = subject({ pageStops: true });
  const startOnly = subject({ startWithHost: true });
  const both = subject({ pageStops: true, startWithHost: true });
  const neither = subject();
  const hostOwnedOnly = subject({ hostOwned: true });
  const hostOwnedAndStart = subject({ hostOwned: true, startWithHost: true });
  const hostOwnedAndPageStops = subject({ hostOwned: true, pageStops: true });
  const allThree = subject({ hostOwned: true, pageStops: true, startWithHost: true });

  check(
    "the page stops it, does not start with host: the stopping sentence alone",
    deleteNote(pageStopsOnly),
    STOPPING,
  );
  check(
    "no forward to stop, starts with host: the start-with-host sentence alone",
    deleteNote(startOnly),
    START,
  );
  check(
    "the page stops it AND it starts with host: both sentences",
    deleteNote(both),
    `${STOPPING} ${START}`,
  );
  check("neither: the fallback sentence", deleteNote(neither), FALLBACK);

  // THE NEW ARM. `store.ts`'s `deleteRule` is a pure persistence filter and
  // `ForwardsPage.tsx`'s `confirmDelete` can only stop what the PAGE started -
  // a terminal-owned forward dies with its tab and with nothing else. Before
  // this arm existed the dialog said "deleting a running rule stops it" for
  // such a rule, which is a false promise inside a destructive confirm.
  //
  // `hostOwned` WITHOUT `startWithHost` looks contradictory and is not:
  // `autostart.ts` only ever claims a rule flagged `startWithHost`, but the
  // user can edit that flag off while the terminal's forward is still up, and
  // the confirm then has to be right about both facts at once.
  check(
    "terminal-owned: the delete does NOT stop it, and says so",
    deleteNote(hostOwnedOnly),
    HOST_OWNED,
  );
  check(
    "terminal-owned AND starts with host: both sentences",
    deleteNote(hostOwnedAndStart),
    `${HOST_OWNED} ${START}`,
  );
  // THE PRECEDENCE CELL, and the reason `hostOwned` is its own field rather
  // than folded into `running`. The two maps are kept exclusive by checks and
  // not by construction (`hostOwned.ts`'s header), so if both ever said yes the
  // sentence that must win is the one about the owner this dialog cannot act
  // on - the same `hostOwned`-first order `page/RuleCard.tsx` applies at all
  // nine of its own sites.
  check(
    "terminal-owned AND the page would stop it: the terminal sentence wins, never the stop promise",
    deleteNote(hostOwnedAndPageStops),
    HOST_OWNED,
  );
  check(
    "all three: the terminal sentence plus the start-with-host one",
    deleteNote(allThree),
    `${HOST_OWNED} ${START}`,
  );

  // D8: the stops-it/does-not pair must differ. A `deleteNote` that branched on
  // `startWithHost` alone (or ignored `pageStops` altogether) would return
  // byte-identical text for `pageStopsOnly` and `neither` here.
  ok(
    "the stops-it and nothing-to-stop sentences are NOT the same text",
    deleteNote(pageStopsOnly) !== deleteNote(neither),
  );
  // And the same claim for the new flag, which is the mutation "drop the
  // hostOwned arm" - it collapses this pair onto one sentence.
  ok(
    "the terminal-owned and page-stops-it sentences are NOT the same text",
    deleteNote(hostOwnedOnly) !== deleteNote(pageStopsOnly),
  );
  ok(
    "nor is the terminal-owned sentence the fallback",
    deleteNote(hostOwnedOnly) !== deleteNote(neither),
  );

  // No claim about how well the secret was kept, or that this delete makes
  // anything "safer" - a forward rule holds no secret at all (see the
  // module's own header), so this is a copy check, not a security claim
  // check, but the same two needles are run over every string anyway.
  const everyNote = [
    pageStopsOnly,
    startOnly,
    both,
    neither,
    hostOwnedOnly,
    hostOwnedAndStart,
    hostOwnedAndPageStops,
    allThree,
  ].map((s) => deleteNote(s));
  for (const note of everyNote) {
    ok(
      `${JSON.stringify(note)} makes no protection claim`,
      !/\bsafer\b|\bsecurely\b|\bmore secure\b/i.test(note) &&
        !note.includes("OS keychain") &&
        !note.includes("Credential Manager"),
    );
  }
}

// --- 11. hasWordBoundaryMatch is IMPORTED, never re-implemented (D3) -------

console.log(
  "\n[11] derive.ts imports the shared word-boundary check - the import specifier set is pinned",
);
{
  const deriveSrc = readFileSync(join(root, "src/modules/forwards/page/derive.ts"), "utf8");

  // An IMPORT-SPECIFIER parse, not a quoted-needle scan.
  // Agreement-by-value (two functions that happen to return the same answer
  // for every fixture) cannot tell a shared import from a local
  // reimplementation that copied the same regex - only pinning the exact set
  // of module specifiers the file imports from does, because a local
  // `hasWordBoundaryMatch` would simply not need the `@/lib/searchTiers`
  // specifier to appear at all.
  const importSpecifiers = [...deriveSrc.matchAll(/from\s*["']([^"']+)["']/g)]
    .map((m) => m[1])
    .sort();
  const want = ["../types", "@/lib/searchTiers", "@/modules/hosts/types"].sort();
  ok(
    `derive.ts's import specifiers are exactly ${JSON.stringify(want)} - found ${JSON.stringify(importSpecifiers)}`,
    JSON.stringify(importSpecifiers) === JSON.stringify(want),
  );

  ok("does not redefine WORD_BOUNDARY locally", !deriveSrc.includes("const WORD_BOUNDARY"));
  ok(
    "does not contain a local word-splitting reimplementation",
    !deriveSrc.includes("value.split(WORD_BOUNDARY)"),
  );
}

// --- 12. Purity: source text, over the raw file, not just reachable code ---

console.log(
  "\n[12] purity: derive.ts imports no store, no Tauri, no React - by relative path OR alias",
);
{
  const deriveSrc = readFileSync(join(root, "src/modules/forwards/page/derive.ts"), "utf8");

  const universal = ["@tauri-apps", 'from "react"', "secrets_get"];
  for (const needle of universal) {
    ok(`derive.ts does not contain ${JSON.stringify(needle)}`, !deriveSrc.includes(needle));
  }

  const relative = ["../store", "../adapters", "../useForwards"];
  for (const needle of relative) {
    ok(`derive.ts does not contain ${JSON.stringify(needle)}`, !deriveSrc.includes(needle));
  }

  // Neither of the checks above catches the ALIAS form - this codebase's own
  // imports use it (`@/modules/hosts/types` above), so a store import spelled
  // `@/modules/forwards/store` would pass both while being exactly the
  // violation this section exists to catch.
  const aliased = [
    "@/modules/forwards/store",
    "@/modules/forwards/adapters",
    "@/modules/forwards/useForwards",
  ];
  for (const needle of aliased) {
    ok(`derive.ts does not contain ${JSON.stringify(needle)}`, !deriveSrc.includes(needle));
  }
}

console.log(failed === 0 ? "\nAll forwards-page checks passed." : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);

// --- mutation table ----------------------------------------------------
//
// Handoff discipline: a check that has not been watched fail is not a check.
// Every mutation below was actually run against this file, its exit code
// recorded, and the source restored by hash.
//
//   Id    Mutation                                          Check(s) it killed
//   ----  -------------------------------------------      ----------------------------
//   D1    ruleRows: hostDangling set from                  section 1's hostDangling
//           `hostName === UNKNOWN_HOST_LABEL` instead of      literal-per-row check
//           `host === undefined`
//   D2    rankRules: `matched.map((m) => m.row)` with the   section 2's tier-order and
//           `.sort(...)` call before it deleted               default-order checks
//   D3    hasWordBoundaryMatch's body inlined into           section 11's structural
//           `ruleMatchTier` instead of imported                import-specifier-set check
//   D4    localPortLabel: `rule.localPort` read in the       section 6's pinned-and-
//           bound branch instead of `boundPort`                bound-differ check
//   D5    bindFailureText's fallback `return error;`         section 7's unrecognised-
//           replaced with `return "Could not bind.";`          io-error check
//   D6    privilegedPortWarning's guard changed from          section 8's port-0 check
//           `localPort >= 1` to `localPort >= 0`
//   D7    ruleMatchTier: `localPort.startsWith(query) ||`    section 3's tier-2-outranks
//           inserted ahead of the substring tier                -every-port-match check
//   D8    deleteNote: `subject.pageStops` read replaced      section 10's stops-it-vs-
//           with `false` (the sentence never fires)             nothing-to-stop
//           [`subject.running` when D8 was run - the            inequality check
//           field was renamed in round 5]
//   Y5    deleteNote's hostOwned arm collapsed into         section 10's four
//           `subject.pageStops || subject.hostOwned`, both      hostOwned sentences AND
//           arms taking the stopping sentence - the             the hostOwned-vs-
//           false promise that round removed                    page-stops-it inequality
//                                                                (5 checks)
//   Y12   ruleRows: hostDangling back to                    section 1's empty-host-map
//           `host === undefined`, `hostsKnown` dropped          pre-load check ONLY -
//                                                                the paired positive and
//                                                                the label check stayed
//                                                                green, which is exactly
//                                                                what having them is for
//                                                                (the fix is not an
//                                                                off-switch)
//   W6b   deleteNote's `subject.pageStops` read replaced   section 10's three
//           with `false` - "drop the starting arm", as        page-stops-it checks
//           far as this file can express it (fp 76/79)
//   W6a   the WIDENING dropped instead, at its only        GREEN HERE, and that is the
//           definition: `RuleCard.tsx`'s                     finding rather than the
//           `const pageStops = running || starting;`         check. This file sees an
//           narrowed to `running`                            already-decided boolean, so
//                                                                no fixture over
//                                                                `deleteNote` can reach the
//                                                                caller that decides it.
//                                                                Pinned at the binding in
//                                                                forwards-shell-verify.ts's
//                                                                section 11, which reddens
//                                                                at 227/228.
