/**
 * Self-check for the pure Vault derivation layer (6e wave 1, step 4).
 * Run: `pnpm verify` (or `npx tsx scripts/vault-page-verify.ts` to iterate).
 *
 * `modules/vault/refs.ts` and `modules/vault/page/derive.ts` are pure - no React,
 * no store, no Tauri, no keychain read - which is the only reason this file can
 * exist. This module has NO production import yet: wave 2 wires the Vault page
 * to it. This script is its only caller in wave 1, and that is deliberate.
 *
 * Modelled on `scripts/hosts-page-verify.ts`: same `canonical()` (JSON is
 * key-order sensitive and drops `undefined` keys, and both matter here), same
 * `check`/`ok` pair, fixtures, numbered sections, and a mutation table at the
 * tail recording every mutation actually run against this file.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  deleteNote,
  deleteRefusalText,
  hostsUsingIdentity,
  identitiesUsingKey,
  identityMissingSecret,
  identityRows,
  keyMissingSecret,
  keyRows,
  rankIdentities,
  rankKeys,
  UNKNOWN_KEY_LABEL,
  type DeleteNoteSubject,
  type IdentityRow,
  type KeyRow,
} from "../src/modules/vault/page/derive";
import type { RdpHost, SshHost } from "../src/modules/hosts/types";
import { VaultInUseError } from "../src/modules/vault/types";
import type { VaultIdentity, VaultKey } from "../src/modules/vault/types";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

let failed = 0;

/**
 * JSON with object keys SORTED, and `undefined` values kept. See
 * `hosts-page-verify.ts`'s helper of the same name for the full reasoning:
 * `JSON.stringify` is key-order sensitive and drops `undefined` keys, and this
 * file cares about both - `keyName: undefined` (names no key) must read
 * differently from `keyName` simply missing from a hand-written `want`.
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
// `hosts-page-verify.ts` follows and for the same reason: no check here can be
// reading a fixture an earlier one mutated.

function identity(id: string, over: Partial<VaultIdentity> = {}): VaultIdentity {
  return {
    id,
    name: `Identity ${id}`,
    username: `user-${id}`,
    authMode: "password",
    hasPassword: true,
    ...over,
  };
}

function key(id: string, over: Partial<VaultKey> = {}): VaultKey {
  return { id, name: `Key ${id}`, hasPrivateKey: true, hasPassphrase: false, ...over };
}

function sshBound(id: string, identityId: string): SshHost {
  return {
    id,
    name: `ssh ${id}`,
    host: `${id}.internal`,
    port: 22,
    protocol: "ssh",
    credential: { kind: "identity", identityId },
  };
}

function sshInline(id: string): SshHost {
  return {
    id,
    name: `ssh ${id}`,
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
  };
}

function rdpBound(id: string, identityId: string): RdpHost {
  return {
    id,
    name: `rdp ${id}`,
    host: `${id}.internal`,
    port: 3389,
    protocol: "rdp",
    desktopWidth: 1920,
    desktopHeight: 1080,
    sizeMode: "preset",
    credential: { kind: "identity", identityId },
  };
}

function rdpInline(id: string): RdpHost {
  return {
    id,
    name: `rdp ${id}`,
    host: `${id}.internal`,
    port: 3389,
    protocol: "rdp",
    desktopWidth: 1920,
    desktopHeight: 1080,
    sizeMode: "preset",
    credential: { kind: "inline", hostId: id, username: "administrator", hasPassword: true },
  };
}

// --- 1. identityMissingSecret truth table -------------------------------

console.log("[1] identityMissingSecret: one branch per auth mode, dangling and broken keys");
{
  const noKeys = new Map<string, VaultKey>();
  check(
    "password auth with a stored password is fine",
    identityMissingSecret(identity("i-1", { authMode: "password", hasPassword: true }), noKeys),
    false,
  );
  check(
    "password auth with no stored password is missing",
    identityMissingSecret(identity("i-2", { authMode: "password", hasPassword: false }), noKeys),
    true,
  );
  // Never missing, and not a shortcut: the local ssh-agent holds the key and
  // signs the handshake, so there is no secret for this record to be missing -
  // must read false even with every flag off.
  check(
    "agent auth is never missing, even with hasPassword false",
    identityMissingSecret(identity("i-3", { authMode: "agent", hasPassword: false }), noKeys),
    false,
  );
  check(
    "key auth with no keyId at all is missing",
    identityMissingSecret(identity("i-4", { authMode: "key", keyId: undefined }), noKeys),
    true,
  );
  // The two that must NOT read as fine.
  check(
    "key auth naming a key the map does not have is missing",
    identityMissingSecret(
      identity("i-5", { authMode: "key", keyId: "k-gone" }),
      new Map([["k-1", key("k-1")]]),
    ),
    true,
  );
  check(
    "key auth naming a key whose private half is gone is missing",
    identityMissingSecret(
      identity("i-6", { authMode: "key", keyId: "k-1" }),
      new Map([["k-1", key("k-1", { hasPrivateKey: false })]]),
    ),
    true,
  );
  check(
    "key auth naming a good key is fine",
    identityMissingSecret(
      identity("i-7", { authMode: "key", keyId: "k-1" }),
      new Map([["k-1", key("k-1", { hasPrivateKey: true })]]),
    ),
    false,
  );
}

// --- 2. hostsUsingIdentity ------------------------------------------------

console.log("\n[2] hostsUsingIdentity: exactly the holders, named, over five hosts");
{
  const hosts = [
    sshBound("h-1", "i-1"),
    rdpBound("h-2", "i-1"),
    sshBound("h-3", "i-2"),
    sshInline("h-4"),
    rdpInline("h-5"),
  ];
  check("i-1 is used by exactly its SSH and RDP holders, named", hostsUsingIdentity(hosts, "i-1"), [
    { id: "h-1", name: "ssh h-1" },
    { id: "h-2", name: "rdp h-2" },
  ]);
  check("i-2 is used by exactly its one holder", hostsUsingIdentity(hosts, "i-2"), [
    { id: "h-3", name: "ssh h-3" },
  ]);
  check("an identity nothing binds to has no holders", hostsUsingIdentity(hosts, "i-unused"), []);
}

// --- 3. identitiesUsingKey ------------------------------------------------

console.log("\n[3] identitiesUsingKey: exactly the identities naming this key");
{
  const identities = [
    identity("i-1", { authMode: "key", keyId: "k-1" }),
    identity("i-2", { authMode: "key", keyId: "k-1" }),
    identity("i-3", { authMode: "password", keyId: undefined }),
  ];
  check("k-1 is named by exactly its two identities", identitiesUsingKey(identities, "k-1"), [
    { id: "i-1", name: "Identity i-1" },
    { id: "i-2", name: "Identity i-2" },
  ]);
  check("a key nothing names has no holders", identitiesUsingKey(identities, "k-unused"), []);
}

// --- 4. Row builders -------------------------------------------------------

console.log("\n[4] identityRows and keyRows: counts and key-name resolution agree");
{
  const keys = [key("k-1"), key("k-2", { hasPrivateKey: false })];
  const keyMap = new Map(keys.map((k) => [k.id, k]));
  const identities = [
    identity("i-1", { authMode: "key", keyId: "k-1" }),
    identity("i-2", { authMode: "key", keyId: "k-gone" }),
    identity("i-3", { authMode: "password", keyId: undefined }),
    identity("i-4", { authMode: "key", keyId: "k-2" }),
  ];
  const hosts = [sshBound("h-1", "i-1"), rdpBound("h-2", "i-1"), sshBound("h-3", "i-3")];

  const rows = identityRows(identities, keyMap, hosts);

  // Literal expected values, not `hosts.map(...).length)`-shaped expressions
  // built from the same lookups the rows are built from: i-1 is bound by h-1
  // and h-2 (2), i-2 and i-3 are bound by nothing under this key (0 each - i-3
  // binds h-3 for host purposes but that is irrelevant to ITS OWN hostCount,
  // which counts hosts binding i-3, not i-1/i-2), i-4 by nothing (0). A check
  // that instead re-ran `hostsUsingIdentity` to build its own "want" would
  // pass even if `hostsUsingIdentity` itself always returned `[]`, because
  // both sides of the comparison would move together.
  check(
    "hostCount: literal count per identity - i-1 has two holders, i-2/i-3/i-4 none",
    rows.map((r) => r.hostCount),
    [2, 0, 1, 0],
  );
  check(
    "keyName: live key's name, UNKNOWN_KEY_LABEL for dangling, undefined for none",
    rows.map((r) => r.keyName),
    ["Key k-1", UNKNOWN_KEY_LABEL, undefined, "Key k-2"],
  );
  // Same literal discipline: i-1's key (k-1) has its private half, so i-1 is
  // fine; i-2 names a key the map does not have, so it is missing; i-3 is
  // password auth with `hasPassword: true` (the `identity()` default), so it
  // is fine; i-4's key (k-2) is missing its private half, so i-4 is missing.
  check(
    "missingSecret: literal per identity - only the dangling key and the key missing its private half are missing",
    rows.map((r) => r.missingSecret),
    [false, true, false, true],
  );

  const kRows = keyRows(keys, identities);
  // k-1 is named by i-1 alone (i-4 names k-2, i-2 names a dangling id, i-3
  // names none): count 1. k-2 is named by i-4 alone: count 1.
  check(
    "keyRows.identityCount: literal per key - each of k-1 and k-2 is named by exactly one identity",
    kRows.map((r) => r.identityCount),
    [1, 1],
  );
}

// --- 5. Ranking -------------------------------------------------------------

console.log("\n[5] rankIdentities and rankKeys: tiers, drops, empty and whitespace queries");
{
  // Six rows, all matched against the query "db", chosen so the DEFAULT order
  // (name, then id) is a genuine permutation of the tier order below - not the
  // identity permutation - so a comparator that returned the input unsorted, or
  // a filter that did not run, would still fail this section.
  //
  //   name           username     tier for "db"
  //   -------------  -----------  -------------------------------------------
  //   "db"           "zz"         1 - exact
  //   "db-prod"      "zz"         2 - prefix (also word-boundary, but tier 2
  //                               is checked first and wins)
  //   "zzzzzz"       "db-admin"   3 - username prefix (name matches nothing)
  //   "prod-db-01"   "zz"         4 - word boundary, NOT a name prefix
  //   "adbox"        "nope"       5 - plain substring, no boundary either side
  //   "nothing"      "nope"       no tier - dropped
  const charlie = identity("i-charlie", { name: "db", username: "zz" });
  const delta = identity("i-delta", { name: "db-prod", username: "zz" });
  const echo = identity("i-echo", { name: "zzzzzz", username: "db-admin" });
  const bravo = identity("i-bravo", { name: "prod-db-01", username: "zz" });
  const alpha = identity("i-alpha", { name: "adbox", username: "nope" });
  const foxtrot = identity("i-foxtrot", { name: "nothing", username: "nope" });

  const rowOf = (i: VaultIdentity): IdentityRow => ({
    identity: i,
    keyName: undefined,
    keyDangling: false,
    hostCount: 0,
    missingSecret: false,
  });
  const rows = [alpha, bravo, charlie, delta, echo, foxtrot].map(rowOf);

  // Default order by name: adbox, db, db-prod, nothing, prod-db-01, zzzzzz.
  check(
    "empty query returns every row in default (name, then id) order",
    rankIdentities(rows, "").map((r) => r.identity.id),
    ["i-alpha", "i-charlie", "i-delta", "i-foxtrot", "i-bravo", "i-echo"],
  );
  check(
    "whitespace-only query behaves as empty",
    rankIdentities(rows, "   ").map((r) => r.identity.id),
    ["i-alpha", "i-charlie", "i-delta", "i-foxtrot", "i-bravo", "i-echo"],
  );
  check(
    "query 'db': exact beats prefix beats username-prefix beats word-boundary beats substring; no-tier dropped",
    rankIdentities(rows, "db").map((r) => r.identity.id),
    ["i-charlie", "i-delta", "i-echo", "i-bravo", "i-alpha"],
  );
  ok(
    "the non-matching row is dropped, not sorted to the bottom",
    !rankIdentities(rows, "db")
      .map((r) => r.identity.id)
      .includes("i-foxtrot"),
  );
  check(
    "how many hits is the array length: 5 of 6 rows match 'db'",
    rankIdentities(rows, "db").length,
    5,
  );

  // keyName reaches tier 5: a user searching for the key an identity uses
  // should find it even though the query matches neither name nor username. A
  // ONE-row list can only prove "matched", not "matched at tier 5" - moving
  // keyName to any other tier would still rank it first (and last) in a list
  // of one. Pairing it with a row that qualifies at tier 2 (name-prefix) makes
  // the tier observable: the tier-2 row must sort first regardless of name,
  // and only does if keyName is genuinely weaker than tier 2.
  const keyNameOnly: IdentityRow = {
    identity: identity("i-key", { name: "zzzzzz", username: "zz-user" }),
    keyName: "deploy-key",
    keyDangling: false,
    hostCount: 0,
    missingSecret: false,
  };
  const namePrefixCompetitor: IdentityRow = {
    identity: identity("i-name", { name: "deploy-box", username: "zz-user2" }),
    keyName: undefined,
    keyDangling: false,
    hostCount: 0,
    missingSecret: false,
  };
  check(
    "keyName participates at tier 5: ranks behind a tier-2 name-prefix match, not ahead or tied",
    rankIdentities([keyNameOnly, namePrefixCompetitor], "deploy").map((r) => r.identity.id),
    ["i-name", "i-key"],
  );

  // domain reaches tier 5 the same way - RDP-only field, untested until now.
  // Same observability shape: a tier-2 name-prefix competitor must outrank it.
  const domainOnly: IdentityRow = {
    identity: identity("i-domain", {
      name: "zzzzzz",
      username: "zz-user",
      domain: "corp.example.com",
    }),
    keyName: undefined,
    keyDangling: false,
    hostCount: 0,
    missingSecret: false,
  };
  const domainCompetitor: IdentityRow = {
    identity: identity("i-domain-name", { name: "corp-box", username: "zz-user2" }),
    keyName: undefined,
    keyDangling: false,
    hostCount: 0,
    missingSecret: false,
  };
  check(
    "domain participates at tier 5: ranks behind a tier-2 name-prefix match, not ahead or tied",
    rankIdentities([domainOnly, domainCompetitor], "corp").map((r) => r.identity.id),
    ["i-domain-name", "i-domain"],
  );

  // rankKeys mirrors the same shape over its own fields. Six rows against
  // query "db", chosen (as above) so the DEFAULT order is a genuine
  // permutation of the tier order - not the input order - so an unsorted
  // result, or a filter that never ran, fails this too.
  //
  //   name           fingerprint       tier for "db"
  //   -------------  ----------------  ------------------------------------
  //   "db"                             1 - exact
  //   "db-prod-key"                    2 - prefix (also word-boundary, but
  //                                    tier 2 is checked first and wins)
  //   "zzzzzz"       "SHA256:dbxxxx"   3 - fingerprint prefix (name matches
  //                                    nothing)
  //   "prod-db-01"                     4 - word boundary, NOT a name prefix
  //   "adbox"                          5 - plain substring, no boundary
  //                                    either side
  //   "nothing"                        no tier - dropped
  const kAlpha = key("k-alpha", { name: "adbox" });
  const kBravo = key("k-bravo", { name: "db-prod-key" });
  const kCharlie = key("k-charlie", { name: "db" });
  const kDelta = key("k-delta", { name: "prod-db-01" });
  const kEcho = key("k-echo", { name: "zzzzzz", fingerprint: "SHA256:dbxxxx" });
  const kNomatch = key("k-nomatch", { name: "nothing" });
  const kRows: KeyRow[] = [kAlpha, kBravo, kCharlie, kDelta, kEcho, kNomatch].map((k) => ({
    key: k,
    identityCount: 0,
    missingPrivateKey: false,
  }));

  // Default order by name: adbox, db, db-prod-key, nothing, prod-db-01, zzzzzz.
  check(
    "rankKeys: empty query returns every row in default (name, then id) order",
    rankKeys(kRows, "").map((r) => r.key.id),
    ["k-alpha", "k-charlie", "k-bravo", "k-nomatch", "k-delta", "k-echo"],
  );
  check(
    "rankKeys 'db': exact beats prefix beats fingerprint-prefix beats word-boundary beats substring; no-tier dropped",
    rankKeys(kRows, "db").map((r) => r.key.id),
    ["k-charlie", "k-bravo", "k-echo", "k-delta", "k-alpha"],
  );
  ok(
    "rankKeys: the non-matching row is dropped, not sorted to the bottom",
    !rankKeys(kRows, "db")
      .map((r) => r.key.id)
      .includes("k-nomatch"),
  );
  check("rankKeys 'db' hit count is 5 of 6 rows", rankKeys(kRows, "db").length, 5);

  // keyType reaches tier 5, same observability shape as keyName/domain above.
  const keyTypeOnly: KeyRow = {
    key: key("k-type", { name: "zzzzzz", keyType: "ed25519" }),
    identityCount: 0,
    missingPrivateKey: false,
  };
  const keyTypeCompetitor: KeyRow = {
    key: key("k-type-name", { name: "ed25519-prod" }),
    identityCount: 0,
    missingPrivateKey: false,
  };
  check(
    "keyType participates at tier 5: ranks behind a tier-2 name-prefix match, not ahead or tied",
    rankKeys([keyTypeOnly, keyTypeCompetitor], "ed25519").map((r) => r.key.id),
    ["k-type-name", "k-type"],
  );
}

// --- 6. The comparator is total --------------------------------------------

console.log("\n[6] two rows equal on name break the tie on id, both input orders");
{
  const a: IdentityRow = {
    identity: identity("i-b", { name: "same" }),
    keyName: undefined,
    keyDangling: false,
    hostCount: 0,
    missingSecret: false,
  };
  const b: IdentityRow = {
    identity: identity("i-a", { name: "same" }),
    keyName: undefined,
    keyDangling: false,
    hostCount: 0,
    missingSecret: false,
  };
  check(
    "forward input order: id order wins the tie",
    rankIdentities([a, b], "").map((r) => r.identity.id),
    ["i-a", "i-b"],
  );
  check(
    "reversed input order: same result",
    rankIdentities([b, a], "").map((r) => r.identity.id),
    ["i-a", "i-b"],
  );

  const ka: KeyRow = {
    key: key("k-b", { name: "same" }),
    identityCount: 0,
    missingPrivateKey: false,
  };
  const kb: KeyRow = {
    key: key("k-a", { name: "same" }),
    identityCount: 0,
    missingPrivateKey: false,
  };
  check(
    "rankKeys forward input order: id order wins the tie",
    rankKeys([ka, kb], "").map((r) => r.key.id),
    ["k-a", "k-b"],
  );
  check(
    "rankKeys reversed input order: same result",
    rankKeys([kb, ka], "").map((r) => r.key.id),
    ["k-a", "k-b"],
  );
}

// --- 7. Case folding is load-bearing ----------------------------------------

console.log("\n[7] mixed-case name vs lowercase query, and the reverse, both fold");
{
  const mixedName: IdentityRow = {
    identity: identity("i-1", { name: "ProdBox" }),
    keyName: undefined,
    keyDangling: false,
    hostCount: 0,
    missingSecret: false,
  };
  check(
    "mixed-case name matches a lowercase query",
    rankIdentities([mixedName], "prodbox").map((r) => r.identity.id),
    ["i-1"],
  );
  const lowerName: IdentityRow = {
    identity: identity("i-2", { name: "prodbox" }),
    keyName: undefined,
    keyDangling: false,
    hostCount: 0,
    missingSecret: false,
  };
  check(
    "lowercase name matches a mixed-case query",
    rankIdentities([lowerName], "ProdBox").map((r) => r.identity.id),
    ["i-2"],
  );

  const mixedKey: KeyRow = {
    key: key("k-1", { name: "DeployKey" }),
    identityCount: 0,
    missingPrivateKey: false,
  };
  check(
    "rankKeys: mixed-case name matches a lowercase query",
    rankKeys([mixedKey], "deploykey").map((r) => r.key.id),
    ["k-1"],
  );
  const lowerKey: KeyRow = {
    key: key("k-2", { name: "deploykey" }),
    identityCount: 0,
    missingPrivateKey: false,
  };
  check(
    "rankKeys: lowercase name matches a mixed-case query",
    rankKeys([lowerKey], "DeployKey").map((r) => r.key.id),
    ["k-2"],
  );
}

// --- 8. rankKeys fingerprint tier --------------------------------------------

console.log(
  "\n[8] fingerprint tier: full SHA256 form and the bare digest both match, at tier 3 specifically",
);
{
  // A one-row list can only prove "matched", not "matched at tier 3" - tiers 3
  // and 5 would look identical with one row. Each check below pairs the
  // fingerprint row with a row that qualifies ONLY at tier 5 (a plain
  // substring of that same query text, no boundary either side, no
  // fingerprint) - the fingerprint row must sort first, which only happens if
  // its match is genuinely tier 3, stronger than tier 5.
  const fp: KeyRow = {
    key: key("k-fp", { name: "zzzzzz", fingerprint: "SHA256:AbCdEf" }),
    identityCount: 0,
    missingPrivateKey: false,
  };

  const subForPrefixed: KeyRow = {
    key: key("k-sub-1", { name: "xxsha256:abcxx" }),
    identityCount: 0,
    missingPrivateKey: false,
  };
  check(
    "query 'sha256:abc': fingerprint row ranks ahead of a tier-5 substring row (tier 3 beats tier 5)",
    rankKeys([subForPrefixed, fp], "sha256:abc").map((r) => r.key.id),
    ["k-fp", "k-sub-1"],
  );

  const subForBare: KeyRow = {
    key: key("k-sub-2", { name: "xxabcdefxx" }),
    identityCount: 0,
    missingPrivateKey: false,
  };
  check(
    "query 'abcdef' (after the prefix): same, tier 3 still beats tier 5",
    rankKeys([subForBare, fp], "abcdef").map((r) => r.key.id),
    ["k-fp", "k-sub-2"],
  );

  // The regression this whole tier exists to prevent: every fingerprint
  // shares the literal "SHA256:" lead, so a query that is only a PREFIX of
  // that constant string - "s", "sh", "sha", ... all the way to "sha256:"
  // itself - must NOT match a fingerprinted key by virtue of the prefix
  // alone. Both rows below have a fingerprint and a name unrelated to any of
  // these queries; the un-stripped-string bug this file used to have (see
  // `derive.ts`'s `keyMatchTier` doc) made every one of them a tier-3 hit
  // against both rows.
  const irrelevant1: KeyRow = {
    key: key("k-irr-1", { name: "zzzzzz1", fingerprint: "SHA256:aaaa" }),
    identityCount: 0,
    missingPrivateKey: false,
  };
  const irrelevant2: KeyRow = {
    key: key("k-irr-2", { name: "zzzzzz2", fingerprint: "SHA256:bbbb" }),
    identityCount: 0,
    missingPrivateKey: false,
  };
  for (const q of ["s", "sh", "sha", "sha2", "sha25", "sha256", "sha256:"]) {
    ok(
      `query ${JSON.stringify(q)} matches neither fingerprinted key by the constant "sha256:" prefix alone`,
      rankKeys([irrelevant1, irrelevant2], q).length === 0,
    );
  }
}

// --- 9. Purity: source text, over the raw file, not just reachable code -----

console.log(
  "\n[9] purity: neither file imports the store, Tauri, React or a secret call - by relative path OR alias",
);
{
  const deriveSrc = readFileSync(join(root, "src/modules/vault/page/derive.ts"), "utf8");
  const refsSrc = readFileSync(join(root, "src/modules/vault/refs.ts"), "utf8");

  // Needles with no relative form at all - true regardless of which file
  // writes them.
  const universal = ["@tauri-apps", 'from "react"', "secrets_get", "getHostSshSecrets"];
  for (const needle of universal) {
    ok(`derive.ts does not contain ${JSON.stringify(needle)}`, !deriveSrc.includes(needle));
    ok(`refs.ts does not contain ${JSON.stringify(needle)}`, !refsSrc.includes(needle));
  }

  // The relative-import needles are NOT path-independent: `derive.ts` sits at
  // `src/modules/vault/page/`, one directory deeper than `refs.ts` at
  // `src/modules/vault/`, so the same sibling module is spelled "../store"
  // from derive.ts but "./store" from refs.ts. Checking "../store" against
  // refs.ts's own text was checking for a form that file could never write -
  // one needle per file, at that file's own depth.
  const deriveRelative = ["../store", "../adapters", "../resolve"];
  for (const needle of deriveRelative) {
    ok(`derive.ts does not contain ${JSON.stringify(needle)}`, !deriveSrc.includes(needle));
  }
  const refsRelative = ["./store", "./adapters", "./resolve"];
  for (const needle of refsRelative) {
    ok(`refs.ts does not contain ${JSON.stringify(needle)}`, !refsSrc.includes(needle));
  }

  // Neither depth-specific check catches the ALIAS form, and this codebase's
  // own imports use it (`@/modules/hosts/types`, `@/lib/searchTiers` above) -
  // `import { createVaultStore } from "@/modules/vault/store"` would pass
  // every needle above while being exactly the violation this section exists
  // to catch.
  const aliased = ["@/modules/vault/store", "@/modules/vault/adapters", "@/modules/vault/resolve"];
  for (const needle of aliased) {
    ok(`derive.ts does not contain ${JSON.stringify(needle)}`, !deriveSrc.includes(needle));
    ok(`refs.ts does not contain ${JSON.stringify(needle)}`, !refsSrc.includes(needle));
  }
}

// --- 10. The Host import in refs.ts stays type-only -------------------------

console.log("\n[10] refs.ts imports Host as a TYPE, never as a value");
{
  const refsSrc = readFileSync(join(root, "src/modules/vault/refs.ts"), "utf8");
  ok(
    "matches the type-only import form",
    /import type \{[^}]*Host[^}]*\} from "@\/modules\/hosts\/types"/.test(refsSrc),
  );
  ok(
    "does not match a value-import form of the same specifier",
    !/^import \{[^}]*\} from "@\/modules\/hosts\/types"/m.test(refsSrc),
  );
}

// --- 11. hosts/search.ts shares the word-boundary primitive -----------------

console.log("\n[11] hosts/search.ts imports the shared word-boundary check, no local copy");
{
  const searchSrc = readFileSync(join(root, "src/modules/hosts/search.ts"), "utf8");
  ok(
    "imports hasWordBoundaryMatch from the shared module",
    /from "@\/lib\/searchTiers"/.test(searchSrc),
  );
  ok("does not redefine WORD_BOUNDARY locally", !searchSrc.includes("const WORD_BOUNDARY"));
}

// --- 12. hosts/page/derive.ts shares the missing-secret answer --------------

console.log("\n[12] hosts/page/derive.ts imports the shared missing-secret check, no local copy");
{
  const deriveSrc = readFileSync(join(root, "src/modules/hosts/page/derive.ts"), "utf8");
  ok(
    "imports identityMissingSecret from the shared module",
    /from "@\/modules\/vault\/refs"/.test(deriveSrc),
  );
  ok(
    "does not redefine sshIdentityMissing locally",
    !deriveSrc.includes("function sshIdentityMissing"),
  );
}

// --- 13. hosts/store.ts shares the identity-holder lookup --------------------

console.log("\n[13] hosts/store.ts's identityHostRefs delegates to the shared lookup");
{
  const storeSrc = readFileSync(join(root, "src/modules/hosts/store.ts"), "utf8");
  ok("calls hostsUsingIdentity(", storeSrc.includes("hostsUsingIdentity("));
  ok(
    "does not re-derive the predicate inline",
    !storeSrc.includes("credential.identityId === identityId"),
  );
}

// --- 14. vault/store.ts shares the key-holder lookup -------------------------

console.log("\n[14] vault/store.ts's deleteKey holder lookup delegates to the shared lookup");
{
  const vaultStoreSrc = readFileSync(join(root, "src/modules/vault/store.ts"), "utf8");
  ok("calls identitiesUsingKey(", vaultStoreSrc.includes("identitiesUsingKey("));
  ok("does not re-derive the predicate inline", !vaultStoreSrc.includes("i.keyId === id"));
}

// --- 15. The dangling-key and missing-private-key fields --------------------

console.log("\n[15] keyDangling and missingPrivateKey: separate facts, literal per row");
{
  const keys = [
    key("k-1"),
    key("k-2", { hasPrivateKey: false }),
    key("k-3", { name: UNKNOWN_KEY_LABEL }),
  ];
  const keyMap = new Map(keys.map((k) => [k.id, k]));
  const identities = [
    identity("i-1", { authMode: "key", keyId: "k-1" }),
    identity("i-2", { authMode: "key", keyId: "k-gone" }),
    identity("i-3", { authMode: "password", keyId: "k-gone" }),
    identity("i-4", { authMode: "password", keyId: undefined }),
    identity("i-5", { authMode: "key", keyId: "k-3" }),
  ];
  const rows = identityRows(identities, keyMap, []);

  // i-5 is the case a label cannot express: it names a key that EXISTS and is
  // called "Unknown key", so its keyName is identical to i-2's and its
  // keyDangling must not be.
  check(
    "keyName cannot tell a dangling reference from a key named 'Unknown key'",
    [rows[1].keyName, rows[4].keyName],
    [UNKNOWN_KEY_LABEL, UNKNOWN_KEY_LABEL],
  );
  check(
    "keyDangling can - literal per row",
    rows.map((r) => r.keyDangling),
    [false, true, true, false, false],
  );
  // i-3 is the row wave 1 filed: a dangling keyId with a working password.
  check(
    "a dangling keyId on password auth is NOT a missing secret",
    [rows[2].keyDangling, rows[2].missingSecret],
    [true, false],
  );
  check("and on key auth it is both", [rows[1].keyDangling, rows[1].missingSecret], [true, true]);

  const kRows = keyRows(keys, identities);
  check(
    "missingPrivateKey: literal per key - only k-2 lacks its private half",
    kRows.map((r) => r.missingPrivateKey),
    [false, true, false],
  );
  // AGREEMENT BY VALUE, not structure: this compares `keys.map(keyMissingSecret)`
  // against rows built from that SAME function, so it cannot tell delegation
  // from duplication - a `key` arm that asked `!key.hasPrivateKey` itself
  // instead of calling `keyMissingSecret` would satisfy this identically.
  // Section 18's source-text check is what actually forbids the duplicate; do
  // not mistake this one for that guarantee.
  check(
    "keyMissingSecret answers the same question the key row shows",
    keys.map((k) => keyMissingSecret(k)),
    kRows.map((r) => r.missingPrivateKey),
  );
}

// --- 16. One definition of "this key has no private half" -------------------

console.log("\n[16] identityMissingSecret's key arm and the key row agree, by construction");
{
  const good = key("k-good");
  const bad = key("k-bad", { hasPrivateKey: false });
  const keyMap = new Map([good, bad].map((k) => [k.id, k]));
  for (const [k, want] of [
    [good, false],
    [bad, true],
  ] as const) {
    const onKey = identityMissingSecret(identity("i", { authMode: "key", keyId: k.id }), keyMap);
    check(`identity on key auth naming ${k.id}`, onKey, want);
    check(
      `...and the key row for ${k.id} says the same`,
      keyRows([k], []).length === 1 && keyRows([k], [])[0].missingPrivateKey,
      want,
    );
  }
  // Not covered by the two above: a key arm that ignored the shared leaf and
  // asked `!identity.hasPassword` instead would still pass them for these
  // fixtures. `hasPassword: false` on an identity whose KEY is fine must read
  // as not-missing.
  check(
    "key auth ignores hasPassword entirely",
    identityMissingSecret(
      identity("i", { authMode: "key", keyId: "k-good", hasPassword: false }),
      keyMap,
    ),
    false,
  );
}

// --- 17. deleteRefusalText ---------------------------------------------------

console.log("\n[17] deleteRefusalText: names the holders and the edit that clears them");
{
  const twoHosts = new VaultInUseError('identity "Prod root"', "host", [
    { id: "h-1", name: "web-1" },
    { id: "h-2", name: "db-1" },
  ]);
  check(
    "two hosts holding an identity",
    deleteRefusalText('identity "Prod root"', "host", twoHosts),
    'Cannot delete identity "Prod root": 2 hosts still use it (web-1, db-1). ' +
      "Point each of them at another credential first.",
  );

  const oneIdentity = new VaultInUseError('key "id_ed25519"', "identity", [
    { id: "i-1", name: "Prod root" },
  ]);
  check(
    "one identity holding a key - singular throughout",
    deleteRefusalText('key "id_ed25519"', "identity", oneIdentity),
    'Cannot delete key "id_ed25519": 1 identity still uses it (Prod root). ' +
      "Point it at another key first.",
  );

  const unnamed = new VaultInUseError('key "k"', "identity", [{ id: "i-7", name: "" }]);
  ok(
    "a holder with no name falls back to its id",
    deleteRefusalText('key "k"', "identity", unnamed).includes("(i-7)"),
  );

  // Anything that is not a refusal passes through untouched. A keychain error
  // eaten here is a user staring at a failure with no reason given.
  check(
    "a plain Error keeps its own message",
    deleteRefusalText('key "k"', "identity", new Error("keyring: access denied")),
    "keyring: access denied",
  );
  check(
    "and a non-Error is stringified rather than dropped",
    deleteRefusalText('key "k"', "identity", "boom"),
    "boom",
  );
}

// --- 18. One definition of "this key has no private half", structurally ----

console.log("\n[18] refs.ts and derive.ts do not duplicate keyMissingSecret's private-half test");
{
  const refsSrc = readFileSync(join(root, "src/modules/vault/refs.ts"), "utf8");
  const deriveSrc = readFileSync(join(root, "src/modules/vault/page/derive.ts"), "utf8");

  // Locate keyMissingSecret's own body FIRST, as ITS OWN check: a rename here
  // must fail loudly rather than the two checks below silently running over
  // `null`. The anchor is the function's signature line, which mentions
  // neither "hasPrivateKey" nor "keyMissingSecret(key)" - the two substrings
  // checked against the captured body below - so neither of those checks can
  // be satisfied by the anchor alone.
  const keyMissingSecretMatch =
    /function keyMissingSecret\(key: VaultKey\): boolean \{([\s\S]*?)\n\}/.exec(refsSrc);
  ok("keyMissingSecret's body is located in refs.ts", keyMissingSecretMatch !== null);
  const keyMissingSecretBody = keyMissingSecretMatch?.[1] ?? "";

  // `hasPrivateKey` names the flag exactly once in the whole file. Two means
  // the `key` arm of `identityMissingSecret` asked the question itself again
  // instead of delegating - duplication rather than the one shared leaf the
  // module's own top-of-file doc requires.
  const hasPrivateKeyCount = (refsSrc.match(/hasPrivateKey/g) ?? []).length;
  check("refs.ts names hasPrivateKey exactly once", hasPrivateKeyCount, 1);
  ok(
    "and that one occurrence sits inside keyMissingSecret's own body",
    keyMissingSecretBody.includes("hasPrivateKey"),
  );

  // keyRows must never read the flag directly - it must ask the shared
  // function instead. Scoped to keyRows's OWN body rather than the whole file:
  // `deleteNote`'s doc comment (`derive.ts` around its `DeleteNoteSubject`
  // type) legitimately names `hasPrivateKey` to explain why THAT function does
  // not model it, so a whole-file "nowhere at all" ban would redden on that
  // honest prose, not on a duplicate. The duplication Y3b actually introduces
  // lives inside `keyRows`, so that is where the negative assertion belongs.
  const keyRowsMatch = /function keyRows\([^)]*\): KeyRow\[\] \{([\s\S]*?)\n\}/.exec(deriveSrc);
  ok("keyRows's body is located in derive.ts", keyRowsMatch !== null);
  const keyRowsBody = keyRowsMatch?.[1] ?? "";
  ok(
    "keyRows's body does not read .hasPrivateKey directly",
    !keyRowsBody.includes("hasPrivateKey"),
  );
  ok(
    "keyRows computes missingPrivateKey by CALLING keyMissingSecret, not by reading the flag itself",
    keyRowsBody.includes("keyMissingSecret(key)"),
  );
}

// --- 19. deleteNote: exact sentence per record, never a protection claim ----

console.log(
  "\n[19] deleteNote: exact sentence per record, and no claim about how well a secret was kept",
);
{
  const keyWithPassphrase: DeleteNoteSubject = { kind: "key", hasPassphrase: true };
  const keyWithoutPassphrase: DeleteNoteSubject = { kind: "key", hasPassphrase: false };
  const passwordAuthWithPassword: DeleteNoteSubject = {
    kind: "identity",
    authMode: "password",
    hasPassword: true,
  };
  const passwordAuthWithoutPassword: DeleteNoteSubject = {
    kind: "identity",
    authMode: "password",
    hasPassword: false,
  };
  const keyAuthWithPassword: DeleteNoteSubject = {
    kind: "identity",
    authMode: "key",
    hasPassword: true,
  };
  const keyAuthWithoutPassword: DeleteNoteSubject = {
    kind: "identity",
    authMode: "key",
    hasPassword: false,
  };
  const agentAuthNoPassword: DeleteNoteSubject = {
    kind: "identity",
    authMode: "agent",
    hasPassword: false,
  };
  // Not one of the plan's minimum cases, but the honest consequence of
  // `hasPassword` being independent of `authMode` (`../types.ts:106`): agent
  // auth never NEEDS a password, but nothing stops the flag being true anyway,
  // and `deleteNote` reads the flag, not the mode, for that half of its answer.
  const agentAuthWithPassword: DeleteNoteSubject = {
    kind: "identity",
    authMode: "agent",
    hasPassword: true,
  };

  check(
    "key with a passphrase: both halves named",
    deleteNote(keyWithPassphrase),
    "Its stored private key and passphrase are deleted too.",
  );
  check(
    "key with no passphrase: only the key named",
    deleteNote(keyWithoutPassphrase),
    "Its stored private key is deleted too.",
  );
  check(
    "password auth with a stored password: the password, nothing about a key",
    deleteNote(passwordAuthWithPassword),
    "Its stored password is deleted too.",
  );
  check(
    "password auth with no stored password: nothing to delete",
    deleteNote(passwordAuthWithoutPassword),
    "There is no stored secret to delete.",
  );
  check(
    "key auth with a stored password: both the password AND the key's separateness",
    deleteNote(keyAuthWithPassword),
    "Its stored password is deleted too. The key it uses is a separate record and is not deleted.",
  );
  check(
    "key auth with no stored password: only the key's separateness",
    deleteNote(keyAuthWithoutPassword),
    "The key it uses is a separate record and is not deleted.",
  );
  check(
    "agent auth with no stored password: nothing to delete",
    deleteNote(agentAuthNoPassword),
    "There is no stored secret to delete.",
  );
  check(
    "agent auth with a stored password anyway: the flag speaks, not the mode",
    deleteNote(agentAuthWithPassword),
    "Its stored password is deleted too.",
  );

  // Never a claim about how well the secret was kept - a private key sits in a
  // mode-0600 plaintext file before and after this delete regardless of which
  // sentence fires. `scripts/vault-shell-verify.ts` section 12 scans
  // `VaultPage.tsx` and the two card files for exactly this pattern; this copy
  // lives in `derive.ts`, which that scan never reaches. Asserted over every
  // string the function above was shown to return, not a sample of one.
  const everyNote = [
    keyWithPassphrase,
    keyWithoutPassphrase,
    passwordAuthWithPassword,
    passwordAuthWithoutPassword,
    keyAuthWithPassword,
    keyAuthWithoutPassword,
    agentAuthNoPassword,
    agentAuthWithPassword,
  ].map((subject) => deleteNote(subject));
  for (const note of everyNote) {
    ok(
      `${JSON.stringify(note)} makes no protection claim`,
      !/\bsafer\b|\bsecurely\b|\bmore secure\b/i.test(note) &&
        !note.includes("OS keychain") &&
        !note.includes("Credential Manager"),
    );
  }
}

console.log(failed === 0 ? "\nAll vault-page checks passed." : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);

// --- mutation table ----------------------------------------------------
//
// Handoff discipline (this wave's plan, step 4): a check that has not been
// watched fail is not a check. Every mutation below was actually run against
// this file, its exit code recorded, and the source restored by hash - see
// /tmp/wave1-step4/MUTATIONS.md for the full before/after/restore transcript.
//
//   Mutation                                          Check(s) it killed
//   -------------------------------------------      ----------------------------
//   refs.ts: identityMissingSecret's `key` arm        section 1's dangling-key and
//     returns `false` unconditionally (B1)             no-private-half checks
//   derive.ts: rankIdentities returns `[...rows]`     section 5 (rebuilt fixture:
//     unsorted (B2)                                    default order is NOT the
//                                                       tier-5 query order)
//   derive.ts: rankKeys with both `.toLowerCase()`    section 7
//     calls deleted (B3)
//   searchTiers.ts: WORD_BOUNDARY changed to /[Q]/    section 5's "prod-db-01"
//     (B4)                                             word-boundary check
//   derive.ts: `id` tie-break deleted from both       section 6
//     comparators (B5)
//
// Step 5 (this wave's plan) adds the cross-file half: each mutation below
// reddens THIS file's section 11-14 check AND a pre-existing suite that now
// depends on the same single definition, proving the delegation, not just the
// source text, actually happened. See /tmp/wave1-step5/MUTATIONS.md.
//
//   refs.ts: hostsUsingIdentity returns `[]` (B6)      section 13, AND
//                                                       hosts-store-verify's
//                                                       "identityHostRefs names
//                                                       every host bound to one
//                                                       identity, across
//                                                       protocols"
//   refs.ts: identityMissingSecret's `key` arm         section 12, AND
//     returns `false` (B7)                              hosts-page-verify's
//                                                       identity-bound
//                                                       missingSecret checks
//   searchTiers.ts: WORD_BOUNDARY changed to /[Q]/     section 11, AND
//     (B8)                                              hosts-search-verify's
//                                                       tier 4 word-boundary
//                                                       checks
//   refs.ts: identitiesUsingKey returns `[]` (B9)      section 14, AND
//                                                       vault-resolve-verify's
//                                                       "a key held by two
//                                                       identities refuses,
//                                                       naming both"
//
// Wave 2 step 1 adds the two new row fields, the shared key-missing leaf and
// the refusal copy. See /tmp/wave2-derive/MUTATIONS.md for the full transcript.
//
//   derive.ts: identityRows' `keyDangling = key ===         section 15's
//     undefined` changed to `keyDangling = false` (W1)        keyDangling
//                                                              literal check
//   derive.ts: `keyDangling = keyName === UNKNOWN_KEY_LABEL`  section 15's
//     instead of `key === undefined` (W2)                     "keyDangling can
//                                                              - literal per
//                                                              row" - NOT the
//                                                              "keyName cannot
//                                                              tell..." check
//                                                              this table used
//                                                              to (wrongly)
//                                                              credit: that one
//                                                              asserts keyName,
//                                                              which W2 never
//                                                              touches. i-5's
//                                                              fixture (a REAL
//                                                              key named
//                                                              "Unknown key")
//                                                              is what makes
//                                                              the surviving
//                                                              check
//                                                              discriminating -
//                                                              it is present
//                                                              and doing its
//                                                              job.
//   refs.ts: keyMissingSecret's body changed to               sections 1, 15,
//     `return false` (W3) - CROSS-FILE                        16 in THIS file,
//                                                              AND hosts-page-
//                                                              verify's identity-
//                                                              bound missingSecret
//                                                              check (proves the
//                                                              `key` arm actually
//                                                              routes through the
//                                                              shared leaf)
//   derive.ts: deleteRefusalText's refusal branch            section 17's two
//     changed to `return e.message` (W4)                       exact-string checks
//   derive.ts: deleteRefusalText's guard changed to           section 17's last
//     `if (e instanceof VaultInUseError) {...}` with the        two checks
//     non-refusal path returning `""` (W5)
//
// Wave 2 fix pass adds section 18 (the structural duplicate-detection check
// gap 1 of that pass names) and section 19 (`deleteNote`, previously
// uncovered). See /tmp/wave2-fix-derivecheck/MUTATIONS.md for the full
// transcript, including W1-W5 re-run to confirm this table is still honest.
//
//   Y3 (measured): refs.ts's `key` arm duplicates          section 18's
//     `!key.hasPrivateKey` AND derive.ts's `keyRows`          "hasPrivateKey
//     reads `!key.hasPrivateKey` directly, BOTH at once -     exactly once" AND
//     before this pass, all of vault-page (91), hosts-page     "derive.ts names
//     (58) and vault-shell (76) stayed EXIT=0 and              hasPrivateKey
//     `keyMissingSecret` became a dead export unnoticed         nowhere at all"
//   Y3a: refs.ts half of Y3 alone                           section 18's
//                                                              "hasPrivateKey
//                                                              exactly once"
//   Y3b: derive.ts half of Y3 alone                         section 18's
//                                                              "hasPrivateKey
//                                                              nowhere at all"
//                                                              AND "keyRows
//                                                              computes... by
//                                                              CALLING"
