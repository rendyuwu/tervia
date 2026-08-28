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
  hostsUsingIdentity,
  identitiesUsingKey,
  identityMissingSecret,
  identityRows,
  keyRows,
  rankIdentities,
  rankKeys,
  UNKNOWN_KEY_LABEL,
  type IdentityRow,
  type KeyRow,
} from "../src/modules/vault/page/derive";
import type { RdpHost, SshHost } from "../src/modules/hosts/types";
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

  check(
    "hostCount matches hostsUsingIdentity(...).length for every row",
    rows.map((r) => r.hostCount),
    identities.map((i) => hostsUsingIdentity(hosts, i.id).length),
  );
  check(
    "keyName: live key's name, UNKNOWN_KEY_LABEL for dangling, undefined for none",
    rows.map((r) => r.keyName),
    ["Key k-1", UNKNOWN_KEY_LABEL, undefined, "Key k-2"],
  );
  check(
    "missingSecret agrees with identityMissingSecret for every row",
    rows.map((r) => r.missingSecret),
    identities.map((i) => identityMissingSecret(i, keyMap)),
  );

  const kRows = keyRows(keys, identities);
  check(
    "keyRows.identityCount matches identitiesUsingKey(...).length for every row",
    kRows.map((r) => r.identityCount),
    keys.map((k) => identitiesUsingKey(identities, k.id).length),
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
  // should find it even though the query matches neither name nor username.
  const withKey: IdentityRow = {
    identity: identity("i-key", { name: "solo", username: "solo-user" }),
    keyName: "deploy-key",
    hostCount: 0,
    missingSecret: false,
  };
  check(
    "keyName participates at tier 5",
    rankIdentities([withKey], "deploy").map((r) => r.identity.id),
    ["i-key"],
  );

  // rankKeys mirrors the same shape over its own fields.
  const kAlpha = key("k-alpha", { name: "alpha", fingerprint: "SHA256:zzzz" });
  const kBravo = key("k-bravo", { name: "db-prod-key", fingerprint: "SHA256:yyyy" });
  const kCharlie = key("k-charlie", { name: "db", fingerprint: "SHA256:xxxx" });
  const kNomatch = key("k-nomatch", { name: "nothing", fingerprint: "SHA256:wwww" });
  const kRows: KeyRow[] = [kAlpha, kBravo, kCharlie, kNomatch].map((k) => ({
    key: k,
    identityCount: 0,
  }));
  check(
    "rankKeys: exact beats prefix beats word-boundary; nomatch dropped",
    rankKeys(kRows, "db").map((r) => r.key.id),
    ["k-charlie", "k-bravo"],
  );
  check("rankKeys empty query returns every row in default order", rankKeys(kRows, "").length, 4);
}

// --- 6. The comparator is total --------------------------------------------

console.log("\n[6] two rows equal on name break the tie on id, both input orders");
{
  const a: IdentityRow = {
    identity: identity("i-b", { name: "same" }),
    keyName: undefined,
    hostCount: 0,
    missingSecret: false,
  };
  const b: IdentityRow = {
    identity: identity("i-a", { name: "same" }),
    keyName: undefined,
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

  const ka: KeyRow = { key: key("k-b", { name: "same" }), identityCount: 0 };
  const kb: KeyRow = { key: key("k-a", { name: "same" }), identityCount: 0 };
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
    hostCount: 0,
    missingSecret: false,
  };
  check(
    "lowercase name matches a mixed-case query",
    rankIdentities([lowerName], "ProdBox").map((r) => r.identity.id),
    ["i-2"],
  );

  const mixedKey: KeyRow = { key: key("k-1", { name: "DeployKey" }), identityCount: 0 };
  check(
    "rankKeys: mixed-case name matches a lowercase query",
    rankKeys([mixedKey], "deploykey").map((r) => r.key.id),
    ["k-1"],
  );
  const lowerKey: KeyRow = { key: key("k-2", { name: "deploykey" }), identityCount: 0 };
  check(
    "rankKeys: lowercase name matches a mixed-case query",
    rankKeys([lowerKey], "DeployKey").map((r) => r.key.id),
    ["k-2"],
  );
}

// --- 8. rankKeys fingerprint tier --------------------------------------------

console.log("\n[8] fingerprint tier: full SHA256 form and the bare digest both match");
{
  const row: KeyRow = { key: key("k-1", { fingerprint: "SHA256:AbCdEf" }), identityCount: 0 };
  check(
    "query 'sha256:abc' matches at tier 3",
    rankKeys([row], "sha256:abc").map((r) => r.key.id),
    ["k-1"],
  );
  check(
    "query 'abcdef' (after the prefix) also matches at tier 3",
    rankKeys([row], "abcdef").map((r) => r.key.id),
    ["k-1"],
  );
}

// --- 9. Purity: source text, over the raw file, not just reachable code -----

console.log("\n[9] purity: neither file imports the store, Tauri, React or a secret call");
{
  const deriveSrc = readFileSync(join(root, "src/modules/vault/page/derive.ts"), "utf8");
  const refsSrc = readFileSync(join(root, "src/modules/vault/refs.ts"), "utf8");
  const forbidden = [
    "@tauri-apps",
    'from "react"',
    "../store",
    "../adapters",
    "../resolve",
    "secrets_get",
    "getHostSshSecrets",
  ];
  for (const needle of forbidden) {
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
