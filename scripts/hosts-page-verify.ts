/**
 * Self-check for everything the Hosts page derives (research §5.2, §5.5).
 * Run: `pnpm verify` (or `npx tsx scripts/hosts-page-verify.ts` to iterate).
 *
 * `page/derive.ts` is pure - no React, no store, no Tauri - which is the only
 * reason this file can exist. The correctness worth checking is not the layout,
 * it is which pip a row shows and what the chips add up to, and the two most
 * expensive answers to get wrong are:
 *
 *   A missing-secret pip that reads "fine". Every branch below comes off the
 *   record's `has*` flags, never a keychain read (§5.2), so a branch that
 *   forgets to ask is silently reassuring about a row that cannot connect - and
 *   the failure only surfaces at the handshake, talking about credentials the
 *   user believes they entered. The two states that must NOT read as fine are an
 *   identity id resolving to nothing, and an identity naming a key whose private
 *   half is gone.
 *
 *   A group count that disagrees with its own chip. A host naming a group that
 *   no longer exists has to land somewhere, and `total` has to keep counting it.
 */
import {
  filterAndRank,
  groupCounts,
  hostUsername,
  identityName,
  matchesGroupFilter,
  missingSecret,
  searchRows,
  UNKNOWN_IDENTITY_LABEL,
  type VaultSnapshot,
} from "../src/modules/hosts/page/derive";
import type { HostGroup, RdpHost, SshHost } from "../src/modules/hosts/types";
import type {
  RdpInlineCredentials,
  SshInlineCredentials,
  VaultIdentity,
  VaultKey,
} from "../src/modules/vault/types";

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
//
// Every builder returns a FRESH record. Nothing below holds a baseline as a live
// object and compares a later mutation against it - one of the two ways a
// vacuous check got through earlier in this phase.

const FULL_SSH_INLINE: SshInlineCredentials = {
  kind: "inline",
  hostId: "h-x",
  user: "root",
  authMode: "password",
  hasPassword: true,
  hasPrivateKey: true,
  hasKeyPassphrase: true,
};

function sshInline(
  id: string,
  cred: Partial<SshInlineCredentials> = {},
  groupId?: string,
): SshHost {
  return {
    id,
    name: `ssh ${id}`,
    host: `${id}.internal`,
    port: 22,
    protocol: "ssh",
    groupId,
    credential: { ...FULL_SSH_INLINE, ...cred, hostId: id },
  };
}

function sshBound(id: string, identityId: string, groupId?: string): SshHost {
  return {
    id,
    name: `ssh ${id}`,
    host: `${id}.internal`,
    port: 22,
    protocol: "ssh",
    groupId,
    credential: { kind: "identity", identityId },
  };
}

function rdpInline(
  id: string,
  cred: Partial<RdpInlineCredentials> = {},
  groupId?: string,
): RdpHost {
  return {
    id,
    name: `rdp ${id}`,
    host: `${id}.internal`,
    port: 3389,
    protocol: "rdp",
    groupId,
    desktopWidth: 1920,
    desktopHeight: 1080,
    sizeMode: "preset",
    credential: {
      kind: "inline",
      hostId: id,
      username: "administrator",
      hasPassword: true,
      ...cred,
    },
  };
}

function rdpBound(id: string, identityId: string, groupId?: string): RdpHost {
  return {
    id,
    name: `rdp ${id}`,
    host: `${id}.internal`,
    port: 3389,
    protocol: "rdp",
    groupId,
    desktopWidth: 1920,
    desktopHeight: 1080,
    sizeMode: "preset",
    credential: { kind: "identity", identityId },
  };
}

function identity(id: string, over: Partial<VaultIdentity> = {}): VaultIdentity {
  return {
    id,
    name: `Identity ${id}`,
    username: "svc",
    authMode: "password",
    hasPassword: true,
    ...over,
  };
}

function key(id: string, over: Partial<VaultKey> = {}): VaultKey {
  return { id, name: `Key ${id}`, hasPrivateKey: true, hasPassphrase: false, ...over };
}

function vault(identities: VaultIdentity[] = [], keys: VaultKey[] = []): VaultSnapshot {
  return {
    identities: new Map(identities.map((i) => [i.id, i])),
    keys: new Map(keys.map((k) => [k.id, k])),
  };
}

const NO_VAULT = vault();

function group(id: string, name: string, order?: number): HostGroup {
  return { id, name, order };
}

// --- missingSecret: SSH, inline -----------------------------------------

console.log("[missingSecret] SSH inline, one branch per auth mode");
check(
  "password auth with a stored password is fine",
  missingSecret(sshInline("h-1", { authMode: "password", hasPassword: true }), NO_VAULT),
  false,
);
check(
  "password auth with no stored password is missing",
  missingSecret(sshInline("h-2", { authMode: "password", hasPassword: false }), NO_VAULT),
  true,
);
check(
  "key auth with a stored private key is fine",
  missingSecret(sshInline("h-3", { authMode: "key", hasPrivateKey: true }), NO_VAULT),
  false,
);
check(
  "key auth with no stored private key is missing",
  missingSecret(sshInline("h-4", { authMode: "key", hasPrivateKey: false }), NO_VAULT),
  true,
);
// The pip must not fire here even with every flag off: the local ssh-agent holds
// the key and signs the handshake, so there is nothing for this record to be
// missing, and a warning would be telling the user to enter something that must
// not be entered.
check(
  "agent auth is never missing, even with every flag false",
  missingSecret(
    sshInline("h-5", {
      authMode: "agent",
      hasPassword: false,
      hasPrivateKey: false,
      hasKeyPassphrase: false,
    }),
    NO_VAULT,
  ),
  false,
);
// The mode decides which flag is consulted, and only that one. A password-auth
// row with a key and no password is missing; the reverse is too.
check(
  "password auth ignores hasPrivateKey",
  missingSecret(
    sshInline("h-6", { authMode: "password", hasPassword: false, hasPrivateKey: true }),
    NO_VAULT,
  ),
  true,
);
check(
  "key auth ignores hasPassword",
  missingSecret(
    sshInline("h-7", { authMode: "key", hasPassword: true, hasPrivateKey: false }),
    NO_VAULT,
  ),
  true,
);
// A key passphrase is optional - plenty of keys have none - so its absence is
// not a missing secret.
check(
  "key auth with no passphrase is still fine",
  missingSecret(
    sshInline("h-8", { authMode: "key", hasPrivateKey: true, hasKeyPassphrase: false }),
    NO_VAULT,
  ),
  false,
);

// --- missingSecret: RDP, inline -----------------------------------------

console.log("\n[missingSecret] RDP inline asks about the password and nothing else");
check("a stored password is fine", missingSecret(rdpInline("h-9"), NO_VAULT), false);
check(
  "no stored password is missing",
  missingSecret(rdpInline("h-10", { hasPassword: false }), NO_VAULT),
  true,
);

// --- missingSecret: identity-bound --------------------------------------

console.log("\n[missingSecret] identity-bound asks the same question of the IDENTITY");
{
  const withPassword = vault([identity("i-1", { authMode: "password", hasPassword: true })]);
  const withoutPassword = vault([identity("i-1", { authMode: "password", hasPassword: false })]);
  check(
    "SSH bound to a password identity that has one is fine",
    missingSecret(sshBound("h-11", "i-1"), withPassword),
    false,
  );
  check(
    "SSH bound to a password identity with no password is missing",
    missingSecret(sshBound("h-12", "i-1"), withoutPassword),
    true,
  );
  check(
    "SSH bound to an agent identity is never missing",
    missingSecret(
      sshBound("h-13", "i-1"),
      vault([identity("i-1", { authMode: "agent", hasPassword: false })]),
    ),
    false,
  );
}
{
  // The one an inline-only rule would miss: the identity itself looks complete,
  // and the key it names is the thing that is gone.
  const brokenKey = vault(
    [identity("i-1", { authMode: "key", keyId: "k-1" })],
    [key("k-1", { hasPrivateKey: false })],
  );
  const goodKey = vault(
    [identity("i-1", { authMode: "key", keyId: "k-1" })],
    [key("k-1", { hasPrivateKey: true })],
  );
  check(
    "key identity naming a key that has its private half is fine",
    missingSecret(sshBound("h-14", "i-1"), goodKey),
    false,
  );
  check(
    "key identity naming a key with hasPrivateKey false is missing",
    missingSecret(sshBound("h-15", "i-1"), brokenKey),
    true,
  );
  check(
    "key identity naming a key that is not in the vault at all is missing",
    missingSecret(
      sshBound("h-16", "i-1"),
      vault([identity("i-1", { authMode: "key", keyId: "k-1" })]),
    ),
    true,
  );
  check(
    "key identity naming no key at all is missing",
    missingSecret(sshBound("h-17", "i-1"), vault([identity("i-1", { authMode: "key" })])),
    true,
  );
  // hasPassword on a key identity is irrelevant over SSH: key auth reads the
  // key, so a stored password cannot stand in for the missing one.
  check(
    "a key identity's stored password does not cover a missing key",
    missingSecret(
      sshBound("h-18", "i-1"),
      vault(
        [identity("i-1", { authMode: "key", keyId: "k-1", hasPassword: true })],
        [key("k-1", { hasPrivateKey: false })],
      ),
    ),
    true,
  );
}
{
  // An id that resolves to nothing is its own missing state. `resolveSshAuth`
  // and `resolveRdpAuth` both throw "identity … no longer exists" here, so the
  // row cannot connect at all - it must never read as fine.
  const empty = NO_VAULT;
  const other = vault([identity("i-other")]);
  check(
    "SSH naming an identity in an empty vault is missing",
    missingSecret(sshBound("h-19", "i-gone"), empty),
    true,
  );
  check(
    "SSH naming an identity the vault does not have is missing",
    missingSecret(sshBound("h-20", "i-gone"), other),
    true,
  );
  check(
    "RDP naming an identity the vault does not have is missing",
    missingSecret(rdpBound("h-21", "i-gone"), other),
    true,
  );
}
{
  // resolveRdpAuth deliberately does NOT check authMode: hasPassword is
  // independent of it, so one identity being a key over SSH and the same
  // account's password over RDP is a legitimate row - that is what sharing an
  // identity across protocols is for.
  const keyIdentityWithPassword = vault(
    [identity("i-1", { authMode: "key", keyId: "k-1", hasPassword: true })],
    [key("k-1")],
  );
  const keyIdentityNoPassword = vault(
    [identity("i-1", { authMode: "key", keyId: "k-1", hasPassword: false })],
    [key("k-1")],
  );
  check(
    "RDP bound to a KEY identity that holds a password is fine",
    missingSecret(rdpBound("h-22", "i-1"), keyIdentityWithPassword),
    false,
  );
  check(
    "RDP bound to a key identity with no password is missing",
    missingSecret(rdpBound("h-23", "i-1"), keyIdentityNoPassword),
    true,
  );
  // The mirror of the above: over RDP the key is irrelevant, so a broken key
  // must not make an otherwise-usable password row look broken.
  check(
    "RDP ignores a broken key when the identity holds a password",
    missingSecret(
      rdpBound("h-24", "i-1"),
      vault(
        [identity("i-1", { authMode: "key", keyId: "k-1", hasPassword: true })],
        [key("k-1", { hasPrivateKey: false })],
      ),
    ),
    false,
  );
}

// --- identityName -------------------------------------------------------

console.log("\n[identityName] inline, resolved, and dangling");
check(
  "an inline SSH binding has no identity name",
  identityName(sshInline("h-25"), NO_VAULT.identities),
  undefined,
);
check(
  "an inline RDP binding has no identity name",
  identityName(rdpInline("h-26"), NO_VAULT.identities),
  undefined,
);
{
  const v = vault([identity("i-1", { name: "root @ prod" })]);
  check(
    "a resolved binding reports the identity's name",
    identityName(sshBound("h-27", "i-1"), v.identities),
    "root @ prod",
  );
  check(
    "a resolved RDP binding reports it too",
    identityName(rdpBound("h-28", "i-1"), v.identities),
    "root @ prod",
  );
  // `undefined` already means "inline" here, so a dangling reference must not
  // return it - the card would render a host that owns its own credential,
  // which is the one thing it definitely is not.
  check(
    "a dangling binding reports the unknown label, not undefined",
    identityName(sshBound("h-29", "i-gone"), v.identities),
    UNKNOWN_IDENTITY_LABEL,
  );
  // The property that matters, stated as a comparison rather than as
  // `LABEL !== undefined` - which is true of any string constant and would have
  // passed against every possible implementation.
  ok(
    "a dangling binding does not read the same as an inline one",
    identityName(sshBound("h-29b", "i-gone"), v.identities) !==
      identityName(sshInline("h-29c"), v.identities),
  );
}

// --- hostUsername -------------------------------------------------------

console.log("\n[hostUsername] wherever the username actually lives");
check(
  "SSH inline reads credential.user",
  hostUsername(sshInline("h-30", { user: "deploy" }), NO_VAULT.identities),
  "deploy",
);
check(
  "RDP inline reads credential.username",
  hostUsername(rdpInline("h-31", { username: "admin" }), NO_VAULT.identities),
  "admin",
);
check(
  "a bound host reads the identity's username",
  hostUsername(
    sshBound("h-32", "i-1"),
    vault([identity("i-1", { username: "ansible" })]).identities,
  ),
  "ansible",
);
check(
  "a dangling binding has no username to report",
  hostUsername(sshBound("h-33", "i-gone"), NO_VAULT.identities),
  undefined,
);

// --- searchRows ---------------------------------------------------------

console.log("\n[searchRows] the two fields rankHosts cannot work out for itself");
{
  const groups = [group("g-1", "Production")];
  const v = vault([identity("i-1", { username: "ansible" })]);
  const rows = searchRows(
    [
      sshInline("h-34", { user: "deploy" }, "g-1"),
      sshBound("h-35", "i-1", "g-gone"),
      sshInline("h-36"),
    ],
    groups,
    v,
  );
  check(
    "usernames come from the host or the identity",
    rows.map((r) => r.username),
    ["deploy", "ansible", "root"],
  );
  check(
    "a group name resolves, and a dangling groupId resolves to nothing",
    rows.map((r) => r.groupName),
    ["Production", undefined, undefined],
  );
}

// --- groupCounts --------------------------------------------------------

console.log("\n[groupCounts] every host lands somewhere, and total keeps counting it");
{
  const groups = [
    group("g-1", "Production", 0),
    group("g-2", "Staging", 1),
    group("g-3", "Empty", 2),
  ];
  const hosts = [
    sshInline("h-37", {}, "g-1"),
    sshInline("h-38", {}, "g-1"),
    rdpInline("h-39", {}, "g-2"),
    sshInline("h-40"), // genuinely ungrouped
    // Names a group that is not in the list: deleted in another window between
    // two renders here. It has to count as ungrouped and stay in `total`.
    rdpInline("h-41", {}, "g-deleted"),
  ];
  const counts = groupCounts(hosts, groups);
  check("total counts every host", counts.total, 5);
  check("ungrouped counts the genuinely ungrouped AND the dangling one", counts.ungrouped, 2);
  check("byGroup counts per existing group", counts.byGroup, { "g-1": 2, "g-2": 1, "g-3": 0 });
  ok("an empty group gets its own zero rather than a missing key", "g-3" in counts.byGroup);
  ok("no key is created for a group that does not exist", !("g-deleted" in counts.byGroup));
  // The invariant the chips depend on. Without the dangling-groupId fallback the
  // chips sum to less than All and that row is reachable from no chip at all.
  const summed = Object.values(counts.byGroup).reduce((a, b) => a + b, 0);
  check("total === ungrouped + sum(byGroup)", counts.ungrouped + summed, counts.total);
}
check("no hosts and no groups is all zeroes", groupCounts([], []), {
  total: 0,
  ungrouped: 0,
  byGroup: {},
});

// --- matchesGroupFilter -------------------------------------------------

console.log("\n[matchesGroupFilter] agrees with the counts, dangling row included");
{
  const known = new Set(["g-1"]);
  const inGroup = sshInline("h-42", {}, "g-1");
  const ungrouped = sshInline("h-43");
  const dangling = sshInline("h-44", {}, "g-deleted");
  check(
    "All keeps everything",
    [inGroup, ungrouped, dangling].map((h) => matchesGroupFilter(h, { kind: "all" }, known)),
    [true, true, true],
  );
  check(
    "Ungrouped keeps the ungrouped and the dangling, not the grouped",
    [inGroup, ungrouped, dangling].map((h) => matchesGroupFilter(h, { kind: "ungrouped" }, known)),
    [false, true, true],
  );
  check(
    "a group chip keeps only its own members",
    [inGroup, ungrouped, dangling].map((h) =>
      matchesGroupFilter(h, { kind: "group", groupId: "g-1" }, known),
    ),
    [true, false, false],
  );
}

// --- filterAndRank ------------------------------------------------------
//
// Protocol, then group, then ranking. Note what this can and cannot pin: a
// predicate and a stable total sort COMMUTE, so no output can distinguish
// filter-then-rank from rank-then-filter. What it does pin is that all three
// run, that ranking is what orders the survivors, and that the order does not
// depend on the input order - which is what a regression actually breaks (a
// top-N slice taken before a filter, or a filter dropped entirely).

console.log("\n[filterAndRank] all three filters run, and ranking orders what survives");
{
  const groups = [group("g-1", "Production")];
  const v = vault([identity("i-1", { username: "ansible" })]);
  const hosts = [
    sshInline("h-45", {}, "g-1"),
    rdpInline("h-46", {}, "g-1"),
    sshInline("h-47"),
    rdpInline("h-48"),
  ];
  const rows = searchRows(hosts, groups, v);
  const ids = (rs: ReturnType<typeof filterAndRank>) => rs.map((r) => r.host.id).sort();

  check(
    "protocol=ssh drops every RDP row",
    ids(
      filterAndRank({
        rows,
        protocol: "ssh",
        group: { kind: "all" },
        knownGroupIds: new Set(["g-1"]),
        query: "",
      }),
    ),
    ["h-45", "h-47"],
  );
  check(
    "protocol=rdp drops every SSH row",
    ids(
      filterAndRank({
        rows,
        protocol: "rdp",
        group: { kind: "all" },
        knownGroupIds: new Set(["g-1"]),
        query: "",
      }),
    ),
    ["h-46", "h-48"],
  );
  check(
    "protocol and group compose",
    ids(
      filterAndRank({
        rows,
        protocol: "ssh",
        group: { kind: "group", groupId: "g-1" },
        knownGroupIds: new Set(["g-1"]),
        query: "",
      }),
    ),
    ["h-45"],
  );
  check(
    "a query narrows what the two filters left",
    ids(
      filterAndRank({
        rows,
        protocol: "all",
        group: { kind: "all" },
        knownGroupIds: new Set(["g-1"]),
        query: "h-45",
      }),
    ),
    ["h-45"],
  );
  check(
    "a query matching nothing leaves nothing",
    filterAndRank({
      rows,
      protocol: "all",
      group: { kind: "all" },
      knownGroupIds: new Set(["g-1"]),
      query: "zzzz",
    }).length,
    0,
  );
}
{
  // Ranking is what decides the order, not the input order. `exact` matches the
  // query on its name exactly (tier 1), `prefix` by name prefix (tier 2),
  // `buried` only as a substring (tier 5).
  const exact: SshHost = { ...sshInline("h-49"), name: "db" };
  const prefix: SshHost = { ...sshInline("h-50"), name: "db-prod" };
  const buried: SshHost = { ...sshInline("h-51"), name: "adbox" };
  const known = new Set<string>();
  const order = (hosts: SshHost[]) =>
    filterAndRank({
      rows: searchRows(hosts, [], NO_VAULT),
      protocol: "all",
      group: { kind: "all" },
      knownGroupIds: known,
      query: "db",
    }).map((r) => r.host.name);
  check("output is ranked, not input-ordered", order([buried, prefix, exact]), [
    "db",
    "db-prod",
    "adbox",
  ]);
  check("a different input order ranks identically", order([exact, buried, prefix]), [
    "db",
    "db-prod",
    "adbox",
  ]);
}

// --- gate: break the implementation and watch each check actually fail --
//
// Handoff §5.12: a check that has not been watched fail is not a check. Every
// check above was run against a deliberately broken `derive.ts` before being
// trusted - the mutation table is in the report sent alongside this file, not
// here, because it is a record of a manual pass rather than something the suite
// can assert.

console.log(failed === 0 ? "\nAll hosts-page checks passed." : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
