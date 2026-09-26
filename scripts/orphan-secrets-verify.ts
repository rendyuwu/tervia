/**
 * Self-check for the unreferenced-keychain-entry sweep.
 * Run: `npx tsx scripts/orphan-secrets-verify.ts`.
 *
 * `scanOrphanSecrets` is the first thing in this app that decides a stored
 * secret is unreferenced, and the consequence of getting it wrong is not a
 * cosmetic list: the user is offered a delete button beside every entry it
 * names. Two mistakes cost a private key each, and neither is visible in a diff.
 *
 * The first is deriving the known set from the `has*` presence flags instead of
 * from the ids and the full field lists. A record claiming no password while an
 * account holds one is a stale flag - which is exactly what a restore leaves
 * behind - and deleting on that mismatch destroys a secret the record can still
 * be corrected to use.
 *
 * The second is scanning at all when a store file could not be read. The known
 * set then comes back empty, every stored secret looks unreferenced, and the
 * sweep offers to delete the user's entire keychain. That branch is asserted on
 * the CALL LOG and not just the verdict, because "returned off" and "returned
 * off without looking" are different guarantees.
 */
import type { Host } from "../src/modules/hosts/types";
import type { SecretEntry } from "../src/modules/vault/adapters";
import {
  deleteOrphanSecrets,
  scanOrphanSecrets,
  type OrphanSecretsIo,
  type StoreFileVerdict,
} from "../src/modules/vault/orphans";
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

const OK: StoreFileVerdict = { found: "ok", recovered: false };

/** An SSH row owning all three of its accounts. */
function sshHost(id: string, flags: { hasPassword?: boolean } = {}): Host {
  return {
    id,
    name: id,
    host: "10.0.0.1",
    port: 22,
    protocol: "ssh",
    credential: {
      kind: "inline",
      hostId: id,
      user: "root",
      authMode: "password",
      hasPassword: flags.hasPassword ?? true,
      hasPrivateKey: true,
      hasKeyPassphrase: true,
    },
  };
}

/** An RDP row, which owns `password` ALONE. Present in every fixture below so
 *  the union of both field lists in `knownAccounts` stays guarded: dropping the
 *  RDP half would still pass every other check here. */
function rdpHost(id: string): Host {
  return {
    id,
    name: id,
    host: "10.0.0.2",
    port: 3389,
    protocol: "rdp",
    desktopWidth: 1920,
    desktopHeight: 1080,
    sizeMode: "preset",
    credential: { kind: "inline", hostId: id, username: "admin", hasPassword: true },
  };
}

const identity: VaultIdentity = {
  id: "i-1",
  name: "root @ prod",
  username: "root",
  authMode: "password",
  hasPassword: true,
};
const key: VaultKey = {
  id: "k-1",
  name: "id_ed25519",
  hasPrivateKey: true,
  hasPassphrase: true,
};

type Harness = {
  io: OrphanSecretsIo;
  /** Every service `list` was asked about, in order. */
  listed: string[];
  /** Every account `delete` was asked to clear, as `service::account`. */
  deleted: string[];
};

/**
 * A keychain as a plain map of service to accounts, plus the call log.
 *
 * `rejects` names services whose `list` fails, and `deleteRejects` the accounts
 * whose delete does - both by exact string, so a check cannot pass by failing
 * everything.
 */
function harness(
  stored: Record<string, string[]>,
  opts: { rejects?: string[]; deleteRejects?: string[] } = {},
): Harness {
  const listed: string[] = [];
  const deleted: string[] = [];
  return {
    listed,
    deleted,
    io: {
      list: async (service) => {
        listed.push(service);
        if (opts.rejects?.includes(service)) throw new Error("keychain is locked");
        return stored[service] ?? [];
      },
      delete: async (service, account) => {
        const name = `${service}::${account}`;
        if (opts.deleteRejects?.includes(name)) throw new Error("access denied");
        deleted.push(name);
      },
    },
  };
}

/** The scan, with both files readable and the standard vault records. */
async function scan(
  h: Harness,
  hosts: Host[],
  files: { hosts?: StoreFileVerdict; vault?: StoreFileVerdict } = {},
) {
  return scanOrphanSecrets({
    hosts: { rows: hosts, file: files.hosts ?? OK },
    vault: { identities: [identity], keys: [key], file: files.vault ?? OK },
    io: h.io,
  });
}

/** `service::account` for every orphan, sorted, so a check reads as a set. */
const names = (orphans: SecretEntry[]): string[] =>
  orphans.map((o) => `${o.service}::${o.account}`).sort();

console.log("[known] an account every record accounts for is not an orphan");
// Both protocols and both vault record kinds at once: an SSH row with its three
// accounts, an RDP row with its one, the identity's password and the key's pair.
const accounted = harness({
  "tervia-hosts": ["h-1::password", "h-1::privateKey", "h-1::keyPassphrase", "h-2::password"],
  "tervia-vault": ["i-1::password", "k-1::privateKey", "k-1::passphrase"],
});
const clean = await scan(accounted, [sshHost("h-1"), rdpHost("h-2")]);
check("nothing is reported", [clean.kind, clean.kind === "ok" && clean.orphans.length], ["ok", 0]);
check("and no service failed", clean.kind === "ok" && clean.failed, []);

console.log("\n[orphan] an account no record names is reported, with its full field");
const stray = harness({
  "tervia-hosts": ["h-1::password", "h-gone::privateKey"],
  "tervia-vault": ["i-1::password"],
});
const found = await scan(stray, [sshHost("h-1")]);
check(
  "the orphan carries its service and its whole `<id>::<field>` account",
  found.kind === "ok" && found.orphans,
  [{ service: "tervia-hosts", account: "h-gone::privateKey" }],
);

console.log("\n[flags] a stale presence flag is NOT an orphan");
// The record says it has no password; the account exists. That is the restore
// case, and the account is still the one this record would be corrected to use.
const stale = harness({
  "tervia-hosts": ["h-1::password", "h-1::privateKey", "h-1::keyPassphrase"],
  "tervia-vault": [],
});
const kept = await scan(stale, [sshHost("h-1", { hasPassword: false })]);
check("the account is left alone", kept.kind === "ok" && kept.orphans, []);

console.log("\n[legacy] every account under the two retired services is an orphan");
const legacy = harness({
  "tervia-ssh": ["old-1::password", "old-1::privateKey"],
  "tervia-rdp": ["old-2::password"],
});
const retired = await scan(legacy, [sshHost("h-1")]);
check("all three are named", retired.kind === "ok" && names(retired.orphans), [
  "tervia-rdp::old-2::password",
  "tervia-ssh::old-1::password",
  "tervia-ssh::old-1::privateKey",
]);

console.log("\n[scope] exactly the four services this app writes, and never sync's");
// `tervia-sync` holds fixed account names rather than `<id>::<field>`, so there
// is no id to subtract and a configured passphrase would read as an orphan.
check("the services listed", legacy.listed, [
  "tervia-hosts",
  "tervia-vault",
  "tervia-ssh",
  "tervia-rdp",
]);

console.log("\n[refusal] an unreadable store file stops the sweep BEFORE it looks");
const blind = harness({ "tervia-hosts": ["h-1::password"] });
const off = await scan(blind, [], { hosts: { found: "unreadable", recovered: false } });
check("the scan is off", off.kind, "off");
check("and NOTHING was listed, so nothing could be offered for deletion", blind.listed, []);
// `missing` is the other side of that line: the contents are known - there are
// none - and it is exactly what a rolled-back restore leaves behind.
const gone = harness({ "tervia-hosts": ["h-1::password"], "tervia-vault": [] });
const swept = await scan(gone, [], { hosts: { found: "missing", recovered: false } });
check("a missing hosts file is scanned, not refused", swept.kind, "ok");
check("and its stored account is the orphan", swept.kind === "ok" && names(swept.orphans), [
  "tervia-hosts::h-1::password",
]);
// A service that will not list is reported without taking the others down.
const partial = harness(
  { "tervia-hosts": ["h-9::password"], "tervia-vault": [] },
  { rejects: ["tervia-vault"] },
);
const mixed = await scan(partial, []);
check("the failing service is named", mixed.kind === "ok" && mixed.failed, [
  "tervia-vault: keychain is locked",
]);
check("and the others still reported", mixed.kind === "ok" && names(mixed.orphans), [
  "tervia-hosts::h-9::password",
]);

console.log("\n[delete] a refusal in the middle does not abandon the rest");
const purge = harness({}, { deleteRejects: ["tervia-hosts::b::password"] });
const result = await deleteOrphanSecrets(
  [
    { service: "tervia-hosts", account: "a::password" },
    { service: "tervia-hosts", account: "b::password" },
    { service: "tervia-hosts", account: "c::password" },
  ],
  purge.io,
);
check("the entries either side of the refusal are cleared", result.cleared, [
  "tervia-hosts::a::password",
  "tervia-hosts::c::password",
]);
check("the refusal is named", result.failed, ["tervia-hosts::b::password: access denied"]);
check("and the third delete was actually issued", purge.deleted, [
  "tervia-hosts::a::password",
  "tervia-hosts::c::password",
]);

console.log(failed === 0 ? "\nAll orphan-secrets checks passed." : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
