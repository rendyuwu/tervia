/**
 * Self-check for 6e wave 4 step 5: moving a host's credentials into the vault
 * and back (`src/modules/hosts/credentialMove.ts`), and the credential
 * picker's pure vocabulary (`src/modules/hosts/editor/credentialChoice.ts`).
 * Run: `pnpm verify credential-move` (or `npx tsx
 * scripts/credential-move-verify.ts` to iterate).
 *
 * ONE in-memory `SecretsIo` shared by a REAL `createHostsStore` and a REAL
 * `createVaultStore` - the harness shapes already proven in
 * `hosts-store-verify.ts:222-366` and `vault-resolve-verify.ts:144-238`,
 * merged here because this is the one module that spans both stores. The copy
 * is real, against a real `kept` map: a stub answering `true` would make every
 * flag check below vacuous.
 *
 * Every property here is one whose failure is SILENT, which is why it is
 * pinned before any UI drives this path:
 *
 * 1. `convertMoves` / `detachMoves` ARE PURE ACCOUNT MAPS. Every field they
 *    name is a keychain account `copyMoves` will actually touch; a field left
 *    out simply never travels, silently.
 *
 * 2. CONVERT COPIES WHAT THE RECORD OWNS, NOT WHAT THE NEW MODE USES. A host on
 *    password auth can still store a stray private key; `inlineNeedsKey` reads
 *    the credential's own flags, never the auth mode a caller is about to pick
 *    for the new identity.
 *
 * 3. A COPY THAT FOUND NOTHING SETS NO FLAG. `secrets.copy` reports `false` for
 *    an empty source, and that must reach the new record as an ABSENT secret
 *    field, not a written empty string - the same rule `hosts-store-verify.ts`
 *    pins for `duplicateHost`.
 *
 * 4. ORDERING (research §5.3): every copy happens before the host record is
 *    rewritten, and the host's own accounts are released only AFTER that
 *    rewrite. A crash between the two must cost at most an orphan account,
 *    never a key that existed nowhere else. The corollary, and the reason
 *    group 9 exists: when the host write REFUSES, the vault records that
 *    ordering already wrote have to be taken back - records AND accounts, or
 *    the failed convert leaves behind exactly the second copy of the credential
 *    it existed to avoid.
 *
 * 5. CONVERT REFUSES A BOUND HOST, AND A KEY-STORING HOST WITH NO KEY NAME. A
 *    bound host owns nothing to move; a host storing key material needs
 *    somewhere in the vault for it to land.
 *
 * 6. CONVERT WRITES ONLY FRESH VAULT IDS. Reusing a seeded or a host's own id
 *    would silently overwrite an unrelated record instead of minting a new one.
 *
 * 7. DETACH TAKES ITS OWN COPY, and a missing identity - or an identity naming
 *    a key that is itself gone - degrades to a WARNING plus an inline record,
 *    never a throw: the host was already unable to connect, and refusing would
 *    leave it that way forever.
 *
 * 8. BIND COPIES NOTHING and releases the host's own accounts - the one
 *    genuinely destructive path in this file, which is the whole reason
 *    `credentialChoice.ts` exists to make the user confirm it first.
 *
 * 9. `credentialChoice.ts` IS PURE VOCABULARY, checked by value: what a picker
 *    selection MEANS against a stored record (or none, in create mode -
 *    amendment A1), and the exact confirmation text for each outcome.
 *
 * 10. THE TWO NEW FILES READ NO SECRET AND CLAIM NO SAFETY. Neither calls
 *     `getAll(`, `secrets_get` or the resolver that would read one back, and
 *     neither claims a keychain buys more than it does - checked over the RAW
 *     source, comments included, because a negative belongs everywhere or it
 *     proves nothing.
 *
 * The store, secrets and event bus are all injectable ports, so all of this
 * runs under plain node with no Tauri runtime and no mocking library.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { createWriteQueue } from "../src/lib/recoveredStore";
import type { HostsStoreIo } from "../src/modules/hosts/adapters";
import {
  bindHostToIdentity,
  convertHostToVault,
  convertMoves,
  detachHostFromVault,
  detachMoves,
  type CredentialMoveDeps,
} from "../src/modules/hosts/credentialMove";
import { createHostsStore } from "../src/modules/hosts/store";
import {
  CREDENTIAL_STAMP_INLINE,
  HOSTS_KEY,
  HOST_GROUPS_KEY,
  HostBindingChangedError,
  type Host,
  type RdpHost,
  type SshHost,
} from "../src/modules/hosts/types";
import {
  CREDENTIAL_CHOICE_INLINE,
  CREDENTIAL_CHOICE_NEW_IDENTITY,
  credentialChangeFor,
  credentialChangeNote,
  hostOwnedSecretNames,
  identityChoice,
  identityIdFromChoice,
} from "../src/modules/hosts/editor/credentialChoice";
import type { SecretsIo, VaultStoreIo } from "../src/modules/vault/adapters";
import { createVaultStore } from "../src/modules/vault/store";
import {
  HOST_KEYRING_SERVICE,
  VAULT_KEYRING_SERVICE,
  type VaultIdentity,
  type VaultKey,
} from "../src/modules/vault/types";

let failed = 0;

/**
 * A canonical rendering of a value, used to compare AND to report, copied from
 * `hosts-store-verify.ts:141-153` rather than reinvented: it drops `undefined`
 * properties (so `{ x: undefined }` and `{}` compare equal, which matters for
 * every optional field on `Host` / `VaultIdentity` / `VaultKey`) and sorts keys
 * (so a spread built in a different order does not fail a check about content).
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
// The merged harness: one `SecretsIo`, a real `createHostsStore` and a real
// `createVaultStore` on their OWN store files (each with its own real write
// queue), so a cross-service copy actually moves a byte between
// `tervia-hosts` and `tervia-vault` rather than two isolated fakes agreeing
// with themselves.
// ---------------------------------------------------------------------------

type SecretCall = {
  op: "getAll" | "set" | "delete" | "copy";
  service: string;
  accounts: string[];
  /** `copy` only - a copy can CROSS services, which is this whole module's job. */
  toService?: string;
};

function harness(
  seed: {
    hosts?: Host[];
    identities?: VaultIdentity[];
    keys?: VaultKey[];
    kept?: Record<string, string>;
  } = {},
) {
  const hostsData: Record<string, unknown> = {
    [HOSTS_KEY]: seed.hosts ?? [],
    [HOST_GROUPS_KEY]: [],
  };
  const vaultData: Record<string, unknown> = {
    identities: seed.identities ?? [],
    keys: seed.keys ?? [],
  };
  const kept = new Map<string, string>(Object.entries(seed.kept ?? {}));
  const calls: SecretCall[] = [];
  /** Keychain calls AND store commits, in one strict order - what group 7's
   *  ordering check is a set of index comparisons over. */
  const trace: string[] = [];

  const hostsIo: HostsStoreIo = {
    async get<T>(key: string): Promise<T | null> {
      return (hostsData[key] as T | undefined) ?? null;
    },
    async set(key: string, value: unknown): Promise<void> {
      hostsData[key] = value;
    },
    async commit(): Promise<void> {
      trace.push("commit:hosts");
    },
    // The REAL queue, so serialization runs through the shipped implementation.
    enqueueWrite: createWriteQueue(),
    async onChanged(): Promise<() => void> {
      return () => {};
    },
    ensureLoaded: async () => null,
    takeRecoveryNotice: () => null,
  };

  const vaultIo: VaultStoreIo = {
    async get<T>(key: string): Promise<T | null> {
      return (vaultData[key] as T | undefined) ?? null;
    },
    async set(key: string, value: unknown): Promise<void> {
      vaultData[key] = value;
    },
    async commit(): Promise<void> {
      trace.push("commit:vault");
    },
    enqueueWrite: createWriteQueue(),
    async onChanged(): Promise<() => void> {
      return () => {};
    },
    ensureLoaded: async () => null,
    takeRecoveryNotice: () => null,
  };

  // A REAL copy against `kept`, deliberately not a stub answering `true` - see
  // the module header and `hosts-store-verify.ts:295-300`. A missing source
  // writes NOTHING, not the empty string.
  const secrets: SecretsIo = {
    async getAll(service, accounts) {
      calls.push({ op: "getAll", service, accounts });
      return accounts.map((a) => kept.get(`${service}::${a}`) ?? null);
    },
    async set(service, account, value) {
      calls.push({ op: "set", service, accounts: [account] });
      trace.push(`set ${service}::${account}`);
      kept.set(`${service}::${account}`, value);
    },
    async delete(service, account) {
      calls.push({ op: "delete", service, accounts: [account] });
      trace.push(`delete ${service}::${account}`);
      kept.delete(`${service}::${account}`);
    },
    async copy(from, to) {
      calls.push({
        op: "copy",
        service: from.service,
        accounts: [from.account, to.account],
        toService: to.service,
      });
      const value = kept.get(`${from.service}::${from.account}`);
      if (value === undefined) {
        trace.push(`copy(miss) ${from.service}::${from.account} -> ${to.service}::${to.account}`);
        return false;
      }
      trace.push(`copy ${from.service}::${from.account} -> ${to.service}::${to.account}`);
      kept.set(`${to.service}::${to.account}`, value);
      return true;
    },
  };

  const hosts = createHostsStore({ store: hostsIo, secrets });
  const vault = createVaultStore({ store: vaultIo, secrets });
  const deps: CredentialMoveDeps = { hosts, vault, secrets };

  return {
    hosts,
    vault,
    deps,
    secrets,
    kept,
    calls,
    trace,
    reads: () => calls.filter((c) => c.op === "getAll"),
    copies: () =>
      calls
        .filter((c) => c.op === "copy")
        .map((c) => `${c.service}::${c.accounts[0]} -> ${c.toService}::${c.accounts[1]}`),
    deletes: () => calls.filter((c) => c.op === "delete").map((c) => c.accounts[0]),
    identities: () => vaultData.identities as VaultIdentity[],
    keys: () => vaultData.keys as VaultKey[],
    hostRows: () => hostsData[HOSTS_KEY] as Host[],
  };
}

const sshHost = (over: Partial<SshHost> = {}): SshHost => ({
  id: over.id ?? "h-1",
  name: "prod",
  host: "prod.example",
  port: 22,
  protocol: "ssh",
  credential: {
    kind: "inline",
    hostId: over.id ?? "h-1",
    user: "root",
    authMode: "password",
    hasPassword: true,
    hasPrivateKey: false,
    hasKeyPassphrase: false,
  },
  ...over,
});

const rdpHost = (over: Partial<RdpHost> = {}): RdpHost => ({
  id: over.id ?? "h-2",
  name: "vps",
  host: "vps.example",
  port: 3389,
  protocol: "rdp",
  credential: { kind: "inline", hostId: over.id ?? "h-2", username: "admin", hasPassword: true },
  desktopWidth: 1600,
  desktopHeight: 900,
  sizeMode: "preset",
  ...over,
});

const identity = (over: Partial<VaultIdentity> = {}): VaultIdentity => ({
  id: "i-1",
  name: "shared",
  username: "root",
  authMode: "password",
  hasPassword: false,
  ...over,
});

const vaultKey = (over: Partial<VaultKey> = {}): VaultKey => ({
  id: "k-1",
  name: "id_ed25519",
  hasPrivateKey: false,
  hasPassphrase: false,
  ...over,
});

const traceIndex = (trace: string[], pred: (e: string) => boolean): number[] =>
  trace.flatMap((e, i) => (pred(e) ? [i] : []));

// ===========================================================================
console.log("\n[1] convertMoves / detachMoves are pure account maps, pinned by literal value");
{
  const host = sshHost({ id: "h-1" });
  check("convertMoves, SSH password only (no key)", convertMoves(host, "i-1", null), [
    {
      field: "password",
      from: { service: "tervia-hosts", account: "h-1::password" },
      to: { service: "tervia-vault", account: "i-1::password" },
    },
  ]);
  check("convertMoves, SSH with a key", convertMoves(host, "i-1", "k-1"), [
    {
      field: "password",
      from: { service: "tervia-hosts", account: "h-1::password" },
      to: { service: "tervia-vault", account: "i-1::password" },
    },
    {
      field: "privateKey",
      from: { service: "tervia-hosts", account: "h-1::privateKey" },
      to: { service: "tervia-vault", account: "k-1::privateKey" },
    },
    {
      field: "keyPassphrase",
      from: { service: "tervia-hosts", account: "h-1::keyPassphrase" },
      to: { service: "tervia-vault", account: "k-1::passphrase" },
    },
  ]);
  check(
    "the keyPassphrase -> passphrase flip, its own named check, literal account strings",
    convertMoves(host, "i-1", "k-1")[2],
    {
      field: "keyPassphrase",
      from: { service: "tervia-hosts", account: "h-1::keyPassphrase" },
      to: { service: "tervia-vault", account: "k-1::passphrase" },
    },
  );

  const rdp = rdpHost({ id: "h-2" });
  check("convertMoves, RDP ignores a key id entirely", convertMoves(rdp, "i-1", "k-1"), [
    {
      field: "password",
      from: { service: "tervia-hosts", account: "h-2::password" },
      to: { service: "tervia-vault", account: "i-1::password" },
    },
  ]);

  const idn = identity({ id: "i-9" });
  check("detachMoves, SSH password only (no key)", detachMoves(host, idn, null), [
    {
      field: "password",
      from: { service: "tervia-vault", account: "i-9::password" },
      to: { service: "tervia-hosts", account: "h-1::password" },
    },
  ]);
  check("detachMoves, SSH with a key", detachMoves(host, idn, "k-2"), [
    {
      field: "password",
      from: { service: "tervia-vault", account: "i-9::password" },
      to: { service: "tervia-hosts", account: "h-1::password" },
    },
    {
      field: "privateKey",
      from: { service: "tervia-vault", account: "k-2::privateKey" },
      to: { service: "tervia-hosts", account: "h-1::privateKey" },
    },
    {
      field: "keyPassphrase",
      from: { service: "tervia-vault", account: "k-2::passphrase" },
      to: { service: "tervia-hosts", account: "h-1::keyPassphrase" },
    },
  ]);
  check(
    "the reverse flip, passphrase -> keyPassphrase, its own named check",
    detachMoves(host, idn, "k-2")[2],
    {
      field: "keyPassphrase",
      from: { service: "tervia-vault", account: "k-2::passphrase" },
      to: { service: "tervia-hosts", account: "h-1::keyPassphrase" },
    },
  );
  check("detachMoves, RDP ignores a key id entirely", detachMoves(rdp, idn, "k-2"), [
    {
      field: "password",
      from: { service: "tervia-vault", account: "i-9::password" },
      to: { service: "tervia-hosts", account: "h-2::password" },
    },
  ]);
}

// ===========================================================================
console.log("\n[2] convert: SSH password auth moves the password and binds the host");
{
  const host = sshHost({ id: "h-1" });
  const h = harness({
    hosts: [host],
    kept: { [`${HOST_KEYRING_SERVICE}::h-1::password`]: "hunter2" },
  });
  const result = await convertHostToVault(
    {
      host,
      identity: {
        name: "shared",
        username: "root",
        domain: "",
        authMode: "password",
        description: "",
      },
      key: null,
    },
    h.deps,
  );
  check(
    "the vault identity holds the host's password",
    h.kept.get(`${VAULT_KEYRING_SERVICE}::${result.identity.id}::password`),
    "hunter2",
  );
  check("the host account is gone", h.kept.has(`${HOST_KEYRING_SERVICE}::h-1::password`), false);
  check("the record's credential is a binding", result.host.credential, {
    kind: "identity",
    identityId: result.identity.id,
  });
  check("identity.hasPassword is true", result.identity.hasPassword, true);
  check("identity.username came from the host's inline arm", result.identity.username, "root");
  check("identity.authMode came from the host's inline arm", result.identity.authMode, "password");
  check("no key record was created", result.key, null);
}

// ===========================================================================
console.log("\n[3] convert: SSH key auth carries the key body and its passphrase");
{
  const host = sshHost({
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
  });
  const h = harness({
    hosts: [host],
    kept: {
      [`${HOST_KEYRING_SERVICE}::h-1::privateKey`]: "PEM-BODY",
      [`${HOST_KEYRING_SERVICE}::h-1::keyPassphrase`]: "s3cr3t",
    },
  });
  const result = await convertHostToVault(
    {
      host,
      identity: { name: "shared", username: "root", domain: "", authMode: "key", description: "" },
      key: { name: "prod key", facts: {} },
    },
    h.deps,
  );
  assert(result.key !== null, "a VaultKey exists");
  if (!result.key) throw new Error("credential-move-verify: expected a key record");
  check(
    "the key's privateKey account holds the host's body",
    h.kept.get(`${VAULT_KEYRING_SERVICE}::${result.key.id}::privateKey`),
    "PEM-BODY",
  );
  check(
    "the key's passphrase account holds the host's passphrase",
    h.kept.get(`${VAULT_KEYRING_SERVICE}::${result.key.id}::passphrase`),
    "s3cr3t",
  );
  check("identity.authMode is key", result.identity.authMode, "key");
  check("identity.keyId is the key's id", result.identity.keyId, result.key.id);
  check(
    "all three host accounts are gone",
    [
      h.kept.has(`${HOST_KEYRING_SERVICE}::h-1::password`),
      h.kept.has(`${HOST_KEYRING_SERVICE}::h-1::privateKey`),
      h.kept.has(`${HOST_KEYRING_SERVICE}::h-1::keyPassphrase`),
    ],
    [false, false, false],
  );
}

// ===========================================================================
console.log(
  "\n[4] convert copies what the RECORD owns, independent of the auth mode picked for the new identity",
);
{
  // A host on PASSWORD auth that also stores a private key - `inlineNeedsKey`
  // reads `hasPrivateKey`/`hasKeyPassphrase` off the credential, never the mode.
  const host = sshHost({
    id: "h-1",
    credential: {
      kind: "inline",
      hostId: "h-1",
      user: "root",
      authMode: "password",
      hasPassword: true,
      hasPrivateKey: true,
      hasKeyPassphrase: false,
    },
  });
  const h = harness({
    hosts: [host],
    kept: {
      [`${HOST_KEYRING_SERVICE}::h-1::password`]: "hunter2",
      [`${HOST_KEYRING_SERVICE}::h-1::privateKey`]: "PEM-BODY",
    },
  });
  const result = await convertHostToVault(
    {
      host,
      identity: {
        name: "shared",
        username: "root",
        domain: "",
        authMode: "password",
        description: "",
      },
      key: { name: "leftover key", facts: {} },
    },
    h.deps,
  );
  assert(result.key !== null, "the leftover key still gets a vault record");
  if (!result.key) throw new Error("credential-move-verify: expected a key record");
  check(
    "the key's body landed at the vault key account, though the mode is password",
    h.kept.get(`${VAULT_KEYRING_SERVICE}::${result.key.id}::privateKey`),
    "PEM-BODY",
  );
  // `identityRecordFrom` normalises `keyId` to the identity's own AUTH MODE
  // (VLT-73): a password-mode identity must not carry a `keyId`, even though a
  // key WAS created and holds real material - the key is a separate record
  // (§1.4), and a non-key identity naming one renders a grey key chip on a row
  // that authenticates with a password.
  check(
    "but the new identity's keyId does not leak it in, since its mode is password",
    result.identity.keyId,
    undefined,
  );
}

// ===========================================================================
console.log("\n[5] convert: RDP moves the password alone and carries the domain");
{
  const host = rdpHost({ id: "h-2" });
  const h = harness({
    hosts: [host],
    kept: { [`${HOST_KEYRING_SERVICE}::h-2::password`]: "s3cret" },
  });
  const result = await convertHostToVault(
    {
      host,
      identity: {
        name: "dc",
        username: "admin",
        domain: "CORP",
        authMode: "password",
        description: "",
      },
      key: null,
    },
    h.deps,
  );
  check(
    "the password landed at the identity account",
    h.kept.get(`${VAULT_KEYRING_SERVICE}::${result.identity.id}::password`),
    "s3cret",
  );
  check("identity.domain is carried", result.identity.domain, "CORP");
  check("no key record is created", result.key, null);
}

// ===========================================================================
console.log("\n[6] a copy that found nothing sets no flag");
{
  // Seeded claiming `hasPassword: true`, with an EMPTY keychain: the copy finds
  // nothing, so the new identity must not claim a password either (§1.5, §5
  // decision 10).
  const host = sshHost({ id: "h-1" });
  const h = harness({ hosts: [host] });
  const result = await convertHostToVault(
    {
      host,
      identity: { name: "x", username: "root", domain: "", authMode: "password", description: "" },
      key: null,
    },
    h.deps,
  );
  check("identity.hasPassword is false", result.identity.hasPassword, false);
  // The copy is still ATTEMPTED - `hosts-store-verify.ts` pins the same thing
  // for a duplicate ("every account was still ATTEMPTED, so none is missed by
  // accident") - it just finds nothing, so nothing actually lands.
  check("the copy was attempted but moved no byte", h.kept.size, 0);
}

// ===========================================================================
console.log(
  "\n[7] ordering: every copy precedes the host store's commit, every host-account delete follows it",
);
{
  const host = sshHost({
    id: "h-1",
    credential: {
      kind: "inline",
      hostId: "h-1",
      user: "root",
      authMode: "key",
      hasPassword: true,
      hasPrivateKey: true,
      hasKeyPassphrase: true,
    },
  });
  const h = harness({
    hosts: [host],
    kept: {
      [`${HOST_KEYRING_SERVICE}::h-1::password`]: "pw",
      [`${HOST_KEYRING_SERVICE}::h-1::privateKey`]: "PEM",
      [`${HOST_KEYRING_SERVICE}::h-1::keyPassphrase`]: "pp",
    },
  });
  const result = await convertHostToVault(
    {
      host,
      identity: { name: "x", username: "root", domain: "", authMode: "key", description: "" },
      key: { name: "k", facts: {} },
    },
    h.deps,
  );
  if (!result.key) throw new Error("credential-move-verify: expected a key record");
  const copyIdx = traceIndex(h.trace, (e) => e.startsWith("copy "));
  const commitHostsIdx = traceIndex(h.trace, (e) => e === "commit:hosts");
  const deleteIdx = traceIndex(h.trace, (e) => e.startsWith(`delete ${HOST_KEYRING_SERVICE}::`));
  assert(copyIdx.length === 3, "three copies happened");
  assert(commitHostsIdx.length === 1, "the host store committed exactly once");
  assert(deleteIdx.length === 3, "three host accounts were deleted");
  assert(Math.max(...copyIdx) < commitHostsIdx[0], "every copy precedes the host store's commit");
  assert(
    Math.min(...deleteIdx) > commitHostsIdx[0],
    "every host-account delete follows the host store's commit",
  );
  // The full trace, pinned - not just its two edges - so a reordering anywhere
  // in the sequence is caught, not only at the two boundaries the asserts above
  // name.
  check("the full trace, in order", h.trace, [
    `copy ${HOST_KEYRING_SERVICE}::h-1::password -> ${VAULT_KEYRING_SERVICE}::${result.identity.id}::password`,
    `copy ${HOST_KEYRING_SERVICE}::h-1::privateKey -> ${VAULT_KEYRING_SERVICE}::${result.key.id}::privateKey`,
    `copy ${HOST_KEYRING_SERVICE}::h-1::keyPassphrase -> ${VAULT_KEYRING_SERVICE}::${result.key.id}::passphrase`,
    "commit:vault",
    "commit:vault",
    "commit:hosts",
    `delete ${HOST_KEYRING_SERVICE}::h-1::password`,
    `delete ${HOST_KEYRING_SERVICE}::h-1::privateKey`,
    `delete ${HOST_KEYRING_SERVICE}::h-1::keyPassphrase`,
  ]);
}

// ===========================================================================
console.log("\n[8] convert refuses a bound host, and a key-storing host with no key name");
{
  const bound = sshHost({ id: "h-1", credential: { kind: "identity", identityId: "i-1" } });
  const h = harness({ hosts: [bound] });
  await rejects(
    "a vault-bound host has nothing to convert",
    () =>
      convertHostToVault(
        {
          host: bound,
          identity: {
            name: "x",
            username: "root",
            domain: "",
            authMode: "password",
            description: "",
          },
          key: null,
        },
        h.deps,
      ),
    ["does not use its own credentials", "nothing to convert"],
  );

  const keyed = sshHost({
    id: "h-2",
    credential: {
      kind: "inline",
      hostId: "h-2",
      user: "root",
      authMode: "key",
      hasPassword: false,
      hasPrivateKey: true,
      hasKeyPassphrase: false,
    },
  });
  const h2 = harness({ hosts: [keyed] });
  await rejects(
    "a host storing a private key refuses convert with no key name",
    () =>
      convertHostToVault(
        {
          host: keyed,
          identity: { name: "x", username: "root", domain: "", authMode: "key", description: "" },
          key: null,
        },
        h2.deps,
      ),
    ["stores a private key", "name for the new key"],
  );
}

// ===========================================================================
console.log("\n[9] a refused convert leaves no vault record, no copy of the secret, and no delete");
{
  // `convertHostToVault` mints the new identity (and key), copies the host's
  // accounts onto them and writes both records BEFORE it calls
  // `hosts.upsertHost` - which is the first call in it that can refuse for any
  // reason beyond its own two pre-checks. That ordering is §4.5's and does not
  // move; what closes the hole is the compensating delete on the failure path.
  // Without it every one of those refusals stranded an identity, a key, and a
  // SECOND copy of the host's secret at vault accounts nothing referenced.
  //
  // So this group asserts the cleanup POSITIVELY, not merely that records are
  // absent. The two pins that carry it: the copies really landed first (an
  // undo of nothing would pass an absence check for free), and the vault
  // accounts are empty AFTERWARDS (a cleanup that dropped the records and left
  // the accounts is exactly the cosmetic version of this fix).
  //
  // Both halves of the refusal are covered, because the stamp path is the
  // near-unreachable one: 9a is the stamp moving underneath a stale editor,
  // 9b is a dangling `proxyJumpId`, which needs no second writer at all and is
  // reachable today by converting a host whose jump target was deleted.
  const keptFor = (h: ReturnType<typeof harness>, service: string): string[] =>
    [...h.kept.entries()]
      .filter(([k]) => k.startsWith(`${service}::`))
      .map(([k, v]) => `${k}=${v}`)
      .sort();
  /** The FIELD of every vault account the cleanup released, so the assertion is
   *  a value pin rather than a count, without naming a freshly minted id. */
  const releasedVaultFields = (h: ReturnType<typeof harness>): string[] =>
    h.calls
      .filter((c) => c.op === "delete" && c.service === VAULT_KEYRING_SERVICE)
      .map((c) => c.accounts[0].split("::")[1])
      .sort();
  const hostDeletes = (h: ReturnType<typeof harness>): string[] =>
    h.calls
      .filter((c) => c.op === "delete" && c.service === HOST_KEYRING_SERVICE)
      .map((c) => c.accounts[0]);
  const landedCopies = (h: ReturnType<typeof harness>): number =>
    traceIndex(h.trace, (e) => e.startsWith(`copy ${HOST_KEYRING_SERVICE}::`)).length;

  // -- 9a: the stamp moved underneath a stale editor -----------------------
  const boundNow = sshHost({
    id: "h-1",
    credential: { kind: "identity", identityId: "i-existing" },
  });
  // Pre-conversion, as an editor loaded it earlier, and storing key material so
  // the refusal has a KEY to strand as well as an identity.
  const staleLoad = sshHost({
    id: "h-1",
    credential: {
      kind: "inline",
      hostId: "h-1",
      user: "root",
      authMode: "key",
      hasPassword: true,
      hasPrivateKey: true,
      hasKeyPassphrase: true,
    },
  });
  const seededIdentity = identity({ id: "i-existing", name: "existing" });
  const hostKept = {
    [`${HOST_KEYRING_SERVICE}::h-1::password`]: "hunter2",
    [`${HOST_KEYRING_SERVICE}::h-1::privateKey`]: "PEM",
    [`${HOST_KEYRING_SERVICE}::h-1::keyPassphrase`]: "pp",
  };
  const h = harness({ hosts: [boundNow], identities: [seededIdentity], kept: hostKept });

  let caught: unknown;
  try {
    await convertHostToVault(
      {
        host: staleLoad,
        identity: { name: "x", username: "root", domain: "", authMode: "key", description: "" },
        key: { name: "k", facts: {} },
      },
      h.deps,
    );
  } catch (e) {
    caught = e;
  }
  assert(
    caught instanceof HostBindingChangedError,
    "the refusal is a HostBindingChangedError, by instance",
  );
  const err = caught as HostBindingChangedError;
  check("hostId, by value", err?.hostId, "h-1");
  check(
    "expected, by value - the stale caller's own stamp",
    err?.expected,
    CREDENTIAL_STAMP_INLINE,
  );
  check("actual, by value - what is really stored now", err?.actual, "identity:i-existing");

  // The undo had something to undo: all three secrets really did land on vault
  // accounts before `upsertHost` refused.
  check("all three secrets landed on vault accounts first", landedCopies(h), 3);
  check("and the cleanup released every one of those accounts", releasedVaultFields(h), [
    "passphrase",
    "password",
    "privateKey",
  ]);

  check("no vault identity survives except the one already there", h.identities(), [
    seededIdentity,
  ]);
  check("no vault key survives", h.keys(), []);
  check("no vault account holds a secret", keptFor(h, VAULT_KEYRING_SERVICE), []);
  check(
    "the host's own accounts are untouched, values included",
    keptFor(h, HOST_KEYRING_SERVICE),
    [
      `${HOST_KEYRING_SERVICE}::h-1::keyPassphrase=pp`,
      `${HOST_KEYRING_SERVICE}::h-1::password=hunter2`,
      `${HOST_KEYRING_SERVICE}::h-1::privateKey=PEM`,
    ],
  );
  check("no host account was deleted", hostDeletes(h), []);
  check("the stored host record is unchanged", h.hostRows(), [boundNow]);
  check(
    "the host store never committed",
    traceIndex(h.trace, (e) => e === "commit:hosts"),
    [],
  );

  // -- 9b: a non-stamp refusal, with no second writer anywhere -------------
  const orphanJump = sshHost({
    id: "h-1",
    proxyJumpId: "h-gone",
    credential: {
      kind: "inline",
      hostId: "h-1",
      user: "root",
      authMode: "key",
      hasPassword: true,
      hasPrivateKey: true,
      hasKeyPassphrase: true,
    },
  });
  const h2 = harness({ hosts: [orphanJump], kept: hostKept });
  await rejects(
    "convert is refused when the host names a jump host that is gone",
    () =>
      convertHostToVault(
        {
          host: orphanJump,
          identity: { name: "x", username: "root", domain: "", authMode: "key", description: "" },
          key: { name: "k", facts: {} },
        },
        h2.deps,
      ),
    ["names a jump host", "does not exist"],
  );
  check("all three secrets landed on vault accounts first", landedCopies(h2), 3);
  check("and the cleanup released every one of those accounts", releasedVaultFields(h2), [
    "passphrase",
    "password",
    "privateKey",
  ]);
  check("no vault identity survives", h2.identities(), []);
  check("no vault key survives", h2.keys(), []);
  check("no vault account holds a secret", keptFor(h2, VAULT_KEYRING_SERVICE), []);
  check(
    "the host's own accounts are untouched, values included",
    keptFor(h2, HOST_KEYRING_SERVICE),
    [
      `${HOST_KEYRING_SERVICE}::h-1::keyPassphrase=pp`,
      `${HOST_KEYRING_SERVICE}::h-1::password=hunter2`,
      `${HOST_KEYRING_SERVICE}::h-1::privateKey=PEM`,
    ],
  );
  check("no host account was deleted", hostDeletes(h2), []);
  check("the stored host record is unchanged", h2.hostRows(), [orphanJump]);
}

// ===========================================================================
console.log("\n[10] convert writes only FRESH vault ids, never reusing a seeded or the host's own");
{
  const seededIdentity = identity({ id: "i-seed", name: "seed identity" });
  const seededKey = vaultKey({ id: "k-seed", name: "seed key" });
  const host = sshHost({
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
  });
  const h = harness({
    hosts: [host],
    identities: [seededIdentity],
    keys: [seededKey],
    kept: { [`${HOST_KEYRING_SERVICE}::h-1::privateKey`]: "PEM" },
  });
  const result = await convertHostToVault(
    {
      host,
      identity: { name: "x", username: "root", domain: "", authMode: "key", description: "" },
      key: { name: "new key", facts: {} },
    },
    h.deps,
  );
  check(
    "the seeded identity is byte-identical afterwards",
    h.identities().find((i) => i.id === "i-seed"),
    seededIdentity,
  );
  check(
    "the seeded key is byte-identical afterwards",
    h.keys().find((k) => k.id === "k-seed"),
    seededKey,
  );
  assert(result.identity.id !== "i-seed", "the new identity id is not the seeded identity's");
  assert(
    result.identity.id !== host.id,
    "the new identity id is not reused from the host's own id",
  );
  assert(
    result.key !== null && result.key.id !== "k-seed",
    "the new key id is not the seeded key's",
  );
  assert(
    result.key !== null && result.key.id !== host.id,
    "the new key id is not reused from the host's own id",
  );
}

// ===========================================================================
console.log("\n[11] detach: SSH key auth copies the identity's and key's values onto the host");
{
  const idn = identity({
    id: "i-1",
    name: "shared",
    username: "root",
    authMode: "key",
    keyId: "k-1",
    hasPassword: true,
  });
  const key = vaultKey({ id: "k-1", name: "shared key", hasPrivateKey: true, hasPassphrase: true });
  const host = sshHost({ id: "h-1", credential: { kind: "identity", identityId: "i-1" } });
  const h = harness({
    hosts: [host],
    identities: [idn],
    keys: [key],
    kept: {
      [`${VAULT_KEYRING_SERVICE}::i-1::password`]: "vault-pw",
      [`${VAULT_KEYRING_SERVICE}::k-1::privateKey`]: "vault-pem",
      [`${VAULT_KEYRING_SERVICE}::k-1::passphrase`]: "vault-pp",
    },
  });
  const result = await detachHostFromVault(
    { host, inline: { user: "root", authMode: "key" } },
    h.deps,
  );
  check("no warning - the identity and its key both resolved", result.warning, undefined);
  check(
    "the three host accounts hold the vault's values, under the host field names",
    [
      h.kept.get(`${HOST_KEYRING_SERVICE}::h-1::password`),
      h.kept.get(`${HOST_KEYRING_SERVICE}::h-1::privateKey`),
      h.kept.get(`${HOST_KEYRING_SERVICE}::h-1::keyPassphrase`),
    ],
    ["vault-pw", "vault-pem", "vault-pp"],
  );
  check(
    "the record's three flags are true exactly where a byte arrived",
    result.host.protocol === "ssh" && result.host.credential.kind === "inline"
      ? [
          result.host.credential.hasPassword,
          result.host.credential.hasPrivateKey,
          result.host.credential.hasKeyPassphrase,
        ]
      : null,
    [true, true, true],
  );
  check(
    "the identity record is byte-identical to before",
    h.identities().find((i) => i.id === "i-1"),
    idn,
  );
  check(
    "the key record is byte-identical to before",
    h.keys().find((k) => k.id === "k-1"),
    key,
  );
}

// ===========================================================================
console.log("\n[12] detach: RDP copies the password alone and does not throw");
{
  // The identity ALSO names a key (an SSH-and-RDP identity is legitimate, per
  // `resolve.ts`'s own comment: `hasPassword` is independent of `authMode`) so
  // that a mutated `detachMoves` emitting key rows for an RDP host has a
  // non-null `keyId` to reach - with no key at all, that branch is unexercised
  // no matter what `detachMoves` does.
  const idn = identity({
    id: "i-2",
    name: "shared rdp",
    username: "administrator",
    domain: "CORP",
    authMode: "key",
    keyId: "k-2",
    hasPassword: true,
  });
  const key = vaultKey({ id: "k-2", name: "shared key", hasPrivateKey: true, hasPassphrase: true });
  const host = rdpHost({ id: "h-2", credential: { kind: "identity", identityId: "i-2" } });
  const h = harness({
    hosts: [host],
    identities: [idn],
    keys: [key],
    kept: {
      [`${VAULT_KEYRING_SERVICE}::i-2::password`]: "rdp-pw",
      [`${VAULT_KEYRING_SERVICE}::k-2::privateKey`]: "vault-pem",
      [`${VAULT_KEYRING_SERVICE}::k-2::passphrase`]: "vault-pp",
    },
  });
  const result = await detachHostFromVault(
    { host, inline: { username: "administrator", domain: "CORP" } },
    h.deps,
  );
  check(
    "the host account holds the identity's password",
    h.kept.get(`${HOST_KEYRING_SERVICE}::h-2::password`),
    "rdp-pw",
  );
  check(
    "no key account was written on the HOST side",
    [...h.kept.keys()].some(
      (k) =>
        k.startsWith(`${HOST_KEYRING_SERVICE}::`) &&
        (k.includes("privateKey") || k.includes("passphrase")),
    ),
    false,
  );
  check("no warning", result.warning, undefined);
}

// ===========================================================================
console.log("\n[13] detach with the identity gone, or with a key the identity names that is gone");
{
  const host = sshHost({ id: "h-1", credential: { kind: "identity", identityId: "i-gone" } });
  const h = harness({ hosts: [host] });
  const result = await detachHostFromVault(
    { host, inline: { user: "root", authMode: "agent" } },
    h.deps,
  );
  check(
    "a missing identity returns a warning naming it, and an inline record",
    [result.warning, result.host.credential.kind],
    ['identity i-gone no longer exists - "prod" now stores its own, empty credentials', "inline"],
  );
  check("nothing was copied", h.copies(), []);

  // Step 3's extension, beyond the plan's own group 13: an identity that DOES
  // exist but names a key that does not. The password still copies and the
  // host still detaches; only the key material is reported missing. Read off
  // the committed `detachHostFromVault`, not from the addendum's paraphrase.
  //
  // Near-unreachable today - `upsertIdentity` refuses a dangling `keyId` and
  // `deleteKey` refuses to orphan one - and reachable only once 6g's import can
  // seed a hand-edited file past both guards.
  const idn = identity({
    id: "i-dangling",
    name: "dangling",
    authMode: "key",
    keyId: "k-gone",
    hasPassword: true,
  });
  const host2 = sshHost({ id: "h-2", credential: { kind: "identity", identityId: "i-dangling" } });
  const h2 = harness({
    hosts: [host2],
    identities: [idn],
    kept: { [`${VAULT_KEYRING_SERVICE}::i-dangling::password`]: "vault-pw" },
  });
  const result2 = await detachHostFromVault(
    { host: host2, inline: { user: "root", authMode: "key" } },
    h2.deps,
  );
  check(
    "the exact warning text, read off the code rather than quoted from a report",
    result2.warning,
    'identity "dangling" names a key that no longer exists - only its password was copied',
  );
  check(
    "the password arrived at the host account",
    h2.kept.get(`${HOST_KEYRING_SERVICE}::h-2::password`),
    "vault-pw",
  );
  check(
    "no key account was written",
    [...h2.kept.keys()].some((k) => k.includes("privateKey") || k.includes("passphrase")),
    false,
  );
  check("the host record is inline", result2.host.credential.kind, "inline");
}

// ===========================================================================
console.log(
  "\n[14] bind copies nothing, and releases the host's own accounts - the destructive path",
);
{
  const host = sshHost({ id: "h-1" });
  const idn = identity({ id: "i-1", name: "shared" });
  const h = harness({
    hosts: [host],
    identities: [idn],
    kept: { [`${HOST_KEYRING_SERVICE}::h-1::password`]: "hunter2" },
  });
  const result = await bindHostToIdentity({ host, identityId: "i-1" }, h.deps);
  check("the copy log is empty", h.copies(), []);
  check(
    "the host's own account is deleted",
    h.kept.has(`${HOST_KEYRING_SERVICE}::h-1::password`),
    false,
  );
  check("the record is bound", result.credential, { kind: "identity", identityId: "i-1" });
}

// ===========================================================================
console.log("\n[15] bind refuses an identity that does not exist");
{
  const host = sshHost({ id: "h-1" });
  const h = harness({ hosts: [host] });
  await rejects(
    "binding to a missing identity is refused",
    () => bindHostToIdentity({ host, identityId: "i-gone" }, h.deps),
    ["i-gone", "no longer exists"],
  );
  check("nothing was written", h.hostRows(), [host]);
}

// ===========================================================================
console.log("\n[16] credentialChoice.ts, by value");
{
  // host === null (create mode, amendment A1): every choice answers `none`.
  check("host===null, inline choice -> none", credentialChangeFor(null, CREDENTIAL_CHOICE_INLINE), {
    kind: "none",
  });
  check(
    "host===null, new-identity choice -> none",
    credentialChangeFor(null, CREDENTIAL_CHOICE_NEW_IDENTITY),
    { kind: "none" },
  );
  check(
    "host===null, an identity choice -> none (the case create mode actually uses)",
    credentialChangeFor(null, identityChoice("i-1")),
    { kind: "none" },
  );

  const inlineHost = sshHost({ id: "h-1" });
  check(
    "inline host, choice unchanged -> none",
    credentialChangeFor(inlineHost, CREDENTIAL_CHOICE_INLINE),
    {
      kind: "none",
    },
  );
  check(
    "inline host, choice new identity -> convert",
    credentialChangeFor(inlineHost, CREDENTIAL_CHOICE_NEW_IDENTITY),
    { kind: "convert" },
  );
  check(
    "inline host, choice an identity -> bind",
    credentialChangeFor(inlineHost, identityChoice("i-2")),
    { kind: "bind", identityId: "i-2" },
  );

  const boundHost = sshHost({ id: "h-2", credential: { kind: "identity", identityId: "i-1" } });
  check(
    "bound host, choice unchanged -> none",
    credentialChangeFor(boundHost, identityChoice("i-1")),
    { kind: "none" },
  );
  check(
    "bound host, choice inline -> detach",
    credentialChangeFor(boundHost, CREDENTIAL_CHOICE_INLINE),
    { kind: "detach", identityId: "i-1" },
  );
  check(
    "bound host, choice new-identity -> none (a bound host owns nothing to move)",
    credentialChangeFor(boundHost, CREDENTIAL_CHOICE_NEW_IDENTITY),
    { kind: "none" },
  );
  check(
    "bound host, choice a DIFFERENT identity -> bind",
    credentialChangeFor(boundHost, identityChoice("i-2")),
    { kind: "bind", identityId: "i-2" },
  );

  // identityIdFromChoice, its own named check - not inferred from the round trip
  // through `identityChoice`, which would miss a sentinel that stopped being
  // distinguishable from an id.
  check(
    "identityIdFromChoice(inline sentinel) is null",
    identityIdFromChoice(CREDENTIAL_CHOICE_INLINE),
    null,
  );
  check(
    "identityIdFromChoice(new-identity sentinel) is null",
    identityIdFromChoice(CREDENTIAL_CHOICE_NEW_IDENTITY),
    null,
  );
  check(
    "identityIdFromChoice(identityChoice(id)) recovers the id",
    identityIdFromChoice(identityChoice("id-1")),
    "id-1",
  );

  check(
    "hostOwnedSecretNames enumerates from the flags, in field order",
    hostOwnedSecretNames(
      sshHost({
        id: "h-9",
        credential: {
          kind: "inline",
          hostId: "h-9",
          user: "root",
          authMode: "key",
          hasPassword: true,
          hasPrivateKey: true,
          hasKeyPassphrase: true,
        },
      }),
    ),
    ["password", "private key", "key passphrase"],
  );
  check(
    "and empty for a vault-bound host, which owns none",
    hostOwnedSecretNames(
      sshHost({ id: "h-10", credential: { kind: "identity", identityId: "i-1" } }),
    ),
    [],
  );

  // The three note strings, by EXACT text.
  check(
    "convert note, exact text",
    credentialChangeNote({ kind: "convert" }, undefined, []),
    "The credentials this host stores move into a new shared identity, and the host stops owning them. Nothing here is deleted until the move has succeeded. This happens as soon as you confirm - cancelling the editor afterwards does not undo it, and what it buys is fewer copies of one credential, nothing else.",
  );
  check(
    "detach note, exact text",
    credentialChangeNote({ kind: "detach", identityId: "i-1" }, "shared", []),
    'This host stops using "shared" and takes its own copy of that identity\'s stored secrets. The identity itself is not changed and every other host bound to it keeps working. This happens as soon as you confirm - cancelling the editor afterwards does not undo it.',
  );
  check(
    "bind note, ONE owned secret - singular verb",
    credentialChangeNote({ kind: "bind", identityId: "i-2" }, "shared", ["password"]),
    'This host stops using its own stored credentials and authenticates as "shared" instead. Its own stored password is deleted and cannot be brought back from here. This happens as soon as you confirm - cancelling the editor afterwards does not undo it.',
  );
  check(
    'bind note, TWO owned secrets - "a and b", plural verb',
    credentialChangeNote({ kind: "bind", identityId: "i-2" }, "shared", [
      "password",
      "private key",
    ]),
    'This host stops using its own stored credentials and authenticates as "shared" instead. Its own stored password and private key are deleted and cannot be brought back from here. This happens as soon as you confirm - cancelling the editor afterwards does not undo it.',
  );
  check(
    "bind note, THREE owned secrets - Oxford comma, plural verb",
    credentialChangeNote({ kind: "bind", identityId: "i-2" }, "shared", [
      "password",
      "private key",
      "key passphrase",
    ]),
    'This host stops using its own stored credentials and authenticates as "shared" instead. Its own stored password, private key, and key passphrase are deleted and cannot be brought back from here. This happens as soon as you confirm - cancelling the editor afterwards does not undo it.',
  );
  assert(
    credentialChangeNote({ kind: "bind", identityId: "i-9" }, undefined, ["password"]).includes(
      '"i-9"',
    ),
    "bind note falls back to the id when no name is known",
  );
}

// ===========================================================================
console.log("\n[17] the two new files read no secret and claim no safety");
{
  const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
  const moveSrc = readFileSync(join(repoRoot, "src/modules/hosts/credentialMove.ts"), "utf8");
  const choiceSrc = readFileSync(
    join(repoRoot, "src/modules/hosts/editor/credentialChoice.ts"),
    "utf8",
  );

  assert(
    !moveSrc.includes("getAll("),
    "credentialMove.ts never calls getAll( - it never reads a secret's value",
  );
  assert(!moveSrc.includes("secrets_get"), "and never invokes secrets_get directly");
  assert(!moveSrc.includes("resolveSshAuth"), "and never calls the resolver that WOULD read one");

  // Over the RAW source, comments and dead branches included (§4.33) - a
  // negative that only checked live code would pass the exact defect it exists
  // to catch: a comment claiming a keychain buys more than it does.
  const safetyClaim = /\bsafer\b|\bsecurely\b|\bmore secure\b|\bsafe\b|\bverified\b|\bprotected\b/i;
  assert(
    !safetyClaim.test(moveSrc),
    "credentialMove.ts makes no safety claim, over the raw source",
  );
  assert(
    !safetyClaim.test(choiceSrc),
    "credentialChoice.ts makes no safety claim, over the raw source",
  );
}

// ---------------------------------------------------------------------------
if (failed > 0) throw new Error(`credential-move-verify: ${failed} FAILED`);
console.log("\ncredential-move-verify: OK\n");
