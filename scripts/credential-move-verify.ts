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
 * 2. CONVERT READS THE RECORD, AND ONLY THE RECORD. A host on password auth can
 *    still store a stray private key; `inlineNeedsKey` reads the credential's
 *    own flags and `inlineAuthMode` reads the mode off the same arm, so the two
 *    cannot disagree. They used to: the mode arrived from the caller's draft,
 *    and that single disagreement was both of wave 4's P0s - a stranded
 *    plaintext password one way (group 8's third arm), a `VaultKey` that nothing
 *    names and `deleteKey` will happily destroy the other (group 4). The
 *    identity therefore NAMES whatever key the copy minted, whatever the mode
 *    says: the record VLT-73 calls off-spec, accepted 2026-09-01 because the
 *    alternative is losing the user's only copy of a private key.
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
 * 5. CONVERT'S THREE PRE-CHECKS ALL REFUSE BEFORE A BYTE MOVES. A bound host
 *    owns nothing to move; a host storing key material needs somewhere in the
 *    vault for it to land; and a record on key auth that stores NO key body
 *    would be refused by `upsertIdentity` two steps after the copies had already
 *    landed, so it is refused here instead. That last one is the state deriving
 *    the mode from the record cannot remove, because one record holds it alone.
 *
 * 6. CONVERT WRITES ONLY FRESH VAULT IDS. Reusing a seeded or a host's own id
 *    would silently overwrite an unrelated record instead of minting a new one.
 *
 * 7. DETACH TAKES ITS OWN COPY, and a missing identity - or an identity naming
 *    a key that is itself gone - degrades to a WARNING plus an inline record,
 *    never a throw: the host was already unable to connect, and refusing would
 *    leave it that way forever. It carries convert's corollary too, mirrored
 *    (group 13b): when the host write refuses, the copies already sitting on
 *    the host's own accounts are taken back - only the fields that copied, and
 *    only while the stored record is still bound.
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
    /**
     * Make the HOST store's `commit` throw.
     *
     * Not a simulation of the persist-half-landed case, but the case itself:
     * `persist` (`hosts/store.ts:420-423`) writes every key through `set` and
     * only THEN commits, so a throw here leaves the new record sitting in the
     * store while `upsertHost` reports failure - which is exactly the state
     * `undoDetachCopies`' re-read guard exists to recognise, and the only way to
     * reach its declining branch through the real store.
     */
    hostCommitThrows?: boolean;
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
      if (seed.hostCommitThrows) {
        // A distinct marker, so group 7's `e === "commit:hosts"` trace pins
        // cannot match a commit that threw.
        trace.push("commit:hosts(threw)");
        throw new Error("hosts: the store failed to persist");
      }
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
      identity: { name: "shared", username: "root", domain: "", description: "" },
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
      identity: { name: "shared", username: "root", domain: "", description: "" },
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
  "\n[4] convert copies what the RECORD owns, and the identity it writes NAMES what that copy created",
);
{
  // A host on PASSWORD auth that also stores a private key - `inlineNeedsKey`
  // reads `hasPrivateKey`/`hasKeyPassphrase` off the credential, and
  // `inlineAuthMode` reads the mode off the same arm, so the two cannot
  // disagree. This is accepted gap 12's record: key material that outlived the
  // mode that used it.
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
      identity: { name: "shared", username: "root", domain: "", description: "" },
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
  check(
    "the new identity's mode is the RECORD's own, which is password",
    result.identity.authMode,
    "password",
  );

  // ---------------------------------------------------------------------------
  // P0-2's regression check, and this row carries the OPPOSITE claim it used to.
  //
  // It read: "the new identity's keyId does not leak it in, since its mode is
  // password", citing VLT-73 - `identityRecordFrom` drops `keyId` for a non-key
  // mode so a password row cannot render a grey key chip that reads as "this
  // identity signs with that key".
  //
  // That is right for the identity EDITOR, where dropping the id costs the user
  // a dropdown selection they can make again. It was wrong here, and it was a
  // P0: convert MINTS this key out of the host's own PEM and
  // `releaseStaleAccounts` then deletes the host's copy, so the vault key is the
  // only copy left - and `deleteKey`'s in-use guard (`vault/store.ts:337-347`)
  // finds holders by `identity.keyId`. With no identity naming it, the guard has
  // nothing to refuse over and one click on the Vault page destroys it, from a
  // convert that reported SUCCESS.
  //
  // Owner's decision, 2026-09-01: the identity names the key whenever one was
  // minted, regardless of mode. That deliberately builds the record VLT-73 calls
  // off-spec (accepted gap 12's case: a host that once used key auth, now
  // authenticates by password, still carries its PEM), and reopens VLT-73's
  // rendering question earlier than 6g. It is strictly better than the delete.
  // `identityRecordFrom`'s `"keep"` rule is where that opt-out lives - on the
  // single normaliser, not assembled by hand at the call site.
  // ---------------------------------------------------------------------------
  check(
    "the new identity NAMES the minted key even though its mode is password (P0-2)",
    result.identity.keyId,
    result.key.id,
  );
  // The part that proves it is not merely present: naming it is what restores
  // the user-visible protection. An absence check cannot tell "the id is on the
  // record" from "the id is on the record and the guard reads it".
  await rejects(
    "and deleteKey on that key is now REFUSED, because the identity names it",
    () => h.vault.deleteKey(result.key?.id ?? ""),
    ["cannot delete", "leftover key", "still used by 1 identity"],
  );
  check(
    "so the only copy of the PEM is still there after the refused delete",
    h.kept.get(`${VAULT_KEYRING_SERVICE}::${result.key.id}::privateKey`),
    "PEM-BODY",
  );
}

// ===========================================================================
console.log(
  "\n[4b] the caller cannot influence the identity's auth mode - it is derived from the STORED record",
);
{
  // Owner's decision, 2026-09-01: `convertHostToVault`'s `args.identity` carries
  // no `authMode` at all. It used to, and it was the ROOT CAUSE of both P0s -
  // the mode came from the caller's draft while `inlineNeedsKey` decided whether
  // a key was needed from the stored record, so the two could disagree in either
  // direction (group 4 is what a disagreement one way did to a key; group 8's
  // third arm is what the other way did to a password).
  //
  // Three records identical but for their stored `authMode`, converted with the
  // SAME `args.identity`, produce three different identity modes. `agent` is the
  // decisive row: it is a mode nothing else in this file converts, and one that
  // could only ever have arrived from a draft before this change.
  const stored = async (authMode: "password" | "key" | "agent") => {
    const host = sshHost({
      id: "h-1",
      credential: {
        kind: "inline",
        hostId: "h-1",
        user: "root",
        authMode,
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
    return convertHostToVault(
      {
        host,
        identity: { name: "shared", username: "root", domain: "", description: "" },
        key: { name: "carried key", facts: {} },
      },
      h.deps,
    );
  };
  const fromPassword = await stored("password");
  const fromKey = await stored("key");
  const fromAgent = await stored("agent");
  check(
    "the three stored modes come back on the three identities, in order",
    [fromPassword.identity.authMode, fromKey.identity.authMode, fromAgent.identity.authMode],
    ["password", "key", "agent"],
  );
  // And decision 2 applies across all three, not only to the password row group
  // 4 pins: whichever mode the record was on, the minted key ends up named.
  check(
    "and every one of them names the key that was minted from its PEM",
    [
      fromPassword.identity.keyId === fromPassword.key?.id,
      fromKey.identity.keyId === fromKey.key?.id,
      fromAgent.identity.keyId === fromAgent.key?.id,
    ],
    [true, true, true],
  );

  // The STRUCTURAL half, and it is a COMPILE-time pin: `pnpm verify` runs under
  // tsx, which strips types without checking them, so this row can only print
  // `ok` here - `pnpm typecheck:scripts` is the gate it actually reddens, the
  // day `authMode` comes back as a parameter and `AuthModeIsNotAParameter`
  // becomes `never`. Said out loud, because a check that cannot fail where it is
  // printed is worth exactly what its label admits and no more.
  type ConvertIdentityArg = Parameters<typeof convertHostToVault>[0]["identity"];
  type AuthModeIsNotAParameter = "authMode" extends keyof ConvertIdentityArg ? never : true;
  const authModeIsNotAParameter: AuthModeIsNotAParameter = true;
  assert(
    authModeIsNotAParameter,
    "convertHostToVault's identity argument declares no authMode (compile-time; typecheck:scripts is the gate)",
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
      identity: { name: "dc", username: "admin", domain: "CORP", description: "" },
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
      identity: { name: "x", username: "root", domain: "", description: "" },
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
      identity: { name: "x", username: "root", domain: "", description: "" },
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
console.log(
  "\n[8] convert's three pre-checks refuse BEFORE any copy: a bound host, key material with no key name, key auth storing no key",
);
{
  const bound = sshHost({ id: "h-1", credential: { kind: "identity", identityId: "i-1" } });
  const h = harness({ hosts: [bound] });
  await rejects(
    "a vault-bound host has nothing to convert",
    () =>
      convertHostToVault(
        {
          host: bound,
          identity: { name: "x", username: "root", domain: "", description: "" },
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
          identity: { name: "x", username: "root", domain: "", description: "" },
          key: null,
        },
        h2.deps,
      ),
    ["stores a private key", "name for the new key"],
  );

  // ---------------------------------------------------------------------------
  // P0-1's regression check. Deriving the identity's mode from the record
  // (`inlineAuthMode`) removes every DISAGREEMENT between the mode and
  // `inlineNeedsKey`, but not this state, which one record holds on its own:
  // `authMode: "key"` with `hasPrivateKey: false`, a key-auth host whose body
  // was never stored. `needsKey` is then false, so no key id is minted, and
  // `upsertIdentity` refuses ("uses key auth but names no key") - at step 7,
  // AFTER the copies of step 5 have landed.
  //
  // Measured before the fix, over two presses of one button: two vault password
  // accounts written under freshly minted identity ids, no identity on record to
  // name either, and three copies of "hunter2" in the keychain - unbounded (one
  // more per press) and unenumerable, since there is no `secrets_list`. The
  // confirmation the user had just read says the point is fewer copies of one
  // credential.
  //
  // Reachable in three clicks with no gate before the fix: a password-auth host
  // with a stored password, flip the radio to "Private key", pick "New shared
  // identity...", confirm. `applyCredentialChange` never calls `validate()`, so
  // the form's own "key auth needs a key" refusal never ran on this path.
  // ---------------------------------------------------------------------------
  const keyAuthNoBody = sshHost({
    id: "h-3",
    credential: {
      kind: "inline",
      hostId: "h-3",
      user: "root",
      authMode: "key",
      hasPassword: true,
      hasPrivateKey: false,
      hasKeyPassphrase: false,
    },
  });
  const h3 = harness({
    hosts: [keyAuthNoBody],
    kept: { [`${HOST_KEYRING_SERVICE}::h-3::password`]: "hunter2" },
  });
  await rejects(
    "a host on key auth that stores no private key is refused, naming the host and what is missing",
    () =>
      convertHostToVault(
        {
          host: keyAuthNoBody,
          identity: { name: "x", username: "root", domain: "", description: "" },
          key: null,
        },
        h3.deps,
      ),
    ["prod", "authenticates with a private key", "stores none"],
  );
  // THE assertion this group exists for, and it is over the CALL LOG rather than
  // over `kept` afterwards: "refused before the copy" is the claim, and an
  // absence check after the fact cannot tell it apart from "copied, then cleaned
  // up". Group 9 is what the second one looks like, and it deletes three vault
  // accounts on its way out; this one issues no copy at all.
  check("no copy was issued at all - the refusal is a pre-check", h3.copies(), []);
  check(
    "so no vault account was written",
    [...h3.kept.keys()].filter((k) => k.startsWith(`${VAULT_KEYRING_SERVICE}::`)),
    [],
  );
  check("no vault identity exists", h3.identities(), []);
  check("no vault key exists", h3.keys(), []);
  check(
    "the host's own password is untouched, value included",
    h3.kept.get(`${HOST_KEYRING_SERVICE}::h-3::password`),
    "hunter2",
  );
  check(
    "and nothing was deleted anywhere",
    h3.calls.filter((c) => c.op === "delete"),
    [],
  );
  check("the stored host record is unchanged", h3.hostRows(), [keyAuthNoBody]);
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
        identity: { name: "x", username: "root", domain: "", description: "" },
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
          identity: { name: "x", username: "root", domain: "", description: "" },
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
      identity: { name: "x", username: "root", domain: "", description: "" },
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
console.log("\n[13b] a refused detach takes its copies back off the host's own accounts");
{
  // The mirror of group 9, one direction over. `copyMoves` writes the
  // identity's password and the key's two secrets onto the HOST's accounts
  // before `upsertHost` is called, and `upsertHost` is again the first call
  // that can refuse - so a refusal used to leave a plaintext copy of a SHARED
  // vault key at `tervia-hosts::<hostId>::privateKey`, named by nothing, and
  // unenumerable because there is no `secrets_list`.
  //
  // Asserted positively, for group 9's reason: the copies must be shown to have
  // LANDED first, or an undo of nothing passes every absence check for free.
  // The delete log is pinned BY VALUE rather than counted, because that is what
  // separates "took back what it wrote" from "deleted every field it could
  // name" - the second is invisible in `kept`, since deleting an account that
  // was never written is a no-op.
  //
  // The refusal is the dangling `proxyJumpId` again: no second writer, no stale
  // load, and reachable today by detaching a host whose jump target was deleted.
  const keptFor = (hh: ReturnType<typeof harness>, service: string): string[] =>
    [...hh.kept.entries()]
      .filter(([k]) => k.startsWith(`${service}::`))
      .map(([k, v]) => `${k}=${v}`)
      .sort();
  const hostDeletes = (hh: ReturnType<typeof harness>): string[] =>
    hh.calls
      .filter((c) => c.op === "delete" && c.service === HOST_KEYRING_SERVICE)
      .map((c) => c.accounts[0]);
  const landedCopies = (hh: ReturnType<typeof harness>): number =>
    traceIndex(hh.trace, (e) => e.startsWith(`copy ${VAULT_KEYRING_SERVICE}::`)).length;

  const idn = identity({
    id: "i-1",
    name: "shared",
    username: "root",
    authMode: "key",
    keyId: "k-1",
    hasPassword: true,
  });
  const key = vaultKey({ id: "k-1", name: "shared key", hasPrivateKey: true, hasPassphrase: true });
  const vaultKept = {
    [`${VAULT_KEYRING_SERVICE}::i-1::password`]: "vault-pw",
    [`${VAULT_KEYRING_SERVICE}::k-1::privateKey`]: "vault-pem",
    [`${VAULT_KEYRING_SERVICE}::k-1::passphrase`]: "vault-pp",
  };
  const boundHost = sshHost({
    id: "h-1",
    proxyJumpId: "h-gone",
    credential: { kind: "identity", identityId: "i-1" },
  });
  const h = harness({ hosts: [boundHost], identities: [idn], keys: [key], kept: vaultKept });

  await rejects(
    "detach is refused when the host names a jump host that is gone",
    () =>
      detachHostFromVault({ host: boundHost, inline: { user: "root", authMode: "key" } }, h.deps),
    ["names a jump host", "does not exist"],
  );

  check("all three secrets landed on the host's accounts first", landedCopies(h), 3);
  check("and the cleanup took back exactly those three accounts, in order", hostDeletes(h), [
    "h-1::password",
    "h-1::privateKey",
    "h-1::keyPassphrase",
  ]);
  check("no host account holds a secret", keptFor(h, HOST_KEYRING_SERVICE), []);
  check(
    "the copied password was taken back",
    h.kept.has(`${HOST_KEYRING_SERVICE}::h-1::password`),
    false,
  );
  check(
    "the copied PRIVATE KEY was taken back - the one that would be a shared secret",
    h.kept.has(`${HOST_KEYRING_SERVICE}::h-1::privateKey`),
    false,
  );
  check(
    "the copied key passphrase was taken back",
    h.kept.has(`${HOST_KEYRING_SERVICE}::h-1::keyPassphrase`),
    false,
  );
  check("the identity record is byte-identical", h.identities(), [idn]);
  check("the key record is byte-identical", h.keys(), [key]);
  check("and both still hold their values", keptFor(h, VAULT_KEYRING_SERVICE), [
    `${VAULT_KEYRING_SERVICE}::i-1::password=vault-pw`,
    `${VAULT_KEYRING_SERVICE}::k-1::passphrase=vault-pp`,
    `${VAULT_KEYRING_SERVICE}::k-1::privateKey=vault-pem`,
  ]);
  check("the stored host record is unchanged, and still bound", h.hostRows(), [boundHost]);

  // The dangling-key arm, refused: ONE field copied, so exactly one is taken
  // back. A cleanup that deleted every field the host could name would pass
  // every check above and fail this one.
  const dangling = identity({
    id: "i-dangling",
    name: "dangling",
    authMode: "key",
    keyId: "k-gone",
    hasPassword: true,
  });
  const host2 = sshHost({
    id: "h-2",
    proxyJumpId: "h-gone",
    credential: { kind: "identity", identityId: "i-dangling" },
  });
  const h2 = harness({
    hosts: [host2],
    identities: [dangling],
    kept: { [`${VAULT_KEYRING_SERVICE}::i-dangling::password`]: "vault-pw" },
  });
  await rejects(
    "the dangling-key arm is refused by the same jump-host check",
    () => detachHostFromVault({ host: host2, inline: { user: "root", authMode: "key" } }, h2.deps),
    ["names a jump host", "does not exist"],
  );
  check("only the password landed", landedCopies(h2), 1);
  check("and only the password was taken back", hostDeletes(h2), ["h-2::password"]);
  check("no host account holds a secret", keptFor(h2, HOST_KEYRING_SERVICE), []);
  check("the identity still holds its password", keptFor(h2, VAULT_KEYRING_SERVICE), [
    `${VAULT_KEYRING_SERVICE}::i-dangling::password=vault-pw`,
  ]);

  // ---------------------------------------------------------------------------
  // The one refusal that is not `upsertHost`'s, and the reason `buildInlineRecord`
  // now runs BEFORE `copyMoves` rather than one statement after it.
  //
  // It throws when `inline`'s shape does not match the host's own protocol, and
  // that throw used to sit between the copies and the `try` - so it escaped with
  // `undoDetachCopies` never running, leaving a plaintext copy of the identity's
  // password on a host account nothing names. Precisely the orphan class every
  // other row in this group exists to prevent, reachable one statement earlier
  // and past the compensation rather than inside it.
  //
  // NOT reachable from the shipped dialog today: `HostEditorDialog` picks the
  // inline shape off the same `protocol` the host carries, and the protocol
  // toggle is create-mode only while this path is edit-only. It is pinned anyway
  // because the ordering is the whole guarantee, and 6f/6g's callers arm it.
  //
  // The two assertions are the same pair the rest of this group uses, read the
  // other way round: nothing landed, so there was nothing to take back. Group
  // 8's third arm makes the identical distinction on convert's side.
  const rdpBound = rdpHost({ id: "h-rdp", credential: { kind: "identity", identityId: "i-1" } });
  const hMismatch = harness({
    hosts: [rdpBound],
    identities: [idn],
    keys: [key],
    kept: vaultKept,
  });
  await rejects(
    "detach refuses an inline credential built for the other protocol",
    () =>
      detachHostFromVault(
        // SSH-shaped `inline` against an RDP host - the union admits it, and
        // `buildInlineRecord` is the only thing that refuses it.
        { host: rdpBound, inline: { user: "root", authMode: "key" } },
        hMismatch.deps,
      ),
    ["vps", "inline credential for the other protocol"],
  );
  check("no copy was issued at all - the refusal precedes copyMoves", hMismatch.copies(), []);
  check(
    "so the identity's password never landed on the host's account, with nothing to take it back",
    hMismatch.kept.has(`${HOST_KEYRING_SERVICE}::h-rdp::password`),
    false,
  );
  check("and nothing was deleted", hostDeletes(hMismatch), []);
  check("the vault's own accounts are untouched", keptFor(hMismatch, VAULT_KEYRING_SERVICE), [
    `${VAULT_KEYRING_SERVICE}::i-1::password=vault-pw`,
    `${VAULT_KEYRING_SERVICE}::k-1::passphrase=vault-pp`,
    `${VAULT_KEYRING_SERVICE}::k-1::privateKey=vault-pem`,
  ]);
  check("the stored host record is unchanged, and still bound", hMismatch.hostRows(), [rdpBound]);

  // The missing-identity arm copies nothing, so a refusal there has nothing to
  // undo - and must still touch no account. Same jump-host refusal.
  const host3 = sshHost({
    id: "h-3",
    proxyJumpId: "h-gone",
    credential: { kind: "identity", identityId: "i-gone" },
  });
  const h3 = harness({ hosts: [host3] });
  await rejects(
    "the missing-identity arm is refused by the same jump-host check",
    () =>
      detachHostFromVault({ host: host3, inline: { user: "root", authMode: "agent" } }, h3.deps),
    ["names a jump host", "does not exist"],
  );
  check("nothing was copied", h3.copies(), []);
  check("and nothing was deleted", hostDeletes(h3), []);

  // The stamp refusal, kept for the ERROR rather than for the cleanup: this is
  // the one that arrives as a `HostBindingChangedError`, and it is checked by
  // instance and by value (§4.39) because `HostEditorDialog`'s recovery arm
  // reads those three fields off it (VLT-29). A cleanup failure replacing the
  // original error would be invisible to a message-text match.
  const boundElsewhere = sshHost({
    id: "h-4",
    credential: { kind: "identity", identityId: "i-other" },
  });
  // The record as an editor loaded it before another writer re-bound it.
  const staleLoad = sshHost({ id: "h-4", credential: { kind: "identity", identityId: "i-1" } });
  const h4 = harness({
    hosts: [boundElsewhere],
    identities: [idn, identity({ id: "i-other", name: "other" })],
    keys: [key],
    kept: vaultKept,
  });
  let caught: unknown;
  try {
    await detachHostFromVault(
      { host: staleLoad, inline: { user: "root", authMode: "key" } },
      h4.deps,
    );
  } catch (e) {
    caught = e;
  }
  assert(
    caught instanceof HostBindingChangedError,
    "the refusal is a HostBindingChangedError, by instance",
  );
  const err = caught as HostBindingChangedError;
  check("hostId, by value", err?.hostId, "h-4");
  check("expected, by value - the stale caller's own stamp", err?.expected, "identity:i-1");
  check("actual, by value - what is really stored now", err?.actual, "identity:i-other");
  check("all three secrets landed on the host's accounts first", landedCopies(h4), 3);
  check("and the cleanup took back exactly those three accounts, in order", hostDeletes(h4), [
    "h-4::password",
    "h-4::privateKey",
    "h-4::keyPassphrase",
  ]);
  check("no host account holds a secret", keptFor(h4, HOST_KEYRING_SERVICE), []);
  check(
    "the identity and key records are byte-identical",
    [h4.keys(), h4.identities().length],
    [[key], 2],
  );
  check("the stored host record is unchanged, and still bound", h4.hostRows(), [boundElsewhere]);

  // ---------------------------------------------------------------------------
  // THE GUARD'S OTHER BRANCH - the one where the cleanup must NOT run, and until
  // now the one nothing exercised.
  //
  // Every refusal above leaves a `kind: "identity"` record in the store, so all
  // of them take the cleanup's PROCEEDING path. The h4 stamp case looks like the
  // exception and is not: it is identity -> identity, a re-bind, not the
  // identity -> inline detach the guard's own doc describes. So the re-read and
  // the guard could both be deleted outright and this group stayed at 138 ok /
  // 0 FAIL - and, worse, the compile-clean weakening to `if (!stored) return;`
  // did too, which declines exactly where it must not and proceeds exactly where
  // it must refuse. A guard whose two branches are never told apart is not
  // checked by the fact that its file is.
  //
  // The fixture is the persist-half-landed case the guard's comment names, built
  // from the real store rather than mimed: `persist` writes the record through
  // `set` and only then commits, so a commit that throws leaves the host stored
  // and INLINE while `upsertHost` reports failure. `LazyStore` runs with
  // autoSave, so a debounced retry sits behind that record in production.
  //
  // WHY DELETING HERE WOULD BE THE CREDENTIAL LOSS. The stored record is now
  // inline and NAMES these three accounts (`secretFieldsFor` returns them for an
  // inline credential), and `releaseStaleAccounts` never ran because persist
  // threw before it. The bytes at them are the host's own, legitimately. A
  // cleanup that deleted them would leave a host claiming three secrets it no
  // longer has, with the vault copy the only survivor - and on the concurrent-
  // detach variant of this same branch, not even that.
  // ---------------------------------------------------------------------------
  const persistHost = sshHost({
    id: "h-5",
    credential: { kind: "identity", identityId: "i-1" },
  });
  const h5 = harness({
    hosts: [persistHost],
    identities: [idn],
    keys: [key],
    kept: vaultKept,
    hostCommitThrows: true,
  });
  await rejects(
    "detach surfaces the persist failure rather than swallowing it",
    () =>
      detachHostFromVault(
        { host: persistHost, inline: { user: "root", authMode: "key" } },
        h5.deps,
      ),
    ["failed to persist"],
  );
  // The branch is REACHED, not merely assumed: the stored record really is
  // inline at the moment the cleanup re-reads it. Without this the two checks
  // below would pass for a fixture that never got near the guard.
  check(
    "the stored record is INLINE when the cleanup re-reads it - the persist landed, the commit did not",
    h5.hostRows().map((h) => h.credential.kind),
    ["inline"],
  );
  check("all three secrets landed on the host's accounts first", landedCopies(h5), 3);
  check("and the cleanup deleted NOTHING - the host now names these accounts", hostDeletes(h5), []);
  check(
    "so the host keeps all three, values included - this is the credential the guard is protecting",
    keptFor(h5, HOST_KEYRING_SERVICE),
    [
      `${HOST_KEYRING_SERVICE}::h-5::keyPassphrase=vault-pp`,
      `${HOST_KEYRING_SERVICE}::h-5::password=vault-pw`,
      `${HOST_KEYRING_SERVICE}::h-5::privateKey=vault-pem`,
    ],
  );
  check("and the vault's own copies are untouched either way", keptFor(h5, VAULT_KEYRING_SERVICE), [
    `${VAULT_KEYRING_SERVICE}::i-1::password=vault-pw`,
    `${VAULT_KEYRING_SERVICE}::k-1::passphrase=vault-pp`,
    `${VAULT_KEYRING_SERVICE}::k-1::privateKey=vault-pem`,
  ]);
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

// --- mutation table (wave 4's P0 round) ------------------------------------
//
// The discipline `vault-draft-verify.ts` records at its own tail: a check that
// has not been watched fail is not a check. Every mutation below was applied to
// the file named, run, its FAIL lines recorded, and the source restored by hash
// - see /tmp/wave4-fix-p0-authmode/MUTATIONS.md for the transcript.
//
//   Mutation                                          Check(s) it killed
//   -------------------------------------------------  ---------------------------
//   H1: credentialMove.ts - the pre-copy key-auth      section 8's third arm: the
//     refusal deleted                                    refusal itself, "no copy
//                                                        was issued at all", and
//                                                        "no vault account was
//                                                        written". The observed
//                                                        throw is P0-1's own,
//                                                        verbatim: `vault:
//                                                        identity "x" uses key
//                                                        auth but names no key`,
//                                                        with the password
//                                                        already copied.
//   H2: credentialMove.ts - the `"keep"` argument      section 4's three P0-2
//     dropped from identityRecordFrom, restoring the     rows and 4b's key-naming
//     auth-mode normalisation on convert's path          row. Reproduces Oracle
//                                                        A's measurement exactly:
//                                                        keyId undefined, and
//                                                        `deleteKey` DID NOT
//                                                        REJECT - the PEM was
//                                                        gone afterwards.
//   H3: credentialMove.ts - authMode taken from a      section 4b's three-mode
//     required args.identity.authMode again              row (11 checks across
//                                                        the file), plus 14
//                                                        errors in
//                                                        typecheck:scripts.
//   H3b: the same, but OPTIONAL, defaulting to the     NOTHING here - `pnpm
//     derived value, so every call site compiles         verify` stays 0. Caught
//                                                        ONLY by section 4b's
//                                                        compile-time pin, which
//                                                        is why that pin exists
//                                                        beside the behavioural
//                                                        rows rather than instead
//                                                        of them.
//   H4: credentialMove.ts - buildInlineRecord moved    section 13b's mismatched-
//     back below copyMoves                               protocol arm: "no copy
//                                                        was issued" and the
//                                                        orphan check. NOTHING
//                                                        before that arm existed
//                                                        - every other 13b row
//                                                        uses a fixture where
//                                                        buildInlineRecord
//                                                        succeeds, so none of
//                                                        them can see its throw.
//   H5: a Prettier-legal reflow of every region this   NOTHING (§4.51), with
//     round changed, in all five files                   `pnpm format:check`
//                                                        still at 0 over the
//                                                        reflowed form.
//
// And reviewer B's two, against 13b's new persist-half-landed fixture - the one
// that reaches `undoDetachCopies`' DECLINING branch. Before it existed, both of
// these left this file at 138 ok / 0 FAIL and `pnpm verify` at 53/53:
//
//   J1: credentialMove.ts - the re-read and the guard   the new fixture's
//     deleted outright                                   "deleted NOTHING" and
//                                                        "keeps all three,
//                                                        values included" rows.
//                                                        (`tsc` also flags the
//                                                        now-unused `hostId`.)
//   J2: credentialMove.ts - the guard weakened to       the same two rows, with
//     `if (!stored) return;`                             `tsc` at 0. THE REAL
//                                                        TEST: it is compile-
//                                                        clean, and it inverts
//                                                        the guard - declining
//                                                        where it must proceed
//                                                        and proceeding where it
//                                                        must refuse.
//
// Residual, stated rather than left to be found: J2's OTHER half - declining
// when the record is GONE, which the guard's doc says must not stop the cleanup
// - is still uncovered, because every fixture here has a stored record. It is a
// register row, not this round's.
