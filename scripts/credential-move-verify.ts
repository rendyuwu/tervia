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
 * 11. A `VaultKey` NEVER DESCRIBES ONE KEY WHILE HOLDING ANOTHER. Property 10 is
 *     what makes this one impossible to check from the inside: convert stamps
 *     the `facts` it is handed over the body it copies and cannot compare them,
 *     so the record is only as honest as the condition its caller inspects
 *     under. That condition is pinned in group [10d], which is the one thing
 *     this file reads out of `HostEditorDialog.tsx`, and group [10e] measures
 *     what a mis-described record costs and which half of the guard holds which
 *     part of it. The cost is not cosmetic: the reuse path copies nothing and
 *     property 4's release then takes the host's own accounts, so an offer made
 *     on a false fingerprint destroys the last copy of a key.
 *
 * The store, secrets and event bus are all injectable ports, so all of this
 * runs under plain node with no Tauri runtime and no mocking library.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import ts from "typescript";

import { createWriteQueue } from "../src/lib/recoveredStore";
import type { HostsStoreIo } from "../src/modules/hosts/adapters";
import {
  bindHostToIdentity,
  convertHostToVault,
  convertMoves,
  detachHostFromVault,
  detachMoves,
  reusableVaultKey,
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
import { createVaultStore, type VaultStore } from "../src/modules/vault/store";
import {
  HOST_KEYRING_SERVICE,
  VAULT_KEYRING_SERVICE,
  VAULT_STAMP_ABSENT,
  VaultRecordChangedError,
  vaultIdentityStamp,
  vaultKeyStamp,
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
// [10b] and [10c] exist because GROUP 10 IS NOT COVER FOR EITHER OF THEM, and
// reading it as cover is the trap the fingerprint-dedupe row names by itself.
// Group 10 forbids reusing a CALLER-SUPPLIED or the HOST's OWN id. It says
// nothing about a record convert was ASKED to reuse, its seeded fixtures are
// named differently, and a dedupe therefore passes it untouched - so without
// these two groups the reuse path would ship with a green gate and no evidence
// at all about the property that changed.
//
// The fixtures below share one shape, and every field of it is load-bearing:
//
//   * The shared key and the host hold THE SAME private key body and DIFFERENT
//     passphrases. That is the real case - a re-encrypted copy of one key file
//     is still that key, and the fingerprint (the public half) cannot tell the
//     two passphrases apart. A reuse path that copied would overwrite the vault
//     record's passphrase with this host's, and every other identity using that
//     record would stop being able to open it.
//   * NO OTHER IDENTITY names the shared key. That is what gives [10b]'s
//     direction-2 check teeth: `deleteKey` refuses only while a holder exists,
//     so a key with no holder is deletable, and a compensating delete pointed at
//     it would go through. The last check of that block proves the delete really
//     would have succeeded, so a green result there is a fact about the code and
//     not about an inert guard.
// ===========================================================================
console.log(
  "\n[10b] convert can REUSE a vault key the caller found, and the reuse path writes NOTHING to it",
);
{
  /** Every vault write and delete, by name and id, in call order, over
   *  deterministic minted ids.
   *
   *  Every claim this group exists for is of the form "this call was not made",
   *  and an absence check over `kept` or over the record list afterwards cannot
   *  tell "never called" from "called, then undone" - group 9 is what the second
   *  one looks like and it leaves the store looking identical. So the calls
   *  themselves are the assertion, by value and in order. */
  const convertSpy = (h: ReturnType<typeof harness>) => {
    const log: string[] = [];
    const vault: CredentialMoveDeps["vault"] = {
      ...h.vault,
      newIdentityId: () => "i-new",
      newKeyId: () => "k-new",
      upsertKey: (...a: Parameters<VaultStore["upsertKey"]>) => {
        log.push(`upsertKey ${a[0].id}`);
        return h.vault.upsertKey(...a);
      },
      upsertIdentity: (...a: Parameters<VaultStore["upsertIdentity"]>) => {
        log.push(`upsertIdentity ${a[0].id}`);
        return h.vault.upsertIdentity(...a);
      },
      deleteKey: (...a: Parameters<VaultStore["deleteKey"]>) => {
        log.push(`deleteKey ${a[0]}`);
        return h.vault.deleteKey(...a);
      },
      deleteIdentity: (...a: Parameters<VaultStore["deleteIdentity"]>) => {
        log.push(`deleteIdentity ${a[0]}`);
        return h.vault.deleteIdentity(...a);
      },
    };
    return { log, deps: { ...h.deps, vault } };
  };

  const sharedKey = vaultKey({
    id: "k-shared",
    name: "laptop key",
    fingerprint: "SHA256:AAAA",
    hasPrivateKey: true,
    hasPassphrase: true,
  });
  const keyedHost = (over: Partial<SshHost> = {}): SshHost =>
    sshHost({
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
      ...over,
    });
  const hostKept = {
    [`${HOST_KEYRING_SERVICE}::h-1::password`]: "hunter2",
    [`${HOST_KEYRING_SERVICE}::h-1::privateKey`]: "PEM-BODY",
    // DIFFERENT from the vault record's, and the same key body: this is the
    // value a reuse path that copied would write over `k-shared::passphrase`.
    [`${HOST_KEYRING_SERVICE}::h-1::keyPassphrase`]: "this-host-passphrase",
  };
  const sharedKept = {
    [`${VAULT_KEYRING_SERVICE}::k-shared::privateKey`]: "PEM-BODY",
    [`${VAULT_KEYRING_SERVICE}::k-shared::passphrase`]: "the-shared-passphrase",
  };
  const sharedAccounts = (h: ReturnType<typeof harness>): (string | undefined)[] => [
    h.kept.get(`${VAULT_KEYRING_SERVICE}::k-shared::privateKey`),
    h.kept.get(`${VAULT_KEYRING_SERVICE}::k-shared::passphrase`),
  ];

  // -- 10b.1: the reuse path itself ----------------------------------------
  {
    const host = keyedHost();
    const h = harness({
      hosts: [host],
      keys: [sharedKey],
      kept: { ...hostKept, ...sharedKept },
    });
    const spy = convertSpy(h);
    const result = await convertHostToVault(
      {
        host,
        identity: { name: "shared", username: "root", domain: "", description: "" },
        key: { reuseKeyId: "k-shared" },
      },
      spy.deps,
    );

    // (1) No `upsertKey` call is made AT ALL - not "an upsertKey that happens to
    // write the same bytes".
    check("the vault write log, by value and in order - there is no upsertKey in it", spy.log, [
      "upsertIdentity i-new",
    ]);
    // (2) The identity names exactly that key id, on the returned record and on
    // the stored one: `identityRecordFrom` is between the two and normalises.
    check(
      "the returned identity names exactly the key that was reused",
      result.identity.keyId,
      "k-shared",
    );
    check(
      "and so does the STORED identity, which is what a connect reads",
      h.identities().map((i) => i.keyId),
      ["k-shared"],
    );
    // (3) THE DANGEROUS DIRECTION. By value and in order, never by count: a
    // count of one is satisfied by a single copy onto the WRONG account.
    check("the copies, by value and in order - the password alone", h.copies(), [
      `${HOST_KEYRING_SERVICE}::h-1::password -> ${VAULT_KEYRING_SERVICE}::i-new::password`,
    ]);
    check(
      "no copy names the shared key's accounts at all",
      h.copies().filter((c) => c.includes("k-shared")),
      [],
    );
    // The same claim one level down, where it actually costs something: what is
    // AT those accounts. A move log can be right while a `secrets.set` somewhere
    // else wrote the value anyway.
    check(
      "the shared key's two accounts still hold what they held, values included - the differing passphrase in particular",
      sharedAccounts(h),
      ["PEM-BODY", "the-shared-passphrase"],
    );
    check("the shared key's RECORD is byte-identical afterwards", h.keys(), [sharedKey]);

    // The return value (amendment G2): the EXISTING record, not `null`. `null`
    // is the honest answer for "this identity names no key", and on this path
    // the identity names one.
    check("the caller is handed the existing key record, not null", result.key, sharedKey);
    check(
      "so result.key.id and result.identity.keyId agree on every path where a key is named",
      result.key !== null && result.key.id === result.identity.keyId,
      true,
    );

    // And the trade the confirmation has to state out loud: the host's own
    // copies are released as stale by `upsertHost`, its passphrase included -
    // that value is not copied anywhere, and it is GONE.
    check(
      "the host's own three accounts are all released, its own key passphrase included",
      [
        h.kept.has(`${HOST_KEYRING_SERVICE}::h-1::password`),
        h.kept.has(`${HOST_KEYRING_SERVICE}::h-1::privateKey`),
        h.kept.has(`${HOST_KEYRING_SERVICE}::h-1::keyPassphrase`),
      ],
      [false, false, false],
    );
    check("the host record is bound to the new identity", result.host.credential, {
      kind: "identity",
      identityId: "i-new",
    });
  }

  // -- 10b.2: DIRECTION 2 - a refused host write must not delete the key ----
  {
    // `proxyJumpId` naming a host that is gone: `upsertHost` refuses, with no
    // second writer anywhere, which is group 9b's own fixture. On the reuse path
    // the compensating delete then runs with a key id that came from OUTSIDE
    // this call - the one case `undoConvertRecords`' provenance argument
    // explicitly does not cover.
    const host = keyedHost({ proxyJumpId: "h-gone" });
    const h = harness({
      hosts: [host],
      keys: [sharedKey],
      kept: { ...hostKept, ...sharedKept },
    });
    const spy = convertSpy(h);
    await rejects(
      "the convert is refused, because the host names a jump host that is gone",
      () =>
        convertHostToVault(
          {
            host,
            identity: { name: "shared", username: "root", domain: "", description: "" },
            key: { reuseKeyId: "k-shared" },
          },
          spy.deps,
        ),
      ["names a jump host", "does not exist"],
    );
    check(
      "the vault write AND delete log, by value and in order - the identity is taken back and deleteKey is NOT called",
      spy.log,
      ["upsertIdentity i-new", "deleteIdentity i-new"],
    );
    check("no identity survives", h.identities(), []);
    check("the shared key survives, byte-identical", h.keys(), [sharedKey]);
    check("with both of its secrets, values included", sharedAccounts(h), [
      "PEM-BODY",
      "the-shared-passphrase",
    ]);
    check(
      "and the only vault accounts left are the shared key's own",
      [...h.kept.keys()].filter((k) => k.startsWith(`${VAULT_KEYRING_SERVICE}::`)).sort(),
      [
        `${VAULT_KEYRING_SERVICE}::k-shared::passphrase`,
        `${VAULT_KEYRING_SERVICE}::k-shared::privateKey`,
      ],
    );
    check(
      "the host's own accounts are untouched, values included",
      [
        h.kept.get(`${HOST_KEYRING_SERVICE}::h-1::password`),
        h.kept.get(`${HOST_KEYRING_SERVICE}::h-1::privateKey`),
        h.kept.get(`${HOST_KEYRING_SERVICE}::h-1::keyPassphrase`),
      ],
      ["hunter2", "PEM-BODY", "this-host-passphrase"],
    );

    // WHY THE CHECK ABOVE IS NOT INERT, done rather than argued. If the shared
    // key were undeletable here - because some identity still named it - then
    // "deleteKey was not called" would be a statement about the fixture rather
    // than about the code, and passing the reused id through would have been
    // harmless. It is not: nothing names this key, so the delete goes through,
    // and it takes both secrets with it. Run LAST in this block, because it
    // empties the store.
    await h.vault.deleteKey("k-shared");
    check(
      "proof the guard is not inert: deleting the shared key from here is NOT refused, so handing its id to the cleanup really would have destroyed it",
      h.keys(),
      [],
    );
    check("and its two secrets go with it", sharedAccounts(h), [undefined, undefined]);
  }

  // -- 10b.3: the mint path is byte-identical to what it was ---------------
  {
    const host = keyedHost();
    const h = harness({
      hosts: [host],
      keys: [sharedKey],
      kept: { ...hostKept, ...sharedKept },
    });
    const spy = convertSpy(h);
    const result = await convertHostToVault(
      {
        host,
        identity: { name: "shared", username: "root", domain: "", description: "" },
        key: { name: "prod key", facts: { fingerprint: "SHA256:AAAA" } },
      },
      spy.deps,
    );
    check("the vault write log, by value and in order - a key IS written", spy.log, [
      "upsertKey k-new",
      "upsertIdentity i-new",
    ]);
    check("all three copies, by value and in order", h.copies(), [
      `${HOST_KEYRING_SERVICE}::h-1::password -> ${VAULT_KEYRING_SERVICE}::i-new::password`,
      `${HOST_KEYRING_SERVICE}::h-1::privateKey -> ${VAULT_KEYRING_SERVICE}::k-new::privateKey`,
      `${HOST_KEYRING_SERVICE}::h-1::keyPassphrase -> ${VAULT_KEYRING_SERVICE}::k-new::passphrase`,
    ]);
    check(
      "the new key holds this host's own passphrase, and the shared record's is not involved",
      [
        h.kept.get(`${VAULT_KEYRING_SERVICE}::k-new::privateKey`),
        h.kept.get(`${VAULT_KEYRING_SERVICE}::k-new::passphrase`),
      ],
      ["PEM-BODY", "this-host-passphrase"],
    );
    check(
      "the same-fingerprint record already in the vault is byte-identical afterwards",
      h.keys().find((k) => k.id === "k-shared"),
      sharedKey,
    );
    check("and its accounts too, values included", sharedAccounts(h), [
      "PEM-BODY",
      "the-shared-passphrase",
    ]);
    check("the identity names the key that was minted", result.identity.keyId, "k-new");
    check("and the caller is handed that record", result.key?.id, "k-new");
    check("which is the record the store now holds", result.key?.name, "prod key");
  }

  // -- 10b.4: the candidate filter, by value -------------------------------
  {
    // `reusableVaultKey` is the ONLY thing in the app that produces a
    // `reuseKeyId`, so the `hasPrivateKey` condition is enforced here rather
    // than at the write. Pure, so it is checked by value.
    const withBody = vaultKey({
      id: "k-1",
      name: "laptop key",
      fingerprint: "SHA256:AAAA",
      hasPrivateKey: true,
    });
    const dupe = vaultKey({
      id: "k-1b",
      name: "laptop key (imported twice)",
      fingerprint: "SHA256:AAAA",
      hasPrivateKey: true,
    });
    const noBody = vaultKey({
      id: "k-2",
      name: "metadata only",
      fingerprint: "SHA256:AAAA",
      hasPrivateKey: false,
    });
    const otherFp = vaultKey({
      id: "k-3",
      name: "other",
      fingerprint: "SHA256:BBBB",
      hasPrivateKey: true,
    });
    const blankFp = vaultKey({ id: "k-4", name: "sealed", fingerprint: "", hasPrivateKey: true });
    const noFp = vaultKey({ id: "k-5", name: "no fingerprint", hasPrivateKey: true });

    check(
      "a fingerprint match that holds the body IS the candidate",
      reusableVaultKey([otherFp, withBody], { fingerprint: "SHA256:AAAA" })?.id,
      "k-1",
    );
    check(
      "a fingerprint match with hasPrivateKey:false is NOT a candidate - a record naming a key nobody holds must not be reused",
      reusableVaultKey([noBody], { fingerprint: "SHA256:AAAA" }),
      null,
    );
    check(
      "and it does not merely lose a race: with the bodyless record FIRST in the list, the one holding the body is still what comes back",
      reusableVaultKey([noBody, withBody], { fingerprint: "SHA256:AAAA" })?.id,
      "k-1",
    );
    check(
      "a non-matching fingerprint is not a candidate",
      reusableVaultKey([otherFp], { fingerprint: "SHA256:AAAA" }),
      null,
    );
    check("no fingerprint in hand, no candidate", reusableVaultKey([withBody], {}), null);
    check(
      "a blank fingerprint in hand is not a wildcard",
      reusableVaultKey([withBody, blankFp], { fingerprint: "" }),
      null,
    );
    check(
      "a blank fingerprint ON THE RECORD matches nothing either",
      reusableVaultKey([blankFp], { fingerprint: "SHA256:AAAA" }),
      null,
    );
    check(
      "nor does a record with no fingerprint at all",
      reusableVaultKey([noFp], { fingerprint: "SHA256:AAAA" }),
      null,
    );
    check(
      "and two blanks do not match each other",
      reusableVaultKey([blankFp], { fingerprint: "" }),
      null,
    );
    check(
      "the FIRST match wins when one fingerprint is on two records - the caller names which one it is offering",
      reusableVaultKey([withBody, dupe], { fingerprint: "SHA256:AAAA" })?.id,
      "k-1",
    );
    check(
      "an empty vault has no candidate",
      reusableVaultKey([], { fingerprint: "SHA256:AAAA" }),
      null,
    );
  }

  // -- 10b.5: a reuse id whose record is gone is refused BEFORE a byte moves -
  {
    // Reachable: the caller lists the vault's keys to build the offer, and
    // another window can delete the one it offered between that list and the
    // confirmation. Without this pre-check `upsertIdentity` refuses the dangling
    // `keyId` at step 7, AFTER step 5 has copied this host's password onto a
    // vault account no record will ever name - P0-1's shape, one door over.
    const host = keyedHost();
    const h = harness({ hosts: [host], kept: hostKept });
    await rejects(
      "a reuseKeyId naming a key that no longer exists is refused, naming the host and the id",
      () =>
        convertHostToVault(
          {
            host,
            identity: { name: "shared", username: "root", domain: "", description: "" },
            key: { reuseKeyId: "k-gone" },
          },
          h.deps,
        ),
      ["prod", "cannot reuse vault key", "k-gone", "no longer exists"],
    );
    check("no copy was issued at all - the refusal is a pre-check", h.copies(), []);
    check(
      "so no vault account was written",
      [...h.kept.keys()].filter((k) => k.startsWith(`${VAULT_KEYRING_SERVICE}::`)),
      [],
    );
    check("no vault identity exists", h.identities(), []);
    check("no vault key exists", h.keys(), []);
    check(
      "the host's own accounts are untouched, values included",
      [
        h.kept.get(`${HOST_KEYRING_SERVICE}::h-1::password`),
        h.kept.get(`${HOST_KEYRING_SERVICE}::h-1::privateKey`),
        h.kept.get(`${HOST_KEYRING_SERVICE}::h-1::keyPassphrase`),
      ],
      ["hunter2", "PEM-BODY", "this-host-passphrase"],
    );
    check("the stored host record is unchanged", h.hostRows(), [host]);
  }
}

// ===========================================================================
console.log(
  "\n[10c] convert's two vault writes claim the record is ABSENT, and the store enforces that claim",
);
{
  // Group 10 pins that convert MINTS fresh ids. That is a property of this
  // code, which any later edit is free to lose. `VAULT_STAMP_ABSENT` turns it
  // into a REFUSAL the store makes: `upsertKey`/`upsertIdentity` compare the
  // stamp inside their own write queue and throw `VaultRecordChangedError`
  // rather than overwriting a record another writer already put at that id.
  //
  // Reached today by nothing, and that is the point - both ids come out of the
  // store's own minters two statements before the write, so the guard is inert
  // in shipped code and only an INJECTED minter can drive it. That is
  // "correct-but-inert", not "unreachable": the day a caller hands convert an id
  // (a v3 import replaying a backup, say) it is the difference between a refusal
  // and a silent overwrite.

  const seededKey = vaultKey({
    id: "k-seed",
    name: "someone else's key",
    fingerprint: "SHA256:CCCC",
    hasPrivateKey: true,
    hasPassphrase: true,
  });
  const keyedHost = sshHost({
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

  // -- 10c.1: the key write -------------------------------------------------
  {
    const h = harness({
      hosts: [keyedHost],
      keys: [seededKey],
      kept: {
        [`${HOST_KEYRING_SERVICE}::h-1::privateKey`]: "PEM-BODY",
        [`${HOST_KEYRING_SERVICE}::h-1::keyPassphrase`]: "this-host-passphrase",
        [`${VAULT_KEYRING_SERVICE}::k-seed::privateKey`]: "OTHER-PEM",
        [`${VAULT_KEYRING_SERVICE}::k-seed::passphrase`]: "other-passphrase",
      },
    });
    const deps: CredentialMoveDeps = {
      ...h.deps,
      vault: { ...h.vault, newKeyId: () => "k-seed", newIdentityId: () => "i-new" },
    };
    let caught: unknown;
    try {
      await convertHostToVault(
        {
          host: keyedHost,
          identity: { name: "x", username: "root", domain: "", description: "" },
          key: { name: "new key", facts: {} },
        },
        deps,
      );
    } catch (e) {
      caught = e;
    }
    assert(
      caught instanceof VaultRecordChangedError,
      "the key write is REFUSED by type, not merely by a differing record afterwards",
    );
    const err = caught as VaultRecordChangedError;
    check("recordId, by value", err?.recordId, "k-seed");
    check(
      "expected, by value - convert's own claim that nothing is stored there",
      err?.expected,
      VAULT_STAMP_ABSENT,
    );
    check("actual, by value - what is really there", err?.actual, vaultKeyStamp(seededKey));
    check("the seeded key's record is byte-identical - the refusal precedes the write", h.keys(), [
      seededKey,
    ]);
    // Stated rather than left to be found: the stamp is over the RECORD, and
    // step 5's copies have already run by the time it fires, so this fixture
    // also shows what the guard does NOT cover. It costs nothing in shipped
    // code, where no id can collide; it is here so the next reader does not read
    // the guard as wider than it is.
    check(
      "and its ACCOUNTS were already overwritten by step 5's copy, which the stamp is not over",
      [
        h.kept.get(`${VAULT_KEYRING_SERVICE}::k-seed::privateKey`),
        h.kept.get(`${VAULT_KEYRING_SERVICE}::k-seed::passphrase`),
      ],
      ["PEM-BODY", "this-host-passphrase"],
    );
  }

  // -- 10c.2: the identity write -------------------------------------------
  {
    const seededIdentity = identity({ id: "i-seed", name: "someone else's identity" });
    const host = sshHost({ id: "h-1" });
    const h = harness({
      hosts: [host],
      identities: [seededIdentity],
      kept: { [`${HOST_KEYRING_SERVICE}::h-1::password`]: "hunter2" },
    });
    const deps: CredentialMoveDeps = {
      ...h.deps,
      vault: { ...h.vault, newIdentityId: () => "i-seed" },
    };
    let caught: unknown;
    try {
      await convertHostToVault(
        {
          host,
          identity: { name: "x", username: "root", domain: "", description: "" },
          key: null,
        },
        deps,
      );
    } catch (e) {
      caught = e;
    }
    assert(
      caught instanceof VaultRecordChangedError,
      "the identity write is REFUSED by type as well",
    );
    const err = caught as VaultRecordChangedError;
    check("recordId, by value", err?.recordId, "i-seed");
    check("expected, by value", err?.expected, VAULT_STAMP_ABSENT);
    check("actual, by value", err?.actual, vaultIdentityStamp(seededIdentity));
    check("the seeded identity is byte-identical afterwards", h.identities(), [seededIdentity]);
    check("and the host was never bound", h.hostRows(), [host]);
  }

  // -- 10c.3: the argument's own expression text ---------------------------
  {
    // ARGUMENT-WISE, never the whole call's text. Prettier adds a trailing comma
    // when it wraps a call across lines, and that comma sits INSIDE the
    // CallExpression's span but OUTSIDE every argument's own span - so a
    // whole-call pin reddens on a legal reflow while an argument-wise one does
    // not.
    //
    // Argument-wise is NOT SUFFICIENT ON ITS OWN, and the `--print-width 60`
    // control is what showed it: argument 0 here is ITSELF a four-argument call,
    // so at a narrow width Prettier wraps that inner call and puts a trailing
    // comma inside the argument's own span, where whitespace-stripping alone
    // does not reach. Measured: this section went to 1 FAIL over unchanged code.
    // So `norm` drops a comma that sits immediately before a closing paren as
    // well. That is formatting and only formatting - a trailing comma before `)`
    // never changes what a call means - and nothing else in the text is
    // normalised, because everything else IS the claim.
    //
    // The arity is checked and the loop `continue`s on a mismatch, so a fourth
    // argument added later reports ONE failure rather than silently skipping
    // every argument pin below it and passing for free.
    const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
    const movePath = join(repoRoot, "src/modules/hosts/credentialMove.ts");
    const moveSf = ts.createSourceFile(
      "credentialMove.ts",
      readFileSync(movePath, "utf8"),
      ts.ScriptTarget.ESNext,
      true,
      ts.ScriptKind.TS,
    );
    const findCalls = (root: ts.Node, callee: string): ts.CallExpression[] => {
      const out: ts.CallExpression[] = [];
      const visit = (n: ts.Node): void => {
        if (ts.isCallExpression(n) && n.expression.getText(moveSf) === callee) out.push(n);
        ts.forEachChild(n, visit);
      };
      visit(root);
      return out;
    };
    const norm = (s: string): string => s.replace(/\s+/g, "").replace(/,(?=\))/g, "");
    const pinArgs = (callee: string, expected: readonly [string, string, string]): void => {
      const calls = findCalls(moveSf, callee);
      check(`found exactly one ${callee}( call to pin`, calls.length, 1);
      for (const c of calls) {
        check(`${callee}( is called with exactly 3 arguments`, c.arguments.length, 3);
        if (c.arguments.length !== 3) continue;
        for (const [i, want] of expected.entries()) {
          check(
            `${callee}('s argument ${i} is exactly \`${want}\`, whitespace aside`,
            norm(c.arguments[i].getText(moveSf)),
            norm(want),
          );
        }
      }
    };
    pinArgs("deps.vault.upsertKey", [
      "keyRecordFrom(mintedKeyId, keyDraft, null, newKey.facts)",
      "keySecrets",
      "VAULT_STAMP_ABSENT",
    ]);
    pinArgs("deps.vault.upsertIdentity", [
      'identityRecordFrom(identityId, identityDraft, "keep")',
      "identitySecrets",
      "VAULT_STAMP_ABSENT",
    ]);

    // The two ids are what the stamp claim rests on, so the split itself is
    // pinned: `convertMoves` and the compensating delete take the id this call
    // MINTED, and only the identity draft takes the one it NAMES. Swapping
    // either is compile-clean and is the whole hazard of this feature.
    const movesCalls = findCalls(moveSf, "convertMoves");
    check("found exactly one convertMoves( call inside the module", movesCalls.length, 1);
    if (movesCalls.length === 1) {
      check(
        "convertMoves takes the MINTED key id, so a reused key's accounts are never a copy destination",
        movesCalls[0].arguments.map((a) => norm(a.getText(moveSf))),
        ["args.host", "identityId", "mintedKeyId"],
      );
    }
    const undoCalls = findCalls(moveSf, "undoConvertRecords");
    check("found exactly one undoConvertRecords( call", undoCalls.length, 1);
    if (undoCalls.length === 1) {
      check(
        "the compensating delete takes the MINTED key id, so a refused host write cannot destroy a key the user already had",
        undoCalls[0].arguments.map((a) => norm(a.getText(moveSf))),
        ["deps", "identityId", "mintedKeyId"],
      );
    }
  }
}

// ===========================================================================
/**
 * The one property of `HostEditorDialog.tsx` this file checks, and it is here
 * rather than beside the dialog's own checks because it is about THIS module's
 * contract.
 *
 * `convertHostToVault` copies the private key from the host's STORED account and
 * stamps whatever `facts` it is handed onto the record it mints. It cannot
 * compare the two: nothing here reads a secret (section [17]), so a fingerprint
 * describing a different key than the body arrives looking exactly like a
 * correct one. The only thing standing between the vault and a record that
 * DESCRIBES one key while HOLDING another is the condition its caller inspects
 * under, so that condition is pinned here, next to the contract it protects.
 *
 * Group [10e] below measures what such a record costs, and which half of the
 * remedy holds which part of it.
 */
console.log("\n[10d] the dialog inspects key facts ONLY from a body that is still the stored one");
{
  const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
  const dialogSf = ts.createSourceFile(
    "HostEditorDialog.tsx",
    readFileSync(join(repoRoot, "src/modules/hosts/HostEditorDialog.tsx"), "utf8"),
    ts.ScriptTarget.ESNext,
    true,
    ts.ScriptKind.TSX,
  );
  const norm = (s: string): string => s.replace(/\s+/g, "").replace(/,(?=\))/g, "");

  /** The body of `const <name> = (...) => ...`, or null. */
  const arrowBody = (name: string): ts.Node | null => {
    let found: ts.Node | null = null;
    const visit = (n: ts.Node): void => {
      if (
        ts.isVariableDeclaration(n) &&
        ts.isIdentifier(n.name) &&
        n.name.text === name &&
        n.initializer !== undefined &&
        (ts.isArrowFunction(n.initializer) || ts.isFunctionExpression(n.initializer))
      ) {
        found = n.initializer.body;
      }
      ts.forEachChild(n, visit);
    };
    visit(dialogSf);
    return found;
  };
  const callsTo = (root: ts.Node, callee: string): ts.CallExpression[] => {
    const out: ts.CallExpression[] = [];
    const visit = (n: ts.Node): void => {
      if (ts.isCallExpression(n) && n.expression.getText(dialogSf) === callee) out.push(n);
      ts.forEachChild(n, visit);
    };
    visit(root);
    return out;
  };
  /** `a && b && c` flattened. Anything else is ONE conjunct, so a condition
   *  that buries a ref inside an `||` or a `?:` does not answer these pins. */
  const conjuncts = (e: ts.Expression): string[] =>
    ts.isBinaryExpression(e) && e.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken
      ? [...conjuncts(e.left), ...conjuncts(e.right)]
      : [norm(e.getText(dialogSf))];

  // Asserted, never assumed: a rename would otherwise leave every check below
  // running over `null`, reporting nothing, and passing for free.
  const applyBody = arrowBody("applyCredentialChange");
  check("applyCredentialChange's body was found in the dialog", applyBody !== null, true);

  if (applyBody) {
    // COUNTED as well as rooted. Rooting excludes the second inspection
    // `offerKeyReuse` makes - a different question, over a body that may be
    // superseded - and only the count excludes a second, ungated one added
    // inside this function beside the gated one.
    const inspects = callsTo(applyBody, "inspectSshKey");
    check("exactly one inspectSshKey call inside applyCredentialChange", inspects.length, 1);

    if (inspects.length === 1) {
      const call = inspects[0];
      // STRUCTURAL POSITION, which is the half a presence check cannot buy: the
      // inspection has to sit INSIDE the gate's then-branch. Hoisting it one
      // statement out leaves every conjunct below still present, still exact,
      // and the guard doing nothing.
      const enclosing: ts.IfStatement[] = [];
      const visit = (n: ts.Node): void => {
        if (
          ts.isIfStatement(n) &&
          n.thenStatement.getStart(dialogSf) <= call.getStart(dialogSf) &&
          call.getEnd() <= n.thenStatement.getEnd()
        ) {
          enclosing.push(n);
        }
        ts.forEachChild(n, visit);
      };
      visit(applyBody);
      check(
        "and it is lexically inside the then-branch of at least one if - a hoisted inspection leaves the conjuncts below exact and inert",
        enclosing.length >= 1,
        true,
      );

      if (enclosing.length >= 1) {
        // The INNERMOST such `if` is the gate: the widest one is
        // `change.kind === "convert"`, which is a different claim.
        const gate = enclosing.reduce((a, b) =>
          b.thenStatement.getStart(dialogSf) >= a.thenStatement.getStart(dialogSf) ? b : a,
        );
        const parts = conjuncts(gate.expression);

        // TWO refs, TWO checks, because they are two facts and the file says so:
        // `sshSeeded` is what the keychain read put on SCREEN, `sshTouched` is
        // whether the user has changed it since. Dropping either one alone leaves
        // a body that is not the stored one being inspected, so each is pinned
        // against the mutation only it catches.
        check(
          "`sshSeeded.current.privateKey` is a top-level conjunct of that gate - facts are read only from a field the keychain read actually filled",
          parts.includes(norm("sshSeeded.current.privateKey")),
          true,
        );
        check(
          "`!sshTouched.current.privateKey` is a top-level conjunct of that gate - and only while the user has not typed over it since",
          parts.includes(norm("!sshTouched.current.privateKey")),
          true,
        );
        // The whole condition by value, so drift in the OTHER conjuncts is
        // visible too rather than hidden behind the two above. Reported as the
        // list, so a failure names what the gate actually says.
        check("the gate's conjuncts, by value and in order", parts, [
          norm("!reused"),
          norm('protocol === "ssh"'),
          norm("sshSeeded.current.privateKey"),
          norm("!sshTouched.current.privateKey"),
          norm("sshCred.privateKey.trim()"),
        ]);
      }
    }
  }
}

// ===========================================================================
/**
 * What a mis-described `VaultKey` costs, and which half of the remedy holds
 * which part of it. Every row here is over a record whose `fingerprint` does not
 * describe the body it holds.
 *
 * 1. THE HAZARD IS REAL, not inert. This module stamps the `facts` it is handed
 *    over the body it copies and has no way to disagree, so a caller inspecting
 *    an edited textarea mints exactly that record. Measured rather than argued,
 *    because "the dialog's gate matters" is a claim about consequences.
 * 2. THE CHAIN IS REAL. `reusableVaultKey` then OFFERS that record to the next
 *    host whose own body genuinely is the key it names - and the reuse path
 *    copies nothing while step 8 releases that host's accounts, so accepting the
 *    offer destroys the last copy of a key the record does not hold.
 * 3. THE BELT. Pre-check 4 re-asserts, on the record that actually resolves, the
 *    two conditions `reusableVaultKey` enforces when it makes the offer: a body
 *    is present, and a fingerprint is recorded. A record failing either is one no
 *    offer could have named.
 *
 * WHAT THE BELT DOES NOT CATCH, stated rather than left to be found: a record
 * that HAS a body and HAS a fingerprint, where that fingerprint describes
 * different material. Nothing in this module can see it - it reads no secret, so
 * it cannot compare a recorded fingerprint against a stored body, and the id it
 * is handed resolves to a record that satisfies every condition an honest offer
 * would. That case is closed at the producer, by group [10d]'s gate, and the belt
 * covers the rest: a bodyless record, a fingerprint-less record, and any
 * `reuseKeyId` that did not come from an offer at all.
 */
console.log("\n[10e] a mis-described key: the hazard, the chain, and what the write refuses");
{
  const keyedHost = sshHost({
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
  const hostKept = {
    [`${HOST_KEYRING_SERVICE}::h-1::password`]: "hunter2",
    [`${HOST_KEYRING_SERVICE}::h-1::privateKey`]: "PEM-OLD",
    [`${HOST_KEYRING_SERVICE}::h-1::keyPassphrase`]: "this-host-passphrase",
  };
  /** Every vault write, by name and id, in call order - group [10b]'s own
   *  discipline: "no identity was written" cannot be told from "written, then
   *  undone" by looking at the store afterwards. */
  const writeSpy = (h: ReturnType<typeof harness>) => {
    const log: string[] = [];
    const vault: CredentialMoveDeps["vault"] = {
      ...h.vault,
      newIdentityId: () => "i-new",
      newKeyId: () => "k-new",
      upsertKey: (...a: Parameters<VaultStore["upsertKey"]>) => {
        log.push(`upsertKey ${a[0].id}`);
        return h.vault.upsertKey(...a);
      },
      upsertIdentity: (...a: Parameters<VaultStore["upsertIdentity"]>) => {
        log.push(`upsertIdentity ${a[0].id}`);
        return h.vault.upsertIdentity(...a);
      },
    };
    return { log, deps: { ...h.deps, vault } };
  };

  // -- 10e.1: the hazard, measured - a stamped fingerprint the body does not have
  {
    const h = harness({ hosts: [keyedHost], kept: { ...hostKept } });
    const spy = writeSpy(h);
    // `SHA256:NEW` is the fingerprint of a key the user PASTED and never saved.
    // `PEM-OLD` is what the host's account actually holds, and what travels.
    const result = await convertHostToVault(
      {
        host: keyedHost,
        identity: { name: "shared", username: "root", domain: "", description: "" },
        key: {
          name: "prod key",
          facts: {
            fingerprint: "SHA256:NEW",
            publicKey: "ssh-ed25519 AAAANEW",
            keyType: "ed25519",
          },
        },
      },
      spy.deps,
    );
    check(
      "the record carries the facts it was HANDED, all three - this module stamps them and cannot disagree",
      [result.key?.fingerprint, result.key?.publicKey, result.key?.keyType],
      ["SHA256:NEW", "ssh-ed25519 AAAANEW", "ed25519"],
    );
    check(
      "while the account under it holds the STORED body, which is a different key entirely",
      h.kept.get(`${VAULT_KEYRING_SERVICE}::k-new::privateKey`),
      "PEM-OLD",
    );
    check(
      "and hasPrivateKey is true, so the record looks complete from every angle a reader has",
      result.key?.hasPrivateKey,
      true,
    );
    check("the key was written, so this is a stored record and not a return value", spy.log, [
      "upsertKey k-new",
      "upsertIdentity i-new",
    ]);

    // (2) THE CHAIN. A second host whose body really IS `SHA256:NEW` inspects it,
    // and this record is what the offer names. By value, over the stored record.
    const offered = reusableVaultKey(h.keys(), { fingerprint: "SHA256:NEW" });
    check(
      "and reusableVaultKey OFFERS it to the next host that really does hold SHA256:NEW - the chain is not hypothetical",
      offered?.id,
      "k-new",
    );
  }

  // -- 10e.2: the belt, first condition - a record with no body -------------
  {
    // Fingerprint present and matching, `hasPrivateKey` false: the state
    // `reusableVaultKey`'s second condition exists for, arriving at the write
    // anyway. A metadata-first import, or a record whose secret write failed.
    const bodyless = vaultKey({
      id: "k-nobody",
      name: "metadata only",
      fingerprint: "SHA256:AAAA",
      hasPrivateKey: false,
    });
    const h = harness({ hosts: [keyedHost], keys: [bodyless], kept: { ...hostKept } });
    const spy = writeSpy(h);
    await rejects(
      "the convert is REFUSED rather than releasing the host's key against a record that holds none",
      () =>
        convertHostToVault(
          {
            host: keyedHost,
            identity: { name: "shared", username: "root", domain: "", description: "" },
            key: { reuseKeyId: "k-nobody" },
          },
          spy.deps,
        ),
      ["cannot reuse vault key", "stores no private key"],
    );
    // BEFORE A BYTE MOVES, which is the whole reason this sits with the other
    // pre-checks: a refusal after step 5 leaves this host's password on a vault
    // account no record will ever name.
    check("no vault record was written", spy.log, []);
    check("nothing was copied at all", h.copies(), []);
    check(
      "the host keeps all three of its own accounts, values included - this is the loss the refusal prevents",
      [
        h.kept.get(`${HOST_KEYRING_SERVICE}::h-1::password`),
        h.kept.get(`${HOST_KEYRING_SERVICE}::h-1::privateKey`),
        h.kept.get(`${HOST_KEYRING_SERVICE}::h-1::keyPassphrase`),
      ],
      ["hunter2", "PEM-OLD", "this-host-passphrase"],
    );
    check("and its record is still inline, bound to nothing", h.hostRows(), [keyedHost]);
    check("the bodyless record is byte-identical afterwards", h.keys(), [bodyless]);
  }

  // -- 10e.3: the belt, second condition - a record with no fingerprint ----
  {
    // `hasPrivateKey` true and the fingerprint ABSENT, then BLANK. Both are
    // records `reusableVaultKey` refuses to offer ("a blank or absent fingerprint
    // matches nothing, on either side"), so both are ids that came from somewhere
    // other than an offer - and nothing about either one says it holds THIS
    // host's key.
    for (const [label, fingerprint] of [
      ["absent", undefined],
      ["blank", ""],
      ["whitespace", "   "],
    ] as const) {
      const unnamed = vaultKey({
        id: "k-nofp",
        name: "sealed import",
        fingerprint,
        hasPrivateKey: true,
      });
      const h = harness({ hosts: [keyedHost], keys: [unnamed], kept: { ...hostKept } });
      const spy = writeSpy(h);
      await rejects(
        `a fingerprint that is ${label} is REFUSED - nothing says that record holds this host's private key`,
        () =>
          convertHostToVault(
            {
              host: keyedHost,
              identity: { name: "shared", username: "root", domain: "", description: "" },
              key: { reuseKeyId: "k-nofp" },
            },
            spy.deps,
          ),
        ["cannot reuse vault key", "records no fingerprint"],
      );
      check(`(${label}) no vault record was written`, spy.log, []);
      check(`(${label}) nothing was copied at all`, h.copies(), []);
      check(
        `(${label}) the host keeps its private key and passphrase, values included`,
        [
          h.kept.get(`${HOST_KEYRING_SERVICE}::h-1::privateKey`),
          h.kept.get(`${HOST_KEYRING_SERVICE}::h-1::keyPassphrase`),
        ],
        ["PEM-OLD", "this-host-passphrase"],
      );
      // Proof the refusal is not inert: `reusableVaultKey` would never have
      // offered this record either, so the two agree - which is the property,
      // not a coincidence of the fixture.
      check(
        `(${label}) and reusableVaultKey would not have offered it either, whatever fingerprint is asked for`,
        reusableVaultKey([unnamed], { fingerprint: fingerprint ?? "" }),
        null,
      );
    }
  }

  // -- 10e.4: the arm that must still work ---------------------------------
  {
    // The belt refuses two shapes and NOTHING else. A record with a body and a
    // fingerprint reuses exactly as it did - stated as its own row, because a
    // guard that refused the good path too would be caught by group [10b] only
    // as a red gate, not as a statement about this change.
    const good = vaultKey({
      id: "k-good",
      name: "laptop key",
      fingerprint: "SHA256:AAAA",
      hasPrivateKey: true,
      hasPassphrase: true,
    });
    const h = harness({ hosts: [keyedHost], keys: [good], kept: { ...hostKept } });
    const spy = writeSpy(h);
    const result = await convertHostToVault(
      {
        host: keyedHost,
        identity: { name: "shared", username: "root", domain: "", description: "" },
        key: { reuseKeyId: "k-good" },
      },
      spy.deps,
    );
    check("a record with a body and a fingerprint still reuses", result.identity.keyId, "k-good");
    check("with no key write of any kind", spy.log, ["upsertIdentity i-new"]);
    check("and the caller is handed that record, byte-identical", result.key, good);
  }
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

  // ---------------------------------------------------------------------------
  // THE GUARD'S OTHER MISTAKE - declining when it should proceed. `h-5` above
  // covers the direction where `stored` exists and is inline, so the cleanup
  // must DECLINE. This fixture covers the direction nothing above does: `stored`
  // is GONE - the host being detached is not in the store at all when the
  // cleanup re-reads it - and the guard's own doc says the cleanup must still
  // run, because nothing names the copied accounts either. Mutation J2
  // (`if (!stored) return;`) breaks both directions at once; only `h-5` used to
  // redden for it, because every other `[13b]` fixture seeds a stored record.
  //
  // Seeded with a DIFFERENT host rather than an empty store, so the absence is
  // shown to be specific to h-1 rather than an artefact of an empty list. The
  // refusal is the same dangling `proxyJumpId` the rest of this group uses:
  // `assertReferences` reads the store's own host list fresh, so it fires
  // whether or not h-1 itself is in that list, and it fires AFTER `copyMoves`
  // has already run - which is why `landedCopies` below is checked first, and
  // must be 3: an undo of nothing passes every absence check for free.
  // ---------------------------------------------------------------------------
  const hGone = harness({
    hosts: [sshHost({ id: "h-other" })],
    identities: [idn],
    keys: [key],
    kept: vaultKept,
  });
  await rejects(
    "detach is refused by the same jump-host check when the host itself is gone from the store",
    () =>
      detachHostFromVault(
        { host: boundHost, inline: { user: "root", authMode: "key" } },
        hGone.deps,
      ),
    ["names a jump host", "does not exist"],
  );
  check("all three secrets landed on the host's accounts first", landedCopies(hGone), 3);
  check(
    "and the cleanup ran anyway, taking back exactly those three accounts, in order",
    hostDeletes(hGone),
    ["h-1::password", "h-1::privateKey", "h-1::keyPassphrase"],
  );
  check("no host account holds a secret", keptFor(hGone, HOST_KEYRING_SERVICE), []);
  check(
    "the copied PRIVATE KEY was taken back - the one that would be a shared secret stranded with nothing to name it",
    hGone.kept.has(`${HOST_KEYRING_SERVICE}::h-1::privateKey`),
    false,
  );
  check("the identity record is byte-identical", hGone.identities(), [idn]);
  check("the key record is byte-identical", hGone.keys(), [key]);
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
//
// --- mutation table (the fingerprint-dedupe round, sections 10b and 10c) ----
//
//   Mutation                                          Check(s) it killed
//   -------------------------------------------------  ---------------------------
//   K1: the reuse path calls upsertKey anyway -        NOT the log check, but
//     mintedKeyId falls back to the reused id and       10c's stamp guard: the
//     the key upsert loses its `newKey` condition       script ABORTS on an
//                                                       uncaught
//                                                       VaultRecordChangedError
//                                                       over the reused record.
//                                                       A red gate, from the
//                                                       guard rather than from
//                                                       the property, so it was
//                                                       re-run as K1b.
//   K1b: the same, with the stamp relaxed on that      12 FAILs, `tsc` at 0.
//     arm (`newKey ? VAULT_STAMP_ABSENT : undefined`)   10b.1's write log first,
//     - the shape an author adding reuse would write    then the copies, the
//                                                       shared key's accounts,
//                                                       its record (the mutation
//                                                       WIPES its fingerprint),
//                                                       the return value, and
//                                                       10b.2's delete log -
//                                                       where the shared key and
//                                                       both of its secrets are
//                                                       gone.
//   K2: convertMoves handed namedKeyId instead of      5 FAILs, `tsc` at 0. The
//     mintedKeyId - direction 1, the copy onto a        copies by value, the
//     shared key's own accounts                         shared key's two
//                                                       accounts (the passphrase
//                                                       is this host's, not the
//                                                       record's), and 10c.3's
//                                                       convertMoves argument
//                                                       pin.
//   K3: reusableVaultKey's `hasPrivateKey` condition   2 FAILs, `tsc` at 0. Both
//     dropped from the candidate filter                 of 10b.4's bodyless-record
//                                                       rows, including the one
//                                                       that puts the bodyless
//                                                       record FIRST.
//   K4: VAULT_STAMP_ABSENT replaced with undefined     13 FAILs, and `tsc`
//     at both upserts                                   flags the now-unused
//                                                       import. 10c.1 and 10c.2
//                                                       show what the guard
//                                                       stops: the seeded key
//                                                       comes back renamed "new
//                                                       key" with its
//                                                       fingerprint gone, the
//                                                       seeded identity is
//                                                       overwritten, and the host
//                                                       is bound to it.
//   K5: undoConvertRecords handed namedKeyId -         5 FAILs, `tsc` at 0.
//     direction 2, the compensating delete pointed      10b.2's delete log, the
//     at a key that existed before this call            shared key's survival,
//                                                       both of its secrets, and
//                                                       10c.3's undoConvertRecords
//                                                       argument pin.
//   K6: a Prettier reflow at --print-width 60 over     NOTHING - after the fix
//     the whole module (§4.51's pair for 10c.3's        below. Before it, ONE
//     exact-text pins)                                  FAIL over unchanged code:
//                                                       argument 0 is itself a
//                                                       four-argument call, and a
//                                                       narrow width wraps it and
//                                                       puts a trailing comma
//                                                       INSIDE that argument's
//                                                       own span, where
//                                                       argument-wise pinning
//                                                       does not reach. `norm`
//                                                       now drops a comma before
//                                                       a closing paren too.
//
// And two over `HostEditorDialog.tsx`. Group [10d] is now the one thing this
// file checks there, and it does not cover either of these; `host-editor-verify.ts`
// does not either - recorded because a green mutation is a statement about the
// CHECKS, and both of these are cause 1, "the check is weak", not "unreachable"
// and not "inert":
//
//   K7: the dialog reuses whenever a candidate exists,  NOTHING. `pnpm verify`
//     ignoring the checkbox the user did or did not     credential-move-verify
//     tick                                              and host-editor-verify
//                                                       both stay green, `tsc` at
//                                                       0. This is the row's own
//                                                       premise - the decision is
//                                                       the USER'S - and nothing
//                                                       holds it.
//   K8: the reuse lookup's generation guard deleted,    NOTHING from either
//     so an answer for the previous row can land on     script; `tsc` alone,
//     this one                                          for the now-unused
//                                                       binding. A guard deleted
//                                                       WITH its binding would be
//                                                       invisible.
//
// --- mutation table (the mis-described-key round, groups 10d and 10e) -------
//
// Two producers of a `VaultKey` that DESCRIBES one key and HOLDS another: the
// dialog inspecting an edited textarea while the stored account travels, and a
// `reuseKeyId` naming a record no offer could have made. Both were green here
// before these groups existed - this file was at 243 ok / 0 FAIL.
//
//   Mutation                                          Check(s) it killed
//   -------------------------------------------------  ---------------------------
//   M1: the dialog's gate reverted to                  THREE, all in 10d: both
//     `!reused && protocol === "ssh" &&                 conjunct rows and the
//     sshCred.privateKey.trim()` - facts inspected      by-value list, which
//     from the draft however it got there               reports the gate it
//                                                       actually found. `tsc` at 0.
//   M1a: `sshSeeded.current.privateKey` dropped        the sshSeeded row and the
//     alone                                             list. `tsc` at 0.
//   M1b: `!sshTouched.current.privateKey` dropped      the sshTouched row and the
//     alone                                             list. `tsc` at 0. Run
//                                                       separately from M1a
//                                                       because they are two
//                                                       facts, not one wearing
//                                                       two names.
//   M1c: the gate KEPT verbatim, governing an          the same three rows, with
//     unrelated statement, and the inspection           the list reporting
//     hoisted out from under it                         `change.kind==="convert"`
//                                                       - the innermost `if` that
//                                                       still contains the call.
//                                                       This is the mutation the
//                                                       structural half catches
//                                                       and a presence check over
//                                                       the file cannot: every
//                                                       conjunct is still there,
//                                                       spelled exactly, and inert.
//                                                       `tsc` at 0.
//   M2a: pre-check 4's `hasPrivateKey` test dropped,   FIVE, all in 10e.2 and
//     the fingerprint test left in place                none in 10e.3: the refusal
//                                                       "did not reject", the
//                                                       identity write, the
//                                                       password copy, and the
//                                                       host's three accounts -
//                                                       all three `undefined`
//                                                       afterwards, which is the
//                                                       loss itself. `tsc` at 0.
//   M2b: the fingerprint test dropped, `hasPrivateKey` TWELVE, all in 10e.3 and
//     left in place                                     none in 10e.2 - four rows
//                                                       per fingerprint shape
//                                                       (absent, blank,
//                                                       whitespace). `tsc` at 0.
//   M3: `prettier --print-width 60` and then `20`      NOTHING in 10d or 10e, at
//     over the whole dialog - the reformat pair         either width, with the file
//     10d's exact pins owe                             measurably changed both
//                                                       times (629 and 3469 diff
//                                                       lines). Width 20 is the
//                                                       one that measures
//                                                       something: it breaks the
//                                                       PINNED spans themselves
//                                                       (`sshSeeded` / `.current` /
//                                                       `.privateKey` onto three
//                                                       lines), where 60 only
//                                                       wraps the call under them.
//                                                       It DID redden 25 checks in
//                                                       `host-editor-verify.ts` at
//                                                       60, and 79 there plus 5 in
//                                                       `key-inspect-verify.ts` and
//                                                       20 in
//                                                       `rdp-lifetime-verify.ts` at
//                                                       20 - measured against the
//                                                       UNMODIFIED dialog first and
//                                                       identical on both sides, so
//                                                       every one of them is
//                                                       pre-existing and none is
//                                                       this round's.
//   M4: `applyCredentialChange` renamed, so 10d's      ONE, loudly: "applyCredential
//     anchor resolves to nothing                        Change's body was found in
//                                                       the dialog". The five rows
//                                                       under it then do not run,
//                                                       which is why the anchor is
//                                                       asserted rather than
//                                                       assumed - a rooted region
//                                                       that resolves to nothing
//                                                       otherwise passes for free.
