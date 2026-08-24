/**
 * Self-check for the vault store, its credential resolver, and the store-file
 * crash recovery they sit on. Run: `npx tsx scripts/vault-resolve-verify.ts`.
 *
 * Every property here is one whose failure is SILENT, which is why they are
 * pinned before any UI exists:
 *
 * 1. IDENTITY -> KEY RESOLUTION. An identity holds a `keyId`; the key holds the
 *    key material. A resolver that read the key material from the IDENTITY's
 *    accounts finds nothing and fails the handshake as "no credentials", on a
 *    path that looks like it read the keychain correctly.
 *
 * 2. DELETE-IN-USE IS REFUSED, both directions, and the refusal NAMES the
 *    holders. Refuse rather than cascade: a cascade turns one confirmed delete
 *    into hosts that can no longer connect, discovered days later by whoever
 *    tries to use one. A refusal that does not name them is nearly as bad -
 *    there is no way to act on "still in use".
 *
 * 3. PRESENCE FLAGS TRACK WRITES, and are never computed by reading a secret
 *    back. They exist so a list screen costs zero `secrets_get` calls; a
 *    read-back on the no-change path spends exactly what they were added to
 *    save, and the three-state convention (`undefined` = leave it alone) is what
 *    stops an edit that never touched a password field from wiping it.
 *
 * 4. A TORN STORE FILE RECOVERS. tauri-plugin-store writes in place with no temp
 *    file and no fsync, and swallows the load error of a file it cannot parse -
 *    so a zeroed or nul-filled file comes back as an EMPTY store and the next
 *    autosave makes that permanent. For the vault that means a private key left
 *    in the keychain with no record naming it.
 *
 * 5. RDP RESOLVES TO A REFERENCE, never a value, for both binding kinds. The
 *    Phase 5 invariant is that an RDP password never enters the webview; here it
 *    holds by construction, so what is checked is that the reference names the
 *    right SERVICE - vault-owned and host-owned secrets live in different ones,
 *    and a wrong service reads as "no password stored" at connect time.
 *
 * 6. SSH RESOLVES TO VALUES in the `SshCredentialValues` shape, for all three
 *    auth modes. That mapping is the line deciding whether a key or a password
 *    reaches the handshake, and a mode that returns nothing connects with no
 *    credentials at all.
 *
 * The store and secrets access are injectable ports, so all of this runs under
 * plain node with no Tauri runtime and no mocking library.
 */
import {
  recoverStoreFile,
  snapshotStoreFile,
  type StoreFileIo,
  type StoreFileRead,
} from "../src/lib/storeRecovery";
import type { SecretsIo, VaultStoreIo } from "../src/modules/vault/adapters";
import { resolveRdpAuth, resolveSshAuth, type ResolveDeps } from "../src/modules/vault/resolve";
import { createVaultStore } from "../src/modules/vault/store";
import {
  VaultInUseError,
  type VaultIdentity,
  type VaultKey,
  type VaultRef,
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
// In-memory ports. `SecretsIo` has no single-value read at all, so the store
// layer CANNOT compute a flag by reading a secret back; the call log is what
// proves it does not batch-read one either.
// ---------------------------------------------------------------------------

type SecretCall = { op: "getAll" | "set" | "delete"; service: string; accounts: string[] };

function harness(seed: { identities?: VaultIdentity[]; keys?: VaultKey[] } = {}) {
  const data: Record<string, unknown> = {
    identities: seed.identities ?? [],
    keys: seed.keys ?? [],
  };
  const kept = new Map<string, string>();
  const calls: SecretCall[] = [];
  const listeners = new Set<() => void>();
  let commits = 0;

  const store: VaultStoreIo = {
    async get<T>(key: string): Promise<T | null> {
      return (data[key] as T | undefined) ?? null;
    },
    async set(key: string, value: unknown): Promise<void> {
      data[key] = value;
    },
    async commit(): Promise<void> {
      commits++;
      for (const l of listeners) l();
    },
    async onChanged(cb: () => void): Promise<() => void> {
      listeners.add(cb);
      return () => void listeners.delete(cb);
    },
    takeRecoveryNotice: () => null,
  };

  const secrets: SecretsIo = {
    async getAll(service, accounts) {
      calls.push({ op: "getAll", service, accounts });
      return accounts.map((a) => kept.get(`${service}::${a}`) ?? null);
    },
    async set(service, account, value) {
      calls.push({ op: "set", service, accounts: [account] });
      kept.set(`${service}::${account}`, value);
    },
    async delete(service, account) {
      calls.push({ op: "delete", service, accounts: [account] });
      kept.delete(`${service}::${account}`);
    },
  };

  const vault = createVaultStore({ store, secrets });
  const reads = () => calls.filter((c) => c.op === "getAll");
  return {
    vault,
    secrets,
    kept,
    calls,
    data,
    commits: () => commits,
    deps: (): ResolveDeps => ({ vault, secrets }),
    reads,
    /** The batch the resolution under test just issued. */
    lastRead: (): SecretCall | undefined => {
      const all = reads();
      return all.length > 0 ? all[all.length - 1] : undefined;
    },
  };
}

const identity = (over: Partial<VaultIdentity> = {}): VaultIdentity => ({
  id: "i-1",
  name: "root @ prod",
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

// ---------------------------------------------------------------------------
console.log("\n[ids] a new record gets an opaque, prefixed id");
{
  const h = harness();
  assert(/^i-[a-z0-9]{8,}$/.test(h.vault.newIdentityId()), "identity ids are i-prefixed");
  assert(/^k-[a-z0-9]{8,}$/.test(h.vault.newKeyId()), "key ids are k-prefixed");
  assert(h.vault.newIdentityId() !== h.vault.newIdentityId(), "two ids differ");
}

// ---------------------------------------------------------------------------
console.log("\n[flags] presence flags track writes, and never read a secret back");
{
  const h = harness();
  const key = vaultKey();

  const created = await h.vault.upsertKey(key, { privateKey: "PEM-BODY", passphrase: "hunter2" });
  check("a written private key sets hasPrivateKey", created.record.hasPrivateKey, true);
  check("a written passphrase sets hasPassphrase", created.record.hasPassphrase, true);
  check(
    "the private key landed on the vault service",
    h.kept.get("tervia-vault::k-1::privateKey"),
    "PEM-BODY",
  );
  check("the passphrase landed beside it", h.kept.get("tervia-vault::k-1::passphrase"), "hunter2");
  check("no secret was read to decide either flag", h.reads().length, 0);

  // The three-state convention: `undefined` must leave the stored secret alone
  // AND keep the flag, without reading anything.
  const untouched = await h.vault.upsertKey({ ...created.record, name: "renamed" }, {});
  check("an edit that skips the fields keeps hasPrivateKey", untouched.record.hasPrivateKey, true);
  check("and keeps hasPassphrase", untouched.record.hasPassphrase, true);
  check("the secret is still there", h.kept.get("tervia-vault::k-1::privateKey"), "PEM-BODY");
  check("and still nothing was read back", h.reads().length, 0);

  // A blank string is the clear, not a no-op.
  const cleared = await h.vault.upsertKey(untouched.record, { passphrase: "" });
  check("a blank passphrase clears the flag", cleared.record.hasPassphrase, false);
  check("and removes the entry", h.kept.has("tervia-vault::k-1::passphrase"), false);
  check("without disturbing the private key", cleared.record.hasPrivateKey, true);
  check("still no read-back", h.reads().length, 0);

  // A brand-new record with no input starts false rather than inheriting.
  const fresh = await h.vault.upsertKey(vaultKey({ id: "k-2", name: "other" }), {});
  check(
    "a new key with no secrets has both flags false",
    [fresh.record.hasPrivateKey, fresh.record.hasPassphrase],
    [false, false],
  );

  const ident = await h.vault.upsertIdentity(identity(), { password: "s3cret" });
  check("a written identity password sets hasPassword", ident.record.hasPassword, true);
  check(
    "stored under the identity's own account",
    h.kept.get("tervia-vault::i-1::password"),
    "s3cret",
  );
  const kept = await h.vault.upsertIdentity({ ...ident.record, name: "root @ prod (renamed)" }, {});
  check("an identity edit that skips the password keeps the flag", kept.record.hasPassword, true);
  check("no read-back on the identity path either", h.reads().length, 0);
}

// ---------------------------------------------------------------------------
console.log("\n[names] a duplicate key name is warned about, not refused");
{
  const h = harness();
  const first = await h.vault.upsertKey(vaultKey(), { privateKey: "A" });
  check("the first key gets no warning", first.warning, undefined);

  const dup = await h.vault.upsertKey(vaultKey({ id: "k-2", name: " ID_Ed25519 " }), {
    privateKey: "B",
  });
  check(
    "a colliding name warns, case- and space-insensitively",
    dup.warning,
    'another key is already named "id_ed25519"',
  );
  check("and the write still happened", (h.data.keys as VaultKey[]).length, 2);

  // A key must not collide with ITSELF: renaming is how the user fixes the
  // warning above, and a rename that always warns is a warning nobody reads.
  const solo = harness();
  const only = await solo.vault.upsertKey(vaultKey(), { privateKey: "A" });
  const resaved = await solo.vault.upsertKey({ ...only.record, description: "edited" }, {});
  check("a key does not collide with itself on re-save", resaved.warning, undefined);
}

// ---------------------------------------------------------------------------
console.log("\n[integrity] an identity may never name a key that does not exist");
{
  const h = harness();
  await rejects(
    "key auth with no keyId is refused",
    () => h.vault.upsertIdentity(identity({ authMode: "key" }), {}),
    ["names no key"],
  );
  await rejects(
    "a dangling keyId is refused",
    () => h.vault.upsertIdentity(identity({ authMode: "key", keyId: "k-gone" }), {}),
    ["does not exist"],
  );
  check("nothing was written", (h.data.identities as VaultIdentity[]).length, 0);

  await h.vault.upsertKey(vaultKey(), { privateKey: "PEM" });
  const ok = await h.vault.upsertIdentity(identity({ authMode: "key", keyId: "k-1" }), {});
  check("a real keyId is accepted", ok.record.keyId, "k-1");
}

// ---------------------------------------------------------------------------
console.log("\n[integrity] deleting something still in use is refused, and names the holders");
{
  const h = harness();
  await h.vault.upsertKey(vaultKey(), { privateKey: "PEM", passphrase: "pp" });
  await h.vault.upsertIdentity(identity({ authMode: "key", keyId: "k-1" }), {});
  await h.vault.upsertIdentity(
    identity({ id: "i-2", name: "deploy", username: "deploy", authMode: "key", keyId: "k-1" }),
    {},
  );

  await rejects(
    "a key held by two identities refuses, naming both",
    () => h.vault.deleteKey("k-1"),
    ["cannot delete", "id_ed25519", "2 identities", "root @ prod", "deploy"],
  );
  check("the key survived the refusal", (h.data.keys as VaultKey[]).length, 1);
  check("and so did its private key", h.kept.get("tervia-vault::k-1::privateKey"), "PEM");

  // The typed error carries the holders, so a dialog can offer to open them.
  try {
    await h.vault.deleteKey("k-1");
  } catch (e) {
    assert(e instanceof VaultInUseError, "the refusal is a VaultInUseError");
    check("carrying the holders", (e as VaultInUseError).holders, [
      { id: "i-1", name: "root @ prod" },
      { id: "i-2", name: "deploy" },
    ]);
  }

  // The other direction. Hosts arrive through the INJECTED lookup, because the
  // host store does not exist yet and will import from this module when it does.
  const hosts: VaultRef[] = [
    { id: "h-1", name: "prod-web" },
    { id: "h-2", name: "prod-db" },
  ];
  await rejects(
    "an identity held by two hosts refuses, naming both",
    () => h.vault.deleteIdentity("i-1", () => hosts),
    ["cannot delete", "root @ prod", "2 hosts", "prod-web", "prod-db"],
  );
  check("the identity survived", (h.data.identities as VaultIdentity[]).length, 2);

  await rejects(
    "one holder reads as singular",
    () => h.vault.deleteIdentity("i-1", () => [hosts[0]]),
    ["1 host (prod-web)"],
  );
  // An async lookup is what the real host store will hand over.
  await rejects(
    "an async lookup is awaited, not truthy-tested",
    () => h.vault.deleteIdentity("i-1", () => Promise.resolve(hosts)),
    ["prod-web"],
  );

  // Clear the references and the delete goes through, secrets and all.
  await h.vault.upsertIdentity(identity({ id: "i-1", name: "root @ prod" }), { password: "pw" });
  check("the identity's password is stored", h.kept.has("tervia-vault::i-1::password"), true);
  await h.vault.deleteIdentity("i-1", () => []);
  check(
    "an unreferenced identity deletes",
    (h.data.identities as VaultIdentity[]).map((i) => i.id),
    ["i-2"],
  );
  check("and its password goes with it", h.kept.has("tervia-vault::i-1::password"), false);

  await h.vault.deleteIdentity("i-2", () => []);
  await h.vault.deleteKey("k-1");
  check("an unreferenced key deletes", (h.data.keys as VaultKey[]).length, 0);
  check("private key removed", h.kept.has("tervia-vault::k-1::privateKey"), false);
  check("passphrase removed", h.kept.has("tervia-vault::k-1::passphrase"), false);

  // A missing id is a no-op, not a throw: the record was deleted in another window.
  await h.vault.deleteKey("k-gone");
  await h.vault.deleteIdentity("i-gone", () => hosts);
  console.log("  ok: deleting a record that is already gone is a no-op");
}

// ---------------------------------------------------------------------------
console.log("\n[queue] concurrent writes are serialized, not interleaved");
{
  // Two upserts in the same tick both read-modify-write the same list. Without
  // the serialized queue the second read happens before the first write lands and
  // one of the two records is simply lost - which on a vault page with inline
  // edits is the ordinary case, not a rare one.
  const h = harness();
  await Promise.all([
    h.vault.upsertKey(vaultKey({ id: "k-1", name: "a" }), { privateKey: "A" }),
    h.vault.upsertKey(vaultKey({ id: "k-2", name: "b" }), { privateKey: "B" }),
    h.vault.upsertKey(vaultKey({ id: "k-3", name: "c" }), { privateKey: "C" }),
  ]);
  check("all three writes survive", (await h.vault.listKeys()).map((k) => k.id).sort(), [
    "k-1",
    "k-2",
    "k-3",
  ]);
}

// ---------------------------------------------------------------------------
console.log("\n[ssh] resolution hands back the authFields shape for every auth mode");
{
  const h = harness();
  await h.vault.upsertKey(vaultKey(), { privateKey: "PRIVATE-PEM", passphrase: "pp" });
  await h.vault.upsertIdentity(identity({ id: "i-pw", name: "pw", username: "alice" }), {
    password: "alice-pw",
  });
  await h.vault.upsertIdentity(
    identity({ id: "i-key", name: "key", username: "bob", authMode: "key", keyId: "k-1" }),
    {},
  );
  await h.vault.upsertIdentity(
    identity({ id: "i-agent", name: "agent", username: "carol", authMode: "agent" }),
    {},
  );

  const before = h.reads().length;
  check(
    "an agent identity resolves to useAgent and nothing else",
    await resolveSshAuth({ kind: "identity", identityId: "i-agent" }, "h-1", h.deps()),
    { user: "carol", useAgent: true },
  );
  check("and reads no secret at all", h.reads().length - before, 0);

  check(
    "a password identity resolves to its own password",
    await resolveSshAuth({ kind: "identity", identityId: "i-pw" }, "h-1", h.deps()),
    { user: "alice", password: "alice-pw" },
  );
  check("from the identity's vault account, in one batch", h.lastRead(), {
    op: "getAll",
    service: "tervia-vault",
    accounts: ["i-pw::password"],
  });

  // Property 1: the key material comes from the KEY's accounts, not the
  // identity's, and the identity's username still wins.
  check(
    "a key identity resolves to the shared key's secrets",
    await resolveSshAuth({ kind: "identity", identityId: "i-key" }, "h-1", h.deps()),
    { user: "bob", privateKey: "PRIVATE-PEM", privateKeyPassphrase: "pp" },
  );
  check("read from the KEY's accounts, in one batch", h.lastRead(), {
    op: "getAll",
    service: "tervia-vault",
    accounts: ["k-1::privateKey", "k-1::passphrase"],
  });

  // A missing secret must come back as undefined, not "", so the backend's
  // explicit "no credentials" guard fires instead of an empty password attempt.
  await h.vault.upsertIdentity(identity({ id: "i-empty", name: "empty", username: "dave" }), {});
  check(
    "an absent password resolves to undefined, not an empty string",
    await resolveSshAuth({ kind: "identity", identityId: "i-empty" }, "h-1", h.deps()),
    { user: "dave", password: undefined },
  );

  // Inline bindings read the HOST's own accounts on the host service.
  check(
    "an inline agent binding needs no keychain",
    await resolveSshAuth(
      {
        kind: "inline",
        user: "eve",
        authMode: "agent",
        hasPassword: false,
        hasPrivateKey: false,
        hasKeyPassphrase: false,
      },
      "h-9",
      h.deps(),
    ),
    { user: "eve", useAgent: true },
  );

  h.kept.set("tervia-hosts::h-9::password", "host-pw");
  h.kept.set("tervia-hosts::h-9::privateKey", "host-pem");
  h.kept.set("tervia-hosts::h-9::keyPassphrase", "host-pp");
  check(
    "an inline password binding reads the host's account",
    await resolveSshAuth(
      {
        kind: "inline",
        user: "eve",
        authMode: "password",
        hasPassword: true,
        hasPrivateKey: false,
        hasKeyPassphrase: false,
      },
      "h-9",
      h.deps(),
    ),
    { user: "eve", password: "host-pw" },
  );
  check("on the hosts service", h.lastRead(), {
    op: "getAll",
    service: "tervia-hosts",
    accounts: ["h-9::password"],
  });
  check(
    "an inline key binding reads the host's key material",
    await resolveSshAuth(
      {
        kind: "inline",
        user: "eve",
        authMode: "key",
        hasPassword: false,
        hasPrivateKey: true,
        hasKeyPassphrase: true,
      },
      "h-9",
      h.deps(),
    ),
    { user: "eve", privateKey: "host-pem", privateKeyPassphrase: "host-pp" },
  );
  check("using the host store's keyPassphrase field name", h.lastRead(), {
    op: "getAll",
    service: "tervia-hosts",
    accounts: ["h-9::privateKey", "h-9::keyPassphrase"],
  });

  // A binding left pointing at a deleted record must say so rather than connect
  // with nothing.
  await rejects(
    "a binding to a deleted identity refuses",
    () => resolveSshAuth({ kind: "identity", identityId: "i-gone" }, "h-1", h.deps()),
    ["no longer exists"],
  );
  await h.vault.upsertIdentity(
    identity({ id: "i-dangle", name: "dangle", username: "f", authMode: "key", keyId: "k-1" }),
    {},
  );
  (h.data.keys as VaultKey[]).length = 0;
  await rejects(
    "a key deleted out from under an identity refuses",
    () => resolveSshAuth({ kind: "identity", identityId: "i-dangle" }, "h-1", h.deps()),
    ["dangle", "no longer exists"],
  );
}

// ---------------------------------------------------------------------------
console.log("\n[rdp] resolution hands back a keychain REFERENCE, never a value");
{
  const h = harness();
  await h.vault.upsertIdentity(
    identity({ id: "i-dc", name: "dc admin", username: "administrator", domain: "CORP" }),
    { password: "dc-pw" },
  );
  await h.vault.upsertIdentity(
    identity({ id: "i-local", name: "local", username: "user@corp.example" }),
    { password: "upn-pw" },
  );

  const before = h.reads().length;
  check(
    "an identity binding references the VAULT service and the identity's account",
    await resolveRdpAuth({ kind: "identity", identityId: "i-dc" }, "h-1", h.deps()),
    {
      username: "administrator",
      domain: "CORP",
      credential: { kind: "keychain", service: "tervia-vault", account: "i-dc::password" },
    },
  );
  check(
    "an inline binding references the HOSTS service and the host's account",
    await resolveRdpAuth(
      { kind: "inline", username: "admin", domain: "WORKGROUP", hasPassword: true },
      "h-42",
      h.deps(),
    ),
    {
      username: "admin",
      domain: "WORKGROUP",
      credential: { kind: "keychain", service: "tervia-hosts", account: "h-42::password" },
    },
  );
  // The invariant, stated as a measurement: resolving RDP spends no keychain
  // read, so there is no value that could have entered the webview.
  check("resolving RDP reads no secret at all", h.reads().length - before, 0);

  check(
    "a UPN identity omits domain rather than sending an empty one",
    "domain" in
      (await resolveRdpAuth({ kind: "identity", identityId: "i-local" }, "h-1", h.deps())),
    false,
  );
  check(
    "an inline binding with no domain omits it too",
    "domain" in
      (await resolveRdpAuth({ kind: "inline", username: "u", hasPassword: true }, "h-7", h.deps())),
    false,
  );

  // hasPassword is independent of authMode on purpose: one account can be a key
  // over SSH and the same password over RDP, which is why sharing an identity
  // across protocols is worth anything.
  await h.vault.upsertKey(vaultKey(), { privateKey: "PEM" });
  await h.vault.upsertIdentity(
    identity({ id: "i-both", name: "both", username: "rendy", authMode: "key", keyId: "k-1" }),
    { password: "rdp-pw" },
  );
  check(
    "a key identity still resolves an RDP password reference",
    (await resolveRdpAuth({ kind: "identity", identityId: "i-both" }, "h-1", h.deps())).credential,
    { kind: "keychain", service: "tervia-vault", account: "i-both::password" },
  );

  await rejects(
    "a binding to a deleted identity refuses",
    () => resolveRdpAuth({ kind: "identity", identityId: "i-gone" }, "h-1", h.deps()),
    ["no longer exists"],
  );
}

// ---------------------------------------------------------------------------
console.log("\n[recovery] a torn store file falls back to its snapshot");

const GOOD = '{"identities":[{"id":"i-1"}],"keys":[]}';

function memFs(files: Record<string, StoreFileRead>) {
  const replaced: string[] = [];
  const io: StoreFileIo = {
    dir: async () => "/data",
    read: async (path) => files[path] ?? { kind: "missing" },
    replace: async (from, to) => {
      replaced.push(`${from} -> ${to}`);
      files[to] = files[from];
    },
  };
  return { io, files, replaced };
}
const text = (content: string): StoreFileRead => ({ kind: "text", content });
const PRIMARY = "/data/tervia-vault.json";
const SNAPSHOT = "/data/tervia-vault.json.bak";

{
  const fs = memFs({ [PRIMARY]: text(GOOD), [SNAPSHOT]: text("{}") });
  const r = await recoverStoreFile("tervia-vault.json", fs.io);
  check("a good primary is left alone", [r.found, r.recovered, r.note], ["ok", false, undefined]);
  check("and nothing is copied over it", fs.replaced, []);
}
{
  // The reported failure mode: zero bytes after a power cut.
  const fs = memFs({ [PRIMARY]: text(""), [SNAPSHOT]: text(GOOD) });
  const r = await recoverStoreFile("tervia-vault.json", fs.io);
  check("a zeroed primary is restored", [r.found, r.recovered], ["empty", true]);
  check("from the snapshot", fs.replaced, [`${SNAPSHOT} -> ${PRIMARY}`]);
  check("and the primary now holds the snapshot's bytes", fs.files[PRIMARY], text(GOOD));
  assert(!!r.note && r.note.includes("empty"), "the note says what was wrong");
}
{
  // The other reported failure mode: full-length and nul-filled. `fs_read_file`
  // reports that as binary, because its null-byte sniff refuses to decode it.
  const fs = memFs({ [PRIMARY]: { kind: "unreadable" }, [SNAPSHOT]: text(GOOD) });
  const r = await recoverStoreFile("tervia-vault.json", fs.io);
  check("a nul-filled primary is restored", [r.found, r.recovered], ["nul", true]);
  check("from the snapshot", fs.files[PRIMARY], text(GOOD));
}
{
  // And the same file short enough to come back as decodable text: `trim()` does
  // not strip U+0000, so this must not read as merely empty.
  const fs = memFs({ [PRIMARY]: text("\0\0\0\0"), [SNAPSHOT]: text(GOOD) });
  const r = await recoverStoreFile("tervia-vault.json", fs.io);
  check("nul bytes that decode are still nul", [r.found, r.recovered], ["nul", true]);
}
{
  const fs = memFs({ [PRIMARY]: text('{"identities":['), [SNAPSHOT]: text(GOOD) });
  const r = await recoverStoreFile("tervia-vault.json", fs.io);
  check("a truncated primary is restored", [r.found, r.recovered], ["unparseable", true]);
}
{
  const fs = memFs({ [PRIMARY]: text("[1,2,3]"), [SNAPSHOT]: text(GOOD) });
  const r = await recoverStoreFile("tervia-vault.json", fs.io);
  check("valid JSON that is not an object is unparseable too", r.found, "unparseable");
}
{
  // A first run. Nothing has ever been written, so there is nothing to report -
  // a note here would be a toast on every fresh install.
  const fs = memFs({});
  const r = await recoverStoreFile("tervia-vault.json", fs.io);
  check("a first run is silent", [r.found, r.recovered, r.note], ["missing", false, undefined]);
  check("and copies nothing", fs.replaced, []);
}
{
  // Both gone. Unrecoverable, and the user is told rather than left with a store
  // that silently came up empty.
  const fs = memFs({ [PRIMARY]: text(""), [SNAPSHOT]: { kind: "unreadable" } });
  const r = await recoverStoreFile("tervia-vault.json", fs.io);
  check("an unusable snapshot cannot recover", [r.found, r.recovered], ["empty", false]);
  assert(!!r.note && r.note.includes("snapshot"), "but it is reported");
  check("and the primary is untouched", fs.replaced, []);
}
{
  const fs = memFs({ [PRIMARY]: text(GOOD) });
  await snapshotStoreFile("tervia-vault.json", fs.io);
  check("a good primary is snapshotted", fs.files[SNAPSHOT], text(GOOD));
}
{
  // The one thing a snapshot must never do: overwrite the last good copy with a
  // torn one, which would turn a recoverable crash into a total loss.
  const fs = memFs({ [PRIMARY]: text(""), [SNAPSHOT]: text(GOOD) });
  await snapshotStoreFile("tervia-vault.json", fs.io);
  check("a torn primary is NOT snapshotted over the good one", fs.files[SNAPSHOT], text(GOOD));
  check("nothing was copied", fs.replaced, []);
}

if (failed > 0) throw new Error(`vault-resolve-verify: ${failed} FAILED`);
console.log("\nvault-resolve-verify: OK\n");
