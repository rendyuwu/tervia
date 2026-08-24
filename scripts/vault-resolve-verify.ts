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
 *    stops an edit that never touched a password field from wiping it. Every
 *    check here feeds the flags in DELIBERATELY WRONG, because handing the
 *    previous record straight back cannot tell "the store read what is stored"
 *    from "the store echoed its caller".
 *
 * 4. A TORN STORE FILE RECOVERS, AND A FILESYSTEM IN A BAD STATE DEGRADES.
 *    tauri-plugin-store writes in place with no temp file and no fsync, and
 *    swallows the load error of a file it cannot parse - so a zeroed or
 *    nul-filled file comes back as an EMPTY store and the next autosave makes
 *    that permanent. For the vault that means a private key left in the keychain
 *    with no record naming it. Recovery therefore never rejects: the settle pass
 *    runs once and its promise is cached, so a cached rejection would leave the
 *    store unreadable for the rest of the process on exactly the profile where
 *    the good snapshot is sitting next to the broken primary.
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
 * 7. THE SETTLE ORDERING: recover, then force the load, then snapshot. Two of
 *    the three are useless in the wrong order - a snapshot taken before the load
 *    proved the file good can copy a torn file over the last good one, and a load
 *    that happens before recovery has already decided the file was worthless.
 *
 * 8. AN INLINE BINDING NAMES THE HOST STORING IT. Carrying `hostId` inside the
 *    binding removes the resolve-time mismatch and MOVES it to write time, where
 *    nothing in the type system catches it: a spread copy is a well-typed way to
 *    hand a duplicate the original's `hostId`, after which the copy authenticates
 *    as the original and shares its secrets without saying so.
 *
 * 9. A SECRET IS NEVER LEFT WITH NO RECORD NAMING IT. `upsertKey` writes two
 *    secrets before it persists, so a throw on the second used to leave the
 *    private key at an account nothing would ever enumerate - there is no
 *    `secrets_list` command, so "unreferenced" means unreachable.
 *
 * The store, secrets, filesystem, plugin store and event bus are all injectable
 * ports, so all of this runs under plain node with no Tauri runtime and no
 * mocking library.
 */
import {
  createRecoveredStore,
  createWriteQueue,
  type KeyValueStore,
  type StoreBroadcast,
} from "../src/lib/recoveredStore";
import {
  recoverStoreFile,
  snapshotStoreFile,
  SNAPSHOT_SUFFIX,
  type StoreFileIo,
  type StoreFileRead,
  type StoreRecovery,
} from "../src/lib/storeRecovery";
import type { SecretsIo, VaultStoreIo } from "../src/modules/vault/adapters";
import { resolveRdpAuth, resolveSshAuth, type ResolveDeps } from "../src/modules/vault/resolve";
import { createVaultStore } from "../src/modules/vault/store";
import {
  assertBindingOwner,
  VaultInUseError,
  type RdpInlineCredentials,
  type SshInlineCredentials,
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

/** A step that throws, to reach the partial-failure paths. `setAccount` is the
 *  keychain account whose write fails; `commit` fails the store persist. */
type Fail = { setAccount?: string; commit?: string };

function harness(
  seed: {
    identities?: VaultIdentity[];
    keys?: VaultKey[];
    notice?: StoreRecovery;
    fail?: Fail;
  } = {},
) {
  const data: Record<string, unknown> = {
    identities: seed.identities ?? [],
    keys: seed.keys ?? [],
  };
  const kept = new Map<string, string>();
  const calls: SecretCall[] = [];
  const listeners = new Set<() => void>();
  let commits = 0;
  let notice = seed.notice ?? null;

  const takeNotice = (): StoreRecovery | null => {
    const held = notice;
    notice = null;
    return held;
  };

  const store: VaultStoreIo = {
    async get<T>(key: string): Promise<T | null> {
      return (data[key] as T | undefined) ?? null;
    },
    async set(key: string, value: unknown): Promise<void> {
      data[key] = value;
    },
    async commit(): Promise<void> {
      if (seed.fail?.commit) throw new Error(seed.fail.commit);
      commits++;
      for (const l of listeners) l();
    },
    // The REAL queue, so the serialization checks below exercise the shipped one
    // rather than a copy of it living in this file.
    enqueueWrite: createWriteQueue(),
    async onChanged(cb: () => void): Promise<() => void> {
      listeners.add(cb);
      return () => void listeners.delete(cb);
    },
    ensureLoaded: async () => takeNotice(),
    takeRecoveryNotice: takeNotice,
  };

  const secrets: SecretsIo = {
    async getAll(service, accounts) {
      calls.push({ op: "getAll", service, accounts });
      return accounts.map((a) => kept.get(`${service}::${a}`) ?? null);
    },
    async set(service, account, value) {
      calls.push({ op: "set", service, accounts: [account] });
      if (seed.fail?.setAccount === account) throw new Error(`keychain refused ${account}`);
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
/** An inline SSH binding. `hostId` lives INSIDE it, so the pair "which host owns
 *  these accounts" and "which accounts to read" cannot come apart. */
const sshInline = (over: Partial<SshInlineCredentials> = {}): SshInlineCredentials => ({
  kind: "inline",
  hostId: "h-9",
  user: "eve",
  authMode: "agent",
  hasPassword: false,
  hasPrivateKey: false,
  hasKeyPassphrase: false,
  ...over,
});
const rdpInline = (over: Partial<RdpInlineCredentials> = {}): RdpInlineCredentials => ({
  kind: "inline",
  hostId: "h-42",
  username: "admin",
  hasPassword: true,
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
  // AND keep the flag. The input carries both flags deliberately WRONG, so the
  // check can distinguish reading the stored record from echoing the caller.
  const untouched = await h.vault.upsertKey(
    { ...created.record, name: "renamed", hasPrivateKey: false, hasPassphrase: false },
    {},
  );
  check(
    "an edit that skips the fields takes hasPrivateKey from the STORE",
    untouched.record.hasPrivateKey,
    true,
  );
  check("and hasPassphrase with it", untouched.record.hasPassphrase, true);
  check(
    "the corrected flag is what got persisted",
    (await h.vault.findKey("k-1"))?.hasPrivateKey,
    true,
  );
  check("the secret is still there", h.kept.get("tervia-vault::k-1::privateKey"), "PEM-BODY");
  check("and still nothing was read back", h.reads().length, 0);

  // A blank string is the clear, not a no-op.
  const cleared = await h.vault.upsertKey(untouched.record, { passphrase: "" });
  check("a blank passphrase clears the flag", cleared.record.hasPassphrase, false);
  check("and removes the entry", h.kept.has("tervia-vault::k-1::passphrase"), false);
  check("without disturbing the private key", cleared.record.hasPrivateKey, true);
  check("still no read-back", h.reads().length, 0);

  // The same for the private key itself - the field whose loss actually costs
  // something, and the one the passphrase case above does not cover.
  const wiped = await h.vault.upsertKey(cleared.record, { privateKey: "   " });
  check("a whitespace-only private key clears the flag", wiped.record.hasPrivateKey, false);
  check("and removes the entry", h.kept.has("tervia-vault::k-1::privateKey"), false);
  check("which the store agrees with", (await h.vault.findKey("k-1"))?.hasPrivateKey, false);

  // A brand-new record starts from what is STORED, not from the flags the caller
  // sent: a duplicated record must not claim secrets that were never copied.
  const fresh = await h.vault.upsertKey(
    vaultKey({ id: "k-2", name: "other", hasPrivateKey: true, hasPassphrase: true }),
    {},
  );
  check(
    "a new key claiming secrets it has none of is forced to both flags false",
    [fresh.record.hasPrivateKey, fresh.record.hasPassphrase],
    [false, false],
  );
  check("and no secret was invented for it", h.kept.has("tervia-vault::k-2::privateKey"), false);

  const ident = await h.vault.upsertIdentity(identity(), { password: "s3cret" });
  check("a written identity password sets hasPassword", ident.record.hasPassword, true);
  check(
    "stored under the identity's own account",
    h.kept.get("tervia-vault::i-1::password"),
    "s3cret",
  );
  const kept = await h.vault.upsertIdentity(
    { ...ident.record, name: "root @ prod (renamed)", hasPassword: false },
    {},
  );
  check(
    "an identity edit that skips the password takes the flag from the STORE",
    kept.record.hasPassword,
    true,
  );
  check("and persists the corrected one", (await h.vault.findIdentity("i-1"))?.hasPassword, true);
  check("no read-back on the identity path either", h.reads().length, 0);
}

// ---------------------------------------------------------------------------
console.log("\n[names] a key must have one, and a duplicate is warned about not refused");
{
  const h = harness();
  // Required, unlike an identity's: a key is picked by name from a dropdown in
  // every host that uses it, and two blank ones "collide" as `already named ""`.
  await rejects(
    "a whitespace-only key name is refused",
    () => h.vault.upsertKey(vaultKey({ name: "  " }), { privateKey: "A" }),
    ["needs a name"],
  );
  check("nothing was written", (h.data.keys as VaultKey[]).length, 0);
  check("and no secret was stored for it either", h.kept.size, 0);

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
console.log("\n[owner] an inline binding must name the host that is storing it");
{
  // Putting `hostId` inside the binding removes the RESOLVE-time mismatch and
  // moves it to write time, where only this guard catches it. The type system
  // cannot: a spread copy is a perfectly well-typed way to get it wrong.
  assertBindingOwner(sshInline(), "h-9");
  console.log("  ok: a binding stored on its own host passes");
  assertBindingOwner({ kind: "identity", identityId: "i-1" }, "h-9");
  console.log("  ok: a reference binding carries no hostId to check");

  await rejects(
    "a binding stored on a different host is refused, naming both",
    async () => assertBindingOwner(sshInline(), "h-copy"),
    ["h-9", "h-copy", "hostId"],
  );
  await rejects(
    "the RDP arm is checked the same way",
    async () => assertBindingOwner(rdpInline(), "h-43"),
    ["h-42", "h-43"],
  );

  // Fails closed rather than vacuously: `"" === ""` would wave a half-built
  // record straight through.
  await rejects(
    "a blank id on both sides is refused, not counted as a match",
    async () => assertBindingOwner(sshInline({ hostId: "" }), ""),
    ["host id on both sides"],
  );
  await rejects(
    "and a blank hostId against a real owner too",
    async () => assertBindingOwner(sshInline({ hostId: "" }), "h-9"),
    ["host id on both sides"],
  );
  // The parameter is required, so a caller omitting it is a type error - but the
  // guard is the last thing between a duplicate and the original's secrets, so it
  // refuses at RUNTIME too rather than trusting the call site.
  await rejects(
    "an ownerId that is not there at all fails closed",
    async () => assertBindingOwner(sshInline(), undefined as unknown as string),
    ["host id on both sides"],
  );
  await rejects(
    "and one that is not a string does too",
    async () => assertBindingOwner(sshInline(), 9 as unknown as string),
    ["h-9"],
  );

  // THE case this exists for. `{ ...source, id: newId() }` is how a duplicate-host
  // action is written, and it carries `hostId` straight over.
  const source = { id: "h-9", ssh: sshInline({ authMode: "password", hasPassword: true }) };
  const copy = { ...source, id: "h-copy" };
  await rejects(
    "a spread copy that kept the source's hostId is refused on write",
    async () => assertBindingOwner(copy.ssh, copy.id),
    ["h-9", "h-copy"],
  );
  const fixed = { ...copy, ssh: { ...copy.ssh, hostId: copy.id } };
  assertBindingOwner(fixed.ssh, fixed.id);
  console.log("  ok: rewriting hostId alongside id is what makes the copy legal");

  // And why it matters, measured rather than asserted: without the rewrite the
  // copy authenticates as the SOURCE, so rotating one password changes both and
  // deleting the source breaks the copy.
  const h = harness();
  h.kept.set("tervia-hosts::h-9::password", "source-pw");
  h.kept.set("tervia-hosts::h-copy::password", "copy-pw");
  check(
    "an unrewritten hostId reads the source host's password",
    (await resolveSshAuth(copy.ssh, h.deps())).password,
    "source-pw",
  );
  check(
    "where the rewritten one reads the copy's own",
    (await resolveSshAuth(fixed.ssh, h.deps())).password,
    "copy-pw",
  );
}

// ---------------------------------------------------------------------------
console.log("\n[orphans] a key whose second secret fails to write leaves nothing behind");
{
  // `upsertKey` writes `privateKey`, then `passphrase`, then persists. A throw on
  // the second write used to leave the PEM at `<id>::privateKey` with no record
  // naming it - and there is no `secrets_list` command, so nothing could ever
  // enumerate or delete it.
  const h = harness({ fail: { setAccount: "k-1::passphrase" } });
  await rejects(
    "a passphrase write that fails takes the whole upsert with it",
    () => h.vault.upsertKey(vaultKey(), { privateKey: "PEM", passphrase: "pp" }),
    ["keychain refused"],
  );
  check("no record was persisted", (h.data.keys as VaultKey[]).length, 0);
  check(
    "and the private key written first was cleared again",
    h.kept.has("tervia-vault::k-1::privateKey"),
    false,
  );

  // An EXISTING record is deliberately left alone: its accounts stay reachable
  // through `deleteKey`, and this layer never reads a secret back, so it has no
  // previous value to restore - clearing them would destroy the stored key.
  const stored = harness({
    keys: [vaultKey({ hasPrivateKey: true })],
    fail: { setAccount: "k-1::passphrase" },
  });
  stored.kept.set("tervia-vault::k-1::privateKey", "OLD-PEM");
  await rejects(
    "the same failure on an existing key still rejects",
    () =>
      stored.vault.upsertKey(vaultKey({ hasPrivateKey: true }), {
        privateKey: "NEW",
        passphrase: "pp",
      }),
    ["keychain refused"],
  );
  check(
    "but does NOT clear material it cannot put back",
    stored.kept.get("tervia-vault::k-1::privateKey"),
    "NEW",
  );
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
console.log("\n[queue] a refused operation rejects alone and leaves the chain alive");
{
  // The queue chains every mutation onto the previous one. A rejection that
  // propagated into the chain would take every LATER write with it - and the
  // integrity guards mean a rejection is an ordinary event, not a rare one.
  const h = harness();
  await h.vault.upsertKey(vaultKey({ id: "k-1", name: "a" }), { privateKey: "A" });

  const before = h.vault.upsertKey(vaultKey({ id: "k-2", name: "b" }), { privateKey: "B" });
  const bad = h.vault.upsertIdentity(identity({ authMode: "key", keyId: "k-gone" }), {});
  const after = h.vault.upsertKey(vaultKey({ id: "k-3", name: "c" }), { privateKey: "C" });

  await before;
  await rejects("the refused operation is the only one that rejects", () => bad, [
    "does not exist",
  ]);
  await after;
  check(
    "the writes on both sides of it landed, in order",
    (await h.vault.listKeys()).map((k) => k.id),
    ["k-1", "k-2", "k-3"],
  );
  check("and the refusal wrote nothing", (h.data.identities as VaultIdentity[]).length, 0);
}

// ---------------------------------------------------------------------------
console.log("\n[ssh] resolution hands back the credential shape for every auth mode");
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
    await resolveSshAuth({ kind: "identity", identityId: "i-agent" }, h.deps()),
    { user: "carol", useAgent: true },
  );
  check("and reads no secret at all", h.reads().length - before, 0);

  check(
    "a password identity resolves to its own password",
    await resolveSshAuth({ kind: "identity", identityId: "i-pw" }, h.deps()),
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
    await resolveSshAuth({ kind: "identity", identityId: "i-key" }, h.deps()),
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
    await resolveSshAuth({ kind: "identity", identityId: "i-empty" }, h.deps()),
    { user: "dave", password: undefined },
  );

  // Inline bindings read the HOST's own accounts on the host service, from the
  // `hostId` the binding itself carries.
  check("an inline agent binding needs no keychain", await resolveSshAuth(sshInline(), h.deps()), {
    user: "eve",
    useAgent: true,
  });

  h.kept.set("tervia-hosts::h-9::password", "host-pw");
  h.kept.set("tervia-hosts::h-9::privateKey", "host-pem");
  h.kept.set("tervia-hosts::h-9::keyPassphrase", "host-pp");
  check(
    "an inline password binding reads the host's account",
    await resolveSshAuth(sshInline({ authMode: "password", hasPassword: true }), h.deps()),
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
      sshInline({ authMode: "key", hasPrivateKey: true, hasKeyPassphrase: true }),
      h.deps(),
    ),
    { user: "eve", privateKey: "host-pem", privateKeyPassphrase: "host-pp" },
  );
  check("using the host store's keyPassphrase field name", h.lastRead(), {
    op: "getAll",
    service: "tervia-hosts",
    accounts: ["h-9::privateKey", "h-9::keyPassphrase"],
  });

  // The owner id travels INSIDE the binding, so a second host's binding reads a
  // second host's accounts with nothing to keep in sync by hand.
  h.kept.set("tervia-hosts::h-other::password", "other-pw");
  check(
    "another host's inline binding reads that host's account",
    await resolveSshAuth(
      sshInline({ hostId: "h-other", authMode: "password", hasPassword: true }),
      h.deps(),
    ),
    { user: "eve", password: "other-pw" },
  );

  // A binding left pointing at a deleted record must say so rather than connect
  // with nothing.
  await rejects(
    "a binding to a deleted identity refuses",
    () => resolveSshAuth({ kind: "identity", identityId: "i-gone" }, h.deps()),
    ["no longer exists"],
  );
  await h.vault.upsertIdentity(
    identity({ id: "i-dangle", name: "dangle", username: "f", authMode: "key", keyId: "k-1" }),
    {},
  );
  (h.data.keys as VaultKey[]).length = 0;
  await rejects(
    "a key deleted out from under an identity refuses",
    () => resolveSshAuth({ kind: "identity", identityId: "i-dangle" }, h.deps()),
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
    await resolveRdpAuth({ kind: "identity", identityId: "i-dc" }, h.deps()),
    {
      username: "administrator",
      domain: "CORP",
      credential: { kind: "keychain", service: "tervia-vault", account: "i-dc::password" },
    },
  );
  check(
    "an inline binding references the HOSTS service and its own host's account",
    await resolveRdpAuth(rdpInline({ domain: "WORKGROUP" }), h.deps()),
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
    "domain" in (await resolveRdpAuth({ kind: "identity", identityId: "i-local" }, h.deps())),
    false,
  );
  check(
    "an inline binding with no domain omits it too",
    "domain" in (await resolveRdpAuth(rdpInline({ hostId: "h-7", username: "u" }), h.deps())),
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
    (await resolveRdpAuth({ kind: "identity", identityId: "i-both" }, h.deps())).credential,
    { kind: "keychain", service: "tervia-vault", account: "i-both::password" },
  );

  await rejects(
    "a binding to a deleted identity refuses",
    () => resolveRdpAuth({ kind: "identity", identityId: "i-gone" }, h.deps()),
    ["no longer exists"],
  );
}

// ---------------------------------------------------------------------------
console.log("\n[recovery] a torn store file falls back to its snapshot");

const GOOD = '{"identities":[{"id":"i-1"}],"keys":[]}';
const STORE_FILE = "tervia-vault.json";
const PRIMARY = `/data/${STORE_FILE}`;
const SNAPSHOT = PRIMARY + SNAPSHOT_SUFFIX;
const text = (content: string): StoreFileRead => ({ kind: "text", content });
const label = (path: string) => (path.endsWith(SNAPSHOT_SUFFIX) ? "snapshot" : "primary");

/**
 * Faults the real filesystem produces and the old delete-then-copy could not
 * survive: a data directory that will not resolve, and a write that is refused.
 *
 * `slowWrite` is the third one - a copy an antivirus or an indexer is sitting on,
 * long enough that more commits land while it is in flight. One-shot, so the
 * trailing pass that follows it is not held too.
 */
type FsFault = {
  dir?: string;
  write?: { suffix: string; message: string };
  slowWrite?: { suffix: string; until: Promise<void> };
};

function memFs(files: Record<string, StoreFileRead>, fault: FsFault = {}, log: string[] = []) {
  const written: string[] = [];
  let slow = fault.slowWrite;
  const io: StoreFileIo = {
    dir: async () => {
      if (fault.dir) throw new Error(fault.dir);
      return "/data";
    },
    read: async (path) => {
      log.push(`read:${label(path)}`);
      return files[path] ?? { kind: "missing" };
    },
    write: async (path, content) => {
      log.push(`write:${label(path)}`);
      if (slow && path.endsWith(slow.suffix)) {
        const gate = slow.until;
        slow = undefined;
        await gate;
      }
      if (fault.write && path.endsWith(fault.write.suffix)) throw new Error(fault.write.message);
      written.push(path);
      files[path] = { kind: "text", content };
    },
  };
  return { io, files, written, log };
}

{
  const fs = memFs({ [PRIMARY]: text(GOOD), [SNAPSHOT]: text("{}") });
  const r = await recoverStoreFile(STORE_FILE, fs.io);
  check("a good primary is left alone", [r.found, r.recovered, r.note], ["ok", false, undefined]);
  check("and nothing is written over it", fs.written, []);
}
{
  // The reported failure mode: zero bytes after a power cut.
  const fs = memFs({ [PRIMARY]: text(""), [SNAPSHOT]: text(GOOD) });
  const r = await recoverStoreFile(STORE_FILE, fs.io);
  check("a zeroed primary is restored", [r.found, r.recovered], ["empty", true]);
  check("by writing the snapshot's bytes over it", fs.written, [PRIMARY]);
  check("so the primary now holds them", fs.files[PRIMARY], text(GOOD));
  assert(!!r.note && r.note.includes("empty"), "the note says what was wrong");
}
{
  // The other reported failure mode: full-length and nul-filled. `fs_read_file`
  // reports that as binary, because its null-byte sniff refuses to decode it.
  const fs = memFs({ [PRIMARY]: { kind: "binary" }, [SNAPSHOT]: text(GOOD) });
  const r = await recoverStoreFile(STORE_FILE, fs.io);
  check("a nul-filled primary is restored", [r.found, r.recovered], ["nul", true]);
  check("from the snapshot", fs.files[PRIMARY], text(GOOD));
}
{
  // And the same file short enough to come back as decodable text: `trim()` does
  // not strip U+0000, so this must not read as merely empty.
  const fs = memFs({ [PRIMARY]: text("\0\0\0\0"), [SNAPSHOT]: text(GOOD) });
  const r = await recoverStoreFile(STORE_FILE, fs.io);
  check("nul bytes that decode are still nul", [r.found, r.recovered], ["nul", true]);
}
{
  const fs = memFs({ [PRIMARY]: text('{"identities":['), [SNAPSHOT]: text(GOOD) });
  const r = await recoverStoreFile(STORE_FILE, fs.io);
  check("a truncated primary is restored", [r.found, r.recovered], ["unparseable", true]);
}
{
  const fs = memFs({ [PRIMARY]: text("[1,2,3]"), [SNAPSHOT]: text(GOOD) });
  const r = await recoverStoreFile(STORE_FILE, fs.io);
  check("valid JSON that is not an object is unparseable too", r.found, "unparseable");
}
{
  // A first run. Nothing has ever been written, so there is nothing to report -
  // a note here would be a toast on every fresh install.
  const fs = memFs({});
  const r = await recoverStoreFile(STORE_FILE, fs.io);
  check("a first run is silent", [r.found, r.recovered, r.note], ["missing", false, undefined]);
  check("and writes nothing", fs.written, []);
}
{
  // Both gone. Unrecoverable, and the user is told rather than left with a store
  // that silently came up empty.
  const fs = memFs({ [PRIMARY]: text(""), [SNAPSHOT]: { kind: "binary" } });
  const r = await recoverStoreFile(STORE_FILE, fs.io);
  check("an unusable snapshot cannot recover", [r.found, r.recovered], ["empty", false]);
  assert(!!r.note && r.note.includes("snapshot"), "but it is reported");
  check("and the primary is untouched", fs.written, []);
}
{
  const fs = memFs({ [PRIMARY]: text(GOOD) });
  const s = await snapshotStoreFile(STORE_FILE, fs.io);
  check("a good primary is snapshotted", [s.taken, fs.files[SNAPSHOT]], [true, text(GOOD)]);
}
{
  // The one thing a snapshot must never do: overwrite the last good copy with a
  // torn one, which would turn a recoverable crash into a total loss.
  const fs = memFs({ [PRIMARY]: text(""), [SNAPSHOT]: text(GOOD) });
  const s = await snapshotStoreFile(STORE_FILE, fs.io);
  check("a torn primary is NOT snapshotted over the good one", fs.files[SNAPSHOT], text(GOOD));
  check("nothing was written, and it says it took nothing", [fs.written, s.taken], [[], false]);
}

// ---------------------------------------------------------------------------
console.log("\n[recovery] a filesystem in a bad state degrades, and never rejects");
{
  // The whole reason: the settle pass runs ONCE and its promise is cached, so a
  // rejection here would leave the store unreadable and unwritable for the rest
  // of the process - on the very profile where the good snapshot is right there.
  const fs = memFs(
    { [PRIMARY]: text(""), [SNAPSHOT]: text(GOOD) },
    { write: { suffix: ".json", message: "os error 13: permission denied" } },
  );
  const r = await recoverStoreFile(STORE_FILE, fs.io);
  check(
    "a restore that cannot be written is not claimed as one",
    [r.found, r.recovered],
    ["empty", false],
  );
  assert(
    !!r.note && r.note.includes("could not be restored") && r.note.includes("permission denied"),
    "and it reports the reason instead of rejecting",
  );
}
{
  const fs = memFs(
    { [PRIMARY]: text(GOOD) },
    { write: { suffix: SNAPSHOT_SUFFIX, message: "no space left" } },
  );
  const s = await snapshotStoreFile(STORE_FILE, fs.io);
  check("a snapshot that cannot be written says it took nothing", s.taken, false);
  assert(!!s.note && s.note.includes("no space left"), "and names the reason");
}
{
  const fs = memFs({}, { dir: "app data dir unavailable" });
  const r = await recoverStoreFile(STORE_FILE, fs.io);
  check(
    "an unusable data directory is reported, not thrown",
    [r.found, r.recovered],
    ["unreachable", false],
  );
  const s = await snapshotStoreFile(STORE_FILE, fs.io);
  check("and a snapshot against it degrades the same way", s.taken, false);
  assert(!!s.note, "with a note a caller can show");
}
{
  // Over `fs_read_file`'s 10 MB limit. The plugin has no such limit and reads it
  // fine, so this is NOT corruption: restoring a snapshot over it, or copying it
  // onto the good snapshot, would each destroy real data.
  const fs = memFs({ [PRIMARY]: { kind: "toolarge" }, [SNAPSHOT]: text(GOOD) });
  const r = await recoverStoreFile(STORE_FILE, fs.io);
  check(
    "a too-large primary is left exactly as it is",
    [r.found, r.recovered],
    ["toolarge", false],
  );
  check("nothing is written over it", fs.written, []);
  assert(!!r.note && !r.note.includes("nul"), "and the note does not call it corruption");
  const s = await snapshotStoreFile(STORE_FILE, fs.io);
  check(
    "nor is it copied onto the good snapshot",
    [s.taken, fs.files[SNAPSHOT]],
    [false, text(GOOD)],
  );
}

// ---------------------------------------------------------------------------
console.log("\n[settle] the shared store wrapper recovers, then loads, then snapshots");

const SPEC = {
  path: STORE_FILE,
  loadKey: "identities",
  changedEvent: "tervia://vault-changed",
};

/**
 * A `KeyValueStore` that behaves the way `LazyStore` does in the two respects
 * that matter here: it loads from the file on first touch and SWALLOWS a load
 * error (which is exactly why recovery has to run before it), and `save()` puts
 * the cache on disk (so a snapshot taken after a commit has something to copy).
 */
function pluginStore(files: Record<string, StoreFileRead>, log: string[]) {
  const data: Record<string, unknown> = {};
  let loaded = false;
  const store: KeyValueStore = {
    async get<T>(key: string): Promise<T | undefined> {
      log.push(`get:${key}`);
      if (!loaded) {
        loaded = true;
        const read = files[PRIMARY];
        if (read?.kind === "text") {
          try {
            Object.assign(data, JSON.parse(read.content) as Record<string, unknown>);
          } catch {
            // Comes up empty, silently, exactly as the plugin does.
          }
        }
      }
      return data[key] as T | undefined;
    },
    async set(key, value) {
      log.push(`set:${key}`);
      data[key] = value;
    },
    async save() {
      log.push("save");
      files[PRIMARY] = { kind: "text", content: JSON.stringify(data) };
    },
  };
  return { store, data };
}

function bus() {
  const emitted: string[] = [];
  const listeners = new Set<() => void>();
  const broadcast: StoreBroadcast = {
    async emit(event) {
      emitted.push(event);
      for (const l of listeners) l();
    },
    async listen(_event, cb) {
      listeners.add(cb);
      return () => void listeners.delete(cb);
    },
  };
  return { broadcast, emitted };
}

{
  const log: string[] = [];
  const fs = memFs({ [PRIMARY]: text(""), [SNAPSHOT]: text(GOOD) }, {}, log);
  const kv = pluginStore(fs.files, log);
  const b = bus();
  const io = createRecoveredStore(SPEC, { store: kv.store, files: fs.io, broadcast: b.broadcast });

  const notice = await io.ensureLoaded();
  // The whole property, as one sequence. Any other order loses data: loading
  // before the restore hands the plugin an empty store it will then autosave,
  // and snapshotting before the load can copy a torn file over the last good one.
  check("recover, then force the load, then snapshot", log, [
    "read:primary",
    "read:snapshot",
    "write:primary",
    "get:identities",
    "read:primary",
    "write:snapshot",
  ]);
  const settled = log.length;
  assert(!!notice && notice.recovered, "ensureLoaded hands back the recovery");
  check("naming what happened", notice?.found, "empty");
  check("and it is a one-shot: the second call has nothing", await io.ensureLoaded(), null);
  check("which also did not re-run the pass", log.length, settled);
  check("as does takeRecoveryNotice, which shares the slot", io.takeRecoveryNotice(), null);
  check("the load saw the RESTORED contents", await io.get("identities"), [{ id: "i-1" }]);
}
{
  // A first run must be silent: a note here is a toast on every fresh install.
  const fs = memFs({});
  const kv = pluginStore(fs.files, []);
  const io = createRecoveredStore(SPEC, {
    store: kv.store,
    files: fs.io,
    broadcast: bus().broadcast,
  });
  check("a first run reports nothing", await io.ensureLoaded(), null);
}
{
  // P2-12: `commit` is on the public port, so a commit before any read must still
  // recover first - otherwise `save()` writes the plugin's empty defaults over a
  // torn but perfectly recoverable file.
  const log: string[] = [];
  const fs = memFs({ [PRIMARY]: text(""), [SNAPSHOT]: text(GOOD) }, {}, log);
  const kv = pluginStore(fs.files, log);
  const b = bus();
  const io = createRecoveredStore(SPEC, { store: kv.store, files: fs.io, broadcast: b.broadcast });

  await io.commit();
  assert(
    log.indexOf("write:primary") < log.indexOf("save"),
    "a commit before any read still restores before it saves",
  );
  check("and the identities survived the commit", kv.data.identities, [{ id: "i-1" }]);
  check("with the other windows told once", b.emitted, [SPEC.changedEvent]);
}
{
  // The session that CREATES the store must end up with a snapshot. At load time
  // there is no file to copy, so the first successful commit is the earliest a
  // private key can be protected at all - and until it was, a power cut on a
  // fresh install left the key in the keychain with nothing naming it.
  const log: string[] = [];
  const fs = memFs({}, {}, log);
  const kv = pluginStore(fs.files, log);
  const io = createRecoveredStore(SPEC, {
    store: kv.store,
    files: fs.io,
    broadcast: bus().broadcast,
  });

  await io.ensureLoaded();
  check("a fresh profile starts with no snapshot to take", fs.files[SNAPSHOT], undefined);
  await io.set("keys", [{ id: "k-1", name: "id_ed25519" }]);
  await io.commit();
  check(
    "and the first commit leaves one behind",
    fs.files[SNAPSHOT],
    text('{"keys":[{"id":"k-1","name":"id_ed25519"}]}'),
  );
}
{
  // Snapshots coalesce. A page of inline edits fires one commit per field the
  // user leaves, and each one paying a full file copy is what the coalescing
  // avoids - without ever leaving the LAST commit uncovered.
  //
  // Each commit saves a DIFFERENT value, and the first copy is held open until
  // all three have landed. Both matter: three identical saves pass for a snapshot
  // taken anywhere in the burst, and a copy that completes before the last save
  // does the same. Held and distinct, "skip while busy" leaves the `.bak` at k-1.
  const log: string[] = [];
  let release = () => {};
  const held = new Promise<void>((resolve) => {
    release = () => resolve();
  });
  const fs = memFs({}, { slowWrite: { suffix: SNAPSHOT_SUFFIX, until: held } }, log);
  const kv = pluginStore(fs.files, log);
  const io = createRecoveredStore(SPEC, {
    store: kv.store,
    files: fs.io,
    broadcast: bus().broadcast,
  });

  await io.ensureLoaded();
  await io.set("keys", [{ id: "k-1" }]);
  const first = io.commit();
  await io.set("keys", [{ id: "k-2" }]);
  const second = io.commit();
  await io.set("keys", [{ id: "k-3" }]);
  const third = io.commit();
  release();
  await Promise.all([first, second, third]);

  const copies = log.filter((e) => e === "write:snapshot").length;
  assert(copies > 0 && copies < 3, `three overlapping commits cost ${copies} snapshot copies`);
  check("and the LAST commit is the one snapshotted", fs.files[SNAPSHOT], fs.files[PRIMARY]);
  check(
    "which is its own value, not the first's",
    fs.files[SNAPSHOT],
    text('{"keys":[{"id":"k-3"}]}'),
  );
}
{
  // A `.bak` write that fails while the primary write succeeds: a Windows path
  // length the extra suffix crosses, a quota hit between the two writes. On a
  // fresh profile the startup pass reports NOTHING - there is no primary to copy
  // yet - so a commit is the first moment anything can say the net is missing.
  const log: string[] = [];
  const fault: FsFault = { write: { suffix: SNAPSHOT_SUFFIX, message: "path too long" } };
  const fs = memFs({}, fault, log);
  const kv = pluginStore(fs.files, log);
  const io = createRecoveredStore(SPEC, {
    store: kv.store,
    files: fs.io,
    broadcast: bus().broadcast,
  });

  check("a fresh profile's startup pass has nothing to report", await io.ensureLoaded(), null);
  await io.set("keys", [{ id: "k-1" }]);
  await io.commit();
  const said = io.takeRecoveryNotice();
  assert(!!said?.note?.includes("path too long"), "a commit whose snapshot fails says so");
  check("without claiming a recovery it did not do", [said?.found, said?.recovered], ["ok", false]);

  // Once, not once per commit: a page of inline edits against a directory that
  // will not take a copy is one notice, not one per field the user leaves.
  await io.commit();
  await io.commit();
  check("and the same failure is not re-reported", io.takeRecoveryNotice(), null);

  // A pass that works clears the memo, so a fault that comes back is said again.
  fault.write = undefined;
  await io.commit();
  check("a working snapshot reports nothing", io.takeRecoveryNotice(), null);
  fault.write = { suffix: SNAPSHOT_SUFFIX, message: "path too long" };
  await io.commit();
  assert(
    !!io.takeRecoveryNotice()?.note?.includes("path too long"),
    "a fault that returns after a good pass is reported again",
  );
}
{
  // P1-1, end to end. The replace used to be `fs_delete` then `fs_copy`, with the
  // delete swallowed - so a held handle or a read-only directory produced an
  // `already exists` error, the settle promise cached THAT rejection, and every
  // later get and set re-awaited it. The vault was then unlistable and unwritable
  // for the rest of the process, on a profile whose good `.bak` was right there.
  const log: string[] = [];
  const fs = memFs(
    { [PRIMARY]: text(""), [SNAPSHOT]: text(GOOD) },
    { write: { suffix: ".json", message: "os error 13: permission denied" } },
    log,
  );
  const kv = pluginStore(fs.files, log);
  const b = bus();
  const io = createRecoveredStore(SPEC, { store: kv.store, files: fs.io, broadcast: b.broadcast });

  const notice = await io.ensureLoaded();
  assert(
    !!notice && !notice.recovered && !!notice.note?.includes("could not be restored"),
    "a restore that fails is reported as a failure, not thrown",
  );
  check("the store is still readable afterwards", await io.get("identities"), null);
  await io.set("identities", [{ id: "i-late" }]);
  await io.commit();
  check("and still writable", kv.data.identities, [{ id: "i-late" }]);
  check("with the broadcast still firing", b.emitted, [SPEC.changedEvent]);
}

// ---------------------------------------------------------------------------
console.log("\n[recovery] the store layer hands the startup notice through");
{
  const h = harness({
    notice: { found: "empty", recovered: true, note: "restored from the snapshot" },
  });
  check(
    "ensureLoaded reaches the port",
    (await h.vault.ensureLoaded())?.note,
    "restored from the snapshot",
  );
  check("and only fires once", await h.vault.ensureLoaded(), null);
  check("sharing one slot with takeRecoveryNotice", h.vault.takeRecoveryNotice(), null);
}

if (failed > 0) throw new Error(`vault-resolve-verify: ${failed} FAILED`);
console.log("\nvault-resolve-verify: OK\n");
