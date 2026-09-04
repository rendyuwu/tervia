/**
 * Self-check for the connection backup parser, both format generations.
 * Run: `npx tsx scripts/backup-verify.ts`.
 *
 * Importing a backup is a TRUST BOUNDARY: the file arrives from a USB stick or
 * a chat, and everything that survives it is written into the host store and
 * later dialled. The failures this pins down are the quiet ones - a port of 0 or
 * 99999 reaching `TcpStream::connect`, a presence flag copied from the file so
 * the UI claims a credential that is not in this machine's keychain, a duplicate
 * id where the second entry silently wins, and an inline credential naming
 * ANOTHER host, which would have the imported row resolve that host's keychain
 * accounts.
 *
 * The v1/v2 split matters here because the boundary MOVED. In v1 the inventory
 * is plaintext, so `parseBackupFile` validates it; in v2 the whole payload is
 * sealed, so `parseBackupFile` can only check the envelope and
 * `sanitizePayload` does the per-host work after the host process has decrypted.
 * Both halves are exercised below - a v2 file that got only the envelope check
 * would write unvalidated rows into the store.
 *
 * Three things are checked here that did not need checking against the two old
 * connection stores, because one merged store can express what two separate ones
 * could not. `upsertHost` REFUSES a jump or tunnel host that is missing, is an
 * RDP row, is the row itself, or closes a cycle - it throws rather than dropping
 * the reference, so a reference this parser leaves in place does not save a
 * broken row, it abandons the rest of the file. Same for the WRITE ORDER: the
 * guard runs against what is on disk at that moment, so a host written before
 * its bastion fails. And `assertBindingOwner` refuses a credential whose
 * `hostId` names someone else.
 *
 * Two more are DESTRUCTIVE when they are missing, which is a different class
 * again: `upsertHost` releases every account the new record can no longer NAME,
 * so a row that arrives vault-bound (owning none) or on the other protocol
 * (owning fewer) deletes the saved host's secrets, with nothing copied first and
 * no `secrets_list` to find what is left (§9.7).
 *
 * `hostRefs` and `storedFields` are reached from `backup.ts` rather than from
 * `backupFile.ts`, and they are the producing half of the `SECRET_ALREADY_STORED`
 * contract: one decides what travels, the other decides which flags the store is
 * told to claim. The consuming half is pinned in `hosts-store-verify.ts`. Nothing
 * here calls `invoke`, so importing that module is safe under plain node.
 *
 * The crypto itself, and the v2 payload assembly that keeps credentials out of
 * the webview, are checked on the Rust side (`modules/backup.rs` tests: round
 * trip, wrong passphrase, tampered ciphertext, nonce reuse, group merge/split,
 * the parked-handle lifecycle).
 */
import { jumpChain, MAX_JUMP_HOPS } from "../src/modules/hosts/jumps";
import { SECRET_ALREADY_STORED } from "../src/modules/hosts/store";
import { hostFingerprint, type Host, type RdpHost, type SshHost } from "../src/modules/hosts/types";
import { arrivedWithoutSecret, hostRefs, storedFields } from "../src/modules/backup/apply";
import {
  BACKUP_KIND,
  BACKUP_KIND_V1,
  carryPins,
  clearDanglingJumps,
  clearDanglingTunnels,
  mergeGroups,
  orderHostWrites,
  parseBackupFile,
  refuseProtocolConflicts,
  resolveIdentityBindings,
  sanitizeGroup,
  sanitizeHost,
  sanitizeLegacyHost,
  sanitizePayload,
  sanitizeSecrets,
} from "../src/modules/backup/file";
import { sshCredentialValues } from "../src/modules/vault/resolve";

let failed = 0;

/**
 * A canonical rendering, used to compare AND to report. The same helper and the
 * same reasoning as `hosts-store-verify.ts`: `JSON.stringify` drops `undefined`
 * properties, so "the field is absent" and "the field is present and empty" - the
 * distinction the whole of `pins` turns on - compare equal; and it is key-order
 * sensitive, so a pin map assembled by spreading two maps together fails a check
 * about which pins survived rather than about their order. Keys sorted, `undefined`
 * rendered, arrays left in order for the checks where order IS the contract (write
 * order, hop order).
 */
function shape(v: unknown): string {
  if (v === undefined) return "undefined";
  if (v === null) return "null";
  if (Array.isArray(v)) return `[${v.map(shape).join(",")}]`;
  if (typeof v === "object") {
    const o = v as Record<string, unknown>;
    return `{${Object.keys(o)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${shape(o[k])}`)
      .join(",")}}`;
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
function throws(label: string, fn: () => unknown, needle: string): void {
  try {
    fn();
    console.error(`  FAIL: ${label} did not throw`);
    failed++;
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (msg.toLowerCase().includes(needle.toLowerCase())) {
      console.log(`  ok: ${label}`);
    } else {
      console.error(`  FAIL: ${label} threw "${msg}", expected to mention "${needle}"`);
      failed++;
    }
  }
}

const SEALED = {
  kdf: "pbkdf2-hmac-sha256",
  iterations: 600000,
  salt: "c2FsdA==",
  nonce: "bm9uY2U=",
  ciphertext: "Y2lwaGVy",
};
/** A v1 envelope: SSH only, plaintext `connections`, sealed `secrets`. */
const v1 = (over: Record<string, unknown> = {}) => ({
  kind: BACKUP_KIND_V1,
  version: 1,
  exportedAt: 1,
  connections: [],
  secrets: SEALED,
  ...over,
});
/** A v2 envelope: nothing but the sealed payload. */
const v2 = (over: Record<string, unknown> = {}) => ({
  kind: BACKUP_KIND,
  version: 2,
  exportedAt: 1,
  payload: SEALED,
  ...over,
});

/**
 * An SSH row as it appears inside a v2 payload. The credential's `hostId`
 * follows the row's own id by default, which is the well-formed case; a check
 * that wants the mismatch passes `credential` explicitly.
 */
const ssh = (over: Record<string, unknown> = {}) => {
  const id = typeof over.id === "string" ? over.id : "h-1";
  return {
    id,
    protocol: "ssh",
    name: "prod",
    host: "example.com",
    port: 22,
    credential: { kind: "inline", hostId: id, user: "root", authMode: "password" },
    ...over,
  };
};
const rdp = (over: Record<string, unknown> = {}) => {
  const id = typeof over.id === "string" ? over.id : "h-9";
  return {
    id,
    protocol: "rdp",
    name: "win",
    host: "vps.example.com",
    port: 3389,
    credential: { kind: "inline", hostId: id, username: "Administrator" },
    desktopWidth: 1600,
    desktopHeight: 900,
    sizeMode: "preset",
    ...over,
  };
};
/** A v1 row: the old SSH-only shape, with `user` and `authMode` at the top
 *  level and no `protocol` or `credential` anywhere. */
const legacy = (over: Record<string, unknown> = {}) => ({
  id: "c-1",
  name: "prod",
  host: "example.com",
  port: 22,
  user: "root",
  authMode: "password",
  ...over,
});

/** A validated host, for the passes that work on records rather than on raw file
 *  data. Throws rather than returning null so a bad fixture fails loudly instead
 *  of quietly skipping the check it was written for. */
function host(raw: unknown): Host {
  const h = sanitizeHost(raw);
  if (!h) throw new Error(`fixture is not a valid host: ${JSON.stringify(raw)}`);
  return h;
}

/** The same, narrowed to one arm, for the checks that have to build a SAVED
 *  record by hand: presence flags are forced false by the parser, so a fixture
 *  standing in for "already in this machine's keychain" cannot come from it. */
function sshHost(raw: unknown): SshHost {
  const h = host(raw);
  if (h.protocol !== "ssh") throw new Error(`fixture is not an SSH host: ${JSON.stringify(raw)}`);
  return h;
}
function rdpHost(raw: unknown): RdpHost {
  const h = host(raw);
  if (h.protocol !== "rdp") throw new Error(`fixture is not an RDP host: ${JSON.stringify(raw)}`);
  return h;
}

/** Reference readers, so a check reads through the protocol guard instead of
 *  casting past it: a row that came back on the wrong arm then reads as null
 *  rather than as a pass. `null` means "no reference". */
function jumpOf(h: Host): string | null {
  return h.protocol === "ssh" ? (h.proxyJumpId ?? null) : null;
}
function tunnelOf(h: Host): string | null {
  return h.protocol === "rdp" ? (h.tunnel?.sshHostId ?? null) : null;
}
function sshInline(h: Host | null) {
  if (!h || h.protocol !== "ssh" || h.credential.kind !== "inline") return null;
  return h.credential;
}
function rdpOf(h: Host | null) {
  return h && h.protocol === "rdp" ? h : null;
}
function rdpInline(h: Host | null) {
  const row = rdpOf(h);
  return row && row.credential.kind === "inline" ? row.credential : null;
}

console.log("[envelope] a file that is not a backup must be rejected outright");
throws("a plain object", () => parseBackupFile({}), "not a Tervia connection backup");
throws("null", () => parseBackupFile(null), "not a Tervia connection backup");
throws("an array", () => parseBackupFile([]), "not a Tervia connection backup");
throws(
  "a theme file",
  () => parseBackupFile({ kind: "tervia-theme" }),
  "not a Tervia connection backup",
);
throws("no version", () => parseBackupFile(v2({ version: "2" })), "version");
// A newer Tervia may add fields this build would silently drop, so refuse rather
// than import a partial host.
throws("a newer format", () => parseBackupFile(v2({ version: 99 })), "newer Tervia");
// A half-converted file is worse than an unreadable one: guessing which of the
// kind and the version to believe decides whether the inventory is read as
// plaintext or as ciphertext.
throws("v1 kind claiming v2", () => parseBackupFile(v2({ kind: BACKUP_KIND_V1 })), "not a");
throws("v2 kind claiming v1", () => parseBackupFile(v1({ kind: BACKUP_KIND })), "not a");

console.log("\n[v2 envelope] everything of substance is inside the sealed payload");
check("a good v2 file parses", parseBackupFile(v2()), { version: 2, payload: SEALED });
throws("no payload", () => parseBackupFile(v2({ payload: undefined })), "encrypted payload");
throws(
  "half a payload block",
  () => parseBackupFile(v2({ payload: { kdf: "x" } })),
  "encrypted payload",
);
throws(
  "non-integer iterations",
  () => parseBackupFile(v2({ payload: { ...SEALED, iterations: 1.5 } })),
  "encrypted payload",
);
// The v1 shape must NOT be accepted under a v2 version: `connections` beside a
// sealed `secrets` is exactly the leak v2 exists to close.
throws(
  "a v2 file carrying v1's plaintext inventory instead of a payload",
  () => parseBackupFile(v2({ payload: undefined, connections: [legacy()], secrets: SEALED })),
  "encrypted payload",
);

console.log("\n[v1 envelope] old files still import");
const v1parsed = parseBackupFile(v1({ connections: [legacy()] }));
check("version is reported", v1parsed.version, 1);
check(
  "the plaintext inventory is validated at parse time",
  v1parsed.version === 1 ? v1parsed.hosts.map((h) => h.id) : null,
  ["c-1"],
);
check(
  "a v1 row lands as an ordinary SSH host with an inline credential",
  v1parsed.version === 1 ? sshInline(v1parsed.hosts[0])?.user : null,
  "root",
);
throws("no connections list", () => parseBackupFile(v1({ connections: {} })), "connections");
throws("no secrets block", () => parseBackupFile(v1({ secrets: undefined })), "credentials");
throws("half a secrets block", () => parseBackupFile(v1({ secrets: { kdf: "x" } })), "credentials");

console.log("\n[ports] what would otherwise reach TcpStream::connect");
check("22 is fine", sanitizeHost(ssh())?.port, 22);
check("65535 is fine", sanitizeHost(ssh({ port: 65535 }))?.port, 65535);
check("0 is dropped", sanitizeHost(ssh({ port: 0 })), null);
check("65536 is dropped", sanitizeHost(ssh({ port: 65536 })), null);
check("negative is dropped", sanitizeHost(ssh({ port: -1 })), null);
check("a float is dropped", sanitizeHost(ssh({ port: 22.5 })), null);
check("a string is dropped", sanitizeHost(ssh({ port: "22" })), null);
check("NaN is dropped", sanitizeHost(ssh({ port: Number.NaN })), null);
check("and the same on the RDP side", sanitizeHost(rdp({ port: 0 })), null);
check("and on a v1 row", sanitizeLegacyHost(legacy({ port: 0 })), null);

console.log("\n[required fields]");
check("no id", sanitizeHost(ssh({ id: "" })), null);
check("no host", sanitizeHost(ssh({ host: "   " })), null);
check("not an object", sanitizeHost("h-1"), null);
check("a blank name falls back to the host", sanitizeHost(ssh({ name: "" }))?.name, "example.com");
check(
  "a blank RDP name falls back to the host too",
  sanitizeHost(rdp({ name: "" }))?.name,
  "vps.example.com",
);
// One record per machine now, discriminated on `protocol`. There is no default:
// an RDP row read as SSH would offer an SSH handshake to port 3389, and a row
// naming neither cannot be dialled either way.
check("no protocol is dropped", sanitizeHost(ssh({ protocol: undefined })), null);
check("an unknown protocol is dropped", sanitizeHost(ssh({ protocol: "vnc" })), null);
check("and it is not case-insensitive either", sanitizeHost(ssh({ protocol: "SSH" })), null);

console.log("\n[credential binding] the file may not point a host at another host's secrets");
// `assertBindingOwner` refuses a mismatch, so a file left to name its own owner
// would abort the whole import - and if it did not, the imported row would
// resolve the NAMED host's accounts: rotating one password would change the
// other, with no error anywhere.
check(
  "hostId is forced to the row's own id, whatever the file claims",
  sshInline(
    host(
      ssh({
        id: "h-mine",
        credential: { kind: "inline", hostId: "h-victim", user: "root", authMode: "password" },
      }),
    ),
  )?.hostId,
  "h-mine",
);
check(
  "and on the RDP side too",
  rdpInline(
    host(
      rdp({
        id: "h-mine",
        credential: { kind: "inline", hostId: "h-victim", username: "Administrator" },
      }),
    ),
  )?.hostId,
  "h-mine",
);
check("a v1 row's binding is owned by the row too", sanitizeLegacyHost(legacy())?.credential, {
  kind: "inline",
  hostId: "c-1",
  user: "root",
  authMode: "password",
  hasPassword: false,
  hasPrivateKey: false,
  hasKeyPassphrase: false,
});
// The PARSER preserves it, so the pass below can see what the file asked for.
// Nothing applies it - see [vault bindings].
check(
  "a vault binding survives the parser, so the row is not lost before it is judged",
  host(ssh({ credential: { kind: "identity", identityId: "i-1" } })).credential,
  { kind: "identity", identityId: "i-1" },
);
check(
  "an identity binding naming nothing falls back to inline rather than losing the host",
  sshInline(host(ssh({ credential: { kind: "identity", identityId: "   " } })))?.user,
  "",
);
check(
  "a credential that is not an object falls back to inline as well",
  sshInline(host(ssh({ credential: "root" })))?.authMode,
  "password",
);
check(
  "the RDP domain rides along, and an absent one stays absent",
  [
    rdpInline(
      host(rdp({ credential: { kind: "inline", hostId: "h-9", username: "a", domain: "CORP" } })),
    )?.domain,
    Object.prototype.hasOwnProperty.call(rdpInline(host(rdp())) ?? {}, "domain"),
  ],
  ["CORP", false],
);

console.log("\n[credential flags] never trusted from the file: they describe the OTHER keychain");
const flagged = sshInline(
  host(
    ssh({
      credential: {
        kind: "inline",
        hostId: "h-1",
        user: "root",
        authMode: "key",
        hasPassword: true,
        hasPrivateKey: true,
        hasKeyPassphrase: true,
      },
    }),
  ),
);
check(
  "all three are forced false",
  [flagged?.hasPassword, flagged?.hasPrivateKey, flagged?.hasKeyPassphrase],
  [false, false, false],
);
check(
  "the RDP flag is forced false as well",
  rdpInline(
    host(rdp({ credential: { kind: "inline", hostId: "h-9", username: "a", hasPassword: true } })),
  )?.hasPassword,
  false,
);
check(
  "and a v1 row's top-level flags do not carry over either",
  sshInline(sanitizeLegacyHost(legacy({ hasPassword: true, hasPrivateKey: true })))?.hasPassword,
  false,
);

console.log("\n[carried fields]");
check(
  "the pinned host key survives, so the new machine keeps the TOFU anchor",
  hostFingerprint(host(ssh({ lastFingerprint: "SHA256:abc" }))),
  "SHA256:abc",
);
check(
  "the pinned RDP certificate survives for the same reason",
  hostFingerprint(host(rdp({ certFingerprint: "49:67:09" }))),
  "49:67:09",
);
check(
  "an unknown authMode falls back to password",
  sshInline(
    host(ssh({ credential: { kind: "inline", hostId: "h-1", user: "r", authMode: "sso" } })),
  )?.authMode,
  "password",
);
check(
  "key auth survives",
  sshInline(
    host(ssh({ credential: { kind: "inline", hostId: "h-1", user: "r", authMode: "key" } })),
  )?.authMode,
  "key",
);
check("proxyJumpId survives", jumpOf(host(ssh({ proxyJumpId: "h-2" }))), "h-2");
check("groupId survives", host(ssh({ groupId: "g-1" })).groupId, "g-1");
check("description survives", host(ssh({ description: "note" })).description, "note");
check(
  "lastConnectedAt survives, but only as a real number",
  [
    host(ssh({ lastConnectedAt: 17 })).lastConnectedAt,
    host(ssh({ lastConnectedAt: "17" })).lastConnectedAt,
  ],
  [17, undefined],
);

console.log("\n[dropped fields] a field the store has no home for must not ride in");
// A forward rule is its own record now (decision 7), so `Host` has no
// `forwards` and the store would carry a key nothing ever reads or edits.
check(
  "`forwards` does not survive a v2 row",
  Object.prototype.hasOwnProperty.call(
    host(ssh({ forwards: [{ localPort: 8080, remoteHost: "127.0.0.1", remotePort: 80 }] })),
    "forwards",
  ),
  false,
);
check(
  "nor a v1 row, which is the format that had them",
  Object.prototype.hasOwnProperty.call(
    sanitizeLegacyHost(
      legacy({ forwards: [{ localPort: 1, remoteHost: "db", remotePort: 5432 }] }),
    ) ?? {},
    "forwards",
  ),
  false,
);
check(
  "nor does anything else the file invents, because every field is copied out by name",
  Object.prototype.hasOwnProperty.call(host(ssh({ sshConnectionId: "c-1" })), "sshConnectionId"),
  false,
);

console.log("\n[rdp desktop size] a bad size must not cost the user the host");
const sizeOf = (raw: unknown): [number, number] | null => {
  const row = rdpOf(sanitizeHost(raw));
  return row ? [row.desktopWidth, row.desktopHeight] : null;
};
check("a good size survives", sizeOf(rdp({ desktopWidth: 1280, desktopHeight: 800 })), [1280, 800]);
check(
  "a zero size falls back instead of dropping the row",
  sizeOf(rdp({ desktopWidth: 0, desktopHeight: 0 })),
  [1600, 900],
);
check("so does an absurd one", sizeOf(rdp({ desktopWidth: 99999 })), [1600, 900]);
// The fixture's own height is deliberately NOT the fallback: `"800"` expecting 900
// proves the string was rejected and replaced, where `"900"` expecting 900 agreed
// with the fallback and with itself. The kept width proves the row was not
// wholesale defaulted on the way through.
check("and a non-number", sizeOf(rdp({ desktopWidth: 1280, desktopHeight: "800" })), [1280, 900]);
// Only one mode exists today. A file written by a later build must resolve to
// the mode THIS build can render, not to a string the pane cannot switch on.
check(
  "an unknown sizeMode becomes preset",
  rdpOf(sanitizeHost(rdp({ sizeMode: "fit" })))?.sizeMode,
  "preset",
);

console.log("\n[rdp tunnel] a bastion that did not travel must not break every connect");
check("a tunnel survives", tunnelOf(host(rdp({ tunnel: { sshHostId: "h-1" } }))), "h-1");
check("a tunnel with no id is dropped", tunnelOf(host(rdp({ tunnel: { sshHostId: "  " } }))), null);
check("a tunnel that is not an object is dropped", tunnelOf(host(rdp({ tunnel: "h-1" }))), null);
const tunnelled = [
  host(rdp({ id: "h-r1", tunnel: { sshHostId: "h-1" } })),
  host(rdp({ id: "h-r2", tunnel: { sshHostId: "gone" } })),
];
const cleared = clearDanglingTunnels(tunnelled, [host(ssh({ id: "h-1" }))]);
check("a resolvable bastion is kept", tunnelOf(cleared[0]), "h-1");
check("a dangling one is cleared", tunnelOf(cleared[1]), null);
check(
  "an SSH host in the SAME file counts as resolvable, not only a saved one",
  tunnelOf(clearDanglingTunnels([...tunnelled, host(ssh({ id: "gone", name: "bastion" }))], [])[1]),
  "gone",
);
// New with one merged store: the two old ones could not express an RDP bastion,
// and `upsertHost` throws on one rather than saving a row that cannot connect.
check(
  "an RDP row named as the bastion is cleared, not saved",
  tunnelOf(clearDanglingTunnels([host(rdp({ id: "h-r3", tunnel: { sshHostId: "h-9" } }))], [])[0]),
  null,
);
check(
  "a tunnel whose bastion's OWN jump host is missing is cleared too",
  tunnelOf(
    clearDanglingTunnels(
      [host(rdp({ id: "h-r4", tunnel: { sshHostId: "h-b" } }))],
      [host(ssh({ id: "h-b", proxyJumpId: "gone" }))],
    )[0],
  ),
  null,
);

console.log("\n[dangling jump hosts] upsertHost THROWS on these, so clear them first");
const jumps = [
  host(ssh({ id: "h-a", proxyJumpId: "h-b" })),
  host(ssh({ id: "h-b" })),
  host(ssh({ id: "h-c", proxyJumpId: "gone" })),
];
const clearedJumps = clearDanglingJumps(jumps, []);
check("a resolvable jump is kept", jumpOf(clearedJumps[0]), "h-b");
check("a dangling jump is cleared", jumpOf(clearedJumps[2]), null);
check(
  "a jump host already saved on THIS machine counts as resolvable",
  jumpOf(
    clearDanglingJumps(
      [host(ssh({ id: "h-x", proxyJumpId: "h-local" }))],
      [host(ssh({ id: "h-local" }))],
    )[0],
  ),
  "h-local",
);
// Three refusals a single merged store made possible, each of which throws at
// the write rather than saving a row that fails at connect.
check(
  "an RDP row named as the jump host is cleared",
  jumpOf(clearDanglingJumps([host(ssh({ id: "h-y", proxyJumpId: "h-9" })), host(rdp())], [])[0]),
  null,
);
check(
  "a host that names ITSELF is cleared",
  jumpOf(clearDanglingJumps([host(ssh({ id: "h-self", proxyJumpId: "h-self" }))], [])[0]),
  null,
);
// A 2-cycle used to save on both sides and then fail every connect to EITHER
// host. Both references go: there is no principled winner, and keeping one would
// mean this pass decided which of two hosts the user meant.
const cycle = clearDanglingJumps(
  [host(ssh({ id: "h-p", proxyJumpId: "h-q" })), host(ssh({ id: "h-q", proxyJumpId: "h-p" }))],
  [],
);
check("a cycle is cleared on both members", [jumpOf(cycle[0]), jumpOf(cycle[1])], [null, null]);
const longChain = Array.from({ length: 20 }, (_, i) =>
  host(ssh({ id: `h-${i}`, ...(i < 19 ? { proxyJumpId: `h-${i + 1}` } : {}) })),
);
check(
  "a chain past the hop cap is cleared rather than truncated",
  jumpOf(clearDanglingJumps(longChain, [])[0]),
  null,
);
check(
  "while a chain within it is left alone",
  jumpOf(clearDanglingJumps(longChain.slice(15), [])[0]),
  "h-16",
);

// THE BOUNDARY, and it is checked against `jumpChain` rather than against a
// literal. `MAX_JUMP_CHAIN` in the parser and `MAX_JUMP_HOPS` in the store are two
// numbers that have to agree, and only one of them is in this module: a chain the
// parser leaves in place is re-walked by `upsertHost`, which REFUSES an over-long
// one rather than truncating it, so a drift of one hop does not save a long chain -
// it abandons the rest of the file. A 20-chain and a 5-chain both pass either way.
const hops = (n: number): Host[] =>
  Array.from({ length: n + 1 }, (_, i) =>
    host(ssh({ id: `h-${i}`, ...(i < n ? { proxyJumpId: `h-${i + 1}` } : {}) })),
  );
const atCap = hops(MAX_JUMP_HOPS);
const pastCap = hops(MAX_JUMP_HOPS + 1);
check(
  "a chain of exactly the cap is left in place",
  jumpOf(clearDanglingJumps(atCap, [])[0]),
  "h-1",
);
check(
  "and the store walks exactly that chain",
  jumpChain("h-1", "h-0", atCap).length,
  MAX_JUMP_HOPS,
);
check(
  "one hop past the cap is cleared, not truncated",
  jumpOf(clearDanglingJumps(pastCap, [])[0]),
  null,
);
throws(
  "and the store would have thrown on it, which is what the clearing is for",
  () => jumpChain("h-1", "h-0", pastCap),
  "too long",
);

console.log("\n[write order] the store judges a chain against DISK, so the bastion goes first");
const chain = [
  host(ssh({ id: "h-a", proxyJumpId: "h-b" })),
  host(ssh({ id: "h-b", proxyJumpId: "h-c" })),
  host(ssh({ id: "h-c" })),
];
check(
  "the far end of the chain is written first",
  orderHostWrites(chain, []).map((h) => h.id),
  ["h-c", "h-b", "h-a"],
);
check("every host is written exactly once", orderHostWrites(chain, []).length, 3);
check(
  "a bastion already saved here needs no reordering",
  orderHostWrites(
    [host(ssh({ id: "h-a", proxyJumpId: "h-saved" }))],
    [host(ssh({ id: "h-saved" }))],
  ).map((h) => h.id),
  ["h-a"],
);
check(
  "an RDP host follows the bastion it tunnels through",
  orderHostWrites(
    [host(rdp({ id: "h-win", tunnel: { sshHostId: "h-b" } })), host(ssh({ id: "h-b" }))],
    [],
  ).map((h) => h.id),
  ["h-b", "h-win"],
);
// The subtle one. `h-a`'s direct target is already on disk, but the chain runs
// THROUGH it into a host that is still in the file - and the store re-walks the
// whole chain on every write, not just the first hop.
check(
  "a chain running through a saved host still orders the file's part first",
  orderHostWrites(
    [host(ssh({ id: "h-a", proxyJumpId: "h-b" })), host(ssh({ id: "h-c" }))],
    [host(ssh({ id: "h-b", proxyJumpId: "h-c" }))],
  ).map((h) => h.id),
  ["h-c", "h-a"],
);
// Unreachable in the import path - `clearDanglingJumps` runs first - but a hang
// here would take startup with it, so the guard is checked rather than assumed.
check(
  "a cycle that somehow survived still terminates",
  orderHostWrites(
    [host(ssh({ id: "h-p", proxyJumpId: "h-q" })), host(ssh({ id: "h-q", proxyJumpId: "h-p" }))],
    [],
  ).length,
  2,
);

console.log("\n[vault bindings] a backup carries no vault, so one must never be APPLIED");
// The failure this closes. `h-7` is a saved inline host holding the only copy of a
// passphrased key. A file says `h-7` is `{kind:"identity"}`; a vault-bound record
// owns no accounts, so `upsertHost` makes all three of that host's fields stale
// and deletes them - nothing copied them, `i-1` does not exist here, and there is
// no `secrets_list`. The import reported `withoutSecrets: 1`, which reads as "the
// credential did not travel" rather than "the credential is gone".
const savedKeyHost: SshHost = {
  ...sshHost(ssh({ id: "h-7" })),
  credential: {
    kind: "inline",
    hostId: "h-7",
    user: "deploy",
    authMode: "key",
    hasPassword: false,
    hasPrivateKey: true,
    hasKeyPassphrase: true,
  },
};
const overSaved = resolveIdentityBindings(
  [host(ssh({ id: "h-7", credential: { kind: "identity", identityId: "i-1" } }))],
  [savedKeyHost],
);
check(
  "landing on a saved inline host keeps that host's own credential, flags and all",
  overSaved.hosts[0].credential,
  savedKeyHost.credential,
);
check("and says so, rather than reporting a missing secret", overSaved.dropped, 1);
// The binding kind is what makes the delete happen, so the check that matters is
// that it did not change: same kind on both sides means nothing is stale.
check(
  "so the record still names the accounts it named before the import",
  overSaved.hosts[0].credential.kind,
  "inline",
);
const fresh = resolveIdentityBindings(
  [host(ssh({ id: "h-new", credential: { kind: "identity", identityId: "i-1" } }))],
  [],
);
check(
  "a host that is NOT saved here arrives as a blank inline row instead of vanishing",
  sshInline(fresh.hosts[0]),
  {
    kind: "inline",
    hostId: "h-new",
    user: "",
    authMode: "password",
    hasPassword: false,
    hasPrivateKey: false,
    hasKeyPassphrase: false,
  },
);
check(
  "its name and address still come through",
  [fresh.hosts[0].name, fresh.hosts[0].port],
  ["prod", 22],
);
check("and it is counted", fresh.dropped, 1);
// A machine re-importing its own backup: the saved binding IS what the file asked
// for, so nothing was refused and there is nothing to report.
const roundTrip = resolveIdentityBindings(
  [host(ssh({ id: "h-7", credential: { kind: "identity", identityId: "i-1" } }))],
  [{ ...sshHost(ssh({ id: "h-7" })), credential: { kind: "identity", identityId: "i-1" } }],
);
check(
  "a binding this machine already has is kept, and not counted",
  [roundTrip.hosts[0].credential, roundTrip.dropped],
  [{ kind: "identity", identityId: "i-1" }, 0],
);
check(
  "a DIFFERENT identity does not repoint the saved host at one it may not have",
  resolveIdentityBindings(
    [host(ssh({ id: "h-7", credential: { kind: "identity", identityId: "i-2" } }))],
    [{ ...sshHost(ssh({ id: "h-7" })), credential: { kind: "identity", identityId: "i-1" } }],
  ).hosts[0].credential,
  { kind: "identity", identityId: "i-1" },
);
const savedRdp: RdpHost = {
  ...rdpHost(rdp({ id: "h-9" })),
  credential: { kind: "inline", hostId: "h-9", username: "Administrator", hasPassword: true },
};
check(
  "the RDP side behaves identically, which is where the password would have gone",
  resolveIdentityBindings(
    [host(rdp({ id: "h-9", credential: { kind: "identity", identityId: "i-1" } }))],
    [savedRdp],
  ).hosts[0].credential,
  savedRdp.credential,
);
check(
  "and a new RDP row arrives blank rather than bound",
  rdpInline(
    resolveIdentityBindings(
      [host(rdp({ id: "h-fresh", credential: { kind: "identity", identityId: "i-1" } }))],
      [],
    ).hosts[0],
  ),
  { kind: "inline", hostId: "h-fresh", username: "", hasPassword: false },
);
const inlineOnly = resolveIdentityBindings([host(ssh()), host(rdp())], []);
check(
  "an inline row is passed through untouched and counted as nothing",
  [inlineOnly.hosts.map((h) => h.credential.kind), inlineOnly.dropped],
  [["inline", "inline"], 0],
);

console.log("\n[protocol conflicts] the other way a merge deletes a secret nothing copied");
// `h-7` is the same saved SSH host, holding the same private key; this time the
// file says it is an RDP host. An RDP record cannot NAME `privateKey` or
// `keyPassphrase`, so `upsertHost` releases both - and unlike the vault case there
// is not even a binding change to notice. Refused, because there is no version of
// the row that is both.
const flipped = refuseProtocolConflicts([host(rdp({ id: "h-7" }))], [savedKeyHost]);
check("an SSH host is not replaced by an RDP row", flipped.hosts, []);
check("and the refusal is counted", flipped.conflicts, 1);
check(
  "the flip that loses nothing is refused too: a saved host does not change kind",
  refuseProtocolConflicts([host(ssh({ id: "h-9" }))], [rdpHost(rdp({ id: "h-9" }))]).hosts.length,
  0,
);
check(
  "an id this machine has never seen is not a conflict",
  refuseProtocolConflicts([host(rdp({ id: "h-brand-new" }))], [savedKeyHost]).hosts.length,
  1,
);
check(
  "and neither is the same protocol, which is every ordinary re-import",
  refuseProtocolConflicts([host(ssh({ id: "h-7" }))], [savedKeyHost]).conflicts,
  0,
);

console.log("\n[pins] a pin the file carries belongs to the address the FILE names");
// The failure this closes, and it is not a rounding error. The store's `nextPins`
// has to give an unkeyed pin an address, and with no map handed over it uses the
// SAVED record's - correct for a `{ ...stored, host: next }` spread, wrong for a
// file, whose row is not a spread of anything on this machine. Let the file name
// `c.example` for an id saved here as `b.example` (which is what
// `ImportCounts.replaced` exists for) and the guess replaces `b.example`'s
// verified key with the other machine's, so every later connect to `b.example`
// aborts as a MISMATCH and can never TOFU past it - while `c.example`, the address
// actually about to be dialled, is left silently unpinned.
check(
  "a keyed map survives the parser, every address of it",
  host(ssh({ host: "c.example", pins: { "b.example": "SHA256:B", "c.example": "SHA256:C" } })).pins,
  { "b.example": "SHA256:B", "c.example": "SHA256:C" },
);
check(
  "a row carrying only a flat pin is keyed onto the address the FILE names",
  host(ssh({ host: "c.example", lastFingerprint: "SHA256:C" })).pins,
  { "c.example": "SHA256:C" },
);
check(
  "the RDP arm the same, off certFingerprint - only the flat field's NAME differs",
  host(rdp({ host: "r.example", certFingerprint: "SHA256:CERT" })).pins,
  { "r.example": "SHA256:CERT" },
);
check(
  "and a v1 row, which is the format that only ever had a flat pin",
  sanitizeLegacyHost(legacy({ host: "v1.example", lastFingerprint: "SHA256:V1" }))?.pins,
  { "v1.example": "SHA256:V1" },
);
// ABSENT, never `{}`. An empty map is Forget's spelling - "discard every pin for
// this host" - and a file that carries no pins may not say that on this machine's
// behalf. `undefined` is what the store reads as "leave what is stored alone".
check(
  "a row with no pin of any kind carries no map at all",
  Object.prototype.hasOwnProperty.call(host(ssh()), "pins"),
  false,
);
check(
  "and neither does one whose map is empty",
  Object.prototype.hasOwnProperty.call(host(ssh({ pins: {} })), "pins"),
  false,
);
// Untrusted like every other field here. A blank key is an address nothing dials,
// and a blank value would read as "a key is pinned here" to every consumer of the
// flat projection while matching no server that ever answers.
check(
  "a blank address, a blank fingerprint and a non-string are each dropped",
  host(
    ssh({
      host: "c.example",
      pins: { "  ": "SHA256:X", "d.example": "   ", "e.example": 7, "f.example": "SHA256:F" },
    }),
  ).pins,
  { "f.example": "SHA256:F" },
);
check(
  "a map with nothing usable left in it falls back to the flat pin rather than to nothing",
  host(ssh({ host: "c.example", lastFingerprint: "SHA256:C", pins: { "": "" } })).pins,
  { "c.example": "SHA256:C" },
);
check(
  "a map that is not an object is ignored rather than spread",
  host(ssh({ host: "c.example", lastFingerprint: "SHA256:C", pins: ["c.example"] })).pins,
  { "c.example": "SHA256:C" },
);
check(
  "an address is trimmed, so it matches the address the store keys on",
  host(ssh({ host: "c.example", pins: { " c.example ": " SHA256:C " } })).pins,
  { "c.example": "SHA256:C" },
);

console.log("\n[pins] the import hands the store a map, so nothing is inferred from an address");
// A pre-keying SAVED record: flat pin, no map. Built by hand rather than through
// the parser, because the parser now keys one - and this is the shape a store file
// written before keying still holds.
const savedFlat: SshHost = {
  ...sshHost(ssh({ id: "h-1", host: "b.example" })),
  lastFingerprint: "SHA256:B",
};
const savedKeyed: SshHost = {
  ...sshHost(ssh({ id: "h-1", host: "b.example" })),
  pins: { "b.example": "SHA256:B" },
  lastFingerprint: "SHA256:B",
};
const fileAtC = host(ssh({ id: "h-1", host: "c.example", lastFingerprint: "SHA256:C" }));
check(
  "the file's pin lands on the file's address, and the saved address keeps its own",
  carryPins([fileAtC], [savedKeyed])[0].pins,
  // The file's address first, which is NOT the order the union inserts them in.
  // Deliberate: which pins survive is the contract here, and their key order is
  // not, so the check must not be sensitive to it - see `shape`.
  { "c.example": "SHA256:C", "b.example": "SHA256:B" },
);
check(
  "a saved record written before keying is read the same way round, so its pin is not lost",
  carryPins([fileAtC], [savedFlat])[0].pins,
  { "b.example": "SHA256:B", "c.example": "SHA256:C" },
);
// A union, not a replacement: nothing else about an import deletes anything, and a
// key this machine verified for an address the file never heard of is in exactly
// that class. Dropping it is a silent TOFU downgrade for a machine already trusted.
check(
  "an address only THIS machine knows survives a file that never heard of it",
  carryPins(
    [host(ssh({ id: "h-1", host: "c.example", pins: { "c.example": "SHA256:C" } }))],
    [savedKeyed],
  )[0].pins,
  { "b.example": "SHA256:B", "c.example": "SHA256:C" },
);
check(
  "the file wins at an address both name, which is its authority over every other field",
  carryPins(
    [host(ssh({ id: "h-1", host: "b.example", lastFingerprint: "SHA256:NEW" }))],
    [savedKeyed],
  )[0].pins,
  { "b.example": "SHA256:NEW" },
);
check(
  "a file row with no pins hands over what this machine trusted rather than clearing it",
  carryPins([host(ssh({ id: "h-1", host: "b.example" }))], [savedKeyed])[0].pins,
  { "b.example": "SHA256:B" },
);
check("an id this machine has never seen carries only its own", carryPins([fileAtC], [])[0].pins, {
  "c.example": "SHA256:C",
});
check(
  "and a row with no pins on either side grows no empty map",
  Object.prototype.hasOwnProperty.call(carryPins([host(ssh({ id: "h-2" }))], [])[0], "pins"),
  false,
);
// §5.6 is not weakened by this pass running after it: it touches `pins` and nothing
// else, so the credential the vault pass CHOSE is the one that gets written, and the
// row still names the address the file gave it. A version that spread the saved
// record instead of the incoming one would silently undo both.
const afterBindings = carryPins(
  resolveIdentityBindings(
    [
      host(
        ssh({ id: "h-7", host: "c.example", credential: { kind: "identity", identityId: "i-1" } }),
      ),
    ],
    [savedKeyHost],
  ).hosts,
  [savedKeyHost],
);
check(
  "the credential the vault pass chose survives the pin pass",
  afterBindings[0].credential,
  savedKeyHost.credential,
);
check(
  "and so does the address the file named, which is what the row will be dialled at",
  afterBindings[0].host,
  "c.example",
);

console.log("\n[secret refs] what an export sends, and what an import claims was stored");
// One ref per field a host COULD own, including the ones with nothing behind them:
// the host process answers `false` for a ref that resolves to nothing, which keeps
// "what exists" in the one place that can answer it.
check(
  "an inline SSH host contributes one ref per field",
  hostRefs(host(ssh())).map((r) => r.field),
  ["password", "privateKey", "keyPassphrase"],
);
check("addressed at the host service, under <id>::<field>", hostRefs(host(ssh()))[1], {
  group: "hostSecrets",
  id: "h-1",
  field: "privateKey",
  service: "tervia-hosts",
  account: "h-1::privateKey",
});
check(
  "an inline RDP host contributes exactly one, because it owns exactly one account",
  hostRefs(host(rdp())).map((r) => r.field),
  ["password"],
);
check(
  "an agent-auth host still contributes all three: what exists is Rust's answer",
  hostRefs(
    host(ssh({ credential: { kind: "inline", hostId: "h-1", user: "r", authMode: "agent" } })),
  ).length,
  3,
);
// A vault-bound host owns nothing on this service, so an export that named its
// accounts would be naming somebody else's, and an import that wrote them would
// put bytes where nothing reads them.
const vaultBound = host(ssh({ id: "h-v", credential: { kind: "identity", identityId: "i-1" } }));
check("a vault-bound host contributes none", hostRefs(vaultBound).length, 0);

/** Which fields were claimed as ALREADY STORED, by name. Read out by name because
 *  the names ARE the contract - `storedFields` promises a claim per field - which
 *  keeps the assertion off how a symbol happens to render. */
const claimed = (h: Host, landed: string[]): string[] =>
  Object.entries(storedFields(h, new Set(landed)))
    .filter(([, v]) => v === SECRET_ALREADY_STORED)
    .map(([k]) => k);

check(
  "every field that landed is claimed",
  claimed(host(ssh()), ["h-1::password", "h-1::privateKey", "h-1::keyPassphrase"]),
  ["password", "privateKey", "keyPassphrase"],
);
// PER FIELD, which is the whole point: the store takes an untouched field's flag
// from the stored record, and for a host it has never seen that is false over a
// live secret - which `RdpPane` pre-flights and refuses to connect on.
check(
  "and only those, so a partial arrival is reported partially",
  claimed(host(ssh()), ["h-1::privateKey"]),
  ["privateKey"],
);
check("nothing landed, nothing claimed", claimed(host(ssh()), []), []);
check("the RDP row claims its one field", claimed(host(rdp()), ["h-9::password"]), ["password"]);
// `HOST_SSH_PRIVATE_KEY_FIELD` and the RDP password field share an id space now,
// so the guard is the protocol arm rather than the account name.
check(
  "an RDP row claims nothing from an SSH field, even at its own id",
  claimed(host(rdp()), ["h-9::privateKey", "h-9::keyPassphrase"]),
  [],
);
check(
  "a vault-bound host claims nothing, which is what stops upsertHost refusing the row",
  claimed(vaultBound, ["h-v::password"]),
  [],
);
check(
  "and what is claimed is the symbol, never a string a file could carry",
  Object.values(storedFields(host(ssh()), new Set(["h-1::password"]))).map((v) => typeof v),
  ["symbol"],
);

console.log("\n[without secrets] counted per FIELD, against the mode that needs it");
const missing = (raw: unknown, landed: string[]): boolean => {
  const h = host(raw);
  return arrivedWithoutSecret(h, storedFields(h, new Set(landed)));
};
const keyAuth = ssh({ credential: { kind: "inline", hostId: "h-1", user: "r", authMode: "key" } });
const agentAuth = ssh({
  credential: { kind: "inline", hostId: "h-1", user: "r", authMode: "agent" },
});
check("password auth with no password is counted", missing(ssh(), []), true);
check("password auth with one is not", missing(ssh(), ["h-1::password"]), false);
// The case a per-host answer got wrong: something landed, so it reported fine,
// and the host cannot connect because the thing that landed was the passphrase.
check(
  "key auth whose passphrase arrived and whose KEY did not is counted",
  missing(keyAuth, ["h-1::keyPassphrase"]),
  true,
);
check("key auth with the key is not", missing(keyAuth, ["h-1::privateKey"]), false);
check(
  "and a key with no passphrase is ordinary, not missing one",
  missing(keyAuth, ["h-1::privateKey"]),
  false,
);
// Agent auth stores nothing by design, so reporting it as missing a credential
// would read as a broken import.
check("agent auth is never counted", missing(agentAuth, []), false);
check("an RDP host with no password is counted", missing(rdp(), []), true);
check("and with one is not", missing(rdp(), ["h-9::password"]), false);
check(
  "a host that kept a vault binding is not counted: its credential is already here",
  arrivedWithoutSecret(vaultBound, {}),
  false,
);

console.log("\n[groups] merged by id, but a name is unique so a collision has to resolve");
check("a good group survives", sanitizeGroup({ id: "g-1", name: "prod" }), {
  id: "g-1",
  name: "prod",
});
check("order rides along", sanitizeGroup({ id: "g-1", name: "prod", order: 2 })?.order, 2);
check("a non-numeric order is ignored", sanitizeGroup({ id: "g-1", name: "prod", order: "2" }), {
  id: "g-1",
  name: "prod",
});
// `upsertGroup` refuses a blank name, because a group is picked by name from a
// dropdown - so a blank one is unpickable and would abort the import.
check("a blank name is dropped", sanitizeGroup({ id: "g-1", name: "   " }), null);
check("so is a missing id", sanitizeGroup({ name: "prod" }), null);
check("and a non-object", sanitizeGroup("g-1"), null);

const collide = mergeGroups(
  [{ id: "g-file", name: "Prod" }],
  [{ id: "g-local", name: " prod " }],
  [host(ssh({ groupId: "g-file" }))],
);
check("a name already held here is not written a second time", collide.groups, []);
check(
  "and its members are repointed at the group that holds the name",
  collide.hosts[0].groupId,
  "g-local",
);
check("and the merge is counted, so it is not silent", [collide.merged, collide.keptNames], [1, 0]);
check(
  "the same id under the same name is an ordinary replace",
  mergeGroups([{ id: "g-1", name: "prod" }], [{ id: "g-1", name: "prod" }], []).groups.map(
    (g) => g.id,
  ),
  ["g-1"],
);
// The other collision, and it resolves the other way. `upsertGroup` would take
// this write - same id, so no uniqueness to violate - and relabel every local host
// in the group: a file where `g-9` is "prod" turns six local staging boxes into
// prod boxes, in a list whose whole job is telling those two apart.
const renamed = mergeGroups(
  [{ id: "g-9", name: "prod" }],
  [{ id: "g-9", name: "staging" }],
  [host(ssh({ groupId: "g-9" }))],
);
check("an incoming rename of a saved group is not written", renamed.groups, []);
check("the local label is kept, and counted", [renamed.keptNames, renamed.merged], [1, 0]);
check("its hosts need no repoint, because the id never changed", renamed.hosts[0].groupId, "g-9");
check(
  "a rename that is only whitespace or case is not one, so the row still writes",
  mergeGroups([{ id: "g-9", name: " PROD " }], [{ id: "g-9", name: "prod" }], []).groups.map(
    (g) => g.name,
  ),
  [" PROD "],
);
// The id check runs FIRST: the local group already holds its own name, so a
// skipped row must not be remapped onto whichever group happens to hold the name
// it wanted. The id is the stronger identity - hosts merge by it.
const bothCollide = mergeGroups(
  [{ id: "g-9", name: "prod" }],
  [
    { id: "g-9", name: "staging" },
    { id: "g-5", name: "prod" },
  ],
  [host(ssh({ groupId: "g-9" }))],
);
check(
  "an id collision beats a name collision, so the host keeps its own group",
  [bothCollide.groups, bothCollide.hosts[0].groupId, bothCollide.keptNames],
  [[], "g-9", 1],
);
const twoIncoming = mergeGroups(
  [
    { id: "g-1", name: "prod" },
    { id: "g-2", name: "PROD" },
  ],
  [],
  [host(ssh({ groupId: "g-2" }))],
);
check(
  "two groups in the FILE colliding with each other resolve the same way",
  twoIncoming.groups.map((g) => g.id),
  ["g-1"],
);
check("the loser's members follow the winner", twoIncoming.hosts[0].groupId, "g-1");
check(
  "a host in no group is left alone",
  mergeGroups([{ id: "g-1", name: "prod" }], [{ id: "g-2", name: "prod" }], [host(ssh())]).hosts[0]
    .groupId,
  undefined,
);

console.log("\n[v2 payload] the same validation, after decryption instead of before");
const payload = sanitizePayload({
  hosts: [ssh(), ssh({ id: "h-2", port: 0 }), ssh({ id: "h-3" }), ssh()],
  groups: [
    { id: "g-1", name: "prod" },
    { id: "g-1", name: "dup" },
  ],
});
check(
  "good hosts survive",
  payload.hosts.map((h) => h.id),
  ["h-1", "h-3"],
);
check(
  "good groups survive",
  payload.groups.map((g) => g.id),
  ["g-1"],
);
// Two bad hosts (port 0, duplicate id) and one bad group (duplicate id): the
// count is across every collection in the payload.
check("skipped counts them all", payload.skipped, 3);
check("an empty payload is not an error", sanitizePayload({}), {
  hosts: [],
  groups: [],
  skipped: 0,
});
check("a payload with only RDP hosts is fine", sanitizePayload({ hosts: [rdp()] }).hosts.length, 1);
check("a payload with no groups is fine", sanitizePayload({ hosts: [ssh()] }).groups, []);
// ONE id space now, and this is the check that changed meaning rather than
// moving. Two stores on two keychain services could keep a `c-1` and an `r-1`
// apart, so an id shared across protocols kept both rows. One store on one
// service cannot: the second row is the same record slot and the same accounts,
// so it is skipped and counted instead.
const shared = sanitizePayload({ hosts: [ssh({ id: "h-same" }), rdp({ id: "h-same" })] });
check(
  "an id used by both protocols keeps the first row and counts the second",
  [shared.hosts.length, shared.hosts[0].protocol, shared.skipped],
  [1, "ssh", 1],
);
throws("a payload that is not an object", () => sanitizePayload([1, 2]), "did not contain");
throws("a payload that is null", () => sanitizePayload(null), "did not contain");
throws("a host inventory that is not a list", () => sanitizePayload({ hosts: {} }), "not a list");
throws("a group list that is not a list", () => sanitizePayload({ groups: "g-1" }), "not a list");
// v2 credentials never come back to JS: the payload the host process returns has
// the secret group removed, and nothing here reads it even if a hand-made file
// puts it back.
check(
  "the secret group in the payload is ignored, not imported",
  Object.keys(
    sanitizePayload({ hosts: [ssh()], hostSecrets: { "h-1": { password: "pw" } } }),
  ).sort(),
  ["groups", "hosts", "skipped"],
);

console.log("\n[v1 list handling] bad entries are skipped and counted, not fatal");
const mixed = parseBackupFile(
  v1({ connections: [legacy(), legacy({ id: "c-2", port: 0 }), null, legacy({ id: "c-3" })] }),
);
check("two good entries survive", mixed.version === 1 ? mixed.hosts.map((h) => h.id) : null, [
  "c-1",
  "c-3",
]);
check("two bad entries counted", mixed.version === 1 ? mixed.skipped : null, 2);
// A duplicate id would import twice and the second would silently win.
const dupes = parseBackupFile(v1({ connections: [legacy(), legacy({ name: "other" })] }));
check("a duplicate id is skipped", dupes.version === 1 ? dupes.hosts.length : null, 1);
check("the first one wins", dupes.version === 1 ? dupes.hosts[0].name : null, "prod");
check("and it is counted", dupes.version === 1 ? dupes.skipped : null, 1);

console.log("\n[secrets] the decrypted v1 payload is validated before it reaches the keychain");
check(
  "well-formed entries survive",
  sanitizeSecrets({ "c-1": { password: "pw", privateKey: "k", keyPassphrase: "p" } }),
  { "c-1": { password: "pw", privateKey: "k", keyPassphrase: "p" } },
);
check("non-string values are dropped", sanitizeSecrets({ "c-1": { password: 123 } }), {});
check("empty strings are dropped", sanitizeSecrets({ "c-1": { password: "" } }), {});
check("a non-object entry is skipped", sanitizeSecrets({ "c-1": "pw" }), {});
check("junk is not fatal", sanitizeSecrets(null), {});
check("an array is not fatal", sanitizeSecrets([1, 2]), {});
check(
  "a partial entry keeps only what is there",
  sanitizeSecrets({ "c-1": { privateKey: "k", password: null } }),
  { "c-1": { privateKey: "k" } },
);

console.log("\n[round trip] the shape an export actually writes");
const real = sanitizePayload({
  hosts: [
    ssh({ id: "h-bastion", name: "bastion" }),
    ssh({ id: "h-db", proxyJumpId: "h-bastion" }),
    rdp({ id: "h-win", tunnel: { sshHostId: "h-bastion" } }),
    ssh({ id: "h-vault", credential: { kind: "identity", identityId: "i-1" } }),
  ],
  groups: [{ id: "g-1", name: "prod" }],
});
check("every host survives", [real.hosts.length, real.groups.length], [4, 1]);
check("nothing skipped", real.skipped, 0);
check("the jump chain is intact", jumpOf(real.hosts[1]), "h-bastion");
check("the RDP tunnel points at the imported bastion", tunnelOf(real.hosts[2]), "h-bastion");
check(
  "the parser leaves the vault-bound host's binding to be judged",
  real.hosts[3].credential.kind,
  "identity",
);
// The whole pipeline in the order `applyV2` runs it, on a fresh machine: nothing
// is saved here, so the vault-bound row lands inline and blank rather than binding
// to an identity this machine does not have.
const pipeline = ((): Host[] => {
  const kinds = refuseProtocolConflicts(real.hosts, []);
  const bound = resolveIdentityBindings(kinds.hosts, []);
  return orderHostWrites(clearDanglingTunnels(clearDanglingJumps(bound.hosts, []), []), []);
})();
check(
  "and the write order puts the bastion ahead of both things that need it",
  pipeline.map((h) => h.id),
  ["h-bastion", "h-db", "h-win", "h-vault"],
);
check(
  "with every row inline by the time it reaches the store",
  pipeline.map((h) => h.credential.kind),
  ["inline", "inline", "inline", "inline"],
);

console.log("\n[auth mode] every mode survives an import and maps to the right wire fields");
check(
  "agent auth is preserved (it was coerced to password before the mode existed)",
  sshInline(
    host(ssh({ credential: { kind: "inline", hostId: "h-1", user: "r", authMode: "agent" } })),
  )?.authMode,
  "agent",
);
check(
  "an unknown mode still falls back to password",
  sshInline(
    host(ssh({ credential: { kind: "inline", hostId: "h-1", user: "r", authMode: "totp" } })),
  )?.authMode,
  "password",
);
check(
  "and a v1 row's top-level mode is read the same way",
  sshInline(sanitizeLegacyHost(legacy({ authMode: "agent" })))?.authMode,
  "agent",
);
// `sshCredentialValues` is the ONE place that turns a saved mode into credentials
// on the wire (it backs `resolveSshAuth`, so terminal session, tunnel, jump hops
// and the dialog's Test all reach it). The agent case matters most: it must send
// the flag and NOTHING else, or a stale key from a previous mode would ride along.
const secrets = { password: "pw", privateKey: "KEY", keyPassphrase: "pp" };
check("password mode sends only the password", sshCredentialValues("password", secrets), {
  password: "pw",
});
check("key mode sends the key and its passphrase", sshCredentialValues("key", secrets), {
  privateKey: "KEY",
  privateKeyPassphrase: "pp",
});
check("agent mode sends no secret at all", sshCredentialValues("agent", secrets), {
  useAgent: true,
});
check("agent mode ignores leftovers in the keychain", sshCredentialValues("agent", {}), {
  useAgent: true,
});
check(
  "a missing secret becomes undefined, not an empty string",
  JSON.stringify(sshCredentialValues("password", { password: "" })),
  "{}",
);

console.log(failed === 0 ? "\nAll ssh-backup checks passed." : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
