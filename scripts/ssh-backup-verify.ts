/**
 * Self-check for the connection backup parser, both format generations.
 * Run: `npx tsx scripts/ssh-backup-verify.ts`.
 *
 * Importing a backup is a TRUST BOUNDARY: the file arrives from a USB stick or
 * a chat, and everything that survives it is written into the connections
 * stores and later dialled. The failures this pins down are the quiet ones - a
 * port of 0 or 99999 reaching `TcpStream::connect`, a `proxyJumpId` or an RDP
 * `tunnel` pointing at a host that does not exist (which makes every connect
 * through it fail with a message about a host the user never deleted), a
 * duplicate id where the second entry silently wins, and `hasPassword: true`
 * copied from the file so the UI claims a credential that is not in the
 * keychain.
 *
 * The v1/v2 split matters here because the boundary MOVED. In v1 the inventory
 * is plaintext, so `parseBackupFile` validates it; in v2 the whole payload is
 * sealed, so `parseBackupFile` can only check the envelope and
 * `sanitizePayload` does the per-connection work after the host process has
 * decrypted. Both halves are exercised below - a v2 file that got only the
 * envelope check would write unvalidated rows into the store.
 *
 * The crypto itself, and the v2 payload assembly that keeps credentials out of
 * the webview, are checked on the Rust side (`modules/backup.rs` tests: round
 * trip, wrong passphrase, tampered ciphertext, nonce reuse, group merge/split,
 * the parked-handle lifecycle).
 */
import {
  BACKUP_KIND,
  BACKUP_KIND_V1,
  clearDanglingJumps,
  clearDanglingTunnels,
  parseBackupFile,
  sanitizeConnection,
  sanitizePayload,
  sanitizeRdpConnection,
  sanitizeSecrets,
} from "../src/modules/ssh/backupFile";
import { authFields } from "../src/modules/ssh/connections";

let failed = 0;
function check(label: string, got: unknown, want: unknown): void {
  if (JSON.stringify(got) === JSON.stringify(want)) {
    console.log(`  ok: ${label}`);
  } else {
    console.error(`  FAIL: ${label} = ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
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
const conn = (over: Record<string, unknown> = {}) => ({
  id: "c-1",
  name: "prod",
  host: "example.com",
  port: 22,
  user: "root",
  authMode: "password",
  ...over,
});
const rdp = (over: Record<string, unknown> = {}) => ({
  id: "r-1",
  name: "win",
  host: "vps.example.com",
  port: 3389,
  username: "Administrator",
  desktopWidth: 1600,
  desktopHeight: 900,
  sizeMode: "preset",
  ...over,
});

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
// than import a partial connection.
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
  () => parseBackupFile(v2({ payload: undefined, connections: [conn()], secrets: SEALED })),
  "encrypted payload",
);

console.log("\n[v1 envelope] old files still import");
const v1parsed = parseBackupFile(v1({ connections: [conn()] }));
check("version is reported", v1parsed.version, 1);
check(
  "the plaintext inventory is validated at parse time",
  v1parsed.version === 1 ? v1parsed.connections.map((c) => c.id) : null,
  ["c-1"],
);
throws("no connections list", () => parseBackupFile(v1({ connections: {} })), "connections");
throws("no secrets block", () => parseBackupFile(v1({ secrets: undefined })), "credentials");
throws(
  "half a secrets block",
  () => parseBackupFile(v1({ secrets: { kdf: "x" } })),
  "credentials",
);

console.log("\n[ports] what would otherwise reach TcpStream::connect");
check("22 is fine", sanitizeConnection(conn())?.port, 22);
check("65535 is fine", sanitizeConnection(conn({ port: 65535 }))?.port, 65535);
check("0 is dropped", sanitizeConnection(conn({ port: 0 })), null);
check("65536 is dropped", sanitizeConnection(conn({ port: 65536 })), null);
check("negative is dropped", sanitizeConnection(conn({ port: -1 })), null);
check("a float is dropped", sanitizeConnection(conn({ port: 22.5 })), null);
check("a string is dropped", sanitizeConnection(conn({ port: "22" })), null);
check("NaN is dropped", sanitizeConnection(conn({ port: Number.NaN })), null);
check("and the same on the RDP side", sanitizeRdpConnection(rdp({ port: 0 })), null);

console.log("\n[required fields]");
check("no id", sanitizeConnection(conn({ id: "" })), null);
check("no host", sanitizeConnection(conn({ host: "   " })), null);
check("not an object", sanitizeConnection("c-1"), null);
check(
  "a blank name falls back to the host",
  sanitizeConnection(conn({ name: "" }))?.name,
  "example.com",
);
check("no RDP id", sanitizeRdpConnection(rdp({ id: "" })), null);
check("no RDP host", sanitizeRdpConnection(rdp({ host: "" })), null);
check(
  "a blank RDP name falls back to the host too",
  sanitizeRdpConnection(rdp({ name: "" }))?.name,
  "vps.example.com",
);

console.log("\n[credential flags] never trusted from the file, or the UI pips lie");
const flagged = sanitizeConnection(
  conn({ hasPassword: true, hasPrivateKey: true, hasKeyPassphrase: true }),
);
check(
  "all three are forced false",
  [flagged?.hasPassword, flagged?.hasPrivateKey, flagged?.hasKeyPassphrase],
  [false, false, false],
);
check(
  "the RDP flag is forced false as well",
  sanitizeRdpConnection(rdp({ hasPassword: true }))?.hasPassword,
  false,
);

console.log("\n[carried fields]");
check(
  "the pinned host key survives, so the new machine keeps the TOFU anchor",
  sanitizeConnection(conn({ lastFingerprint: "SHA256:abc" }))?.lastFingerprint,
  "SHA256:abc",
);
check(
  "an unknown authMode falls back to password",
  sanitizeConnection(conn({ authMode: "sso" }))?.authMode,
  "password",
);
check("key auth survives", sanitizeConnection(conn({ authMode: "key" }))?.authMode, "key");
check("proxyJumpId survives", sanitizeConnection(conn({ proxyJumpId: "c-2" }))?.proxyJumpId, "c-2");
check(
  "the pinned RDP certificate survives for the same reason",
  sanitizeRdpConnection(rdp({ certFingerprint: "49:67:09" }))?.certFingerprint,
  "49:67:09",
);
check(
  "domain and description survive",
  [
    sanitizeRdpConnection(rdp({ domain: "CORP" }))?.domain,
    sanitizeRdpConnection(rdp({ description: "note" }))?.description,
  ],
  ["CORP", "note"],
);
check(
  "an absent domain stays absent rather than becoming an empty string",
  Object.prototype.hasOwnProperty.call(sanitizeRdpConnection(rdp()) ?? {}, "domain"),
  false,
);

console.log("\n[rdp desktop size] a bad size must not cost the user the host");
check(
  "a good size survives",
  [
    sanitizeRdpConnection(rdp({ desktopWidth: 1280, desktopHeight: 800 }))?.desktopWidth,
    sanitizeRdpConnection(rdp({ desktopWidth: 1280, desktopHeight: 800 }))?.desktopHeight,
  ],
  [1280, 800],
);
check(
  "a zero size falls back instead of dropping the row",
  [
    sanitizeRdpConnection(rdp({ desktopWidth: 0, desktopHeight: 0 }))?.desktopWidth,
    sanitizeRdpConnection(rdp({ desktopWidth: 0, desktopHeight: 0 }))?.desktopHeight,
  ],
  [1600, 900],
);
check(
  "so does an absurd one",
  sanitizeRdpConnection(rdp({ desktopWidth: 99999 }))?.desktopWidth,
  1600,
);
check(
  "and a non-number",
  sanitizeRdpConnection(rdp({ desktopHeight: "900" }))?.desktopHeight,
  900,
);
// Only one mode exists today. A file written by a later build must resolve to
// the mode THIS build can render, not to a string the pane cannot switch on.
check(
  "an unknown sizeMode becomes preset",
  sanitizeRdpConnection(rdp({ sizeMode: "fit" }))?.sizeMode,
  "preset",
);

console.log("\n[rdp tunnel] a bastion that did not travel must not break every connect");
check(
  "a tunnel survives",
  sanitizeRdpConnection(rdp({ tunnel: { sshConnectionId: "c-1" } }))?.tunnel,
  { sshConnectionId: "c-1" },
);
check(
  "a tunnel with no id is dropped",
  sanitizeRdpConnection(rdp({ tunnel: { sshConnectionId: "  " } }))?.tunnel,
  undefined,
);
check(
  "a tunnel that is not an object is dropped",
  sanitizeRdpConnection(rdp({ tunnel: "c-1" }))?.tunnel,
  undefined,
);
const tunnelled = [
  sanitizeRdpConnection(rdp({ id: "r-1", tunnel: { sshConnectionId: "c-1" } })),
  sanitizeRdpConnection(rdp({ id: "r-2", tunnel: { sshConnectionId: "gone" } })),
].flatMap((c) => (c ? [c] : []));
const clearedTunnels = clearDanglingTunnels(tunnelled, new Set(["c-1"]));
check("a resolvable bastion is kept", clearedTunnels[0].tunnel, { sshConnectionId: "c-1" });
check("a dangling one is cleared", clearedTunnels[1].tunnel, undefined);
check(
  "an SSH host already saved on THIS machine counts as resolvable",
  clearDanglingTunnels(tunnelled.slice(1), new Set(["gone"]))[0].tunnel,
  { sshConnectionId: "gone" },
);

console.log("\n[forwards] a bad rule must not look configured while binding nothing");
check(
  "a good rule survives",
  sanitizeConnection(
    conn({ forwards: [{ localPort: 8080, remoteHost: "127.0.0.1", remotePort: 80 }] }),
  )?.forwards,
  [{ localPort: 8080, remoteHost: "127.0.0.1", remotePort: 80 }],
);
// localPort 0 is meaningful (bind an ephemeral port); remotePort 0 is not.
check(
  "localPort 0 is kept, it means 'pick a free port'",
  sanitizeConnection(conn({ forwards: [{ localPort: 0, remoteHost: "db", remotePort: 5432 }] }))
    ?.forwards,
  [{ localPort: 0, remoteHost: "db", remotePort: 5432 }],
);
check(
  "remotePort 0 is dropped",
  sanitizeConnection(conn({ forwards: [{ localPort: 1, remoteHost: "db", remotePort: 0 }] }))
    ?.forwards,
  undefined,
);
check(
  "a missing remoteHost is dropped",
  sanitizeConnection(conn({ forwards: [{ localPort: 1, remotePort: 5432 }] }))?.forwards,
  undefined,
);
check(
  "forwards that is not an array is ignored",
  sanitizeConnection(conn({ forwards: "8080:80" }))?.forwards,
  undefined,
);
check(
  "a bad rule is dropped without taking the good one with it",
  sanitizeConnection(
    conn({ forwards: [{ localPort: 1, remoteHost: "a", remotePort: 2 }, { localPort: 3 }] }),
  )?.forwards,
  [{ localPort: 1, remoteHost: "a", remotePort: 2 }],
);

console.log("\n[v1 list handling] bad entries are skipped and counted, not fatal");
const mixed = parseBackupFile(
  v1({ connections: [conn(), conn({ id: "c-2", port: 0 }), null, conn({ id: "c-3" })] }),
);
check(
  "two good entries survive",
  mixed.version === 1 ? mixed.connections.map((c) => c.id) : null,
  ["c-1", "c-3"],
);
check("two bad entries counted", mixed.version === 1 ? mixed.skipped : null, 2);
// A duplicate id would import twice and the second would silently win.
const dupes = parseBackupFile(v1({ connections: [conn(), conn({ name: "other" })] }));
check("a duplicate id is skipped", dupes.version === 1 ? dupes.connections.length : null, 1);
check("the first one wins", dupes.version === 1 ? dupes.connections[0].name : null, "prod");
check("and it is counted", dupes.version === 1 ? dupes.skipped : null, 1);

console.log("\n[v2 payload] the same validation, after decryption instead of before");
const payload = sanitizePayload({
  connections: [conn(), conn({ id: "c-2", port: 0 }), conn({ id: "c-3" }), conn()],
  rdpConnections: [rdp(), rdp({ id: "r-2", host: "" }), rdp()],
});
check("good SSH rows survive", payload.connections.map((c) => c.id), ["c-1", "c-3"]);
check("good RDP rows survive", payload.rdpConnections.map((c) => c.id), ["r-1"]);
// Two bad SSH entries (port 0, duplicate id) and two bad RDP ones (no host,
// duplicate id): the count is across both inventories.
check("skipped counts both protocols", payload.skipped, 4);
check("an empty payload is not an error", sanitizePayload({}), {
  connections: [],
  rdpConnections: [],
  skipped: 0,
});
check(
  "a payload with only RDP hosts is fine",
  sanitizePayload({ rdpConnections: [rdp()] }).rdpConnections.length,
  1,
);
// The same id in both inventories is odd but harmless: separate stores,
// separate keychain services. Dropping one of them would lose a host.
check(
  "an id shared across protocols keeps both",
  (() => {
    const p = sanitizePayload({
      connections: [conn({ id: "shared" })],
      rdpConnections: [rdp({ id: "shared" })],
    });
    return [p.connections.length, p.rdpConnections.length, p.skipped];
  })(),
  [1, 1, 0],
);
throws("a payload that is not an object", () => sanitizePayload([1, 2]), "did not contain");
throws("a payload that is null", () => sanitizePayload(null), "did not contain");
throws(
  "an SSH inventory that is not a list",
  () => sanitizePayload({ connections: {} }),
  "not a list",
);
throws(
  "an RDP inventory that is not a list",
  () => sanitizePayload({ rdpConnections: "r-1" }),
  "not a list",
);
// v2 credentials never come back to JS: the payload the host process returns
// has the secret groups removed, and nothing here reads them even if a
// hand-made file puts them back.
check(
  "secret groups in the payload are ignored, not imported",
  Object.keys(
    sanitizePayload({
      connections: [conn()],
      secrets: { "c-1": { password: "pw" } },
      rdpSecrets: { "r-1": { password: "pw" } },
    }),
  ).sort(),
  ["connections", "rdpConnections", "skipped"],
);

console.log("\n[dangling jump hosts] resolveJumpHops throws on these, so clear them first");
const list = [
  { ...conn({ id: "a", proxyJumpId: "b" }) },
  { ...conn({ id: "b" }) },
  { ...conn({ id: "c", proxyJumpId: "gone" }) },
] as Parameters<typeof clearDanglingJumps>[0];
const cleared = clearDanglingJumps(list, new Set(["a", "b", "c"]));
check("a resolvable jump is kept", cleared[0].proxyJumpId, "b");
check("a dangling jump is cleared", cleared[2].proxyJumpId, undefined);
check(
  "a jump host already saved on THIS machine counts as resolvable",
  clearDanglingJumps(
    [{ ...conn({ id: "x", proxyJumpId: "local-only" }) }] as never,
    new Set(["x", "local-only"]),
  )[0].proxyJumpId,
  "local-only",
);

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
  connections: [
    conn({ id: "bastion" }),
    conn({
      id: "db",
      proxyJumpId: "bastion",
      forwards: [{ localPort: 0, remoteHost: "127.0.0.1", remotePort: 5432 }],
    }),
  ],
  rdpConnections: [rdp({ id: "win", tunnel: { sshConnectionId: "bastion" } })],
});
check("every host survives", [real.connections.length, real.rdpConnections.length], [2, 1]);
check("nothing skipped", real.skipped, 0);
check("the jump chain is intact", real.connections[1].proxyJumpId, "bastion");
check("the forward is intact", real.connections[1].forwards?.[0].remotePort, 5432);
check("the RDP tunnel points at the imported bastion", real.rdpConnections[0].tunnel, {
  sshConnectionId: "bastion",
});

console.log("\n[auth mode] every mode survives an import and maps to the right wire fields");
check(
  "agent auth is preserved (it was coerced to password before the mode existed)",
  sanitizeConnection({ id: "a", host: "h", port: 22, authMode: "agent" })?.authMode,
  "agent",
);
check(
  "an unknown mode still falls back to password",
  sanitizeConnection({ id: "a", host: "h", port: 22, authMode: "totp" })?.authMode,
  "password",
);
// `authFields` is the ONE place that turns a saved mode into credentials on the
// wire (terminal session, tunnel, jump hops and the dialog's Test all call it).
// The agent case matters most: it must send the flag and NOTHING else, or a
// stale key from a previous mode would ride along.
const secrets = { password: "pw", privateKey: "KEY", keyPassphrase: "pp" };
check("password mode sends only the password", authFields("password", secrets), {
  password: "pw",
});
check("key mode sends the key and its passphrase", authFields("key", secrets), {
  privateKey: "KEY",
  privateKeyPassphrase: "pp",
});
check("agent mode sends no secret at all", authFields("agent", secrets), { useAgent: true });
check("agent mode ignores leftovers in the keychain", authFields("agent", {}), { useAgent: true });
check(
  "a missing secret becomes undefined, not an empty string",
  JSON.stringify(authFields("password", { password: "" })),
  "{}",
);

console.log(failed === 0 ? "\nAll ssh-backup checks passed." : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
