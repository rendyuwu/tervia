/**
 * Self-check for the connection backup parser.
 * Run: `pnpm verify backup-verify` (or `npx tsx scripts/backup-verify.ts` to
 * iterate). The full name, not `backup`: `backup-import-verify.ts` matches the
 * short one too, and a run that measured both would report the other script's
 * state as this one's.
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
 * ONE FORMAT IS READ, and the envelope/payload split follows from it. v3 seals
 * the whole payload, so `parseBackupFile` can only reach the ENVELOPE and
 * `sanitizePayload` does the per-record work after the host process has
 * decrypted. Both halves are exercised below - a file that got only the envelope
 * check would write unvalidated rows into the store.
 *
 * v1 and v2 are REFUSED rather than converted, and the two refusals are pinned
 * by their WHOLE sentence rather than by a substring. The two sentences share
 * "format v3 only" and "There is no converter", so a substring pin on either is
 * satisfied by the other, and one of the two refusals could then be deleted
 * outright with this suite still green. There is no v1 parsing left to check:
 * the plaintext-inventory arm, its `sanitizeLegacyHost` row validator and its
 * `sanitizeSecrets` credential-map validator are gone with the format.
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
 * `hostRefs` and `storedFields` are reached from `backup/apply.ts` rather than
 * from `backup/file.ts`, and they are the producing half of the
 * `SECRET_ALREADY_STORED` contract: one decides what travels, the other decides
 * which flags the store is told to claim. The consuming half is pinned in
 * `hosts-store-verify.ts`. Nothing here calls `invoke`, so importing that module
 * is safe under plain node.
 *
 * `identityRefs` and `keyRefs` come from the same module for the same reason:
 * they are the other two thirds of what an export NAMES, and a field one of them
 * stops naming simply stops travelling. They are imported rather than described,
 * so a rename fails loudly here instead of leaving a name-based pin running over
 * nothing. `landedKey` is imported for a sharper reason - it is the key an import
 * remembers a landed credential under, and building a fixture by CALLING it means
 * a group dropped out of that key collapses two fixtures onto one entry, so the
 * arithmetic reddens on its own rather than this file and the implementation
 * making the same mistake in two places.
 *
 * THREE THINGS HERE CANNOT BE REACHED BEHAVIOURALLY AT ALL, and they are
 * source-pinned rather than skipped. `buildBackup` calls `invoke`, so no fixture
 * in a plain-node run can enter it; `applyV3`'s `landed` set, its `identityIds`
 * set and `keyRecord` are all internal to a function that starts with one. What
 * those pins compare is read off the AST - the argument's own expression, rooted
 * at the function that owns it - and not a substring: `refs` is assembled from
 * three spreads, and a substring pin on `identityRefs` is satisfied by the import
 * clause at the top of that file. Every pin reads INDIVIDUAL sub-expressions and
 * never a whole comma list, which is also what makes them survive a legal
 * reformat: a narrower print width moves line breaks and trailing commas, and
 * moves nothing a pin compares.
 *
 * The crypto itself, and the payload assembly that keeps credentials out of the
 * webview, are checked on the Rust side (`modules/backup.rs` tests: round trip,
 * wrong passphrase, tampered ciphertext, nonce reuse, group merge/split, the
 * parked-handle lifecycle). That the plaintext read path stays DELETED - no
 * `backup_open` call in `src/`, no `backup_open` handler registered - is pinned
 * in `backup-import-verify.ts`, which already reads source text by path.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import ts from "typescript";

import type { ForwardRule } from "../src/modules/forwards/types";
import { jumpChain, MAX_JUMP_HOPS } from "../src/modules/hosts/jumps";
import { SECRET_ALREADY_STORED } from "../src/modules/hosts/store";
import { hostFingerprint, type Host, type RdpHost, type SshHost } from "../src/modules/hosts/types";
import {
  arrivedWithoutSecret,
  hostRefs,
  identityRefs,
  keyRefs,
  landedKey,
  storedFields,
} from "../src/modules/backup/apply";
import {
  BACKUP_EXTENSION_V1,
  BACKUP_KIND,
  BACKUP_KIND_V1,
  BACKUP_VERSION,
  HOST_SECRET_GROUP,
  IDENTITY_SECRET_GROUP,
  KEY_SECRET_GROUP,
  SECRET_GROUPS,
  carryPins,
  clearDanglingJumps,
  clearDanglingRuleHosts,
  clearDanglingTunnels,
  mergeGroups,
  normaliseIdentityKeys,
  orderHostWrites,
  parseBackupFile,
  refuseProtocolConflicts,
  resolveIdentityBindings,
  sanitizeGroup,
  sanitizeHost,
  sanitizeIdentity,
  sanitizeKey,
  sanitizePayload,
  sanitizeRule,
} from "../src/modules/backup/file";
import { sshCredentialValues } from "../src/modules/vault/resolve";
import {
  IDENTITY_PASSWORD_FIELD,
  KEY_PRIVATE_KEY_FIELD,
  VAULT_IDENTITY_SECRET_FIELDS,
  VAULT_KEY_SECRET_FIELDS,
  type VaultIdentity,
  type VaultKey,
} from "../src/modules/vault/types";

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

/**
 * The message a refusal produced, matched WHOLE.
 *
 * {@link throws} matches a substring, case-insensitively, which is the right
 * shape for a check about WHICH failure fired. It is the wrong shape for the two
 * format refusals: their sentences share "format v3 only" and "There is no
 * converter", so a substring pin on either one is satisfied by the other, and
 * either refusal could then be deleted outright with this suite still green.
 */
function throwsExactly(label: string, fn: () => unknown, message: string): void {
  try {
    fn();
    console.error(`  FAIL: ${label} did not throw`);
    failed++;
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (msg === message) {
      console.log(`  ok: ${label}`);
    } else {
      console.error(`  FAIL: ${label} threw "${msg}", expected exactly "${message}"`);
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
/** A v1 envelope. Only the kind and the version are read now - the refusal fires
 *  before anything looks for `connections` or `secrets`. */
const v1 = (over: Record<string, unknown> = {}) => ({
  kind: BACKUP_KIND_V1,
  version: 1,
  exportedAt: 1,
  ...over,
});
/** A v2 envelope, refused the same way and by its own sentence. */
const v2 = (over: Record<string, unknown> = {}) => ({
  kind: BACKUP_KIND,
  version: 2,
  exportedAt: 1,
  payload: SEALED,
  ...over,
});
/**
 * The one readable envelope: nothing but the sealed payload.
 *
 * The version is the LITERAL 3 rather than `BACKUP_VERSION`, so that "a v3 file
 * parses" stays a claim about v3. Written off the constant, this fixture would
 * follow a bumped constant into being a file about some other format while every
 * check below still read as green. The constant's own value is pinned once, in
 * `[format version]`.
 */
const v3 = (over: Record<string, unknown> = {}) => ({
  kind: BACKUP_KIND,
  version: 3,
  exportedAt: 1,
  payload: SEALED,
  ...over,
});

/**
 * An SSH row as it appears inside a sealed payload. The credential's `hostId`
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
/**
 * The old SSH-only row: `user` and `authMode` at the top level, no `protocol`
 * and no `credential`. Nothing validates this shape any more, and it survives
 * here for one check only - that an envelope numbered v3 carrying a PLAINTEXT
 * inventory instead of a sealed payload is still refused. Renumbering a file is
 * the cheapest way to try to reopen the leak sealing closed.
 */
const LEGACY_ROW = {
  id: "c-1",
  name: "prod",
  host: "example.com",
  port: 22,
  user: "root",
  authMode: "password",
};

/**
 * A vault identity as it appears inside a sealed payload: the well-formed case,
 * with every field a check might want to break passed explicitly.
 *
 * `hasPassword` is deliberately NOT here. It is a claim about the exporting
 * machine's keychain and the parser forces it false, so a fixture that carried it
 * by default would make every check below read as though the file had said
 * nothing - and the check that matters is the one where the file says `true`.
 */
const identity = (over: Record<string, unknown> = {}) => ({
  id: "i-1",
  name: "deploy",
  username: "deploy",
  authMode: "password",
  ...over,
});
/** A vault key row. Its two presence flags are absent for the same reason. */
const key = (over: Record<string, unknown> = {}) => ({
  id: "k-1",
  name: "laptop",
  keyType: "ed25519",
  fingerprint: "SHA256:FPR",
  publicKey: "ssh-ed25519 AAAAC3Nz",
  ...over,
});
/** A forward rule row. `localPort` is deliberately not 0 by default, so the
 *  check that 0 is LEGAL there says so on purpose rather than by inheritance. */
const rule = (over: Record<string, unknown> = {}) => ({
  id: "f-1",
  name: "postgres",
  hostId: "h-1",
  localPort: 15432,
  remoteHost: "127.0.0.1",
  remotePort: 5432,
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
/** The vault equivalents, for the passes that take records rather than raw rows.
 *  Same loud failure, for the same reason: a fixture that came back null would
 *  otherwise skip the check it was written for and report nothing. */
function identityOf(raw: unknown): VaultIdentity {
  const i = sanitizeIdentity(raw);
  if (!i) throw new Error(`fixture is not a valid identity: ${JSON.stringify(raw)}`);
  return i;
}
function keyOf(raw: unknown): VaultKey {
  const k = sanitizeKey(raw);
  if (!k) throw new Error(`fixture is not a valid key: ${JSON.stringify(raw)}`);
  return k;
}
function ruleOf(raw: unknown): ForwardRule {
  const r = sanitizeRule(raw);
  if (!r) throw new Error(`fixture is not a valid rule: ${JSON.stringify(raw)}`);
  return r;
}

/**
 * Whether the object carries the property AT ALL, which is a different question
 * from whether reading it gives `undefined`.
 *
 * The distinction is the check, in two places. `sanitizeKey` OMITS an unknown
 * `keyType` rather than coercing it, and `undefined` and `"unknown"` are
 * different facts - `KeyCard.tsx` renders "Unknown type" for the first and the
 * recorded "UNKNOWN" for the second. `JSON.stringify` cannot tell an absent
 * property from a present `undefined` one, so a check written through it passes
 * over a parser that stored one.
 */
const has = (o: object, prop: string): boolean => Object.prototype.hasOwnProperty.call(o, prop);

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

console.log("[format version] one number, and the whole compatibility story with it");
check("BACKUP_VERSION is 3", BACKUP_VERSION, 3);
// Neither of these is read for its CONTENTS any more. Both survive so the v1
// refusal can name the shape it is refusing, and so the open dialog can still
// offer the extension - a `.tervia-ssh` file gets picked and told what it is
// rather than being filtered out of the picker with no explanation. Pinned here
// because without a check the next reader deletes them as dead.
check(
  "the v1 kind and extension are still exported, so a refusal can name what it refuses",
  [BACKUP_KIND_V1, BACKUP_EXTENSION_V1],
  ["tervia-ssh-connections", "tervia-ssh"],
);

console.log("\n[envelope] a file that is not a backup must be rejected outright");
throws("a plain object", () => parseBackupFile({}), "not a Tervia connection backup");
throws("null", () => parseBackupFile(null), "not a Tervia connection backup");
throws("an array", () => parseBackupFile([]), "not a Tervia connection backup");
throws(
  "a theme file",
  () => parseBackupFile({ kind: "tervia-theme" }),
  "not a Tervia connection backup",
);
throws("no version", () => parseBackupFile(v3({ version: "3" })), "version");
// A newer Tervia may add fields this build would silently drop, so refuse rather
// than import a partial host.
throws("a newer format", () => parseBackupFile(v3({ version: 99 })), "newer Tervia");

console.log("\n[refusals] a format this build cannot read is NAMED, not converted");
// WHOLE-SENTENCE pins, and that is the point of them rather than tidiness. The
// two sentences share "format v3 only" and "There is no converter", so a
// substring pin on either one is also satisfied by the other: either refusal
// could be deleted outright and this suite would stay green on the survivor's
// text. There is no converter for either format - a v1 file's sealed block IS a
// credential map, and reading it would mean holding plaintext credentials in the
// webview - so the sentence is the only thing left to tell the user what they
// are holding, and it has to be the right one.
throwsExactly(
  "a v1 file is refused by the v1 sentence",
  () => parseBackupFile(v1()),
  "This is a Tervia v1 backup (.tervia-ssh). This build reads format v3 only, and there is no converter — the hosts in it have to be entered again.",
);
throwsExactly(
  "a v2 file is refused by its own, different sentence",
  () => parseBackupFile(v2()),
  "This backup is format v2 and this build reads format v3 only. There is no converter, and nothing in it can be imported.",
);
// This one pins BACKUP_VERSION's VALUE as well as the sentence, and deliberately:
// the message templates `v${BACKUP_VERSION}`, so "up to v3" is the constant
// rendered rather than a literal in the source. Bumping the constant without
// bumping the format is what this catches.
throwsExactly(
  "a v4 file is refused as newer, and the ceiling the message names is v3",
  () => parseBackupFile(v3({ version: 4 })),
  "This backup was written by a newer Tervia (format v4); this build reads up to v3.",
);
// The kind and the version have to AGREE, and that check runs before the two
// refusals above. A half-edited file is worse than an unreadable one, so it is
// told it is half-edited rather than being named as a format it never was -
// which is what these three pin: each one would read as a plain v1 or v2 refusal
// if the order were the other way round.
throwsExactly(
  "the v1 kind carrying a v2 version is called half-edited, not named as v2",
  () => parseBackupFile(v2({ kind: BACKUP_KIND_V1 })),
  `Backup file says format v2 but is not a ${BACKUP_KIND} file.`,
);
throwsExactly(
  "and the current kind carrying a v1 version, the same the other way round",
  () => parseBackupFile(v1({ kind: BACKUP_KIND })),
  `Backup file says format v1 but is not a ${BACKUP_KIND_V1} file.`,
);
throwsExactly(
  "and the READABLE version under the old kind, which a rename alone produces",
  () => parseBackupFile(v3({ kind: BACKUP_KIND_V1 })),
  `Backup file says format v3 but is not a ${BACKUP_KIND} file.`,
);

console.log("\n[v3 envelope] everything of substance is inside the sealed payload");
check("a good v3 file parses", parseBackupFile(v3()), { version: 3, payload: SEALED });
throws("no payload", () => parseBackupFile(v3({ payload: undefined })), "encrypted payload");
throws(
  "half a payload block",
  () => parseBackupFile(v3({ payload: { kdf: "x" } })),
  "encrypted payload",
);
throws(
  "non-integer iterations",
  () => parseBackupFile(v3({ payload: { ...SEALED, iterations: 1.5 } })),
  "encrypted payload",
);
// A plaintext inventory must NOT be accepted under the readable version:
// `connections` beside a sealed `secrets` is exactly the leak sealing closed, and
// renumbering a file is the cheapest way to try to reopen it.
throws(
  "a v3 file carrying v1's plaintext inventory instead of a payload",
  () => parseBackupFile(v3({ payload: undefined, connections: [LEGACY_ROW], secrets: SEALED })),
  "encrypted payload",
);

console.log("\n[secret groups] a credential group may not be an inventory collection");
// The JS-side statement of the Rust guard. `merge_secrets` in `modules/backup.rs`
// checks EVERY reference's group before inserting any and refuses to write into a
// group the payload already carries - so a colliding name fails the whole seal
// rather than replacing an inventory list with a credential map partway through.
// Named here and passed to `backup_open_payload`, a group missing from this list
// is not withheld from the metadata handed back to the webview.
check(
  "SECRET_GROUPS is exactly these three, in this order",
  [...SECRET_GROUPS],
  ["hostSecrets", "identitySecrets", "keySecrets"],
);
// The half that matters, and it survives a deliberate edit of the literal above:
// a rename that collided would replace an inventory collection with a credential
// map and report success.
const INVENTORY_KEYS: string[] = ["hosts", "groups", "identities", "keys", "rules"];
check(
  "and none of them is a payload key that carries inventory",
  SECRET_GROUPS.filter((group) => INVENTORY_KEYS.includes(group)),
  [],
);

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
  "`forwards` does not survive a payload row",
  Object.prototype.hasOwnProperty.call(
    host(ssh({ forwards: [{ localPort: 8080, remoteHost: "127.0.0.1", remotePort: 80 }] })),
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

console.log(
  "\n[vault bindings] a v3 payload carries a vault, so this is a DECISION, not a refusal",
);
// THREE OUTCOMES, and the third one covers two rows that are conservative for
// different reasons - so four cases are checked below, each on its own fixture.
// `identityIds` is what separates outcome 2 from outcome 3, and it is REQUIRED
// rather than optional for exactly that reason: a caller allowed to omit it would
// skip the guard silently, and outcome 2 would either never fire or fire for an
// identity that is not going to be there.
//
// The set is what `applyV3` builds - the ids `normaliseIdentityKeys` RETURNED,
// unioned with the ids already saved here - and it is spelled per check rather
// than shared, because which ids are in it is the whole question.
const travelled = (...ids: string[]): ReadonlySet<string> => new Set(ids);
/** No identity travelled and none is saved here: the pre-v3 world, where every
 *  binding was refused because there was nothing for it to name. */
const NO_IDENTITIES: ReadonlySet<string> = new Set();

// The failure this closes. `h-7` is a saved inline host holding the only copy of a
// passphrased key. A file says `h-7` is `{kind:"identity"}`; a vault-bound record
// owns no accounts, so `upsertHost` makes all three of that host's fields stale
// and deletes them - nothing copied them, and there is no `secrets_list`. The
// import reported `withoutSecrets: 1`, which reads as "the credential did not
// travel" rather than "the credential is gone".
//
// THE IDENTITY HAVING TRAVELLED DOES NOT MAKE IT SAFE TO APPLY, which is the step
// this is easy to get wrong on, so `i-1` is IN the set below: the user's local
// inline password for this host is not necessarily the identity's password, and
// this module has read neither. That is why the case is checked with the identity
// present rather than absent - with it absent the row takes outcome 3 for the
// weaker reason and the check would pass over an implementation that applies the
// binding whenever the identity is there.
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
  travelled("i-1"),
);
check(
  "landing on a saved inline host keeps that host's own credential, flags and all",
  overSaved.hosts[0].credential,
  savedKeyHost.credential,
);
check("and says so, rather than reporting a missing secret", overSaved.dropped, 1);
// Not applied, and counted in NEITHER direction: `applied` is what the summary
// reports as a binding honoured, and a row that kept its own credential must not
// appear there. Checked beside `dropped` because the two counters are one
// decision - an implementation that incremented both would report a row twice.
check("and it is not counted as applied either", overSaved.applied, 0);
// The binding kind is what makes the delete happen, so the check that matters is
// that it did not change: same kind on both sides means nothing is stale.
check(
  "so the record still names the accounts it named before the import",
  overSaved.hosts[0].credential.kind,
  "inline",
);
// OUTCOME 3, SECOND AND WEAKER REASON, and it is a separate case rather than a
// variation on the one above. A saved host already bound to a DIFFERENT identity
// loses no account by being repointed - vault-to-vault releases none either side -
// so keeping it is not about preventing a loss at all. It is kept because the
// saved binding is this machine's own current answer to how a host it already has
// authenticates, and a file has no better claim on that than on a group's local
// label, which `mergeGroups` declines for the same reason and counts as
// `keptNames`. BOTH identities travel here, so the only thing left standing in the
// way is the decision itself.
const repoint = resolveIdentityBindings(
  [host(ssh({ id: "h-7", credential: { kind: "identity", identityId: "i-2" } }))],
  [{ ...sshHost(ssh({ id: "h-7" })), credential: { kind: "identity", identityId: "i-1" } }],
  travelled("i-1", "i-2"),
);
check(
  "a saved host bound to another identity is not repointed, even when both travelled",
  [repoint.hosts[0].credential, repoint.applied, repoint.dropped],
  [{ kind: "identity", identityId: "i-1" }, 0, 1],
);
// OUTCOME 2, and it needs BOTH halves. The host is new, so there is no stored
// record whose accounts could be released, and the identity it names will exist -
// which together are what make applying provably free rather than merely likely.
const applied = resolveIdentityBindings(
  [host(ssh({ id: "h-new", credential: { kind: "identity", identityId: "i-1" } }))],
  [],
  travelled("i-1"),
);
check(
  "a NEW host naming an identity that will exist keeps the binding, and is counted",
  [applied.hosts[0].credential, applied.applied, applied.dropped],
  [{ kind: "identity", identityId: "i-1" }, 1, 0],
);
// THE OTHER HALF OF THE UNION, behaviourally. `applyV3` builds the set from the
// identities the FILE brought plus the ones already saved here, and this is the
// only observable difference the saved half makes: before it, a host naming an
// identity this machine already holds took outcome 3 and arrived blank. The set
// here carries an id that is in NO incoming identity, which is exactly the shape
// the saved half contributes.
//
// This proves what a right set DOES; that the set is BUILT right is a different
// question and cannot be reached from here - see `[apply source]`.
const savedIdentityOnly = resolveIdentityBindings(
  [host(ssh({ id: "h-new", credential: { kind: "identity", identityId: "i-local" } }))],
  [],
  travelled("i-local"),
);
check(
  "an identity already saved HERE counts as existing, so the binding is applied",
  [savedIdentityOnly.hosts[0].credential, savedIdentityOnly.applied],
  [{ kind: "identity", identityId: "i-local" }, 1],
);
// And the half that is NOT enough on its own: the host is new, the identity did
// not travel and is not saved here, so there is nothing for the binding to name.
const fresh = resolveIdentityBindings(
  [host(ssh({ id: "h-new", credential: { kind: "identity", identityId: "i-1" } }))],
  [],
  NO_IDENTITIES,
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
check(
  "and it is counted, on the dropped side and not the applied one",
  [fresh.dropped, fresh.applied],
  [1, 0],
);
// OUTCOME 1. A machine re-importing its own backup: the saved binding IS what the
// file asked for, so nothing was refused and there is nothing to report. The
// mechanism outcome 3 exists for is not merely unlikely here but unreachable -
// the binding KIND does not change across the write, so nothing goes stale.
const roundTrip = resolveIdentityBindings(
  [host(ssh({ id: "h-7", credential: { kind: "identity", identityId: "i-1" } }))],
  [{ ...sshHost(ssh({ id: "h-7" })), credential: { kind: "identity", identityId: "i-1" } }],
  travelled("i-1"),
);
check(
  "a binding this machine already has is kept byte for byte, and counted in neither",
  [roundTrip.hosts[0].credential, roundTrip.dropped, roundTrip.applied],
  [{ kind: "identity", identityId: "i-1" }, 0, 0],
);
check(
  "a DIFFERENT identity does not repoint the saved host at one it may not have",
  resolveIdentityBindings(
    [host(ssh({ id: "h-7", credential: { kind: "identity", identityId: "i-2" } }))],
    [{ ...sshHost(ssh({ id: "h-7" })), credential: { kind: "identity", identityId: "i-1" } }],
    travelled("i-1"),
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
    travelled("i-1"),
  ).hosts[0].credential,
  savedRdp.credential,
);
check(
  "and a new RDP row whose identity did not travel arrives blank rather than bound",
  rdpInline(
    resolveIdentityBindings(
      [host(rdp({ id: "h-fresh", credential: { kind: "identity", identityId: "i-1" } }))],
      [],
      NO_IDENTITIES,
    ).hosts[0],
  ),
  { kind: "inline", hostId: "h-fresh", username: "", hasPassword: false },
);
const inlineOnly = resolveIdentityBindings([host(ssh()), host(rdp())], [], NO_IDENTITIES);
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
    travelled("i-1"),
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

// THE OTHER TWO THIRDS OF WHAT AN EXPORT NAMES. `hostRefs` answers for one host
// and one group only - a vault-bound host's identity has its secrets on another
// service - so an identity's password and a key's body and passphrase are named by
// their own builders or they do not travel at all.
const refIdentity = identityOf(identity());
const refKey = keyOf(key());
check("an identity contributes one ref, and it is its password", identityRefs(refIdentity), [
  {
    group: "identitySecrets",
    id: "i-1",
    field: "password",
    service: "tervia-vault",
    account: "i-1::password",
  },
]);
check("a key contributes its private body and its passphrase", keyRefs(refKey), [
  {
    group: "keySecrets",
    id: "k-1",
    field: "privateKey",
    service: "tervia-vault",
    account: "k-1::privateKey",
  },
  {
    group: "keySecrets",
    id: "k-1",
    field: "passphrase",
    service: "tervia-vault",
    account: "k-1::passphrase",
  },
]);
// THREE PAYLOAD GROUPS, TWO KEYCHAIN SERVICES. Identities and keys SHARE
// `tervia-vault`; the groups are three because the three record kinds draw their
// ids from three separate collections, and a group is not a service. Reading both
// off the same fixtures keeps that distinction stated rather than assumed.
check(
  "the three kinds sit on two services, the vault's shared by identities and keys",
  [
    hostRefs(host(ssh()))[0].service,
    identityRefs(refIdentity)[0].service,
    keyRefs(refKey)[0].service,
  ],
  ["tervia-hosts", "tervia-vault", "tervia-vault"],
);
check(
  "and on three distinct groups, which is what keeps one id space out of another's",
  [hostRefs(host(ssh()))[0].group, identityRefs(refIdentity)[0].group, keyRefs(refKey)[0].group],
  [HOST_SECRET_GROUP, IDENTITY_SECRET_GROUP, KEY_SECRET_GROUP],
);
// COUNTED AGAINST THE CONSTANTS, never against the literals 1 and 2. A field added
// to either list has to be named by its builder or it simply stops travelling -
// which is the same contract `hostRefs`' own doc states - and this is the only
// thing that would say so.
check(
  "each builder names every field in its own list, in the list's order",
  [identityRefs(refIdentity).map((r) => r.field), keyRefs(refKey).map((r) => r.field)],
  [[...VAULT_IDENTITY_SECRET_FIELDS], [...VAULT_KEY_SECRET_FIELDS]],
);
check(
  "so the ref count is the field list's length, and a fourth field cannot be added silently",
  [identityRefs(refIdentity).length, keyRefs(refKey).length],
  [VAULT_IDENTITY_SECRET_FIELDS.length, VAULT_KEY_SECRET_FIELDS.length],
);
// A field is asked for whether or not anything is stored at it: the host process
// skips a reference that resolves to nothing, which keeps the decision about what
// exists in the one place that can answer it. So a record whose flags are all
// false still contributes its full set, exactly as an agent-auth host does.
check(
  "a record with no stored material still contributes every ref, because Rust answers that",
  [
    identityRefs(identityOf(identity({ hasPassword: false }))).length,
    keyRefs(keyOf(key({ hasPrivateKey: false, hasPassphrase: false }))).length,
  ],
  [1, 2],
);

/**
 * The keys an import remembers a landed credential under, built by CALLING
 * `landedKey` rather than by respelling `<group>::<id>::<field>` here.
 *
 * That is what the export is for. The group is part of the key because v3 draws
 * three groups from three separate id spaces, so an id alone no longer says which
 * record it came off - and a fixture that spelled the format itself could make the
 * same mistake the implementation made and then agree with it in two places.
 * Called, a group dropped out of the key collapses the host fixture and the
 * identity one onto a single entry, and the collision checks below redden on their
 * own arithmetic.
 */
const hostLanded = (id: string, ...fields: string[]): string[] =>
  fields.map((field) => landedKey(HOST_SECRET_GROUP, id, field));

/** Which fields were claimed as ALREADY STORED, by name. Read out by name because
 *  the names ARE the contract - `storedFields` promises a claim per field - which
 *  keeps the assertion off how a symbol happens to render. */
const claimed = (h: Host, landed: string[]): string[] =>
  Object.entries(storedFields(h, new Set(landed)))
    .filter(([, v]) => v === SECRET_ALREADY_STORED)
    .map(([k]) => k);

check(
  "every field that landed is claimed",
  claimed(host(ssh()), hostLanded("h-1", "password", "privateKey", "keyPassphrase")),
  ["password", "privateKey", "keyPassphrase"],
);
// PER FIELD, which is the whole point: the store takes an untouched field's flag
// from the stored record, and for a host it has never seen that is false over a
// live secret - which `RdpPane` pre-flights and refuses to connect on.
check(
  "and only those, so a partial arrival is reported partially",
  claimed(host(ssh()), hostLanded("h-1", "privateKey")),
  ["privateKey"],
);
check("nothing landed, nothing claimed", claimed(host(ssh()), []), []);
check("the RDP row claims its one field", claimed(host(rdp()), hostLanded("h-9", "password")), [
  "password",
]);
// `HOST_SSH_PRIVATE_KEY_FIELD` and the RDP password field share an id space now,
// so the guard is the protocol arm rather than the account name.
check(
  "an RDP row claims nothing from an SSH field, even at its own id",
  claimed(host(rdp()), hostLanded("h-9", "privateKey", "keyPassphrase")),
  [],
);
check(
  "a vault-bound host claims nothing, which is what stops upsertHost refusing the row",
  claimed(vaultBound, hostLanded("h-v", "password")),
  [],
);
check(
  "and what is claimed is the symbol, never a string a file could carry",
  Object.values(storedFields(host(ssh()), new Set(hostLanded("h-1", "password")))).map(
    (v) => typeof v,
  ),
  ["symbol"],
);

// THE GROUP IN THE KEY, asked of the one consumer a plain-node run can reach.
// Three groups over three id spaces means an id no longer identifies the record
// it came off: an identity and a host sharing an id, each with a `password`
// field, collide on a bare `<id>::<field>` key - and `storedFields` would then
// report SECRET_ALREADY_STORED for a host whose secret never landed, so the host
// is written with `hasPassword: true` over nothing. That is a presence flag taken
// from the file by the back door, which is the one thing this module exists to
// stop.
//
// A REAL EXPORT CANNOT PRODUCE THE COLLISION - the three stores mint ids
// independently - but a hand-made payload can, and an import is a trust boundary.
// Both fixtures are built through `landedKey`, so dropping the group from it makes
// these two sets equal to the host's own and the two checks fail together.
check(
  "an identity's landed password does not answer for a host that shares its id",
  claimed(host(ssh()), [landedKey(IDENTITY_SECRET_GROUP, "h-1", IDENTITY_PASSWORD_FIELD)]),
  [],
);
check(
  "and a key's landed private body does not answer for a host that shares ITS id",
  claimed(host(ssh()), [landedKey(KEY_SECRET_GROUP, "h-1", KEY_PRIVATE_KEY_FIELD)]),
  [],
);
// The positive control for the pair above: the same id and the same field under
// the HOST group is claimed. Without it, both checks are satisfied by a
// `storedFields` that claims nothing at all.
check(
  "while the host's own group at the same id and field is claimed",
  claimed(host(ssh()), hostLanded("h-1", "password")),
  ["password"],
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
check("password auth with one is not", missing(ssh(), hostLanded("h-1", "password")), false);
// The case a per-host answer got wrong: something landed, so it reported fine,
// and the host cannot connect because the thing that landed was the passphrase.
check(
  "key auth whose passphrase arrived and whose KEY did not is counted",
  missing(keyAuth, hostLanded("h-1", "keyPassphrase")),
  true,
);
check("key auth with the key is not", missing(keyAuth, hostLanded("h-1", "privateKey")), false);
check(
  "and a key with no passphrase is ordinary, not missing one",
  missing(keyAuth, hostLanded("h-1", "privateKey")),
  false,
);
// Agent auth stores nothing by design, so reporting it as missing a credential
// would read as a broken import.
check("agent auth is never counted", missing(agentAuth, []), false);
check("an RDP host with no password is counted", missing(rdp(), []), true);
check("and with one is not", missing(rdp(), hostLanded("h-9", "password")), false);
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

console.log("\n[identities] a bad row is wrong everywhere it is referenced, not just once");
check("a good identity survives", sanitizeIdentity(identity()), {
  id: "i-1",
  name: "deploy",
  username: "deploy",
  authMode: "password",
  hasPassword: false,
});
check("no id is dropped", sanitizeIdentity(identity({ id: "  " })), null);
// `name` is required even though the STORE accepts a blank one - `vault/store.ts`
// asks only that key auth names a key. It is what every host picking a credential
// shows and searches, so a nameless row would render an empty card title here and
// fall back to an opaque id in its own delete refusal.
check(
  "a blank name is dropped here, stricter than the store on purpose",
  sanitizeIdentity(identity({ name: "   " })),
  null,
);
check("a non-object is dropped", sanitizeIdentity("i-1"), null);
// `username` may be BLANK, and the asymmetry with `name` is deliberate: it is a
// field the user can see and fix on the Vault page, and refusing the row over it
// throws away the name, the domain, the auth mode and the description with it.
check(
  "a blank username is kept, because refusing the row would cost every other field",
  sanitizeIdentity(identity({ username: "   ", description: "note" })),
  {
    id: "i-1",
    name: "deploy",
    username: "",
    authMode: "password",
    hasPassword: false,
    description: "note",
  },
);
check(
  "an unknown authMode - including one a later build writes - falls to password",
  [
    sanitizeIdentity(identity({ authMode: "sso" }))?.authMode,
    sanitizeIdentity(identity({ authMode: undefined }))?.authMode,
    sanitizeIdentity(identity({ authMode: "agent" }))?.authMode,
  ],
  ["password", "password", "agent"],
);
// PRESERVED, not applied: this function records what the file ASKED for, and
// `normaliseIdentityKeys` is what decides whether the key it names will exist.
check(
  "keyId rides along verbatim, for the later pass to judge",
  sanitizeIdentity(identity({ authMode: "key", keyId: " k-9 " }))?.keyId,
  "k-9",
);
// THE ONE THAT MATTERS. Left true it would render a stored-password indicator for
// a secret this machine does not hold, on a row the user then never fills in -
// and whether a password arrives is decided by what the sealed payload carried,
// which this function cannot see.
check(
  "hasPassword is forced false even when the file says true",
  sanitizeIdentity(identity({ hasPassword: true }))?.hasPassword,
  false,
);
const sparse = identityOf(identity({ domain: "   ", description: "  " }));
check(
  "a blank domain and a blank description are OMITTED rather than stored as empty strings",
  [has(sparse, "domain"), has(sparse, "description")],
  [false, false],
);
check(
  "and a real domain rides along, trimmed",
  sanitizeIdentity(identity({ domain: " CORP " }))?.domain,
  "CORP",
);

console.log("\n[keys] the record a private key hangs off, and two flags that are not ours");
check("a good key survives", sanitizeKey(key()), {
  id: "k-1",
  name: "laptop",
  keyType: "ed25519",
  fingerprint: "SHA256:FPR",
  publicKey: "ssh-ed25519 AAAAC3Nz",
  hasPrivateKey: false,
  hasPassphrase: false,
});
check("no id is dropped", sanitizeKey(key({ id: "" })), null);
// `upsertKey` THROWS on a blank name, and a throw inside the import loop costs
// every record behind it - so the refusal is made here, where it is one skipped
// row and a count.
check(
  "a blank name is dropped, because the store would throw on it",
  sanitizeKey(key({ name: " " })),
  null,
);
check("a non-object is dropped", sanitizeKey(7), null);
check(
  "all four types this build can name are recorded",
  ["rsa", "ed25519", "ecdsa", "unknown"].map((keyType) => sanitizeKey(key({ keyType }))?.keyType),
  ["rsa", "ed25519", "ecdsa", "unknown"],
);
// OMITTED, never coerced, and the assertion is that the PROPERTY IS ABSENT rather
// than that it reads `undefined`: `JSON.stringify` cannot tell those apart, and
// they are different facts. `KeyCard.tsx` renders "Unknown type" for the absent
// one and the recorded "UNKNOWN" for `"unknown"`, so coercing would turn "nobody
// looked" into "we looked and could not tell".
check(
  "an illegal keyType is omitted, not coerced - and the property is gone, not undefined",
  has(keyOf(key({ keyType: "dsa" })), "keyType"),
  false,
);
check(
  "which is a different fact from the recorded unknown sitting beside it",
  sanitizeKey(key({ keyType: "unknown" }))?.keyType,
  "unknown",
);
const bareKey = keyOf(key({ fingerprint: "  ", publicKey: "", description: " " }));
check(
  "a blank fingerprint, publicKey and description are omitted rather than empty-stringed",
  [has(bareKey, "fingerprint"), has(bareKey, "publicKey"), has(bareKey, "description")],
  [false, false, false],
);
// Carried as trimmed strings and NOT parsed: both are display-only on this side,
// so an unrecognised `SHA256:` shape says nothing about whether the private half
// is usable - and a stricter parse would drop a good key over a cosmetic field.
check(
  "and an unparseable fingerprint is still carried, because it is display only",
  sanitizeKey(key({ fingerprint: " not-a-sha " }))?.fingerprint,
  "not-a-sha",
);
check(
  "both presence flags are forced false even when the file says true",
  [
    sanitizeKey(key({ hasPrivateKey: true, hasPassphrase: true }))?.hasPrivateKey,
    sanitizeKey(key({ hasPrivateKey: true, hasPassphrase: true }))?.hasPassphrase,
  ],
  [false, false],
);

console.log("\n[identity keys] a keyId may never dangle: upsertIdentity throws on one either way");
// SKIPPED, never downgraded, and the downgrade is the tempting wrong answer: every
// host bound to this identity would quietly start offering a password where it used
// to offer a key, with no error and nothing on the host row that says so - and the
// password it would offer is one the identity has no reason to hold. Skipping costs
// the user an identity they can see is absent and re-enter.
const keyAuthDangling = normaliseIdentityKeys(
  [identityOf(identity({ authMode: "key", keyId: "k-gone" }))],
  [],
  [],
);
check(
  "key auth naming a key that will not exist is SKIPPED, and counted in withoutKeys",
  [keyAuthDangling.identities, keyAuthDangling.withoutKeys, keyAuthDangling.keysDropped],
  [[], 1, 0],
);
// The second shape `upsertIdentity` throws on, and not a milder version of the
// first: key auth with no `keyId` at all names nothing.
// The count and the SKIP are asserted together, and not the count alone: a
// downgrade increments `withoutKeys` too, so a check on the counter by itself
// passes over exactly the repair this arm refuses to make.
check(
  "key auth with no keyId at all is skipped too, not saved as key auth naming nothing",
  ((r) => [r.identities, r.withoutKeys])(
    normaliseIdentityKeys([identityOf(identity({ authMode: "key" }))], [], []),
  ),
  [[], 1],
);
// The other failure, and it does NOT cost the same thing: the identity
// authenticates exactly as it did before, so there is nothing to gain by refusing
// the whole record.
const droppedKeyId = normaliseIdentityKeys(
  [identityOf(identity({ keyId: "k-gone", description: "note" }))],
  [],
  [],
);
check(
  "any other mode KEEPS the identity and loses only the keyId",
  [
    droppedKeyId.identities.length,
    droppedKeyId.identities[0]?.name,
    droppedKeyId.identities[0]?.authMode,
    droppedKeyId.identities[0]?.description,
    droppedKeyId.keysDropped,
    droppedKeyId.withoutKeys,
  ],
  [1, "deploy", "password", "note", 1, 0],
);
// `undefined` rather than rebuilt without the field, the same spelling
// `clearDanglingJumps` uses for a `proxyJumpId`: one way of saying "this reference
// is gone" across the module, and the store persists as JSON so the field does not
// survive the write either way. Asserted as undefined and not as absent, because
// this is the one place the two are deliberately the same.
check(
  "cleared to undefined, one spelling of a gone reference",
  droppedKeyId.identities[0]?.keyId,
  undefined,
);
// "WILL EXIST" IS A UNION, and both halves are checked, because a key the user
// already has is as good as one that travelled.
check(
  "a key travelling in the SAME payload counts as existing",
  normaliseIdentityKeys(
    [identityOf(identity({ authMode: "key", keyId: "k-1" }))],
    [keyOf(key({ id: "k-1" }))],
    [],
  ).identities[0]?.keyId,
  "k-1",
);
check(
  "and so does a key already saved on THIS machine",
  normaliseIdentityKeys(
    [identityOf(identity({ authMode: "key", keyId: "k-local" }))],
    [],
    [keyOf(key({ id: "k-local" }))],
  ).identities[0]?.keyId,
  "k-local",
);
// A `keyId` on a NON-KEY identity is ordinary rather than a malformed row to be
// tidied: `convertHostToVault` writes precisely that shape on purpose, minting a
// `VaultKey` out of a host's stored private key - and if the new identity did not
// name that key then nothing would, `deleteKey`'s in-use guard would have no
// holder to refuse over, and one click could destroy the user's only copy of it.
check(
  "a resolvable keyId on a password identity is left alone, whatever the mode says",
  normaliseIdentityKeys([identityOf(identity({ keyId: "k-1" }))], [keyOf(key({ id: "k-1" }))], []),
  {
    identities: [
      {
        id: "i-1",
        name: "deploy",
        username: "deploy",
        authMode: "password",
        hasPassword: false,
        keyId: "k-1",
      },
    ],
    withoutKeys: 0,
    keysDropped: 0,
  },
);

console.log("\n[rules] every refusal here mirrors one upsertRule makes, so a row costs one count");
check("a good rule survives", sanitizeRule(rule()), {
  id: "f-1",
  name: "postgres",
  hostId: "h-1",
  localPort: 15432,
  remoteHost: "127.0.0.1",
  remotePort: 5432,
  startWithHost: false,
});
// THE TWO PORTS ARE DIFFERENT, and they are asserted ADJACENTLY because they are
// the pair a single shared predicate gets wrong: `localPort` may be 0, which means
// "let the OS pick" and is the value a rule is saved with until it binds, and
// `remotePort` may not, because it is dialled on the far side.
check(
  "localPort 0 is LEGAL, and means let the OS pick",
  sanitizeRule(rule({ localPort: 0 }))?.localPort,
  0,
);
check("remotePort 0 is NOT, because it is dialled", sanitizeRule(rule({ remotePort: 0 })), null);
check(
  "each port is bound at 1 and at 65535",
  [
    sanitizeRule(rule({ localPort: 1, remotePort: 1 }))?.localPort,
    sanitizeRule(rule({ localPort: 65535, remotePort: 65535 }))?.remotePort,
    sanitizeRule(rule({ localPort: 65536 })),
    sanitizeRule(rule({ remotePort: 65536 })),
    sanitizeRule(rule({ localPort: -1 })),
  ],
  [1, 65535, null, null, null],
);
check(
  "a float is refused on either port, not rounded to something dialable",
  [sanitizeRule(rule({ localPort: 8080.5 })), sanitizeRule(rule({ remotePort: 80.5 }))],
  [null, null],
);
check(
  "and so is a string, on either",
  [sanitizeRule(rule({ localPort: "8080" })), sanitizeRule(rule({ remotePort: "80" }))],
  [null, null],
);
check(
  "a blank name, hostId, remoteHost or id is refused, each on its own",
  [
    sanitizeRule(rule({ name: "  " })),
    sanitizeRule(rule({ hostId: "" })),
    sanitizeRule(rule({ remoteHost: "   " })),
    sanitizeRule(rule({ id: " " })),
    sanitizeRule("f-1"),
  ],
  [null, null, null, null, null],
);
// `false` is the safe direction: a rule that does not start itself is visible and
// one click from running, where one that starts unasked opens a listening socket
// the user did not ask for.
check(
  "startWithHost is true only for a literal true",
  [
    sanitizeRule(rule({ startWithHost: true }))?.startWithHost,
    sanitizeRule(rule({ startWithHost: "true" }))?.startWithHost,
    sanitizeRule(rule({ startWithHost: 1 }))?.startWithHost,
    sanitizeRule(rule({ startWithHost: undefined }))?.startWithHost,
  ],
  [true, false, false, false],
);
check(
  "and a blank description is omitted",
  has(sanitizeRule(rule({ description: " " })) ?? {}, "description"),
  false,
);

console.log("\n[rule hosts] a rule rides an SSH session, so it needs one that will be there");
// Two refusals, and both are `upsertRule`'s: a `hostId` naming no host at all, and
// a `hostId` naming an RDP host, which has no session for a forward to ride. Both
// are throws at the write, and a throw costs the rules queued behind it.
const ruledMissing = clearDanglingRuleHosts([ruleOf(rule({ hostId: "gone" }))], [], []);
check(
  "a rule whose host is nowhere is dropped, and counted",
  [ruledMissing.rules, ruledMissing.dropped],
  [[], 1],
);
const ruledRdp = clearDanglingRuleHosts(
  [ruleOf(rule({ hostId: "h-9" }))],
  [host(rdp({ id: "h-9" }))],
  [],
);
check(
  "a rule riding an RDP host is dropped too, which is the refusal one merged store made possible",
  [ruledRdp.rules, ruledRdp.dropped],
  [[], 1],
);
// "Will be there" is the union the jump passes already build - the file's hosts
// over the saved ones - so this pass and those cannot come to different
// conclusions about what the import produces.
check(
  "a host travelling in the SAME payload keeps the rule",
  clearDanglingRuleHosts([ruleOf(rule({ hostId: "h-1" }))], [host(ssh({ id: "h-1" }))], []),
  {
    rules: [
      {
        id: "f-1",
        name: "postgres",
        hostId: "h-1",
        localPort: 15432,
        remoteHost: "127.0.0.1",
        remotePort: 5432,
        startWithHost: false,
      },
    ],
    dropped: 0,
  },
);
check(
  "and a host already saved HERE keeps it as well",
  clearDanglingRuleHosts([ruleOf(rule({ hostId: "h-local" }))], [], [host(ssh({ id: "h-local" }))])
    .dropped,
  0,
);

console.log("\n[payload] the same validation, after decryption instead of before");
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
// EVERY collection, and an exact shape rather than a spot check. A payload sealed
// by a build that had no vault is a legitimate file, so an absent list imports as
// empty rather than failing - which means a collection accidentally dropped from
// the return shape reads as an empty import and not as an error. The five names
// are also what the export seals, so this and `[export source]` are the two ends
// of one round trip.
check("an empty payload is not an error, and every collection comes back", sanitizePayload({}), {
  hosts: [],
  groups: [],
  identities: [],
  keys: [],
  rules: [],
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
// Credentials never come back to JS: the payload the host process returns has
// the secret groups removed, and nothing here reads one even if a hand-made file
// puts it back. Read as an exact key list, so a sixth collection cannot be added
// to the return shape without this saying so.
check(
  "the secret group in the payload is ignored, not imported",
  Object.keys(
    sanitizePayload({ hosts: [ssh()], hostSecrets: { "h-1": { password: "pw" } } }),
  ).sort(),
  ["groups", "hosts", "identities", "keys", "rules", "skipped"],
);

console.log("\n[payload collections] five of them, each answering for itself");
// A MISSING collection is not an error, one at a time: a build with no vault
// sealed no `identities`, `keys` or `rules`, and its file is still readable. Each
// is asked on its own, so a return shape that dropped one of the five to `[]`
// unconditionally would still have to face the dedupe and count checks below.
check(
  "each collection is independently absent-is-empty",
  [
    sanitizePayload({ groups: [], identities: [], keys: [], rules: [] }).hosts,
    sanitizePayload({ hosts: [], identities: [], keys: [], rules: [] }).groups,
    sanitizePayload({ hosts: [], groups: [], keys: [], rules: [] }).identities,
    sanitizePayload({ hosts: [], groups: [], identities: [], rules: [] }).keys,
    sanitizePayload({ hosts: [], groups: [], identities: [], keys: [] }).rules,
  ],
  [[], [], [], [], []],
);
// A NON-ARRAY throws instead, and by a sentence that NAMES the collection - one
// bad row is a count, but a payload that is not the shape this build seals is not
// something to import four fifths of. Pinned WHOLE rather than on "not a list",
// which every one of the five shares: a substring pin here is satisfied by any of
// them, so a label copied from the wrong collection would read as green.
throwsExactly(
  "a host inventory that is not a list names the hosts",
  () => sanitizePayload({ hosts: {} }),
  "The encrypted payload's hosts are not a list.",
);
throwsExactly(
  "a group list that is not a list names the host groups, as the user reads them",
  () => sanitizePayload({ groups: "g-1" }),
  "The encrypted payload's host groups are not a list.",
);
throwsExactly(
  "an identity list that is not a list names the identities",
  () => sanitizePayload({ identities: 1 }),
  "The encrypted payload's identities are not a list.",
);
throwsExactly(
  "a key list that is not a list names the keys",
  () => sanitizePayload({ keys: {} }),
  "The encrypted payload's keys are not a list.",
);
throwsExactly(
  "a rule list that is not a list names the forward rules",
  () => sanitizePayload({ rules: "f-1" }),
  "The encrypted payload's forward rules are not a list.",
);
// Hosts go first, so a payload with two bad collections keeps the sentence it has
// always had rather than reporting whichever one a reordering put in front.
throwsExactly(
  "hosts are checked first, so two bad collections still report the hosts",
  () => sanitizePayload({ hosts: {}, rules: {} }),
  "The encrypted payload's hosts are not a list.",
);
// PER COLLECTION, not app-wide. Two keys sharing an id are the same record slot
// and the same `tervia-vault :: <id>::privateKey` account, so the second would
// silently overwrite the first. An id reused BETWEEN two stores is not a conflict
// at all, and one shared `seen` set would drop a row over it.
const dupes = sanitizePayload({
  hosts: [ssh({ id: "x-1" }), ssh({ id: "x-1", name: "second" })],
  groups: [
    { id: "x-1", name: "prod" },
    { id: "x-1", name: "second" },
  ],
  identities: [identity({ id: "x-1" }), identity({ id: "x-1", name: "second" })],
  keys: [key({ id: "x-1" }), key({ id: "x-1", name: "second" })],
  rules: [rule({ id: "x-1" }), rule({ id: "x-1", name: "second" })],
});
check(
  "every collection dedupes by id, and the FIRST row wins in each",
  [
    dupes.hosts.map((h) => h.name),
    dupes.groups.map((g) => g.name),
    dupes.identities.map((i) => i.name),
    dupes.keys.map((k) => k.name),
    dupes.rules.map((r) => r.name),
  ],
  [["prod"], ["prod"], ["deploy"], ["laptop"], ["postgres"]],
);
check(
  "and one id reused across all five collections is no conflict at all",
  [
    dupes.hosts.length,
    dupes.groups.length,
    dupes.identities.length,
    dupes.keys.length,
    dupes.rules.length,
  ],
  [1, 1, 1, 1, 1],
);
// ONE `skipped` across the five. It is a "rows the file lost" number for the
// summary rather than a diagnosis - there is nothing different for the user to do
// per kind - so a per-collection breakdown would suggest an action that does not
// exist.
check("and one shared count carries all five collections' losses", dupes.skipped, 5);
const oneBadEach = sanitizePayload({
  hosts: [ssh({ port: 0 })],
  groups: [{ id: "g-1", name: "  " }],
  identities: [identity({ name: "" })],
  keys: [key({ name: "   " })],
  rules: [rule({ remotePort: 0 })],
});
check(
  "one unusable row in each collection is five skipped and nothing imported",
  [
    oneBadEach.skipped,
    oneBadEach.hosts.length +
      oneBadEach.groups.length +
      oneBadEach.identities.length +
      oneBadEach.keys.length +
      oneBadEach.rules.length,
  ],
  [5, 0],
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
// The whole pipeline in the order `applyV3` runs it, on a fresh machine. THIS
// PAYLOAD CARRIES NO IDENTITIES, which is what the empty set says: nothing
// travelled and nothing is saved, so the vault-bound row lands inline and blank
// rather than binding to an identity that will not be there. The same file WITH
// its identity would take outcome 2 instead, which `[vault bindings]` checks on
// its own fixture.
const pipeline = ((): Host[] => {
  const kinds = refuseProtocolConflicts(real.hosts, []);
  const bound = resolveIdentityBindings(kinds.hosts, [], NO_IDENTITIES);
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

// ============================================================================
// SOURCE PINS. Three things in `apply.ts` that no fixture in a plain-node run can
// reach, and each of them is one expression away from a silent credential loss.
// ============================================================================
//
// `buildBackup` calls `invoke`, so the whole export half is unreachable from
// here; `applyV3`'s `identityIds` set, its `landed` set and `keyRecord` are all
// internal to a function that starts with one. Nor does the COMPILER see any of
// them: each defect below is an edit between two expressions of the same type -
// two `VaultIdentity[]`s, two `string`s, two `boolean`s - so `tsc` cannot tell
// the wrong one from the right one, and without these pins nothing in the tree
// looks at all.
//
// READ OFF THE AST, AND ROOTED AT THE FUNCTION THAT OWNS THE EXPRESSION. A
// substring search is the wrong instrument twice over: `refs` is assembled from
// three spreads, so a search for `identityRefs` is satisfied by the import clause
// at the top of that file, and an unrooted search for a name that appears twice
// compares whichever declaration comes last. Both sides of every comparison go
// through `squash`, so the expected value can be written the way the source writes
// it while a narrower print width - moving line breaks and trailing commas around -
// moves nothing that is compared. That pairing is what keeps these pins from being
// a landmine on the next `pnpm format`.
const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const APPLY_PATH = "src/modules/backup/apply.ts";
const applySf = ts.createSourceFile(
  APPLY_PATH,
  readFileSync(join(repoRoot, APPLY_PATH), "utf8"),
  ts.ScriptTarget.ESNext,
  /* setParentNodes */ true,
);

/** Every layout difference removed: whitespace gone, and a trailing comma before
 *  a closer gone. Applied to BOTH sides of every pin below. */
const squash = (s: string): string => s.replace(/\s+/g, "").replace(/,(?=[)\]}])/g, "");
const exprOf = (n: ts.Node): string => squash(n.getText(applySf));

/** The function that owns a pin, by name: a declaration, or the arrow a `const`
 *  holds. Rooting every lookup at one of these is what makes the pins below
 *  answer about the right expression - `refs` is declared in two functions here,
 *  and an unrooted search would compare the second one. */
function functionNamed(name: string): ts.Node | null {
  let out: ts.Node | null = null;
  const visit = (n: ts.Node): void => {
    if (ts.isFunctionDeclaration(n) && n.name?.text === name) out = n;
    else if (
      ts.isVariableDeclaration(n) &&
      ts.isIdentifier(n.name) &&
      n.name.text === name &&
      n.initializer &&
      (ts.isArrowFunction(n.initializer) || ts.isFunctionExpression(n.initializer))
    ) {
      out = n.initializer;
    }
    ts.forEachChild(n, visit);
  };
  visit(applySf);
  return out;
}

/** The initialiser of `const <name> = ...` inside `root`. */
function localInit(root: ts.Node | null, name: string): ts.Expression | null {
  if (!root) return null;
  let out: ts.Expression | null = null;
  const visit = (n: ts.Node): void => {
    if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.name.text === name) {
      out = n.initializer ?? null;
    }
    ts.forEachChild(n, visit);
  };
  visit(root);
  return out;
}

/** Every call to `<callee>` inside `root`, in source order. The callee is matched
 *  through `squash` so a property access (`JSON.stringify`) and a bare name
 *  (`landedKey`) are found by the same helper. */
function calls(root: ts.Node | null, callee: string): ts.CallExpression[] {
  const out: ts.CallExpression[] = [];
  if (!root) return out;
  const target = squash(callee);
  const visit = (n: ts.Node): void => {
    if (ts.isCallExpression(n) && exprOf(n.expression) === target) out.push(n);
    ts.forEachChild(n, visit);
  };
  visit(root);
  return out;
}

/** The SPREAD elements of an array literal, or of the array a `new Set([...])`
 *  is built from - each one's own expression, never the list's text. Read
 *  individually on purpose: the list's text carries the trailing comma a reformat
 *  adds and removes, and each element is the fact being pinned anyway. */
function spreadsOf(expr: ts.Expression | null): string[] {
  if (!expr) return [];
  let arr: ts.ArrayLiteralExpression | null = null;
  if (ts.isArrayLiteralExpression(expr)) arr = expr;
  else if (ts.isNewExpression(expr) || ts.isCallExpression(expr)) {
    const first = expr.arguments?.[0];
    if (first && ts.isArrayLiteralExpression(first)) arr = first;
  }
  if (!arr) return [];
  return arr.elements.filter(ts.isSpreadElement).map((e) => exprOf(e.expression));
}

/** The operands of an `&&` chain, flattened. */
function andOperands(e: ts.Expression): string[] {
  if (ts.isBinaryExpression(e) && e.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken) {
    return [...andOperands(e.left), ...andOperands(e.right)];
  }
  return [exprOf(e)];
}

/** The first `return`'s own expression inside `root`. */
function returnExprOf(root: ts.Node | null): string | null {
  if (!root) return null;
  let out: string | null = null;
  const visit = (n: ts.Node): void => {
    if (out !== null) return;
    if (ts.isReturnStatement(n) && n.expression) {
      out = exprOf(n.expression);
      return;
    }
    ts.forEachChild(n, visit);
  };
  visit(root);
  return out;
}

/** Every `if` inside `root`, in source order. */
function ifsIn(root: ts.Node | null): ts.IfStatement[] {
  const out: ts.IfStatement[] = [];
  if (!root) return out;
  const visit = (n: ts.Node): void => {
    if (ts.isIfStatement(n)) out.push(n);
    ts.forEachChild(n, visit);
  };
  visit(root);
  return out;
}

/** The named function a node sits inside, for a pin that is about WHICH consumer
 *  asks the question rather than about the question being asked somewhere. */
function enclosingName(n: ts.Node): string {
  let cursor: ts.Node | undefined = n.parent;
  while (cursor) {
    if (ts.isFunctionDeclaration(cursor) && cursor.name) return cursor.name.text;
    cursor = cursor.parent;
  }
  return "(top level)";
}

const applyV3Fn = functionNamed("applyV3");
const buildFn = functionNamed("buildBackup");
const keyRecordFn = functionNamed("keyRecord");
const landedKeyFn = functionNamed("landedKey");

console.log("\n[apply source] identityIds' provenance, which is one expression from destructive");
// THE MUTATION THIS EXISTS FOR compiles clean and puts the destructive path back:
// build the set from `sanitizePayload`'s raw `identities` instead of from what
// `normaliseIdentityKeys` RETURNED, and an identity that pass SKIPPED counts as
// existing - so a host naming it takes outcome 2, the binding is APPLIED, and the
// host is pointed at an identity that was never written. Both expressions are
// `VaultIdentity[]`, so the compiler cannot tell them apart, and every gate in
// this repository was green over exactly that edit.
const identityIdsInit = localInit(applyV3Fn, "identityIds");
const identityHalves = spreadsOf(identityIdsInit);
// The pin's own precondition, checked out loud: a rename that took either name
// away would otherwise leave every comparison below running over `(missing)` and
// reporting it as a failure of the wrong thing.
check(
  "applyV3 and the identityIds it hands the credential pass are both found",
  [applyV3Fn !== null, identityIdsInit !== null],
  [true, true],
);
// THE SET IS A UNION AND EACH HALF IS PINNED ON ITS OWN, because a pin that
// asserts only the first passes over an implementation that drops the second, and
// the other way round. Two checks, so one mutation reddens one of them and the
// pair says which fact broke rather than that "the expression changed".
check(
  "the FILE's half comes from normaliseIdentityKeys' return, and parsed.identities is not read",
  [
    identityHalves[0] ?? "(missing)",
    identityIdsInit ? exprOf(identityIdsInit).includes(squash("parsed.identities")) : true,
  ],
  [squash("normalised.identities.map((i) => i.id)"), false],
);
check(
  "and the SAVED half is there, so an identity this machine already holds counts as existing",
  [identityHalves.length, identityHalves[1] ?? "(missing)"],
  [2, squash("existingIdentities.map((i) => i.id)")],
);

console.log(
  "\n[apply source] the landed key carries its GROUP, and each consumer asks with its own",
);
// The group was not in this key before v3, where every reference came from one
// group over one id space. Dropping it back out compiles, and `storedFields` then
// reports a stored credential for a host whose secret never landed - a presence
// flag taken from the file by the back door. `[secret refs]` above catches that
// behaviourally through the one consumer a plain-node run can call; these two pin
// the key itself and the two consumers it cannot reach.
check(
  "landedKey returns the payload group, then the id, then the field",
  returnExprOf(landedKeyFn) ?? "(missing)",
  squash("`${group}::${id}::${field}`"),
);
// The behavioural half of the same fact, and the reason the function is exported:
// two groups over one id and one field have to be two different keys. A group
// dropped from the key collapses them onto one, and this says so without reading
// any source at all.
check(
  "so the same id and field under two groups are two different keys",
  landedKey(HOST_SECRET_GROUP, "x-1", "password") ===
    landedKey(IDENTITY_SECRET_GROUP, "x-1", "password"),
  false,
);
check(
  "and the construction site keys by the REF's own group, not by a bare id",
  calls(applyV3Fn, "landedKey")
    .filter((c) => exprOf(c.arguments[0]) === "r.group")
    .map((c) => c.arguments.map((a) => exprOf(a)))[0] ?? ["(missing)"],
  ["r.group", "r.id", "r.field"],
);
// EACH CONSUMER WITH ITS OWN CONSTANT. Keying by group and then querying two of
// the three with the wrong one is silently equivalent to not having keyed at all,
// and a pin on the key alone would not see it. Sorted rather than in source order:
// which consumer asks with which group is the contract, and where the passes sit
// relative to each other is `applyV3`'s own documented write order, pinned there.
check(
  "every landedKey consumer asks under its own group",
  calls(applySf, "landedKey")
    .map((c) => `${enclosingName(c)}: ${exprOf(c.arguments[0])}`)
    .sort(),
  [
    "applyV3: IDENTITY_SECRET_GROUP",
    "applyV3: KEY_SECRET_GROUP",
    "applyV3: KEY_SECRET_GROUP",
    "applyV3: r.group",
    "storedFields: HOST_SECRET_GROUP",
  ],
);

console.log(
  "\n[apply source] keyRecord is called TWICE, and the first call is the conservative one",
);
// "Did the private body land" is UNANSWERABLE at the record write: it is only
// known after `backup_apply_secrets`, which the RECORDS-BEFORE-SECRETS order puts
// after the key write. So the first call passes a literal `false` - nothing has
// landed yet, so the conservative arm is the TRUE one rather than merely the safe
// one - and the flag pass calls it again with the real answer. The file's
// fingerprint therefore never sits over this machine's private key at any moment,
// and it lands in the same import once the body does.
//
// The two-call SHAPE is the check: a single call would be a silent regression to a
// record that momentarily names a key nobody holds.
check(
  "two calls, and the record write hands over a literal false",
  calls(applyV3Fn, "keyRecord").map((c) => exprOf(c.arguments[2])),
  ["false", "landedBody"],
);
// The two arms of `keyRecord` are a pair, and a check on one is satisfied by an
// implementation that gets the other wrong - so both are in one condition. A key
// that is NEW keeps the file's triple whatever landed, because there is nothing
// stored to keep, and its `hasPrivateKey` stays false, so the fingerprint reads as
// metadata for a key still to be added rather than a claim about one the store
// holds. A key already here whose body DID land keeps the file's triple too, over
// the private key it actually describes.
check(
  "nothing stored, or the body landed: either way the file's triple wins",
  ifsIn(keyRecordFn).map((s) => exprOf(s.expression))[0] ?? "(missing)",
  squash("!stored || landedBody"),
);

console.log("\n[export source] what buildBackup names, which no fixture here can reach");
// `buildBackup` calls `invoke`, so this half has no behavioural gate and cannot
// have one: a real export is ciphertext, and the hand test can only do
// well-formed round trips. All three of these are one deletion from a silent loss
// with every other gate in the repository green.
check(
  "buildBackup is found, so the three pins below are asking about something",
  buildFn !== null,
  true,
);
// (a) ALL THREE BUILDERS. Delete the identities spread and every identity password
// stops travelling; delete the keys spread and every stored private key body
// does. That is exactly the contract `hostRefs`' own doc states - a field this
// stops naming simply stops travelling - and nothing else enforces it for two of
// the three record kinds.
check(
  "the export names every record kind that owns a secret",
  spreadsOf(localInit(buildFn, "refs")),
  [
    squash("hosts.flatMap(hostRefs)"),
    squash("identities.flatMap(identityRefs)"),
    squash("keys.flatMap(keyRefs)"),
  ],
);
// (b) ALL FIVE COLLECTIONS SEALED. A collection dropped here exports as absent,
// and `sanitizePayload` imports an absent collection as EMPTY rather than
// failing - by design, so a payload sealed by a build with no vault stays
// readable - so the round trip would lose it in silence at both ends. The
// importing end of this pin is `[payload collections]` above.
check(
  "and seals all five inventory collections",
  calls(buildFn, "JSON.stringify")
    .map((c) => c.arguments[0])
    .filter(ts.isObjectLiteralExpression)
    .map((o) => o.properties.map((p) => p.name?.getText(applySf) ?? "(computed)"))[0] ?? ["(none)"],
  ["hosts", "groups", "identities", "keys", "rules"],
);
// (c) THE EMPTINESS REFUSAL NEEDS ALL FIVE. Reverting it to `hosts.length === 0`
// makes a vault-only profile - identities and keys and no host yet - unable to
// export at all, which is the defect this condition exists to fix.
const emptinessGuard = ifsIn(buildFn).find(
  (s) =>
    ts.isBinaryExpression(s.expression) &&
    s.expression.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken,
);
check(
  "and refuses to export only when every one of the five is empty",
  emptinessGuard ? andOperands(emptinessGuard.expression) : ["(no conjunction at all)"],
  ["hosts", "groups", "identities", "keys", "rules"].map((c) => squash(`${c}.length === 0`)),
);

console.log(failed === 0 ? "\nAll backup checks passed." : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
