/**
 * Self-check for the key-import diagnostics (issue #3 / Track C).
 * Run: `pnpm verify key-inspect`.
 *
 * `src-tauri/src/modules/ssh/mod.rs` already classifies a pasted or picked key
 * and phrases every dead end - that half shipped in `07d20d5`, `90e4c87` and
 * `79ce0aa`, with its own cargo tests at `mod.rs:941-1070`. What this file checks
 * is the frontend half added alongside it: the pure translation in
 * `src/modules/vault/keyInspect.ts` (behavioural, called directly - it is a plain
 * module with no Tauri surface), and the wiring into
 * `src/modules/hosts/editor/SshCredentialSection.tsx` (source-text, for the same
 * reason `host-editor-verify.ts` reads React effects as text: there is no DOM in
 * this suite to drive `checkKey` through a real click).
 *
 * The source-text sections exist to catch three specific ways this wiring goes
 * wrong quietly:
 *   - `checkKey` calls the bridge only in name, e.g. because a refactor left the
 *     real call somewhere else in the file (check 8).
 *   - `checkKey` also patches the draft, which would mark the key field "touched"
 *     from a read - and touched is what decides whether a save can delete a
 *     stored key (check 9).
 *   - `pickKeyFile` calls the inspector before it commits the picked text to the
 *     draft, so a failed inspection leaves nothing on screen to look at (check 10).
 *
 * Every region below is asserted to have been FOUND before anything is checked
 * over it: `between()` returns `""` for a missing anchor, and an empty string
 * satisfies a negative check (`!"".includes(...)`) for free. An unwatched anchor
 * would turn "the call was removed" into a silent pass on exactly the checks that
 * exist to catch it.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  describeKeyError,
  describeKeyInfo,
  vaultKeyTypeFrom,
  type KeyInspectResult,
} from "../src/modules/vault/keyInspect";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (p: string) => readFileSync(join(root, p), "utf8");

let checked = 0;
let failed = 0;
function check(name: string, ok: boolean, detail?: unknown): void {
  checked++;
  if (ok) {
    console.log(`  ok: ${name}`);
    return;
  }
  console.error(`  FAIL: ${name}`, detail === undefined ? "" : JSON.stringify(detail));
  failed++;
}

/**
 * The source between two anchors, or "" if either is missing. Anchored on code
 * rather than line numbers so an edit above does not move the region.
 */
function between(src: string, from: string, to: string): string {
  const start = src.indexOf(from);
  if (start < 0) return "";
  const end = src.indexOf(to, start + from.length);
  if (end < 0) return "";
  return src.slice(start, end);
}

// ---------------------------------------------------------------------------
console.log("[1] describeKeyInfo - the container's answer, translated for the panel");
{
  check(
    "a sealed container reports locked, not an error",
    JSON.stringify(
      describeKeyInfo({
        parsed: false,
        encrypted: true,
        keyType: null,
        fingerprint: null,
        publicKey: null,
        comment: null,
      }),
    ) === JSON.stringify({ kind: "locked" }),
  );

  const plainEd25519: KeyInspectResult = {
    parsed: true,
    encrypted: false,
    keyType: "ssh-ed25519",
    fingerprint: "SHA256:abc123",
    publicKey: "ssh-ed25519 AAAAC3Nz... rendy@host",
    comment: "rendy@host",
  };
  const okPlain = describeKeyInfo(plainEd25519);
  check(
    "a plain ed25519 key reports ok, its algorithm, and its fingerprint carried through",
    okPlain.kind === "ok" &&
      okPlain.keyType === "ssh-ed25519" &&
      okPlain.fingerprint === "SHA256:abc123",
    okPlain,
  );
  check(
    "and it is not reported as encrypted",
    okPlain.kind === "ok" && okPlain.encrypted === false,
    okPlain,
  );
  check(
    "and its comment survives",
    okPlain.kind === "ok" && okPlain.comment === "rendy@host",
    okPlain,
  );

  // The case the doc comment calls out by name: an encrypted openssh-key-v1 key
  // inspected without its passphrase keeps the public half in cleartext but seals
  // the comment away. A missing comment here is normal, not a failure.
  const encryptedNoPass: KeyInspectResult = {
    parsed: true,
    encrypted: true,
    keyType: "ssh-ed25519",
    fingerprint: "SHA256:def456",
    publicKey: "ssh-ed25519 AAAAC3Nz...",
    comment: null,
  };
  const okEncrypted = describeKeyInfo(encryptedNoPass);
  check(
    "an encrypted OpenSSH key inspected without a passphrase still reports ok",
    okEncrypted.kind === "ok" && okEncrypted.encrypted === true,
    okEncrypted,
  );
  check(
    "and its absent comment renders as absent, not as a failure",
    okEncrypted.kind === "ok" && okEncrypted.comment === undefined,
    okEncrypted,
  );

  const parsedNoType: KeyInspectResult = {
    parsed: true,
    encrypted: false,
    keyType: null,
    fingerprint: "SHA256:xyz",
    publicKey: null,
    comment: null,
  };
  const okNoType = describeKeyInfo(parsedNoType);
  check(
    'a parsed key with no reported algorithm renders "unknown", not null and not blank',
    okNoType.kind === "ok" && okNoType.keyType === "unknown",
    okNoType,
  );
}

// ---------------------------------------------------------------------------
console.log("\n[2] describeKeyError - the backend's own sentence, minus its prefix");
{
  const stripped = describeKeyError(
    new Error("ssh: that is a public key. Paste the private key instead"),
  );
  check(
    "the ssh: prefix is gone and the rest of the sentence is untouched",
    stripped.kind === "error" &&
      stripped.message === "that is a public key. Paste the private key instead",
    stripped,
  );

  const fromString = describeKeyError("plain string");
  check(
    "a plain thrown string still becomes an error state with a message",
    fromString.kind === "error" && fromString.message.length > 0,
    fromString,
  );
  const fromUndefined = describeKeyError(undefined);
  check(
    "and so does throwing nothing at all",
    fromUndefined.kind === "error" && fromUndefined.message.length > 0,
    fromUndefined,
  );
}

// ---------------------------------------------------------------------------
console.log("\n[3] vaultKeyTypeFrom - the wire name, mapped to the vault's four-member union");
{
  // Eleven rows, not three: a three-row table (one per non-"unknown" member)
  // passes for almost any implementation, including one that only inspects the
  // first character.
  const table: { algorithm: string | null; want: string }[] = [
    { algorithm: "ssh-ed25519", want: "ed25519" },
    { algorithm: "ssh-rsa", want: "rsa" },
    { algorithm: "rsa-sha2-256", want: "rsa" },
    { algorithm: "rsa-sha2-512", want: "rsa" },
    { algorithm: "ecdsa-sha2-nistp256", want: "ecdsa" },
    { algorithm: "ecdsa-sha2-nistp521", want: "ecdsa" },
    { algorithm: "sk-ssh-ed25519@openssh.com", want: "ed25519" },
    { algorithm: "sk-ecdsa-sha2-nistp256@openssh.com", want: "ecdsa" },
    { algorithm: "ssh-dss", want: "unknown" },
    { algorithm: "", want: "unknown" },
    { algorithm: null, want: "unknown" },
  ];
  for (const row of table) {
    check(
      `vaultKeyTypeFrom(${JSON.stringify(row.algorithm)}) -> ${row.want}`,
      vaultKeyTypeFrom(row.algorithm) === row.want,
      vaultKeyTypeFrom(row.algorithm),
    );
  }
}

// ---------------------------------------------------------------------------
console.log("\n[4] SshCredentialSection.tsx - the wiring, over the raw source");
{
  const sectionRaw = read("src/modules/hosts/editor/SshCredentialSection.tsx");

  check(
    "inspectSshKey is imported from the ssh bridge",
    /import \{[^}]*\binspectSshKey\b[^}]*\}\s*from\s*"@\/modules\/ssh\/bridge";/.test(sectionRaw),
  );

  // checkKey's own region: from its declaration to the next sibling declaration,
  // so "inside checkKey" means the innermost enclosing block rather than merely
  // somewhere nearby in the file. A distance heuristic ("within N characters of
  // the function name") would read a call sitting just past checkKey's closing
  // brace as gated, and is exactly what let C1 and C2 hide.
  const checkKeyRegion = between(
    sectionRaw,
    "const checkKey = async (pem: string, passphrase: string) => {",
    "const pickKeyFile = async () => {",
  );
  check("checkKey's region was located", checkKeyRegion.length > 50, checkKeyRegion.length);

  check(
    "checkKey calls the real bridge function, not a stand-in",
    /\binspectSshKey\(/.test(checkKeyRegion),
    checkKeyRegion,
  );
  // Negative, over the raw source including comments and dead branches: an
  // inspection that also patched the draft would mark the key field edited
  // without the user having touched it, which is what decides whether a save can
  // delete a stored key.
  check(
    "and checkKey never calls onChange - it only reads, it does not patch the draft",
    !checkKeyRegion.includes("onChange("),
    checkKeyRegion,
  );

  // pickKeyFile's own region, likewise bounded by the next sibling in the file
  // rather than a fixed character window.
  const pickKeyFileRegion = between(
    sectionRaw,
    "const pickKeyFile = async () => {",
    "// The user and the credential are one block",
  );
  check(
    "pickKeyFile's region was located",
    pickKeyFileRegion.length > 200,
    pickKeyFileRegion.length,
  );

  const onChangeAt = pickKeyFileRegion.indexOf("onChange({ privateKey: result.content });");
  const checkKeyCallAt = pickKeyFileRegion.indexOf("checkKey(");
  check(
    "both the draft write and the inspection call were found inside pickKeyFile",
    onChangeAt >= 0 && checkKeyCallAt >= 0,
    { onChangeAt, checkKeyCallAt },
  );
  check(
    "and the draft write happens BEFORE the inspection, so a failed check still leaves the picked text on screen",
    onChangeAt >= 0 && checkKeyCallAt >= 0 && onChangeAt < checkKeyCallAt,
    { onChangeAt, checkKeyCallAt },
  );

  check(
    "the rendered panel labels the fingerprint, so it cannot be mistaken for the recorded server key's",
    /Key fingerprint/.test(sectionRaw),
  );

  // The two-hard-constraints trap: nothing the panel RENDERS may claim a secret
  // is safer than it is. Scoped to the panel component's own body (from its
  // declaration to the end of the file, where it is the last thing defined)
  // rather than the whole file, because the doc comment right above it names
  // "safe"/"verified" explicitly to state the rule it is not allowed to violate -
  // checking the whole file would fail on the rule's own wording.
  const panelAt = sectionRaw.indexOf("function KeyInspectPanel(");
  check("KeyInspectPanel's declaration was located", panelAt >= 0, panelAt);
  const panelBody = panelAt >= 0 ? sectionRaw.slice(panelAt) : "";
  check(
    'no copy the panel renders claims the key or the vault is "safe" or "verified"',
    !/\bsafe\b|\bverified\b/i.test(panelBody),
    /.{0,40}(\bsafe\b|\bverified\b).{0,40}/i.exec(panelBody)?.[0],
  );
}

// ---------------------------------------------------------------------------
console.log("\n[5] the Rust side's own messages have not silently changed under this UI's feet");
{
  const modRs = read("src-tauri/src/modules/ssh/mod.rs");
  for (const substring of [
    "that is a public key",
    "DSA keys are not supported",
    "SEC1",
    "wrong passphrase for this private key",
    "unrecognised key format",
  ]) {
    check(`mod.rs still carries the message naming "${substring}"`, modRs.includes(substring));
  }

  const libRs = read("src-tauri/src/lib.rs");
  check("ssh_key_inspect is still registered as a command", /ssh::ssh_key_inspect/.test(libRs));
}

console.log(`\n${checked - failed}/${checked} key-inspect checks passed`);
if (failed > 0) console.error(`${failed} check(s) FAILED.`);

// --- mutation record for this file's own checks ---------------------------
//
//   Mutation                                          Check it killed
//   -------------------------------------------------  ---------------------------
//   C1: checkKey's body replaced with just             "checkKey calls the real
//     `setInspected({ kind: "idle" });`                  bridge function, not a
//                                                       stand-in"
//   C2: `onChange({ privateKey: pem });` added          "and checkKey never calls
//     inside checkKey                                    onChange..."
//   C3: `await checkKey(...)` moved above               "and the draft write
//     `onChange({ privateKey: result.content })`         happens BEFORE the
//     in pickKeyFile                                     inspection..."
//   C4: mod.rs's ERR_DSA text changed to "nope"         "mod.rs still carries the
//     (src-tauri/, restored by hash - see the wave        message naming "DSA keys
//     orchestrator's mutation log, not this repo)         are not supported""
//   C5: vaultKeyTypeFrom made to `return "unknown"`     eight of the eleven rows in
//     unconditionally                                    section [3] (every row
//                                                       whose expectation was not
//                                                       already "unknown")
process.exit(failed === 0 ? 0 : 1);
