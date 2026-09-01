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
  vaultKeyFactsFrom,
  vaultKeyTypeFrom,
  type KeyInspectResult,
  type VaultKeyFacts,
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

function count(src: string, re: RegExp): number {
  return [...src.matchAll(re)].length;
}

/**
 * A single line with any `//` that starts OUTSIDE a string literal, and
 * everything after it, cut off. Quote-aware so a URL or a literal `//` inside a
 * string survives - same convention as `host-editor-verify.ts` and
 * `rdp-lifetime-verify.ts`'s own `stripLineComment`, duplicated here rather than
 * imported because this file owns no shared module to import it from.
 */
function stripLineComment(line: string): string {
  let quote = "";
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote) {
      if (c === "\\") i++;
      else if (c === quote) quote = "";
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      quote = c;
      continue;
    }
    if (c === "/" && line[i + 1] === "/") return line.slice(0, i);
  }
  return line;
}

/**
 * The same source with comments removed: a whole line is dropped if its
 * trimmed text opens a `//`, `/*` or `*` comment (which is every continuation
 * line of a prettier-formatted block or doc comment), and a trailing `//` is
 * stripped from what is left. Used by section [5]'s whole-file safe/verified
 * check so that check runs over what this file RENDERS rather than over a doc
 * comment that states the rule by quoting the words it forbids.
 */
function stripComments(src: string): string {
  return src
    .split("\n")
    .filter((line) => {
      const t = line.trim();
      return !(t.startsWith("//") || t.startsWith("/*") || t.startsWith("*"));
    })
    .map(stripLineComment)
    .join("\n");
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
console.log("\n[3b] vaultKeyFactsFrom - what the STORE records, which is not what the panel shows");
{
  const facts = (info: Partial<KeyInspectResult>): VaultKeyFacts =>
    vaultKeyFactsFrom({
      parsed: true,
      encrypted: false,
      keyType: null,
      fingerprint: null,
      publicKey: null,
      comment: null,
      ...info,
    });

  // A sealed container yields NOTHING - not `keyType: "unknown"`, which would
  // claim the algorithm was read. `KeyCard.tsx:53-57` renders the two
  // differently, so this is a visible difference and not a nicety.
  check(
    "a sealed container records no keyType at all",
    facts({ parsed: false, encrypted: true, keyType: "ssh-rsa" }).keyType === undefined,
    facts({ parsed: false, encrypted: true, keyType: "ssh-rsa" }),
  );
  check(
    "...and no fingerprint or public half either",
    Object.keys(facts({ parsed: false })).length === 0,
    facts({ parsed: false }),
  );

  // A PARSED key with no algorithm reported is the opposite case: it WAS read,
  // and "unknown" is the honest answer rather than an absent field.
  check(
    "a parsed key with no algorithm records keyType 'unknown'",
    facts({ keyType: null }).keyType === "unknown",
    facts({ keyType: null }),
  );

  const ed = facts({
    keyType: "ssh-ed25519",
    fingerprint: "SHA256:abc123",
    publicKey: "ssh-ed25519 AAAAC3Nz... rendy@host",
  });
  check("the wire algorithm is mapped, not stored raw", ed.keyType === "ed25519", ed);
  check("the fingerprint is carried verbatim", ed.fingerprint === "SHA256:abc123", ed);
  check(
    "and so is the public half, which describeKeyInfo drops",
    ed.publicKey === "ssh-ed25519 AAAAC3Nz... rendy@host",
    ed,
  );

  // The `??` trap: `KeyCard.tsx:68` renders
  // `vaultKey.fingerprint ?? "No fingerprint recorded"`, and `"" ?? x` is `""`,
  // so a blank stored here is a blank LINE on screen where the sentence
  // belongs. Same for the public half.
  const blank = facts({ keyType: "ssh-rsa", fingerprint: "", publicKey: "" });
  check('a blank fingerprint becomes undefined, never ""', blank.fingerprint === undefined, blank);
  check('a blank public half becomes undefined, never ""', blank.publicKey === undefined, blank);

  // STRUCTURAL, not behavioural: the mapping is DELEGATED. The three
  // checks above agree with an implementation that reimplemented the algorithm
  // table here, and a second table is how two surfaces come to disagree about
  // what an `sk-ecdsa-` key is. V8 in this step's mutation list is the
  // cross-file half of the same claim.
  const keyInspectSrc = read("src/modules/vault/keyInspect.ts");
  const factsBody =
    /function vaultKeyFactsFrom\(info: KeyInspectResult\): VaultKeyFacts \{([\s\S]*?)\n\}/.exec(
      keyInspectSrc,
    );
  check("vaultKeyFactsFrom's body is located", factsBody !== null);
  const factsSrc = factsBody?.[1] ?? "";
  // VLT-80/7d(b): comment-stripped before the positive below - a raw
  // `.includes("vaultKeyTypeFrom(")` is satisfied by moving the real call
  // into a comment and deleting it. Sanity-checked first, the same model as
  // this file's own section [5] at :576-580: an empty string would pass the
  // next check for free.
  const strippedFacts = stripComments(factsSrc);
  check(
    "stripping comments left real code behind (vaultKeyFactsFrom's body)",
    strippedFacts.length > 50,
    strippedFacts.length,
  );
  check(
    "it calls vaultKeyTypeFrom rather than mapping the algorithm itself",
    strippedFacts.includes("vaultKeyTypeFrom("),
  );
  check(
    "and names no algorithm literal of its own",
    !/ed25519|ecdsa|ssh-rsa|rsa-sha2/.test(strippedFacts),
    strippedFacts,
  );
}

// ---------------------------------------------------------------------------
console.log("\n[4] stripComments - the helper this section's whole-file check depends on");
{
  // Proved before it is trusted, because section [5]'s safe/verified check is
  // only as honest as this stripper: too little stripped and it fails on the
  // rule's own wording (the gap D4 found, scoped to KeyInspectPanel's body
  // specifically to dodge it); too much stripped, or silently vacuous, and it
  // passes for free over a live violation sitting in real, rendered code.
  check(
    "drops a whole-line comment that merely NAMES a forbidden word",
    !stripComments('// this key is now "verified" and safe\nwriteIt();').includes("verified"),
  );
  check(
    "drops a TRAILING comment naming a forbidden word, not only a whole line",
    !stripComments('const ok = true; // was: reads as "protected"').includes("protected"),
  );
  check(
    "does not touch a forbidden word sitting inside a STRING literal",
    stripComments('const s = "still safe // not a comment";').includes("safe"),
  );
  check(
    "keeps the code that sits around the comment it drops",
    stripComments("// safe\nwriteIt();").includes("writeIt();"),
  );
}

// ---------------------------------------------------------------------------
console.log("\n[5] SshCredentialSection.tsx - the wiring, over the raw source");
{
  const sectionRaw = read("src/modules/hosts/editor/SshCredentialSection.tsx");

  check(
    "inspectSshKey is imported from the ssh bridge",
    /import \{[^}]*\binspectSshKey\b[^}]*\}\s*from\s*"@\/modules\/ssh\/bridge";/.test(sectionRaw),
  );

  // checkKey's own region: from its declaration to the next sibling declaration
  // (`invalidateInspection`, added between it and `pickKeyFile` to close D1-D3),
  // so "inside checkKey" means the innermost enclosing block rather than merely
  // somewhere nearby in the file. A distance heuristic ("within N characters of
  // the function name") would read a call sitting just past checkKey's closing
  // brace as gated, and is exactly what let C1 and C2 hide (see the mutation
  // record at the bottom of this file).
  const checkKeyRegion = between(
    sectionRaw,
    "const checkKey = async (pem: string, passphrase: string) => {",
    "const invalidateInspection = () => {",
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

  // D1: a checkKey response must be discarded unless the input it answers is
  // still the input in the field. A generation counter needs to be three
  // things at once - claimed before the first await (so a second call outruns
  // a first one still in flight), and checked again on BOTH the resolved and
  // the rejected path (so neither can slip a stale panel past a guard the
  // other one has) - and all three are asserted, not just the counter's
  // existence.
  check(
    "checkKey claims a generation before its first await, not after",
    /const generation = \+\+inspectGeneration\.current;\s*\n\s*if \(!pem\.trim\(\)\)/.test(
      checkKeyRegion,
    ),
    checkKeyRegion,
  );
  check(
    "both the resolved and the rejected path gate setInspected behind that generation - not one of the two, and not neither",
    count(
      checkKeyRegion,
      /if \(inspectGeneration\.current === generation\) setInspected\(result\);/g,
    ) === 2,
    checkKeyRegion,
  );

  // D2/D3: `invalidateInspection` is the one place that retires a stale panel,
  // so it must exist, actually reset to idle (not merely bump a counter no
  // renderer reads), and actually be wired to BOTH inputs checkKey consumes -
  // not only the key body, which is the half D3 already had a comment, but no
  // check, for.
  const invalidateRegion = between(
    sectionRaw,
    "const invalidateInspection = () => {",
    "const pickKeyFile = async () => {",
  );
  check(
    "invalidateInspection's region was located",
    invalidateRegion.length > 20,
    invalidateRegion.length,
  );
  check(
    "invalidateInspection bumps the generation AND resets the panel to idle - either alone leaves a gap the other closes",
    invalidateRegion.includes("inspectGeneration.current += 1;") &&
      invalidateRegion.includes('setInspected({ kind: "idle" });'),
    invalidateRegion,
  );

  const textareaOnChangeRegion = between(
    sectionRaw,
    "<Textarea",
    'placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"',
  );
  check(
    "the key-body textarea's onChange region was located",
    textareaOnChangeRegion.length > 20,
    textareaOnChangeRegion.length,
  );
  check(
    "editing the key body invalidates the panel (D3) through the shared helper, not a bare reset D1/D2's generation guard could then be bypassed by",
    textareaOnChangeRegion.includes("invalidateInspection();"),
    textareaOnChangeRegion,
  );

  const passphraseFieldRegion = between(
    sectionRaw,
    '<Field label="Key passphrase (optional)">',
    "</Field>",
  );
  check(
    "the key-passphrase field's region was located",
    passphraseFieldRegion.length > 20,
    passphraseFieldRegion.length,
  );
  check(
    "editing the key passphrase ALSO invalidates the panel (D2) - checkKey reads this field too, so a stale panel can outlive it exactly as it can the key body",
    passphraseFieldRegion.includes("invalidateInspection();"),
    passphraseFieldRegion,
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

  const onChangeAt = pickKeyFileRegion.indexOf("onChange({ privateKey: result.content");
  const emptyGuardAt = pickKeyFileRegion.indexOf("if (!result.content.trim())");
  const loadedAt = pickKeyFileRegion.indexOf('setImported({ kind: "loaded", path: picked });');
  const checkKeyCallAt = pickKeyFileRegion.indexOf('await checkKey(result.content, "");');
  check(
    "the draft write, the emptiness check, the loaded status and the inspection call were all found inside pickKeyFile",
    onChangeAt >= 0 && emptyGuardAt >= 0 && loadedAt >= 0 && checkKeyCallAt >= 0,
    { onChangeAt, emptyGuardAt, loadedAt, checkKeyCallAt },
  );
  check(
    "and they run in that order: commit the picked text, THEN check whether it was blank, THEN report loaded, THEN inspect - so a failed check still leaves the picked text on screen and a blank one is never reported as a load",
    onChangeAt >= 0 &&
      emptyGuardAt >= 0 &&
      loadedAt >= 0 &&
      checkKeyCallAt >= 0 &&
      onChangeAt < emptyGuardAt &&
      emptyGuardAt < loadedAt &&
      loadedAt < checkKeyCallAt,
    { onChangeAt, emptyGuardAt, loadedAt, checkKeyCallAt },
  );

  // D6a: a passphrase left over from whatever key WAS in the field must not be
  // reused against a newly picked one.
  check(
    "picking a new key file clears the passphrase field rather than reusing whatever was already in it",
    /onChange\(\{ privateKey: result\.content, keyPassphrase: "" \}\);/.test(pickKeyFileRegion),
    pickKeyFileRegion,
  );
  check(
    "and checks the newly picked key with that blank passphrase, not the stale value.keyPassphrase",
    pickKeyFileRegion.includes('await checkKey(result.content, "");'),
    pickKeyFileRegion,
  );

  // D6b: the empty-file guard's own region, so its message and its cleanup are
  // asserted to be INSIDE the branch only a blank file takes, not merely
  // present somewhere in pickKeyFile.
  const emptyGuardRegion = between(
    pickKeyFileRegion,
    "if (!result.content.trim())",
    'setImported({ kind: "loaded"',
  );
  check(
    "the empty-file guard's own region was located",
    emptyGuardRegion.length > 20,
    emptyGuardRegion.length,
  );
  check(
    'a whitespace-only picked file reports a diagnostic - "Picked file is empty" - instead of silently landing on "Loaded <path>" beside a panel showing nothing',
    /kind:\s*"error"/.test(emptyGuardRegion) && emptyGuardRegion.includes('"Picked file is empty"'),
    emptyGuardRegion,
  );
  check(
    "and it retires any inspection panel already on screen from whatever key was there before",
    emptyGuardRegion.includes("invalidateInspection();"),
    emptyGuardRegion,
  );

  check(
    "the rendered panel labels the fingerprint, so it cannot be mistaken for the recorded server key's",
    /Key fingerprint/.test(sectionRaw),
  );

  // D5: "Encrypted" alone, beside the algorithm, in an editor that is about to
  // persist the key body to a mode-0600 plaintext JSON file, reads as a claim
  // about THIS app's storage rather than the key file's own passphrase. The
  // label must name the object the encryption belongs to.
  check(
    'the encrypted badge names what is encrypted (the key FILE) rather than the bare, misreadable word "Encrypted"',
    sectionRaw.includes("Key file is passphrase-encrypted") &&
      !/>Encrypted<\/span>/.test(sectionRaw),
    sectionRaw.match(/<span[^>]*>[^<]*[Ee]ncrypted[^<]*<\/span>/)?.[0],
  );

  // The two-hard-constraints trap: nothing this FILE renders may claim a secret
  // is safer than it is. D4: scoping this to KeyInspectPanel's own body missed
  // the "Check key" button and the imported-file status line - same visual
  // block, same ability to overclaim - so this now runs over the WHOLE file,
  // comments stripped, rather than one component's tail. Comments are stripped
  // rather than excluded by carving out one doc comment's byte range, because a
  // doc comment naming these words to STATE the rule is not the only place in
  // this file allowed to name them, and is not the only place a future comment
  // might.
  const strippedSection = stripComments(sectionRaw);
  check(
    "stripping comments left real code behind - not an empty or near-empty string, which would pass the next check for free",
    strippedSection.length > 3000 && strippedSection.includes("function KeyInspectPanel("),
    strippedSection.length,
  );
  check(
    'no copy this file renders - the panel, the "Check key" button, or the imported-file status line - claims a key or the vault is "safe", "verified" or "protected"',
    !/\bsafe\b|\bverified\b|\bprotected\b/i.test(strippedSection),
    /.{0,40}(\bsafe\b|\bverified\b|\bprotected\b).{0,40}/i.exec(strippedSection)?.[0],
  );
}

// ---------------------------------------------------------------------------
console.log("\n[6] the Rust side's own messages have not silently changed under this UI's feet");
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
//   C3: `await checkKey(...)` moved above               "and they run in that
//     `onChange({ privateKey: result.content,             order: commit the picked
//     keyPassphrase: "" })` in pickKeyFile                 text, THEN check whether
//                                                       it was blank..."
//   C4: mod.rs's ERR_DSA text changed to "nope"         "mod.rs still carries the
//     (src-tauri/, restored by hash - see the wave        message naming "DSA keys
//     orchestrator's mutation log, not this repo)         are not supported""
//   C5: vaultKeyTypeFrom made to `return "unknown"`     eight of the eleven rows in
//     unconditionally                                    section [3] (every row
//                                                       whose expectation was not
//                                                       already "unknown")
//
// V3-V4, V8 (wave 3 step 1, over keyInspect.ts's new vaultKeyFactsFrom):
//
//   V3: `fingerprint: info.fingerprint || undefined`      section [3b]'s "a blank
//     changed to `fingerprint: info.fingerprint ?? undefined`  fingerprint becomes
//                                                       undefined, never \"\"" check
//   V4: `if (!info.parsed) return {};` changed to         section [3b]'s first two
//     `if (!info.parsed) return { keyType:                 checks (sealed container
//     vaultKeyTypeFrom(info.keyType) };`                    records no keyType/facts)
//   V8: vaultKeyTypeFrom's body changed to                section [3]'s eight
//     `return "unknown";` unconditionally                  non-"unknown" rows AND
//                                                       section [3b]'s mapping row
//                                                       ("the wire algorithm is
//                                                       mapped, not stored raw") -
//                                                       ALSO fails vault-draft-verify
//                                                       section 1, which is the
//                                                       cross-file half of this claim
//
// D1-D6 (this pass, live UI defects rather than the wiring shape above):
//
//   D1: both `if (inspectGeneration.current ===          count(...) === 2 check:
//     generation)` guards in checkKey replaced with        "both the resolved and
//     bare `setInspected(result);`                         the rejected path gate
//                                                       setInspected behind that
//                                                       generation..."
//   D1: `const generation = ++inspectGeneration.current;`  "checkKey claims a
//     moved to AFTER the `if (!pem.trim())` guard            generation before its
//                                                       first await, not after"
//   D2: `invalidateInspection();` deleted from the         "editing the key
//     passphrase Input's onChange                           passphrase ALSO
//                                                       invalidates the panel
//                                                       (D2)..."
//   D3: textarea onChange's `invalidateInspection();`      "editing the key body
//     reverted to a bare `setInspected({ kind: "idle" });`   invalidates the panel
//                                                       (D3) through the shared
//                                                       helper..."
//   D6a: `keyPassphrase: ""` dropped from pickKeyFile's     "picking a new key file
//     `onChange` call                                       clears the passphrase
//                                                       field..."
//   D6b: the `if (!result.content.trim())` branch          "the empty-file guard's
//     deleted from pickKeyFile                               own region was
//                                                       located" (region collapses
//                                                       to length 0)
//   D6b: the branch kept but its `invalidateInspection();`  "and it retires any
//     line removed                                          inspection panel
//                                                       already on screen..."
//   D5: "Key file is passphrase-encrypted" reverted to      the D5 check itself
//     bare `Encrypted`
//   D4: `verified` written into KeyInspectPanel's           "no copy this file
//     rendered JSX (not a comment)                          renders...safe...
//                                                       verified...protected"
process.exit(failed === 0 ? 0 : 1);
