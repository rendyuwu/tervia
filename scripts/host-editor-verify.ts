/**
 * Self-check for the credential state machine in the merged host editor.
 * Run: `pnpm verify host-editor`.
 *
 * Source text, not imports, for the reason `rdp-lifetime-verify.ts` gives: these
 * invariants live inside a React component's effects and event handlers, and
 * there is no DOM or renderer in this suite to drive them through. What is
 * checkable without one is the STRUCTURE - and structure is exactly what all four
 * findings below were: a write with no guard, a guard reading a value captured
 * before the thing it guards could happen, a persisted change gated on nothing.
 *
 * 1. THE KEYCHAIN SEED YIELDS TO A FIELD THE USER TYPED. The form is interactive
 *    from `setReady(true)` while `getHostSshSecrets` is still in flight, and that
 *    read is three sequential `keyring::Entry::get_password` calls on macOS, any
 *    of which can stop on an OS access prompt. A seed that wrote all three fields
 *    unconditionally therefore had two ways to lose: it replaced a password typed
 *    during the read with the STORED one while the field still counted as touched,
 *    so the save sent the old secret back and reported success - a rotation
 *    silently discarded; or it wrote `""` over a password typed on a host with
 *    nothing stored, and validation then refused over a field the user had just
 *    filled. `stale()` does not help: it asks whether the form moved to a
 *    different ROW, and typing does not move it.
 *
 *    The touched record is a REF for this reason and not for a render budget. A
 *    `useState` value read from the effect's closure is the one captured when the
 *    load started - all three false, forever, because the reset at the top of the
 *    same effect is what set them.
 *
 * 2. ONLY A FIELD THE USER TOUCHED REACHES THE SECRET STORE. An untouched field
 *    is `undefined`, the store's "leave whatever is stored alone"; `""` is its
 *    CLEAR instruction. Echoing the seed back would make an edit that only renamed
 *    a host take its password with it. Correct today, pinned because it is invisible
 *    at the call site: `sshSecretsForSave(cred, touched)` looks like a formatter.
 *
 * 3. TEST PINS THE SAVED RECORD ONLY FOR THE ADDRESS THAT RECORD NAMES. `runTest`
 *    dials the DRAFT address, so trusting a certificate persisted a fingerprint
 *    from one machine onto a record still saved at another: re-point the form,
 *    Test, accept, Cancel, and the old pin is destroyed with nothing saved. The
 *    record's next real connect aborts as a MISMATCH, which reads as an attack
 *    rather than as a cancelled dialog, and the pin cannot be recovered because
 *    only that machine can present it. The FORM's pin is deliberately still
 *    ungated on the address - it is unsaved, visible, and disposed of by Cancel.
 *
 *    The guard SURVIVES pins being keyed per address, and the reason is not the
 *    mismatch any more: a keyed write for the address being proposed would never be
 *    compared against by a record saved elsewhere, so it fails neither open nor
 *    closed - but it would still be a trust change this dialog persisted and then
 *    had cancelled. Save is the only thing that commits a pin.
 *
 * 6. FORGET RECORDS INTENT IN THE DRAFT, AND TEST VERIFIES AGAINST THE MACHINE IT
 *    IS ACTUALLY DIALLING. The inverse of 3, found by hand (gaps 15 and 20), and it
 *    failed OPEN. `Test` verified against the pin of the machine the SAVED record
 *    named, so a re-pointed host could not be tested until `Forget` had destroyed
 *    the old pin - and `Forget` wrote straight to the store, outside the dialog
 *    transaction. Cancel reverted the address and nothing reverted the pin, so the
 *    host was left with no pinned key at all, silently on TOFU, accepting whatever
 *    the next connect presented. Unrecoverable: only that machine can present that
 *    key. One fix closes both halves - pins keyed per address, so an address never
 *    visited has no pin to compare against and none has to be destroyed first, and
 *    Forget edits the draft map that Save writes.
 *
 * 4. A VAULT-BOUND SAVE WRITES NO SECRET AND HANDS THE BINDING BACK. A non-inline
 *    record owns no accounts, so the draft loads blank - and rebuilding an inline
 *    credential from that blank draft sent the store its CLEAR instruction, losing
 *    the binding AND the secret while the identity's own secrets sat untouched
 *    (handoff §5.3). Both protocols, since one save path now serves them.
 *
 * 5. THE HELP TEXT NAMES NO STORE THE PLATFORM DOES NOT HAVE. The copy said "your
 *    OS keychain (Windows Credential Manager / macOS Keychain)". On Linux
 *    `secrets.rs` writes plaintext JSON at mode 0600, and Windows has been a
 *    DPAPI file since the Credential Manager's 2560-byte CredentialBlob started
 *    truncating RSA key bodies. Nothing here may imply a secret is safer than it
 *    is, so the location is stated once and reused.
 *
 * Section [0] tests the helpers the other five depend on, against samples whose
 * answers are known. That is not ceremony: `rdp-lifetime-verify.ts` shipped a
 * gating check that looked back a fixed 90 characters, found the PREVIOUS
 * statement's guard, and reported a deliberately ungated write as gated. A
 * structural check nobody has watched fail is a comment.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (p: string) => readFileSync(join(root, p), "utf8");

let failed = 0;
function check(name: string, ok: boolean, detail?: unknown): void {
  if (ok) {
    console.log(`  ok: ${name}`);
    return;
  }
  console.error(`  FAIL: ${name}`, detail === undefined ? "" : JSON.stringify(detail));
  failed++;
}

/**
 * The source between two anchors, or "" if either is missing. Anchored on code
 * rather than line numbers so an edit above does not move the region, and every
 * region below is checked for having been FOUND - otherwise a renamed anchor
 * turns every check over the empty string into a pass.
 */
function between(src: string, from: string, to: string): string {
  const start = src.indexOf(from);
  if (start < 0) return "";
  const end = src.indexOf(to, start + from.length);
  if (end < 0) return "";
  return src.slice(start, end);
}

/**
 * A line with its trailing `//` comment removed, string literals respected.
 *
 * Quote-aware rather than a regex because a `//` inside a string is not a
 * comment, and this editor's help text is exactly the sort of string that would
 * one day contain one. An apostrophe in unquoted JSX text opens a quote state
 * that never closes, which loses the strip for that one line - it fails towards
 * keeping text, never towards deleting code.
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
 * The same source with comments removed.
 *
 * Every structural check below runs on this rather than on the raw file, because
 * the prose in this component describes its own guards in detail - "the same
 * comparison `save`'s `keepPin` makes" is a sentence that would satisfy a regex
 * looking for that comparison. Deleting a guard and leaving the comment must
 * fail, and stripping first is what makes it fail.
 *
 * Trailing comments are stripped as well as whole-line ones, and that is not
 * tidiness: with only whole lines removed, `const keepPin = true; // was: const
 * keepPin = !existing || existing.host === host;` passed every check in section
 * [3] with the comparison gone. Confirmed by breaking it exactly that way.
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

/**
 * The condition of the `if` attached to the statement `needle` sits in, or "" if
 * that statement has no guard of its own.
 *
 * Deliberately not "is there an `if` somewhere before this": it walks back to the
 * nearest statement boundary, so a write following a guarded statement borrows
 * nothing, and it makes exactly ONE hop over an opening brace so a block-bodied
 * `if` is read while a write merely sitting deeper in a function is not. Section
 * [0] holds it to both.
 */
function guardFor(region: string, needle: string): string {
  let at = region.indexOf(needle);
  if (at < 0) return "";
  for (let hop = 0; hop < 2; hop++) {
    const from = Math.max(
      region.lastIndexOf(";", at - 1),
      region.lastIndexOf("{", at - 1),
      region.lastIndexOf("}", at - 1),
    );
    const stmt = region
      .slice(from + 1, at)
      .trim()
      // A statement may open with an operator keyword before the call a check
      // names (`void pinFingerprint(…)`), and that is still the same statement.
      // Dropped only at the END, so it cannot swallow a guard.
      .replace(/\b(?:void|await|return)$/, "")
      .trim();
    const m = /^if \((.*)\)$/s.exec(stmt);
    if (m) return m[1];
    if (stmt.length > 0 || from < 0 || region[from] !== "{") return "";
    at = from;
  }
  return "";
}

/** What `const <ident> = …;` assigns, so a check can ask what a guard's operands
 *  ARE rather than assuming the names they go by. */
function assignedIn(region: string, ident: string): string {
  const m = new RegExp(`const ${ident} = ([^;]*);`).exec(region);
  return m ? m[1].trim() : "";
}

/** The one line of an object literal that sets `field`, trimmed. */
function propertyLine(region: string, field: string): string {
  const line = region.split("\n").find((l) => l.trim().startsWith(`${field}:`));
  return line ? line.trim() : "";
}

function count(src: string, re: RegExp): number {
  return [...src.matchAll(re)].length;
}

const identifiers = (src: string): string[] =>
  [...src.matchAll(/[A-Za-z_$][\w$]*/g)].map((m) => m[0]);

const editorRaw = read("src/modules/hosts/HostEditorDialog.tsx");
const editorSrc = stripComments(editorRaw);
const rdpSectionRaw = read("src/modules/hosts/editor/RdpCredentialSection.tsx");
const copyRaw = read("src/modules/hosts/editor/secretStoreCopy.ts");

const SECRET_FIELDS = ["password", "privateKey", "keyPassphrase"] as const;

// ---------------------------------------------------------------------------
console.log("[0] the helpers the checks below depend on");
{
  check(
    "guardFor reads the condition of a block-bodied guard",
    guardFor("if (a === b) {\n  writeIt();\n}\n", "writeIt()") === "a === b",
    guardFor("if (a === b) {\n  writeIt();\n}\n", "writeIt()"),
  );
  check(
    "and of a single-statement guard",
    guardFor("if (a === b) writeIt();\n", "writeIt()") === "a === b",
  );
  check(
    "and of a guard whose body opens with void, which is how a fire-and-forget write reads",
    guardFor("if (a === b) {\n  void writeIt();\n}\n", "writeIt()") === "a === b",
    guardFor("if (a === b) {\n  void writeIt();\n}\n", "writeIt()"),
  );
  // The false pass this file exists not to repeat.
  check(
    "but an unguarded write does not borrow the guard of the statement above it",
    guardFor("if (a === b) other();\nwriteIt();\n", "writeIt()") === "",
    guardFor("if (a === b) other();\nwriteIt();\n", "writeIt()"),
  );
  check(
    "not even when that write opens with void",
    guardFor("if (a === b) other();\nvoid writeIt();\n", "writeIt()") === "",
    guardFor("if (a === b) other();\nvoid writeIt();\n", "writeIt()"),
  );
  check(
    "nor the guard that opened the block it sits in two statements deep",
    guardFor("if (a === b) {\n  other();\n  writeIt();\n}\n", "writeIt()") === "",
    guardFor("if (a === b) {\n  other();\n  writeIt();\n}\n", "writeIt()"),
  );
  check(
    "and an unguarded write in a bare block reports nothing",
    guardFor("{\n  writeIt();\n}\n", "writeIt()") === "",
  );
  check(
    "a missing needle reports nothing rather than throwing",
    guardFor("x();\n", "writeIt()") === "",
  );

  check(
    "stripComments drops a comment that merely NAMES a guard",
    !stripComments("// if (a === b)\nwriteIt();").includes("a === b"),
  );
  check(
    "and drops it when it TRAILS the line that removed the guard",
    !stripComments("const keep = true; // was: keep = a === b;").includes("a === b"),
    stripComments("const keep = true; // was: keep = a === b;"),
  );
  check(
    "but leaves a // that is inside a string, which is not a comment",
    stripComments('const s = "a // b";').includes("a // b"),
  );
  check("and keeps the code around it", stripComments("// x\nwriteIt();").includes("writeIt();"));
  check("the editor survived it", editorSrc.includes("export function HostEditorDialog("));
  check("and it removed something", editorSrc.length < editorRaw.length);

  check(
    "assignedIn reports what a local was assigned",
    assignedIn("const a = b?.c;", "a") === "b?.c",
  );
  check("and nothing for a local it cannot find", assignedIn("const a = b;", "z") === "");
}

// ---------------------------------------------------------------------------
console.log("\n[1] the keychain seed cannot overwrite a field the user typed");
{
  const effect = between(editorSrc, "if (applied.current === token) return;", "void load();");
  check("the load effect was found", effect.length > 1000, effect.length);

  const seed = between(
    effect,
    "const secrets = await getHostSshSecrets(host.id);",
    "} catch (e) {",
  );
  check("the keychain seed was found", seed.length > 100, seed.length);
  check(
    "it is applied only once the row is still the one that asked for it",
    seed.includes("if (stale()) return;"),
  );
  // Through `setSshCred`, never the patch channel: a patch is what MARKS a field
  // touched, so seeding through it would make every load look like typing and
  // every rename send all three secrets back.
  check("it writes the draft directly", seed.includes("setSshCred("));
  check(
    "and not through the patch channel, which marks a field touched",
    !seed.includes("patchSshCred"),
  );

  const guards = new Set<string>();
  for (const f of SECRET_FIELDS) {
    const line = propertyLine(seed, f);
    check(`the seed for ${f} was found`, line.length > 0, line);
    // The whole finding in one assertion per field: the seed is the ALTERNATE of
    // a conditional whose consequent keeps the draft value.
    const m = new RegExp(`^${f}: (\\w+)\\.${f} \\? d\\.${f} :`).exec(line);
    check(
      `${f} keeps what the user typed instead of the stored value when touched`,
      m !== null,
      line,
    );
    if (m) guards.add(m[1]);
    check(
      `and ${f} still gets seeded when it was not touched`,
      new RegExp(`secrets\\.${f} \\?\\? ""`).test(line),
      line,
    );
  }
  check("all three consult one record rather than three", guards.size === 1, [...guards]);

  // Not the name of the record but WHAT IT IS: a `.current` read, evaluated when
  // the seed runs. A `useState` value here is the one captured before the user
  // could have typed anything, which is the defect wearing the fix's shape.
  const guardName = [...guards][0] ?? "";
  const guardSource = assignedIn(effect, guardName);
  check(
    "and that record is read live from a ref, not captured from state",
    /\.current$/.test(guardSource),
    { guardName, guardSource },
  );
  check(
    "the editor keeps exactly one touched record, so no guard can drift from the save",
    count(editorSrc, /useRef<SshSecretTouched>/g) === 1 &&
      count(editorSrc, /useState<SshSecretTouched>/g) === 0,
    {
      refs: count(editorSrc, /useRef<SshSecretTouched>/g),
      states: count(editorSrc, /useState<SshSecretTouched>/g),
    },
  );

  // Per row: without this, typing on row A would suppress row B's seed and B
  // would save blank fields it never showed.
  const reset = between(effect, 'setTest({ kind: "idle" });', "const stale = () =>");
  check("the effect's reset block was found", reset.length > 20, reset.length);
  check(
    "and a new row starts with nothing touched",
    /\.current = NO_SSH_SECRETS_TOUCHED;/.test(reset),
    reset.trim(),
  );
}

// ---------------------------------------------------------------------------
console.log("\n[2] only a field the user touched is sent to the secret store");
{
  const forSave = between(
    editorSrc,
    "function sshSecretsForSave(",
    "export function HostEditorDialog(",
  );
  check("sshSecretsForSave was found", forSave.length > 100, forSave.length);
  for (const f of SECRET_FIELDS) {
    check(
      `${f} is sent only when it was touched`,
      new RegExp(`if \\(touched\\.${f}\\) out\\.${f} = cred\\.${f};`).test(forSave),
      propertyLine(forSave, f),
    );
  }
  // Three writes, so a fourth field added later cannot arrive unguarded.
  check(
    "and it writes nothing else",
    count(forSave, /out\./g) === SECRET_FIELDS.length,
    count(forSave, /out\./g),
  );

  const patch = between(editorSrc, "const patchSshCred = (patch:", "const changeProtocol =");
  check("patchSshCred was found", patch.length > 100, patch.length);
  for (const f of SECRET_FIELDS) {
    // `||` because the mark is STICKY: a second patch that does not carry this
    // field must not un-touch it. `!== undefined` because "" is a real edit -
    // clearing a password is a thing the user is allowed to do.
    check(
      `a patch carrying ${f} marks it touched, and one that does not leaves the mark alone`,
      new RegExp(`${f}: \\w+\\.current\\.${f} \\|\\| patch\\.${f} !== undefined`).test(patch),
      propertyLine(patch, f),
    );
  }

  const save = between(editorSrc, "const save = async () => {", "const protocolLabel =");
  check("save was found", save.length > 1000, save.length);
  check(
    "the SSH secrets are taken from the live touched record",
    /sshSecretsForSave\(sshCred, \w+\.current\)/.test(save),
  );
  // The RDP half of the same convention, which has no touched record because the
  // stored password is never read back: blank is `undefined`, not the `""` that
  // would delete it on a save that only renamed the host.
  check(
    "an RDP password left blank is sent as undefined, not the empty string that clears it",
    /password: rdpCred\.password \? rdpCred\.password : undefined/.test(save),
  );
}

// ---------------------------------------------------------------------------
console.log("\n[3] Test pins the saved record only for the address that record names");
{
  const runTest = between(editorSrc, "const runTest = async () => {", "const save = async () => {");
  check("runTest was found", runTest.length > 500, runTest.length);
  const onTrusted = between(runTest, "const onTrusted = (fingerprint: string) => {", "try {");
  check("its trust callback was found", onTrusted.length > 50, onTrusted.length);

  const storeGuard = guardFor(onTrusted, "pinFingerprint(");
  check("the write to the SAVED record is guarded", storeGuard.length > 0, onTrusted.trim());
  check("by an equality rather than a presence test", storeGuard.includes("==="), storeGuard);

  // What the guard's operands ARE, not what they are called: a rename keeps this
  // passing, dropping the address comparison does not.
  const operands = identifiers(storeGuard).map((id) => ({ id, from: assignedIn(runTest, id) }));
  const sources = operands.map((o) => o.from);
  check(
    "it compares the address the SAVED record names",
    sources.includes("existing?.host"),
    operands,
  );
  check("against the address the probe dialled", sources.includes("shared.host.trim()"), operands);
  check(
    "and it still refuses to pin a host that has never been saved",
    sources.includes("existing?.id"),
    operands,
  );

  // The other half of the split, and it must NOT be address-gated: the form's pins
  // are unsaved, one of them shows in the recorded-key row, and Cancel disposes of
  // the map, so one may describe the address being proposed. It is gated on the ROW
  // instead, because a probe outlives the row it started on.
  check(
    "the form's own pin is gated on the row rather than the address",
    guardFor(onTrusted, "setPins(") === "onProbeRow()",
    guardFor(onTrusted, "setPins("),
  );
  // And keyed by the address the probe DIALLED rather than by whatever is in the
  // field now: a trust prompt waits on a human, who is free to keep typing.
  const trustedKey = /setPins\(\(\w+\) => \(\{ \.\.\.\w+, \[(\w+)\]: fingerprint \}\)\)/.exec(
    onTrusted,
  )?.[1];
  check(
    "and filed under the address the probe dialled",
    trustedKey !== undefined && assignedIn(runTest, trustedKey) === "shared.host.trim()",
    { trustedKey, from: trustedKey ? assignedIn(runTest, trustedKey) : null },
  );

  // Save must agree with Test about which pin is the current one, and the agreement
  // is now structural: both index the same draft map by a trimmed address, so there
  // is no second predicate to drift.
  const save = between(editorSrc, "const save = async () => {", "const protocolLabel =");
  check("save was found", save.length > 1000, save.length);
  check(
    "save hands the whole keyed map down, addresses and all",
    /^\s*pins,$/m.test(save),
    propertyLine(save, "pins"),
  );
  // The flat pin is the STORE's projection of that map. A form that also wrote it
  // would be a second writer for one fact, and the old `keepPin` - "the address
  // changed, so the pin must be stale" - is exactly the wrong answer once Test can
  // TOFU a new address: the pin the user just accepted belongs to the new one.
  check(
    "and sets neither flat pin field itself",
    !/lastFingerprint:|certFingerprint:/.test(save),
    /.*(lastFingerprint|certFingerprint):.*/.exec(save)?.[0],
  );
  check("so no address heuristic survives in the save path", !/keepPin/.test(editorSrc));
}

// ---------------------------------------------------------------------------
console.log("\n[6] Forget edits the draft, and Test dials with the pin for that address");
{
  // Gap 20. `Forget` used to call `clearFingerprint` straight through, so Cancel
  // reverted the address and left the host with NO pin - silently back on TOFU.
  const forget = between(editorSrc, "const forgetPin = () => {", "const runTest = async () => {");
  check("forgetPin was found", forget.length > 50, forget.length);
  check("it edits the draft pin map", /setPins\(/.test(forget), forget.trim());
  check(
    "and removes only the address on screen",
    /delete \w+\[draftAddress\];/.test(forget),
    forget.trim(),
  );

  // Every name this file imports from the store, read out of the file rather than
  // listed here, so adding a NEW store import and calling it from Forget also fails.
  const storeImports = /import \{([^}]*)\} from "\.\/store";/.exec(editorRaw)?.[1] ?? "";
  const storeFns = [...storeImports.matchAll(/\b([a-z]\w*)\b/g)]
    .map((m) => m[1])
    .filter((n) => n !== "type");
  check("the store's imported surface was found", storeFns.length >= 4, storeFns);
  const leaks = storeFns.filter((fn) => forget.includes(`${fn}(`));
  check(
    "Forget calls nothing in the store, so Cancel has something to revert",
    leaks.length === 0,
    {
      leaks,
      forget: forget.trim(),
    },
  );
  check("and awaits nothing, because there is nothing to wait for", !/\bawait\b/.test(forget));
  // The store no longer offers the write either, so this cannot be re-added by
  // reaching for the old helper.
  check(
    "no pin-clearing store call is reachable from here at all",
    !editorSrc.includes("clearFingerprint"),
  );

  // Gap 15. Test must verify against the machine it is ACTUALLY DIALLING, or a
  // re-pointed host cannot be tested without destroying its pin first - which is
  // what made gap 20 reachable.
  const runTest = between(editorSrc, "const runTest = async () => {", "const save = async () => {");
  const expected = [
    ...runTest.matchAll(/expected(?:Cert)?Fingerprint: (\w+)\[(\w+)\] \|\| undefined/g),
  ];
  // BOTH protocol arms. One `indexOf` here would have examined the SSH branch only
  // while this file's header claimed it covered both - handoff §5.17.
  check(
    "both probes take their expected pin from a keyed map",
    expected.length === 2,
    expected.length,
  );
  for (const [whole, map, key] of expected) {
    check(
      `${whole.split(":")[0]} is keyed by the address the probe dialled`,
      assignedIn(runTest, key) === "shared.host.trim()",
      { key, from: assignedIn(runTest, key) },
    );
    check(
      `${whole.split(":")[0]} reads the draft map rather than the saved record`,
      new RegExp(`const \\[${map}, set\\w+\\] = useState<HostPins>\\(`).test(editorSrc),
      map,
    );
  }
}

// ---------------------------------------------------------------------------
console.log("\n[4] a vault-bound save writes no secret and hands the binding back");
{
  const save = between(editorSrc, "const save = async () => {", "const protocolLabel =");
  check("save was found", save.length > 1000, save.length);
  // Both protocols, both halves. The count is the check: one arm fixed and the
  // other left rebuilding an inline credential is the original defect.
  check(
    "each protocol reproduces an existing binding instead of rebuilding a credential",
    count(
      save,
      /credential: boundIdentity\s*\? \{ kind: "identity", identityId: boundIdentity \}/g,
    ) === 2,
    count(
      save,
      /credential: boundIdentity\s*\? \{ kind: "identity", identityId: boundIdentity \}/g,
    ),
  );
  check(
    "and each sends no secret at all for a bound row",
    count(save, /secrets = boundIdentity\s*\?\s*\{\}/g) === 2,
    count(save, /secrets = boundIdentity\s*\?\s*\{\}/g),
  );
  check(
    "an inline credential is built only as the alternative to a binding",
    count(save, /kind: "inline"/g) === 2,
    count(save, /kind: "inline"/g),
  );
  // The store, not the form, decides what was actually written.
  check(
    "the record and those secrets go down together",
    /upsertHost\(record, secrets\)/.test(save),
  );
  check(
    "and the caller is handed the persisted record rather than the one built here",
    /onSaved\?\.\(saved\)/.test(save),
  );
}

// ---------------------------------------------------------------------------
console.log("\n[5] the credential copy names no store the platform does not have");
{
  const location = /SECRET_STORE_LOCATIONS =\s*\n?\s*"([^"]*)"/.exec(copyRaw)?.[1] ?? "";
  check("the shared location string was found", location.length > 20, location);
  for (const os of ["macOS", "Windows", "Linux"]) {
    check(`it names ${os}`, location.includes(os), location);
  }
  const linux = location.split(",").find((clause) => clause.includes("Linux")) ?? "";
  check("the Linux clause was found", linux.length > 0, location);
  // `secrets.rs`: `serde_json::to_vec` plus an atomic write at mode 0600. No
  // keyring, no encryption, and the copy may not imply either.
  check("and it says plaintext, which is what is written there", /plaintext/.test(linux), linux);
  check(
    "and claims no keychain and no encryption on a platform that has neither",
    !/keychain|keyring|encrypt/i.test(linux),
    linux,
  );

  for (const [path, src] of [
    ["HostEditorDialog.tsx", editorRaw],
    ["editor/RdpCredentialSection.tsx", rdpSectionRaw],
  ] as const) {
    check(
      `${path} names no OS keychain of its own`,
      !/OS keychain|Credential Manager/.test(src),
      /.{0,60}(OS keychain|Credential Manager).{0,40}/.exec(src)?.[0],
    );
  }
  // Three help strings, one source of truth: three copies of a sentence is how
  // this became wrong on two platforms in the first place.
  check(
    "every help string takes the location from that one string",
    count(editorRaw, /\$\{SECRET_STORE_LOCATIONS\}/g) === 2 &&
      count(rdpSectionRaw, /\$\{SECRET_STORE_LOCATIONS\}/g) === 1,
    {
      editor: count(editorRaw, /\$\{SECRET_STORE_LOCATIONS\}/g),
      rdpSection: count(rdpSectionRaw, /\$\{SECRET_STORE_LOCATIONS\}/g),
    },
  );
}

console.log(failed === 0 ? "\nAll host-editor checks passed." : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
