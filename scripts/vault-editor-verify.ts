/**
 * Self-check for wave 3 step 5: the two vault editors -
 * `src/modules/vault/editor/KeyEditorDialog.tsx` and
 * `.../IdentityEditorDialog.tsx`. Run: `pnpm verify vault-editor`.
 *
 * Written by a DIFFERENT agent from the one that wrote either dialog (steps 2
 * and 3): the author of a piece of code defends it, so every section here
 * exists to try to redden theirs, not to restate what the dialogs already say
 * about themselves in their own comments.
 *
 * SOURCE-TEXT, like `key-inspect-verify.ts`, with the compiler API
 * (`vault-shell-verify.ts`'s precedent) wherever a question is about NESTING -
 * "is this call lexically inside `save`" is a shape a distance heuristic
 * cannot tell from "these two strings happen to sit near each other" (see
 * `vault-shell-verify.ts`'s own header on its section 6/M3).
 *
 * Every anchored region is asserted to have been FOUND before anything is
 * checked over it: `between()` returns `""` for a missing anchor, and an
 * empty string satisfies a negative check for free.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import ts from "typescript";

import {
  identityPasswordHelp,
  passphraseHelp,
  privateKeyHelp,
} from "../src/modules/vault/editor/draft";

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

const FILES = {
  keyDialog: "src/modules/vault/editor/KeyEditorDialog.tsx",
  identityDialog: "src/modules/vault/editor/IdentityEditorDialog.tsx",
} as const;
const src = Object.fromEntries(Object.entries(FILES).map(([k, p]) => [k, read(p)])) as Record<
  keyof typeof FILES,
  string
>;

// ---------------------------------------------------------------------------
// Copied helpers - VLT-33, there is no `scripts/lib`.
// ---------------------------------------------------------------------------

/** The source between two anchors, or "" if either is missing - copied from
 *  `key-inspect-verify.ts`. */
function between(str: string, from: string, to: string): string {
  const start = str.indexOf(from);
  if (start < 0) return "";
  const end = str.indexOf(to, start + from.length);
  if (end < 0) return "";
  return str.slice(start, end);
}

function count(str: string, re: RegExp): number {
  return [...str.matchAll(re)].length;
}

/** A single line with any `//` that starts outside a string literal cut off -
 *  copied from `key-inspect-verify.ts`'s `stripLineComment`. */
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

/** The same source with comments removed - copied from
 *  `key-inspect-verify.ts`'s `stripComments`. Used so a doc comment's own
 *  PROSE about what a function does NOT do (which is free to name the very
 *  words a check forbids, in order to disclaim them) cannot redden that
 *  check. `KeyEditorDialog.tsx`'s `save` has exactly this shape: its comment
 *  says "read off `inspected`" while explaining why it does not. */
function stripComments(str: string): string {
  return str
    .split("\n")
    .filter((line) => {
      const t = line.trim();
      return !(t.startsWith("//") || t.startsWith("/*") || t.startsWith("*"));
    })
    .map(stripLineComment)
    .join("\n");
}

/** The function DECLARATION body named `name` - `KeyEditorDialog` and
 *  `IdentityEditorDialog` are both plain `export function Name(...) { ... }`
 *  declarations, the same shape `vault-shell-verify.ts`'s own
 *  `findFunctionBody` covers. */
function findFunctionBody(root: ts.Node, name: string): ts.Node | null {
  let result: ts.Node | null = null;
  const visit = (n: ts.Node): void => {
    if (ts.isFunctionDeclaration(n) && n.name?.text === name && n.body) result = n.body;
    ts.forEachChild(n, visit);
  };
  visit(root);
  return result;
}

/** The body of a `const <name> = (...) => { ... }` / `async (...) => { ... }`
 *  arrow function declaration - the shape `checkKey`, `invalidateInspection`,
 *  `pickKeyFile` and both `save`s all use. Not `vault-shell-verify.ts`'s
 *  `useCallbackFactory`, because none of these five is wrapped in
 *  `useCallback`. */
function findConstArrowBody(root: ts.Node, name: string): ts.Node | null {
  let result: ts.Node | null = null;
  const visit = (n: ts.Node): void => {
    if (
      ts.isVariableDeclaration(n) &&
      ts.isIdentifier(n.name) &&
      n.name.text === name &&
      n.initializer &&
      ts.isArrowFunction(n.initializer)
    ) {
      result = n.initializer.body;
    }
    ts.forEachChild(n, visit);
  };
  visit(root);
  return result;
}

/** Every call expression anywhere under `root` whose callee's own source text
 *  is exactly one of `calleeNames`. */
function findCalls(root: ts.Node, sf: ts.SourceFile, calleeNames: string[]): ts.CallExpression[] {
  const out: ts.CallExpression[] = [];
  const visit = (n: ts.Node): void => {
    if (ts.isCallExpression(n) && calleeNames.includes(n.expression.getText(sf))) out.push(n);
    ts.forEachChild(n, visit);
  };
  visit(root);
  return out;
}

/** Every JSX element or self-closing element in `root` whose tag is
 *  `tagName`, as its opening element - copied from `vault-shell-verify.ts`. */
function findOpeningElementsByTag(
  root: ts.Node,
  tagName: string,
  sf: ts.SourceFile,
): (ts.JsxOpeningElement | ts.JsxSelfClosingElement)[] {
  const out: (ts.JsxOpeningElement | ts.JsxSelfClosingElement)[] = [];
  const visit = (n: ts.Node): void => {
    if (ts.isJsxSelfClosingElement(n) && n.tagName.getText(sf) === tagName) out.push(n);
    if (ts.isJsxOpeningElement(n) && n.tagName.getText(sf) === tagName) out.push(n);
    ts.forEachChild(n, visit);
  };
  visit(root);
  return out;
}

const sourceFile = (key: keyof typeof FILES): ts.SourceFile =>
  ts.createSourceFile(FILES[key], src[key], ts.ScriptTarget.ESNext, true, ts.ScriptKind.TSX);

// ============================================================================
// 1. Anchors - every region the sections below depend on is located, on its
//    own, before anything is asserted over it. A rename fails HERE, loudly,
//    rather than leaving every later check running over `null`/"".
// ============================================================================
console.log("[1. anchors] both files parse, and every region below is found");
{
  const keySf = sourceFile("keyDialog");
  const identitySf = sourceFile("identityDialog");

  check(
    "KeyEditorDialog's function body is located",
    findFunctionBody(keySf, "KeyEditorDialog") !== null,
  );
  check(
    "IdentityEditorDialog's function body is located",
    findFunctionBody(identitySf, "IdentityEditorDialog") !== null,
  );
  check("checkKey's body is located", findConstArrowBody(keySf, "checkKey") !== null);
  check(
    "invalidateInspection's body is located",
    findConstArrowBody(keySf, "invalidateInspection") !== null,
  );
  check("pickKeyFile's body is located", findConstArrowBody(keySf, "pickKeyFile") !== null);
  check("KeyEditorDialog's save body is located", findConstArrowBody(keySf, "save") !== null);
  check(
    "IdentityEditorDialog's save body is located",
    findConstArrowBody(identitySf, "save") !== null,
  );
}

// ============================================================================
// 2. The generation counter, in the key editor. (D1-D3 of key-inspect-verify,
//    re-run over the vault's OWN copy of this mechanism.)
// ============================================================================
// Protects: a `checkKey` response repainting the panel after a newer call, or
// an edit to either input, has moved the generation on - the exact race
// `SshCredentialSection.tsx`'s own D1-D3 defects were.
console.log(
  "\n[2. generation counter] checkKey/invalidateInspection close the race on both inputs",
);
{
  const ks = src.keyDialog;

  const checkKeyRegion = between(
    ks,
    "const checkKey = async (pem: string, passphrase: string) => {",
    "const invalidateInspection = () => {",
  );
  check("checkKey's region was located", checkKeyRegion.length > 50, checkKeyRegion.length);
  check(
    "checkKey claims a generation before its first await, not after (before the blank-body guard's return)",
    /const generation = \+\+inspectGeneration\.current;\s*\n\s*if \(!pem\.trim\(\)\)/.test(
      checkKeyRegion,
    ),
    checkKeyRegion,
  );
  check(
    "both the resolved and the rejected path gate setInspected behind that generation - exactly 2, not merely >= 1",
    count(
      checkKeyRegion,
      /if \(inspectGeneration\.current === generation\) setInspected\(result\);/g,
    ) === 2,
    checkKeyRegion,
  );

  const invalidateRegion = between(
    ks,
    "const invalidateInspection = () => {",
    "const pickKeyFile = async () => {",
  );
  check(
    "invalidateInspection's region was located",
    invalidateRegion.length > 20,
    invalidateRegion.length,
  );
  check(
    "invalidateInspection bumps the generation AND resets the panel to idle",
    invalidateRegion.includes("inspectGeneration.current += 1;") &&
      invalidateRegion.includes('setInspected({ kind: "idle" });'),
    invalidateRegion,
  );

  const textareaRegion = between(
    ks,
    "<Textarea",
    'placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"',
  );
  check(
    "the key-body textarea's onChange region was located",
    textareaRegion.length > 20,
    textareaRegion.length,
  );
  check(
    "editing the key body invalidates the panel",
    textareaRegion.includes("invalidateInspection();"),
    textareaRegion,
  );

  // The half wave 1's host-editor version shipped WITHOUT: this file's own
  // passphrase input closes it. If this fails alone (textarea above staying
  // green), the check is doing its per-input job; if both fail together, the
  // check cannot tell the two apart and is not doing its job at all.
  const passphraseRegion = between(ks, '<Field label="Key passphrase (optional)">', "</Field>");
  check(
    "the key-passphrase field's region was located",
    passphraseRegion.length > 20,
    passphraseRegion.length,
  );
  check(
    "editing the key passphrase ALSO invalidates the panel",
    passphraseRegion.includes("invalidateInspection();"),
    passphraseRegion,
  );

  const loadEffectRegion = between(
    ks,
    "useEffect(() => {",
    "const patch = (next: Partial<KeyDraft>)",
  );
  check(
    "the load effect's region was located",
    loadEffectRegion.length > 50,
    loadEffectRegion.length,
  );
  check(
    "loading a (possibly different) target bumps the generation, so a stale inspection cannot repaint over it",
    loadEffectRegion.includes("inspectGeneration.current += 1;"),
    loadEffectRegion,
  );
}

// ============================================================================
// 3. The save inspects the FIELDS, not the panel.
// ============================================================================
// Protects: a save that read `inspected` would inherit the same
// still-in-flight question one level deeper, and would silently pass every
// OTHER check in this section - the negative is what catches it.
console.log("\n[3. save inspects fields] KeyEditorDialog's save reads draft.privateKey itself");
{
  const saveRegion = between(src.keyDialog, "const save = async () => {", "const busy = saving");
  check("KeyEditorDialog's save region was located", saveRegion.length > 100, saveRegion.length);
  check(
    "save calls inspectSshKey on the draft's own field",
    saveRegion.includes("inspectSshKey(draft.privateKey"),
    saveRegion,
  );
  check(
    "guarded by a non-blank test on draft.privateKey",
    /if \(draft\.privateKey\.trim\(\) !== ""\)/.test(saveRegion),
    saveRegion,
  );
  // Comment-stripped: the save's own doc comment explains why it does NOT
  // read `inspected`, and does so by naming it - "read off `inspected`" -
  // which is prose about the negative, not a use of the negative. Checking
  // the raw text here would redden the correct, committed code.
  // Anchored on `validateKeyDraft(draft, mode)`, not on `inspectSshKey` or
  // `upsertKey` - the self-test must stay meaningful even under the
  // mutations THIS section and section 4 exist to catch (X4 removes the
  // `inspectSshKey` call, X5 moves `upsertKey` out of this body entirely), so
  // it cannot depend on either call being tested for.
  const strippedSave = stripComments(saveRegion);
  check(
    "stripping comments left real code behind (not near-empty, which would pass the next check for free)",
    strippedSave.length > 100 && strippedSave.includes("validateKeyDraft(draft, mode)"),
    strippedSave.length,
  );
  check(
    "and save's own CODE - comments stripped - never mentions `inspected` at all: a save that read the panel would pass every other check above",
    !/inspected/i.test(strippedSave),
    strippedSave,
  );
}

// ============================================================================
// 4. Store writes live only in `save`. (COMPILER API)
// ============================================================================
// Protects: §4.16's question asked of a new dialog - does anything here
// survive Cancel. A distance heuristic reads a write sitting just past
// save's closing brace as "inside" it; only lexical containment can tell.
console.log("\n[4. store writes] every upsert call is lexically inside its file's own save");
{
  const keySf = sourceFile("keyDialog");
  const saveBody = findConstArrowBody(keySf, "save");
  check("KeyEditorDialog's save body was located (compiler API)", saveBody !== null);
  const upsertKeyCalls = findCalls(keySf, keySf, ["upsertKey"]);
  check("found at least one upsertKey call", upsertKeyCalls.length > 0, upsertKeyCalls.length);
  if (saveBody) {
    for (const c of upsertKeyCalls) {
      check(
        `${c.getText(keySf)} is lexically inside KeyEditorDialog's save`,
        c.getStart(keySf) >= saveBody.getStart(keySf) && c.end <= saveBody.end,
        c.getText(keySf),
      );
    }
  }
  check(
    "KeyEditorDialog.tsx contains no deleteKey/deleteIdentity call",
    !/delete(Key|Identity)\(/.test(src.keyDialog),
  );

  const identitySf = sourceFile("identityDialog");
  const identitySaveBody = findConstArrowBody(identitySf, "save");
  check("IdentityEditorDialog's save body was located (compiler API)", identitySaveBody !== null);
  const upsertIdentityCalls = findCalls(identitySf, identitySf, ["upsertIdentity"]);
  check(
    "found at least one upsertIdentity call",
    upsertIdentityCalls.length > 0,
    upsertIdentityCalls.length,
  );
  if (identitySaveBody) {
    for (const c of upsertIdentityCalls) {
      check(
        `${c.getText(identitySf)} is lexically inside IdentityEditorDialog's save`,
        c.getStart(identitySf) >= identitySaveBody.getStart(identitySf) &&
          c.end <= identitySaveBody.end,
        c.getText(identitySf),
      );
    }
  }
  check(
    "IdentityEditorDialog.tsx contains no deleteKey/deleteIdentity call",
    !/delete(Key|Identity)\(/.test(src.identityDialog),
  );

  // Neither file imports the delete helpers from `../page/derive` -
  // `IdentityEditorDialog.tsx` DOES import that module (for the `KeyRow`
  // type only), so this checks the import CLAUSE, not merely the module
  // specifier's absence.
  for (const key of ["keyDialog", "identityDialog"] as const) {
    const deriveImport =
      /import\s+(?:type\s+)?\{([^}]*)\}\s*from\s*["']\.\.\/page\/derive["']/.exec(src[key]);
    check(
      `${FILES[key]}: if it imports from ../page/derive, the clause names no delete helper`,
      deriveImport === null || !/delete/i.test(deriveImport[1]),
      deriveImport?.[1],
    );
  }
}

// ============================================================================
// 5. The record and the secrets come from the shared pure functions.
// ============================================================================
// Protects: §4.46 - agreement BY VALUE cannot forbid a second, silently
// divergent implementation. Structural: `save` must call the shared builders,
// and the file must not carry the object-literal keys that are the tell of a
// record assembled by hand instead.
console.log(
  "\n[5. shared pure functions] save calls the draft.ts builders, and assembles nothing itself",
);
{
  check("KeyEditorDialog.tsx calls keyRecordFrom(", src.keyDialog.includes("keyRecordFrom("));
  check(
    "KeyEditorDialog.tsx calls keySecretsForSave(",
    src.keyDialog.includes("keySecretsForSave("),
  );
  check(
    "IdentityEditorDialog.tsx calls identityRecordFrom(",
    src.identityDialog.includes("identityRecordFrom("),
  );
  check(
    "IdentityEditorDialog.tsx calls identitySecretsForSave(",
    src.identityDialog.includes("identitySecretsForSave("),
  );

  const smellKeys = [
    "keyType:",
    "fingerprint:",
    "publicKey:",
    "hasPassword:",
    "hasPrivateKey:",
    "hasPassphrase:",
  ];
  for (const key of ["keyDialog", "identityDialog"] as const) {
    const stripped = stripComments(src[key]);
    for (const smell of smellKeys) {
      check(
        `${FILES[key]} (comments stripped) does not assemble a record with a literal \`${smell}\``,
        !stripped.includes(smell),
        stripped.includes(smell) ? smell : undefined,
      );
    }
  }
}

// ============================================================================
// 6. Neither editor reads a secret.
// ============================================================================
// Protects: §1.1's invariant, said as a check. The vault exposes no
// single-value secret read by design; the day one is added, these files must
// not be the first callers.
console.log(
  "\n[6. no secret read] neither dialog reads a secret off the vault or the SSH resolver",
);
{
  const needles = [
    "secrets_get",
    "getAll(",
    "resolveSshAuth",
    "SECRET_ALREADY_STORED",
    "getHostSshSecrets",
  ];
  for (const key of ["keyDialog", "identityDialog"] as const) {
    for (const needle of needles) {
      check(`${FILES[key]} does not contain \`${needle}\``, !src[key].includes(needle));
    }
  }
}

// ============================================================================
// 7. The picker is the shared one.
// ============================================================================
// Protects: §4.25 - `Combobox` carries the stopPropagation fix for the modal
// scroll lock. A bare `<select>` would compile, render, and lose it silently.
console.log("\n[7. shared picker] IdentityEditorDialog uses the shared Combobox, not its own list");
{
  const idn = src.identityDialog;
  check(
    "imports Combobox from @/modules/hosts/editor/Combobox",
    /import\s*\{[^}]*\bCombobox\b[^}]*\}\s*from\s*"@\/modules\/hosts\/editor\/Combobox";/.test(idn),
  );
  const comboboxTags = count(idn, /<Combobox\b/g);
  check("renders exactly one <Combobox", comboboxTags === 1, comboboxTags);
  check("IdentityEditorDialog.tsx has no listKeys( call", !idn.includes("listKeys("));
  check(
    "IdentityEditorDialog.tsx has no keyRows( call (keyRows is a prop, not a function)",
    !idn.includes("keyRows("),
  );
  check(
    "IdentityEditorDialog.tsx does not read hasPrivateKey directly - it reads missingPrivateKey off the shared row",
    !idn.includes("hasPrivateKey"),
  );
  check(
    "reads chosenKey?.missingPrivateKey off the shared row",
    idn.includes("chosenKey?.missingPrivateKey"),
  );
}

// ============================================================================
// 8. The help copy is the shared copy.
// ============================================================================
// Protects: inlining a help sentence is a second place the wording lives,
// which is how it goes stale silently (§4.15's shape, one file over). The
// negative is asserted against the FUNCTIONS' actual return values, imported
// and sliced at runtime - a hard-coded sentence here would be a THIRD place
// the copy lives.
console.log(
  "\n[8. shared help copy] both dialogs call the draft.ts help functions, and never inline them",
);
{
  check("KeyEditorDialog.tsx calls privateKeyHelp(", src.keyDialog.includes("privateKeyHelp("));
  check("KeyEditorDialog.tsx calls passphraseHelp(", src.keyDialog.includes("passphraseHelp("));
  check(
    "IdentityEditorDialog.tsx calls identityPasswordHelp(",
    src.identityDialog.includes("identityPasswordHelp("),
  );

  // A distinctive middle slice of each of the six possible return values -
  // not the whole string (too easy to accidentally reformat around) and not
  // the first few words (too generic to be a real tell).
  const slice = (s: string): string => s.slice(10, 40);
  const strings: { label: string; value: string }[] = [
    { label: 'privateKeyHelp("create")', value: privateKeyHelp("create") },
    { label: 'privateKeyHelp("edit")', value: privateKeyHelp("edit") },
    { label: "passphraseHelp(true)", value: passphraseHelp(true) },
    { label: "passphraseHelp(false)", value: passphraseHelp(false) },
    { label: "identityPasswordHelp(true)", value: identityPasswordHelp(true) },
    { label: "identityPasswordHelp(false)", value: identityPasswordHelp(false) },
  ];
  for (const key of ["keyDialog", "identityDialog"] as const) {
    for (const { label, value } of strings) {
      const needle = slice(value);
      check(
        `${FILES[key]} does not inline a verbatim slice of ${label}'s sentence`,
        !src[key].includes(needle),
        needle,
      );
    }
  }
}

// ============================================================================
// 9. One controlled dialog per file, and no caret claim. (COMPILER API for
//    the `open=` attribute, to dodge `=>` inside onOpenChange breaking a
//    naive text scan to the next `>`.)
// ============================================================================
// Protects: locality - `modal-shortcut-verify.ts` sweeps this from the
// outside across all of `src/`; asserting it here too means a future refactor
// that moves these files out of its consumer list does not silently drop
// this coverage as well.
console.log("\n[9. controlled dialog] exactly one <Dialog>, and it carries a literal open=");
{
  for (const key of ["keyDialog", "identityDialog"] as const) {
    const sf = sourceFile(key);
    const tags = findOpeningElementsByTag(sf, "Dialog", sf);
    check(`${FILES[key]}: exactly one <Dialog opening tag`, tags.length === 1, tags.length);
    if (tags.length === 1) {
      const hasOpen = tags[0].attributes.properties.some(
        (attr) =>
          ts.isJsxAttribute(attr) &&
          attr.name.getText(sf) === "open" &&
          attr.initializer !== undefined,
      );
      check(`${FILES[key]}: its <Dialog> carries a literal open= attribute`, hasOpen);
    }
    check(`${FILES[key]} does not reference paneCaret`, !src[key].includes("paneCaret"));
    check(`${FILES[key]} does not call createPortal`, !src[key].includes("createPortal"));
    check(`${FILES[key]} does not hand-roll "fixed inset-0"`, !src[key].includes("fixed inset-0"));
  }
}

// ============================================================================
// 10. Wording, over comment-stripped code.
// ============================================================================
// Protects: this panel reports what a key IS, and answers no question about
// how well anything is kept - the same rule `key-inspect-verify.ts` runs over
// the host editor's own copy of this panel, for the same reason.
console.log(
  '\n[10. wording] neither dialog\'s rendered copy overclaims "safe"/"verified"/"protected"',
);
{
  // Proved before trusted - both fixtures, the same two `key-inspect-verify.ts`
  // uses: a whole-line comment naming the word is dropped, and so is a
  // trailing one.
  check(
    "stripComments drops a whole-line comment that merely NAMES a forbidden word",
    !stripComments('// this key is now "verified" and safe\nwriteIt();').includes("verified"),
  );
  check(
    "stripComments drops a TRAILING comment naming a forbidden word too",
    !stripComments('const ok = true; // was: reads as "protected"').includes("protected"),
  );

  for (const key of ["keyDialog", "identityDialog"] as const) {
    const stripped = stripComments(src[key]);
    check(
      `${FILES[key]}: stripping comments left real code behind`,
      stripped.length > 3000,
      stripped.length,
    );
    check(
      `${FILES[key]}: no rendered copy claims a key or the vault is "safe", "verified" or "protected"`,
      !/\bsafe\b|\bverified\b|\bprotected\b/i.test(stripped),
      /.{0,40}(\bsafe\b|\bverified\b|\bprotected\b).{0,40}/i.exec(stripped)?.[0],
    );
    // The sentence must arrive through SECRET_STORE_LOCATIONS - three copies
    // of a store-name literal is how it came to be wrong on two platforms
    // (§4.15). `mode-0600` is deliberately NOT a needle here: both headers use
    // it honestly, to DISCLAIM a safety claim, and forbidding it would redden
    // the sentence that disclaims the very overclaim this section exists to
    // catch.
    check(
      `${FILES[key]}: does not re-inline a store name literal instead of using SECRET_STORE_LOCATIONS`,
      !/Keychain|DPAPI|Credential Manager/.test(stripped),
    );
  }
}

console.log(`\n${checked - failed}/${checked} vault-editor checks passed`);
if (failed > 0) console.error(`${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
