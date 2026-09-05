/**
 * Self-check for the two vault editors -
 * `src/modules/vault/editor/KeyEditorDialog.tsx` and
 * `.../IdentityEditorDialog.tsx`. Run: `pnpm verify vault-editor`.
 *
 * Written by a DIFFERENT author from the one that wrote either dialog:
 * the author of a piece of code defends it, so every section here
 * exists to try to redden theirs, not to restate what the dialogs already say
 * about themselves in their own comments.
 *
 * SOURCE-TEXT, like `key-inspect-verify.ts`, with the compiler API
 * (`vault-shell-verify.ts`'s precedent) wherever a question is about NESTING -
 * "is this call lexically inside `save`" is a shape a distance heuristic
 * cannot tell from "these two strings happen to sit near each other" (see
 * `vault-shell-verify.ts`'s own header on its section 6).
 *
 * Every anchored region is asserted to have been FOUND before anything is
 * checked over it: `between()` returns `""` for a missing anchor, and an
 * empty string satisfies a negative check for free.
 *
 * Sections 14-16 reach past the two dialogs, because the contract they
 * cover does: the stamp the editors pass is only worth passing if the store
 * still compares it, and a source-text check on the CONSUMER stays green while
 * three separate mutations to the PRODUCER disable it (a plain `Error` of the
 * same message, `actual` set to `expected`, an empty id). So the stamps are
 * exercised as functions, the refusal is caught and its fields read by value,
 * and the compare's POSITION in the write body is asserted structurally - a
 * present-and-counted pin cannot tell a compare before the secret write from
 * one moved after it.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import ts from "typescript";

import { createWriteQueue } from "../src/lib/recoveredStore";
import type { SecretsIo, VaultStoreIo } from "../src/modules/vault/adapters";
import {
  identityPasswordHelp,
  passphraseHelp,
  privateKeyHelp,
} from "../src/modules/vault/editor/draft";
import { createVaultStore } from "../src/modules/vault/store";
import {
  VAULT_KEYRING_SERVICE,
  VAULT_STAMP_ABSENT,
  VaultRecordChangedError,
  vaultAccount,
  vaultIdentityStamp,
  vaultKeyStamp,
  type VaultIdentity,
  type VaultKey,
} from "../src/modules/vault/types";

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
  // Section 16's subject only. Every section that sweeps "both dialogs" names
  // its two keys explicitly rather than iterating `FILES`, so adding a third
  // entry here widens nothing by accident.
  store: "src/modules/vault/store.ts",
} as const;
const src = Object.fromEntries(Object.entries(FILES).map(([k, p]) => [k, read(p)])) as Record<
  keyof typeof FILES,
  string
>;

// ---------------------------------------------------------------------------
// Copied helpers - there is no `scripts/lib`.
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
  // JSX comment expressions - `{/* ... */}` - are the only comment syntax
  // legal INSIDE JSX children (a bare `//` there renders as literal text),
  // and the line-based filter below only ever recognised `//`, `/*` and `*`
  // starting a trimmed line, none of which match a line starting `{`.
  // Discovered live, not hypothesised: a paired mutation moved
  // `chosenKey?.missingPrivateKey` into exactly this shape -
  // `{/* chosenKey?.missingPrivateKey */}` - and the original version of this
  // helper passed it straight through, leaving section 7's positive green
  // over dead, commented-out code.
  //
  // The inner group may not CROSS a `*/`. The first form here was
  // `\{\s*\/\*[\s\S]*?\*\/\s*\}` - lazy, but still allowed to skip past an
  // intervening `*/` while hunting for one that a `}` follows. A type literal
  // opening with a doc comment (`{ /** null = closed. */ target: … }`) matches
  // at that `{`, and the group then keeps extending past every later `*/` not
  // followed by `}` until it finds one that is, eating everything in between.
  // In `host-editor-verify.ts` that cost 50752 characters and 70 cascading
  // failures, and the fix landed there first (in that file's `stripComments`).
  // Here it was LATENT and reddened nothing, which is the worse half:
  // measured on `KeyEditorDialog.tsx` with such a comment added, the old form
  // swallowed 10954 of 22505 characters and the suite still passed 151/151,
  // because the two `> 3000` floors clear on the remainder and every positive
  // happens to anchor outside the swallowed span. What it does silence is the
  // NEGATIVES: a record assembly with a literal `keyType:` planted inside that
  // span passes section 5 for free - a check over stripped-away text
  // goes green. With the lookahead the first `*/` is final: either a `}`
  // follows it and this is a real `{/* … */}`, or the match fails at that `{`
  // rather than searching onward for a luckier one.
  const withoutJsxComments = str.replace(/\{\s*\/\*(?:(?!\*\/)[\s\S])*\*\/\s*\}/g, "");
  return withoutJsxComments
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

/** Whitespace-stripped, for comparing two expressions' source text - section
 *  3's pins 1 and 2 both need this: Prettier decides whether a call spans one
 *  line or four, and that choice is not the claim. Everything else in the
 *  text IS the claim, so this is the ONLY normalisation applied before an
 *  exact-text pin compares two sides. */
function norm(s: string): string {
  return s.replace(/\s+/g, "");
}

/** Every top-level (`=`) assignment expression anywhere under `root` whose
 *  left side is the bare identifier `name` - added for pin 2: "what
 *  is assigned to `facts` inside this function" is a nesting question the
 *  compiler API answers directly, where a regex over the region cannot tell
 *  a real assignment from the same identifier mentioned in a comment or a
 *  different scope. */
function findAssignmentsTo(root: ts.Node, name: string): ts.BinaryExpression[] {
  const out: ts.BinaryExpression[] = [];
  const visit = (n: ts.Node): void => {
    if (
      ts.isBinaryExpression(n) &&
      n.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      ts.isIdentifier(n.left) &&
      n.left.text === name
    ) {
      out.push(n);
    }
    ts.forEachChild(n, visit);
  };
  visit(root);
  return out;
}

/** The `let`/`const` variable declaration named `name` anywhere under `root` -
 *  the declaration node itself, not its enclosing statement (callers that
 *  need the `let`/keyword and the trailing `;` read `.parent.parent`). */
function findVariableDeclaration(root: ts.Node, name: string): ts.VariableDeclaration | null {
  let result: ts.VariableDeclaration | null = null;
  const visit = (n: ts.Node): void => {
    if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.name.text === name) {
      result = n;
    }
    ts.forEachChild(n, visit);
  };
  visit(root);
  return result;
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

/** The literal SOURCE TEXT of a named attribute's expression (`{...}`) or
 *  string value on one opening element - copied from `vault-shell-verify.ts`'s
 *  helper of the same name. `null` if the element has no such attribute. */
function jsxAttrExprText(
  el: ts.JsxOpeningElement | ts.JsxSelfClosingElement,
  attrName: string,
  sf: ts.SourceFile,
): string | null {
  for (const attr of el.attributes.properties) {
    if (ts.isJsxAttribute(attr) && attr.name.getText(sf) === attrName && attr.initializer) {
      if (ts.isStringLiteral(attr.initializer)) return attr.initializer.text;
      if (ts.isJsxExpression(attr.initializer) && attr.initializer.expression) {
        return attr.initializer.expression.getText(sf);
      }
    }
  }
  return null;
}

/** The full `<tag label="label">...</tag>` JsxElement (not merely its opening
 *  tag, which `findOpeningElementsByTag` returns) - so a caller can search
 *  CALLS made inside its children, the way section 12 needs to. */
function findJsxElementByTagAndLabel(
  root: ts.Node,
  tag: string,
  label: string,
  sf: ts.SourceFile,
): ts.JsxElement | null {
  let result: ts.JsxElement | null = null;
  const visit = (n: ts.Node): void => {
    if (
      ts.isJsxElement(n) &&
      n.openingElement.tagName.getText(sf) === tag &&
      jsxAttrExprText(n.openingElement, "label", sf) === label
    ) {
      result = n;
    }
    ts.forEachChild(n, visit);
  };
  visit(root);
  return result;
}

/** Walking UP from `node`, the source text of the first ternary condition or
 *  `&&`/`||` left-hand side whose own text names `name` - or `null` if the
 *  walk runs out of parents first. "Is this JSX element wrapped in
 *  a conditional that mentions authMode" is a nesting question a string scan
 *  cannot answer - the field's own comment names `authMode` right beside it,
 *  to disclaim exactly this, which is why this cannot be a substring check. */
function findAncestorConditionOn(node: ts.Node, name: string, sf: ts.SourceFile): string | null {
  let n: ts.Node | undefined = node.parent;
  while (n) {
    if (ts.isConditionalExpression(n)) {
      const condText = n.condition.getText(sf);
      if (condText.includes(name)) return condText;
    }
    if (
      ts.isBinaryExpression(n) &&
      (n.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken ||
        n.operatorToken.kind === ts.SyntaxKind.BarBarToken)
    ) {
      const condText = n.left.getText(sf);
      if (condText.includes(name)) return condText;
    }
    n = n.parent;
  }
  return null;
}

/** Whether some ancestor of `node` is a `<tag>...</tag>` JsxElement - lets a
 *  Button standing inside a `<DialogClose>` satisfy section 13's sweep
 *  without an onClick of its own, the same way the rendered Cancel button
 *  does in both dialogs. */
function findAncestorJsxElementByTag(node: ts.Node, tag: string, sf: ts.SourceFile): boolean {
  let n: ts.Node | undefined = node.parent;
  while (n) {
    if (ts.isJsxElement(n) && n.openingElement.tagName.getText(sf) === tag) return true;
    n = n.parent;
  }
  return false;
}

/** TSX for the dialogs, TS for `store.ts`, and the difference is not cosmetic:
 *  parsed as TSX, `store.ts`'s own `const enqueueWrite = <T>(op: ...) => ...`
 *  reads as an unclosed JSX element and everything after it is recovered
 *  garbage - the compare statement section 16 looks for lands in no block at
 *  all. Chosen off the extension so a file added to `FILES` cannot get it
 *  wrong. */
const sourceFile = (key: keyof typeof FILES): ts.SourceFile =>
  ts.createSourceFile(
    FILES[key],
    src[key],
    ts.ScriptTarget.ESNext,
    true,
    FILES[key].endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS,
  );

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

  const checkKeyAnchor = "const checkKey = async (pem: string, passphrase: string) => {";
  const checkKeyRegion = between(ks, checkKeyAnchor, "const invalidateInspection = () => {");
  // Above the ANCHOR's own length (61) by a wide margin, not an
  // arbitrary round number below it - `between()` returns a slice that
  // STARTS WITH `from`, so a floor at or below 61 is satisfied by the anchor
  // text alone with an empty region behind it.
  // Measured: the real region is ~600+ characters.
  check(
    "checkKey's region was located",
    checkKeyRegion.length > checkKeyAnchor.length + 40,
    checkKeyRegion.length,
  );
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

  const invalidateAnchor = "const invalidateInspection = () => {";
  const invalidateRegion = between(ks, invalidateAnchor, "const pickKeyFile = async () => {");
  // Above the anchor's own length (36) by a wide margin - see
  // the checkKeyRegion floor just above for why a floor at or below it is
  // vacuous.
  check(
    "invalidateInspection's region was located",
    invalidateRegion.length > invalidateAnchor.length + 40,
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

  // The half the host-editor version shipped WITHOUT: this file's own
  // passphrase input closes it. If this fails alone (textarea above staying
  // green), the check is doing its per-input job; if both fail together, the
  // check cannot tell the two apart and is not doing its job at all.
  const passphraseAnchor = '<Field label="Key passphrase (optional)">';
  const passphraseRegion = between(ks, passphraseAnchor, "</Field>");
  // Above the anchor's own length (41) by a wide margin - same
  // reasoning as the two floors above.
  check(
    "the key-passphrase field's region was located",
    passphraseRegion.length > passphraseAnchor.length + 40,
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
//
// This section pins the BRANCH SHAPE around
// `encryptedKeyRefusal` - one call, the refusal branch returns - and is
// deliberately agnostic about where the value it sets ends up rendered. That
// is why renaming `setError` to `setKeyRefusal` needed no update here:
// correct for what this section claims, and exactly why placement has no
// cover of its own. What holds `keyRefusal` under the Private key `Field`
// today is `noUnusedLocals` alone - incidental, and it survives only while
// `keyRefusal` has exactly one reader; a second reader, or a render routed
// through a helper the unused-check cannot see through, and a regression that
// moves or drops the slot passes every gate in this suite.
//
// A placement pin was weighed and DECLINED here, not overlooked: the defect
// it would catch is cosmetic (the message rendering under the wrong field,
// not a credential loss), and an
// exact pin over parsed JSX is brittle by design - worth spending only where
// drift costs a secret. What it would have been, so it does not have to be
// re-derived: assert over the parsed JSX that the `keyRefusal` reader is a
// descendant of the key `Field` and not a sibling of the bottom `error` line.
console.log("\n[3. save inspects fields] KeyEditorDialog's save reads draft.privateKey itself");
{
  const saveRegion = between(src.keyDialog, "const save = async () => {", "const busy = saving");
  check("KeyEditorDialog's save region was located", saveRegion.length > 100, saveRegion.length);
  // Whitespace-normalised (a paired reformat control found this one
  // vulnerable too): a bare substring check breaks the moment Prettier wraps
  // this call's arguments across lines, which is a real Prettier output shape
  // once the line is long enough - not a hypothetical.
  check(
    "save calls inspectSshKey on the draft's own field",
    norm(saveRegion).includes(norm("inspectSshKey(draft.privateKey")),
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

  // Pin 2: the declaration and the SINGLE
  // assignment to `facts`, pinned exactly, over the COMPILER API's own view
  // of `save`'s body - `findConstArrowBody(keySf, "save")` is already used by
  // section 4. A name scoped check (the `!/inspected/i` negative above) does
  // not survive an alias: `const panel = inspected;` above `save`, with
  // `facts` assigned from `panel` instead of a fresh `inspectSshKey` call,
  // passes every check above while reintroducing exactly the "inherit that
  // question one level deeper" failure this file's own header on `save`
  // forbids. Only pinning what is actually assigned to `facts` closes that.
  //
  // An encrypted-with-no-passphrase refusal was inserted
  // between the inspection and the assignment, so the inspection now lives in
  // its own `info` binding that both the refusal and `vaultKeyFactsFrom`
  // read - this pin follows it there instead of naming the old inline call.
  const keySfForFacts = sourceFile("keyDialog");
  const saveBodyForFacts = findConstArrowBody(keySfForFacts, "save");
  check("KeyEditorDialog's save body is located (compiler API, pin 2)", saveBodyForFacts !== null);
  if (saveBodyForFacts) {
    const factsDecl = findVariableDeclaration(saveBodyForFacts, "facts");
    check("save declares `facts` (compiler API)", factsDecl !== null);
    if (factsDecl) {
      const declStatement = factsDecl.parent.parent;
      const declText = ts.isVariableStatement(declStatement)
        ? declStatement.getText(keySfForFacts)
        : "";
      check(
        "the `facts` declaration is exactly `let facts: VaultKeyFacts | null = null;` - an" +
          " `= lastInfo.current` initializer is the alias mutation, and this pin is what catches it",
        norm(declText) === norm("let facts: VaultKeyFacts | null = null;"),
        declText,
      );
    }

    // Exactly one, not merely "at least one": a second assignment in a later
    // arm of `save` is how a fallback hides behind this pin's positive.
    const factsAssignments = findAssignmentsTo(saveBodyForFacts, "facts");
    check(
      "save contains exactly one assignment to `facts`",
      factsAssignments.length === 1,
      factsAssignments.length,
    );
    if (factsAssignments.length === 1) {
      // Decomposed into callee + its own single argument, rather than one
      // getText() over the whole right-hand side: `vaultKeyFactsFrom(...)` is
      // committed as a MULTI-LINE call (its one argument on its own line),
      // and Prettier's trailing comma on that line sits INSIDE this node's
      // own span - unlike pin 1's arguments, which sit inside a call ONE
      // LEVEL UP from any trailing comma of their own. A whole-text compare
      // here would falsely FAIL against the correct, committed code the
      // moment Prettier's trailing comma is counted as part of "the claim"
      // rather than as formatting pin 1's rule 2 already says to discount.
      const rhs = factsAssignments[0].right;
      const rhsIsVaultKeyFactsFromCall =
        ts.isCallExpression(rhs) && rhs.expression.getText(keySfForFacts) === "vaultKeyFactsFrom";
      check(
        "the single assignment to `facts` calls vaultKeyFactsFrom(",
        rhsIsVaultKeyFactsFromCall,
        rhs.getText(keySfForFacts),
      );
      if (rhsIsVaultKeyFactsFromCall && ts.isCallExpression(rhs)) {
        check(
          "vaultKeyFactsFrom( is called with exactly 1 argument",
          rhs.arguments.length === 1,
          rhs.arguments.length,
        );
        if (rhs.arguments.length === 1) {
          const argText = rhs.arguments[0].getText(keySfForFacts);
          // Re-aimed: `save` now inspects the
          // key ONCE into a local `info` and reuses it for both the refusal
          // below and this call, rather than inspecting twice - so the
          // argument here is the bare identifier `info`, not the inline
          // `inspectSshKey(...)` call this pin used to name directly. The
          // claim that `facts` comes from a FRESH inspection has not
          // weakened: it has moved one line up, onto `info`'s own
          // initializer, which the next two checks pin instead.
          check(
            "vaultKeyFactsFrom's argument is exactly info - the fresh inspection bound above, not" +
              " a cached one (e.g. `lastInfo.current`) that would reintroduce the alias mutation" +
              " this pin exists to catch",
            norm(argText) === norm("info"),
            argText,
          );
        }
      }
    }

    // `save` inspects the key into `info` before
    // deciding whether to refuse it, and `vaultKeyFactsFrom` above is pinned
    // to consume exactly that binding. These two checks are what actually
    // carries the "fresh inspection" claim now that the argument pin above
    // names `info` rather than the call itself.
    const infoDecl = findVariableDeclaration(saveBodyForFacts, "info");
    check("save declares `info`", infoDecl !== null);
    if (infoDecl) {
      const init = infoDecl.initializer;
      // Decomposed into the awaited call's callee + each argument, rather
      // than one getText() over the whole initializer (the same trap pin 1's
      // own comment names, one level further in): `inspectSshKey`'s own
      // arguments are long enough that a real `pnpm format` CAN wrap them
      // across lines, and Prettier's trailing comma on the last argument
      // then sits INSIDE this initializer's own span (the call IS the
      // initializer here, unlike pin 1's arguments, which sit one level
      // below any trailing comma of their own). A whole-text compare would
      // falsely FAIL against the correct, committed code the moment that
      // reflow happens - caught by this section's own paired reformat
      // control, which is what moved this pin here.
      const awaited = init && ts.isAwaitExpression(init) ? init.expression : init;
      const isInspectCall =
        awaited !== undefined &&
        ts.isCallExpression(awaited) &&
        awaited.expression.getText(keySfForFacts) === "inspectSshKey";
      check(
        "info's initializer is an `await inspectSshKey(...)` call",
        isInspectCall,
        init ? init.getText(keySfForFacts) : undefined,
      );
      if (isInspectCall && awaited && ts.isCallExpression(awaited)) {
        check(
          "inspectSshKey( is called with exactly 2 arguments",
          awaited.arguments.length === 2,
          awaited.arguments.length,
        );
        if (awaited.arguments.length === 2) {
          const arg0 = awaited.arguments[0].getText(keySfForFacts);
          const arg1 = awaited.arguments[1].getText(keySfForFacts);
          check(
            "inspectSshKey's argument 0 is exactly draft.privateKey",
            norm(arg0) === norm("draft.privateKey"),
            arg0,
          );
          check(
            "inspectSshKey's argument 1 is exactly draft.passphrase || undefined",
            norm(arg1) === norm("draft.passphrase || undefined"),
            arg1,
          );
        }
      }
    }

    // The encrypted-with-no-passphrase refusal. Pinned by
    // argument VALUE (so `encryptedKeyRefusal(info.encrypted, draft.privateKey)`
    // - the wrong field, and a real defect a save could ship with no type
    // error - is caught) and by NESTING (so a refusal computed but never
    // actually returned on - "a refusal that sets the error and then saves
    // anyway is one line away", per this section's own brief - is caught
    // too, the same class section 4's lexical-containment check exists for).
    const refusalCalls = findCalls(saveBodyForFacts, keySfForFacts, ["encryptedKeyRefusal"]);
    check(
      "save contains exactly one call to encryptedKeyRefusal",
      refusalCalls.length === 1,
      refusalCalls.length,
    );
    if (refusalCalls.length === 1) {
      const refusalCall = refusalCalls[0];
      check(
        "encryptedKeyRefusal( is called with exactly 2 arguments",
        refusalCall.arguments.length === 2,
        refusalCall.arguments.length,
      );
      if (refusalCall.arguments.length === 2) {
        const arg0 = refusalCall.arguments[0].getText(keySfForFacts);
        const arg1 = refusalCall.arguments[1].getText(keySfForFacts);
        check(
          "encryptedKeyRefusal's argument 0 is exactly info.encrypted",
          norm(arg0) === norm("info.encrypted"),
          arg0,
        );
        check(
          "encryptedKeyRefusal's argument 1 is exactly draft.passphrase",
          norm(arg1) === norm("draft.passphrase"),
          arg1,
        );
      }

      // The call's own enclosing `const refusal = ...` declaration, so the
      // `if` that tests it can be found by NAME rather than by guessing it is
      // the next sibling statement - a distance heuristic is exactly what
      // section 4's own header warns reads a correctly nested call as
      // un-nested.
      const refusalDeclParent = refusalCall.parent;
      const refusalVarName =
        ts.isVariableDeclaration(refusalDeclParent) && ts.isIdentifier(refusalDeclParent.name)
          ? refusalDeclParent.name.text
          : null;
      check(
        "encryptedKeyRefusal's result is bound to a variable the save body can branch on",
        refusalVarName !== null,
        refusalVarName ?? undefined,
      );
      if (refusalVarName) {
        let refusalIf: ts.IfStatement | null = null;
        const visitIf = (n: ts.Node): void => {
          if (
            ts.isIfStatement(n) &&
            n.expression.getText(keySfForFacts).trim() === refusalVarName
          ) {
            refusalIf = n;
          }
          ts.forEachChild(n, visitIf);
        };
        visitIf(saveBodyForFacts);
        check(
          `an if statement tests ${refusalVarName} directly (bare, not wrapped)`,
          refusalIf !== null,
        );
        if (refusalIf) {
          const thenText = (refusalIf as ts.IfStatement).thenStatement.getText(keySfForFacts);
          check(
            `the branch that tests ${refusalVarName} contains a return - a refusal that sets the` +
              " error and saves anyway is one line away",
            /\breturn\b/.test(thenText),
            thenText,
          );
        }
      }
    }
  }
}

// ============================================================================
// 4. Store writes live only in `save`. (COMPILER API)
// ============================================================================
// Protects: the question every dialog owes - does anything here
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
// Protects: agreement BY VALUE cannot forbid a second, silently
// divergent implementation. Structural: `save` must call the shared builders,
// and the file must not carry the object-literal keys that are the tell of a
// record assembled by hand instead.
//
// Pin 1: `includes("keyRecordFrom(")` is satisfied by
// `{ ...keyRecordFrom(id, draft, existing, facts), ...existing }` - the
// decisive mutation this section exists to close, which spreads the shared
// builder's own output and then overwrites its `hasPassword`/`hasPrivateKey`
// fields (or, on the identity twin, its stored password) with the STALE
// object's. A substring check cannot tell "calls the builder" from "calls the
// builder and then undoes it", so each `upsert*` call's own argument
// expressions are pinned EXACTLY below instead - whitespace-normalised only,
// because Prettier alone decides whether the committed call spans one line or
// four (`KeyEditorDialog.tsx`'s does; `IdentityEditorDialog.tsx`'s doesn't).
console.log(
  "\n[5. shared pure functions] save calls the draft.ts builders, and assembles nothing itself",
);
{
  // A THIRD argument was added - the stamp of the record the form loaded -
  // so the arity, the `continue` guarding the argument loop, the tuple type and
  // the expected list all moved from 2 to 3 together. They have to: leaving the
  // arity at 2 makes the `continue` below skip EVERY argument pin for that call,
  // so the section reports one FAIL where it should report three and the two
  // surviving pins silently do not run at all - a check that cannot fail, one
  // level in.
  const pinUpsertArgs = (
    fileKey: keyof typeof FILES,
    calleeName: string,
    expectedArgs: readonly [string, string, string],
  ): void => {
    const sf = sourceFile(fileKey);
    const calls = findCalls(sf, sf, [calleeName]);
    // Found independently of section 4's own `found at least one` - a check
    // is not allowed to rely on a precondition asserted in an earlier
    // section: a renamed callee would otherwise leave THIS section's loop
    // below silently iterating zero times, which is a check that cannot fail.
    check(
      `${FILES[fileKey]}: found at least one ${calleeName}( call to pin (section 5)`,
      calls.length > 0,
      calls.length,
    );
    for (const c of calls) {
      check(
        `${FILES[fileKey]}: ${calleeName}( is called with exactly 3 arguments`,
        c.arguments.length === 3,
        c.arguments.length,
      );
      if (c.arguments.length !== 3) continue;
      for (const [i, expected] of expectedArgs.entries()) {
        const actual = c.arguments[i].getText(sf);
        check(
          `${FILES[fileKey]}: ${calleeName}('s argument ${i} is exactly ${expected}`,
          norm(actual) === norm(expected),
          actual,
        );
      }
    }
  };

  // Argument 2 is pinned to `existing` specifically, not merely to "a call to
  // the stamp function": `vaultKeyStamp(keyRecordFrom(id, draft, existing,
  // facts))` type-checks, reads as a stamp, and stamps the record ABOUT TO BE
  // WRITTEN rather than the one this form loaded - which makes the compare
  // compare a value against itself and pass always. So the argument's whole
  // expression text is the claim, the same way arguments 0 and 1 are.
  pinUpsertArgs("keyDialog", "upsertKey", [
    "keyRecordFrom(id, draft, existing, facts)",
    "keySecretsForSave(draft)",
    "vaultKeyStamp(existing)",
  ]);
  pinUpsertArgs("identityDialog", "upsertIdentity", [
    "identityRecordFrom(id, draft)",
    "identitySecretsForSave(draft)",
    "vaultIdentityStamp(existing)",
  ]);

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
// Protects: the invariant, said as a check. The vault exposes no
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
// Protects: `Combobox` carries the stopPropagation fix for the modal
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

  // Comment-stripped before the positive below - a raw
  // `.includes(...)` is satisfied by moving the real read into a comment and
  // deleting it. Sanity-checked first: an empty string would pass the
  // next check for free (the model is this same file's section 10).
  const strippedIdnForRow = stripComments(idn);
  check(
    "IdentityEditorDialog.tsx: stripping comments left real code behind (section 7)",
    strippedIdnForRow.length > 3000,
    strippedIdnForRow.length,
  );
  check(
    "reads chosenKey?.missingPrivateKey off the shared row",
    strippedIdnForRow.includes("chosenKey?.missingPrivateKey"),
  );
}

// ============================================================================
// 8. The help copy is the shared copy.
// ============================================================================
// Protects: inlining a help sentence is a second place the wording lives,
// which is how it goes stale silently. The
// negative is asserted against the FUNCTIONS' actual return values, imported
// and sliced at runtime - a hard-coded sentence here would be a THIRD place
// the copy lives.
console.log(
  "\n[8. shared help copy] both dialogs call the draft.ts help functions, and never inline them",
);
{
  // Comment-stripped before the three positives below, for the
  // same reason section 7 just applied it to `chosenKey?.missingPrivateKey` -
  // moving a call into a comment and deleting the real one would otherwise
  // pass a raw `.includes(...)`. Sanity-checked first, same floor as
  // section 10 (which already proves both files' stripped length clears it).
  const strippedKeyForHelp = stripComments(src.keyDialog);
  const strippedIdentityForHelp = stripComments(src.identityDialog);
  check(
    "KeyEditorDialog.tsx: stripping comments left real code behind (section 8)",
    strippedKeyForHelp.length > 3000,
    strippedKeyForHelp.length,
  );
  check(
    "IdentityEditorDialog.tsx: stripping comments left real code behind (section 8)",
    strippedIdentityForHelp.length > 3000,
    strippedIdentityForHelp.length,
  );
  check(
    "KeyEditorDialog.tsx calls privateKeyHelp(",
    strippedKeyForHelp.includes("privateKeyHelp("),
  );
  check(
    "KeyEditorDialog.tsx calls passphraseHelp(",
    strippedKeyForHelp.includes("passphraseHelp("),
  );
  check(
    "IdentityEditorDialog.tsx calls identityPasswordHelp(",
    strippedIdentityForHelp.includes("identityPasswordHelp("),
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

  // Every self-test above only proves a comment is REMOVED. The
  // direction that actually shipped broken (see this file's own header on
  // `stripComments`) is the other one - the lazy JSX-comment regex let its
  // match cross an intervening `*/` and kept eating source looking for a
  // luckier one, and both `> 3000` floors below still cleared on the remainder
  // while every positive happened to anchor outside the swallowed span.
  // Measured on `KeyEditorDialog.tsx` with that lazy form, it swallowed 10954
  // of 22505 characters and this script still passed 151/151.
  const STRIPPER_PROBE =
    "type P = { /** c */ x: X };\nconst KEEP = 1;\nconst j = <div>{/* c */}</div>;";
  check(
    "stripComments does not over-strip: a doc comment opening inside a type literal does not eat" +
      " past it to the next unrelated */} it can find",
    stripComments(STRIPPER_PROBE).includes("KEEP"),
  );
  check(
    // The needle is worded so it cannot be satisfied by the `/** c */` on line
    // 1 - only the JSX comment expression's own braces spell "{/*".
    "stripComments does not under-strip: the JSX comment expression {/* c */} is gone",
    !stripComments(STRIPPER_PROBE).includes("{/*"),
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
    // of a store-name literal is how it came to be wrong on two
    // platforms. `mode-0600` is deliberately NOT a needle here: both headers use
    // it honestly, to DISCLAIM a safety claim, and forbidding it would redden
    // the sentence that disclaims the very overclaim this section exists to
    // catch.
    check(
      `${FILES[key]}: does not re-inline a store name literal instead of using SECRET_STORE_LOCATIONS`,
      !/Keychain|DPAPI|Credential Manager/.test(stripped),
    );
  }
}

// ============================================================================
// 11. The identity password field renders in every auth mode. (COMPILER API
//     for the nesting question a string scan cannot answer.)
// ============================================================================
// Protects: the comment `IdentityEditorDialog.tsx` carries above its
// `<Field label="Password">` on why
// this field must NOT be hidden under key/agent auth - `VaultIdentity.hasPassword`
// is independent of `authMode` by design and `resolveRdpAuth` never consults
// the mode - and nothing but that comment currently enforces it.
console.log("\n[11] the identity Password field is never wrapped in an authMode conditional");
{
  const sf = sourceFile("identityDialog");
  const passwordFields = findOpeningElementsByTag(sf, "Field", sf).filter(
    (el) => jsxAttrExprText(el, "label", sf) === "Password",
  );
  check(
    'found exactly one <Field label="Password"> in IdentityEditorDialog.tsx',
    passwordFields.length === 1,
    passwordFields.length,
  );
  if (passwordFields.length === 1) {
    const cond = findAncestorConditionOn(passwordFields[0], "authMode", sf);
    check(
      "the Password field has no ancestor conditional (ternary or &&/||) whose condition names authMode",
      cond === null,
      cond ?? undefined,
    );
  }
}

// ============================================================================
// 12. keyId is normalised only at the record, never at either toggle handler.
//     (COMPILER API.)
// ============================================================================
// Protects: the claim `editor/draft.ts` makes on `IdentityKeyIdRule`, that a
// second assembly elsewhere "is exactly the drift it exists to prevent" -
// `identityRecordFrom` is the ONE
// place `keyId` is dropped for a non-key auth mode, so every `patch({...})`
// inside the Authentication field must touch `authMode` alone.
console.log("\n[12] no auth-mode toggle handler patches keyId - only identityRecordFrom does");
{
  const sf = sourceFile("identityDialog");
  const authField = findJsxElementByTagAndLabel(sf, "Field", "Authentication", sf);
  check('found the <Field label="Authentication"> element to search inside', authField !== null);
  if (authField) {
    const patchCalls = findCalls(authField, sf, ["patch"]);
    check(
      "found at least one patch( call inside the Authentication field (one per toggle button)",
      patchCalls.length > 0,
      patchCalls.length,
    );
    for (const c of patchCalls) {
      const callText = c.getText(sf);
      check(
        `${callText}: called with exactly 1 argument`,
        c.arguments.length === 1,
        c.arguments.length,
      );
      if (c.arguments.length !== 1) continue;
      const arg = c.arguments[0];
      const isObjectLiteral = ts.isObjectLiteralExpression(arg);
      check(`${callText}: argument is an object literal`, isObjectLiteral);
      if (isObjectLiteral && ts.isObjectLiteralExpression(arg)) {
        const keys = arg.properties
          .map((p) => (p.name && ts.isIdentifier(p.name) ? p.name.text : null))
          .filter((k): k is string => k !== null);
        check(
          `${callText}: patches exactly ["authMode"] - not keyId alongside it`,
          keys.length === 1 && keys[0] === "authMode",
          keys,
        );
      }
    }
  }
}

// ============================================================================
// 13. A dead-affordance sweep over both dialogs. (COMPILER API.)
// ============================================================================
// Protects: `vault-shell-verify.ts` section 14 covers VaultPage/IdentityCard/
// KeyCard only; the two editor dialogs are the app's largest new interactive
// surface and had no such check before this. Every <Button> either wires an
// onClick or is a Cancel standing inside <DialogClose> (which wires the close
// itself); and neither file offers a SECOND, nested "New key"/"New identity"
// creator - reachable from nowhere and dead by construction if it existed.
console.log("\n[13] every <Button> in either dialog does something; no nested New key/identity");
{
  for (const key of ["keyDialog", "identityDialog"] as const) {
    const sf = sourceFile(key);
    const buttons = findOpeningElementsByTag(sf, "Button", sf);
    check(`${FILES[key]}: found at least one <Button>`, buttons.length > 0, buttons.length);
    for (const el of buttons) {
      const onClick = jsxAttrExprText(el, "onClick", sf);
      const owner: ts.Node = ts.isJsxOpeningElement(el) ? el.parent : el;
      const insideDialogClose = findAncestorJsxElementByTag(owner, "DialogClose", sf);
      const tagDesc = el.getText(sf).replace(/\s+/g, " ").slice(0, 60);
      check(
        `<${tagDesc}> has an onClick, or stands inside <DialogClose>`,
        onClick !== null || insideDialogClose,
        { onClick, insideDialogClose },
      );

      // The button's own direct text children only - not the whole file - so
      // this cannot be tripped by unrelated prose elsewhere that happens to
      // contain the same two words: IdentityEditorDialog.tsx's own "no keys
      // saved yet" help line literally says "use New key first".
      if (ts.isJsxOpeningElement(el) && ts.isJsxElement(owner)) {
        const label = owner.children
          .filter(ts.isJsxText)
          .map((t) => t.getText(sf))
          .join("")
          .trim();
        check(
          `<${tagDesc}>'s own label text is not a second, nested "New key…"/"New identity…" creator: ${JSON.stringify(label)}`,
          !label.startsWith("New key") && !label.startsWith("New identity"),
          label,
        );
      }
    }
  }
}

// ============================================================================
// 14. The stamps are pure, and NARROW. (The functions themselves.)
// ============================================================================
// Protects: the whole design turns on what is OUTSIDE the stamp. A stamp
// widened to the record's other fields still passes every "it changed when the
// secret changed" check while refusing ordinary concurrent RENAMES - which is
// last-write-wins working correctly, not a conflict - so the invariance checks
// below are the load-bearing half of this section, not the padding.
console.log("\n[14. stamps] secret material moves the stamp; a rename does not");
{
  const aKey = (over: Partial<VaultKey> = {}): VaultKey => ({
    id: "k-1",
    name: "id_ed25519",
    keyType: "ed25519",
    fingerprint: "SHA256:aaa",
    publicKey: "ssh-ed25519 AAAA",
    hasPrivateKey: true,
    hasPassphrase: false,
    description: "",
    ...over,
  });
  const anIdentity = (over: Partial<VaultIdentity> = {}): VaultIdentity => ({
    id: "i-1",
    name: "root @ prod",
    username: "root",
    authMode: "password",
    hasPassword: true,
    description: "",
    ...over,
  });

  check(`VAULT_STAMP_ABSENT is exactly "absent"`, VAULT_STAMP_ABSENT === "absent");
  check("vaultKeyStamp(null) is absent", vaultKeyStamp(null) === VAULT_STAMP_ABSENT);
  check("vaultKeyStamp(undefined) is absent", vaultKeyStamp(undefined) === VAULT_STAMP_ABSENT);
  check("vaultIdentityStamp(null) is absent", vaultIdentityStamp(null) === VAULT_STAMP_ABSENT);
  check(
    "vaultIdentityStamp(undefined) is absent",
    vaultIdentityStamp(undefined) === VAULT_STAMP_ABSENT,
  );

  // Two DISTINCT objects with the same fields, not the same object twice: a
  // stamp that closed over anything per-instance would pass the latter.
  check(
    "the same key twice, as two separate objects, stamps the same",
    vaultKeyStamp(aKey()) === vaultKeyStamp(aKey()),
    vaultKeyStamp(aKey()),
  );
  check(
    "the same identity twice, as two separate objects, stamps the same",
    vaultIdentityStamp(anIdentity()) === vaultIdentityStamp(anIdentity()),
    vaultIdentityStamp(anIdentity()),
  );
  // A present record's stamp is never the absent one, and the two kinds never
  // collide: one prefix each, so an identity stamp handed to `upsertKey` is a
  // mismatch rather than an accidental match.
  check("a present key does not stamp as absent", vaultKeyStamp(aKey()) !== VAULT_STAMP_ABSENT);
  check(
    "a present identity does not stamp as absent",
    vaultIdentityStamp(anIdentity()) !== VAULT_STAMP_ABSENT,
  );
  check(
    "a key stamp and an identity stamp are never the same string",
    vaultKeyStamp(aKey()) !== vaultIdentityStamp(anIdentity()),
  );

  const keyMoves: { label: string; over: Partial<VaultKey> }[] = [
    { label: "hasPrivateKey flips", over: { hasPrivateKey: false } },
    { label: "hasPassphrase flips", over: { hasPassphrase: true } },
    { label: "the fingerprint changes", over: { fingerprint: "SHA256:bbb" } },
    { label: "the fingerprint is dropped", over: { fingerprint: undefined } },
  ];
  for (const { label, over } of keyMoves) {
    check(
      `vaultKeyStamp changes when ${label}`,
      vaultKeyStamp(aKey(over)) !== vaultKeyStamp(aKey()),
      { moved: vaultKeyStamp(aKey(over)), base: vaultKeyStamp(aKey()) },
    );
  }
  // The narrowness, said positively - and the check the "widen it to include
  // `name`" mutation exists to redden.
  const keyStays: { label: string; over: Partial<VaultKey> }[] = [
    { label: "renamed", over: { name: "id_ed25519 (work laptop)" } },
    { label: "re-described", over: { description: "opens the bastion" } },
    { label: "given a keyType it lacked", over: { keyType: "rsa" } },
    { label: "given a different public half", over: { publicKey: "ssh-ed25519 BBBB" } },
  ];
  for (const { label, over } of keyStays) {
    check(
      `vaultKeyStamp does NOT change when the key is ${label} - a rename is last-write-wins' job`,
      vaultKeyStamp(aKey(over)) === vaultKeyStamp(aKey()),
      { moved: vaultKeyStamp(aKey(over)), base: vaultKeyStamp(aKey()) },
    );
  }

  const identityMoves: { label: string; over: Partial<VaultIdentity> }[] = [
    { label: "hasPassword flips", over: { hasPassword: false } },
    { label: "the auth mode changes", over: { authMode: "agent" } },
    { label: "a keyId appears", over: { authMode: "key", keyId: "k-1" } },
  ];
  for (const { label, over } of identityMoves) {
    check(
      `vaultIdentityStamp changes when ${label}`,
      vaultIdentityStamp(anIdentity(over)) !== vaultIdentityStamp(anIdentity()),
      { moved: vaultIdentityStamp(anIdentity(over)), base: vaultIdentityStamp(anIdentity()) },
    );
  }
  // Re-pointing a key is a move even though the mode is unchanged - the
  // material this identity signs with is a different key afterwards.
  check(
    "vaultIdentityStamp changes when the keyId is re-pointed at another key",
    vaultIdentityStamp(anIdentity({ authMode: "key", keyId: "k-2" })) !==
      vaultIdentityStamp(anIdentity({ authMode: "key", keyId: "k-1" })),
  );
  const identityStays: { label: string; over: Partial<VaultIdentity> }[] = [
    { label: "renamed", over: { name: "root @ production" } },
    { label: "given a different username", over: { username: "admin" } },
    { label: "given a domain", over: { domain: "CORP" } },
    { label: "re-described", over: { description: "the prod bastion account" } },
  ];
  for (const { label, over } of identityStays) {
    check(
      `vaultIdentityStamp does NOT change when the identity is ${label}`,
      vaultIdentityStamp(anIdentity(over)) === vaultIdentityStamp(anIdentity()),
      { moved: vaultIdentityStamp(anIdentity(over)), base: vaultIdentityStamp(anIdentity()) },
    );
  }
}

// ============================================================================
// 15. The store actually refuses, and refuses BEFORE it writes a secret.
//     (Behaviour - a real `createVaultStore` on in-memory ports.)
// ============================================================================
// Protects: the seam between the two files. Everything above this line is
// source text over the CONSUMER, and stays green while the producer is
// disabled three separate ways - the compare deleted, `actual` set to
// `expected`, an empty id passed to the error - none of which changes a
// character in either dialog. So the refusal is caught here and read by
// INSTANCE and by FIELD VALUE, never by message text, which all three of those
// mutations leave identical.
console.log("\n[15. refusal] the store refuses a moved record, touching no keychain account");
{
  type SecretCall = { op: "getAll" | "set" | "delete" | "copy"; account: string };

  const vaultHarness = () => {
    const data: Record<string, unknown> = { identities: [], keys: [] };
    const kept = new Map<string, string>();
    const calls: SecretCall[] = [];

    const store: VaultStoreIo = {
      async get<T>(key: string): Promise<T | null> {
        return (data[key] as T | undefined) ?? null;
      },
      async set(key: string, value: unknown): Promise<void> {
        data[key] = value;
      },
      async commit(): Promise<void> {},
      // The REAL queue, so "inside the write queue" is exercised against the
      // shipped one rather than a copy living in this file.
      enqueueWrite: createWriteQueue(),
      async onChanged(): Promise<() => void> {
        return () => {};
      },
      ensureLoaded: async () => null,
      takeRecoveryNotice: () => null,
    };

    // Every call is logged, because "the refusal wrote no secret" is the only
    // way the BEFORE half of the compare's placement can be observed from
    // outside: a compare moved after `writeKeySecrets` still throws, still
    // throws the right class, and still carries the right fields.
    const secrets: SecretsIo = {
      async getAll(service, accounts) {
        for (const account of accounts) calls.push({ op: "getAll", account });
        return accounts.map((a) => kept.get(`${service}::${a}`) ?? null);
      },
      async set(service, account, value) {
        calls.push({ op: "set", account });
        kept.set(`${service}::${account}`, value);
      },
      async delete(service, account) {
        calls.push({ op: "delete", account });
        kept.delete(`${service}::${account}`);
      },
      async copy(from, to) {
        calls.push({ op: "copy", account: to.account });
        const value = kept.get(`${from.service}::${from.account}`);
        if (value === undefined) return false;
        kept.set(`${to.service}::${to.account}`, value);
        return true;
      },
    };

    return { vault: createVaultStore({ store, secrets }), kept, calls };
  };

  const at = (id: string, field: string) => `${VAULT_KEYRING_SERVICE}::${vaultAccount(id, field)}`;
  const aKey = (over: Partial<VaultKey> = {}): VaultKey => ({
    id: "k-1",
    name: "id_ed25519",
    fingerprint: "SHA256:aaa",
    hasPrivateKey: false,
    hasPassphrase: false,
    ...over,
  });
  const anIdentity = (over: Partial<VaultIdentity> = {}): VaultIdentity => ({
    id: "i-1",
    name: "root @ prod",
    username: "root",
    authMode: "password",
    hasPassword: false,
    ...over,
  });
  /** What `fn` threw, or `null` if it resolved - so "did not reject at all" is
   *  a distinguishable outcome rather than a silently absent check. */
  const thrownBy = async (fn: () => Promise<unknown>): Promise<unknown> => {
    try {
      await fn();
      return null;
    } catch (e) {
      return e;
    }
  };

  // -- a key whose secret material moved under the caller ------------------
  {
    const h = vaultHarness();
    const loaded = (await h.vault.upsertKey(aKey(), { privateKey: "PEM-ONE" })).record;
    const stamp = vaultKeyStamp(loaded);
    // Another writer adds a passphrase. No expectation passed, which is what an
    // import is.
    await h.vault.upsertKey(aKey(), { passphrase: "s3cret" });
    h.calls.length = 0;

    const thrown = await thrownBy(() =>
      h.vault.upsertKey(aKey({ name: "renamed" }), { privateKey: "PEM-TWO" }, stamp),
    );
    check(
      "a save against moved secret material is refused, by INSTANCE not by message",
      thrown instanceof VaultRecordChangedError,
      thrown instanceof Error ? thrown.message : thrown,
    );
    const stored = await h.vault.findKey("k-1");
    if (thrown instanceof VaultRecordChangedError) {
      check("it carries the id of the record it was refused against", thrown.recordId === "k-1", {
        got: thrown.recordId,
      });
      check("it carries what the caller expected", thrown.expected === stamp, {
        got: thrown.expected,
        want: stamp,
      });
      check(
        "it carries what is actually stored now - which is NOT what was expected",
        thrown.actual === vaultKeyStamp(stored) && thrown.actual !== thrown.expected,
        { actual: thrown.actual, expected: thrown.expected, stored: vaultKeyStamp(stored) },
      );
    }
    // The BEFORE half of the placement, observed from outside: this save
    // carries a private key, so a compare moved after `writeKeySecrets` has
    // already put `PEM-TWO` at the account before refusing.
    check(
      "the refusal touched no keychain account at all",
      h.calls.length === 0,
      h.calls.map((c) => `${c.op} ${c.account}`),
    );
    check(
      "and the private key stored before it is untouched",
      h.kept.get(at("k-1", "privateKey")) === "PEM-ONE",
      h.kept.get(at("k-1", "privateKey")),
    );
    check("the name the stale save proposed did not land", stored?.name === "id_ed25519", {
      got: stored?.name,
    });
  }

  // -- the demonstrated failure: resurrection of a deleted key --------------
  {
    const h = vaultHarness();
    const loaded = (await h.vault.upsertKey(aKey(), { privateKey: "PEM-ONE" })).record;
    const stamp = vaultKeyStamp(loaded);
    await h.vault.deleteKey("k-1");
    h.calls.length = 0;

    // A BLANK-BODY save - `{}` means "leave the stored secret alone" - which is
    // exactly the shape that used to bring the row back as
    // `hasPrivateKey: false, hasPassphrase: false` while still carrying the
    // deleted key's fingerprint and public half.
    const thrown = await thrownBy(() => h.vault.upsertKey(aKey(), {}, stamp));
    check(
      "a blank-body save against a DELETED key is refused",
      thrown instanceof VaultRecordChangedError,
      thrown instanceof Error ? thrown.message : thrown,
    );
    if (thrown instanceof VaultRecordChangedError) {
      check(
        "and it reports the record as absent, not merely as different",
        thrown.actual === VAULT_STAMP_ABSENT,
        thrown.actual,
      );
    }
    check("nothing was put back", (await h.vault.listKeys()).length === 0);
    check("and `findKey` still finds nothing", (await h.vault.findKey("k-1")) === undefined);
  }

  // -- create mode: `absent` is enforced, not read as "no expectation" ------
  {
    // The editors never special-case create mode: `existing` is null there, so
    // the stamp they pass is `VAULT_STAMP_ABSENT` on every create. A guard
    // rewritten to skip the compare whenever `expect === "absent"` - on the
    // theory that absent means "no expectation" - leaves every other group in
    // this section green. This is the group that closes it.
    const h = vaultHarness();
    await h.vault.upsertKey(aKey({ name: "someone else's key" }), { privateKey: "THEIRS" });
    h.calls.length = 0;

    const thrown = await thrownBy(() =>
      h.vault.upsertKey(aKey({ name: "my new key" }), { privateKey: "MINE" }, VAULT_STAMP_ABSENT),
    );
    check(
      "a create against an id someone else already claimed is refused",
      thrown instanceof VaultRecordChangedError,
      thrown instanceof Error ? thrown.message : thrown,
    );
    const stored = await h.vault.findKey("k-1");
    check(
      "the id's actual owner survived the refused create",
      stored?.name === "someone else's key",
      {
        got: stored?.name,
      },
    );
    check(
      "and their private key was not overwritten - the refusal wrote nothing",
      h.kept.get(at("k-1", "privateKey")) === "THEIRS" && h.calls.length === 0,
      { stored: h.kept.get(at("k-1", "privateKey")), calls: h.calls.length },
    );
  }

  // -- the control: an unchanged record still saves ------------------------
  {
    // Without this, a compare that simply always threw would pass every group
    // above.
    const h = vaultHarness();
    const loaded = (await h.vault.upsertKey(aKey(), { privateKey: "PEM-ONE" })).record;
    const saved = (await h.vault.upsertKey(aKey({ name: "renamed" }), {}, vaultKeyStamp(loaded)))
      .record;
    check("an unchanged record saves normally", saved.name === "renamed", saved.name);
    check(
      "and the untouched private key is still there",
      h.kept.get(at("k-1", "privateKey")) === "PEM-ONE",
    );
  }

  // -- the other control: no expectation means no check --------------------
  {
    // The four v3-import call sites pass two arguments deliberately: an import
    // holds no earlier snapshot, so a required third parameter would only make
    // it invent one. This is the positive evidence for the parameter being
    // optional, and it is why those call sites need no edit.
    const h = vaultHarness();
    await h.vault.upsertKey(aKey(), { privateKey: "PEM-ONE" });
    await h.vault.upsertKey(aKey({ fingerprint: "SHA256:bbb" }), { privateKey: "PEM-TWO" });
    const forced = (await h.vault.upsertKey(aKey({ name: "by import" }), {})).record;
    check("an import with no expectation still writes", forced.name === "by import", forced.name);
  }

  // -- the identity twin ---------------------------------------------------
  {
    const h = vaultHarness();
    const loaded = (await h.vault.upsertIdentity(anIdentity(), { password: "pw-one" })).record;
    const stamp = vaultIdentityStamp(loaded);
    await h.vault.upsertIdentity(anIdentity({ authMode: "agent" }), {});
    h.calls.length = 0;

    const thrown = await thrownBy(() =>
      h.vault.upsertIdentity(anIdentity({ name: "renamed" }), { password: "pw-two" }, stamp),
    );
    check(
      "an identity whose auth moved under the caller is refused, by INSTANCE",
      thrown instanceof VaultRecordChangedError,
      thrown instanceof Error ? thrown.message : thrown,
    );
    const stored = await h.vault.findIdentity("i-1");
    if (thrown instanceof VaultRecordChangedError) {
      check("it carries the identity's own id", thrown.recordId === "i-1", thrown.recordId);
      check("it carries what the caller expected", thrown.expected === stamp, {
        got: thrown.expected,
        want: stamp,
      });
      check(
        "and what is stored now, which differs from it",
        thrown.actual === vaultIdentityStamp(stored) && thrown.actual !== thrown.expected,
        { actual: thrown.actual, expected: thrown.expected },
      );
    }
    check(
      "the refusal touched no keychain account at all",
      h.calls.length === 0,
      h.calls.map((c) => `${c.op} ${c.account}`),
    );
    check(
      "and the stored password is untouched",
      h.kept.get(at("i-1", "password")) === "pw-one",
      h.kept.get(at("i-1", "password")),
    );
  }

  // -- an identity deleted under the caller, and the identity control ------
  {
    const h = vaultHarness();
    const loaded = (await h.vault.upsertIdentity(anIdentity(), { password: "pw-one" })).record;
    await h.vault.deleteIdentity("i-1", () => []);
    const thrown = await thrownBy(() =>
      h.vault.upsertIdentity(anIdentity(), {}, vaultIdentityStamp(loaded)),
    );
    check(
      "a save against a DELETED identity is refused and says it is absent",
      thrown instanceof VaultRecordChangedError && thrown.actual === VAULT_STAMP_ABSENT,
      thrown instanceof VaultRecordChangedError ? thrown.actual : thrown,
    );
    check("nothing was put back", (await h.vault.findIdentity("i-1")) === undefined);
  }
  {
    const h = vaultHarness();
    const loaded = (await h.vault.upsertIdentity(anIdentity(), { password: "pw-one" })).record;
    const saved = (
      await h.vault.upsertIdentity(anIdentity({ name: "renamed" }), {}, vaultIdentityStamp(loaded))
    ).record;
    check("an unchanged identity saves normally", saved.name === "renamed", saved.name);
    check(
      "and its untouched password is still there",
      h.kept.get(at("i-1", "password")) === "pw-one",
    );
  }
}

// ============================================================================
// 16. WHERE the compare sits in each write body. (COMPILER API.)
// ============================================================================
// Protects: the half section 15 cannot see for the blank-body case, and the
// half no rooted-and-counted pin can see at all. A compare MOVED after the
// secret write is still present, still exactly one, still inside the right
// function - the count reads 1 before and after - and a deletion leaves the
// count at 1 too if anything replaces it. Only its INDEX among the block's own
// direct statements distinguishes the three.
console.log("\n[16. placement] the compare is a direct statement of the queued write body");
{
  const sf = sourceFile("store");

  /** The block `enqueueWrite(async () => { ... })` runs for the named store
   *  function - the statement list the compare has to be a member of. Not the
   *  function's own body: a compare sitting outside the queue entry is the
   *  window another writer fits into, and it would still be "inside
   *  `upsertKey`". */
  const queuedWriteBody = (fnName: string): ts.Block | null => {
    const fnBody = findFunctionBody(sf, fnName);
    if (!fnBody) return null;
    const [queued] = findCalls(fnBody, sf, ["enqueueWrite"]);
    if (!queued || queued.arguments.length !== 1) return null;
    const arrow = queued.arguments[0];
    if (!ts.isArrowFunction(arrow) || !ts.isBlock(arrow.body)) return null;
    return arrow.body;
  };

  /** The index of the block's own direct statement that `node` sits inside, or
   *  -1 if `node` is nested in something that is not one (a callback, a nested
   *  function). Walking up beats matching source text: a comment naming
   *  `writeKeySecrets(` must not be able to stand in for the call. */
  const directStatementIndex = (block: ts.Block, node: ts.Node): number => {
    let n: ts.Node | undefined = node;
    while (n && n.parent !== block) n = n.parent;
    if (!n) return -1;
    return block.statements.findIndex((s) => s === n);
  };

  const isCompare = (s: ts.Statement): boolean =>
    ts.isIfStatement(s) && norm(s.expression.getText(sf)) === norm("expect !== undefined");

  const pinPlacement = (fnName: string, stampFn: string, writeFn: string): void => {
    const body = queuedWriteBody(fnName);
    check(`${fnName}: its queued write body was located`, body !== null);
    if (!body) return;

    const compares = body.statements.filter(isCompare);
    check(
      `${fnName}: exactly one \`if (expect !== undefined)\` compare, as a DIRECT statement of that body`,
      compares.length === 1,
      compares.length,
    );
    const [writeCall] = findCalls(body, sf, [writeFn]);
    check(`${fnName}: the ${writeFn}( call was located`, writeCall !== undefined);
    if (compares.length !== 1 || !writeCall) return;

    const compareIdx = body.statements.indexOf(compares[0]);
    const writeIdx = directStatementIndex(body, writeCall);
    check(`${fnName}: the ${writeFn}( call is a direct statement of that body too`, writeIdx >= 0, {
      writeIdx,
    });
    if (writeIdx < 0) return;
    check(
      `${fnName}: the compare runs BEFORE ${writeFn}( - a refusal after it has already written a secret`,
      compareIdx < writeIdx,
      { compareIdx, writeIdx },
    );

    // What the compare is made of, so a compare left in the right PLACE but
    // stamping the wrong thing does not pass on position alone.
    const compareText = compares[0].getText(sf);
    check(
      `${fnName}: it stamps the record found in the store, as ${stampFn}(existing)`,
      norm(compareText).includes(norm(`${stampFn}(existing)`)),
      compareText,
    );
    check(
      `${fnName}: and refuses with the shared VaultRecordChangedError`,
      norm(compareText).includes(norm("throw new VaultRecordChangedError(")),
      compareText,
    );
  };

  pinPlacement("upsertKey", "vaultKeyStamp", "writeKeySecrets");
  pinPlacement("upsertIdentity", "vaultIdentityStamp", "writeSecret");
}

// ============================================================================
// 17. The two refusal messages tell the user what to do, not to press Save
//     again. (COMPILER API to locate each arm; SOURCE-TEXT over its content.)
// ============================================================================
// Protects: `KNOWN-LIMITS.md`'s entry accepting no refresh/recovery on this
// refusal rests on the strength of these two messages saying what to do -
// close and reopen - instead of inviting a second press that is refused the
// same way every time. Nothing else holds either sentence: both are
// assembled inline in a `.tsx` catch arm, never exported, so there is no
// function to pin by return value the way `vault-draft-verify.ts` section [9]
// pins `encryptedKeyRefusal`. This section is the closest equivalent that
// shape allows - the ternary each `save` branches on, found structurally so a
// swap of its two arms cannot hide from a check that reads the file as one
// blob, and its own two arm texts read directly off the AST rather than by a
// fragile string anchor.
//
// PINS THE PROPERTY, NOT THE SENTENCE: neither arm may read as an invitation
// to press Save again, and each arm must still say its own instruction - the
// deleted-record arm says "close this editor" (no reopen: there is nothing
// left to reopen against), the moved-record arm says "close and reopen"
// (there is). A pure negative set passes a message reduced to nothing, which
// is why each arm also carries its own positive.
//
// ONE SPELLING DECISION IS DISCLOSED HERE, because it decides how a future
// rewrite of either message may be worded: the deleted-record arm's own
// correct text says "pressing Save again will not help" - it NAMES the
// invitation in order to refuse it, which a bare `!/save again/i` test cannot
// tell from an actual invitation. `dulled()` below removes exactly that one
// phrase before the negative checks run, so the negatives read the rest of
// the sentence. Rewording that phrase (e.g. "won't help" for "will not
// help") requires updating `dulled()` alongside it, or the negative goes
// stale and starts failing the correct, committed text.
//
// WHAT THIS CANNOT SEE: whether either message ever reaches a render at all -
// section 14's own entry above this one is the closest existing coverage of
// that, and it is an absence, not a check.
console.log("\n[17. refusal wording] neither vault refusal message invites a second press");
{
  /** The first ConditionalExpression under `root` whose own condition text
   *  names `name` - the same nesting question `findAncestorConditionOn`
   *  above answers walking UP; this walks DOWN from a `save` body to find
   *  the `e.actual === VAULT_STAMP_ABSENT` ternary structurally, so a swap of
   *  its two arms moves with the node and cannot be missed by treating the
   *  region as one blob of text. */
  function findConditionalOn(
    root: ts.Node,
    name: string,
    sf: ts.SourceFile,
  ): ts.ConditionalExpression | null {
    let result: ts.ConditionalExpression | null = null;
    const visit = (n: ts.Node): void => {
      if (result) return;
      if (ts.isConditionalExpression(n) && n.condition.getText(sf).includes(name)) {
        result = n;
      }
      ts.forEachChild(n, visit);
    };
    visit(root);
    return result;
  }

  /** Strips the one phrase the deleted-record arm legitimately contains -
   *  see this section's header comment on why a bare negative cannot tell
   *  the refusal's own "will not help" from an actual invitation. */
  const dulled = (s: string): string => s.replace(/save again will not help/gi, "");

  const pinRefusalArm = (
    fileLabel: string,
    armLabel: string,
    text: string,
    positive: RegExp,
    positiveLabel: string,
  ): void => {
    const d = dulled(text);
    check(`${fileLabel}: ${armLabel} does not say to save again`, !/save again/i.test(d), d);
    check(`${fileLabel}: ${armLabel} does not say to press Save`, !/press save\b/i.test(d), d);
    check(`${fileLabel}: ${armLabel} does not say to try again`, !/try again/i.test(d), d);
    check(
      `${fileLabel}: ${armLabel} says ${positiveLabel} - so an empty or gutted message fails this`,
      positive.test(text),
      text,
    );
  };

  for (const key of ["keyDialog", "identityDialog"] as const) {
    const sf = sourceFile(key);
    const saveBody = findConstArrowBody(sf, "save");
    check(`${FILES[key]}: save's body was located (section 17)`, saveBody !== null);
    if (!saveBody) continue;

    const ternary = findConditionalOn(saveBody, "VAULT_STAMP_ABSENT", sf);
    check(
      `${FILES[key]}: the e.actual === VAULT_STAMP_ABSENT ternary was located`,
      ternary !== null,
    );
    if (!ternary) continue;

    const deletedArm = ternary.whenTrue.getText(sf);
    const movedArm = ternary.whenFalse.getText(sf);

    pinRefusalArm(
      FILES[key],
      "the deleted-record arm",
      deletedArm,
      /close this editor/i,
      '"close this editor"',
    );
    pinRefusalArm(
      FILES[key],
      "the moved-record arm",
      movedArm,
      /close and reopen/i,
      '"close and reopen"',
    );
  }
}

console.log(`\n${checked - failed}/${checked} vault-editor checks passed`);
if (failed > 0) console.error(`${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
