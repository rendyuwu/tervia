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
  // JSX comment expressions - `{/* ... */}` - are the only comment syntax
  // legal INSIDE JSX children (a bare `//` there renders as literal text),
  // and the line-based filter below only ever recognised `//`, `/*` and `*`
  // starting a trimmed line, none of which match a line starting `{`.
  // Discovered live, not hypothesised: P11 (VLT-80/7d(b)'s own paired
  // mutation) moved `chosenKey?.missingPrivateKey` into exactly this shape -
  // `{/* chosenKey?.missingPrivateKey */}` - and the original version of this
  // helper passed it straight through, leaving section 7's positive green
  // over dead, commented-out code.
  //
  // VLT-83: the inner group may not CROSS a `*/`. The first form here was
  // `\{\s*\/\*[\s\S]*?\*\/\s*\}` - lazy, but still allowed to skip past an
  // intervening `*/` while hunting for one that a `}` follows. A type literal
  // opening with a doc comment (`{ /** null = closed. */ target: … }`) matches
  // at that `{`, and the group then keeps extending past every later `*/` not
  // followed by `}` until it finds one that is, eating everything in between.
  // In `host-editor-verify.ts` that cost 50752 characters and 70 cascading
  // failures, and the fix landed there first (`host-editor-verify.ts:216`).
  // Here it was LATENT and reddened nothing, which is the worse half:
  // measured on `KeyEditorDialog.tsx` with such a comment added, the old form
  // swallowed 10954 of 22505 characters and the suite still passed 151/151,
  // because the two `> 3000` floors clear on the remainder and every positive
  // happens to anchor outside the swallowed span. What it does silence is the
  // NEGATIVES: a record assembly with a literal `keyType:` planted inside that
  // span passes section 5 for free (§4.17 - a check over stripped-away text
  // goes green). With the lookahead the first `*/` is final: either a `}`
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

/** Whitespace-stripped, for comparing two expressions' source text - VLT-76's
 *  pins 1 and 2 both need this: Prettier decides whether a call spans one
 *  line or four, and that choice is not the claim. Everything else in the
 *  text IS the claim, so this is the ONLY normalisation applied before an
 *  exact-text pin compares two sides. */
function norm(s: string): string {
  return s.replace(/\s+/g, "");
}

/** Every top-level (`=`) assignment expression anywhere under `root` whose
 *  left side is the bare identifier `name` - added for VLT-76's pin 2: "what
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
 *  CALLS made inside its children, the way section 12 (VLT-79.2) needs to. */
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
 *  walk runs out of parents first. VLT-79.1: "is this JSX element wrapped in
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

  const checkKeyAnchor = "const checkKey = async (pem: string, passphrase: string) => {";
  const checkKeyRegion = between(ks, checkKeyAnchor, "const invalidateInspection = () => {");
  // VLT-80/7d(c): above the ANCHOR's own length (61) by a wide margin, not an
  // arbitrary round number below it - `between()` returns a slice that
  // STARTS WITH `from`, so a floor at or below 61 is satisfied by the anchor
  // text alone with an empty region behind it (P13 empties exactly that).
  // Measured: the real region is ~600+ characters (the model is
  // `host-editor-verify.ts:1013-1022`).
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
  // VLT-80/7d(c): above the anchor's own length (36) by a wide margin - see
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

  // The half wave 1's host-editor version shipped WITHOUT: this file's own
  // passphrase input closes it. If this fails alone (textarea above staying
  // green), the check is doing its per-input job; if both fail together, the
  // check cannot tell the two apart and is not doing its job at all.
  const passphraseAnchor = '<Field label="Key passphrase (optional)">';
  const passphraseRegion = between(ks, passphraseAnchor, "</Field>");
  // VLT-80/7d(c): above the anchor's own length (41) by a wide margin - same
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
console.log("\n[3. save inspects fields] KeyEditorDialog's save reads draft.privateKey itself");
{
  const saveRegion = between(src.keyDialog, "const save = async () => {", "const busy = saving");
  check("KeyEditorDialog's save region was located", saveRegion.length > 100, saveRegion.length);
  // Whitespace-normalised (VLT-80's own §4.51 reformat pair found this one
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

  // Pin 2 (VLT-76, re-aimed for VLT-77): the declaration and the SINGLE
  // assignment to `facts`, pinned exactly, over the COMPILER API's own view
  // of `save`'s body - `findConstArrowBody(keySf, "save")` is already used by
  // section 4. A name scoped check (the `!/inspected/i` negative above) does
  // not survive an alias: `const panel = inspected;` above `save`, with
  // `facts` assigned from `panel` instead of a fresh `inspectSshKey` call,
  // passes every check above while reintroducing exactly the "inherit that
  // question one level deeper" failure this file's own header on `save`
  // forbids. Only pinning what is actually assigned to `facts` closes that.
  //
  // VLT-77 (`e4cc903`) inserted an encrypted-with-no-passphrase refusal
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
          // Re-aimed for VLT-77 (step 2, `e4cc903`): `save` now inspects the
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

    // New for VLT-77/step 2: `save` now inspects the key into `info` before
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
      // mutation (§4.51), which is what moved this pin here.
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

    // New for VLT-77: the encrypted-with-no-passphrase refusal. Pinned by
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
//
// Pin 1 (VLT-76): `includes("keyRecordFrom(")` is satisfied by
// `{ ...keyRecordFrom(id, draft, existing, facts), ...existing }` - the
// decisive mutation this round exists to close, which spreads the shared
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
  const pinUpsertArgs = (
    fileKey: keyof typeof FILES,
    calleeName: string,
    expectedArgs: readonly [string, string],
  ): void => {
    const sf = sourceFile(fileKey);
    const calls = findCalls(sf, sf, [calleeName]);
    // Found independently of section 4's own `found at least one` - a check
    // is not allowed to rely on a precondition asserted in an earlier
    // section: a renamed callee would otherwise leave THIS section's loop
    // below silently iterating zero times, which is a pass for free (the
    // §4.38 shape).
    check(
      `${FILES[fileKey]}: found at least one ${calleeName}( call to pin (section 5)`,
      calls.length > 0,
      calls.length,
    );
    for (const c of calls) {
      check(
        `${FILES[fileKey]}: ${calleeName}( is called with exactly 2 arguments`,
        c.arguments.length === 2,
        c.arguments.length,
      );
      if (c.arguments.length !== 2) continue;
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

  pinUpsertArgs("keyDialog", "upsertKey", [
    "keyRecordFrom(id, draft, existing, facts)",
    "keySecretsForSave(draft)",
  ]);
  pinUpsertArgs("identityDialog", "upsertIdentity", [
    "identityRecordFrom(id, draft)",
    "identitySecretsForSave(draft)",
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

  // VLT-80/7d(b): comment-stripped before the positive below - a raw
  // `.includes(...)` is satisfied by moving the real read into a comment and
  // deleting it (P11). Sanity-checked first: an empty string would pass the
  // next check for free (the model is this same file's section 10, and
  // `key-inspect-verify.ts:576-580`).
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
// which is how it goes stale silently (§4.15's shape, one file over). The
// negative is asserted against the FUNCTIONS' actual return values, imported
// and sliced at runtime - a hard-coded sentence here would be a THIRD place
// the copy lives.
console.log(
  "\n[8. shared help copy] both dialogs call the draft.ts help functions, and never inline them",
);
{
  // VLT-80/7d(b): comment-stripped before the three positives below, for the
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

// ============================================================================
// 11. The identity password field renders in every auth mode. (VLT-79.1,
//     COMPILER API for the nesting question a string scan cannot answer.)
// ============================================================================
// Protects: `IdentityEditorDialog.tsx:274-280`'s own five-line comment on why
// this field must NOT be hidden under key/agent auth - `VaultIdentity.hasPassword`
// is independent of `authMode` by design and `resolveRdpAuth` never consults
// the mode - and nothing but that comment currently enforces it.
console.log(
  "\n[11. VLT-79.1] the identity Password field is never wrapped in an authMode conditional",
);
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
//     (VLT-79.2, COMPILER API.)
// ============================================================================
// Protects: `editor/draft.ts:39-44`'s own claim that a second normalisation in
// a toggle handler "is how the two drift" - `identityRecordFrom` is the ONE
// place `keyId` is dropped for a non-key auth mode, so every `patch({...})`
// inside the Authentication field must touch `authMode` alone.
console.log(
  "\n[12. VLT-79.2] no auth-mode toggle handler patches keyId - only identityRecordFrom does",
);
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
// 13. A dead-affordance sweep over both dialogs. (VLT-79.3, COMPILER API.)
// ============================================================================
// Protects: `vault-shell-verify.ts` section 14 covers VaultPage/IdentityCard/
// KeyCard only; the two editor dialogs are the app's largest new interactive
// surface and had no such check before this. Every <Button> either wires an
// onClick or is a Cancel standing inside <DialogClose> (which wires the close
// itself); and neither file offers a SECOND, nested "New key"/"New identity"
// creator - reachable from nowhere and dead by construction if it existed.
console.log(
  "\n[13. VLT-79.3] every <Button> in either dialog does something; no nested New key/identity",
);
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

console.log(`\n${checked - failed}/${checked} vault-editor checks passed`);
if (failed > 0) console.error(`${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
