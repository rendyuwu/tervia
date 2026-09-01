/**
 * Self-check for the credential state machine in the merged host editor.
 * Run: `pnpm verify host-editor`.
 *
 * Source text, not imports, for the reason `rdp-lifetime-verify.ts` gives: these
 * invariants live inside a React component's effects and event handlers, and
 * there is no DOM or renderer in this suite to drive them through. What is
 * checkable without one is the STRUCTURE - and structure is exactly what the
 * findings below were: a write with no guard, a guard reading a value captured
 * before the thing it guards could happen, a persisted change gated on nothing, a
 * guard that permitted the destructive case of the two it could see.
 *
 * Section [2] is the exception, and deliberately: its rule is about VALUES - which
 * of `undefined`, `""` and a string a field sends - so it calls the real function
 * over a truth table. `sshSecretsForSave` lives in `editor/sshSecrets.ts` for that
 * reason. A regex cannot tell an omitted key from one set to `""`, and those are
 * the store's "leave it alone" and "delete the account".
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
 * 2. ONLY A FIELD THE USER TOUCHED REACHES THE SECRET STORE, AND EMPTYING ONE IS A
 *    CLEAR ONLY IF ITS VALUE WAS ON SCREEN. An untouched field is `undefined`, the
 *    store's "leave whatever is stored alone"; `""` is its CLEAR instruction, which
 *    deletes the keychain account. Echoing the seed back would make an edit that
 *    only renamed a host take its password with it - and the touched mark alone is
 *    not enough to send `""` either, because it is set by ANY patch carrying the
 *    key. One character typed and backspaced marks the field touched while it is
 *    empty, and the seed may not have landed yet, so the save deleted the password
 *    of a host the user never meant to touch and reported success. `seeded` is the
 *    second record that tells those apart, and section [2] is a truth table over
 *    the real function rather than a regex, because the rule is about VALUES.
 *
 * 3. THE DIALOG PERSISTS NO PIN AT ALL. Save is the only writer, and Cancel
 *    therefore cannot change what a host trusts in either direction.
 *
 *    Two defects got here. `onTrusted` first persisted a fingerprint ungated while
 *    `runTest` dialled the DRAFT address, so re-pointing the form, testing,
 *    accepting and cancelling left a record saved at 10.0.0.1 carrying 10.0.0.2's
 *    key - the next real connect aborts as a MISMATCH, which reads as an attack
 *    (§5.16). Gating the write on the saved address stopped it landing on the wrong
 *    address but not on the right one: press Forget (a DRAFT edit), Test the same
 *    address, and the probe TOFUs instead of raising the mismatch the pin existed
 *    for; accept, and the addresses match, so the gate passes and the stored pin is
 *    REPLACED; Cancel, and it cannot come back. The write the gate permitted was
 *    the destructive one, so the write is gone rather than gated again. The FORM's
 *    pin stays, gated on the row rather than the address: it is unsaved, visible in
 *    the recorded-key row, and disposed of by Cancel.
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
 * 7. THE PASSWORD FIELD'S COPY SAYS WHAT BLANK DOES, AND THAT IS TWO DIFFERENT
 *    THINGS. On a host with nothing stored, blank saves a host without a password.
 *    On a host that HAS one, blank is the state the field is in for the whole of the
 *    keychain read - the form is interactive before its secrets arrive, deliberately
 *    - and it means "leave the stored one alone". One string served both, so a user
 *    who typed a character and backspaced read "Leave blank to save the host without
 *    one" at the exact moment that described a deletion. The copy was not incidental
 *    to that defect; it confirmed the mental model that made someone press Save.
 *
 *    Also here: what a credential-less connect reports. The comment justifying the
 *    relaxed password rule claimed the server's own authentication error, and no
 *    server is reached - `resolve.ts` maps an empty secret to `undefined` and
 *    `session.rs` pre-flights it. The real outcome is the better one, which is why
 *    the prose has to name it rather than an invented one.
 *
 * Section [0] tests the helpers the source-text sections depend on, against samples whose
 * answers are known. That is not ceremony: `rdp-lifetime-verify.ts` shipped a
 * gating check that looked back a fixed 90 characters, found the PREVIOUS
 * statement's guard, and reported a deliberately ungated write as gated. A
 * structural check nobody has watched fail is a comment.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import ts from "typescript";

import {
  NOTHING_SEEDED,
  sshSecretsForSave,
  type SshSecretSeeded,
} from "../src/modules/hosts/editor/sshSecrets";
import type { SshCredentialDraft, SshSecretTouched } from "../src/modules/hosts/editor/types";

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
  // JSX comment expressions - `{/* ... */}` - are the only comment syntax
  // legal INSIDE JSX children (a bare `//` there renders as literal text),
  // and the line-based filter below only ever recognised `//`, `/*` and `*`
  // starting a trimmed line, none of which match a line starting `{`.
  // Fixed here per `vault-editor-verify.ts`'s own fix (VLT-83, found live by
  // step 7 of this wave against a DIFFERENT file): without this, a mutation
  // that moves code into exactly this shape slips past every comment-stripped
  // positive in this file, of which section [7] already has one -
  // `/\{passwordHelp\(hasStoredPassword\)\}/.test(sshSectionSrc)` would still
  // match a `{/* passwordHelp(hasStoredPassword) */}` left behind by a delete.
  //
  // NOT a straight copy of that fix's regex: `vault-editor-verify.ts`'s
  // `\{\s*\/\*[\s\S]*?\*\/\s*\}` is lazy but still ALLOWED to skip over an
  // intervening `*/` while searching for one followed by `}` - and
  // `HostEditorDialogProps`'s own `{ /** null = closed. */ target: … }` type
  // literal opens with exactly a `{` immediately followed by `/*`, with no
  // `}` after ITS `*/`. Measured: with that regex, the lazy group kept
  // extending past every later `*/` that was not immediately followed by `}`
  // until it found one 50KB downstream that was - eating the entire file in
  // between, including `save` and everything section [4]/[7]/[8] anchor on.
  // The negative lookahead below forbids the inner group from ever crossing a
  // `*/` at all, so the first one found is final: either `}` follows it and
  // this is a real `{/* … */}`, or it does not and the match fails HERE,
  // at this `{`, rather than searching onward for a luckier one.
  const withoutJsxComments = src.replace(/\{\s*\/\*(?:(?!\*\/)[\s\S])*\*\/\s*\}/g, "");
  return withoutJsxComments
    .split("\n")
    .filter((line) => {
      const t = line.trim();
      return !(t.startsWith("//") || t.startsWith("/*") || t.startsWith("*"));
    })
    .map(stripLineComment)
    .join("\n");
}

/**
 * The condition of the `if` attached to EVERY statement `needle` occurs in, in
 * source order, with "" for an occurrence that has no guard of its own.
 *
 * Deliberately not "is there an `if` somewhere before this": it walks back to the
 * nearest statement boundary, so a write following a guarded statement borrows
 * nothing, and it makes exactly ONE hop over an opening brace so a block-bodied
 * `if` is read while a write merely sitting deeper in a function is not. Section
 * [0] holds it to both.
 *
 * ALL matches rather than the first, because the first-match form this replaces was
 * a false pass waiting to happen: add a second write of the same kind and it reads
 * the one that is still correct while reporting nothing about the new one. Handoff
 * §5.17, which `expectedFingerprint` already follows in section [6] by asserting a
 * count of two. A caller asserts the count as well, because an empty list satisfies
 * `every` - a write that DISAPPEARS must not pass either.
 */
function guardsFor(region: string, needle: string): string[] {
  const out: string[] = [];
  for (let at = region.indexOf(needle); at >= 0; at = region.indexOf(needle, at + 1)) {
    out.push(guardAt(region, at));
  }
  return out;
}

/** The shared walk, from a position rather than a needle, so one implementation
 *  serves both the first-match and the all-matches form. */
function guardAt(region: string, start: number): string {
  let at = start;
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

// ---------------------------------------------------------------------------
// Compiler-API helpers for section [9] (6b, and 6a's re-aim of section [8]).
// Copied from `vault-editor-verify.ts` / `vault-shell-verify.ts` where a
// helper of the same job already exists there, so this file's shape matches
// the rest of the suite rather than inventing a sixth way to do the same walk
// (§4.43's list of `check()` shapes is exactly this kind of drift, one level
// up). New helpers are ones neither file needed: `conditionalArmOf`,
// `findIfByCondition`, `ifConditionsEnclosing`, `findObjectLiteralProperties`,
// `parseFragment`.
// ---------------------------------------------------------------------------

/** The function DECLARATION body named `name` - `HostEditorDialog` is a plain
 *  `export function HostEditorDialog(...) { ... }`, the shape
 *  `vault-editor-verify.ts`'s helper of the same name covers. */
function findFunctionBody(root: ts.Node, name: string): ts.Node | null {
  let result: ts.Node | null = null;
  const visit = (n: ts.Node): void => {
    if (ts.isFunctionDeclaration(n) && n.name?.text === name && n.body) result = n.body;
    ts.forEachChild(n, visit);
  };
  visit(root);
  return result;
}

/** The body of a `const <name> = (...) => { ... }` arrow function declaration -
 *  the shape `applyCredentialChange` uses. */
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

/** Every call expression under `root` whose callee's own source text is
 *  exactly one of `calleeNames`. */
function findCalls(root: ts.Node, sf: ts.SourceFile, calleeNames: string[]): ts.CallExpression[] {
  const out: ts.CallExpression[] = [];
  const visit = (n: ts.Node): void => {
    if (ts.isCallExpression(n) && calleeNames.includes(n.expression.getText(sf))) out.push(n);
    ts.forEachChild(n, visit);
  };
  visit(root);
  return out;
}

/** Whitespace-stripped, for comparing two expressions' source text - Prettier
 *  decides whether a call or a ternary spans one line or several, and that
 *  choice is not the claim (§4.51). The ONLY normalisation applied before an
 *  exact-text pin compares two sides. */
function norm(s: string): string {
  return s.replace(/\s+/g, "");
}

/** The `let`/`const` variable declaration named `name` anywhere under `root`. */
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

/** Every identifier reference to `name` anywhere under `root` - scope `root`
 *  to exclude a declaration or an import specifier a caller does not want
 *  counted. */
function findIdentifierUses(root: ts.Node, name: string): ts.Identifier[] {
  const out: ts.Identifier[] = [];
  const visit = (n: ts.Node): void => {
    if (ts.isIdentifier(n) && n.text === name) out.push(n);
    ts.forEachChild(n, visit);
  };
  visit(root);
  return out;
}

/** Every JSX element or self-closing element in `root` whose tag is
 *  `tagName`, as its opening element - copied from `vault-shell-verify.ts` /
 *  `vault-editor-verify.ts`. */
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
 *  string value on one opening element - copied from `vault-editor-verify.ts`'s
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

/** Whether some ancestor of `node` is a `<tag>...</tag>` JsxElement - copied
 *  from `vault-editor-verify.ts`. */
function findAncestorJsxElementByTag(node: ts.Node, tag: string, sf: ts.SourceFile): boolean {
  let n: ts.Node | undefined = node.parent;
  while (n) {
    if (ts.isJsxElement(n) && n.openingElement.tagName.getText(sf) === tag) return true;
    n = n.parent;
  }
  return false;
}

/**
 * Walking UP from `node`, the nearest ConditionalExpression ancestor together
 * with which arm the walk left through - "then" for `whenTrue`, "else" for
 * `whenFalse`; `null` once the walk runs out of parents.
 *
 * This resolves nesting through the AST rather than by scanning for the
 * nearest `?`/`:` in the text (§4.17's shape): `mode === "create" ?
 * identityIdFromChoice(choice) : …` and `mode === "edit" ? [ { value:
 * CREDENTIAL_CHOICE_NEW_IDENTITY, … } ] : []` both bury the identifier this
 * file checks for several nodes below the ternary whose gate actually
 * matters - an object literal, an array literal, a property assignment - and
 * a text-distance walk has no principled way to see through those.
 */
function conditionalArmOf(
  node: ts.Node,
): { cond: ts.ConditionalExpression; arm: "then" | "else" } | null {
  let child: ts.Node = node;
  let n: ts.Node | undefined = node.parent;
  while (n) {
    if (ts.isConditionalExpression(n)) {
      if (n.whenTrue === child) return { cond: n, arm: "then" };
      if (n.whenFalse === child) return { cond: n, arm: "else" };
    }
    child = n;
    n = n.parent;
  }
  return null;
}

/** The nearest IfStatement anywhere under `root` (source order) whose own
 *  condition's text CONTAINS `substr` - locates one arm of an `if (x) {} else
 *  if (y) {} else if (z) {}` chain by what it TESTS rather than by position,
 *  so re-ordering `applyCredentialChange`'s three arms does not mis-locate
 *  one. */
function findIfByCondition(
  root: ts.Node,
  sf: ts.SourceFile,
  substr: string,
): ts.IfStatement | null {
  let result: ts.IfStatement | null = null;
  const visit = (n: ts.Node): void => {
    if (result) return;
    if (ts.isIfStatement(n) && n.expression.getText(sf).includes(substr)) {
      result = n;
      return;
    }
    ts.forEachChild(n, visit);
  };
  visit(root);
  return result;
}

/** Every enclosing `if` statement's own condition text, walking upward from
 *  `node`, innermost first - resolved through the AST rather than by how far
 *  away the text sits (§4.17), which is what section [8]'s 6a re-aim needs:
 *  `setSshCred(`/`setRdpCred(` sit two `if`s below the one that actually
 *  names the refreshed record's credential kind, with an `if (isSshHost(fresh))`
 *  in between that a fixed-hop walk would stop at instead. */
function ifConditionsEnclosing(node: ts.Node, sf: ts.SourceFile): string[] {
  const out: string[] = [];
  let n: ts.Node | undefined = node.parent;
  while (n) {
    if (ts.isIfStatement(n)) out.push(n.expression.getText(sf));
    n = n.parent;
  }
  return out;
}

/** Every plain `name: value` property assignment under `root` whose key is
 *  one of `names` - the parsed-object-literal form of "no secret field is
 *  written with anything but the empty string", which a regex on the text
 *  cannot tell from the same words inside a comment, a string, or a shorthand
 *  property of the same name bound to something else entirely. */
function findObjectLiteralProperties(root: ts.Node, names: string[]): ts.PropertyAssignment[] {
  const out: ts.PropertyAssignment[] = [];
  const visit = (n: ts.Node): void => {
    if (ts.isPropertyAssignment(n) && ts.isIdentifier(n.name) && names.includes(n.name.text)) {
      out.push(n);
    }
    ts.forEachChild(n, visit);
  };
  visit(root);
  return out;
}

/**
 * Parses a STATEMENT fragment - not a whole file - by wrapping it in a
 * throwaway function, so section [8]'s recovery arm (already isolated as a
 * plain string by `between()`, the file's existing convention) gets the same
 * compiler-API nesting checks section [9] uses, without re-deriving `save`'s
 * location a second way through the compiler API as well.
 *
 * `recoveryArmRaw` already ends in the arm's own closing brace - `between()`'s
 * `"} else {"` anchor consumed the OPENING one - so exactly one new `{` is
 * what balances it; the fragment is `TS`, not `TSX`, since nothing inside an
 * async function body here is JSX.
 */
function parseFragment(statements: string): ts.SourceFile {
  return ts.createSourceFile(
    "fragment.ts",
    `function _fragment() {${statements}`,
    ts.ScriptTarget.ESNext,
    true,
    ts.ScriptKind.TS,
  );
}

const editorRaw = read("src/modules/hosts/HostEditorDialog.tsx");
const editorSrc = stripComments(editorRaw);
const rdpSectionRaw = read("src/modules/hosts/editor/RdpCredentialSection.tsx");
const sshSectionRaw = read("src/modules/hosts/editor/SshCredentialSection.tsx");
const sshSectionSrc = stripComments(sshSectionRaw);
const copyRaw = read("src/modules/hosts/editor/secretStoreCopy.ts");
const hostsPageRaw = read("src/modules/hosts/HostsPage.tsx");

// Parsed once, for section [9]'s compiler-API checks (VLT-76's shape - the
// precedent is `vault-editor-verify.ts:482-540` and `pane-caret-verify.ts`,
// both already on `typescript` for exactly this reason: "is this call
// lexically inside X" is a nesting question a distance heuristic answers
// wrong, per §4.17). `ScriptKind.TSX` on both, since either file's JSX would
// otherwise parse its own generics as JSX and vice versa.
const editorSf = ts.createSourceFile(
  "HostEditorDialog.tsx",
  editorRaw,
  ts.ScriptTarget.ESNext,
  true,
  ts.ScriptKind.TSX,
);
const hostsPageSf = ts.createSourceFile(
  "HostsPage.tsx",
  hostsPageRaw,
  ts.ScriptTarget.ESNext,
  true,
  ts.ScriptKind.TSX,
);

const SECRET_FIELDS = ["password", "privateKey", "keyPassphrase"] as const;

// ---------------------------------------------------------------------------
console.log("[0] the helpers the checks below depend on");
{
  /** The guard of the only occurrence in a sample, so a one-write case reads as
   *  one value. Asserts the sample HAS exactly one, or a walker that found none
   *  would look like a walker that found no guard. */
  const oneGuard = (region: string, needle: string): string => {
    const all = guardsFor(region, needle);
    return all.length === 1 ? all[0] : `<${all.length} matches>`;
  };

  check(
    "guardsFor reads the condition of a block-bodied guard",
    oneGuard("if (a === b) {\n  writeIt();\n}\n", "writeIt()") === "a === b",
    oneGuard("if (a === b) {\n  writeIt();\n}\n", "writeIt()"),
  );
  check(
    "and of a single-statement guard",
    oneGuard("if (a === b) writeIt();\n", "writeIt()") === "a === b",
  );
  check(
    "and of a guard whose body opens with void, which is how a fire-and-forget write reads",
    oneGuard("if (a === b) {\n  void writeIt();\n}\n", "writeIt()") === "a === b",
    oneGuard("if (a === b) {\n  void writeIt();\n}\n", "writeIt()"),
  );
  // The false pass this file exists not to repeat.
  check(
    "but an unguarded write does not borrow the guard of the statement above it",
    oneGuard("if (a === b) other();\nwriteIt();\n", "writeIt()") === "",
    oneGuard("if (a === b) other();\nwriteIt();\n", "writeIt()"),
  );
  check(
    "not even when that write opens with void",
    oneGuard("if (a === b) other();\nvoid writeIt();\n", "writeIt()") === "",
    oneGuard("if (a === b) other();\nvoid writeIt();\n", "writeIt()"),
  );
  check(
    "nor the guard that opened the block it sits in two statements deep",
    oneGuard("if (a === b) {\n  other();\n  writeIt();\n}\n", "writeIt()") === "",
    oneGuard("if (a === b) {\n  other();\n  writeIt();\n}\n", "writeIt()"),
  );
  check(
    "and an unguarded write in a bare block reports nothing",
    oneGuard("{\n  writeIt();\n}\n", "writeIt()") === "",
  );
  check(
    "a missing needle reports an empty list rather than throwing",
    guardsFor("x();\n", "writeIt()").length === 0,
  );

  // The reason this is the all-matches form: a second, ungated write of the same
  // kind used to hide behind a correctly gated first one.
  {
    const two = "if (a === b) writeIt();\nwriteIt();\n";
    check(
      "and a second occurrence is reported even when the first is guarded",
      JSON.stringify(guardsFor(two, "writeIt()")) === JSON.stringify(["a === b", ""]),
      guardsFor(two, "writeIt()"),
    );
  }

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
  // VLT-83: the only comment syntax legal inside JSX children, and the one the
  // line-based filter above cannot see because it never starts a line with `{`.
  check(
    "and strips a JSX comment expression too, not just a // or /* one",
    !stripComments("<div>{/* writeIt() */}</div>").includes("writeIt()"),
    stripComments("<div>{/* writeIt() */}</div>"),
  );
  check(
    "without eating the JSX around it",
    stripComments("<div>{/* writeIt() */}</div>").includes("<div>") &&
      stripComments("<div>{/* writeIt() */}</div>").includes("</div>"),
  );
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
  // And with nothing seeded, or the previous row's seed would license clearing
  // this row's secret - the same drift, one field over.
  check("and with nothing seeded either", /\.current = NOTHING_SEEDED;/.test(reset), reset.trim());

  // The record section [2] enforces the clear rule with. Two properties, and both
  // of them are what keeps it from re-opening the hole it closes: a field the seed
  // YIELDED to is not seeded (the stored value never reached the screen, so the
  // user cannot have meant to remove it), and a field seeded with an empty value is
  // not either.
  const seededWrite = between(seed, "sshSeeded.current = {", "};");
  check("the seeded record's write was found", seededWrite.length > 50, seededWrite.length);
  for (const f of SECRET_FIELDS) {
    const line = propertyLine(seededWrite, f);
    check(
      `${f} counts as seeded only where the seed was not yielded to`,
      new RegExp(`^${f}: !\\w+\\.${f} &&`).test(line),
      line,
    );
    check(
      `and only when what arrived for ${f} is not the store's own clear value`,
      new RegExp(`!clearsSecret\\(secrets\\.${f} \\?\\? ""\\)`).test(line),
      line,
    );
  }
  // Outside the updater, which must stay pure: React may call an updater twice,
  // and §5.14's whole lesson is about what a value read in the wrong place says.
  check(
    "and it is written outside the draft updater",
    seed.indexOf("sshSeeded.current = {") > seed.indexOf("}));"),
    { seededAt: seed.indexOf("sshSeeded.current = {"), updaterEndsAt: seed.indexOf("}));") },
  );
}

// ---------------------------------------------------------------------------
console.log("\n[2] a secret is sent only when touched, and cleared only when it was on screen");
{
  // The real function, called directly - `sshSecretsForSave` lives in a plain
  // module for exactly this reason. A source-text check here would be a regex over
  // a rule about VALUES, which is §5.18's first failure shape: it cannot tell `""`
  // being FORWARDED from `""` being omitted, and those are the two outcomes the
  // whole thing turns on.
  const draft = (value: string): SshCredentialDraft => ({
    user: "u",
    authMode: "password",
    password: value,
    privateKey: value,
    keyPassphrase: value,
  });
  const all = (on: boolean): SshSecretTouched => ({
    password: on,
    privateKey: on,
    keyPassphrase: on,
  });
  const only = (field: keyof SshSecretSeeded): SshSecretSeeded => ({
    ...NOTHING_SEEDED,
    [field]: true,
  });

  // `absent` and `""` are DIFFERENT instructions to the store - leave it alone
  // versus delete the account - and `JSON.stringify` cannot tell them apart, which
  // is why the expectation is `null` for absent and the key test is `in`.
  const table: {
    what: string;
    value: string;
    touched: boolean;
    seeded: boolean;
    expect: string | null;
  }[] = [
    { what: "an untouched empty field", value: "", touched: false, seeded: false, expect: null },
    {
      what: "an untouched field holding the seeded value, which must not be echoed back",
      value: "stored",
      touched: false,
      seeded: true,
      expect: null,
    },
    { what: "a typed value", value: "typed", touched: true, seeded: false, expect: "typed" },
    {
      what: "a typed value over a seeded one",
      value: "rotated",
      touched: true,
      seeded: true,
      expect: "rotated",
    },
    // The defect. One character typed and backspaced before the keychain read
    // landed used to send `""`, and the store deletes the account on `""`.
    {
      what: "a field emptied before the seed could land",
      value: "",
      touched: true,
      seeded: false,
      expect: null,
    },
    // And the deliberate clear, which must survive the fix.
    {
      what: "a seeded value the user selected and deleted",
      value: "",
      touched: true,
      seeded: true,
      expect: "",
    },
    // The store trims before it decides, so a space is its clear value too: judging
    // emptiness any other way leaves the space bar as a way past the rule.
    {
      what: "a field holding only whitespace, before the seed could land",
      value: "   ",
      touched: true,
      seeded: false,
      expect: null,
    },
    {
      what: "a seeded value replaced with whitespace, which the store trims to a clear",
      value: "   ",
      touched: true,
      seeded: true,
      expect: "   ",
    },
  ];

  for (const f of SECRET_FIELDS) {
    for (const row of table) {
      const out = sshSecretsForSave(
        draft(row.value),
        { ...all(false), [f]: row.touched },
        row.seeded ? only(f) : NOTHING_SEEDED,
      );
      const present = f in out;
      check(
        `${f}: ${row.what} is ${row.expect === null ? "left alone" : `sent as ${JSON.stringify(row.expect)}`}`,
        row.expect === null ? !present : present && out[f] === row.expect,
        { present, value: out[f] },
      );
    }
  }

  // Per field, not per form: one seeded field must not license clearing another.
  // The cross-field version of the same bug, and a `seeded` read with the wrong
  // index passes every check above.
  {
    const out = sshSecretsForSave(draft(""), all(true), only("password"));
    check(
      "a seeded password authorises clearing the password and nothing else",
      "password" in out && out.password === "" && !("privateKey" in out),
      out,
    );
    check("nor the key passphrase", !("keyPassphrase" in out), out);
  }

  // A fourth field added to the draft cannot arrive by spread.
  {
    const out = sshSecretsForSave(draft("v"), all(true), NOTHING_SEEDED);
    check(
      "and nothing but the three secret fields is ever sent",
      JSON.stringify(Object.keys(out).sort()) === JSON.stringify([...SECRET_FIELDS].sort()),
      Object.keys(out),
    );
  }

  const patch = between(editorSrc, "const patchSshCred = (patch:", "const changeProtocol =");
  check("patchSshCred was found", patch.length > 100, patch.length);
  for (const f of SECRET_FIELDS) {
    // `||` because the mark is STICKY: a second patch that does not carry this
    // field must not un-touch it. `!== undefined` because emptying a field IS an
    // edit - and deliberately nothing more than that, because this handler cannot
    // tell a backspace over a seeded value from one over a field the read has not
    // reached. Whether that edit may delete anything is `seeded`'s answer, above.
    check(
      `a patch carrying ${f} marks it touched, and one that does not leaves the mark alone`,
      new RegExp(`${f}: \\w+\\.current\\.${f} \\|\\| patch\\.${f} !== undefined`).test(patch),
      propertyLine(patch, f),
    );
  }

  const save = between(editorSrc, "const save = async () => {", "const protocolLabel =");
  check("save was found", save.length > 1000, save.length);
  // BOTH live records. Reading either from state instead is §5.14's defect wearing
  // the fix's shape, and a stale seeded record is the same fault one field over -
  // it would license a clear the user could not see, which is the whole finding.
  check(
    "the SSH secrets are taken from the live touched AND seeded records",
    /sshSecretsForSave\(sshCred, \w+\.current, \w+\.current\)/.test(save),
    /.*sshSecretsForSave\([^;]*/s.exec(save)?.[0]?.slice(0, 160),
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
console.log("\n[3] nothing inside the dialog persists a pin, in either direction");
{
  const runTest = between(editorSrc, "const runTest = async () => {", "const save = async () => {");
  check("runTest was found", runTest.length > 500, runTest.length);
  const onTrusted = between(runTest, "const onTrusted = (fingerprint: string) => {", "try {");
  check("its trust callback was found", onTrusted.length > 50, onTrusted.length);

  // The store write is GONE, not gated, and the check is the absence rather than
  // the guard. Gating it on the saved address (§5.16) closed the case where a
  // cancelled dialog left a FOREIGN machine's fingerprint on a record - the next
  // real connect aborts as a MISMATCH, which reads as an attack. It did not close
  // the case where the write lands on the address the record does name: Forget (a
  // draft edit) removes the pin from `pins`, so Test TOFUs instead of raising the
  // mismatch the pin existed for, accepting overwrites the STORED pin because the
  // addresses agree, and Cancel leaves that in place with nothing warned. The write
  // the gate permitted was the destructive one. With no write here, both cases are
  // closed by construction and §5.16's question - does this survive Cancel, and
  // should it - has nothing left in this dialog to ask it of.
  //
  // Read out of the import statement rather than listed here, so importing a NEW
  // store function and calling it from the trust callback fails too.
  const storeImports = /import \{([^}]*)\} from "\.\/store";/.exec(editorRaw)?.[1] ?? "";
  const storeFns = [...storeImports.matchAll(/\b([a-z]\w*)\b/g)]
    .map((m) => m[1])
    .filter((n) => n !== "type");
  check("the store's imported surface was found", storeFns.length >= 3, storeFns);
  check(
    "the trust callback calls nothing in the store at all",
    storeFns.filter((fn) => onTrusted.includes(`${fn}(`)).length === 0,
    { called: storeFns.filter((fn) => onTrusted.includes(`${fn}(`)), onTrusted: onTrusted.trim() },
  );
  // And the pin-writing call is not reachable from anywhere in this file, so it
  // cannot be re-added to some other handler with the same effect. `pinFingerprint`
  // still exists for the real connect paths, which are the only things that have
  // been presented a key by a connection the user asked for.
  check(
    "and the editor does not import the store's pin writer at all",
    !editorSrc.includes("pinFingerprint"),
    /.*pinFingerprint.*/.exec(editorSrc)?.[0],
  );
  // Save is the only writer left, and the recorded-key row's footnote says so - a
  // footnote promising "Forget applies when you save" while Test could overwrite the
  // stored pin behind it was half of what made the sequence above invisible.
  check(
    "the recorded-key footnote promises that saving is what applies a pin change",
    count(editorRaw, /apply when you save/g) === 2,
    count(editorRaw, /apply when you save/g),
  );

  // The FORM's pin stays, and it must NOT be address-gated: the form's pins are
  // unsaved, one of them shows in the recorded-key row, and Cancel disposes of the
  // map, so one may describe the address being proposed. It is gated on the ROW
  // instead, because a probe outlives the row it started on.
  //
  // ALL of them, with the count asserted: a second trust write added beside a
  // correctly gated first one is invisible to a first-match search, and an empty
  // list satisfies `every` (handoff §5.17).
  const formPins = guardsFor(onTrusted, "setPins(");
  check("the callback holds exactly one write to the form's pins", formPins.length === 1, formPins);
  check(
    "and every one of them is gated on the row rather than the address",
    formPins.length > 0 && formPins.every((g) => g === "onProbeRow()"),
    formPins,
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
  // The store, not the form, decides what was actually written. The third
  // argument (the binding stamp, section [8]) is part of every call, including
  // this one, so the record-and-secrets pairing is asserted as a prefix rather
  // than the whole call.
  check("the record and those secrets go down together", /upsertHost\(record, secrets,/.test(save));
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

  // 6c: extended to the two files this wave adds, `credentialMove.ts` and
  // `editor/credentialChoice.ts` - VLT-83's sibling risk, not comments this
  // time: these two are now where a sentence about a stored private key is
  // most likely to be written (the convert/bind/detach confirmations), and
  // the vault files already hold the wording rule below
  // (`vault-shell-verify.ts:620-623`).
  const credentialMoveRaw = read("src/modules/hosts/credentialMove.ts");
  const credentialChoiceRaw = read("src/modules/hosts/editor/credentialChoice.ts");
  const KEYCHAIN_SWEEP_FILES = [
    ["HostEditorDialog.tsx", editorRaw],
    ["editor/RdpCredentialSection.tsx", rdpSectionRaw],
    ["editor/SshCredentialSection.tsx", sshSectionRaw],
    ["credentialMove.ts", credentialMoveRaw],
    ["editor/credentialChoice.ts", credentialChoiceRaw],
  ] as const;
  for (const [path, src] of KEYCHAIN_SWEEP_FILES) {
    check(
      `${path} names no OS keychain of its own`,
      !/OS keychain|Credential Manager/.test(src),
      /.{0,60}(OS keychain|Credential Manager).{0,40}/.exec(src)?.[0],
    );
  }
  // Deviation from 6c's literal "over the same set": `HostEditorDialog.tsx`'s
  // own module-header comment already reads "Nothing here makes a secret
  // safer than it was" - a NEGATED, true disclaimer that happens to use the
  // one word this needle bans. The vault files this rule is modelled on never
  // hit that: they phrase the identical disclaimer around the ban instead
  // ("Nothing here says how well a secret is protected",
  // `vault/page/IdentityCard.tsx:14`), which is the established convention -
  // but rewording `HostEditorDialog.tsx`'s prose is a product-code edit this
  // step does not own (its write list is this file alone). Scoped to the
  // other four, which is where 6c's own reasoning actually points ("these two
  // are now where a sentence about a stored private key is most likely to be
  // written") plus the two credential sections, which already pass it clean.
  // `Encrypted` is deliberately not forbidden - wave 3's key panel says it
  // about a locked key, truthfully, and that is a different claim
  // (`vault-shell-verify.ts:610-611`).
  for (const [path, src] of KEYCHAIN_SWEEP_FILES) {
    if (path === "HostEditorDialog.tsx") continue;
    check(
      `${path} makes no safety comparison`,
      !/\bsafer\b|\bsecurely\b|\bmore secure\b/i.test(src),
      /.{0,60}(safer|securely|more secure).{0,40}/i.exec(src)?.[0],
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

// ---------------------------------------------------------------------------
console.log("\n[7] the password field says what BLANK does, which is two different things");
{
  // The copy half of section [2]'s rule, and it is here because the wrong version
  // of it was load-bearing in the defect rather than incidental: a user who typed
  // one character and backspaced saw a blank field plus "Leave blank to save the
  // host without one", which describes the destruction the save used to perform and
  // confirms the mental model that makes them press Save.
  const help = between(
    sshSectionSrc,
    "function passwordHelp(",
    "export function SshCredentialSection",
  );
  check("passwordHelp was found", help.length > 200, help.length);
  check(
    "it branches on what the STORED record claims",
    /if \(hasStoredPassword\)/.test(help),
    help,
  );

  const stored = between(help, "if (hasStoredPassword) {", "}");
  check("the stored-password branch was found", stored.length > 60, stored.length);
  check(
    "and it does not offer to save the host without a password",
    !/without one/.test(stored),
    stored.trim(),
  );
  check(
    "it says blank leaves the stored one alone",
    /blank does not remove it/.test(stored),
    stored.trim(),
  );
  // The clear is still reachable, and the copy names the precondition section [2]
  // enforces - otherwise the honest text becomes "you cannot remove it".
  check(
    "and it says how to remove one, precondition included",
    /load into this field/.test(stored) && /clear it, and save/.test(stored),
    stored.trim(),
  );

  // Everything after the stored-password branch, and "" when that branch is not
  // there at all - so a single-string version of this function reddens both halves
  // rather than passing the second by accident.
  const fresh = stored.length > 0 ? help.slice(help.indexOf(stored) + stored.length) : "";
  check(
    "the no-password branch still says blank saves a host without one",
    /without one/.test(fresh),
    fresh.trim(),
  );
  // §5.20: a string the component cannot reach is the same as no string at all.
  check(
    "the field renders the branch rather than a literal of its own",
    /\{passwordHelp\(hasStoredPassword\)\}/.test(sshSectionSrc),
    /.*passwordHelp\(.*/.exec(sshSectionSrc)?.[0],
  );
  check(
    "and the dialog threads the stored flag in from the record, not from the draft",
    /hasStoredPassword=\{hasStoredSshPassword\}/.test(editorSrc) &&
      /const hasStoredSshPassword =[\s\S]{0,200}?credential\.hasPassword;/.test(editorSrc),
    /.*hasStoredPassword=.*/.exec(editorSrc)?.[0],
  );

  // What a credential-less connect actually does, because the comment justifying
  // the relaxed validation named something that does not happen: it claimed the
  // server's own authentication error. `resolve.ts` maps an empty secret to
  // `undefined` and `session.rs`'s `connect` pre-flights that before opening a
  // socket, so nothing reaches a server at all. The real message is the better one,
  // which is exactly why the prose must name it rather than the invented one.
  check(
    "the relaxation is justified by the refusal that happens, named as the backend words it",
    /no credentials/.test(sshSectionRaw),
    /.{0,80}no credentials.{0,40}/.exec(sshSectionRaw)?.[0],
  );
  check(
    "and claims no authentication failure, which a connect with no credentials never reaches",
    !/authentication error|fails authentication/.test(sshSectionRaw),
    /.{0,80}(authentication error|fails authentication).{0,40}/.exec(sshSectionRaw)?.[0],
  );
  check(
    "the pre-flight it names is still the backend's own wording",
    /"ssh: no credentials: set use_agent, password, or private_key"/.test(
      read("src-tauri/src/modules/ssh/session.rs"),
    ),
  );
}

// ---------------------------------------------------------------------------
console.log("\n[8] the save hands the store the binding it loaded, and recovers from a refusal");
{
  // Scoped through `save` first, exactly as section [4] locates it: `} catch (e) {`
  // is not unique in this file - the keychain seed's own inner try/catch (around
  // `getHostSshSecrets`) has one too - so anchoring on it directly from the top of
  // the file would capture everything between the WRONG catch and the one
  // `} finally {` in the component, which is almost the whole body. Narrowing to
  // `save` first is what makes the anchor unique.
  const save = between(editorSrc, "const save = async () => {", "const protocolLabel =");
  check("save was found", save.length > 1000, save.length);
  const saveRaw = between(editorRaw, "const save = async () => {", "const protocolLabel =");

  // Stripped, per the file's own convention: the comment blocks written for this
  // recovery quote the very strings the checks below search for, and a check that
  // matches its own explanatory comment is green over a deleted implementation.
  const catchRegion = between(save, "} catch (e) {", "} finally {");
  check("the catch region was located", catchRegion.length > 40, catchRegion.length);

  check(
    "the save hands the store the binding it loaded",
    /upsertHost\(\s*record,\s*secrets,\s*credentialStamp\(existing\)\s*\)/.test(editorSrc),
  );

  // Over the RAW source, comments included: a forbidden call parked behind a
  // comment or a dead branch is one edit from live, and a negative assertion
  // belongs over everything, not over what stripComments left behind.
  check(
    "and there is no unconditional two-argument save left",
    !/upsertHost\(record,\s*secrets\)/.test(editorRaw),
  );

  check(
    "the refusal is recognised by type, not by matching its text",
    /e instanceof HostBindingChangedError/.test(catchRegion) &&
      !/message.*includes\(/.test(catchRegion),
  );

  // The CREDENTIAL_STAMP_ABSENT arm, located by its own lexical boundaries -
  // the literal `else if (...) {` that opens it and the `} else {` that closes
  // it - rather than by how far away `findHost(` sits. A distance heuristic
  // reads a correctly guarded call that is the second statement in a block as
  // ungated, which is a false PASS on exactly the negative check this exists
  // to catch: `guardsFor` was checked against this shape directly and reports
  // "" for both `CREDENTIAL_STAMP_ABSENT` and `findHost(` here, because neither
  // sits as the bare first statement of an `if (cond) { ... }` it recognises -
  // an `else if`/`else` chain is not a pattern it models. Anchored extraction is
  // what actually resolves the block; a distance check would not "abstain", it
  // would silently pass every wiring.
  const absentAnchor = "e.actual === CREDENTIAL_STAMP_ABSENT) {";
  const absentArm = between(catchRegion, absentAnchor, "} else {");
  // Above the ANCHOR's own length, not an arbitrary round number: `between`
  // returns a slice that STARTS WITH `from`, so a threshold at or below
  // `absentAnchor.length` (39) is satisfied by the anchor text alone, with an
  // empty arm body behind it - measured, deleting the whole arm body left this
  // check green. The real arm is currently ~260 characters; this only has to
  // clear the anchor by a wide margin to stop being vacuous.
  check(
    "the CREDENTIAL_STAMP_ABSENT arm was located",
    absentArm.length > absentAnchor.length + 40,
    absentArm.length,
  );
  check("a deleted record gets no recover-and-retry path", !absentArm.includes("findHost("));
  // The arm's own message, not a substring shared with its own anchor -
  // `absentArm.includes("CREDENTIAL_STAMP_ABSENT")` is true of the anchor text
  // by construction and asserts nothing about the code after it. Checked
  // against the ACTUAL wording so a regression back to the old, false claim -
  // "saving again would create a different host" - fails here rather than only
  // reading wrong in the running app.
  check(
    "its message says a retry is refused, not that a retry creates something new",
    /pressing Save again will not help/.test(absentArm) &&
      !/create a different host/.test(absentArm),
  );

  // Raw, not stripped, and scoped through the raw `save` for the same
  // not-unique-anchor reason above.
  const catchRegionRaw = between(saveRaw, "} catch (e) {", "} finally {");
  check("the raw catch region was located", catchRegionRaw.length > 40, catchRegionRaw.length);

  // The recovery arm - the FINAL `else { ... }`, past the ABSENT arm above -
  // located the same anchored way and taken from BOTH the stripped and the raw
  // region, because the positive and negative checks below need different text.
  // Bundling them onto one region forces one of the two onto the wrong text:
  // the positive check ("does this call exist") has to run where a call parked
  // behind a `//` comment does not count as present, which only the STRIPPED
  // region gives; the negative checks ("is this call ABSENT") have to run
  // where a call pasted back in cannot hide behind its own comment, which only
  // the RAW region gives. Measured: with the recovery region collapsed onto raw
  // text alone, commenting out both `setExisting(fresh)` calls left "recovery
  // refreshes the record" passing, because the comment above them still
  // contained the word `setExisting`.
  const recoveryMarker = "} else {";
  const recoveryAt = catchRegion.indexOf(recoveryMarker);
  check("the recovery arm's opening brace was found", recoveryAt >= 0, recoveryAt);
  const recoveryArm = catchRegion.slice(recoveryAt + recoveryMarker.length);
  check("the recovery arm has a body", recoveryArm.length > 100, recoveryArm.length);

  const recoveryAtRaw = catchRegionRaw.indexOf(recoveryMarker);
  check("the raw recovery arm's opening brace was found", recoveryAtRaw >= 0, recoveryAtRaw);
  const recoveryArmRaw = catchRegionRaw.slice(recoveryAtRaw + recoveryMarker.length);

  check("recovery refreshes the record", recoveryArm.includes("setExisting("));

  // 6a (re-aim, §1.10): VLT-29's fix added a SECOND write to this arm -
  // `setSshCred`/`setRdpCred`, gated on the refreshed record having just
  // become inline where the loaded one was not - and the flat forbidden list
  // this section used to run named both calls unconditionally, so step 4's
  // correct, gated write reddened it. The list below drops those two names
  // and the three checks after it replace the flat ban with what the gate
  // actually has to be: present, lexically inside a branch that names the
  // refreshed record's credential kind, and writing nothing but `""`.
  const stillForbidden = [
    "getHostSshSecrets(",
    "sshSeeded.current =",
    "sshTouched.current =",
    "setPins(",
    "setPresetId(",
    "setProxyJumpId(",
    "setTunnelSshHostId(",
    "setReady(",
    "onClose(",
    "setShared(",
  ];
  check(
    "and touches nothing else - not the pin map, not the seed/touch records, not the dialog itself",
    !stillForbidden.some((s) => recoveryArmRaw.includes(s)),
    stillForbidden.filter((s) => recoveryArmRaw.includes(s)),
  );

  // Parsed as its own fragment (compiler API - `parseFragment`), over the RAW
  // arm: a call parked behind a `//` comment or a dead branch must still fail
  // the negative above (§4.33), but the structural checks below need real
  // nodes to walk, which only the raw, uncommented text reliably parses as
  // (stripComments's line filter can turn a multi-line call into invalid
  // syntax if a comment sits mid-expression).
  const recoveryFrag = parseFragment(recoveryArmRaw);

  const armSetExisting = findCalls(recoveryFrag, recoveryFrag, ["setExisting"]);
  check(
    "the arm calls setExisting exactly once (compiler API)",
    armSetExisting.length === 1,
    armSetExisting.length,
  );
  if (armSetExisting.length === 1) {
    const arg = armSetExisting[0].arguments[0];
    check(
      "and it is given exactly `fresh` - not a value rebuilt here that could carry a stale field back (§4.47)",
      arg !== undefined && norm(arg.getText(recoveryFrag)) === norm("fresh"),
      arg?.getText(recoveryFrag),
    );
  }

  // N1's own guard: a branch that no longer EXISTS must not read as a branch
  // with nothing forbidden in it - the seed calls have to be found, not
  // merely absent-and-therefore-vacuously-fine.
  const armSeedCalls = findCalls(recoveryFrag, recoveryFrag, ["setSshCred", "setRdpCred"]);
  check(
    "the arm's conditional reseed (§1.10) is present - both the SSH and the RDP call - so the branch below is not asserting over an absent one",
    armSeedCalls.length === 2,
    armSeedCalls.length,
  );
  for (const call of armSeedCalls) {
    const conds = ifConditionsEnclosing(call, recoveryFrag);
    check(
      `${call.expression.getText(recoveryFrag)}( sits inside a branch naming the refreshed record's credential kind, resolved lexically rather than by distance (§4.17)`,
      conds.some((c) => /credential\.kind/.test(c)),
      conds,
    );
  }

  // Every `password:` / `privateKey:` / `keyPassphrase:` property literal in
  // the arm, parsed - not a regex on the text, which cannot tell a real
  // assignment from the same words in a comment or a shorthand property bound
  // to something else.
  const armSecretProps = findObjectLiteralProperties(recoveryFrag, [...SECRET_FIELDS]);
  check(
    "the arm writes at least one secret field, so the check below is not vacuous",
    armSecretProps.length > 0,
    armSecretProps.length,
  );
  for (const prop of armSecretProps) {
    check(
      `${prop.name.getText(recoveryFrag)} is written as the empty string, never a real value`,
      ts.isStringLiteral(prop.initializer) && prop.initializer.text === "",
      prop.initializer.getText(recoveryFrag),
    );
  }

  check(
    "the error text tells the user their edits survived",
    /edits are still here/.test(catchRegion),
  );
}

// ---------------------------------------------------------------------------
console.log(
  "\n[9] the credential picker: options from the prop, moves behind one confirmed action",
);
{
  // -------------------------------------------------------------------------
  // 6b.1: the options come from the `identityRows` PROP, never a vault
  // subscription of this dialog's own - and the page's own prop wiring is
  // pinned too (VLT-76's pin-3 shape), so an unfiltered list feeding the
  // picker cannot quietly become the page's filtered `visible` rows.
  // -------------------------------------------------------------------------
  check(
    "the dialog holds no vault subscription of its own",
    !/useVault\(/.test(editorRaw) && !/listIdentities\(/.test(editorRaw),
    { useVault: /useVault\(/.test(editorRaw), listIdentities: /listIdentities\(/.test(editorRaw) },
  );

  const identityOptionsDecl = findVariableDeclaration(editorSf, "identityOptions");
  check("identityOptions's declaration was found (compiler API)", identityOptionsDecl !== null);
  if (identityOptionsDecl?.initializer) {
    const init = identityOptionsDecl.initializer;
    check(
      "the picker's options are built by mapping the identityRows PROP, not a store read of this file's own",
      ts.isCallExpression(init) &&
        ts.isPropertyAccessExpression(init.expression) &&
        init.expression.name.text === "map" &&
        ts.isIdentifier(init.expression.expression) &&
        init.expression.expression.text === "identityRows",
      init.getText(editorSf),
    );
  }

  const editorOpeningEls = findOpeningElementsByTag(hostsPageSf, "HostEditorDialog", hostsPageSf);
  check(
    "HostsPage renders exactly one HostEditorDialog",
    editorOpeningEls.length === 1,
    editorOpeningEls.length,
  );
  if (editorOpeningEls.length === 1) {
    const prop = jsxAttrExprText(editorOpeningEls[0], "identityRows", hostsPageSf);
    check(
      "and hands it identityRows={identityRowList} - the page's own unfiltered list",
      prop === "identityRowList",
      prop,
    );
  }

  const identityRowListDecl = findVariableDeclaration(hostsPageSf, "identityRowList");
  check("identityRowList's declaration was found (compiler API)", identityRowListDecl !== null);
  if (identityRowListDecl?.initializer) {
    const init = identityRowListDecl.initializer;
    check(
      "identityRowList is a useMemo(...)",
      ts.isCallExpression(init) &&
        ts.isIdentifier(init.expression) &&
        init.expression.text === "useMemo",
      init.getText(hostsPageSf),
    );
    if (ts.isCallExpression(init) && init.arguments[0]) {
      const factoryText = init.arguments[0].getText(hostsPageSf);
      check(
        "and its initializer calls identityRows(",
        /\bidentityRows\(/.test(factoryText),
        factoryText,
      );
      // VLT-76's pin-3 shape: the check that stops the picker following the
      // page's own search box - a memo built off `visible` (the filtered,
      // ranked rows) or re-derived from `query` would still satisfy every
      // check above while quietly narrowing what the picker can offer.
      check(
        "and names neither `visible` nor `query` - the fix would otherwise follow the search box",
        !/\bvisible\b/.test(factoryText) && !/\bquery\b/.test(factoryText),
        factoryText,
      );
    }
  }

  // -------------------------------------------------------------------------
  // 6b.2: the three movers are called only from applyCredentialChange's body -
  // compiler-API containment, not distance, per §4.17.
  // -------------------------------------------------------------------------
  const applyBody = findConstArrowBody(editorSf, "applyCredentialChange");
  check("applyCredentialChange's body was found (compiler API)", applyBody !== null);

  const MOVER_NAMES = ["convertHostToVault", "bindHostToIdentity", "detachHostFromVault"];
  const allMoverCalls = findCalls(editorSf, editorSf, MOVER_NAMES);
  check(
    "each of the three movers is called at least once",
    MOVER_NAMES.every((name) => allMoverCalls.some((c) => c.expression.getText(editorSf) === name)),
    allMoverCalls.map((c) => c.expression.getText(editorSf)),
  );
  if (applyBody) {
    const insideBody = findCalls(applyBody, editorSf, MOVER_NAMES);
    check(
      "and EVERY call to any of them is lexically inside applyCredentialChange's body - a call just past its closing brace does not count as inside (§4.17)",
      allMoverCalls.length === insideBody.length,
      { total: allMoverCalls.length, inside: insideBody.length },
    );
  }

  // -------------------------------------------------------------------------
  // 6b.3 / addendum note 1: `setExisting` takes what the write returned, in
  // each of the three arms - pinned exactly, whitespace aside, because
  // `{ ...result.host, name: shared.name }` type-checks and would carry a
  // stale field back into the stamp, and a substring cannot tell it from the
  // right thing (§4.47). `norm()` strips ALL whitespace before comparing, so
  // this pin is its own §4.51 reformat pair - wrapping either side across
  // lines changes nothing it compares.
  // -------------------------------------------------------------------------
  const CHANGE_ARMS = [
    { kind: "convert", pin: "result.host" },
    { kind: "bind", pin: "saved" },
    { kind: "detach", pin: "result.host" },
  ] as const;
  if (applyBody) {
    for (const { kind, pin } of CHANGE_ARMS) {
      const ifStmt = findIfByCondition(applyBody, editorSf, `change.kind === "${kind}"`);
      check(`the ${kind} branch was found (compiler API)`, ifStmt !== null);
      if (!ifStmt) continue;
      const setExistingCalls = findCalls(ifStmt.thenStatement, editorSf, ["setExisting"]);
      check(
        `the ${kind} branch calls setExisting exactly once`,
        setExistingCalls.length === 1,
        setExistingCalls.length,
      );
      if (setExistingCalls.length === 1) {
        const arg = setExistingCalls[0].arguments[0];
        check(
          `and ${kind}'s setExisting is given exactly \`${pin}\` - the write's own result, whitespace-normalised only`,
          arg !== undefined && norm(arg.getText(editorSf)) === norm(pin),
          arg?.getText(editorSf),
        );
      }
    }
  }

  // -------------------------------------------------------------------------
  // 6b.4: the action is behind a confirmation.
  // -------------------------------------------------------------------------
  const applyCalls = findCalls(editorSf, editorSf, ["applyCredentialChange"]);
  check("applyCredentialChange is called exactly once", applyCalls.length === 1, applyCalls.length);
  if (applyCalls.length === 1) {
    check(
      "and only from inside an AlertDialogAction element",
      findAncestorJsxElementByTag(applyCalls[0], "AlertDialogAction", editorSf),
    );
  }
  const alertDialogEls = findOpeningElementsByTag(editorSf, "AlertDialog", editorSf);
  check("exactly one AlertDialog element", alertDialogEls.length === 1, alertDialogEls.length);
  if (alertDialogEls.length === 1) {
    const openExpr = jsxAttrExprText(alertDialogEls[0], "open", editorSf);
    check(
      "and its open attribute is a literal expression naming pendingChange",
      openExpr !== null && /\bpendingChange\b/.test(openExpr),
      openExpr,
    );
  }

  // -------------------------------------------------------------------------
  // 6b.5: the detach arm seeds no secret.
  // -------------------------------------------------------------------------
  const detachIf = applyBody
    ? findIfByCondition(applyBody, editorSf, 'change.kind === "detach"')
    : null;
  check("the detach branch was found (compiler API)", detachIf !== null);
  if (detachIf) {
    const detachBlock = detachIf.thenStatement;
    const detachSeedCalls = findCalls(detachBlock, editorSf, ["setSshCred", "setRdpCred"]);
    check(
      "the detach branch reseeds the draft via setSshCred/setRdpCred",
      detachSeedCalls.length > 0,
      detachSeedCalls.length,
    );
    const detachSecretProps = findObjectLiteralProperties(detachBlock, [...SECRET_FIELDS]);
    check(
      "the detach branch writes at least one secret field, so the check below is not vacuous",
      detachSecretProps.length > 0,
      detachSecretProps.length,
    );
    for (const prop of detachSecretProps) {
      check(
        `detach's ${prop.name.getText(editorSf)} is seeded with the empty string, never a value`,
        ts.isStringLiteral(prop.initializer) && prop.initializer.text === "",
        prop.initializer.getText(editorSf),
      );
    }
    const detachText = detachBlock.getText(editorSf);
    check(
      "and marks nothing touched or seeded - a later blank Save must not be licensed to clear what detachHostFromVault just copied",
      !/sshSeeded\.current =/.test(detachText) && !/sshTouched\.current =/.test(detachText),
      detachText,
    );
  }

  // -------------------------------------------------------------------------
  // Addendum check 2 (A1, 2026-09-01): the draft arm is create-gated.
  //
  // Section [4]'s six checks count three patterns keyed on the identifier
  // `boundIdentity` inside `save`'s own text - they stay green under this
  // wave because `save()` is genuinely unchanged, but that also means they
  // cannot see WHERE `boundIdentity` comes from. This pin - and the two
  // checks after it - are where that claim actually lives: `save()` staying
  // untouched is the check that widening `boundIdentity` did not drag `save`
  // along with it, not a check on the widening itself.
  // -------------------------------------------------------------------------
  const boundIdentityDecl = findVariableDeclaration(editorSf, "boundIdentity");
  check("boundIdentity's declaration was found (compiler API)", boundIdentityDecl !== null);
  if (boundIdentityDecl?.initializer) {
    const init = boundIdentityDecl.initializer;
    // Pin 1: the WHOLE definition, whitespace aside. Whitespace is Prettier's;
    // everything else here IS the claim (§4.51) - N17 reflows this same
    // expression and must stay green under it.
    const pinnedText =
      'mode === "create"\n' +
      "    ? identityIdFromChoice(choice)\n" +
      '    : existing && existing.credential.kind === "identity"\n' +
      "      ? existing.credential.identityId\n" +
      "      : null";
    check(
      "boundIdentity's definition is exactly this expression, whitespace aside",
      norm(init.getText(editorSf)) === norm(pinnedText),
      init.getText(editorSf),
    );

    const idChoiceCalls = findCalls(init, editorSf, ["identityIdFromChoice"]);
    check(
      "boundIdentity's definition calls identityIdFromChoice exactly once",
      idChoiceCalls.length === 1,
      idChoiceCalls.length,
    );
    if (idChoiceCalls.length === 1) {
      const arm = conditionalArmOf(idChoiceCalls[0]);
      check(
        'the identityIdFromChoice(choice) arm is reached only under a condition naming mode === "create" - never by adjacency (§4.17)',
        arm !== null &&
          arm.arm === "then" &&
          /mode === "create"/.test(arm.cond.condition.getText(editorSf)),
        arm ? { arm: arm.arm, cond: arm.cond.condition.getText(editorSf) } : null,
      );
      if (arm) {
        check(
          "and the other arm reads existing's own stored credential, not another draft value",
          /existing[\s\S]*\.credential/.test(arm.cond.whenFalse.getText(editorSf)),
          arm.cond.whenFalse.getText(editorSf),
        );
      }
    }
  }

  // -------------------------------------------------------------------------
  // Addendum check 3 (A1): the convert option is edit-mode only. Supersedes
  // 6b.6 as literally written ("the picker is edit-mode only") - amendment A1
  // supersedes plan §0's "no picker in create mode", and the committed
  // `HostEditorDialog.tsx` renders the whole `Field label="Credential"` in
  // BOTH modes (its own comment says so); only this ONE option inside it is
  // edit-mode gated. Checking the superseded 6b.6 literally would redden
  // against the correct, committed code, so this is the check that replaces
  // it rather than one added beside it.
  // -------------------------------------------------------------------------
  const hostEditorFnBody = findFunctionBody(editorSf, "HostEditorDialog");
  check("HostEditorDialog's function body was found (compiler API)", hostEditorFnBody !== null);
  if (hostEditorFnBody) {
    const newIdentityRefs = findIdentifierUses(hostEditorFnBody, "CREDENTIAL_CHOICE_NEW_IDENTITY");
    check(
      "CREDENTIAL_CHOICE_NEW_IDENTITY is used exactly once inside the component",
      newIdentityRefs.length === 1,
      newIdentityRefs.length,
    );
    if (newIdentityRefs.length === 1) {
      const arm = conditionalArmOf(newIdentityRefs[0]);
      check(
        'it is offered only under a condition naming mode === "edit" - the other picker option is not (amendment A1)',
        arm !== null &&
          arm.arm === "then" &&
          /mode === "edit"/.test(arm.cond.condition.getText(editorSf)),
        arm ? { arm: arm.arm, cond: arm.cond.condition.getText(editorSf) } : null,
      );
    }
  }

  // -------------------------------------------------------------------------
  // 6b.7: save() is unchanged, deliberately - section [4]'s six checks are
  // the check on that, and this comment exists so the next reader does not
  // read [4] as covering the picker's provenance too: it counts an
  // identifier, `boundIdentity`, and the three checks above this comment are
  // where that identifier's OWN provenance is actually pinned.
  //
  // 6b.8: the confirmation copy comes from the pure module.
  // -------------------------------------------------------------------------
  check(
    "the confirmation calls the pure module's title and note builders, not literals of its own",
    count(editorRaw, /credentialChangeTitle\(/g) >= 1 &&
      count(editorRaw, /credentialChangeNote\(/g) === 1,
    {
      titles: count(editorRaw, /credentialChangeTitle\(/g),
      notes: count(editorRaw, /credentialChangeNote\(/g),
    },
  );
  // The three note strings' own fixed text (no `${}` inside the fragment
  // chosen), so a literal copy pasted into the dialog instead of a call is
  // caught even though the dialog's title now ALSO comes from the same pure
  // module (no separate one-line-description string was added - see step 4's
  // own note on this).
  const NOTE_FRAGMENTS = [
    "move into a new shared identity, and the host stops owning them",
    "stops using its own stored credentials and authenticates as",
    "takes its own copy of that identity's stored secrets",
  ];
  for (const frag of NOTE_FRAGMENTS) {
    check(
      `the "${frag.slice(0, 28)}…" note string does not appear in the dialog itself`,
      !editorRaw.includes(frag),
    );
  }
}

console.log(failed === 0 ? "\nAll host-editor checks passed." : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
