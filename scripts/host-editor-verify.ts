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
 *    attempt. Gating the write on the saved address stopped it landing on the wrong
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
 *    Both protocols, since one save path now serves them.
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
 * 8. THE SAVE LOOKS AT THE KEY BODY BEFORE IT STORES ONE, AND SAYS SO IN THAT FIELD.
 *    It used to store whatever was in the textarea. An encrypted `openssh-key-v1`
 *    key pasted with a blank passphrase PARSES - the container answers with a type,
 *    a fingerprint and a public half without it - so the record came out with
 *    `hasPrivateKey: true`, complete-looking and unusable at every connect, and the
 *    card's own pip reads that flag alone. The vault key editor already refused
 *    exactly this, so the refusal is IMPORTED rather than restated: a second copy of
 *    that policy is how the two surfaces come to disagree at the next key-format
 *    finding, and only an import-set pin can tell a shared function from a duplicate
 *    with the same body - agreement-by-value cannot.
 *
 *    The refusal renders as the last child of the key field rather than in the
 *    bottom `error` line, because its sentence tells the user to enter the
 *    passphrase BELOW and the passphrase input is the next field down. The vault
 *    editor's version once rendered under the description field while saying those
 *    words, and that was a hand-tested defect. The bottom line still carries store
 *    refusals and keychain errors, which are about the form rather than one input.
 *
 *    The rule this replaces went the other way: "Private key body is required for
 *    key auth" refused the one key-auth state that is HONEST on the card
 *    (`hasPrivateKey: false` renders "Missing secret") and caught none of the states
 *    that are not. It is gone, exactly as the password rule was. The RDP
 *    password rule is deliberately NOT gone with it - `RdpPane` declines to connect
 *    at all without a password, so such a row's only reachable outcome is a failure.
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
  forgetKeyNote,
  forgetKeyRowLabel,
  hostKeySecretNames,
} from "../src/modules/hosts/editor/credentialChoice";
import {
  NOTHING_SEEDED,
  sshSecretsForSave,
  type SshSecretSeeded,
} from "../src/modules/hosts/editor/sshSecrets";
import {
  NO_SSH_SECRETS_TOUCHED,
  type SshCredentialDraft,
  type SshSecretTouched,
} from "../src/modules/hosts/editor/types";
import type { Host } from "../src/modules/hosts/types";

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
  // Fixed here per `vault-editor-verify.ts`'s own fix (found live against a
  // DIFFERENT file): without this, a mutation
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
 * the one that is still correct while reporting nothing about the new one. The
 * all-matches rule, which `expectedFingerprint` already follows in section [6] by asserting a
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
// Compiler-API helpers for section [9], and for section [8]'s re-aim.
// Copied from `vault-editor-verify.ts` / `vault-shell-verify.ts` where a
// helper of the same job already exists there, so this file's shape matches
// the rest of the suite rather than inventing a sixth way to do the same walk
// - a suite that spells one `check()` shape six ways is exactly this kind of
// drift, one level up. New helpers are ones neither file needed: `conditionalArmOf`,
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
 *  choice is not the claim. The ONLY normalisation applied before an
 *  exact-text pin compares two sides. */
function norm(s: string): string {
  return s.replace(/\s+/g, "");
}

/**
 * A call's ARGUMENTS as their own normalised source text.
 *
 * Argument by argument rather than "the whole call's text, whitespace aside",
 * and that is not a style preference: Prettier ADDS A TRAILING COMMA when it
 * breaks a call across lines, and `norm()` does not remove one, so a
 * whole-call pin is width-sensitive - it reddens on a legal reformat while
 * claiming to be about the arguments. Measured: at `--print-width 60` both
 * calls in section [10] wrapped and both whole-call pins went red over
 * unchanged code. An argument's own text carries no separator, so this form is
 * the reformat pair the pin needs. `vault-editor-verify.ts` pins the same call
 * this way.
 */
function argTexts(call: ts.CallExpression, sf: ts.SourceFile): string[] {
  return call.arguments.map((a) => norm(a.getText(sf)));
}

/** The `let`/`const` variable declaration named `name` anywhere under `root`.
 *
 *  IT RETURNS THE LAST ONE, because `result` is overwritten on every match, and
 *  a caller that roots this at the whole SourceFile is therefore pinning
 *  whichever declaration traversal reaches last. For a pin that is the ONLY
 *  guard on a rule, that is defeatable by appending a decoy - see
 *  {@link findVariableDeclarations} and section [9]'s `boundIdentity` block. */
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

/**
 * EVERY `let`/`const` declaration named `name` under `root`, so a caller can
 * assert how many there are instead of silently taking the last.
 *
 * The singular above answers "show me one", which is a different question from
 * "is there exactly one, and is it the one I mean". An executed
 * evasion is the difference: with a real break applied to `boundIdentity`
 * inside the component AND an `export function resolveBoundIdentity(...)`
 * appended below it whose body declares `boundIdentity` with the pinned
 * expression verbatim, the singular helper returned the DECOY, the exact-text
 * pin compared it against itself, and `tsc`, this file (211/211) and
 * `pnpm verify` (53/53) all stayed green over a host that silently detaches.
 *
 * Two things close it, and both are needed: ROOT the search at the component's
 * own body, which excludes a decoy declared outside it, and ASSERT THE COUNT,
 * which excludes one declared inside. Both were re-run against the fix and both
 * redden, `tsc` staying at 0 for each:
 *
 *   B1  the break + `export function resolveBoundIdentity` below the component
 *         -> "boundIdentity's definition is exactly this expression, whitespace
 *            aside" and the `mode === "create"` arm check. Caught by the ROOTING;
 *         the count stays 1, because the decoy is outside the body.
 *   B1b the break + the same decoy as a nested arrow INSIDE the component, which
 *       rooting cannot exclude
 *         -> "boundIdentity is declared EXACTLY ONCE ... = 2". Caught by the
 *            COUNT alone.
 */
function findVariableDeclarations(root: ts.Node, name: string): ts.VariableDeclaration[] {
  const out: ts.VariableDeclaration[] = [];
  const visit = (n: ts.Node): void => {
    if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.name.text === name) {
      out.push(n);
    }
    ts.forEachChild(n, visit);
  };
  visit(root);
  return out;
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

/** Every `import ... from "x"` declaration at the top level of `sf`.
 *
 *  Parsed rather than regexed. `vault-draft-verify.ts`'s proven form scans
 *  `/from\s*["']([^"']+)["']/g` over the source, which also matches an
 *  `export ... from` re-export and any string literal that happens to contain
 *  ` from "` - neither is an import, and a check that counts them is asserting
 *  something other than what it says. */
function importDeclarations(sf: ts.SourceFile): ts.ImportDeclaration[] {
  const out: ts.ImportDeclaration[] = [];
  sf.forEachChild((n) => {
    if (ts.isImportDeclaration(n)) out.push(n);
  });
  return out;
}

/** A declaration's module specifier text, or "" for the non-literal form no
 *  static import actually uses. */
function moduleSpecifierOf(decl: ts.ImportDeclaration): string {
  return ts.isStringLiteral(decl.moduleSpecifier) ? decl.moduleSpecifier.text : "";
}

/** The NAMES a declaration takes from its module - `import { a, b as c }`
 *  yields `["a", "b"]`, the names as the exporting module spells them, so a
 *  local rename cannot make the pin below pass over a different export. */
function namedImportsOf(decl: ts.ImportDeclaration): string[] {
  const bindings = decl.importClause?.namedBindings;
  if (!bindings || !ts.isNamedImports(bindings)) return [];
  return bindings.elements.map((e) => (e.propertyName ?? e.name).text);
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

/** An element's own JSX children with whitespace-only text dropped, so "the
 *  LAST child" means the last thing rendered rather than the newline and
 *  indentation Prettier put after it. A `{/* ... *\/}` comment IS kept: it is a
 *  real child node, and one left behind as the last child by a render that
 *  moved away is exactly the state the caller must not read as a pass. */
function renderedChildren(el: ts.JsxElement, sf: ts.SourceFile): ts.JsxChild[] {
  return el.children.filter((c) => !(ts.isJsxText(c) && c.getText(sf).trim() === ""));
}

/** Every reference to `ident` under `root` that sits inside JSX at all - i.e.
 *  has a `{...}` expression somewhere above it. Counting JSX EXPRESSIONS
 *  instead does not work: a `{...}` node's own text contains every nested one,
 *  so the enclosing `{ready ? <>…</> : null}` matches whatever any descendant
 *  names. An identifier has exactly one position, which is the question. */
function jsxUsesOf(root: ts.Node, ident: string): ts.Identifier[] {
  return findIdentifierUses(root, ident).filter((id) => {
    for (let n: ts.Node | undefined = id.parent; n; n = n.parent) {
      if (ts.isJsxExpression(n)) return true;
    }
    return false;
  });
}

/** Whether `node` sits inside a `foo={...}` attribute value - which PASSES a
 *  string to a child rather than rendering one, the opposite claim. */
function insideJsxAttribute(node: ts.Node): boolean {
  for (let n: ts.Node | undefined = node.parent; n; n = n.parent) {
    if (ts.isJsxAttribute(n)) return true;
  }
  return false;
}

/**
 * The NEAREST `{ … }` block `node` sits in, or null.
 *
 * Section [12] needs it to ask about ORDER: "the intent is retired above the arm
 * that re-seeds the auth mode" is a question about which statement comes first in
 * one block, and a presence check passes with the two swapped. Nearest rather
 * than outermost, or every statement in the component would answer with the
 * component's own body and every order would look the same.
 */
function enclosingBlock(node: ts.Node): ts.Block | null {
  for (let n: ts.Node | undefined = node.parent; n; n = n.parent) {
    if (ts.isBlock(n)) return n;
  }
  return null;
}

/** Whether `ancestor` is on `node`'s parent chain. */
function isDescendantOf(node: ts.Node, ancestor: ts.Node): boolean {
  for (let n: ts.Node | undefined = node.parent; n; n = n.parent) {
    if (n === ancestor) return true;
  }
  return false;
}

/**
 * Walking UP from `node`, the nearest ConditionalExpression ancestor together
 * with which arm the walk left through - "then" for `whenTrue`, "else" for
 * `whenFalse`; `null` once the walk runs out of parents.
 *
 * This resolves nesting through the AST rather than by scanning for the
 * nearest `?`/`:` in the text: `mode === "create" ?
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
 *  away the text sits, which is what section [8]'s re-aim needs:
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

// Parsed once, for section [9]'s compiler-API checks. The precedent is
// `vault-editor-verify.ts` and `pane-caret-verify.ts`,
// both already on `typescript` for exactly this reason: "is this call
// lexically inside X" is a nesting question a distance heuristic answers
// wrong. `ScriptKind.TSX` on both, since either file's JSX would
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
// Section [10] asks WHERE a string renders, which is a JSX nesting question:
// "is this expression the last child of the Field labelled X" cannot be asked
// of the text, and asserting the string merely appears in the file is exactly
// what a render move walks past.
const sshSectionSf = ts.createSourceFile(
  "SshCredentialSection.tsx",
  sshSectionRaw,
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
  // The only comment syntax legal inside JSX children, and the one the
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
  // The OVER-strip direction, which is the one that actually
  // shipped broken and which no stripper self-test in this suite covers - every
  // other one asserts only that a comment was removed. The original lazy form
  // `\{\s*\/\*[\s\S]*?\*\/\s*\}` swallowed 50752 characters of
  // `HostEditorDialog.tsx`, because `HostEditorDialogProps`' own `{ /** null =
  // closed. */ target: … }` type literal opens with `{` immediately followed by
  // `/*` and has no `}` after its `*/`: the lazy group kept extending past
  // every later `*/` until it found one that WAS followed by `}`, eating `save`
  // and everything sections [4]/[7]/[8] anchor on. One probe carries both
  // shapes - the type literal on line 1 and a real JSX comment on line 3 - so
  // one string tests both directions at once.
  const STRIPPER_PROBE =
    "type P = { /** c */ x: X };\nconst KEEP = 1;\nconst j = <div>{/* c */}</div>;";
  check(
    "stripComments does not OVER-strip: a `{ /** … */ …` type literal does not eat the code after it",
    stripComments(STRIPPER_PROBE).includes("KEEP"),
    stripComments(STRIPPER_PROBE),
  );
  // Worded as "no `{/*` survives" rather than "no `c` survives", because the
  // `/** c */` on line 1 would satisfy the latter without the JSX comment on
  // line 3 having been touched at all.
  check(
    "and does not UNDER-strip: no JSX comment expression survives it",
    !stripComments(STRIPPER_PROBE).includes("{/*"),
    stripComments(STRIPPER_PROBE),
  );
  check("the editor survived it", editorSrc.includes("export function HostEditorDialog("));
  check("and it removed something", editorSrc.length < editorRaw.length);

  check(
    "assignedIn reports what a local was assigned",
    assignedIn("const a = b?.c;", "a") === "b?.c",
  );
  check("and nothing for a local it cannot find", assignedIn("const a = b;", "z") === "");

  // `enclosingBlock`, which section [12] asks an ORDER question of. The probe
  // carries the one way it can be wrong: returning the outermost block instead
  // of the nearest would report the fragment's own body, whose statement count
  // is deliberately different here, and every order in the file would then look
  // the same.
  {
    const sf = parseFragment("if (a) { first(); } second(); third(); }");
    const inner = findCalls(sf, sf, ["first"])[0];
    const block = inner === undefined ? null : enclosingBlock(inner);
    check(
      "enclosingBlock returns the NEAREST block a statement sits in, not the function body around it",
      block !== null && block.statements.length === 1,
      block === null ? null : block.statements.length,
    );
    const outer = findCalls(sf, sf, ["second"])[0];
    const outerBlock = outer === undefined ? null : enclosingBlock(outer);
    check(
      "and the enclosing body for one that sits directly in it",
      outerBlock !== null && outerBlock.statements.length === 3,
      outerBlock === null ? null : outerBlock.statements.length,
    );
  }
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
  // the whole lesson is about what a value read in the wrong place says.
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
  // a rule about VALUES, whose first failure shape is this: it cannot tell `""`
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
      // The forget-key intent is OFF for every row of this table, which is what
      // makes the table the evidence that it changed nothing: the three-state
      // rule above is unaltered, and the override lives in section [12].
      const out = sshSecretsForSave(
        draft(row.value),
        { ...all(false), [f]: row.touched },
        row.seeded ? only(f) : NOTHING_SEEDED,
        false,
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
    const out = sshSecretsForSave(draft(""), all(true), only("password"), false);
    check(
      "a seeded password authorises clearing the password and nothing else",
      "password" in out && out.password === "" && !("privateKey" in out),
      out,
    );
    check("nor the key passphrase", !("keyPassphrase" in out), out);
  }

  // A fourth field added to the draft cannot arrive by spread.
  {
    const out = sshSecretsForSave(draft("v"), all(true), NOTHING_SEEDED, false);
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
  // BOTH live records. Reading either from state instead is that defect wearing
  // the fix's shape, and a stale seeded record is the same fault one field over -
  // it would license a clear the user could not see, which is the whole finding.
  // The fourth argument is section [12]'s, and it is pinned there over the
  // parsed call as well - argument by argument, which is the form this
  // line-shaped regex is not. Named here too because this is the check that
  // would otherwise have gone quietly green over three arguments and a dropped
  // intent.
  check(
    "the SSH secrets are taken from the live touched AND seeded records, plus the forget-key intent",
    /sshSecretsForSave\(sshCred, \w+\.current, \w+\.current, forgetKey\)/.test(save),
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
  // the guard. Gating it on the saved address closed the case where a
  // cancelled dialog left a FOREIGN machine's fingerprint on a record - the next
  // real connect aborts as a MISMATCH, which reads as an attack. It did not close
  // the case where the write lands on the address the record does name: Forget (a
  // draft edit) removes the pin from `pins`, so Test TOFUs instead of raising the
  // mismatch the pin existed for, accepting overwrites the STORED pin because the
  // addresses agree, and Cancel leaves that in place with nothing warned. The write
  // the gate permitted was the destructive one. With no write here, both cases are
  // closed by construction and the question - does this survive Cancel, and
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
  // list satisfies `every`.
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
  // `Forget` used to call `clearFingerprint` straight through, so Cancel
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

  // Test must verify against the machine it is ACTUALLY DIALLING, or a
  // re-pointed host cannot be tested without destroying its pin first - which is
  // what made the Forget-then-Cancel loss above reachable.
  const runTest = between(editorSrc, "const runTest = async () => {", "const save = async () => {");
  const expected = [
    ...runTest.matchAll(/expected(?:Cert)?Fingerprint: (\w+)\[(\w+)\] \|\| undefined/g),
  ];
  // BOTH protocol arms. One `indexOf` here would have examined the SSH branch only
  // while this file's header claimed it covered both.
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

  // Extended to `credentialMove.ts` and `editor/credentialChoice.ts` - a
  // sibling risk, not comments this
  // time: these two are now where a sentence about a stored private key is
  // most likely to be written (the convert/bind/detach confirmations), and
  // the vault files already hold the wording rule below
  // (`vault-shell-verify.ts`'s section 12).
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
  // All five files, `HostEditorDialog.tsx` included: its module header was
  // reworded to the vault convention that phrases this disclaimer AROUND the
  // ban ("Nothing here protects a secret better than it was protected
  // before", per `vault/page/IdentityCard.tsx:14-16`) rather than the sweep
  // being narrowed to fit the one file most likely to grow a safety claim.
  // `Encrypted` is deliberately not forbidden - the key panel says it
  // about a locked key, truthfully, and that is a different claim
  // (`vault-shell-verify.ts`'s section 12 carries the same note).
  for (const [path, src] of KEYCHAIN_SWEEP_FILES) {
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
  // A string the component cannot reach is the same as no string at all.
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

  // The recovery fix added a SECOND write to this arm -
  // `setSshCred`/`setRdpCred`, gated on the refreshed record having just
  // become inline where the loaded one was not - and the flat forbidden list
  // this section used to run named both calls unconditionally, so that
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
  // the negative above, but the structural checks below need real
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
      "and it is given exactly `fresh` - not a value rebuilt here that could carry a stale field back",
      arg !== undefined && norm(arg.getText(recoveryFrag)) === norm("fresh"),
      arg?.getText(recoveryFrag),
    );
  }

  // N1's own guard: a branch that no longer EXISTS must not read as a branch
  // with nothing forbidden in it - the seed calls have to be found, not
  // merely absent-and-therefore-vacuously-fine.
  const armSeedCalls = findCalls(recoveryFrag, recoveryFrag, ["setSshCred", "setRdpCred"]);
  check(
    "the arm's conditional reseed is present - both the SSH and the RDP call - so the branch below is not asserting over an absent one",
    armSeedCalls.length === 2,
    armSeedCalls.length,
  );
  for (const call of armSeedCalls) {
    const conds = ifConditionsEnclosing(call, recoveryFrag);
    check(
      `${call.expression.getText(recoveryFrag)}( sits inside a branch naming the refreshed record's credential kind, resolved lexically rather than by distance`,
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
  // The options come from the `identityRows` PROP, never a vault
  // subscription of this dialog's own - and the page's own prop wiring is
  // pinned at its DEFINITION too, so an unfiltered list feeding the
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
      // Pinned at its definition: the check that stops the picker following the
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
  // The three movers are called only from applyCredentialChange's body -
  // compiler-API containment, not distance.
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
      "and EVERY call to any of them is lexically inside applyCredentialChange's body - a call just past its closing brace does not count as inside",
      allMoverCalls.length === insideBody.length,
      { total: allMoverCalls.length, inside: insideBody.length },
    );
  }

  // -------------------------------------------------------------------------
  // `setExisting` takes what the write returned, in
  // each of the three arms - pinned exactly, whitespace aside, because
  // `{ ...result.host, name: shared.name }` type-checks and would carry a
  // stale field back into the stamp, and a substring cannot tell it from the
  // right thing. `norm()` strips ALL whitespace before comparing, so
  // this pin is its own reformat control - wrapping either side across
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
  // The action is behind a confirmation.
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
  // The detach arm seeds no secret.
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
  // The draft arm is create-gated.
  //
  // Section [4]'s six checks count three patterns keyed on the identifier
  // `boundIdentity` inside `save`'s own text - they stay green under this
  // wave because `save()` is genuinely unchanged, but that also means they
  // cannot see WHERE `boundIdentity` comes from. This pin - and the two
  // checks after it - are where that claim actually lives: `save()` staying
  // untouched is the check that widening `boundIdentity` did not drag `save`
  // along with it, not a check on the widening itself.
  // -------------------------------------------------------------------------
  // Rooted at the COMPONENT'S OWN BODY, not the SourceFile, and counted.
  // `findVariableDeclaration` returns the LAST match in traversal order, so the
  // SourceFile-rooted version of this pin compared a decoy against itself while
  // the real `boundIdentity` was broken - that evasion was run and got
  // 211/211 here and 53/53 from `pnpm verify`. See
  // {@link findVariableDeclarations} for the full transcript of the evasion.
  // The count is the other half: rooting alone still admits a second
  // declaration added INSIDE the component.
  const hostEditorFnBody = findFunctionBody(editorSf, "HostEditorDialog");
  check("HostEditorDialog's function body was found (compiler API)", hostEditorFnBody !== null);
  const boundIdentityDecls = hostEditorFnBody
    ? findVariableDeclarations(hostEditorFnBody, "boundIdentity")
    : [];
  check(
    "boundIdentity is declared EXACTLY ONCE inside the component - a second declaration anywhere is what lets this pin compare a decoy against itself",
    boundIdentityDecls.length === 1,
    boundIdentityDecls.length,
  );
  const boundIdentityDecl = boundIdentityDecls.length === 1 ? boundIdentityDecls[0] : null;
  check("boundIdentity's declaration was found (compiler API)", boundIdentityDecl !== null);
  if (boundIdentityDecl?.initializer) {
    const init = boundIdentityDecl.initializer;
    // Pin 1: the WHOLE definition, whitespace aside. Whitespace is Prettier's;
    // everything else here IS the claim - a legal reflow of this same
    // expression must leave it green.
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
        'the identityIdFromChoice(choice) arm is reached only under a condition naming mode === "create" - never by adjacency',
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
  // Pin 1: the create arm RESETS `choice` to the inline sentinel, and
  // does so on the path that `return`s before the edit arm's own reset.
  //
  // The three checks above pin where `boundIdentity` READS `choice`. Nothing
  // pinned where `choice` is WRITTEN per target, and `choice` is component
  // state that survives a close - the load effect returns at `if (!target ||
  // !token)` without resetting anything. So with this one statement deleted:
  // edit a vault-bound host, close, press New host, and `boundIdentity` is
  // still the previous sitting's identity id; `save()` then writes a
  // `{kind:"identity"}` record and DISCARDS the password the user typed.
  // Measured with the statement deleted: `tsc` 0, this file 212/212,
  // `pnpm verify` 53/53. The line is correct in shipped code; what was
  // missing was anything holding it there.
  //
  // Rooted at `load`'s own body and then counted, per
  // {@link findVariableDeclarations}: rooting excludes a decoy appended
  // outside the effect, the count excludes a second reset added inside it.
  // A THIRD check the `boundIdentity` pin did not need is below, because the
  // mutation here is a DELETION rather than a rewrite - a decoy nested one
  // arrow deeper REPLACES the real call instead of joining it, so the count
  // stays at exactly one and only the direct-statement check bites.
  // -------------------------------------------------------------------------
  const loadBody = hostEditorFnBody ? findConstArrowBody(hostEditorFnBody, "load") : null;
  check("the load effect's `load` arrow body was found (compiler API)", loadBody !== null);
  const inlineResets = loadBody
    ? findCalls(loadBody, editorSf, ["setChoice"]).filter(
        (c) =>
          c.arguments.length === 1 &&
          norm(c.arguments[0].getText(editorSf)) === "CREDENTIAL_CHOICE_INLINE",
      )
    : [];
  check(
    "the load effect resets choice to the inline sentinel EXACTLY ONCE - rooted at `load` so a decoy outside it is not counted, counted so a second one inside it is",
    inlineResets.length === 1,
    inlineResets.length,
  );
  if (inlineResets.length === 1) {
    const reset = inlineResets[0];
    // Callee and argument as separate comparisons rather than the
    // CallExpression's whole text: a trailing comma sits INSIDE a multi-line
    // call's own span but OUTSIDE its arguments' spans, so pinning the two
    // smallest nodes that carry the claim cannot falsely redden on a reflow
    // that pinning the whole right-hand side would. Whitespace is normalised
    // and only whitespace - Prettier owns the line breaks, everything else
    // here IS the claim.
    check(
      "and the reset it makes is setChoice(CREDENTIAL_CHOICE_INLINE) - the sentinel, not some other draft value",
      norm(reset.expression.getText(editorSf)) === "setChoice" &&
        norm(reset.arguments[0].getText(editorSf)) === "CREDENTIAL_CHOICE_INLINE",
      { callee: reset.expression.getText(editorSf), arg: reset.arguments[0].getText(editorSf) },
    );
    check(
      'and it is reached only under a condition naming target.mode === "create" - never by adjacency',
      ifConditionsEnclosing(reset, editorSf).some((c) => /target\.mode === "create"/.test(c)),
      ifConditionsEnclosing(reset, editorSf),
    );
  }
  // The half of the claim that "a setChoice call exists in the create arm"
  // does not carry: the reset has to run BEFORE the arm's `return`, or it is
  // dead code AND the edit arm's reset below is never reached either. Direct
  // statements of the block only - a call one arrow deeper is not one, which
  // is what closes the nested-decoy case the count above cannot see.
  const createIf = loadBody
    ? findIfByCondition(loadBody, editorSf, 'target.mode === "create"')
    : null;
  check("the create arm's own `if` was found (compiler API)", createIf !== null);
  if (createIf && ts.isBlock(createIf.thenStatement)) {
    const stmts = createIf.thenStatement.statements;
    // By NODE IDENTITY against the set already filtered above, not by a second
    // comparison of the call's own text. Two reasons, and the first is a
    // landmine this check shipped with for one draft: a TRAILING COMMA sits
    // inside a multi-line call's own span but outside its arguments' spans, so
    // `norm(s.expression.getText())` against "setChoice(CREDENTIAL_CHOICE_INLINE)"
    // reddened the moment the statement was legally reflowed onto three lines -
    // caught by running exactly that reflow. Second, it keeps ONE definition of
    // "which call is the reset" instead of two that can drift.
    const resetAt = stmts.findIndex(
      (s) =>
        ts.isExpressionStatement(s) &&
        ts.isCallExpression(s.expression) &&
        inlineResets.includes(s.expression),
    );
    const returnAt = stmts.findIndex((s) => ts.isReturnStatement(s));
    check(
      "the reset is a DIRECT statement of the create arm's block and precedes its return - the path that returns before the edit arm's reset is reached",
      resetAt >= 0 && returnAt >= 0 && resetAt < returnAt,
      { resetAt, returnAt, statements: stmts.length },
    );
  }

  // -------------------------------------------------------------------------
  // Pin 2: what makes the stale-`choice` window UNREACHABLE THROUGH
  // SAVE. A pin on the mitigation, deliberately not a rewrite of the effect -
  // the shipped behaviour is correct today and this region has been
  // hand-tested three times.
  //
  // The window is real. `setMode(target.mode)` runs SYNCHRONOUSLY in the
  // effect body while both `setChoice` resets sit behind the `Promise.all`
  // two awaits down, so for the whole duration of a load `mode` is already
  // the new target's mode while `choice` is still the previous sitting's
  // value - and `boundIdentity` reads exactly that pair. That is the
  // `!existing`-versus-`mode === "create"` argument one step to the side.
  //
  // Three links close it and all three are pinned, because any one of them
  // going reopens it:
  //
  //   1. `setReady(false)` is a DIRECT statement of the effect body, in the
  //      same synchronous run as `setMode(target.mode)` and before
  //      `void load();`. One React batch, one render out of it, so no render
  //      observes the new `mode` with `ready` still true.
  //   2. `busy` still carries the `!ready` term.
  //   3. the ONE Save entry point is `disabled={busy}`.
  //
  // WHAT THIS DOES NOT COVER, said here rather than left as a silence.
  // (a) `boundIdentity` has a consumer that is NOT behind the gate:
  // the `DialogDescription` renders outside the `{ready ? … }` branch, so
  // during the window it can say "This host authenticates with a shared vault
  // identity" about a row that does not. Cosmetic, costs no credential, left
  // unpinned on purpose. (b) `runTest`'s `if (boundIdentity)` refusal is its
  // own fail-safe guard and is not part of this chain. (c) A second Save entry
  // point added later that does not read `busy` - an Enter-key submit, a
  // keyboard shortcut - would reopen the window; link 3 counts the Buttons so
  // that addition reddens rather than passing silently, but it cannot pin a
  // gate on an entry point that does not exist yet. (d) This pins the
  // MITIGATION, not the invariant: `setReady(false)` moved behind an await
  // reddens, an effect split in two reddens, a change in React's batching
  // semantics would not.
  // -------------------------------------------------------------------------
  const loadEffect = hostEditorFnBody
    ? findCalls(hostEditorFnBody, editorSf, ["useEffect"]).find(
        (c) =>
          c.arguments.length > 0 &&
          c.arguments[0].getText(editorSf).includes("applied.current === token"),
      )
    : undefined;
  check("the load effect's useEffect call was found (compiler API)", loadEffect !== undefined);
  const effectArg = loadEffect?.arguments[0];
  const effectBody =
    effectArg && ts.isArrowFunction(effectArg) && ts.isBlock(effectArg.body)
      ? effectArg.body
      : null;
  check("and its callback is a block-bodied arrow (compiler API)", effectBody !== null);
  if (effectBody) {
    const stmts = effectBody.statements;
    const indexOfExpr = (text: string) =>
      stmts.findIndex(
        (s) => ts.isExpressionStatement(s) && norm(s.expression.getText(editorSf)) === text,
      );
    const readyAt = indexOfExpr("setReady(false)");
    const modeAt = indexOfExpr("setMode(target.mode)");
    const loadAt = indexOfExpr("voidload()");
    check(
      "setReady(false) and setMode(target.mode) are both direct statements of the effect body, both before `void load()` - one synchronous batch, so no render sees the new mode with ready still true",
      readyAt >= 0 && modeAt >= 0 && loadAt >= 0 && readyAt < loadAt && modeAt < loadAt,
      { readyAt, modeAt, loadAt },
    );
  }
  const busyDecls = hostEditorFnBody ? findVariableDeclarations(hostEditorFnBody, "busy") : [];
  check(
    "busy is declared exactly once inside the component",
    busyDecls.length === 1,
    busyDecls.length,
  );
  const busyInit = busyDecls.length === 1 ? busyDecls[0].initializer : undefined;
  if (busyInit) {
    check(
      "and it is exactly `saving || !ready || changing`, whitespace aside - dropping the !ready term is what reopens the window",
      norm(busyInit.getText(editorSf)) === norm("saving || !ready || changing"),
      busyInit.getText(editorSf),
    );
  }
  const saveButtons = hostEditorFnBody
    ? findOpeningElementsByTag(hostEditorFnBody, "Button", editorSf).filter((el) =>
        (jsxAttrExprText(el, "onClick", editorSf) ?? "").includes("save()"),
      )
    : [];
  check(
    "there is exactly ONE Save entry point in the dialog - a second one is a second thing that has to read the gate",
    saveButtons.length === 1,
    saveButtons.length,
  );
  if (saveButtons.length === 1) {
    check(
      "and it is disabled={busy}, so it cannot fire during the load window",
      jsxAttrExprText(saveButtons[0], "disabled", editorSf) === "busy",
      jsxAttrExprText(saveButtons[0], "disabled", editorSf),
    );
  }

  // -------------------------------------------------------------------------
  // The convert option is edit-mode only. NOT the whole picker: the committed
  // `HostEditorDialog.tsx` renders the whole `Field label="Credential"` in
  // BOTH modes (its own comment says so); only this ONE option inside it is
  // edit-mode gated. A check for "the picker is edit-mode only" would redden
  // against the correct, committed code, so this is the narrower claim that
  // is actually true.
  // -------------------------------------------------------------------------
  // `hostEditorFnBody` is the one computed above, for the `boundIdentity` pin -
  // the same component body, found once.
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
        'it is offered only under a condition naming mode === "edit" - the other picker option is not',
        arm !== null &&
          arm.arm === "then" &&
          /mode === "edit"/.test(arm.cond.condition.getText(editorSf)),
        arm ? { arm: arm.arm, cond: arm.cond.condition.getText(editorSf) } : null,
      );
    }
  }

  // -------------------------------------------------------------------------
  // save() is unchanged, deliberately - section [4]'s six checks are
  // the check on that, and this comment exists so the next reader does not
  // read [4] as covering the picker's provenance too: it counts an
  // identifier, `boundIdentity`, and the three checks above this comment are
  // where that identifier's OWN provenance is actually pinned.
  //
  // The confirmation copy comes from the pure module.
  // -------------------------------------------------------------------------
  // Over `editorSrc`, the COMMENT-STRIPPED source, and the direction is why:
  // a POSITIVE count over the raw file is satisfied by a comment that merely
  // names the call. Replacing the real call with `{/* credentialChangeNote(...)
  // */}` plus three hand-written strings left `tsc` at 0, this count green, and
  // the three negatives below green as well - the mutation writes DIFFERENT
  // copy, which is exactly the drift this check exists to catch - while
  // `credential-move-verify` section [16]'s exact-text pins went dead in the
  // same move: the three strings are still pinned there, the dialog simply
  // stops rendering them. `stripComments` above carries the corrected
  // negative-lookahead JSX branch, so the JSX comment form is removed
  // here rather than counted.
  check(
    "the confirmation calls the pure module's title and note builders, not literals of its own",
    count(editorSrc, /credentialChangeTitle\(/g) >= 1 &&
      count(editorSrc, /credentialChangeNote\(/g) === 1,
    {
      titles: count(editorSrc, /credentialChangeTitle\(/g),
      notes: count(editorSrc, /credentialChangeNote\(/g),
    },
  );
  // The three note strings' own fixed text (no `${}` inside the fragment
  // chosen), so a literal copy pasted into the dialog instead of a call is
  // caught even though the dialog's title now ALSO comes from the same pure
  // module (no separate one-line-description string was added - see step 4's
  // own note on this).
  //
  // These stay on `editorRaw` while the positive above moved to `editorSrc`,
  // and the two directions genuinely want different inputs rather than one of
  // them being an oversight. A NEGATIVE over raw source catches a comment that
  // CLAIMS the banned thing, which is the defect a negative exists for - copy
  // pasted into a comment is still copy that drifted from the pure module. A
  // POSITIVE over raw source is SATISFIED by a comment that claims it, which
  // is the defect above. Do not "fix" either one to match the other.
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

// ---------------------------------------------------------------------------
console.log(
  "\n[10] the save inspects a key body before it stores one, and the refusal names the field it is about",
);
{
  // The gap this closes: the save stored whatever was in the key textarea. An
  // encrypted `openssh-key-v1` key pasted with a blank passphrase parses, so
  // the record came out with a key type, a fingerprint and `hasPrivateKey:
  // true` - complete-looking, and unusable at every connect, with nothing on
  // the card to say so because the pip reads that flag alone. The vault key
  // editor already refused exactly this; this editor refused nothing.
  //
  // ONE policy, imported. A private local copy of the refusal passes every
  // other check here, and every gate in this repo - agreement-by-value cannot
  // tell a shared function from a duplicate of it, so the import declaration
  // itself is pinned below.
  const saveBody = findConstArrowBody(editorSf, "save");
  check("save's body was found (compiler API)", saveBody !== null);

  if (saveBody) {
    const inspectCalls = findCalls(saveBody, editorSf, ["inspectSshKey"]);
    check(
      "save inspects the key body exactly once - none is the hole, twice is two answers about one key",
      inspectCalls.length === 1,
      inspectCalls.length,
    );

    if (inspectCalls.length === 1) {
      const call = inspectCalls[0];
      // The shape that defeats a name-scoped positive: alias the result above
      // `save` and demote the call to a `??` arm that never runs. The text
      // `inspectSshKey(` is still inside the body, so "the name appears here"
      // stays green over a call that cannot execute. What forbids it is the
      // call's own PARENTAGE - awaited, and the WHOLE of a `const`
      // initializer. A `??`/`||` arm's parent is a BinaryExpression and a
      // ternary arm's is a ConditionalExpression, so neither can wear this
      // shape.
      const awaited: ts.Node | undefined = call.parent;
      const decl: ts.Node | undefined = awaited?.parent;
      const declIsInfo =
        awaited !== undefined &&
        ts.isAwaitExpression(awaited) &&
        decl !== undefined &&
        ts.isVariableDeclaration(decl) &&
        ts.isIdentifier(decl.name) &&
        decl.name.text === "info";
      check(
        "and it is awaited straight into a const, never an arm of a ?? / || / ternary a cached result could skip",
        declIsInfo,
        {
          parent: awaited ? ts.SyntaxKind[awaited.kind] : null,
          grandparent: decl ? ts.SyntaxKind[decl.kind] : null,
        },
      );
      // What it is asked ABOUT. Argument by argument - see `argTexts` for why a
      // whole-call pin is a landmine here - because arguments drifting off the
      // draft is how the inspection comes to answer about a key that is not the
      // one the save is about to store.
      check(
        "and it is asked about the draft's own body and passphrase",
        JSON.stringify(argTexts(call, editorSf)) ===
          JSON.stringify([norm("sshCred.privateKey"), norm("sshCred.keyPassphrase || undefined")]),
        argTexts(call, editorSf),
      );

      // The other half of "statically reachable": exactly ONE enclosing `if`,
      // pinned. A `if (!cachedInfo.current)` wrapper - the reason the call
      // above could be demoted at all - is a second one and reddens here even
      // if the call itself keeps its shape.
      const conds = ifConditionsEnclosing(call, editorSf);
      check(
        "the only thing gating the inspection is its own guard, and that guard is exactly the four states it is for",
        conds.length === 1 &&
          norm(conds[0]) ===
            norm(
              'protocol === "ssh" && !boundIdentity && sshCred.authMode === "key" && sshCred.privateKey.trim() !== ""',
            ),
        conds,
      );
    }

    // The inspection's OWN answer feeds the refusal. `info.encrypted` rather
    // than anything read off the draft is the whole point: an
    // `openssh-key-v1` container answers with a real type, a fingerprint and a
    // public half WITHOUT its passphrase, so nothing the draft knows says the
    // passphrase is missing.
    const refusalDecls = findVariableDeclarations(saveBody, "refusal");
    check("refusal is declared exactly once inside save", refusalDecls.length === 1, {
      count: refusalDecls.length,
    });
    const refusalCalls = findCalls(saveBody, editorSf, ["encryptedKeyRefusal"]);
    check(
      "save calls the vault's refusal exactly once",
      refusalCalls.length === 1,
      refusalCalls.length,
    );
    if (refusalCalls.length === 1) {
      check(
        "and hands it the INSPECTION's own answer beside the draft passphrase - never something the draft alone knows, which says nothing about whether the container is sealed",
        JSON.stringify(argTexts(refusalCalls[0], editorSf)) ===
          JSON.stringify([norm("info.encrypted"), norm("sshCred.keyPassphrase")]),
        argTexts(refusalCalls[0], editorSf),
      );
      const bound: ts.Node = refusalCalls[0].parent;
      check(
        "and binds the answer to a name the save then branches on, rather than computing it and dropping it",
        ts.isVariableDeclaration(bound) &&
          ts.isIdentifier(bound.name) &&
          bound.name.text === "refusal",
        ts.SyntaxKind[bound.kind],
      );
    }

    const refusalIf = findIfByCondition(saveBody, editorSf, "refusal");
    check("the refusal's own if was found (compiler API)", refusalIf !== null);
    if (refusalIf) {
      check(
        "it tests the refusal itself",
        refusalIf.expression.getText(editorSf) === "refusal",
        refusalIf.expression.getText(editorSf),
      );
      const branch = refusalIf.thenStatement;
      const stmts = ts.isBlock(branch) ? [...branch.statements] : [branch];
      const first: ts.Statement | undefined = stmts[0];
      const second: ts.Statement | undefined = stmts[1];
      const firstCall =
        first !== undefined &&
        ts.isExpressionStatement(first) &&
        ts.isCallExpression(first.expression)
          ? first.expression
          : null;
      check(
        "and its branch is exactly setKeyRefusal(refusal) then a bare return - so no write, and no partial one, can hide inside it",
        stmts.length === 2 &&
          firstCall !== null &&
          firstCall.expression.getText(editorSf) === "setKeyRefusal" &&
          JSON.stringify(argTexts(firstCall, editorSf)) === JSON.stringify(["refusal"]) &&
          second !== undefined &&
          ts.isReturnStatement(second) &&
          second.expression === undefined,
        stmts.map((s) => norm(s.getText(editorSf))),
      );

      const upserts = findCalls(saveBody, editorSf, ["upsertHost"]);
      check("save writes through upsertHost exactly once", upserts.length === 1, upserts.length);
      check(
        "and that write is downstream of the refusal, so a refused save has not reached it",
        upserts.length === 1 && upserts[0].getStart(editorSf) > refusalIf.end,
        upserts.length === 1
          ? { writeAt: upserts[0].getStart(editorSf), refusalEndsAt: refusalIf.end }
          : null,
      );
    }
  }

  // -------------------------------------------------------------------------
  // The import-set pin. This is the ONLY thing that can tell the shared policy
  // from a duplicate of it: replace the import with a private
  // `encryptedKeyRefusal` of the same body and every value-level check above
  // stays green, measured. MEMBERSHIP rather than an exact set -
  // `vault-draft-verify.ts` asserts an exact two-element set because the file
  // it reads imports two things; this one imports a dozen, and an exact set
  // there is a red check on the next unrelated import, which the person who
  // hits it weakens rather than investigates.
  // -------------------------------------------------------------------------
  const editorImports = importDeclarations(editorSf);
  // Zero import declarations satisfies the membership check's negative form
  // and would satisfy nothing else. Asserted as its own check so a parse that
  // silently found nothing cannot read as a pass.
  check(
    "the dialog's import declarations were found at all",
    editorImports.length > 10,
    editorImports.length,
  );
  const DRAFT_MODULE = "@/modules/vault/editor/draft";
  const specifiers = editorImports.map(moduleSpecifierOf);
  check(
    `the dialog imports ${DRAFT_MODULE}, so the refusal is the vault's and not a second copy of it`,
    specifiers.includes(DRAFT_MODULE),
    specifiers,
  );
  const draftImport = editorImports.find((d) => moduleSpecifierOf(d) === DRAFT_MODULE);
  check(
    "and encryptedKeyRefusal is one of the names it takes from there - importing the module for something else is not the claim",
    draftImport !== undefined && namedImportsOf(draftImport).includes("encryptedKeyRefusal"),
    draftImport ? namedImportsOf(draftImport) : null,
  );
  // The one shape the two checks above cannot see: the import kept, and a
  // same-named local declared beside it. `tsc` refuses that today, so this
  // guards against a rename making it legal rather than against a live hole.
  check(
    "and the dialog declares no encryptedKeyRefusal of its own",
    findVariableDeclarations(editorSf, "encryptedKeyRefusal").length === 0 &&
      !/function encryptedKeyRefusal\b/.test(editorRaw),
    /.{0,40}function encryptedKeyRefusal.{0,40}/.exec(editorRaw)?.[0],
  );

  // -------------------------------------------------------------------------
  // WHERE it renders, over the parsed JSX on both sides of the prop. The
  // refusal's own sentence tells the user to enter the passphrase BELOW, so it
  // has to be the last child of the key field with the passphrase input
  // directly under it. The vault key editor's version once rendered under the
  // description field while saying those words, and that was a hand-tested
  // defect - asserting the string appears somewhere in the file is exactly
  // what a render move walks past.
  // -------------------------------------------------------------------------
  const keyFields = findOpeningElementsByTag(sshSectionSf, "Field", sshSectionSf).filter(
    (el) => jsxAttrExprText(el, "label", sshSectionSf) === "Private key (PEM / OpenSSH)",
  );
  check("the key body's own Field was found, exactly once", keyFields.length === 1, {
    count: keyFields.length,
  });
  const sectionJsxUses = jsxUsesOf(sshSectionSf, "keyRefusal");
  check(
    "the section renders the refusal at all - zero uses would pass every placement check below for free",
    sectionJsxUses.length > 0,
    sectionJsxUses.length,
  );
  if (keyFields.length === 1) {
    const el: ts.Node = keyFields[0].parent;
    const children = ts.isJsxElement(el) ? renderedChildren(el, sshSectionSf) : [];
    check(
      "and it is a container with children rather than a self-closing tag",
      children.length > 0,
      { count: children.length },
    );
    const last: ts.JsxChild | undefined = children[children.length - 1];
    check(
      "the refusal is the LAST child of that Field, so the passphrase input its sentence points at is the next thing on screen",
      last !== undefined &&
        ts.isJsxExpression(last) &&
        last.expression !== undefined &&
        /\bkeyRefusal\b/.test(last.expression.getText(sshSectionSf)),
      last?.getText(sshSectionSf).slice(0, 140),
    );
    // EVERY use, not just the last child: a second render further up this
    // component - beside the agent panel, under the user field - would be a
    // second place the same sentence can point at the wrong input.
    check(
      "and every use of it in this component is inside that same Field",
      sectionJsxUses.length > 0 && sectionJsxUses.every((u) => isDescendantOf(u, el)),
      sectionJsxUses
        .filter((u) => !isDescendantOf(u, el))
        .map((u) => u.parent.getText(sshSectionSf).slice(0, 80)),
    );
  }

  const sshSections = findOpeningElementsByTag(editorSf, "SshCredentialSection", editorSf);
  check(
    "the dialog renders exactly one SshCredentialSection",
    sshSections.length === 1,
    sshSections.length,
  );
  if (sshSections.length === 1) {
    check(
      "and hands the refusal down as keyRefusal={keyRefusal}",
      jsxAttrExprText(sshSections[0], "keyRefusal", editorSf) === "keyRefusal",
      jsxAttrExprText(sshSections[0], "keyRefusal", editorSf),
    );
  }
  // The move this forbids, in the other direction: rendering the refusal in
  // the dialog puts it beside the bottom `error` line, where "enter it below"
  // points at the Test button. Stated positively - EVERY JSX use here is an
  // attribute value - because the negative "it is not rendered" is satisfied by
  // the string not being here at all, which is the same mutation one step
  // further on.
  const dialogJsxUses = jsxUsesOf(editorSf, "keyRefusal");
  check(
    "the dialog uses the refusal in JSX at all - it has to hand it down from somewhere",
    dialogJsxUses.length > 0,
    dialogJsxUses.length,
  );
  check(
    "and every one of those uses is an attribute value: the dialog PASSES the refusal, it never renders one beside the bottom error line, which carries store refusals and keychain errors instead",
    dialogJsxUses.length > 0 && dialogJsxUses.every(insideJsxAttribute),
    dialogJsxUses
      .filter((u) => !insideJsxAttribute(u))
      .map((u) => u.parent.getText(editorSf).slice(0, 80)),
  );

  // -------------------------------------------------------------------------
  // The key-body half: the blank-body rule is gone, and the RDP password
  // rule is deliberately not gone with it.
  // -------------------------------------------------------------------------
  check(
    "validateSshCredential no longer refuses a key-auth host with a blank body - the pip on the card is what says so now",
    !/Private key body is required/.test(sshSectionRaw),
    /.{0,60}Private key body is required.{0,40}/.exec(sshSectionRaw)?.[0],
  );
  const validateRegion = between(
    sshSectionSrc,
    "export function validateSshCredential(",
    "function passwordHelp(",
  );
  check("validateSshCredential's region was found", validateRegion.length > 100, {
    length: validateRegion.length,
  });
  check(
    "and it still refuses a blank user, which has no flag, no pip, and no path that fills it in later",
    /if \(!draft\.user\.trim\(\)\) return "User is required";/.test(validateRegion),
    validateRegion.trim().slice(0, 200),
  );
  check(
    "and refuses nothing else - one message, so a second secret rule cannot creep back beside the relaxed ones",
    count(validateRegion, /return "/g) === 1,
    [...validateRegion.matchAll(/return "[^"]*"/g)].map((m) => m[0]),
  );
  check(
    "the RDP password rule is untouched - `RdpPane` will not dial without one, so that row's only outcome is a failure",
    /if \(!draft\.password && !hasStoredPassword\) return "Password is required";/.test(
      rdpSectionRaw,
    ),
    /.{0,80}Password is required.{0,20}/.exec(rdpSectionRaw)?.[0],
  );

  // --- what was watched fail, and what `tsc` did while it did ---------------
  //
  // E1  the whole guarded block deleted from `save`
  //       -> "save inspects the key body exactly once" (0), "refusal is declared
  //          exactly once inside save" (0), "the refusal's own if was found".
  //          `tsc` reddened TS6133 on the now-unused import - INCIDENTAL, and
  //          not on `inspectSshKey`, which `applyCredentialChange` still uses.
  // E1b the block AND the import deleted, which is what a real regression looks
  //     like
  //       -> the three above PLUS the two import-set checks. `tsc` at 0. This
  //          is the pair that prices the pin: the compiler covers none of it.
  // E2  `const info = lastInspection.current ?? (await inspectSshKey(...))`,
  //     with a ref seeded above `save` so the right arm never runs
  //       -> "and it is awaited straight into a const, never an arm of a ?? /
  //          || / ternary" alone. `tsc` at 0. The name-scoped positive
  //          ("inspectSshKey( appears in save") stays satisfied throughout,
  //          which is the whole reason parentage is asserted instead.
  // E3  the import replaced with a private copy of `encryptedKeyRefusal`
  //       -> both import-set checks and the no-local-copy belt, plus
  //          `key-inspect-verify` section [7]'s restatement check, which sees
  //          the sentence the copy brought with it. `tsc` at 0.
  // E4  the render moved out of the key `Field` and rendered beside the bottom
  //     `error` line instead, prop and all
  //       -> five: the section's three placement checks, the
  //          `keyRefusal={keyRefusal}` prop pin, and the dialog's
  //          every-JSX-use-is-an-attribute check. `tsc` at 0.
  // E5  the refusal branch's `return;` deleted, leaving a warning that still
  //     writes
  //       -> "and its branch is exactly setKeyRefusal(refusal) then a bare
  //          return". `tsc` at 0.
  // E6  `Private key body is required for key auth` put back
  //       -> the relaxation check and the one-message count. `tsc` at 0.
  // E7  `prettier --print-width 60 --write` over both source files - the
  //     control the exact-text pins above owe
  //       -> nothing in this section, which is the point. It DID redden the two
  //          whole-call pins this section had first: Prettier breaks a wrapped
  //          call AND adds a trailing comma, which `norm()` does not strip, so
  //          both became argument-wise (see `argTexts`). Sections [1], [2],
  //          [4], [6] and [8] do not survive that reformat - their anchors and
  //          regexes are line-shaped, they are pre-existing, and nothing here
  //          touched them.
}

/**
 * [11] REUSING A VAULT KEY IS THE USER'S ANSWER, AND A STALE LOOKUP MAY NOT
 * ANSWER FOR THEM.
 *
 * Convert offers to point the new identity at a key the vault already holds
 * rather than minting a second record for the same private key. The whole
 * reason the module takes `{reuseKeyId}` and performs no lookup of its own is
 * that reuse hands the new identity a record whose name, description and
 * passphrase belong to an earlier import, and getting it wrong is SILENT - the
 * connect works, using someone else's record. So the decision is the user's,
 * and this section is the only thing in the suite that says so.
 *
 * It exists because the property was measured UNCOVERED. Dropping the checkbox
 * from the conjunct below - reusing whenever a candidate exists - left this
 * script and all fifty-eight in the suite green, with `tsc` at 0. The module's
 * own checks cannot see it: they are handed a `reuseKeyId` and asked what
 * happens next, which is a different question from who decided to send one.
 *
 * The second half is the lookup's generation guard. It runs across two awaits -
 * an inspection and a vault read - so a second convert opened while the first
 * is in flight can land its answer on the wrong host. Deleting it is caught by
 * `tsc` today, but only because the binding it compares goes unused; a
 * regression that removed the binding with it compiles clean, which is exactly
 * the kind of cover that prices a pin wrong.
 */
console.log(
  "\n[11] reusing a vault key is the user's answer, and a stale lookup cannot answer for them",
);
{
  const applyBody = findConstArrowBody(editorSf, "applyCredentialChange");
  const offerBody = findConstArrowBody(editorSf, "offerKeyReuse");
  // Asserted rather than assumed: a rename otherwise leaves every check below
  // running over `null` and reporting nothing, which is a pass for free.
  check("applyCredentialChange's body was found", applyBody !== null);
  check("offerKeyReuse's body was found", offerBody !== null);

  if (applyBody) {
    // Rooted at the function body AND counted. Rooting excludes a decoy
    // declared outside the component; only the count excludes one declared as
    // a nested arrow inside it.
    const reusedDecls = findVariableDeclarations(applyBody, "reused");
    check(
      "`reused` is declared EXACTLY ONCE inside applyCredentialChange",
      reusedDecls.length === 1,
      reusedDecls.length,
    );
    const init = reusedDecls.length === 1 ? reusedDecls[0].initializer : undefined;
    check("and that declaration has an initializer to pin", init !== undefined);
    if (init) {
      check(
        "`reused` is exactly this expression, whitespace aside - the checkbox is a CONJUNCT, so reuse cannot happen because a candidate merely exists",
        norm(init.getText(editorSf)) ===
          norm('reuseExistingKey && reuseOffer.kind === "candidate" ? reuseOffer.key : null'),
        init.getText(editorSf),
      );
    }
    // A belt on the pin above: the checkbox state has to be READ in this
    // function. An exact-text pin that someone re-points at a different
    // identifier of the same shape still passes; a state that is never read
    // cannot decide anything.
    check(
      "and `reuseExistingKey` is read inside applyCredentialChange at all",
      findIdentifierUses(applyBody, "reuseExistingKey").length >= 1,
      findIdentifierUses(applyBody, "reuseExistingKey").length,
    );

    const convertCalls = findCalls(applyBody, editorSf, ["convertHostToVault"]);
    check(
      "exactly one convertHostToVault call in applyCredentialChange",
      convertCalls.length === 1,
      convertCalls.length,
    );
    if (convertCalls.length === 1) {
      const args = argTexts(convertCalls[0], editorSf);
      check("and it is called with exactly one argument", args.length === 1, args.length);
      check(
        "whose `key` arm names only what `reused` resolved to - an id read straight off the offer would route around the choice above",
        args[0]?.includes(norm("reused ? { reuseKeyId: reused.id }")) === true,
        args[0],
      );
    }
  }

  if (offerBody && ts.isBlock(offerBody)) {
    const statements = [...offerBody.statements];
    const guardIdx = statements.findIndex(
      (s) =>
        ts.isIfStatement(s) &&
        norm(s.expression.getText(editorSf)) === norm("reuseGeneration.current !== generation"),
    );
    // A DIRECT statement of the body, not merely somewhere under it: parked
    // inside an `if` or a callback the guard still parses and still never runs
    // on the path that matters, and a count would read exactly 1 either way.
    check(
      "the lookup's generation guard is a direct statement of offerKeyReuse's own body",
      guardIdx !== -1,
      statements.map((s) => norm(s.getText(editorSf)).slice(0, 40)),
    );
    const publishIdx = statements.findIndex((s) =>
      norm(s.getText(editorSf)).startsWith(norm("setReuseOffer(candidate")),
    );
    check("and the statement that publishes the answer was found", publishIdx !== -1, publishIdx);
    if (guardIdx !== -1 && publishIdx !== -1) {
      check(
        "and it runs BEFORE the answer is published - a guard after the write has already painted the wrong host's key",
        guardIdx < publishIdx,
        { guardIdx, publishIdx },
      );
    }
    if (guardIdx !== -1) {
      const guard = statements[guardIdx] as ts.IfStatement;
      check(
        "and its branch is a bare return, so nothing can be smuggled into the discard path",
        norm(guard.thenStatement.getText(editorSf)).replace(/[{}]/g, "") === "return;",
        guard.thenStatement.getText(editorSf),
      );
      check(
        "and it has no else arm - a superseded lookup is DISCARDED, never published down another route",
        guard.elseStatement === undefined,
        guard.elseStatement?.getText(editorSf),
      );
    }
  }

  // --- what was watched fail, and what `tsc` did while it did ---------------
  //
  // K7  `const reused = reuseOffer.kind === "candidate" ? reuseOffer.key : null`
  //     - reuse whenever a candidate exists, ignoring the checkbox
  //       -> TWO: the exact-expression pin on `reused`, AND the "is read at
  //          all" belt at 0. The belt was written expecting to need its own
  //          mutation and it does not: dropping the conjunct removes the only
  //          read of `reuseExistingKey` in this function, so both fire
  //          together. `tsc` at 0. This whole script was green under K7 before
  //          the section existed, which is why it exists.
  // K8  `if (reuseGeneration.current !== generation) return;` deleted
  //       -> ONE: the direct-statement check. The ordering and branch checks
  //          are guarded on having found the statement, so they do not run -
  //          correct, and worth knowing before reading their silence as cover.
  //          `tsc` reddens TS6133, but only because `generation` then goes
  //          unused: a deletion that took the binding with it compiles clean.
  // K8b the same guard moved BELOW `setReuseOffer(candidate ...)`, which is
  //     the shape a presence check and a count both miss - the statement is
  //     still there, still direct, still exactly one
  //       -> the ordering check alone, `{"guardIdx":7,"publishIdx":6}`.
  //          `tsc` at 0. This is the mutation only the position half catches.
  // K9  `prettier --print-width 60 --write` over the dialog - the reformat pair
  //     these exact-text pins owe
  //       -> nothing in this section, which is the point: every pin above reads
  //          a node's own span rather than a whole call's, so a trailing comma
  //          Prettier adds when it wraps sits outside the claim. It DID redden
  //          24 checks in sections [1], [2], [4], [6] and [8], whose anchors
  //          and regexes are line-shaped. Those are pre-existing and untouched.
}

/**
 * [12] A HOST THAT STOPPED USING KEY AUTH CAN BE TOLD TO FORGET THE KEY, AND
 * ONLY FROM A ROW THAT SAYS SO.
 *
 * The trap this closes had four parts and every one of them was correct on its
 * own. The record stays honest about holding a private key, because `writeSecret`
 * returns the STORED flag for a field the save does not mention. Nothing releases
 * it, because `releaseStaleAccounts` releases the accounts the new record cannot
 * NAME and an inline SSH row names all three under every auth mode - releasing on
 * a narrower rule would destroy the only copy of a secret this layer cannot read
 * back. The export carries it, because `hostRefs` enumerates every field the
 * protocol owns. And the field is not on screen, because the key textarea renders
 * only under key auth. So the one route that removes a stored key - clear the
 * textarea, save, and `writeSecret` turns `""` into a delete - disappears at
 * exactly the moment it becomes the thing the user wants, and the key ships in
 * every export forever.
 *
 * `hostRefs` is deliberately NOT filtered by the presence flags, which was the
 * other candidate fix: a store restored from its `.bak` snapshot rolls metadata
 * back while the secret store does not, and an export that quietly omits a LIVE
 * credential is worse than one carrying a secret the user can now delete.
 *
 * WHAT THIS SECTION IS FOR, and it is not "the button exists". A button wired to
 * nothing passes that. The chain is pinned link by link: the button's `onClick`
 * is the row's `onForget`, which is the section's `onForgetKey`, which the dialog
 * hands `forgetSshKey`, which is the only thing that arms the intent, which
 * `save` passes as `sshSecretsForSave`'s fourth argument, which forces both key
 * fields to the store's clear. Plus the render gate, structurally: the row is a
 * function of the STORED record's flags and of the auth modes that have no key
 * field - never of the draft, whose key body is an open-time snapshot of the
 * secret store and is blank both when nothing is stored and when the read has not
 * landed.
 *
 * The intent is a DRAFT intent for the reason `forgetPin` is: writing the deletion
 * as the button is pressed was a real defect there, because Cancel reverted the
 * visible field and nothing reverted the write.
 */
console.log(
  "\n[12] a host that stopped using key auth can be told to forget the key, from a row that says so",
);
{
  // --- the payload, over the real function ---------------------------------
  //
  // Values, not source text, for section [2]'s reason: an omitted key and one
  // set to `""` are the store's "leave it alone" and "delete the account", and
  // no regex tells them apart. The whole point of the flag is that it works with
  // NOTHING TOUCHED AND NOTHING SEEDED - the field cannot be touched when it is
  // not rendered - so every row below is that state unless it says otherwise.
  const cred = (over: Partial<SshCredentialDraft> = {}): SshCredentialDraft => ({
    user: "u",
    authMode: "password",
    password: "",
    privateKey: "",
    keyPassphrase: "",
    ...over,
  });
  const touching = (fields: (keyof SshSecretSeeded)[]): SshSecretTouched => ({
    ...NO_SSH_SECRETS_TOUCHED,
    ...Object.fromEntries(fields.map((f) => [f, true])),
  });
  const seeding = (fields: (keyof SshSecretSeeded)[]): SshSecretSeeded => ({
    ...NOTHING_SEEDED,
    ...Object.fromEntries(fields.map((f) => [f, true])),
  });

  {
    const out = sshSecretsForSave(cred(), NO_SSH_SECRETS_TOUCHED, NOTHING_SEEDED, true);
    check(
      "the intent clears the key body with nothing touched and nothing seeded, which is the only state it is ever in",
      "privateKey" in out && out.privateKey === "",
      out,
    );
    check(
      "and the key passphrase with it - a passphrase whose body is gone opens nothing and no field in this editor can reach it",
      "keyPassphrase" in out && out.keyPassphrase === "",
      out,
    );
    check(
      "and it sends no password at all: an untouched password is still left exactly alone",
      !("password" in out),
      out,
    );
    check(
      "and nothing but those two fields",
      JSON.stringify(Object.keys(out).sort()) === JSON.stringify(["keyPassphrase", "privateKey"]),
      Object.keys(out),
    );
  }
  {
    // The auth mode the host has MOVED TO must survive the intent, and this is
    // the check that would catch a clear written as "blank the whole draft".
    const out = sshSecretsForSave(
      cred({ password: "typed" }),
      touching(["password"]),
      NOTHING_SEEDED,
      true,
    );
    check(
      "a password typed in the same sitting still carries its typed value",
      out.password === "typed",
      out,
    );
    check(
      "while both key fields still go down as the clear",
      out.privateKey === "" && out.keyPassphrase === "",
      out,
    );
  }
  {
    // The intent WINS over a body that is touched and seeded, rather than being
    // a fallback for an empty one. Unreachable as the form stands - switching to
    // key auth retracts the intent, pinned below - and pinned anyway, because
    // "the flag decides" is the contract the row's promise rests on.
    const out = sshSecretsForSave(
      cred({ privateKey: "-----BEGIN", keyPassphrase: "p" }),
      touching(["privateKey", "keyPassphrase"]),
      seeding(["privateKey", "keyPassphrase"]),
      true,
    );
    check(
      "the intent overrides a key body that is touched AND seeded, rather than only an empty one",
      out.privateKey === "" && out.keyPassphrase === "",
      out,
    );
  }
  {
    // The complement, and the reason section [2]'s table is the evidence that
    // nothing else moved: with the intent off, an untouched form still sends
    // nothing at all.
    const out = sshSecretsForSave(
      cred({ privateKey: "-----BEGIN", keyPassphrase: "p" }),
      NO_SSH_SECRETS_TOUCHED,
      seeding(["privateKey", "keyPassphrase"]),
      false,
    );
    check(
      "with the intent OFF, a seeded but untouched key body is still left alone - the flag is off by construction, not on by accident",
      JSON.stringify(out) === "{}",
      out,
    );
  }

  // --- which records own key material, over real records --------------------
  const sshRow = (over: {
    authMode?: "password" | "key" | "agent";
    hasPassword?: boolean;
    hasPrivateKey?: boolean;
    hasKeyPassphrase?: boolean;
  }): Host => ({
    id: "h-1",
    name: "prod",
    host: "example.com",
    port: 22,
    protocol: "ssh",
    credential: {
      kind: "inline",
      hostId: "h-1",
      user: "u",
      authMode: over.authMode ?? "password",
      hasPassword: over.hasPassword ?? false,
      hasPrivateKey: over.hasPrivateKey ?? false,
      hasKeyPassphrase: over.hasKeyPassphrase ?? false,
    },
  });
  const boundRow: Host = {
    ...sshRow({}),
    credential: { kind: "identity", identityId: "i-1" },
  };
  const rdpRow: Host = {
    id: "h-2",
    name: "win",
    host: "win.example.com",
    port: 3389,
    protocol: "rdp",
    credential: { kind: "inline", hostId: "h-2", username: "u", hasPassword: true },
    desktopWidth: 1920,
    desktopHeight: 1080,
    sizeMode: "preset",
  };

  check(
    "both flags set names both accounts, in the order the field list enumerates them",
    JSON.stringify(hostKeySecretNames(sshRow({ hasPrivateKey: true, hasKeyPassphrase: true }))) ===
      JSON.stringify(["private key", "key passphrase"]),
    hostKeySecretNames(sshRow({ hasPrivateKey: true, hasKeyPassphrase: true })),
  );
  check(
    "a key body alone names one",
    JSON.stringify(hostKeySecretNames(sshRow({ hasPrivateKey: true }))) ===
      JSON.stringify(["private key"]),
    hostKeySecretNames(sshRow({ hasPrivateKey: true })),
  );
  // The orphan the row exists for as much as the key body does: a stored
  // passphrase whose key is already gone is unreachable from every field in
  // this editor, and it is why the copy is a function of the flags.
  check(
    "and a stored key passphrase with NO stored body still gets the row",
    JSON.stringify(hostKeySecretNames(sshRow({ hasKeyPassphrase: true }))) ===
      JSON.stringify(["key passphrase"]),
    hostKeySecretNames(sshRow({ hasKeyPassphrase: true })),
  );
  check(
    "a stored password is not key material",
    hostKeySecretNames(sshRow({ hasPassword: true })).length === 0,
    hostKeySecretNames(sshRow({ hasPassword: true })),
  );
  check(
    "a row with neither flag has nothing to forget",
    hostKeySecretNames(sshRow({})).length === 0,
    hostKeySecretNames(sshRow({})),
  );
  // Not a belt: a bound host owns no accounts of its own, and `bind` already
  // deleted them and said so in its own confirmation.
  check(
    "a vault-bound row owns no key material to forget",
    hostKeySecretNames(boundRow).length === 0,
    hostKeySecretNames(boundRow),
  );
  check(
    "and an RDP row never held any",
    hostKeySecretNames(rdpRow).length === 0,
    hostKeySecretNames(rdpRow),
  );
  // The flags decide, NOT the stored auth mode: a record still on key auth whose
  // draft has been switched to a password is the whole case, and it is the
  // RENDER that owns the auth-mode half of the gate (pinned structurally below).
  check(
    "and the answer is the flags rather than the stored auth mode, which the render gate owns instead",
    JSON.stringify(
      hostKeySecretNames(sshRow({ authMode: "key", hasPrivateKey: true, hasKeyPassphrase: true })),
    ) === JSON.stringify(["private key", "key passphrase"]),
    hostKeySecretNames(sshRow({ authMode: "key", hasPrivateKey: true, hasKeyPassphrase: true })),
  );

  // --- the copy, by value ---------------------------------------------------
  //
  // In `credentialChoice.ts` rather than inline JSX for the reason every string
  // in that file is: it can be exercised here. Three flag cases, because a
  // sentence naming a private key is wrong for the passphrase-only orphan.
  {
    const bodyOnly = ["private key"];
    const passOnly = ["key passphrase"];
    const both = ["private key", "key passphrase"];
    for (const forgetting of [false, true]) {
      const notes = [bodyOnly, passOnly, both].map((s) => forgetKeyNote(s, forgetting));
      check(
        `the note names the secrets it is called with (forgetting=${forgetting})`,
        notes[0].includes("private key") &&
          !notes[0].includes("key passphrase") &&
          notes[1].includes("key passphrase") &&
          !notes[1].includes("private key") &&
          notes[2].includes("private key") &&
          notes[2].includes("key passphrase"),
        notes,
      );
      check(
        `and differs across body-only, passphrase-only and both (forgetting=${forgetting})`,
        new Set(notes).size === 3,
        notes,
      );
      check(
        `and agrees with the count of them (forgetting=${forgetting})`,
        / is never read| is deleted/.test(notes[0]) && / are /.test(notes[2]),
        notes,
      );
    }
    // The three things it has to say, and the third is the difference between
    // this and a button that writes as it is pressed.
    const before = forgetKeyNote(both, false);
    check(
      "the un-pressed note says the host does not authenticate with a key",
      /does not authenticate with a key/.test(before),
      before,
    );
    check("and that SAVE is what deletes it", /when you save/.test(before), before);
    check(
      "and that nothing undoes the deletion afterwards",
      /undoes that deletion/.test(before),
      before,
    );
    const after = forgetKeyNote(both, true);
    check(
      "the pressed note still says Save is what deletes it",
      /when you save/.test(after),
      after,
    );
    check(
      "and that cancelling this editor leaves the stored secrets alone, which is what makes the press an intent",
      /Cancelling this editor/.test(after),
      after,
    );
    check("and the two arms are different sentences", before !== after, [before, after]);
    check(
      "the row's own label names what is held and differs per case",
      new Set([bodyOnly, passOnly, both].map(forgetKeyRowLabel)).size === 3 &&
        forgetKeyRowLabel(bodyOnly).includes("private key"),
      [bodyOnly, passOnly, both].map(forgetKeyRowLabel),
    );
  }

  // --- the render gate, structurally ---------------------------------------
  const rowRenders = findOpeningElementsByTag(sshSectionSf, "ForgetKeyRow", sshSectionSf);
  check(
    "the SSH section renders exactly one ForgetKeyRow - a second one is a second promise about the same two accounts",
    rowRenders.length === 1,
    rowRenders.length,
  );
  if (rowRenders.length === 1) {
    const row = rowRenders[0];
    const arm = conditionalArmOf(row);
    check("the row sits in a conditional arm at all", arm !== null);
    if (arm) {
      check(
        "and it is the THEN arm, so the gate is what makes it appear rather than what hides it",
        arm.arm === "then",
        arm.arm,
      );
      // The exact-text pin, and both halves of it are the finding. The auth-mode
      // half: the key textarea IS the route to clearing a stored key, so this
      // row may not exist where that textarea does. The list half: it comes off
      // the STORED record (see the dialog's own pin below) - gating on
      // `value.privateKey` instead would show the row for a host with nothing
      // stored and hide it while the keychain read was still in flight.
      check(
        "and the gate is exactly the non-key auth modes AND the stored record's own key accounts",
        norm(arm.cond.condition.getText(sshSectionSf)) ===
          norm('value.authMode !== "key" && forgettableKeySecrets.length > 0'),
        arm.cond.condition.getText(sshSectionSf),
      );
    }
    check(
      "the row is handed the stored list, the intent and the intent's setter, and nothing else decides what it shows",
      jsxAttrExprText(row, "keySecrets", sshSectionSf) === "forgettableKeySecrets" &&
        jsxAttrExprText(row, "forgetting", sshSectionSf) === "forgetKey" &&
        jsxAttrExprText(row, "onForget", sshSectionSf) === "onForgetKey",
      {
        keySecrets: jsxAttrExprText(row, "keySecrets", sshSectionSf),
        forgetting: jsxAttrExprText(row, "forgetting", sshSectionSf),
        onForget: jsxAttrExprText(row, "onForget", sshSectionSf),
      },
    );
  }

  // --- the button is wired to the intent, and retires once pressed ----------
  const rowBody = findFunctionBody(sshSectionSf, "ForgetKeyRow");
  check("ForgetKeyRow's body was found (compiler API)", rowBody !== null);
  if (rowBody) {
    const buttons = findOpeningElementsByTag(rowBody, "Button", sshSectionSf).filter(
      (el) => jsxAttrExprText(el, "onClick", sshSectionSf) === "onForget",
    );
    check(
      "exactly one Button in the row calls the intent - a button wired to nothing is what an existence check would have passed",
      buttons.length === 1,
      buttons.length,
    );
    if (buttons.length === 1) {
      const arm = conditionalArmOf(buttons[0]);
      check(
        "and it is rendered in the ELSE arm of the intent itself, so pressing it visibly retires it - the only feedback there is that anything happened",
        arm !== null &&
          arm.arm === "else" &&
          norm(arm.cond.condition.getText(sshSectionSf)) === norm("forgetting"),
        arm ? { arm: arm.arm, cond: arm.cond.condition.getText(sshSectionSf) } : null,
      );
    }
    // Both strings from the checkable module, neither restated here: a literal
    // in this component is a sentence nothing in the suite can read.
    const labelCalls = findCalls(rowBody, sshSectionSf, ["forgetKeyRowLabel"]);
    const noteCalls = findCalls(rowBody, sshSectionSf, ["forgetKeyNote"]);
    check("the row takes its label from credentialChoice.ts", labelCalls.length === 1, {
      count: labelCalls.length,
    });
    check("and its note too", noteCalls.length === 1, { count: noteCalls.length });
    if (noteCalls.length === 1) {
      check(
        "and the note is asked about the same list it is showing AND the intent, so the two arms cannot drift from what is on screen",
        JSON.stringify(argTexts(noteCalls[0], sshSectionSf)) ===
          JSON.stringify([norm("keySecrets"), norm("forgetting")]),
        argTexts(noteCalls[0], sshSectionSf),
      );
    }
  }
  const sectionImports = importDeclarations(sshSectionSf);
  const choiceImport = sectionImports.find((d) => moduleSpecifierOf(d) === "./credentialChoice");
  check(
    "the section imports both strings from credentialChoice.ts rather than carrying copies of them",
    choiceImport !== undefined &&
      namedImportsOf(choiceImport).includes("forgetKeyNote") &&
      namedImportsOf(choiceImport).includes("forgetKeyRowLabel"),
    choiceImport ? namedImportsOf(choiceImport) : sectionImports.map(moduleSpecifierOf),
  );
  check(
    "and declares neither of them locally",
    !/function forgetKeyNote\b|function forgetKeyRowLabel\b/.test(sshSectionRaw),
    /.{0,40}function forgetKey(Note|RowLabel).{0,40}/.exec(sshSectionRaw)?.[0],
  );

  // --- the list is the STORED record's, and no other surface is promising ---
  const editorBody = findFunctionBody(editorSf, "HostEditorDialog");
  check("the dialog's body was found (compiler API)", editorBody !== null);
  if (editorBody) {
    // Rooted at the body AND counted, per `findVariableDeclarations`: rooting
    // excludes a decoy declared outside the component, only the count excludes
    // one declared as a nested arrow inside it.
    const decls = findVariableDeclarations(editorBody, "forgettableKeySecrets");
    check(
      "`forgettableKeySecrets` is declared exactly once inside the component",
      decls.length === 1,
      decls.length,
    );
    const init = decls.length === 1 ? decls[0].initializer : undefined;
    check("and that declaration has an initializer to pin", init !== undefined);
    if (init) {
      // Every operand is load-bearing. `existing` is the STORED record, which is
      // what makes the row a function of what is stored rather than of a draft
      // that is blank while the keychain read is in flight. `pendingChange` and
      // `changing` are the two moments another surface is already promising
      // something about these same accounts - a convert moves them, a bind
      // deletes them, both saying so in their own confirmation - and two
      // surfaces promising something about one secret is how the two come to say
      // different things.
      check(
        "and it is exactly this expression, whitespace aside: the stored record, and neither a pending credential change nor one in flight",
        norm(init.getText(editorSf)) ===
          norm(
            "existing && pendingChange === null && !changing ? hostKeySecretNames(existing) : []",
          ),
        init.getText(editorSf),
      );
    }
    const nameCalls = findCalls(editorBody, editorSf, ["hostKeySecretNames"]);
    check(
      "and the dialog asks for the names exactly once, about the stored record",
      nameCalls.length === 1 &&
        JSON.stringify(argTexts(nameCalls[0], editorSf)) === JSON.stringify(["existing"]),
      nameCalls.map((c) => argTexts(c, editorSf)),
    );
    // The save's own end of the chain, over the parsed call - the line-shaped
    // regex in section [2] says the same thing and does not survive a reformat.
    const saveBody = findConstArrowBody(editorSf, "save");
    check("save's body was found for the payload pin", saveBody !== null);
    if (saveBody) {
      const calls = findCalls(saveBody, editorSf, ["sshSecretsForSave"]);
      check("save builds the SSH secrets exactly once", calls.length === 1, calls.length);
      if (calls.length === 1) {
        check(
          "and hands the intent down as its own fourth argument, beside the live touched and seeded records",
          JSON.stringify(argTexts(calls[0], editorSf)) ===
            JSON.stringify([
              norm("sshCred"),
              norm("sshTouched.current"),
              norm("sshSeeded.current"),
              norm("forgetKey"),
            ]),
          argTexts(calls[0], editorSf),
        );
      }
    }
  }
  const sshSectionRenders = findOpeningElementsByTag(editorSf, "SshCredentialSection", editorSf);
  if (sshSectionRenders.length === 1) {
    check(
      "the dialog hands the section the list, the intent and the one function that arms it",
      jsxAttrExprText(sshSectionRenders[0], "forgettableKeySecrets", editorSf) ===
        "forgettableKeySecrets" &&
        jsxAttrExprText(sshSectionRenders[0], "forgetKey", editorSf) === "forgetKey" &&
        jsxAttrExprText(sshSectionRenders[0], "onForgetKey", editorSf) === "forgetSshKey",
      {
        list: jsxAttrExprText(sshSectionRenders[0], "forgettableKeySecrets", editorSf),
        intent: jsxAttrExprText(sshSectionRenders[0], "forgetKey", editorSf),
        setter: jsxAttrExprText(sshSectionRenders[0], "onForgetKey", editorSf),
      },
    );
  }

  // --- exactly one thing arms the intent, and four things retire it ---------
  check(
    "the intent is armed in exactly one place in the dialog",
    count(editorSrc, /setForgetKey\(true\)/g) === 1,
    count(editorSrc, /setForgetKey\(true\)/g),
  );
  check(
    "and that place is forgetSshKey, which does nothing else - Save is what writes",
    assignedIn(editorSrc, "forgetSshKey") === "() => setForgetKey(true)",
    assignedIn(editorSrc, "forgetSshKey"),
  );

  const effect = between(editorSrc, "if (applied.current === token) return;", "void load();");
  const reset = between(effect, 'setTest({ kind: "idle" });', "const stale = () =>");
  check("the load effect's reset block was found", reset.length > 20, reset.length);
  // Per row, exactly as the touched and seeded records are: an intent carried
  // onto the next row would delete a key nothing on screen has mentioned.
  check(
    "a new row starts with no forget intent",
    /setForgetKey\(false\);/.test(reset),
    reset.trim(),
  );

  // The remaining three retirements are pinned over the PARSED dialog rather
  // than over `between()` regions, and that is not a preference: the region form
  // was written first, and the `--print-width 60` control below reddened all
  // three of them over unchanged code - their anchors are line-shaped, exactly
  // as sections [1], [2], [4], [6] and [8] are. The reset above survives it, so
  // it stays as it is.
  const patchBody = findConstArrowBody(editorSf, "patchSshCred");
  check("patchSshCred's body was found (compiler API)", patchBody !== null);
  if (patchBody) {
    const clears = findCalls(patchBody, editorSf, ["setForgetKey"]);
    check(
      "patchSshCred retires the intent in exactly one place",
      clears.length === 1 && JSON.stringify(argTexts(clears[0], editorSf)) === '["false"]',
      clears.map((c) => argTexts(c, editorSf)),
    );
    if (clears.length === 1) {
      // The interaction that makes this a retraction rather than a nicety: from
      // the moment key auth is back the textarea is on screen holding the seeded
      // body, and the field itself is the route - so an intent left set would
      // delete the body the user is now looking at, with no row anywhere saying
      // so. Exactly ONE enclosing `if`, pinned: a second condition would be a
      // case where the switch happens and the intent survives it.
      const conds = ifConditionsEnclosing(clears[0], editorSf);
      check(
        "and the only thing gating it is the switch back to key auth itself",
        conds.length === 1 && norm(conds[0]) === norm('patch.authMode === "key"'),
        conds,
      );
    }
  }

  const applyBody = findConstArrowBody(editorSf, "applyCredentialChange");
  check("applyCredentialChange's body was found (compiler API)", applyBody !== null);
  if (applyBody) {
    const clears = findCalls(applyBody, editorSf, ["setForgetKey"]);
    check(
      "a credential change retires the intent, because it changes which accounts the host owns",
      clears.length === 1 && JSON.stringify(argTexts(clears[0], editorSf)) === '["false"]',
      clears.map((c) => argTexts(c, editorSf)),
    );
    if (clears.length === 1) {
      // UNCONDITIONAL, and that is the claim rather than the absence of one:
      // convert moves those accounts, bind deletes them and detach copies an
      // identity's secrets into fresh ones. Detach is the arm that would bite -
      // it leaves the row inline again with a private key just copied in, and a
      // stale intent would delete that copy on the next Save - so a version of
      // this gated on the change kind is a version with a hole in it.
      check(
        "and it retires it for every arm, not one of them",
        ifConditionsEnclosing(clears[0], editorSf).length === 0,
        ifConditionsEnclosing(clears[0], editorSf),
      );
    }
  }

  const saveBodyNode = findConstArrowBody(editorSf, "save");
  if (saveBodyNode) {
    const clears = findCalls(saveBodyNode, editorSf, ["setForgetKey"]);
    check(
      "save's stale-stamp recovery retires the intent, once",
      clears.length === 1 && JSON.stringify(argTexts(clears[0], editorSf)) === '["false"]',
      clears.map((c) => argTexts(c, editorSf)),
    );
    if (clears.length === 1) {
      // The fourth route, and the one that is not obvious: the arm BELOW this
      // re-seeds `authMode` from the refreshed record, so a record now on key
      // auth would put the textarea back on screen with the intent still set and
      // the second press of Save would delete the body on it. Asserted as
      // POSITION within the same block as the refresh, which is what says
      // "before the re-seed" - a presence check passes with the clear moved
      // below it, and that ordering is the whole point.
      const block = enclosingBlock(clears[0]);
      check("the recovery's own block was found", block !== null);
      if (block) {
        const stmts = [...block.statements];
        const at = (pred: (s: ts.Statement) => boolean) => stmts.findIndex(pred);
        const refreshIdx = at((s) => findCalls(s, editorSf, ["setExisting"]).length > 0);
        const clearIdx = at((s) => isDescendantOf(clears[0], s));
        const reseedIdx = at(
          (s) => ts.isIfStatement(s) && s.expression.getText(editorSf).includes('!== "inline"'),
        );
        check(
          "and it sits beside the record refresh, ABOVE the arm that re-seeds the auth mode",
          refreshIdx !== -1 &&
            clearIdx !== -1 &&
            reseedIdx !== -1 &&
            refreshIdx < clearIdx &&
            clearIdx < reseedIdx,
          { refreshIdx, clearIdx, reseedIdx },
        );
      }
    }
  }

  // --- what was watched fail, and what `tsc` did while it did ---------------
  //
  // Every mutation below was applied to the file named, the script and `tsc` were
  // both run, the FAIL lines were recorded as printed, and the source was
  // restored from a snapshot whose checksum was verified afterwards.
  //
  // F1  `sshSecretsForSave`'s `forgetKey` branch deleted, the parameter kept
  //       -> FIVE: the three in the first payload block, "while both key fields
  //          still go down as the clear", and "the intent overrides a key body
  //          that is touched AND seeded". `tsc` DOES redden here - TS6133 on the
  //          now-unread parameter, `noUnusedParameters` being on - so the
  //          compiler catches the deletion while these five are what say which
  //          behaviour went with it.
  // F2  the branch blanks the draft's password along with the two key fields
  //       -> THREE: "and it sends no password at all", "and nothing but those two
  //          fields", and "a password typed in the same sitting still carries its
  //          typed value". `tsc` at 0. This is the mutation the row's whole
  //          promise turns on: the password is the credential the host has moved
  //          TO.
  // F3  the fourth argument dropped at the call site in `save`
  //       -> TWO: section [2]'s call-text check and this section's argument-wise
  //          pin. `tsc` reddens TS2554 (4 arguments expected, 3 given), which is
  //          why the parameter is REQUIRED rather than defaulted - a default
  //          would have made this silent in the compiler and left the two pins as
  //          the only cover.
  // F4  the render gate changed to `value.privateKey.trim() !== ""`, the draft
  //     instead of the stored record
  //       -> ONE: the exact-text gate pin. `tsc` at 0. That gate shows the row
  //          for a host with nothing stored and hides it while the read is in
  //          flight, which is the confusion `sshSeeded` exists to keep out.
  // F5  the `patch.authMode === "key"` retraction deleted
  //       -> ONE: "patchSshCred retires the intent in exactly one place",
  //          reporting `[]`. `tsc` at 0.
  // F5b the retraction kept but UNGATED, which a presence check reads as correct
  //       -> ONE: "and the only thing gating it is the switch back to key auth
  //          itself". `tsc` at 0. This is the mutation only the
  //          enclosing-condition half catches, and it fails the other way -
  //          every keystroke would retract an intent the user had set.
  // F6  the row rendered unconditionally (the ternary removed)
  //       -> ONE: "the row sits in a conditional arm at all". The two checks
  //          guarded on it do not run - `ok` drops by three, not one - which is
  //          worth knowing before reading their silence as cover. `tsc` at 0.
  // F7  `forgetKeyNote` inlined as a literal in `ForgetKeyRow`
  //       -> ONE: "and its note too", at `{"count":0}`. The argument pin is
  //          guarded on that count and does not run, and the IMPORT-SET check
  //          still passes, because the import itself stayed. `tsc` reddens TS6133
  //          on the unused import.
  // F9  `applyCredentialChange`'s retirement deleted
  //       -> ONE: "a credential change retires the intent". `tsc` at 0.
  // F10 the recovery's retirement kept, still exactly one, but moved BELOW the
  //     arm that re-seeds the auth mode
  //       -> ONE: the ordering check, at
  //          `{"refreshIdx":0,"clearIdx":2,"reseedIdx":1}`. `tsc` at 0. The
  //          presence half stays green throughout, which is why position is
  //          asserted rather than presence.
  // F8  `prettier --print-width 60 --write` over the four source files - the
  //     reformat pair every exact-text pin here owes
  //       -> NOTHING in this section, and that is what the three parsed pins
  //          above were rewritten for: the first version of them was
  //          `between()`-anchored and this same control reddened all three (six
  //          checks) over unchanged code. It still reddens 24 checks in sections
  //          [1], [2], [4], [6] and [8], whose anchors and regexes are
  //          line-shaped - the same 24 sections [10] and [11] record. One of them
  //          is section [2]'s own `sshSecretsForSave` call-text check, extended
  //          here for the fourth argument and no less line-shaped than it was.
}

console.log(failed === 0 ? "\nAll host-editor checks passed." : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
