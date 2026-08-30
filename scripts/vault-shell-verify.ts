/**
 * Self-check for wave 2 step 3: the Vault page SHELL - the rail-view branch
 * swap in `RailViewArea.tsx`, and `VaultPage.tsx` itself, which is assembly
 * only. Run: `pnpm verify vault-shell` (or `npx tsx
 * scripts/vault-shell-verify.ts` to iterate).
 *
 * SOURCE-TEXT, exactly as `hosts-page-verify.ts` and `hosts-error-toast-verify.ts`
 * are - there is no DOM or layout engine in this suite - with ONE exception:
 * sections 3 and 6 use the TypeScript compiler API (`scripts/pane-caret-verify.ts`
 * is the precedent), because both are nesting questions, and a distance
 * heuristic reads a correctly-nested call as un-nested. "Is this call inside a
 * `useMemo(...)`" and "is this call inside `confirmDelete`'s body" are both
 * shapes a regex cannot tell from "these two strings happen to be near each
 * other" - and getting either wrong is a false PASS on exactly the defect the
 * section exists to catch (see the header note on M3 below).
 *
 * Every section states, in a comment, the ONE property it protects - most of
 * them are re-derivation smells or missing-nesting bugs that this page's own
 * wave-1/wave-2 siblings already shipped once (see `derive.ts`'s own header for
 * why the row builders live where they do).
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import ts from "typescript";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (rel: string) => readFileSync(join(repoRoot, rel), "utf8");

let failed = 0;
function check(name: string, ok: boolean, detail?: string | number): void {
  if (ok) {
    console.log(`  ok: ${name}`);
    return;
  }
  console.error(`  FAIL: ${name}`, detail === undefined ? "" : JSON.stringify(detail));
  failed++;
}

const FILES = {
  vaultPage: "src/modules/vault/VaultPage.tsx",
  identityCard: "src/modules/vault/page/IdentityCard.tsx",
  keyCard: "src/modules/vault/page/KeyCard.tsx",
  railViewArea: "src/app/components/RailViewArea.tsx",
} as const;

const src = Object.fromEntries(Object.entries(FILES).map(([k, p]) => [k, read(p)])) as Record<
  keyof typeof FILES,
  string
>;

// The three files this wave's other checks call "the three new files" -
// VaultPage.tsx plus the two cards next to it. `RailViewArea.tsx` is an
// EDIT, not a new file, and is deliberately excluded from every whole-suite
// sweep below (sections 9 and 12) for that reason.
const NEW_FILES = ["vaultPage", "identityCard", "keyCard"] as const;

// ============================================================================
// Shared compiler-API helpers - sections 9, 10, 13 and 15 all ask some
// variant of "what does THIS element's THIS attribute actually say", never
// "does this string appear somewhere in the file": a plain substring check
// on the raw source is satisfied by a comment that merely mentions the same
// text, which is exactly the flank left open in the first draft of sections
// 9 and 10.
// ============================================================================

/** The function DECLARATION body named `name`, or `null` if there is none.
 *  `IdentityCard`, `KeyCard` and `VaultPage` are all plain
 *  `export function Name(...) { ... }` declarations - never an arrow bound to
 *  a `const` - so this one shape covers every call site below. */
function findFunctionBody(root: ts.Node, name: string): ts.Node | null {
  let result: ts.Node | null = null;
  const visit = (n: ts.Node): void => {
    if (ts.isFunctionDeclaration(n) && n.name?.text === name && n.body) result = n.body;
    ts.forEachChild(n, visit);
  };
  visit(root);
  return result;
}

/** The JSX element a function body's own `return (...)` renders, unwrapping
 *  parentheses - i.e. what the component actually puts on screen, not any
 *  JSX elsewhere in its body (a helper it calls, for instance). */
function findReturnedJsxRoot(
  functionBody: ts.Node,
): ts.JsxElement | ts.JsxSelfClosingElement | null {
  let result: ts.JsxElement | ts.JsxSelfClosingElement | null = null;
  const visit = (n: ts.Node): void => {
    if (ts.isReturnStatement(n) && n.expression) {
      let expr: ts.Expression = n.expression;
      while (ts.isParenthesizedExpression(expr)) expr = expr.expression;
      if (ts.isJsxElement(expr) || ts.isJsxSelfClosingElement(expr)) result = expr;
    }
    ts.forEachChild(n, visit);
  };
  visit(functionBody);
  return result;
}

/** The `className` attribute's VALUE on a JSX opening tag - a bare string
 *  literal (`className="…"`) or an expression (`className={cn(…)}`) - or
 *  `null` if the element has none. */
function classNameAttrValue(
  el: ts.JsxElement | ts.JsxSelfClosingElement,
  sf: ts.SourceFile,
): ts.StringLiteral | ts.Expression | null {
  const opening = ts.isJsxElement(el) ? el.openingElement : el;
  for (const attr of opening.attributes.properties) {
    if (ts.isJsxAttribute(attr) && attr.name.getText(sf) === "className" && attr.initializer) {
      if (ts.isStringLiteral(attr.initializer)) return attr.initializer;
      if (ts.isJsxExpression(attr.initializer) && attr.initializer.expression) {
        return attr.initializer.expression;
      }
    }
  }
  return null;
}

/** Every STRING-LITERAL argument a `cn(...)` call is given - recursing into
 *  nested calls and both arms of a ternary - space-joined: the class names
 *  actually applied at runtime, read from the AST's own string-literal
 *  nodes. A `//` comment sitting between two arguments is trivia BETWEEN
 *  nodes, never inside one, so it cannot leak into this text the way it
 *  leaks into a raw `src.includes(...)` scan of the whole file. */
function literalClassNameText(value: ts.StringLiteral | ts.Expression): string {
  if (ts.isStringLiteral(value) || ts.isNoSubstitutionTemplateLiteral(value)) return value.text;
  if (ts.isCallExpression(value)) return value.arguments.map(literalClassNameText).join(" ");
  if (ts.isConditionalExpression(value)) {
    return [literalClassNameText(value.whenTrue), literalClassNameText(value.whenFalse)].join(" ");
  }
  return "";
}

/** Every JSX element or self-closing element in `root` whose tag is
 *  `tagName`, returned as its OPENING element (so callers read attributes off
 *  either shape uniformly). */
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
 *  string value on one opening element - e.g. `variant` off `<Badge
 *  variant={missingSecret ? "destructive" : "outline"}>` reads back
 *  `missingSecret ? "destructive" : "outline"`. `null` if the element has no
 *  such attribute. */
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

/** The nearest ancestor `JsxElement` (an open/children/close element, never a
 *  self-closing one) above `node` - used to climb from an icon like
 *  `<KeyRound />` up to the `<span>` that wraps it, when that wrapper carries
 *  no attribute distinctive enough to search for directly. */
function nearestAncestorJsxElement(node: ts.Node): ts.JsxElement | null {
  for (let cur: ts.Node | undefined = node.parent; cur; cur = cur.parent) {
    if (ts.isJsxElement(cur)) return cur;
  }
  return null;
}

// ============================================================================
// 1. The rail branch was replaced, and only that branch.
// ============================================================================
// Protects: `RailViewArea.tsx`'s `vault` case renders `<VaultPage />`, its
// `PagePlaceholder` call is gone, and - the negative control - the `forwards`
// case (6f's, untouched) still renders its placeholder. The third check is
// what stops an edit that replaced BOTH branches from reading as correct: M2
// below flips `forwards` to `<VaultPage />` too, and only the third check can
// notice.
console.log("[1. rail branch] only the vault case was replaced");
{
  const r = src.railViewArea;
  check(
    "the vault case renders <VaultPage />",
    /case "vault":[\s\S]{0,200}<VaultPage\s*\/>/.test(r),
  );
  check(
    "the vault case no longer renders PagePlaceholder",
    !/case "vault":[\s\S]{0,200}PagePlaceholder/.test(r),
  );
  check(
    'NEGATIVE CONTROL: the forwards case still renders <PagePlaceholder page="forwards"',
    /case "forwards":[\s\S]{0,200}<PagePlaceholder page="forwards"/.test(r),
  );
}

// ============================================================================
// 2. The page calls the shared row builders and assembles nothing itself.
// ============================================================================
// Protects: the Hosts page and the header quick-connect once disagreed about
// which hosts a query matched because each assembled its own rows instead of
// calling one shared builder (`page/derive.ts`'s own header tells that story).
// The negative half runs over the RAW source - comments and dead branches
// included - because "this page never re-derives X" has to hold everywhere in
// the file, not just in the reachable lines.
console.log("\n[2. no re-derivation] the page calls the shared builders, not its own logic");
{
  const v = src.vaultPage;
  for (const name of ["identityRows(", "keyRows(", "rankIdentities(", "rankKeys("]) {
    check(`VaultPage.tsx calls ${name}`, v.includes(name));
  }
  for (const smell of ["credential.identityId", "credential.kind", ".keyId ===", "hasPrivateKey"]) {
    check(`VaultPage.tsx does not re-derive via \`${smell}\``, !v.includes(smell));
  }
}

// ============================================================================
// 3. Every row-builder call is inside a useMemo. (COMPILER API)
// ============================================================================
// Protects: zustand v5 matches `Object.is`, and each row builder ends in
// `.map` - a fresh array every call. A call site that is not wrapped re-renders
// on every store broadcast and, called from a selector, throws "Maximum
// update depth exceeded" outright; called from the render body, it just
// re-derives every render for nothing. THIS IS THE CHECK M3 IS FOR: a check
// that only greps for `useMemo(` anywhere in the file passes over "hoist the
// call out of its useMemo into the render body", because the text `useMemo(`
// is still sitting a few lines above, unconnected to anything.
console.log("\n[3. memo rule, compiler-verified] every builder call sits inside a useMemo factory");
{
  const sf = ts.createSourceFile(
    FILES.vaultPage,
    src.vaultPage,
    ts.ScriptTarget.ESNext,
    /* setParentNodes */ true,
    ts.ScriptKind.TSX,
  );

  function findCalls(root: ts.Node, calleeName: string): ts.CallExpression[] {
    const out: ts.CallExpression[] = [];
    const visit = (n: ts.Node): void => {
      if (ts.isCallExpression(n) && n.expression.getText(sf) === calleeName) out.push(n);
      ts.forEachChild(n, visit);
    };
    visit(root);
    return out;
  }

  /** Walk up the parent chain from `call` looking for an enclosing
   *  `useMemo(factory, deps)` whose FIRST ARGUMENT spans `call` - i.e. `call`
   *  is actually inside the memoized function, not merely inside the same
   *  statement or a neighbouring dependency array. */
  function insideUseMemoFactory(call: ts.CallExpression): boolean {
    for (let cur: ts.Node | undefined = call.parent; cur; cur = cur.parent) {
      if (ts.isCallExpression(cur) && cur.expression.getText(sf) === "useMemo") {
        const factory = cur.arguments[0];
        if (factory && call.getStart(sf) >= factory.getStart(sf) && call.end <= factory.end) {
          return true;
        }
      }
    }
    return false;
  }

  for (const name of ["identityRows", "keyRows", "rankIdentities", "rankKeys"]) {
    const calls = findCalls(sf, name);
    check(`found exactly one \`${name}(\` call to check`, calls.length === 1, calls.length);
    for (const call of calls) {
      check(
        `${name}(...) is called from inside a useMemo(...) factory`,
        insideUseMemoFactory(call),
        call.getText(sf),
      );
    }
  }
}

// ============================================================================
// 4. No row builder is inside a selector.
// ============================================================================
// Protects: the same "Maximum update depth exceeded" failure mode, from the
// other direction - a selector (`useStore((s) => ...)`, or `useShallow`, which
// appears nowhere in `src/` today) calling one of the row builders directly.
// Kept simple and negative, per the plan.
console.log("\n[4. no selector] the page reads useVault()/useHosts(), it does not select");
check("VaultPage.tsx does not import/use useShallow", !src.vaultPage.includes("useShallow"));
check("VaultPage.tsx has no useStore( call", !/useStore\(/.test(src.vaultPage));

// ============================================================================
// 5. The identity delete hands the store the injected lookup.
// ============================================================================
// Protects: `identityHostRefs` is the ONE place that answers "which hosts
// bind this identity" - an inline `(id) => [...]` here would be a second,
// silently-divergent implementation of that same question.
console.log("\n[5. injected lookup] deleteIdentity is called with the shared identityHostRefs");
{
  const v = src.vaultPage;
  check(
    "deleteIdentity(<id>, identityHostRefs) - the shared lookup, passed by name",
    /deleteIdentity\(\s*[^,)]+,\s*identityHostRefs\s*\)/.test(v),
  );
  check(
    'imports identityHostRefs from "@/modules/hosts/store"',
    /from "@\/modules\/hosts\/store"/.test(v) && /identityHostRefs/.test(v),
  );
  check(
    "NEGATIVE: no inline (identityId) => ... lookup passed to deleteIdentity",
    !/deleteIdentity\(\s*[^,)]+,\s*\(\s*identityId\s*\)/.test(v),
  );
  check(
    "NEGATIVE: no inline async (...) => ... lookup passed to deleteIdentity",
    !/deleteIdentity\(\s*[^,)]+,\s*async\s*\(/.test(v),
  );
}

// ============================================================================
// 6. Deletes are confirmed, and only from one place. (COMPILER API)
// ============================================================================
// Protects: a card that could delete on its own, without the confirm dialog in
// between - M5 moves exactly that mutation (a `deleteKey(...)` call into a
// card's `onDelete` arrow) and this section is what catches it, because the
// call would then sit outside `confirmDelete`'s body in the syntax tree, no
// matter how visually close it ends up to the rest of the file.
console.log(
  "\n[6. confirmed deletes, compiler-verified] every delete call is inside confirmDelete",
);
{
  const sf = ts.createSourceFile(
    FILES.vaultPage,
    src.vaultPage,
    ts.ScriptTarget.ESNext,
    true,
    ts.ScriptKind.TSX,
  );

  /** The factory function handed to `useCallback` in `const <name> =
   *  useCallback(fn, deps)`, or `null` if that shape is not found. */
  function useCallbackFactory(root: ts.Node, name: string): ts.Node | null {
    let result: ts.Node | null = null;
    const visit = (n: ts.Node): void => {
      if (
        ts.isVariableDeclaration(n) &&
        ts.isIdentifier(n.name) &&
        n.name.text === name &&
        n.initializer &&
        ts.isCallExpression(n.initializer) &&
        n.initializer.expression.getText(sf) === "useCallback"
      ) {
        const fn = n.initializer.arguments[0];
        if (fn) result = fn;
      }
      ts.forEachChild(n, visit);
    };
    visit(root);
    return result;
  }

  function findCalls(root: ts.Node, calleeNames: string[]): ts.CallExpression[] {
    const out: ts.CallExpression[] = [];
    const visit = (n: ts.Node): void => {
      if (ts.isCallExpression(n) && calleeNames.includes(n.expression.getText(sf))) out.push(n);
      ts.forEachChild(n, visit);
    };
    visit(root);
    return out;
  }

  const confirmDelete = useCallbackFactory(sf, "confirmDelete");
  check("found confirmDelete's useCallback factory", confirmDelete !== null);

  const deleteCalls = findCalls(sf, ["deleteIdentity", "deleteKey"]);
  check(
    "found at least one deleteIdentity/deleteKey call",
    deleteCalls.length > 0,
    deleteCalls.length,
  );
  if (confirmDelete) {
    for (const call of deleteCalls) {
      const inside =
        call.getStart(sf) >= confirmDelete.getStart(sf) && call.end <= confirmDelete.end;
      check(`${call.getText(sf)} is lexically inside confirmDelete`, inside, call.getText(sf));
    }
  }

  for (const key of ["identityCard", "keyCard"] as const) {
    check(
      `${FILES[key]} contains no deleteIdentity/deleteKey call of its own`,
      !/delete(Identity|Key)\(/.test(src[key]),
    );
    check(
      `${FILES[key]} does not import from ../store`,
      !/from ["']\.\.\/store["']/.test(src[key]),
    );
  }
}

// ============================================================================
// 7. The refusal goes to the shared toast; the page has no error surface of
//    its own.
// ============================================================================
// Protects: VLT-36's still-unfinished half - a page-owned `useState<string |
// null>` (or a hand-rolled `role="alert"` line) that never expires, instead of
// the shared, self-expiring `toast()`.
console.log("\n[7. one error surface] the refusal reaches toast(), and nowhere else");
{
  const v = src.vaultPage;
  check(
    "toast(deleteRefusalText(...)) - tolerates both one-line and multi-line call shapes",
    /toast\(\s*deleteRefusalText\(/.test(v),
  );
  check(
    'imports toast from "@/components/ui/toast"',
    /import\s*\{\s*toast\s*\}\s*from\s*"@\/components\/ui\/toast";/.test(v),
  );
  for (const smell of ["setError", "useState<string | null>", 'role="alert"']) {
    check(`no \`${smell}\` in VaultPage.tsx`, !v.includes(smell));
  }
}

// ============================================================================
// 8. The page keeps its own search box, with both narrow rules.
// ============================================================================
// Protects: the element exists and is unique. The WIDTH BEHAVIOUR itself -
// `@max-[420px]:basis-full` / `@max-[420px]:min-w-40` - is
// `scripts/hosts-header-narrow-verify.ts`'s job, forcing the container width
// directly; this section only proves there is one search box here for that
// script (and this one) to be checking in the first place.
console.log("\n[8. search box] exactly one, with its placeholder and label");
{
  const v = src.vaultPage;
  const matches = v.match(/<InputGroup /g) ?? [];
  check("exactly one <InputGroup ...> in VaultPage.tsx", matches.length === 1, matches.length);
  check('placeholder="Search vault…" present', v.includes('placeholder="Search vault…"'));
  check('aria-label="Search vault" present', v.includes('aria-label="Search vault"'));
}

// ============================================================================
// 9. Container queries, not viewport breakpoints.
// ============================================================================
// Protects: this page renders inside the workspace column, whose width comes
// from the sidebar drag and the right slot, never the window - so a viewport
// breakpoint here is wrong at every window size where the pane and the window
// disagree. Runs over the three NEW files (not `RailViewArea.tsx`, which
// carries no layout of its own).
console.log("\n[9. @container, not sm:/md:/lg:/xl:/2xl:] no viewport breakpoints anywhere new");
for (const key of NEW_FILES) {
  check(`${FILES[key]} has no viewport breakpoint`, !/\b(sm|md|lg|xl|2xl):/.test(src[key]));
}
{
  // Compiler-verified, not `src.vaultPage.includes("@container")`: this
  // file's own header comment on the page root (just above its `return`)
  // SAYS "@container" in prose to explain the decision, so a plain substring
  // check passes on that comment alone with the real `@container` deleted
  // from the root `className` - and every `@[…]:` rule downstream, in this
  // file and both cards, would then resolve against some other ancestor or
  // nothing. Root only, and read from the className ATTRIBUTE's own
  // string-literal node, which cannot see a comment sitting elsewhere in the
  // file.
  const sf = ts.createSourceFile(
    FILES.vaultPage,
    src.vaultPage,
    ts.ScriptTarget.ESNext,
    true,
    ts.ScriptKind.TSX,
  );
  const body = findFunctionBody(sf, "VaultPage");
  check("found VaultPage's function body to check", body !== null);
  const root = body && findReturnedJsxRoot(body);
  check("found VaultPage's own root returned JSX element", root !== null);
  const classValue = root && classNameAttrValue(root, sf);
  check("found the root element's className attribute", classValue !== null);
  const classText = classValue ? literalClassNameText(classValue) : "";
  check(
    "the root element's className is non-trivial (extraction sanity)",
    classText.length > "@container".length,
    classText,
  );
  check(
    "the root element's className token list includes @container",
    /(^|\s)@container(?=\s|$)/.test(classText),
    classText,
  );
}

// ============================================================================
// 10. content-visibility comes with its floor.
// ============================================================================
// Protects: without `contain-intrinsic-size`, an off-screen card lays out at
// 0px and the scrollbar jumps while the user scrolls - the pair is
// load-bearing, and M7 deletes exactly the half that is easy to drop by
// accident.
console.log("\n[10. content-visibility + its floor] both halves, on both cards, actually applied");
for (const key of ["identityCard", "keyCard"] as const) {
  const functionName = key === "identityCard" ? "IdentityCard" : "KeyCard";
  // Compiler-verified for the same reason as section 9: M7 deleting the
  // whole `[contain-intrinsic-size:auto_100px]` string is caught by a plain
  // substring check just fine, but a mutation that empties that STRING
  // LITERAL and moves the same text into a `//` comment on the line above is
  // not - the comment and the real class both satisfy `src[key].includes`.
  // Extracting only the STRING-LITERAL arguments actually passed to
  // `cn(...)` on the root element cannot see a comment sitting between them.
  const sf = ts.createSourceFile(
    FILES[key],
    src[key],
    ts.ScriptTarget.ESNext,
    true,
    ts.ScriptKind.TSX,
  );
  const body = findFunctionBody(sf, functionName);
  check(`found ${functionName}'s function body to check`, body !== null);
  const root = body && findReturnedJsxRoot(body);
  check(`found ${functionName}'s own root returned JSX element`, root !== null);
  const classValue = root && classNameAttrValue(root, sf);
  check(`found ${FILES[key]}'s root element's className attribute`, classValue !== null);
  const classText = classValue ? literalClassNameText(classValue) : "";
  check(
    `${FILES[key]}'s root className is non-trivial (extraction sanity)`,
    classText.length > "[content-visibility:auto]".length,
    classText,
  );
  check(
    `${FILES[key]} applies [content-visibility:auto] on its root element`,
    classText.includes("[content-visibility:auto]"),
    classText,
  );
  check(
    `${FILES[key]} applies [contain-intrinsic-size:auto_100px] on its root element`,
    classText.includes("[contain-intrinsic-size:auto_100px]"),
    classText,
  );
}

// ============================================================================
// 11. The key card's record prop is not called `key`.
// ============================================================================
// Protects: `key` is React's reserved prop name - a prop literally named `key`
// never reaches the component. Checked from BOTH ends: the card's own prop
// type, and the page's two separate uses of the list key and the record prop.
console.log("\n[11. vaultKey, not key] the reserved prop name is avoided on both sides");
{
  const k = src.keyCard;
  check("KeyCard.tsx declares `vaultKey: VaultKey`", /vaultKey: VaultKey/.test(k));
  check("KeyCard.tsx's props do not declare a `key:` field", !/\bkey:/.test(k));

  const v = src.vaultPage;
  check("VaultPage.tsx passes vaultKey={row.key}", /vaultKey=\{row\.key\}/.test(v));
  check(
    "VaultPage.tsx's <KeyCard> also carries the LIST key key={row.key.id}",
    /<KeyCard[\s\S]{0,120}key=\{row\.key\.id\}/.test(v),
  );
}

// ============================================================================
// 12. Nothing claims a secret is safe.
// ============================================================================
// Protects: nothing in this wave protects a secret better than it was
// protected before - what a shared identity buys is fewer COPIES of one
// secret, never a stronger guarantee, and the copy must not imply otherwise.
// NOTE: "Encrypted" is deliberately NOT forbidden here - wave 3's key panel
// says it about a locked key, truthfully, and that is a different claim.
console.log(
  '\n[12. no false safety claim] "safer"/"securely"/"OS keychain" etc. appear nowhere new',
);
for (const key of NEW_FILES) {
  check(
    `${FILES[key]} does not name a specific secret store`,
    !/OS keychain|Credential Manager/.test(src[key]),
  );
  check(
    `${FILES[key]} makes no safety comparison`,
    !/\bsafer\b|\bsecurely\b|\bmore secure\b/i.test(src[key]),
  );
}

// ============================================================================
// 13. Both empty states are two-way.
// ============================================================================
// Protects: "there is nothing here" and "your query excludes everything" are
// different facts and need different next steps - a single message for both
// is the defect this catches (M10 collapses them to one).
//
// The four literal strings are NECESSARY but not SUFFICIENT: they are also
// present as PROP VALUES at the two `<SectionEmpty>` call sites regardless of
// whether its render logic ever reads `noMatch` - collapsing
// `matching ? noMatch : nothingYet` to always `nothingYet` leaves every one
// of the four literals sitting in the file, byte for byte, while the two
// failure states read identically on screen. The first draft of this section
// checked only the four literals and went GREEN over exactly that mutation
// (M10) - a positive assertion the dead branch can satisfy, the same class
// `pane-caret-verify.ts`'s header warns about. So the render logic itself is
// checked too, via the compiler API: `SectionEmpty`'s function body must
// contain the literal ternary shape, not just the two identifiers somewhere
// in scope.
console.log(
  "\n[13. two-way empty states] all four messages present, actually branched on (headline AND",
);
console.log(
  "    hint), the predicate is hasAny && filtering, and both call sites feed hasAny from the",
);
console.log("    UNFILTERED row list");
{
  const v = src.vaultPage;
  for (const msg of [
    "No saved identities yet.",
    "No identities match.",
    "No saved keys yet.",
    "No keys match.",
  ]) {
    check(`VaultPage.tsx contains "${msg}"`, v.includes(msg));
  }

  const sf = ts.createSourceFile(
    FILES.vaultPage,
    v,
    ts.ScriptTarget.ESNext,
    true,
    ts.ScriptKind.TSX,
  );

  // --- SectionEmpty's own body: the predicate, and BOTH ternaries it feeds.
  // The first draft of this check only asserted the headline ternary, which
  // Z4 (the hint's ternary collapsed to `{nothingYetHint}`) and Z1 (the
  // predicate narrowed to `filtering` alone) both leave green.
  let sectionEmptyBody: string | null = null;
  const visitBody = (n: ts.Node): void => {
    if (ts.isFunctionDeclaration(n) && n.name?.text === "SectionEmpty" && n.body) {
      sectionEmptyBody = n.body.getText(sf);
    }
    ts.forEachChild(n, visitBody);
  };
  visitBody(sf);
  check("found SectionEmpty's function body to check", sectionEmptyBody !== null);
  if (sectionEmptyBody) {
    check(
      "SectionEmpty derives its predicate as `hasAny && filtering` - not `filtering` alone",
      /const\s+matching\s*=\s*hasAny\s*&&\s*filtering/.test(sectionEmptyBody),
      sectionEmptyBody,
    );
    check(
      "SectionEmpty's headline actually branches: `matching ? noMatch : nothingYet`",
      /matching\s*\?\s*noMatch\s*:\s*nothingYet/.test(sectionEmptyBody),
      sectionEmptyBody,
    );
    check(
      "SectionEmpty's HINT branches too, not only the headline: `matching ? … : nothingYetHint`",
      /matching\s*\?[^:]*:\s*nothingYetHint/.test(sectionEmptyBody),
      sectionEmptyBody,
    );
  }

  // --- Both call sites feed `hasAny` from the UNFILTERED row list. `hasAny`
  // asks "does this section have anything AT ALL, ignoring the query" - the
  // one thing that tells `matching` apart from `filtering` alone. Feeding it
  // from the FILTERED/visible list instead makes it agree with `filtering`
  // exactly when the section is empty, so `noMatch` can never render: the
  // section 13 defect, reached from the call site rather than from inside
  // `SectionEmpty` itself, which the body-only check above cannot see.
  const sectionEmptyCalls = findOpeningElementsByTag(sf, "SectionEmpty", sf);
  check(
    "found exactly two <SectionEmpty> call sites to check",
    sectionEmptyCalls.length === 2,
    sectionEmptyCalls.length,
  );
  const seenHasAny = new Set<string>();
  for (const el of sectionEmptyCalls) {
    const hasAnyText = jsxAttrExprText(el, "hasAny", sf);
    check("a <SectionEmpty> call site's hasAny expression was found", hasAnyText !== null);
    if (hasAnyText !== null) {
      seenHasAny.add(hasAnyText);
      check(
        `<SectionEmpty hasAny={${hasAnyText}}> is fed from the row list, not the filtered list`,
        hasAnyText === "identityRowList.length > 0" || hasAnyText === "keyRowList.length > 0",
        hasAnyText,
      );
    }
  }
  check(
    "the two call sites feed hasAny from DIFFERENT row lists, one per section",
    seenHasAny.size === 2,
    [...seenHasAny].join(", "),
  );
}

// ============================================================================
// 14. No dead affordance.
// ============================================================================
// Protects: a button that opens nothing is the dead-affordance class already
// filed against this app once. Wave 3 deletes items off this list as it
// implements them, deliberately.
console.log("\n[14. no dead affordance] no button/prop for something this wave does not implement");
for (const label of ["New identity", "New key", "Edit", "Export", "Import"]) {
  check(`VaultPage.tsx contains no "${label}" string`, !src.vaultPage.includes(label));
}
for (const key of ["identityCard", "keyCard"] as const) {
  for (const prop of ["onEdit", "onSelect", "onConnect"]) {
    check(`${FILES[key]} declares no ${prop} prop`, !src[key].includes(prop));
  }
}

// ============================================================================
// 15. Each card's new prop reaches the one element it is meant to colour,
//     and no other.
// ============================================================================
// Protects: `IdentityCard.tsx`'s own header on `keyDangling` - it colours the
// KEY CHIP alone, deliberately. A stale `keyId` does not stop most auth modes
// from connecting, so marking the ROW destructive over it is a false alarm on
// a record that works fine; and for `authMode: "key"` the row is ALREADY
// destructive through `missingSecret`, so a second destructive mark on the
// row says the same fact twice. `missingSecret` (identity) and
// `missingPrivateKey` (key) are the ones that DO belong on the row `Badge`,
// driving both its `variant` and its label. Nothing in `scripts/` checked any
// of this before this section - `tsc`'s `noUnusedLocals` catches a prop with
// BOTH reads deleted, by accident, but a prop moved to the wrong element
// keeps every read alive and passes `tsc`, `pnpm verify` and (until now) this
// file, all three.
console.log("\n[15. card props reach the right element] keyDangling -> chip only; missingSecret /");
console.log("    missingPrivateKey -> the row Badge's variant AND its label");
{
  const sfIdentity = ts.createSourceFile(
    FILES.identityCard,
    src.identityCard,
    ts.ScriptTarget.ESNext,
    true,
    ts.ScriptKind.TSX,
  );
  const identityBody = findFunctionBody(sfIdentity, "IdentityCard");
  check("found IdentityCard's function body to check", identityBody !== null);

  // --- keyDangling: reaches the key chip, and ONLY the key chip. Anchored on
  // the `<KeyRound />` icon - the chip's own wrapping `<span>` carries no
  // attribute distinctive enough to search for directly - so a rename of
  // that icon fails this loudly instead of leaving every check below it
  // running over `null`.
  const keyRoundIcons = identityBody
    ? findOpeningElementsByTag(identityBody, "KeyRound", sfIdentity)
    : [];
  check(
    "found the <KeyRound /> icon, the key chip's anchor",
    keyRoundIcons.length === 1,
    keyRoundIcons.length,
  );
  const keyRoundIcon = keyRoundIcons[0] ?? null;
  const chip = keyRoundIcon ? nearestAncestorJsxElement(keyRoundIcon) : null;
  check("found the key chip element (the <KeyRound />'s wrapping <span>)", chip !== null);
  const chipClassValue = chip ? classNameAttrValue(chip, sfIdentity) : null;
  check("found the key chip's className attribute", chipClassValue !== null);
  if (chipClassValue) {
    const chipClassText = chipClassValue.getText(sfIdentity);
    check(
      "the key chip's className is non-trivial (extraction sanity)",
      chipClassText.length > "keyDangling".length,
      chipClassText,
    );
    check(
      "keyDangling reaches the key chip's className",
      /\bkeyDangling\b/.test(chipClassText),
      chipClassText,
    );
  }

  const identityBadges = identityBody
    ? findOpeningElementsByTag(identityBody, "Badge", sfIdentity)
    : [];
  check(
    "found exactly one <Badge> in IdentityCard.tsx",
    identityBadges.length === 1,
    identityBadges.length,
  );
  const identityBadge = identityBadges[0] ?? null;
  const identityVariant = identityBadge
    ? jsxAttrExprText(identityBadge, "variant", sfIdentity)
    : null;
  check("found the row Badge's variant expression", identityVariant !== null);
  if (identityVariant !== null) {
    check(
      "the row Badge's variant is driven by missingSecret",
      /\bmissingSecret\b/.test(identityVariant),
      identityVariant,
    );
    check(
      "NEGATIVE: the row Badge's variant is NOT also driven by keyDangling",
      !/\bkeyDangling\b/.test(identityVariant),
      identityVariant,
    );
  }

  const identityBadgeElement =
    identityBadge && ts.isJsxOpeningElement(identityBadge) && ts.isJsxElement(identityBadge.parent)
      ? identityBadge.parent
      : null;
  check(
    "found the row Badge's own JSX element (for its label text)",
    identityBadgeElement !== null,
  );
  if (identityBadgeElement) {
    const badgeText = identityBadgeElement.getText(sfIdentity);
    check(
      'the row Badge\'s LABEL also switches on missingSecret: `missingSecret ? "Missing secret" : …`',
      /missingSecret\s*\?\s*"Missing secret"/.test(badgeText),
      badgeText,
    );
  }

  // --- missingPrivateKey: the same shape, on KeyCard, with no chip to
  // protect - `KeyCard.tsx` has only the one destructive signal.
  const sfKey = ts.createSourceFile(
    FILES.keyCard,
    src.keyCard,
    ts.ScriptTarget.ESNext,
    true,
    ts.ScriptKind.TSX,
  );
  const keyBody = findFunctionBody(sfKey, "KeyCard");
  check("found KeyCard's function body to check", keyBody !== null);

  const keyBadges = keyBody ? findOpeningElementsByTag(keyBody, "Badge", sfKey) : [];
  check("found exactly one <Badge> in KeyCard.tsx", keyBadges.length === 1, keyBadges.length);
  const keyBadge = keyBadges[0] ?? null;
  const keyVariant = keyBadge ? jsxAttrExprText(keyBadge, "variant", sfKey) : null;
  check("found KeyCard's row Badge's variant expression", keyVariant !== null);
  if (keyVariant !== null) {
    check(
      "KeyCard's row Badge variant is driven by missingPrivateKey",
      /\bmissingPrivateKey\b/.test(keyVariant),
      keyVariant,
    );
  }

  const keyBadgeElement =
    keyBadge && ts.isJsxOpeningElement(keyBadge) && ts.isJsxElement(keyBadge.parent)
      ? keyBadge.parent
      : null;
  check(
    "found KeyCard's row Badge's own JSX element (for its label text)",
    keyBadgeElement !== null,
  );
  if (keyBadgeElement) {
    const badgeText = keyBadgeElement.getText(sfKey);
    check(
      'KeyCard\'s row Badge LABEL also switches on missingPrivateKey: `missingPrivateKey ? "Missing private key" : …`',
      /missingPrivateKey\s*\?\s*"Missing private key"/.test(badgeText),
      badgeText,
    );
  }
}

console.log(failed === 0 ? "\nAll vault-shell checks passed." : `\n${failed} check(s) FAILED.`);

// ----------------------------------------------------------------------------
// Mutation table - every mutation actually run against this file's own
// checks, by hand, before this file was considered done. Restored by hash
// each time (`git hash-object` / `git cat-file blob`), never by `git checkout
// --` or `git show HEAD:` (HEAD is wave 2 step 1/2's baseline and would
// discard uncommitted work in the same file). Full transcript, exit codes and
// restore hashes: /tmp/wave2-shell/MUTATIONS.md.
//
//   Mutation                                          Check(s) it killed
//   -------------------------------------------------  ---------------------------
//   M1: RailViewArea.tsx's vault case reverted to      section 1's first two
//     <PagePlaceholder page="vault" />                  checks
//   M2: RailViewArea.tsx's forwards case changed to    section 1's third check
//     <VaultPage /> (negative-control check)             (the negative control)
//   M3: identityRows(...) hoisted out of its useMemo   section 3, naming
//     into the render body                              identityRows(...)
//   M4: deleteIdentity(target.id, async () => [])      section 5, both the
//     - an inline lookup instead of identityHostRefs     positive regex and the
//                                                        "async (" negative
//   M5: a deleteKey(row.key.id) call moved into a       section 6, naming that
//     card's onDelete arrow, outside confirmDelete       call as outside
//                                                        confirmDelete's span
//   M6: the .catch changed to                           section 7's toast(
//     .catch((e) => console.error(e))                    deleteRefusalText(
//                                                        check
//   M7: [contain-intrinsic-size:auto_100px] deleted     section 10, for
//     from IdentityCard.tsx                              identityCard only
//   M8: KeyCard's `vaultKey` prop renamed to `key`      section 11, both the
//     (and VaultPage's call site updated to match)        `vaultKey: VaultKey`
//                                                        check and the `key:`
//                                                        negative
//   M9: "Stored securely in the OS keychain." added     section 12, both the
//     to the delete description                          keychain-name and the
//                                                        safety-word checks
//   M10: SectionEmpty made to always render              section 13's ternary
//     `nothingYet`, collapsing the two cases              check ("actually
//     (`{nothingYet}` instead of                          branches on"),
//     `{matching ? noMatch : nothingYet}`)                 naming the broken
//                                                        function body. NOT the
//                                                        four-literal checks:
//                                                        those stayed green,
//                                                        because `noMatch` and
//                                                        `nothingYet` are still
//                                                        passed as PROP VALUES
//                                                        at both call sites
//                                                        regardless of whether
//                                                        the render logic ever
//                                                        reads `noMatch` - the
//                                                        first draft of section
//                                                        13 checked only the
//                                                        four literals and this
//                                                        mutation went GREEN
//                                                        over it. The ternary
//                                                        check (compiler API,
//                                                        over SectionEmpty's own
//                                                        function body) is what
//                                                        was added to catch it.
//
// ROUND 2 - four gaps an Oracle review measured against the checks above,
// each confirmed by running the mutation in a worktree and recording the
// exit code (transcript: /tmp/wave2-fix-shellcheck/MUTATIONS.md):
//
//   Z2: VaultPage.tsx's root className had          section 9's compiler-
//     `@container` deleted, leaving the header        verified check, naming
//     comment above `return` (which also says          the root className
//     "@container") untouched                          with `@container`
//                                                       missing
//   Z3: IdentityCard.tsx's `cn()` argument           section 10's two
//     `"[contain-intrinsic-size:auto_100px]           compiler-verified
//     [content-visibility:auto]"` emptied to `""`,     checks for
//     the original string moved to a `//` comment      identityCard, naming
//     on the line above                                the (now-empty)
//                                                       root className
//   Z1: SectionEmpty's `const matching = hasAny &&    section 13's new
//     filtering;` narrowed to `const matching =         predicate check,
//     filtering;`                                       naming the
//                                                       mutated body
//   Z5: the identity <SectionEmpty>'s                section 13's new
//     `hasAny={identityRowList.length > 0}` call-       per-call-site check,
//     site prop switched to                             naming
//     `hasAny={visibleIdentities.length > 0}`            `visibleIdentities…`
//   Z4: the hint ternary `{matching ? "Clear the      section 13's new HINT
//     search box…" : nothingYetHint}` collapsed to      check (the headline
//     `{nothingYetHint}`                                check alone stayed
//                                                       green)
//   M10 RE-RUN: both ternaries collapsed to           still kills section
//     `{nothingYet}` / `{nothingYetHint}` (the          13's headline AND
//     original regression this section exists for)      HINT checks
//   Y6: `keyDangling` moved from the key chip's        section 15's chip
//     className to the row `<Badge variant={           check (chip no
//     missingSecret || keyDangling ? …}>`               longer references
//                                                       keyDangling) AND
//                                                       its NEGATIVE Badge
//                                                       check (variant now
//                                                       does)
//   keyDangling-ternary: the chip's                   section 15's chip
//     `keyDangling ? "text-destructive" :               check (chip's
//     "text-muted-foreground"` collapsed to just        className no longer
//     `"text-muted-foreground"`                         mentions
//                                                       keyDangling)
process.exit(failed === 0 ? 0 : 1);
