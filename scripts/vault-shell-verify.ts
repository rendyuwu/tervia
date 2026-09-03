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
  identityEditorDialog: "src/modules/vault/editor/IdentityEditorDialog.tsx",
  keyEditorDialog: "src/modules/vault/editor/KeyEditorDialog.tsx",
  draft: "src/modules/vault/editor/draft.ts",
  hostCard: "src/modules/hosts/page/HostCard.tsx",
  hostsPage: "src/modules/hosts/HostsPage.tsx",
  // Section 16's fourth containment root (step 10, 6f wave 2) - see that
  // section for why this grows the parity check instead of the file getting
  // its own copy of it.
  ruleCard: "src/modules/forwards/page/RuleCard.tsx",
  // Section 16's FOURTH GRID CALL SITE (VLT-101(b)) - Port Forwarding stopped
  // being a full-width list and took the same grid literal. Added here and to
  // section 16 alone: the only thing that walks every key of this map is the
  // `read` below, and every section that sweeps a SET names it as its own
  // explicit list (`NEW_FILES`, `SAFETY_CLAIM_FILES`, section 16's own
  // containment tuple), so a new key joins no sweep by accident.
  //
  // CHECKED RATHER THAN ASSUMED, and worth checking again the next time this
  // map grows, because the sections sweep RAW SOURCE and a file can fail one
  // on its prose: section 9's `/\b(sm|md|lg|xl|2xl):/` ban would match this
  // page today purely on the `sm:`/`xl:` inside the comment above its grid,
  // which says those are the breakpoints it is NOT using. That is a false FAIL
  // one careless `...NEW_FILES` away, not a hypothetical one.
  forwardsPage: "src/modules/forwards/ForwardsPage.tsx",
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

// Section 12's sweep is wider than section 9's: the two editor dialogs and
// `editor/draft.ts` are where a sentence about a stored private key is most
// likely to be written, so they join the "no false safety claim" check.
// Section 9 must keep using NEW_FILES, not this - a dialog is portalled to
// `document.body`, outside every `@container`, so `sm:max-w-lg` is correct
// there and would be a false FAIL under section 9's viewport-breakpoint ban.
const SAFETY_CLAIM_FILES = [
  ...NEW_FILES,
  "identityEditorDialog",
  "keyEditorDialog",
  "draft",
] as const;

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

/** The `const <name> = ...` variable declaration anywhere under `root` -
 *  VLT-76's pin 3 needs this, and this file had no variable-declaration
 *  finder before it (VLT-33: there is no `scripts/lib`, so helpers are
 *  copied per script on purpose). Pins a definition, not an identifier: a
 *  check that only reads WHICH NAME is handed to a prop (like section 14's
 *  `rowsProp === "keyRowList"` below) is satisfied by
 *  `const keyRowList = visibleKeys;`, or by the two definitions swapped -
 *  either makes the key picker silently follow the page's search box. */
function findConstDeclaration(root: ts.Node, name: string): ts.VariableDeclaration | null {
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

// ============================================================================
// 1. The rail branch was replaced, and only that branch.
// ============================================================================
// Protects: `RailViewArea.tsx`'s `vault` case renders `<VaultPage />`, its
// `PagePlaceholder` call is gone, and - the negative control - the `forwards`
// case (6f wave 2's own, landed at step 8) still renders `<ForwardsPage />`.
// The third check is what stops an edit that replaced BOTH branches from
// reading as correct: M2 below flips `forwards` to `<VaultPage />` too, and
// only the third check can notice.
//
// RE-AIMED (step 10, closing the red window step 8 opened on purpose): this
// check used to read `<PagePlaceholder page="forwards"`, which was correct
// while 6f wave 2 had not yet replaced that branch and deliberately wrong
// (a FAIL on purpose) from the moment `RailViewArea.tsx`'s `forwards` case
// itself changed - the orchestrator measured the window as exactly this one
// check, `vault-shell` going 165 ok -> 164 ok + 1 FAIL, and nothing else in
// this file. Kept as its own check, separate from the vault positives above,
// so a failure here names WHICH page's branch drifted.
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
    "NEGATIVE CONTROL: the forwards case renders <ForwardsPage /> (its own branch, landed 6f wave 2)",
    /case "forwards":[\s\S]{0,200}<ForwardsPage\s*\/>/.test(r),
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
for (const key of SAFETY_CLAIM_FILES) {
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
// 14. Every affordance opens something, and nothing else is offered yet.
// ============================================================================
// Protects: a button that opens nothing is the dead-affordance class already
// filed against this app once (VLT-69, a header drag that silently does
// nothing under a rail view). Wave 2 held that line by FORBIDDING the strings;
// wave 3 implements three of the five, so those three move from the forbidden
// list to a positive claim - the New buttons set an editor target, the cards'
// Edit prop does too, and both dialogs are actually rendered. Export and
// Import stay forbidden: nothing implements them before 6g.
console.log("\n[14] every affordance opens something; Export/Import are still not offered");
for (const label of ["Export", "Import"]) {
  check(`VaultPage.tsx contains no "${label}" string`, !src.vaultPage.includes(label));
}
for (const key of ["identityCard", "keyCard"] as const) {
  for (const prop of ["onSelect", "onConnect"]) {
    check(`${FILES[key]} declares no ${prop} prop`, !src[key].includes(prop));
  }
  // The cards are still non-interactive containers: two icon buttons, and no
  // focusable card. `HostCard.tsx:63,73-82` carries tabIndex/onClick/
  // onDoubleClick/onKeyDown because that card IS interactive; adding any of
  // them here would create a focusable element that does nothing.
  for (const smell of ["tabIndex", "onDoubleClick", "onKeyDown"]) {
    check(`${FILES[key]} has no ${smell}`, !src[key].includes(smell));
  }
}

{
  const sf = ts.createSourceFile(
    FILES.vaultPage,
    src.vaultPage,
    ts.ScriptTarget.ESNext,
    true,
    ts.ScriptKind.TSX,
  );
  const body = findFunctionBody(sf, "VaultPage");
  check("found VaultPage's function body to check", body !== null);

  const buttons = body ? findOpeningElementsByTag(body, "Button", sf) : [];
  check("found VaultPage's header buttons", buttons.length >= 2, buttons.length);
  for (const [label, setter] of [
    ["New identity", "setIdentityTarget"],
    ["New key", "setKeyTarget"],
  ] as const) {
    const el = buttons.find((b) => jsxAttrExprText(b, "aria-label", sf) === label) ?? null;
    check(`found the <Button aria-label="${label}">`, el !== null);
    const onClick = el ? jsxAttrExprText(el, "onClick", sf) : null;
    check(`${label}'s onClick expression was found`, onClick !== null);
    if (onClick !== null) {
      check(
        `${label} opens an editor: its onClick calls ${setter}`,
        onClick.includes(`${setter}(`) && onClick.includes(`mode: "create"`),
        onClick,
      );
    }
  }

  // ...and the dialogs the setters open are actually rendered, with a target.
  for (const tag of ["IdentityEditorDialog", "KeyEditorDialog"]) {
    const els = body ? findOpeningElementsByTag(body, tag, sf) : [];
    check(`exactly one <${tag}> is rendered`, els.length === 1, els.length);
    const target = els[0] ? jsxAttrExprText(els[0], "target", sf) : null;
    check(`<${tag}> is handed a target`, target !== null, target ?? undefined);
  }

  // The identity editor gets the UNFILTERED rows. Handing it `visibleKeys`
  // would make the key picker follow the page's search box, which is a
  // different surface's query deciding what a form can name - and it would
  // look right in every screenshot where the box is empty.
  const identityEditor =
    (body ? findOpeningElementsByTag(body, "IdentityEditorDialog", sf) : [])[0] ?? null;
  const rowsProp = identityEditor ? jsxAttrExprText(identityEditor, "keyRows", sf) : null;
  check(
    "the identity editor is handed keyRowList, not the filtered list",
    rowsProp === "keyRowList",
    rowsProp ?? undefined,
  );

  // Pin 3 (VLT-76): `keyRowList` pinned by its own DEFINITION, not merely by
  // the identifier the check above reads off the prop. `const keyRowList =
  // visibleKeys;` - or the two definitions swapped so `keyRowList` itself
  // becomes the ranked list - leaves the check above green while the key
  // picker silently starts following the page's search box.
  const keyRowListDecl = body ? findConstDeclaration(body, "keyRowList") : null;
  check(
    "keyRowList's variable declaration was found - a missing anchor must fail loudly here",
    keyRowListDecl !== null,
  );
  if (keyRowListDecl) {
    const init = keyRowListDecl.initializer;
    const initText = init ? init.getText(sf) : "";
    check(
      "keyRowList's initializer is a useMemo(...) call",
      init !== undefined && ts.isCallExpression(init) && init.expression.getText(sf) === "useMemo",
      initText,
    );
    check(
      "keyRowList's initializer text contains keyRows(",
      initText.includes("keyRows("),
      initText,
    );
    // A negative over a FOUND declaration, never over "" - `rankKeys`/`query`
    // are the two tells of the FILTERED list, so their absence here is what
    // tells `keyRowList` apart from `visibleKeys` by what it actually is,
    // not by what it happens to be named.
    check(
      "keyRowList's initializer names neither rankKeys nor query",
      !/\brankKeys\b/.test(initText) && !/\bquery\b/.test(initText),
      initText,
    );
  }

  // Each card's onEdit reaches the matching setter, in edit mode.
  for (const [tag, setter, idExpr] of [
    ["IdentityCard", "setIdentityTarget", "row.identity.id"],
    ["KeyCard", "setKeyTarget", "row.key.id"],
  ] as const) {
    const el = (body ? findOpeningElementsByTag(body, tag, sf) : [])[0] ?? null;
    check(`found the <${tag}> call site`, el !== null);
    const onEdit = el ? jsxAttrExprText(el, "onEdit", sf) : null;
    check(`<${tag}> passes onEdit`, onEdit !== null);
    if (onEdit !== null) {
      check(
        `${tag}'s onEdit opens the editor on THIS row, in edit mode`,
        onEdit.includes(`${setter}(`) && onEdit.includes(`mode: "edit"`) && onEdit.includes(idExpr),
        onEdit,
      );
    }
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

// ============================================================================
// 16. The duplicated layout strings still agree with each other.
// ============================================================================
// Protects: four files carry the identical containment pair and four call
// sites carry the identical responsive grid, and nothing asserted that they
// match. The remedy a review proposed was one shared shell; the reason it is
// not here is that a vault-only shell would cut three copies to two -
// `hosts/page/HostCard.tsx` is the third and lives in another module - so it
// would shrink the property rather than close it, while rewriting hand-tested
// code and moving the root element sections 10 and 15 anchor on. A structural
// equality between the copies costs one section and makes a later divergence
// deliberate, which is exactly what the search box already gets
// (`hosts-header-narrow-verify.ts:244-247`). If a shared shell ever lands,
// this section is what has to be deleted on purpose.
//
// `usageDetail` is deliberately NOT checked here: it is nine lines of copy
// differing only in its noun, a drift in it is visible on screen rather than
// silent, and a check per duplicated helper is the "one check per copy" this
// section exists to avoid.
//
// GROWN A FOURTH ROOT (step 10, 6f wave 2): `RuleCard.tsx` carries the
// identical containment pair too (§4(a) Q3) - "this is the fourth root that
// carries it", per that file's own comment on the pair. If a future owner
// picks the shared shell instead of a fourth hand-written copy, THIS is the
// line where this section is deleted on purpose, per that same decision.
//
// AND A FOURTH GRID CALL SITE (VLT-101(b)): `ForwardsPage.tsx` swapped its
// `flex flex-col gap-2` list for the same literal, so the containment tuple
// and the grid tuple now cover the same four modules. The two halves of this
// section stayed the same size for three waves and grew together in this one,
// which is the argument FOR the shared shell getting stronger rather than the
// argument against it changing - a fifth surface should take that trade,
// not a fifth hand-written copy.
//
// THE 100px IN THAT PAIR IS NOW WRONG FOR `RuleCard`, and this section is why
// it was not fixed here: a quarter-width forwards card measures ~128px empty
// and ~205px with a running rule's stop note (`RuleCard.tsx`'s own comment on
// the pair does the arithmetic), but the check below demands all four roots be
// IDENTICAL, so moving one is a red check and moving all four is a re-measure
// of `HostCard`, `IdentityCard` and `KeyCard` as well. Deliberately deferred:
// an under-estimate grows the scrollbar as cards paint in and never jumps it
// backwards, which is the failure the pair exists for.
console.log("\n[16. VLT-75 parity] the containment pair and the responsive grid still agree");
{
  // --- the containment pair: IdentityCard, KeyCard, HostCard, RuleCard ---
  const CONTAINMENT_TOKEN = /^\[(contain-intrinsic-size|content-visibility):/;
  const containmentTexts: string[] = [];
  for (const [key, functionName] of [
    ["identityCard", "IdentityCard"],
    ["keyCard", "KeyCard"],
    ["hostCard", "HostCard"],
    ["ruleCard", "RuleCard"],
  ] as const) {
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
      classText.length > "[contain-intrinsic-size:auto_100px]".length,
      classText,
    );
    const tokens = classText
      .split(/\s+/)
      .filter((t) => CONTAINMENT_TOKEN.test(t))
      .sort();
    check(
      `${FILES[key]}'s root carries exactly two containment tokens`,
      tokens.length === 2,
      tokens.join(" "),
    );
    containmentTexts.push(tokens.join(" "));
  }
  check(
    "the containment pair is identical across IdentityCard, KeyCard, HostCard and RuleCard",
    containmentTexts.every((t) => t === containmentTexts[0]),
    containmentTexts.join(" | "),
  );

  // --- the responsive grid: two call sites on VaultPage, one on HostsPage,
  //     one on ForwardsPage ---
  //
  // GRID_RE ONLY SEES A SINGLE-LINE `<div className="grid …">`, which is a
  // shape rather than an accident: prettier (printWidth 100) never breaks a
  // JSX element whose sole attribute is a string literal, so all four of these
  // stay on one line at 114-116 columns. Give any of those divs a SECOND
  // attribute and prettier splits it across lines, this regex stops seeing it,
  // and the file's count drops. The counts below are what make that loud - a
  // section that only compared the strings it found would go green on finding
  // none, which is the failure mode this shape has to be paired with.
  const GRID_RE = /<div className="(grid [^"]*)">/g;
  const vaultGridMatches = [...src.vaultPage.matchAll(GRID_RE)].map((m) => m[1]);
  const hostsGridMatches = [...src.hostsPage.matchAll(GRID_RE)].map((m) => m[1]);
  const forwardsGridMatches = [...src.forwardsPage.matchAll(GRID_RE)].map((m) => m[1]);
  check(
    "VaultPage.tsx has exactly 2 responsive-grid divs",
    vaultGridMatches.length === 2,
    vaultGridMatches.length,
  );
  check(
    "HostsPage.tsx has exactly 1 responsive-grid div",
    hostsGridMatches.length === 1,
    hostsGridMatches.length,
  );
  // VLT-101(b): Port Forwarding used to render `flex flex-col gap-2`, one
  // full-width row per rule, and this section could not tell - it named the
  // files it swept, and that page was not one of them, so the fourth surface
  // in the set was free to be laid out any way at all. DCR-5's row is exactly
  // "the cross-module decision that nothing pins decays silently"; this is the
  // check that stops the decay being invisible rather than the one that stops
  // it happening.
  check(
    "ForwardsPage.tsx has exactly 1 responsive-grid div",
    forwardsGridMatches.length === 1,
    forwardsGridMatches.length,
  );
  if (
    vaultGridMatches.length === 2 &&
    hostsGridMatches.length === 1 &&
    forwardsGridMatches.length === 1
  ) {
    check(
      "VaultPage's two grid strings are equal to each other",
      vaultGridMatches[0] === vaultGridMatches[1],
      vaultGridMatches.join(" | "),
    );
    check(
      "VaultPage's grid string equals HostsPage's",
      vaultGridMatches[0] === hostsGridMatches[0],
      [vaultGridMatches[0], hostsGridMatches[0]].join(" | "),
    );
    check(
      "VaultPage's grid string equals ForwardsPage's",
      vaultGridMatches[0] === forwardsGridMatches[0],
      [vaultGridMatches[0], forwardsGridMatches[0]].join(" | "),
    );
    // VLT-80/7d(d): a LITERAL pin, not merely agreement between the four call
    // sites. The three checks above pass a coordinated edit that changes all
    // four grids together - exactly the mutation withheld from this step
    // (P14, run by the orchestrator once step 4 has retired) - because they
    // never compare against a value nobody can move for free. Nothing else in
    // this 53-script suite anchors this string, so without this pin a
    // coordinated four-site change passes every one of them.
    const PINNED_GRID =
      "grid grid-cols-1 gap-2 @[580px]:grid-cols-2 @[860px]:grid-cols-3 @[1140px]:grid-cols-4";
    // AGAINST ALL FOUR STRINGS AND NOT JUST VaultPage'S, which is what it
    // compared while there were three sites. Transitively the two were the
    // same claim - if every equality above holds and VaultPage matches the
    // pin, so does everyone - but that made this check's verdict depend on
    // OTHER checks passing, and the first mutation run of the ForwardsPage
    // arm proved what that costs: moving ForwardsPage's `@[1140px]` to
    // `@[1200px]` turned the equality red and left the PIN green, so the one
    // check whose name says "the grid className is pinned" was reporting ok
    // about a call site that was off the literal. Reading `.every` here makes
    // each check answer its own question. The equalities stay because they
    // name WHICH pair diverged, which a single `.every` cannot.
    const allGridMatches = [...vaultGridMatches, ...hostsGridMatches, ...forwardsGridMatches];
    check(
      "every responsive grid className, at all four call sites, is pinned to its current literal value",
      allGridMatches.every((g) => g === PINNED_GRID),
      allGridMatches.join(" | "),
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
//
// STEP 10 (6f wave 2) - two extensions, not new mutations of THIS file's own
// logic: section 1's third check was RE-AIMED (see that section's comment for
// the red window it closes) and section 16 grew a fourth root:
//
//   P1 (forwards-shell-verify.ts's table): both RailViewArea branches to     section 1's re-aimed
//     <ForwardsPage />                                                       third check
//   RuleCard.tsx's containment pair                                          section 16's new
//     ([contain-intrinsic-size:auto_100px]                                    per-root check for
//     [content-visibility:auto]) deleted                                      ruleCard, and the
//                                                                              4-way equality
//
// VLT-101(b) - section 16's grid half grew its fourth call site
// (`ForwardsPage.tsx`), and the pin check was re-aimed at all four strings
// because M1 caught it answering for one:
//
//   M1: ForwardsPage.tsx's grid literal moved from            RED, exit 1. FIRST RUN killed
//     @[1140px]:grid-cols-4 to @[1200px]:grid-cols-4           the vault==forwards equality
//                                                              ALONE - the pin compared
//                                                              vaultGridMatches[0] to
//                                                              PINNED_GRID and VaultPage was
//                                                              untouched, so the one check
//                                                              named "the grid className is
//                                                              pinned" stayed GREEN over a
//                                                              call site that was off the
//                                                              literal. The pin now reads
//                                                              `.every` over all four; RE-RUN
//                                                              kills both.
//   M2: ForwardsPage.tsx's grid div reverted to              RED, exit 1 - "ForwardsPage.tsx
//     <div className="flex flex-col gap-2">                    has exactly 1 responsive-grid
//                                                              div", reporting 0. The three
//                                                              string checks went SILENT, not
//                                                              green: the count guard skips
//                                                              them. That is the check that
//                                                              proves GRID_RE actually sees
//                                                              this file's div, and the reason
//                                                              a count has to sit in front of
//                                                              every comparison here.
//   M3: RuleCard.tsx's root className narrowed to            RED, exit 1 - both the per-root
//     "[content-visibility:auto]"                              "exactly two containment
//                                                              tokens" check for ruleCard and
//                                                              the 4-way equality
process.exit(failed === 0 ? 0 : 1);
