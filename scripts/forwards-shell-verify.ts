/**
 * Self-check for wave 2 step 10: the Port Forwarding page UI - the rail-view
 * branch swap in `RailViewArea.tsx`, `runtime.ts`'s selector shapes,
 * `RuleEditorDialog.tsx`/`draft.ts`'s save path, `ForwardsPage.tsx`'s
 * assembly, `RuleCard.tsx`'s row, and `controller.ts`'s Start/Stop. Run:
 * `pnpm verify forwards-shell` (or `npx tsx scripts/forwards-shell-verify.ts`
 * to iterate).
 *
 * Sections 1-10 are SOURCE-TEXT and TypeScript-compiler-API checks, the same
 * split `vault-shell-verify.ts` uses and for the same reason stated there:
 * "is this call inside a useMemo(...)" and "is this identifier read inside
 * THIS JSX element's subtree" are nesting/ancestry questions a distance
 * heuristic reads wrong, so those go through the compiler API; everything
 * else is plain source text, because a false PASS from the wrong tool is
 * worse than the extra code the right one costs.
 *
 * The C-series (bottom of the file) is behavioural: it drives `controller.ts`'s
 * `startRule`/`stopRule` under plain node through the `RuntimeDeps` seam that
 * file exports for exactly this purpose (see its own header) - never through a
 * Tauri bridge stand-in, because the seam's whole point is that a check does
 * not need one. The harness SHAPE - parked opens resolved by hand, `settle()`,
 * a call log - is copied from `scripts/rdp-tunnel-verify.ts`, applied to the
 * seam instead of the bridge.
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import ts from "typescript";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (rel: string) => readFileSync(join(repoRoot, rel), "utf8");

let failed = 0;
function check(name: string, ok: boolean, detail?: unknown): void {
  if (ok) {
    console.log(`  ok: ${name}`);
    return;
  }
  console.error(`  FAIL: ${name}`, detail === undefined ? "" : JSON.stringify(detail));
  failed++;
}

const FILES = {
  runtime: "src/modules/forwards/runtime.ts",
  draft: "src/modules/forwards/editor/draft.ts",
  ruleEditorDialog: "src/modules/forwards/editor/RuleEditorDialog.tsx",
  forwardsPage: "src/modules/forwards/ForwardsPage.tsx",
  controller: "src/modules/forwards/controller.ts",
  derive: "src/modules/forwards/page/derive.ts",
  ruleCard: "src/modules/forwards/page/RuleCard.tsx",
  railViewArea: "src/app/components/RailViewArea.tsx",
} as const;

const src = Object.fromEntries(Object.entries(FILES).map(([k, p]) => [k, read(p)])) as Record<
  keyof typeof FILES,
  string
>;

// ============================================================================
// stripComments - the tenth copy of this helper in this suite (VLT-33's
// extraction is the real remedy; this step does not attempt it, per the
// plan's §5 boundary 9). Copied from `host-editor-verify.ts:191-225`, JSX
// branch in the NEGATIVE-LOOKAHEAD form - the lazy form reads as equivalent
// and is not: it crosses an intervening `*/` and once swallowed 50752
// characters in a different script, silencing a negative that then ran blind
// over deleted text. Every new script stripping a `.tsx` carries the same
// two-assertion self-test (below, right after the function).
// ============================================================================
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

function stripComments(src: string): string {
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

// Self-test: KEEP survives, and the JSX comment does not.
{
  const selfTest = stripComments(
    "type P = { /** c */ x: X };\nconst KEEP = 1;\nconst j = <div>{/* c */}</div>;",
  );
  check("stripComments self-test: KEEP survives", selfTest.includes("KEEP"));
  check(
    "stripComments self-test: the JSX comment {/* c */} does not survive",
    !/\{\s*\/\*\s*c\s*\*\/\s*\}/.test(selfTest),
  );
}

// ============================================================================
// Shared compiler-API helpers - copied/adapted from `vault-shell-verify.ts`,
// "your closest model" per the brief.
// ============================================================================

function findFunctionBody(root: ts.Node, name: string): ts.Node | null {
  let result: ts.Node | null = null;
  const visit = (n: ts.Node): void => {
    if (ts.isFunctionDeclaration(n) && n.name?.text === name && n.body) result = n.body;
    ts.forEachChild(n, visit);
  };
  visit(root);
  return result;
}

/** The `const <name> = (...) => ...` arrow function, sync or async, anywhere
 *  under `root` - `RuleEditorDialog`'s `save` is this shape. */
function findConstArrowDeclaration(root: ts.Node, name: string): ts.ArrowFunction | null {
  let result: ts.ArrowFunction | null = null;
  const visit = (n: ts.Node): void => {
    if (
      ts.isVariableDeclaration(n) &&
      ts.isIdentifier(n.name) &&
      n.name.text === name &&
      n.initializer &&
      ts.isArrowFunction(n.initializer)
    ) {
      result = n.initializer;
    }
    ts.forEachChild(n, visit);
  };
  visit(root);
  return result;
}

function findCallsTo(root: ts.Node, calleeName: string, sf: ts.SourceFile): ts.CallExpression[] {
  const out: ts.CallExpression[] = [];
  const visit = (n: ts.Node): void => {
    if (ts.isCallExpression(n) && n.expression.getText(sf) === calleeName) out.push(n);
    ts.forEachChild(n, visit);
  };
  visit(root);
  return out;
}

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

/** Every `<Field label="...">...</Field>` JSX element whose `label` string
 *  equals `label`. */
function findFieldByLabel(root: ts.Node, label: string, sf: ts.SourceFile): ts.JsxElement | null {
  let result: ts.JsxElement | null = null;
  const visit = (n: ts.Node): void => {
    if (ts.isJsxElement(n) && n.openingElement.tagName.getText(sf) === "Field") {
      const labelText = jsxAttrExprText(n.openingElement, "label", sf);
      if (labelText === label) result = n;
    }
    ts.forEachChild(n, visit);
  };
  visit(root);
  return result;
}

/** Does any `{...}` JSX expression anywhere under `root` reference the
 *  identifier `name` (an exact AST identifier match, never a substring - so
 *  `hostError` cannot be mistaken for a reference to `error`)? */
function containsIdentifierInJsxExpression(root: ts.Node, name: string): boolean {
  let found = false;
  const visitExpr = (m: ts.Node): void => {
    if (found) return;
    if (ts.isIdentifier(m) && m.text === name) {
      found = true;
      return;
    }
    ts.forEachChild(m, visitExpr);
  };
  const visit = (n: ts.Node): void => {
    if (found) return;
    if (ts.isJsxExpression(n) && n.expression) visitExpr(n.expression);
    ts.forEachChild(n, visit);
  };
  visit(root);
  return found;
}

function findPropertyValue(
  obj: ts.ObjectLiteralExpression,
  name: string,
  sf: ts.SourceFile,
): ts.Expression | null {
  for (const prop of obj.properties) {
    if (ts.isPropertyAssignment(prop) && prop.name.getText(sf) === name) return prop.initializer;
  }
  return null;
}

/** Walking up from `node`, is every ancestor up to (and including reaching)
 *  `fnBody` free of crossing into a NESTED function? Used to tell a direct
 *  statement of a function's own body from a call buried inside a decoy arrow
 *  declared in the same scope - the count alone cannot bite that deletion
 *  (VLT-76's own lesson, `vault-shell-verify.ts`'s M5/section 6). */
function isDirectlyInFunctionBody(node: ts.Node, fnBody: ts.Node): boolean {
  let cur: ts.Node | undefined = node.parent;
  while (cur && cur !== fnBody) {
    if (
      ts.isFunctionDeclaration(cur) ||
      ts.isFunctionExpression(cur) ||
      ts.isArrowFunction(cur) ||
      ts.isMethodDeclaration(cur)
    ) {
      return false;
    }
    cur = cur.parent;
  }
  return cur === fnBody;
}

/** The source text of `const <name> = <expr>`'s initializer, or `null`. Pins a
 *  derived flag at ITS OWN DEFINITION - a check on the identifier handed to a
 *  callback is defeated by an alias (`const pageStops = running;`), which is
 *  the rebind trap §4's trap list names. */
function findConstInitializerText(root: ts.Node, name: string, sf: ts.SourceFile): string | null {
  let result: string | null = null;
  const visit = (n: ts.Node): void => {
    if (
      ts.isVariableDeclaration(n) &&
      ts.isIdentifier(n.name) &&
      n.name.text === name &&
      n.initializer
    ) {
      result = n.initializer.getText(sf);
    }
    ts.forEachChild(n, visit);
  };
  visit(root);
  return result;
}

/** The property names of `type <name> = { … }`, or `null` when there is no such
 *  alias with an object-literal type. Used to keep an AST negative over
 *  `x.<field>` from going vacuous when `<field>` is renamed away. */
function findTypeAliasMembers(root: ts.Node, name: string, sf: ts.SourceFile): string[] | null {
  let result: string[] | null = null;
  const visit = (n: ts.Node): void => {
    if (ts.isTypeAliasDeclaration(n) && n.name.text === name && ts.isTypeLiteralNode(n.type)) {
      result = n.type.members.filter(ts.isPropertySignature).map((m) => m.name.getText(sf));
    }
    ts.forEachChild(n, visit);
  };
  visit(root);
  return result;
}

/**
 * Walking out from `stmt`, does anything DECIDE whether it runs before the
 * enclosing function's own body is reached? `true` only when every step out is
 * an unconditional one - a plain block, or a `try`'s own `tryBlock` - so an
 * `if`, `switch`, loop or `catch` anywhere on that path answers `false`.
 *
 * Transplanted from `forward-autostart-verify.ts:1342-1348`'s
 * `stmt.parent === body`, with the one extra hop this file's two call sites
 * need: each guarded stop is a direct statement of its function's own `try`, so
 * a bare parent comparison against the function body is `false` for the code as
 * written. Self-terminating on the nearest function so neither caller has to
 * hand it a body - the `if` at `ForwardsPage.tsx`'s confirm sits inside an
 * async IIFE, not inside the `useCallback` factory.
 *
 * WHY IT IS NEEDED BESIDE {@link isDirectlyInFunctionBody}, which is the
 * distinction the comment on section 12's use of that helper used to blur:
 * that one refuses NESTING inside another function and nothing else - its own
 * docstring says so - and neither a count, an index order, an awaited parent
 * nor an exact-condition pin can see a wrapper. Measured against round 4:
 *
 *   // ForwardsPage.tsx        if (target.rule.id === "") {
 *   // RuleEditorDialog.tsx    if (id === "") {
 *
 * around either guarded stop left all four scripts, `tsc --noEmit` and
 * `prettier --check` green with the stop unreachable for every rule. Everything
 * else survives by construction: the count stays 1, the index order holds,
 * `ts.isAwaitExpression(stop.parent)` holds, the argument node is unchanged, and
 * `enclosingIf` walks to the NEAREST `if`, so the exact-condition pin still
 * matches the inner one.
 */
function isUnguardedToItsFunctionBody(stmt: ts.Statement): boolean {
  let cur: ts.Node = stmt;
  for (;;) {
    const block: ts.Node | undefined = cur.parent;
    // Not a block at all means a braceless `if (x) <stmt>` / `for (…) <stmt>`,
    // which is a guard written without the braces.
    if (block === undefined || !ts.isBlock(block)) return false;
    const owner: ts.Node | undefined = block.parent;
    if (owner === undefined) return false;
    if (
      ts.isFunctionDeclaration(owner) ||
      ts.isFunctionExpression(owner) ||
      ts.isArrowFunction(owner) ||
      ts.isMethodDeclaration(owner)
    ) {
      return true;
    }
    // A `try` runs its own block unconditionally; `catch` and `finally` do not,
    // so only `tryBlock` continues the walk.
    if (ts.isTryStatement(owner) && owner.tryBlock === block) {
      cur = owner;
      continue;
    }
    return false;
  }
}

/** The arrow function's own returned expression: the concise body directly,
 *  or a block body's single `return <expr>;` statement's expression. `null`
 *  for anything else (multi-statement blocks, no return) - every selector in
 *  `runtime.ts` today is a concise-body arrow, but this does not assume it. */
function arrowBodyExpression(arrow: ts.ArrowFunction): ts.Expression | null {
  if (!ts.isBlock(arrow.body)) return arrow.body;
  const stmts = arrow.body.statements;
  if (stmts.length === 1 && ts.isReturnStatement(stmts[0]) && stmts[0].expression) {
    return stmts[0].expression;
  }
  return null;
}

/** Every `.ts`/`.tsx` file under `dir`, recursively. */
function walkSrcFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) out.push(...walkSrcFiles(full));
    else if (/\.(ts|tsx)$/.test(entry)) out.push(full);
  }
  return out;
}

// Whitespace AND trailing commas are Prettier's; everything else is the
// claim. E4 measured why the comma half is needed: a legal multi-line
// reformat of `ruleRecordFrom(id, draft)` under this repo's Prettier config
// (trailing commas) adds a comma after the last argument, which plain
// whitespace-collapsing does not remove - a false FAIL on a reformat that
// changed nothing the claim cares about, the exact trap the brief's mutation
// discipline section names.
const norm = (s: string): string => s.replace(/\s+/g, "").replace(/,+([)\]}])/g, "$1");

// ============================================================================
// The selector allow-list - A COPY of `scripts/forward-autostart-verify.ts`'s
// `selectorParamName` + `primitiveSelectorBody`, the eleventh copied helper in
// this suite. There is no `scripts/lib` to share it through and creating one is
// VLT-33's extraction, not this round's; the copy is noted here so the two
// cannot silently diverge unremarked.
//
// WHAT IT REPLACED, AND WHY THE POLARITY HAD TO FLIP. This section used to run
// a four-name DENY-LIST (`isForbiddenSelectorBody`: object literal, array
// literal, spread, and a call to `.map`/`Object.keys`/`Object.values`/
// `Object.entries`) over `useForwardRuntime`'s selectors, while its twin in
// `forward-autostart-verify.ts` had already flipped to this allow-list for
// `useHostOwnedForwards`. So the store EVERY ROW READS was the one still behind
// the weaker check. Measured against four fresh-reference hooks added to
// `runtime.ts`, each of which came back GREEN with a fresh PASSING assertion
// calling it "a primitive shape" (141 -> 157 ok, `tsc` and `prettier` clean):
//
//   useForwardRuntime((s) => ({ port: …, sid: … }))
//   useForwardRuntime((s) => (s.byRule[id]?.status ?? "x", Object.keys(s.byRule)))
//   useForwardRuntime((s) => s.byRule[ruleId] ?? {})
//   useForwardRuntime((s) => new Set(Object.getOwnPropertyNames(s.byRule)))
//
// Two of the deny-list's four names could never fire at all (an object-literal
// arrow body must be parenthesised, so the node here is a
// `ParenthesizedExpression`; `(s) => ...x` is a syntax error, so a
// `SpreadElement` cannot occupy this position), and the set of ways to build a
// fresh reference is OPEN while the set of shapes that can only yield a
// primitive is small and CLOSED. Hence: anything not named below is guilty until
// argued, INCLUDING EVERY CALL EXPRESSION.
//
// The live code was fine throughout - `runtime.ts`'s four real selectors all
// return primitives - so this was a check hole, not a defect.
// ============================================================================

/** The selector arrow's own parameter name, whitespace-normalised, or `""` when
 *  it has none. What {@link primitiveSelectorBody}'s access-chain arm is ROOTED
 *  ON: the letter `s` is this codebase's habit and not the claim, and a check
 *  that reddens when somebody writes `(state) => state.byRule[id]?.status` is a
 *  check the next reader weakens rather than reads. */
function selectorParamName(arrow: ts.ArrowFunction, sf: ts.SourceFile): string {
  const p = arrow.parameters[0];
  return p ? norm(p.name.getText(sf)) : "";
}

/**
 * Can this selector body only ever yield a PRIMITIVE? Returns the REASON as
 * well as the verdict, so a failure names the shape it refused instead of only
 * echoing the text. See the block comment above for why this is an allow-list.
 */
function primitiveSelectorBody(
  expr: ts.Expression,
  sf: ts.SourceFile,
  param: string,
): { ok: true } | { ok: false; why: string } {
  // Parentheses FIRST and to a fixed point, because parenthesising is how an
  // object-literal arrow body has to be written at all - unwrapping later would
  // leave the headline case looking like a shape nobody named.
  let cur: ts.Expression = expr;
  while (ts.isParenthesizedExpression(cur)) cur = cur.expression;

  // `!x`, `-x`, `+x`, `~x`, `typeof x`: a primitive whatever the operand is.
  if (ts.isPrefixUnaryExpression(cur) || ts.isTypeOfExpression(cur)) return { ok: true };

  if (ts.isBinaryExpression(cur)) {
    const kind = cur.operatorToken.kind;
    // `??`, `||` and `&&` PASS AN OPERAND THROUGH, so each side has to qualify
    // on its own: `s.byRule[id] ?? {}` is a fresh object on every miss.
    if (
      kind === ts.SyntaxKind.QuestionQuestionToken ||
      kind === ts.SyntaxKind.BarBarToken ||
      kind === ts.SyntaxKind.AmpersandAmpersandToken
    ) {
      const left = primitiveSelectorBody(cur.left, sf, param);
      if (!left.ok) return left;
      return primitiveSelectorBody(cur.right, sf, param);
    }
    // THE COMMA OPERATOR PASSES ITS RIGHT OPERAND THROUGH, exactly like `??`,
    // and the LEFT one is evaluated and thrown away so it need not qualify.
    // `(0, X)` alone is caught by TS2695; any non-trivial left operand dodges
    // that, and a return annotation cannot see it either.
    if (kind === ts.SyntaxKind.CommaToken) return primitiveSelectorBody(cur.right, sf, param);
    // THE ASSIGNMENTS - `=`, `+=`, `??=`, `||=`, `&&=` and the rest - the other
    // operator class whose value is an operand. BOTH operands have to qualify,
    // because `??=`/`||=`/`&&=` yield EITHER side; in practice that refuses
    // every assignment, since a target is an identifier or an access chain that
    // does not reach a primitive field - and refusing is the right answer:
    // nothing legitimate assigns inside a zustand selector.
    if (kind >= ts.SyntaxKind.FirstAssignment && kind <= ts.SyntaxKind.LastAssignment) {
      const left = primitiveSelectorBody(cur.left, sf, param);
      if (!left.ok) return left;
      return primitiveSelectorBody(cur.right, sf, param);
    }
    // Every other binary operator - the comparisons, the arithmetic, the
    // bitwise ones - produces a primitive from any pair of operands. TRUE OF
    // WHAT IS LEFT, which is what the two arms above are for.
    return { ok: true };
  }

  // A ternary is its two arms, for the same reason `??` is.
  if (ts.isConditionalExpression(cur)) {
    const whenTrue = primitiveSelectorBody(cur.whenTrue, sf, param);
    if (!whenTrue.ok) return whenTrue;
    return primitiveSelectorBody(cur.whenFalse, sf, param);
  }

  if (
    ts.isNumericLiteral(cur) ||
    ts.isStringLiteral(cur) ||
    ts.isNoSubstitutionTemplateLiteral(cur) ||
    ts.isTemplateExpression(cur) ||
    cur.kind === ts.SyntaxKind.TrueKeyword ||
    cur.kind === ts.SyntaxKind.FalseKeyword ||
    cur.kind === ts.SyntaxKind.NullKeyword ||
    (ts.isIdentifier(cur) && cur.text === "undefined")
  ) {
    return { ok: true };
  }

  if (ts.isPropertyAccessExpression(cur) || ts.isElementAccessExpression(cur)) {
    // `.length` / `.size` is a number however the thing it counts was reached -
    // and this arm passes UNCONDITIONALLY ON THE NAME, which is the honest
    // description of a LEXICAL guess. This script builds no `ts.Program`, so
    // there is no checker here that could tell `array.length` from a
    // user-defined field named `length` holding an object. What makes the guess
    // sound for the store it is applied to: `ForwardRuntimeEntry`
    // (`runtime.ts:38-48`) is a status string plus numbers, `byRule` is a plain
    // `Record`, and a `.length`/`.size` written against either is a TS error
    // rather than a selector this arm waves through. Kept as a comment rather
    // than tightened - the tightening that would close it is a type lookup, and
    // refusing the two names outright would refuse `useRunningCount`, the one
    // real selector here that builds a collection inside itself.
    if (
      ts.isPropertyAccessExpression(cur) &&
      (cur.name.text === "length" || cur.name.text === "size")
    ) {
      return { ok: true };
    }
    // Otherwise the chain has to reach PAST the entry, to one of its own
    // fields. `<param>.byRule` is the whole map and `<param>.byRule[id]` is the
    // whole entry; both are objects the four actions rebuild, so neither is
    // ever `Object.is` its own last return.
    const text = norm(cur.getText(sf));
    if (!/^[A-Za-z_$][\w$]*$/.test(param)) {
      return {
        ok: false,
        why: `the selector's parameter \`${param}\` is not a plain identifier, so no access chain can be rooted on it`,
      };
    }
    const entryField = new RegExp(`^${param}\\.byRule\\[[^\\]]+\\]\\??\\.[A-Za-z_$][\\w$]*$`);
    if (entryField.test(text)) return { ok: true };
    return {
      ok: false,
      why: `access chain \`${text}\` does not reach a primitive field off \`${param}.byRule[…]\``,
    };
  }

  return {
    ok: false,
    why: `${ts.SyntaxKind[cur.kind]} \`${norm(cur.getText(sf)).slice(0, 60)}\` is not a shape that can only yield a primitive`,
  };
}

// AND THE TWO COPIES STILL AGREE, said as a check rather than as the paragraph
// above's promise. Both are live and both guard a store every row reads, so a
// tightening applied to one alone leaves the other passing what its twin now
// refuses - which is how the polarity hole above survived in the first place,
// one script ahead of the other. Compared as CODE: both files are
// comment-stripped first (the two copies' comments differ deliberately, each
// naming its own store) and whitespace-normalised after, so a legal reformat of
// either is invisible here. VLT-33's extraction into a shared module is the real
// remedy and is not this round's; until then this is what makes "cannot silently
// diverge" true.
{
  const twin = "scripts/forward-autostart-verify.ts";
  const bodyOf = (fileSrc: string, rel: string, name: string): string | null => {
    const sf = ts.createSourceFile(rel, stripComments(fileSrc), ts.ScriptTarget.ESNext, true);
    const found = findFunctionBody(sf, name);
    return found === null ? null : norm(found.getText(sf));
  };
  for (const name of ["selectorParamName", "primitiveSelectorBody"]) {
    const mine = bodyOf(read("scripts/forwards-shell-verify.ts"), "self", name);
    const theirs = bodyOf(read(twin), twin, name);
    check(
      `${name}'s body is byte-identical (comments aside) to ${twin}'s copy`,
      mine !== null && theirs !== null && mine === theirs,
      { mine: mine?.slice(0, 80), theirs: theirs?.slice(0, 80) },
    );
  }
}

// The allow-list's own self-test, over SYNTHETIC selectors, so its verdicts are
// pinned here rather than only by whatever `runtime.ts` happens to contain
// today - without it the helper is only ever exercised on four inputs that all
// pass, and every refusal it is supposed to make is unmeasured. The four
// measured-green mutations from the block comment above are each in the table.
{
  const probes: Array<[string, boolean, string?]> = [
    // The four real ones, plus a reordered comparison that means the same.
    ['s.byRule[ruleId]?.status ?? "stopped"', true],
    ["s.byRule[ruleId]?.boundPort", true],
    ["s.byRule[ruleId]?.error", true],
    ['Object.values(s.byRule).filter((e) => e.status === "running").length', true],
    ["s.byRule[ruleId] !== undefined", true],
    // The refusals, headed by the four that came back GREEN under the deny-list
    // with a fresh hook in `runtime.ts` for each.
    ["({ port: s.byRule[ruleId]?.boundPort, sid: s.byRule[ruleId]?.sessionId })", false],
    ['(s.byRule[ruleId]?.status ?? "x", Object.keys(s.byRule))', false],
    ["s.byRule[ruleId] ?? {}", false],
    ["new Set(Object.getOwnPropertyNames(s.byRule))", false],
    // And the rest of the family, so the polarity is pinned rather than the
    // four names the deny-list happened to hold.
    ["Object.keys(s.byRule)", false],
    ["Object.entries(s.byRule)", false],
    ["Object.values(s.byRule).map((e) => e.boundPort)", false],
    ["structuredClone(s.byRule)", false],
    ["s.byRule", false],
    ["s.byRule[ruleId]", false],
    ["[s.byRule[ruleId]?.boundPort]", false],
    ["(lastIds = Object.keys(s.byRule))", false],
    ["(s.byRule[ruleId]?.boundPort ?? 0, s.byRule[ruleId]?.boundPort)", true],
    // THE PARAMETER NAME IS NOT THE LETTER `s`. The first is the legal selector
    // a rename produces - accepted, and REFUSED before the arm was
    // parameterised. The second proves the rename does not blanket-accept. The
    // third proves the arm is rooted on the PARAMETER rather than on any
    // identifier that happens to read `.byRule`: here `s` is a free variable
    // the selector never received.
    ['state.byRule[ruleId]?.status ?? "stopped"', true, "state"],
    ["state.byRule[ruleId] ?? {}", false, "state"],
    ['s.byRule[ruleId]?.status ?? "stopped"', false, "state"],
  ];
  for (const [text, want, paramName = "s"] of probes) {
    const probeSf = ts.createSourceFile(
      "selector-probe.ts",
      `useForwardRuntime((${paramName}) => ${text});`,
      ts.ScriptTarget.ESNext,
      true,
      ts.ScriptKind.TS,
    );
    const arg = findCallsTo(probeSf, "useForwardRuntime", probeSf)[0]?.arguments[0];
    const arrow = arg && ts.isArrowFunction(arg) ? arg : null;
    const body = arrow ? arrowBodyExpression(arrow) : null;
    const got =
      arrow === null || body === null
        ? "no selector body parsed"
        : primitiveSelectorBody(body, probeSf, selectorParamName(arrow, probeSf)).ok;
    check(
      `allow-list self-test: \`${text}\` under \`(${paramName}) =>\` is ${want ? "primitive" : "REFUSED"}`,
      got === want,
      got,
    );
  }
}

// ============================================================================
// 1. The rail branch: forwards renders <ForwardsPage />, not a placeholder -
//    and the OTHER way round from vault-shell's own section 1, because THIS
//    is the branch that changed this wave. Vault is now the negative control:
//    without it, an edit that replaced BOTH branches reads as correct.
// ============================================================================
console.log("[1. rail branch] only the forwards case was replaced");
{
  const r = src.railViewArea;
  check(
    "the forwards case renders <ForwardsPage />",
    /case "forwards":[\s\S]{0,200}<ForwardsPage\s*\/>/.test(r),
  );
  check(
    "the forwards case no longer renders PagePlaceholder",
    !/case "forwards":[\s\S]{0,200}PagePlaceholder/.test(r),
  );
  check(
    "NEGATIVE CONTROL: the vault case still renders <VaultPage />",
    /case "vault":[\s\S]{0,200}<VaultPage\s*\/>/.test(r),
  );
}

// ============================================================================
// 2. The selector rule: every useForwardRuntime( call in runtime.ts returns a
//    primitive (§1.6), useShallow is imported nowhere in runtime.ts NOR
//    anywhere under src/, and useForwardRuntime( is called ONLY from
//    runtime.ts - added after step 6 landed, because step 6 exports four
//    selector hooks and no action wrappers, so a component's own object
//    selector would sit outside this section's parse entirely (Z5).
// ============================================================================
console.log(
  "\n[2. selector rule] every useForwardRuntime( call returns a primitive, only from runtime.ts",
);
{
  const sf = ts.createSourceFile(
    FILES.runtime,
    src.runtime,
    ts.ScriptTarget.ESNext,
    true,
    ts.ScriptKind.TS,
  );
  const calls = findCallsTo(sf, "useForwardRuntime", sf);
  check("found at least one useForwardRuntime( call to check", calls.length > 0, calls.length);
  for (const call of calls) {
    check(
      `${call.getText(sf)} has exactly one argument`,
      call.arguments.length === 1,
      call.getText(sf),
    );
    const arg = call.arguments[0];
    const isArrow = !!arg && ts.isArrowFunction(arg);
    check(`${call.getText(sf)}'s argument is an arrow function`, isArrow, arg?.getText(sf));
    if (arg && isArrow) {
      const body = arrowBodyExpression(arg as ts.ArrowFunction);
      check(`found ${call.getText(sf)}'s selector body`, body !== null, arg.getText(sf));
      if (body) {
        const verdict = primitiveSelectorBody(
          body,
          sf,
          selectorParamName(arg as ts.ArrowFunction, sf),
        );
        check(
          `${call.getText(sf)}'s selector body is a shape that can ONLY yield a primitive`,
          verdict.ok,
          verdict.ok ? body.getText(sf) : verdict.why,
        );
      }
    }
  }

  check(
    "runtime.ts imports nothing from zustand/react/shallow",
    !/from ["']zustand\/react\/shallow["']/.test(src.runtime),
  );

  // Comment-stripped, not raw: `runtime.ts`'s own header explains IN PROSE why
  // useShallow is avoided, and that sentence legitimately contains the word.
  // A raw substring check would fail on the very comment documenting the
  // rule - the same one exception §3/correction 1 already carves out for
  // section 8's `pane` check, applied here for the same reason.
  const allSrcFiles = walkSrcFiles(join(repoRoot, "src"));
  const shallowOffenders = allSrcFiles.filter((f) =>
    stripComments(readFileSync(f, "utf8")).includes("useShallow"),
  );
  check(
    "useShallow appears NOWHERE under src/ (repo-wide, comment-stripped) - v5 selectors stay primitive",
    shallowOffenders.length === 0,
    shallowOffenders.map((f) => f.slice(repoRoot.length)),
  );

  const runtimeAbsPath = join(repoRoot, FILES.runtime);
  const callSiteOffenders = allSrcFiles.filter(
    (f) => f !== runtimeAbsPath && readFileSync(f, "utf8").includes("useForwardRuntime("),
  );
  check(
    "useForwardRuntime( is called ONLY from runtime.ts, nowhere else under src/",
    callSiteOffenders.length === 0,
    callSiteOffenders.map((f) => f.slice(repoRoot.length)),
  );
  check(
    "sanity: useForwardRuntime( does appear in runtime.ts itself",
    src.runtime.includes("useForwardRuntime("),
  );
}

// ============================================================================
// 3. The store write is unmodified: upsertRule's first argument is EXACTLY
//    ruleRecordFrom(id, draft) (whitespace-normalised), rooted at save's own
//    body and counted (exactly one call), AND a direct statement of that
//    body - not merely somewhere inside it. Rooting+counting alone is
//    defeated by a DELETION whose decoy keeps the count at 1 (VLT-76's
//    lesson, `vault-shell-verify.ts`'s M5) - the direct-statement check is
//    what a nested-arrow decoy cannot survive.
// ============================================================================
console.log(
  "\n[3. store write unmodified] upsertRule(ruleRecordFrom(id, draft), findHost) - pinned, rooted, direct",
);
{
  const sf = ts.createSourceFile(
    FILES.ruleEditorDialog,
    src.ruleEditorDialog,
    ts.ScriptTarget.ESNext,
    true,
    ts.ScriptKind.TSX,
  );
  const save = findConstArrowDeclaration(sf, "save");
  check("found RuleEditorDialog's save function", save !== null);
  const saveBody = save && ts.isBlock(save.body) ? save.body : null;
  check("save's body is a block", saveBody !== null);

  const upsertCalls = saveBody ? findCallsTo(saveBody, "upsertRule", sf) : [];
  check("exactly one upsertRule( call inside save", upsertCalls.length === 1, upsertCalls.length);

  // The COUNT half of "rooted and counted" has to count `ruleRecordFrom(`
  // itself, not `upsertRule(` - found by mutation E3: a second
  // `ruleRecordFrom` call added in a sibling branch (never passed to
  // upsertRule at all) left the `upsertRule(` count at 1 and passed
  // undetected until this check was added. `ruleRecordFrom` is THE place a
  // `ForwardRule` is built from this editor (`draft.ts`'s own header) - a
  // second call anywhere in `save` is itself the drift VLT-76 named, whether
  // or not its result ever reaches `upsertRule`.
  const ruleRecordFromCalls = saveBody ? findCallsTo(saveBody, "ruleRecordFrom", sf) : [];
  check(
    "exactly one ruleRecordFrom( call inside save",
    ruleRecordFromCalls.length === 1,
    ruleRecordFromCalls.length,
  );

  if (upsertCalls.length === 1 && saveBody) {
    const call = upsertCalls[0];
    const firstArg = call.arguments[0];
    check("upsertRule's first argument was found", firstArg !== undefined);
    if (firstArg) {
      check(
        "upsertRule's first argument is EXACTLY ruleRecordFrom(id, draft), whitespace-normalised",
        norm(firstArg.getText(sf)) === norm("ruleRecordFrom(id, draft)"),
        firstArg.getText(sf),
      );
    }
    check(
      "the upsertRule(...) call is a DIRECT statement of save's own body, not nested in a decoy",
      isDirectlyInFunctionBody(call, saveBody),
      call.getText(sf),
    );
  }
}

// ============================================================================
// 4. Message placement (VLT-90/VLT-93's remedy). privilegedPortWarning's
//    reader is a descendant of the Local port Field; the host-refusal reader
//    (hostError, NOT the generic error) is a descendant of the SSH host
//    Field; error is a descendant of NEITHER - the third is what makes the
//    first two mean something (a check that only asserted the first two would
//    pass a form where every message rendered everywhere).
// ============================================================================
console.log(
  "\n[4. message placement] privilegedPortWarning -> Local port Field; hostError -> SSH host Field; error -> neither",
);
{
  const sf = ts.createSourceFile(
    FILES.ruleEditorDialog,
    src.ruleEditorDialog,
    ts.ScriptTarget.ESNext,
    true,
    ts.ScriptKind.TSX,
  );
  const localPortField = findFieldByLabel(sf, "Local port", sf);
  check("found the Local port Field", localPortField !== null);
  const sshHostField = findFieldByLabel(sf, "SSH host", sf);
  check("found the SSH host Field", sshHostField !== null);

  if (localPortField) {
    check(
      "localPortWarning's reader is a descendant of the Local port Field",
      containsIdentifierInJsxExpression(localPortField, "localPortWarning"),
    );
    check(
      "NEGATIVE: error's reader is not inside the Local port Field",
      !containsIdentifierInJsxExpression(localPortField, "error"),
    );
  }
  if (sshHostField) {
    check(
      "hostError's reader is a descendant of the SSH host Field (not the generic error)",
      containsIdentifierInJsxExpression(sshHostField, "hostError"),
    );
    check(
      "NEGATIVE: error's reader is not inside the SSH host Field",
      !containsIdentifierInJsxExpression(sshHostField, "error"),
    );
  }
}

// ============================================================================
// 5. No dead affordances.
// ============================================================================
console.log(
  "\n[5. no dead affordances] Export/Import absent; RuleCard is non-interactive; every Button has an onClick; one dialog, with a target",
);
{
  for (const label of ["Export", "Import"]) {
    check(`ForwardsPage.tsx contains no "${label}" string`, !src.forwardsPage.includes(label));
  }
  for (const prop of ["onSelect", "onConnect"]) {
    check(`RuleCard.tsx declares no ${prop} prop`, !src.ruleCard.includes(prop));
  }
  for (const smell of ["tabIndex", "onDoubleClick", "onKeyDown"]) {
    check(`RuleCard.tsx has no ${smell}`, !src.ruleCard.includes(smell));
  }

  // Every <Button> in the page and the card has a non-empty onClick. Compiler
  // API over the RAW source (not stripComments'd): the TS parser does not
  // see a `{/* ... */}` JSX comment as an element at all, so a commented-out
  // Button is invisible to this walk on its own - no stripping needed for a
  // POSITIVE reachability check phrased this way.
  for (const key of ["forwardsPage", "ruleCard"] as const) {
    const sf = ts.createSourceFile(
      FILES[key],
      src[key],
      ts.ScriptTarget.ESNext,
      true,
      ts.ScriptKind.TSX,
    );
    const buttons = findOpeningElementsByTag(sf, "Button", sf);
    check(`found at least one <Button> in ${FILES[key]}`, buttons.length > 0, buttons.length);
    for (const b of buttons) {
      const onClick = jsxAttrExprText(b, "onClick", sf);
      check(
        `a <Button> in ${FILES[key]} has a non-empty onClick`,
        onClick !== null && onClick.trim().length > 0,
        b.getText(sf).slice(0, 80),
      );
    }
  }

  // Exactly one <RuleEditorDialog>, handed a target.
  {
    const sf = ts.createSourceFile(
      FILES.forwardsPage,
      src.forwardsPage,
      ts.ScriptTarget.ESNext,
      true,
      ts.ScriptKind.TSX,
    );
    const dialogs = findOpeningElementsByTag(sf, "RuleEditorDialog", sf);
    check("exactly one <RuleEditorDialog> is rendered", dialogs.length === 1, dialogs.length);
    const target = dialogs[0] ? jsxAttrExprText(dialogs[0], "target", sf) : null;
    check("<RuleEditorDialog> is handed a target", target !== null, target ?? undefined);
  }

  // The stripper self-test's LIVE proof (P9): a positive, comment-stripped
  // reachability check on the "Host missing" badge's own text - NOT on
  // `hostDangling` itself, which was the first draft here and went GREEN
  // over P9 for the wrong reason: `hostDangling` is read TWICE MORE in this
  // file (`startDisabled`, `toggleTooltip`), so hiding only the Badge's JSX
  // left the substring reachable anyway, an unpredicted green a mutation run
  // caught. "Host missing" is the badge's own unique text - present nowhere
  // else in the file - so it is what actually falls silent when the badge's
  // JSX is hidden inside `{/* ... */}`. With the correct (negative-lookahead)
  // stripper, that hiding removes it from the stripped text and this FAILs;
  // a stripper missing the JSX branch entirely leaves it in the "stripped"
  // text and this stays green over dead code - which is exactly the defect
  // this check exists to catch, per `host-editor-verify.ts:191-215`'s own
  // header.
  check(
    'RuleCard.tsx\'s hostDangling Badge ("Host missing") is REACHABLE (comment-stripped), not merely present',
    stripComments(src.ruleCard).includes("Host missing"),
  );
}

// ============================================================================
// 6. The empty state branches, and 7. hasAny from the unfiltered list.
// ============================================================================
console.log(
  "\n[6/7. empty state] the ternary actually branches (compiler-verified), and hasAny names the UNFILTERED list",
);
{
  const sf = ts.createSourceFile(
    FILES.forwardsPage,
    src.forwardsPage,
    ts.ScriptTarget.ESNext,
    true,
    ts.ScriptKind.TSX,
  );

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
  }

  // [7] hasAny's expression NAMES the unfiltered list (ruleRowList), read off
  // the call site - a pin keyed on "differs from the ranked identifier" would
  // miss a differently-named always-empty expression (step 8's G2 mutation).
  const calls = findOpeningElementsByTag(sf, "SectionEmpty", sf);
  check("found exactly one <SectionEmpty> call site", calls.length === 1, calls.length);
  if (calls[0]) {
    const hasAnyText = jsxAttrExprText(calls[0], "hasAny", sf);
    check("<SectionEmpty>'s hasAny expression was found", hasAnyText !== null);
    check(
      "hasAny is fed from ruleRowList (the UNFILTERED list), not visibleRules",
      hasAnyText === "ruleRowList.length > 0",
      hasAnyText ?? undefined,
    );
  }
}

// ============================================================================
// 8. The caret contract: deps present AND empty (recorded separately), pane
//    is exactly `() => pageRef.current` with no closest( in ITS OWN text
//    (scoped to the property, not a raw-file negative - `ForwardsPage.tsx`'s
//    own comment legitimately contains the literal string `closest(` to
//    explain why the page must not use it, so a raw-source negative would
//    FAIL on the comment that documents the rule), and stillOnScreen reads a
//    ref.
// ============================================================================
console.log(
  "\n[8. caret contract] deps present+empty (separately), pane === () => pageRef.current (scoped, not raw), stillOnScreen reads a ref",
);
{
  const sf = ts.createSourceFile(
    FILES.forwardsPage,
    src.forwardsPage,
    ts.ScriptTarget.ESNext,
    true,
    ts.ScriptKind.TSX,
  );
  const body = findFunctionBody(sf, "ForwardsPage");
  check("found ForwardsPage's function body to check", body !== null);

  let effectCall: ts.CallExpression | null = null;
  if (body) {
    const visit = (n: ts.Node): void => {
      if (effectCall) return;
      if (
        ts.isCallExpression(n) &&
        n.expression.getText(sf) === "useEffect" &&
        n.getText(sf).includes("paneCaret.claim(")
      ) {
        effectCall = n;
      }
      ts.forEachChild(n, visit);
    };
    visit(body);
  }
  check("found the caret claim's useEffect(...) call", effectCall !== null);

  if (effectCall) {
    const call = effectCall as ts.CallExpression;
    check(
      "the effect's deps argument is PRESENT (recorded separately from its contents)",
      call.arguments.length === 2,
      call.arguments.length,
    );
    const deps = call.arguments[1];
    check(
      "the effect's deps argument is an EMPTY array literal []",
      deps !== undefined && ts.isArrayLiteralExpression(deps) && deps.elements.length === 0,
      deps?.getText(sf),
    );

    const factory = call.arguments[0];
    const claimCalls = factory ? findCallsTo(factory, "paneCaret.claim", sf) : [];
    check(
      "found the paneCaret.claim(...) call inside the effect",
      claimCalls.length === 1,
      claimCalls.length,
    );
    const claimObj = claimCalls[0]?.arguments[1];
    check(
      "paneCaret.claim's second argument is an object literal",
      claimObj !== undefined && ts.isObjectLiteralExpression(claimObj),
      claimObj?.getText(sf),
    );
    if (claimObj && ts.isObjectLiteralExpression(claimObj)) {
      const paneVal = findPropertyValue(claimObj, "pane", sf);
      check("found the pane property", paneVal !== null);
      if (paneVal) {
        check(
          "pane is EXACTLY () => pageRef.current",
          norm(paneVal.getText(sf)) === norm("() => pageRef.current"),
          paneVal.getText(sf),
        );
        check(
          "pane's OWN expression text contains no closest( (scoped to the property, not the raw file)",
          !/closest\(/.test(paneVal.getText(sf)),
          paneVal.getText(sf),
        );
      }
      const stillOnScreenVal = findPropertyValue(claimObj, "stillOnScreen", sf);
      check("found the stillOnScreen property", stillOnScreenVal !== null);
      if (stillOnScreenVal) {
        check(
          "stillOnScreen reads a ref (.current), not a hardcoded literal",
          /\.current\b/.test(stillOnScreenVal.getText(sf)),
          stillOnScreenVal.getText(sf),
        );
      }
    }
  }
}

// ============================================================================
// 9. No safety claim - the five needles, over raw source (a negative catches
//    a comment that CLAIMS the thing; a positive over raw source would be
//    satisfied by one).
// ============================================================================
console.log(
  '\n[9. no false safety claim] "safer"/"securely"/"OS keychain" etc. appear nowhere new',
);
const SAFETY_CLAIM_FILES = ["forwardsPage", "ruleCard", "ruleEditorDialog", "draft"] as const;
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
// 10. stopNote is used, not restated. NOTE (deviation from the plan's prose):
//     the plan says "RuleCard.tsx and ForwardsPage.tsx ... both reach that
//     copy through stopNote(" - but ForwardsPage.tsx does not reference
//     stopNote at all (only RuleCard.tsx does; ForwardsPage.tsx uses
//     deleteNote for its own dialog). The NEGATIVE (no inlined literal) holds
//     for both files - neither may restate the copy - but the POSITIVE
//     ("reaches it through stopNote(") only applies where the file actually
//     uses it. Adapted to the code; see the step's report for the deviation
//     verbatim.
// ============================================================================
console.log(
  "\n[10. stopNote via function, not restated] the two-sentence copy is never inlined; RuleCard reaches it through stopNote(",
);
for (const key of ["ruleCard", "forwardsPage"] as const) {
  for (const phrase of ["No new connections", "stays up while"]) {
    check(`${FILES[key]} does not inline "${phrase}"`, !src[key].includes(phrase));
  }
}
check("RuleCard.tsx reaches the Stop copy through stopNote(", /stopNote\(/.test(src.ruleCard));

// ============================================================================
// 11. DELETE STOPS FIRST. `deleteRule` is a pure persistence filter and there
//     is no reconciler anywhere in `src/` - `grep stopRule` finds exactly the
//     two callers this section and `RuleCard.tsx` name - so deleting a
//     page-running rule used to leave `runtime.ts`'s entry naming a rule no row
//     renders (no Stop ever offered again), `ssh/tunnel.ts`'s entry at
//     `refs: 1` (the SSH session never closes for the rest of the app's life)
//     and the local port bound, with re-creating a rule on the same pinned port
//     failing EADDRINUSE and no in-app recovery. `derive.ts`'s confirm copy
//     said "deleting a running rule stops it" throughout, which was FALSE - a
//     false promise inside a destructive confirm.
//
//     ORDER, not presence. Both calls being in the same function is satisfied
//     by `deleteRule` first, which is the same leak with an extra IPC; and the
//     await is what separates "stops it" from "asks for a stop and races the
//     delete against it". A nested-arrow decoy (`() => { void stopRule(r); }`)
//     keeps the text and the order and drops the await, which is why the
//     awaited-parent check is here too.
// ============================================================================
console.log(
  "\n[11. delete stops first] confirmDelete awaits stopRule for a page-running rule BEFORE deleteRule",
);
{
  const sf = ts.createSourceFile(
    FILES.forwardsPage,
    src.forwardsPage,
    ts.ScriptTarget.ESNext,
    true,
    ts.ScriptKind.TSX,
  );

  /** The factory handed to `useCallback` in `const <name> = useCallback(fn,
   *  deps)`, or null. Copied from `vault-shell-verify.ts:402`. */
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

  const confirmDelete = useCallbackFactory(sf, "confirmDelete");
  check("found confirmDelete's useCallback factory", confirmDelete !== null);
  if (confirmDelete) {
    const stopCalls = findCallsTo(confirmDelete, "stopRule", sf);
    const deleteCalls = findCallsTo(confirmDelete, "deleteRule", sf);
    check(
      "exactly one stopRule( call inside confirmDelete",
      stopCalls.length === 1,
      stopCalls.length,
    );
    check(
      "exactly one deleteRule( call inside confirmDelete",
      deleteCalls.length === 1,
      deleteCalls.length,
    );
    const stop = stopCalls[0];
    const del = deleteCalls[0];
    if (stop && del) {
      check(
        "the stopRule call is ORDERED BEFORE the deleteRule call - both being present is satisfied by the leak with an extra IPC",
        stop.getStart(sf) < del.getStart(sf),
        { stop: stop.getStart(sf), delete: del.getStart(sf) },
      );
      // AWAITED, and read off the AST rather than by looking for the word:
      // `void stopRule(r)` and `() => { void stopRule(r) }` both keep the text
      // and the order while racing the delete against the stop (or never
      // running it at all).
      check(
        "and it is AWAITED, not fired off - a stop that has not landed is not a stop",
        stop.parent !== undefined && ts.isAwaitExpression(stop.parent),
        stop.parent === undefined ? undefined : ts.SyntaxKind[stop.parent.kind],
      );
      check(
        "the deleteRule call is awaited too, so a rejection from either half reaches the one toast",
        del.parent !== undefined && ts.isAwaitExpression(del.parent),
        del.parent === undefined ? undefined : ts.SyntaxKind[del.parent.kind],
      );
      // It is the PAGE's rule that gets stopped - the whole record, not an id.
      // `stopRule` needs the host and both endpoints to name the entry it is
      // releasing, so a `PendingDelete` carrying only `id`/`name` cannot do
      // this at all, which is why that state was widened.
      check(
        "stopRule is handed the captured RULE record, not an id",
        norm(stop.arguments.map((a) => a.getText(sf)).join(",")) === norm("target.rule"),
        stop.arguments.map((a) => a.getText(sf)),
      );
      // THE PREDICATE, which nothing pinned and which is where this section's
      // own fix left a hole. Presence, order, the awaits and the argument were
      // all pinned; the CONDITION was not. Measured: with the guard rewritten
      // to `if (target.running && target.hostOwned)` - a combination
      // `RuleCard.tsx:25-41` argues is unconstructible, so `stopRule` becomes
      // unreachable for every rule - this section stayed at 57/57 scripts with
      // `tsc` and `prettier` clean. That is the runtime-false-guard shape, newly
      // created by the commit that fixed the old one.
      //
      // The whole condition NODE, whitespace-normalised, so `false &&
      // pageMustStopFirst(...)` and `pageMustStopFirst(other.id)` are both
      // different text. `pageMustStopFirst` itself is pinned BEHAVIOURALLY as
      // C11 against the real stores - an AST-only pin is what let the last one
      // through.
      const enclosingIf = (node: ts.Node): ts.IfStatement | null => {
        let cur: ts.Node | undefined = node;
        while (cur && !ts.isIfStatement(cur)) cur = cur.parent;
        return cur ? (cur as ts.IfStatement) : null;
      };
      const guard = enclosingIf(stop);
      check("the stopRule call sits inside an if statement at all", guard !== null);
      check(
        "and that if's condition is EXACTLY pageMustStopFirst(target.rule.id) - the LIVE read, not the flag captured at Delete-click time",
        guard !== null &&
          norm(guard.expression.getText(sf)) === norm("pageMustStopFirst(target.rule.id)"),
        guard === null ? undefined : guard.expression.getText(sf),
      );
      // AND THAT IF IS THE ONLY THING DECIDING IT. `enclosingIf` walks to the
      // NEAREST `if`, so every check above still matches with the whole guarded
      // statement wrapped in a second, runtime-false one - measured green at
      // this exact site. See {@link isUnguardedToItsFunctionBody}.
      check(
        "and nothing above it decides whether it runs - the guarded stop is unconditional within its own function, so a runtime-false wrapper cannot make it dead code",
        guard !== null && isUnguardedToItsFunctionBody(guard),
        guard === null ? undefined : ts.SyntaxKind[guard.parent.kind],
      );
    }
    // AND THE CAPTURED FLAGS ARE NOT CONSULTED HERE AT ALL. `target.pageStops`
    // and `target.hostOwned` are the dialog's copy of what the user was TOLD
    // (`deleteNote`, in the JSX below), and reading either one to decide
    // whether to stop is the P0 this round fixed - the row is `starting` for the
    // whole dial and the Delete button is not disabled during it, so the
    // ordinary ordering has the dial resolving before the confirm click.
    //
    // `pageStops` AND NOT `running`, moved with the field it names. A needle
    // left on the old name is a negative that can never fire again, which is
    // strictly worse than no check: it reads as covering the captured half
    // while the field it watches no longer exists.
    //
    // Read off the AST rather than as a substring, deliberately: the code's own
    // comment there NAMES `target.pageStops` in order to say it must not be
    // used, and a raw-text negative would fail on the sentence documenting the
    // rule. A comment is not a `PropertyAccessExpression`.
    const capturedReads: string[] = [];
    const visitReads = (n: ts.Node): void => {
      if (ts.isPropertyAccessExpression(n)) {
        const t = norm(n.getText(sf));
        if (t === "target.pageStops" || t === "target.hostOwned") capturedReads.push(t);
      }
      ts.forEachChild(n, visitReads);
    };
    visitReads(confirmDelete);
    check(
      "confirmDelete reads NEITHER captured flag (AST, so its own comment naming target.pageStops does not count)",
      capturedReads.length === 0,
      capturedReads,
    );
    // AND THE FIELD IT WOULD READ EXISTS UNDER THAT NAME. The negative above is
    // vacuous for any name `PendingDelete` does not carry, and a rename is
    // exactly what makes a negative vacuous without reddening anything - so the
    // positive that keeps it honest is pinned here, off the type declaration
    // itself rather than off a use of it.
    const pendingDelete = findTypeAliasMembers(sf, "PendingDelete", sf);
    check(
      "PendingDelete still carries `pageStops` and `hostOwned`, so the negative above is watching fields that exist",
      pendingDelete !== null &&
        pendingDelete.includes("pageStops") &&
        pendingDelete.includes("hostOwned"),
      pendingDelete,
    );
  }
  // NO RECONCILER, said as a check rather than as prose. `stopRule` has exactly
  // THREE callers in `src/` and they are NAMED rather than counted: the row's
  // own button, the confirm above, and the editor's save (section 12). Its own
  // declaration in `controller.ts` is excluded by path, not by a cleverer
  // needle. Comment-stripped, so this file's own prose about `stopRule` in
  // another module would not count as a caller.
  //
  // A SET AND NOT A COUNT, because a count of three is satisfied by a caller
  // MOVED to a file that has no business stopping a forward - and a fourth
  // caller is exactly the kind of thing this check exists to make somebody
  // argue for.
  //
  // WHICH NEW CALLER WOULD ACTUALLY MATTER, corrected here because the previous
  // version of this comment said "a third" and meant something narrower.
  // `RuleCard.tsx`'s header names its trigger as a second caller that STARTS a
  // rule from outside that row: the unconstructibility argument is about
  // `controller.ts:169-175` running the terminal-owned refusal and
  // `markStarting` with no `await` between them, so it is a new `startRule`
  // caller that opens that gap. The editor's caller added this round only ever
  // STOPS, which takes a rule out of `running` and cannot manufacture the
  // `hostOwned && <page status>` pair. `startRule(` is swept for separately
  // below, and it is still the row's button alone.
  const controllerAbs = join(repoRoot, FILES.controller);
  const callersOf = (needle: string): string[] =>
    walkSrcFiles(join(repoRoot, "src"))
      .filter((f) => f !== controllerAbs && stripComments(readFileSync(f, "utf8")).includes(needle))
      .map((f) => f.slice(repoRoot.length))
      .sort();
  check(
    "stopRule( is called from exactly these three files: the row's button, the page's confirm, the editor's save",
    JSON.stringify(callersOf("stopRule(")) ===
      JSON.stringify([
        "/src/modules/forwards/ForwardsPage.tsx",
        "/src/modules/forwards/editor/RuleEditorDialog.tsx",
        "/src/modules/forwards/page/RuleCard.tsx",
      ]),
    callersOf("stopRule("),
  );
  check(
    "and startRule( is still called from the row's button ALONE - the caller whose addition makes RuleCard.tsx's unconstructible combination reachable",
    JSON.stringify(callersOf("startRule(")) ===
      JSON.stringify(["/src/modules/forwards/page/RuleCard.tsx"]),
    callersOf("startRule("),
  );
  // THE CAPTURED FLAG'S OWN DEFINITION, in the row that hands it over - the
  // other half of the claim the live read above makes, and nothing pinned it.
  // `RuleCard` computes what the CONFIRM DIALOG IS TOLD, so a definition
  // narrower than `pageMustStopFirst`'s own status set is a destructive confirm
  // reading "Deleting it changes nothing else." over a bind it is about to
  // close. `deleteNote` is a pure function of its argument, so no fixture in
  // `forwards-page-verify.ts` can see this: that script only ever sees the
  // boolean already decided.
  //
  // PINNED AT THE BINDING AND COMPARED WHOLE. `onDelete(running, hostOwned)`
  // and `onDelete(pageStops, hostOwned)` both satisfy a needle for `onDelete(`,
  // and pinning the ARGUMENT NAME alone is defeated by an alias
  // (`const pageStops = running;`) - so the argument list and the initializer
  // of each binding it is built from are read off the AST and compared whole.
  // Whitespace-normalised, and only whitespace: that part is Prettier's, the
  // rest is the claim.
  {
    const cardSf = ts.createSourceFile(
      FILES.ruleCard,
      stripComments(src.ruleCard),
      ts.ScriptTarget.ESNext,
      true,
      ts.ScriptKind.TSX,
    );
    const onDeleteCalls = findCallsTo(cardSf, "onDelete", cardSf);
    check(
      "RuleCard.tsx calls onDelete( exactly once - the row's trash button",
      onDeleteCalls.length === 1,
      onDeleteCalls.length,
    );
    const onDelete = onDeleteCalls[0];
    check(
      "and it hands over EXACTLY `pageStops, hostOwned` - both owners, hostOwned second to match the prop",
      onDelete !== undefined &&
        norm(onDelete.arguments.map((a) => a.getText(cardSf)).join(",")) ===
          norm("pageStops,hostOwned"),
      onDelete?.arguments.map((a) => a.getText(cardSf)),
    );
    const bindings: Array<[string, string]> = [
      // THE WIDENING ITSELF. Narrowed back to `running`, the dialog's sentence
      // is false for every rule the user deletes mid-dial - and every other
      // check in this file, all four scripts, `tsc` and `prettier` stay green,
      // because the flag is only ever read by a sentence.
      ["pageStops", "running || starting"],
      // The two it is built from, so `pageStops` cannot be re-rooted onto
      // something that merely reads the same today.
      ["running", 'status === "running"'],
      ["starting", 'status === "starting"'],
    ];
    for (const [name, want] of bindings) {
      const initializer = findConstInitializerText(cardSf, name, cardSf);
      check(
        `and \`${name}\` is EXACTLY \`${want}\` at its own binding`,
        initializer !== null && norm(initializer) === norm(want),
        initializer,
      );
    }
  }
  // And the live-read helper both record-changing paths go through, swept the
  // same way: a fourth reader of it is a fourth place that removes or rewrites
  // the record under a live forward.
  check(
    "pageMustStopFirst( is read by exactly the two record-changing paths",
    JSON.stringify(callersOf("pageMustStopFirst(")) ===
      JSON.stringify([
        "/src/modules/forwards/ForwardsPage.tsx",
        "/src/modules/forwards/editor/RuleEditorDialog.tsx",
      ]),
    callersOf("pageMustStopFirst("),
  );
}

// ============================================================================
// 12. THE EDITOR'S SAVE STOPS FIRST TOO - the same leak on the sibling path,
//     and it is a pure-click route with no timing in it at all.
//     `ssh/tunnel.ts`'s `forwardKey` is
//     `connectionId|remoteHost|remotePort|localPort` (`tunnel.ts:246-252`) and
//     this form edits ALL FOUR, so: Start on 18080, Edit, Local port 18081,
//     Save, Stop -> the close names `h|10.0.0.9|5432|18081`, there is no entry
//     under that key, `markStopped` discards the claim in its `finally`, and
//     the row reads "Stopped" with no Stop that can ever be issued again while
//     18080 stays bound for the rest of the app's life.
//
//     ORDER AND IDENTITY, not presence. The stop has to land BEFORE the write
//     (after it, the record no longer names the entry) and it has to be handed
//     `existing`, the record as LOADED - `ruleRecordFrom(id, draft)` is the new
//     identity and closing with it is the defect itself. C13 below is the
//     behavioural half: the same close, once with each record, against a fake
//     that models `forwardKey`.
// ============================================================================
console.log(
  "\n[12. the editor stops first] save awaits stopRule(existing) BEFORE upsertRule, guarded on the live read",
);
{
  const sf = ts.createSourceFile(
    FILES.ruleEditorDialog,
    src.ruleEditorDialog,
    ts.ScriptTarget.ESNext,
    true,
    ts.ScriptKind.TSX,
  );
  const save = findConstArrowDeclaration(sf, "save");
  const saveBody = save && ts.isBlock(save.body) ? save.body : null;
  check("found RuleEditorDialog's save block to check", saveBody !== null);
  if (saveBody) {
    const stopCalls = findCallsTo(saveBody, "stopRule", sf);
    const upsertCalls = findCallsTo(saveBody, "upsertRule", sf);
    check("exactly one stopRule( call inside save", stopCalls.length === 1, stopCalls.length);
    check("exactly one upsertRule( call inside save", upsertCalls.length === 1, upsertCalls.length);
    const stop = stopCalls[0];
    const upsert = upsertCalls[0];
    if (stop && upsert) {
      check(
        "the stopRule call is ORDERED BEFORE the upsertRule call - after the write, the record no longer names the entry its Stop would close",
        stop.getStart(sf) < upsert.getStart(sf),
        { stop: stop.getStart(sf), upsert: upsert.getStart(sf) },
      );
      check(
        "and it is AWAITED - a stop that has not landed has not landed before the write either",
        stop.parent !== undefined && ts.isAwaitExpression(stop.parent),
        stop.parent === undefined ? undefined : ts.SyntaxKind[stop.parent.kind],
      );
      // THE OLD RECORD. `existing` is what was loaded; `ruleRecordFrom(id,
      // draft)` is the identity being written. Handing the NEW one to
      // `stopRule` reproduces the defect exactly - the close names a key
      // nothing is stored under - so this is an exact-node pin, not a
      // "mentions existing" one.
      check(
        "stopRule is handed `existing`, the record as LOADED - never the one being written",
        norm(stop.arguments.map((a) => a.getText(sf)).join(",")) === norm("existing"),
        stop.arguments.map((a) => a.getText(sf)),
      );
      const enclosingIf = (node: ts.Node): ts.IfStatement | null => {
        let cur: ts.Node | undefined = node;
        while (cur && !ts.isIfStatement(cur)) cur = cur.parent;
        return cur ? (cur as ts.IfStatement) : null;
      };
      const guard = enclosingIf(stop);
      check("the stopRule call sits inside an if statement at all", guard !== null);
      check(
        "and that if's condition is EXACTLY `existing && pageMustStopFirst(existing.id)` - the whole node, so a runtime-false operator cannot be slipped in front of it",
        guard !== null &&
          norm(guard.expression.getText(sf)) === norm("existing && pageMustStopFirst(existing.id)"),
        guard === null ? undefined : guard.expression.getText(sf),
      );
      // Structural position, for the reason section 3 gives about its own
      // `upsertRule` statement: a deletion whose decoy re-adds the guarded stop
      // inside a nested arrow keeps every count and every index above intact
      // and never runs.
      //
      // WHAT THIS ONE ESTABLISHES AND WHAT IT DOES NOT. It refuses NESTING
      // INSIDE ANOTHER FUNCTION - the deletion-with-a-decoy family - and that
      // is all; `isDirectlyInFunctionBody`'s own docstring says "tests
      // NESTING". The previous version of this comment claimed it closed the
      // decoy family full stop, which is the kind of overclaiming label that
      // stops the next reader looking: a runtime-false STATEMENT wrapper is
      // nesting-free, so this check passes over it. The assertion below is the
      // one that refuses that.
      check(
        "and the guarded stop is a DIRECT statement of save's own body, not nested in a decoy",
        guard !== null && isDirectlyInFunctionBody(guard, saveBody),
        guard === null ? undefined : guard.getText(sf).slice(0, 80),
      );
      // THE WRAPPER FAMILY, transplanted from `forward-autostart-verify.ts`'s
      // own call-site pin. Measured green at this exact site with the guarded
      // stop wrapped in `if (id === "") { … }` - `save` then never stops
      // anything, and the editor's whole half of the leak is back.
      check(
        "and nothing above it decides whether it runs - the guarded stop is unconditional within save, so a runtime-false wrapper cannot make it dead code",
        guard !== null && isUnguardedToItsFunctionBody(guard),
        guard === null ? undefined : ts.SyntaxKind[guard.parent.kind],
      );
    }
  }
}

console.log(
  failed === 0
    ? "\nAll forwards-shell sections 1-12 passed."
    : `\n${failed} check(s) FAILED so far.`,
);

// ============================================================================
// C1-C8: controller.ts's Start/Stop, driven through its OWN RuntimeDeps seam.
//
// `controller.ts` has zero committed checks before this step - step 9 wrote
// no script of its own. The seam exists (its header says so) precisely so a
// check never needs a Tauri bridge to drive Start/Stop: `defaultRuntimeDeps`
// is the only thing that touches `@/modules/ssh/tunnel`'s real
// `openForwardForConnection`/`closeForwardForConnection`, and every fixture
// below passes its OWN fake instead. A minimal Tauri `window` stand-in is
// still set up before the dynamic import, because `defaultRuntimeDeps`
// references the real functions as VALUES at module scope (so `tunnel.ts`,
// and therefore `hosts/store.ts`, load into the import graph even though
// nothing here calls them) - the stand-in below THROWS on any command it
// receives, which is the harness's own proof that the seam, not the bridge,
// is what every fixture actually drove.
// ============================================================================
console.log("\n[C1-C8] controller.ts's Start/Stop, driven through the RuntimeDeps seam");

type BridgeCall = { cmd: string; args: Record<string, unknown> };
const bridgeCalls: BridgeCall[] = [];
let nextBridgeCallbackId = 1;
const bridgeCallbacks = new Map<number, (payload: unknown) => void>();

async function handleBridgeInvoke(cmd: string, args: Record<string, unknown>): Promise<unknown> {
  bridgeCalls.push({ cmd, args });
  switch (cmd) {
    case "plugin:store|load":
    case "plugin:store|get_store":
      return 1;
    case "plugin:store|get":
      return [[], true];
    case "plugin:store|set":
    case "plugin:store|save":
    case "plugin:event|emit":
      return undefined;
    case "secrets_get_all":
      return (args.accounts as string[]).map(() => null);
    default:
      // Nothing in the C-series should ever reach the real bridge -
      // startRule/stopRule are always driven with a FAKE
      // openForward/closeForward/toast. Reaching here means a fixture forgot
      // to inject the seam, which is exactly the fidelity bug wave 1's
      // ssh_forward_open mock hid (a mock that cannot tell its input from its
      // output turns a check into a tautology) - thrown loudly instead.
      throw new Error(
        `forwards-shell-verify: unexpected bridge command "${cmd}" - the C-series must never reach the real Tauri bridge`,
      );
  }
}

(globalThis as { window?: unknown }).window = {
  __TAURI_INTERNALS__: {
    transformCallback: (cb: (payload: unknown) => void) => {
      const id = nextBridgeCallbackId++;
      bridgeCallbacks.set(id, cb);
      return id;
    },
    unregisterCallback: (id: number) => bridgeCallbacks.delete(id),
    invoke: (cmd: string, args: Record<string, unknown>) => handleBridgeInvoke(cmd, args ?? {}),
  },
};

const { pageMustStopFirst, startRule, stopRule } =
  await import("../src/modules/forwards/controller");
type RuntimeDepsType = NonNullable<Parameters<typeof startRule>[1]>;
const { useForwardRuntime } = await import("../src/modules/forwards/runtime");
const { useHostKeyPrompt } = await import("../src/modules/ssh/hostKeyPrompt");
// The TERMINAL's map, read by `startRule` directly rather than through
// `RuntimeDeps` - see C9, and `controller.ts`'s own note on why: a zustand
// store runs fine under `tsx`, so a check reads what the REAL store says.
const { useHostOwnedForwards } = await import("../src/modules/forwards/hostOwned");

/** Let queued microtasks settle, the same shape `rdp-tunnel-verify.ts`'s
 *  `settle()` gives the real bridge. */
async function settle(): Promise<void> {
  for (let i = 0; i < 8; i++) await new Promise((r) => setTimeout(r, 0));
}

type FakeForward = { sessionId: number; localPort: number; claim: number };
type OpenCall = {
  connectionId: string;
  remoteHost: string;
  remotePort: number;
  opts: { localPort?: number; promptForHostKey?: boolean; onHostKeyPrompt?: (id: string) => void };
};
type CloseCall = {
  connectionId: string;
  remoteHost: string;
  remotePort: number;
  localPort: number;
  claim: number;
};
type ToastCall = { message: string; variant?: string };

let openCalls: OpenCall[] = [];
let closeCalls: CloseCall[] = [];
let toastCalls: ToastCall[] = [];
type ParkedFakeOpen = { resolve: (f: FakeForward) => void; reject: (e: unknown) => void };
let parkedFakeOpens: ParkedFakeOpen[] = [];
let autoAnswerFakeOpen = true;
let nextFakeClaim = 1;
let nextFakeSessionId = 1;
let nextFakeAutoPort = 30000;

/** Full reset: call logs, park queue, and every counter - used at the top of
 *  each fixture. */
function resetFakes(): void {
  openCalls = [];
  closeCalls = [];
  toastCalls = [];
  parkedFakeOpens = [];
  autoAnswerFakeOpen = true;
  nextFakeClaim = 1;
  nextFakeSessionId = 1;
  nextFakeAutoPort = 30000;
}
/** Clear only the call LOGS, mid-fixture - used to isolate one call's log
 *  (e.g. stopRule's) from an earlier startRule in the same fixture, without
 *  losing the claim/port counters that tie the two together. */
function resetCallLogs(): void {
  openCalls = [];
  closeCalls = [];
  toastCalls = [];
}

/**
 * The fake RuntimeDeps every C-series fixture drives startRule/stopRule
 * through. Fidelity notes, checked against the real implementations this
 * stands in for:
 *
 * - `openForward` refuses (rejects) when `promptForHostKey !== true`, the
 *   same shape `tunnel.ts:316-334`'s dialSession takes for an unpinned
 *   target with no way to ask - this is what makes C1's mutation
 *   (`promptForHostKey: false`) bite BEHAVIOURALLY (a refusal instead of a
 *   running row), not merely as a recorded-argument mismatch.
 * - `closeForward` NEVER REJECTS, matching `closeForwardForConnection`'s own
 *   chain, which ends in `.catch(() => {})` (`tunnel.ts:561`) and cannot
 *   reject either. C8m's prediction ("nothing should change today") depends
 *   on this being true - a fake that COULD reject would test a contract the
 *   real function does not have, the exact mock-fidelity trap wave 1 hit.
 */
const FAKE_RUNTIME = {
  openForward: (
    connectionId: string,
    remoteHost: string,
    remotePort: number,
    opts: OpenCall["opts"] = {},
  ): Promise<FakeForward> => {
    openCalls.push({ connectionId, remoteHost, remotePort, opts });
    if (opts.promptForHostKey !== true) {
      return Promise.reject(new Error(`ssh: "${connectionId}" has no verified host key yet.`));
    }
    return new Promise<FakeForward>((resolve, reject) => {
      const settleNow = () =>
        resolve({
          sessionId: nextFakeSessionId++,
          localPort: opts.localPort || nextFakeAutoPort++,
          claim: nextFakeClaim++,
        });
      if (autoAnswerFakeOpen) settleNow();
      else parkedFakeOpens.push({ resolve, reject });
    });
  },
  closeForward: (
    connectionId: string,
    remoteHost: string,
    remotePort: number,
    localPort: number,
    claim: number,
  ): Promise<void> => {
    closeCalls.push({ connectionId, remoteHost, remotePort, localPort, claim });
    return Promise.resolve();
  },
  toast: (message: string, options?: { variant?: string }): void => {
    toastCalls.push({ message, variant: options?.variant });
  },
} satisfies RuntimeDepsType;

function fakeRule(over: {
  id: string;
  localPort?: number;
  hostId?: string;
  remoteHost?: string;
  remotePort?: number;
}): {
  id: string;
  name: string;
  hostId: string;
  localPort: number;
  remoteHost: string;
  remotePort: number;
  startWithHost: boolean;
  description?: string;
} {
  return {
    id: over.id,
    name: `rule-${over.id}`,
    hostId: over.hostId ?? "h-1",
    localPort: over.localPort ?? 18080,
    remoteHost: over.remoteHost ?? "10.0.0.9",
    remotePort: over.remotePort ?? 5432,
    startWithHost: false,
    description: undefined,
  };
}

function resetStores(): void {
  useForwardRuntime.setState({ byRule: {} });
  useHostKeyPrompt.setState({ queue: [] });
  // `startRule` refuses a rule in here outright, so a fixture that left an
  // entry behind would silently turn every later Start into a no-op.
  useHostOwnedForwards.setState({ byRule: {} });
}

// ---------------------------------------------------------------------------
console.log(
  "[C1] startRule dials with promptForHostKey: true - an unpinned bastion gets the prompt, not a refusal",
);
{
  resetFakes();
  resetStores();
  const rule = fakeRule({ id: "c1" });
  await startRule(rule, FAKE_RUNTIME);
  check(
    "C1: the open call carries promptForHostKey: true",
    openCalls[0]?.opts.promptForHostKey === true,
    openCalls[0]?.opts,
  );
  check(
    "C1: the row ends up running - an unpinned bastion got the prompt, not a refusal",
    useForwardRuntime.getState().byRule["c1"]?.status === "running",
    useForwardRuntime.getState().byRule["c1"],
  );
}

// ---------------------------------------------------------------------------
console.log(
  "\n[C2] stopRule's close call names rule.localPort - the value closeForwardForConnection's forwardKey needs to find the entry at all",
);
{
  resetFakes();
  resetStores();
  const rule = fakeRule({ id: "c2", localPort: 18080 });
  await startRule(rule, FAKE_RUNTIME);
  resetCallLogs();
  await stopRule(rule, FAKE_RUNTIME);
  check(
    "C2: the close call names rule.localPort",
    closeCalls[0]?.localPort === rule.localPort,
    closeCalls[0],
  );
  check(
    "C2: the row ends stopped",
    useForwardRuntime.getState().byRule["c2"]?.status === "stopped",
  );
}

// ---------------------------------------------------------------------------
console.log("\n[C3] stopRule with NO claim recorded calls close ZERO times - nothing to spend");
{
  resetFakes();
  resetStores();
  const rule = fakeRule({ id: "c3" });
  await stopRule(rule, FAKE_RUNTIME);
  check("C3: no close call was made", closeCalls.length === 0, closeCalls.length);
  check(
    "C3: the row still ends stopped",
    useForwardRuntime.getState().byRule["c3"]?.status === "stopped",
  );
}

// ---------------------------------------------------------------------------
console.log("\n[C4] startRule records the BOUND port, not the port asked for - the auto-port case");
{
  resetFakes();
  resetStores();
  const rule = fakeRule({ id: "c4", localPort: 0 });
  await startRule(rule, FAKE_RUNTIME);
  const recorded = useForwardRuntime.getState().byRule["c4"]?.boundPort;
  check(
    "C4: the recorded boundPort is the fake's OS-chosen port (30000), not the requested 0",
    recorded === 30000,
    recorded,
  );
}

// ---------------------------------------------------------------------------
console.log(
  "\n[C5] stop while starting: row ends stopped, no claim spent at stop time, and the late forward is released with its OWN claim",
);
{
  resetFakes();
  resetStores();
  const rule = fakeRule({ id: "c5" });
  autoAnswerFakeOpen = false;
  const starting = startRule(rule, FAKE_RUNTIME);
  await settle();
  check(
    "C5: the dial is parked mid-handshake",
    parkedFakeOpens.length === 1,
    parkedFakeOpens.length,
  );

  await stopRule(rule, FAKE_RUNTIME);
  check(
    "C5: the row ends stopped while the dial is still in flight",
    useForwardRuntime.getState().byRule["c5"]?.status === "stopped",
  );
  check(
    "C5: no claim was spent at stop time - nothing was recorded yet to spend",
    closeCalls.length === 0,
    closeCalls.length,
  );

  const landedClaim = nextFakeClaim;
  parkedFakeOpens[0].resolve({
    sessionId: nextFakeSessionId++,
    localPort: rule.localPort,
    claim: landedClaim,
  });
  nextFakeClaim++;
  await starting;
  await settle();
  check(
    "C5: the late forward is released with its own claim",
    closeCalls.length === 1 && closeCalls[0]?.claim === landedClaim,
    closeCalls[0],
  );
  check(
    "C5: the row is still stopped after the late landing - it was not clobbered",
    useForwardRuntime.getState().byRule["c5"]?.status === "stopped",
  );
}

// ---------------------------------------------------------------------------
console.log(
  "\n[C6] stop while starting with a prompt raised: abandon fires, backend told {promptId, accept:false}, prompt leaves the queue, forward still released with its own claim",
);
{
  resetFakes();
  resetStores();
  const rule = fakeRule({ id: "c6" });
  autoAnswerFakeOpen = false;
  const confirmCalls: { promptId: string; accept: boolean }[] = [];
  const starting = startRule(rule, FAKE_RUNTIME);
  await settle();
  const promptId = "c6-prompt";
  // Fidelity with tunnel.ts's dialSession (:356-371): the backend's
  // hostKeyPrompt event both (a) invokes the CALLER's onHostKeyPrompt and
  // (b) enqueues the SAME prompt into the shared useHostKeyPrompt queue - two
  // things one real event does together. This fixture does both by hand.
  openCalls[0]?.opts.onHostKeyPrompt?.(promptId);
  useHostKeyPrompt.getState().enqueue({
    promptId,
    fingerprint: "SHA256:fake",
    host: "fake.example.com",
    confirm: (id: string, accept: boolean) => {
      confirmCalls.push({ promptId: id, accept });
      return Promise.resolve();
    },
  });
  check("C6: the prompt is queued before the stop", useHostKeyPrompt.getState().queue.length === 1);

  await stopRule(rule, FAKE_RUNTIME);
  check(
    "C6: abandon told the backend to reject {promptId, accept:false}",
    confirmCalls.length === 1 &&
      confirmCalls[0].promptId === promptId &&
      confirmCalls[0].accept === false,
    confirmCalls,
  );
  check(
    "C6: the prompt left the shared queue",
    useHostKeyPrompt.getState().queue.length === 0,
    useHostKeyPrompt.getState().queue.length,
  );
  check("C6: no claim spent at stop time", closeCalls.length === 0, closeCalls.length);

  // Modelling choice: this fixture lets the parked dial LAND (rather than
  // simulating the backend aborting the handshake on the rejected key, which
  // is tunnel.ts's own contract and rdp-tunnel-verify.ts's to prove) so this
  // check can also prove controller.ts's release obligation holds on this
  // interleaving, same as C5.
  const landedClaim = nextFakeClaim;
  parkedFakeOpens[0].resolve({
    sessionId: nextFakeSessionId++,
    localPort: rule.localPort,
    claim: landedClaim,
  });
  nextFakeClaim++;
  await starting;
  await settle();
  check(
    "C6: the late forward is released with its own claim",
    closeCalls.length === 1 && closeCalls[0]?.claim === landedClaim,
    closeCalls[0],
  );
  check(
    "C6: the row is still stopped",
    useForwardRuntime.getState().byRule["c6"]?.status === "stopped",
  );
}

// ---------------------------------------------------------------------------
console.log(
  "\n[C7] start -> stop -> start again, the FIRST dial landing late: the superseded attempt releases its own reference without clobbering the row, then the wanted attempt marks running with its own claim",
);
{
  resetFakes();
  resetStores();
  const rule = fakeRule({ id: "c7" });
  autoAnswerFakeOpen = false;

  const first = startRule(rule, FAKE_RUNTIME);
  await settle();
  check("C7: first dial parked", parkedFakeOpens.length === 1, parkedFakeOpens.length);

  await stopRule(rule, FAKE_RUNTIME);
  check(
    "C7: row stopped after the stop",
    useForwardRuntime.getState().byRule["c7"]?.status === "stopped",
  );

  const second = startRule(rule, FAKE_RUNTIME);
  await settle();
  check("C7: second dial also parked", parkedFakeOpens.length === 2, parkedFakeOpens.length);
  check(
    "C7: row is starting again for the wanted attempt",
    useForwardRuntime.getState().byRule["c7"]?.status === "starting",
  );

  const firstClaim = nextFakeClaim;
  parkedFakeOpens[0].resolve({
    sessionId: nextFakeSessionId++,
    localPort: rule.localPort,
    claim: firstClaim,
  });
  nextFakeClaim++;
  await first;
  await settle();
  check(
    "C7: the superseded attempt released its own reference",
    closeCalls.length === 1 && closeCalls[0]?.claim === firstClaim,
    closeCalls[0],
  );
  check(
    "C7: the row is UNCLOBBERED - still starting for the wanted attempt",
    useForwardRuntime.getState().byRule["c7"]?.status === "starting",
    useForwardRuntime.getState().byRule["c7"],
  );

  const secondClaim = nextFakeClaim;
  parkedFakeOpens[1].resolve({
    sessionId: nextFakeSessionId++,
    localPort: rule.localPort,
    claim: secondClaim,
  });
  nextFakeClaim++;
  await second;
  await settle();
  check(
    "C7: the wanted attempt marks running with its own claim",
    useForwardRuntime.getState().byRule["c7"]?.status === "running" &&
      useForwardRuntime.getState().byRule["c7"]?.claim === secondClaim,
    useForwardRuntime.getState().byRule["c7"],
  );
  check(
    "C7: still exactly one close call total - the wanted attempt was never released",
    closeCalls.length === 1,
    closeCalls.length,
  );
}

// ---------------------------------------------------------------------------
console.log(
  "\n[C8] plain running -> stop: closes with rule.localPort AND the recorded claim, then marks stopped",
);
{
  resetFakes();
  resetStores();
  const rule = fakeRule({ id: "c8", localPort: 18080 });
  await startRule(rule, FAKE_RUNTIME);
  const claim = useForwardRuntime.getState().byRule["c8"]?.claim;
  check(
    "C8: the rule is running with a claim recorded",
    useForwardRuntime.getState().byRule["c8"]?.status === "running" && claim !== undefined,
    useForwardRuntime.getState().byRule["c8"],
  );

  resetCallLogs();
  await stopRule(rule, FAKE_RUNTIME);
  check(
    "C8: close was called with rule.localPort and the recorded claim",
    closeCalls.length === 1 &&
      closeCalls[0]?.localPort === rule.localPort &&
      closeCalls[0]?.claim === claim,
    closeCalls[0],
  );
  check(
    "C8: the row ends stopped",
    useForwardRuntime.getState().byRule["c8"]?.status === "stopped",
  );
}

// ---------------------------------------------------------------------------
console.log(
  "\n[C9] startRule REFUSES a rule a terminal already owns - no dial, a toast, and the page's store untouched",
);
// `controller.ts` had zero `hostOwned` awareness: `RuleCard`'s `startDisabled`
// was the entire defence, and a disabled button is a rendering rather than an
// invariant. `hostOwned` can also become true while this page's own Start is in
// flight (the terminal reads the page's status before its bind and claims after
// it), so the guard has to live where the dial does. First claim wins (VLT-94),
// and the terminal's is the one already taken.
//
// This lives here and NOT in `rdp-tunnel-verify.ts`, which the brief named:
// that script has no reference to `startRule`, `stopRule` or `controller` at
// all. This file is the one that owns the `RuntimeDeps` seam.
{
  resetFakes();
  resetStores();
  const rule = fakeRule({ id: "c9", localPort: 18080 });
  useHostOwnedForwards.setState({ byRule: { c9: { sessionId: 41, boundPort: 54321 } } });
  await startRule(rule, FAKE_RUNTIME);
  check(
    "C9: nothing was dialled - the refusal is ahead of the open",
    openCalls.length === 0,
    openCalls,
  );
  check(
    "C9: the user was told why, naming the rule",
    toastCalls.length === 1 && (toastCalls[0]?.message ?? "").includes(`"${rule.name}"`),
    toastCalls,
  );
  check(
    "C9: and it points at the terminal tab rather than at this page",
    /terminal tab/.test(toastCalls[0]?.message ?? ""),
    toastCalls[0]?.message,
  );
  // The refusal sits ABOVE `markStarting`, so the page publishes no status it
  // would then need a claim to leave. A row left "starting" for a rule this
  // page never dialled is the third self-contradiction B3 describes.
  check(
    "C9: the page's own store is untouched - it took no claim, so it holds none",
    useForwardRuntime.getState().byRule["c9"] === undefined,
    useForwardRuntime.getState().byRule["c9"],
  );
  check(
    "C9: and the terminal's entry is left exactly as it was",
    useHostOwnedForwards.getState().byRule["c9"]?.sessionId === 41,
    useHostOwnedForwards.getState().byRule["c9"],
  );
}
{
  // The paired positive: the same rule dials normally once no terminal holds
  // it. Without this the guard passes with the refusal widened to "always".
  resetFakes();
  resetStores();
  const rule = fakeRule({ id: "c9b", localPort: 18080 });
  await startRule(rule, FAKE_RUNTIME);
  check(
    "C9: with the terminal's map empty the same Start dials and the row runs",
    openCalls.length === 1 && useForwardRuntime.getState().byRule["c9b"]?.status === "running",
    { opens: openCalls.length, row: useForwardRuntime.getState().byRule["c9b"] },
  );
  check("C9: and nothing was toasted", toastCalls.length === 0, toastCalls);
}

// ---------------------------------------------------------------------------
console.log(
  "\n[C10] startRule's dial resolves into a rule the TERMINAL claimed meanwhile - the page releases its own reference, marks STOPPED (not failed) and says so once",
);
// THE PAGE'S HALF OF ONE RULE SEEN FROM TWO SIDES. `autostart.ts`'s post-bind
// re-read used to yield on `taken === "starting"`, and the sequence that
// exposed it has DEFAULT step ordering rather than unlucky ordering: the
// terminal's bind wins in the backend because it arrived first, the page's bind
// returns EADDRINUSE, the terminal's `await` resolves first and reads
// `"starting"`. With the terminal yielding there, it closed its own live
// listener and the page's rejection then marked the row failed - no owner on
// either side, and a row reading "Failed - port 18080 is already in use" naming
// a port nothing held.
//
// So the terminal CLAIMS on `starting` (`forward-autostart-verify.ts`'s section
// 14) and the PAGE gives up the duplicate when its own dial lands into a rule
// the terminal now owns. Whoever resolves SECOND yields, on both sides, and
// neither side ever takes the other's listener down.
//
// `markStopped` and NOT `markFailed` is the load-bearing half of this fixture:
// nothing failed. The forward the user asked for is up, and `RuleCard` renders
// that off `hostOwned` alone.
{
  resetFakes();
  resetStores();
  const rule = fakeRule({ id: "c10", localPort: 0 });
  autoAnswerFakeOpen = false;
  const starting = startRule(rule, FAKE_RUNTIME);
  await settle();
  check(
    "C10: the dial is parked mid-handshake",
    parkedFakeOpens.length === 1,
    parkedFakeOpens.length,
  );
  check(
    "C10: the page's row is starting - the pre-dial refusal did not fire, the map was empty",
    useForwardRuntime.getState().byRule["c10"]?.status === "starting",
    useForwardRuntime.getState().byRule["c10"],
  );

  // The terminal's autostart claims WHILE this dial is in flight. Synchronous
  // in production too - `claimHostOwned` is a plain store write - so no timing
  // trick is needed to reach it.
  useHostOwnedForwards.setState({ byRule: { c10: { sessionId: 41, boundPort: 54321 } } });

  const landedClaim = nextFakeClaim;
  parkedFakeOpens[0].resolve({
    sessionId: nextFakeSessionId++,
    localPort: 30000,
    claim: landedClaim,
  });
  nextFakeClaim++;
  await starting;
  await settle();

  check(
    "C10: the reference this dial just received went straight back, with ITS OWN claim",
    closeCalls.length === 1 && closeCalls[0]?.claim === landedClaim,
    closeCalls[0],
  );
  check(
    "C10: and the close named rule.localPort, the value that finds the entry",
    closeCalls[0]?.localPort === rule.localPort,
    closeCalls[0],
  );
  check(
    "C10: the row is STOPPED, never failed - nothing failed",
    useForwardRuntime.getState().byRule["c10"]?.status === "stopped",
    useForwardRuntime.getState().byRule["c10"],
  );
  check(
    "C10: and it published no claim - the page holds nothing it would have to spend",
    useForwardRuntime.getState().byRule["c10"]?.claim === undefined &&
      useForwardRuntime.getState().byRule["c10"]?.boundPort === undefined,
    useForwardRuntime.getState().byRule["c10"],
  );
  check(
    "C10: exactly ONE toast, naming the rule and pointing at the terminal tab",
    toastCalls.length === 1 &&
      (toastCalls[0]?.message ?? "").includes(`"${rule.name}"`) &&
      /terminal tab/.test(toastCalls[0]?.message ?? ""),
    toastCalls,
  );
  check(
    "C10: and it is a WARNING, not an error - an error is what the old code said",
    toastCalls[0]?.variant === "warning",
    toastCalls[0],
  );
  check(
    "C10: the terminal's entry is left exactly as it was - the page never touches that map",
    useHostOwnedForwards.getState().byRule["c10"]?.sessionId === 41 &&
      useHostOwnedForwards.getState().byRule["c10"]?.boundPort === 54321,
    useHostOwnedForwards.getState().byRule["c10"],
  );
}
{
  // The paired control, and it is what tells "the post-dial guard bites" from
  // "the park bites": the SAME parked dial, resolved the same way, with the
  // terminal's map left EMPTY. The row runs and nothing is released.
  resetFakes();
  resetStores();
  const rule = fakeRule({ id: "c10b", localPort: 0 });
  autoAnswerFakeOpen = false;
  const starting = startRule(rule, FAKE_RUNTIME);
  await settle();
  const landedClaim = nextFakeClaim;
  parkedFakeOpens[0].resolve({
    sessionId: nextFakeSessionId++,
    localPort: 30000,
    claim: landedClaim,
  });
  nextFakeClaim++;
  await starting;
  await settle();
  check(
    "C10: with no terminal claim the same dial marks running, with its own claim and bound port",
    useForwardRuntime.getState().byRule["c10b"]?.status === "running" &&
      useForwardRuntime.getState().byRule["c10b"]?.claim === landedClaim &&
      useForwardRuntime.getState().byRule["c10b"]?.boundPort === 30000,
    useForwardRuntime.getState().byRule["c10b"],
  );
  check("C10: and released nothing", closeCalls.length === 0, closeCalls);
  check("C10: and said nothing", toastCalls.length === 0, toastCalls);
}

// ---------------------------------------------------------------------------
console.log(
  "\n[C11] pageMustStopFirst answers about NOW, over the real stores - every status in, both owners",
);
// The predicate `ForwardsPage.tsx`'s confirm and `RuleEditorDialog.tsx`'s save
// both gate on. Driven against the REAL `useForwardRuntime` and
// `useHostOwnedForwards` rather than a table of booleans, which is what also
// pins WHICH KEYS it reads: a version consulting `boundPort`, or the wrong
// store, disagrees with a row of this table.
//
// THE STATUS SET IS THE CLAIM, and the sentence here used to have it backwards:
// `"starting"` must answer `true` and a version consulting `"running"` ALONE is
// what disagrees with a row of this table. That inversion is not a typo with no
// consequence - the row below asserted `want: false` for `starting`, so this
// table certified the defect G1/G2 measure as correct behaviour. `"failed"` and
// `"stopped"` stay `false`, and those two rows are what stop the fix from being
// "answer true for anything that is not stopped": `markFailed` only runs when
// the open rejected and neither it nor `markStopped` retains a claim, so there
// is nothing for a Stop to spend.
//
// Why it exists at all, rather than the flag `RuleCard` hands over: that flag
// is captured when the trash icon is clicked, the row is on screen as
// `starting` for the whole dial, and neither the trash nor the Edit button is
// disabled during it - so BOTH orderings of the same two clicks are ordinary.
// The dial resolving BEFORE the confirm is C12; the dial resolving AFTER it is
// G1, and only the `starting` row of this table separates them.
/** `runtime.ts`'s own `ForwardStatus`, read off the store's state type rather
 *  than imported - this file reaches every module under test through the
 *  dynamic imports above, because the Tauri stand-in has to be installed
 *  first, and taking the type off the value keeps the two from drifting. */
type ForwardStatusType = NonNullable<
  ReturnType<typeof useForwardRuntime.getState>["byRule"][string]
>["status"];
{
  resetStores();
  const cases: Array<{ status?: ForwardStatusType; hostOwned: boolean; want: boolean }> = [
    { status: undefined, hostOwned: false, want: false },
    { status: "stopped", hostOwned: false, want: false },
    // THE ROW THIS ROUND FLIPPED. A bind is in flight and the page owns it, so
    // the record must not go until it has been stopped - G1 and G2 drive both
    // callers on exactly this status.
    { status: "starting", hostOwned: false, want: true },
    { status: "running", hostOwned: false, want: true },
    { status: "failed", hostOwned: false, want: false },
    // `hostOwned` FIRST, the one precedence order `RuleCard.tsx`'s header
    // states for all nine of its own sites: a forward the TERMINAL opened is
    // not this page's to stop, and the page holds no reference to spend on it.
    // The `running` row here is the combination that header calls
    // unconstructible; the arm is written anyway, and this is what measures it.
    { status: undefined, hostOwned: true, want: false },
    { status: "stopped", hostOwned: true, want: false },
    { status: "starting", hostOwned: true, want: false },
    { status: "running", hostOwned: true, want: false },
    { status: "failed", hostOwned: true, want: false },
  ];
  for (const c of cases) {
    useForwardRuntime.setState({
      byRule: c.status === undefined ? {} : { c11: { status: c.status } },
    });
    useHostOwnedForwards.setState({
      byRule: c.hostOwned ? { c11: { sessionId: 41, boundPort: 54321 } } : {},
    });
    check(
      `C11: status=${c.status ?? "(no entry)"} hostOwned=${c.hostOwned} -> ${c.want}`,
      pageMustStopFirst("c11") === c.want,
      pageMustStopFirst("c11"),
    );
  }
  // And it is keyed by the rule it was asked about, not by "anything is
  // running": without this, a predicate ignoring its argument passes every row
  // of the table above whose answer is `true`.
  useForwardRuntime.setState({ byRule: { c11: { status: "running" } } });
  useHostOwnedForwards.setState({ byRule: {} });
  check(
    "C11: and it answers about the rule it was ASKED about - a different id is not running",
    pageMustStopFirst("c11") === true && pageMustStopFirst("c11-other") === false,
    { c11: pageMustStopFirst("c11"), other: pageMustStopFirst("c11-other") },
  );
}

// ---------------------------------------------------------------------------
console.log(
  "\n[C12] THE P0, driven end to end: a dial that resolves while the confirm dialog is up, stopped before the delete - and the same interleaving under the old guard, which releases nothing",
);
// The sequence, and none of it is unlucky timing: click Start (the row goes
// `starting`), click Delete, the dial resolves - connect, host key, bind,
// routinely 1-3 seconds, against a confirm click that adds about a second - and
// only then is Delete rule pressed. Under the old guard the record went away
// while `runtime.ts` kept an entry naming a rule no row renders,
// `ssh/tunnel.ts`'s entry stayed at `refs: 1` so the SSH session never closed
// again, and the local port stayed bound with no in-app recovery.
//
// `capturedRunning` BELOW IS THE NARROW FLAG, computed here as
// `status === "running"` because that is what `RuleCard` handed over before
// this round widened it to `pageStops` (`running || starting`) - so it is now a
// historical control rather than a reading of today's row, and it is kept
// because the claim it measures is not about that flag's width. THE CLAIM IS
// THAT A CAPTURED FLAG IS A CLAIM ABOUT A MOMENT THAT HAS PASSED, which no
// widening fixes: the guard has to be the live read whatever the row handed
// over. G1 is the interleaving where the widened flag and the live read agree
// and the OLD PREDICATE is what leaks.
//
// `confirmDelete` is a `useCallback` inside a component whose import graph
// reaches React and Radix, so it is not drivable here; what IS drivable is
// every part of it that decides anything - the live guard and the real
// `stopRule` - and its call site is pinned structurally as section 11.
{
  resetFakes();
  resetStores();
  const rule = fakeRule({ id: "c12", localPort: 18080 });
  autoAnswerFakeOpen = false;
  const starting = startRule(rule, FAKE_RUNTIME);
  await settle();

  // THE DELETE CLICK. The NARROW captured flag, computed the way `RuleCard`
  // computed it before this round - see the note above on why it is kept.
  const capturedRunning = useForwardRuntime.getState().byRule["c12"]?.status === "running";
  const capturedHostOwned = useHostOwnedForwards.getState().byRule["c12"] !== undefined;
  check(
    "C12: at Delete-click time the row is `starting`, so the NARROW captured flag says not-running and neither store reports a terminal owner",
    useForwardRuntime.getState().byRule["c12"]?.status === "starting" &&
      capturedRunning === false &&
      capturedHostOwned === false,
    { status: useForwardRuntime.getState().byRule["c12"]?.status, capturedRunning },
  );

  // The dial lands while the dialog is on screen.
  const landedClaim = nextFakeClaim;
  parkedFakeOpens[0].resolve({
    sessionId: nextFakeSessionId++,
    localPort: rule.localPort,
    claim: landedClaim,
  });
  nextFakeClaim++;
  await starting;
  await settle();
  check(
    "C12: by confirm time the forward is UP - the captured flag is now a wrong answer about a live listener",
    useForwardRuntime.getState().byRule["c12"]?.status === "running" &&
      useForwardRuntime.getState().byRule["c12"]?.claim === landedClaim,
    useForwardRuntime.getState().byRule["c12"],
  );
  check(
    "C12: and the live guard DISAGREES with the narrow captured flag, which is the whole defect in one line",
    capturedRunning === false && pageMustStopFirst("c12") === true,
    { capturedRunning, live: pageMustStopFirst("c12") },
  );

  // confirmDelete's own two statements, in its own order.
  resetCallLogs();
  if (pageMustStopFirst(rule.id)) await stopRule(rule, FAKE_RUNTIME);
  check(
    "C12: the forward was released before the delete, with the claim this dial recorded",
    closeCalls.length === 1 && closeCalls[0]?.claim === landedClaim,
    closeCalls[0],
  );
  check(
    "C12: named by rule.localPort - the value that finds the entry",
    closeCalls[0]?.localPort === rule.localPort,
    closeCalls[0],
  );
  check(
    "C12: and the row ends stopped, with no claim left behind",
    useForwardRuntime.getState().byRule["c12"]?.status === "stopped" &&
      useForwardRuntime.getState().byRule["c12"]?.claim === undefined,
    useForwardRuntime.getState().byRule["c12"],
  );
}
{
  // THE OLD GUARD ON THE SAME INTERLEAVING, measured rather than argued - and
  // this is the control that makes the fixture above mean something. Identical
  // steps; the only difference is that the guard is the narrow captured flag.
  resetFakes();
  resetStores();
  const rule = fakeRule({ id: "c12b", localPort: 18080 });
  autoAnswerFakeOpen = false;
  const starting = startRule(rule, FAKE_RUNTIME);
  await settle();
  const capturedRunning = useForwardRuntime.getState().byRule["c12b"]?.status === "running";
  const landedClaim = nextFakeClaim;
  parkedFakeOpens[0].resolve({
    sessionId: nextFakeSessionId++,
    localPort: rule.localPort,
    claim: landedClaim,
  });
  nextFakeClaim++;
  await starting;
  await settle();

  resetCallLogs();
  if (capturedRunning) await stopRule(rule, FAKE_RUNTIME);
  check(
    "C12: CONTROL - guarded on the narrow captured flag, closeForward is called ZERO times",
    closeCalls.length === 0,
    closeCalls,
  );
  check(
    "C12: CONTROL - and runtime.ts is left naming the rule as running, holding a claim nothing will ever spend",
    useForwardRuntime.getState().byRule["c12b"]?.status === "running" &&
      useForwardRuntime.getState().byRule["c12b"]?.claim === landedClaim,
    useForwardRuntime.getState().byRule["c12b"],
  );
}

// ---------------------------------------------------------------------------
console.log(
  "\n[C13] the editor's leak: a Stop issued with the EDITED record MISSES its entry, and the record as loaded HITS it",
);
// `ssh/tunnel.ts`'s `forwardKey` is `connectionId|remoteHost|remotePort|localPort`
// (`tunnel.ts:246-252`) and `RuleEditorDialog.tsx` edits all four, so the write
// invalidates the key that rule's own Stop names. Pure clicks, no timing: Start
// on 18080, Edit, Local port 18081, Save, Stop.
//
// `FAKE_RUNTIME`'s `closeForward` only LOGS, so it cannot tell a close that
// found its entry from one that did not - a mock that cannot distinguish its
// input from its output is the fidelity trap this file's header names, and it
// would make this fixture a tautology. So this one keeps a keyed map and
// reports the hit.
{
  const keyOf = (
    connectionId: string,
    remoteHost: string,
    remotePort: number,
    localPort: number,
  ): string => `${connectionId}|${remoteHost}|${remotePort}|${localPort}`;
  const entries = new Map<string, { claim: number }>();
  const closeResults: Array<{ key: string; hit: boolean }> = [];
  const KEYED_RUNTIME = {
    openForward: (
      connectionId: string,
      remoteHost: string,
      remotePort: number,
      opts: OpenCall["opts"] = {},
    ): Promise<FakeForward> => {
      const asked = opts.localPort ?? 0;
      const forward = {
        sessionId: nextFakeSessionId++,
        localPort: asked || nextFakeAutoPort++,
        claim: nextFakeClaim++,
      };
      // Keyed on the port ASKED FOR, exactly as `tunnel.ts` keys it - the
      // asymmetry with the port it resolves is that file's own doc.
      entries.set(keyOf(connectionId, remoteHost, remotePort, asked), { claim: forward.claim });
      return Promise.resolve(forward);
    },
    closeForward: (
      connectionId: string,
      remoteHost: string,
      remotePort: number,
      localPort: number,
    ): Promise<void> => {
      const key = keyOf(connectionId, remoteHost, remotePort, localPort);
      const hit = entries.delete(key);
      closeResults.push({ key, hit });
      return Promise.resolve();
    },
    toast: (): void => {},
  } satisfies RuntimeDepsType;

  const original = fakeRule({ id: "c13", localPort: 18080 });
  const edited = { ...original, localPort: 18081 };

  resetFakes();
  resetStores();
  await startRule(original, KEYED_RUNTIME);
  check(
    "C13: the entry is stored under the key the open asked for",
    entries.has(keyOf(original.hostId, original.remoteHost, original.remotePort, 18080)),
    [...entries.keys()],
  );

  // THE DEFECT: the save wrote first, so the only record left to stop with is
  // the edited one.
  await stopRule(edited, KEYED_RUNTIME);
  const missed = closeResults[closeResults.length - 1];
  check(
    "C13: a Stop issued with the EDITED record MISSES - there is no entry under its new key",
    missed?.hit === false && missed?.key.endsWith("|18081"),
    missed,
  );
  check(
    "C13: the original entry is STILL OPEN, and markStopped has discarded the claim - no Stop can ever be issued again",
    entries.size === 1 &&
      entries.has(keyOf(original.hostId, original.remoteHost, original.remotePort, 18080)) &&
      useForwardRuntime.getState().byRule["c13"]?.status === "stopped" &&
      useForwardRuntime.getState().byRule["c13"]?.claim === undefined,
    { keys: [...entries.keys()], row: useForwardRuntime.getState().byRule["c13"] },
  );

  // THE FIX: the save's guarded stop, with the record as LOADED, while it is
  // still the identity the entry is under. Its ORDER against the write is
  // section 12's claim - the write itself is the dialog's and is not drivable
  // from here.
  entries.clear();
  closeResults.length = 0;
  resetFakes();
  resetStores();
  await startRule(original, KEYED_RUNTIME);
  check("C13: the page is running it, so the live guard says stop", pageMustStopFirst("c13"));
  if (pageMustStopFirst(original.id)) await stopRule(original, KEYED_RUNTIME);
  const landed = closeResults[closeResults.length - 1];
  check(
    "C13: the close HIT its entry - `existing` is the identity the forward was opened under",
    landed?.hit === true && landed?.key.endsWith("|18080"),
    landed,
  );
  check(
    "C13: and nothing is left bound",
    entries.size === 0 && useForwardRuntime.getState().byRule["c13"]?.status === "stopped",
    { keys: [...entries.keys()], row: useForwardRuntime.getState().byRule["c13"] },
  );
  check(
    "C13: CONTROL - a rule the page is NOT running is left alone by the same guard",
    pageMustStopFirst("c13") === false,
    pageMustStopFirst("c13"),
  );
}

// ---------------------------------------------------------------------------
console.log(
  "\n[G1] DELETE CONFIRMED WHILE THE ROW IS STILL `starting` - the other ordering of C12's two clicks, and the one a `running`-only guard leaks",
);
// SAME TWO CLICKS AS C12, with a faster second one or a slower connect. C12 has
// the dial resolving BETWEEN the trash click and the confirm click; this has it
// resolving AFTER the confirm, and reading live closes only the first of the
// two. The trash button carries no `disabled` at all (`RuleCard.tsx`'s
// `startDisabled` gates the toggle alone), so neither ordering is unlucky.
//
// WHAT A `running`-ONLY GUARD DOES HERE, which the CONTROL below measures: the
// guard says no, `deleteRule` removes the record, and nothing cleared
// `startAttempts` - so the dial that lands afterwards is still the CURRENT
// attempt, `hostOwned` is absent, and `markRunning` runs for a rule no row can
// ever render. `runtime.ts` then names a deleted rule as running, `tunnel.ts`'s
// entry stays at `refs: 1`, and the port is bound with no in-app recovery.
//
// AND THE FIXED PREDICATE IS SAFE RATHER THAN MERELY DIFFERENT, which is the
// half worth measuring: `stopRule` deletes the attempt Set, so the resolving
// dial finds itself superseded and hands its reference straight back
// (`controller.ts:182-196`) - one close, the row `stopped`, no claim retained.
{
  resetFakes();
  resetStores();
  const rule = fakeRule({ id: "g1", localPort: 18080 });
  autoAnswerFakeOpen = false;
  const starting = startRule(rule, FAKE_RUNTIME);
  await settle();
  check(
    "G1: the row is still `starting` when Delete rule is pressed - the dial has not landed",
    useForwardRuntime.getState().byRule["g1"]?.status === "starting",
    useForwardRuntime.getState().byRule["g1"],
  );
  check(
    "G1: and the live guard says STOP FIRST for a mid-dial rule - a bind in flight is this page's forward too",
    pageMustStopFirst("g1") === true,
    pageMustStopFirst("g1"),
  );

  // `confirmDelete`'s own two statements, in its own order. `deleteRule` is a
  // `LazyStore` write and is not drivable here; what it does - remove the
  // record, so no row can render this rule again - is what makes the CONTROL's
  // leak unrecoverable, and section 11 pins the call itself.
  resetCallLogs();
  if (pageMustStopFirst(rule.id)) await stopRule(rule, FAKE_RUNTIME);
  check(
    "G1: that stop had no claim to spend - `markRunning` has not run, so nothing is bound YET and nothing is closed",
    closeCalls.length === 0 && useForwardRuntime.getState().byRule["g1"]?.status === "stopped",
    { closes: closeCalls.length, row: useForwardRuntime.getState().byRule["g1"] },
  );

  // AND ONLY NOW DOES THE BIND LAND, into a rule the user has already deleted.
  const landedClaim = nextFakeClaim;
  parkedFakeOpens[0].resolve({
    sessionId: nextFakeSessionId++,
    localPort: rule.localPort,
    claim: landedClaim,
  });
  nextFakeClaim++;
  await starting;
  await settle();
  check(
    "G1: the dial handed its reference straight back - exactly one close, carrying the claim that dial received",
    closeCalls.length === 1 && closeCalls[0]?.claim === landedClaim,
    closeCalls,
  );
  check(
    "G1: named by rule.localPort - the value that finds the entry",
    closeCalls[0]?.localPort === rule.localPort,
    closeCalls[0],
  );
  check(
    "G1: and the row is left `stopped` with no claim retained - nothing names a rule the user deleted",
    useForwardRuntime.getState().byRule["g1"]?.status === "stopped" &&
      useForwardRuntime.getState().byRule["g1"]?.claim === undefined,
    useForwardRuntime.getState().byRule["g1"],
  );
}
{
  // THE `running`-ONLY PREDICATE ON THE SAME INTERLEAVING - what round 4
  // landed, measured rather than argued. Identical steps; the only difference
  // is the guard.
  resetFakes();
  resetStores();
  const rule = fakeRule({ id: "g1b", localPort: 18080 });
  autoAnswerFakeOpen = false;
  const starting = startRule(rule, FAKE_RUNTIME);
  await settle();
  const runningOnlyGuard = useForwardRuntime.getState().byRule["g1b"]?.status === "running";
  check(
    "G1: CONTROL - the `running`-only predicate says DO NOT STOP, because the status is `starting` and not `running`",
    runningOnlyGuard === false,
    { status: useForwardRuntime.getState().byRule["g1b"]?.status, guard: runningOnlyGuard },
  );
  resetCallLogs();
  if (runningOnlyGuard) await stopRule(rule, FAKE_RUNTIME);
  const landedClaim = nextFakeClaim;
  parkedFakeOpens[0].resolve({
    sessionId: nextFakeSessionId++,
    localPort: rule.localPort,
    claim: landedClaim,
  });
  nextFakeClaim++;
  await starting;
  await settle();
  check(
    "G1: CONTROL - THE LEAK: closeForward was never called, so the listener on 18080 is still up",
    closeCalls.length === 0,
    closeCalls,
  );
  check(
    "G1: CONTROL - THE LEAK: runtime.ts now names a rule the delete removed as running, holding a claim nothing will ever spend",
    useForwardRuntime.getState().byRule["g1b"]?.status === "running" &&
      useForwardRuntime.getState().byRule["g1b"]?.claim === landedClaim,
    useForwardRuntime.getState().byRule["g1b"],
  );
}

// ---------------------------------------------------------------------------
console.log(
  "\n[G2] SAVE WHILE THE ROW IS STILL `starting` - C13's own sequence with one difference, and the editor's half of G1",
);
// C13 drives Start, Edit, Save, Stop with the dial already landed, where the
// fix is correct. This drives the SAME clicks with the Save landing mid-dial,
// where a `running`-only guard is inert: the record is rewritten, the bind
// lands under the OLD `forwardKey`, and the row's Stop - all the user has left -
// names the NEW one and misses, while `markStopped` discards the claim.
//
// `FAKE_RUNTIME` cannot express this: its `closeForward` only logs, so it
// cannot tell a close that found its entry from one that did not, and the trap
// this file's header names would make the fixture a tautology. So this block
// keeps C13's keyed map and adds the one thing C13 has no need of - a PARKED
// open, so the entry appears when the bind lands rather than when it was asked
// for.
{
  const keyOf = (
    connectionId: string,
    remoteHost: string,
    remotePort: number,
    localPort: number,
  ): string => `${connectionId}|${remoteHost}|${remotePort}|${localPort}`;
  const entries = new Map<string, { claim: number }>();
  const closeResults: Array<{ key: string; hit: boolean }> = [];
  const landParkedOpen: Array<() => void> = [];
  const PARKED_KEYED_RUNTIME = {
    openForward: (
      connectionId: string,
      remoteHost: string,
      remotePort: number,
      opts: OpenCall["opts"] = {},
    ): Promise<FakeForward> => {
      const asked = opts.localPort ?? 0;
      return new Promise<FakeForward>((resolve) => {
        landParkedOpen.push(() => {
          const forward = {
            sessionId: nextFakeSessionId++,
            localPort: asked || nextFakeAutoPort++,
            claim: nextFakeClaim++,
          };
          // Keyed on the port ASKED FOR, exactly as `tunnel.ts` keys it, and
          // created HERE rather than at call time - the listener does not exist
          // until the bind lands, which is the whole of what "mid-dial" means.
          entries.set(keyOf(connectionId, remoteHost, remotePort, asked), {
            claim: forward.claim,
          });
          resolve(forward);
        });
      });
    },
    closeForward: (
      connectionId: string,
      remoteHost: string,
      remotePort: number,
      localPort: number,
    ): Promise<void> => {
      const key = keyOf(connectionId, remoteHost, remotePort, localPort);
      const hit = entries.delete(key);
      closeResults.push({ key, hit });
      return Promise.resolve();
    },
    toast: (): void => {},
  } satisfies RuntimeDepsType;

  // The edited record is never handed to a Stop in THIS half - that is the
  // point of the fix. The CONTROL below is where it is, and where it misses.
  const original = fakeRule({ id: "g2", localPort: 18080 });

  resetFakes();
  resetStores();
  const starting = startRule(original, PARKED_KEYED_RUNTIME);
  await settle();
  check(
    "G2: nothing is bound yet - the open is still parked, so there is no entry under any key",
    entries.size === 0 && useForwardRuntime.getState().byRule["g2"]?.status === "starting",
    { keys: [...entries.keys()], row: useForwardRuntime.getState().byRule["g2"] },
  );
  // `save`'s own guarded stop, with `existing` - the record as LOADED, which is
  // still the identity the open asked under. The `upsertRule` beside it is the
  // dialog's and is not drivable from here; section 12 pins the order.
  check("G2: the live guard says stop, because the row is mid-dial", pageMustStopFirst("g2"));
  if (pageMustStopFirst(original.id)) await stopRule(original, PARKED_KEYED_RUNTIME);
  // THE BIND LANDS, under the OLD key, after the write has replaced the record.
  landParkedOpen[0]?.();
  await starting;
  await settle();
  const landed = closeResults[closeResults.length - 1];
  check(
    "G2: the superseded dial released what it had bound, HITTING the old key - `existing` is the identity the open asked under",
    landed?.hit === true && landed?.key.endsWith("|18080"),
    { landed, all: closeResults },
  );
  check(
    "G2: so nothing is left bound and the row holds no claim - the user's next Start binds 18081 cleanly",
    entries.size === 0 &&
      useForwardRuntime.getState().byRule["g2"]?.status === "stopped" &&
      useForwardRuntime.getState().byRule["g2"]?.claim === undefined,
    { keys: [...entries.keys()], row: useForwardRuntime.getState().byRule["g2"] },
  );
}
{
  // THE `running`-ONLY PREDICATE ON THE SAME SEQUENCE. The save declines, the
  // dial lands under the old key and publishes itself, and the only Stop the
  // user has left reads the record the save WROTE.
  const keyOf = (
    connectionId: string,
    remoteHost: string,
    remotePort: number,
    localPort: number,
  ): string => `${connectionId}|${remoteHost}|${remotePort}|${localPort}`;
  const entries = new Map<string, { claim: number }>();
  const closeResults: Array<{ key: string; hit: boolean }> = [];
  const landParkedOpen: Array<() => void> = [];
  const PARKED_KEYED_RUNTIME = {
    openForward: (
      connectionId: string,
      remoteHost: string,
      remotePort: number,
      opts: OpenCall["opts"] = {},
    ): Promise<FakeForward> => {
      const asked = opts.localPort ?? 0;
      return new Promise<FakeForward>((resolve) => {
        landParkedOpen.push(() => {
          const forward = {
            sessionId: nextFakeSessionId++,
            localPort: asked || nextFakeAutoPort++,
            claim: nextFakeClaim++,
          };
          entries.set(keyOf(connectionId, remoteHost, remotePort, asked), {
            claim: forward.claim,
          });
          resolve(forward);
        });
      });
    },
    closeForward: (
      connectionId: string,
      remoteHost: string,
      remotePort: number,
      localPort: number,
    ): Promise<void> => {
      const key = keyOf(connectionId, remoteHost, remotePort, localPort);
      const hit = entries.delete(key);
      closeResults.push({ key, hit });
      return Promise.resolve();
    },
    toast: (): void => {},
  } satisfies RuntimeDepsType;

  const original = fakeRule({ id: "g2b", localPort: 18080 });
  const edited = { ...original, localPort: 18081 };

  resetFakes();
  resetStores();
  const starting = startRule(original, PARKED_KEYED_RUNTIME);
  await settle();
  const runningOnlyGuard = useForwardRuntime.getState().byRule["g2b"]?.status === "running";
  check(
    "G2: CONTROL - the `running`-only guard declines, because the row is `starting`",
    runningOnlyGuard === false,
    { status: useForwardRuntime.getState().byRule["g2b"]?.status, guard: runningOnlyGuard },
  );
  if (runningOnlyGuard) await stopRule(original, PARKED_KEYED_RUNTIME);
  landParkedOpen[0]?.();
  await starting;
  await settle();
  check(
    "G2: CONTROL - the dial published itself under the OLD key, so the row reads running over a listener the saved record no longer names",
    entries.size === 1 &&
      entries.has(keyOf(original.hostId, original.remoteHost, original.remotePort, 18080)) &&
      useForwardRuntime.getState().byRule["g2b"]?.status === "running",
    { keys: [...entries.keys()], row: useForwardRuntime.getState().byRule["g2b"] },
  );
  // The row's own Stop - all the user has left, and it reads the record from
  // the store, which is the one the save wrote.
  await stopRule(edited, PARKED_KEYED_RUNTIME);
  const missed = closeResults[closeResults.length - 1];
  check(
    "G2: CONTROL - THE LEAK: that Stop MISSES its entry (the new key), and markStopped has discarded the claim - no Stop can ever be issued again",
    missed?.hit === false &&
      missed?.key.endsWith("|18081") &&
      entries.size === 1 &&
      useForwardRuntime.getState().byRule["g2b"]?.claim === undefined,
    { missed, keys: [...entries.keys()], row: useForwardRuntime.getState().byRule["g2b"] },
  );
}

console.log(failed === 0 ? "\nAll forwards-shell checks passed." : `\n${failed} check(s) FAILED.`);

// ----------------------------------------------------------------------------
// Mutation table - every mutation actually run against this file's own
// checks, by hand, before this step was considered done. Restored by hash
// each time (`git hash-object` / `git cat-file blob`), never by
// `git checkout --` or `git show HEAD:`. Full transcript, exit codes and
// restore hashes: the step-10 report sent to the orchestrator.
//
//   Mutation                                          Check(s) it killed
//   -------------------------------------------------  ---------------------------
//   Z1: RuleCard.tsx uses one object selector          [2]'s "only in runtime.ts"
//     (s) => ({...s.byRule[id]}) instead of the          check, naming
//     three primitive hooks                              page/RuleCard.tsx
//   Z2: a runtime.ts selector returns                  [2]'s primitive-shape
//     Object.values(s.byRule) with no .length            check for that selector
//   Z3: import { useShallow } from                     [2]'s repo-wide grep
//     "zustand/react/shallow" added and used in           (plus two more,
//     runtime.ts                                          legitimately - the
//                                                          argument is no longer
//                                                          a bare arrow, and the
//                                                          import line itself)
//   Z4: useRunningCount returns                        [2]'s primitive-shape
//     Object.values(s.byRule).filter(...) with no         check, naming that
//     .length                                             selector - FIRST DRAFT
//                                                          of isForbiddenSelectorBody
//                                                          only inspected the
//                                                          OUTERMOST call's callee
//                                                          (".filter", not
//                                                          "Object.values") and
//                                                          went GREEN over this;
//                                                          fixed to walk the whole
//                                                          primary chain
//   Z5: a CONFORMING primitive                         [2]'s "only in
//     useForwardRuntime((s) => ...) call added in         runtime.ts" check,
//     RuleCard.tsx                                        naming page/RuleCard.tsx
//   E1: upsertRule({ ...ruleRecordFrom(id, draft),      [3]'s exact-text pin
//     hostId: draft.hostId }, findHost)
//   E2: the upsertRule(...) statement deleted,          [3]'s direct-statement
//     replaced by a nested-arrow decoy containing the      check ONLY - the
//     same text                                           count and the text
//                                                          pin both stayed
//                                                          green, the asymmetry
//                                                          the brief predicted
//   E3: a second ruleRecordFrom(...) call added in a    [3]'s NEW
//     sibling branch (never passed to upsertRule)          ruleRecordFrom(
//                                                          count check - FIRST
//                                                          DRAFT of section 3
//                                                          only counted
//                                                          upsertRule( calls and
//                                                          went GREEN over this;
//                                                          added a dedicated
//                                                          ruleRecordFrom( count
//   E4: the upsertRule(ruleRecordFrom(id, draft),       GREEN, as predicted -
//     findHost) call reformatted across multiple           but only after norm()
//     lines (Prettier trailing comma)                      was fixed to strip
//                                                          trailing commas too;
//                                                          FIRST DRAFT only
//                                                          stripped whitespace
//                                                          and a legal reformat
//                                                          spuriously reddened
//                                                          the exact-text pin
//   E5: privilegedPortWarning's reader moved to the     [4]'s first check
//     bottom of the form, outside every Field
//   E6: the generic error reader ALSO rendered inside   [4]'s "error not in
//     the Local port Field                                 Local port Field"
//                                                          negative
//   P1: both RailViewArea branches flipped to           forwards-shell's [1]
//     <ForwardsPage />                                    vault negative
//                                                          control, AND
//                                                          vault-shell's [1]
//                                                          "vault case renders
//                                                          <VaultPage />"
//                                                          positive (each
//                                                          script's own angle
//                                                          on the same file)
//   P2: SectionEmpty's headline ternary collapsed to    [6]'s ternary check
//     {nothingYet}
//   P3: the <SectionEmpty> call site's hasAny fed from  [7]
//     visibleRules.length > 0 instead of ruleRowList
//   P4: the caret effect's deps changed to [query]      [8]'s "empty array"
//                                                          check only
//   P5: the caret effect's deps argument dropped        [8]'s "present" check
//     entirely (bare useEffect(fn))                       (and, as a natural
//                                                          consequence, the
//                                                          "empty array" check
//                                                          too - deps is
//                                                          undefined, so
//                                                          neither can be true)
//   P6: pane: () => pageRef.current?.closest(           [8]'s exact-pin AND
//     "[data-pane-leaf]")                                  its closest(-scoped
//                                                          negative
//   P7: RuleCard.tsx's stopNote() calls replaced with   [10], all three checks
//     the two sentences inlined
//   P8: "securely" added to ForwardsPage.tsx's module   [9]'s safety-
//     header comment                                      comparison check
//   P9: RuleCard.tsx's hostDangling Badge hidden        [5]'s stripper
//     inside {/* ... */}                                   self-test - FIRST
//                                                          DRAFT anchored on
//                                                          "hostDangling" itself,
//                                                          which reads TWICE
//                                                          MORE in this file
//                                                          (startDisabled,
//                                                          toggleTooltip) and
//                                                          went GREEN over this;
//                                                          re-anchored on the
//                                                          badge's own unique
//                                                          text, "Host missing"
//   K1 (in hosts-header-narrow-verify.ts): the          the three-way equality,
//     forwards search InputGroup's @max-[420px]:           and the 400px/420px
//     basis-full dropped                                   width assertions
//   K2 (in hosts-header-narrow-verify.ts): the SAME     the equality stayed
//     search className on all three pages (hosts,          GREEN; the 480px
//     vault, forwards) - @[480px] moved to @[500px]         width assertion on
//                                                          all three FAILed
//   C1: startRule passes promptForHostKey: false        C1, both checks (the
//                                                          argument pin and the
//                                                          behavioural outcome)
//   C2: stopRule's close call names 0 instead of        C2's argument pin
//     rule.localPort
//   C3: stopRule's `if (claim !== undefined)` guard     C3's "zero close
//     removed                                              calls" check
//   C4: startRule records rule.localPort as boundPort   C4, the auto-port
//     instead of forward.localPort                        fixture
//   C5m: isCurrentAttempt reimplemented as               C7 ONLY (all three of
//     `?.status === "starting"` instead of Set identity   its checks) - C5 and
//                                                          C6 stayed green,
//                                                          exactly as the brief
//                                                          predicted: both
//                                                          interleavings have
//                                                          the row already
//                                                          "stopped" by the time
//                                                          the late resolve
//                                                          lands, so the buggy
//                                                          status check agrees
//                                                          with the correct one
//   C6m: the abandon(promptId) loop in stopRule dropped  C6's two abandon-
//                                                          related checks only
//   C7m: startRule's superseded-resolve guard's early    C7 (as predicted) AND
//     `return` removed - markRunning always runs           C5, C6 (broader than
//                                                          the brief's narrow
//                                                          claim - the guard is
//                                                          load-bearing for
//                                                          every superseded-
//                                                          resolve interleaving,
//                                                          not only C7's)
//   Y3: startRule's post-dial hostOwned check deleted    C10, all six of its
//     (the page's half of the two-sided yield)             checks; C10's paired
//                                                          control, which has the
//                                                          terminal's map empty,
//                                                          stayed green
//   Y4: confirmDelete's `await stopRule(target.rule)`     [11]'s ORDER check and
//     and `await deleteRule(target.rule.id)`               nothing else - both
//     statements swapped                                   calls are still
//                                                          present, still awaited
//                                                          and still one each,
//                                                          which is the asymmetry
//                                                          the section exists for
//   C8m: stopRule's try/finally replaced with a bare     NOTHING changed - all
//     sequence (close, then markStopped)                   114 checks stayed
//                                                          green, exactly as
//                                                          predicted:
//                                                          closeForwardForConnection's
//                                                          real chain ends in
//                                                          .catch(() => {}) and
//                                                          cannot reject, so the
//                                                          finally is not
//                                                          exercised by anything
//                                                          this harness can
//                                                          observe today
// ----------------------------------------------------------------------------
// Mutation table - FIX ROUND 4. Applied to a byte-identical copy of `src/` AND
// `scripts/` (both trees reset each time), with the ok-COUNT printed on every
// run rather than the exit code alone - a harness that silently stops asserting
// reports GREEN for everything. Baseline: fa 238 ok, fs 202 ok, fp 79 ok, both
// tsc projects and `prettier --check` green.
//
//   Id    Mutation                                       Result
//   ----  ---------------------------------------------  --------------------------
//   Z1    ForwardsPage.tsx: the delete guard restored    RED, fs 199/202 - the
//           to `if (target.running)`, the flag             exact-condition pin, the
//           captured at Delete-CLICK time                  captured-flag AST
//                                                          negative, and the
//                                                          pageMustStopFirst caller
//                                                          sweep. Plus tsc RED
//                                                          (TS6133, the now-unused
//                                                          import) - a second,
//                                                          accidental tripwire.
//   Z2    controller.ts: pageMustStopFirst rewritten to  RED, fs 192/202 - C11's two
//           `status === "running" && hostOwned` (the       `running` rows, C11's
//           runtime-false shape this round's own pin       keyed-by-rule check, and
//           was written for)                                every C12 and C13 check
//                                                          downstream of the guard.
//                                                          `tsc` and `prettier`
//                                                          stayed GREEN, which is
//                                                          why the pin had to be
//                                                          behavioural.
//   Z4a   runtime.ts: a new hook returning               RED (each, separately), fs
//    -d     ({ port, sid }) / (…, Object.keys(s.byRule))   205/202 - section 2's
//           / s.byRule[id] ?? {} /                         primitive-shape check for
//           new Set(Object.getOwnPropertyNames(…))         that selector, each with
//                                                          the refused shape NAMED.
//                                                          All four were GREEN under
//                                                          the deny-list this round
//                                                          replaced, each printing a
//                                                          fresh PASSING "primitive
//                                                          shape" assertion.
//   Z5    runtime.ts AND hostOwned.ts: a legal           GREEN, as predicted - the
//           selector's parameter renamed `s` -> `state`    control for the
//                                                          parameterisation.
//   Z5c   the same rename with the parameterised regex   RED, fa 235/238 and fs
//           reverted to a hardcoded `^s\.byRule`          199/202 - so the
//                                                          parameterisation is
//                                                          load-bearing rather than
//                                                          cosmetic: without it a
//                                                          rename reddens BOTH
//                                                          copies.
//   Z6    RuleEditorDialog.tsx: the guarded stop        RED, fs 193/202 - section
//           deleted from save                              12's stopRule count, the
//                                                          three-file caller SET and
//                                                          the pageMustStopFirst
//                                                          sweep. NOT caught by C13,
//                                                          which drives `stopRule`
//                                                          rather than the dialog -
//                                                          the editor's ORDER claim
//                                                          is AST, and this says so.
//   Z8    a legal Prettier reflow at --print-width 60   GREEN (all three scripts,
//           over all ten source files carrying a          both tsc projects). The
//           source-text or exact-node pin                 reflow is real: the
//                                                          autostart call site split
//                                                          across five lines and both
//                                                          new `if` guards split from
//                                                          their `await`. `prettier
//                                                          --check` reddens, which is
//                                                          the point - a reflow at a
//                                                          width the repo does not
//                                                          use is what makes it a
//                                                          reflow.
//
//   Round 5 - the `starting` arm, and the two families the AST pins could not see
//   ----  -------------------------------------------      ----------------------------
//   W1    controller.ts: pageMustStopFirst back to        RED, fs 219/228 - C11's
//           `=== "running"` only                            flipped `starting` row
//                                                          plus 8 of G1/G2. Nothing
//                                                          else in the suite saw it,
//                                                          which is why G1/G2 exist.
//   W2    the same predicate widened to include            RED, fs 227/228 - C11's
//           `"failed"` as well                              `failed` row. The two
//                                                          excluded statuses are a
//                                                          claim, not a leftover.
//   W3a   ForwardsPage.tsx: the guarded stop wrapped     RED, fs 227/228 - section
//           in `if (target.rule.id === "") { … }`           11's new unconditional
//                                                          assert, and ONLY that one.
//                                                          tsc green.
//   W3b   RuleEditorDialog.tsx: the same wrapper,        RED, fs 227/228 - section
//           `if (id === "") { … }`                          12's new one, and only it.
//   W5    forward-autostart-verify.ts: the twin           RED, fs 227/228 - the new
//           classifier's prefix-unary arm deleted           cross-script equality
//           (one copy only)                                 assert. `fa` ITSELF stayed
//                                                          GREEN at 242 with the
//                                                          tightened copy, which is
//                                                          the whole reason the assert
//                                                          is worth three lines.
//   W6a   RuleCard.tsx: `pageStops` narrowed back to      RED, fs 227/228 - section
//           `running` (the widening, dropped at its         11's new binding pin.
//           only definition)                                `forwards-page` stayed
//                                                          GREEN at 79 and `fa` at
//                                                          242: `deleteNote` is a pure
//                                                          function of an
//                                                          already-decided boolean, so
//                                                          no fixture over it can see
//                                                          the caller narrow.
//   W7    a legal Prettier reflow at --print-width 60   GREEN, 228/79/242/36 with
//           over all fifteen source files these four       tsc clean - the paired
//           scripts read                                    control, as predicted.
// ----------------------------------------------------------------------------

process.exit(failed === 0 ? 0 : 1);
