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

/**
 * Is `expr` a FORBIDDEN selector-body shape - an object/array literal, a
 * spread, or a call to `.map(`/`Object.keys(`/`Object.values(`/`Object.entries(`
 * - UNLESS the whole expression ends in `.length` (§1.6's exemption: building
 * an array INSIDE the selector is fine when the RETURNED value, compared by
 * `Object.is`, is the length - a primitive).
 */
function isForbiddenSelectorBody(
  expr: ts.Expression,
  sf: ts.SourceFile,
): { forbidden: boolean; reason?: string } {
  // The .length exemption applies to the WHOLE expression only - checked
  // before anything else, exactly once, against `expr` itself.
  if (ts.isPropertyAccessExpression(expr) && expr.name.text === "length") {
    return { forbidden: false };
  }
  if (ts.isObjectLiteralExpression(expr)) return { forbidden: true, reason: "object literal" };
  if (ts.isArrayLiteralExpression(expr)) return { forbidden: true, reason: "array literal" };
  if (ts.isSpreadElement(expr)) return { forbidden: true, reason: "spread" };

  // Walk the PRIMARY CHAIN - repeatedly unwrapping a CallExpression's own
  // callee through any PropertyAccessExpression in between - for a forbidden
  // call ANYWHERE in it, not only as the outermost call. Found by mutation Z4:
  // `Object.values(s.byRule).filter(...)` (no `.length`) is still forbidden,
  // but `.filter(` itself is not one of the four named forms - only checking
  // the OUTERMOST call's callee text (`Object.values(s.byRule).filter`)
  // missed the `Object.values(` sitting one level further down the chain, and
  // this mutation reddened nothing until the walk was added.
  let cur: ts.Node = expr;
  for (;;) {
    if (ts.isCallExpression(cur)) {
      const callee = cur.expression.getText(sf);
      if (
        /\.map$/.test(callee) ||
        callee === "Object.keys" ||
        callee === "Object.values" ||
        callee === "Object.entries"
      ) {
        return { forbidden: true, reason: `call to ${callee}(` };
      }
      cur = cur.expression;
      continue;
    }
    if (ts.isPropertyAccessExpression(cur)) {
      cur = cur.expression;
      continue;
    }
    break;
  }
  return { forbidden: false };
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
        const verdict = isForbiddenSelectorBody(body, sf);
        check(
          `${call.getText(sf)}'s selector body is a primitive shape` +
            (verdict.reason ? ` (not ${verdict.reason})` : ""),
          !verdict.forbidden,
          body.getText(sf),
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

console.log(
  failed === 0
    ? "\nAll forwards-shell sections 1-10 passed."
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

const { startRule, stopRule } = await import("../src/modules/forwards/controller");
type RuntimeDepsType = NonNullable<Parameters<typeof startRule>[1]>;
const { useForwardRuntime } = await import("../src/modules/forwards/runtime");
const { useHostKeyPrompt } = await import("../src/modules/ssh/hostKeyPrompt");

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

process.exit(failed === 0 ? 0 : 1);
