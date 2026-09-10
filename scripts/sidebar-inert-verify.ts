/**
 * Self-check for the tab order of a column that is shut but still mounted.
 * Run: `npx tsx scripts/sidebar-inert-verify.ts`.
 *
 * THE HAZARD. `react-resizable-panels` collapses a `collapsible` panel to its
 * `collapsedSize`, and a size is not an unmount: the children of a zero-width
 * panel are still in the document, so every focusable node inside a sidebar the
 * user has shut stays in sequential focus order. Tab from the sidebar toggle
 * walks into a file tree nobody can see. The answer is `inert` on the column
 * wrapper - one attribute that removes the whole subtree from focus order and
 * from hit-testing, with no unmount, so reopening does not pay to re-virtualize
 * the tree.
 *
 * THIS CHECK IS A PROXY, NOT AN OUTCOME PIN, and that is worth saying plainly
 * rather than leaving for a reader to work out. Nothing in this suite mounts a
 * component, so no check here can observe focus order at all. What is asserted
 * is that the mechanism is wired: the attribute is present, on the wrapper
 * rather than on a section body, and driven by the panel's own reported size.
 * A browser could still disagree with all three, which is why the outcome is
 * answered by hand - Tab out of the sidebar toggle with the sidebar shut and
 * confirm focus does not enter the tree - and only the wiring is answered here.
 *
 * TWO LAYERS THAT MUST NOT BE CONFLATED. `SectionStack` gives each section its
 * own `collapsed` flag, which collapses that section to its own header while
 * the column around it is fully on screen. This file is about the layer one
 * step out: the whole column being gone. A fix keyed off the section flag would
 * make a visible column's sections unreachable and leave the actual defect in
 * place, so the panel-level binding is asserted to be neither that parameter
 * nor a constant.
 *
 * THE COLUMNS ARE DISCOVERED, NOT LISTED. The wrappers are found by walking
 * `src/` for a `data-section-column` JSX attribute rather than by naming two
 * files, so a third column cannot arrive unseen; and the requirement is applied
 * per column against that column's own panel, so it is the `collapsible` panel
 * that owes an `inert` and not whichever file happens to be named here. Both
 * columns' discriminator is pinned by value: the left panel IS collapsible and
 * the right one is NOT, so either changing reddens and gets re-decided instead
 * of silently moving a column into or out of the requirement.
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

import ts from "typescript";

import { parseSource } from "./lib/ast";

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

// ---------------------------------------------------------------------------
// AST helpers
// ---------------------------------------------------------------------------

type Open = ts.JsxOpeningElement | ts.JsxSelfClosingElement;

function walk(root: ts.Node, visit: (n: ts.Node) => void): void {
  visit(root);
  ts.forEachChild(root, (c) => {
    walk(c, visit);
  });
}

const asOpen = (n: ts.Node): Open | null =>
  ts.isJsxOpeningElement(n) || ts.isJsxSelfClosingElement(n) ? n : null;

function attributeOf(open: Open, name: string): ts.JsxAttribute | null {
  for (const p of open.attributes.properties) {
    if (ts.isJsxAttribute(p) && ts.isIdentifier(p.name) && p.name.text === name) return p;
  }
  return null;
}

/** The expression inside `name={...}`. Null for an absent attribute, for the
 *  valueless boolean form (`collapsible`) and for a plain string value. */
function attributeExpression(open: Open, name: string): ts.Expression | null {
  const init = attributeOf(open, name)?.initializer;
  if (!init || !ts.isJsxExpression(init)) return null;
  return init.expression ?? null;
}

/** The literal text of `name="..."`, or null. */
function attributeString(open: Open, name: string): string | null {
  const init = attributeOf(open, name)?.initializer;
  return init && ts.isStringLiteral(init) ? init.text : null;
}

/** The nearest enclosing `<tag ...>` opening element, or null. */
function enclosingElement(node: ts.Node, tag: string): Open | null {
  for (let p: ts.Node | undefined = node.parent; p; p = p.parent) {
    if (!ts.isJsxElement(p)) continue;
    if (p.openingElement.tagName.getText() === tag) return p.openingElement;
  }
  return null;
}

/** Identifiers an expression reads. `a.b` names `a`; `{ x: 1 }` names neither. */
function identifiersIn(root: ts.Node): Set<string> {
  const out = new Set<string>();
  walk(root, (n) => {
    if (!ts.isIdentifier(n)) return;
    const p: ts.Node | undefined = n.parent;
    if (p && ts.isPropertyAccessExpression(p) && p.name === n) return;
    if (p && ts.isPropertyAssignment(p) && p.name === n) return;
    out.add(n.text);
  });
  return out;
}

/**
 * The setter paired with `name` by a `const [name, setter] = useState(...)`.
 *
 * Asked as a pairing rather than as "is there a `useState` in this file",
 * because the property is that the attribute reads STATE THAT SOMETHING
 * WRITES. A `const panelCollapsed = false` beside an unrelated `useState`
 * satisfies the weaker form and leaves the attribute frozen.
 */
function stateSetterFor(sf: ts.SourceFile, name: string): string | null {
  let found: string | null = null;
  walk(sf, (n) => {
    if (!ts.isVariableDeclaration(n) || !n.initializer) return;
    if (!ts.isCallExpression(n.initializer)) return;
    if (n.initializer.expression.getText() !== "useState") return;
    const bind = n.name;
    if (!ts.isArrayBindingPattern(bind) || bind.elements.length !== 2) return;
    const [value, setter] = bind.elements;
    if (!ts.isBindingElement(value) || !ts.isBindingElement(setter)) return;
    if (!ts.isIdentifier(value.name) || !ts.isIdentifier(setter.name)) return;
    if (value.name.text === name) found = setter.name.text;
  });
  return found;
}

/** The parameter names of the first `const <name> = (...) => ...` in a file. */
function arrowParameterNames(sf: ts.SourceFile, name: string): string[] {
  let out: string[] = [];
  walk(sf, (n) => {
    if (!ts.isVariableDeclaration(n) || !ts.isIdentifier(n.name) || n.name.text !== name) return;
    const init = n.initializer;
    if (!init || !ts.isArrowFunction(init)) return;
    out = init.parameters.map((p) => p.name.getText());
  });
  return out;
}

// ---------------------------------------------------------------------------
// The columns, discovered
// ---------------------------------------------------------------------------

const SKIP_DIRS = new Set(["node_modules", "dist", "build"]);
function everyFile(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      if (!SKIP_DIRS.has(entry)) everyFile(full, out);
      continue;
    }
    if (/\.tsx?$/.test(entry)) out.push(relative(repoRoot, full).split("\\").join("/"));
  }
  return out;
}

const COLUMN_ATTR = "data-section-column";

type Column = { rel: string; sf: ts.SourceFile; wrapper: Open; side: string };

const columns: Column[] = [];
for (const rel of everyFile(join(repoRoot, "src"))) {
  const src = read(rel);
  // Cheap gate before parsing. `SectionStack.tsx` matches the text (it holds
  // the `querySelector` that finds the OTHER column) and contributes no
  // wrapper, which is exactly why the enumeration is over JSX attributes and
  // not over occurrences of the string.
  if (!src.includes(COLUMN_ATTR)) continue;
  const sf = parseSource(rel, src);
  walk(sf, (n) => {
    const open = asOpen(n);
    if (!open) return;
    const side = attributeString(open, COLUMN_ATTR);
    if (side === null) return;
    columns.push({ rel, sf, wrapper: open, side });
  });
}

console.log(`[columns] the wrappers, found by walking src/ for a ${COLUMN_ATTR} attribute`);
check(
  "exactly two section columns exist",
  columns.length === 2,
  columns.map((c) => `${c.rel}:${c.side}`),
);
check(
  "and they are the left and the right one",
  columns
    .map((c) => c.side)
    .sort()
    .join(",") === "left,right",
  columns.map((c) => c.side),
);

// ---------------------------------------------------------------------------
// Per column: does its panel create the hazard, and if so is it answered?
// ---------------------------------------------------------------------------

/** Measured state, pinned so a change to either column is re-decided rather
 *  than silently moving that column into or out of the `inert` requirement. */
const COLLAPSIBLE_BY_SIDE: Record<string, boolean> = { left: true, right: false };

for (const column of columns) {
  const { rel, sf, wrapper, side } = column;
  console.log(`\n[${side}] ${rel}`);

  const panel = enclosingElement(wrapper, "ResizablePanel");
  check("the wrapper sits inside a ResizablePanel", panel !== null);
  if (!panel) continue;

  const collapsible = attributeOf(panel, "collapsible") !== null;
  check(
    `its panel is ${COLLAPSIBLE_BY_SIDE[side] ? "collapsible" : "NOT collapsible"}, as measured`,
    collapsible === COLLAPSIBLE_BY_SIDE[side],
    { collapsible },
  );

  if (!collapsible) {
    // Nothing to answer: a panel that cannot collapse cannot hold a mounted
    // subtree at zero width, so this column owes no `inert`. The pin above is
    // what makes that conditional honest - the moment this panel gains
    // `collapsible`, the branch below applies to it too.
    check(
      "...so this column cannot hold a mounted zero-width subtree and owes no inert",
      attributeExpression(panel, "collapsedSize") === null,
      panel.getText(),
    );
    continue;
  }

  const collapsedSize = attributeExpression(panel, "collapsedSize");
  check(
    "...to a collapsedSize of 0, which is a size and not an unmount",
    collapsedSize !== null && ts.isNumericLiteral(collapsedSize) && collapsedSize.text === "0",
    collapsedSize?.getText() ?? "(absent)",
  );

  const inert = attributeOf(wrapper, "inert");
  check("the wrapper carries `inert`", inert !== null);

  const inertExpr = attributeExpression(wrapper, "inert");
  // `inert` / `inert={true}` / `inert={false}` all type-check and all switch
  // the fix off in one direction or the other: always-on makes a visible
  // sidebar unusable, always-off is the defect back.
  check(
    "...as an expression rather than a constant",
    inertExpr !== null &&
      inertExpr.kind !== ts.SyntaxKind.TrueKeyword &&
      inertExpr.kind !== ts.SyntaxKind.FalseKeyword,
    inert?.getText() ?? "(absent)",
  );
  if (!inertExpr) continue;

  const names = [...identifiersIn(inertExpr)];
  check("...reading exactly one name", names.length === 1, names);
  const bound = names[0] ?? "";

  const setter = stateSetterFor(sf, bound);
  check(
    `...which is \`useState\` state with a paired setter (\`${bound}\`)`,
    setter !== null,
    setter ?? "(no `const [x, setX] = useState(...)` for it)",
  );

  // THE LAYER CHECK. `renderBuiltin`'s third parameter is the per-SECTION
  // collapsed flag - a section shrunk to its own header inside a column that is
  // fully on screen. Keying the wrapper off that would inert a visible column's
  // sections and leave a shut column in the tab order, which is the defect
  // plus a second one.
  // Indexed rather than `.at(-1)`: the same answer without depending on how
  // high the `lib` level of whichever tsconfig compiles this file happens to be.
  const sectionParams = arrowParameterNames(sf, "renderBuiltin");
  // ASSERTED, NOT ASSUMED, and that is the whole point of this line.
  // `arrowParameterNames` matches only `const renderBuiltin = (...) => ...`.
  // Rename that binding, or convert it to a `function` declaration, and it
  // returns `[]` - and a bare `if (flag !== undefined)` would then SKIP the
  // layer check silently, with no FAIL and no output, taking this file's stated
  // reason for existing with it. A check that can stop existing without saying
  // so is the vacuity class this suite refuses elsewhere: the same file already
  // asserts its column discovery found exactly two rather than trusting it.
  check(
    "found renderBuiltin's parameter list, so the layer check below runs",
    sectionParams.length > 0,
    sectionParams,
  );
  const sectionFlag: string | undefined = sectionParams[sectionParams.length - 1];
  if (sectionFlag !== undefined) {
    check(
      `...and NOT the per-section flag \`renderBuiltin\` takes (\`${sectionFlag}\`)`,
      bound !== sectionFlag,
      { bound, sectionFlag },
    );
  }

  const onResize = attributeExpression(panel, "onResize");
  check("the panel reports its own size back through onResize", onResize !== null);
  if (!onResize || !setter) continue;
  check(
    `...calling \`${setter}\` from it`,
    identifiersIn(onResize).has(setter),
    onResize.getText(),
  );
  // `onResize={() => setPanelCollapsed(false)}` satisfies every check above
  // and freezes the attribute. The size has to be the input: the handler takes
  // a parameter and the value it writes reads that parameter.
  const sizeParam =
    ts.isArrowFunction(onResize) && onResize.parameters.length > 0
      ? onResize.parameters[0].name.getText()
      : null;
  check("...and deciding from the size it is handed, not from a literal", sizeParam !== null, {
    onResize: onResize.getText(),
  });
  if (sizeParam === null) continue;
  const setterCall = (() => {
    let call: ts.CallExpression | null = null;
    walk(onResize, (n) => {
      if (ts.isCallExpression(n) && n.expression.getText() === setter) call = n;
    });
    return call as ts.CallExpression | null;
  })();
  check(
    `...where the argument to \`${setter}\` reads \`${sizeParam}\``,
    setterCall !== null &&
      setterCall.arguments.length === 1 &&
      identifiersIn(setterCall.arguments[0]).has(sizeParam),
    setterCall?.getText() ?? "(no call found)",
  );

  const sectionStack = (() => {
    let found = false;
    walk(sf, (n) => {
      const open = asOpen(n);
      if (!open || open.tagName.getText() !== "SectionStack") return;
      if (open.getStart() >= wrapper.getStart() && open.end <= wrapper.parent.end) found = true;
    });
    return found;
  })();
  check("and the wrapper is the element the whole SectionStack renders inside", sectionStack);
}

console.log(failed === 0 ? "\nALL PASS" : `\n${failed} FAILED`);
process.exit(failed === 0 ? 0 : 1);
