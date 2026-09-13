/**
 * Compiler-API helpers shared by the `*-verify.ts` suite.
 *
 * Every function here answers a question about a parsed source file that a
 * regex over its text cannot: which function body a call sits in, whether
 * anything decides that a statement runs, what a module imports. The scripts
 * that need them build their own `ts.SourceFile` and pass it in — nothing here
 * reads a file or builds a `ts.Program`, so nothing here can resolve a type.
 * Where a helper guesses lexically instead, its own doc comment says so.
 */
import ts from "typescript";

/**
 * Source with ALL whitespace removed and any comma sitting immediately before a
 * closing bracket dropped.
 *
 * Whitespace AND trailing commas are Prettier's; everything else is the claim.
 * The comma half is the one that is easy to miss: a legal multi-line reformat
 * under this repo's config adds a comma after the last argument that plain
 * whitespace-collapsing does not remove, so a pin over unchanged code goes red
 * on a reformat alone — a landmine rather than a check.
 */
export const norm = (s: string): string => s.replace(/\s+/g, "").replace(/,+([)\]}])/g, "$1");

/**
 * Walking up from `node`, is every ancestor up to (and including reaching)
 * `fnBody` free of crossing into a NESTED function?
 *
 * Used to tell a direct statement of a function's own body from a call buried
 * inside a decoy arrow declared in the same scope — a count alone cannot bite
 * that deletion. This refuses NESTING and nothing else: see
 * {@link isUnguardedToItsFunctionBody} for the different question of whether
 * anything DECIDES that the statement runs.
 */
export function isDirectlyInFunctionBody(node: ts.Node, fnBody: ts.Node): boolean {
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

/**
 * Walking out from `stmt`, does anything DECIDE whether it runs before the
 * enclosing function's own body is reached?
 *
 * `true` only when every step out is unconditional, which the code reads
 * strictly: the parent must be a `ts.Block` whose owner is either the function
 * itself or a `try` whose own `tryBlock` this is. An `if`, `switch`, loop or
 * `catch` anywhere on that path answers `false` — and so does a bare nested
 * block, whose owner matches neither arm. That last case is stricter than it
 * needs to be and is left that way deliberately: it fails CLOSED, refusing a
 * reachable statement rather than passing an unreachable one.
 *
 * Self-terminating on the nearest function so no caller has to hand it a body,
 * because a guarded stop can sit inside an async IIFE rather than inside the
 * factory that returns it.
 *
 * WHY IT IS NEEDED BESIDE {@link isDirectlyInFunctionBody}: that one refuses
 * nesting inside another function and nothing else, and neither a count, an
 * index order, an awaited parent nor an exact-condition pin can see a wrapper.
 * Measured: wrapping a guarded stop in `if (id === "") { … }` left every
 * script, `tsc --noEmit` and `prettier --check` green with the stop
 * unreachable, because the count stayed 1, the index order held, the awaited
 * parent held, and a walk to the NEAREST `if` still matched the inner one.
 *
 * NECESSARY, NOT SUFFICIENT. Three ways to kill the same statement survive
 * this walk, and a caller must not read a `true` as "this runs":
 *
 *   1. The enclosing function is never called at all — the call site deleted,
 *      the prop dropped, the handler renamed. Nothing here looks outward.
 *   2. A preceding statement that never completes (`while (true) {}`, an
 *      awaited promise that never settles) or that exits through a helper
 *      (`assertNever(x)`), neither of which is syntactically `return`/`throw`.
 *   3. A preceding statement in an ancestor block above the one this walk
 *      started in, on a path this function does not enumerate.
 *
 * What it DOES cover beyond the walk itself: an unconditional `return` or
 * `throw` among the preceding siblings of any statement on the path. Either
 * leaves the guarded stop dead with every step out still unconditional, so the
 * walk alone would answer `true` over code that cannot run.
 */
export function isUnguardedToItsFunctionBody(stmt: ts.Statement): boolean {
  let cur: ts.Node = stmt;
  for (;;) {
    const block: ts.Node | undefined = cur.parent;
    // Not a block at all means a braceless `if (x) <stmt>` / `for (…) <stmt>`,
    // which is a guard written without the braces.
    if (block === undefined || !ts.isBlock(block)) return false;
    // An unconditional exit ABOVE `cur` in this block kills everything after
    // it. The walk out is about what decides that `cur` runs; this is about
    // whether control ever reaches it in the first place, and both have to hold.
    for (const sibling of block.statements) {
      if (sibling === cur) break;
      if (ts.isReturnStatement(sibling) || ts.isThrowStatement(sibling)) return false;
    }
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

/**
 * Every module specifier `sf` pulls in, sorted, deduplicated.
 *
 * All three resolving forms, because the property these pins hold is that a
 * module does not REACH a forbidden dependency, and each of the three reaches
 * it: a static `import`, a re-`export ... from`, and a dynamic `import()`.
 * The dynamic form is the one an enumeration of quoted needles misses and the
 * one that still resolves and executes.
 *
 * Type-only imports are included. A caller pinning an exact set over a file
 * whose imports are all `import type` is pinning type-only specifiers, and a
 * value import added beside them changes the set, which is the point.
 */
export function importSpecifiersOf(sf: ts.SourceFile): string[] {
  const out = new Set<string>();
  const visit = (n: ts.Node): void => {
    if (
      (ts.isImportDeclaration(n) || ts.isExportDeclaration(n)) &&
      n.moduleSpecifier !== undefined &&
      ts.isStringLiteral(n.moduleSpecifier)
    ) {
      out.add(n.moduleSpecifier.text);
    } else if (
      ts.isCallExpression(n) &&
      n.expression.kind === ts.SyntaxKind.ImportKeyword &&
      n.arguments.length > 0 &&
      ts.isStringLiteral(n.arguments[0])
    ) {
      out.add(n.arguments[0].text);
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return [...out].sort();
}

/**
 * `src` parsed, with the script kind taken from `rel`'s extension.
 *
 * The kind is not cosmetic and defaulting it to TSX is a live bug: under TSX a
 * `.ts` file's `<T>(x: T) => x` is read as a JSX element, the parse recovers
 * somewhere unhelpful, and a walk over the result answers about a tree the file
 * does not have. Measured - a call pin over a `.ts` store went red under TSX
 * and green under TS, over identical source.
 */
export function parseSource(rel: string, src: string): ts.SourceFile {
  return ts.createSourceFile(
    rel,
    src,
    ts.ScriptTarget.ESNext,
    true,
    rel.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS,
  );
}

/**
 * The names imported from `specifier` in `src`, and whether the clause brings
 * in types only. `null` when the module is not imported at all.
 *
 * The shape a POSITIVE check over raw source cannot have: a regex like
 * `/from "@\/lib\/searchTiers"/.test(src)` is satisfied by a sentence in the
 * file's own docblock explaining why it used to import that module, so the
 * check passes over the deletion it exists to catch. An import declaration read
 * AS a declaration cannot be spelled in a comment. (The NEGATIVE half of such a
 * pair is safe over raw text - prose reddens it, which costs a round rather
 * than a defect - so only the positives need this.)
 *
 * Both spellings of type-only count: `import type { A }` on the clause and
 * `import { type A }` per element say the same thing about whether a value
 * crosses the boundary, and a check that knows only one is about syntax.
 */
export function namedImportsFrom(
  rel: string,
  src: string,
  specifier: string,
): { names: string[]; typeOnly: boolean } | null {
  const sf = parseSource(rel, src);
  for (const st of sf.statements) {
    if (!ts.isImportDeclaration(st) || !ts.isStringLiteral(st.moduleSpecifier)) continue;
    if (st.moduleSpecifier.text !== specifier) continue;
    const bindings = st.importClause?.namedBindings;
    const named = bindings !== undefined && ts.isNamedImports(bindings) ? bindings.elements : [];
    return {
      names: named.map((e) => e.name.text).sort(),
      typeOnly:
        st.importClause?.isTypeOnly === true ||
        (named.length > 0 && named.every((e) => e.isTypeOnly)),
    };
  }
  return null;
}

/**
 * Does `src` CALL `name` - as a call expression, not as text?
 *
 * `src.includes("hostsUsingIdentity(")` is true of a comment that names the
 * call, including the comment somebody leaves behind when they inline it. A
 * method call of the same name counts, because the claim these callers make is
 * that the work is delegated rather than re-derived, and `x.foo()` delegates
 * exactly as much as `foo()`.
 */
export function callsFunction(rel: string, src: string, name: string): boolean {
  const sf = parseSource(rel, src);
  let found = false;
  const visit = (n: ts.Node): void => {
    if (found) return;
    if (ts.isCallExpression(n)) {
      const callee = n.expression;
      if (ts.isIdentifier(callee) && callee.text === name) found = true;
      else if (ts.isPropertyAccessExpression(callee) && callee.name.text === name) found = true;
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return found;
}

/**
 * Does `expr` reach `name`, following local variable initialisers?
 *
 * The direct question - "does this condition mention `authMode`" - is answered
 * by any substring scan and is defeated by one line of indirection:
 *
 *   const showPassword = draft.authMode === "password";
 *   {showPassword && <Field label="Password">…}
 *
 * The condition names `showPassword` and nothing else, so a check that reads
 * the condition alone says the field is unconditional while it is hidden in two
 * of three modes. This resolves every identifier in `expr` against the
 * declarations in `sf` and recurses into their initialisers, so the indirection
 * has to be laundered through something this cannot follow - a function call, a
 * prop, another module - before it hides again.
 *
 * `seen` breaks the cycle a self-referential or mutually-referential
 * declaration would otherwise spin on. LEXICAL, not scope-aware: a declaration
 * anywhere in the file answers for an identifier of that name anywhere else,
 * which over-reaches rather than under-reaches - it can only make a condition
 * look MORE dependent than it is, which fails closed.
 */
export function expressionReachesName(
  expr: ts.Node,
  name: string,
  sf: ts.SourceFile,
  seen: Set<string> = new Set(),
): boolean {
  let found = false;
  const visit = (n: ts.Node): void => {
    if (found) return;
    if (ts.isIdentifier(n)) {
      if (n.text === name) {
        found = true;
        return;
      }
      if (!seen.has(n.text)) {
        seen.add(n.text);
        const init = findVariableInitializer(sf, n.text);
        if (init !== null && expressionReachesName(init, name, sf, seen)) {
          found = true;
          return;
        }
      }
    }
    ts.forEachChild(n, visit);
  };
  visit(expr);
  return found;
}

/** The initialiser of the first `const`/`let` named `name` anywhere in `sf`. */
function findVariableInitializer(sf: ts.SourceFile, name: string): ts.Expression | null {
  let result: ts.Expression | null = null;
  const visit = (n: ts.Node): void => {
    if (
      result === null &&
      ts.isVariableDeclaration(n) &&
      ts.isIdentifier(n.name) &&
      n.name.text === name &&
      n.initializer !== undefined
    ) {
      result = n.initializer;
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return result;
}

/** The nearest enclosing function-like declaration's name, or `""`. */
export function enclosingFunctionName(node: ts.Node, sf: ts.SourceFile): string {
  let cur: ts.Node | undefined = node.parent;
  while (cur) {
    if (ts.isFunctionDeclaration(cur)) return cur.name?.text ?? "";
    if (ts.isArrowFunction(cur) || ts.isFunctionExpression(cur)) {
      const decl = cur.parent;
      if (ts.isVariableDeclaration(decl) && ts.isIdentifier(decl.name)) return decl.name.text;
      return cur.name?.getText(sf) ?? "";
    }
    if (ts.isMethodDeclaration(cur)) return cur.name.getText(sf);
    cur = cur.parent;
  }
  return "";
}

/**
 * The selector arrow's own parameter name, whitespace-normalised, or `""` when
 * it has none.
 *
 * What {@link primitiveSelectorBody}'s access-chain arm is ROOTED ON: the
 * letter `s` is this codebase's habit and not the claim, and a check that
 * reddens when somebody writes `(state) => state.byRule[id]?.status` is a check
 * the next reader weakens rather than reads.
 */
export function selectorParamName(arrow: ts.ArrowFunction, sf: ts.SourceFile): string {
  const p = arrow.parameters[0];
  return p ? norm(p.name.getText(sf)) : "";
}

/**
 * Can this selector body only ever yield a PRIMITIVE? Returns the REASON as
 * well as the verdict, so a failure names the shape it refused instead of only
 * echoing the text.
 *
 * AN ALLOW-LIST, AND THE POLARITY MATTERS. This replaced a four-name deny-list
 * (object literal, array literal, spread, and a call to
 * `.map`/`Object.keys`/`Object.values`/`Object.entries`). Measured against four
 * fresh-reference selectors, each of which came back GREEN under the deny-list
 * with a fresh PASSING assertion calling it "a primitive shape":
 *
 *   (s) => ({ port: …, sid: … })
 *   (s) => (s.byRule[id]?.status ?? "x", Object.keys(s.byRule))
 *   (s) => s.byRule[ruleId] ?? {}
 *   (s) => new Set(Object.getOwnPropertyNames(s.byRule))
 *
 * Two of the deny-list's four names could never fire at all — an object-literal
 * arrow body must be parenthesised, so the node here is a
 * `ParenthesizedExpression`, and `(s) => ...x` is a syntax error, so a
 * `SpreadElement` cannot occupy this position. The set of ways to build a fresh
 * reference is OPEN while the set of shapes that can only yield a primitive is
 * small and CLOSED. Hence: anything not named below is guilty until argued,
 * INCLUDING EVERY CALL EXPRESSION.
 */
export function primitiveSelectorBody(
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
    // description of a LEXICAL guess. No `ts.Program` is built here, so there is
    // no checker that could tell `array.length` from a user-defined field named
    // `length` holding an object. What makes the guess sound for the stores it
    // is applied to: an entry is a status string plus numbers, `byRule` is a
    // plain `Record`, and a `.length`/`.size` written against either is a TS
    // error rather than a selector this arm waves through. Kept as a comment
    // rather than tightened - the tightening that would close it is a type
    // lookup, and refusing the two names outright would refuse the one real
    // selector that builds a collection inside itself.
    if (
      ts.isPropertyAccessExpression(cur) &&
      (cur.name.text === "length" || cur.name.text === "size")
    ) {
      return { ok: true };
    }
    // Otherwise the chain has to reach PAST the entry, to one of its own
    // fields. `<param>.byRule` is the whole map and `<param>.byRule[id]` is the
    // whole entry; both are objects the actions rebuild, so neither is ever
    // `Object.is` its own last return.
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
