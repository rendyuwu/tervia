/**
 * Self-check that `RdpSizeMode`'s membership and the sites writing it agree.
 * Run: `npx tsx scripts/rdp-size-mode-verify.ts`.
 *
 * WHAT REDDENS. The membership of the union and the set of literals actually
 * written have to be the same set. A member nothing writes is a mode the user
 * can never end up in: the picker offers it, every save path rewrites it to
 * something else, and nothing raises. `tsc` does not catch that, because a
 * narrower literal stays assignable to the wider union, so every site that
 * hardcodes one keeps compiling. This file is the thing that notices.
 *
 * It has already fired once for its intended reason: `"fit"` was added to the
 * union and this check named the sites that had to be revisited.
 *
 * The sites are DISCOVERED by walking `src/` rather than listed, so a new one
 * cannot arrive unseen; the pinned table below then has to account for what the
 * walk found. Fixtures under `scripts/` are out of scope on purpose: a fixture
 * naming an existing member stays valid when the union widens, so reddening
 * every one of them would be a dozen edits with nothing on the other side.
 *
 * WHAT THE WALK SEES. A property assigned a string literal, a `const`
 * declaration of one, a `??` whose right side is one, and BOTH ARMS of a
 * conditional. The arms are followed because a conditional is the shape both
 * write sites have today - each picks between `"fit"` and `"preset"` - and a
 * walk that stopped at them would find nothing at all and report the trip-wire
 * as broken rather than as passing.
 *
 * Two shapes still pass unseen, and both were measured by adding a site in that
 * shape and watching the count: a literal reached through a local binding
 * (`const m = "fit"` then `sizeMode: m`), and an assertion (`sizeMode: "fit" as
 * RdpSizeMode`). Following those would mean an indirection walk and an unwrap,
 * for shapes nothing in the tree uses.
 *
 * They are left unmatched because the cost of missing one is bounded, and the
 * bound was measured too: widening the union with the new member written ONLY
 * through an unseen shape still reddens, because the trip-wire compares the
 * union's membership against the literals found and an unseen write contributes
 * nothing to the second set. So a blind spot costs the COMPLETENESS OF THE SITE
 * LIST in the failure message, never the failure itself, and it fails towards
 * reporting one site too few rather than towards going green.
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

const FIELD = "sizeMode";
const UNION = "RdpSizeMode";

function walk(root: ts.Node, visit: (n: ts.Node) => void): void {
  visit(root);
  ts.forEachChild(root, (c) => {
    walk(c, visit);
  });
}

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
const SRC_FILES = everyFile(join(repoRoot, "src"));

// ---------------------------------------------------------------------------
// 1. The union's membership, read off the type alias
// ---------------------------------------------------------------------------

console.log(`[union] ${UNION}'s members`);

/** The string-literal members of a `type X = "a" | "b"` alias. Null when the
 *  alias is missing or is not built out of string literals, which is itself a
 *  finding: this whole check assumes the union is enumerable. */
function unionMembers(rel: string, name: string): string[] | null {
  const sf = parseSource(rel, read(rel));
  let out: string[] | null = null;
  walk(sf, (n) => {
    if (!ts.isTypeAliasDeclaration(n) || n.name.text !== name) return;
    const node = n.type;
    const arms = ts.isUnionTypeNode(node) ? [...node.types] : [node];
    const members: string[] = [];
    for (const arm of arms) {
      if (!ts.isLiteralTypeNode(arm) || !ts.isStringLiteral(arm.literal)) return;
      members.push(arm.literal.text);
    }
    out = members.sort();
  });
  return out;
}

const members = unionMembers("src/modules/hosts/types.ts", UNION);
check(`${UNION} is a union of string literals`, members !== null, members ?? "(not found)");
check(
  `...and its membership is exactly ["fit","preset"]`,
  members !== null && [...members].sort().join(",") === "fit,preset",
  members ?? "(not found)",
);

// ---------------------------------------------------------------------------
// 2. The write sites, discovered
// ---------------------------------------------------------------------------

type Kind = "unconditional" | "default" | "conditional";
type Site = { rel: string; kind: Kind; literals: string[]; text: string };

/**
 * The string literals an initializer can produce, and the shape that produced
 * them: a conditional contributes BOTH arms, a `??` its right side, anything
 * else nothing. The outermost shape names the site.
 */
function shapeOf(expr: ts.Expression): { kind: Kind; literals: string[] } | null {
  if (ts.isStringLiteral(expr)) return { kind: "unconditional", literals: [expr.text] };
  if (ts.isConditionalExpression(expr)) {
    const arms = [expr.whenTrue, expr.whenFalse].flatMap((arm) => shapeOf(arm)?.literals ?? []);
    return arms.length > 0 ? { kind: "conditional", literals: arms } : null;
  }
  if (
    ts.isBinaryExpression(expr) &&
    expr.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken
  ) {
    const right = shapeOf(expr.right);
    return right ? { kind: "default", literals: right.literals } : null;
  }
  return null;
}

const sites: Site[] = [];
for (const rel of SRC_FILES) {
  const src = read(rel);
  if (!src.includes(FIELD)) continue;
  const sf = parseSource(rel, src);
  walk(sf, (n) => {
    // `{ sizeMode: <expr> }`. A property SIGNATURE (`sizeMode: RdpSizeMode;` in
    // a type) is a different node kind and is not a write, so it is not matched.
    if (ts.isPropertyAssignment(n) && ts.isIdentifier(n.name) && n.name.text === FIELD) {
      const shape = shapeOf(n.initializer);
      if (shape) sites.push({ rel, ...shape, text: n.getText() });
      return;
    }
    // `const sizeMode: RdpSizeMode = <expr>` - the same write through a binding
    // instead of straight into the object.
    if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.name.text === FIELD) {
      const shape = n.initializer ? shapeOf(n.initializer) : null;
      if (shape) sites.push({ rel, ...shape, text: n.getText() });
    }
  });
}

/**
 * The measured state, and the question each site owes when the union widens.
 * Pinned by file and kind so the walk above has to account for what it found:
 * a new write site reddens here and gets classified, instead of joining a
 * silent majority.
 */
const EXPECTED: Array<{ rel: string; kind: Kind; owes: string }> = [
  {
    rel: "src/modules/hosts/HostEditorDialog.tsx",
    kind: "conditional",
    owes: "the editor save path mints a row and must write the mode that was chosen",
  },
  {
    rel: "src/modules/backup/file.ts",
    kind: "conditional",
    owes: "the import path resolves an unrecognised mode to one this build can render; decide where a third mode should land",
  },
];

console.log(`\n[write sites] every literal written into \`${FIELD}\` under src/`);
check("the walk found write sites at all", sites.length > 0, sites.length);
check(
  `found exactly ${EXPECTED.length} of them`,
  sites.length === EXPECTED.length,
  sites.map((s) => `${s.rel} (${s.kind})`),
);
const found = sites.map((s) => `${s.rel}#${s.kind}`).sort();
const wanted = EXPECTED.map((e) => `${e.rel}#${e.kind}`).sort();
check(
  "...and they are the sites this check accounts for, each with its own question",
  found.join("|") === wanted.join("|"),
  { found, wanted },
);
for (const site of sites) {
  const entry = EXPECTED.find((e) => e.rel === site.rel);
  check(`  ${site.rel}: ${entry?.owes ?? "(unaccounted for)"}`, entry !== undefined);
}

// ---------------------------------------------------------------------------
// 3. Agreement: the trip-wire
// ---------------------------------------------------------------------------

console.log("\n[agreement] the union's membership and the literals written are one set");
const written = [...new Set(sites.flatMap((s) => s.literals))].sort();
check(
  "every literal written is a member of the union",
  members !== null && written.every((w) => members.includes(w)),
  { written, members },
);
check(
  `every member of the union is written somewhere - widening ${UNION} reddens HERE, and the sites above are the ones to revisit`,
  members !== null && members.every((m) => written.includes(m)),
  { members, written, sites: EXPECTED.map((e) => `${e.rel}: ${e.owes}`) },
);

console.log(failed === 0 ? "\nALL PASS" : `\n${failed} FAILED`);
process.exit(failed === 0 ? 0 : 1);
