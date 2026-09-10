/**
 * Self-check that `RdpSizeMode`'s membership and the sites writing it agree.
 * Run: `npx tsx scripts/rdp-size-mode-verify.ts`.
 *
 * NOTHING IS BROKEN TODAY. `RdpSizeMode` has one member, `"preset"`, and every
 * site writes it, which is consistent. This file exists because of what happens
 * on the day a second member is added: `"preset"` stays assignable to the wider
 * union, so every site that hardcodes it keeps compiling, and a mode the user
 * picked would be silently rewritten to `"preset"` on the next save, import or
 * restore. The union feels guarded and is not.
 *
 * `tsc` HELPS IN EXACTLY ONE PLACE, WHICH IS WORSE THAN NONE. `workspaces/store.ts`
 * types the persisted field as the LITERAL `"preset"` rather than as
 * `RdpSizeMode`, so widening the union does produce one type error, where
 * `serialize.ts` assigns a live leaf's mode into that saved shape. One error out
 * of five sites reads as "the compiler has this covered". It does not, and the
 * arm it covers is the persistence hop rather than any of the writes. That
 * asymmetry is pinned below so this check does not claim credit for it.
 *
 * WHAT REDDENS. The membership of the union and the set of literals actually
 * written have to be the same set. Adding `"fit"` to the type breaks that
 * equality on the day it is added rather than on the day a user notices their
 * choice did not stick - and the failure hands over the list of sites with the
 * question each one owes, because the question is not the same at each:
 *
 *   - the editor save path mints a fresh row and has to write what was chosen;
 *   - the import path deliberately FLATTENS to the only mode this build can
 *     render, so its question is whether an imported second mode should now
 *     survive rather than be replaced;
 *   - the aux-tab opener mints a leaf and has to carry the host's mode;
 *   - the restore path's `??` is a default for a snapshot that predates the
 *     field, which `"preset"` is the correct answer for whatever else the union
 *     gains. It is enumerated so the list is complete and DELIBERATELY EXCLUDED
 *     from the revisit requirement, and it is asserted to still BE a `??`, so
 *     turning it into an unconditional write moves it into the other class.
 *
 * The sites are DISCOVERED by walking `src/` rather than listed, so a fifth one
 * cannot arrive unseen; the pinned table below then has to account for what the
 * walk found. Fixtures under `scripts/` are out of scope on purpose: a fixture
 * naming an existing member stays valid when the union widens, so reddening
 * every one of them would be a dozen edits with nothing on the other side.
 *
 * WHAT THE WALK DOES NOT SEE, measured by probing it rather than reasoned. It
 * matches three shapes - a property assigned a string literal, a `const`
 * declaration of one, and a `??` whose right side is one - and each was proved
 * by adding a fifth site in that shape and watching the count redden. Three
 * shapes pass it unseen, all three measured the same way: a literal reached
 * through a local binding (`const m = "fit"` then `sizeMode: m`), a conditional
 * (`sizeMode: c ? "fit" : "preset"`), and an assertion (`sizeMode: "fit" as
 * RdpSizeMode`). Following those would mean an indirection walk, both arms of a
 * ternary and an unwrap, for shapes nothing in the tree uses.
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
  `...and its membership is exactly ["preset"]`,
  members !== null && members.join(",") === "preset",
  members ?? "(not found)",
);

// ---------------------------------------------------------------------------
// 2. The write sites, discovered
// ---------------------------------------------------------------------------

type Kind = "unconditional" | "default";
type Site = { rel: string; kind: Kind; literal: string; text: string };

/** `?? "literal"` on the right of a nullish coalesce, or null. */
function nullishDefault(expr: ts.Expression): ts.StringLiteral | null {
  if (!ts.isBinaryExpression(expr)) return null;
  if (expr.operatorToken.kind !== ts.SyntaxKind.QuestionQuestionToken) return null;
  return ts.isStringLiteral(expr.right) ? expr.right : null;
}

const sites: Site[] = [];
for (const rel of SRC_FILES) {
  const src = read(rel);
  if (!src.includes(FIELD)) continue;
  const sf = parseSource(rel, src);
  walk(sf, (n) => {
    // `{ sizeMode: <literal> }` and `{ sizeMode: x ?? <literal> }`. A property
    // SIGNATURE (`sizeMode: "preset";` in a type) is a different node kind and
    // is deliberately not matched here - that one is section 4's subject.
    if (ts.isPropertyAssignment(n) && ts.isIdentifier(n.name) && n.name.text === FIELD) {
      const init = n.initializer;
      if (ts.isStringLiteral(init)) {
        sites.push({ rel, kind: "unconditional", literal: init.text, text: n.getText() });
        return;
      }
      const fallback = nullishDefault(init);
      if (fallback) {
        sites.push({ rel, kind: "default", literal: fallback.text, text: n.getText() });
      }
      return;
    }
    // `const sizeMode: RdpSizeMode = <literal>` - the same write through a
    // binding instead of straight into the object.
    if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.name.text === FIELD) {
      const init = n.initializer;
      if (init && ts.isStringLiteral(init)) {
        sites.push({ rel, kind: "unconditional", literal: init.text, text: n.getText() });
      }
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
    kind: "unconditional",
    owes: "the editor save path mints a row and must write the mode that was chosen",
  },
  {
    rel: "src/modules/backup/file.ts",
    kind: "unconditional",
    owes: "the import path flattens to the only renderable mode on purpose; decide whether an imported second mode should survive",
  },
  {
    rel: "src/modules/tabs/lib/useAuxTabs.ts",
    kind: "unconditional",
    owes: "the aux-tab opener mints a leaf and must carry the host's mode",
  },
  {
    rel: "src/modules/workspaces/serialize.ts",
    kind: "default",
    owes: "EXCLUDED: a default for a snapshot predating the field, for which `preset` stays the right answer",
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
const written = [...new Set(sites.map((s) => s.literal))].sort();
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

// ---------------------------------------------------------------------------
// 4. The excluded default, and what `tsc` covers on its own
// ---------------------------------------------------------------------------

console.log("\n[excluded] the restore path's default is a different shape and stays");
const restoreDefault = sites.filter((s) => s.kind === "default");
check("exactly one site is the `??` default form", restoreDefault.length === 1, restoreDefault);
check(
  "...and it is the restore path in workspaces/serialize.ts",
  restoreDefault[0]?.rel === "src/modules/workspaces/serialize.ts",
  restoreDefault[0]?.rel ?? "(none)",
);
check(
  "...reading the saved field rather than restating it, so a snapshot that HAS a mode keeps it",
  restoreDefault[0]?.text.includes(`.${FIELD} ??`) === true,
  restoreDefault[0]?.text ?? "(none)",
);

console.log("\n[tsc] the one arm the compiler covers by itself, so this file cannot claim it");
{
  const rel = "src/modules/workspaces/store.ts";
  const sf = parseSource(rel, read(rel));
  let signature: ts.PropertySignature | null = null;
  walk(sf, (n) => {
    if (!ts.isPropertySignature(n) || !ts.isIdentifier(n.name) || n.name.text !== FIELD) return;
    // The saved RDP leaf is the only persisted shape declaring the field.
    signature = n;
  });
  const declared = signature as ts.PropertySignature | null;
  check("the saved leaf declares the field", declared !== null);
  const typeNode = declared?.type;
  check(
    `...as the literal "preset" and NOT as ${UNION}, which is why widening the union is one type error there and none at the four write sites`,
    typeNode !== undefined &&
      ts.isLiteralTypeNode(typeNode) &&
      ts.isStringLiteral(typeNode.literal) &&
      typeNode.literal.text === "preset",
    typeNode?.getText() ?? "(absent)",
  );
}

console.log(failed === 0 ? "\nALL PASS" : `\n${failed} FAILED`);
process.exit(failed === 0 ? 0 : 1);
