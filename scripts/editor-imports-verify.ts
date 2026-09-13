/**
 * Self-check: the five editor dialogs that reach into ANOTHER module's
 * `editor/` directory keep reaching, and keep taking the same names.
 * Run: `pnpm verify editor-imports`.
 *
 * WHAT THIS PINS, AND WHY IT IS NOT A STYLE RULE. Five primitives are shared
 * across module boundaries today - the combobox, the form controls, the
 * secret-store copy, the host option builder, and the vault's draft module.
 * Sharing them is the decision; this file is what stops the decision from
 * decaying silently. The failure it exists to catch is not a deleted import,
 * which breaks the build - it is a private LOCAL REIMPLEMENTATION added beside
 * the import: a second `Field`, a second combobox, a copy of
 * `encryptedKeyRefusal`. Every gate in this repo stays green through that, the
 * two copies then drift, and the first anybody hears of it is a dialog that
 * validates differently from its twin.
 *
 * TWO ASSERTIONS PER FILE, AND THE DISTINCTION IS THE POINT.
 *   - The SPECIFIER set, sorted and compared whole. Only this form catches a
 *     dependency that DISAPPEARS: a membership test over what is there says
 *     nothing about what left.
 *   - The NAMED-IMPORT set per specifier, sorted and compared whole. Only this
 *     form catches one name dropped from a module that is still imported for
 *     the others - `Field` reimplemented locally while `ToggleButton` keeps
 *     coming from the shared file.
 *
 * A SEPARATE SCRIPT FOR INDEPENDENCE, NOT FOR OWNERSHIP. All five importing
 * files are already read by some other script in this suite. Nothing requires
 * one check over all five, and the reason to add one anyway is the reason this
 * suite gives elsewhere for keeping a duplicate pin: separate script, separate
 * parser, so a regression in one script's machinery - or one of them going dark
 * on a module-load error rather than red - does not leave these call sites
 * unpinned.
 *
 * CROSS-MODULE IS DECIDED BY RESOLVING THE SPECIFIER, not by matching its text.
 * `@/modules/hosts/editor/Combobox` and `../../hosts/editor/Combobox` name the
 * same file, and a text rule that knows only the first is one rewrite away from
 * seeing nothing at all. Each specifier is resolved against the importing file
 * to a repo-relative path, and it counts here when that path lands under a
 * DIFFERENT module's `editor/` directory. A dialog importing from its own
 * module's `editor/` is ordinary and is not this file's business.
 */
import { readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import ts from "typescript";

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

/** The module a repo-relative `src/modules/<name>/...` path belongs to, or "". */
function moduleOf(rel: string): string {
  return /^src\/modules\/([^/]+)\//.exec(rel.split("\\").join("/"))?.[1] ?? "";
}

/**
 * Where `spec`, written inside `fromRel`, points - repo-relative, extensionless
 * - or `null` when it leaves the source tree.
 *
 * `@/` is this repo's alias for `src/`; anything else that does not start with
 * `.` is a package. No file-system probe: the question here is which DIRECTORY
 * the specifier names, and an extension would only get in the way of comparing
 * that against `src/modules/<mod>/editor`.
 */
function resolveSpecifier(fromRel: string, spec: string): string | null {
  if (spec.startsWith("@/")) return `src/${spec.slice(2)}`;
  if (!spec.startsWith(".")) return null;
  const abs = resolve(join(root, dirname(fromRel)), spec);
  const rel = relative(root, abs).split("\\").join("/");
  return rel.startsWith("..") ? null : rel;
}

type EditorImport = { spec: string; target: string; names: string[] };

/**
 * Every import in `rel` that resolves into another module's `editor/`.
 *
 * The specifier walk takes EVERY `ImportDeclaration`, whatever its clause: a
 * default binding and an `import * as FormControls from ...` are both imports
 * of the module, and a walk that only understands `ts.isNamedImports` would
 * report the module as absent. The name list is a different matter - it is
 * NAMED IMPORTS ONLY, and a namespace or default binding is recorded as such
 * rather than expanded, because what a namespace binding actually uses is a
 * question about the whole file's body and not about this statement.
 */
function crossModuleEditorImports(rel: string): EditorImport[] {
  const sf = ts.createSourceFile(rel, read(rel), ts.ScriptTarget.ESNext, true, ts.ScriptKind.TSX);
  const own = moduleOf(rel);
  const out: EditorImport[] = [];
  for (const st of sf.statements) {
    if (!ts.isImportDeclaration(st) || !ts.isStringLiteral(st.moduleSpecifier)) continue;
    const spec = st.moduleSpecifier.text;
    const target = resolveSpecifier(rel, spec);
    if (target === null) continue;
    const targetModule = moduleOf(target);
    if (targetModule === "" || targetModule === own) continue;
    if (!target.startsWith(`src/modules/${targetModule}/editor/`)) continue;
    const names: string[] = [];
    const clause = st.importClause;
    if (clause?.name) names.push(`default as ${clause.name.text}`);
    if (clause?.namedBindings) {
      if (ts.isNamespaceImport(clause.namedBindings)) {
        names.push(`* as ${clause.namedBindings.name.text}`);
      } else {
        for (const el of clause.namedBindings.elements) names.push(el.name.text);
      }
    }
    out.push({ spec, target, names: names.sort() });
  }
  return out.sort((a, b) => (a.spec < b.spec ? -1 : a.spec > b.spec ? 1 : 0));
}

/**
 * The pinned set. Each entry is one importing file, the exact specifiers it is
 * expected to reach another module's `editor/` through, and the exact names it
 * takes from each.
 */
const PINNED: Array<{ file: string; imports: Array<[string, string[]]> }> = [
  {
    file: "src/modules/vault/editor/IdentityEditorDialog.tsx",
    imports: [
      ["@/modules/hosts/editor/Combobox", ["Combobox", "ComboboxOption"]],
      ["@/modules/hosts/editor/FormControls", ["Field", "ToggleButton"]],
      ["@/modules/hosts/editor/secretStoreCopy", ["SECRET_STORE_LOCATIONS"]],
    ],
  },
  {
    file: "src/modules/vault/editor/KeyEditorDialog.tsx",
    imports: [
      ["@/modules/hosts/editor/FormControls", ["Field"]],
      ["@/modules/hosts/editor/secretStoreCopy", ["SECRET_STORE_LOCATIONS"]],
    ],
  },
  {
    file: "src/modules/forwards/editor/RuleEditorDialog.tsx",
    imports: [
      ["@/modules/hosts/editor/Combobox", ["Combobox", "ComboboxOption"]],
      ["@/modules/hosts/editor/FormControls", ["Field"]],
      ["@/modules/hosts/editor/hostOptions", ["savedHostOptions"]],
    ],
  },
  {
    file: "src/modules/hosts/HostEditorDialog.tsx",
    imports: [["@/modules/vault/editor/draft", ["encryptedKeyRefusal"]]],
  },
  {
    file: "src/modules/hosts/credentialMove.ts",
    imports: [
      [
        "@/modules/vault/editor/draft",
        ["IdentityDraft", "KeyDraft", "identityRecordFrom", "keyRecordFrom"],
      ],
    ],
  },
];

console.log("[1] the resolver answers about DIRECTORIES, both spellings and neither by accident");
{
  // The instrument before the measurement. A resolver that quietly returned
  // `null` for everything would make every set below empty and every
  // comparison pass by agreement on nothing, so it is proved in both
  // directions first: the two spellings of one file agree, and a package
  // specifier is refused.
  const fromVault = "src/modules/vault/editor/IdentityEditorDialog.tsx";
  check(
    "the @/ alias resolves to src/",
    resolveSpecifier(fromVault, "@/modules/hosts/editor/Combobox") ===
      "src/modules/hosts/editor/Combobox",
    resolveSpecifier(fromVault, "@/modules/hosts/editor/Combobox"),
  );
  check(
    "and a relative spelling of the same file resolves to the same path",
    resolveSpecifier(fromVault, "../../hosts/editor/Combobox") ===
      "src/modules/hosts/editor/Combobox",
    resolveSpecifier(fromVault, "../../hosts/editor/Combobox"),
  );
  check("a package specifier is not a path", resolveSpecifier(fromVault, "react") === null);
  check(
    "and a file's own module is read off its path",
    moduleOf("src/modules/vault/editor/IdentityEditorDialog.tsx") === "vault",
  );
}

console.log(
  "\n[2] each importing file's cross-module editor specifier set is EXACTLY the pinned one",
);
for (const { file, imports } of PINNED) {
  const found = crossModuleEditorImports(file);
  // The vacuity floor, asserted as its own check so a parse that silently
  // found nothing cannot read as a pass: every one of these files imports far
  // more than it takes from another module's editor, so a zero here means the
  // parse failed rather than that the file changed.
  const total = ts
    .createSourceFile(file, read(file), ts.ScriptTarget.ESNext, true, ts.ScriptKind.TSX)
    .statements.filter(ts.isImportDeclaration).length;
  check(`${file}: parsed its imports at all`, total > 5, { imports: total });
  check(
    `${file}: reaches another module's editor/ through exactly ${JSON.stringify(imports.map(([s]) => s))}`,
    JSON.stringify(found.map((i) => i.spec)) === JSON.stringify(imports.map(([s]) => s)),
    found.map((i) => i.spec),
  );
}

console.log("\n[3] and takes EXACTLY the pinned names from each");
for (const { file, imports } of PINNED) {
  const found = crossModuleEditorImports(file);
  for (const [spec, names] of imports) {
    const got = found.find((i) => i.spec === spec);
    check(
      `${file}: takes ${JSON.stringify(names)} from ${spec}`,
      got !== undefined && JSON.stringify(got.names) === JSON.stringify([...names].sort()),
      got?.names,
    );
  }
}

console.log("\n[4] the count over the whole set, so a whole file dropping out is visible");
{
  const all = PINNED.flatMap(({ file }) => crossModuleEditorImports(file));
  const want = PINNED.reduce((n, p) => n + p.imports.length, 0);
  check(
    `exactly ${want} cross-module editor imports across the five files`,
    all.length === want,
    all.length,
  );
  // Five shared modules, and the count of DISTINCT targets is what a
  // per-file set cannot say: three files importing `FormControls` still
  // reads as three passing per-file checks if two of them start pointing at
  // private copies with the same name in their own module's editor/.
  const targets = [...new Set(all.map((i) => i.target))].sort();
  check(
    "and they land on exactly the five shared modules",
    JSON.stringify(targets) ===
      JSON.stringify([
        "src/modules/hosts/editor/Combobox",
        "src/modules/hosts/editor/FormControls",
        "src/modules/hosts/editor/hostOptions",
        "src/modules/hosts/editor/secretStoreCopy",
        "src/modules/vault/editor/draft",
      ]),
    targets,
  );
}

console.log(failed === 0 ? "\nAll editor-imports checks passed." : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
