/**
 * Self-check for VLT-60: the Import dialog's failure surface, and the order
 * validation runs in relative to the passphrase prompt.
 * Run: `pnpm verify ssh-backup-import` (or `npx tsx
 * scripts/ssh-backup-import-verify.ts` to iterate).
 *
 * SOURCE-TEXT for both halves, and for the same reason `hosts-error-toast-
 * verify.ts` is: there is no DOM/layout engine in this repo's check suite, and
 * neither half of VLT-60 is about what one render call produces - it is about
 * WHICH code path a failure or a passphrase prompt runs through, which is a
 * property of the source rather than of any one render. The one piece that IS
 * ordinary behaviour (does `parseBackupFile` actually accept what it should,
 * and reject what it should not) is already exercised in `ssh-backup-verify
 * .ts`'s `[envelope]`/`[v1 envelope]`/`[v2 envelope]` sections; this file
 * reuses that function directly for two checks specific to VLT-60's claims
 * (a v1 envelope is not rejected, a v2 envelope with garbage ciphertext is
 * not rejected pre-passphrase) rather than re-deriving that coverage.
 *
 * Two files, two concerns:
 *
 *   `SshBackupDialog.tsx` - Import's run() failure must toast(), not setError()
 *   into the dialog's own inline line (VLT-36 left this one surface out:
 *   "three surfaces become one" is still deferred, so Export's inline line is
 *   checked to be UNCHANGED, not merged away).
 *
 *   `HostsBackupActions.tsx` - openImport() must establish the envelope shape
 *   (kind/version/payload presence) BEFORE opening the dialog that asks for a
 *   passphrase, so a plainly non-Tervia file is rejected on the pick rather
 *   than after a secret has been typed for it. A plain Cancel must still fall
 *   through to nothing - no toast, no dialog - which is checked by asserting
 *   the pre-existing `if (!path) return;` line survives untouched.
 *
 * COMMENTS ARE REMOVED FIRST, quote-aware, before any source-text scan below
 * runs - handoff §4.17. A commented-out call (`// was: parseBackupFile(raw);`)
 * still contains the literal an un-stripped scan looks for, and this file's
 * own prose above names both guarded calls in the same identifiers the code
 * uses, so raw source is not safe to scan directly either way.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { BACKUP_KIND, BACKUP_KIND_V1, parseBackupFile } from "../src/modules/ssh/backupFile";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (p: string) => readFileSync(join(root, p), "utf8");

let failed = 0;
function check(label: string, cond: boolean): void {
  if (cond) console.log(`  ok: ${label}`);
  else {
    console.error(`  FAIL: ${label}`);
    failed++;
  }
}

/**
 * A line with its trailing `//` comment removed, string literals respected.
 *
 * Quote-aware rather than a regex because a `//` inside a string is not a
 * comment, and this editor's help text is exactly the sort of string that would
 * one day contain one. An apostrophe in unquoted JSX text opens a quote state
 * that never closes, which loses the strip for that one line - it fails towards
 * keeping text, never towards deleting code.
 *
 * Copied verbatim from `host-editor-verify.ts` (also duplicated in
 * `rdp-lifetime-verify.ts`) rather than reimplemented. VLT-33 - extract this
 * and `stripComments` into `scripts/lib` - is still open and out of scope
 * here; this is now the THIRD copy of the same two functions, not the second.
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
 * Every check below runs on this rather than on the raw file, for the reason
 * `host-editor-verify.ts` and `rdp-lifetime-verify.ts` both give: the prose in
 * this file's own docblock names the guarded calls it checks for by their
 * literal text, so a regex over raw source could be satisfied by a comment
 * alone. Deleting (or commenting out) a guarded call and leaving a trailing
 * `// was: ...` behind it must fail, and stripping first is what makes it
 * fail. Confirmed by breaking `parseBackupFile(raw);` exactly that way.
 */
function stripComments(src: string): string {
  // JSX comment expressions - `{/* ... */}` - are the only comment syntax
  // legal INSIDE JSX children, and the line-based filter below only ever
  // recognised `//`, `/*` and `*` starting a trimmed line, none of which match
  // a line starting `{`. Both `dialogSrc` and `actionsSrc` below strip a
  // `.tsx` file, so this file is exposed exactly as VLT-83 describes: a
  // deleted guarded call left behind as `{/* ... */}` would pass every
  // positive check run over the stripped source.
  //
  // VLT-83: the inner group must NOT be allowed to cross a `*/` while hunting
  // for one followed by `}` - a lazy `[\s\S]*?` is still permitted to do that,
  // and a type literal opening `{ /** ... */ x: T }` then swallows everything
  // up to some later, unrelated `*/}`. The negative lookahead below forbids
  // that: the first `*/` is final, either a real `{/* ... */}` or the match
  // fails right there. Copied from `host-editor-verify.ts:191`'s fixed form;
  // see that file's comment for the measured damage the lazy form did.
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

// VLT-83 self-test: both directions of the JSX-comment branch above.
const STRIPPER_PROBE =
  "type P = { /** c */ x: X };\nconst KEEP = 1;\nconst j = <div>{/* c */}</div>;";
check(
  "stripComments does not over-strip past a type literal's doc comment (the lazy-regex trap)",
  stripComments(STRIPPER_PROBE).includes("KEEP"),
);
check(
  "stripComments does remove a JSX comment expression's own body",
  !stripComments(STRIPPER_PROBE).includes("{/*"),
);

const dialogSrc = stripComments(read("src/modules/ssh/SshBackupDialog.tsx"));
const actionsSrc = stripComments(read("src/modules/hosts/page/HostsBackupActions.tsx"));

// --- Part 1: SshBackupDialog.tsx --------------------------------------------

console.log("[dialog] imports the shared toast");
check(
  "imports toast from @/components/ui/toast",
  /import\s*\{\s*toast\s*\}\s*from\s*"@\/components\/ui\/toast";/.test(dialogSrc),
);

console.log("\n[dialog] run()'s catch splits export from import");
// Isolate the body between `catch (e) {` and the shared `} finally {` so the
// export/import checks below cannot accidentally match text from run()'s TRY
// block (which also mentions both branches) or from a stray comment.
const catchBody = dialogSrc.match(/\}\s*catch \(e\) \{([\s\S]*?)\}\s*finally \{/)?.[1] ?? "";
check("the catch block was found at all", catchBody.length > 0);
const [exportArm = "", importArm = ""] = catchBody.split(/\}\s*else\s*\{/);

check("export's arm still calls setError(message)", /setError\(message\)/.test(exportArm));
check(
  "export's arm does NOT toast - VLT-36's consolidation is deferred, not done here",
  !/toast\(/.test(exportArm),
);
check(
  'import\'s arm toasts with variant "error"',
  /toast\(message,\s*\{\s*variant:\s*"error"\s*\}\)/.test(importArm),
);
check(
  "import's arm does NOT setError - the old inline line must not still fire too",
  !/setError\(/.test(importArm),
);

console.log("\n[dialog] the inline error line still renders (export's surface, unchanged)");
check(
  "the {error ? ... text-destructive} line is still present",
  /\{error \? <span className="text-destructive/.test(dialogSrc),
);

// --- Part 2: HostsBackupActions.tsx -----------------------------------------

console.log("\n[actions] imports parseBackupFile to pre-check the envelope");
check(
  "imports parseBackupFile from @/modules/ssh/backupFile",
  /import\s*\{[^}]*\bparseBackupFile\b[^}]*\}\s*from\s*"@\/modules\/ssh\/backupFile";/.test(
    actionsSrc,
  ),
);

console.log("\n[actions] openImport() checks the shape BEFORE opening the passphrase dialog");
// Textual order is the contract here: reading is not enough (VLT-60's bug was
// exactly that the read happened first and the check ran only after Import
// was clicked, inside applyBackup). Each anchor must appear, and exactly once,
// so a future refactor that duplicates or removes a step fails loudly instead
// of the indexOf comparison silently comparing -1 against something.
const anchors = {
  readFile: 'invoke<FsReadResult>("fs_read_file"',
  parseJson: "JSON.parse(result.content)",
  shapeCheck: "parseBackupFile(raw)",
  openDialog: 'setBackup({ kind: "import"',
} as const;
for (const needle of Object.values(anchors)) {
  const count = actionsSrc.split(needle).length - 1;
  check(`"${needle}" appears exactly once (found ${count})`, count === 1);
}
const idx = Object.fromEntries(
  Object.entries(anchors).map(([name, needle]) => [name, actionsSrc.indexOf(needle)]),
) as Record<keyof typeof anchors, number>;
check(
  "the file is read before its JSON is parsed",
  idx.readFile >= 0 && idx.parseJson > idx.readFile,
);
check(
  "the JSON is parsed before the envelope shape is checked",
  idx.parseJson >= 0 && idx.shapeCheck > idx.parseJson,
);
check(
  "the envelope shape is checked before the passphrase dialog opens - the actual fix",
  idx.shapeCheck >= 0 && idx.openDialog > idx.shapeCheck,
);

console.log("\n[actions] a failed pre-check toasts and returns, never reaching the dialog");
// The two guard clauses this adds (bad JSON, bad envelope) each have to STOP
// the function - `return;` right after the toast - or a rejected file would
// fall through into `setBackup`/`setBackupOpen` anyway, silently undoing the
// order checked above.
// Both guards below anchor on the TRY that precedes the catch, not merely on
// the catch's own toast/return shape. A regex starting at `catch {` matches
// regardless of what the try attempted (or attempted nothing at all, its call
// commented out), which is exactly how a deleted `parseBackupFile(raw);` used
// to survive: the catch immediately after it, and `setBackup` immediately
// after that, are scaffolding this file's own guarded call sits inside, not
// evidence the call is still there. Confirmed by removing each call in turn.
const jsonGuard = actionsSrc.match(
  /try \{\s*\n\s*raw = JSON\.parse\(result\.content\);\s*\n\s*\} catch \{\s*\n\s*toast\("That file is not valid JSON\.",\s*\{\s*variant:\s*"error"\s*\}\);\s*\n\s*return;/,
);
check(
  "the try that parses JSON is guarded by a catch that toasts then returns",
  jsonGuard !== null,
);
const shapeGuard = actionsSrc.match(
  /try \{\s*\n\s*parseBackupFile\(raw\);\s*\n\s*\} catch \(e\) \{\s*\n\s*toast\(e instanceof Error \? e\.message : String\(e\), \{ variant: "error" \}\);\s*\n\s*return;\s*\n\s*\}\s*\n\s*setBackup\(\{ kind: "import"/,
);
check(
  "the try that calls parseBackupFile is guarded by a catch that toasts then returns, immediately before setBackup",
  shapeGuard !== null,
);

console.log("\n[actions] a plain Cancel is still not an error - untouched by this change");
check(
  "the cancel guard (`if (!path) return;`) is unchanged: no toast, just a silent return",
  /if \(!path\) return;/.test(actionsSrc),
);
// The cancel guard has to run BEFORE the file is even read, let alone
// shape-checked - otherwise a null path would reach `fs_read_file` with
// nothing to read.
check(
  "the cancel guard runs before the file read",
  actionsSrc.indexOf("if (!path) return;") < idx.readFile,
);

// --- Functional: the SAME function used for the pre-check still tells v1 ---
// --- from v2 the way VLT-60 requires: neither format is wrongly rejected ---

console.log("\n[functional] the pre-check function itself does not reject what must still import");
const SEALED = {
  kdf: "pbkdf2-hmac-sha256",
  iterations: 600000,
  salt: "c2FsdA==",
  nonce: "bm9uY2U=",
  ciphertext: "Y2lwaGVy",
};
function noThrow(label: string, fn: () => void): void {
  try {
    fn();
    console.log(`  ok: ${label}`);
  } catch (e) {
    console.error(`  FAIL: ${label} threw: ${e instanceof Error ? e.message : String(e)}`);
    failed++;
  }
}
noThrow("a v1 envelope (BACKUP_EXTENSION_V1's format) is not rejected by the pre-check", () =>
  parseBackupFile({
    kind: BACKUP_KIND_V1,
    version: 1,
    exportedAt: 1,
    connections: [],
    secrets: SEALED,
  }),
);
noThrow(
  "a well-formed v2 envelope is not rejected pre-passphrase, whatever the ciphertext holds",
  () => parseBackupFile({ kind: BACKUP_KIND, version: 2, exportedAt: 1, payload: SEALED }),
);
// The negative case the whole feature is FOR: a file that is plainly not a
// Tervia backup must be caught by the same function the pre-check calls.
try {
  parseBackupFile({ kind: "some-other-app-file", version: 1 });
  console.error("  FAIL: a non-Tervia file did not throw");
  failed++;
} catch {
  console.log("  ok: a non-Tervia file still throws, which is what the pre-check surfaces early");
}

console.log(
  failed === 0 ? "\nAll ssh-backup-import checks passed." : `\n${failed} check(s) FAILED.`,
);
process.exit(failed === 0 ? 0 : 1);
