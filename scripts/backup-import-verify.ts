/**
 * Self-check for VLT-60: the Import dialog's failure surface, and the order
 * validation runs in relative to the passphrase prompt.
 * Run: `pnpm verify backup-import` (or `npx tsx
 * scripts/backup-import-verify.ts` to iterate).
 *
 * SOURCE-TEXT for most of it, and for the same reason `hosts-error-toast-
 * verify.ts` is: there is no DOM/layout engine in this repo's check suite, and
 * neither half of VLT-60 is about what one render call produces - it is about
 * WHICH code path a failure or a passphrase prompt runs through, which is a
 * property of the source rather than of any one render. Whether the envelope
 * rules themselves are right (which sentence each refused format gets, what a
 * good file parses to) is `backup-verify.ts`'s `[refusals]` and `[v3 envelope]`
 * sections; this file reuses `parseBackupFile` only to establish WHAT the
 * pre-check decides at the point it runs, which is VLT-60's own claim.
 *
 * Three concerns:
 *
 *   `BackupDialog.tsx` - Import's run() failure must toast(), not setError()
 *   into the dialog's own inline line (VLT-36 left this one surface out:
 *   "three surfaces become one" is still deferred, so Export's inline line is
 *   checked to be UNCHANGED, not merged away).
 *
 *   `HostsBackupActions.tsx` - openImport() must establish the envelope shape
 *   (kind/version/payload presence) BEFORE opening the dialog that asks for a
 *   passphrase, so a file this build cannot read is rejected on the pick rather
 *   than after a secret has been typed for it. A plain Cancel must still fall
 *   through to nothing - no toast, no dialog - which is checked by asserting
 *   the pre-existing `if (!path) return;` line survives untouched.
 *
 *   THE PLAINTEXT READ PATH STAYS DELETED. `backup_open` returned a decrypted
 *   credential map to the webview, and it is gone from both sides: nothing in
 *   `src/` calls it, and `lib.rs` does not register it. Neither half is visible
 *   anywhere else - an unregistered command fails only at runtime, as "command
 *   not found", and nothing in this repo otherwise reads the handler list.
 *
 * COMMENTS ARE REMOVED FIRST, quote-aware, before any source-text scan below
 * runs - handoff §4.17. A commented-out call (`// was: parseBackupFile(raw);`)
 * still contains the literal an un-stripped scan looks for, and this file's
 * own prose above names both guarded calls in the same identifiers the code
 * uses, so raw source is not safe to scan directly either way.
 */
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { BACKUP_KIND, BACKUP_KIND_V1, parseBackupFile } from "../src/modules/backup/file";

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

const dialogSrc = stripComments(read("src/modules/backup/BackupDialog.tsx"));
const actionsSrc = stripComments(read("src/modules/hosts/page/HostsBackupActions.tsx"));

// --- Part 1: BackupDialog.tsx --------------------------------------------

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

console.log("\n[dialog] the export/import descriptions name the five backup collections");
// Bounded to the <DialogDescription> tag first: DialogTitle right above it is
// ALSO an `isExport ? "..." : "..."` ternary (just of two short strings), so
// an unbounded match here would silently latch onto the title instead - which
// is exactly what happened the first time this check was written.
const descriptionBlock =
  dialogSrc.match(/<DialogDescription>([\s\S]*?)<\/DialogDescription>/)?.[1] ?? "";
check("the DialogDescription block was found", descriptionBlock.length > 0);
// The descriptions are a plain ternary of two single-line string literals -
// captured together so "export names X" and "import keeps Y verbatim" both
// read off the same match instead of two independent regexes that could each
// silently latch onto the wrong string if the ternary's shape ever changes.
const descMatch = descriptionBlock.match(/isExport\s*\?\s*"([^"]*)"\s*:\s*"([^"]*)"/);
check("the DialogDescription ternary was found", descMatch !== null);
const exportDesc = descMatch?.[1] ?? "";
const importDesc = descMatch?.[2] ?? "";
for (const noun of ["host", "host group", "vault identity", "vault key", "forward rule"]) {
  check(`export description names "${noun}"`, exportDesc.includes(noun));
}
// Exact-string pin, not a paraphrase check: this sentence is the module's
// contract (step 6 spent real design on keeping it true), so a rewording
// that keeps the same MEANING but not the same words must still fail here.
check(
  'import description keeps "Nothing is deleted" verbatim',
  importDesc.includes("Nothing is deleted"),
);
// "identity" is plural here ("identities"), unlike the export description's
// "every saved ... identity" - a regular plural still contains its singular
// stem ("hosts" contains "host"), but "identities" does not contain
// "identity" (the "y" breaks at the same letter the "-ies" replaces), so this
// list spells that one out rather than reusing exportNouns above.
for (const noun of ["host", "host group", "vault identities", "vault key", "forward rule"]) {
  check(`import description names "${noun}"`, importDesc.includes(noun));
}

console.log(
  "\n[dialog] the export result line hides a zero-valued collection, not just identities/keys/rules",
);
// Pin the guard EXPRESSIONS, not just the field names: `counts.identities`
// appearing somewhere in the function is also true of a version that always
// pushes it. `describeExport`'s parameter is a multi-line object type, so the
// non-greedy `[^)]*` (which, being a negated class, matches newlines too)
// walks past it to the first real `)` before the body starts.
const describeExportBody =
  dialogSrc.match(/function describeExport\([^)]*\)[^{]*\{([\s\S]*?)\n\}/)?.[1] ?? "";
check("describeExport() was found", describeExportBody.length > 0);
for (const field of ["hosts", "groups", "identities", "keys", "rules"]) {
  check(
    `describeExport() only includes "${field}" when it is non-zero (counts.${field} > 0)`,
    describeExportBody.includes(`counts.${field} > 0`),
  );
}

// --- Part 2: HostsBackupActions.tsx -----------------------------------------

console.log("\n[actions] imports parseBackupFile to pre-check the envelope");
check(
  "imports parseBackupFile from @/modules/backup/file",
  /import\s*\{[^}]*\bparseBackupFile\b[^}]*\}\s*from\s*"@\/modules\/backup\/file";/.test(
    actionsSrc,
  ),
);

console.log(
  "\n[actions] the picker filter still offers all three extensions - dropping v1 was withdrawn",
);
// Bounded to the `extensions: [...]` array rather than pinned as one line of
// exact text: a Prettier reformat is free to break that array across lines,
// and a check anchored to the single-line form would then read a live filter
// as broken. `[\s\S]*?` inside the brackets tolerates that; the word-boundary
// on BACKUP_EXTENSION keeps it from also matching inside BACKUP_EXTENSION_V1.
const filterExtensions = actionsSrc.match(/extensions:\s*\[([\s\S]*?)\]/)?.[1] ?? "";
check("the picker filter array was found", filterExtensions.length > 0);
check("the picker filter contains BACKUP_EXTENSION", /\bBACKUP_EXTENSION\b/.test(filterExtensions));
check(
  "the picker filter contains BACKUP_EXTENSION_V1 - a filtered-out v1 file would have nothing to click",
  /\bBACKUP_EXTENSION_V1\b/.test(filterExtensions),
);
check('the picker filter contains "json"', /"json"/.test(filterExtensions));

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

// --- Part 3: the plaintext read path stays deleted, on both sides -----------

/** Every `.ts`/`.tsx` under `dir`, recursively, as repo-relative paths. */
function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(join(root, dir), { withFileTypes: true })) {
    const rel = `${dir}/${entry.name}`;
    if (entry.isDirectory()) out.push(...sourceFiles(rel));
    else if (rel.endsWith(".ts") || rel.endsWith(".tsx")) out.push(rel);
  }
  return out;
}

/**
 * How many times `name` appears in `src` WITHOUT being the start of `longer`.
 *
 * The shared prefix is the whole difficulty here. `backup_open` is the command
 * that must be gone and `backup_open_payload` is the command that must be there,
 * so `src.includes("backup_open")` is satisfied by the survivor: it passes
 * forever while saying nothing at all, which is exactly the check a reader would
 * write and then trust.
 *
 * Counted rather than located, because the only source these callers have is
 * COMMENT-STRIPPED - a line number off it does not name a line of the file, and
 * one that looked like it did would send the next reader to the wrong place.
 * The file's name is what a failure reports, which is one grep from the line.
 */
function bareUses(src: string, name: string, longer: string): number {
  let found = 0;
  for (let at = src.indexOf(name); at !== -1; at = src.indexOf(name, at + 1)) {
    if (!src.startsWith(longer, at)) found++;
  }
  return found;
}

console.log("\n[webview] nothing in src/ asks the host process for a plaintext credential map");
// Comments are stripped first, and here that is load-bearing rather than
// defensive: `apply.ts`'s module header says out loud that the `backup_open`
// call is gone, which is the correct thing for it to say and the exact literal
// an un-stripped scan would trip on.
const bareCallers: string[] = [];
let payloadCalls = 0;
for (const file of sourceFiles("src")) {
  const src = stripComments(read(file));
  payloadCalls += src.split("backup_open_payload").length - 1;
  if (bareUses(src, "backup_open", "backup_open_payload") > 0) bareCallers.push(file);
}
// Vacuity guard: a scan that read nothing, or a stripper that emptied every
// file, would report no offenders and read as a pass. The one call that must
// still be there is what says the scan reached real source.
check(
  `the scan reached the one backup_open_payload call there is (found ${payloadCalls})`,
  payloadCalls === 1,
);
check(
  bareCallers.length === 0
    ? "and nothing under src/ names backup_open except as part of backup_open_payload"
    : `src/ names backup_open bare, in ${bareCallers.join(", ")}`,
  bareCallers.length === 0,
);

console.log(
  "\n[handlers] lib.rs registers the four sealed-path commands and not the plaintext one",
);
// Read by path because nothing else in the repo reads the handler list: an
// unregistered command is a compile-clean file that fails at runtime with
// "command not found", and a re-registered one is a compile-clean file that
// hands a decrypted credential map back to the webview.
const libSrc = stripComments(read("src-tauri/src/lib.rs"));
for (const command of [
  "backup_seal_payload",
  "backup_open_payload",
  "backup_apply_secrets",
  "backup_release",
]) {
  const count = libSrc.split(`backup::${command}`).length - 1;
  check(`lib.rs registers backup::${command} (found ${count})`, count === 1);
}
const bareHandlers = bareUses(libSrc, "backup::backup_open", "backup::backup_open_payload");
check(
  bareHandlers === 0
    ? "and does NOT register backup::backup_open, whose whole job was returning that map"
    : `lib.rs registers backup::backup_open (found ${bareHandlers})`,
  bareHandlers === 0,
);

// --- Functional: WHAT the pre-check decides, at the point it runs -----------

console.log("\n[functional] the pre-check decides the envelope BEFORE a passphrase is asked for");
// This section's property did not change when v1 and v2 stopped being readable,
// it got stricter. The pre-check still has to settle the envelope on the pick,
// and it now has three answers to settle it with: the one readable format goes
// through untouched, and each unreadable one is named rather than left to fail
// after a secret has been typed for it. The refusal SENTENCES are pinned whole
// in `backup-verify.ts`; what is pinned here is only that each refusal names the
// format the file actually is, so the two cannot swap.
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
function throwsMentioning(label: string, fn: () => void, needle: string): void {
  try {
    fn();
    console.error(`  FAIL: ${label} did not throw`);
    failed++;
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (msg.includes(needle)) console.log(`  ok: ${label}`);
    else {
      console.error(`  FAIL: ${label} threw "${msg}", expected it to mention "${needle}"`);
      failed++;
    }
  }
}
noThrow(
  "a well-formed v3 envelope is not rejected pre-passphrase, whatever the ciphertext holds",
  () => parseBackupFile({ kind: BACKUP_KIND, version: 3, exportedAt: 1, payload: SEALED }),
);
// `.tervia-ssh` is still offered by the open dialog's filter, so a v1 file can be
// picked at all; being picked, it has to be told what it is here rather than at
// the passphrase prompt. The needle is the extension because that is the half of
// the v1 sentence the v2 sentence cannot also satisfy.
throwsMentioning(
  "a v1 envelope is refused on the pick, by a message naming the format it is",
  () => parseBackupFile({ kind: BACKUP_KIND_V1, version: 1, exportedAt: 1 }),
  "(.tervia-ssh)",
);
throwsMentioning(
  "a v2 envelope likewise, and by the other sentence rather than v1's",
  () => parseBackupFile({ kind: BACKUP_KIND, version: 2, exportedAt: 1, payload: SEALED }),
  "is format v2",
);
// The negative case the whole feature is FOR: a file that is plainly not a
// Tervia backup must be caught by the same function the pre-check calls.
throwsMentioning(
  "a non-Tervia file still throws, which is what the pre-check surfaces early",
  () => parseBackupFile({ kind: "some-other-app-file", version: 1 }),
  "Not a Tervia connection backup file.",
);

console.log(failed === 0 ? "\nAll backup-import checks passed." : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
