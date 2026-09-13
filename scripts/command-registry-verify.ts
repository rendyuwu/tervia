/**
 * Self-check for the Tauri command registry: the `generate_handler!` list in
 * `src-tauri/src/lib.rs` against every `invoke` call site in `src/`.
 * Run: `npx tsx scripts/command-registry-verify.ts`.
 *
 * Nothing else ties the two sides together, and both directions fail silently:
 *
 *  1. INVOKED IMPLIES REGISTERED. A command the frontend invokes but nobody
 *     registered fails only at runtime, as "command not found", which from the
 *     frontend reads as a backend bug rather than as a missing line in a list.
 *     `tsc` cannot see it: the name is a string.
 *  2. REGISTERED IMPLIES INVOKED, OR ALLOWED. `tauri.conf.json` sets
 *     `"removeUnusedCommands": true`, so a registered command with no frontend
 *     `invoke` call site can be stripped from a release build while the debug
 *     build keeps it. That is fine for a command nothing calls and fatal for one
 *     whose only caller was just deleted or renamed, and the two are
 *     indistinguishable without a list saying which is which. UNINVOKED is that
 *     list.
 *  3. NO STALE ALLOWANCE. An entry in UNINVOKED that has since gained a caller
 *     is worse than no list: it goes on excusing the command after the reason
 *     expired, so a later deletion of that caller passes.
 *
 * Direction 2 is why UNINVOKED is spelled out here rather than derived. A
 * derived list is satisfied by any tree, including the tree where the caller
 * you needed is gone.
 *
 * `Cargo.toml` gains nothing from this: the check reads text, needs no
 * `[dev-dependencies]` section and no `tauri` test feature, and runs on the
 * platform `cargo test` already runs on.
 */
/// <reference types="node" />
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve, relative } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));

/**
 * Registered, with no `invoke` call site in `src/`. Each is strippable from a
 * release build by `removeUnusedCommands`, and each is accepted because nothing
 * in `src/` calls it: the shell command surface has no consuming frontend module
 * at all (`src/modules/` has no shell or tasks module), and the rest are broader
 * backends the frontend reaches through a narrower sibling.
 *
 * This list is a ledger, not a suppression. Adding a name to it is the record
 * that a command ships with no caller on purpose. Removing a caller for a name
 * NOT on it reddens check 2, which is the point.
 */
const UNINVOKED = new Set([
  // The shell surface: registered, implemented, and not wired to any UI.
  // `format.rs` records why the formatter path deliberately does not route
  // through `shell_run_command` (formatters need raw stdin piping).
  "shell_run_command",
  "shell_session_open",
  "shell_session_run",
  "shell_session_close",
  "shell_bg_spawn",
  "shell_bg_spawn_direct",
  "shell_bg_logs",
  "shell_bg_kill",
  "shell_bg_remove",
  "shell_bg_list",
  // Wider backends with a narrower sibling the frontend actually calls:
  // `fs_read_file` over `fs_read_file_portion`, `fs_grep` over `fs_glob`,
  // `secrets_get_all` over `secrets_get`, `port_is_open` over `http_ping`
  // (a TCP connect, because a self-signed vhost cert fails an HTTPS probe).
  "fs_read_file_portion",
  "fs_canonicalize",
  "fs_copy",
  "fs_glob",
  "secrets_get",
  "http_ping",
  "http_stream",
  "http_abort",
  "ssh_list_sessions",
  "ssh_attach",
]);

/**
 * `invoke` call sites whose command name is not a literal at the call. Each is
 * listed with the literals it can take, so a dynamic name cannot hide an
 * unregistered command behind a variable. The set is pinned: a new dynamic call
 * site reddens rather than silently escaping check 1.
 */
const DYNAMIC_SITES: { file: string; candidates: string[] }[] = [
  {
    file: "src/modules/explorer/lib/useFileTree.ts",
    candidates: ["fs_create_dir", "fs_create_file"],
  },
];

let failed = 0;
function assert(cond: boolean, msg: string): void {
  if (!cond) {
    console.error(`  FAIL: ${msg}`);
    failed++;
  } else {
    console.log(`  ok: ${msg}`);
  }
}

const read = (p: string) => readFileSync(join(ROOT, p), "utf8");

// --- the registered set -----------------------------------------------------

const libRs = read("src-tauri/src/lib.rs");
const handlerBlock = /generate_handler!\[([\s\S]*?)\]\s*\)/.exec(libRs);
if (!handlerBlock) throw new Error("command-registry-verify: no generate_handler! block in lib.rs");
// Entries are `module::path::name,` or a bare `name,`; take the last segment.
// Trailing comma is required by the macro's own formatting, so every entry has
// one and the last line is not a special case.
const registered = new Set(
  [...handlerBlock[1].matchAll(/(?:[A-Za-z_][A-Za-z0-9_]*::)*([A-Za-z_][A-Za-z0-9_]*)\s*,/g)].map(
    (m) => m[1],
  ),
);

console.log(`1. the handler list parses (${registered.size} commands)`);
{
  assert(registered.size > 80, `parsed ${registered.size} registered commands`);
  // A duplicated entry compiles and makes the second one dead, so the count and
  // the set agreeing is itself a check.
  const entryCount = (handlerBlock[1].match(/,/g) ?? []).length;
  assert(entryCount === registered.size, `no duplicate entries (${entryCount} lines)`);
  // Parse anchors, not registration claims: the list holds both a bare entry
  // and a two-segment path, and the name pattern has to reduce each to its last
  // segment. If either shape stopped parsing, the set would be quietly short
  // and check 4 would report the missing names as orphans instead.
  assert(registered.has("open_settings_window"), "a bare entry parses to its own name");
  assert(registered.has("ssh_sftp_home"), "a nested path parses to its last segment");
}

// --- every invoke call site in src/ -----------------------------------------

const tsFiles: string[] = [];
const walk = (dir: string) => {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) walk(full);
    else if (/\.tsx?$/.test(name)) tsFiles.push(full);
  }
};
walk(join(ROOT, "src"));

/**
 * The first argument of every `invoke` call in `text`, as a literal command
 * name or `null` for a name computed at the call.
 *
 * Written as a scanner rather than one regex because both parts that follow
 * `invoke` defeat a flat pattern, and each defeated an earlier draft of this
 * file: the type argument can contain parentheses and nested angle brackets
 * (`invoke<(string | null)[]>`), so a `[^>(]*` generic silently skips the call
 * and drops a real command from the invoked set; and `invoke(fetch)` appears in
 * prose inside doc comments, which a pattern over raw source reads as a dynamic
 * call site.
 */
function invokeArgs(text: string): { name: string | null; line: number }[] {
  const out: { name: string | null; line: number }[] = [];
  const lines = text.split("\n");
  for (let ln = 0; ln < lines.length; ln++) {
    const line = lines[ln];
    // Doc-comment and comment bodies mention `invoke(...)` as prose. A
    // line-level guard is enough here and cannot truncate a string literal the
    // way stripping comment syntax out of the whole file can.
    const lead = line.trimStart();
    if (lead.startsWith("*") || lead.startsWith("//") || lead.startsWith("/*")) continue;
    for (const m of line.matchAll(/\binvoke\b/g)) {
      let i = m.index + "invoke".length;
      while (i < line.length && /\s/.test(line[i])) i++;
      if (line[i] === "<") {
        // Skip the type argument by angle-bracket depth, so a nested generic
        // does not end the skip early.
        let depth = 0;
        while (i < line.length) {
          if (line[i] === "<") depth++;
          else if (line[i] === ">" && --depth === 0) {
            i++;
            break;
          }
          i++;
        }
        while (i < line.length && /\s/.test(line[i])) i++;
      }
      if (line[i] !== "(") continue; // `invoke` as a bare identifier, not a call
      i++;
      while (i < line.length && /\s/.test(line[i])) i++;
      const literal = /^"([a-z0-9_]+)"/.exec(line.slice(i));
      out.push({ name: literal ? literal[1] : null, line: ln + 1 });
    }
  }
  return out;
}

const invokedLiterals = new Map<string, string[]>();
const dynamicFound: string[] = [];
const noteInvoked = (cmd: string, rel: string) => {
  const sites = invokedLiterals.get(cmd) ?? [];
  if (!sites.includes(rel)) sites.push(rel);
  invokedLiterals.set(cmd, sites);
};
for (const full of tsFiles) {
  const rel = relative(ROOT, full).replace(/\\/g, "/");
  for (const call of invokeArgs(readFileSync(full, "utf8"))) {
    if (call.name) noteInvoked(call.name, rel);
    else if (!dynamicFound.includes(rel)) dynamicFound.push(rel);
  }
}
// A dynamic site's enumerated candidates are callers too. Without this, check 4
// reports a command as having lost its last caller because the caller passes it
// through a variable, which is the false alarm that would train a reader to
// widen the ledger instead of reading it.
for (const site of DYNAMIC_SITES) for (const cmd of site.candidates) noteInvoked(cmd, site.file);

console.log("\n2. every command invoked from src/ is registered");
{
  assert(invokedLiterals.size > 0, `found ${invokedLiterals.size} invoked command names in src/`);
  const unregistered = [...invokedLiterals.keys()].filter((c) => !registered.has(c));
  assert(
    unregistered.length === 0,
    `every invoked command is in generate_handler!${
      unregistered.length ? ` (missing: ${unregistered.join(", ")})` : ""
    }`,
  );
}

console.log("\n3. dynamic invoke sites are enumerated, and their names registered");
{
  const expected = DYNAMIC_SITES.map((s) => s.file).sort();
  assert(
    JSON.stringify(dynamicFound.sort()) === JSON.stringify(expected),
    `the dynamic invoke sites are the known ones${
      JSON.stringify(dynamicFound) === JSON.stringify(expected)
        ? ""
        : ` (found: ${dynamicFound.join(", ") || "none"}; expected: ${expected.join(", ")})`
    }`,
  );
  for (const site of DYNAMIC_SITES) {
    const text = read(site.file);
    for (const cmd of site.candidates) {
      // Both halves matter: the literal is still in the file it was recorded
      // in, and the name it holds is registered.
      assert(text.includes(`"${cmd}"`), `${site.file} still names ${cmd}`);
      assert(registered.has(cmd), `${cmd} is registered`);
    }
  }
}

// --- the reverse direction, and the ledger ----------------------------------

console.log("\n4. every registered command has a caller in src/, or is on the ledger");
{
  const orphans = [...registered].filter((c) => !invokedLiterals.has(c) && !UNINVOKED.has(c));
  assert(
    orphans.length === 0,
    `no registered command lost its last caller${
      orphans.length ? ` (uninvoked and not on the ledger: ${orphans.join(", ")})` : ""
    }`,
  );
}

console.log("\n5. the ledger has no stale entries");
{
  // An entry that has gained a caller stops meaning anything and starts
  // excusing the next deletion.
  const gainedCallers = [...UNINVOKED].filter((c) => invokedLiterals.has(c));
  assert(
    gainedCallers.length === 0,
    `no ledger entry has gained a caller${
      gainedCallers.length
        ? ` (remove from UNINVOKED: ${gainedCallers.map((c) => `${c} <- ${invokedLiterals.get(c)!.join(", ")}`).join("; ")})`
        : ""
    }`,
  );
  // An entry naming a command that is no longer registered at all is dead
  // weight, and hides that the command was removed rather than allowed.
  const unregisteredLedger = [...UNINVOKED].filter((c) => !registered.has(c));
  assert(
    unregisteredLedger.length === 0,
    `every ledger entry is still registered${
      unregisteredLedger.length ? ` (stale: ${unregisteredLedger.join(", ")})` : ""
    }`,
  );
  // Reported, not asserted: the ratio is context for a reader, and pinning it
  // would redden on every legitimate wiring of a shell command to the UI. It
  // deliberately does not use the `ok:` prefix, which is the suite's assertion
  // marker and would count this line as a check it is not.
  console.log(`  (${UNINVOKED.size} of ${registered.size} commands ship with no frontend caller)`);
}

// `throw` (not process.exit) for a non-zero exit, matching the other verify scripts.
if (failed > 0) throw new Error(`command-registry-verify: ${failed} check(s) failed`);
console.log("\ncommand-registry-verify: all checks passed");
