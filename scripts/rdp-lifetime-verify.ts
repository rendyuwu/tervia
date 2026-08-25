/**
 * Self-check for the three things in the RDP frontend that must not outlive
 * their owner: a trust prompt, a held key, and a Test probe.
 * Run: `pnpm verify rdp-lifetime`.
 *
 * Source text, not imports, and for the same reason `toast-verify.ts` gives:
 * these live inside a React component's effects and event handlers, and there is
 * no DOM or renderer in this suite to drive them through. What is checkable
 * without one is the STRUCTURE, and structure is exactly what all three
 * regressions were - a branch that returned instead of answering, a set that was
 * not in a guard, a state write with no staleness check. Each check below names
 * the failure it exists to catch, and each one is verified to fail when the
 * corresponding line is removed.
 *
 * 1. A CERTIFICATE PROMPT THAT LANDS AFTER THE PANE IS GONE IS REJECTED. The
 *    pane's teardown answers the id it recorded, and the id is recorded INSIDE
 *    the prompt handler - so a handler that returns early on `!alive` records
 *    nothing and the teardown has nothing to answer. The window is the TCP
 *    connect plus the TLS handshake, and closing a tab that says "Connecting…"
 *    is an ordinary thing to do. Behind an unanswered prompt the backend's
 *    verifier is parked on its full confirm timeout, holding the socket, the
 *    in-flight handshake and - because it blocks - a displaced runtime thread,
 *    once per open/close cycle. `rdp_open` has not returned, so no session id
 *    exists and `rdp_close` cannot help: the rejection is the only way out.
 *
 * 2. EVERY HELD SET IS COVERED BY `releaseAll`. A key with no scancode goes out
 *    as `unicodeDown`, so it never reaches `heldKeys`; while that was the only
 *    record, `releaseAll` saw nothing held on blur and sent no marker at all.
 *    The stranded character then stays pressed in the backend's own record, and
 *    since `Database::apply` suppresses no-op transitions its next real press
 *    emits nothing either - a key gone dead rather than merely stuck. So the
 *    check is not "is there a unicode set" but the general form: every held set
 *    the pane declares is in `releaseAll`'s guard, cleared by it, and cleared
 *    when a redial resets state - which also fails for a FOURTH set added later
 *    and forgotten. The forward-looking half ("a new press-side kind records
 *    what it pressed") reads the STATEMENT LIST the write sits in, not a fixed
 *    number of characters behind it: with comments stripped, the 220 this used
 *    to look back reached out of `unicodeDown`'s own branch into `keyDown`'s and
 *    borrowed its `heldKeys.current.add`, so deleting the unicode record passed.
 *
 * 3. A TEST PROBE CANNOT WRITE TO A ROW IT NO LONGER BELONGS TO. The merged host
 *    editor (`HostEditorDialog`, 6d - this used to be `RdpConnectionDialog`) is
 *    mounted persistently once latched and the trust prompt is global, so
 *    closing the dialog neither cancels a probe nor hides its question: row A ->
 *    Test -> cancel -> open row B -> answer, and an ungated
 *    `setPinnedFingerprint` writes A's certificate (or SSH host key) into B's
 *    form state, which Save then persists onto B. It fails closed (B's next
 *    connect aborts as a mismatch) but it is a pinned key on a row the user
 *    never tested.
 *
 *    One `runTest` and one `onTrusted` serve both protocols now, and the two
 *    success writes are reached through their OWN arm of the protocol branch
 *    rather than by searching for `kind: "ok"` - which occurs twice, so a single
 *    search examined the SSH write and the RDP one could lose its guard in
 *    silence. The two pin writes are gated on DIFFERENT things and the split is
 *    what this section pins: the form's pin on the row (unsaved, visible,
 *    disposed of by Cancel, so it may describe an address being proposed), the
 *    saved record's pin on the address that record names (persistent, and a pin
 *    destroyed by a probe of another machine cannot be recovered).
 *    `host-editor-verify.ts` §3 owns that address rule in full; what is here is
 *    that the two guards do not collapse into one.
 *
 * 4. THE `pagehide` BACKSTOP ANSWERS BOTH PROTOCOLS. `HostKeyPromptDialog` is
 *    shared, so its backstop fires for an SSH host key as well as an RDP
 *    certificate. That is deliberate - `ssh_open` waits on the same 120 seconds
 *    holding the same mid-handshake socket - and it is pinned here because it
 *    reads like an accident of sharing, so the obvious "tidy-up" is to scope it
 *    back to certificates. This check makes that argue with the comment first.
 *
 * Two things every check below depends on, and both are load-bearing rather than
 * tidiness.
 *
 * COMMENTS ARE REMOVED FIRST. Every guard here is described in prose directly
 * above itself, in detail, in the same identifiers: "an ungated write puts A's
 * certificate into B's pin state" satisfies a search for the guard it describes.
 * A sibling script's whole suite passed against `const keepPin = true; // was:
 * const keepPin = !existing || existing.host === host;` for exactly that reason,
 * so trailing comments go as well as whole-line ones - and the stripper is
 * quote-aware, because a `//` inside a string literal is not a comment.
 *
 * GUARD SCOPE IS READ BY WALKING BRACES, not by measuring distance. Two proxies
 * for "this write is inside that guard" have now failed in this file. A fixed
 * 90-character lookback found the PREVIOUS statement's guard and called a
 * deliberately ungated write gated. The `;`-counting rule that replaced it
 * passed BOTH halves of section [3] - the positive AND the negative - against
 * the exact regression the negative half exists to catch, because a write that
 * is the second statement inside a guard has a `;` behind it and one that is the
 * first does not. Section [0] holds the replacements to samples whose answers
 * are known: a structural check nobody has watched fail is a comment.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

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

/**
 * The source between two anchors, or "" if either is missing.
 *
 * Anchored on code rather than line numbers so an edit above does not move the
 * region, and the "region was found" check below is what catches an anchor that
 * has been renamed out from under this file - otherwise every check over an
 * empty string would pass for the wrong reason.
 */
function between(src: string, from: string, to: string): string {
  const start = src.indexOf(from);
  if (start < 0) return "";
  const end = src.indexOf(to, start + from.length);
  if (end < 0) return "";
  return src.slice(start, end);
}

/**
 * A line with its trailing `//` comment removed, string literals respected.
 *
 * Quote-aware rather than a regex because a `//` inside a string is not a
 * comment. An apostrophe in unquoted JSX text opens a quote state that never
 * closes, which loses the strip for that one line - it fails towards keeping
 * text, never towards deleting code.
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
 * The same source with comments removed. The docblock's first "load-bearing"
 * note is the why; the shape is `host-editor-verify.ts`'s, deliberately, so the
 * two files cannot drift into disagreeing about what counts as code.
 */
function stripComments(src: string): string {
  return src
    .split("\n")
    .filter((line) => {
      const t = line.trim();
      return !(t.startsWith("//") || t.startsWith("/*") || t.startsWith("*"));
    })
    .map(stripLineComment)
    .join("\n");
}

/**
 * Does the `{` at `brace` open a statement list, or an object literal?
 *
 * `) {` is an `if`/`for`/`while`/function, `> {` is an arrow body, and
 * `;`/`{`/`}` mean the brace follows a statement. `(`, `,`, `:`, `=`, `[` and `$`
 * all introduce a VALUE, so the brace opens a literal and anything inside it is
 * an argument rather than a statement. The distinction is what lets a check name
 * a field of an argument object (`kind: "keyDown"`) and still be told which
 * BLOCK the call it belongs to sits in.
 */
function opensABlock(src: string, brace: number): boolean {
  let i = brace - 1;
  while (i >= 0 && /\s/.test(src[i])) i--;
  if (i < 0) return true;
  const prev = src[i];
  if (")>;{}".includes(prev)) return true;
  const word = /(\w+)$/.exec(src.slice(0, i + 1))?.[1] ?? "";
  return word === "else" || word === "try" || word === "do" || word === "finally";
}

/**
 * Does the `}` at `brace` close a statement list?
 *
 * Its partner is found first, because right-to-left a closing brace says nothing
 * about what it closes: `focus({ ok: true });` and `if (a) { other(); }` end the
 * same way, and only one of them ends a STATEMENT. Called only at depth 0, where
 * the answer changes an outcome.
 */
function closesABlock(src: string, brace: number): boolean {
  let depth = 0;
  for (let i = brace; i >= 0; i--) {
    if (src[i] === "}") depth++;
    else if (src[i] === "{") {
      depth--;
      if (depth === 0) return opensABlock(src, i);
    }
  }
  return false;
}

/**
 * The innermost statement list containing `at`: where its block opens, and the
 * text of the list up to `at` with nested groups elided.
 *
 * Walking out over object-literal braces is what makes a needle inside an
 * ARGUMENT (`kind: "mouseDown"`) report the block its call sits in. Eliding
 * nested groups, and standing a `;` where a nested BLOCK closed, is what stops
 * `if (a) { record(); }\nsend(…)` from reading as though `send` were inside that
 * guard or as though `record()` were a statement of its own list. Both are
 * merely text that precedes it - which is all a slice could ever report, and is
 * exactly how a fixed lookback lies.
 */
function scopeOf(src: string, at: number): { block: number; before: string } {
  let before = "";
  let depth = 0;
  for (let i = at - 1; i >= 0; i--) {
    const c = src[i];
    if (c === "}") {
      if (depth === 0 && closesABlock(src, i)) before = ";" + before;
      depth++;
      continue;
    }
    if (c === "{") {
      if (depth > 0) {
        depth--;
        continue;
      }
      if (opensABlock(src, i)) return { block: i, before };
      continue;
    }
    if (depth === 0) before = c + before;
  }
  return { block: -1, before };
}

/** The statements of that list, with the partial one `at` itself sits in dropped. */
function statementsBefore(src: string, at: number): string[] {
  const parts = scopeOf(src, at).before.split(";");
  // Whatever follows the last `;` is the statement in progress - the one `at` is
  // inside - however far into it `at` happens to point.
  parts.pop();
  return parts.map((s) => s.trim()).filter((s) => s.length > 0);
}

/**
 * The condition of the innermost `if` whose block `needle` sits inside, or of the
 * `if` attached to its own statement, or "" if neither exists.
 *
 * This is `host-editor-verify.ts`'s `guardFor` with its one-hop limit removed,
 * and the divergence is deliberate rather than drift: one hop reports NOTHING
 * for a write that is the second statement inside a correct guard, which is a
 * false alarm against a legitimate reordering. Walking out is only safe because
 * every assertion below compares the condition it gets against the one that has
 * to be there - a guard from further out than intended is not that string and
 * fails. Asking merely whether SOME guard exists is the unsound way to use this.
 *
 * The needle must name a STATEMENT (`setTest({`, not `kind: "ok"`) or the
 * statement text read back is a fragment of an argument list.
 */
function enclosingGuard(region: string, needle: string): string {
  let at = region.indexOf(needle);
  if (at < 0) return "";
  // Bounded rather than `for (;;)`: eight levels of nesting is already more than
  // anything here has, and a bound cannot spin on a source this does not expect.
  for (let level = 0; level < 8; level++) {
    const { block, before } = scopeOf(region, at);
    const parts = before.split(";");
    const stmt = (parts[parts.length - 1] ?? "")
      .trim()
      // A statement may open with an operator keyword before the call a check
      // names (`void pinFingerprint(…)`), and that is still the same statement.
      // Dropped only at the END, so it cannot swallow a guard.
      .replace(/\b(?:void|await|return)$/, "")
      .trim();
    const own = /^if \((.*)\)$/s.exec(stmt);
    if (own) return own[1];
    // Some other statement head - a `for`, an arrow declaration, a call whose
    // argument list this needle is inside. Not a guard, and not something to
    // look past either.
    if (stmt.length > 0 || block < 0) return "";
    at = block;
  }
  return "";
}

/** What `const <ident> = …;` assigns, so a check can ask what a guard's operands
 *  ARE rather than assuming the names they go by. */
function assignedIn(region: string, ident: string): string {
  const m = new RegExp(`const ${ident} = ([^;]*);`).exec(region);
  return m ? m[1].trim() : "";
}

function count(src: string, re: RegExp): number {
  return [...src.matchAll(re)].length;
}

const identifiers = (src: string): string[] =>
  [...src.matchAll(/[A-Za-z_$][\w$]*/g)].map((m) => m[0]);

const paneRaw = read("src/modules/rdp/RdpPane.tsx");
const editorRaw = read("src/modules/hosts/HostEditorDialog.tsx");
const promptDialogRaw = read("src/modules/ssh/HostKeyPromptDialog.tsx");
const paneSrc = stripComments(paneRaw);
const editorSrc = stripComments(editorRaw);
const promptDialogSrc = stripComments(promptDialogRaw);

// ---------------------------------------------------------------------------
console.log("[0] the helpers the checks below depend on");
{
  check(
    "enclosingGuard reads the condition of a block-bodied guard",
    enclosingGuard("if (a === b) {\n  writeIt();\n}\n", "writeIt()") === "a === b",
    enclosingGuard("if (a === b) {\n  writeIt();\n}\n", "writeIt()"),
  );
  check(
    "and of a single-statement guard",
    enclosingGuard("if (a === b) writeIt();\n", "writeIt()") === "a === b",
  );
  check(
    "and of a guard whose body opens with void, which is how a fire-and-forget write reads",
    enclosingGuard("if (a === b) {\n  void writeIt();\n}\n", "writeIt()") === "a === b",
    enclosingGuard("if (a === b) {\n  void writeIt();\n}\n", "writeIt()"),
  );
  // The two failures this section exists to keep out. The fixed lookback's was a
  // false PASS: it saw the previous statement's guard and called an ungated write
  // gated. The `;`-rule's went the other way - it reported a correctly guarded
  // SECOND statement as ungated, and the negative assertion built on that then
  // passed against the exact regression it names.
  check(
    "but an unguarded write does not borrow the guard of the statement above it",
    enclosingGuard("if (a === b) other();\nwriteIt();\n", "writeIt()") === "",
    enclosingGuard("if (a === b) other();\nwriteIt();\n", "writeIt()"),
  );
  check(
    "not even when that write opens with void",
    enclosingGuard("if (a === b) other();\nvoid writeIt();\n", "writeIt()") === "",
    enclosingGuard("if (a === b) other();\nvoid writeIt();\n", "writeIt()"),
  );
  check(
    "while a write that IS the second statement inside a guard still reports it",
    enclosingGuard("if (a === b) {\n  other();\n  void writeIt();\n}\n", "writeIt()") === "a === b",
    enclosingGuard("if (a === b) {\n  other();\n  void writeIt();\n}\n", "writeIt()"),
  );
  check(
    "and one AFTER that guard's block closes does not, however close it reads",
    enclosingGuard("if (a === b) {\n  other();\n}\nwriteIt();\n", "writeIt()") === "",
    enclosingGuard("if (a === b) {\n  other();\n}\nwriteIt();\n", "writeIt()"),
  );
  check(
    "nor does one inside a block the guard does not control",
    enclosingGuard(
      "if (a === b) {\n  other();\n}\nfor (const x of xs) {\n  writeIt();\n}\n",
      "writeIt()",
    ) === "",
    enclosingGuard(
      "if (a === b) {\n  other();\n}\nfor (const x of xs) {\n  writeIt();\n}\n",
      "writeIt()",
    ),
  );
  check(
    "the INNERMOST guard is the one reported, not the outermost",
    enclosingGuard("if (a) {\n  if (b === c) {\n    writeIt();\n  }\n}\n", "writeIt()") ===
      "b === c",
    enclosingGuard("if (a) {\n  if (b === c) {\n    writeIt();\n  }\n}\n", "writeIt()"),
  );
  check(
    "an unguarded write in a bare block reports nothing",
    enclosingGuard("{\n  writeIt();\n}\n", "writeIt()") === "",
  );
  check(
    "a missing needle reports nothing rather than throwing",
    enclosingGuard("x();\n", "writeIt()") === "",
  );

  const sample = 'if (a) {\n  mark();\n  send({ kind: "x" });\n}\n';
  check(
    "statementsBefore walks out of an argument position to the block the call is in",
    statementsBefore(sample, sample.indexOf('kind: "x"')).join(" | ") === "mark()",
    statementsBefore(sample, sample.indexOf('kind: "x"')),
  );
  const sibling = 'if (a) { mark(); }\nsend({ kind: "x" });\n';
  check(
    "and does not report a statement from a nested block that merely precedes it in the text",
    !statementsBefore(sibling, sibling.indexOf('kind: "x"')).join(" | ").includes("mark()"),
    statementsBefore(sibling, sibling.indexOf('kind: "x"')),
  );
  const literal = 'f({ kind: "yDown" });\nsend({ kind: "x" });\n';
  check(
    "a nested literal's fields are not statements of the list either",
    !statementsBefore(literal, literal.indexOf('kind: "x"')).join(" | ").includes("yDown"),
    statementsBefore(literal, literal.indexOf('kind: "x"')),
  );
  const two = "a();\nb();\n";
  check(
    "and the statement the needle itself sits in is not reported as preceding it",
    statementsBefore(two, two.indexOf("b()")).join(" | ") === "a()",
    statementsBefore(two, two.indexOf("b()")),
  );
  const arrow = "h = (e) => {\n  mark(e);\n  send({ k: 1 });\n}";
  check(
    "an arrow body counts as a statement list, which is what every handler here is",
    statementsBefore(arrow, arrow.indexOf("k: 1")).join(" | ") === "mark(e)",
    statementsBefore(arrow, arrow.indexOf("k: 1")),
  );

  check(
    "stripComments drops a comment that merely NAMES a guard",
    !stripComments("// if (a === b)\nwriteIt();").includes("a === b"),
  );
  check(
    "and drops it when it TRAILS the line that removed the guard",
    !stripComments("const keep = true; // was: keep = a === b;").includes("a === b"),
    stripComments("const keep = true; // was: keep = a === b;"),
  );
  check(
    "but leaves a // that is inside a string, which is not a comment",
    stripComments('const s = "a // b";').includes("a // b"),
  );
  check("and keeps the code around it", stripComments("// x\nwriteIt();").includes("writeIt();"));
  for (const [path, raw, stripped] of [
    ["RdpPane.tsx", paneRaw, paneSrc],
    ["HostEditorDialog.tsx", editorRaw, editorSrc],
    ["HostKeyPromptDialog.tsx", promptDialogRaw, promptDialogSrc],
  ] as const) {
    check(
      `${path} survived stripping, and something was removed from it`,
      stripped.length > 1000 && stripped.length < raw.length,
      [stripped.length, raw.length],
    );
  }

  check(
    "assignedIn reports what a local was assigned",
    assignedIn("const a = b?.c;", "a") === "b?.c",
  );
  check("and nothing for a local it cannot find", assignedIn("const a = b;", "z") === "");
}

// ---------------------------------------------------------------------------
console.log("\n[1] a certificate prompt raised after the teardown is ANSWERED");
{
  const handler = between(paneSrc, "onCertPrompt: (prompt) => {", "onResize:");
  check("the cert-prompt handler was found", handler.length > 100, handler.length);

  const guard = handler.indexOf("if (!alive)");
  const records = handler.indexOf("promptId = prompt.promptId");
  check("it guards on liveness", guard >= 0);
  check("and records the id for the teardown to answer", records > guard, [guard, records]);

  // The whole finding in one assertion: the rejection is what the liveness
  // branch DOES, and it has to be, because that branch runs before the id exists
  // anywhere the teardown can reach.
  check(
    "the liveness branch rejects the prompt itself",
    enclosingGuard(handler, "confirmRdpCert(prompt.promptId, false)") === "!alive",
    enclosingGuard(handler, "confirmRdpCert(prompt.promptId, false)"),
  );
  check(
    "and does not merely return, which would drop it with nobody to answer",
    !/if \(!alive\) return;/.test(handler),
  );
}
{
  // The other half of the invariant, unchanged by this fix and pinned so it
  // stays: a prompt the pane DID record is answered on the way out, and the
  // tunnel's host-key questions with it.
  const teardown = between(paneSrc, "return () => {\n      alive = false;", "}, [connectionId");
  check("the session effect's teardown was found", teardown.length > 100, teardown.length);
  check(
    "a recorded certificate prompt is abandoned on the way out",
    /if \(promptId\) useHostKeyPrompt\.getState\(\)\.abandon\(promptId\);/.test(teardown),
  );
  check(
    "and so is every tunnel host-key prompt this attempt raised",
    /for \(const id of sshPromptIds\) useHostKeyPrompt\.getState\(\)\.abandon\(id\);/.test(
      teardown,
    ),
  );
}

// ---------------------------------------------------------------------------
console.log("\n[2] every held set the pane keeps is released on blur");
{
  // Whatever they are called and however many there are. A fourth set added
  // later and left out of any of the three places below fails this.
  const held = [...paneSrc.matchAll(/const (held\w+) = useRef</g)].map((m) => m[1]);
  check("the pane's held sets were found", held.length >= 3, held);
  check("including one for keys with no scancode", held.includes("heldUnicode"), held);

  const releaseAll = between(
    paneSrc,
    "const releaseAll = useCallback(() => {",
    "}, [queueInputNow]);",
  );
  check("releaseAll was found", releaseAll.length > 50, releaseAll.length);
  // The early return is the bug's location: it decides whether the marker is
  // sent at all, and a set missing from it is a set that cannot trigger one.
  const guard = between(releaseAll, "if (", "{\n      return;");
  check("its early return guard was found", guard.length > 20, guard);
  for (const set of held) {
    check(`${set} is in the guard, so holding only it still sends the marker`, guard.includes(set));
    check(`${set} is cleared by releaseAll`, releaseAll.includes(`${set}.current.clear()`));
  }

  // A redial starts from nothing held: the server has a fresh session and the
  // old record would make the first release of a carried-over key a no-op.
  const reset = between(paneSrc, 'setStatus({ kind: "connecting" });', "void (async () => {");
  check("the redial reset was found", reset.length > 50, reset.length);
  for (const set of held) {
    check(`${set} is cleared when the pane redials`, reset.includes(`${set}.current.clear()`));
  }

  // Forward-looking: a new "down" input kind must record what it pressed, or
  // `releaseAll` cannot know about it however many sets exist.
  //
  // Ctrl+Alt+Del is the one exemption, and a real one rather than an oversight:
  // it synthesises its own matching ups in the same batch, so nothing is ever
  // left held for a blur to release. `rdp-frame-verify.ts` is where that pairing
  // is asserted ("released in reverse", "nothing is left held"), so skipping it
  // here does not leave it unchecked.
  const cadFrom = paneSrc.indexOf("const sendCtrlAltDel = useCallback(");
  const cadTo = paneSrc.indexOf("}, [queueInput]);", cadFrom);
  check(
    "the Ctrl+Alt+Del synthesiser was found, so the exemption is real",
    cadFrom >= 0 && cadTo > cadFrom,
    [cadFrom, cadTo],
  );
  const downKinds = [...paneSrc.matchAll(/kind: "(\w+Down)"/g)]
    .map((m) => ({ kind: m[1], at: m.index ?? 0 }))
    .filter(({ at }) => at < cadFrom || at > cadTo);
  check(
    "the pane's press-side input kinds were found",
    downKinds.length >= 3,
    downKinds.map((d) => d.kind),
  );
  const isRecord = (stmt: string) => /held\w+\.current\.add\(/.test(stmt);
  for (const { kind, at } of downKinds) {
    // The statement list this write sits in, not a window of characters behind
    // it: the record is taken before the event is queued, which is a fact about
    // the block and not about how much prose the handler carries.
    const before = statementsBefore(paneSrc, at);
    check(`${kind} records what it pressed in a held set`, before.some(isRecord), before.slice(-3));
    // Adjacency, deliberately: a fourth kind bolted on AFTER an existing
    // record/queue pair sits in the same block as that record and would borrow
    // it. The pairing is one statement wide in all three handlers, and a
    // refactor that separates them should have to say why here.
    check(
      `and takes that record immediately before queueing ${kind}, not somewhere above it`,
      isRecord(before[before.length - 1] ?? ""),
      before.slice(-2),
    );
  }
}

// ---------------------------------------------------------------------------
console.log("\n[3] a Test probe cannot write to a row it no longer belongs to");
{
  check(
    "the editor tracks the target it is showing right now",
    /applied\.current = token;/.test(editorSrc),
  );

  const runTest = between(editorSrc, "const runTest = async () => {", "const save = async () => {");
  check("runTest was found", runTest.length > 500, runTest.length);
  check("a probe captures the token it started on", /const probeToken = token;/.test(runTest));

  // The row guard by what it IS, not by the name it goes by: a callable, so it
  // is evaluated when the answer arrives rather than captured with the probe,
  // comparing the target on screen against that capture. Reading the name out of
  // the source is also what keeps a rename from turning the four guard checks
  // below into searches for a string no longer in the file.
  const rowGuard =
    /const (\w+) = \(\) => applied\.current === probeToken;/.exec(runTest)?.[1] ?? "";
  check(
    "and the row guard compares the target on screen against that capture, live",
    rowGuard.length > 0,
    runTest.slice(0, 600),
  );
  const onRow = `${rowGuard}()`;

  const onTrusted = between(runTest, "const onTrusted = (fingerprint: string) => {", "\n    try {");
  check("its trust callback was found", onTrusted.length > 50, onTrusted.length);

  check(
    "the FORM's pin is written only while the editor is still on the row that was probed",
    enclosingGuard(onTrusted, "setPinnedFingerprint(fingerprint)") === onRow,
    enclosingGuard(onTrusted, "setPinnedFingerprint(fingerprint)"),
  );

  // The other half of the split. The saved row is not the row on screen and must
  // not be gated as if it were: `probeHostId` is the row that was tested, so the
  // pin belongs there however long the answer took - but only if that record
  // still names the machine that answered.
  const storeGuard = enclosingGuard(onTrusted, "pinFingerprint(");
  check("the SAVED row's pin is guarded too", storeGuard.length > 0, onTrusted.trim());
  check("by an equality rather than a bare presence test", storeGuard.includes("==="), storeGuard);
  const operands = identifiers(storeGuard).map((id) => ({ id, from: assignedIn(runTest, id) }));
  const sources = operands.map((o) => o.from);
  check("on the address the SAVED record names", sources.includes("existing?.host"), operands);
  check("against the address the probe dialled", sources.includes("shared.host.trim()"), operands);
  check(
    "and NOT on the row the form is showing, which the probe has already outlived",
    rowGuard.length > 0 && !storeGuard.includes(rowGuard),
    storeGuard,
  );

  // Both protocol arms, reached separately. `kind: "ok"` occurs twice, so one
  // search over `runTest` examined the SSH write and left the RDP guard
  // unchecked; the `setTest` count per arm is what keeps a drifted anchor from
  // quietly merging them again.
  const arms = [
    {
      what: "the SSH probe's success",
      region: between(
        runTest,
        'if (protocol === "ssh") {',
        "const credential = rdpCredentialForTest(",
      ),
      kind: 'kind: "ok"',
    },
    {
      what: "the RDP probe's success",
      region: between(runTest, "const result = await runRdpProbe(", "} catch (e) {"),
      kind: 'kind: "ok"',
    },
    {
      what: "either probe's failure",
      region: between(runTest, "} catch (e) {", "\n  };"),
      kind: 'kind: "fail"',
    },
  ];
  for (const { what, region, kind } of arms) {
    check(`${what} arm was found`, region.length > 50, region.length);
    check(
      `${what} arm holds exactly one result write, so this is that arm's own`,
      count(region, /setTest\(/g) === 1,
      count(region, /setTest\(/g),
    );
    check(`${what} arm writes ${kind}`, region.includes(kind), region.trim().slice(0, 120));
    check(
      `${what} is reported only while the editor is still on the row that was probed`,
      enclosingGuard(region, "setTest({") === onRow,
      enclosingGuard(region, "setTest({"),
    );
  }

  // The synchronous one at the top of the probe is deliberately not gated: it
  // runs before any await, so it cannot be stale.
  check(
    "the probe's own 'running' state is not gated, being written before any await",
    enclosingGuard(runTest, 'setTest({ kind: "running" })') === "",
    enclosingGuard(runTest, 'setTest({ kind: "running" })'),
  );
}

// ---------------------------------------------------------------------------
console.log("\n[4] the pagehide backstop answers BOTH protocols' prompts");
{
  const backstop = between(promptDialogSrc, "const abandonAll = () => {", "};");
  check("the backstop was found", backstop.length > 50, backstop.length);
  check(
    "it walks the whole queue",
    /for \(const p of \[\.\.\.pending\]\) abandon\(p\.promptId\);/.test(backstop),
  );
  // The decision this pins: an SSH host key is answered on the way out too, not
  // only an RDP certificate. Scoping it to `certificate` would leave `ssh_open`
  // parked on its own 120-second wait for the same reason, so a later narrowing
  // has to argue with the comment above the effect rather than slip through.
  // Comments are gone by here, so the prose that explains the decision cannot be
  // mistaken for the filter it is arguing against.
  check(
    "and does not filter on the field that distinguishes the two",
    !backstop.includes("certificate"),
    backstop.trim(),
  );
  check(
    "on pagehide rather than this component's unmount, which live panes survive",
    /addEventListener\("pagehide", abandonAll\)/.test(promptDialogSrc) &&
      !/return \(\) => abandonAll\(\)/.test(promptDialogSrc),
  );
}

console.log(failed === 0 ? "\nAll rdp-lifetime checks passed." : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
