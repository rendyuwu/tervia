/**
 * Self-check: a connect that failed for a LOCAL reason must not
 * enter the reconnect ladder.
 * Run: `npx tsx scripts/ssh-retry-verify.ts`.
 *
 * The bug: a host saved with no password (a legal state since the save
 * validation was relaxed) was clicked to connect, and the pane spent 1s + 3s + 7s
 * failing three more times with the identical message before it would let the
 * user do anything. Nothing about the saved host changes while the pane waits,
 * so every one of those attempts was known-doomed at the moment it was
 * scheduled.
 *
 * This is a DIFFERENT question from `scripts/ssh-exit-verify.ts`'s, and the
 * distinction is the whole point: that file is about a shell channel that
 * existed and then ended, so it flows through `decideSshEnding`. The failure
 * here happens before any channel exists - `openSsh` rejects, `finishSsh` is
 * never called, and `decideSshEnding` never runs. The retry for it is scheduled
 * from the two catch blocks around `openPtyForSession` instead, which is where
 * the fourth category has to be honoured.
 *
 * What is checked here:
 *   1. `canAuthenticate` - the pre-dial guard, against the same truth table the
 *      backend's `has_credential` is tested with.
 *   2. `classifySshConnectFailure` - structural (an error TYPE), so it cannot
 *      rot the way a list of message prefixes would.
 *   3. `decideSshConnectFailure` - only the transport category reconnects, and
 *      the two categories stay DISTINCT.
 *   4. `hostKeyRefused` - an ANSWER decides, and any refusal in a chain counts.
 *   5. Rust/TS parity for the mirrored guard and its wording.
 *   6. Source text: at both catch sites the park arm lexically CONTROLS the
 *      ladder call - it is a statement of the same block and it terminates it -
 *      and the pre-flight block marks what it throws. Pure functions that nobody
 *      calls fix nothing, and a gate that is merely NEAR the ladder is not a
 *      gate (see the section's own header).
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  canAuthenticate,
  classifySshConnectFailure,
  decideSshConnectFailure,
  hostKeyRefused,
  SshLocalConnectError,
  type SshAuthAttempt,
} from "../src/modules/terminal/lib/ssh-exit-decision";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const readRaw = (rel: string) => readFileSync(join(repoRoot, rel), "utf8");

/**
 * Comment-stripped, quote-aware - the convention every source-text check in this
 * repo follows (ssh-exit-verify.ts, host-editor-verify.ts, rdp-lifetime-verify.ts).
 *
 * Not optional politeness: a source-text check that reads raw text goes GREEN
 * over `// was: decideSshConnectFailure(...)`, so deleting the gate and leaving
 * its corpse in a comment would pass. Every read below goes through this.
 *
 * `quotes` is parameterised because the two languages need different sets. TS
 * takes `"`, `'` and backtick. Rust must take ONLY `"`: a lifetime (`'static`)
 * or a char literal opens an apostrophe that never closes, and the scanner would
 * swallow the rest of the line - which for `has_credential('a ...)` would hide
 * real code from a check rather than reveal it.
 */
// No JSX-comment branch here, deliberately. `readTs` strips only
// `ssh-session.ts` (a `.ts` file), and `readRust` strips Rust source - neither
// language gives `{/* ... */}` any meaning, so this stripper cannot be fooled
// the way `host-editor-verify.ts`'s was (fixed in that file's own
// `stripComments` - copy the branch from there, and not the lazy form
// `\{\s*\/\*[\s\S]*?\*\/\s*\}`, which is not a substitute: it can still cross
// an intervening `*/` while hunting for one followed by `}`) and in
// `vault-editor-verify.ts`'s. If this file is ever pointed at a `.tsx`
// file, that branch has to be added first - to the `quotes` two-argument form
// below, not a copy-pasted single-argument one.
function stripComments(src: string, quotes: string): string {
  const stripLine = (line: string): string => {
    let quote = "";
    for (let i = 0; i < line.length; i++) {
      const c = line[i];
      if (quote) {
        if (c === "\\") i++;
        else if (c === quote) quote = "";
        continue;
      }
      if (quotes.includes(c)) {
        quote = c;
        continue;
      }
      if (c === "/" && line[i + 1] === "/") return line.slice(0, i);
    }
    return line;
  };
  return src
    .split("\n")
    .filter((line) => {
      const t = line.trim();
      return !(t.startsWith("//") || t.startsWith("/*") || t.startsWith("*"));
    })
    .map(stripLine)
    .join("\n");
}

/** Every source-text read below is comment-free by construction. */
const readTs = (rel: string) => stripComments(readRaw(rel), "\"'`");
const readRust = (rel: string) => stripComments(readRaw(rel), '"');

let failed = 0;
function assert(cond: boolean, msg: string): void {
  if (cond) console.log(`  ok: ${msg}`);
  else {
    console.error(`  FAIL: ${msg}`);
    failed++;
  }
}

console.log("[canAuthenticate] any one credential is enough to be worth dialling");
for (const [label, attempt] of [
  ["ssh-agent alone", { useAgent: true }],
  ["password alone", { password: "pw" }],
  ["private key alone", { privateKey: "-----BEGIN..." }],
] as [string, SshAuthAttempt][]) {
  assert(canAuthenticate(attempt), `${label} -> dial`);
}

console.log("\n[canAuthenticate] nothing configured is the state that must not dial");
assert(!canAuthenticate({}), "no agent, no password, no key -> refuse before dialling");
assert(
  !canAuthenticate({ useAgent: false }),
  "an explicit useAgent:false with nothing else is still nothing to authenticate with",
);
// `resolveSshAuth` maps an empty secret to `undefined`, never "", so this row is
// about agreeing with the backend rather than about a reachable state: the
// backend's `has_credential` tests presence (`is_some`), so an empty string is
// a credential to SEND and the server decides. Testing emptiness on one side
// only would make the two guards disagree about the same input.
console.log("\n[canAuthenticate] presence, not emptiness - matching the backend guard");
assert(
  canAuthenticate({ password: "" }),
  'password "" is present, so it is dialled (server\'s call)',
);
assert(canAuthenticate({ privateKey: "" }), 'private key "" is present, so it is dialled');

console.log("\n[classifySshConnectFailure] the category rides on the error TYPE, not its wording");
{
  const local = classifySshConnectFailure(new SshLocalConnectError("ssh: no credentials: …"), "m");
  assert(local.kind === "local" && local.message === "m", "SshLocalConnectError -> local");

  // The exact regression a message match would introduce: reword the backend's
  // string, or add a new local failure, and a prefix list silently mis-files it.
  // Here the wording is irrelevant by construction, so prove it: the same text
  // classifies differently depending only on how it was thrown.
  const sameWordsPlainError = classifySshConnectFailure(
    new Error("ssh: no credentials: …"),
    "ssh: no credentials: …",
  );
  assert(
    sameWordsPlainError.kind === "transport",
    "the identical message thrown as a plain Error is NOT local - the type decides, not the text",
  );
}

console.log("\n[classifySshConnectFailure] anything the frontend did not raise stays transport");
for (const [label, thrown] of [
  ["a plain Error from the bridge", new Error("ssh: connect failed: connection refused")],
  ["a bare string rejection", "ssh: connect to h:22 timed out"],
  ["a non-Error object", { message: "ssh: open tunnel to h:22 failed" }],
  ["null", null],
] as [string, unknown][]) {
  assert(
    classifySshConnectFailure(thrown, "msg").kind === "transport",
    `${label} -> transport (still reconnect-eligible)`,
  );
}

console.log("\n[decideSshConnectFailure] only the transport category enters the ladder");
{
  const parked = decideSshConnectFailure({ kind: "local", message: "cfg" });
  assert(parked.action === "park" && parked.message === "cfg", "local -> park, message preserved");
  const laddered = decideSshConnectFailure({ kind: "transport", message: "drop" });
  assert(
    laddered.action === "reconnect" && laddered.message === "drop",
    "transport -> reconnect, message preserved",
  );
  // The collapse guard, same shape as ssh-exit-verify.ts's: a change that mapped
  // both categories onto one action would leave every assertion above passing
  // for one of them and still reintroduce the bug.
  assert(parked.action !== laddered.action, "the two categories map to two DISTINCT actions");
}

// ============================================================================
// HOST KEYS: which of them the frontend may call its own fault.
//
// The rejected shape is the one 76da6a5 shipped: `asked > trusted`, compared at
// failure time. It reads "a prompt was raised and never trusted" as "the user
// refused", and those are different worlds - a link that drops while the dialog
// is still on screen leaves a prompt raised and untrusted with nobody having
// refused anything, and parking it kills the ladder for exactly the blip the
// ladder exists for. The row that pins it is the empty one.

console.log("\n[hostKeyRefused] an ANSWER decides, and any refusal in a chain counts");
{
  // THE misfiling case, behaviourally: prompts were raised (that is why this is
  // even asked) and none were answered, because the transport died underneath
  // the dialog. Nothing was refused, so nothing is local, so the ladder stands.
  assert(
    !hostKeyRefused([]),
    "no answer at all -> NOT a refusal (the link dropped while the prompt was still on screen)",
  );
  assert(!hostKeyRefused([true]), "the one key was trusted -> not a refusal");
  assert(hostKeyRefused([false]), "the one key was refused -> a refusal");
  // The ProxyJump property the counters were protecting, kept: one question per
  // hop, and trusting the bastion says nothing about the target's key. Both
  // orders, because a latch that records the LAST answer passes one and fails
  // the other.
  assert(
    hostKeyRefused([true, false]),
    "bastion trusted, target refused -> still a refusal (a trust cannot mask it)",
  );
  assert(
    hostKeyRefused([false, true]),
    "target refused, then another hop trusted -> order does not change the verdict",
  );
  assert(!hostKeyRefused([true, true]), "every hop in the chain trusted -> not a refusal");
}

// ============================================================================
// RUST/TS PARITY: the pre-dial guard exists on both sides on purpose (the
// frontend needs it to CLASSIFY, the backend keeps it for its other callers -
// the forward tunnel and the host editor's Test probe). Two copies of a
// predicate is a drift risk, so the pairing is checked rather than trusted.

console.log("\n[parity] the backend guard and its frontend mirror agree");
{
  const rust = readRust("src-tauri/src/modules/ssh/session.rs");
  const ts = readTs("src/modules/terminal/lib/ssh-session.ts");

  const rustBody =
    /fn has_credential\([^)]*\)\s*->\s*bool\s*\{([\s\S]*?)\n\}/.exec(rust)?.[1] ?? "";
  assert(rustBody !== "", "found has_credential's body in session.rs");
  assert(
    /use_agent/.test(rustBody) && /password\.is_some\(\)/.test(rustBody),
    "the backend guard still tests PRESENCE (is_some), matching canAuthenticate above",
  );
  assert(
    !/is_empty\(\)|unwrap_or_default\(\)/.test(rustBody),
    "the backend guard has not been switched to an emptiness test the frontend does not mirror",
  );

  // Both call sites go through the one predicate. A third inline copy is how
  // the target and a jump hop start disagreeing about the same question.
  //
  // Counted INSIDE `connect` only. A whole-file count is not a check: the test
  // module below calls `has_credential` five more times, so deleting both real
  // call sites would still clear any file-wide threshold.
  const connectAt = rust.indexOf("pub async fn connect(");
  const connectOpen = rust.indexOf("{", connectAt);
  const connectBody =
    connectAt === -1 ? "" : rust.slice(connectOpen, matchingBrace(rust, connectOpen));
  assert(connectBody !== "", "found connect()'s body in session.rs");
  const callSites = connectBody.match(/has_credential\(/g) ?? [];
  assert(
    callSites.length === 2,
    `connect() asks the one predicate exactly twice - the target and each hop (found ${callSites.length})`,
  );
  assert(
    !/!\s*hop\.use_agent\s*&&/.test(rust),
    "the jump-hop guard no longer carries its own inline copy of the predicate",
  );

  const rustMsg = /const NO_CREDENTIALS_ERROR: &str = "([^"]*)"/.exec(rust)?.[1] ?? null;
  const tsMsg = /const NO_CREDENTIALS_MESSAGE = "([^"]*)"/.exec(ts)?.[1] ?? null;
  assert(rustMsg !== null, "found NO_CREDENTIALS_ERROR in session.rs");
  assert(tsMsg !== null, "found NO_CREDENTIALS_MESSAGE in ssh-session.ts");
  assert(
    rustMsg !== null && rustMsg === tsMsg,
    `the two sides tell the user the same sentence (rust=${JSON.stringify(rustMsg)}, ts=${JSON.stringify(tsMsg)})`,
  );
}

// ============================================================================
// SOURCE TEXT: the decision has to be CONSULTED, and it has to CONTROL the
// ladder. Both retry sites are in files that cannot be imported under plain node
// (ssh-session.ts reaches `window` transitively - see the header of
// ssh-exit-decision.ts), and neither exposes its catch block as a pure function,
// so this half is read rather than run.
//
// Read by SCOPE, never by distance. This section used to compare
// character indices ("the gate's text comes before the ladder's in this block"),
// and two mutants walked through it green:
//
//   * the park arm loses its `return`, so a local failure parks AND THEN walks
//     1s + 3s + 7s. Every index assertion still held. That is the bug restored
//     in full, passing the check written to catch it.
//   * `const decision = …; void decision; scheduleSshReconnect(…)`. The verdict
//     is computed and dropped on the floor; `gate < ladder` cannot notice, and
//     its own label claimed the ladder was gated.
//
// What is asserted instead: resolve the innermost statement list the ladder call
// belongs to, and require a `parkSshConnectFailure` arm that is a sibling
// statement of it, earlier in that same list, and that TERMINATES the list. No
// index is compared to another index anywhere below.

/** Index of the `}` matching the `{` at `openIdx`, or -1. */
function matchingBrace(src: string, openIdx: number): number {
  let depth = 0;
  for (let i = openIdx; i < src.length; i++) {
    if (src[i] === "{") depth++;
    else if (src[i] === "}") {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

/** Every offset of `needle`, in source order - search by all matches, not the
 *  first: one `indexOf` examines whichever occurrence happens to come first,
 *  which is ordering luck rather than a check. */
function allIndexes(src: string, needle: string): number[] {
  const out: number[] = [];
  for (let at = src.indexOf(needle); at !== -1; at = src.indexOf(needle, at + 1)) out.push(at);
  return out;
}

// ----------------------------------------------------------------------------
// The scope walker, ported from scripts/rdp-lifetime-verify.ts. The
// duplication is deliberate: these scripts exit on load, there is no scripts/lib to share
// from, and a third divergent copy of "which block is this in" is worse than a
// second identical one. The doc comments there carry the full reasoning.

/** Does the `{` at `brace` open a statement list rather than a value? `)`, `>`,
 *  `;`, `{`, `}` and the block keywords precede a BLOCK; `(`, `,`, `:`, `=`, `[`
 *  and `$` all introduce a value, so the brace opens a literal. */
function opensABlock(src: string, brace: number): boolean {
  let i = brace - 1;
  while (i >= 0 && /\s/.test(src[i])) i--;
  if (i < 0) return true;
  const prev = src[i];
  if (")>;{}".includes(prev)) return true;
  const word = /(\w+)$/.exec(src.slice(0, i + 1))?.[1] ?? "";
  return word === "else" || word === "try" || word === "do" || word === "finally";
}

/** Does the `}` at `brace` close a statement list? Its partner is found first,
 *  because right-to-left a closing brace says nothing about what it closes. */
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

/** The innermost statement list containing `at`: where its block opens (-1 at
 *  module scope), and the text of the list up to `at` with nested groups elided
 *  and a `;` standing where a nested BLOCK closed. */
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

/** The condition of the innermost `if` whose block contains `start`, or "". */
function guardAt(src: string, start: number): string {
  let at = start;
  if (at < 0) return "";
  // Bounded rather than `for (;;)`: eight levels is more nesting than anything
  // here has, and a bound cannot spin on a source this does not expect.
  for (let level = 0; level < 8; level++) {
    const { block, before } = scopeOf(src, at);
    const parts = before.split(";");
    const stmt = (parts[parts.length - 1] ?? "")
      .trim()
      .replace(/\b(?:void|await|return)$/, "")
      .trim();
    const own = /^if \((.*)\)$/s.exec(stmt);
    if (own) return own[1];
    // Some other statement head - a `for`, an arrow declaration, a call whose
    // argument list this needle sits inside. Not a guard, and not something to
    // look past either.
    if (stmt.length > 0 || block < 0) return "";
    at = block;
  }
  return "";
}

/**
 * The statement list around the SOLE occurrence of `anchor`.
 *
 * `hits` is reported rather than swallowed because the cheap trap is an
 * anchor that matches twice and an `indexOf` that takes whichever came first:
 * this section's previous anchor, `if (s.sshConnectionId) {`, occurs TWICE in
 * session-lifecycle.ts, and only source order put the spawn catch ahead of the
 * status re-emit at the bottom of `attachSession`. Reordering the file would
 * have silently pointed every assertion below at a block with no ladder in it -
 * and a block with no ladder in it passes a check for an ungated ladder.
 */
function soleBlockAround(
  src: string,
  anchor: string,
): { hits: number; open: number; close: number } {
  const hits = allIndexes(src, anchor);
  if (hits.length !== 1) return { hits: hits.length, open: -1, close: -1 };
  const open = scopeOf(src, hits[0]).block;
  return { hits: 1, open, close: open < 0 ? -1 : matchingBrace(src, open) };
}

/** Does this block body end by leaving the block, rather than falling out of the
 *  bottom of it? The single question the index comparison could not ask, and the
 *  one the "park loses its return" mutant turns on. */
function terminates(body: string): boolean {
  return /\b(?:return|throw)\b[^;{}]*;\s*$/.test(body);
}

/**
 * The park arm that lexically CONTROLS the ladder call at `ladderAt`: an `if`
 * whose block calls `parkSshConnectFailure`, whose block is a statement of the
 * very list the ladder call is a statement of, and which comes earlier in it.
 *
 * Sibling-of, not near: an arm nested one level deeper, or sitting in the
 * enclosing function rather than in this block, does not decide whether this
 * call runs, and neither does one that follows it.
 */
function parkArmControlling(
  src: string,
  list: number,
  ladderAt: number,
): { guard: string; body: string } | null {
  for (const p of allIndexes(src, "parkSshConnectFailure(")) {
    if (p > ladderAt) continue;
    const armOpen = scopeOf(src, p).block;
    // -1 is the function DECLARATION of parkSshConnectFailure at module scope,
    // which is not an arm of anything.
    if (armOpen < 0) continue;
    if (scopeOf(src, armOpen).block !== list) continue;
    const armClose = matchingBrace(src, armOpen);
    if (armClose === -1) continue;
    return { guard: guardAt(src, p), body: src.slice(armOpen + 1, armClose) };
  }
  return null;
}

/**
 * Both catch sites, asserted identically. The first attempt (session-lifecycle)
 * and the ladder's own re-entry (ssh-session) have to answer the same question,
 * so they are checked by one body of code rather than by two that could drift.
 *
 * Anchored on `isHostKeyMismatchError(e)`: the one statement that is unambiguous
 * in BOTH files (the import spells the name without `(e)`), and one that belongs
 * to this decision rather than to the logging around it - it is the other
 * unretryable category, and it can only ever live in the connect-failure catch.
 * Its uniqueness is asserted rather than assumed.
 */
function checkLadderSite(label: string, rel: string): void {
  const src = readTs(rel);
  const region = soleBlockAround(src, "isHostKeyMismatchError(e)");
  assert(region.hits === 1, `${label}: the anchor occurs exactly once (found ${region.hits})`);
  assert(
    region.open >= 0 && region.close > region.open,
    `${label}: resolved the connect-failure catch block around the anchor`,
  );
  if (region.open < 0 || region.close < 0) return;

  const regionText = src.slice(region.open, region.close);
  const verdict =
    /(?:const|let)\s+(\w+)\s*=\s*decideSshConnectFailure\(\s*classifySshConnectFailure\(\s*e\s*,/.exec(
      regionText,
    );
  assert(
    verdict !== null,
    `${label}: the catch classifies the error IT caught and keeps the verdict`,
  );

  const sites = allIndexes(src, "scheduleSshReconnect(").filter(
    (at) => at > region.open && at < region.close,
  );
  assert(
    sites.length === 1,
    `${label}: exactly one scheduleSshReconnect call in that catch (found ${sites.length})`,
  );
  for (const at of sites) {
    const list = scopeOf(src, at).block;
    assert(list >= 0, `${label}: resolved the block that lexically controls the ladder call`);
    const arm = list < 0 ? null : parkArmControlling(src, list, at);
    assert(
      arm !== null,
      `${label}: a parkSshConnectFailure arm is a sibling statement of the ladder call, earlier in the same block`,
    );
    assert(
      arm !== null && terminates(arm.body),
      `${label}: the park arm TERMINATES that block - falling out of it parks AND ladders`,
    );
    assert(
      arm !== null &&
        verdict !== null &&
        new RegExp(`\\b${verdict[1]}\\.action\\b`).test(arm.guard) &&
        /"park"/.test(arm.guard),
      `${label}: the arm is taken on the classifier's own verdict (guard: ${JSON.stringify(arm?.guard ?? "")})`,
    );
  }
}

console.log("\n[source-text] the first attempt's catch: the park arm controls the ladder");
checkLadderSite("first attempt", "src/modules/terminal/lib/session-lifecycle.ts");

console.log("\n[source-text] the ladder's own re-entry: same question, same answer");
checkLadderSite("attempts 2 and 3", "src/modules/terminal/lib/ssh-session.ts");

console.log("\n[source-text] nothing is dialled that could not authenticate");
{
  const src = readTs("src/modules/terminal/lib/ssh-session.ts");
  // Everything from the resolve block down to the dial itself: the property is
  // "asked BEFORE openSsh", so the region is bounded by the call rather than by
  // a brace, and a check that drifted below the dial would fall out of it.
  // Both bounds are asserted unambiguous - a second `await openSsh(` would make
  // "before the dial" mean "before whichever one came first".
  const fromHits = allIndexes(src, "let jumps: SshJumpHop[];");
  const dialHits = allIndexes(src, "sshSession = await openSsh(");
  assert(fromHits.length === 1, `one resolve block opens the region (found ${fromHits.length})`);
  assert(dialHits.length === 1, `one dial closes it (found ${dialHits.length})`);
  const from = fromHits.length === 1 ? fromHits[0] : -1;
  const dial = dialHits.length === 1 ? dialHits[0] : -1;
  const body = from !== -1 && dial > from ? src.slice(from, dial) : null;
  assert(body !== null, "found the region between the resolve block and the dial");
  assert(
    /canAuthenticate\(auth\)/.test(body ?? ""),
    "the target's credential is checked before openSsh is called",
  );
  assert(
    /canAuthenticate\(hop\)/.test(body ?? ""),
    "every ProxyJump hop's credential is checked too - a chain fails the same way",
  );
  // The resolve block's catch re-wraps whatever it threw, which is what makes a
  // failure ADDED to that block later local by default. Losing this line is how
  // the next pre-flight error silently rejoins the ladder.
  assert(
    /new SshLocalConnectError\(message/.test(body ?? ""),
    "the resolve block's catch re-wraps every failure as local, not just the ones it raises itself",
  );
}

console.log("\n[source-text] a REFUSED host key is a local decision - an unanswered one is not");
{
  const src = readTs("src/modules/terminal/lib/ssh-session.ts");

  // A list of answers, not a latch on "was one trusted". The type is asserted
  // because it is the multi-hop property in one token: a `boolean` cannot hold
  // "the bastion said yes and the target said no", and a chain is exactly where
  // the counters this replaces were pointed.
  const record = /const (\w+): boolean\[\] = \[\];/.exec(src);
  assert(record !== null, "the attempt keeps a LIST of host-key answers, not a single verdict");
  // A name no identifier can have, so the assertions below fail loudly rather
  // than searching for "" and matching at every offset in the file.
  const answers = record?.[1] ?? "<no record>";

  // The queue routes every answer through the prompt's own `confirm` - the
  // user's Trust, the user's Reject, and the rejection `abandon` sends when
  // whatever asked the question has gone away. Wrapping it is what lets the
  // answer be recorded AS IT IS MADE instead of guessed at afterwards.
  const enqueueHits = allIndexes(src, ".enqueue(");
  const confirmHits = allIndexes(src, "confirm: (");
  assert(enqueueHits.length === 1, `the connect enqueues one prompt (found ${enqueueHits.length})`);
  assert(confirmHits.length === 1, `carrying one confirm wrapper (found ${confirmHits.length})`);
  const argOpen = enqueueHits.length === 1 ? src.indexOf("{", enqueueHits[0]) : -1;
  const argClose = argOpen === -1 ? -1 : matchingBrace(src, argOpen);
  const confirmAt = confirmHits.length === 1 ? confirmHits[0] : -1;
  assert(
    confirmAt > argOpen && argOpen !== -1 && confirmAt < argClose,
    "the wrapper is a field of the prompt handed to enqueue - anywhere else and the queue calls the bare command instead",
  );
  const confirmBody = confirmAt === -1 ? -1 : src.indexOf("{", src.indexOf("=>", confirmAt));
  assert(confirmBody > 0, "found the wrapper's body");
  assert(
    /confirmHostKey\(/.test(
      confirmBody === -1 ? "" : src.slice(confirmBody, matchingBrace(src, confirmBody)),
    ),
    "the wrapper still forwards the answer - the paused handshake is blocked on this very call",
  );

  // THE misfiling regression, in source terms: recording an answer where the
  // PROMPT is raised rather than where it is answered restores `asked > trusted`
  // under a new name, and files a link that dropped under the dialog as a local
  // refusal. Every write to the record must sit in the wrapper.
  const writes = allIndexes(src, `${answers}.push(`);
  assert(
    writes.length === 1,
    `the record is written from exactly one place (found ${writes.length})`,
  );
  assert(
    writes.length > 0 && writes.every((at) => scopeOf(src, at).block === confirmBody),
    "the record is written only from the answer wrapper, never where a prompt is merely raised",
  );

  // Pinning stays on the accept callback. In the wrapper it would fire for every
  // answer, which means pinning a key the user just REFUSED.
  const pins = allIndexes(src, "pinFingerprint(");
  assert(pins.length === 1, `the fingerprint is pinned from one place (found ${pins.length})`);
  assert(
    pins.length === 1 && scopeOf(src, pins[0]).block !== confirmBody,
    "pinning is on the accept path, not on every answer",
  );

  // And the catch reads the verdict, rather than any restatement of "a prompt
  // was raised and not trusted".
  const marker = allIndexes(src, "throw new SshLocalConnectError(describeError(e)");
  assert(
    marker.length === 1,
    `one host-key local marker in the connect catch (found ${marker.length})`,
  );
  const guard = marker.length === 1 ? guardAt(src, marker[0]) : "";
  assert(
    guard === `hostKeyRefused(${answers})`,
    `the marker is thrown only for a REFUSAL, nothing weaker (guard: ${JSON.stringify(guard)})`,
  );
}

console.log(failed === 0 ? "\nAll ssh-retry checks passed." : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
