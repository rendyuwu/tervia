/**
 * Self-check for VLT-57: a connect that failed for a LOCAL reason must not
 * enter the reconnect ladder.
 * Run: `npx tsx scripts/ssh-retry-verify.ts`.
 *
 * The bug: a host saved with no password (a legal state since VLT-44 relaxed
 * the save validation) was clicked to connect, and the pane spent 1s + 3s + 7s
 * failing three more times with the identical message before it would let the
 * user do anything. Nothing about the saved host changes while the pane waits,
 * so every one of those attempts was known-doomed at the moment it was
 * scheduled.
 *
 * This is a DIFFERENT question from VLT-42's (scripts/ssh-exit-verify.ts), and
 * the distinction is the whole point: VLT-42 is about a shell channel that
 * existed and then ended, so it flows through `decideSshEnding`. VLT-57's
 * failure happens before any channel exists - `openSsh` rejects, `finishSsh` is
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
 *   4. Rust/TS parity for the mirrored guard and its wording.
 *   5. Source text: both catch sites actually consult the decision before
 *      reaching `scheduleSshReconnect`, and the pre-flight block marks what it
 *      throws. Pure functions that nobody calls fix nothing.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  canAuthenticate,
  classifySshConnectFailure,
  decideSshConnectFailure,
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

console.log("\n[canAuthenticate] nothing configured is the VLT-57 state");
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
// SOURCE TEXT: the decision has to be CONSULTED. Both retry sites are in files
// that cannot be imported under plain node (ssh-session.ts reaches `window`
// transitively - see the header of ssh-exit-decision.ts), and neither exposes
// its catch block as a pure function, so this half is read rather than run.
// Honest about its strength: weaker than the behavioural checks above, and
// exactly as strong as it needs to be to catch "the gate was deleted".

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

/** The source between `anchor`'s opening brace and its match. */
function blockAfter(src: string, anchor: string): string | null {
  const at = src.indexOf(anchor);
  if (at === -1) return null;
  const open = src.indexOf("{", at);
  const close = matchingBrace(src, open);
  return close === -1 ? null : src.slice(open, close);
}

console.log("\n[source-text] the first attempt's catch gates the ladder");
{
  const src = readTs("src/modules/terminal/lib/session-lifecycle.ts");
  const body = blockAfter(src, "if (s.sshConnectionId) {");
  assert(body !== null, "found the SSH branch of attachSession's spawn catch");
  const gate = body?.indexOf("decideSshConnectFailure") ?? -1;
  const ladder = body?.indexOf("scheduleSshReconnect") ?? -1;
  assert(gate !== -1, "the SSH branch consults decideSshConnectFailure");
  assert(ladder !== -1, "the SSH branch still has a scheduleSshReconnect path for transport drops");
  assert(
    gate !== -1 && ladder !== -1 && gate < ladder,
    "the classification is consulted BEFORE the ladder is scheduled, not after",
  );
  assert(/parkSshConnectFailure\(/.test(body ?? ""), "a local failure parks instead of laddering");
}

console.log("\n[source-text] the reconnect path gates the ladder too");
{
  const src = readTs("src/modules/terminal/lib/ssh-session.ts");
  const body = blockAfter(src, "async function runSshReconnect(");
  assert(body !== null, "found runSshReconnect");
  const gate = body?.indexOf("decideSshConnectFailure") ?? -1;
  const ladder = body?.lastIndexOf("scheduleSshReconnect") ?? -1;
  assert(
    gate !== -1 && ladder !== -1 && gate < ladder,
    "attempts 2 and 3 re-run the classification rather than assuming the first attempt's verdict",
  );
}

console.log("\n[source-text] nothing is dialled that could not authenticate");
{
  const src = readTs("src/modules/terminal/lib/ssh-session.ts");
  // Everything from the resolve block down to the dial itself: the property is
  // "asked BEFORE openSsh", so the region is bounded by the call rather than by
  // a brace, and a check that drifted below the dial would fall out of it.
  const from = src.indexOf("let jumps: SshJumpHop[];");
  const dial = src.indexOf("sshSession = await openSsh(", from === -1 ? 0 : from);
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

console.log("\n[source-text] a host key the user did not trust is a local decision");
{
  const src = readTs("src/modules/terminal/lib/ssh-session.ts");
  const handler = blockAfter(src, "onHostKeyPrompt: (prompt) => {");
  assert(handler !== null, "found the onHostKeyPrompt handler");
  const asked = handler?.indexOf("hostKeysAsked += 1") ?? -1;
  const enqueue = handler?.indexOf("enqueue(prompt, () => {") ?? -1;
  const trusted = handler?.indexOf("hostKeysTrusted += 1") ?? -1;
  assert(asked !== -1, "every prompt raised by this attempt is counted");
  // The load-bearing detail: the trusted counter lives INSIDE the accept
  // callback. Bumped alongside `asked` in the handler it would always match,
  // the comparison below would never fire, and a rejected key would quietly
  // rejoin the ladder with all the other assertions still passing.
  assert(
    enqueue !== -1 && trusted > enqueue,
    "the trusted counter is bumped only from the accept callback, not when the prompt is raised",
  );

  const comparison = src.indexOf("if (hostKeysAsked > hostKeysTrusted)");
  assert(comparison !== -1, "the connect catch compares prompts raised against prompts trusted");
  const wrap = src.indexOf("new SshLocalConnectError", comparison);
  assert(
    comparison !== -1 && wrap !== -1 && wrap - comparison < 200,
    "an unanswered or refused key throws the local marker, so the ladder does not re-ask it",
  );
}

console.log(failed === 0 ? "\nAll ssh-retry checks passed." : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
