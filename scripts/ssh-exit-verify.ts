/**
 * Self-check for VLT-42: a clean SSH shell exit must not be reported as a
 * dropped connection.
 * Run: `npx tsx scripts/ssh-exit-verify.ts`.
 *
 * The bug: typing `exit` in an SSH terminal produced a "connection lost;
 * reconnecting (1/3)" banner and an automatic reconnect, because the Rust
 * pump collapsed three different channel endings onto the same
 * `SshEvent::Exit { code: 0 }` shape:
 *   1. `ChannelMsg::ExitStatus` - the remote reported its own exit code.
 *   2. `ChannelMsg::ExitSignal` - the remote process was killed by a signal.
 *   3. `Eof`/`Close`/`wait()` returning `None` with NEITHER of the above
 *      ever reported - the channel just ended, ambiguously.
 * Only (3) is a real candidate for "maybe the transport died, try again".
 * (1) and (2) are the remote saying, in-band, that it is done on purpose.
 *
 * `decideSshEnding` (ssh-exit-decision.ts) is the pure decision that keeps
 * these apart once ssh-session.ts's `finishSsh` receives the distinguished
 * event (see `SshExitReason` in bridge.ts, and
 * `SshEvent::Exit`/`Signal`/`Disconnected` in session.rs for the Rust side
 * of the same split). It takes no live Session/Terminal, so the ONE
 * property this bug is actually about - a reported ending never reconnects,
 * only the ambiguous one does - is checked directly here, without standing
 * up xterm/tauri/the SSH bridge (importing ssh-session.ts itself would pull
 * those in transitively and fail under plain Node - see the top of
 * ssh-exit-decision.ts).
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { decideSshEnding, type SshEnding } from "../src/modules/terminal/lib/ssh-exit-decision";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (rel: string) => readFileSync(join(repoRoot, rel), "utf8");

let failed = 0;
function assert(cond: boolean, msg: string): void {
  if (cond) console.log(`  ok: ${msg}`);
  else {
    console.error(`  FAIL: ${msg}`);
    failed++;
  }
}

console.log("[decideSshEnding] a reported clean exit closes the pane, never reconnects");
const clean0: SshEnding = { kind: "clean", code: 0 };
const cleanDecision = decideSshEnding(clean0, false);
assert(
  cleanDecision.action === "closePane" && cleanDecision.code === 0,
  "code 0 (the user typed `exit`) -> closePane, not reconnect",
);

console.log("\n[decideSshEnding] a reported nonzero exit also closes, code is preserved");
const cleanNonZero = decideSshEnding({ kind: "clean", code: 17 }, false);
assert(
  cleanNonZero.action === "closePane" && cleanNonZero.code === 17,
  "nonzero exit code survives to closePane and is not collapsed to 0",
);

console.log("\n[decideSshEnding] a signal death also never reconnects");
const signalDecision = decideSshEnding({ kind: "signal", name: "KILL", coreDumped: false }, false);
assert(
  signalDecision.action === "parkKilled" && signalDecision.signalName === "KILL",
  "signal death -> parkKilled, not reconnect, and the signal name reaches the decision unchanged",
);

console.log("\n[decideSshEnding] only the ambiguous ending reconnects");
const ambiguousDecision = decideSshEnding({ kind: "ambiguous", reason: "remote closed" }, false);
assert(
  ambiguousDecision.action === "reconnect" && ambiguousDecision.reason === "remote closed",
  "Eof/Close/None with nothing reported -> reconnect, and the reason string is threaded through for the banner",
);

console.log("\n[decideSshEnding] a user-initiated close wins over any ending shape");
for (const ending of [
  { kind: "clean", code: 0 } as const,
  { kind: "signal", name: "TERM", coreDumped: true } as const,
  { kind: "ambiguous", reason: "remote closed" } as const,
]) {
  const decision = decideSshEnding(ending, true);
  assert(
    decision.action === "userClosed",
    `sshUserClose=true overrides ${ending.kind} -> userClosed`,
  );
}

// ============================================================================
// SOURCE-TEXT: the translation `decideSshEnding` above is never handed -
// bridge.ts's SshEvent -> SshExitReason, and ssh-session.ts's SshExitReason
// -> SshEnding.
//
// Rust's `build_exit_event` covers the FIRST half of that pipe on its own
// side; `decideSshEnding` above covers what happens once an `SshEnding`
// exists. NOTHING exercises the two JS mappings in between - a regression
// that re-collapses the three variants back together at either seam (the
// original bug, one layer up) reddens nothing today. Example: rewriting
// ssh-session.ts's `disconnected` case to
// `finishSsh({ kind: "clean", code: 0 })` would make a dropped connection
// report as a deliberate exit and reconnect-eligibility silently vanish -
// `decideSshEnding`'s own tests above never see it, because by the time its
// input is constructed it has already been mis-mapped.
//
// Both files are owned by other agents this round and neither exports a pure
// function for this - bridge.ts's mapping lives inline in `channel.onmessage`,
// ssh-session.ts's inline in `onExit`. ssh-session.ts additionally cannot be
// IMPORTED under plain node at all (it transitively touches `window` - see
// the file header above), so even with an export a same-process behavioural
// test could only ever cover bridge.ts's half. The fix that unblocks a real
// behavioural test for both - extracting each mapping into an exported pure
// function, `bridge.ts`'s reachable directly and `ssh-session.ts`'s living in
// the dependency-free `ssh-exit-decision.ts` next to `decideSshEnding` - is
// written up in this round's report rather than applied here.
//
// Until that lands, this is what's checkable without editing either file:
// read the source, and confirm each of the three wire/reason cases maps to
// the kind this bug requires it to, AND that the three cases remain
// pairwise DISTINCT - which is exactly what a re-collapse breaks. Honest
// about its strength: this is source text, not execution, and weaker than
// importing a real function - see the `decideSshEnding` checks above for
// what a behavioural version of this looks like once the export exists.

/** Comment-stripped, quote-aware (matches the convention in
 *  host-editor-verify.ts / rdp-lifetime-verify.ts) so a case's own prose
 *  can't be mistaken for the code it's read alongside. */
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
// VLT-83: no JSX-comment branch here, deliberately. Every input this file
// strips is a `.ts` file - `bridge.ts` and `ssh-session.ts` - and a `{/* ...
// */}` is only meaningful inside JSX children, so a `.ts` source can never
// contain one that would hide code from a positive check the way it did in
// `host-editor-verify.ts` (fixed at `host-editor-verify.ts:191` - copy the
// branch from there, and not the lazy form `\{\s*\/\*[\s\S]*?\*\/\s*\}`,
// which is not a substitute: it can still cross an intervening `*/` while
// hunting for one followed by `}`) and `vault-editor-verify.ts:101`. If this
// file is ever pointed at a `.tsx` file, that branch has to be added first.
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

console.log("\n[source-text] bridge.ts: SshEvent -> SshExitReason, per wire case");
{
  const src = stripComments(read("src/modules/ssh/bridge.ts"));
  const anchor = src.indexOf("channel.onmessage = (event) => {");
  assert(anchor !== -1, "found channel.onmessage's switch");
  const braceIdx = src.indexOf("{", anchor);
  const endIdx = anchor !== -1 ? matchingBrace(src, braceIdx) : -1;
  assert(endIdx !== -1, "channel.onmessage's braces balance");
  const body = endIdx !== -1 ? src.slice(braceIdx, endIdx) : "";

  const caseArgs = (wireType: string): string | null => {
    const re = new RegExp(
      `case\\s*"${wireType}":\\s*handlers\\.onExit\\?\\.\\(([\\s\\S]*?)\\)\\s*;\\s*break\\s*;`,
    );
    return re.exec(body)?.[1] ?? null;
  };
  const exitArgs = caseArgs("exit");
  const signalArgs = caseArgs("signal");
  const disconnectedArgs = caseArgs("disconnected");
  assert(exitArgs !== null, "found the 'exit' case");
  assert(signalArgs !== null, "found the 'signal' case");
  assert(disconnectedArgs !== null, "found the 'disconnected' case");

  assert(
    !!exitArgs && /^event\.code\s*,/.test(exitArgs.trim()) && /kind:\s*"exit"/.test(exitArgs),
    "'exit' threads event.code through (not hardcoded) and maps to SshExitReason.kind 'exit'",
  );
  assert(
    !!signalArgs &&
      /kind:\s*"signal"/.test(signalArgs) &&
      /name:\s*event\.name/.test(signalArgs) &&
      /coreDumped:\s*event\.coreDumped/.test(signalArgs),
    "'signal' maps to SshExitReason.kind 'signal', name/coreDumped threaded through",
  );
  assert(
    !!disconnectedArgs && /kind:\s*"disconnected"/.test(disconnectedArgs),
    "'disconnected' maps to SshExitReason.kind 'disconnected' - the only ambiguous one",
  );

  const kinds = [exitArgs, signalArgs, disconnectedArgs].map(
    (a) => /kind:\s*"([a-z]+)"/.exec(a ?? "")?.[1] ?? null,
  );
  assert(
    kinds.every((k) => k !== null) && new Set(kinds).size === 3,
    `the three wire events map to three DISTINCT SshExitReason kinds, got [${kinds.join(", ")}]`,
  );
}

console.log("\n[source-text] ssh-session.ts: SshExitReason -> SshEnding, per reason case");
{
  const src = stripComments(read("src/modules/terminal/lib/ssh-session.ts"));
  const anchor = src.indexOf("onExit: (code, reason) => {");
  assert(anchor !== -1, "found the onExit: (code, reason) => {...} handler");
  const braceIdx = src.indexOf("{", anchor);
  const endIdx = anchor !== -1 ? matchingBrace(src, braceIdx) : -1;
  assert(endIdx !== -1, "onExit handler braces balance");
  const body = endIdx !== -1 ? src.slice(braceIdx, endIdx) : "";

  const caseArgs = (reasonKind: string): string | null => {
    const re = new RegExp(
      `case\\s*"${reasonKind}":\\s*finishSsh\\(([\\s\\S]*?)\\)\\s*;\\s*break\\s*;`,
    );
    return re.exec(body)?.[1] ?? null;
  };
  const exitCase = caseArgs("exit");
  const signalCase = caseArgs("signal");
  const disconnectedCase = caseArgs("disconnected");
  assert(exitCase !== null, "found the 'exit' case");
  assert(signalCase !== null, "found the 'signal' case");
  assert(disconnectedCase !== null, "found the 'disconnected' case");

  assert(
    !!exitCase &&
      /kind:\s*"clean"/.test(exitCase) &&
      !/code\s*:\s*0\b/.test(exitCase) &&
      /\bcode\b/.test(exitCase),
    "reason.kind 'exit' -> SshEnding.kind 'clean', code threaded through (not hardcoded to 0)",
  );
  assert(
    !!signalCase &&
      /kind:\s*"signal"/.test(signalCase) &&
      /name:\s*reason\.name/.test(signalCase) &&
      /coreDumped:\s*reason\.coreDumped/.test(signalCase),
    "reason.kind 'signal' -> SshEnding.kind 'signal', name/coreDumped threaded through",
  );
  assert(
    !!disconnectedCase && /kind:\s*"ambiguous"/.test(disconnectedCase),
    "reason.kind 'disconnected' -> SshEnding.kind 'ambiguous' - the only reconnect-eligible one",
  );

  // THE regression this whole section exists for: two different reason.kinds
  // collapsed onto the same SshEnding.kind (e.g. "disconnected" quietly
  // rewritten to reuse "exit"'s "clean" shape) reddens nothing anywhere else
  // - decideSshEnding never sees the mis-map, only its already-wrong result.
  const kinds = [exitCase, signalCase, disconnectedCase].map(
    (a) => /kind:\s*"([a-z]+)"/.exec(a ?? "")?.[1] ?? null,
  );
  assert(
    kinds.every((k) => k !== null) && new Set(kinds).size === 3,
    `the three reason.kinds map to three DISTINCT SshEnding kinds, got [${kinds.join(", ")}]`,
  );
  assert(
    kinds[0] === "clean" && kinds[1] === "signal" && kinds[2] === "ambiguous",
    `specifically: exit->clean, signal->signal, disconnected->ambiguous, got [${kinds.join(", ")}]`,
  );
}

console.log(failed === 0 ? "\nAll ssh-exit checks passed." : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
