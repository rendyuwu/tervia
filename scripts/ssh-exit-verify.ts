/**
 * Self-check: a clean SSH shell exit must not be reported as a
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
 * Keeping them apart is a pipe of three pure functions, and all three are
 * checked here by CALLING them - the wire event arrives distinguished from
 * `SshEvent::Exit`/`Signal`/`Disconnected` in session.rs, and then:
 *   `exitReasonFromSshEvent` (bridge.ts)          wire event -> SshExitReason
 *   `endingFromExitReason`   (ssh-exit-decision)  SshExitReason -> SshEnding
 *   `decideSshEnding`        (ssh-exit-decision)  SshEnding -> what to do
 * None of them takes a live Session or Terminal, so the property this bug is
 * about - a reported ending never reconnects, only the ambiguous one does -
 * is checked at every seam it could break at, without standing up
 * xterm/tauri (importing ssh-session.ts itself would pull those in
 * transitively and fail under plain Node - see the top of
 * ssh-exit-decision.ts, which is why the middle function lives there rather
 * than beside its own call site).
 *
 * What is left to source text is only that the two production call sites
 * route through those functions instead of keeping a second copy of the
 * mapping inline; see the last section.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { exitReasonFromSshEvent } from "../src/modules/ssh/bridge";
import {
  decideSshEnding,
  endingFromExitReason,
  type SshEnding,
} from "../src/modules/terminal/lib/ssh-exit-decision";
import { stripCommentsNoJsx } from "./lib/source";

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
// The two translations `decideSshEnding` above is never handed, each now an
// exported pure function and so checked by CALLING it: bridge.ts's
// `exitReasonFromSshEvent` (wire `SshEvent` -> `SshExitReason`) and
// ssh-exit-decision.ts's `endingFromExitReason` (`SshExitReason` ->
// `SshEnding`).
//
// Why both halves need their own section rather than one end-to-end check: a
// regression that re-collapses the three variants can land at EITHER seam, and
// a single check cannot say which. Rewriting the `disconnected` case to produce
// `{ kind: "clean", code: 0 }` at either layer makes a dropped connection report
// as a deliberate exit and reconnect-eligibility silently vanish, and
// `decideSshEnding`'s own checks above never see it - by the time its input is
// constructed it has already been mis-mapped.
//
// Rust's `build_exit_event` covers the wire event's own construction on its own
// side; these cover the two JS mappings between it and `decideSshEnding`.

console.log("\n[exitReasonFromSshEvent] bridge.ts: SshEvent -> SshExitReason, per wire case");
{
  const fromExit = exitReasonFromSshEvent({ type: "exit", code: 17 });
  assert(
    fromExit.reason.kind === "exit" && fromExit.reason.code === 17,
    "wire 'exit' -> SshExitReason.kind 'exit', the remote's code threaded through (not hardcoded)",
  );
  assert(
    fromExit.code === 17,
    "and onExit's own `code` argument is that same code, not a 0 the caller would then report as a clean exit",
  );

  const fromSignal = exitReasonFromSshEvent({ type: "signal", name: "KILL", coreDumped: true });
  assert(
    fromSignal.reason.kind === "signal" &&
      fromSignal.reason.name === "KILL" &&
      fromSignal.reason.coreDumped === true,
    "wire 'signal' -> SshExitReason.kind 'signal', name/coreDumped threaded through",
  );
  assert(
    fromSignal.code === 0,
    "a signal death reports code 0 - the remote never gave an exit status, so there is none to pass on",
  );

  const fromDisconnected = exitReasonFromSshEvent({ type: "disconnected" });
  assert(
    fromDisconnected.reason.kind === "disconnected",
    "wire 'disconnected' -> SshExitReason.kind 'disconnected' - the only ambiguous one",
  );
  assert(fromDisconnected.code === 0, "and it too reports code 0, for the same reason");

  // THE regression this section exists for, at this seam.
  const kinds = [fromExit, fromSignal, fromDisconnected].map((r) => r.reason.kind);
  assert(
    new Set(kinds).size === 3,
    `the three wire events map to three DISTINCT SshExitReason kinds, got [${kinds.join(", ")}]`,
  );
}

console.log(
  "\n[endingFromExitReason] ssh-exit-decision.ts: SshExitReason -> SshEnding, per reason case",
);
{
  // The `code` argument is onExit's own, not `reason.code`. Both are 17 here,
  // and a 17 that comes out as 0 is the hardcode this asserts against.
  const exitEnding = endingFromExitReason({ kind: "exit", code: 17 }, 17);
  assert(
    exitEnding.kind === "clean" && exitEnding.code === 17,
    "reason 'exit' -> SshEnding.kind 'clean', code threaded through (not hardcoded to 0)",
  );

  const signalEnding = endingFromExitReason({ kind: "signal", name: "TERM", coreDumped: true }, 0);
  assert(
    signalEnding.kind === "signal" &&
      signalEnding.name === "TERM" &&
      signalEnding.coreDumped === true,
    "reason 'signal' -> SshEnding.kind 'signal', name/coreDumped threaded through",
  );

  const disconnectedEnding = endingFromExitReason({ kind: "disconnected" }, 0);
  assert(
    disconnectedEnding.kind === "ambiguous" && disconnectedEnding.reason.length > 0,
    "reason 'disconnected' -> SshEnding.kind 'ambiguous' with a non-empty reason for the banner - the only reconnect-eligible one",
  );

  const kinds = [exitEnding, signalEnding, disconnectedEnding].map((e) => e.kind);
  assert(
    new Set(kinds).size === 3,
    `the three reason kinds map to three DISTINCT SshEnding kinds, got [${kinds.join(", ")}]`,
  );
  assert(
    kinds[0] === "clean" && kinds[1] === "signal" && kinds[2] === "ambiguous",
    `specifically: exit->clean, signal->signal, disconnected->ambiguous, got [${kinds.join(", ")}]`,
  );
}

console.log("\n[end to end] wire event -> reason -> ending -> action, the whole pipe at once");
{
  // What the bug was, stated in one line per wire case. Redundant against the
  // two sections above by construction, and kept anyway because it is the only
  // check whose subject is the property the user reported rather than a seam:
  // typing `exit` must not produce a reconnect.
  const cases = [
    { event: { type: "exit", code: 0 } as const, action: "closePane" },
    { event: { type: "signal", name: "KILL", coreDumped: false } as const, action: "parkKilled" },
    { event: { type: "disconnected" } as const, action: "reconnect" },
  ];
  for (const { event, action } of cases) {
    const { code, reason } = exitReasonFromSshEvent(event);
    const decision = decideSshEnding(endingFromExitReason(reason, code), false);
    assert(
      decision.action === action,
      `wire '${event.type}' survives both mappings and decides '${action}' (got '${decision.action}')`,
    );
  }
}

// ============================================================================
// SOURCE-TEXT: only the WIRING is left here, and it is a much weaker claim than
// the sections above - that the two production call sites route through the two
// functions rather than keeping a second copy of the mapping inline. Neither
// call site can be reached from here: bridge.ts's lives inside `openSsh`, which
// invokes a Tauri command, and ssh-session.ts cannot be IMPORTED under plain
// node at all (it transitively touches `window` - see the header of
// ssh-exit-decision.ts). So an extraction that left the original switch in place
// beside it would pass every behavioural check above, and this is what notices.
//
// The shared stripper this reads through is `stripCommentsNoJsx` rather than
// `stripComments`: both inputs are `.ts` files, where a brace wrapping a block
// comment is an object or type literal, and the JSX branch would delete it along
// with the code inside.

/** Whitespace removed, so a legal Prettier reformat of a pinned expression is
 *  invisible to the pin. Safe on both inputs below: neither contains a string
 *  literal whose spacing matters. */
const squash = (src: string) => src.replace(/\s+/g, "");

console.log("\n[source-text] the two call sites route through the two functions");
{
  const bridge = stripCommentsNoJsx(read("src/modules/ssh/bridge.ts"));
  const calls = bridge.split("exitReasonFromSshEvent(").length - 1;
  assert(
    calls === 2,
    `exitReasonFromSshEvent appears exactly twice in bridge.ts - its declaration and this one call (found ${calls})`,
  );
  // Counting `onExit?.(` as well, because the three arms sharing one call is
  // the property: a fourth arm added with its own inline object literal would
  // satisfy the count above and still hand `onExit` an unmapped reason.
  const handoffs = bridge.split("handlers.onExit?.(").length - 1;
  assert(
    handoffs === 1 && squash(bridge).includes("handlers.onExit?.(ending.code,ending.reason)"),
    `channel.onmessage hands onExit the pure function's own result and nothing else (${handoffs} call site(s))`,
  );

  const sshSession = squash(stripCommentsNoJsx(read("src/modules/terminal/lib/ssh-session.ts")));
  assert(
    sshSession.includes("onExit:(code,reason)=>finishSsh(endingFromExitReason(reason,code))"),
    "ssh-session.ts's onExit is exactly one call - no switch of its own left in front of finishSsh",
  );
}

console.log(failed === 0 ? "\nAll ssh-exit checks passed." : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
