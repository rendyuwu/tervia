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
import { decideSshEnding, type SshEnding } from "../src/modules/terminal/lib/ssh-exit-decision";

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
assert(
  decideSshEnding({ kind: "clean", code: 0 }, false).action !== "reconnect",
  "a clean exit is never the 'reconnect' action, by construction",
);

console.log("\n[decideSshEnding] a reported nonzero exit also closes, code is preserved");
const cleanNonZero = decideSshEnding({ kind: "clean", code: 17 }, false);
assert(
  cleanNonZero.action === "closePane" && cleanNonZero.code === 17,
  "nonzero exit code survives to closePane and is not collapsed to 0",
);

console.log("\n[decideSshEnding] a signal death also never reconnects");
const signalDecision = decideSshEnding({ kind: "signal", name: "KILL", coreDumped: false }, false);
assert(signalDecision.action === "parkKilled", "signal death -> parkKilled, not reconnect");
assert(
  signalDecision.action === "parkKilled" && signalDecision.signalName === "KILL",
  "the signal name reaches the decision unchanged",
);

console.log("\n[decideSshEnding] only the ambiguous ending reconnects");
const ambiguousDecision = decideSshEnding({ kind: "ambiguous", reason: "remote closed" }, false);
assert(
  ambiguousDecision.action === "reconnect",
  "Eof/Close/None with nothing reported -> reconnect",
);
assert(
  ambiguousDecision.action === "reconnect" && ambiguousDecision.reason === "remote closed",
  "the reason string is threaded through for the banner",
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

console.log(failed === 0 ? "\nAll ssh-exit checks passed." : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
