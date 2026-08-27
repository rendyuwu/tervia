// VLT-42: pure decision for how an ended SSH channel should be handled -
// split out from ssh-session.ts (which uses it inside `finishSsh`) so it can
// be unit-tested directly (scripts/ssh-exit-verify.ts) without importing the
// full session module. ssh-session.ts transitively pulls in Tauri webview
// APIs (via the hosts store) that call `getCurrentWebviewWindow()` at module
// scope, which throws under plain Node/tsx with no `window` - the same
// reason `status.ts` next door is its own dependency-free file.
//
// See the `SshEvent`/`SshExitReason` doc comments in session.rs / bridge.ts
// for the full reasoning behind the three ending shapes this switches on.

/** How the shell channel ended, in the shape `finishSsh` (in ssh-session.ts)
 *  needs to decide what to do next. Kept as its own local type, rather than
 *  reusing the wire `SshExitReason`, so this decision stays decoupled from
 *  exactly how the Rust side spells it. */
export type SshEnding =
  | { kind: "clean"; code: number }
  | { kind: "signal"; name: string; coreDumped: boolean }
  | { kind: "ambiguous"; reason: string };

/** What `finishSsh` should do about an ending. VLT-42 in one sentence: a
 *  reported exit or signal death must never reconnect - only "ambiguous"
 *  may. */
export type SshEndingAction =
  | { action: "userClosed" }
  | { action: "closePane"; code: number }
  | { action: "parkKilled"; signalName: string; coreDumped: boolean }
  | { action: "reconnect"; reason: string };

export function decideSshEnding(ending: SshEnding, sshUserClose: boolean): SshEndingAction {
  // A user-initiated disconnect wins the display regardless of how the
  // remote itself ended - it raced the user's own close request.
  if (sshUserClose) return { action: "userClosed" };
  switch (ending.kind) {
    case "clean":
      // Reported exit status (ChannelMsg::ExitStatus): deliberate, in-band,
      // NOT a dropped connection.
      return { action: "closePane", code: ending.code };
    case "signal":
      // Killed by a signal on the remote side (ChannelMsg::ExitSignal):
      // also deliberate, also NOT a dropped connection - never
      // reconnect-eligible, same as "clean".
      return { action: "parkKilled", signalName: ending.name, coreDumped: ending.coreDumped };
    case "ambiguous":
      // Eof/Close/wait()->None with neither of the above ever reported -
      // the only ending that is reconnect-eligible.
      return { action: "reconnect", reason: ending.reason };
  }
}
