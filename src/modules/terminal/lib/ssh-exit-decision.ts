// The pure decisions behind "should this SSH leaf reconnect?", split out from
// ssh-session.ts (which uses them inside `finishSsh` and in the two connect
// catch blocks) so they can be unit-tested directly - scripts/ssh-exit-verify.ts
// for the ended-channel half, scripts/ssh-retry-verify.ts for the failed-connect
// half - without importing the full session module. ssh-session.ts transitively
// pulls in Tauri webview APIs (via the hosts store) that call
// `getCurrentWebviewWindow()` at module scope, which throws under plain Node/tsx
// with no `window` - the same reason `status.ts` next door is its own
// dependency-free file. Everything here must stay import-free for that reason,
// which is why the credential shape below is spelled structurally rather than
// imported from the vault module.
//
// Two different questions live here, and they are genuinely different:
//
//   VLT-42 (`decideSshEnding`): a channel EXISTED and then ended. See the
//   `SshEvent`/`SshExitReason` doc comments in session.rs / bridge.ts for the
//   reasoning behind the three ending shapes it switches on.
//
//   VLT-57 (`classifySshConnectFailure`/`decideSshConnectFailure`): the connect
//   failed before any channel existed, so none of the ending shapes apply and
//   `decideSshEnding` is never reached at all.

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

/**
 * VLT-57. A connect that failed before a shell channel existed, in the shape the
 * two catch blocks around `openPtyForSession` need to decide whether the
 * reconnect ladder applies at all.
 *
 * "local" is the fourth category, alongside `SshEnding`'s three: the attempt
 * failed for a reason that lives on THIS side of the wire - either the inputs it
 * would have dialled with could not be assembled here, or the local user
 * declined to trust the server's key. Nothing the remote said decided it, so a
 * retry with the same inputs reproduces it byte for byte; the 1s + 3s + 7s
 * ladder is pure waiting, and for a rejected key it re-asks a question the user
 * has already answered.
 *
 * Note what is deliberately NOT the test: "the connect never reached
 * authentication". That is true of the whole category but is not sufficient -
 * a refused TCP connect and a DNS failure also never reach authentication, and
 * those are exactly the blips the ladder exists for. The discriminant is WHOSE
 * fact ended the attempt, not how far it got.
 */
export type SshConnectFailure =
  { kind: "local"; message: string } | { kind: "transport"; message: string };

/** What a connect failure should do. The mirror of `SshEndingAction`: only the
 *  transport category enters the ladder. */
export type SshConnectFailureAction =
  { action: "park"; message: string } | { action: "reconnect"; message: string };

/**
 * The carrier that makes the classification STRUCTURAL rather than a match on
 * the failure's text.
 *
 * Everything the frontend can classify, it classifies by throwing this instead
 * of a bare `Error` at the point the fact is known - which is the only place it
 * IS known. Reading it back out is an `instanceof`, so a new local failure is
 * categorised by the code that raises it and cannot be forgotten by a list of
 * message prefixes somewhere else: there is no list to add to. A message match
 * would have to enumerate every wording ("no credentials", "not found", "is an
 * RDP host", "host key not trusted", ...) and would silently mis-file the next
 * one, and every reworded one.
 */
export class SshLocalConnectError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "SshLocalConnectError";
  }
}

export function classifySshConnectFailure(e: unknown, message: string): SshConnectFailure {
  // Not `e instanceof Error && ...`: the wrapper is the whole signal, and
  // anything else - a string rejection, a russh failure relayed by the backend,
  // a rejected promise from a Tauri command - is by definition a fact we did not
  // establish here, so it stays transport and stays reconnect-eligible.
  if (e instanceof SshLocalConnectError) return { kind: "local", message };
  return { kind: "transport", message };
}

export function decideSshConnectFailure(failure: SshConnectFailure): SshConnectFailureAction {
  switch (failure.kind) {
    case "local":
      // Park, do not ladder. The user has to change something (edit the host,
      // answer the key prompt differently) before any retry can behave
      // differently, so the pane offers a manual retry and waits.
      return { action: "park", message: failure.message };
    case "transport":
      // The network, the server being down, a mid-handshake drop: the next
      // attempt genuinely may go differently. This is what the ladder is for.
      return { action: "reconnect", message: failure.message };
  }
}

/**
 * VLT-57: did this attempt's host-key questions end in a refusal?
 *
 * `answers` holds one entry per ANSWER a first-connect prompt was given - the
 * user's Trust, the user's Reject, or the rejection the app sends on its own
 * behalf when whatever asked the question has gone away (`abandon`). Answers
 * only. A prompt that was raised and never answered is not in the list at all,
 * and that absence is the whole point: "asked but not trusted" is equally what a
 * link dropping while the dialog is still on screen looks like from here, and
 * that is a transport blip the ladder exists for. Deciding from what was RAISED
 * mis-files it as a local refusal and parks it.
 *
 * ANY refusal counts - not the last answer, and not "every answer". A ProxyJump
 * chain raises one question per hop, and trusting the bastion says nothing about
 * whether the target's key was accepted, so a `true` must never be able to erase
 * a `false`, in either order. That is the property a single "was one trusted?"
 * latch loses the moment a connect has more than one hop.
 */
export function hostKeyRefused(answers: readonly boolean[]): boolean {
  return answers.includes(false);
}

/**
 * Just the three fields that decide whether a credential can authenticate at
 * all. Structural on purpose (see the header): `ResolvedSshAuth` from the vault
 * module and `SshJumpHop` from the ssh bridge both satisfy it by shape, so the
 * target and every ProxyJump hop are judged by one predicate.
 */
export type SshAuthAttempt = {
  useAgent?: boolean;
  password?: string;
  privateKey?: string;
};

/**
 * Whether an attempt has anything to authenticate WITH. Mirrors the backend's
 * own guard (`has_credential` in src-tauri/src/modules/ssh/session.rs) exactly,
 * including its `is_none()` rather than emptiness test, so the two can never
 * disagree about a given input.
 *
 * The frontend checks it too, rather than leaving it to the backend, because
 * this is the one fact about the attempt that only the frontend can attribute:
 * `ssh_open` reports the failure as a string like every other failure, and by
 * then "your host has no password saved" is indistinguishable from "the server
 * hung up". Asking before dialling keeps the answer categorised. The backend
 * guard stays as the backstop for its other callers (the forward tunnel and the
 * host editor's Test probe), which do not come through here.
 */
export function canAuthenticate(attempt: SshAuthAttempt): boolean {
  return (
    attempt.useAgent === true || attempt.password !== undefined || attempt.privateKey !== undefined
  );
}
