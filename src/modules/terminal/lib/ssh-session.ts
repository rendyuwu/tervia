import { startHostForwards } from "@/modules/forwards/autostart";
import { useHostOwnedForwards } from "@/modules/forwards/hostOwned";
import { listHosts, markConnected, pinFingerprint } from "@/modules/hosts/store";
import { resolveJumpHops } from "@/modules/hosts/jumps";
import { isSshHost, type SshHost } from "@/modules/hosts/types";
import { resolveSshAuth } from "@/modules/vault/resolve";
import {
  confirmHostKey,
  openSsh,
  openSshForward,
  isHostKeyMismatchError,
  type SshJumpHop,
  type SshSession,
} from "@/modules/ssh/bridge";
import { hostKeyOwners, useHostKeyPrompt } from "@/modules/ssh/hostKeyPrompt";
import {
  allSshHopsUp,
  buildSshRoute,
  failPendingSshHops,
  markSshHop,
  type SshStatus,
} from "@/modules/ssh/status";
import { remotePortOf, toLocalUrl } from "./forwardUrl";
import type { PtySession } from "./pty-bridge";
import { sessions, type Session } from "./sessionState";
import { describeError } from "./session-helpers";
import { flushPendingInput, openPtyForSession, syncPtySize } from "./pty-lifecycle";
import {
  canAuthenticate,
  classifySshConnectFailure,
  decideSshConnectFailure,
  decideSshEnding,
  hostKeyRefused,
  SshLocalConnectError,
  type SshEnding,
} from "./ssh-exit-decision";

const RECONNECT_BACKOFF_MS = [1_000, 3_000, 7_000] as const;
const MAX_SSH_RECONNECT_ATTEMPTS = RECONNECT_BACKOFF_MS.length;

/**
 * The backend's own "nothing to authenticate with" wording, mirrored verbatim
 * (see `NO_CREDENTIALS_ERROR` in src-tauri/src/modules/ssh/session.rs).
 *
 * Deliberately identical rather than improved: this pre-flight check exists to
 * CLASSIFY the failure, not to reword it, and a user who hits the backend guard
 * through some other caller must read the same sentence. The two constants are
 * cross-referenced in both directions so a change to either is a change to a
 * documented pair.
 */
const NO_CREDENTIALS_MESSAGE = "ssh: no credentials: set use_agent, password, or private_key";

/** The jump-hop half of the same guard, mirroring `connect`'s per-hop message. */
function noJumpCredentialsMessage(host: string): string {
  return `ssh: jump host ${host} has no ssh-agent, password or private key configured`;
}

// On an SSH drop the remote program (vim/htop/tmux) never got to send its
// mode-reset teardown, so xterm.js stays in whatever stateful modes it left on -
// most visibly mouse tracking, which then streams `ESC[<35;col;rowM` motion
// reports into the reconnected shell as garbage (buffered into pendingInput while
// pty is null, then flushed). Feed the DECRST teardown to the LOCAL term so it
// stops generating those events and any leaked alt-screen / scroll-region /
// cursor state is cleared, without wiping scrollback the way term.reset() would.
const TERM_MODE_RESET =
  "\x1b[?1000l\x1b[?1002l\x1b[?1003l" + // mouse tracking off (X11 / btn-event / any-motion)
  "\x1b[?1005l\x1b[?1006l\x1b[?1015l" + // mouse encodings off (UTF-8 / SGR / urxvt)
  "\x1b[?1004l" + // focus reporting off
  "\x1b[?2004l" + // bracketed paste off
  "\x1b[?1049l" + // leave alternate screen (restore normal buffer)
  "\x1b[?25h" + // show cursor
  "\x1b[?7h" + // autowrap on
  "\x1b[r" + // reset scroll region (full height)
  "\x1b[0m"; // reset SGR

export function writeSshBanner(s: Session, text: string): void {
  // Several callers are async continuations - a port forward resolving, a
  // reconnect landing - so the pane can be gone by the time the banner is
  // written, and xterm throws on a disposed terminal. Guarding here rather
  // than at each callsite keeps the ones that already exist correct too.
  if (s.disposed) return;
  const enc = new TextEncoder();
  s.term.write(enc.encode(text));
}

export function emitSshStatus(s: Session, next: SshStatus): void {
  // Carry the route on every status so no emit site has to remember to, and so
  // the chain stays visible while disconnected/errored - which is exactly when
  // the user needs to see WHICH hop failed.
  const withRoute: SshStatus = s.sshRoute ? { ...next, route: s.sshRoute } : next;
  s.sshStatus = withRoute;
  s.callbacks.onSshStatus?.(withRoute);
}

export function canRetrySsh(status: SshStatus): boolean {
  return (
    (status.kind === "disconnected" && status.canRetry) ||
    (status.kind === "error" && status.canRetry)
  );
}

export async function openSshForSession(
  s: Session,
  sshConnectionId: string,
  cols: number,
  rows: number,
  onData: (bytes: Uint8Array) => void,
  onExit: (code: number) => void,
): Promise<PtySession> {
  // Look up connection metadata at open time so settings changes are picked up on
  // the next reconnect. These pre-flight failures (profile deleted, jump chain
  // broken or cyclic) are the only ones that happen BEFORE the "connecting"
  // status below, so they are reported explicitly: a leaf that throws here would
  // otherwise sit at `idle` forever, which reads as "still coming up" to
  // everything watching - the terminal's Enter-to-retry stays disabled, and a
  // remote editor pane bound to this profile waits on a session that will never
  // arrive instead of offering to reconnect.
  let conn: SshHost;
  let auth: Awaited<ReturnType<typeof resolveSshAuth>>;
  let jumps: SshJumpHop[];
  try {
    const list = await listHosts();
    const found = list.find((h) => h.id === sshConnectionId);
    if (!found) throw new Error(`ssh: connection "${sshConnectionId}" not found`);
    // A saved id can now name an RDP host - the two used to be different id
    // spaces. Refused rather than cast: reading `proxyJumpId` off an RdpHost
    // would be a type error, not a narrowing that happens to be safe.
    if (!isSshHost(found)) {
      throw new Error(`ssh: "${found.name}" is an RDP host and cannot open a terminal`);
    }
    conn = found;
    auth = await resolveSshAuth(conn.credential);
    // Resolve the ProxyJump chain (if this host tunnels through others). Done at
    // open time so each reconnect re-reads the current chain + jump secrets.
    jumps = await resolveJumpHops(conn.proxyJumpId, conn.id, list);
  } catch (e) {
    // Drop the previous attempt's route first. Reaching here means the chain
    // could not even be resolved (a jump host was deleted, or it is cyclic), so
    // the hops from last time no longer describe anything.
    s.sshRoute = null;
    const message = describeError(e);
    emitSshStatus(s, { kind: "error", message, canRetry: true });
    // VLT-57: everything this block can fail on is a fact about THIS machine -
    // the profile is gone, it names an RDP host, its jump chain is broken or
    // cyclic, its vault binding no longer resolves, it has no credential. None
    // of them involve the network and none of them can come out differently on
    // the next attempt, so they are marked local at the point that is known
    // rather than guessed at from the wording downstream. Re-wrapped whole (via
    // `cause`, so the original still reaches the console) instead of tagging
    // each `throw` above, which is what makes a failure added to this block
    // later local by default - the safe direction for a block that by
    // construction never touches the wire.
    throw e instanceof SshLocalConnectError ? e : new SshLocalConnectError(message, { cause: e });
  }

  // Rebuild the route for this attempt, so an edited chain is picked up on
  // reconnect. Null for a direct connection - see `buildSshRoute`. `conn` no
  // longer carries a flat `user` (it moved under `credential`), so the target
  // endpoint is built from the resolved auth instead.
  s.sshRoute = buildSshRoute(jumps, { user: auth.user, host: conn.host, port: conn.port });

  // `sshReconnectAttempts` is bumped by `scheduleSshReconnect`. 0 means first open.
  const attempt = Math.max(1, s.sshReconnectAttempts);
  emitSshStatus(s, { kind: "connecting", attempt });
  writeSshBanner(
    s,
    `\x1b[2m[tervia] connecting to ${auth.user}@${conn.host}:${conn.port}…\x1b[0m\r\n`,
  );

  // VLT-57: refuse to dial with nothing to authenticate with. Saving a host with
  // no password has been a supported state since VLT-44 relaxed the save
  // validation, which made this previously-unreachable failure routine - and the
  // backend can only report it as one more connect-failed string, at which point
  // the ladder cannot tell it apart from a server that is merely down. Asked
  // here, the answer is attributable: it is a fact about the saved host, and no
  // amount of retrying changes a saved host.
  //
  // Deliberately AFTER the banner above rather than up in the resolve block, so
  // the failure still reads like every other connect failure - "connecting to
  // user@host:port", then why it did not. The alternative prints an error naming
  // no host at all, which in a split workspace does not say which pane failed.
  if (!canAuthenticate(auth)) throw new SshLocalConnectError(NO_CREDENTIALS_MESSAGE);
  // Every hop is dialled with its own credential and fails the same way, so the
  // same question is asked of each. Named rather than counted so the banner says
  // WHICH hop, matching the backend's per-hop message.
  const hopWithoutCredential = jumps.find((hop) => !canAuthenticate(hop));
  if (hopWithoutCredential) {
    throw new SshLocalConnectError(noJumpCredentialsMessage(hopWithoutCredential.host));
  }

  // Route the first ending (onExit or onError) through here; russh can fire
  // both for one drop (an error followed by the channel closing), and only
  // the first should be acted on. The actual reconnect-or-not decision is
  // `decideSshEnding` (module scope, above) - kept pure and separate from
  // these side effects so it stays unit-testable on its own.
  let terminated = false;
  const finishSsh = (ending: SshEnding) => {
    if (terminated) return;
    terminated = true;
    // The forwards this session's autostart opened die WITH the session, so
    // they are released here - ABOVE the disposed guard below, deliberately. A
    // disposed pane's forwards are exactly as dead as a live one's, and a
    // release under that guard would leak every entry for every tab the user
    // closed. `resolvedSessionId` is null until `openSsh` resolves, and an
    // attempt that never got that far claimed nothing.
    if (resolvedSessionId !== null) {
      useHostOwnedForwards.getState().releaseSession(resolvedSessionId);
    }
    if (s.disposed) return;
    // SSH dropped. Reset the AI CLI detector so its state doesn't ghost into the next reconnect.
    s.aiCliDetector?.reset();
    // Clear terminal modes the dead program left enabled (mouse tracking, alt
    // screen, ...) so they don't leak into the reconnected shell as garbage.
    s.term.write(TERM_MODE_RESET);
    // Whichever hop had not come up is where the chain broke; freeze that into
    // the route so the indicator names the failing link.
    if (s.sshRoute) s.sshRoute = failPendingSshHops(s.sshRoute);

    const decision = decideSshEnding(ending, s.sshUserClose);
    switch (decision.action) {
      case "userClosed":
        emitSshStatus(s, {
          kind: "disconnected",
          reason: "closed by user",
          canRetry: true,
        });
        onExit(0);
        return;
      case "closePane":
        // Deliberate, in-band termination: no banner, no reconnect. Route
        // through the normal PTY exit path so the leaf closes (or respawns,
        // if it is the last one left in the workspace) exactly like a local
        // shell exiting would - reusing that logic instead of duplicating
        // pane-closing decisions here.
        s.pty = null;
        s.ptySpawnedAt = null;
        onExit(decision.code);
        return;
      case "parkKilled":
        // Also deliberate, not a transport failure, so no auto-reconnect -
        // but unlike a plain exit this is unusual enough to flag rather
        // than silently close under: park the pane with a banner naming
        // the signal and let the user decide (Enter or the Retry button),
        // the same manual path used once auto-reconnect below gives up.
        s.pty = null;
        s.ptySpawnedAt = null;
        s.sshReconnectAttempts = 0;
        emitSshStatus(s, {
          kind: "disconnected",
          reason: `killed by signal ${decision.signalName}`,
          canRetry: true,
        });
        writeSshBanner(
          s,
          `\r\n\x1b[33m[tervia] remote process killed by signal ${decision.signalName}${
            decision.coreDumped ? " (core dumped)" : ""
          }. Press Enter or click Retry to reconnect.\x1b[0m\r\n`,
        );
        return;
      case "reconnect":
        // Drop the live handle so attachSession/retrySsh treat the leaf as "needs spawn".
        s.pty = null;
        s.ptySpawnedAt = null;
        scheduleSshReconnect(s, decision.reason);
        return;
    }
  };

  // Need both russh session id (from openSsh) and server fingerprint (from onConnected).
  // The two events can land in either order, so emit on session id and re-emit when fingerprint arrives.
  let pendingFingerprint: string | null = null;
  let resolvedSessionId: number | null = null;
  const emitConnectedIfReady = () => {
    if (resolvedSessionId === null) return;
    s.sshReconnectAttempts = 0;
    // The shell channel is open, so every hop behind it carried: mark the whole
    // chain up. `onJumpConnected` covers the hops individually, but a resumed or
    // reused chain may not re-announce them.
    if (s.sshRoute) s.sshRoute = allSshHopsUp(s.sshRoute);
    emitSshStatus(s, {
      kind: "connected",
      fingerprint: pendingFingerprint ?? "",
      since: Date.now(),
      sessionId: resolvedSessionId,
    });
  };

  // Track the first-connect host-key prompt so it can be cleaned up if this
  // attempt dies before the user answers it (see the catch below).
  let hostKeyPromptId: string | null = null;
  // VLT-57: every ANSWER this attempt's host-key questions were given, in the
  // order they arrived. Recorded at the moment the answer is MADE - see the
  // `confirm` wrapper below - rather than inferred at failure time from how many
  // prompts were raised against how many were trusted.
  //
  // The difference is a real failure, not a tidiness one: "raised and not
  // trusted" is also the state a link dropping while the dialog is still on
  // screen leaves behind, so counting parks the exact transport blip the ladder
  // exists for. Only an answer proves someone on this side ended the attempt.
  const hostKeyAnswers: boolean[] = [];
  let sshSession: SshSession;
  try {
    const { user, ...credentialValues } = auth;
    sshSession = await openSsh(
      {
        host: conn.host,
        port: conn.port,
        user,
        ...credentialValues,
        // Pin against the last recorded fingerprint. First connect is TOFU; later connects fail fast on mismatch.
        expectedFingerprint: conn.lastFingerprint || undefined,
        jumps,
        cols,
        rows,
      },
      {
        // Pin each jump host's fingerprint on its own saved connection as the
        // chain authenticates, so the next connect verifies it fail-fast.
        onJumpConnected: (connectionId, fp) => {
          // Index by position, not by id: the same host can legitimately appear
          // twice in a chain, and `jumps` is already in connect order. This is
          // the one place a route change has no status emit of its own, so it
          // re-emits - and only when the hop actually moved, since `markSshHop`
          // returns the same array for a hop reporting twice.
          if (s.sshRoute) {
            const next = markSshHop(
              s.sshRoute,
              jumps.findIndex((j) => j.connectionId === connectionId),
              "up",
            );
            if (next !== s.sshRoute) {
              s.sshRoute = next;
              emitSshStatus(s, s.sshStatus);
            }
          }
          void markConnected(connectionId, fp).catch(() => {});
        },
        onConnected: (fp) => {
          // Handshake cleared the host-key gate (pinned, or the user trusted it
          // via the dialog, which already dequeued the prompt). Drop our ref so
          // the failure path can never dismiss a prompt that isn't ours.
          hostKeyPromptId = null;
          writeSshBanner(s, `\x1b[2m[tervia] server key ${fp}\x1b[0m\r\n`);
          pendingFingerprint = fp;
          // Fire-and-forget. Timestamp write failure shouldn't break the session.
          void markConnected(sshConnectionId, fp).catch(() => {});
          emitConnectedIfReady();
        },
        // First connect to a new host: pause for the user to verify the server
        // fingerprint before credentials are sent (shown by the global dialog).
        // Trusting it pins it right away, on whichever saved host the key
        // actually belongs to - the prompt can come from any hop in the chain,
        // so it is matched by host rather than assumed to be the target. Waiting
        // for a successful connect instead meant a rejected password re-asked
        // the same question on every retry.
        onHostKeyPrompt: (prompt) => {
          hostKeyPromptId = prompt.promptId;
          const owners = hostKeyOwners(
            prompt.host,
            { host: conn.host, connectionId: sshConnectionId },
            jumps,
          );
          useHostKeyPrompt.getState().enqueue(
            {
              ...prompt,
              // VLT-57: the queue answers every prompt through the prompt's own
              // `confirm`, so wrapping it here is the one place that sees EVERY
              // answer this attempt's questions get - the user's Trust, the
              // user's Reject, and the rejection `abandon` sends on the user's
              // behalf when the pane that asked has gone away. Recording the
              // answer here is what makes the classification a fact rather than
              // an inference: nothing is written when a prompt is merely raised,
              // which is why a drop under the dialog stays a transport failure.
              //
              // Forwarded unchanged, and its result untouched: the paused
              // handshake is blocked on this very call, so swallowing it would
              // hang the connect until the backend's confirm window ran out.
              confirm: (promptId, accept) => {
                hostKeyAnswers.push(accept);
                return confirmHostKey(promptId, accept);
              },
            },
            () => {
              for (const id of owners) void pinFingerprint(id, prompt.fingerprint).catch(() => {});
            },
          );
        },
        onData,
        onExit: (code, reason) => {
          switch (reason.kind) {
            case "exit":
              finishSsh({ kind: "clean", code });
              break;
            case "signal":
              finishSsh({ kind: "signal", name: reason.name, coreDumped: reason.coreDumped });
              break;
            case "disconnected":
              finishSsh({ kind: "ambiguous", reason: "remote closed" });
              break;
          }
        },
        onError: (msg) => {
          writeSshBanner(s, `\r\n\x1b[31m[tervia] ssh error: ${msg}\x1b[0m\r\n`);
          finishSsh({ kind: "ambiguous", reason: msg });
        },
      },
    );
  } catch (e) {
    // The connect failed before a live session existed: the host-key prompt
    // timed out (120s backend cap) or was rejected, the credentials were wrong,
    // or the transport dropped. ssh_open surfaces all of these as a promise
    // rejection - NOT via onError - so this is the only place that sees them.
    // If a first-connect prompt was emitted and is still sitting in the queue,
    // drop it: the dialog renders only queue[0], so a dead prompt left at the
    // front would shadow every later attempt's prompt (the bug that forced an
    // app restart to recover).
    if (hostKeyPromptId) {
      useHostKeyPrompt.getState().dismiss(hostKeyPromptId);
      hostKeyPromptId = null;
    }
    // VLT-57: a key this attempt asked about and was REFUSED trust for is the
    // other failure the frontend can attribute on its own. A refusal aborts the
    // handshake before any credential is sent, and the ladder's answer to that
    // was to ask the same question again, up to three more times. The user
    // already answered.
    //
    // Refused, not "unanswered". A prompt still sitting in the queue when the
    // connect died says nothing about who ended it: the link dropping under the
    // dialog leaves exactly that state, and it is the blip the ladder is FOR.
    // The backend's own 120s confirm window lapsing lands in the same bucket for
    // the same reason - it is the backend's decision, made where this side
    // cannot see it, and telling it apart from a drop needs the connect failure
    // to carry a phase (the wire change VLT-63 describes). Left transport, so
    // the reconnect re-raises the question for whoever comes back to it, rather
    // than parking a pane whose link merely blinked.
    //
    // Everything else here (a credential the server refused, an unparseable key,
    // a host that would not resolve) is left transport for the same reason: the
    // backend reports it as one more string and the frontend has nothing
    // structural to tell those apart with.
    if (hostKeyRefused(hostKeyAnswers)) {
      throw new SshLocalConnectError(describeError(e), { cause: e });
    }
    throw e;
  }

  resolvedSessionId = sshSession.id;
  emitConnectedIfReady();

  // Saved `ssh -L` rules used to be re-opened here on every fresh session.
  // `Host` carries no `forwards` field any more - a forward rule is its own
  // `ForwardRule` record (6f), so this reads the rules that name THIS host and
  // starts the ones flagged `startWithHost` on the session just opened.
  //
  // Fire-and-forget on purpose, and safe because `startHostForwards` never
  // rejects: a rule that cannot bind writes a banner and the connect carries
  // on. Awaiting it would hold the pane's first prompt behind N binds, and
  // letting it throw would turn a busy local port into a failed SSH connect.
  void startHostForwards(sshConnectionId, sshSession.id, (text) => writeSshBanner(s, text));

  // Adapter so SSH looks like a PtySession to the rest of the file. SSH
  // sessions are not persisted via daemon UUIDs (`pty_attach` is local
  // PTY only), so `sessionId` is empty - serialize.ts skips ptyId for
  // SSH leaves.
  return {
    id: sshSession.id,
    sessionId: "",
    alive: true,
    write: (data) => sshSession.write(data),
    resize: (cols, rows) => sshSession.resize(cols, rows),
    close: () => {
      // The second release site, for the ending that never reaches `finishSsh`
      // - a user-initiated `disconnectSsh`, or a pane closing under a session
      // that reports nothing back. Idempotent, so firing both is harmless.
      useHostOwnedForwards.getState().releaseSession(sshSession.id);
      return sshSession.close();
    },
  };
}

/**
 * Turn a `localhost:PORT` URL printed by a REMOTE shell into one this machine
 * can actually open: bind a local port, tunnel it to that port as resolved on
 * the SERVER, and rewrite the URL's authority. Returns null when there is no
 * live session or the tunnel could not be bound, so the caller can leave the
 * pill unfired rather than offer a link to a dead (or worse, unrelated local)
 * port - the reason url detection was disabled for SSH leaves until now.
 *
 * The port is picked by the OS (`localPort` 0), not mirrored from the remote:
 * the remote's 5173 is very often busy on the developer's own machine too, and
 * quietly binding it would tunnel over their own dev server.
 *
 * `cache` is keyed by remote port and owned by the caller's pty spawn, which
 * is the exact lifetime of these forwards: they die with the SSH session, and
 * a reconnect runs a fresh `openPtyForSession` with a fresh cache. It holds the
 * in-flight PROMISE, not the resolved port, because a dev server prints its
 * banner in bursts: caching only the result would let a second announcement
 * arrive while the first bind was still in flight, miss the cache, and leave
 * two tunnels standing for one port. A failed bind drops out of the cache so
 * the next announcement retries rather than inheriting the failure forever.
 */
export async function forwardDetectedUrl(
  s: Session,
  url: string,
  cache: Map<number, Promise<number>>,
): Promise<string | null> {
  // On an SSH leaf `pty` is the adapter returned by `openSshForSession`, whose
  // `id` IS the ssh session id - not a local PTY handle. Only ever reached with
  // `s.sshConnectionId` set, which is what makes that true. Null while a
  // reconnect is still resolving, and the caller retries on the next print.
  const sessionId = s.pty?.id;
  if (sessionId === undefined) return null;
  const remotePort = remotePortOf(url);
  if (remotePort === null) return null;
  let pending = cache.get(remotePort);
  if (pending === undefined) {
    // Always 127.0.0.1 as the tunnel's target: the url's host is whatever the
    // server calls itself, and a server bound to 0.0.0.0 is on loopback too.
    pending = openSshForward(sessionId, 0, "127.0.0.1", remotePort).then(
      (bound) => {
        writeSshBanner(
          s,
          `\x1b[2m[tervia] forwarding localhost:${bound} -> remote localhost:${remotePort}\x1b[0m\r\n`,
        );
        return bound;
      },
      (e) => {
        cache.delete(remotePort);
        throw e;
      },
    );
    cache.set(remotePort, pending);
  }
  return toLocalUrl(url, await pending);
}

/**
 * VLT-57: the ladder's counterpart for a connect failure that retrying cannot
 * change. One attempt, one banner, then wait for the user.
 *
 * Parks in `error` with `canRetry` - the same state a host-key mismatch parks in
 * (`runSshReconnect` below, and its twin in session-lifecycle's spawn catch),
 * and for the same reason: nothing about the attempt changes until the user
 * changes something. NOT the state the ladder gives up in; that one is
 * `disconnected` with `canRetry`, which reads as "the link went away", and this
 * failure never had a link. Both satisfy `canRetrySsh`, so Enter and the status
 * pill's Retry behave identically either way - the difference is what the pill
 * says. What differs from the ladder is only how long the user waited to get
 * here: immediately, instead of 11 seconds and three identical failures.
 *
 * `sshReconnectAttempts` is reset so a later manual retry starts a fresh
 * three-attempt window if it fails for a transport reason instead.
 */
export function parkSshConnectFailure(s: Session, message: string): void {
  s.sshReconnectAttempts = 0;
  writeSshBanner(
    s,
    `\r\n\x1b[31m[tervia] ssh connect failed: ${message}\x1b[0m\r\n` +
      `\x1b[33m[tervia] Press Enter or click Retry to reconnect.\x1b[0m\r\n`,
  );
  emitSshStatus(s, { kind: "error", message, canRetry: true });
}

export function scheduleSshReconnect(s: Session, reason: string): void {
  if (s.disposed || s.sshUserClose) return;
  if (!s.sshConnectionId) return;
  if (s.sshReconnectTimer) {
    clearTimeout(s.sshReconnectTimer);
    s.sshReconnectTimer = null;
  }
  const attempt = s.sshReconnectAttempts + 1;
  if (attempt > MAX_SSH_RECONNECT_ATTEMPTS) {
    s.sshReconnectAttempts = 0;
    emitSshStatus(s, {
      kind: "disconnected",
      reason,
      canRetry: true,
    });
    writeSshBanner(
      s,
      `\r\n\x1b[33m[tervia] disconnected (${reason}). Press Enter or click Retry to reconnect.\x1b[0m\r\n`,
    );
    return;
  }
  s.sshReconnectAttempts = attempt;
  const delay = RECONNECT_BACKOFF_MS[attempt - 1];
  emitSshStatus(s, {
    kind: "reconnecting",
    attempt,
    nextDelayMs: delay,
    reason,
  });
  writeSshBanner(
    s,
    `\r\n\x1b[33m[tervia] connection lost (${reason}); reconnecting in ${Math.round(
      delay / 1000,
    )}s (attempt ${attempt}/${MAX_SSH_RECONNECT_ATTEMPTS})…\x1b[0m\r\n`,
  );
  s.sshReconnectTimer = setTimeout(() => {
    s.sshReconnectTimer = null;
    void runSshReconnect(s);
  }, delay);
}

async function runSshReconnect(s: Session): Promise<void> {
  if (s.disposed || s.sshUserClose) return;
  if (!s.sshConnectionId) return;
  if (s.pty) return; // already alive
  if (s.ptyOpening) return;
  s.ptyOpening = true;
  s.lastPtyError = null;
  s.term.options.disableStdin = false;
  try {
    const pty = await openPtyForSession(s, s.initialCwd);
    s.ptyOpening = false;
    if (s.disposed) {
      void pty.close();
      return;
    }
    s.pty = pty;
    flushPendingInput(s);
    s.ptySpawnedAt = Date.now();
    // Only sync after the ResizeObserver is wired. Pre-fit defaults would push the wrong size.
    if (s.observer) syncPtySize(s);
  } catch (e) {
    s.ptyOpening = false;
    const msg = describeError(e);
    console.error("ssh reconnect failed:", e);
    if (isHostKeyMismatchError(e)) {
      // Fingerprint mismatches can't auto-recover. Park in error so the user can
      // edit the saved connection (clear lastFingerprint) and retry manually.
      s.sshReconnectAttempts = 0;
      writeSshBanner(s, `\r\n\x1b[31m[tervia] ${msg}\x1b[0m\r\n`);
      emitSshStatus(s, { kind: "error", message: msg, canRetry: true });
      return;
    }
    // VLT-57: the ladder re-enters here for attempts 2 and 3, so the same gate
    // has to stand here as on the first attempt - otherwise a host edited into a
    // credential-less state mid-session would still walk the whole ladder.
    const decision = decideSshConnectFailure(classifySshConnectFailure(e, msg));
    if (decision.action === "park") {
      parkSshConnectFailure(s, decision.message);
      return;
    }
    scheduleSshReconnect(s, msg);
  }
}

/** Manually re-arm a disconnected SSH leaf. Resets the attempt counter for a fresh 3-attempt window. */
export async function retrySsh(s: Session): Promise<void> {
  if (s.disposed) return;
  if (!s.sshConnectionId) return;
  if (s.pty) return;
  if (s.ptyOpening) return;
  if (s.sshReconnectTimer) {
    clearTimeout(s.sshReconnectTimer);
    s.sshReconnectTimer = null;
  }
  s.sshReconnectAttempts = 0;
  s.sshUserClose = false;
  s.term.reset();
  s.placeholderShown = false;
  s.term.options.disableStdin = false;
  await runSshReconnect(s);
}

/** User-initiated SSH close. Sets the user-close flag so the exit handler skips auto-reconnect. */
export async function disconnectSsh(leafId: number): Promise<void> {
  const s = sessions.get(leafId);
  if (!s) return;
  if (!s.sshConnectionId) return;
  s.sshUserClose = true;
  if (s.sshReconnectTimer) {
    clearTimeout(s.sshReconnectTimer);
    s.sshReconnectTimer = null;
  }
  const pty = s.pty;
  s.pty = null;
  s.ptySpawnedAt = null;
  if (pty) await pty.close().catch(() => {});
  emitSshStatus(s, {
    kind: "disconnected",
    reason: "closed by user",
    canRetry: true,
  });
  writeSshBanner(
    s,
    `\r\n\x1b[33m[tervia] disconnected. Press Enter or click Reconnect to come back.\x1b[0m\r\n`,
  );
}

/** Status pill "Reconnect" handle. */
export async function reconnectSsh(leafId: number): Promise<void> {
  const s = sessions.get(leafId);
  if (!s) return;
  if (!s.sshConnectionId) return;
  await retrySsh(s);
}
