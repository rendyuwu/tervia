import { attachHostForwards } from "@/modules/forwards/autostart";
import { listHosts, markConnected } from "@/modules/hosts/store";
import { resolveJumpHops } from "@/modules/hosts/jumps";
import { isSshHost, type SshHost } from "@/modules/hosts/types";
import { resolveSshAuth } from "@/modules/vault/resolve";
import {
  closeSshForward,
  isHostKeyMismatchError,
  openSshForward,
  type SshForwardHandle,
  type SshJumpHop,
} from "@/modules/ssh/bridge";
import { openShellForConnection } from "@/modules/ssh/tunnel";
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
  classifySshConnectFailure,
  decideSshConnectFailure,
  decideSshEnding,
  endingFromExitReason,
  SshLocalConnectError,
  type SshEnding,
} from "./ssh-exit-decision";

const RECONNECT_BACKOFF_MS = [1_000, 3_000, 7_000] as const;
const MAX_SSH_RECONNECT_ATTEMPTS = RECONNECT_BACKOFF_MS.length;

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
  hostId: string,
  cols: number,
  rows: number,
  onData: (bytes: Uint8Array) => void,
  onExit: (code: number) => void,
  urlForwards: Map<number, Promise<SshForwardHandle>>,
): Promise<PtySession> {
  // Look up connection metadata at open time so a RECONNECT that re-dials
  // picks up settings changes; a tab that JOINS a live session instead rides
  // whatever settings that session was originally dialled with. These
  // pre-flight failures (profile deleted, jump chain broken or cyclic) are
  // the only ones that happen BEFORE the "connecting" status below, so they
  // are reported explicitly: a leaf that throws here would otherwise sit at
  // `idle` forever, which reads as "still coming up" to everything watching -
  // the terminal's Enter-to-retry stays disabled, and a remote editor pane
  // bound to this profile waits on a session that will never arrive instead
  // of offering to reconnect.
  let conn: SshHost;
  let auth: Awaited<ReturnType<typeof resolveSshAuth>>;
  let jumps: SshJumpHop[];
  try {
    const list = await listHosts();
    const found = list.find((h) => h.id === hostId);
    if (!found) throw new Error(`ssh: connection "${hostId}" not found`);
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
    // Everything this block can fail on is a fact about THIS machine -
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

  // Route the shell's ending through here, once: `terminated` keeps a second
  // report from being acted on. The actual reconnect-or-not decision is
  // `decideSshEnding` (module scope, above) - kept pure and separate from
  // these side effects so it stays unit-testable on its own.
  let terminated = false;
  // This tab's release, run from both places it can end: `finishSsh` below
  // (the session dropped, or an ending that closes the pane) and the
  // adapter's `close` (user-initiated). One-shot via `tabReleased`, so firing
  // both is harmless. It detaches this tab from `attachHostForwards` and
  // closes this tab's own url tunnels - the shared session itself may now
  // outlive the tab, riding whatever other tabs or forwards still hold it.
  const finishSsh = (ending: SshEnding) => {
    if (terminated) return;
    terminated = true;
    // Released ABOVE the disposed guard below, deliberately. A disposed
    // pane's forwards are exactly as dead as a live one's, and a release
    // under that guard would leak every entry for every tab the user closed.
    releaseTab();
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
        // the signal and let the user decide (Enter), the same manual path
        // used once auto-reconnect below gives up.
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
          }. Press Enter to reconnect.\x1b[0m\r\n`,
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

  let resolvedSessionId: number | null = null;
  let tabReleased = false;
  let detachForwards: (() => void) | null = null;
  const releaseTab = () => {
    if (tabReleased) return;
    tabReleased = true;
    detachForwards?.();
    detachForwards = null;
    const sid = resolvedSessionId;
    if (sid === null) return;
    // This tab's url tunnels: the session may outlive the tab now.
    for (const pending of urlForwards.values()) {
      void pending.then((h) => closeSshForward(sid, h.boundPort, h.generation)).catch(() => {});
    }
  };

  const claim = await openShellForConnection(hostId, {
    promptForHostKey: true,
    cols,
    rows,
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
    onData,
    onExit: (code, reason) => finishSsh(endingFromExitReason(reason, code)),
  });

  resolvedSessionId = claim.sessionId;
  writeSshBanner(s, `\x1b[2m[tervia] server key ${claim.fingerprint}\x1b[0m\r\n`);
  void markConnected(hostId, claim.fingerprint).catch(() => {});
  s.sshReconnectAttempts = 0;
  if (s.sshRoute) s.sshRoute = allSshHopsUp(s.sshRoute);
  emitSshStatus(s, {
    kind: "connected",
    fingerprint: claim.fingerprint,
    since: Date.now(),
    sessionId: claim.sessionId,
  });

  // The FIRST tab on this session starts its `startWithHost` forwards; later
  // tabs ride the forwards already up. A tab whose own teardown already ran
  // while this dial was in flight (the pane closed mid-connect) must not
  // attach forwards nothing will ever release.
  if (!tabReleased) {
    detachForwards = attachHostForwards(hostId, claim.sessionId, (text) => writeSshBanner(s, text));
  }

  // Adapter so SSH looks like a PtySession to the rest of the file. SSH
  // sessions are not persisted via daemon UUIDs (`pty_attach` is local
  // PTY only), so `sessionId` is empty - serialize.ts skips ptyId for
  // SSH leaves.
  return {
    id: claim.sessionId,
    sessionId: "",
    alive: true,
    write: claim.write,
    resize: claim.resize,
    close: () => {
      // The second release site, for the ending that never reaches `finishSsh`
      // - a user-initiated `disconnectSsh`, or a pane closing under a session
      // that reports nothing back. Idempotent via `tabReleased`, so firing
      // both is harmless.
      //
      // BOTH BEFORE `claim.close()`, and that order is the claim. Written as
      // `claim.close().finally(() => releaseTab())` this file would still
      // mention both calls while moving the release AFTER the close IPC
      // resolves - which is exactly the window an in-flight autostart claim
      // slips through.
      releaseTab();
      return claim.close();
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
 * is the exact lifetime of these forwards: `openSshForSession`'s `releaseTab`
 * closes each one when THIS TAB detaches - the shared session may now
 * outlive it - and a reconnect runs a fresh `openPtyForSession` with a fresh
 * cache. It holds the
 * in-flight PROMISE, not the resolved port, because a dev server prints its
 * banner in bursts: caching only the result would let a second announcement
 * arrive while the first bind was still in flight, miss the cache, and leave
 * two tunnels standing for one port. A failed bind drops out of the cache so
 * the next announcement retries rather than inheriting the failure forever.
 */
export async function forwardDetectedUrl(
  s: Session,
  url: string,
  cache: Map<number, Promise<SshForwardHandle>>,
): Promise<string | null> {
  // On an SSH leaf `pty` is the adapter returned by `openSshForSession`, whose
  // `id` IS the ssh session id - not a local PTY handle. Only ever reached with
  // `s.hostId` set, which is what makes that true. Null while a
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
      (handle) => {
        writeSshBanner(
          s,
          `\x1b[2m[tervia] forwarding localhost:${handle.boundPort} -> remote localhost:${remotePort}\x1b[0m\r\n`,
        );
        return handle;
      },
      (e) => {
        cache.delete(remotePort);
        throw e;
      },
    );
    cache.set(remotePort, pending);
  }
  return toLocalUrl(url, (await pending).boundPort);
}

/**
 * The ladder's counterpart for a connect failure that retrying cannot change.
 * One attempt, one banner, then wait for the user.
 *
 * Parks in `error` with `canRetry` - the same state a host-key mismatch parks in
 * (`runSshReconnect` below, and its twin in session-lifecycle's spawn catch),
 * and for the same reason: nothing about the attempt changes until the user
 * changes something. NOT the state the ladder gives up in; that one is
 * `disconnected` with `canRetry`, which reads as "the link went away", and this
 * failure never had a link. Both satisfy `canRetrySsh`, which is what the
 * Enter-to-retry path in session-lifecycle reads, so the key behaves identically
 * either way - the difference is only what the status text says. A terminal pane
 * has no clickable retry control, so Enter is the whole manual path and the
 * banners say so. What differs from the ladder is only how long the user waited
 * to get here: immediately, instead of 11 seconds and three identical failures.
 *
 * `sshReconnectAttempts` is reset so a later manual retry starts a fresh
 * three-attempt window if it fails for a transport reason instead.
 */
export function parkSshConnectFailure(s: Session, message: string): void {
  s.sshReconnectAttempts = 0;
  writeSshBanner(
    s,
    `\r\n\x1b[31m[tervia] ssh connect failed: ${message}\x1b[0m\r\n` +
      `\x1b[33m[tervia] Press Enter to reconnect.\x1b[0m\r\n`,
  );
  emitSshStatus(s, { kind: "error", message, canRetry: true });
}

export function scheduleSshReconnect(s: Session, reason: string): void {
  if (s.disposed || s.sshUserClose) return;
  if (!s.hostId) return;
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
      `\r\n\x1b[33m[tervia] disconnected (${reason}). Press Enter to reconnect.\x1b[0m\r\n`,
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
  if (!s.hostId) return;
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
    // The ladder re-enters here for attempts 2 and 3, so the same gate
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
  if (!s.hostId) return;
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
  if (!s.hostId) return;
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
  writeSshBanner(s, `\r\n\x1b[33m[tervia] disconnected. Press Enter to come back.\x1b[0m\r\n`);
}

/**
 * Manual reconnect by leaf id, for a caller outside the terminal that holds one.
 * Nothing in the tree calls it today - the status text is rendered as plain text
 * in WorkspacesPanel and renderEntryBody, neither of which is clickable - so the
 * banners promise Enter and nothing else. Kept because `disconnectSsh` next to
 * it is the same shape and the pair is what a pane control would bind to.
 */
export async function reconnectSsh(leafId: number): Promise<void> {
  const s = sessions.get(leafId);
  if (!s) return;
  if (!s.hostId) return;
  await retrySsh(s);
}
