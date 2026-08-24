/**
 * Headless SSH port forwards, for callers that want a TCP tunnel rather than a
 * terminal: an RDP session against a Windows box that only a jump host can
 * reach, or a database behind a bastion.
 *
 * SECURITY: credentials never leave this module. The caller names a SAVED SSH
 * connection by id and gets back a loopback port; the password / private key
 * come from the OS keychain exactly the way the terminal's own connect reads
 * them. That is what lets a caller tunnel to a private
 * database without ever handling the key.
 *
 * A connection with no pinned server key is REFUSED by default, mirroring
 * `openSshConnection`: a first connect needs a human to verify the host key.
 * A caller that HAS a human in front of it - the RDP connect flow puts a dialog
 * on screen anyway - passes `promptForHostKey` and gets the TOFU prompt instead
 * of the refusal. Nothing else changes: the bastion is still trusted before a
 * session rides it, the user just does not have to open a terminal tab first.
 *
 * # Session sharing, and what a reference means
 *
 * One russh session per saved connection, shared by every forward over it, so an
 * RDP session and an SFTP browser against one bastion cost one SSH connection
 * rather than two. The contract is one reference per SUCCESSFUL
 * `openForwardForConnection`, released by one `closeForwardForConnection` for the
 * same target - including when the call reused an existing forward, which is the
 * whole reason reuse takes a reference of its own.
 *
 * Note what is NOT shared: a terminal tab against the same bastion opens its own
 * session in `terminal/lib/ssh-session.ts` and never touches this module's map,
 * because the terminal owns its session's lifetime (it dies with the tab) and
 * this one is refcounted. Two live paths to one bastion are therefore two russh
 * sessions today; unifying them means moving the terminal onto this module.
 */

import { openSsh, openSshForward, type SshJumpHop, type SshSession } from "./bridge";
import {
  authFields,
  getConnectionSecrets,
  listConnections,
  pinFingerprint,
  resolveJumpHops,
} from "./connections";
import { hostKeyOwners, useHostKeyPrompt } from "./hostKeyPrompt";

export type SshForward = {
  /** Runtime SSH session id, as used by `ssh_list_sessions` / `ssh_close`. */
  sessionId: number;
  /** Loopback port the caller should connect to. */
  localPort: number;
};

/** How a caller wants an unverified bastion handled, and how it hears about the
 *  question that gets asked. */
export type SshForwardOptions = {
  /**
   * Surface the first-connect host-key prompt and WAIT for it, instead of
   * refusing a connection with no pinned key.
   *
   * Only for a caller with a UI on screen to answer it. The default refusal
   * exists because a caller that cannot show the dialog would otherwise leave
   * the backend parked mid-handshake with nobody to answer, which is a held
   * socket and a blocked thread until its confirm timeout - the same failure the
   * RDP certificate prompt has to defend against.
   */
  promptForHostKey?: boolean;
  /**
   * Called with the id of every host-key prompt raised while opening, so the
   * caller's teardown can ANSWER one the user never got to (see
   * `hostKeyPrompt.ts`'s `abandon`). A prompt left pending after the pane that
   * would have answered it has gone is the leak this exists to close.
   */
  onHostKeyPrompt?: (promptId: string) => void;
};

/**
 * Live sessions opened by this module, keyed by saved-connection id, so several
 * forwards over one bastion share a single SSH session.
 *
 * The value holds the PROMISE, not the resolved session, and that is what makes
 * the sharing hold under concurrency: restoring a workspace with two RDP leaves
 * behind one bastion runs both connects in the same tick, and a map of resolved
 * sessions would have both miss, both dial, and the second overwrite the first -
 * leaking a russh session with a reference count nobody can ever release. It is
 * also what lets a reference be dropped while the dial is still in flight: the
 * session is closed when it arrives, rather than outliving the pane that asked
 * for it.
 */
const sessions = new Map<string, { session: Promise<SshSession>; refs: number }>();
/**
 * Forwards already open on a session, keyed by `connId|host|port`, so a second
 * consumer of the same target reuses its port instead of binding another.
 *
 * Refcounted per target as well as per session, because reuse used to hand back
 * a port without taking a reference: two panes tunnelling to the same host
 * shared ONE reference, and the first one to close tore the session out from
 * under the second. An entry at zero references is kept rather than deleted -
 * the forward is still bound on the backend for as long as the session lives, so
 * reusing it later is both free and correct, and `ssh_forward_open` has no
 * counterpart to close one on its own.
 */
const forwards = new Map<string, { forward: Promise<SshForward>; refs: number }>();

function forwardKey(connectionId: string, remoteHost: string, remotePort: number): string {
  return `${connectionId}|${remoteHost}|${remotePort}`;
}

/**
 * Open (or reuse) the SSH session for a saved connection, taking a reference.
 *
 * Deliberately NOT `async`: the map entry has to be published in the same tick as
 * the lookup that missed it. Every step of a dial - reading the store, resolving
 * the jump chain, reading the keychain - is an await, so an async body would let
 * a second caller in the same tick past the lookup and into a second dial.
 */
function sessionFor(connectionId: string, opts: SshForwardOptions): Promise<SshSession> {
  const live = sessions.get(connectionId);
  if (live) {
    live.refs += 1;
    // An in-flight dial is awaited rather than duplicated, so the second caller
    // rides the first one's handshake - including its host-key prompt, which is
    // already on screen and whose answer serves both.
    return live.session;
  }
  const pending = dialSession(connectionId, opts);
  sessions.set(connectionId, { session: pending, refs: 1 });
  return pending.catch((e: unknown) => {
    // The dial failed (or its host-key question was rejected). Forget it so the
    // next request tries again, but only if this is still the entry we put
    // there: a release that already dropped it to zero, or a later dial, owns it
    // now.
    if (sessions.get(connectionId)?.session === pending) dropSession(connectionId);
    throw e;
  });
}

/** The dial itself. Only ever called by {@link sessionFor}, which owns the
 *  bookkeeping around it. */
async function dialSession(connectionId: string, opts: SshForwardOptions): Promise<SshSession> {
  const list = await listConnections();
  const conn = list.find((c) => c.id === connectionId);
  if (!conn) throw new Error(`ssh: connection "${connectionId}" not found`);
  const jumps: SshJumpHop[] = await resolveJumpHops(conn.proxyJumpId, conn.id, list);
  if (!opts.promptForHostKey) {
    // Refused rather than dialled, for a caller with no way to ask. Every hop is
    // checked and not just the target: an unpinned JUMP host raises the prompt
    // just as surely, from `resolveJumpHops`'s per-hop `expectedFingerprint`,
    // and parking the backend on a question nobody can answer is worse than an
    // error message.
    const unverified = [
      { pinned: !!conn.lastFingerprint, label: conn.name || conn.host },
      ...jumps.map((j) => ({
        pinned: !!j.expectedFingerprint,
        label: list.find((c) => c.id === j.connectionId)?.name || j.host,
      })),
    ].find((c) => !c.pinned);
    if (unverified) {
      throw new Error(
        `ssh: "${unverified.label}" has no verified host key yet. Open it once as an SSH tab and accept the fingerprint, then try again.`,
      );
    }
  }

  const secrets = await getConnectionSecrets(connectionId);

  return openSsh(
    {
      host: conn.host,
      port: conn.port,
      user: conn.user,
      ...authFields(conn.authMode, secrets),
      // Pinned whenever there is a pin. Unset only on the prompting path, which
      // is a deliberate first connect; a changed key still fails the handshake
      // rather than prompting, because a pin that exists is always sent.
      expectedFingerprint: conn.lastFingerprint || undefined,
      jumps,
      // A shell is opened alongside the forward because that is the shape of
      // `ssh_open`; nothing reads from it, so the size is arbitrary.
      cols: 80,
      rows: 24,
    },
    {
      onData: () => {},
      onHostKeyPrompt: (prompt) => {
        // The prompt names a host; the pin belongs on whichever saved rows are
        // dialling it - the target, a jump hop, or both if one machine is saved
        // twice. Same attribution the terminal's connect uses.
        const owners = hostKeyOwners(
          prompt.host,
          { host: conn.host, connectionId: conn.id },
          jumps,
        );
        opts.onHostKeyPrompt?.(prompt.promptId);
        useHostKeyPrompt.getState().enqueue(prompt, () => {
          for (const id of owners) void pinFingerprint(id, prompt.fingerprint).catch(() => {});
        });
      },
      onExit: () => dropSession(connectionId),
      onError: () => dropSession(connectionId),
    },
  );
}

/** Forget a session, and every forward that lived on it. Called when it dies on
 *  its own and when the last reference goes. */
function dropSession(connectionId: string): void {
  sessions.delete(connectionId);
  for (const key of [...forwards.keys()]) {
    if (key.startsWith(`${connectionId}|`)) forwards.delete(key);
  }
}

/**
 * Tunnel `remoteHost:remotePort` (as resolved from the SSH server) to a
 * loopback port. Repeat calls for the same target reuse the existing forward and
 * take their own reference to the session, so each one must be matched by a
 * `closeForwardForConnection` for the same target.
 */
export function openForwardForConnection(
  connectionId: string,
  remoteHost: string,
  remotePort: number,
  opts: SshForwardOptions = {},
): Promise<SshForward> {
  const host = remoteHost.trim();
  if (!host) return Promise.reject(new Error("ssh: port forward needs a remote host"));
  if (!Number.isInteger(remotePort) || remotePort <= 0 || remotePort > 65535) {
    return Promise.reject(new Error("ssh: port forward needs a valid remote port"));
  }
  const key = forwardKey(connectionId, host, remotePort);

  /**
   * One caller's view of a shared forward: it fails on its own if the bind does,
   * and gives back the reference it took on the way in.
   *
   * Per-caller and not once per forward, because the references are per-caller:
   * a bind that fails has to release as many as it took, while the map entry is
   * dropped by whichever of them gets there first.
   */
  const claim = (pending: Promise<SshForward>): Promise<SshForward> =>
    pending.catch((e: unknown) => {
      if (forwards.get(key)?.forward === pending) forwards.delete(key);
      // The session may still be fine (a refused target, say), so only give up
      // our own reference rather than tearing it down for other forwards.
      releaseSession(connectionId);
      throw e;
    });

  const existing = forwards.get(key);
  const liveSession = sessions.get(connectionId);
  if (existing && liveSession) {
    // Reuse takes a reference of its own on BOTH counters. A forward outlives
    // its opener - that is the point of the map - so the session must be held by
    // the number of consumers, not by the number of ports bound.
    liveSession.refs += 1;
    existing.refs += 1;
    return claim(existing.forward);
  }
  // A forward whose session is gone is a dead port number. `dropSession` clears
  // these, so this only fires if the two maps ever disagreed.
  if (existing) forwards.delete(key);

  // Synchronous down to the `set` below, for the same reason `sessionFor` is:
  // two panes restored into the same target in one tick would otherwise both
  // miss, both bind a port, and the second entry would replace the first -
  // leaving the first consumer's reference with no entry left to release it.
  const session = sessionFor(connectionId, opts);
  const pending = (async () => {
    const live = await session;
    const localPort = await openSshForward(live.id, 0, host, remotePort);
    return { sessionId: live.id, localPort };
  })();
  forwards.set(key, { forward: pending, refs: 1 });
  return claim(pending);
}

/** Drop one reference to a connection's session, closing it when the last
 *  forward goes away. Forwards themselves close with the session. */
function releaseSession(connectionId: string): void {
  const live = sessions.get(connectionId);
  if (!live) return;
  live.refs -= 1;
  if (live.refs > 0) return;
  // Forget the forwards with it: their ports die with the session, and a stale
  // entry would hand the next caller a number nothing is listening on.
  dropSession(connectionId);
  // `.then`, because the reference can be dropped while the dial is still in
  // flight - a pane that unmounted before its tunnel finished opening. The
  // session is closed the moment it exists; a dial that failed instead has
  // nothing to close, which the catch covers.
  void live.session.then((s) => s.close()).catch(() => {});
}

/**
 * Release the tunnel a caller opened. Safe to call for an unknown target, and
 * for one whose references are already spent - so a teardown can fire it without
 * tracking whether the open succeeded.
 */
export async function closeForwardForConnection(
  connectionId: string,
  remoteHost: string,
  remotePort: number,
): Promise<void> {
  const entry = forwards.get(forwardKey(connectionId, remoteHost.trim(), remotePort));
  // Refs at zero means every consumer of this target has let go already. The
  // entry stays (the port is still bound while the session lives), but there is
  // no reference left here to spend, and spending someone else's would close a
  // session another target is still using.
  if (!entry || entry.refs === 0) return;
  entry.refs -= 1;
  releaseSession(connectionId);
}
