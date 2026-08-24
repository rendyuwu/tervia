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
 * `openForwardForConnection`, released by one `closeForwardForConnection`
 * carrying the `claim` that open handed back - including when the call reused an
 * existing forward, which is the whole reason reuse takes a reference of its own.
 * The claim, and not the target, is what a release names: the entries for a
 * target are deleted and re-created when the bastion dies mid-life, and a
 * key-bearing release cannot tell its own entry from its successor.
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
  /**
   * Opaque token naming the forward ENTRY this call took its reference from.
   * Hand it back to {@link closeForwardForConnection}; it is what makes a
   * release identity-bearing instead of key-bearing.
   *
   * Why a key is not enough: `dropSession` deletes a connection's entries the
   * moment the bastion dies, and the next consumer of the same target creates
   * fresh ones under the same key. A release that only looked the key up could
   * not tell "my entry is gone" from "a NEW entry exists here", so a pane
   * whose `disconnected` lagged behind a dead bastion - a parked TCP connection
   * only fails on a keepalive - would spend the reference of whoever re-opened
   * the target and close a session that pane is still using. Tokens are
   * monotonic and never reused, so a release against a spent generation is a
   * no-op rather than someone else's teardown.
   */
  claim: number;
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
   *
   * PER DIAL, not per caller: read by whichever caller starts the handshake, and
   * a caller that JOINS an in-flight or established session inherits that dial's
   * choice, because the handshake the flag would apply to has already begun.
   * That is safe in both directions it can differ. Joining a dial that IS
   * prompting means the question already has an audience, which is the only
   * thing the refusal protects against; joining one that is not means the key
   * was pinned and there is no question to ask. The flag is deliberately not
   * re-checked on the reuse path, because "refuse" there would fail a caller
   * that is riding a handshake already known to be answerable.
   */
  promptForHostKey?: boolean;
  /**
   * Called with the id of every host-key prompt raised by the dial this call
   * rides, so the caller's teardown can ANSWER one the user never got to (see
   * `hostKeyPrompt.ts`'s `abandon`). A prompt left pending after the pane that
   * would have answered it has gone is the leak this exists to close.
   *
   * A caller that JOINS an in-flight dial is told too, including about a
   * question raised before it joined that is still on screen - otherwise its
   * teardown has nothing to abandon and it depends entirely on the caller that
   * started the dial still being around to close the leak.
   *
   * The consequence, accepted deliberately: ANY of the callers riding one dial
   * can now fail it for all of them by abandoning, since a rejected host key
   * aborts the shared handshake. That is the fail-safe direction. Rejecting
   * costs whoever is left one Reconnect, which re-dials and re-asks; a prompt
   * nobody answers costs a held socket, a handshake parked for the backend's
   * full confirm timeout and - because the verifier blocks - a displaced runtime
   * thread. The alternative, rejecting only when the LAST interested caller
   * lets go, needs a liveness signal this module does not have: the reference of
   * a caller waiting on the prompt is held by the very `openSsh` the prompt is
   * blocking, so the refcount cannot tell "still on screen" from "blocked on
   * this question", and a rule built on it would deadlock the handshake it was
   * meant to protect.
   */
  onHostKeyPrompt?: (promptId: string) => void;
};

/**
 * Host-key questions one dial has raised, and the callers riding it that want
 * to hear about them.
 *
 * Fanned out rather than handed to `dialSession`'s own caller, because a dial is
 * shared: the reuse branch of {@link sessionFor} hands back a handshake someone
 * else started, and a joiner that never learned the prompt ids cannot answer
 * one on its way out.
 */
type PromptFanout = {
  /** Ids this dial has raised, in order, so a late joiner can be caught up. */
  raised: string[];
  /** One listener per caller riding this dial. */
  listeners: Set<(promptId: string) => void>;
};

/** Tell every caller riding this dial about a new question. */
function announcePrompt(fanout: PromptFanout, promptId: string): void {
  fanout.raised.push(promptId);
  for (const listener of fanout.listeners) listener(promptId);
}

/**
 * Register a caller riding this dial, and catch it up on anything still
 * unanswered.
 *
 * Filtered against the live queue rather than replayed wholesale: an id the user
 * has already answered is not a prompt the joiner needs to abandon, and handing
 * it one would have its teardown fire a rejection at a decision that is already
 * made (harmless - `abandon` no-ops off the queue - but it would read as though
 * the joiner could undo it).
 */
function watchPrompts(fanout: PromptFanout, listener?: (promptId: string) => void): void {
  if (!listener) return;
  fanout.listeners.add(listener);
  const queued = useHostKeyPrompt.getState().queue;
  for (const promptId of fanout.raised) {
    if (queued.some((p) => p.promptId === promptId)) listener(promptId);
  }
}

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
const sessions = new Map<
  string,
  { session: Promise<SshSession>; refs: number; prompts: PromptFanout }
>();
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
 *
 * Each entry also carries a `claim`, the generation a consumer must hand back to
 * release: an entry can be DELETED and re-created under the same key when the
 * bastion dies mid-life, and a key-bearing release cannot tell the two apart.
 * See {@link SshForward.claim}.
 */
const forwards = new Map<string, { forward: Promise<SshForward>; refs: number; claim: number }>();

/** Source of {@link SshForward.claim}: monotonic and never reused, so a token
 *  from a deleted entry can never match a live one. */
let nextClaim = 1;

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
    // already on screen and whose answer serves both. It is told the prompt ids
    // either way: the joiner's teardown has to be able to answer a question
    // raised by a dial it did not start. See `onHostKeyPrompt`.
    watchPrompts(live.prompts, opts.onHostKeyPrompt);
    return live.session;
  }
  // Built before the dial rather than inside it, so a prompt raised during the
  // handshake always has somewhere to land - and so the reuse branch above can
  // subscribe to a dial that has not finished.
  const prompts: PromptFanout = { raised: [], listeners: new Set() };
  watchPrompts(prompts, opts.onHostKeyPrompt);
  const pending = dialSession(connectionId, opts, prompts);
  sessions.set(connectionId, { session: pending, refs: 1, prompts });
  // Host keys are verified once, during the handshake, so a settled dial can
  // raise no more questions. Dropping the listeners then keeps a long-lived
  // bastion session from retaining one closure per pane that ever rode it.
  void pending.then(
    () => prompts.listeners.clear(),
    () => prompts.listeners.clear(),
  );
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
async function dialSession(
  connectionId: string,
  opts: SshForwardOptions,
  prompts: PromptFanout,
): Promise<SshSession> {
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
        // Fanned out to every caller riding this dial, not just the one whose
        // options started it.
        announcePrompt(prompts, prompt.promptId);
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
  const claimed = (pending: Promise<SshForward>): Promise<SshForward> =>
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
    // Subscribed HERE as well as in `sessionFor`, because this branch never
    // reaches it: two panes restored onto the SAME target in one tick is the
    // commonest joiner there is, and it is the one that would otherwise learn
    // no prompt ids at all.
    watchPrompts(liveSession.prompts, opts.onHostKeyPrompt);
    // The SAME claim both consumers see, because it names the entry rather than
    // the caller: the resolved forward is shared, and so is the generation it
    // carries.
    return claimed(existing.forward);
  }
  // A forward whose session is gone is a dead port number. `dropSession` clears
  // these, so this only fires if the two maps ever disagreed.
  if (existing) forwards.delete(key);

  // Synchronous down to the `set` below, for the same reason `sessionFor` is:
  // two panes restored into the same target in one tick would otherwise both
  // miss, both bind a port, and the second entry would replace the first -
  // leaving the first consumer's reference with no entry left to release it.
  const session = sessionFor(connectionId, opts);
  const claim = nextClaim++;
  const pending = (async () => {
    const live = await session;
    const localPort = await openSshForward(live.id, 0, host, remotePort);
    return { sessionId: live.id, localPort, claim };
  })();
  forwards.set(key, { forward: pending, refs: 1, claim });
  return claimed(pending);
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
 * Release the tunnel a caller opened, naming the entry it took its reference
 * from with the `claim` its {@link SshForward} carried.
 *
 * Safe to call for an unknown target, for one whose references are already
 * spent, and for one that has since been re-created by somebody else - so a
 * teardown can fire it without tracking whether the open succeeded or whether
 * the bastion died in between.
 */
export async function closeForwardForConnection(
  connectionId: string,
  remoteHost: string,
  remotePort: number,
  claim: number,
): Promise<void> {
  const entry = forwards.get(forwardKey(connectionId, remoteHost.trim(), remotePort));
  if (!entry) return;
  // A different generation under the same key means this caller's entry was
  // deleted (the bastion dropped, `dropSession` cleared it) and somebody else
  // re-opened the target since. Its reference belongs to them; spending it here
  // would tear down a session they are still using, which is the whole reason
  // the release names an entry rather than a target.
  if (entry.claim !== claim) return;
  // Refs at zero means every consumer of this target has let go already. The
  // entry stays (the port is still bound while the session lives), but there is
  // no reference left here to spend, and spending someone else's would close a
  // session another target is still using.
  if (entry.refs === 0) return;
  entry.refs -= 1;
  releaseSession(connectionId);
}
