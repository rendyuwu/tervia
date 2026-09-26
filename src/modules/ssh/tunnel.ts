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
 * Terminal tabs ride this same map, through `openShellForConnection`: each
 * one takes a reference here exactly like a forward does, and opens its own
 * shell channel on the session underneath. A tab and a forward against the
 * same bastion therefore cost one russh session between them, not two.
 */

import {
  closeSshForward,
  closeSshRemoteForward,
  confirmHostKey,
  openSsh,
  openSshForward,
  openSshRemoteForward,
  openSshShell,
  openSshSocks,
  type SshExitReason,
  type SshJumpHop,
  type SshSession,
  type SshShell,
} from "./bridge";
import { describeError } from "@/lib/describeError";
import { listHosts, pinFingerprint } from "@/modules/hosts/store";
import { resolveJumpHops } from "@/modules/hosts/jumps";
import { isSshHost, type SshHost } from "@/modules/hosts/types";
import { resolveSshAuth } from "@/modules/vault/resolve";
import { hostKeyOwners, useHostKeyPrompt } from "./hostKeyPrompt";
// Same carrier `bridge.ts` (this module's sibling) already imports across
// this alias, off `ssh_open`'s own "config" kind - reused here so a fact this
// function already knows structurally (a saved id that does not exist, an
// RDP host, an unpinned bastion with no way to ask) files as "local" rather
// than falling through `classifySshConnectFailure`'s default "transport",
// which would otherwise walk `controller.ts`'s backoff ladder on a failure no
// retry can fix. See that file's own doc for why this is attribution, not a
// message match.
import { hostKeyRefused, SshLocalConnectError } from "@/modules/terminal/lib/ssh-exit-decision";

export type SshForward = {
  /** Runtime SSH session id, as used by `ssh_list_sessions` / `ssh_close`. */
  sessionId: number;
  /** Loopback port the caller should connect to. The port the backend BOUND,
   *  which is the requested one when a caller pinned it and an OS-chosen one
   *  when it asked for 0. */
  localPort: number;
  /**
   * The backend's own name for the listener on {@link localPort}, carried so a
   * release can say WHICH listener it means. The port alone cannot: the backend
   * keys a session's forwards by port, so a listener that has gone and its
   * successor on the same pinned port share one key. See `SshForwardHandle` in
   * `./bridge` for what that bought.
   *
   * Distinct from {@link claim}, and the two are not interchangeable: this one
   * names a LISTENER to the backend and is minted by it, while `claim` names an
   * ENTRY in this module's own map and is minted here.
   */
  generation: number;
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
   * monotonic and never reused, so a release against a spent token is a no-op
   * rather than someone else's teardown.
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
  /**
   * Bind this local port instead of letting the OS choose. 0 or absent means
   * the OS picks, which is what every caller that only wants "a port to connect
   * to" should send; a pinned value is bound literally, and a bind failure
   * surfaces as the backend's own
   * `ssh: bind 127.0.0.1:<port> failed: <io error>` string rather than being
   * retried somewhere else.
   *
   * Part of a forward's IDENTITY, not decoration: two rules onto the same
   * remote target through different local ports are two forwards, and a key
   * that left this out made them one - the second caller took the reuse branch,
   * was handed the first one's bound port and the first one's claim, and
   * nothing reported it.
   *
   * Note the asymmetry with {@link closeForwardForConnection}, which takes the
   * local port positionally and REQUIRED. Omitting it here means "any port the
   * OS likes", which is a sensible default; omitting it there would mean "some
   * other entry", which is never what a release wants. So the two spellings are
   * deliberate and not an oversight to be tidied up.
   */
  localPort?: number;
};

/**
 * How a caller wants an unverified bastion handled, and how it hears about the
 * question a dial raises - the subset {@link sessionFor} and
 * {@link openShellForConnection} need, shared with {@link SshForwardOptions}
 * rather than duplicated.
 */
type DialOptions = Pick<SshForwardOptions, "promptForHostKey" | "onHostKeyPrompt"> & {
  /** A hop in the ProxyJump chain authenticated. LIVE ONLY, with no replay: a
   *  tab that joins after a hop came up gets its route marked all-up when its
   *  own claim resolves instead - see `allSshHopsUp` in `ssh-session.ts`. */
  onJumpConnected?: (connectionId: string, fingerprint: string) => void;
};

/** The two callbacks a dial fans out to every caller riding it. */
type DialWatcher = Pick<DialOptions, "onHostKeyPrompt" | "onJumpConnected">;

/**
 * Host-key questions one dial has raised, and the callers riding it that want
 * to hear about them.
 *
 * Fanned out rather than handed to `dialSession`'s own caller, because a dial is
 * shared: the reuse branch of {@link sessionFor} hands back a handshake someone
 * else started, and a joiner that never learned the prompt ids cannot answer
 * one on its way out.
 */
type DialFanout = {
  /** Prompt ids this dial has raised, in order, so a late joiner can be
   *  caught up and a failed dial can dismiss what it raised. */
  raised: string[];
  /** Every ANSWER this dial's prompts got, in order - for `hostKeyRefused`. */
  answers: boolean[];
  /** One watcher per caller riding this dial. */
  watchers: Set<DialWatcher>;
  /** Host keys are verified once, during the handshake: a settled dial can
   *  raise no more questions, so a late joiner is not registered at all. */
  settled: boolean;
};

/** Tell every caller riding this dial about a new question. */
function announcePrompt(fanout: DialFanout, promptId: string): void {
  fanout.raised.push(promptId);
  for (const watcher of fanout.watchers) watcher.onHostKeyPrompt?.(promptId);
}

/** Tell every caller riding this dial that a hop authenticated. Live only -
 *  see {@link DialOptions.onJumpConnected}. */
function announceHop(fanout: DialFanout, connectionId: string, fingerprint: string): void {
  for (const watcher of fanout.watchers) watcher.onJumpConnected?.(connectionId, fingerprint);
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
 *
 * No-ops for a settled dial, or a caller with neither callback set - which
 * fixes today's leak: a joiner of a settled dial used to be added to a set
 * nobody ever clears.
 */
function watchDial(fanout: DialFanout, opts: DialWatcher): void {
  if (fanout.settled) return;
  if (!opts.onHostKeyPrompt && !opts.onJumpConnected) return;
  const watcher: DialWatcher = {
    onHostKeyPrompt: opts.onHostKeyPrompt,
    onJumpConnected: opts.onJumpConnected,
  };
  fanout.watchers.add(watcher);
  const queued = useHostKeyPrompt.getState().queue;
  for (const promptId of fanout.raised) {
    if (queued.some((p) => p.promptId === promptId)) watcher.onHostKeyPrompt?.(promptId);
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
type SessionEntry = { session: Promise<SshSession>; refs: number; prompts: DialFanout };
const sessions = new Map<string, SessionEntry>();
/**
 * Forwards already open on a session, keyed by `connId|host|port|localPort`, so
 * a second consumer of the same target through the same local port reuses its
 * port instead of binding another.
 *
 * Refcounted per target as well as per session, because reuse used to hand back
 * a port without taking a reference: two panes tunnelling to the same host
 * shared ONE reference, and the first one to close tore the session out from
 * under the second. An entry whose last reference goes is DELETED, and its
 * backend listener closed with it. It used to be kept at zero references
 * instead - the port stayed bound while the session lived, so reusing it later
 * was free, and `ssh_forward_open` had no counterpart to close one on its own.
 * It has one now (`ssh_forward_close`), and a rule that has been stopped has to
 * give its port back: kept, the next Start asks for a port this map is still
 * holding and the bind fails.
 *
 * Each entry also carries a `claim`, the token a consumer must hand back to
 * release: an entry can be DELETED and re-created under the same key when the
 * bastion dies mid-life, and a key-bearing release cannot tell the two apart.
 * See {@link SshForward.claim}, and note it is a different thing from
 * {@link SshForward.generation}, which names a backend listener rather than an
 * entry here.
 */
const forwards = new Map<string, { forward: Promise<SshForward>; refs: number; claim: number }>();

/** Source of {@link SshForward.claim}: monotonic and never reused, so a token
 *  from a deleted entry can never match a live one. */
let nextClaim = 1;

/**
 * The identity of one forward ENTRY.
 *
 * The requested local port is part of it, not decoration: two rules onto the
 * same remote target through DIFFERENT local ports are two forwards, and a
 * three-part key made them one. The second caller took the reuse branch, was
 * handed the first one's bound port and the first one's claim, and nothing
 * reported it - so a rule pinned to 18081 ran on 18080 and looked fine.
 *
 * `0` is a value like any other here and means "the OS picks": two auto-port
 * callers onto one target legitimately share one forward, which is what the RDP
 * path has always done.
 */
function forwardKey(
  connectionId: string,
  remoteHost: string,
  remotePort: number,
  localPort: number,
): string {
  return `${connectionId}|${remoteHost}|${remotePort}|${localPort}`;
}

/**
 * Open (or reuse) the SSH session for a saved connection, taking a reference.
 *
 * Deliberately NOT `async`: the map entry has to be published in the same tick as
 * the lookup that missed it. Every step of a dial - reading the store, resolving
 * the jump chain, reading the keychain - is an await, so an async body would let
 * a second caller in the same tick past the lookup and into a second dial.
 */
function sessionFor(connectionId: string, opts: DialOptions): Promise<SshSession> {
  const live = sessions.get(connectionId);
  if (live) {
    live.refs += 1;
    // An in-flight dial is awaited rather than duplicated, so the second caller
    // rides the first one's handshake - including its host-key prompt, which is
    // already on screen and whose answer serves both. It is told the prompt ids
    // either way: the joiner's teardown has to be able to answer a question
    // raised by a dial it did not start. See `onHostKeyPrompt`.
    watchDial(live.prompts, opts);
    return live.session;
  }
  // Built before the dial rather than inside it, so a prompt raised during the
  // handshake always has somewhere to land - and so the reuse branch above can
  // subscribe to a dial that has not finished.
  const prompts: DialFanout = { raised: [], answers: [], watchers: new Set(), settled: false };
  // The ORIGINATING caller too, not just a later joiner - this used to be the
  // only registration, at `watchPrompts(prompts, opts.onHostKeyPrompt)`, which
  // is why a caller that starts a dial now hears hop events too.
  watchDial(prompts, opts);
  const pending: Promise<SshSession> = dialSession(
    connectionId,
    opts,
    prompts,
    () => sessions.get(connectionId)?.session === pending,
  );
  sessions.set(connectionId, { session: pending, refs: 1, prompts });
  // Host keys are verified once, during the handshake, so a settled dial can
  // raise no more questions. Dropping the watchers then keeps a long-lived
  // bastion session from retaining one closure per pane that ever rode it.
  void pending.then(
    () => {
      prompts.settled = true;
      prompts.watchers.clear();
    },
    () => {
      prompts.settled = true;
      prompts.watchers.clear();
    },
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
  opts: DialOptions,
  prompts: DialFanout,
  isCurrent: () => boolean,
): Promise<SshSession> {
  let conn: SshHost;
  let jumps: SshJumpHop[];
  let user: string;
  let credentialValues: Omit<Awaited<ReturnType<typeof resolveSshAuth>>, "user">;
  try {
    const list = await listHosts();
    const found = list.find((h) => h.id === connectionId);
    if (!found) throw new Error(`ssh: connection "${connectionId}" not found`);
    // A saved id can now name an RDP host. Refused rather than cast - there is
    // nothing to tunnel through.
    if (!isSshHost(found)) {
      throw new Error(`ssh: "${found.name}" is an RDP host and cannot be tunnelled through`);
    }
    conn = found;
    jumps = await resolveJumpHops(conn.proxyJumpId, conn.id, list);
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
    ({ user, ...credentialValues } = await resolveSshAuth(conn.credential));
  } catch (e) {
    // Re-wrapped WHOLE (via `cause`, so the original still reaches the
    // console) instead of tagging each throw above individually - the same
    // shape `terminal/lib/ssh-session.ts`'s own pre-connect block uses, and
    // for the identical reason: everything this block can fail on is a fact
    // about THIS machine (a saved id gone, an RDP host, an unpinned hop, a
    // vault binding that no longer resolves), so a failure added here later
    // is local by default rather than falling through to `controller.ts`'s
    // ladder as `"transport"`.
    throw e instanceof SshLocalConnectError
      ? e
      : new SshLocalConnectError(describeError(e), { cause: e });
  }

  try {
    return await openSsh(
      {
        host: conn.host,
        port: conn.port,
        user,
        ...credentialValues,
        // Pinned whenever there is a pin. Unset only on the prompting path, which
        // is a deliberate first connect; a changed key still fails the handshake
        // rather than prompting, because a pin that exists is always sent.
        expectedFingerprint: conn.lastFingerprint || undefined,
        jumps,
      },
      {
        onJumpConnected: (cid, fp) => announceHop(prompts, cid, fp),
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
          useHostKeyPrompt.getState().enqueue(
            {
              ...prompt,
              // Recorded at the moment the answer is MADE, so `hostKeyRefused`
              // reads a fact rather than "a prompt was raised and never
              // trusted" - which is also what a link dropping under the dialog
              // looks like from here.
              confirm: (promptId, accept) => {
                prompts.answers.push(accept);
                return confirmHostKey(promptId, accept);
              },
            },
            () => {
              for (const id of owners) void pinFingerprint(id, prompt.fingerprint).catch(() => {});
            },
          );
        },
        // A late end from a released session must not delete its successor -
        // `sessionFor` has already re-dialled by the time it lands.
        onClosed: () => {
          if (isCurrent()) dropSession(connectionId);
        },
      },
    );
  } catch (e) {
    // The dial failed, or a host-key question it raised was rejected. Drop any
    // prompt still on screen - the same "dead prompt at the front of the queue
    // shadows every later attempt" hazard the terminal's own connect guards
    // against - and attribute a REFUSAL as local, same as `ssh-session.ts`.
    for (const id of prompts.raised) useHostKeyPrompt.getState().dismiss(id);
    throw hostKeyRefused(prompts.answers) && !(e instanceof SshLocalConnectError)
      ? new SshLocalConnectError(describeError(e), { cause: e })
      : e;
  }
}

/** Forget a session, and every forward that lived on it. Called when it dies on
 *  its own and when the last reference goes. */
function dropSession(connectionId: string): void {
  sessions.delete(connectionId);
  for (const key of [...forwards.keys()]) {
    if (key.startsWith(`${connectionId}|`)) forwards.delete(key);
  }
  for (const key of [...remoteForwards.keys()]) {
    if (key.startsWith(`${connectionId}|`)) remoteForwards.delete(key);
  }
  for (const key of [...socksForwards.keys()]) {
    if (key.startsWith(`${connectionId}|`)) socksForwards.delete(key);
  }
}

export type SshShellOptions = DialOptions & {
  cols: number;
  rows: number;
  onData: (bytes: Uint8Array) => void;
  /** The shell ended on its own; this claim's session reference is already given back. */
  onExit: (code: number, reason: SshExitReason) => void;
};

export type SshShellClaim = {
  sessionId: number;
  fingerprint: string;
  write: (data: string) => Promise<void>;
  resize: (cols: number, rows: number) => Promise<void>;
  /** Close this shell and give back the session reference it took. Idempotent; the session closes when it was the last reference. */
  close: () => Promise<void>;
};

// ponytail: every tab is one more channel on its host's single session, so OpenSSH's MaxSessions
// (default 10, SFTP and git exec channels included) caps concurrent tabs per host - the next one
// fails "ssh: open channel failed" and ladders. Upgrade: on that refusal, dial a dedicated session.
export function openShellForConnection(
  connectionId: string,
  opts: SshShellOptions,
): Promise<SshShellClaim> {
  const session = sessionFor(connectionId, opts);
  // The entry THIS call took its reference on. A release against a dropped or re-dialled entry
  // is a no-op - the same identity rule `claim` gives forwards.
  const entry = sessions.get(connectionId);
  let released = false;
  const release = () => {
    if (released) return;
    released = true;
    if (sessions.get(connectionId) === entry) releaseSession(connectionId);
  };
  return session.then(
    async (live) => {
      let shell: SshShell;
      try {
        shell = await openSshShell(live.id, opts.cols, opts.rows, {
          onData: opts.onData,
          onExit: (code, reason) => {
            release();
            opts.onExit(code, reason);
          },
        });
      } catch (e) {
        release();
        throw e;
      }
      return {
        sessionId: live.id,
        fingerprint: live.fingerprint,
        write: shell.write,
        resize: shell.resize,
        close: () => {
          release();
          return shell.close();
        },
      };
    },
    (e: unknown) => {
      release();
      throw e;
    },
  );
}

/**
 * The refcount+claim protocol shared by every `open*ForConnection`/
 * `close*ForConnection` pair below: reuse a live entry under `key` (taking a
 * reference on both it and the session), or dial a fresh one through
 * {@link sessionFor} and remember it. `dial` gets the live session and the
 * claim this acquire minted, and returns the value the entry resolves to -
 * `-L`, `-R` and `-D` each shape that value differently (`SshForward`,
 * `SshRemoteForward`, `SshSocksForward`), which is why this is generic over
 * it rather than over one shared forward type.
 */
function acquireForward<T>(
  map: Map<string, { forward: Promise<T>; refs: number; claim: number }>,
  key: string,
  connectionId: string,
  opts: SshForwardOptions,
  dial: (live: SshSession, claim: number) => Promise<T>,
): Promise<T> {
  /**
   * One caller's view of a shared forward: it fails on its own if the dial
   * does, and gives back the reference it took on the way in.
   *
   * Per-caller and not once per forward, because the references are
   * per-caller: a dial that fails has to release as many as it took, while
   * the map entry is dropped by whichever of them gets there first.
   *
   * `held` names the session entry THIS call took its reference on. Tabs now
   * share this map, so a forward dial that rejects after its entry was
   * dropped and re-dialled must not spend the successor's reference.
   */
  const claimed = (pending: Promise<T>, held: SessionEntry | undefined): Promise<T> =>
    pending.catch((e: unknown) => {
      if (map.get(key)?.forward === pending) map.delete(key);
      // The session may still be fine (a refused target, say), so only give
      // up our own reference rather than tearing it down for other forwards -
      // and only if it is still OUR entry.
      if (sessions.get(connectionId) === held) releaseSession(connectionId);
      throw e;
    });

  const existing = map.get(key);
  const liveSession = sessions.get(connectionId);
  if (existing && liveSession) {
    // Reuse takes a reference of its own on BOTH counters. A forward outlives
    // its opener - that is the point of the map - so the session must be held
    // by the number of consumers, not by the number of ports bound.
    liveSession.refs += 1;
    const held = sessions.get(connectionId);
    existing.refs += 1;
    // Subscribed HERE as well as in `sessionFor`, because this branch never
    // reaches it: two panes restored onto the SAME target in one tick is the
    // commonest joiner there is, and it is the one that would otherwise learn
    // no prompt ids at all.
    watchDial(liveSession.prompts, opts);
    // The SAME claim both consumers see, because it names the entry rather
    // than the caller: the resolved forward is shared, and so is the token it
    // carries.
    return claimed(existing.forward, held);
  }
  // An entry whose session is gone is dead. `dropSession` clears these, so
  // this only fires if the map and `sessions` ever disagreed.
  if (existing) map.delete(key);

  // Synchronous down to the `set` below, for the same reason `sessionFor` is:
  // two panes restored into the same target in one tick would otherwise both
  // miss, both dial, and the second entry would replace the first - leaving
  // the first consumer's reference with no entry left to release it.
  const session = sessionFor(connectionId, opts);
  const held = sessions.get(connectionId);
  const claim = nextClaim++;
  const pending = session.then((live) => dial(live, claim));
  map.set(key, { forward: pending, refs: 1, claim });
  return claimed(pending, held);
}

/**
 * The release half of {@link acquireForward}: spend one reference on `key`'s
 * entry, closing the backend listener through `close` when the last one
 * goes.
 *
 * Safe to call for an unknown target, for one whose references are already
 * spent, and for one that has since been re-created by somebody else - so a
 * teardown can fire it without tracking whether the open succeeded or whether
 * the bastion died in between.
 *
 * RESOLVES ONLY ONCE THE LISTENER IS ACTUALLY CLOSED, when this release is
 * the last one: the returned promise is what a caller awaits to know the
 * port is free again, and the page's Stop relies on it before it lets the
 * row offer Start. The cost, deliberately accepted: releasing a reference on
 * an open that is STILL IN FLIGHT waits for that dial to resolve or fail,
 * because the port is not free until the open that binds it has finished. A
 * caller that can shorten that wait should abandon the dial's host-key
 * prompt first (see {@link SshForwardOptions.onHostKeyPrompt}); a caller
 * that does not care can drop the promise on the floor, which is what the
 * RDP pane's teardown does.
 *
 * The port stayed bound at zero refs once, before `ssh_forward_close`
 * existed; it does not any more - a released forward gives its port back,
 * and its entry is deleted BEFORE the await, and only if it is still ours:
 * an entry re-created by another caller in the meantime is theirs. `close`
 * is awaited so this call resolves only once the backend has actually been
 * told, and the generation each `close` reads off the resolved value is what
 * keeps a close still in flight from naming a listener a later open on the
 * same port has since superseded.
 */
async function releaseForward<T>(
  map: Map<string, { forward: Promise<T>; refs: number; claim: number }>,
  key: string,
  connectionId: string,
  claim: number,
  close: (value: T) => Promise<unknown>,
): Promise<void> {
  const entry = map.get(key);
  if (!entry) return;
  // A different claim under the same key means this caller's entry was
  // deleted (the bastion dropped, `dropSession` cleared it) and somebody else
  // re-opened the target since. Its reference belongs to them; spending it
  // here would tear down a session they are still using.
  if (entry.claim !== claim) return;
  // Refs at zero means every consumer of this target has let go already:
  // there is no reference left here to spend, and spending someone else's
  // would close a session another target is still using.
  if (entry.refs === 0) return;
  entry.refs -= 1;
  // The session entry this reference was taken on - current, since the claim
  // check above proves `dropSession` has not run. Tabs share the map, so the
  // bastion can drop and a tab re-dial while the close below is in flight, and
  // the successor's reference is not this caller's to spend.
  const held = sessions.get(connectionId);
  if (entry.refs === 0) {
    if (map.get(key) === entry) map.delete(key);
    // The `.catch` stays: a dial that died has no listener to close, and
    // that is not a failure for whoever is letting go of it.
    await entry.forward.then(close).catch(() => {});
  }
  if (sessions.get(connectionId) === held) releaseSession(connectionId);
}

/**
 * Tunnel `remoteHost:remotePort` (as resolved from the SSH server) to a
 * loopback port - `opts.localPort` if it names one, otherwise whichever the OS
 * picks. Repeat calls for the same target THROUGH THE SAME LOCAL PORT reuse the
 * existing forward and take their own reference to the session, so each one must
 * be matched by a `closeForwardForConnection` naming that same local port.
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
  const localPort = opts.localPort ?? 0;
  const key = forwardKey(connectionId, host, remotePort, localPort);
  return acquireForward(forwards, key, connectionId, opts, async (live, claim) => {
    // `boundPort` and not `localPort`: what comes back is the port the
    // backend actually bound, which for a request of 0 is not the number
    // that was sent. The pair is what `closeSshForward` accepts, so both
    // halves - and not the request - are what {@link SshForward} carries.
    const { boundPort, generation } = await openSshForward(live.id, localPort, host, remotePort);
    return { sessionId: live.id, localPort: boundPort, generation, claim };
  });
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
 * `localPort` is the port the open ASKED FOR - `opts.localPort`, or 0 for a
 * caller that let the OS choose - because that is what names the entry
 * alongside the target: two rules onto one target through different local ports
 * are two forwards, and a release has to say which one it is giving up.
 *
 * Positional and required, unlike open's optional `opts.localPort`, and the
 * asymmetry is deliberate. Omitting it on open means "any port the OS likes",
 * which is a reasonable default; omitting it on close would mean "the wrong
 * entry", which is never what a caller wants and which nothing would report.
 *
 * See {@link releaseForward} for the shared refcount/await contract every
 * `close*ForConnection` below follows identically.
 */
export async function closeForwardForConnection(
  connectionId: string,
  remoteHost: string,
  remotePort: number,
  localPort: number,
  claim: number,
): Promise<void> {
  const key = forwardKey(connectionId, remoteHost.trim(), remotePort, localPort);
  await releaseForward(forwards, key, connectionId, claim, (f) =>
    closeSshForward(f.sessionId, f.localPort, f.generation),
  );
}

/**
 * A live `-R` remote forward: the port the SERVER bound, and the token this
 * module needs back to release it. Mirrors {@link SshForward}'s shape - the
 * pair (`sessionId`, `claim`) means the same thing here it does there - the
 * one difference is that `boundPort` names a port on the SERVER rather than
 * on this machine.
 */
export type SshRemoteForward = {
  sessionId: number;
  boundPort: number;
  generation: number;
  claim: number;
};

/** `-R` forwards already open on a session, keyed by
 *  `connId|bindAddress|bindPort|localHost|localPort` - the same
 *  every-component-of-the-target reasoning {@link forwardKey} gives for `-L`,
 *  except the port that may legally be 0 here is `bindPort` (the SERVER lets
 *  the OS pick), not the local one. */
const remoteForwards = new Map<
  string,
  { forward: Promise<SshRemoteForward>; refs: number; claim: number }
>();

function remoteForwardKey(
  connectionId: string,
  bindAddress: string,
  bindPort: number,
  localHost: string,
  localPort: number,
): string {
  return `${connectionId}|${bindAddress}|${bindPort}|${localHost}|${localPort}`;
}

/**
 * Ask `connectionId`'s SSH server to listen on `bindAddress:bindPort`
 * (`bindPort` 0 lets the SERVER pick) and route every connection it accepts
 * back to `localHost:localPort` on THIS machine. Shares {@link acquireForward}'s
 * refcount+claim protocol with {@link openForwardForConnection} - see that
 * function's own doc for the contract this one follows identically, one
 * port-ownership swap aside.
 */
export function openRemoteForwardForConnection(
  connectionId: string,
  bindAddress: string,
  bindPort: number,
  localHost: string,
  localPort: number,
  opts: SshForwardOptions = {},
): Promise<SshRemoteForward> {
  const host = localHost.trim();
  if (!host) return Promise.reject(new Error("ssh: remote forward needs a local target host"));
  if (!Number.isInteger(localPort) || localPort <= 0 || localPort > 65535) {
    return Promise.reject(new Error("ssh: remote forward needs a valid local target port"));
  }
  const address = bindAddress.trim() || "localhost";
  const key = remoteForwardKey(connectionId, address, bindPort, host, localPort);
  return acquireForward(remoteForwards, key, connectionId, opts, async (live, claim) => {
    const { boundPort, generation } = await openSshRemoteForward(
      live.id,
      address,
      bindPort,
      host,
      localPort,
    );
    return { sessionId: live.id, boundPort, generation, claim };
  });
}

/** Release the tunnel a caller opened with {@link openRemoteForwardForConnection},
 *  naming it with `claim` and every field that formed its key - mirrors
 *  {@link closeForwardForConnection}'s own contract exactly, `bindPort` in
 *  place of the local port. */
export async function closeRemoteForwardForConnection(
  connectionId: string,
  bindAddress: string,
  bindPort: number,
  localHost: string,
  localPort: number,
  claim: number,
): Promise<void> {
  const address = bindAddress.trim() || "localhost";
  const key = remoteForwardKey(connectionId, address, bindPort, localHost.trim(), localPort);
  await releaseForward(remoteForwards, key, connectionId, claim, (f) =>
    closeSshRemoteForward(f.sessionId, address, f.boundPort, f.generation),
  );
}

/** A live `-D` SOCKS5 listener - mirrors {@link SshForward}'s shape exactly;
 *  `localPort` is the SOCKS5 listen port THIS MACHINE bound. */
export type SshSocksForward = {
  sessionId: number;
  localPort: number;
  generation: number;
  claim: number;
};

/** `-D` listeners already open on a session, keyed by `connId|socks|localPort` -
 *  a `-D` rule has no dial target of its own (a SOCKS5 CONNECT names one per
 *  connection), so the port is the whole target this map needs to key on. */
const socksForwards = new Map<
  string,
  { forward: Promise<SshSocksForward>; refs: number; claim: number }
>();

function socksKey(connectionId: string, localPort: number): string {
  return `${connectionId}|socks|${localPort}`;
}

/**
 * Start a `-D` SOCKS5 listener on `connectionId`'s SSH session, on
 * `127.0.0.1:localPort` (0 lets the OS pick). Shares {@link acquireForward}'s
 * refcount+claim protocol with {@link openForwardForConnection} - see that
 * function's own doc for the contract this one follows identically.
 */
export function openSocksForConnection(
  connectionId: string,
  localPort: number,
  opts: SshForwardOptions = {},
): Promise<SshSocksForward> {
  const key = socksKey(connectionId, localPort);
  return acquireForward(socksForwards, key, connectionId, opts, async (live, claim) => {
    const { boundPort, generation } = await openSshSocks(live.id, localPort);
    return { sessionId: live.id, localPort: boundPort, generation, claim };
  });
}

/** Release the tunnel a caller opened with {@link openSocksForConnection},
 *  naming it with `claim` - mirrors {@link closeForwardForConnection}'s own
 *  contract exactly. Closes through the SAME `closeSshForward` `-L` uses: a
 *  SOCKS5 listener lives in the backend's identical per-session forward map. */
export async function closeSocksForConnection(
  connectionId: string,
  localPort: number,
  claim: number,
): Promise<void> {
  const key = socksKey(connectionId, localPort);
  await releaseForward(socksForwards, key, connectionId, claim, (f) =>
    closeSshForward(f.sessionId, f.localPort, f.generation),
  );
}
