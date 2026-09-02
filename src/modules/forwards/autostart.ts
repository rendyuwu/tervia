/**
 * `startWithHost`: bring a host's saved forward rules up on the TERMINAL's own
 * SSH session, as that session connects.
 *
 * Reproduces what `conn.forwards` used to do before the SSH/RDP unification
 * (`types.ts`'s `startWithHost` doc, accepted gap 1), on the session the
 * terminal already holds - never through `ssh/tunnel.ts`, which would dial a
 * SECOND russh session to a host this pane is already connected to and show up
 * on the server as two logins (research §5.4, VLT-11). That is why the bridge
 * call here is `openSshForward` (a forward on a session id) rather than
 * `openForwardForConnection` (a forward on a host id, dialling if needed).
 *
 * A MODULE AND NOT A HOOK, for the reason `controller.ts`'s header gives: this
 * runs from a session callback, not a render, so it reads both stores through
 * `getState()` and stays exercisable under plain `node`/`tsx` -
 * `scripts/forward-autostart-verify.ts` drives it through {@link AutostartDeps}
 * with no Tauri and no DOM.
 */

import { closeSshForward, openSshForward } from "@/modules/ssh/bridge";

import { useHostOwnedForwards, type HostOwnedEntry } from "./hostOwned";
import { useForwardRuntime, type ForwardStatus } from "./runtime";
import { listRules } from "./store";
import type { ForwardRule } from "./types";

/**
 * The calls {@link startHostForwards} makes into the rest of the app, so a
 * check can substitute them. The production caller passes the three positional
 * arguments plus `{ ...defaultAutostartDeps, stillLive }` - `stillLive` is the
 * one dep only the CALL SITE's scope can answer, and every other key comes
 * straight off the default. Same seam, and the same reason, as
 * `controller.ts`'s `RuntimeDeps`.
 *
 * `runtimeStatus`, `hostOwnedBy` and `claimHostOwned` are the two STORES, taken
 * as functions rather than imported store handles, so a fixture can drive both
 * exclusions and the claim without reaching into module-level state that other
 * sections of the same script have already written to.
 */
export type AutostartDeps = {
  listRules: () => Promise<ForwardRule[]>;
  /** `ssh/bridge.ts`'s `openSshForward`: binds one `ssh -L` listener on a LIVE
   *  session and resolves with the port it actually bound. */
  openForward: (
    id: number,
    localPort: number,
    remoteHost: string,
    remotePort: number,
  ) => Promise<number>;
  /** `ssh/bridge.ts`'s `closeSshForward`. Needed for exactly one case: a bind
   *  that resolved into a rule the PAGE took while it was in flight. First
   *  claim wins (VLT-94), so the loser closes the listener it just bound rather
   *  than leaving a second one standing that nothing on either side names. */
  closeForward: (id: number, boundPort: number) => Promise<boolean>;
  runtimeStatus: (ruleId: string) => ForwardStatus;
  /** The session id that already owns this rule on some terminal, or
   *  `undefined`. The TERMINAL side of the exclusion, and symmetric with
   *  `runtimeStatus`: that one answers for the page, this one for every other
   *  pane. `hostOwned.ts` is keyed by rule id alone and so cannot represent two
   *  owners, which is why the answer to a second owner is to refuse it. */
  hostOwnedBy: (ruleId: string) => number | undefined;
  claimHostOwned: (ruleId: string, entry: HostOwnedEntry) => void;
  /**
   * Is the session these forwards are being opened on still alive? OPTIONAL,
   * defaulting to `() => true`, because only the caller's own scope can answer
   * it - `ssh-session.ts` closes over a flag it sets at both of its release
   * sites, and module scope here has nothing to close over.
   *
   * Same idiom as `controller.ts:88`'s `isCurrentAttempt` and
   * `pty-lifecycle.ts:75`'s epoch check: an `await` in a lifetime-scoped loop
   * needs a way to ask whether the lifetime is still the one it started in.
   */
  stillLive?: () => boolean;
};

export const defaultAutostartDeps: AutostartDeps = {
  listRules,
  openForward: openSshForward,
  closeForward: closeSshForward,
  // Both stores are read at CALL time, not captured at module load: an action
  // identity read once here would be a second reference to a store this file
  // does not own, and `getState()` is what every other event-handler caller in
  // this codebase does (`controller.ts`, `tunnel.ts:183`).
  runtimeStatus: (ruleId) => useForwardRuntime.getState().byRule[ruleId]?.status ?? "stopped",
  hostOwnedBy: (ruleId) => useHostOwnedForwards.getState().byRule[ruleId]?.sessionId,
  claimHostOwned: (ruleId, entry) => useHostOwnedForwards.getState().claim(ruleId, entry),
  // Module scope knows of no session, so the default answers "alive" and the
  // real one is supplied per call site. A caller that forgets it gets today's
  // behaviour rather than a loop that stops on its first rule.
  stillLive: () => true,
};

/**
 * `terminal/lib/session-helpers.ts`'s `describeError`, copied rather than
 * imported - the third copy, and the same trade `controller.ts:104` already
 * made one file over. That module cannot even be LOADED outside the app: it
 * imports `@xterm/xterm` and `@tauri-apps/plugin-os`, and importing it under
 * `tsx` throws `Cannot read properties of undefined (reading 'currentWindow')`
 * before a single line of this file would run. Six lines is the cheaper of the
 * two prices; VLT-33's extraction is the real remedy.
 *
 * The string branch is the load-bearing one and not boilerplate: a Tauri
 * `invoke` rejects with a RAW STRING, so that is how the backend's own
 * `ssh: bind 127.0.0.1:<port> failed: <io error>` reaches the banner at all.
 */
function describeError(e: unknown): string {
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  try {
    return JSON.stringify(e);
  } catch {
    return String(e);
  }
}

// The banners. `->` in ASCII and not `→`, matching
// `ssh-session.ts:498-501`'s existing forward banner: a terminal under a
// non-UTF-8 font renders the arrow as garbage. The PAGE's route uses `→` - two
// surfaces, two correct answers.
//
// The success line names `bound`, the port the open RESOLVED WITH, and never
// `rule.localPort`: an auto rule asked for 0 and a pinned rule can be handed a
// different port, so naming the requested one is §4.10's second defect exactly.

function forwardingBanner(rule: ForwardRule, bound: number): string {
  return `\x1b[2m[tervia] forwarding localhost:${bound} -> ${rule.remoteHost}:${rule.remotePort} (${rule.name})\x1b[0m\r\n`;
}

/** Non-fatal, so yellow rather than red - the session continues, and only this
 *  one rule is missing. `describeError` and NOT `bindFailureText`: that one is
 *  the page's copy, and it names a port in a sentence a terminal banner has no
 *  room to qualify. */
function failedBanner(rule: ForwardRule, message: string): string {
  return `\x1b[33m[tervia] forward "${rule.name}" failed: ${message}\x1b[0m\r\n`;
}

/**
 * Mutual exclusion (VLT-94): a rule the PAGE has, is left alone, and said out
 * loud - a rule silently not coming up is the shape of a bug.
 *
 * SPLIT BY STATUS, and the difference is not a nicety. `starting` is a page
 * Start still dialling, which can then FAIL - and a rule that is down on both
 * sides, having been told it was up elsewhere, is a wrong answer rather than a
 * louder one. VLT-94's accepted cost covers "already up from the page", not
 * "tried and failed".
 */
function skippedBanner(rule: ForwardRule, status: "running" | "starting"): string {
  return status === "running"
    ? `\x1b[33m[tervia] forward "${rule.name}" is already running from the Port Forwarding page; not starting a second one.\x1b[0m\r\n`
    : `\x1b[33m[tervia] forward "${rule.name}" is starting from the Port Forwarding page; not starting a second one.\x1b[0m\r\n`;
}

/** The other half of the exclusion: another PANE's session already has this
 *  rule open on this host. The terminal deliberately dials its own session per
 *  pane (`ssh/tunnel.ts:31-35`), so two tabs to one host are two autostart
 *  runs. Deliberately does NOT say the page owns it - it does not. */
function otherTerminalBanner(rule: ForwardRule): string {
  return `\x1b[33m[tervia] forward "${rule.name}" is already open on another terminal for this host; not starting a second one.\x1b[0m\r\n`;
}

/** The page took this rule while this bind was in flight. First claim wins, so
 *  this one closes the listener it just bound and says so, rather than leaving
 *  a second listener up that no store on either side names. */
function yieldedBanner(rule: ForwardRule): string {
  return `\x1b[33m[tervia] forward "${rule.name}" was started from the Port Forwarding page while this one was binding; closing the one this terminal just opened.\x1b[0m\r\n`;
}

/**
 * Open every `startWithHost` rule bound to `hostId` on the terminal's own live
 * session, writing one banner per rule.
 *
 * NEVER REJECTS, and STRUCTURALLY so rather than by a neighbour's ordering. The
 * call site is fire-and-forget from inside the connect path, so a rejection
 * would be an unhandled promise rejection - and worse, one rule that cannot
 * bind would silently drop every rule after it. A busy local port must not turn
 * into a failed SSH connect.
 *
 * SEQUENTIAL, in `listRules` order, one `await` each. Not `Promise.all`: the
 * banner order is what the user reads, and N concurrent binds on one fresh
 * session buys nothing.
 */
export async function startHostForwards(
  hostId: string,
  sessionId: number,
  writeBanner: (text: string) => void,
  deps: AutostartDeps = defaultAutostartDeps,
): Promise<void> {
  // THE OUTER CATCH IS WHAT MAKES THE SIGNATURE HONEST, and it is not the same
  // guard as the per-rule one below. That one keeps the LOOP going: one rule
  // whose bind rejected must not drop the rules after it. This one covers
  // everything the loop's own body is not wrapped in - `writeBanner` itself,
  // `deps.runtimeStatus`, `deps.hostOwnedBy`, and a `writeBanner` that throws
  // from INSIDE the per-rule catch, where there is no handler left. Today none
  // of those throws in production, but only because `writeSshBanner` guards
  // `s.disposed` and `s.term.dispose()` runs after that flag is set
  // (`ssh-session.ts:76-84`, `session-lifecycle.ts:732,744`) - a claim about
  // another file's ordering, which is not what a doc comment saying NEVER
  // REJECTS should rest on.
  try {
    let rules: ForwardRule[];
    try {
      rules = await deps.listRules();
    } catch (e) {
      // The store itself is unreadable (a torn file recovery that failed, a
      // plugin error). One banner and nothing else - there is no rule to name.
      writeBanner(
        `\x1b[33m[tervia] could not read the forward rules: ${describeError(e)}\x1b[0m\r\n`,
      );
      return;
    }

    const mine = rules.filter((rule) => rule.hostId === hostId && rule.startWithHost);
    for (const rule of mine) {
      // THE TERMINAL'S OWN MAP FIRST, then the page's. Two exclusions, neither
      // implying the other, and this one is checked first for two reasons: it is
      // the more specific claim (a rule another pane holds is not a rule the
      // page is running), and the page's banner would name the wrong owner if it
      // won the race to be printed.
      //
      // `!== sessionId` and not a bare presence test: a rule THIS session
      // already owns is the reconnect-with-the-same-id case, and that cannot
      // happen - `next_id` is a monotonic `AtomicU32` from 1
      // (`src-tauri/src/modules/ssh/mod.rs:52,59,476`). The comparison is
      // written anyway so the code says what it means instead of resting on
      // that.
      const owner = deps.hostOwnedBy(rule.id);
      if (owner !== undefined && owner !== sessionId) {
        writeBanner(otherTerminalBanner(rule));
        continue;
      }
      const status = deps.runtimeStatus(rule.id);
      if (status === "running" || status === "starting") {
        writeBanner(skippedBanner(rule, status));
        continue;
      }
      try {
        const bound = await deps.openForward(
          sessionId,
          rule.localPort,
          rule.remoteHost,
          rule.remotePort,
        );
        // THE SESSION DIED WHILE THIS BIND WAS IN FLIGHT. Both release sites are
        // ONE-SHOT - `finishSsh` is behind `terminated` and the pane adapter's
        // `close` fires once - so an entry claimed after either of them ran is
        // never released: the row reads "Running (with host)" for the rest of
        // the app's life, with Start/Stop disabled and a note telling the user
        // to close a tab that is already gone.
        //
        // The window is the whole run - `disposeSession` releases SYNCHRONOUSLY
        // and only then issues `ssh_close`, while this loop is already parked on
        // an `ssh_forward_open` issued earlier, and the backend's read lock
        // usually wins that race.
        //
        // BREAK, not `continue`: there is nothing to bind further forwards on,
        // and no banner is worth writing because the pane is gone. Not claiming
        // is sufficient - the backend reaps the orphaned listener when the last
        // `Arc<Session>` drops (`src-tauri/src/modules/ssh/session.rs:386-393`
        // and the `Drop` at `:627-643`), so what leaks here is only frontend
        // state.
        if (!(deps.stillLive?.() ?? true)) break;
        // RE-READ THE PAGE'S STATUS, because the read above happened before the
        // await and `controller.ts`'s `markStarting` is synchronous: the user
        // can click Start at any point during this bind. First claim wins
        // (VLT-94), so the loser closes its own listener - anything else leaves
        // two live listeners for one rule, or a row whose button and status line
        // disagree about who owns it.
        const taken = deps.runtimeStatus(rule.id);
        if (taken === "running" || taken === "starting") {
          // Not awaited into the per-rule catch below: a close that reports a
          // failure must not print `failedBanner`, which would say the forward
          // could not be opened when in fact it opened and was handed over.
          // `.catch` and not a bare `void`, matching this file's call site and
          // `ssh-session.ts:336`.
          void deps.closeForward(sessionId, bound).catch(() => {});
          writeBanner(yieldedBanner(rule));
          continue;
        }
        // CLAIMED BEFORE THE BANNER. The banner is what the user sees; the claim
        // is what the page reads. Reversed, anything that threw in between would
        // leave the user told about a forward the page cannot see.
        deps.claimHostOwned(rule.id, { sessionId, boundPort: bound });
        writeBanner(forwardingBanner(rule, bound));
      } catch (e) {
        // Per-rule and non-fatal: this rule says why, and the loop CONTINUES to
        // the next one.
        writeBanner(failedBanner(rule, describeError(e)));
      }
    }
  } catch {
    // Swallowed on purpose and with nowhere else to go: this function's own
    // contract is that it never rejects, and its caller is a bare `void` inside
    // the connect path. There is no surface left to report on either - the
    // thing that failed is very often the banner writer itself.
  }
}
