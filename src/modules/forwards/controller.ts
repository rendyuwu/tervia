/**
 * Start and stop one forward rule: the single place a saved `ForwardRule`
 * becomes an SSH call.
 *
 * A MODULE AND NOT A HOOK, deliberately. Start and Stop are event handlers, so
 * they read the runtime store through `getState()` rather than a selector
 * (`runtime.ts`'s note on the `claim`), and keeping them out of the component
 * tree is what lets a self-check drive them under plain node against the same
 * Tauri stand-in `scripts/rdp-tunnel-verify.ts` already builds. That is also
 * why `toast` arrives through {@link RuntimeDeps} instead of a module-level
 * import: `components/ui/toast` is a `.tsx` that pulls in React and
 * lucide-react, and exercising a Start must not cost a node process a JSX
 * module.
 *
 * # What a failed Start owes
 *
 * The same sentence in two places, on purpose. A toast, which is self-expiring
 * and outlives the row's own mount, AND the row's status line, which is where
 * the user looks for THIS rule. Both come from `bindFailureText`
 * (`page/derive.ts`), so the two cannot drift into two paraphrases of one
 * failure.
 *
 * # What a Stop owes a Start that has not finished
 *
 * Two things, and neither is optional. It must answer a host-key question the
 * user never got to, because a prompt nobody answers costs a held socket, a
 * handshake parked for the backend's full confirm timeout and - the verifier
 * blocks - a displaced runtime thread. And it must leave the arriving forward
 * with no owner, so the Start that eventually resolves gives the reference
 * straight back instead of publishing a rule the user has already stopped.
 *
 * # Autostart and the backoff ladder
 *
 * {@link startForwardAutostart} is the ONLY caller that keeps retrying after a
 * Start that never rejects: `src/app/hooks/useForwardsAutostart.ts` calls it
 * once per `startWithApp` rule after the stores it needs have hydrated, and it
 * re-calls itself, through a `setTimeout` on `FORWARD_RECONNECT_BACKOFF_MS`,
 * whenever the failure `startRule`'s new `onFailure` hook handed it classifies
 * as `"reconnect"` - the exact `classifySshConnectFailure`/
 * `decideSshConnectFailure` pair `ssh-session.ts`'s own terminal ladder uses
 * (`@/modules/terminal/lib/ssh-exit-decision`), reused rather than mirrored so
 * a local/rejected failure (bad credential, host removed, host key declined)
 * parks on the FIRST attempt exactly as it does there. Bounded at the first
 * attempt plus `FORWARD_RECONNECT_BACKOFF_MS.length` retries, then the row is
 * left `failed` with the last error - no poll loop.
 *
 * `cancelForwardRetry` runs at the top of `startRule` (a manual Start resets
 * the ladder) and inside `stopRule`, right after its terminal-owned guard (a
 * manual Stop cancels it). `pageMustStopFirst` answers `true` for a rule with
 * a pending retry as well as for `running`/`starting`, so the delete confirm
 * and the editor's save - the two callers this ladder must never survive -
 * both route through `stopRule` for an already-`failed` row too, and that one
 * call is enough: there is no separate cancel in `releaseRule`.
 */

import { toast } from "@/components/ui/toast";
import { describeError } from "@/lib/describeError";
import { useHostKeyPrompt } from "@/modules/ssh/hostKeyPrompt";
import {
  closeForwardForConnection,
  closeRemoteForwardForConnection,
  closeSocksForConnection,
  openForwardForConnection,
  openRemoteForwardForConnection,
  openSocksForConnection,
} from "@/modules/ssh/tunnel";
// The pair `ssh-session.ts`'s own terminal ladder classifies a connect
// failure with, imported the same way `src/modules/ssh/bridge.ts` (a sibling
// `ssh` module) already imports these same two carrier classes - they belong
// to `ssh-exit-decision.ts`, not to this file. See this file's header.
import {
  classifySshConnectFailure,
  decideSshConnectFailure,
} from "@/modules/terminal/lib/ssh-exit-decision";

import { useHostOwnedForwards } from "./hostOwned";
import { bindFailureText } from "./page/derive";
import { useForwardRuntime } from "./runtime";
import { dropRulesForHost, listRules } from "./store";
import type { ForwardRule } from "./types";

/**
 * The calls {@link startRule} and {@link stopRule} make into the rest of the
 * app, so a check can substitute them. EVERY PRODUCTION CALLER PASSES ONE
 * ARGUMENT and never builds one of these.
 *
 * Exactly the three things a plain node process cannot have: the two halves of
 * the forward bridge, which would otherwise need a real Tauri IPC, and `toast`,
 * which is a JSX module. Everything else is imported directly and stays out of
 * here on purpose - a zustand store runs fine under `tsx` (this suite already
 * drives `hostKeyPrompt.ts`'s), so `useForwardRuntime.getState()` is how a
 * check reads what a Start recorded, and `useHostKeyPrompt.getState().queue` is
 * how it sees what a Stop did to an abandoned question. A seam wide enough to
 * fake those would be a seam that can pass while the real store disagrees.
 */
export type RuntimeDeps = {
  openForward: typeof openForwardForConnection;
  closeForward: typeof closeForwardForConnection;
  toast: typeof toast;
};

export const defaultRuntimeDeps: RuntimeDeps = {
  openForward: openForwardForConnection,
  closeForward: closeForwardForConnection,
  toast,
};

/**
 * The retry ladder {@link startForwardAutostart} walks on a transport-class
 * failure - longer than `ssh-session.ts`'s own `RECONNECT_BACKOFF_MS` because
 * nobody is watching a terminal tab for it to give up sooner.
 */
const FORWARD_RECONNECT_BACKOFF_MS = [1_000, 3_000, 7_000, 15_000, 30_000] as const;

/**
 * One pending retry's timer, per rule id - the handle {@link
 * cancelForwardRetry} clears and {@link pageMustStopFirst} checks for.
 * Entries live only while a retry is SCHEDULED, never while a dial is in
 * flight - {@link attemptForwardAutostart} deletes its own entry before it
 * calls `startRule`. How many attempts this ladder run has already made
 * travels as {@link attemptForwardAutostart}'s own `priorAttempts` parameter
 * instead of living here, since nothing outside that recursion ever reads it.
 */
const forwardRetries = new Map<string, ReturnType<typeof setTimeout>>();

/** Cancel `ruleId`'s pending retry, if it has one. Idempotent - safe to call
 *  from every site that ends a rule's autostart lifecycle whether or not one
 *  is actually pending. */
function cancelForwardRetry(ruleId: string): void {
  const timer = forwardRetries.get(ruleId);
  if (timer === undefined) return;
  clearTimeout(timer);
  forwardRetries.delete(ruleId);
}

/**
 * Host-key questions raised by each rule's IN-FLIGHT Start, keyed by rule id.
 *
 * The Set's IDENTITY is load-bearing as well as its contents, which is why the
 * map holds one per attempt rather than a flat list of ids:
 *
 * - A Stop while a Start is still dialling has to abandon the question, or the
 *   rule leaves a prompt behind that nobody will ever answer (see
 *   `SshForwardOptions.onHostKeyPrompt`). Now that the release is awaited, that
 *   same question is also what the release would be waiting on.
 * - A Start that finally resolves has to know whether it is still WANTED. A
 *   Stop deletes this entry and a later Start replaces it, so an attempt whose
 *   own Set is no longer the one on file has been superseded - whatever the
 *   store happens to say by then. Same reasoning as `SshForward.claim`: an
 *   identity survives a key being re-used, and "is the status still
 *   `starting`?" cannot tell a stop from a restart.
 */
const startAttempts = new Map<string, Set<string>>();

/** True while `prompts` is still the rule's current Start: no Stop has cleared
 *  it and no later Start has replaced it. */
function isCurrentAttempt(ruleId: string, prompts: Set<string>): boolean {
  return startAttempts.get(ruleId) === prompts;
}

/** What a Start refused because a terminal already holds the rule says. Not the
 *  same sentence as `RuleCard`'s `HOST_OWNED_NOTE`, and not shared with it: that
 *  file is a `.tsx` and importing it here would cost this module the
 *  "exercisable under plain node" property the header exists for. This one also
 *  names the rule, because a toast outlives the row it came from. */
function hostOwnedRefusalText(rule: ForwardRule): string {
  return `"${rule.name}" is already open on its terminal. Close that terminal tab to stop it.`;
}

/** What a Start says when its dial LANDED - resolved or rejected - into a rule
 *  that had meanwhile come up on its TERMINAL. A different sentence from
 *  {@link hostOwnedRefusalText} because a different thing happened: that one
 *  never dialled, this one did and then stood down - giving the reference
 *  back if the dial resolved, or discarding its failure if it rejected (most
 *  often EADDRINUSE on the port the terminal now holds). A warning, not an
 *  error, and the row goes to `stopped`: the forward the user asked for is
 *  up. Ends in the same sentence as the refusal, because the answer to "how
 *  do I stop it now" is the same. */
function hostOwnedYieldText(rule: ForwardRule): string {
  return `"${rule.name}" came up on its terminal while this Start was dialling. Close that terminal tab to stop it.`;
}

/**
 * Bring `rule` up, and record the bound port and the claim its Stop will need.
 *
 * `promptForHostKey` is passed because the page has a dialog on screen and can
 * answer, which is the flag's one precondition
 * (`SshForwardOptions.promptForHostKey`). This is the second of the two callers
 * that meet it; `rdp/dial.ts` is the other.
 *
 * NEVER REJECTS. The caller is a click handler with nowhere to put an
 * exception, so a failure reports through the store and a toast instead.
 * `onFailure`, if given, sees the RAW error anyway - {@link
 * startForwardAutostart} is the one caller that passes it, to classify a real
 * failure (never a hostOwned yield, which is not one) for its own retry
 * ladder.
 *
 * REFUSES A TERMINAL-OWNED RULE, ahead of everything else, AND YIELDS TO ONE
 * THAT ARRIVES MID-DIAL. `RuleCard` disables the button for one, but a disabled
 * button is a rendering and not an invariant - and the row's `hostOwned` can
 * become true while this page's own Start is in flight, so the guard has to live
 * where the dial does and it has to be read on BOTH sides of the await. First
 * claim wins: if the terminal's claim was already taken this never
 * dials, and if it lands during the dial this hands the reference it just
 * received straight back. If its own dial rejects after such a claim, it marks
 * the rule `stopped` rather than `failed`.
 *
 * CANCELS ANY PENDING RETRY FIRST, unconditionally - the other line this
 * function's own cancel is paired with is {@link stopRule}'s, which
 * `releaseRule` reaches through `pageMustStopFirst` rather than calling
 * `cancelForwardRetry` a second time itself. A manual Start (the ordinary
 * caller) resets the ladder; the ladder's OWN re-entry
 * (`startForwardAutostart`) cancels its own already-fired timer, a harmless
 * no-op against an entry that is already gone.
 */
export async function startRule(
  rule: ForwardRule,
  runtime: RuntimeDeps = defaultRuntimeDeps,
  onFailure?: (e: unknown) => void,
): Promise<void> {
  cancelForwardRetry(rule.id);
  // `-R`/`-D` are a SEPARATE code path, not routed through `RuntimeDeps`:
  // nothing in this codebase drives them through a fake yet (see
  // `KNOWN-LIMITS.md`). Kept as an early branch so every statement below this
  // one is the ORIGINAL `-L` body, untouched.
  if (rule.type) {
    await startTypedRule(rule, runtime, onFailure);
    return;
  }
  // `useHostOwnedForwards` imported directly rather than routed through
  // `RuntimeDeps`, exactly as `useForwardRuntime` and `useHostKeyPrompt`
  // already are and for the reason this file's header gives: a zustand store
  // runs fine under `tsx`, so a check reads what the REAL store says, and a
  // seam wide enough to fake one would be a seam that can pass while the real
  // store disagrees.
  //
  // Before `markStarting`, so a refused Start leaves the page's own store
  // untouched: it took no claim, so it must not publish a status it would then
  // have to spend a claim to leave.
  if (useHostOwnedForwards.getState().byRule[rule.id] !== undefined) {
    runtime.toast(hostOwnedRefusalText(rule), { variant: "warning" });
    return;
  }
  const prompts = new Set<string>();
  startAttempts.set(rule.id, prompts);
  useForwardRuntime.getState().markStarting(rule.id);
  try {
    const forward = await runtime.openForward(rule.hostId, rule.remoteHost, rule.remotePort, {
      localPort: rule.localPort,
      promptForHostKey: true,
      onHostKeyPrompt: (promptId) => prompts.add(promptId),
    });
    if (!isCurrentAttempt(rule.id, prompts)) {
      // Stopped, or restarted, while this dial was in flight. The reference it
      // took is real and nothing names it any more - `markStopped` drops the
      // claim - so it goes back here, or the port stays bound with no consumer
      // left that could free it. Awaited rather than fired off, so the close
      // cannot land on a listener a later Start has since bound on that port.
      await runtime.closeForward(
        rule.hostId,
        rule.remoteHost,
        rule.remotePort,
        rule.localPort,
        forward.claim,
      );
      return;
    }
    // THE PAGE'S HALF OF THE YIELD, and it is the same rule as `autostart.ts`'s
    // post-bind one seen from the other side: whoever resolves SECOND gives up
    // the duplicate it created. The refusal at the top of this function is the
    // pre-dial read; this is the post-dial one, and it is needed for the same
    // reason every pre-await read in this pair needs a partner - the terminal's
    // claim is synchronous and can land at any point during this dial.
    //
    // The terminal now CLAIMS on `starting` rather than yielding
    // (`autostart.ts`'s note on that branch), which is what makes this side's
    // yield the one that closes the window: without it, a dial that RESOLVES
    // after the terminal's claim publishes a second listener beside the
    // terminal's. A dial that REJECTS instead - EADDRINUSE, because the
    // terminal holds the pinned port - is the `catch` arm's half of this same
    // yield. With this yield, the reference this dial just took goes straight
    // back and nothing is left that no store names.
    //
    // `markStopped` and NOT `markFailed`: nothing failed. The forward the user
    // asked for is up; it is simply up somewhere this store cannot see, and
    // `RuleCard` renders that off `hostOwned` alone.
    if (useHostOwnedForwards.getState().byRule[rule.id] !== undefined) {
      // Awaited, for the same reason the superseded-attempt release above is:
      // a close that landed later could land on a listener a subsequent Start
      // has since bound on that port.
      await runtime.closeForward(
        rule.hostId,
        rule.remoteHost,
        rule.remotePort,
        rule.localPort,
        forward.claim,
      );
      useForwardRuntime.getState().markStopped(rule.id);
      runtime.toast(hostOwnedYieldText(rule), { variant: "warning" });
      return;
    }
    useForwardRuntime.getState().markRunning(rule.id, {
      boundPort: forward.localPort,
      sessionId: forward.sessionId,
      claim: forward.claim,
    });
  } catch (e) {
    // A Start the user has already stopped says nothing at all. The failure is
    // very often the abandon itself - a rejected host key aborts the handshake -
    // and "failed" on a row the user deliberately stopped is a wrong answer,
    // not a louder one.
    if (!isCurrentAttempt(rule.id, prompts)) return;
    // THE REJECTING HALF OF THE SAME YIELD. The terminal claimed this rule
    // mid-dial (`autostart.ts` claims on `starting`) and usually holds the very
    // pinned port this dial just failed to bind, so the rejection is the
    // forward the user asked for being up. `markFailed` here would park an
    // error `RuleCard` hides under `hostOwned` and brings back when that tab
    // closes. Same arm as the resolved yield above, minus the release: a
    // rejected dial took no reference.
    if (useHostOwnedForwards.getState().byRule[rule.id] !== undefined) {
      useForwardRuntime.getState().markStopped(rule.id);
      runtime.toast(hostOwnedYieldText(rule), { variant: "warning" });
      return;
    }
    // Dismissed before reporting a real failure: a prompt left on screen
    // would queue behind the next rung's own question and ask the user
    // twice, the same reason `ssh-session.ts`'s own connect catch dismisses
    // its prompt first.
    for (const id of prompts) useHostKeyPrompt.getState().dismiss(id);
    // `rule.localPort`, not a bound port: a bind that failed bound nothing, and
    // the port these sentences name is the one that was asked for.
    onFailure?.(e);
    const text = bindFailureText(describeError(e), rule.localPort);
    useForwardRuntime.getState().markFailed(rule.id, text);
    runtime.toast(text, { variant: "error" });
  } finally {
    // Only ever ours to clear: a later Start has published its own Set, and a
    // Stop has already taken this one out.
    if (startAttempts.get(rule.id) === prompts) startAttempts.delete(rule.id);
  }
}

/**
 * One open call plus its matching close, picked by `rule.type`, with the
 * result normalised to the three fields {@link startTypedRule} reads:
 * `boundPort` names `tunnel.ts`'s `SshSocksForward.localPort` for a `-D`
 * rule and its `SshRemoteForward.boundPort` for a `-R` one - the same
 * "whichever party actually listens" fact under one name, so the caller
 * below does not need its own type branch to read it.
 *
 * `rule.bindAddress` is passed through AS-IS, blank and all: `tunnel.ts`'s
 * `openRemoteForwardForConnection`/`closeRemoteForwardForConnection` each
 * normalise it identically (`.trim() || "localhost"`), which is the one
 * place that owns the map key built from it, so handing both the same raw
 * string keeps them agreeing without a second copy of that rule here.
 */
function openTypedRule(
  rule: ForwardRule,
  prompts: Set<string>,
): [
  Promise<{ boundPort: number; sessionId: number; claim: number }>,
  (claim: number) => Promise<void>,
] {
  const promptOpts = {
    promptForHostKey: true as const,
    onHostKeyPrompt: (promptId: string) => prompts.add(promptId),
  };
  if (rule.type === "dynamic") {
    return [
      openSocksForConnection(rule.hostId, rule.localPort, promptOpts).then((f) => ({
        boundPort: f.localPort,
        sessionId: f.sessionId,
        claim: f.claim,
      })),
      (claim) => closeSocksForConnection(rule.hostId, rule.localPort, claim),
    ];
  }
  const bindAddress = rule.bindAddress ?? "";
  const bindPort = rule.bindPort ?? 0;
  const targetHost = rule.targetHost ?? "";
  const targetPort = rule.targetPort ?? 0;
  return [
    openRemoteForwardForConnection(
      rule.hostId,
      bindAddress,
      bindPort,
      targetHost,
      targetPort,
      promptOpts,
    ).then((f) => ({ boundPort: f.boundPort, sessionId: f.sessionId, claim: f.claim })),
    (claim) =>
      closeRemoteForwardForConnection(
        rule.hostId,
        bindAddress,
        bindPort,
        targetHost,
        targetPort,
        claim,
      ),
  ];
}

/**
 * The `-R`/`-D` half of {@link startRule}, split out because the shape is
 * different enough from `-L`'s single-port dial to make one function harder
 * to read rather than easier - see `src/modules/forwards/types.ts`'s
 * field-by-field doc on `ForwardRule` for which field each type dials.
 *
 * Repeats `-L`'s own refusal/yield shape (terminal-owned refusal, the
 * superseded-attempt release, the post-dial yield, the rejecting-dial yield)
 * rather than sharing code with it, because the two dials take different
 * arguments end to end and a shared helper would have to accept both shapes
 * anyway. {@link openTypedRule} above is the `-R`/`-D` PAIR sharing code
 * with EACH OTHER, which is the duplication that was actually free to
 * remove: both arms took the same refusal/yield shape written out twice,
 * open and close each spelled with every one of their own five/six
 * arguments a second time.
 */
async function startTypedRule(
  rule: ForwardRule,
  runtime: RuntimeDeps,
  onFailure?: (e: unknown) => void,
): Promise<void> {
  if (useHostOwnedForwards.getState().byRule[rule.id] !== undefined) {
    runtime.toast(hostOwnedRefusalText(rule), { variant: "warning" });
    return;
  }
  const prompts = new Set<string>();
  startAttempts.set(rule.id, prompts);
  useForwardRuntime.getState().markStarting(rule.id);
  try {
    const [pending, close] = openTypedRule(rule, prompts);
    const forward = await pending;
    if (!isCurrentAttempt(rule.id, prompts)) {
      await close(forward.claim);
      return;
    }
    if (useHostOwnedForwards.getState().byRule[rule.id] !== undefined) {
      await close(forward.claim);
      useForwardRuntime.getState().markStopped(rule.id);
      runtime.toast(hostOwnedYieldText(rule), { variant: "warning" });
      return;
    }
    useForwardRuntime.getState().markRunning(rule.id, {
      boundPort: forward.boundPort,
      sessionId: forward.sessionId,
      claim: forward.claim,
    });
  } catch (e) {
    if (!isCurrentAttempt(rule.id, prompts)) return;
    if (useHostOwnedForwards.getState().byRule[rule.id] !== undefined) {
      useForwardRuntime.getState().markStopped(rule.id);
      runtime.toast(hostOwnedYieldText(rule), { variant: "warning" });
      return;
    }
    // Dismissed before reporting a real failure - see `-L`'s own catch above
    // for why.
    for (const id of prompts) useHostKeyPrompt.getState().dismiss(id);
    const text = describeError(e);
    onFailure?.(e);
    useForwardRuntime.getState().markFailed(rule.id, text);
    runtime.toast(text, { variant: "error" });
  } finally {
    if (startAttempts.get(rule.id) === prompts) startAttempts.delete(rule.id);
  }
}

/**
 * Is this rule's forward THIS PAGE's to stop, RIGHT NOW?
 *
 * READ LIVE, and that is the whole of why the function exists: both facts it
 * asks about change while a dialog is on screen. `page/RuleCard.tsx` hands the
 * page a `running` flag captured at CLICK time, and the row is on screen as
 * `starting` for the whole dial - connect, host key, bind, routinely 1-3
 * seconds - so the ORDINARY sequence is Start, Delete, the dial resolves, then
 * the confirm click. That is not the unlucky ordering, it is the common one.
 *
 * A guard on the captured flag therefore removes (or rewrites) the record of a
 * forward that came up in between, and the cost of that is not a stale label:
 * `runtime.ts` keeps an entry naming a rule no row renders, so no Stop is ever
 * offered again; `ssh/tunnel.ts`'s entry stays at `refs: 1`, so the SSH session
 * never closes for the rest of the app's life; and the local port stays bound,
 * with re-creating a rule on the same pinned port then failing EADDRINUSE and
 * no in-app recovery.
 *
 * `"starting"` COUNTS, AND NOT ONLY `"running"`. Reading live closes the
 * ordering where the dial resolves BETWEEN the trash click and the confirm
 * click; it leaves open the one where it resolves AFTER the confirm, which is
 * the same two clicks with a faster second one or a slower connect (and neither
 * the trash nor the Edit button is disabled while the row dials - only the
 * toggle is). On that ordering a `running`-only guard says no, the caller
 * removes or rewrites the record, nothing clears {@link startAttempts}, and the
 * dial that lands afterwards is still the CURRENT attempt: `markRunning` runs
 * for a rule no row can render, and every cost the paragraph above names is
 * back.
 *
 * `"stopped"` MUST STAY OUT, unconditionally: `markStopped` never retains a
 * claim (`runtime.ts`'s note on the reset), so there is nothing for a Stop to
 * spend and a Stop nobody asked for is what including it would buy.
 *
 * `"failed"` IS OUT TOO, UNLESS A RETRY IS PENDING. `markFailed` only ever
 * runs when the open REJECTED and retains no claim either, so an ordinary
 * `failed` row is the same as `stopped` here. But {@link forwardRetries} can
 * hold a SCHEDULED re-dial for one - the backoff ladder's own re-entry, see
 * this file's header - and that timer is exactly the "pending Start" this
 * function already answers `true` for while a dial is in flight. Left
 * unguarded, the delete confirm and the editor's save (the two callers below)
 * would leave that timer alive, and it would re-bind a rule the write just
 * removed or rewrote - the leak this predicate's own doc used to warn only
 * `stopRule` about. So `forwardRetries.has` is read right after the
 * `hostOwned` line, ahead of the status check, and a hit answers `true`
 * regardless of what `status` says.
 *
 * INCLUDING `"starting"` IS SAFE AND NOT MERELY DIFFERENT, which is the half
 * worth writing down: `stopRule` deletes the attempt Set and abandons the
 * host-key questions, so the dial that resolves next finds itself superseded
 * (see `isCurrentAttempt`) and hands the reference it just took straight
 * back. One close,
 * the row `stopped`, no claim retained - the same release path a Stop clicked
 * mid-dial has always taken.
 *
 * `getState()` and not a selector, for the reason this file's header gives:
 * every caller is an event handler and not a render. The two owners are read in
 * the SAME ORDER `page/RuleCard.tsx`'s header states for all nine of its own
 * sites - `hostOwned` FIRST. A forward a TERMINAL opened is never this page's to
 * stop (it dies with that tab, and this page holds no reference it could spend),
 * and while the combination that arm refuses - a terminal owning a rule the page
 * also has `running` - is unconstructible today for exactly the reasons that
 * header sets out, the answer here must not rest on an argument about two other
 * files' interleavings.
 *
 * THE TWO CALLERS are the page's delete confirm and the editor's save: the two
 * places that REMOVE or REWRITE the record a live forward was opened under.
 * `RuleCard`'s own Start/Stop button deliberately does not use it - that button
 * reads its status through selectors and re-renders on every change, so it has
 * no stale flag to correct.
 */
export function pageMustStopFirst(ruleId: string): boolean {
  if (useHostOwnedForwards.getState().byRule[ruleId] !== undefined) return false;
  if (forwardRetries.has(ruleId)) return true;
  const status = useForwardRuntime.getState().byRule[ruleId]?.status;
  return status === "running" || status === "starting";
}

/**
 * Take `rule` down: answer anything its Start is still parked on, hand the
 * reference back, and mark it stopped once the backend has heard.
 *
 * NO `stopping` STATUS, and none is needed. `RuleCard` offers Start only for
 * `stopped`/`failed`, so while this is in flight the row still reads `running`
 * and still shows Stop - which serialises Stop-then-Start by construction
 * rather than by a guard, for a transition that lasts one IPC round trip.
 * Firing it twice over is safe either way: `closeForwardForConnection` is a
 * no-op for an entry already spent.
 *
 * A STOP WITH NO CLAIM RECORDED closes nothing and still marks the rule
 * stopped. Either it was never started or the store has forgotten it, and
 * spending a reference that was never taken is how another consumer's session
 * gets closed - see `SshForward.claim`.
 *
 * CANCELS A PENDING RETRY, unconditionally, right after the terminal-owned
 * guard below - see this file's header on the backoff ladder, and that
 * guard's own comment for why skipping the cancel there is safe. A no-op for
 * a rule with none.
 */
export async function stopRule(
  rule: ForwardRule,
  runtime: RuntimeDeps = defaultRuntimeDeps,
): Promise<void> {
  // DEFENCE IN DEPTH, AND UNREACHABLE TODAY - said here so the next reader does
  // not delete it as dead. A forward a TERMINAL opened is never this page's to
  // stop: this side holds no claim it could spend, so a close issued from here
  // either misses (there is no entry under this key) or spends a reference the
  // terminal still needs, which is how another consumer's session gets closed -
  // see `SshForward.claim`.
  //
  // WHAT REACHES IT. Nothing today: every caller either asks
  // {@link pageMustStopFirst} first, whose own FIRST line reads this same map,
  // or is `page/RuleCard.tsx`'s Stop button, which sits behind that row's early
  // return on `hostOwned` - and an early return is a RENDERING, not an
  // invariant. The sequence that DOES reach it is a second unguarded caller: a
  // "Stop all" button that sweeps the page's rules, a reconciler, or a
  // regression in `RuleCard`'s early return. This guard is here so the answer
  // does not depend on which of those lands first, and on the same reasoning
  // {@link startRule}'s own terminal-owned refusal gives - the guard has to live
  // where the close does.
  //
  // KEPT AS THE FIRST STATEMENT, ahead of the retry cancel right below it: a
  // host-owned rule can never hold a page retry - `onFailure` only fires
  // after BOTH catch arms' own `hostOwned` checks have already returned false
  // - so there is nothing this early return skips cancelling, and a rule
  // this page never touches is never even considered for one.
  if (useHostOwnedForwards.getState().byRule[rule.id] !== undefined) return;

  // A no-op for a rule with none. Placed here, rather than at the very top,
  // so the guard above stays this function's first statement - see its own
  // comment for why that ordering is safe.
  cancelForwardRetry(rule.id);

  // Answered FIRST, ahead of the close below. A Start parked on an unanswered
  // host-key question holds a socket, a handshake and a blocked runtime thread
  // until the backend's confirm timeout - and now that a release waits for the
  // open that is binding the port, that question is also what the wait would be
  // waiting on. Abandoning rejects it, which aborts the handshake, which is
  // what lets both of them finish.
  const prompts = startAttempts.get(rule.id);
  startAttempts.delete(rule.id);
  for (const promptId of prompts ?? []) useHostKeyPrompt.getState().abandon(promptId);

  // `getState()` and not a selector, the same way `tunnel.ts` reads the prompt
  // queue: this is an event handler and not a render, and a `claim` behind a
  // selector would be a value that changes on every restart driving renders
  // that do not care.
  const claim = useForwardRuntime.getState().byRule[rule.id]?.claim;
  try {
    if (claim !== undefined) {
      if (rule.type === "dynamic") {
        await closeSocksForConnection(rule.hostId, rule.localPort, claim);
      } else if (rule.type === "remote") {
        // `bindAddress` passed AS-IS - see `openTypedRule`'s own doc above
        // for why an unnormalised value here still agrees with the open.
        await closeRemoteForwardForConnection(
          rule.hostId,
          rule.bindAddress ?? "",
          rule.bindPort ?? 0,
          rule.targetHost ?? "",
          rule.targetPort ?? 0,
          claim,
        );
      } else {
        await runtime.closeForward(
          rule.hostId,
          rule.remoteHost,
          rule.remotePort,
          // The port the open ASKED FOR - `rule.localPort`, 0 for an auto rule -
          // and never the bound one. That is what names the entry alongside the
          // target; `closeForwardForConnection`'s own doc spells out why the
          // asymmetry with open's optional `opts.localPort` is deliberate.
          rule.localPort,
          claim,
        );
      }
    }
  } finally {
    // Stopped even if the close threw. The entry it named is deleted before the
    // backend is told anything, so a row left `running` would offer a Stop with
    // nothing behind it. Nothing reaches this today - the release's own chain
    // ends in `.catch(() => {})` - and it is a `finally` rather than a `catch`
    // precisely so a close that one day DOES report is not swallowed here.
    useForwardRuntime.getState().markStopped(rule.id);
  }
}

/**
 * Give up whatever THIS PAGE holds for `rule`, ahead of a write that removes or
 * rewrites the record the forward was opened under.
 *
 * The two lines `ForwardsPage`'s delete confirm and `RuleEditorDialog`'s save
 * each already write inline, named once here so a third caller cannot get the
 * pair wrong. {@link pageMustStopFirst} is a LIVE read and not a flag captured
 * at click time, for every reason its own doc gives.
 *
 * NOT A NO-OP THAT PRETENDS OTHERWISE. For a rule this page never started, one
 * a terminal owns, and one already `stopped` (or `failed` with no retry
 * pending), the guard says no and nothing is spent - which is the whole of why
 * the guard is inside this function rather than at each caller.
 *
 * NO CANCEL OF ITS OWN. A `failed` row with a pending retry is exactly the
 * case {@link pageMustStopFirst} now answers `true` for as well, so `stopRule`
 * already runs for it and already cancels the timer (see that function's own
 * doc) - a second cancel here would be redundant with the one call this
 * function already makes.
 */
export async function releaseRule(rule: ForwardRule): Promise<void> {
  if (pageMustStopFirst(rule.id)) await stopRule(rule);
}

/**
 * Release every rule riding `hostId`, then drop the rules themselves.
 *
 * `deleteHost`'s required cleanup parameter (`hosts/store.ts`'s
 * `ForwardRuleCleanup`), and this rather than `dropRulesForHost` alone because
 * dropping the RECORDS releases nothing: `runtime.ts` is left naming rules no
 * row can render, so no Stop is ever offered again; `ssh/tunnel.ts`'s entries
 * stay at `refs: 1`, so those SSH sessions never close for the rest of the
 * app's life; and each local port stays bound, with re-creating a rule on the
 * same pinned port then failing EADDRINUSE and no in-app recovery. That is the
 * single-rule leak `ForwardsPage`'s delete confirm already fixes, times N.
 *
 * ORDER IS THE PROPERTY, NOT PRESENCE. Every release is awaited BEFORE the
 * drop. Dropping first is the same leak with an extra IPC: the record carries
 * the host and both endpoints `stopRule` needs to NAME the entry it is
 * releasing, and once the record is gone nothing can name it.
 *
 * IT RUNS INSIDE THE HOSTS STORE'S WRITE QUEUE, which is a real cost stated
 * rather than designed away. `deleteHost` awaits this from inside its own
 * `enqueueWrite`, so deleting a host with N page-running rules holds that queue
 * open for N close round trips. That is the price of a cleanup no caller can
 * skip, and the alternative - a reconciler that sweeps later - is what leaves a
 * rule outliving its host in the window between.
 *
 * NO DEADLOCK, written down so it is not "fixed" later. `store.ts`'s header
 * warns that a HOST LOOKUP inside `dropRulesForHost` would re-enter a queue
 * already mid-entry; nothing here makes one. `listRules` is a read, and
 * `dropRulesForHost` serialises on the FORWARDS store's write queue, which is
 * not the hosts queue this call is running inside.
 *
 * A REJECTING STOP ABORTS THE HOST DELETE, deliberately. {@link stopRule} has a
 * `finally` and no `catch`, so a close that reports propagates out of here and
 * `deleteHost` throws before it touches the keychain or the host list. That
 * leaves the host and its rules both intact, which is recoverable - the same
 * argument `deleteHost`'s own comment makes for awaiting this call at all.
 * Swallowing it would drop the host while a forward it owns is still up, with
 * nothing left that names the entry. The row does not lie either way:
 * `stopRule`'s `finally` marks the rule stopped whether the close reported or
 * not.
 */
export async function releaseRulesForHost(hostId: string): Promise<void> {
  const riding = (await listRules()).filter((r) => r.hostId === hostId);
  for (const rule of riding) await releaseRule(rule);
  await dropRulesForHost(hostId);
}

/**
 * Start `rule` and, on a transport-class failure, keep retrying it on
 * {@link FORWARD_RECONNECT_BACKOFF_MS} until it succeeds, a local/rejected
 * failure parks it, or the ladder runs out - see this file's header. The
 * launch trigger (`src/app/hooks/useForwardsAutostart.ts`) is the only
 * production caller, once per `startWithApp` rule; a rule missing its host or
 * naming an RDP one needs no separate pre-check here, because `dialSession`
 * (`ssh/tunnel.ts`) already raises that as a `SshLocalConnectError`, which
 * {@link decideSshConnectFailure} parks on the first attempt the same as a bad
 * credential.
 *
 * ONE TOAST FOR THE WHOLE LADDER, not one per rung: `startRule` itself is
 * handed a runtime whose `toast` drops every `"error"` (a rung that will
 * retry silently updates the row instead - see {@link
 * attemptForwardAutostart}'s own doc), and the real `runtime.toast` is called
 * exactly once, from here, when a rung parks or the ladder gives up. A down
 * bastion would otherwise cost one error toast per rung per rule.
 */
export async function startForwardAutostart(
  rule: ForwardRule,
  runtime: RuntimeDeps = defaultRuntimeDeps,
): Promise<void> {
  await attemptForwardAutostart(rule, runtime, 0);
}

/** `runtime` with its `toast` silenced for `"error"` - what {@link
 *  attemptForwardAutostart} hands `startRule` so a rung that is about to
 *  retry never raises the toast `startRule`'s own catch would otherwise
 *  emit; every other variant (the hostOwned-yield warning) still reaches the
 *  real `runtime.toast` unchanged. */
function silencedRuntime(runtime: RuntimeDeps): RuntimeDeps {
  return {
    ...runtime,
    toast: (message, options) => {
      if (options?.variant === "error") return;
      runtime.toast(message, options);
    },
  };
}

/**
 * One rung of {@link startForwardAutostart}'s ladder. `priorAttempts` is how
 * many retries have already run in THIS ladder walk (0 for the first, real
 * call `startForwardAutostart` makes); the attempt this call is making is
 * `priorAttempts + 1`, which is also the index `FORWARD_RECONNECT_BACKOFF_MS`
 * is read at for the NEXT one, if there is one.
 *
 * REUSES THE SAME `rule` OBJECT across every rung rather than re-reading the
 * store - safe because {@link cancelForwardRetry} inside `stopRule` already
 * clears the pending timer before a Stop, delete or edit can land
 * (`pageMustStopFirst`'s own `forwardRetries.has` check routes all three
 * through that one call), so a rung that fires has always been wanted for
 * the whole wait; a re-read would buy nothing here and would cost the ladder
 * its `RuntimeDeps`-only testability (`findRule` reaches the real store,
 * which needs a live Tauri bridge under plain node).
 *
 * THE ROW'S OWN STATUS TEXT, NOT A TOAST, ON A RUNG THAT SCHEDULES ANOTHER:
 * a "retrying in Ns" suffix, appended to the message `startRule`'s own catch
 * just set and re-published through `markFailed` - the one surface a
 * silenced error toast (see {@link startForwardAutostart}'s header) must not
 * also silence, or a pending retry stays invisible until it starts.
 */
async function attemptForwardAutostart(
  rule: ForwardRule,
  runtime: RuntimeDeps,
  priorAttempts: number,
): Promise<void> {
  let failure: unknown;
  let failed = false;
  await startRule(rule, silencedRuntime(runtime), (e) => {
    failed = true;
    failure = e;
  });
  // Resolved, or yielded to a terminal/page owner that beat it - neither is a
  // failure this ladder should react to.
  if (!failed) return;
  const text = useForwardRuntime.getState().byRule[rule.id]?.error ?? describeError(failure);
  if (decideSshConnectFailure(classifySshConnectFailure(failure, "")).action !== "reconnect") {
    runtime.toast(text, { variant: "error" });
    return;
  }
  const attempt = priorAttempts + 1;
  if (attempt > FORWARD_RECONNECT_BACKOFF_MS.length) {
    runtime.toast(text, { variant: "error" });
    return;
  }
  const delayMs = FORWARD_RECONNECT_BACKOFF_MS[attempt - 1];
  useForwardRuntime
    .getState()
    .markFailed(rule.id, `${text} (retrying in ${Math.round(delayMs / 1000)}s)`);
  const timer = setTimeout(() => {
    forwardRetries.delete(rule.id);
    void attemptForwardAutostart(rule, runtime, attempt);
  }, delayMs);
  forwardRetries.set(rule.id, timer);
}
