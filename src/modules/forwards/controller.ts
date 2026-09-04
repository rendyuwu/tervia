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
 */

import { toast } from "@/components/ui/toast";
import { useHostKeyPrompt } from "@/modules/ssh/hostKeyPrompt";
import { closeForwardForConnection, openForwardForConnection } from "@/modules/ssh/tunnel";

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

/**
 * `terminal/lib/session-helpers.ts`'s `describeError`, copied rather than
 * imported. That file also holds `wallpaperActive()`, which reads `document`,
 * and putting a DOM-reading module into this one's import graph would cost this
 * file the "exercisable under plain node" property it exists for. Six lines is
 * the cheaper of the two prices.
 *
 * The string branch is the load-bearing one and not boilerplate: a Tauri
 * `invoke` rejects with a RAW STRING, so that is how the backend's own
 * `ssh: bind 127.0.0.1:<port> failed: <io error>` reaches `bindFailureText` at
 * all.
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

/** What a Start refused because a terminal already holds the rule says. Not the
 *  same sentence as `RuleCard`'s `HOST_OWNED_NOTE`, and not shared with it: that
 *  file is a `.tsx` and importing it here would cost this module the
 *  "exercisable under plain node" property the header exists for. This one also
 *  names the rule, because a toast outlives the row it came from. */
function hostOwnedRefusalText(rule: ForwardRule): string {
  return `"${rule.name}" is already open on its terminal. Close that terminal tab to stop it.`;
}

/** What a Start says when it dialled successfully and found, on the way back,
 *  that the rule had meanwhile come up on its TERMINAL. A different sentence
 *  from {@link hostOwnedRefusalText} because a different thing happened: that
 *  one never dialled, this one dialled and then gave the reference back. Not an
 *  error - nothing failed - so the row goes to `stopped` and this is a warning.
 *  Ends in the same sentence as the refusal, because the answer to "how do I
 *  stop it now" is the same. */
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
 *
 * REFUSES A TERMINAL-OWNED RULE, ahead of everything else, AND YIELDS TO ONE
 * THAT ARRIVES MID-DIAL. `RuleCard` disables the button for one, but a disabled
 * button is a rendering and not an invariant - and the row's `hostOwned` can
 * become true while this page's own Start is in flight, so the guard has to live
 * where the dial does and it has to be read on BOTH sides of the await. First
 * claim wins (VLT-94): if the terminal's claim was already taken this never
 * dials, and if it lands during the dial this hands the reference it just
 * received straight back.
 */
export async function startRule(
  rule: ForwardRule,
  runtime: RuntimeDeps = defaultRuntimeDeps,
): Promise<void> {
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
    // yield the one that closes the window: without it the terminal keeps its
    // listener, this dial's EADDRINUSE marks the row failed, and the row reads
    // "Failed - port N is already in use" beside a forward that is up. With it,
    // the reference this dial just took goes straight back and nothing is left
    // that no store names.
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
    // `rule.localPort`, not a bound port: a bind that failed bound nothing, and
    // the port these sentences name is the one that was asked for.
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
 * `"failed"` AND `"stopped"` MUST STAY OUT. `markFailed` only ever runs when
 * the open REJECTED, and neither it nor `markStopped` retains a claim
 * (`runtime.ts`'s note on the reset), so there is nothing for a Stop to spend
 * and a Stop nobody asked for is what including them would buy.
 *
 * INCLUDING `"starting"` IS SAFE AND NOT MERELY DIFFERENT, which is the half
 * worth writing down: `stopRule` deletes the attempt Set and abandons the
 * host-key questions, so the dial that resolves next finds itself superseded
 * (`:182-196`) and hands the reference it just took straight back. One close,
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
  if (useHostOwnedForwards.getState().byRule[rule.id] !== undefined) return;

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
 * a terminal owns, and one already `stopped` or `failed`, the guard says no and
 * nothing is spent - which is the whole of why the guard is inside this
 * function rather than at each caller.
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
