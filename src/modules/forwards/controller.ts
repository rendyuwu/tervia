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
 * REFUSES A TERMINAL-OWNED RULE, ahead of everything else. `RuleCard` disables
 * the button for one, but a disabled button is a rendering and not an
 * invariant - and the row's `hostOwned` can become true while this page's own
 * Start is in flight, so the guard has to live where the dial does. First claim
 * wins (VLT-94), and the terminal's claim is the one already taken.
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
