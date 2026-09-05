/**
 * The forwards a TERMINAL opened for itself: one entry per rule that
 * `startWithHost` brought up on a live SSH session, with the session that owns
 * it and the loopback port it actually bound.
 *
 * SESSION-SCOPED ONLY, and one step more so than `runtime.ts` - nothing here is
 * persisted, and nothing here outlives the tab either. A terminal owns every
 * forward it opened, so the ending an entry has is the SESSION's: `finishSsh`
 * and the pane's own `close()` both call {@link HostOwnedState.releaseSession},
 * and a reconnect comes back with a new session id and claims afresh.
 *
 * THE OTHER SIDE OF `runtime.ts:12-20`. That store is the PAGE's and is keyed
 * by `ruleId` alone; this one is the TERMINAL's, and it is keyed by `ruleId`
 * alone too - which is exactly why it CANNOT REPRESENT TWO OWNERS, and why the
 * answer to a second owner is to refuse it rather than to record it: a forward
 * rule runs under one owner at a time.
 *
 * TWO EXCLUSIONS, EACH WITH ITS OWN CHECK, and neither is "by construction":
 *
 * - **This map against `useForwardRuntime`.** `autostart.ts` reads
 *   `runtimeStatus` before the bind AND again immediately before the claim, and
 *   yields (closes its own just-bound listener) if the page has the rule
 *   RUNNING by then; `controller.ts`'s `startRule` refuses outright a rule that
 *   is already in here, and also yields - releasing the reference its own dial
 *   just received - when it finds one here on the way back. One rule, seen from
 *   two sides: whoever resolves SECOND gives up the duplicate it created, so
 *   neither side can take the other's listener down and leave the rule down on
 *   both.
 * - **This map against ITSELF.** Two panes on one host are two sessions and two
 *   autostart runs (`ssh/tunnel.ts:31-35`), with nothing serialising them, so
 *   `autostart.ts` reads `hostOwnedBy` TWICE as well - before the bind and again
 *   immediately before the claim. The pre-bind read alone is a read two
 *   concurrent runs both pass.
 *
 * The page's Start/Stop never writes here at all. The page reads this map
 * read-only: it shows such a rule as "Running (with host)" with a disabled
 * Start/Stop, because a Stop offered here would spend a reference nobody on the
 * page ever took.
 */

import { create } from "zustand";

/** What a terminal-owned forward is: the session that opened it, and the
 *  loopback port that open RESOLVED WITH - never the port the rule asked for.
 *  An auto rule asks for 0, and a pinned rule can be handed a different port
 *  than it named, so the requested one describes nothing that is listening. */
export type HostOwnedEntry = { sessionId: number; boundPort: number };

type HostOwnedState = {
  byRule: Record<string, HostOwnedEntry>;
  /**
   * Record a forward this session just opened. Overwrites, and the overwrite is
   * NOT how two live owners are resolved - it cannot be, because this map is
   * keyed by rule id and a lost entry is a listener nothing names.
   *
   * A LIVE first owner never reaches here twice: `autostart.ts` asks
   * `hostOwnedBy` before its bind and AGAIN immediately before this call, with
   * no suspension point between that second read and this one, and refuses a
   * rule any other session already holds. Both reads are load-bearing and the
   * second one is the one that covers CONCURRENCY - two panes connecting at once
   * are two autostart runs that both pass the first read, and before the second
   * read existed the later of them overwrote a live entry here and left the
   * first pane's listener untracked for the app's lifetime. What is left for the
   * overwrite is the STALE entry - a session whose release never ran - where
   * last-writer-wins is the right fallback and the newer write is the one that
   * describes something listening.
   */
  claim(ruleId: string, entry: HostOwnedEntry): void;
  /**
   * Drop every entry `sessionId` opened, whatever rule it belongs to.
   *
   * A SESSION ID, NOT A RULE ID. The terminal is the owner here, so the
   * ending is the session's - one tab closing takes exactly its own forwards
   * with it and leaves every other tab's standing. Idempotent, because both
   * release sites (`ssh-session.ts`'s `finishSsh` and the pane adapter's
   * `close`) fire without knowing whether the other already did.
   */
  releaseSession(sessionId: number): void;
};

export const useHostOwnedForwards = create<HostOwnedState>((set) => ({
  byRule: {},
  claim: (ruleId, entry) => set((s) => ({ byRule: { ...s.byRule, [ruleId]: entry } })),
  // Builds a fresh `byRule` unconditionally, including when nothing matched.
  // Returning the same object for a no-op release would be an optimisation
  // with nothing to optimise: every selector below returns a PRIMITIVE, so a
  // fresh-but-equal `byRule` re-runs the selectors and changes no rendered
  // value, and `Object.is` on the primitive is what decides the re-render.
  releaseSession: (sessionId) =>
    set((s) => ({
      byRule: Object.fromEntries(
        Object.entries(s.byRule).filter(([, entry]) => entry.sessionId !== sessionId),
      ),
    })),
}));

// Every selector below returns a PRIMITIVE, for the reason `runtime.ts:79-85`
// spells out and against the same failure: a selector building a fresh object
// or array literal is never `Object.is` its own last return, and under zustand
// v5 that loops with "Maximum update depth exceeded". `useShallow` is imported
// nowhere in `src/` and stays that way.

/** True while this rule has a forward open on some live terminal session. */
export function useIsHostOwned(ruleId: string): boolean {
  return useHostOwnedForwards((s) => s.byRule[ruleId] !== undefined);
}

/** The loopback port that terminal-owned forward bound, or `undefined` when no
 *  terminal owns this rule. What the row must LABEL, since it is the port that
 *  is actually listening. */
export function useHostOwnedPort(ruleId: string): number | undefined {
  return useHostOwnedForwards((s) => s.byRule[ruleId]?.boundPort);
}

// `claim` and `releaseSession` are read through `getState()`, never a selector:
// both callers are event handlers (a session coming up, a session ending) and
// not renders - the same idiom `runtime.ts`'s note on `claim` describes, and
// the one `tunnel.ts:183` already uses for `useHostKeyPrompt.getState()`.
