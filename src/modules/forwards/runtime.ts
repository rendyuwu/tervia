/**
 * Runtime status of the forward rules defined in `modules/forwards/types.ts` -
 * whether each one is stopped, starting, running, or failed, and (once
 * running) the loopback port it bound and the claim its session is held
 * under.
 *
 * SESSION-SCOPED ONLY - nothing here is persisted, so a relaunch comes up with
 * every rule stopped. That is the design and not an omission: do not add a
 * `LazyStore` (or any other persistence) to "fix" it.
 *
 * KEYED BY `ruleId` ALONE, not `(ruleId, owner)`, because a rule runs under one
 * owner at a time. That has a consequence worth stating up front: a
 * rule with `startWithHost: true` is started by `startWithHost` on the
 * TERMINAL's own session, dies with the tab, and this store never hears about
 * it - the page shows it "Running (with host)" read-only, off a SEPARATE map
 * the terminal writes (`./hostOwned.ts`) and this page only reads. A
 * terminal-owned forward is therefore never in `byRule`; the two are mutually
 * exclusive by construction, not by a check either side has to make.
 *
 * The `claim` field is what makes Stop safe. `SshForward.claim`
 * (`ssh/tunnel.ts:51-74`) is monotonic and names the ENTRY a caller took its
 * reference from, not the target: `dropSession` deletes a connection's
 * entries the moment a bastion dies, and the next consumer of the same target
 * creates fresh ones under the same key. A Stop that looked the target up
 * instead of passing the claim back would, on a bastion that dropped and was
 * re-dialled by an RDP pane, spend THAT pane's reference and close the
 * session it is using. So the claim rides in this store's entry, and Stop
 * reads it with `getState()` rather than a selector - see the comment above
 * the hooks below.
 */

import { create } from "zustand";

export type ForwardStatus = "stopped" | "starting" | "running" | "failed";

type ForwardRuntimeEntry = {
  status: ForwardStatus;
  boundPort?: number;
  sessionId?: number;
  /** The token `closeForwardForConnection` requires. Identity-bearing on
   *  purpose - see `ssh/tunnel.ts:51-74`. A Stop that looked the target up
   *  instead would, on a bastion that dropped and was re-dialled by an RDP
   *  pane, spend THAT pane's reference and close the session it is using. */
  claim?: number;
  error?: string;
};

type ForwardRuntimeState = {
  byRule: Record<string, ForwardRuntimeEntry>;
  markStarting(ruleId: string): void;
  markRunning(ruleId: string, live: { boundPort: number; sessionId: number; claim: number }): void;
  markFailed(ruleId: string, error: string): void;
  /**
   * Resets the entry to `{ status: "stopped" }` and NOTHING else - no
   * `boundPort`, no `sessionId`, no `claim`, no `error` survive. A retained
   * claim is a token whose entry is gone: `controller.ts`'s `stopRule` is a
   * no-op when there is no claim recorded, precisely so a stale one left by a
   * previous run can never be spent against a session another consumer is now
   * using.
   */
  markStopped(ruleId: string): void;
};

export const useForwardRuntime = create<ForwardRuntimeState>((set) => ({
  byRule: {},
  markStarting: (ruleId) =>
    set((s) => ({ byRule: { ...s.byRule, [ruleId]: { status: "starting" } } })),
  markRunning: (ruleId, live) =>
    set((s) => ({
      byRule: { ...s.byRule, [ruleId]: { status: "running", ...live } },
    })),
  markFailed: (ruleId, error) =>
    set((s) => ({ byRule: { ...s.byRule, [ruleId]: { status: "failed", error } } })),
  markStopped: (ruleId) =>
    set((s) => ({ byRule: { ...s.byRule, [ruleId]: { status: "stopped" } } })),
}));

// Every selector below returns a PRIMITIVE. `useShallow` is imported nowhere
// in `src/` and stays that way here: a selector that builds a fresh object or
// array literal is never `Object.is` its own last return, and under zustand
// v5 that loops with "Maximum update depth exceeded". If a future selector
// genuinely needs an object, the fix is
// `useShallow` from `zustand/react/shallow` - not a bare object selector, and
// not a workaround that avoids importing it.

/** The rule's status, or `"stopped"` for a rule this store has never heard of
 *  (nothing has started it yet, or the app just launched). */
export function useForwardStatus(ruleId: string): ForwardStatus {
  return useForwardRuntime((s) => s.byRule[ruleId]?.status ?? "stopped");
}

/** The loopback port a running forward bound, or `undefined` before it has. */
export function useForwardBoundPort(ruleId: string): number | undefined {
  return useForwardRuntime((s) => s.byRule[ruleId]?.boundPort);
}

/** The message from the entry's last `markFailed`, or `undefined`. */
export function useForwardError(ruleId: string): string | undefined {
  return useForwardRuntime((s) => s.byRule[ruleId]?.error);
}

/** How many rules are currently `"running"`. Builds an array INSIDE the
 *  selector - that is fine, because `Object.is` compares the RETURNED value,
 *  and the returned value here is the length, a primitive. */
export function useRunningCount(): number {
  return useForwardRuntime(
    (s) => Object.values(s.byRule).filter((e) => e.status === "running").length,
  );
}

// The four actions (`markStarting`, `markRunning`, `markFailed`,
// `markStopped`) are function identities created once by `create()` above and
// never replaced, so they are stable under `Object.is` and need no dedicated
// wrapper hook of their own: a caller selects one directly, e.g.
// `useForwardRuntime((s) => s.markRunning)`.
//
// `claim`, by contrast, NEVER goes through a selector at all. Stop is an
// event handler, not a render, so it reads
// `useForwardRuntime.getState().byRule[id]?.claim` - the same idiom
// `tunnel.ts:183` and `:368` already use for `useHostKeyPrompt.getState()`. A
// `claim` in a selector would be a value that changes on every restart
// driving a render that does not care.
