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

import { openSshForward } from "@/modules/ssh/bridge";

import { useHostOwnedForwards, type HostOwnedEntry } from "./hostOwned";
import { useForwardRuntime, type ForwardStatus } from "./runtime";
import { listRules } from "./store";
import type { ForwardRule } from "./types";

/**
 * The calls {@link startHostForwards} makes into the rest of the app, so a
 * check can substitute them. EVERY PRODUCTION CALLER PASSES THREE ARGUMENTS
 * and never builds one of these - the same seam, and the same reason, as
 * `controller.ts`'s `RuntimeDeps`.
 *
 * `runtimeStatus` and `claimHostOwned` are the two STORES, taken as functions
 * rather than imported store handles, so a fixture can drive the mutual
 * exclusion and the claim without reaching into module-level state that other
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
  runtimeStatus: (ruleId: string) => ForwardStatus;
  claimHostOwned: (ruleId: string, entry: HostOwnedEntry) => void;
};

export const defaultAutostartDeps: AutostartDeps = {
  listRules,
  openForward: openSshForward,
  // Both stores are read at CALL time, not captured at module load: an action
  // identity read once here would be a second reference to a store this file
  // does not own, and `getState()` is what every other event-handler caller in
  // this codebase does (`controller.ts`, `tunnel.ts:183`).
  runtimeStatus: (ruleId) => useForwardRuntime.getState().byRule[ruleId]?.status ?? "stopped",
  claimHostOwned: (ruleId, entry) => useHostOwnedForwards.getState().claim(ruleId, entry),
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

// The three banners. `->` in ASCII and not `→`, matching
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

/** Mutual exclusion (VLT-94): a rule the PAGE is running is left alone, and
 *  said out loud - a rule silently not coming up is the shape of a bug. */
function skippedBanner(rule: ForwardRule): string {
  return `\x1b[33m[tervia] forward "${rule.name}" is already running from the Port Forwarding page; not starting a second one.\x1b[0m\r\n`;
}

/**
 * Open every `startWithHost` rule bound to `hostId` on the terminal's own live
 * session, writing one banner per rule.
 *
 * NEVER REJECTS. The call site is fire-and-forget from inside the connect path,
 * so a rejection would be an unhandled promise rejection - and worse, one rule
 * that cannot bind would silently drop every rule after it. A busy local port
 * must not turn into a failed SSH connect.
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
    const status = deps.runtimeStatus(rule.id);
    if (status === "running" || status === "starting") {
      writeBanner(skippedBanner(rule));
      continue;
    }
    try {
      const bound = await deps.openForward(
        sessionId,
        rule.localPort,
        rule.remoteHost,
        rule.remotePort,
      );
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
}
