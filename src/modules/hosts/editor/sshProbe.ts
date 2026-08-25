import { openSsh } from "@/modules/ssh/bridge";
import { useHostKeyPrompt } from "@/modules/ssh/hostKeyPrompt";
import { sshCredentialValues, type SshSecretValues } from "@/modules/vault/resolve";
import type { VaultAuthMode } from "@/modules/vault/types";

import { resolveJumpHops } from "../jumps";
import type { Host } from "../types";

// `SshConnectionDialog`'s Test probe, lifted out whole: open a session with the
// values on screen, wait for Connected, close. Only the handshake matters.
//
// A function rather than a method on the dialog because the merged editor has two
// of these and one Test button. Everything it needs is a parameter, and the two
// things it cannot do alone - update the form, pin the key on the saved row - come
// back through `onTrusted`.

export type SshProbeArgs = {
  host: string;
  port: number;
  user: string;
  authMode: VaultAuthMode;
  /** Whatever the form currently holds, straight off the draft. */
  secrets: SshSecretValues;
  /** The pin to verify against, so Test cannot silently re-anchor on a different
   *  key. A new host leaves it unset and takes the TOFU prompt. */
  expectedFingerprint?: string;
  proxyJumpId?: string;
  /** The host being edited, excluded from its own jump chain. Undefined for one
   *  that is not saved yet. */
  hostId?: string;
  /** Every saved host, for resolving the jump chain. */
  hosts: Host[];
  /** The user trusted a key mid-probe. Called before the backend hears the
   *  answer, so it must not throw. */
  onTrusted: (fingerprint: string) => void;
};

export type SshProbeResult = { fingerprint: string; durationMs: number };

export async function runSshProbe(args: SshProbeArgs): Promise<SshProbeResult> {
  const started = performance.now();
  // A new host (no pinned key) makes the backend pause the handshake on a
  // first-connect prompt; we route it to the global confirmation dialog and
  // remember the id so it can be cleared if the probe ends without an answer.
  let testPromptId: string | null = null;
  try {
    // Resolve the jump chain (if a jump host is selected) so the probe dials
    // through it, exactly like a real connect would.
    const jumps = await resolveJumpHops(args.proxyJumpId || undefined, args.hostId, args.hosts);
    // Budget scales with chain depth: each hop is a full handshake the backend
    // caps at ~15s, and a fully-pinned chain fires no host-key prompt to clear
    // this timer, so a deep chain needs more than the base 20s.
    const probeTimeoutMs = 20_000 + jumps.length * 15_000;
    let resolved = false;
    const result = await new Promise<{ fingerprint: string }>((resolve, reject) => {
      const timer = setTimeout(() => {
        if (resolved) return;
        resolved = true;
        reject(new Error(`test timed out after ${Math.round(probeTimeoutMs / 1000)}s`));
      }, probeTimeoutMs);
      openSsh(
        {
          host: args.host,
          port: args.port,
          user: args.user,
          // Same mapping the real connect uses, straight off the draft, so Test
          // can never authenticate differently from what Save produces.
          ...sshCredentialValues(args.authMode, args.secrets),
          expectedFingerprint: args.expectedFingerprint || undefined,
          jumps,
          cols: 80,
          rows: 24,
        },
        {
          onData: () => {},
          // New host: hand the fingerprint to the global host-key dialog so the
          // user can verify it, and stop the probe deadline - waiting on a human
          // can take arbitrarily long and the handshake stays paused (no
          // credentials sent) until they answer. Without this, a first-connect
          // Test dropped the prompt and could only ever time out.
          onHostKeyPrompt: (prompt) => {
            testPromptId = prompt.promptId;
            clearTimeout(timer);
            // Trusting the key here counts, whatever the rest of the test does. A
            // saved host records it on the spot; a brand-new one has no id yet,
            // so Save writes it from the same state. Both used to be forgotten,
            // which is why testing a new server and then saving it asked the very
            // same question again.
            useHostKeyPrompt.getState().enqueue(prompt, () => args.onTrusted(prompt.fingerprint));
          },
          onConnected: (fingerprint) => {
            if (resolved) return;
            resolved = true;
            clearTimeout(timer);
            resolve({ fingerprint });
          },
          onError: (msg) => {
            if (resolved) return;
            resolved = true;
            clearTimeout(timer);
            reject(new Error(msg));
          },
          onExit: () => {
            if (resolved) return;
            resolved = true;
            clearTimeout(timer);
            reject(new Error("session ended before authenticating"));
          },
        },
      )
        .then(async (sess) => {
          // Close immediately. Only the handshake matters.
          try {
            await sess.close();
          } catch {
            // Runtime will reap the dead session.
          }
        })
        .catch((err) => {
          if (resolved) return;
          resolved = true;
          clearTimeout(timer);
          reject(err);
        });
    });
    return { fingerprint: result.fingerprint, durationMs: Math.round(performance.now() - started) };
  } finally {
    // If the probe ended while a host-key prompt was still pending (rejected,
    // timed out, or the user walked away), drop it so it can't linger in the
    // shared queue and block a later real connect's dialog.
    //
    // `dismiss`, not `abandon`, and that asymmetry with the RDP probe next door is
    // carried over rather than chosen: dismissing leaves the backend parked in the
    // handshake until its own timeout, while leaving the question answerable in the
    // global queue if the user is still reading it. Changing it is a behaviour
    // decision, not part of merging the two dialogs.
    if (testPromptId) useHostKeyPrompt.getState().dismiss(testPromptId);
  }
}
