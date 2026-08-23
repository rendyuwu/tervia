import { create } from "zustand";
import { confirmHostKey, type SshHostKeyPrompt } from "./bridge";

/**
 * What an RDP prompt carries beyond the fingerprint: the leaf certificate's
 * own identity. Present ONLY for RDP, and its presence is what switches the
 * dialog's copy - an SSH host key has no subject or issuer to show, and an RDP
 * certificate has nothing you could run `ssh-keygen -lf` against.
 */
export type TrustPromptCertificate = { subject: string; issuer: string };

/**
 * One first-connect trust decision, whichever protocol raised it. RDP's server
 * certificate is the same TOFU shape as an SSH host key - the backend pauses
 * mid-handshake before sending a credential, the user verifies a fingerprint
 * out-of-band, and the answer either lets it proceed or aborts it - so both go
 * through this one queue and one dialog rather than a second copy of each.
 */
export type TrustPrompt = SshHostKeyPrompt & {
  certificate?: TrustPromptCertificate;
  /**
   * How the answer reaches the backend. Defaults to `ssh_confirm_host_key`, so
   * every existing SSH caller is unchanged; the RDP caller passes
   * `confirmRdpCert`. Injected rather than switched on a protocol tag so this
   * module needs no knowledge of - and no import from - the RDP module.
   */
  confirm?: (promptId: string, accept: boolean) => Promise<void>;
};

/** A queued prompt plus what the caller wants done if the user says yes. The
 *  callback is how the fingerprint gets pinned at the moment of trust: only the
 *  code that started the connect knows which saved host this key belongs to. It
 *  runs before the backend hears the answer, so it must not throw or the paused
 *  handshake would be left waiting out its confirm timeout. */
type QueuedPrompt = TrustPrompt & { onAccept?: () => void };

/**
 * Pending first-connect trust confirmations - SSH host keys and RDP server
 * certificates alike. The backend pauses each handshake (no credentials sent
 * yet) and asks the user to verify the server's fingerprint before trusting it;
 * the answer flows back via the prompt's own `confirm`, defaulting to
 * `confirmHostKey`. Queued so two concurrent first-connects each get their own
 * turn - and shared across protocols so an SSH and an RDP prompt raised at the
 * same time take turns rather than rendering on top of each other.
 */
type HostKeyPromptState = {
  queue: QueuedPrompt[];
  /** Push a prompt emitted by the backend (deduped by id). */
  enqueue: (prompt: TrustPrompt, onAccept?: () => void) => void;
  /** Answer a prompt: run the accept hook, tell the backend, drop it. */
  resolve: (promptId: string, accept: boolean) => void;
  /**
   * Drop a prompt from the queue WITHOUT answering the backend, for a handshake
   * that already ended on its own (connect failed, the 120s confirm timeout
   * fired, or the probe was abandoned). The dialog only renders `queue[0]`, so a
   * dead prompt left at the front shadows every later connect's prompt - the
   * exact state that used to require an app restart to clear.
   *
   * Use {@link HostKeyPromptState.abandon} instead whenever the handshake might
   * still be waiting: this one leaves the backend parked.
   */
  dismiss: (promptId: string) => void;
  /**
   * REJECT a still-pending prompt and drop it, for the case where whatever
   * asked the question has gone away - the pane unmounted, the tab closed, the
   * workspace switched, the webview navigated.
   *
   * The difference from `dismiss` is the whole point, and for RDP it is a
   * resource leak rather than a tidiness issue. The certificate prompt is
   * emitted from INSIDE the TLS handshake, so `rdp_open` has not returned and
   * **no session id exists yet**: `rdp_close` has nothing to look up and logs
   * "unknown id". Until an answer arrives, the socket, the in-flight handshake
   * and a blocked thread are held for the backend's full 120-second confirm
   * timeout. Answering is the only thing that releases them.
   *
   * Rejection is the safe default and not a judgement call: refusing an
   * unverified certificate costs the user one reconnect, while accepting one
   * unattended is precisely the outcome the prompt exists to prevent.
   *
   * A no-op when the prompt is no longer queued, which is what makes it safe to
   * call unconditionally from a teardown that cannot know whether the user
   * already answered - and what stops a second answer racing the first.
   */
  abandon: (promptId: string) => void;
};

/**
 * Which saved connections a host-key prompt belongs to, so trusting it pins the
 * key on the right rows. A prompt only names the HOST, and one connect can be
 * dialling several: every hop of a ProxyJump chain plus the target, each with
 * its own saved connection and its own pin.
 *
 * Returns every match rather than the first. Two different saved connections can
 * legitimately point at the same machine (one used as a jump host, one as a
 * target), and they have the same key by definition, so pinning both is the
 * honest answer and spares the other one a prompt it would only answer the same
 * way. No match at all means the prompt is not ours to record.
 */
export function hostKeyOwners(
  promptHost: string,
  target: { host: string; connectionId: string },
  jumps: readonly { host: string; connectionId: string }[],
): string[] {
  const ids = jumps.filter((j) => j.host === promptHost).map((j) => j.connectionId);
  if (target.host === promptHost) ids.unshift(target.connectionId);
  return [...new Set(ids)];
}

export const useHostKeyPrompt = create<HostKeyPromptState>((set, get) => ({
  queue: [],
  enqueue: (prompt, onAccept) =>
    set((s) =>
      s.queue.some((p) => p.promptId === prompt.promptId)
        ? s
        : { queue: [...s.queue, { ...prompt, onAccept }] },
    ),
  resolve: (promptId, accept) => {
    const answered = get().queue.find((p) => p.promptId === promptId);
    // Runs BEFORE the backend is told, so trusting the key is recorded even if
    // the handshake that follows dies (bad password, dropped link).
    if (accept) answered?.onAccept?.();
    // The queued prompt names its own confirm command. Falling back to the SSH
    // one when the entry is already gone keeps the previous behaviour exactly:
    // that only happens for an id the queue never held, which the dialog cannot
    // produce (it renders `queue[0]`), and the backend answers an unknown id
    // with an error either way.
    void (answered?.confirm ?? confirmHostKey)(promptId, accept).catch(() => {});
    set((s) => ({ queue: s.queue.filter((p) => p.promptId !== promptId) }));
  },
  dismiss: (promptId) => set((s) => ({ queue: s.queue.filter((p) => p.promptId !== promptId) })),
  abandon: (promptId) => {
    const pending = get().queue.find((p) => p.promptId === promptId);
    // Not queued means already answered (or never ours). Returning here is what
    // makes this safe to call from a teardown that has no way to know which,
    // and stops a rejection racing in behind a user's "Trust".
    if (!pending) return;
    // The prompt's own confirm command, so an RDP prompt is never answered with
    // `ssh_confirm_host_key`. The catch covers the handshake having already
    // given up on its own, which answers with an error rather than a hang.
    void (pending.confirm ?? confirmHostKey)(promptId, false).catch(() => {});
    set((s) => ({ queue: s.queue.filter((p) => p.promptId !== promptId) }));
  },
}));
