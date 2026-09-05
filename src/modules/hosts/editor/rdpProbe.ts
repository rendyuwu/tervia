import { confirmRdpCert, openRdp, type RdpCredential } from "@/modules/rdp/bridge";
import { openRdpDialTarget, type RdpDialTarget } from "@/modules/rdp/dial";
import { useHostKeyPrompt } from "@/modules/ssh/hostKeyPrompt";

// `RdpConnectionDialog`'s Test probe, lifted out whole: open the tunnel if there
// is one, dial, wait for the capability exchange, close. Only the handshake was
// under test - frames for a desktop nobody is looking at are pure cost.

/** A full RDP connect is TCP, then TLS, then CredSSP, then the capability
 *  exchange, and a domain controller in the middle of the NTLM leg can be slow.
 *  Generous, because the alternative is calling a working host broken. */
const TEST_TIMEOUT_MS = 30_000;

export type RdpProbeArgs = {
  host: string;
  port: number;
  username: string;
  domain?: string;
  /** Picked by `rdpCredentialForTest`: a typed password inline, or the keychain
   *  reference for a stored one. */
  credential: RdpCredential;
  width: number;
  height: number;
  /** The pin to verify against, so Test cannot silently re-anchor on a different
   *  certificate. A new host leaves it unset and takes the TOFU prompt. */
  expectedCertFingerprint?: string;
  tunnelSshHostId?: string;
  /** The user accepted a certificate mid-probe. Called before the backend hears
   *  the answer, so it must not throw. */
  onTrusted: (fingerprint: string) => void;
  /**
   * The trust questions this probe raises, mirrored out so a teardown can answer
   * one the user never got to.
   *
   * Two of them, in the order they can arrive: the tunnel's SSH host key, then
   * the RDP certificate. Each leaves a backend parked mid-handshake - for the
   * certificate `rdp_open` has not even returned, so no session id exists and
   * there is nothing to close - and until an answer arrives the socket and a
   * blocked thread are held for the full 120-second confirm timeout.
   */
  prompts: {
    raised: (promptId: string) => void;
    settled: (promptId: string) => void;
  };
};

export type RdpProbeResult = {
  fingerprint: string;
  width: number;
  height: number;
  durationMs: number;
};

export async function runRdpProbe(args: RdpProbeArgs): Promise<RdpProbeResult> {
  const raised = new Set<string>();
  const remember = (promptId: string) => {
    raised.add(promptId);
    args.prompts.raised(promptId);
  };
  let dial: RdpDialTarget | null = null;
  try {
    // The tunnel first, and deliberately outside the timer below: dialling the
    // bastion can stop for a host-key dialog, and a probe that can only ever time
    // out while a human reads a fingerprint is worse than no probe.
    const target = await openRdpDialTarget(
      {
        host: args.host,
        port: args.port,
        tunnel: args.tunnelSshHostId ? { sshHostId: args.tunnelSshHostId } : undefined,
      },
      { onHostKeyPrompt: remember },
    );
    dial = target;
    // Measured from here, so the number reported is the RDP handshake and not
    // however long the tunnel (or the user) took.
    const started = performance.now();
    let resolved = false;
    const result = await new Promise<{ fingerprint: string; width: number; height: number }>(
      (resolve, reject) => {
        const timer = setTimeout(() => {
          if (resolved) return;
          resolved = true;
          reject(new Error(`test timed out after ${Math.round(TEST_TIMEOUT_MS / 1000)}s`));
        }, TEST_TIMEOUT_MS);
        openRdp(
          {
            // The tunnel's local end when there is one, so Test exercises the
            // transport a real connect will use rather than a direct dial the
            // saved row would never make.
            host: target.host,
            port: target.port,
            username: args.username,
            domain: args.domain || undefined,
            credential: args.credential,
            width: args.width,
            height: args.height,
            expectedCertFingerprint: args.expectedCertFingerprint || undefined,
          },
          {
            onCertPrompt: (prompt) => {
              // Recorded for the `finally` below AND mirrored out, so a teardown
              // can answer it if the editor disappears before this probe
              // finishes.
              remember(prompt.promptId);
              // Stop the deadline: the handshake is paused waiting on a human,
              // which can take arbitrarily long, and no credential has been sent.
              // Without this a first-connect Test could only ever time out.
              clearTimeout(timer);
              useHostKeyPrompt.getState().enqueue(
                {
                  promptId: prompt.promptId,
                  fingerprint: prompt.fingerprint,
                  // The typed host, not the backend's: through a tunnel the
                  // backend dialled `127.0.0.1`, which names the wrong end of it
                  // for a question about a remote machine's certificate.
                  host: args.host,
                  certificate: { subject: prompt.subject, issuer: prompt.issuer },
                  confirm: confirmRdpCert,
                },
                // Accepting counts whatever the rest of the test does. A saved
                // host records it on the spot; a brand-new one has no id yet, so
                // Save writes it from this same state. Both used to be forgotten,
                // which is why testing a new server and then saving it asked the
                // very same question twice.
                () => args.onTrusted(prompt.fingerprint),
              );
            },
            onConnected: (width, height, fingerprint) => {
              if (resolved) return;
              resolved = true;
              clearTimeout(timer);
              resolve({ fingerprint, width, height });
            },
            onError: (message) => {
              if (resolved) return;
              resolved = true;
              clearTimeout(timer);
              reject(new Error(message));
            },
            onDisconnected: (reason) => {
              if (resolved) return;
              resolved = true;
              clearTimeout(timer);
              reject(new Error(reason || "session ended before authenticating"));
            },
          },
        )
          .then(async (session) => {
            try {
              await session.close();
            } catch {
              // The runtime reaps a dead session on its own.
            }
          })
          .catch((err) => {
            if (resolved) return;
            resolved = true;
            clearTimeout(timer);
            reject(err);
          });
      },
    );
    return { ...result, durationMs: Math.round(performance.now() - started) };
  } finally {
    // A prompt still pending when the probe ended - rejected, timed out, or the
    // user walked away - is ANSWERED, not merely dropped. Dropping it would clear
    // the queue while leaving the backend parked in the handshake until its
    // 120-second confirm timeout, holding the socket and a thread; and a dead
    // prompt left at the head of the shared queue also shadows every later
    // connect's dialog. `abandon` fixes both, and no-ops when the user already
    // answered.
    for (const id of raised) {
      useHostKeyPrompt.getState().abandon(id);
      args.prompts.settled(id);
    }
    // The probe is over either way, so the tunnel goes with it: a Test that left a
    // bastion session open would hold one for as long as the app runs, since
    // nothing else has a handle on it.
    dial?.release();
  }
}
