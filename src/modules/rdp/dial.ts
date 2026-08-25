import { closeForwardForConnection, openForwardForConnection } from "@/modules/ssh/tunnel";
import { resolveRdpAuth } from "@/modules/vault/resolve";
import type { RdpHost } from "@/modules/hosts/types";
import type { RdpOpenInput } from "./bridge";

/**
 * Turning a saved RDP row into a dial: the address to connect to, and the
 * `rdp_open` input that goes with it.
 *
 * Two callers, one path: the pane and the dialog's Test button. Both need the
 * same decision - dial the host, or dial the local end of an SSH tunnel to it -
 * and Test is only worth anything if it exercises what a real connect will use.
 *
 * # Why the backend needs no part in this
 *
 * A tunnelled session is the same code against a different address. The pin
 * travels IN the open input and the backend never derives a storage key from the
 * address, so `vps:3389` and `127.0.0.1:<ephemeral>` are the same pinned
 * machine - which is exactly what {@link rdpOpenInput} is written to keep true.
 * Verified against the real hosts: the `rdp_live` tests connect through a plain
 * `ssh -L` and report a server fingerprint identical to the direct dial's.
 */

/**
 * Where `ssh_forward_open` binds. Matched to the backend rather than guessed at:
 * a forward is bound on loopback, so dialling anything else would leave the RDP
 * connect knocking on a port nobody is listening on.
 */
const LOOPBACK = "127.0.0.1";

export type RdpDialTarget = {
  /** Address to hand to `rdp_open`. */
  host: string;
  port: number;
  /** True when `host:port` is the local end of an SSH forward, for status copy. */
  viaTunnel: boolean;
  /**
   * Give up this dial's claim on the tunnel. A no-op for a direct dial, and
   * idempotent: the caller's teardown can fire it without knowing whether the
   * connect got far enough to use it, or whether an error path released it
   * already. Calling it twice must NOT release twice - a second release spends
   * another consumer's reference and closes a session still in use.
   */
  release: () => void;
};

/**
 * Resolve the address to dial, opening an SSH forward first when the row carries
 * a tunnel.
 *
 * The caller owns the result's lifetime. In particular a caller that can go away
 * mid-connect - a pane that unmounts while `rdp_open` is still in flight - must
 * release it on the way out, or the bastion session it opened is held with no
 * consumer left to close it.
 */
export async function openRdpDialTarget(
  conn: Pick<RdpHost, "host" | "port" | "tunnel">,
  opts: {
    /** Ids of host-key prompts raised while opening the tunnel, so the caller's
     *  teardown can answer one the user never got to. */
    onHostKeyPrompt?: (promptId: string) => void;
  } = {},
): Promise<RdpDialTarget> {
  const sshHostId = conn.tunnel?.sshHostId;
  if (!sshHostId) {
    return { host: conn.host, port: conn.port, viaTunnel: false, release: () => {} };
  }
  const forward = await openForwardForConnection(sshHostId, conn.host, conn.port, {
    // The RDP connect flow has a dialog on screen anyway, so an unverified
    // bastion asks instead of refusing. This is the ONLY caller that passes it.
    promptForHostKey: true,
    onHostKeyPrompt: opts.onHostKeyPrompt,
  });
  let released = false;
  return {
    host: LOOPBACK,
    port: forward.localPort,
    viaTunnel: true,
    release: () => {
      if (released) return;
      released = true;
      // `forward.claim` names the entry this dial took its reference from, so a
      // release that arrives after the bastion died and somebody else re-opened
      // the same target is a no-op instead of spending their reference.
      void closeForwardForConnection(sshHostId, conn.host, conn.port, forward.claim).catch(
        () => {},
      );
    },
  };
}

/**
 * The `rdp_open` input for a saved row dialled at `target`.
 *
 * The point of it being one function: every field except the address is taken
 * from the ROW, so a tunnelled connect and a direct one differ in the address
 * and in nothing else. `expectedCertFingerprint` in particular is the row's pin
 * whichever way the machine is reached, which is what stops a tunnel - whose
 * local port is ephemeral and different on every connect - from re-asking the
 * certificate question forever.
 */
export async function rdpOpenInput(
  row: RdpHost,
  target: { host: string; port: number },
): Promise<RdpOpenInput> {
  // `resolveRdpAuth` hands back a keychain REFERENCE, never the secret: the
  // host process reads it itself and hands the plaintext straight into
  // CredSSP, so it does not exist on this side of the IPC at any point. It
  // also covers a vault-bound identity, which `row.credential` alone cannot.
  const { username, domain, credential } = await resolveRdpAuth(row.credential);
  return {
    host: target.host,
    port: target.port,
    username,
    domain,
    credential,
    width: row.desktopWidth,
    height: row.desktopHeight,
    expectedCertFingerprint: row.certFingerprint,
  };
}
