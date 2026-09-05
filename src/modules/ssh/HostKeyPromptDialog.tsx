import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useEffect } from "react";
import { useHostKeyPrompt } from "./hostKeyPrompt";

/**
 * Blocking confirmation for a NEW server identity - an SSH host key, or the
 * leaf certificate of an RDP server (trust-on-first-use). Both protocols share
 * this dialog because they share the shape exactly: the backend pauses the
 * handshake BEFORE sending credentials and emits a prompt, the user verifies
 * the fingerprint out-of-band and accepts, or rejects to abort.
 *
 * Deliberately not dismissable without a decision (no close button, Escape and
 * click-outside disabled) so credentials are never sent to an unverified host
 * by accident. Mounted once at the app root.
 *
 * A prompt carrying `certificate` is the RDP case; the copy switches on that
 * rather than on a protocol tag, because the difference IS the certificate: an
 * SSH host key has no subject or issuer to show, and there is no `ssh-keygen`
 * to point an RDP user at.
 */
export function HostKeyPromptDialog() {
  const queue = useHostKeyPrompt((s) => s.queue);
  const resolve = useHostKeyPrompt((s) => s.resolve);
  const current = queue[0];
  const cert = current?.certificate;

  // The webview going away is the one exit from this dialog that no button
  // covers, and it parks a backend whichever protocol asked: `ssh_open` waits on
  // `HOSTKEY_CONFIRM_TIMEOUT` and the RDP verifier on `CERT_CONFIRM_TIMEOUT`,
  // both 120 seconds, both holding a socket mid-handshake with no session id yet
  // for anything else to close. Reject everything still queued on the way out.
  //
  // DELIBERATELY BOTH PROTOCOLS, which is a behaviour change to SSH that arrived
  // with this dialog being shared and was decided rather than inherited. The
  // reasoning is that the failure is the same shape for both and rejecting is
  // fail-safe either way - a rejected prompt costs the user one reconnect, an
  // unanswered one costs a parked handshake. The costs are not identical, and it
  // is the cheaper case that is SSH's: `ssh_open` waits on an async
  // `tokio::time::timeout`, so it holds a task, while the RDP verifier blocks
  // and needs `block_in_place` to hand its worker away, so it holds a displaced
  // runtime thread as well. Scoping the backstop to certificate prompts would
  // therefore save nothing worth the asymmetry.
  //
  // `pagehide` rather than `beforeunload`: it fires on navigation AND on the
  // page being discarded, and it does not need the event to be cancellable. The
  // answer is best-effort by nature - the IPC message is posted synchronously
  // but nothing can guarantee it lands once the webview is being torn down -
  // which is exactly why the per-connect teardowns in `RdpPane` and
  // `HostEditorDialog` (its RDP Test probe, `hosts/editor/rdpProbe.ts`) are the
  // primary guarantee and this is the backstop.
  //
  // Deliberately NOT done on this component's own unmount: that would reject
  // live prompts whose owning pane is still up and still waiting for an answer.
  useEffect(() => {
    const abandonAll = () => {
      const { queue: pending, abandon } = useHostKeyPrompt.getState();
      // Snapshot first: `abandon` replaces the queue on each call.
      for (const p of [...pending]) abandon(p.promptId);
    };
    window.addEventListener("pagehide", abandonAll);
    return () => window.removeEventListener("pagehide", abandonAll);
  }, []);

  return (
    <Dialog open={current != null} onOpenChange={() => {}}>
      {current && (
        <DialogContent
          showCloseButton={false}
          onEscapeKeyDown={(e) => e.preventDefault()}
          onInteractOutside={(e) => e.preventDefault()}
          className="sm:max-w-lg"
        >
          <DialogHeader>
            <DialogTitle>
              {cert ? "Verify RDP server certificate" : "Verify SSH host key"}
            </DialogTitle>
            <DialogDescription>
              First connection to{" "}
              <span className="text-foreground font-medium">{current.host}</span>.{" "}
              {cert ? (
                <>
                  Confirm this certificate is the machine's real one by checking the fingerprint
                  out-of-band: ask the admin, or read it from{" "}
                  <code className="text-foreground">
                    Get-ChildItem Cert:\LocalMachine\Remote?Desktop
                  </code>{" "}
                  on the server. Most RDP hosts present a self-signed certificate, so a warning here
                  is normal - but trusting an attacker's certificate on first connect hands them
                  your password. Once trusted, this connection is not asked about again.
                </>
              ) : (
                <>
                  Confirm this fingerprint matches the server's real key by checking it out-of-band:
                  ask the admin, or run{" "}
                  <code className="text-foreground">ssh-keygen -lf &lt;hostkey&gt;</code> on the
                  server. Trusting an attacker's key on first connect hands them your credentials.
                  Once trusted, this host is not asked about again.
                </>
              )}
            </DialogDescription>
          </DialogHeader>
          <div className="bg-muted text-foreground rounded-md p-2.5 font-mono text-xs break-all select-all">
            {current.fingerprint}
          </div>
          {/* The certificate's own claims about itself. Shown BELOW the
              fingerprint and visibly secondary, because they are unverified
              strings the server chose: useful for recognising the right machine,
              worthless as proof. The fingerprint is the thing being trusted. */}
          {cert && (
            <dl className="text-muted-foreground grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-[11px]">
              <dt>Subject</dt>
              <dd className="text-foreground truncate font-mono" title={cert.subject}>
                {cert.subject || "(none)"}
              </dd>
              <dt>Issuer</dt>
              <dd className="text-foreground truncate font-mono" title={cert.issuer}>
                {cert.issuer || "(none)"}
              </dd>
            </dl>
          )}
          {/* Two-column full-width footer to match the app's other
              confirmation modals (AlertDialogFooter's `grid grid-cols-2`):
              Reject + Trust split the row into equal columns that fill the
              dialog width, instead of clustering on the right. */}
          <DialogFooter className="grid grid-cols-2 gap-2">
            <Button variant="outline" onClick={() => resolve(current.promptId, false)}>
              Reject
            </Button>
            <Button onClick={() => resolve(current.promptId, true)}>Trust &amp; connect</Button>
          </DialogFooter>
        </DialogContent>
      )}
    </Dialog>
  );
}
