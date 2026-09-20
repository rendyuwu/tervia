import { useCallback, useEffect, useRef, useState } from "react";
import { Monitor, MonitorOff, Unplug } from "lucide-react";
import { cn } from "@/lib/utils";
import { paneCaret } from "@/lib/paneCaret";
import { useHostKeyPrompt } from "@/modules/ssh/hostKeyPrompt";
import {
  confirmRdpCert,
  openRdp,
  rdpSnapshot,
  rdpTakeFrame,
  type RdpInputEvent,
  type RdpSession,
} from "./bridge";
import { listHosts, markConnected, pinFingerprint } from "@/modules/hosts/store";
import { isRdpHost, type RdpHost } from "@/modules/hosts/types";
import { openRdpDialTarget, rdpOpenInput, type RdpDialTarget } from "./dial";
import type { RdpFrameBatch } from "./frame";
import { fitViewport, toRemotePoint, wheelRotation, type RdpViewport } from "./lib/viewport";
import { onRdpPaneAction, type RdpPaneAction } from "./paneActions";
import { CTRL_ALT_DEL_SCANCODES, scancodeFor } from "./scancodes";

/**
 * One RDP session, rendered in-pane on a canvas.
 *
 * # How the pixels get there
 *
 * Two canvases, not one. An OFFSCREEN canvas at the remote desktop's own
 * resolution is the authoritative framebuffer: every dirty-rect batch is
 * blitted into it with `putImageData`, which is a straight memcpy because the
 * wire format already hands over R,G,B,A at the byte offsets `ImageData` wants.
 * The VISIBLE canvas is sized to the pane in device pixels and gets one
 * `drawImage` of the whole framebuffer, letterboxed.
 *
 * The split is what makes a delta batch cheap. Blitting rects straight onto a
 * scaled visible canvas would need per-rect scaling with its own rounding, and
 * the seams between adjacent rects would not line up; going through a
 * full-resolution intermediate means the scale happens once, over one image,
 * with the browser's own filtering.
 *
 * Pixels are PULLED, not pushed. The session channel carries a tiny
 * `frameReady`; the pane asks for the accumulated batch with `rdpTakeFrame` on
 * a frame, with at most one pull outstanding. That single credit is the
 * backpressure: while it is in flight the backend keeps coalescing into its
 * own batcher, whose collapse rule caps it at one framebuffer, so a stalled
 * main thread costs resolution in time rather than an unbounded local queue.
 * There is no frame queue on this side at all.
 *
 * # How the keys get there
 *
 * `KeyboardEvent.code` -> set-1 scancode via a static table (see
 * `scancodes.ts`), because a scancode names a physical key and `code` is the
 * only DOM property that does. Input is batched onto the same rAF as the
 * composite - a drag produces dozens of moves per second and each IPC round
 * trip costs more than the frame it causes - with consecutive mouse moves
 * collapsed, since an absolute position supersedes the one before it.
 *
 * Blur sends `releaseAll`, and that is not a nicety: a modifier held while
 * focus leaves the pane stays down on the SERVER, so every later keystroke
 * anywhere in the session arrives with Ctrl held.
 *
 * # What is deliberately not here
 *
 * The remote cursor is composited into the framebuffer by the server, so the
 * CSS cursor stays at its default and no cursor bitmap is drawn - two cursors
 * is worse than one in the wrong shape. Clipboard, audio, device redirection
 * and dynamic resize are not implemented.
 */

type Props = {
  /** Leaf identifier. Addresses this pane's header actions (Ctrl+Alt+Del). */
  leafId: number;
  /** Saved connection to dial. */
  connectionId: string;
  /** Tab containing this pane is on screen. */
  visible: boolean;
  /** Active pane within its tab. Takes keyboard focus. */
  focused?: boolean;
};

type Status =
  /** `viaTunnel` only changes the copy: an SSH tunnel has to be dialled, and
   *  authenticated, before the RDP connect can even start, so a first connect
   *  through a bastion can sit here through TWO trust prompts. */
  | { kind: "connecting"; viaTunnel?: boolean }
  | { kind: "connected" }
  | { kind: "error"; message: string }
  | { kind: "closed"; reason: string };

/** The framebuffer, at the remote desktop's resolution. */
type Framebuffer = {
  canvas: HTMLCanvasElement;
  ctx: CanvasRenderingContext2D;
  width: number;
  height: number;
};

export function RdpPane({ leafId, connectionId, visible, focused = true }: Props) {
  const hostRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const fbRef = useRef<Framebuffer | null>(null);
  const viewportRef = useRef<RdpViewport>({ left: 0, top: 0, width: 0, height: 0, scale: 0 });
  const sessionRef = useRef<RdpSession | null>(null);

  const [status, setStatus] = useState<Status>({ kind: "connecting" });
  const [conn, setConn] = useState<RdpHost | null>(null);
  // Bumping this redials. The dependency of the connect effect, so a reconnect
  // is one state write rather than a hand-rolled teardown.
  const [attempt, setAttempt] = useState(0);

  // Latest `visible` for the frame path, which runs from a channel callback and
  // must not close over a stale render.
  const visibleRef = useRef(visible);
  visibleRef.current = visible;

  // ---------------------------------------------------------------- rendering

  const compositeHandle = useRef<number | null>(null);
  /** At most one pull in flight; that single credit IS the backpressure. While
   *  it is outstanding the backend keeps coalescing into its batcher, which is
   *  capped at one framebuffer by the collapse rule. */
  const pullingRef = useRef(false);
  /** `pullFrame`, read through a ref so `composite` can drive it without the
   *  two memoizations depending on each other. Assigned on every render, and
   *  only ever read from a frame callback, so there is nothing stale here. */
  const pullRef = useRef<() => void>(() => {});

  /** Point the framebuffer at a `width` x `height` desktop, discarding whatever
   *  was there. Called on connect and on a server-side resize, where the
   *  backend has already rebuilt its own framebuffer blank. */
  const resetFramebuffer = useCallback((width: number, height: number) => {
    const canvas = document.createElement("canvas");
    canvas.width = width;
    canvas.height = height;
    const ctx = canvas.getContext("2d", { alpha: false });
    if (!ctx) {
      fbRef.current = null;
      return;
    }
    ctx.fillStyle = "#000";
    ctx.fillRect(0, 0, width, height);
    fbRef.current = { canvas, ctx, width, height };
  }, []);

  /**
   * Blit one pulled batch into the framebuffer. Runs on a frame, never on the
   * channel callback.
   *
   * `false` means it was not applied. `putImageData` should not be able to
   * throw here - the parser has already proved every rect is in bounds and
   * every view in range - but if it ever does, the caller resyncs instead of
   * retrying the same poison bytes forever.
   */
  const blitBatch = useCallback(
    (batch: RdpFrameBatch): boolean => {
      try {
        // The batch header is authoritative about the framebuffer it describes:
        // a batch that arrives right after a server-side resize carries the NEW
        // size whether or not the `resize` event has been handled yet, so sizing
        // off it means the two can never disagree.
        let fb = fbRef.current;
        if (!fb || fb.width !== batch.fbWidth || fb.height !== batch.fbHeight) {
          resetFramebuffer(batch.fbWidth, batch.fbHeight);
          fb = fbRef.current;
          if (!fb) return false;
        }
        const { buffer, pixelOffsets, rects } = batch;
        for (let i = 0; i < rects.length; i++) {
          const r = rects[i];
          // A view, not a copy: the payload is already RGBA at the offsets
          // `ImageData` wants, and a keyframe is a whole framebuffer. The parser
          // has already proved every one of these ranges is in bounds.
          const data = new Uint8ClampedArray(buffer, pixelOffsets[i], r.w * r.h * 4);
          fb.ctx.putImageData(new ImageData(data, r.w, r.h), r.x, r.y);
        }
        return true;
      } catch (e) {
        console.error("rdp: dropped a frame batch that could not be blitted", e);
        return false;
      }
    },
    [resetFramebuffer],
  );

  /** Draw the framebuffer onto the visible canvas, letterboxed and at device
   *  resolution. Also the only place `viewportRef` is written, so the input
   *  mapping below can never disagree with what is on screen. */
  const composite = useCallback(() => {
    compositeHandle.current = null;
    const host = hostRef.current;
    const canvas = canvasRef.current;
    // Pull first, and unconditionally, before the early returns: a hidden pane
    // must still drain the backend's batcher, or the session sits holding
    // dirty rects nothing will ever ask for.
    pullRef.current();
    const fb = fbRef.current;
    if (!host || !canvas) return;
    if (!visibleRef.current) return;
    // `getBoundingClientRect`, not `clientWidth`: the workspace column applies
    // a CSS `zoom` to counter the UI zoom, and the rect is in the SAME space as
    // the pointer coordinates below. Measuring in layout pixels here and
    // hit-testing in visual ones is how a click lands away from the cursor.
    const rect = host.getBoundingClientRect();
    if (rect.width <= 0 || rect.height <= 0) return;
    const dpr = window.devicePixelRatio || 1;
    const backingW = Math.max(1, Math.round(rect.width * dpr));
    const backingH = Math.max(1, Math.round(rect.height * dpr));
    // Assigning width/height clears the canvas, so only do it on a real change
    // - and because it clears, the full redraw below has to follow it.
    if (canvas.width !== backingW || canvas.height !== backingH) {
      canvas.width = backingW;
      canvas.height = backingH;
    }
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    // The bars. An RDP desktop is opaque, so anything not covered by it is
    // padding rather than transparency.
    ctx.fillStyle = "#000";
    ctx.fillRect(0, 0, backingW, backingH);
    if (!fb) return;
    const vp = fitViewport(rect.width, rect.height, fb.width, fb.height);
    viewportRef.current = vp;
    if (vp.width <= 0 || vp.height <= 0) return;
    ctx.imageSmoothingEnabled = true;
    ctx.imageSmoothingQuality = "high";
    ctx.drawImage(
      fb.canvas,
      0,
      0,
      fb.width,
      fb.height,
      vp.left * dpr,
      vp.top * dpr,
      vp.width * dpr,
      vp.height * dpr,
    );
  }, []);

  const scheduleComposite = useCallback(() => {
    if (compositeHandle.current !== null) return;
    compositeHandle.current = requestAnimationFrame(composite);
  }, [composite]);

  /**
   * Repair the framebuffer by asking the host process for the current one as
   * a whole keyframe.
   *
   * This is what `rdp_snapshot` is for: deltas cannot be merged on this side,
   * so a batch that failed to blit leaves the framebuffer holding pixels the
   * server has since changed, and on an idle desktop nothing will ever repaint
   * the lost region.
   */
  const resync = useCallback(async () => {
    const session = sessionRef.current;
    if (!session) return;
    try {
      const keyframe = await rdpSnapshot(session.id);
      // Still the same session: a reconnect in flight owns the canvas now.
      if (keyframe && sessionRef.current === session) {
        blitBatch(keyframe);
        scheduleComposite();
      }
    } catch {
      // The session went away mid-fetch. The next keyframe from the server
      // repairs the image anyway; there is nothing useful to report here.
    }
  }, [blitBatch, scheduleComposite]);

  /** Collect whatever the backend has accumulated. */
  const pullFrame = useCallback(() => {
    const session = sessionRef.current;
    if (!session || pullingRef.current) return;
    pullingRef.current = true;
    void rdpTakeFrame(session.id)
      .then((batch) => {
        if (!batch || sessionRef.current !== session) return;
        // Failed blits are not retried with the same bytes: a keyframe is the
        // only way back, since deltas cannot be merged on this side.
        if (!blitBatch(batch)) void resync();
        // There may be more behind it. Scheduling a composite rather than
        // pulling again immediately is what rate-limits pulls to one per frame
        // and lets the backend coalesce in between.
        scheduleComposite();
      })
      .catch(() => {})
      .finally(() => {
        pullingRef.current = false;
      });
  }, [blitBatch, resync, scheduleComposite]);

  pullRef.current = pullFrame;

  // Re-letterbox on a pane resize (a divider drag, a window resize, the sidebar
  // collapsing). The desktop resolution is fixed, so this only moves the bars
  // and rescales - nothing is renegotiated with the server.
  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;
    const ro = new ResizeObserver(() => scheduleComposite());
    ro.observe(host);
    return () => ro.disconnect();
  }, [scheduleComposite]);

  // Redraw on becoming visible: composites are skipped while the tab is hidden,
  // so without this the pane shows whatever was on screen when it left. It also
  // RE-ARMS the pull loop, which is why there is no "was it stale" condition -
  // the loop stops whenever a pull comes back empty.
  useEffect(() => {
    if (visible) scheduleComposite();
  }, [visible, scheduleComposite]);

  // Same re-arm for the webview pausing `requestAnimationFrame` on a minimised
  // or backgrounded window: the loop stopped on an empty pull, and nothing else
  // would restart it when the batcher refills while frames were not running.
  useEffect(() => {
    document.addEventListener("visibilitychange", scheduleComposite);
    return () => document.removeEventListener("visibilitychange", scheduleComposite);
  }, [scheduleComposite]);

  useEffect(
    () => () => {
      if (compositeHandle.current !== null) cancelAnimationFrame(compositeHandle.current);
    },
    [],
  );

  // ------------------------------------------------------------------- input

  const pendingRef = useRef<RdpInputEvent[]>([]);
  const flushHandle = useRef<number | null>(null);
  const heldKeys = useRef<Set<number>>(new Set());
  /**
   * Characters sent as `unicodeDown` with no `keyUp` yet - a dead key, IME
   * output, or a layout position `scancodes.ts` cannot name.
   *
   * A third set and not a special case: these keys never reach `heldKeys`
   * (they have no scancode to put there), so without their own record
   * `releaseAll` sees nothing held and sends no marker at all. The stranded
   * character then stays pressed in the backend's own record, and because
   * `Database::apply` suppresses no-op transitions its next real press emits
   * nothing either - a key that has gone permanently dead rather than merely
   * stuck. Keyed by character because that is what the wire carries.
   */
  const heldUnicode = useRef<Set<string>>(new Set());
  const heldButtons = useRef<Set<number>>(new Set());

  const flushInput = useCallback(() => {
    flushHandle.current = null;
    const batch = pendingRef.current;
    if (batch.length === 0) return;
    pendingRef.current = [];
    // Dropped rather than retried: input is only meaningful in order and in
    // time, and the session is torn down on any error worth surfacing.
    void sessionRef.current?.sendInput(batch).catch(() => {});
  }, []);

  const queueInput = useCallback(
    (event: RdpInputEvent) => {
      const pending = pendingRef.current;
      // Collapse consecutive moves. A drag produces one per pointer event and
      // an absolute position supersedes the one before it, so only the last in
      // a frame carries information - but a move that follows a button event
      // must NOT be collapsed backwards past it, which is why this only looks
      // at the immediately preceding entry.
      const last = pending[pending.length - 1];
      if (event.kind === "mouseMove" && last?.kind === "mouseMove") {
        pending[pending.length - 1] = event;
      } else {
        pending.push(event);
      }
      if (flushHandle.current === null) flushHandle.current = requestAnimationFrame(flushInput);
    },
    [flushInput],
  );

  /** Send immediately instead of on the next frame. For `releaseAll`, which
   *  fires on blur and on unmount - a frame later is a frame too late when the
   *  component is going away. */
  const queueInputNow = useCallback(
    (event: RdpInputEvent) => {
      queueInput(event);
      if (flushHandle.current !== null) {
        cancelAnimationFrame(flushHandle.current);
        flushHandle.current = null;
      }
      flushInput();
    },
    [queueInput, flushInput],
  );

  /** Release everything held. Sent as one marker the backend expands against
   *  its own record of what is down, because only it knows. */
  const releaseAll = useCallback(() => {
    // Every set, or the marker is skipped for a key the pane really is holding.
    // The backend's own `release_all` drains its unicode state alongside its
    // scancodes, so a held character is released the moment the marker arrives;
    // it was only ever the marker that went missing.
    if (
      heldKeys.current.size === 0 &&
      heldUnicode.current.size === 0 &&
      heldButtons.current.size === 0
    ) {
      return;
    }
    heldKeys.current.clear();
    heldUnicode.current.clear();
    heldButtons.current.clear();
    queueInputNow({ kind: "releaseAll" });
  }, [queueInputNow]);

  // Focus left the pane, the tab, or the window. Any of the three strands a
  // held modifier on the server, so all three release.
  useEffect(() => {
    if (!visible || !focused) releaseAll();
  }, [visible, focused, releaseAll]);

  useEffect(() => {
    const onWindowBlur = () => releaseAll();
    window.addEventListener("blur", onWindowBlur);
    return () => window.removeEventListener("blur", onWindowBlur);
  }, [releaseAll]);

  /**
   * `visible` / `focused` as of the LATEST render, read by the claim below at
   * FLUSH time - one frame after it is made - so a claim made from a render
   * that is already stale by the time the frame runs is dropped rather than
   * honoured. Same property `liveFocus` gives `useTerminalSession`, here
   * applied to a component rather than a hook closed over a stable `leafId`.
   */
  const liveFocus = useRef({ visible, focused });
  liveFocus.current = { visible, focused };

  // Claimed, not taken. This effect can run INSIDE the mousedown that
  // switched the tab (Radix `Tabs` changes value on mousedown and React 19
  // flushes the commit synchronously there), so a `.focus()` call here is
  // undone a moment later by the browser focusing the tab chip that was
  // clicked - the same defect the terminal pane had, fixed here the same way
  // (see `@/lib/paneCaret` for the measured sequence). The arbiter re-checks
  // `liveFocus` one frame later before handing the caret over.
  useEffect(() => {
    if (!visible || !focused) return;
    paneCaret.claim(leafId, {
      // The pane frame around this leaf, not just the RDP host element: a
      // click on this pane's own header (Ctrl+Alt+Del, float, close) has to
      // count as "the caret is already in my pane", or the claim would pull
      // it back onto the canvas a frame later. Falls back to the host element
      // itself when there is no such ancestor, mirroring
      // `useTerminalSession`'s fallback for a pane with no `[data-pane-leaf]`
      // frame.
      pane: () => hostRef.current?.closest<HTMLElement>("[data-pane-leaf]") ?? hostRef.current,
      stillOnScreen: () => liveFocus.current.visible && liveFocus.current.focused,
      take: () => hostRef.current?.focus({ preventScroll: true }),
    });
  }, [leafId, visible, focused]);

  // A claim outlives the render that made it by a frame, so an unmount
  // between the two would otherwise focus a torn-down pane's host element.
  useEffect(() => () => paneCaret.release(leafId), [leafId]);

  useEffect(
    () => () => {
      if (flushHandle.current !== null) cancelAnimationFrame(flushHandle.current);
    },
    [],
  );

  /** Pointer coordinates -> remote pixel, or null in the letterbox bars. */
  const mapPoint = useCallback((clientX: number, clientY: number) => {
    const host = hostRef.current;
    const fb = fbRef.current;
    if (!host || !fb) return null;
    const rect = host.getBoundingClientRect();
    return toRemotePoint(
      viewportRef.current,
      fb.width,
      fb.height,
      clientX - rect.left,
      clientY - rect.top,
    );
  }, []);

  const sendCtrlAltDel = useCallback(() => {
    for (const scancode of CTRL_ALT_DEL_SCANCODES.down) queueInput({ kind: "keyDown", scancode });
    for (const scancode of CTRL_ALT_DEL_SCANCODES.up) queueInput({ kind: "keyUp", scancode });
  }, [queueInput]);

  // Pane-header actions. Keyed by leaf id over a window event, so the header
  // needs no handle on this component - see `paneActions.ts`. Dispatched through
  // a total Record rather than an if/else, so a new action added to the union is
  // a compile error here instead of an event that arrives and does nothing.
  useEffect(() => {
    const actions: Record<RdpPaneAction, () => void> = { ctrlAltDel: sendCtrlAltDel };
    return onRdpPaneAction(leafId, (action) => actions[action]());
  }, [leafId, sendCtrlAltDel]);

  // ----------------------------------------------------------------- session

  useEffect(() => {
    let alive = true;
    let session: RdpSession | null = null;
    let promptId: string | null = null;
    /**
     * The tunnel this connect is riding, once it is open. Held here rather than
     * in a ref because it belongs to THIS attempt: the teardown that releases it
     * is the same one that closes the session.
     */
    let dial: RdpDialTarget | null = null;
    /**
     * Host-key prompts the tunnel raised. A tunnelled first connect can ask TWO
     * trust questions - the bastion's host key, then the RDP certificate - and
     * every one of them has a backend parked mid-handshake behind it, so every
     * one has to be answered on the way out. A set because a ProxyJump chain
     * asks once per unpinned hop.
     */
    const sshPromptIds = new Set<string>();
    /** Idempotent, and safe on a path that cannot know whether the tunnel ever
     *  opened - which is every teardown that beats the `await` below.
     *
     *  The release's promise is DROPPED, because this function is called from an
     *  effect cleanup and a cleanup cannot await. Nothing is lost by that: what
     *  waiting would have bought - a close that cannot land on a listener a
     *  later open bound on the same port - is carried by the forward's own
     *  generation (`SshForward.generation` in `ssh/tunnel.ts`). */
    const releaseDial = () => {
      void dial?.release();
      dial = null;
    };
    // An `error` event while connected is not necessarily fatal (the backend
    // follows a fatal one with `disconnected`), so it is remembered rather than
    // shown: the reason a session dropped is far more useful than the bare
    // "disconnected" that follows it.
    let lastError: string | null = null;

    setStatus({ kind: "connecting" });
    fbRef.current = null;
    heldKeys.current.clear();
    heldUnicode.current.clear();
    heldButtons.current.clear();

    void (async () => {
      const found = (await listHosts()).find((h) => h.id === connectionId);
      if (!alive) return;
      // A saved id can now name an SSH host - the two used to be different id
      // spaces. Refused rather than cast: there is no RDP row to dial.
      const row = found && isRdpHost(found) ? found : null;
      setConn(row);
      if (!found) {
        setStatus({
          kind: "error",
          message: "This saved RDP connection no longer exists. It may have been deleted.",
        });
        return;
      }
      if (!row) {
        setStatus({ kind: "error", message: `"${found.name}" is not an RDP host.` });
        return;
      }
      // `resolveRdpAuth` (inside `rdpOpenInput`) hands `rdp_open` the account
      // reference unconditionally, so this pre-flight check only applies to an
      // inline credential; a vault-bound identity's presence is not knowable
      // without resolving it, and the connect attempt below reports it either way.
      if (row.credential.kind === "inline" && !row.credential.hasPassword) {
        setStatus({
          kind: "error",
          message: `No password is stored for "${row.name}". Edit the connection and enter it.`,
        });
        return;
      }
      try {
        if (row.tunnel) setStatus({ kind: "connecting", viaTunnel: true });
        // The tunnel first, and it can block for a long time: dialling the
        // bastion, and a first connect to it waits on the host-key dialog.
        const target = await openRdpDialTarget(row, {
          onHostKeyPrompt: (id) => sshPromptIds.add(id),
        });
        // Teardown can win this race, and a tunnel nobody claims is a bastion
        // session held open with no consumer left to release it.
        if (!alive) {
          await target.release();
          return;
        }
        dial = target;
        const opened = await openRdp(
          // Every field except the address comes from the row, so a tunnelled
          // connect differs from a direct one in the address and nothing else -
          // the pinned certificate included, which is what stops an ephemeral
          // local port from looking like a new machine every time.
          await rdpOpenInput(row, target),
          {
            onConnected: (width, height, fingerprint) => {
              if (!alive) return;
              resetFramebuffer(width, height);
              setStatus({ kind: "connected" });
              scheduleComposite();
              void markConnected(row.id, fingerprint).catch(() => {});
            },
            onCertPrompt: (prompt) => {
              // REJECT rather than return. `promptId` is recorded on the line
              // below, so a prompt that lands once this attempt is dead is
              // recorded nowhere and the teardown's `abandon` has no id to
              // answer - and the window for it is the TCP connect plus the TLS
              // handshake, seconds wide, with "closed the tab while it said
              // Connecting…" as the ordinary way in. Behind an unanswered
              // prompt the backend's verifier is parked on its full confirm
              // timeout, holding the socket, the in-flight handshake and (the
              // verifier blocks) a displaced runtime thread; `rdp_open` has not
              // returned, so there is no session id and `close()` cannot help.
              // This is the same rejection the teardown would have sent, and
              // the only thing that releases them.
              if (!alive) {
                void confirmRdpCert(prompt.promptId, false).catch(() => {});
                return;
              }
              promptId = prompt.promptId;
              useHostKeyPrompt.getState().enqueue(
                {
                  promptId: prompt.promptId,
                  fingerprint: prompt.fingerprint,
                  // The row's host, not the backend's: through a tunnel the
                  // backend dialled `127.0.0.1`, and "First connection to
                  // 127.0.0.1" names the wrong end of the tunnel for a
                  // question about a remote machine's certificate. Identical
                  // for a direct dial, where the backend echoes this host.
                  host: row.host,
                  certificate: { subject: prompt.subject, issuer: prompt.issuer },
                  confirm: confirmRdpCert,
                },
                // Pinned at the moment of trust, not on a successful connect:
                // a wrong password otherwise re-asks the same question on
                // every retry.
                () => void pinFingerprint(row.id, prompt.fingerprint).catch(() => {}),
              );
            },
            onResize: (width, height) => {
              if (!alive) return;
              // The backend has already rebuilt its framebuffer blank at this
              // size and the server repaints it, so the deltas that follow are
              // ordinary ones against a fresh buffer.
              resetFramebuffer(width, height);
              scheduleComposite();
            },
            onFrameReady: () => {
              if (alive) scheduleComposite();
            },
            onDisconnected: (reason) => {
              if (!alive) return;
              sessionRef.current = null;
              setStatus({ kind: "closed", reason: lastError || reason });
              // Nothing is riding the tunnel any more, and the pane stays
              // mounted on its "ended" overlay for as long as the user leaves
              // it there. Holding a bastion session open behind a dead RDP
              // session is pure cost; Reconnect opens a fresh one.
              releaseDial();
            },
            onError: (message) => {
              if (!alive) return;
              lastError = message;
              setStatus((prev) => (prev.kind === "connected" ? prev : { kind: "error", message }));
            },
          },
        );
        // Teardown can win the race with the open: closing here is the only
        // thing that stops the session outliving the pane that asked for it.
        if (!alive) {
          void opened.close().catch(() => {});
          return;
        }
        session = opened;
        sessionRef.current = opened;
      } catch (e) {
        // Covers the tunnel's own failures too - a refused bastion, a rejected
        // host key, a target the jump host cannot reach - so the message a user
        // sees for "no route to 3389" is the SSH one that explains it.
        releaseDial();
        if (alive)
          setStatus({ kind: "error", message: e instanceof Error ? e.message : String(e) });
      }
    })();

    return () => {
      alive = false;
      sessionRef.current = null;
      // ANSWER the certificate question, do not merely drop it from the queue.
      //
      // This teardown is every way out of an RDP pane: unmount, tab close,
      // workspace switch, a reconnect, re-pointing the leaf at another host. If
      // the certificate dialog was on screen for any of them, the backend is
      // still parked inside the TLS handshake - which means `rdp_open` has NOT
      // returned and there is no session id in existence, so the `close()` below
      // finds nothing and logs "unknown id". A rejection is the only thing that
      // releases the socket, the handshake and the blocked thread before the
      // 120-second confirm timeout.
      //
      // `abandon` no-ops when the user already answered, so this is safe to run
      // unconditionally on a path that cannot know whether they did.
      if (promptId) useHostKeyPrompt.getState().abandon(promptId);
      // The tunnel's own trust question has exactly the same shape one step
      // earlier: the bastion's handshake is parked, `openSsh` has not returned,
      // and this pane was the only thing that would have answered.
      for (const id of sshPromptIds) useHostKeyPrompt.getState().abandon(id);
      sshPromptIds.clear();
      void session?.close().catch(() => {});
      // The tunnel outlives nothing: a forward opened for a pane that unmounted
      // before `rdp_open` returned is released by the `!alive` check above, and
      // one that got as far as a live session is released here.
      releaseDial();
    };
  }, [connectionId, attempt, resetFramebuffer, scheduleComposite]);

  const hostLabel = conn ? conn.name.trim() || conn.host : "";

  return (
    <div
      ref={hostRef}
      // Focusable so the pane can own the keyboard, and `outline-none` because
      // the pane frame already draws the focus ring.
      tabIndex={0}
      data-rdp-leaf-id={leafId}
      className="relative h-full w-full overflow-hidden bg-black outline-none"
      onBlur={releaseAll}
      onKeyDown={(e) => {
        // Everything the pane is focused for goes to the remote, including Tab
        // (which would otherwise move focus out) and the browser's own
        // accelerators. App-level chords never reach here: `useGlobalShortcuts`
        // listens at window capture and stops propagation for the ones it
        // owns, and App's `isDisabled` gate lets a focused RDP pane keep the
        // bare-Ctrl and bare-Alt sequences exactly as a focused terminal does.
        e.preventDefault();
        e.stopPropagation();
        const scancode = scancodeFor(e.code);
        if (scancode !== undefined) {
          heldKeys.current.add(scancode);
          // Repeats are forwarded rather than filtered: RDP has no client-side
          // auto-repeat, so swallowing them means a held arrow key moves once.
          queueInput({ kind: "keyDown", scancode });
          return;
        }
        // No scancode for this physical key: a dead key, IME output, or a
        // layout position the table cannot name. `[...key]` because the
        // backend takes one Unicode scalar, and an astral character is two
        // UTF-16 units.
        if (e.key.length > 0 && [...e.key].length === 1) {
          // Recorded so blur releases it. A shifted release can report a
          // different `key` than its press, which leaves a stale entry here -
          // harmless, because it only means the marker is sent when nothing is
          // held, and the backend's `release_all` is what actually decides what
          // comes up.
          heldUnicode.current.add(e.key);
          queueInput({ kind: "unicodeDown", ch: e.key });
        }
      }}
      onKeyUp={(e) => {
        e.preventDefault();
        e.stopPropagation();
        const scancode = scancodeFor(e.code);
        if (scancode !== undefined) {
          heldKeys.current.delete(scancode);
          queueInput({ kind: "keyUp", scancode });
          return;
        }
        if (e.key.length > 0 && [...e.key].length === 1) {
          heldUnicode.current.delete(e.key);
          queueInput({ kind: "unicodeUp", ch: e.key });
        }
      }}
      onPointerDown={(e) => {
        hostRef.current?.focus({ preventScroll: true });
        const point = mapPoint(e.clientX, e.clientY);
        if (!point) return;
        // Capture so a drag that leaves the canvas still reports its moves and
        // its release. Without it a selection dragged off the edge sticks down
        // on the remote.
        e.currentTarget.setPointerCapture(e.pointerId);
        queueInput({ kind: "mouseMove", x: point.x, y: point.y });
        heldButtons.current.add(e.button);
        queueInput({ kind: "mouseDown", button: e.button });
      }}
      onPointerMove={(e) => {
        const point = mapPoint(e.clientX, e.clientY);
        if (point) queueInput({ kind: "mouseMove", x: point.x, y: point.y });
      }}
      onPointerUp={(e) => {
        const point = mapPoint(e.clientX, e.clientY);
        if (point) queueInput({ kind: "mouseMove", x: point.x, y: point.y });
        // Only release a button this pane saw pressed, so a release that
        // arrives after a `releaseAll` does not press-release it again.
        if (heldButtons.current.delete(e.button)) {
          queueInput({ kind: "mouseUp", button: e.button });
        }
        if (e.currentTarget.hasPointerCapture(e.pointerId)) {
          e.currentTarget.releasePointerCapture(e.pointerId);
        }
      }}
      onWheel={(e) => {
        // The pane does not scroll; the remote does.
        e.preventDefault();
        const vertical = wheelRotation(e.deltaY);
        if (vertical) queueInput({ kind: "wheel", vertical: true, delta: vertical });
        const horizontal = wheelRotation(e.deltaX);
        if (horizontal) queueInput({ kind: "wheel", vertical: false, delta: horizontal });
      }}
      // The right button belongs to the remote desktop's context menu, not the
      // webview's.
      onContextMenu={(e) => e.preventDefault()}
    >
      <canvas
        ref={canvasRef}
        // The server composites its own cursor into the framebuffer, so the
        // pane keeps the default arrow rather than drawing a second one.
        className="absolute inset-0 h-full w-full"
        aria-label={hostLabel ? `Remote desktop: ${hostLabel}` : "Remote desktop"}
      />
      {status.kind !== "connected" && (
        <StatusOverlay
          status={status}
          hostLabel={hostLabel}
          onReconnect={() => setAttempt((n) => n + 1)}
        />
      )}
    </div>
  );
}

const OVERLAY_SHELL =
  "bg-background text-muted-foreground absolute inset-0 flex flex-col items-center justify-center gap-3 p-6 text-center text-[11px]";

/**
 * Connecting / failed / ended, over the canvas.
 *
 * Same shape as the pane-level SSH surface (`RemoteEditorPending`) and the same
 * tone tokens: `icon-working` and its pulse for "on its way", `icon-blocked`
 * for a dead one - which are exactly what `statusLabelClass` maps `connecting`
 * and `error` onto in the tab strip, so an RDP pane reads the way an SSH one
 * does rather than inventing a third palette.
 *
 * The prop type excludes `connected` rather than ignoring it: this overlay is
 * only rendered over a session that is NOT up, and spelling that out means a
 * later state added to `Status` has to be handled here instead of silently
 * falling into the error arm.
 */
function StatusOverlay({
  status,
  hostLabel,
  onReconnect,
}: {
  status: Exclude<Status, { kind: "connected" }>;
  hostLabel: string;
  onReconnect: () => void;
}) {
  if (status.kind === "connecting") {
    return (
      <div className={OVERLAY_SHELL}>
        <Monitor
          size={22}
          strokeWidth={1.5}
          className="text-icon-working animate-pulse opacity-80"
        />
        <span className="text-icon-working max-w-72 animate-pulse leading-relaxed">
          Connecting to <span className="font-medium">{hostLabel || "the remote desktop"}</span>
          {/* Named because it is the slow half and the one that can stop for a
              trust prompt: the bastion is dialled and authenticated before the
              RDP connect starts at all. */}
          {status.viaTunnel ? " through its SSH tunnel" : null}…
        </span>
      </div>
    );
  }
  const Icon = status.kind === "closed" ? Unplug : MonitorOff;
  return (
    <div className={OVERLAY_SHELL}>
      <Icon size={22} strokeWidth={1.5} className={cn("text-icon-blocked", "opacity-80")} />
      <span className="max-w-96 leading-relaxed break-words">
        {status.kind === "closed" ? (
          <>
            <span className="text-foreground">{hostLabel || "The session"}</span> ended
            {status.reason ? <> · {status.reason}</> : null}
          </>
        ) : (
          status.message
        )}
      </span>
      <button
        type="button"
        onClick={onReconnect}
        className="hover:bg-muted hover:text-foreground border-border rounded-md border px-2 py-1 transition-colors"
      >
        Reconnect
      </button>
    </div>
  );
}
