import { useCallback, useEffect, useRef, useState } from "react";
import { Monitor, MonitorOff, Unplug } from "lucide-react";
import { cn } from "@/lib/utils";
import { useHostKeyPrompt } from "@/modules/ssh/hostKeyPrompt";
import {
  confirmRdpCert,
  openRdp,
  rdpSnapshot,
  type RdpInputEvent,
  type RdpSession,
} from "./bridge";
import { listConnections, markConnected, pinFingerprint, type RdpConnection } from "./connections";
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
 * NOTHING touches a canvas on the channel callback. That is a constraint Tauri
 * imposes, not a preference: a raw payload of 1024 bytes or more is parked in a
 * process-global map and only freed when the JS side's `invoke(fetch)` actually
 * runs, and Tauri's own wrapper swallows failures with `.catch(console.error)` -
 * so a handler that throws, or that blocks long enough for messages to pile up
 * behind it, can strand payloads in that map with nothing left to collect them.
 * The callback queues a reference and returns; the blit and the composite both
 * happen on the next frame, which also coalesces several batches into one draw.
 *
 * The queue is bounded (`MAX_QUEUED_FRAME_BYTES`) because a batch is bounded at
 * one framebuffer - 33 MB at 4K - and they can arrive at up to 62 Hz, so an
 * unbounded backlog behind a stalled main thread is an OOM rather than a stutter.
 * Overflowing drops the backlog and repairs the image from `rdp_snapshot`.
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
 * is worse than one in the wrong shape (RDP-12). Clipboard, audio, device
 * redirection and dynamic resize are out of scope for this phase.
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

/**
 * Cap on the queued frame BACKLOG, in bytes.
 *
 * A batch is bounded at one framebuffer, which is ~4 MiB at 1280x800 but ~33 MB
 * at 4K, and they can arrive at up to 62 Hz. A main thread stalled for a second
 * would queue gigabytes, so the backlog cannot be unbounded.
 *
 * It caps the BACKLOG and not a single batch, which is why the check below only
 * fires with something already queued. One batch is affordable by definition -
 * it is exactly what would be held for the duration of a synchronous blit - and
 * capping a lone batch would mean a framebuffer larger than this could never be
 * drawn at all: each one would trip the cap, request a resync, and get back a
 * keyframe that trips it again.
 */
const MAX_QUEUED_FRAME_BYTES = 48 * 1024 * 1024;

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
  const [conn, setConn] = useState<RdpConnection | null>(null);
  // Bumping this redials. The dependency of the connect effect, so a reconnect
  // is one state write rather than a hand-rolled teardown.
  const [attempt, setAttempt] = useState(0);

  // Latest `visible` for the frame path, which runs from a channel callback and
  // must not close over a stale render.
  const visibleRef = useRef(visible);
  visibleRef.current = visible;
  // A composite was skipped while hidden, so becoming visible must redraw even
  // if no new frame has arrived since.
  const staleRef = useRef(false);

  // ---------------------------------------------------------------- rendering

  const compositeHandle = useRef<number | null>(null);
  /**
   * Batches waiting to be blitted into the framebuffer, oldest first.
   *
   * Frames do NOT touch a canvas on the channel callback. Tauri's `Channel`
   * makes that dangerous rather than merely slow: a payload of 1024 bytes or
   * more is parked in a process-global map and only removed when the JS side's
   * `invoke(fetch)` actually runs, and Tauri's own wrapper ends in
   * `.catch(console.error)` - so a handler that throws, or that blocks long
   * enough to pile messages up behind it, can leave payloads parked with
   * nothing left to collect them. The handler therefore does the cheapest
   * possible thing: push a reference and return.
   *
   * References, not copies. The `ArrayBuffer` handed to `onmessage` belongs to
   * that message alone and nothing reuses it, so holding a view across a frame
   * is safe - and copying would cost the same memcpy the blit is being deferred
   * to avoid, on up to 33 MB.
   */
  const pendingBatches = useRef<RdpFrameBatch[]>([]);
  /** Bytes held in `pendingBatches`, to bound it. */
  const queuedBytes = useRef(0);
  /** The queue overflowed and deltas were dropped, so the framebuffer no longer
   *  matches the server's and only a fresh keyframe can reconcile them. */
  const desyncedRef = useRef(false);

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
   * Blit every queued batch into the framebuffer, oldest first. Runs on a frame,
   * never on the channel callback.
   *
   * Wrapped so one bad batch cannot wedge the pane: `putImageData` should not be
   * able to throw here (the parser has already proved every rect is in bounds
   * and every view in range), but if it ever does, the queue is cleared and a
   * resync requested rather than the same poison batch being retried on every
   * subsequent frame forever.
   */
  const drainBatches = useCallback(() => {
    const queued = pendingBatches.current;
    if (queued.length === 0) return;
    pendingBatches.current = [];
    queuedBytes.current = 0;
    try {
      for (const batch of queued) {
        // The batch header is authoritative about the framebuffer it describes:
        // a batch that arrives right after a server-side resize carries the NEW
        // size whether or not the `resize` event has been handled yet, so sizing
        // off it means the two can never disagree.
        let fb = fbRef.current;
        if (!fb || fb.width !== batch.fbWidth || fb.height !== batch.fbHeight) {
          resetFramebuffer(batch.fbWidth, batch.fbHeight);
          fb = fbRef.current;
          if (!fb) return;
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
        // A keyframe replaces everything, so it also clears any earlier loss.
        if (batch.keyframe) desyncedRef.current = false;
      }
    } catch (e) {
      console.error("rdp: dropped a frame batch that could not be blitted", e);
      desyncedRef.current = true;
    }
  }, [resetFramebuffer]);

  /** Draw the framebuffer onto the visible canvas, letterboxed and at device
   *  resolution. Also the only place `viewportRef` is written, so the input
   *  mapping below can never disagree with what is on screen. */
  const composite = useCallback(() => {
    compositeHandle.current = null;
    const host = hostRef.current;
    const canvas = canvasRef.current;
    // Drain first, and unconditionally: the queue holds Tauri's own buffers, so
    // leaving it full while the tab is hidden would pin tens of megabytes for as
    // long as the user is looking somewhere else.
    drainBatches();
    const fb = fbRef.current;
    if (!host || !canvas) return;
    if (!visibleRef.current) {
      staleRef.current = true;
      return;
    }
    staleRef.current = false;
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
  }, [drainBatches]);

  const scheduleComposite = useCallback(() => {
    if (compositeHandle.current !== null) return;
    compositeHandle.current = requestAnimationFrame(composite);
  }, [composite]);

  /**
   * What the channel callback does with a batch, and all it does: queue the
   * reference, note the bytes, ask for a frame. No canvas, no allocation beyond
   * the push, no `await`. See `pendingBatches` for why the work is deferred
   * rather than done here.
   */
  const enqueueBatch = useCallback(
    (batch: RdpFrameBatch) => {
      // A keyframe replaces the whole framebuffer, so everything queued behind
      // it is already dead. Dropping those is free correctness AND the main
      // thing that keeps the queue short on a busy desktop, where the Rust
      // batcher collapses to a keyframe whenever the dirty area passes half the
      // screen.
      if (batch.keyframe) {
        pendingBatches.current = [];
        queuedBytes.current = 0;
      }
      const bytes = batch.buffer.byteLength;
      // `length > 0` is load-bearing: the cap bounds the BACKLOG, so a lone
      // batch is always accepted however large. See `MAX_QUEUED_FRAME_BYTES`.
      if (
        pendingBatches.current.length > 0 &&
        queuedBytes.current + bytes > MAX_QUEUED_FRAME_BYTES
      ) {
        // The main thread is far enough behind that holding the backlog costs
        // more than the picture is worth. Deltas cannot be merged on this side,
        // so the whole queue goes and the framebuffer is declared out of date;
        // `resync` below fetches a keyframe to repair it. Dropping is the only
        // bounded option - an unbounded queue at 33 MB a batch takes the webview
        // out with it.
        console.warn(
          `rdp: frame queue exceeded ${MAX_QUEUED_FRAME_BYTES} bytes, dropping the backlog and resyncing`,
        );
        pendingBatches.current = [];
        queuedBytes.current = 0;
        desyncedRef.current = true;
        scheduleComposite();
        void resync();
        return;
      }
      pendingBatches.current.push(batch);
      queuedBytes.current += bytes;
      scheduleComposite();
    },
    // `resync` is declared just below and is only ever read when the channel
    // calls this - long after both are bound - and it is memoized on the same
    // dependency, so there is nothing stale to capture and nothing to list.
    [scheduleComposite],
  );

  /**
   * Repair the framebuffer after dropped deltas, by asking the host process for
   * the current framebuffer as one keyframe.
   *
   * This is what `rdp_snapshot` is for, and why dropping a backlog is safe
   * rather than permanent: without it a desktop that went idle straight after an
   * overflow would show a stale image until something happened to repaint the
   * lost region, which on an idle desktop is never.
   */
  const resync = useCallback(async () => {
    const session = sessionRef.current;
    if (!session) return;
    try {
      const keyframe = await rdpSnapshot(session.id);
      // Still the same session, and nothing has arrived that already fixed it.
      if (keyframe && sessionRef.current === session && desyncedRef.current) {
        pendingBatches.current = [keyframe];
        queuedBytes.current = keyframe.buffer.byteLength;
        scheduleComposite();
      }
    } catch {
      // The session went away mid-fetch. The next keyframe from the server
      // repairs the image anyway; there is nothing useful to report here.
    }
  }, [scheduleComposite]);

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
  // so without this the pane shows whatever was on screen when it left.
  useEffect(() => {
    if (visible && staleRef.current) scheduleComposite();
  }, [visible, scheduleComposite]);

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

  useEffect(() => {
    if (visible && focused) hostRef.current?.focus({ preventScroll: true });
  }, [visible, focused]);

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
     *  opened - which is every teardown that beats the `await` below. */
    const releaseDial = () => {
      dial?.release();
      dial = null;
    };
    // An `error` event while connected is not necessarily fatal (the backend
    // follows a fatal one with `disconnected`), so it is remembered rather than
    // shown: the reason a session dropped is far more useful than the bare
    // "disconnected" that follows it.
    let lastError: string | null = null;

    setStatus({ kind: "connecting" });
    fbRef.current = null;
    pendingBatches.current = [];
    queuedBytes.current = 0;
    desyncedRef.current = false;
    heldKeys.current.clear();
    heldUnicode.current.clear();
    heldButtons.current.clear();

    void (async () => {
      const row = (await listConnections()).find((c) => c.id === connectionId);
      if (!alive) return;
      setConn(row ?? null);
      if (!row) {
        setStatus({
          kind: "error",
          message: "This saved RDP connection no longer exists. It may have been deleted.",
        });
        return;
      }
      if (!row.hasPassword) {
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
          target.release();
          return;
        }
        dial = target;
        const opened = await openRdp(
          // Every field except the address comes from the row, so a tunnelled
          // connect differs from a direct one in the address and nothing else -
          // the pinned certificate included, which is what stops an ephemeral
          // local port from looking like a new machine every time.
          rdpOpenInput(row, target),
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
            onFrame: (batch) => {
              if (alive) enqueueBatch(batch);
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
      // Drop references to Tauri's frame buffers rather than holding them until
      // the next GC. A queued keyframe is a whole framebuffer - 33 MB at 4K.
      pendingBatches.current = [];
      queuedBytes.current = 0;
    };
  }, [connectionId, attempt, enqueueBatch, resetFramebuffer, scheduleComposite]);

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
