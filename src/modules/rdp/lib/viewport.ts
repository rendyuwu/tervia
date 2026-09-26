/**
 * Letterbox geometry for a fixed-resolution remote desktop inside a pane that
 * is whatever size the user dragged it to, plus the CSS-px -> remote-px mapping
 * that has to be its exact inverse.
 *
 * Pure functions, no DOM: the mapping is where an off-by-one shows up as "the
 * click landed a few pixels from the cursor", which is unpleasant to chase
 * through a canvas and trivial to reason about here.
 *
 * In `"preset"` the remote desktop never changes size to match the pane, so
 * letterboxing is not optional: the aspect ratios genuinely differ. In `"fit"`
 * the remote is asked to match the pane (see `fitDesktopSize`), so the bars
 * shrink to the rounding/parity remainder - but they never vanish, because the
 * server may grant a different size than requested and an older server grants
 * none at all. Both `fitViewport` and `toRemotePoint` therefore stay exactly as
 * they are: they are driven by the framebuffer dimensions the backend reports,
 * whatever those turn out to be.
 */

/** Where the remote desktop lands inside the pane, in CSS pixels. */
export type RdpViewport = {
  /** Offset of the drawn image within the pane. */
  left: number;
  top: number;
  /** Size of the drawn image. Preserves the remote aspect ratio. */
  width: number;
  height: number;
  /** CSS px per remote px. Uniform on both axes by construction. */
  scale: number;
};

/**
 * Fit `remoteWidth` x `remoteHeight` into `paneWidth` x `paneHeight`, centred,
 * preserving aspect ratio.
 *
 * Scales UP as well as down. A preset smaller than the pane would otherwise sit
 * as a postage stamp in the middle of a maximised pane, which is what an RDP
 * pane looks like most of the time given the pane is a fraction of the window;
 * the cost is a soft image, which the browser's own bilinear filtering handles
 * better than any nearest-neighbour rule we could pick here.
 *
 * A zero-sized pane (mid-layout, or a hidden tab) yields a zero-sized viewport
 * rather than an infinity, so the caller can skip drawing without a special
 * case of its own.
 */
export function fitViewport(
  paneWidth: number,
  paneHeight: number,
  remoteWidth: number,
  remoteHeight: number,
): RdpViewport {
  if (paneWidth <= 0 || paneHeight <= 0 || remoteWidth <= 0 || remoteHeight <= 0) {
    return { left: 0, top: 0, width: 0, height: 0, scale: 0 };
  }
  const scale = Math.min(paneWidth / remoteWidth, paneHeight / remoteHeight);
  const width = remoteWidth * scale;
  const height = remoteHeight * scale;
  return {
    // Halves rather than rounded halves: the canvas is drawn in device pixels,
    // so rounding here would quantise the image to a CSS pixel and reintroduce
    // the seam a fractional devicePixelRatio is trying to avoid.
    left: (paneWidth - width) / 2,
    top: (paneHeight - height) / 2,
    width,
    height,
    scale,
  };
}

/**
 * Map a pane-relative CSS point to a remote-desktop pixel, or `null` when the
 * point is in the letterbox bars rather than on the desktop.
 *
 * `null` is the whole reason this returns an option: clamping an arbitrary
 * letterbox point instead would report a click on the desktop edge for a click
 * that was demonstrably beside it, which is how a stray drag ends up dropping a
 * file on the remote taskbar.
 *
 * The far boundary is the one exception, and it is deliberate: the accepted
 * range is the CLOSED interval `[0, viewport.width]`, so a point exactly on the
 * right or bottom edge maps to `remote - 1` rather than being rejected. Without
 * that, the last remote column and row are unreachable whenever the desktop is
 * downscaled and the pointer reports integer CSS pixels - at `scale` 0.5 the
 * reachable set is the even columns, and the odd last one is where Windows
 * keeps the bottom-right "show desktop" hot corner and a maximised window's
 * scrollbar. One CSS pixel past a drawn edge is what a user aiming AT that edge
 * actually produces, so treating it as the edge is both what they meant and
 * what every other RDP client does. No allowance is needed at the near edge,
 * where `0` already addresses pixel 0.
 *
 * The result is clamped on top of that, because RDP mouse coordinates are u16
 * pixel indices and the server does not bounds-check them for us.
 */
export function toRemotePoint(
  viewport: RdpViewport,
  remoteWidth: number,
  remoteHeight: number,
  cssX: number,
  cssY: number,
): { x: number; y: number } | null {
  if (viewport.scale <= 0) return null;
  const dx = cssX - viewport.left;
  const dy = cssY - viewport.top;
  // `>` and not `>=`: the far edge itself is on the desktop. See above.
  if (dx < 0 || dy < 0 || dx > viewport.width || dy > viewport.height) return null;
  return {
    x: Math.min(remoteWidth - 1, Math.max(0, Math.floor(dx / viewport.scale))),
    y: Math.min(remoteHeight - 1, Math.max(0, Math.floor(dy / viewport.scale))),
  };
}

/**
 * One wheel notch in RDP rotation units, from a DOM `WheelEvent` delta.
 *
 * Two conversions at once, and both are easy to get backwards:
 *
 * * MAGNITUDE. `deltaY` is in whatever `deltaMode` says (pixels for a trackpad,
 *   lines for a wheel, pages for some drivers) and its size is not comparable
 *   across devices. RDP counts detents of 120 units, so only the SIGN is taken
 *   and one notch is reported per event. A trackpad flick therefore scrolls at
 *   event rate rather than pixel rate, which is the behaviour every RDP client
 *   has.
 * * SIGN. The DOM's positive Y is "content moved down" (scroll down); RDP's
 *   positive rotation is scroll UP. Same inversion on the X axis, where RDP
 *   positive is left. So the sign is flipped, not passed through.
 *
 * Returns 0 for a zero delta, which the caller drops rather than sending an
 * event the server would read as a notch in the positive direction.
 */
export function wheelRotation(delta: number): number {
  if (!delta) return 0;
  return delta > 0 ? -120 : 120;
}

/**
 * The desktop size to ask for so the remote matches the pane one-to-one, or
 * `null` when the pane cannot be measured (a hidden tab, or mid-layout).
 *
 * DEVICE pixels, not CSS pixels. `paneWidth`/`paneHeight` come from
 * `getBoundingClientRect`, so they are already in the visual space the UI zoom
 * produces; multiplying by `devicePixelRatio` is what makes one remote pixel
 * one physical pixel, which is the whole point of fit mode - asking for CSS
 * pixels on a 2x display would upscale the framebuffer and give a blurrier
 * picture than the preset it replaced.
 *
 * The 200..=8192 clamp and the even width are MS-RDPEDISP 2.2.2.2.1. The
 * backend re-applies them through `MonitorLayoutEntry::adjust_display_size`,
 * but they are applied here too so that the value the pane remembers as
 * "already requested" is the value the server is actually asked for -
 * otherwise an odd pane width would re-request the same adjusted size on every
 * resize.
 */
export function fitDesktopSize(
  paneWidth: number,
  paneHeight: number,
  devicePixelRatio: number,
): { width: number; height: number } | null {
  if (paneWidth <= 0 || paneHeight <= 0 || devicePixelRatio <= 0) return null;
  const width = Math.min(8192, Math.max(200, Math.round(paneWidth * devicePixelRatio)));
  const height = Math.min(8192, Math.max(200, Math.round(paneHeight * devicePixelRatio)));
  // `& ~1` after the clamp, not before: 200 and 8192 are both even, so the
  // clamped range is closed under it.
  return { width: width & ~1, height };
}
