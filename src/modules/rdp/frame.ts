/**
 * Reader for the host -> webview RDP frame wire format.
 *
 * The format is defined by `src-tauri/src/modules/rdp/frame.rs` (version 1);
 * this is the other half of it. Every multi-byte field is little-endian.
 *
 * ```text
 * offset size field       notes
 * ------ ---- ----------- ----------------------------------------------
 *      0    4 magic       ASCII "RDPF", in byte order
 *      4    1 version     1
 *      5    1 kind        0 = delta, 1 = keyframe
 *      6    2 rectCount   u16
 *      8    2 fbWidth     u16
 *     10    2 fbHeight    u16
 *     12    4 payloadLen  u32
 *     16  8*n rect table  8 bytes each: x, y, w, h (all u16)
 *  16+8*n  pl pixels      rects' contents concatenated in table order
 * ```
 *
 * `w`/`h` are real pixel counts, so a rect contributes `h` rows of `w * 4`
 * bytes, tightly packed with no row padding and no gap between rects. Channel
 * order is R, G, B, A - which is exactly what `ImageData` wants, so a rect is
 * blitted with `putImageData` and no per-pixel rework. The encoder forces alpha
 * to 0xFF, so a decoded rect is opaque.
 *
 * A batch that fails any check is DROPPED rather than partially applied: the
 * pixels are the only thing being described, so a half-trusted header would
 * either paint garbage or index past the payload. Losing one batch costs at
 * most one repaint - the next update covers the same region.
 */

/** `"RDPF"`, the bytes at offset 0..4. */
const MAGIC = [0x52, 0x44, 0x50, 0x46] as const;
/** Wire-format version this reader understands. Anything else is refused
 *  rather than guessed at, which is the point of the field. */
export const RDP_FRAME_VERSION = 1;
const HEADER_LEN = 16;
const RECT_LEN = 8;
const BYTES_PER_PIXEL = 4;

/** One dirty rectangle. `w`/`h` are pixel counts, not edges. */
export type RdpRect = { x: number; y: number; w: number; h: number };

export type RdpFrameBatch = {
  /** True when this batch replaces the whole framebuffer. Always exactly one
   *  rect covering `fbWidth` x `fbHeight`. */
  keyframe: boolean;
  /** Framebuffer this batch belongs to. Authoritative: a batch that arrives
   *  after a server-side resize carries the NEW size, whether or not the
   *  `resize` event has been processed yet. */
  fbWidth: number;
  fbHeight: number;
  rects: RdpRect[];
  /**
   * The received buffer itself, kept rather than copied out: a keyframe is a
   * whole framebuffer, and every rect is blitted as a VIEW over this
   * (`new Uint8ClampedArray(buffer, pixelOffsets[i], w * h * 4)` feeds
   * `ImageData` with no allocation).
   */
  buffer: ArrayBuffer;
  /**
   * ABSOLUTE byte offset of each rect's pixels within `buffer`, in table order.
   * Absolute so a caller needs nothing but the batch to build a view; every one
   * is in bounds by construction (see the payload-length check below).
   */
  pixelOffsets: number[];
};

/**
 * Decode one batch, or `null` when the payload is not a batch this reader
 * trusts. Never throws: a `Channel` handler has nowhere useful to send an
 * exception, and a corrupt batch must not take the session down with it.
 */
export function parseFrameBatch(buffer: ArrayBuffer): RdpFrameBatch | null {
  if (buffer.byteLength < HEADER_LEN) return null;
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < MAGIC.length; i++) {
    if (bytes[i] !== MAGIC[i]) return null;
  }
  const view = new DataView(buffer);
  if (view.getUint8(4) !== RDP_FRAME_VERSION) return null;
  const kind = view.getUint8(5);
  // Only the two documented kinds. An unknown kind is a layout change that
  // should have bumped the version, so treat it as corrupt.
  if (kind !== 0 && kind !== 1) return null;
  const rectCount = view.getUint16(6, true);
  // A batch with no rects describes nothing. The encoder can emit one when
  // every rect clipped away, and there is nothing to paint either way.
  if (rectCount === 0) return null;
  const fbWidth = view.getUint16(8, true);
  const fbHeight = view.getUint16(10, true);
  if (fbWidth === 0 || fbHeight === 0) return null;
  const payloadLen = view.getUint32(12, true);

  const tableLen = rectCount * RECT_LEN;
  // The length the header implies must be the length that arrived, exactly:
  // short means a truncated payload, long means this is not the format we
  // think it is.
  if (buffer.byteLength !== HEADER_LEN + tableLen + payloadLen) return null;

  const payloadStart = HEADER_LEN + tableLen;
  const rects: RdpRect[] = new Array(rectCount);
  const pixelOffsets: number[] = new Array(rectCount);
  let expected = 0;
  for (let i = 0; i < rectCount; i++) {
    const at = HEADER_LEN + i * RECT_LEN;
    const rect: RdpRect = {
      x: view.getUint16(at, true),
      y: view.getUint16(at + 2, true),
      w: view.getUint16(at + 4, true),
      h: view.getUint16(at + 6, true),
    };
    // A zero-extent rect has no pixels behind it, and one reaching past the
    // framebuffer would be blitted outside the canvas the header just sized.
    // The encoder clips both away, so either means the table is not the one
    // that produced this payload.
    if (rect.w === 0 || rect.h === 0) return null;
    if (rect.x + rect.w > fbWidth || rect.y + rect.h > fbHeight) return null;
    rects[i] = rect;
    pixelOffsets[i] = payloadStart + expected;
    expected += rect.w * rect.h * BYTES_PER_PIXEL;
  }
  // The encoder guarantees `payloadLen === sum(w * h * 4)`. Checking it here
  // (rather than only the total length, which the byteLength test above
  // covers) is what makes every per-rect slice below in-bounds by
  // construction: a table that sums to more than the payload would otherwise
  // read past the end on the last rect.
  if (expected !== payloadLen) return null;

  return { keyframe: kind === 1, fbWidth, fbHeight, rects, buffer, pixelOffsets };
}
