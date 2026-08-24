/**
 * RDP frame-format, letterbox and scancode audit. Four properties, and every
 * one of them fails SILENTLY: there is no exception to see, just wrong pixels,
 * a cursor that lands away from the click, or a key that types something else.
 *
 * 1. WIRE FORMAT. `frame.ts` is the reader for the format `src-tauri/src/
 *    modules/rdp/frame.rs` writes. The fixtures below are byte-for-byte the
 *    ones that file's own `header_layout_is_stable` test asserts, so a change
 *    to the layout on either side breaks both ends instead of one silently
 *    mis-parsing the other. A wrong offset here is a garbled desktop, not an
 *    error.
 * 2. CORRUPTION IS DROPPED, NOT PARTIALLY APPLIED. Every malformed shape the
 *    format documents - and the ones it does not, like a rect table that
 *    reaches past the framebuffer or sums to more than the payload - must
 *    return null. The alternative is an out-of-bounds view feeding `ImageData`.
 * 3. THE LETTERBOX MAPPING IS AN EXACT INVERSE. `fitViewport` decides where the
 *    desktop is drawn and `toRemotePoint` decides what a click hit; if they
 *    disagree by a pixel the cursor is permanently offset from the pointer, and
 *    if the bars are not excluded a click beside the desktop lands on its edge.
 * 4. SCANCODES CARRY THE EXTENDED FLAG. The navigation cluster and the numpad
 *    share low bytes, so a missing `0xE0` makes Delete type numpad-period and
 *    the arrows move the numpad. Nothing reports that; the remote just does the
 *    wrong thing.
 *
 * Run: `npx tsx scripts/rdp-frame-verify.ts`.
 */
import { parseFrameBatch, RDP_FRAME_VERSION } from "../src/modules/rdp/frame";
import { fitViewport, toRemotePoint, wheelRotation } from "../src/modules/rdp/lib/viewport";
import { CTRL_ALT_DEL_SCANCODES, scancodeFor } from "../src/modules/rdp/scancodes";

let failures = 0;
function check(label: string, actual: unknown, expected: unknown): void {
  const a = JSON.stringify(actual);
  const e = JSON.stringify(expected);
  if (a === e) {
    console.log(`  ok    ${label}`);
  } else {
    console.log(`  FAIL  ${label}\n          expected ${e}\n          actual   ${a}`);
    failures++;
  }
}
function checkTrue(label: string, cond: boolean): void {
  check(label, cond, true);
}

type Rect = { x: number; y: number; w: number; h: number };

/**
 * The encoder, written independently of the reader so the two cannot share a
 * mistake. Mirrors `encode_batch`: little-endian throughout, the rect table in
 * order, then the rects' pixels concatenated with no padding, alpha forced
 * opaque.
 */
function encode(opts: {
  magic?: string;
  version?: number;
  keyframe?: boolean;
  fbWidth: number;
  fbHeight: number;
  rects: Rect[];
  /** Override the declared rect count, to forge a mismatched header. */
  rectCount?: number;
  /** Override the declared payload length, ditto. */
  payloadLen?: number;
  /** Bytes actually written after the table. Defaults to sum(w*h*4). */
  payloadBytes?: number;
}): ArrayBuffer {
  const magic = opts.magic ?? "RDPF";
  const rects = opts.rects;
  const trueLen = rects.reduce((n, r) => n + r.w * r.h * 4, 0);
  const payloadBytes = opts.payloadBytes ?? trueLen;
  const buf = new ArrayBuffer(16 + rects.length * 8 + payloadBytes);
  const view = new DataView(buf);
  const bytes = new Uint8Array(buf);
  for (let i = 0; i < 4; i++) bytes[i] = magic.charCodeAt(i);
  view.setUint8(4, opts.version ?? RDP_FRAME_VERSION);
  view.setUint8(5, opts.keyframe ? 1 : 0);
  view.setUint16(6, opts.rectCount ?? rects.length, true);
  view.setUint16(8, opts.fbWidth, true);
  view.setUint16(10, opts.fbHeight, true);
  view.setUint32(12, opts.payloadLen ?? trueLen, true);
  rects.forEach((r, i) => {
    const at = 16 + i * 8;
    view.setUint16(at, r.x, true);
    view.setUint16(at + 2, r.y, true);
    view.setUint16(at + 4, r.w, true);
    view.setUint16(at + 6, r.h, true);
  });
  // Each pixel encodes its own position within the rect, so a mis-strided read
  // is visible in the assertion rather than merely plausible.
  let at = 16 + rects.length * 8;
  for (const r of rects) {
    for (let y = 0; y < r.h; y++) {
      for (let x = 0; x < r.w; x++) {
        if (at + 3 >= buf.byteLength) break;
        bytes[at++] = (r.x + x) % 256;
        bytes[at++] = (r.y + y) % 256;
        bytes[at++] = 0x33;
        bytes[at++] = 0xff;
      }
    }
  }
  return buf;
}

console.log("\n[wire] a well-formed batch parses exactly");
{
  // The same 8x4 framebuffer and the same two rects `frame.rs`'s
  // `header_layout_is_stable` asserts, so the two ends pin one layout.
  const rects: Rect[] = [
    { x: 1, y: 1, w: 2, h: 2 },
    { x: 5, y: 0, w: 3, h: 1 },
  ];
  const buf = encode({ fbWidth: 8, fbHeight: 4, rects });
  check("total length is header + table + payload", buf.byteLength, 16 + 2 * 8 + (2 * 2 + 3) * 4);

  const batch = parseFrameBatch(buf);
  checkTrue("it parses", batch !== null);
  if (!batch) throw new Error("unreachable: guarded above");
  check("delta, not keyframe", batch.keyframe, false);
  check("framebuffer size", [batch.fbWidth, batch.fbHeight], [8, 4]);
  check("rect table, in order", batch.rects, rects);
  // The offsets are ABSOLUTE into the buffer, which is what lets a caller build
  // an ImageData view from the batch alone.
  check("first rect's pixels start right after the table", batch.pixelOffsets[0], 16 + 2 * 8);
  check(
    "second rect's pixels follow the first with no padding",
    batch.pixelOffsets[1],
    16 + 2 * 8 + 2 * 2 * 4,
  );

  // Read the second rect back through the same view a blit would use.
  const second = new Uint8ClampedArray(batch.buffer, batch.pixelOffsets[1], 3 * 1 * 4);
  check(
    "its pixels are the right ones, tightly packed and opaque",
    [...second],
    [5, 0, 0x33, 0xff, 6, 0, 0x33, 0xff, 7, 0, 0x33, 0xff],
  );
}

console.log("\n[wire] a keyframe is one full-framebuffer rect");
{
  const batch = parseFrameBatch(
    encode({ keyframe: true, fbWidth: 6, fbHeight: 3, rects: [{ x: 0, y: 0, w: 6, h: 3 }] }),
  );
  checkTrue("it parses", batch !== null);
  check("kind 1 reads as a keyframe", batch?.keyframe, true);
  check("covering the whole framebuffer", batch?.rects, [{ x: 0, y: 0, w: 6, h: 3 }]);
}

console.log("\n[wire] anything malformed is dropped whole");
{
  const good = { fbWidth: 8, fbHeight: 4, rects: [{ x: 0, y: 0, w: 2, h: 2 }] };
  const dropped = (label: string, buf: ArrayBuffer) => check(label, parseFrameBatch(buf), null);

  dropped("a truncated header", new ArrayBuffer(8));
  dropped("an empty payload", new ArrayBuffer(0));
  dropped("unknown magic", encode({ ...good, magic: "XDPF" }));
  // The version field exists precisely so a layout change is refused rather
  // than mis-read against the old offsets.
  dropped("a future version", encode({ ...good, version: RDP_FRAME_VERSION + 1 }));
  dropped("a past version", encode({ ...good, version: 0 }));
  dropped("a rectCount of 0", encode({ ...good, rects: [], rectCount: 0 }));
  dropped("a zero-sized framebuffer", encode({ ...good, fbWidth: 0 }));
  dropped("a payloadLen longer than the data", encode({ ...good, payloadLen: 999 }));
  dropped("a payloadLen shorter than the data", encode({ ...good, payloadLen: 4 }));
  dropped(
    "a rectCount the table cannot back",
    encode({ ...good, rectCount: 4, payloadLen: 2 * 2 * 4 }),
  );
  dropped("a zero-extent rect", encode({ ...good, rects: [{ x: 0, y: 0, w: 0, h: 2 }] }));
  // These two are the ones that would be an out-of-bounds VIEW rather than a
  // wrong picture, which is why the reader checks them even though the format
  // only documents the three above.
  dropped(
    "a rect reaching past the framebuffer",
    encode({ ...good, rects: [{ x: 7, y: 0, w: 4, h: 1 }] }),
  );
  dropped(
    "a rect table that sums to more than the payload",
    encode({
      fbWidth: 8,
      fbHeight: 4,
      rects: [
        { x: 0, y: 0, w: 2, h: 2 },
        { x: 4, y: 0, w: 2, h: 2 },
      ],
      // Declared and written as one rect's worth, table says two.
      payloadLen: 2 * 2 * 4,
      payloadBytes: 2 * 2 * 4,
    }),
  );
  // An unknown kind byte would be a layout change that failed to bump the
  // version, so it is corruption rather than a third batch type.
  {
    const buf = encode(good);
    new DataView(buf).setUint8(5, 2);
    dropped("an unknown batch kind", buf);
  }

  // Sanity: the fixture the mutations are derived from must itself be valid, or
  // every check above passes for the wrong reason.
  checkTrue("(the unmutated fixture parses)", parseFrameBatch(encode(good)) !== null);
}

console.log("\n[wire] the reader NEVER throws, on any input");
{
  // Not a nicety. `parseFrameBatch` runs on Tauri's channel callback, and a raw
  // payload of 1024 bytes or more is parked in a process-global map that is only
  // freed when the JS side collects it - so an exception escaping the handler can
  // strand later payloads there with nothing left to collect them, leaking whole
  // framebuffers for the life of the process. Returning null is the contract;
  // throwing is a resource leak, not a dropped frame.
  const valid = encode({
    fbWidth: 8,
    fbHeight: 4,
    rects: [
      { x: 1, y: 1, w: 2, h: 2 },
      { x: 5, y: 0, w: 3, h: 1 },
    ],
  });
  const thrown: string[] = [];
  const noThrow = (label: string, buf: ArrayBuffer) => {
    try {
      parseFrameBatch(buf);
    } catch (e) {
      thrown.push(`${label}: ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  // Every truncation of a valid batch, including the empty one. These walk the
  // reader straight off the end of every field it reads.
  for (let n = 0; n <= valid.byteLength; n++) {
    noThrow(`truncated to ${n}`, valid.slice(0, n));
  }
  // Every single-byte corruption of the header and rect table, which is where
  // the lengths and counts the reader trusts come from.
  for (let at = 0; at < 16 + 2 * 8; at++) {
    for (const value of [0x00, 0x01, 0x7f, 0xff]) {
      const buf = valid.slice(0);
      new DataView(buf).setUint8(at, value);
      noThrow(`byte ${at} set to ${value}`, buf);
    }
  }
  // A header claiming the largest counts the fields can hold, with no data
  // behind them.
  {
    const buf = new ArrayBuffer(16);
    const view = new DataView(buf);
    for (const [i, b] of [0x52, 0x44, 0x50, 0x46].entries()) view.setUint8(i, b);
    view.setUint8(4, RDP_FRAME_VERSION);
    view.setUint16(6, 0xffff, true);
    view.setUint16(8, 0xffff, true);
    view.setUint16(10, 0xffff, true);
    view.setUint32(12, 0xffffffff, true);
    noThrow("a header claiming u16/u32 maxima with no payload", buf);
  }
  check("nothing threw", thrown, []);
}

console.log("\n[letterbox] the mapping is the exact inverse of the draw");
{
  // 16:9 desktop in a 4:3 pane: fits on width, bars top and bottom.
  const vp = fitViewport(800, 600, 1600, 900);
  check("scales to fit the narrower axis", vp.scale, 0.5);
  check("fills the pane's width", vp.width, 800);
  // 450 tall inside 600 leaves 75 of bar above and below.
  check("and is letterboxed vertically", [vp.left, vp.top, vp.height], [0, 75, 450]);

  check("the top-left of the desktop", toRemotePoint(vp, 1600, 900, 0, 75), { x: 0, y: 0 });
  check("the centre", toRemotePoint(vp, 1600, 900, 400, 300), { x: 800, y: 450 });
  // Clamped to the LAST addressable pixel: RDP mouse coordinates are u16 pixel
  // indices and the server does not bounds-check them.
  check("the bottom-right stays inside the desktop", toRemotePoint(vp, 1600, 900, 799.9, 524.9), {
    x: 1599,
    y: 899,
  });
  // Null, not clamped: clamping would report a click ON the desktop for one
  // demonstrably beside it.
  check(
    "a point in the top bar is not on the desktop",
    toRemotePoint(vp, 1600, 900, 400, 74),
    null,
  );
  check(
    "a point in the bottom bar is not on the desktop",
    toRemotePoint(vp, 1600, 900, 400, 526),
    null,
  );

  // The far EDGE is on the desktop, and it has to be: at scale 0.5 an integer
  // pointer can only reach the even columns, so without the closed interval the
  // last column and row - the bottom-right hot corner - are unreachable.
  check("the bottom edge maps to the last row", toRemotePoint(vp, 1600, 900, 400, 525), {
    x: 800,
    y: 899,
  });
  check("the right edge maps to the last column", toRemotePoint(vp, 1600, 900, 800, 300), {
    x: 1599,
    y: 450,
  });
  check("and the far corner to both", toRemotePoint(vp, 1600, 900, 800, 525), { x: 1599, y: 899 });
  // What an integer pointer reaches one pixel short of the edge, which is the
  // second-to-last column - the gap the closed interval exists to close.
  check("one pixel inside is NOT the last column", toRemotePoint(vp, 1600, 900, 799, 300), {
    x: 1598,
    y: 450,
  });
  // The allowance is the boundary point itself and nothing beyond it, so this
  // is a closed interval rather than a general clamp.
  check(
    "one pixel past the edge is the letterbox again",
    toRemotePoint(vp, 1600, 900, 801, 300),
    null,
  );
  // No allowance at the near edge: 0 already addresses pixel 0, so a point
  // before it is still outside.
  check("one pixel before the left edge", toRemotePoint(vp, 1600, 900, -1, 300), null);

  // A pane taller than the desktop's aspect: bars left and right instead.
  const tall = fitViewport(600, 800, 1600, 900);
  check("a tall pane fits on height and bars the sides", [tall.left, tall.top], [0, 231.25]);
  checkTrue("with the same scale on both axes", tall.width / 1600 === tall.height / 900);

  // Upscaling is deliberate: a 1280x720 preset in a maximised pane would
  // otherwise sit as a postage stamp in the middle of it.
  checkTrue(
    "a desktop smaller than the pane scales UP",
    fitViewport(2560, 1440, 1280, 720).scale > 1,
  );

  // A pane mid-layout (or on a hidden tab) has no size, and the caller must be
  // able to skip drawing without a special case of its own.
  check("a zero-sized pane yields a zero viewport", fitViewport(0, 0, 1280, 720).scale, 0);
  check("which maps nothing", toRemotePoint(fitViewport(0, 0, 1280, 720), 1280, 720, 0, 0), null);
}

console.log("\n[wheel] one notch per event, with RDP's sign");
{
  // The DOM's positive Y is scroll DOWN; RDP's positive rotation is scroll UP.
  check("scrolling down is negative rotation", wheelRotation(53), -120);
  check("scrolling up is positive rotation", wheelRotation(-53), 120);
  // Magnitude is dropped on purpose: deltaMode makes it incomparable across a
  // trackpad, a wheel and a page-scrolling driver, and RDP counts detents.
  check("a huge delta is still one notch", wheelRotation(4000), -120);
  check("a tiny one too", wheelRotation(-0.5), 120);
  check("and a zero delta sends nothing", wheelRotation(0), 0);
}

console.log("\n[scancodes] the extended flag is what separates nav from numpad");
{
  check("Enter is the plain make code", scancodeFor("Enter"), 0x001c);
  check("NumpadEnter is its extended twin", scancodeFor("NumpadEnter"), 0xe01c);
  // The pairs that share a low byte. Without 0xE0 the left arrow IS numpad-4.
  const pairs: [string, string][] = [
    ["ArrowLeft", "Numpad4"],
    ["ArrowRight", "Numpad6"],
    ["ArrowUp", "Numpad8"],
    ["ArrowDown", "Numpad2"],
    ["Home", "Numpad7"],
    ["End", "Numpad1"],
    ["PageUp", "Numpad9"],
    ["PageDown", "Numpad3"],
    ["Insert", "Numpad0"],
    ["Delete", "NumpadDecimal"],
  ];
  for (const [nav, pad] of pairs) {
    const n = scancodeFor(nav);
    const p = scancodeFor(pad);
    checkTrue(
      `${nav} is ${pad} plus the 0xE0 flag`,
      n !== undefined && p !== undefined && n === 0xe000 + p,
    );
  }
  check("ControlRight is extended", scancodeFor("ControlRight"), 0xe01d);
  check("ControlLeft is not", scancodeFor("ControlLeft"), 0x001d);
  check("AltRight is extended", scancodeFor("AltRight"), 0xe038);
  check("AltLeft is not", scancodeFor("AltLeft"), 0x0038);

  // Pause's make code is the three-byte 0xE1 0x1D 0x45 sequence, which does not
  // fit the u16 the backend takes. Absent on purpose, so the Unicode fallback
  // handles it rather than a wrong key being typed.
  check("Pause has no expressible scancode", scancodeFor("Pause"), undefined);
  check("an unknown code has none either", scancodeFor("NoSuchKey"), undefined);

  // Two physical keys mapping to one scancode means one of them types the
  // other, which is invisible until someone presses it.
  const codes = [
    "Escape",
    "Digit1",
    "Digit0",
    "Minus",
    "Equal",
    "Backspace",
    "Tab",
    "KeyQ",
    "KeyP",
    "BracketLeft",
    "BracketRight",
    "Enter",
    "ControlLeft",
    "KeyA",
    "KeyL",
    "Semicolon",
    "Quote",
    "Backquote",
    "ShiftLeft",
    "Backslash",
    "KeyZ",
    "KeyM",
    "Comma",
    "Period",
    "Slash",
    "ShiftRight",
    "NumpadMultiply",
    "AltLeft",
    "Space",
    "CapsLock",
    "F1",
    "F10",
    "F11",
    "F12",
    "NumLock",
    "ScrollLock",
    "Numpad0",
    "Numpad9",
    "NumpadSubtract",
    "NumpadAdd",
    "NumpadDecimal",
    "NumpadDivide",
    "NumpadEnter",
    "IntlBackslash",
    "IntlRo",
    "IntlYen",
    "ControlRight",
    "AltRight",
    "MetaLeft",
    "MetaRight",
    "ContextMenu",
    "Insert",
    "Delete",
    "Home",
    "End",
    "PageUp",
    "PageDown",
    "ArrowUp",
    "ArrowDown",
    "ArrowLeft",
    "ArrowRight",
    "PrintScreen",
  ];
  const seen = new Map<number, string>();
  const collisions: string[] = [];
  for (const code of codes) {
    const sc = scancodeFor(code);
    if (sc === undefined) {
      collisions.push(`${code} has no scancode`);
      continue;
    }
    const prev = seen.get(sc);
    if (prev) collisions.push(`${code} collides with ${prev} at 0x${sc.toString(16)}`);
    else seen.set(sc, code);
  }
  check("no two physical keys share a scancode", collisions, []);
}

console.log("\n[scancodes] Ctrl+Alt+Del releases exactly what it pressed");
{
  const { down, up } = CTRL_ALT_DEL_SCANCODES;
  check("three keys down", down, [0x001d, 0x0038, 0xe053]);
  // Reversed, and it matters: the server tracks modifier state, so releasing in
  // the wrong order - or not at all - strands Ctrl or Alt held down for every
  // later keystroke in the session.
  check("released in reverse", up, [...down].reverse());
  check("and nothing is left held", [...down].sort(), [...up].sort());
}

if (failures > 0) throw new Error(`rdp-frame-verify: ${failures} FAILED`);
console.log("\nrdp-frame-verify: OK\n");
