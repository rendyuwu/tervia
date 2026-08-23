//! Dirty-rectangle coalescing and the host -> webview frame wire format.
//!
//! # Wire format (version 1)
//!
//! One RDP frame batch is a single `InvokeResponseBody::Raw` payload, which
//! Tauri hands to the webview as an `ArrayBuffer`. Every multi-byte field is
//! **little-endian** (every platform Tervia ships on is little-endian, and so is
//! every `DataView`/`TypedArray` read the frontend will do with
//! `littleEndian = true`).
//!
//! ```text
//! offset size field         notes
//! ------ ---- ------------- -----------------------------------------------
//!      0    4 magic         ASCII "RDPF" (0x52 0x44 0x50 0x46), in order
//!      4    1 version       1. Bump on any layout change.
//!      5    1 kind          0 = delta, 1 = keyframe
//!      6    2 rectCount     u16, number of entries in the rect table
//!      8    2 fbWidth       u16, framebuffer width this batch belongs to
//!     10    2 fbHeight      u16, framebuffer height this batch belongs to
//!     12    4 payloadLen    u32, total bytes of pixel data after the table
//!     16  8*n rect table    n = rectCount, 8 bytes each (see below)
//!  16+8*n  pl pixel payload pl = payloadLen
//! ```
//!
//! Rect table entry, 8 bytes:
//!
//! ```text
//! offset size field notes
//! ------ ---- ----- ------------------------------------------------------
//!      0    2 x     u16, left edge in framebuffer pixels
//!      2    2 y     u16, top edge in framebuffer pixels
//!      4    2 w     u16, width in pixels (EXCLUSIVE, i.e. a real count)
//!      6    2 h     u16, height in pixels (EXCLUSIVE)
//! ```
//!
//! The pixel payload is the rects' contents concatenated **in table order**.
//! Each rect contributes `h` rows of `w * 4` bytes, tightly packed with no row
//! padding and no gap between rects, so `payloadLen == sum(w * h * 4)`.
//! Channel order within a pixel is **R, G, B, A** at byte offsets 0, 1, 2, 3 -
//! the layout `ImageData` / `Uint8ClampedArray` want, so a rect can be blitted
//! with `putImageData` or uploaded as a `RGBA8` texture with no per-pixel
//! rework. Alpha is always `0xFF` (see `encode_batch`).
//!
//! `kind`:
//!
//! * `1` (keyframe) - exactly one rect, always `x = 0, y = 0, w = fbWidth,
//!   h = fbHeight`. Replaces the whole framebuffer. Sent on attach/snapshot,
//!   and whenever a delta batch grew past the collapse threshold below.
//! * `0` (delta) - one or more sub-rects to blit over the existing image.
//!
//! A reader should treat an unknown `magic`, an unknown `version`, a
//! `rectCount` of 0, or a length that disagrees with
//! `16 + 8 * rectCount + payloadLen` as a corrupt batch and drop it.

use ironrdp_pdu::geometry::{InclusiveRectangle, Rectangle as _};

/// `b"RDPF"`, written in byte order so it reads as ASCII in a hex dump.
pub const FRAME_MAGIC: [u8; 4] = *b"RDPF";
/// Wire-format version. Bump on any layout change; the frontend refuses
/// anything it does not recognise rather than mis-parsing it.
pub const FRAME_VERSION: u8 = 1;
/// Fixed header size, before the rect table.
pub const HEADER_LEN: usize = 16;
/// Size of one rect-table entry.
pub const RECT_LEN: usize = 8;
/// Bytes per pixel, for both the framebuffer and the wire payload.
const BYTES_PER_PIXEL: usize = 4;

/// Upper bound on rects in one batch. Past this the batcher unions everything
/// into its bounding box: 64 rects already cost 512 header bytes and 64
/// separate `putImageData` calls on the frontend, and a dirty region scattered
/// that widely is nearly always cheaper to ship as one block. Comfortably
/// inside `u16`, so `rectCount` can never overflow its field.
pub const MAX_RECTS: usize = 64;

/// Whether a batch replaces the framebuffer or patches it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchKind {
    Delta = 0,
    Keyframe = 1,
}

impl BatchKind {
    fn as_u8(self) -> u8 {
        match self {
            Self::Delta => 0,
            Self::Keyframe => 1,
        }
    }
}

/// An **exclusive** rectangle: `w`/`h` are real pixel counts.
///
/// The RDP side speaks [`InclusiveRectangle`], where `right`/`bottom` are the
/// last pixel *inside* the rectangle, so the conversion is
/// `w = right - left + 1`. Getting that wrong shows up as a one-pixel seam
/// down the right and bottom edge of every update, which is exactly the class
/// of bug IronRDP issue #1251 covers - hence [`Rect::from_inclusive`] being the
/// only way to build one from the wire type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rect {
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
}

/// True for the all-zero rectangle IronRDP uses to mean "nothing happened".
///
/// When a bitmap update falls outside the framebuffer, `DecodedImage` logs it
/// and returns `InclusiveRectangle::empty()` - all zeros - instead of reporting
/// nothing (`ironrdp-session` image.rs:556-561). Because the bounds are
/// *inclusive*, `{0,0,0,0}` reports `width() == 1` and `height() == 1`, so
/// [`Rect::from_inclusive`] would turn it into a spurious 1x1 update at the
/// origin rather than a zero-area one. Filtering it here is what prevents that.
///
/// **What this does not fix.** `fast_path::Processor` unions the sentinel into
/// the region accumulated from the same PDU (fast_path.rs:297-300), and
/// `Rectangle::union` takes the `min` of left/top (`ironrdp-pdu`
/// geometry.rs:73-85), so when the sentinel arrives alongside a real rect the
/// region's origin has already been dragged to (0,0) *before* we see it - and
/// the result is not all-zero, so this returns `false` for it. The filter
/// therefore catches only the case where the sentinel is the sole contributor.
/// The inflated-region case is harmless: the framebuffer is authoritative, so an
/// over-large rect over-ships pixels that happen to be correct, and the only
/// cost is bandwidth.
///
/// It fires when the server sends updates sized for the old desktop after a
/// resize but before the framebuffer has been rebuilt, which is why
/// `apply_reactivation` rebuilds `DecodedImage` in the same breath as handling
/// `DeactivateAll`.
///
/// Unavoidably a heuristic: there is no way to tell the sentinel from a genuine
/// one-pixel update at the top-left corner. Losing the occasional real corner
/// pixel is the right trade, since the next update covering it repaints it.
pub fn is_empty_sentinel(rect: &InclusiveRectangle) -> bool {
    rect.left == 0 && rect.top == 0 && rect.right == 0 && rect.bottom == 0
}

impl Rect {
    /// Convert from IronRDP's inclusive rectangle.
    ///
    /// `InclusiveRectangle::width()`/`height()` already add the 1, and both
    /// document `0 < output`, so a well-formed rectangle always has a non-zero
    /// extent here. A malformed one (`right < left`) would panic inside
    /// IronRDP's own subtraction long before reaching us.
    ///
    /// Callers must reject [`is_empty_sentinel`] rects first; this conversion
    /// would turn one into a bogus 1x1 update at the origin.
    pub fn from_inclusive(rect: &InclusiveRectangle) -> Self {
        Self {
            x: rect.left,
            y: rect.top,
            w: rect.width(),
            h: rect.height(),
        }
    }

    /// A rect covering a whole `width` x `height` framebuffer.
    pub fn full(width: u16, height: u16) -> Self {
        Self {
            x: 0,
            y: 0,
            w: width,
            h: height,
        }
    }

    /// Pixel count. `u32` because 8192x8192 (RDP's own ceiling) overflows u16
    /// by a wide margin.
    pub fn area(self) -> u32 {
        u32::from(self.w) * u32::from(self.h)
    }

    /// Bytes this rect contributes to the pixel payload.
    pub fn byte_len(self) -> usize {
        usize::from(self.w) * usize::from(self.h) * BYTES_PER_PIXEL
    }

    /// Smallest rect containing both. Used to fold a batch down when it grew
    /// past [`MAX_RECTS`].
    pub fn union(self, other: Self) -> Self {
        let x = self.x.min(other.x);
        let y = self.y.min(other.y);
        // Saturating because this is a public method: `x + w` on an
        // out-of-bounds rect can overflow u16, and clamping the edge is a
        // better failure than a panic. Every rect the batcher unions has
        // already been clipped, so the clamp is unreachable there.
        let right = self
            .x
            .saturating_add(self.w)
            .max(other.x.saturating_add(other.w));
        let bottom = self
            .y
            .saturating_add(self.h)
            .max(other.y.saturating_add(other.h));
        Self {
            x,
            y,
            w: right - x,
            h: bottom - y,
        }
    }

    /// Clip to a `width` x `height` framebuffer, or `None` if nothing is left.
    ///
    /// Nothing downstream indexes the framebuffer without going through this:
    /// a rect that reaches past the buffer would otherwise be an out-of-bounds
    /// slice, i.e. a panic on a thread with no supervisor.
    pub fn clip(self, width: u16, height: u16) -> Option<Self> {
        if self.x >= width || self.y >= height || self.w == 0 || self.h == 0 {
            return None;
        }
        Some(Self {
            x: self.x,
            y: self.y,
            w: self.w.min(width - self.x),
            h: self.h.min(height - self.y),
        })
    }

    /// True when `other` is entirely inside `self`.
    fn contains(self, other: Self) -> bool {
        other.x >= self.x
            && other.y >= self.y
            && u32::from(other.x) + u32::from(other.w) <= u32::from(self.x) + u32::from(self.w)
            && u32::from(other.y) + u32::from(other.h) <= u32::from(self.y) + u32::from(self.h)
    }
}

/// One coalesced group of dirty rects, ready for [`encode_batch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Batch {
    pub kind: BatchKind,
    pub rects: Vec<Rect>,
}

impl Batch {
    /// A full-framebuffer keyframe. What a fresh `rdp_attach` / `rdp_snapshot`
    /// gets, since there is no byte stream to replay the way SSH has.
    pub fn keyframe(width: u16, height: u16) -> Self {
        Self {
            kind: BatchKind::Keyframe,
            rects: vec![Rect::full(width, height)],
        }
    }
}

/// Accumulates `GraphicsUpdate` regions over one flush window.
///
/// # Backpressure
///
/// This is the MVP's *only* backpressure guard, and it is a cap on batch size
/// rather than real flow control: once the accumulated dirty area passes half
/// the framebuffer, the batch collapses to a single full-framebuffer keyframe.
/// So one batch can never cost more than one framebuffer, no matter how many
/// updates landed in the window. The push transport has no way to learn that
/// the webview is behind, so a consumer that cannot keep up still falls
/// further behind - one framebuffer at a time instead of unboundedly. Swapping
/// push for a pull / credit-based model is tracked as **RDP-01** and is a local
/// change: a second [`FrameTransport`] impl plus a different flush trigger in
/// `session.rs`.
#[derive(Debug)]
pub struct FrameBatcher {
    rects: Vec<Rect>,
    /// Accumulated dirty area, counting overlaps more than once. That is
    /// deliberately an upper bound on the payload bytes the batch would cost,
    /// which is the quantity the collapse rule is about - not on how much of
    /// the screen is actually covered.
    area: u32,
    width: u16,
    height: u16,
}

impl FrameBatcher {
    pub fn new(width: u16, height: u16) -> Self {
        Self {
            rects: Vec::new(),
            area: 0,
            width,
            height,
        }
    }

    /// Adopt a new framebuffer size after a Deactivation-Reactivation, and
    /// drop whatever had accumulated: those rects describe the old
    /// framebuffer, which no longer exists.
    pub fn resize(&mut self, width: u16, height: u16) {
        self.width = width;
        self.height = height;
        self.clear();
    }

    fn clear(&mut self) {
        self.rects.clear();
        self.area = 0;
    }

    pub fn is_empty(&self) -> bool {
        self.rects.is_empty()
    }

    /// Area at which a delta batch is no longer worth shipping as rects.
    fn collapse_threshold(&self) -> u32 {
        // Half the framebuffer. `/ 2` on the u32 product, so a 1x1 desktop
        // yields 0 and any update at all collapses - which is correct.
        (u32::from(self.width) * u32::from(self.height)) / 2
    }

    /// True once the batch is already a full-framebuffer collapse, so further
    /// pushes are free.
    fn collapsed(&self) -> bool {
        self.rects.len() == 1 && self.rects[0] == Rect::full(self.width, self.height)
    }

    /// Fold everything into one full-framebuffer rect.
    fn collapse(&mut self) {
        let full = Rect::full(self.width, self.height);
        self.rects.clear();
        self.rects.push(full);
        self.area = full.area();
    }

    /// Add one dirty region. Silently drops rects that fall outside the
    /// framebuffer and rects already covered by one we are holding.
    pub fn push(&mut self, rect: Rect) {
        if self.collapsed() {
            return;
        }
        let Some(rect) = rect.clip(self.width, self.height) else {
            return;
        };
        if self.rects.iter().any(|held| held.contains(rect)) {
            return;
        }
        // Drop the ones this rect now subsumes, so a repeatedly-growing region
        // does not leave a trail of dead sub-rects behind it.
        self.rects.retain(|held| !rect.contains(*held));
        self.area = self.rects.iter().map(|r| r.area()).sum();

        self.rects.push(rect);
        self.area = self.area.saturating_add(rect.area());

        if self.area > self.collapse_threshold() {
            self.collapse();
            return;
        }
        if self.rects.len() > MAX_RECTS {
            let folded = self
                .rects
                .iter()
                .copied()
                .reduce(Rect::union)
                .and_then(|r| r.clip(self.width, self.height));
            match folded {
                Some(folded) => {
                    self.rects.clear();
                    self.rects.push(folded);
                    self.area = folded.area();
                    if self.area > self.collapse_threshold() {
                        self.collapse();
                    }
                }
                // Unreachable: every held rect was clipped on the way in, so
                // their union is in bounds too. Collapse rather than carry an
                // over-long list.
                None => self.collapse(),
            }
        }
    }

    /// Take the accumulated batch, leaving the batcher empty. `None` when
    /// nothing was dirty in this window.
    pub fn take(&mut self) -> Option<Batch> {
        if self.rects.is_empty() {
            return None;
        }
        let kind = if self.collapsed() {
            BatchKind::Keyframe
        } else {
            BatchKind::Delta
        };
        let rects = core::mem::take(&mut self.rects);
        self.area = 0;
        Some(Batch { kind, rects })
    }
}

/// Borrowed view of a framebuffer: tightly packed rows of RGBA pixels.
///
/// Decoupled from `DecodedImage` so [`encode_batch`] stays a pure function
/// over bytes and can be unit-tested without a live RDP session.
#[derive(Debug, Clone, Copy)]
pub struct FrameBuffer<'a> {
    pub data: &'a [u8],
    pub width: u16,
    pub height: u16,
}

/// Serialise one batch into the wire format documented at the top of this file.
///
/// Rects are clipped to `fb` and empty ones are dropped first, so the rect
/// table always agrees with the payload that follows it and no slice index can
/// run off the end of `fb.data`.
///
/// Alpha is forced to `0xFF` on the way out, because IronRDP's framebuffer does
/// not guarantee it.
///
/// **The reason is unpainted pixels, not decoded ones.** `DecodedImage::new`
/// zero-fills (`ironrdp-session` image.rs:146-151), so every pixel the server
/// has not painted yet has alpha 0 and would be fully transparent in a canvas.
/// That is exactly what `rdp_snapshot` and a fresh `rdp_attach` return in the
/// window between reaching the active stage and the first full repaint, and
/// again after every reactivation, which rebuilds the framebuffer blank.
///
/// An earlier version of this comment blamed `apply_rgb32_bitmap`'s memcpy
/// branch copying the wire's padding byte. That is **not** reachable in this
/// configuration: the framebuffer is `RgbA32` and that function is always
/// called with `BgrX32` (`fast_path.rs:273,290`), so `format ==
/// self.pixel_format` is never true, and the conversion branch it takes instead
/// already writes opaque alpha because `BgrX32::has_alpha()` is false. The
/// citation was wrong; the fixup is still load-bearing for the reason above.
///
/// Possibly also relevant, unverified as to pixel format: the RemoteFX
/// `apply_tile` -> `copy_to` path has an `else` branch that memcpys a full row
/// including the alpha byte (`image.rs:138-141`).
///
/// An RDP desktop is opaque by definition, so there is nothing to lose, and
/// doing it here means the frontend can hand a rect to `ImageData` as-is.
///
/// Cost: fused into the row copy rather than run as a second pass over the
/// finished payload. Same number of writes, but they land on bytes still hot in
/// cache from `extend_from_slice`, instead of re-traversing up to a whole
/// framebuffer (8.3M pixels for a collapsed 4K keyframe) after the fact.
pub fn encode_batch(fb: FrameBuffer<'_>, batch: &Batch) -> Vec<u8> {
    let rects: Vec<Rect> = batch
        .rects
        .iter()
        .take(MAX_RECTS)
        .filter_map(|r| r.clip(fb.width, fb.height))
        .collect();

    let payload_len: usize = rects.iter().map(|r| r.byte_len()).sum();
    let mut out = Vec::with_capacity(HEADER_LEN + rects.len() * RECT_LEN + payload_len);

    out.extend_from_slice(&FRAME_MAGIC);
    out.push(FRAME_VERSION);
    out.push(batch.kind.as_u8());
    // Bounded by MAX_RECTS above, so neither conversion can saturate.
    out.extend_from_slice(&u16::try_from(rects.len()).unwrap_or(u16::MAX).to_le_bytes());
    out.extend_from_slice(&fb.width.to_le_bytes());
    out.extend_from_slice(&fb.height.to_le_bytes());
    out.extend_from_slice(&u32::try_from(payload_len).unwrap_or(u32::MAX).to_le_bytes());

    for r in &rects {
        out.extend_from_slice(&r.x.to_le_bytes());
        out.extend_from_slice(&r.y.to_le_bytes());
        out.extend_from_slice(&r.w.to_le_bytes());
        out.extend_from_slice(&r.h.to_le_bytes());
    }

    let stride = usize::from(fb.width) * BYTES_PER_PIXEL;
    for r in &rects {
        let row_bytes = usize::from(r.w) * BYTES_PER_PIXEL;
        for row in 0..usize::from(r.h) {
            let start = (usize::from(r.y) + row) * stride + usize::from(r.x) * BYTES_PER_PIXEL;
            let end = start + row_bytes;
            let row_start = out.len();
            match fb.data.get(start..end) {
                Some(src) => out.extend_from_slice(src),
                // Only reachable if `fb.data` is shorter than width * height *
                // 4, i.e. the caller lied about the dimensions. Pad so the
                // payload still matches the length in the header.
                None => out.resize(row_start + row_bytes, 0),
            }
            // Opaque alpha, on the row just appended while it is still in cache.
            for alpha in out[row_start..]
                .iter_mut()
                .skip(BYTES_PER_PIXEL - 1)
                .step_by(BYTES_PER_PIXEL)
            {
                *alpha = 0xFF;
            }
        }
    }

    out
}

/// The one place encoded frames leave the session task.
///
/// Today there is a single push implementation: the session task encodes a
/// batch and hands the bytes to the IPC channel immediately. A pull / credit
/// model (**RDP-01**) slots in as a second impl plus a different flush trigger
/// in `session.rs`; nothing else in the module knows how frames get out.
pub trait FrameTransport: Send {
    /// Deliver one encoded batch. `Err` means this sink is gone for good and
    /// the caller should stop using it.
    fn deliver(&mut self, bytes: Vec<u8>) -> Result<(), TransportGone>;
}

/// The sink has closed - the webview navigated away or the channel was dropped.
#[derive(Debug, Clone, Copy)]
pub struct TransportGone;

#[cfg(test)]
mod tests {
    use super::*;

    /// A framebuffer whose every pixel encodes its own coordinates, so a
    /// mis-strided copy is visible in the assertion rather than silently
    /// plausible. Alpha is left at 0 to exercise the opaque-alpha fixup.
    fn checker(width: u16, height: u16) -> Vec<u8> {
        let mut data = Vec::with_capacity(usize::from(width) * usize::from(height) * 4);
        for y in 0..height {
            for x in 0..width {
                data.extend_from_slice(&[
                    u8::try_from(x % 256).unwrap(),
                    u8::try_from(y % 256).unwrap(),
                    0x33,
                    0x00,
                ]);
            }
        }
        data
    }

    /// `InclusiveRectangle` has an inclusive right/bottom edge, so the width is
    /// `right - left + 1`. An off-by-one here is a one-pixel seam on every
    /// update.
    #[test]
    fn inclusive_to_exclusive_conversion() {
        let single = InclusiveRectangle {
            left: 7,
            top: 9,
            right: 7,
            bottom: 9,
        };
        assert_eq!(
            Rect::from_inclusive(&single),
            Rect {
                x: 7,
                y: 9,
                w: 1,
                h: 1
            },
            "a rect whose edges coincide is 1x1, not 0x0"
        );

        let block = InclusiveRectangle {
            left: 0,
            top: 0,
            right: 1279,
            bottom: 799,
        };
        assert_eq!(
            Rect::from_inclusive(&block),
            Rect {
                x: 0,
                y: 0,
                w: 1280,
                h: 800
            },
            "a full 1280x800 desktop arrives as right=1279 bottom=799"
        );
        assert_eq!(block.width(), 1280);
        assert_eq!(block.height(), 800);
    }

    /// The all-zero sentinel must be recognised, and the reason it matters is
    /// that the inclusive-bounds conversion makes it look like a real 1x1
    /// update at the origin rather than an empty one.
    #[test]
    fn empty_sentinel_is_detected_not_converted() {
        let sentinel = InclusiveRectangle {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        };
        assert!(is_empty_sentinel(&sentinel));
        assert_eq!(
            Rect::from_inclusive(&sentinel),
            Rect {
                x: 0,
                y: 0,
                w: 1,
                h: 1
            },
            "this is exactly why it must be filtered before conversion, not after"
        );

        // A genuine 1x1 update anywhere else is not the sentinel.
        assert!(!is_empty_sentinel(&InclusiveRectangle {
            left: 1,
            top: 0,
            right: 1,
            bottom: 0,
        }));
        assert!(!is_empty_sentinel(&InclusiveRectangle {
            left: 0,
            top: 0,
            right: 0,
            bottom: 1,
        }));
        // And a real full-screen update is obviously not.
        assert!(!is_empty_sentinel(&InclusiveRectangle {
            left: 0,
            top: 0,
            right: 1279,
            bottom: 799,
        }));
    }

    /// The case the filter does **not** catch, pinned so nobody assumes it
    /// does: unioned with a real rect inside the same PDU, the sentinel drags
    /// the origin to (0,0) and inflates the region before it ever reaches us,
    /// and the result is not all-zero so `is_empty_sentinel` returns false.
    /// Harmless - the framebuffer is authoritative, so this only over-ships
    /// correct pixels - but it is bandwidth, not a no-op. Also asserts
    /// IronRDP's own `union` behaviour, so a version bump that changes it fails
    /// loudly here.
    #[test]
    fn sentinel_unioned_with_a_real_rect_is_not_caught() {
        let real = InclusiveRectangle {
            left: 600,
            top: 400,
            right: 619,
            bottom: 409,
        };
        let sentinel = InclusiveRectangle {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        };
        let polluted = real.union(&sentinel);
        assert_eq!(Rect::from_inclusive(&real).area(), 20 * 10);
        assert_eq!(
            Rect::from_inclusive(&polluted).area(),
            620 * 410,
            "a 200 px update becomes a 254k px one once the sentinel is unioned in"
        );
        assert!(
            !is_empty_sentinel(&polluted),
            "the filter cannot see this case - the damage is done upstream of us"
        );
    }

    #[test]
    fn clip_drops_and_trims() {
        let r = Rect {
            x: 10,
            y: 10,
            w: 100,
            h: 100,
        };
        assert_eq!(r.clip(1280, 800), Some(r), "in-bounds rect is untouched");
        assert_eq!(
            r.clip(50, 40),
            Some(Rect {
                x: 10,
                y: 10,
                w: 40,
                h: 30
            }),
            "an overhanging rect is trimmed to the framebuffer"
        );
        assert_eq!(
            r.clip(10, 800),
            None,
            "a rect starting at the edge is empty"
        );
        assert_eq!(
            Rect {
                x: 0,
                y: 0,
                w: 0,
                h: 5
            }
            .clip(100, 100),
            None,
            "a zero-extent rect is dropped"
        );
    }

    #[test]
    fn coalesces_disjoint_rects_into_one_delta() {
        let mut b = FrameBatcher::new(1280, 800);
        assert!(b.is_empty());
        assert!(b.take().is_none(), "an empty window yields no batch");

        b.push(Rect {
            x: 0,
            y: 0,
            w: 10,
            h: 10,
        });
        b.push(Rect {
            x: 500,
            y: 500,
            w: 20,
            h: 20,
        });
        assert!(!b.is_empty());

        let batch = b.take().expect("two pushes make a batch");
        assert_eq!(batch.kind, BatchKind::Delta);
        assert_eq!(batch.rects.len(), 2, "disjoint rects stay separate");
        assert!(b.is_empty(), "take() drains the batcher");
    }

    #[test]
    fn drops_rects_already_covered() {
        let mut b = FrameBatcher::new(1280, 800);
        let outer = Rect {
            x: 0,
            y: 0,
            w: 100,
            h: 100,
        };
        b.push(outer);
        b.push(Rect {
            x: 10,
            y: 10,
            w: 5,
            h: 5,
        });
        let batch = b.take().expect("batch");
        assert_eq!(batch.rects, vec![outer], "a contained rect adds nothing");

        // The reverse order must also settle on the single covering rect.
        let mut b = FrameBatcher::new(1280, 800);
        b.push(Rect {
            x: 10,
            y: 10,
            w: 5,
            h: 5,
        });
        b.push(outer);
        let batch = b.take().expect("batch");
        assert_eq!(
            batch.rects,
            vec![outer],
            "a covering rect subsumes the old one"
        );
    }

    /// The half-framebuffer rule: past that much accumulated dirty area, many
    /// rects cost more than one whole frame, so the batch becomes a keyframe.
    #[test]
    fn collapses_past_half_the_framebuffer() {
        // 1000x800 framebuffer => the threshold is 400_000 px. Each column
        // below is 100x800 = 80_000 px, and ten of them tile the screen
        // exactly, so the batch crosses the threshold on the sixth.
        let (w, h) = (1000u16, 800u16);
        let half = u32::from(w) * u32::from(h) / 2;
        let column = |i: u16| Rect {
            x: i * 100,
            y: 0,
            w: 100,
            h: 800,
        };
        let mut b = FrameBatcher::new(w, h);

        for i in 0..4u16 {
            b.push(column(i));
        }
        let batch = b.take().expect("batch");
        assert_eq!(
            batch.kind,
            BatchKind::Delta,
            "320k px is under the 400k threshold"
        );
        assert_eq!(batch.rects.len(), 4);
        assert!(
            batch.rects.iter().map(|r| r.area()).sum::<u32>() <= half,
            "sanity: the fixture must stay under the threshold"
        );

        for i in 0..6u16 {
            b.push(column(i));
        }
        let batch = b.take().expect("batch");
        assert_eq!(
            batch.kind,
            BatchKind::Keyframe,
            "480k px trips the collapse"
        );
        assert_eq!(
            batch.rects,
            vec![Rect::full(w, h)],
            "a collapse is exactly one full-framebuffer rect"
        );
    }

    /// A single huge rect must collapse on its own, not just an accumulation.
    #[test]
    fn one_oversized_rect_collapses_immediately() {
        let mut b = FrameBatcher::new(1280, 800);
        b.push(Rect {
            x: 0,
            y: 0,
            w: 1280,
            h: 600,
        });
        let batch = b.take().expect("batch");
        assert_eq!(batch.kind, BatchKind::Keyframe);
        assert_eq!(batch.rects, vec![Rect::full(1280, 800)]);
    }

    /// Once collapsed, more pushes in the same window are free and cannot grow
    /// the batch back into a rect list.
    #[test]
    fn pushes_after_a_collapse_are_absorbed() {
        let mut b = FrameBatcher::new(100, 100);
        b.push(Rect::full(100, 100));
        for i in 0..10u16 {
            b.push(Rect {
                x: i,
                y: i,
                w: 3,
                h: 3,
            });
        }
        let batch = b.take().expect("batch");
        assert_eq!(batch.rects, vec![Rect::full(100, 100)]);
        assert_eq!(batch.kind, BatchKind::Keyframe);
    }

    /// Past MAX_RECTS the batch folds to a bounding box rather than growing an
    /// arbitrarily long table. Rects here are tiny and spread out, so the area
    /// rule alone would never fire.
    #[test]
    fn folds_to_a_bounding_box_past_max_rects() {
        let mut b = FrameBatcher::new(4096, 4096);
        for i in 0..=u16::try_from(MAX_RECTS).unwrap() {
            b.push(Rect {
                x: i * 4,
                y: i * 4,
                w: 2,
                h: 2,
            });
        }
        let batch = b.take().expect("batch");
        assert_eq!(
            batch.rects.len(),
            1,
            "MAX_RECTS + 1 pushes fold to one rect"
        );
        let folded = batch.rects[0];
        assert_eq!(folded.x, 0);
        assert_eq!(folded.y, 0);
        let last = u16::try_from(MAX_RECTS).unwrap() * 4;
        assert_eq!(
            folded.w,
            last + 2,
            "the box reaches the last rect's right edge"
        );
        assert_eq!(folded.h, last + 2);
        assert_eq!(
            batch.kind,
            BatchKind::Delta,
            "the bounding box is still well under half of 4096x4096"
        );
    }

    #[test]
    fn resize_discards_stale_rects() {
        let mut b = FrameBatcher::new(1280, 800);
        b.push(Rect {
            x: 1000,
            y: 700,
            w: 100,
            h: 50,
        });
        b.resize(640, 480);
        assert!(
            b.is_empty(),
            "rects describing the old framebuffer are dropped"
        );
        b.push(Rect {
            x: 0,
            y: 0,
            w: 10,
            h: 10,
        });
        assert_eq!(b.take().expect("batch").rects.len(), 1);
    }

    #[test]
    fn header_layout_is_stable() {
        let (w, h) = (8u16, 4u16);
        let data = checker(w, h);
        let fb = FrameBuffer {
            data: &data,
            width: w,
            height: h,
        };
        let batch = Batch {
            kind: BatchKind::Delta,
            rects: vec![
                Rect {
                    x: 1,
                    y: 1,
                    w: 2,
                    h: 2,
                },
                Rect {
                    x: 5,
                    y: 0,
                    w: 3,
                    h: 1,
                },
            ],
        };
        let bytes = encode_batch(fb, &batch);

        assert_eq!(&bytes[0..4], b"RDPF");
        assert_eq!(bytes[4], FRAME_VERSION);
        assert_eq!(bytes[5], 0, "delta");
        assert_eq!(u16::from_le_bytes([bytes[6], bytes[7]]), 2, "rectCount");
        assert_eq!(u16::from_le_bytes([bytes[8], bytes[9]]), w, "fbWidth");
        assert_eq!(u16::from_le_bytes([bytes[10], bytes[11]]), h, "fbHeight");
        let payload_len = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        // 2x2 + 3x1 pixels, four bytes each.
        assert_eq!(payload_len, (2 * 2 + 3) * 4, "payloadLen");

        // Rect table, in batch order.
        assert_eq!(&bytes[16..24], &[1, 0, 1, 0, 2, 0, 2, 0]);
        assert_eq!(&bytes[24..32], &[5, 0, 0, 0, 3, 0, 1, 0]);

        assert_eq!(
            bytes.len(),
            HEADER_LEN + 2 * RECT_LEN + usize::try_from(payload_len).unwrap(),
            "total length must be header + table + payload, with nothing else"
        );
    }

    /// Rows must be tightly packed per rect, taken from the right framebuffer
    /// offsets, and opaque.
    #[test]
    fn payload_is_tightly_packed_and_opaque() {
        let (w, h) = (8u16, 4u16);
        let data = checker(w, h);
        let fb = FrameBuffer {
            data: &data,
            width: w,
            height: h,
        };
        let batch = Batch {
            kind: BatchKind::Delta,
            rects: vec![Rect {
                x: 5,
                y: 2,
                w: 3,
                h: 2,
            }],
        };
        let bytes = encode_batch(fb, &batch);
        let payload = &bytes[HEADER_LEN + RECT_LEN..];
        assert_eq!(payload.len(), 3 * 2 * 4);

        // checker() writes [x, y, 0x33, 0x00]; alpha must come back as 0xFF.
        let expected: Vec<u8> = (2..4u8)
            .flat_map(|y| (5..8u8).flat_map(move |x| [x, y, 0x33, 0xFF]))
            .collect();
        assert_eq!(payload, expected.as_slice());
    }

    #[test]
    fn keyframe_covers_the_whole_framebuffer() {
        let (w, h) = (6u16, 3u16);
        let data = checker(w, h);
        let fb = FrameBuffer {
            data: &data,
            width: w,
            height: h,
        };
        let bytes = encode_batch(fb, &Batch::keyframe(w, h));

        assert_eq!(bytes[5], 1, "keyframe");
        assert_eq!(
            u16::from_le_bytes([bytes[6], bytes[7]]),
            1,
            "exactly one rect"
        );
        assert_eq!(&bytes[16..24], &[0, 0, 0, 0, 6, 0, 3, 0]);
        assert_eq!(bytes.len(), HEADER_LEN + RECT_LEN + data.len());
        // Same bytes as the framebuffer, alpha aside.
        assert!(bytes[HEADER_LEN + RECT_LEN..]
            .chunks_exact(4)
            .zip(data.chunks_exact(4))
            .all(|(got, want)| got[..3] == want[..3] && got[3] == 0xFF));
    }

    /// A rect the framebuffer cannot back must not be able to panic the
    /// session task on an out-of-bounds slice.
    #[test]
    fn out_of_range_rects_are_clipped_not_fatal() {
        let (w, h) = (4u16, 4u16);
        let data = checker(w, h);
        let fb = FrameBuffer {
            data: &data,
            width: w,
            height: h,
        };
        let batch = Batch {
            kind: BatchKind::Delta,
            rects: vec![
                Rect {
                    x: 2,
                    y: 2,
                    w: 100,
                    h: 100,
                },
                Rect {
                    x: 900,
                    y: 900,
                    w: 4,
                    h: 4,
                },
            ],
        };
        let bytes = encode_batch(fb, &batch);
        assert_eq!(
            u16::from_le_bytes([bytes[6], bytes[7]]),
            1,
            "the fully-outside rect is dropped from the table"
        );
        assert_eq!(
            &bytes[16..24],
            &[2, 0, 2, 0, 2, 0, 2, 0],
            "the other is trimmed to 2x2"
        );
        assert_eq!(bytes.len(), HEADER_LEN + RECT_LEN + 2 * 2 * 4);
    }
}
