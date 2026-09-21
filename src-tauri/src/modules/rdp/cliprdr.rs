//! The CLIPRDR (MS-RDPECLIP) backend: the host clipboard, bridged to the
//! remote's.
//!
//! Text and images, both ways. Files are deliberately out of scope, and that
//! is enforced by capability rather than by a runtime refusal: the client
//! advertises `USE_LONG_FORMAT_NAMES` alone, so the server never asks for a
//! file transfer and the four file / lock callbacks below are unreachable.
//!
//! # Where the work happens
//!
//! Every arboard call is a synchronous round trip to whichever process owns
//! the selection, and every DIB conversion is CPU work over a buffer that can
//! reach [`MAX_CLIPBOARD_BYTES`]. Neither may run on the session task, which
//! also decodes bitmaps and writes frames - so every callback here hands its
//! work to the RDP runtime's blocking pool and returns immediately. That pool
//! is disjoint from the runtime's two worker threads, so a blocking call made
//! from a task on that runtime cannot starve it.
//!
//! # Why the backend holds a `WeakSender`
//!
//! The backend is owned by `CliprdrClient`, owned by `ActiveStage`, owned by
//! `run` - the very task that drains the receiver. A strong `Sender` parked
//! there would mean `input_rx.recv()` could never return `None`, and `None` is
//! exactly how `run` learns the `RdpSession` was dropped. `WeakSender::upgrade`
//! returns `None` once the last strong sender is gone, which keeps that branch
//! live.
//!
//! `ClipboardMessageProxy` is not implemented: that trait is shaped for
//! upstream's winit event loops and buys nothing over the `SessionOp` queue
//! that already exists. `CliprdrBackendFactory` is not implemented either - the
//! Deactivation-Reactivation path mutates `stage` in place and never rebuilds
//! `ActiveStage`, so the SVC set and this backend survive a reactivation.
//!
//! Every failure here is logged and swallowed. A clipboard error must never end
//! the session.

use std::sync::{Arc, Mutex};

use ironrdp_cliprdr::backend::{ClipboardMessage, CliprdrBackend};
use ironrdp_cliprdr::pdu::{
    ClipboardFormat, ClipboardFormatId, ClipboardGeneralCapabilityFlags, FileContentsRequest,
    FileContentsResponse, FormatDataRequest, FormatDataResponse, LockDataId,
    OwnedFormatDataResponse,
};
use ironrdp_cliprdr_format::bitmap::{dib_to_png, dibv5_to_png, png_to_cf_dib, png_to_cf_dibv5};
use ironrdp_core::IntoOwned as _;
use tokio::sync::mpsc;

use crate::modules::clipboard;
use crate::modules::lockext::LockExt as _;

use super::{RdpClipboardMode, SessionOp};

/// Largest clipboard payload accepted in either direction.
///
/// A hostile server controls the length of a `FormatDataResponse`, so this
/// bounds the allocation before any decoder sees it; it also bounds what a
/// decode can expand to, since a `CF_DIB` is uncompressed and its dimensions
/// fall out of its length. `ironrdp-cliprdr-format` rejects malformed and
/// oversized bitmaps itself (`ironrdp-cliprdr-format` 0.2.0, `BitmapError`);
/// this is the cap on our side of that.
///
/// A 4K 32-bpp screenshot is 3840 * 2160 * 4 = 31.6 MiB, so the largest
/// legitimate copy anybody actually makes still fits.
const MAX_CLIPBOARD_BYTES: usize = 32 * 1024 * 1024;

/// Advertised when the host clipboard holds text.
///
/// BOTH, not just the Unicode one: a server that accepts only `CF_TEXT` would
/// otherwise never be offered anything, and both are served from the same
/// single read in [`host_format_data`].
const TEXT_FORMATS: [ClipboardFormatId; 2] = [
    ClipboardFormatId::CF_UNICODETEXT,
    ClipboardFormatId::CF_TEXT,
];

/// Advertised when the host clipboard holds an image and no text.
///
/// `CF_DIBV5` first because `png_to_cf_dibv5` writes the 124-byte
/// `BITMAPV5HEADER`, so an alpha channel survives the trip instead of being
/// dropped.
const IMAGE_FORMATS: [ClipboardFormatId; 2] =
    [ClipboardFormatId::CF_DIBV5, ClipboardFormatId::CF_DIB];

/// Formats we will ask the remote for, best first.
///
/// Text outranks images because a copy offering both is normally a text copy
/// with a rendered fallback.
const PASTE_PREFERENCE: [ClipboardFormatId; 5] = [
    ClipboardFormatId::CF_UNICODETEXT,
    ClipboardFormatId::CF_TEXT,
    ClipboardFormatId::CF_OEMTEXT,
    ClipboardFormatId::CF_DIBV5,
    ClipboardFormatId::CF_DIB,
];

/// State the backend (task side) and [`super::session::RdpSession`] (command
/// side) both touch.
#[derive(Debug)]
pub(crate) struct ClipboardShared {
    pub(crate) mode: RdpClipboardMode,
    /// The single best format the remote last advertised, already reduced by
    /// [`best_paste_format`]. `Cliprdr::initiate_paste` takes exactly one
    /// format and the full list is never consulted again, so nothing keeps the
    /// `Vec`.
    pub(crate) best_remote: Mutex<Option<ClipboardFormatId>>,
    /// The format `initiate_paste` last asked for, so `on_format_data_response`
    /// knows how to decode bytes the PDU does not label - the callback carries
    /// no format argument even though `Cliprdr` tracks the request internally.
    pub(crate) pending_paste: Mutex<Option<ClipboardFormatId>>,
}

impl ClipboardShared {
    pub(crate) fn new(mode: RdpClipboardMode) -> Self {
        Self {
            mode,
            best_remote: Mutex::new(None),
            pending_paste: Mutex::new(None),
        }
    }
}

// ---------------------------------------------------------------------------
// Conversions. Pure, and therefore the part worth unit-testing.
// ---------------------------------------------------------------------------

/// LF to CRLF, which is what every Windows clipboard format expects.
///
/// Two passes on purpose: a single `replace('\n', "\r\n")` would turn text that
/// already carries CRLF into CRCRLF.
fn to_crlf(s: &str) -> String {
    s.replace("\r\n", "\n").replace('\n', "\r\n")
}

/// CRLF back to LF, so pasting into a host editor does not litter it with `^M`.
fn to_lf(s: &str) -> String {
    s.replace("\r\n", "\n")
}

/// The best format we are willing to paste out of what the remote offered, or
/// `None` when it offered nothing we handle.
fn best_paste_format(offered: &[ClipboardFormat]) -> Option<ClipboardFormatId> {
    PASTE_PREFERENCE
        .into_iter()
        .find(|wanted| offered.iter().any(|format| format.id() == *wanted))
}

/// Host text, encoded for `format`. `None` for a format that is not text.
fn text_to_format_data(text: &str, format: ClipboardFormatId) -> Option<OwnedFormatDataResponse> {
    let text = to_crlf(text);
    // `new_unicode_string` encodes UTF-16LE and appends the two-byte NUL
    // itself; `new_string` appends the one-byte one.
    let response = match format {
        ClipboardFormatId::CF_UNICODETEXT => FormatDataResponse::new_unicode_string(&text),
        ClipboardFormatId::CF_TEXT => FormatDataResponse::new_string(&text),
        _ => return None,
    };
    Some(response.into_owned())
}

/// Remote bytes in `format`, decoded to host text.
fn format_data_to_text(data: &[u8], format: ClipboardFormatId) -> Result<String, String> {
    let response = FormatDataResponse::new_data(data);
    // Both decoders stop at the NUL terminator.
    let decoded = match format {
        ClipboardFormatId::CF_UNICODETEXT => response.to_unicode_string(),
        ClipboardFormatId::CF_TEXT | ClipboardFormatId::CF_OEMTEXT => response.to_string(),
        _ => return Err(format!("{format:?} is not a text format")),
    };
    decoded
        .map(|text| to_lf(&text))
        .map_err(|e| format!("decoding remote clipboard text failed: {e}"))
}

/// A host PNG, re-encoded as the DIB flavour `format` names.
fn png_to_format_data(png: &[u8], format: ClipboardFormatId) -> Result<Vec<u8>, String> {
    match format {
        ClipboardFormatId::CF_DIBV5 => png_to_cf_dibv5(png),
        ClipboardFormatId::CF_DIB => png_to_cf_dib(png),
        _ => return Err(format!("{format:?} is not a bitmap format")),
    }
    .map_err(|e| format!("converting the host image to a DIB failed: {e:?}"))
}

/// Remote DIB bytes, decoded to a PNG the host clipboard can take.
fn format_data_to_png(data: &[u8], format: ClipboardFormatId) -> Result<Vec<u8>, String> {
    match format {
        ClipboardFormatId::CF_DIBV5 => dibv5_to_png(data),
        ClipboardFormatId::CF_DIB => dib_to_png(data),
        _ => return Err(format!("{format:?} is not a bitmap format")),
    }
    .map_err(|e| format!("converting the remote DIB to an image failed: {e:?}"))
}

// ---------------------------------------------------------------------------
// The two blocking halves
// ---------------------------------------------------------------------------

/// Read the host clipboard and encode it for `format`.
///
/// BLOCKING - call from a blocking thread. Read fresh rather than reusing what
/// the last advertise saw: there is nothing to invalidate, and a format that
/// vanished in between is exactly what an error response is for.
fn host_format_data(format: ClipboardFormatId) -> Result<OwnedFormatDataResponse, String> {
    match format {
        ClipboardFormatId::CF_UNICODETEXT | ClipboardFormatId::CF_TEXT => {
            let text = clipboard::read_text()?;
            if text.len() > MAX_CLIPBOARD_BYTES {
                return Err(format!("host clipboard text is {} bytes", text.len()));
            }
            text_to_format_data(&text, format)
                .ok_or_else(|| format!("{format:?} is not a text format"))
        }
        ClipboardFormatId::CF_DIBV5 | ClipboardFormatId::CF_DIB => {
            let png = clipboard::read_image_png()?;
            let dib = png_to_format_data(&png, format)?;
            if dib.len() > MAX_CLIPBOARD_BYTES {
                return Err(format!("host clipboard image is {} bytes", dib.len()));
            }
            Ok(FormatDataResponse::new_data(dib).into_owned())
        }
        _ => Err(format!("{format:?} is not a format we serve")),
    }
}

/// Decode remote clipboard bytes and put them on the host clipboard.
///
/// BLOCKING - call from a blocking thread.
fn write_host_clipboard(format: ClipboardFormatId, data: &[u8]) -> Result<(), String> {
    match format {
        ClipboardFormatId::CF_UNICODETEXT
        | ClipboardFormatId::CF_TEXT
        | ClipboardFormatId::CF_OEMTEXT => {
            clipboard::write_text(&format_data_to_text(data, format)?)
        }
        ClipboardFormatId::CF_DIBV5 | ClipboardFormatId::CF_DIB => {
            clipboard::write_image_png(&format_data_to_png(data, format)?)
        }
        _ => Err(format!("{format:?} is not a format we accept")),
    }
}

/// What the host clipboard currently holds, as the formats to advertise.
///
/// BLOCKING - call from a blocking thread.
///
/// Text is read first so a focus edge does not ship a multi-megabyte image
/// every time; a clipboard carrying both is rare enough that preferring the
/// text is also the right answer.
///
/// No size check here: an advertise puts no content bytes on the wire at all,
/// and [`host_format_data`] caps the serve that would follow.
fn host_clipboard_state() -> Option<&'static [ClipboardFormatId]> {
    match clipboard::read_text() {
        Ok(text) if !text.is_empty() => return Some(&TEXT_FORMATS),
        Ok(_) => {}
        Err(e) => log::trace!("rdp: no text on the host clipboard: {e}"),
    }
    match clipboard::read_image_png() {
        Ok(_) => Some(&IMAGE_FORMATS),
        Err(e) => {
            log::trace!("rdp: no image on the host clipboard: {e}");
            None
        }
    }
}

/// Advertise the host clipboard to the remote.
///
/// BLOCKING - reads arboard. Call from a blocking thread.
///
/// An empty host clipboard still sends an empty Format List, and that is
/// load-bearing rather than merely harmless: a CLIPRDR client only leaves
/// `Initialization` when the server answers a Format List it sent,
/// `initiate_copy` is the only thing that sends one, and that first call also
/// carries the Capabilities and Temporary Directory PDUs
/// (`ironrdp-cliprdr` 0.6.0, `Cliprdr::initiate_copy`). Returning early on an
/// empty clipboard would leave the channel in `Initialization` forever, every
/// later paste failing `require_ready`, and the remote-to-host direction dead
/// with no error anywhere to say why.
pub(crate) fn advertise(shared: &ClipboardShared, ops: &mpsc::Sender<SessionOp>) {
    let formats: &[ClipboardFormatId] = if shared.mode.host_to_remote() {
        host_clipboard_state().unwrap_or(&[])
    } else {
        &[]
    };
    let formats = formats.iter().copied().map(ClipboardFormat::new).collect();
    if let Err(e) = ops.try_send(SessionOp::Clipboard(ClipboardMessage::SendInitiateCopy(
        formats,
    ))) {
        // Nothing is stranded: no peer is waiting on this, and the next focus
        // edge retries.
        log::warn!("rdp: could not queue a clipboard advertise: {e}");
    }
}

// ---------------------------------------------------------------------------
// The backend
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub(crate) struct TerviaCliprdrBackend {
    shared: Arc<ClipboardShared>,
    ops: mpsc::WeakSender<SessionOp>,
}

// `CliprdrBackend` is declared `AsAny + Debug + Send` and there is no blanket
// `AsAny` impl, so the derive above is not enough on its own.
ironrdp_core::impl_as_any!(TerviaCliprdrBackend);

impl TerviaCliprdrBackend {
    pub(crate) fn new(shared: Arc<ClipboardShared>, ops: mpsc::WeakSender<SessionOp>) -> Self {
        Self { shared, ops }
    }
}

impl CliprdrBackend for TerviaCliprdrBackend {
    fn temporary_directory(&self) -> &str {
        // Empty on purpose. This string only ends up in the Temporary
        // Directory PDU, which names where the server should drop clipboard
        // FILE transfers - and no file capability is advertised, so it is
        // never used and nothing is created on disk either way. The PDU is
        // sent regardless and zero-fills its 520-byte buffer, doing no I/O
        // with the name (`ironrdp-cliprdr` 0.6.0, `ClientTemporaryDirectory::new`).
        ""
    }

    fn client_capabilities(&self) -> ClipboardGeneralCapabilityFlags {
        // Long format names and nothing else. Leaving STREAM_FILECLIP_ENABLED,
        // FILECLIP_NO_FILE_PATHS, CAN_LOCK_CLIPDATA and
        // HUGE_FILE_SUPPORT_ENABLED off is what makes the file and lock
        // callbacks below unreachable.
        ClipboardGeneralCapabilityFlags::USE_LONG_FORMAT_NAMES
    }

    fn on_ready(&mut self) {
        log::debug!("rdp: the clipboard channel is ready");
    }

    fn on_process_negotiated_capabilities(
        &mut self,
        capabilities: ClipboardGeneralCapabilityFlags,
    ) {
        // Nothing to adjust: we asked for one flag and use no capability that
        // depends on the server's answer.
        log::debug!("rdp: server clipboard capabilities {capabilities:?}");
    }

    fn on_request_format_list(&mut self) {
        // Fires ONCE, during channel initialization, and is not a change
        // signal. See `advertise` for why an empty clipboard must still
        // produce a Format List here.
        let Some(ops) = self.ops.upgrade() else {
            return;
        };
        let shared = Arc::clone(&self.shared);
        super::rdp_runtime().spawn_blocking(move || advertise(&shared, &ops));
    }

    fn on_remote_copy(&mut self, available_formats: &[ClipboardFormat]) {
        // Recorded, not fetched. The fetch happens on pane blur - see
        // `RdpSession::clipboard_focus` for why that is the right moment.
        *self.shared.best_remote.lock_or_recover() = best_paste_format(available_formats);
        // `Cliprdr` drops its own request correlation on a new Format List, so
        // ours has to go with it or a late response would decode against a
        // format from the previous copy.
        *self.shared.pending_paste.lock_or_recover() = None;
    }

    fn on_format_data_request(&mut self, request: FormatDataRequest) {
        let format = request.format;
        let Some(ops) = self.ops.upgrade() else {
            log::warn!("rdp: dropping a clipboard format-data request; the session is gone");
            return;
        };
        let mode = self.shared.mode;
        super::rdp_runtime().spawn_blocking(move || {
            let response = if mode.host_to_remote() {
                host_format_data(format)
            } else {
                Err("the saved clipboard direction excludes host-to-remote".to_owned())
            };
            let response = response.unwrap_or_else(|e| {
                log::debug!("rdp: answering a clipboard request for {format:?} with an error: {e}");
                FormatDataResponse::new_error().into_owned()
            });
            // `blocking_send` and not `try_send`, unlike every other send in
            // this file: the server has an OUTSTANDING Format Data Request and
            // nothing on our side re-fires it, so a dropped reply hangs that
            // paste. The wait is bounded by the session's life - the send
            // fails the moment the task is gone.
            //
            // THIS LINE MUST STAY INSIDE `spawn_blocking`. `blocking_send`
            // panics when called from a scheduler context, and with
            // `panic = "abort"` that takes the whole app down rather than one
            // tab. A blocking-pool thread is not a scheduler context, so it is
            // legal here and only here - verified against tokio by driving a
            // `blocking_send` on a FULL queue from a `spawn_blocking` closure,
            // which is the case that actually parks.
            if ops
                .blocking_send(SessionOp::Clipboard(ClipboardMessage::SendFormatData(
                    response,
                )))
                .is_err()
            {
                log::warn!("rdp: the session ended before a clipboard reply could be sent");
            }
        });
    }

    fn on_format_data_response(&mut self, response: FormatDataResponse<'_>) {
        // Taken unconditionally, so a refused or malformed response cannot
        // leave a stale format for the next one to decode against.
        let pending = self.shared.pending_paste.lock_or_recover().take();
        if !self.shared.mode.remote_to_host() {
            return;
        }
        let Some(format) = pending else {
            log::debug!("rdp: ignoring clipboard data we did not ask for");
            return;
        };
        if response.is_error() {
            log::debug!("rdp: the server has no clipboard data in {format:?}");
            return;
        }
        let data = response.data();
        if data.len() > MAX_CLIPBOARD_BYTES {
            log::warn!(
                "rdp: refusing a {}-byte clipboard payload (cap is {MAX_CLIPBOARD_BYTES})",
                data.len()
            );
            return;
        }
        let data = data.to_vec();
        // The decode goes to the blocking pool too, not just the arboard write:
        // a 32 MiB DIB-to-PNG encode on the session task stalls the graphics
        // path exactly as an arboard call would.
        super::rdp_runtime().spawn_blocking(move || {
            if let Err(e) = write_host_clipboard(format, &data) {
                log::warn!("rdp: putting the remote clipboard on the host failed: {e}");
            }
        });
    }

    // The four below are unreachable while the file and lock capabilities stay
    // unadvertised. Warned about rather than silently ignored, so a future
    // capability change is visible instead of mysterious.

    fn on_file_contents_request(&mut self, request: FileContentsRequest) {
        log::warn!(
            "rdp: ignoring an out-of-scope clipboard file-contents request for stream {}",
            request.stream_id
        );
    }

    fn on_file_contents_response(&mut self, response: FileContentsResponse<'_>) {
        log::warn!(
            "rdp: ignoring an out-of-scope clipboard file-contents response for stream {}",
            response.stream_id()
        );
    }

    fn on_lock(&mut self, data_id: LockDataId) {
        log::warn!("rdp: ignoring an out-of-scope clipboard lock {data_id:?}");
    }

    fn on_unlock(&mut self, data_id: LockDataId) {
        log::warn!("rdp: ignoring an out-of-scope clipboard unlock {data_id:?}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crlf_conversion_is_idempotent_and_reversible() {
        assert_eq!(to_crlf("a\nb"), "a\r\nb");
        // The two-pass shape is the whole point: one pass would produce
        // "a\r\r\nb" here.
        assert_eq!(to_crlf("a\r\nb"), "a\r\nb");
        assert_eq!(to_crlf(to_crlf("a\nb").as_str()), "a\r\nb");
        assert_eq!(to_lf("a\r\nb"), "a\nb");
        assert_eq!(
            to_lf(&to_crlf("line one\nline two\n")),
            "line one\nline two\n"
        );
    }

    #[test]
    fn unicode_text_round_trips_through_the_wire_encoding() {
        let encoded = text_to_format_data("line one\nline two", ClipboardFormatId::CF_UNICODETEXT)
            .expect("CF_UNICODETEXT is a text format");
        let bytes = encoded.data();
        // UTF-16LE plus the two-byte NUL the format requires. A missing
        // terminator is accepted by some servers and silently truncates on
        // others, which is the bug this pins.
        assert_eq!(&bytes[bytes.len() - 2..], &[0x00, 0x00]);
        let utf16: Vec<u16> = bytes[..bytes.len() - 2]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect();
        assert_eq!(String::from_utf16_lossy(&utf16), "line one\r\nline two");

        let decoded = format_data_to_text(bytes, ClipboardFormatId::CF_UNICODETEXT)
            .expect("the bytes we just encoded decode");
        assert_eq!(decoded, "line one\nline two");
    }

    #[test]
    fn ansi_text_round_trips_and_carries_one_terminator() {
        let encoded = text_to_format_data("a\nb", ClipboardFormatId::CF_TEXT)
            .expect("CF_TEXT is a text format");
        assert_eq!(encoded.data(), b"a\r\nb\0");
        assert_eq!(
            format_data_to_text(encoded.data(), ClipboardFormatId::CF_TEXT).unwrap(),
            "a\nb"
        );
    }

    #[test]
    fn non_text_formats_are_refused_rather_than_mis_encoded() {
        assert!(text_to_format_data("a", ClipboardFormatId::CF_DIB).is_none());
        assert!(format_data_to_text(b"\0", ClipboardFormatId::CF_DIB).is_err());
    }

    #[test]
    fn paste_preference_puts_text_above_images() {
        let offered = |ids: &[ClipboardFormatId]| -> Vec<ClipboardFormat> {
            ids.iter().copied().map(ClipboardFormat::new).collect()
        };
        assert_eq!(
            best_paste_format(&offered(&[
                ClipboardFormatId::CF_DIB,
                ClipboardFormatId::CF_TEXT,
                ClipboardFormatId::CF_UNICODETEXT,
            ])),
            Some(ClipboardFormatId::CF_UNICODETEXT)
        );
        assert_eq!(
            best_paste_format(&offered(&[
                ClipboardFormatId::CF_DIB,
                ClipboardFormatId::CF_TEXT
            ])),
            Some(ClipboardFormatId::CF_TEXT)
        );
        assert_eq!(
            best_paste_format(&offered(&[
                ClipboardFormatId::CF_DIB,
                ClipboardFormatId::CF_DIBV5
            ])),
            Some(ClipboardFormatId::CF_DIBV5)
        );
        // Nothing we handle: a metafile and a palette.
        assert_eq!(
            best_paste_format(&offered(&[
                ClipboardFormatId::CF_METAFILEPICT,
                ClipboardFormatId::CF_PALETTE
            ])),
            None
        );
        assert_eq!(best_paste_format(&[]), None);
    }

    /// The invariant that makes the channel usable at all.
    ///
    /// A CLIPRDR client only leaves `Initialization` once the server answers a
    /// Format List it sent, and `initiate_copy` is the only thing that sends
    /// one. So an advertise with nothing to advertise still has to reach the
    /// queue - otherwise the channel never becomes `Ready`, `initiate_paste`
    /// fails `require_ready`, and the remote-to-host direction is dead with no
    /// error anywhere to say why.
    ///
    /// `RemoteToHost` keeps this hermetic: `host_to_remote()` is false, so
    /// nothing here touches arboard or a real display.
    #[test]
    fn an_empty_clipboard_still_advertises() {
        let shared = ClipboardShared::new(RdpClipboardMode::RemoteToHost);
        let (tx, mut rx) = mpsc::channel::<SessionOp>(4);

        advertise(&shared, &tx);
        match rx.try_recv() {
            Ok(SessionOp::Clipboard(ClipboardMessage::SendInitiateCopy(formats))) => {
                assert!(formats.is_empty(), "nothing to offer, so an empty list");
            }
            _ => panic!("an advertise must always queue a format list"),
        }
    }

    /// A 2x1 RGBA PNG whose second pixel is half-transparent.
    fn translucent_png() -> Vec<u8> {
        let mut image = image::RgbaImage::new(2, 1);
        image.put_pixel(0, 0, image::Rgba([0x11, 0x22, 0x33, 0xFF]));
        image.put_pixel(1, 0, image::Rgba([0x44, 0x55, 0x66, 0x80]));
        let mut png = Vec::new();
        image::DynamicImage::ImageRgba8(image)
            .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
            .expect("encoding a 2x1 PNG");
        png
    }

    #[test]
    fn dibv5_round_trip_keeps_the_alpha_channel() {
        let png = translucent_png();
        let dib = png_to_format_data(&png, ClipboardFormatId::CF_DIBV5).expect("PNG to CF_DIBV5");
        let back = format_data_to_png(&dib, ClipboardFormatId::CF_DIBV5).expect("CF_DIBV5 to PNG");
        let decoded = image::load_from_memory_with_format(&back, image::ImageFormat::Png)
            .expect("the round trip produced a PNG")
            .to_rgba8();
        assert_eq!(decoded.dimensions(), (2, 1));
        assert_eq!(decoded.get_pixel(0, 0).0, [0x11, 0x22, 0x33, 0xFF]);
        // The whole reason CF_DIBV5 is advertised ahead of CF_DIB: the
        // BITMAPV5HEADER carries the alpha mask, so this byte survives.
        assert_eq!(decoded.get_pixel(1, 0).0, [0x44, 0x55, 0x66, 0x80]);
    }

    #[test]
    fn dib_round_trip_keeps_the_colour_channels() {
        let png = translucent_png();
        let dib = png_to_format_data(&png, ClipboardFormatId::CF_DIB).expect("PNG to CF_DIB");
        let back = format_data_to_png(&dib, ClipboardFormatId::CF_DIB).expect("CF_DIB to PNG");
        let decoded = image::load_from_memory_with_format(&back, image::ImageFormat::Png)
            .expect("the round trip produced a PNG")
            .to_rgba8();
        assert_eq!(decoded.dimensions(), (2, 1));
        assert_eq!(decoded.get_pixel(0, 0).0[..3], [0x11, 0x22, 0x33]);
        assert_eq!(decoded.get_pixel(1, 0).0[..3], [0x44, 0x55, 0x66]);
    }

    #[test]
    fn a_truncated_dib_is_an_error_rather_than_a_panic() {
        assert!(format_data_to_png(&[0u8; 4], ClipboardFormatId::CF_DIB).is_err());
        assert!(format_data_to_png(&[], ClipboardFormatId::CF_DIBV5).is_err());
    }
}
