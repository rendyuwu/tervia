//! Host-process clipboard, in both directions.
//!
//! # Why reads are here and not in the webview
//!
//! `navigator.clipboard.readText()` is not usable on Linux: wry only enables
//! WebKitGTK's `javascript_can_access_clipboard` - which also flips WebCore's
//! `DOMPasteAllowed`, the flag gating clipboard READS - when the webview is built
//! with `clipboard: true`, and Tauri defaults that to false with no
//! tauri.conf.json knob to raise it for a config-declared window like `main`. So
//! every read rejected with NotAllowedError while writes kept working off the
//! keystroke's user gesture: copy fine, paste dead. Ordinary app writes stay on
//! the webview API; reads come through here, on all three platforms so there is
//! one path to reason about.
//!
//! # Why the handle is process-global
//!
//! One `arboard::Clipboard` for the app's lifetime, and this is load-bearing
//! now that the RDP clipboard bridge (`modules/rdp/cliprdr.rs`) WRITES through
//! here. An X11 selection is owned by a live connection, not stored in a
//! server: a per-call handle that writes and then drops loses the data
//! outright (a following `xclip -o` reports no such target) while paying
//! arboard's `max_handover_duration` wait against a clipboard manager that is
//! not there. A long-lived handle serves the selection for as long as the app
//! runs.
//!
//! An earlier version of this file argued the opposite ("a fresh `Clipboard`
//! per call is deliberate"), and that argument was sound while the only
//! operation was a read. It is not sound for a write, so it is gone rather than
//! amended.
//!
//! Every function here is a synchronous round trip to whichever process owns
//! the selection, so every one of them must be called from a blocking thread -
//! a slow owner would otherwise stall the window, the same reason `pty_open` is
//! async.
//!
//! An empty clipboard, or one holding no data in the requested shape, comes
//! back as `Err` from arboard, which callers map to "nothing to paste" like any
//! other failure.

use std::sync::{Mutex, OnceLock};

use crate::modules::lockext::LockExt as _;

static CLIPBOARD: OnceLock<Mutex<arboard::Clipboard>> = OnceLock::new();

/// The one handle for the app's lifetime.
///
/// BLOCKING - call only from a blocking thread.
///
/// `OnceLock` and not `LazyLock`, which is otherwise the house default:
/// `Clipboard::new()` is FALLIBLE, and a `LazyLock` would run it once and
/// then hand back the same failure for the rest of the process. A transient
/// failure - no X display yet, a Wayland compositor mid-restart - must not
/// poison every later call, so nothing is cached until one succeeds. If two
/// threads race here the loser's handle is dropped immediately; that drop is
/// cheap precisely because it never owned a selection, so it cannot hit the
/// handover wait.
fn handle() -> Result<&'static Mutex<arboard::Clipboard>, String> {
    if let Some(existing) = CLIPBOARD.get() {
        return Ok(existing);
    }
    let fresh = arboard::Clipboard::new().map_err(|e| e.to_string())?;
    Ok(CLIPBOARD.get_or_init(|| Mutex::new(fresh)))
}

/// BLOCKING - call only from a blocking thread.
pub(crate) fn read_text() -> Result<String, String> {
    handle()?
        .lock_or_recover()
        .get_text()
        .map_err(|e| e.to_string())
}

/// BLOCKING - call only from a blocking thread.
///
/// The data is marked so host clipboard managers skip it. Remote clipboard
/// content can be a password a user copied out of a vault inside the session,
/// and a history tool indexing it would outlive the session that produced it.
/// macOS has no OS-level flag for this, only the `org.nspasteboard.ConcealedType`
/// community convention, which is what arboard sets there.
pub(crate) fn write_text(text: &str) -> Result<(), String> {
    let clipboard = handle()?;
    let mut clipboard = clipboard.lock_or_recover();
    let set = conceal(clipboard.set());
    set.text(text).map_err(|e| e.to_string())
}

/// BLOCKING - call only from a blocking thread.
///
/// PNG rather than arboard's native `ImageData`, because every
/// `ironrdp-cliprdr-format` conversion speaks PNG and nothing else in this app
/// wants raw RGBA.
pub(crate) fn read_image_png() -> Result<Vec<u8>, String> {
    let image = handle()?
        .lock_or_recover()
        .get_image()
        .map_err(|e| e.to_string())?;
    let width = u32::try_from(image.width).map_err(|_| "clipboard: image too wide".to_string())?;
    let height =
        u32::try_from(image.height).map_err(|_| "clipboard: image too tall".to_string())?;
    // `ImageData` is row-major RGBA8, four channels, which is exactly
    // `RgbaImage`'s layout - so this is a length check, not a conversion.
    let rgba = image::RgbaImage::from_raw(width, height, image.bytes.into_owned())
        .ok_or_else(|| format!("clipboard: image buffer is not {width}x{height} RGBA"))?;
    let mut png = Vec::new();
    image::DynamicImage::ImageRgba8(rgba)
        .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
        .map_err(|e| format!("clipboard: encoding the image as PNG failed: {e}"))?;
    Ok(png)
}

/// BLOCKING - call only from a blocking thread.
pub(crate) fn write_image_png(png: &[u8]) -> Result<(), String> {
    let decoded = image::load_from_memory_with_format(png, image::ImageFormat::Png)
        .map_err(|e| format!("clipboard: decoding the PNG failed: {e}"))?
        .to_rgba8();
    let (width, height) = (decoded.width() as usize, decoded.height() as usize);
    let clipboard = handle()?;
    let mut clipboard = clipboard.lock_or_recover();
    let set = conceal(clipboard.set());
    set.image(arboard::ImageData {
        width,
        height,
        bytes: decoded.into_raw().into(),
    })
    .map_err(|e| e.to_string())
}

/// Mark a pending write as "do not index".
///
/// On Windows this is `exclude_from_monitoring` ALONE: arboard's own docs say
/// not to pair it with `exclude_from_cloud` or `exclude_from_history`, and it
/// already subsumes both.
fn conceal(set: arboard::Set<'_>) -> arboard::Set<'_> {
    #[cfg(target_os = "linux")]
    {
        use arboard::SetExtLinux as _;
        set.exclude_from_history()
    }
    #[cfg(target_os = "windows")]
    {
        use arboard::SetExtWindows as _;
        set.exclude_from_monitoring()
    }
    #[cfg(target_os = "macos")]
    {
        use arboard::SetExtApple as _;
        set.exclude_from_history()
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    set
}

/// Clipboard text for a paste, read in the HOST process instead of the webview.
#[tauri::command]
pub async fn clipboard_read_text() -> Result<String, String> {
    tokio::task::spawn_blocking(read_text)
        .await
        .map_err(|e| format!("clipboard task failed: {e}"))?
}

/// Tests against a real X selection. They need a display and `xclip`, so every
/// one is `#[ignore]`d and `cargo test` stays hermetic - the same arrangement
/// `rdp::session::rdp_live` uses for tests that need a real server.
///
/// ```text
/// xvfb-run -a cargo test selection_survives -- --ignored --nocapture
/// ```
///
/// What they prove cannot be proved any other way: that a selection written
/// here is readable BY ANOTHER PROCESS afterwards. That is the entire reason
/// the handle is process-global, and it is the claim the previous version of
/// this file had backwards - a per-call handle passes an in-process
/// write-then-read and still loses the data the moment anything else asks for
/// it.
#[cfg(test)]
mod smoke {
    use std::process::Command;

    /// True once there is a display and an `xclip` to talk to it.
    fn usable() -> bool {
        if std::env::var_os("DISPLAY").is_none() {
            eprintln!("skipped: no DISPLAY; run under `xvfb-run -a`");
            return false;
        }
        if Command::new("xclip").arg("-version").output().is_err() {
            eprintln!("skipped: xclip is not installed");
            return false;
        }
        true
    }

    fn xclip_out(args: &[&str]) -> Vec<u8> {
        let out = Command::new("xclip").args(args).output().expect("xclip");
        assert!(out.status.success(), "xclip failed: {out:?}");
        out.stdout
    }

    #[test]
    #[ignore]
    fn selection_survives_for_another_process_to_read() {
        if !usable() {
            return;
        }
        // Text out, read by a DIFFERENT process. This is the whole claim: a
        // per-call handle would have dropped the selection before xclip ran.
        super::write_text("line one\nline two").unwrap();
        assert_eq!(
            String::from_utf8(xclip_out(&["-selection", "clipboard", "-o"])).unwrap(),
            "line one\nline two"
        );
        // And our own read sees it.
        assert_eq!(super::read_text().unwrap(), "line one\nline two");

        // A second write replaces it, still readable from outside.
        super::write_text("second").unwrap();
        assert_eq!(
            String::from_utf8(xclip_out(&["-selection", "clipboard", "-o"])).unwrap(),
            "second"
        );

        // Image out, read by another process as image/png.
        let mut png = Vec::new();
        let mut rgba = image::RgbaImage::new(2, 1);
        rgba.put_pixel(0, 0, image::Rgba([0x11, 0x22, 0x33, 0xFF]));
        rgba.put_pixel(1, 0, image::Rgba([0x44, 0x55, 0x66, 0x80]));
        image::DynamicImage::ImageRgba8(rgba)
            .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
            .unwrap();
        super::write_image_png(&png).unwrap();
        let outside = xclip_out(&["-selection", "clipboard", "-t", "image/png", "-o"]);
        let decoded = image::load_from_memory_with_format(&outside, image::ImageFormat::Png)
            .unwrap()
            .to_rgba8();
        assert_eq!(decoded.dimensions(), (2, 1));
        assert_eq!(decoded.get_pixel(1, 0).0, [0x44, 0x55, 0x66, 0x80]);

        // And read back in through our own path.
        let round = super::read_image_png().unwrap();
        let round = image::load_from_memory_with_format(&round, image::ImageFormat::Png)
            .unwrap()
            .to_rgba8();
        assert_eq!(round.get_pixel(1, 0).0, [0x44, 0x55, 0x66, 0x80]);

        // Text set by another process is read back through our handle, which
        // proves the long-lived handle does not stale-cache its own write.
        let mut child = Command::new("xclip")
            .args(["-selection", "clipboard"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        {
            use std::io::Write as _;
            child
                .stdin
                .as_mut()
                .unwrap()
                .write_all(b"from outside")
                .unwrap();
        }
        child.wait().unwrap();
        assert_eq!(super::read_text().unwrap(), "from outside");
    }
}
