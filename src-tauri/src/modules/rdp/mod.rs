//! RDP client sessions.
//!
//! Mirrors the SSH module's shape - a shared tokio runtime, an id-keyed state
//! map, one IPC `Channel` per session, exit-signal janitor eviction, and mirror
//! sinks via `rdp_attach` - so the frontend plumbs an RDP tab the same way it
//! plumbs an SSH one.
//!
//! # What travels on the session channel
//!
//! One `Channel` carries both control events and pixels:
//!
//! * JSON payloads are [`RdpEvent`]s (a plain object on the JS side).
//! * Raw payloads are frame batches (an `ArrayBuffer` on the JS side). The
//!   binary layout is documented in [`frame`].
//!
//! So a frontend handler dispatches on `message instanceof ArrayBuffer`.
//!
//! # Certificate trust
//!
//! SHA-256 fingerprint pinning over the leaf certificate, checked *inside* the
//! TLS handshake, so a rejection happens before CredSSP sends the password or
//! runs the NTLM exchange. The username does go out earlier, as the X.224
//! Connection Request cookie on plain TCP - see [`tls`] and
//! `session::build_config`. First connect prompts the user; later connects pass
//! the recorded fingerprint back as `expectedCertFingerprint` and a mismatch
//! aborts. See [`tls`] for the full policy, including why the pin is keyed to
//! the saved connection rather than to `host:port`.
//!
//! # Out of scope for this phase
//!
//! Clipboard, audio, device redirection, RD Gateway, KDC proxy, dynamic resize,
//! EGFX/H.264, `.rdp` import and multi-monitor. Transport is direct TCP only;
//! tunnelling through SSH needs no change here, it just dials a different
//! address.

mod frame;
mod session;
mod tls;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};

use ironrdp_input::{MouseButton, MousePosition, Operation, Scancode, WheelRotations};
use serde::{Deserialize, Serialize};
use tauri::ipc::{Channel, InvokeResponseBody, Response};
use tokio::runtime::Runtime;

use crate::modules::secrets;

pub use session::RdpEvent;
use session::RdpSession;

/// The per-session IPC channel. Typed as `InvokeResponseBody` rather than
/// `RdpEvent` because the same channel carries raw frame batches; see the
/// module docs.
pub(crate) type EventSink = Channel<InvokeResponseBody>;

/// Serialise one event for the sink. Falling back to a synthetic `error`
/// payload keeps the channel typed even if a field somehow fails to serialise -
/// which, with only strings and integers in [`RdpEvent`], it cannot. The
/// fallback goes through `serde_json` too, so a quote in the error text cannot
/// produce a payload the frontend fails to parse.
pub(crate) fn event_body(event: &RdpEvent) -> InvokeResponseBody {
    match serde_json::to_string(event) {
        Ok(json) => InvokeResponseBody::Json(json),
        Err(e) => InvokeResponseBody::Json(
            serde_json::to_string(&RdpEvent::Error {
                message: format!("rdp: could not serialise event: {e}"),
            })
            .unwrap_or_else(|_| {
                r#"{"type":"error","message":"rdp: could not serialise event"}"#.to_owned()
            }),
        ),
    }
}

/// Dedicated runtime for RDP sessions.
///
/// Separate from `ssh_runtime()` on purpose: bitmap decode and frame encoding
/// run synchronously on the session task, so an RDP session is CPU-bound in a
/// way an SSH pump never is. Sharing a pool would let a busy desktop add
/// latency to every keystroke in every SSH tab.
fn rdp_runtime() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("tervia-rdp")
            .build()
            .expect("init rdp tokio runtime")
    })
}

pub struct RdpState {
    sessions: Arc<tokio::sync::RwLock<HashMap<u32, Arc<RdpSession>>>>,
    next_id: AtomicU32,
}

impl Default for RdpState {
    fn default() -> Self {
        Self {
            sessions: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            next_id: AtomicU32::new(1),
        }
    }
}

/// How `rdp_open` gets at the password.
///
/// Internally tagged, so a caller must pick exactly one: serde rejects a
/// payload with neither arm and cannot accept both.
///
/// The default and only path for a *saved* connection is [`Self::Keychain`]: JS
/// sends a reference, the host process reads the plaintext itself and hands it
/// straight into the CredSSP exchange. The password is never returned to, nor
/// passed in from, the webview.
///
/// This deliberately does NOT mirror the SSH module. There, `connections.ts`
/// calls `secrets_get`, which hands the plaintext back to JS, and `bridge.ts`
/// passes it down to `ssh_open` - so for SSH the secret does transit the
/// webview. The Phase 5 exit gate forbids that for RDP.
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum RdpCredential {
    /// Read the password out of the OS keychain in the host process.
    /// `service` / `account` are the same pair `secrets_get` takes, so there is
    /// one keychain key format and not two: `service` is `tervia-rdp` and
    /// `account` is whatever the frontend composes (`<connectionId>::password`,
    /// matching `keyringAccount` in `connections.ts`). The backend stays
    /// agnostic about how the account string is built, exactly as
    /// `secrets_get` does.
    Keychain { service: String, account: String },
    /// Plaintext straight from the caller.
    ///
    /// This exists for ONE case: the connection dialog's Test button, where the
    /// user has just typed a password that has not been saved to the keychain
    /// yet, so there is no reference to send. Never use it for a saved
    /// connection - that would put the secret back in the webview and defeat
    /// the whole point of [`Self::Keychain`].
    Inline { password: String },
}

// Hand-written so a stray `log::debug!("{input:?}")` - or anything else that
// formats the input, now or later - cannot print the password.
impl core::fmt::Debug for RdpCredential {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Keychain { service, account } => f
                .debug_struct("Keychain")
                .field("service", service)
                .field("account", account)
                .finish(),
            Self::Inline { .. } => f
                .debug_struct("Inline")
                .field("password", &"<redacted>")
                .finish(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RdpOpenInput {
    pub host: String,
    /// 0 is treated as the default, 3389.
    #[serde(default = "default_rdp_port")]
    pub port: u16,
    pub username: String,
    /// NetBIOS or DNS domain. Absent for a local account; a UPN
    /// (`user@domain`) can also go in `username` with this left unset.
    pub domain: Option<String>,
    /// Where the password comes from. See [`RdpCredential`].
    pub credential: RdpCredential,
    pub width: u16,
    pub height: u16,
    /// SHA-256 fingerprint of the server's leaf certificate as recorded by a
    /// previous successful connect. When set, the TLS handshake fails fast if
    /// the server presents anything else - before CredSSP sends a credential.
    /// `None` on first connect, which prompts the user instead.
    pub expected_cert_fingerprint: Option<String>,
}

fn default_rdp_port() -> u16 {
    3389
}

/// Metadata for one live session, returned by `rdp_list_sessions`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RdpSessionInfo {
    pub id: u32,
    pub host: String,
    pub username: String,
    pub desktop_width: u16,
    pub desktop_height: u16,
    pub server_fingerprint: String,
    pub alive: bool,
    pub created_at_ms: u64,
}

/// One input event from the frontend.
///
/// Deliberately close to the DOM events that produce them: `button` is
/// `MouseEvent.button`, `scancode` is a PC/AT set-1 scancode with the `0xE0`
/// prefix folded into the high byte (so `0xE04B` is the extended left arrow) -
/// which is what `KeyboardEvent.code` maps to via a static table on the
/// frontend, not something derivable from `key`.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum RdpInputEvent {
    MouseMove {
        x: u16,
        y: u16,
    },
    MouseDown {
        button: u8,
    },
    MouseUp {
        button: u8,
    },
    /// One wheel notch. `delta` is in RDP rotation units; 120 is one detent, and
    /// the sign follows RDP (positive scrolls up / left), not the DOM.
    Wheel {
        #[serde(default)]
        vertical: bool,
        delta: i16,
    },
    KeyDown {
        scancode: u16,
    },
    KeyUp {
        scancode: u16,
    },
    /// A character with no scancode - dead keys, IME output, anything a
    /// keyboard-layout table cannot express.
    UnicodeDown {
        ch: char,
    },
    UnicodeUp {
        ch: char,
    },
    /// Release every held key and button. Sent on window blur so a modifier
    /// held while focus left does not stick down on the server, which is
    /// otherwise a guaranteed bug (and the reason `Database` state has to live
    /// for the whole session).
    ReleaseAll,
}

/// One item on the wire to the session task.
///
/// `ReleaseAll` cannot be expressed as an [`Operation`]: only the task's
/// long-lived `Database` knows what is currently held. It therefore travels as
/// a marker and is expanded there, in place, so a batch that interleaves it
/// with ordinary events keeps its order.
pub(crate) enum InputOp {
    Op(Operation),
    ReleaseAll,
}

impl RdpInputEvent {
    /// Translate to a task-side input item. `None` for an event that cannot be
    /// expressed (an unknown mouse button), which is dropped rather than
    /// failing the whole batch.
    fn into_input_op(self) -> Option<InputOp> {
        Some(InputOp::Op(match self {
            Self::MouseMove { x, y } => Operation::MouseMove(MousePosition { x, y }),
            Self::MouseDown { button } => {
                Operation::MouseButtonPressed(MouseButton::from_web_button(button)?)
            }
            Self::MouseUp { button } => {
                Operation::MouseButtonReleased(MouseButton::from_web_button(button)?)
            }
            Self::Wheel { vertical, delta } => Operation::WheelRotations(WheelRotations {
                is_vertical: vertical,
                rotation_units: delta,
            }),
            Self::KeyDown { scancode } => Operation::KeyPressed(Scancode::from_u16(scancode)),
            Self::KeyUp { scancode } => Operation::KeyReleased(Scancode::from_u16(scancode)),
            Self::UnicodeDown { ch } => Operation::UnicodeKeyPressed(ch),
            Self::UnicodeUp { ch } => Operation::UnicodeKeyReleased(ch),
            Self::ReleaseAll => return Some(InputOp::ReleaseAll),
        }))
    }
}

/// Resolve the input's credential to a plaintext password.
///
/// The plaintext exists only as a Rust `String` from here until it reaches the
/// CredSSP exchange; it is never serialised, logged or handed back to JS.
fn resolve_password(
    app: &tauri::AppHandle,
    secrets: &secrets::SecretsState,
    credential: &RdpCredential,
) -> Result<String, String> {
    match credential {
        RdpCredential::Keychain { service, account } => {
            match secrets::read_secret(app, secrets, service, account)? {
                Some(password) if !password.is_empty() => Ok(password),
                // Distinguish "nothing stored" from "stored empty": both leave
                // the user unable to connect, and the fix - re-enter and save
                // the password - is the same, so one message covers it.
                _ => Err(format!(
                    "rdp: no password stored for this connection (keychain {service} / {account}). \
                     Edit the connection and re-enter it."
                )),
            }
        }
        RdpCredential::Inline { password } => Ok(password.clone()),
    }
}

#[tauri::command]
pub async fn rdp_open(
    app: tauri::AppHandle,
    state: tauri::State<'_, RdpState>,
    secrets: tauri::State<'_, secrets::SecretsState>,
    input: RdpOpenInput,
    on_event: EventSink,
) -> Result<u32, String> {
    // Read the keychain on this side of the spawn: `tauri::State` is borrowed
    // from the command invocation and cannot cross into the RDP runtime, and
    // resolving here keeps the plaintext's life as short as possible.
    let password = resolve_password(&app, &secrets, &input.credential)?;
    let rt = rdp_runtime();
    let session = rt
        .spawn(session::connect(input, password, on_event))
        .await
        .map_err(|e| format!("rdp task join failed: {e}"))?
        .map_err(|e| {
            log::error!("rdp_open failed: {e}");
            e
        })?;
    let id = state.next_id.fetch_add(1, Ordering::Relaxed);
    // Take the exit receiver before the Arc reaches the map, so the janitor
    // cannot race another caller for the slot. It fires both when the session
    // task ends on its own and when `rdp_close` aborts it (the sender is
    // dropped mid-future), so every teardown path wakes it; it no-ops on an
    // already-removed id.
    let exit_signal = session.take_exit_signal();
    let sessions = Arc::clone(&state.sessions);
    state.sessions.write().await.insert(id, session);
    if let Some(rx) = exit_signal {
        rt.spawn(async move {
            let _ = rx.await;
            sessions.write().await.remove(&id);
            log::info!("rdp session id={id} evicted after task exit");
        });
    }
    log::info!("rdp opened id={id}");
    Ok(id)
}

/// Queue a batch of input events. Batched rather than one command per event
/// because a single mouse drag produces dozens of moves per second and each IPC
/// round trip is far more expensive than the fastpath frame it produces.
///
/// **The batch size is unbounded from the caller's side.** There is a hard
/// 255-event ceiling on a single RDP fastpath PDU, but the caller does not need
/// to know the number or do the arithmetic: the session task splits the events
/// a batch produces into PDU-sized runs, in order (see `MAX_FASTPATH_EVENTS` in
/// `session.rs`). Send whatever accumulated in the frame - a 1000 Hz pointer
/// stream, a pasted line arriving as keystrokes, a `releaseAll` releasing
/// everything at once - and do not pre-chunk on the frontend. The count that
/// matters is the one the events *expand into*, which only the backend can see:
/// one `releaseAll` can become hundreds of events on its own.
#[tauri::command]
pub async fn rdp_input(
    state: tauri::State<'_, RdpState>,
    id: u32,
    events: Vec<RdpInputEvent>,
) -> Result<(), String> {
    if events.is_empty() {
        return Ok(());
    }
    let session = lookup(&state, id, "rdp_input").await?;
    let ops: Vec<InputOp> = events
        .into_iter()
        .filter_map(RdpInputEvent::into_input_op)
        .collect();
    session.send_input(ops)
}

#[tauri::command]
pub async fn rdp_close(state: tauri::State<'_, RdpState>, id: u32) -> Result<(), String> {
    let session = state.sessions.write().await.remove(&id);
    if let Some(session) = session {
        session.close().await;
        log::info!("rdp closed id={id}");
    } else {
        log::debug!("rdp_close: unknown id={id}");
    }
    Ok(())
}

#[tauri::command]
pub async fn rdp_list_sessions(
    state: tauri::State<'_, RdpState>,
) -> Result<Vec<RdpSessionInfo>, String> {
    let sessions = state.sessions.read().await;
    Ok(sessions
        .iter()
        .map(|(id, session)| session.info(*id))
        .collect())
}

/// Attach an extra event sink to a live session, so a second consumer (the
/// remote-access bridge, a detached window) mirrors it and drives input through
/// `rdp_input`.
///
/// Unlike SSH there is no byte stream to replay, so the new sink gets a
/// `connected` event and one full-framebuffer keyframe first, then the same
/// dirty-rect deltas the primary sink sees. Returns `alive`.
#[tauri::command]
pub async fn rdp_attach(
    state: tauri::State<'_, RdpState>,
    id: u32,
    on_event: EventSink,
) -> Result<bool, String> {
    let session = lookup(&state, id, "rdp_attach").await?;
    Ok(session.add_mirror_sink(on_event))
}

/// The current framebuffer as one keyframe batch, in the same wire format the
/// session channel uses.
///
/// Returned as a raw `Response`, which is the one path in this module where
/// pixels genuinely never touch JSON. The channel path is not so clean: Tauri
/// only avoids JSON for raw payloads of 1024 bytes or more
/// (`MAX_RAW_DIRECT_EXECUTE_THRESHOLD`, `tauri-2.11.5/src/ipc/channel.rs:39`).
/// Below that it serialises the bytes as a JSON number array and `eval`s
/// `new Uint8Array([...]).buffer` (channel.rs:163-167) - and a small delta like
/// a blinking text caret (~2x16 px = 128 bytes) is exactly that case, so on an
/// idle desktop most batches do go through JSON. At or above the threshold the
/// body is parked in `ChannelDataIpcQueue` and pulled back by a JS `invoke`
/// (channel.rs:169-181).
#[tauri::command]
pub async fn rdp_snapshot(state: tauri::State<'_, RdpState>, id: u32) -> Result<Response, String> {
    let session = lookup(&state, id, "rdp_snapshot").await?;
    Ok(Response::new(session.keyframe()))
}

/// Answer a first-connect `certPrompt`. `accept = true` lets the paused TLS
/// handshake proceed (and the caller pins the fingerprint on success);
/// `accept = false` aborts the connect before any credential is sent. `Err`
/// when the prompt already timed out or was answered.
#[tauri::command]
pub fn rdp_confirm_cert(prompt_id: String, accept: bool) -> Result<(), String> {
    match tls::take_pending_cert(&prompt_id) {
        Some(tx) => {
            // The verifier may already have given up waiting; ignore.
            let _ = tx.send(accept);
            Ok(())
        }
        None => Err("rdp: unknown or already-answered certificate prompt".into()),
    }
}

async fn lookup(
    state: &tauri::State<'_, RdpState>,
    id: u32,
    who: &str,
) -> Result<Arc<RdpSession>, String> {
    state
        .sessions
        .read()
        .await
        .get(&id)
        .cloned()
        .ok_or_else(|| {
            log::warn!("{who}: unknown id={id}");
            "no session".to_string()
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: &str) -> RdpInputEvent {
        serde_json::from_str(json).expect("deserialize")
    }

    /// The frontend writes these by hand, so the tags and field names are the
    /// contract.
    #[test]
    fn input_events_deserialize_from_camel_case() {
        assert!(matches!(
            parse(r#"{"kind":"mouseMove","x":10,"y":20}"#),
            RdpInputEvent::MouseMove { x: 10, y: 20 }
        ));
        assert!(matches!(
            parse(r#"{"kind":"mouseDown","button":0}"#),
            RdpInputEvent::MouseDown { button: 0 }
        ));
        assert!(matches!(
            parse(r#"{"kind":"wheel","vertical":true,"delta":-120}"#),
            RdpInputEvent::Wheel {
                vertical: true,
                delta: -120
            }
        ));
        assert!(matches!(
            parse(r#"{"kind":"keyDown","scancode":57419}"#),
            RdpInputEvent::KeyDown { scancode: 0xE04B }
        ));
        assert!(matches!(
            parse(r#"{"kind":"unicodeDown","ch":"e"}"#),
            RdpInputEvent::UnicodeDown { ch: 'e' }
        ));
        assert!(matches!(
            parse(r#"{"kind":"releaseAll"}"#),
            RdpInputEvent::ReleaseAll
        ));
    }

    /// `MouseEvent.button` numbering, straight through.
    #[test]
    fn mouse_buttons_follow_the_dom() {
        let mapped = |button: u8| {
            matches!(
                RdpInputEvent::MouseDown { button }.into_input_op(),
                Some(InputOp::Op(Operation::MouseButtonPressed(_)))
            )
        };
        for button in 0..=4u8 {
            assert!(mapped(button), "button {button} maps");
        }
        assert!(
            RdpInputEvent::MouseDown { button: 5 }
                .into_input_op()
                .is_none(),
            "an unknown button is dropped, not an error"
        );
    }

    /// An extended scancode must keep its 0xE0 flag through the round trip, or
    /// arrow keys and the right-hand modifiers arrive as their numpad twins.
    #[test]
    fn extended_scancodes_survive() {
        let Some(InputOp::Op(Operation::KeyPressed(scancode))) =
            (RdpInputEvent::KeyDown { scancode: 0xE04B }).into_input_op()
        else {
            panic!("expected a key press");
        };
        assert_eq!(scancode.as_u16(), 0xE04B);
        assert_eq!(scancode.as_u8(), (true, 0x4B));

        let Some(InputOp::Op(Operation::KeyPressed(plain))) =
            (RdpInputEvent::KeyDown { scancode: 0x001C }).into_input_op()
        else {
            panic!("expected a key press");
        };
        assert_eq!(plain.as_u16(), 0x001C);
        assert_eq!(plain.as_u8(), (false, 0x1C));
    }

    /// A batch keeps its order, drops only what it cannot express, and passes
    /// the `releaseAll` marker through for the task to expand in place.
    #[test]
    fn batches_preserve_order() {
        let ops: Vec<InputOp> = vec![
            RdpInputEvent::MouseMove { x: 1, y: 2 },
            RdpInputEvent::MouseDown { button: 99 },
            RdpInputEvent::KeyDown { scancode: 0x1C },
            RdpInputEvent::ReleaseAll,
            RdpInputEvent::KeyUp { scancode: 0x1C },
        ]
        .into_iter()
        .filter_map(RdpInputEvent::into_input_op)
        .collect();

        assert_eq!(ops.len(), 4, "only the bogus button is dropped");
        assert!(matches!(ops[0], InputOp::Op(Operation::MouseMove(_))));
        assert!(matches!(ops[1], InputOp::Op(Operation::KeyPressed(_))));
        assert!(matches!(ops[2], InputOp::ReleaseAll));
        assert!(matches!(ops[3], InputOp::Op(Operation::KeyReleased(_))));
    }

    #[test]
    fn open_input_defaults_the_port() {
        let input: RdpOpenInput = serde_json::from_str(
            r#"{"host":"win.example.com","username":"admin",
                "credential":{"kind":"keychain","service":"tervia-rdp","account":"c1::password"},
                "width":1280,"height":800}"#,
        )
        .expect("deserialize");
        assert_eq!(input.port, 3389);
        assert!(input.domain.is_none());
        assert!(input.expected_cert_fingerprint.is_none());
    }

    /// The saved-connection path: JS sends a reference, never a secret.
    #[test]
    fn credential_reference_deserializes() {
        let credential: RdpCredential = serde_json::from_str(
            r#"{"kind":"keychain","service":"tervia-rdp","account":"c1::password"}"#,
        )
        .expect("deserialize");
        let RdpCredential::Keychain { service, account } = credential else {
            panic!("expected a keychain reference");
        };
        assert_eq!(service, "tervia-rdp");
        // Same `<id>::<field>` shape `keyringAccount` builds in connections.ts,
        // so there is one keychain key format across SSH and RDP.
        assert_eq!(account, "c1::password");
    }

    /// The escape hatch, for the dialog's Test button only.
    #[test]
    fn inline_credential_deserializes() {
        let credential: RdpCredential =
            serde_json::from_str(r#"{"kind":"inline","password":"draft"}"#).expect("deserialize");
        assert!(matches!(credential, RdpCredential::Inline { .. }));
    }

    /// A caller must pick exactly one arm. An internally-tagged enum makes
    /// "neither" and "both" unrepresentable rather than something the backend
    /// has to police at runtime.
    #[test]
    fn credential_requires_exactly_one_form() {
        assert!(
            serde_json::from_str::<RdpCredential>(r#"{"password":"p"}"#).is_err(),
            "an untagged payload is rejected"
        );
        assert!(
            serde_json::from_str::<RdpCredential>(r#"{"kind":"keychain"}"#).is_err(),
            "a keychain reference without service/account is rejected"
        );
        assert!(
            serde_json::from_str::<RdpCredential>(
                r#"{"kind":"inline","password":"p","service":"s","account":"a"}"#
            )
            .is_ok(),
            "extra keys are ignored, but the tag still selects exactly one arm"
        );
        // Missing entirely is rejected at the RdpOpenInput level.
        assert!(
            serde_json::from_str::<RdpOpenInput>(
                r#"{"host":"h","username":"u","width":1,"height":1}"#
            )
            .is_err(),
            "a connect with no credential at all is rejected"
        );
    }

    /// A stray `{input:?}` must never print the password. `RdpOpenInput`
    /// derives Debug, so this is one careless log line away from being real.
    #[test]
    fn debug_never_leaks_the_password() {
        let inline = format!(
            "{:?}",
            RdpCredential::Inline {
                password: "hunter2-correct-horse".into()
            }
        );
        assert!(!inline.contains("hunter2"), "got: {inline}");
        assert!(inline.contains("<redacted>"));

        let input = RdpOpenInput {
            host: "win.example.com".into(),
            port: 3389,
            username: "admin".into(),
            domain: None,
            credential: RdpCredential::Inline {
                password: "hunter2-correct-horse".into(),
            },
            width: 1280,
            height: 800,
            expected_cert_fingerprint: None,
        };
        let rendered = format!("{input:?}");
        assert!(!rendered.contains("hunter2"), "got: {rendered}");

        // A reference carries no secret, so it prints in full - that is the
        // point of preferring it.
        let reference = format!(
            "{:?}",
            RdpCredential::Keychain {
                service: "tervia-rdp".into(),
                account: "c1::password".into(),
            }
        );
        assert!(reference.contains("tervia-rdp"));
        assert!(reference.contains("c1::password"));
    }

    #[test]
    fn event_body_is_json() {
        let body = event_body(&RdpEvent::Resize {
            width: 640,
            height: 480,
        });
        match body {
            InvokeResponseBody::Json(json) => {
                assert_eq!(json, r#"{"type":"resize","width":640,"height":480}"#);
            }
            InvokeResponseBody::Raw(_) => panic!("events must go as JSON, frames as raw"),
        }
    }
}
