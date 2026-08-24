//! One RDP session: the connect sequence and the active-stage task.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ironrdp_connector::connection_activation::{
    ConnectionActivationSequence, ConnectionActivationState,
};
use ironrdp_connector::sspi::generator::NetworkRequest;
use ironrdp_connector::{
    ClientConnector, Config, ConnectionResult, ConnectorError, ConnectorErrorExt as _,
    ConnectorErrorKind, ConnectorResult, Credentials, DesktopSize,
};
use ironrdp_core::WriteBuf;
use ironrdp_graphics::image_processing::PixelFormat;
use ironrdp_input::{Database, Operation};
use ironrdp_pdu::gcc::KeyboardType;
use ironrdp_pdu::rdp::capability_sets::MajorPlatformType;
use ironrdp_pdu::rdp::client_info::{PerformanceFlags, TimezoneInfo};
use ironrdp_session::image::DecodedImage;
use ironrdp_session::{fast_path, ActiveStage, ActiveStageOutput, SessionError};
use ironrdp_tokio::bytes::BytesMut;
use ironrdp_tokio::{FramedWrite as _, NetworkClient, TokioFramed};
use serde::Serialize;
use tauri::ipc::InvokeResponseBody;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::modules::lockext::LockExt as _;

use super::frame::{
    self, encode_batch, Batch, FrameBatcher, FrameBuffer, FrameTransport, Rect, TransportGone,
    HEADER_LEN,
};
use super::tls;
use super::{event_body, EventSink, InputOp, RdpOpenInput, RdpSessionInfo};

type TlsFramed = TokioFramed<tokio_rustls::client::TlsStream<TcpStream>>;

/// TCP connect budget. Deliberately the same order as the SSH module's.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
/// Budget for each of the three handshake legs (X.224, TLS, CredSSP + MCS +
/// capability exchange). Generous because CredSSP is several round trips and a
/// licence exchange can be slow on a first connect to a fresh host.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(45);
/// Dirty-rect coalescing window, ~60 Hz. Short enough that interactive latency
/// is not noticeable, long enough that a burst of small updates ships as one
/// batch rather than one IPC message each.
const FLUSH_WINDOW: Duration = Duration::from_millis(16);

/// Maximum input events in one fastpath PDU. **Do not remove the chunking this
/// feeds; it is not an optimisation.**
///
/// `FastPathInput::new` rejects any slice outside `1..=255`
/// (`ironrdp-pdu-0.8.0/src/input/fast_path.rs:284-290`) because `nEvents` is a
/// single byte on the wire, and `ActiveStage::process_fastpath_input` calls it
/// on the whole slice unconditionally and propagates the error
/// (`ironrdp-session-0.10.0/src/active_stage.rs:104`). The session task treats
/// that as fatal, so an over-long batch would not drop input - it would emit
/// `error` + `disconnected` and take the tab down.
///
/// This is reachable from ordinary use, with no attacker and no bug on the
/// frontend's side:
///
/// * a drag of 256 moves in one batch - a 1000 Hz `pointerrawupdate` with the
///   webview's main thread stalled ~300 ms gets there without trying;
/// * 128 characters pasted as keystrokes, which is 256
///   `unicodeDown`/`unicodeUp` events;
/// * a single `releaseAll`, on its own: `Database::release_all` walks a 512-bit
///   keyboard array plus five mouse buttons and appends every held one to the
///   same vector (`ironrdp-input-0.6.0/src/lib.rs:351-381`).
///
/// Chunking has to happen on the *emitted* `FastPathInputEvent`s rather than on
/// the incoming operations: `Database::apply` emits zero, one or two events per
/// operation, so bounding the operation count would not bound this.
const MAX_FASTPATH_EVENTS: usize = 255;

/// Process the server's pointer updates rather than dropping them, and
/// composite the cursor into the framebuffer instead of emitting bitmaps.
///
/// **This pair deliberately differs from the 5a spike, which used
/// `enable_server_pointer: false`.** With that value
/// `fast_path::Processor::process_pointer_update` returns immediately for every
/// pointer PDU, and the `Pointer` capability set is advertised with a non-zero
/// cache size regardless - so the server keeps sending the cursor out of band
/// and IronRDP throws it away. The result is a desktop with no cursor at all,
/// not a server-composited one. `true` + `true` is what actually gets the
/// behaviour the MVP needs: `image.update_pointer` / `image.move_pointer`
/// composite the cursor into the framebuffer and report the affected region as
/// an ordinary `GraphicsUpdate`, so no `pointerBitmap` rendering is needed on
/// the frontend (that is RDP-12, deferred). Upstream `ironrdp-client` defaults
/// to `enable_server_pointer: true` for the same reason; it pairs it with
/// software rendering off only because it has a native cursor to hand the
/// bitmap to, which a webview does not.
const ENABLE_SERVER_POINTER: bool = true;
const POINTER_SOFTWARE_RENDERING: bool = true;

/// Events pushed to the frontend over the session's IPC channel as JSON.
///
/// Frame batches travel on the *same* channel as `InvokeResponseBody::Raw`, so
/// the frontend distinguishes the two by payload type: an `ArrayBuffer` is a
/// frame batch (see `frame.rs` for the layout), anything else is one of these.
///
/// `rename_all` camelCases the variant *tags*; `rename_all_fields` is what
/// camelCases the fields inside struct variants. Both are load-bearing - the
/// SSH module lost a whole confirmation dialog to the missing second one.
#[derive(Serialize, Clone, Debug)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum RdpEvent {
    /// The connect sequence reached the active stage. Also re-sent to a sink
    /// that arrives later via `rdp_attach`, immediately before its keyframe.
    Connected {
        desktop_width: u16,
        desktop_height: u16,
        server_fingerprint: String,
    },
    /// First-connect certificate confirmation request, emitted from inside the
    /// TLS handshake - so before CredSSP, i.e. before any credential is sent.
    /// The handshake blocks until the frontend answers with
    /// `rdp_confirm_cert(promptId, accept)`; rejecting aborts the connect.
    CertPrompt {
        prompt_id: String,
        fingerprint: String,
        host: String,
        subject: String,
        issuer: String,
    },
    /// The server changed the desktop size (Deactivation-Reactivation). The
    /// framebuffer has been rebuilt at this size and is blank; the server
    /// repaints it, so the next frames arrive as ordinary deltas.
    Resize { width: u16, height: u16 },
    /// Show the platform's default cursor.
    PointerDefault,
    /// Hide the cursor entirely.
    PointerHidden,
    /// Server-initiated cursor warp.
    PointerPosition { x: u16, y: u16 },
    /// The session ended, for this reason. Always the last event, on every
    /// path: a remote hangup, a fault, and a local `rdp_close` all emit it
    /// (`close` sends it before aborting the task, since the abort means the
    /// task's own tail never runs). Treat it as idempotent - a local close
    /// racing a remote hangup can deliver two.
    Disconnected { reason: String },
    /// Something went wrong. Followed by `disconnected` when it was fatal.
    Error { message: String },
}

/// CredSSP only reaches for the network on Kerberos KDC round-trips. Tervia
/// passes `None` for `KerberosConfig`, so NTLM is the only mechanism and this
/// is never called. Kept as an explicit refusal rather than a silent stub so a
/// future Kerberos change fails loudly instead of hanging.
struct NoNetworkClient;

impl NetworkClient for NoNetworkClient {
    async fn send(&mut self, request: &NetworkRequest) -> ConnectorResult<Vec<u8>> {
        log::warn!(
            "rdp: CredSSP asked for a KDC round-trip ({:?}); Kerberos is not implemented",
            request.protocol
        );
        Err(ConnectorError::general(
            "rdp: Kerberos is not supported; NTLM should never need a KDC network client",
        ))
    }
}

/// Push transport: encode on the session task, hand the bytes straight to the
/// IPC channel. The only [`FrameTransport`] impl today; see the trait's docs
/// for what a pull model (RDP-01) would replace.
struct ChannelTransport {
    primary: EventSink,
    mirrors: Arc<Mutex<Vec<EventSink>>>,
}

impl FrameTransport for ChannelTransport {
    /// One owned copy of the batch per sink, which is Tauri's floor and not a
    /// missed optimisation: `InvokeResponseBody::Raw` owns a `Vec<u8>`, and
    /// under the 1024-byte threshold the channel `eval`s it while at or above it
    /// the body is parked in `ChannelDataIpcQueue` as its own map entry - so
    /// there is no point in the API where an `Arc` could be shared. The
    /// original is moved into the last send rather than cloned, so N sinks cost
    /// exactly N buffers. `MAX_MIRROR_SINKS` is what bounds the total, and it is
    /// deliberately low for this reason.
    ///
    /// `Err(TransportGone)` is **currently unreachable**. `Channel::send`
    /// returns `Ok` on both paths whether or not the frontend ever collects the
    /// payload - the queued path's JS side is `.catch(console.error)`
    /// (channel.rs:178) and never reports back - so this is not a liveness
    /// signal and the caller must not treat it as backpressure. Kept because it
    /// is the right shape for the seam and a pull transport (RDP-01) would have
    /// a real answer here.
    fn deliver(&mut self, bytes: Vec<u8>) -> Result<(), TransportGone> {
        {
            // Prune sinks whose channel has closed, exactly as the SSH pump's
            // fan does, so dead mirrors do not cost a copy per frame forever.
            let mut mirrors = self.mirrors.lock_or_recover();
            mirrors.retain(|sink| sink.send(InvokeResponseBody::Raw(bytes.clone())).is_ok());
        }
        self.primary
            .send(InvokeResponseBody::Raw(bytes))
            .map_err(|_| TransportGone)
    }
}

/// Shared handles the session task and the command layer both touch.
struct Shared {
    /// The authoritative framebuffer. Shared rather than task-private so
    /// `rdp_attach` / `rdp_snapshot` can take a keyframe without a round trip
    /// through the task. Every critical section is pure CPU work with no await
    /// inside it, so a plain `std::sync::Mutex` is correct here.
    image: Mutex<DecodedImage>,
    /// Extra event sinks (the remote-access bridge / a second view).
    mirrors: Arc<Mutex<Vec<EventSink>>>,
    /// Live desktop size, updated on reactivation.
    dims: Mutex<(u16, u16)>,
    alive: AtomicBool,
}

pub struct RdpSession {
    /// Batched input, drained by the session task. The task owns the
    /// `ironrdp_input::Database` because it holds key/button state and
    /// suppresses no-op transitions, so it must be one long-lived instance per
    /// session rather than rebuilt per command.
    input_tx: mpsc::UnboundedSender<Vec<InputOp>>,
    /// The active-stage task. Aborted on close.
    task: tokio::sync::Mutex<Option<JoinHandle<()>>>,
    /// Fires when the task exits, by `send` on a normal end or by the sender
    /// dropping on abort. Taken once by `rdp_open` to drive the janitor that
    /// evicts the id from `RdpState`.
    exit_signal: Mutex<Option<oneshot::Receiver<()>>>,
    shared: Arc<Shared>,
    /// The GUI's own sink. Held so `close` can emit the final `disconnected`
    /// itself: aborting the task means `run`'s tail never executes, so without
    /// this a locally-closed session would end silently and the documented
    /// "`disconnected` is always the last event" would be false for mirrors,
    /// which have no other way to learn the session is gone.
    primary: EventSink,
    host: String,
    username: String,
    /// SHA-256 fingerprint the server actually presented. The frontend persists
    /// this on the saved connection and passes it back as
    /// `expectedCertFingerprint` on every later connect.
    fingerprint: String,
    created_at_ms: u64,
}

impl RdpSession {
    /// Queue a batch of input operations. `Err` once the session task is gone.
    pub fn send_input(&self, ops: Vec<InputOp>) -> Result<(), String> {
        if ops.is_empty() {
            return Ok(());
        }
        self.input_tx
            .send(ops)
            .map_err(|_| "rdp: session is closed".to_string())
    }

    /// Encode the current framebuffer as a full keyframe batch. Backs both
    /// `rdp_snapshot` and the keyframe a fresh `rdp_attach` gets: unlike SSH
    /// there is no byte stream to replay, so a new consumer needs one whole
    /// frame before deltas mean anything.
    ///
    /// Empty when there is no framebuffer to describe, rather than a
    /// `rectCount == 0` header the wire format tells the reader to treat as
    /// corrupt. Unreachable while `connect` refuses a zero desktop size, but
    /// this is the same guard `flush` carries and the two should not disagree.
    pub fn keyframe(&self) -> Vec<u8> {
        self.keyframe_with_dims().0
    }

    /// The keyframe plus the dimensions it describes, read under one lock so
    /// the two cannot disagree - `Shared::dims` and the framebuffer are updated
    /// in sequence during a reactivation, not atomically.
    fn keyframe_with_dims(&self) -> (Vec<u8>, u16, u16) {
        let image = self.shared.image.lock_or_recover();
        let (width, height) = (image.width(), image.height());
        let bytes = encode_batch(
            FrameBuffer {
                data: image.data(),
                width,
                height,
            },
            &Batch::keyframe(width, height),
        );
        if bytes.len() <= HEADER_LEN {
            return (Vec::new(), width, height);
        }
        (bytes, width, height)
    }

    /// Register an extra sink and prime it with `connected` plus a full
    /// keyframe, after which it sees the same deltas the primary does.
    /// Returns whether the session is still live.
    pub fn add_mirror_sink(&self, sink: EventSink) -> bool {
        // The mirror list is taken FIRST and held across the priming sends, so
        // a batch the session task delivers in between cannot slip past the
        // keyframe and leave this sink permanently stale in that region.
        //
        // That means holding `mirrors` while `keyframe()` takes `image`, which
        // is only safe because the session task never does the reverse: it
        // encodes under `image`, releases it, and only then fans out under
        // `mirrors` (see `flush` and `run`'s `emit`). Keep it that way or this
        // becomes a lock-order inversion.
        let mut mirrors = self.shared.mirrors.lock_or_recover();
        let (keyframe, width, height) = self.keyframe_with_dims();
        let _ = sink.send(event_body(&RdpEvent::Connected {
            desktop_width: width,
            desktop_height: height,
            server_fingerprint: self.fingerprint.clone(),
        }));
        if !keyframe.is_empty() {
            let _ = sink.send(InvokeResponseBody::Raw(keyframe));
        }
        // Bound the live sink count: a buggy caller could call rdp_attach in a
        // loop, and every extra sink costs a full owned copy of every batch.
        // Evict the oldest.
        while mirrors.len() >= MAX_MIRROR_SINKS {
            mirrors.remove(0);
        }
        mirrors.push(sink);
        drop(mirrors);
        self.shared.alive.load(Ordering::Acquire)
    }

    pub fn dims(&self) -> (u16, u16) {
        *self.shared.dims.lock_or_recover()
    }

    /// Snapshot for `rdp_list_sessions`. `id` is owned by `RdpState`, so the
    /// caller fills it in.
    pub fn info(&self, id: u32) -> RdpSessionInfo {
        let (desktop_width, desktop_height) = self.dims();
        RdpSessionInfo {
            id,
            host: self.host.clone(),
            username: self.username.clone(),
            desktop_width,
            desktop_height,
            server_fingerprint: self.fingerprint.clone(),
            alive: self.shared.alive.load(Ordering::Acquire),
            created_at_ms: self.created_at_ms,
        }
    }

    pub fn take_exit_signal(&self) -> Option<oneshot::Receiver<()>> {
        self.exit_signal.lock_or_recover().take()
    }

    /// End the session. Aborting the task drops the TLS stream, which closes
    /// the TCP connection; the server then treats the RDP session as
    /// *disconnected* rather than logged off, which is what every other RDP
    /// client does on window close. A graceful `ShutdownRequest` would need a
    /// round trip and is not worth blocking a tab close on.
    ///
    /// The `disconnected` event is emitted HERE, before the abort, because
    /// aborting means `run`'s tail never runs. The caller of `rdp_close` already
    /// knows it closed the session, but attached mirrors do not, and they have
    /// no other way to find out.
    pub async fn close(self: Arc<Self>) {
        self.shared.alive.store(false, Ordering::Release);
        self.emit_all(&RdpEvent::Disconnected {
            reason: "closed by the client".to_owned(),
        });
        if let Some(task) = self.task.lock().await.take() {
            task.abort();
        }
    }

    /// Fan an event to the primary sink and every mirror, pruning dead ones.
    /// Mirrors `run`'s own `emit`; kept as a method so `close` can use it after
    /// the task is gone.
    fn emit_all(&self, event: &RdpEvent) {
        let body = event_body(event);
        let _ = self.primary.send(body.clone());
        let mut mirrors = self.shared.mirrors.lock_or_recover();
        mirrors.retain(|mirror| mirror.send(body.clone()).is_ok());
    }
}

impl Drop for RdpSession {
    fn drop(&mut self) {
        // Last-resort cleanup when the frontend hung up without calling
        // rdp_close.
        if let Ok(mut guard) = self.task.try_lock() {
            if let Some(task) = guard.take() {
                task.abort();
            }
        }
    }
}

/// Idle time before the kernel starts probing, and the gap between probes.
///
/// An RDP session is almost entirely server-driven: the task sits in
/// `read_pdu()`, and the only writes are responses to server PDUs or user input.
/// So if the network dies silently there is nothing to fail against - no write
/// to error, no FIN to read - and `read_pdu()` simply never returns. The session
/// then hangs with no `disconnected`, and `rdp_list_sessions` keeps reporting
/// `alive: true`. Kernel keepalive is what turns that into a read error.
///
/// `30s` idle matches the SSH module's `KEEPALIVE` (`ssh/session.rs`), which
/// exists for the same failure. With `10s` probes and the platform default
/// retry count, a dead peer surfaces in roughly a minute.
const KEEPALIVE_IDLE: Duration = Duration::from_secs(30);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);

/// Live mirror sinks per session. Low because Tauri's channel API needs an
/// owned `Vec<u8>` per sink (see `ChannelTransport::deliver`), so each extra
/// mirror is a full copy of every batch - up to one framebuffer.
const MAX_MIRROR_SINKS: usize = 4;

/// Turn on kernel TCP keepalive with a usable idle time.
///
/// tokio only offers `TcpSocket::set_keepalive(bool)`, which enables
/// SO_KEEPALIVE at the OS default idle - 7200 s on Linux - so it would satisfy
/// the letter of "keepalive is on" while leaving a dead session undetected for
/// two hours. Setting `TCP_KEEPIDLE`/`TCP_KEEPINTVL` needs socket2.
fn set_keepalive(tcp: &TcpStream) -> std::io::Result<()> {
    let params = socket2::TcpKeepalive::new()
        .with_time(KEEPALIVE_IDLE)
        .with_interval(KEEPALIVE_INTERVAL);
    socket2::SockRef::from(tcp).set_tcp_keepalive(&params)
}

/// Flatten an error's `Display` and its whole `source()` chain into one line.
///
/// This is not cosmetic. `ironrdp`'s error types print only the *kind*, and the
/// kind that matters most throws its cause away: `ConnectorErrorKind::Credssp(_)`
/// renders as the bare word `"CredSSP"` (`ironrdp-connector` lib.rs:358) and
/// hides the entire `sspi::Error` behind `source()`. An NLA failure - wrong
/// password, disabled account, no Remote Desktop Users membership, by far the
/// most likely thing a user hits - would otherwise reach the UI as one useless
/// word.
///
/// `ironrdp_error::Error::report()` walks the chain too, but prefixes the
/// crate's own `file:line`, which is noise in a user-visible string.
fn flatten(
    head: &dyn core::fmt::Display,
    source: Option<&(dyn core::error::Error + 'static)>,
) -> String {
    let mut out = head.to_string();
    let mut next = source;
    while let Some(err) = next {
        let text = err.to_string();
        // Some kinds already embed their cause (Negotiation does), so a naive
        // walk would print it twice.
        if !text.is_empty() && !out.contains(&text) {
            out.push_str(": ");
            out.push_str(&text);
        }
        next = err.source();
    }
    out
}

/// Turn a connect-sequence failure into something a user can act on.
///
/// `NegotiationFailure` gets explicit remediation because it is the most
/// actionable failure class in RDP: it is the server stating exactly which
/// security protocol it wanted. `ConnectorErrorKind` is `#[non_exhaustive]`,
/// hence the wildcard.
fn connect_error(context: &str, err: &ConnectorError) -> String {
    use ironrdp_pdu::nego::FailureCode;

    let base = format!(
        "{context}: {}",
        flatten(err.kind(), core::error::Error::source(err))
    );
    let ConnectorErrorKind::Negotiation(failure) = err.kind() else {
        return base;
    };
    let advice = match failure.code() {
        // We asked for HYBRID (NLA) and the server only speaks Standard RDP
        // Security. Refusing is deliberate - see `build_config`.
        FailureCode::SSL_NOT_ALLOWED_BY_SERVER => {
            "Tervia requires Network Level Authentication and will not fall back to Standard \
             RDP Security, which authenticates only after the session is already up. Enable NLA \
             on the server (System Properties -> Remote -> \"Allow connections only from \
             computers running Remote Desktop with Network Level Authentication\")."
        }
        FailureCode::SSL_CERT_NOT_ON_SERVER => {
            "The server has no usable TLS certificate. On Windows this usually means the Remote \
             Desktop Configuration service could not create its self-signed certificate; \
             restarting that service normally fixes it."
        }
        FailureCode::SSL_REQUIRED_BY_SERVER | FailureCode::HYBRID_REQUIRED_BY_SERVER => {
            "This should not happen - Tervia already requests CredSSP - so it usually means a \
             middlebox or gateway rewrote the negotiation."
        }
        FailureCode::SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER => {
            "The server wants certificate-based client authentication, which Tervia does not \
             implement."
        }
        _ => return base,
    };
    format!("{base}. {advice}")
}

/// Same flattening for an active-stage failure.
fn session_error(context: &str, err: &SessionError) -> String {
    format!(
        "{context}: {}",
        flatten(err.kind(), core::error::Error::source(err))
    )
}

/// Connector configuration.
///
/// `enable_tls: false` + `enable_credssp: true` refuses to fall back to the
/// legacy "TLS only" security protocol, which would put the server in graphical
/// login mode with every static channel joined before authentication - a much
/// wider attack surface (see `ironrdp_connector::Config::enable_tls`). NLA or
/// nothing.
/// `password` arrives already resolved (from the OS keychain, or inline for an
/// unsaved draft) so this module never has to know where secrets live.
fn build_config(input: &RdpOpenInput, password: &str) -> Config {
    Config {
        desktop_size: DesktopSize {
            width: input.width,
            height: input.height,
        },
        desktop_scale_factor: 0,
        enable_tls: false,
        enable_credssp: true,
        credentials: Credentials::UsernamePassword {
            username: input.username.clone(),
            password: password.to_owned(),
        },
        domain: input.domain.clone(),
        client_build: 0,
        // Truncated to 15 characters by the connector.
        client_name: "Tervia".to_owned(),
        keyboard_type: KeyboardType::IbmEnhanced,
        keyboard_subtype: 0,
        keyboard_functional_keys_count: 12,
        keyboard_layout: 0,
        ime_file_name: String::new(),
        bitmap: None,
        dig_product_id: String::new(),
        client_dir: "C:\\Windows\\System32\\mstscax.dll".to_owned(),
        alternate_shell: String::new(),
        work_dir: String::new(),
        platform: MajorPlatformType::UNIX,
        hardware_id: None,
        // `None` makes the connector fill the X.224 Connection Request with
        // `NegoRequestData::cookie(username)` (`ironrdp-connector-0.9.0`
        // connection.rs:270-277). That cookie goes out on plain TCP inside
        // `connect_begin`, i.e. before TLS and therefore before the certificate
        // check. Kept deliberately: `mstsc` sends it and RD Connection Broker
        // routes on it, so suppressing it would be a real interop regression to
        // buy a small disclosure. See the note on `connect` about exactly what
        // does and does not cross the wire before the certificate is verified.
        request_data: None,
        autologon: false,
        enable_audio_playback: false,
        performance_flags: PerformanceFlags::default(),
        license_cache: None,
        timezone_info: TimezoneInfo::default(),
        // No bulk compression: it costs CPU on a link that is already carrying
        // a compressed bitmap codec, and RDP-02 (a wire encoder for our own
        // frame batches) is the lever that actually matters here.
        compression_type: None,
        enable_server_pointer: ENABLE_SERVER_POINTER,
        pointer_software_rendering: POINTER_SOFTWARE_RENDERING,
        multitransport_flags: None,
    }
}

/// Run the whole connect sequence and hand back a live session.
///
/// Ordering matters: `connect_begin` stops as soon as the connector wants the
/// security upgrade, i.e. before any TLS exists. The certificate check then
/// happens inside the TLS handshake, and only after it passes does
/// `connect_finalize` run CredSSP.
///
/// # What crosses the wire before the certificate is verified
///
/// Precisely one thing: the **username**, as the X.224 Connection Request
/// cookie, on plain TCP inside `connect_begin` (see `request_data` in
/// `build_config`). So a first-connect man-in-the-middle that the user then
/// rejects still learns the account name.
///
/// What does **not** cross: the password, and the NTLM exchange that would
/// expose a crackable NetNTLMv2 response. Both live inside `connect_finalize`,
/// which runs only after `verify_server_cert` has returned `Ok`. That is the
/// property the certificate check buys, and it is worth being exact about
/// rather than claiming "no credential of any kind", which is not true.
pub async fn connect(
    input: RdpOpenInput,
    password: String,
    sink: EventSink,
) -> Result<Arc<RdpSession>, String> {
    let host = input.host.trim().to_owned();
    if host.is_empty() {
        return Err("rdp: no host given".into());
    }
    if input.username.trim().is_empty() {
        return Err("rdp: no username given".into());
    }
    if input.width == 0 || input.height == 0 {
        return Err("rdp: desktop size must be non-zero".into());
    }
    let port = if input.port == 0 { 3389 } else { input.port };

    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host.as_str(), port)))
        .await
        .map_err(|_| format!("rdp: connect to {host}:{port} timed out"))?
        .map_err(|e| format!("rdp: tcp connect to {host}:{port} failed: {e}"))?;
    // Input latency is the whole product here; a 40 ms Nagle delay on a
    // single keystroke fastpath frame is not acceptable.
    if let Err(e) = tcp.set_nodelay(true) {
        log::warn!("rdp: could not disable Nagle on {host}:{port}: {e}");
    }
    if let Err(e) = set_keepalive(&tcp) {
        // Not fatal: the session works, it just will not notice a silently
        // dropped network until something tries to write.
        log::warn!("rdp: could not enable TCP keepalive on {host}:{port}: {e}");
    }
    let client_addr = tcp
        .local_addr()
        .map_err(|e| format!("rdp: reading local address failed: {e}"))?;

    let mut framed = TokioFramed::new(tcp);
    let mut connector = ClientConnector::new(build_config(&input, &password), client_addr);
    // The plaintext now lives only inside the connector's `Credentials`, on its
    // way to CredSSP. Drop our copy.
    drop(password);

    let should_upgrade = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        ironrdp_tokio::connect_begin(&mut framed, &mut connector),
    )
    .await
    .map_err(|_| format!("rdp: X.224 negotiation with {host}:{port} timed out"))?
    .map_err(|e| connect_error("rdp: security negotiation failed", &e))?;

    // Hand the raw TCP stream over.
    //
    // `into_inner_no_leftover()` would be the idiomatic call here, but it checks
    // for leftover bytes with a `debug_assert_eq!` (`ironrdp-async` framed.rs:86)
    // - so a RELEASE build silently discards anything still buffered and
    // desyncs the TLS record stream, which then surfaces as a random-looking
    // handshake failure. Check it ourselves and fail with something readable.
    // In practice this is unreachable: the connector guarantees the buffer is
    // drained at exactly this handoff point, which is the only place this may
    // be called.
    let (tcp, leftover) = framed.into_inner();
    if !leftover.is_empty() {
        return Err(format!(
            "rdp: the server sent {} unexpected byte(s) before the TLS upgrade; \
             refusing to continue rather than desync the TLS stream",
            leftover.len()
        ));
    }

    let (verifier, report, prompt_id, needs_confirm) = tls::build_verifier(
        input.expected_cert_fingerprint.clone(),
        sink.clone(),
        host.clone(),
    );
    // A first connect can park inside the verifier waiting on the dialog, so it
    // gets the confirmation window on top of the handshake budget. The timeout
    // cannot actually cut that park short - the verifier is synchronous, so
    // this future is not being polled while it blocks - but it still bounds a
    // server that stalls the handshake itself, and `CERT_CONFIRM_TIMEOUT`
    // bounds the park from the inside.
    let tls_budget = if needs_confirm {
        HANDSHAKE_TIMEOUT + tls::CERT_CONFIRM_TIMEOUT
    } else {
        HANDSHAKE_TIMEOUT
    };
    let upgraded_tls =
        match tokio::time::timeout(tls_budget, tls::upgrade(tcp, &host, verifier)).await {
            Err(_) => {
                tls::drop_pending_cert(&prompt_id);
                return Err(format!("rdp: TLS handshake with {host}:{port} timed out"));
            }
            Ok(Err(e)) => {
                tls::drop_pending_cert(&prompt_id);
                return Err(tls::upgrade_error(&report, e));
            }
            Ok(Ok(tls)) => tls,
        };
    // The verifier ran (or the handshake would have failed), so nothing is left
    // parked; this only matters for the paths above.
    tls::drop_pending_cert(&prompt_id);

    let negotiated = ironrdp_tls::negotiated(&upgraded_tls);
    log::info!(
        "rdp: TLS up to {host}:{port} version={:?} suite={:?}",
        negotiated.version,
        negotiated.cipher_suite
    );

    let leaf_der = upgraded_tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|chain| chain.first())
        .ok_or_else(|| "rdp: server presented no certificate".to_string())?
        .to_vec();
    // CredSSP binds to the server's SubjectPublicKey, not to the whole
    // certificate, so this is a separate extraction from the fingerprint. The
    // parse cannot fail here: the verifier already parsed the same DER and
    // refused the connection if it would not, specifically so a user is never
    // asked to confirm a certificate that is about to be rejected anyway.
    let server_public_key = {
        use x509_cert::der::Decode as _;
        let cert = x509_cert::Certificate::from_der(&leaf_der)
            .map_err(|e| format!("rdp: parsing the server certificate failed: {e}"))?;
        ironrdp_tls::extract_tls_server_public_key(&cert)
            .ok_or_else(|| {
                "rdp: the server certificate's subject public key is not byte-aligned".to_string()
            })?
            .to_vec()
    };
    let fingerprint = report
        .lock_or_recover()
        .seen
        .clone()
        .unwrap_or_else(|| tls::fingerprint_sha256(&leaf_der));

    // `mark_as_upgraded` is an `assert!` on the connector being in
    // `EnhancedSecurityUpgrade` (`ironrdp-connector` connection.rs:183), and
    // with `panic = "abort"` in release an assert takes the whole app down
    // rather than failing one tab. `connect_begin` loops until that state is
    // reached and nothing since has stepped the connector, so this is
    // unreachable - it is here so a future reordering fails a connect instead
    // of the process.
    if !connector.should_perform_security_upgrade() {
        return Err(
            "rdp: the connector is not expecting a security upgrade; refusing to continue".into(),
        );
    }
    let upgraded = ironrdp_tokio::mark_as_upgraded(should_upgrade, &mut connector);
    let mut framed: TlsFramed = TokioFramed::new(upgraded_tls);

    let result = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        ironrdp_tokio::connect_finalize(
            upgraded,
            connector,
            &mut framed,
            &mut NoNetworkClient,
            host.as_str().into(),
            server_public_key,
            // No KerberosConfig: NTLM only. See NoNetworkClient.
            None,
        ),
    )
    .await
    .map_err(|_| format!("rdp: authentication with {host}:{port} timed out"))?
    .map_err(|e| connect_error("rdp: authentication failed", &e))?;

    // The server's size, not ours - it is free to disagree with what we asked
    // for. A zero in either axis has to be refused here: `DecodedImage::new`
    // would happily build an empty framebuffer, nothing would panic, and the
    // session would sit at `alive: true` forever delivering no frames while
    // `keyframe()` emitted a `rectCount == 0` header that the wire format tells
    // the frontend to treat as corrupt. Failing the connect says what happened.
    let (width, height) = (result.desktop_size.width, result.desktop_size.height);
    if width == 0 || height == 0 {
        return Err(format!(
            "rdp: {host}:{port} reported an unusable desktop size of {width}x{height}"
        ));
    }
    log::info!(
        "rdp: active on {host}:{port} desktop={width}x{height} share_id={} compression={:?}",
        result.share_id,
        result.compression_type
    );

    let mirrors: Arc<Mutex<Vec<EventSink>>> = Arc::new(Mutex::new(Vec::new()));
    let shared = Arc::new(Shared {
        image: Mutex::new(DecodedImage::new(PixelFormat::RgbA32, width, height)),
        mirrors: Arc::clone(&mirrors),
        dims: Mutex::new((width, height)),
        alive: AtomicBool::new(true),
    });

    let _ = sink.send(event_body(&RdpEvent::Connected {
        desktop_width: width,
        desktop_height: height,
        server_fingerprint: fingerprint.clone(),
    }));

    let (input_tx, input_rx) = mpsc::unbounded_channel::<Vec<InputOp>>();
    // The task owns the sender; whether it fires or merely drops on abort, the
    // receiver handed to `rdp_open` unblocks and the janitor evicts the id.
    let (exit_tx, exit_rx) = oneshot::channel::<()>();
    let transport = ChannelTransport {
        primary: sink.clone(),
        mirrors,
    };
    let task_shared = Arc::clone(&shared);
    let task_sink = sink.clone();
    let task = tokio::spawn(async move {
        let _exit_tx = exit_tx;
        run(result, framed, input_rx, task_shared, task_sink, transport).await;
    });

    let created_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0);

    Ok(Arc::new(RdpSession {
        input_tx,
        task: tokio::sync::Mutex::new(Some(task)),
        exit_signal: Mutex::new(Some(exit_rx)),
        shared,
        primary: sink,
        host,
        username: input.username,
        fingerprint,
        created_at_ms,
    }))
}

/// How the session task stopped.
enum Ending {
    /// The server or the client asked for it. No `error` event.
    Graceful(String),
    /// A transport or protocol fault. Reported as `error` then `disconnected`.
    Faulted(String),
}

/// The active-stage loop.
///
/// Every `ActiveStageOutput` variant is handled. `ResponseFrame` **must** be
/// written back or the server stalls waiting for fastpath acknowledgements.
async fn run(
    result: ConnectionResult,
    mut framed: TlsFramed,
    mut input_rx: mpsc::UnboundedReceiver<Vec<InputOp>>,
    shared: Arc<Shared>,
    sink: EventSink,
    mut transport: ChannelTransport,
) {
    let (mut width, mut height) = (result.desktop_size.width, result.desktop_size.height);
    // Kept for the Deactivation-Reactivation rebuild below: the MCS channels
    // stay joined across a reactivation, so the ids do not change and
    // `ConnectionActivationSequence` (0.9) does not expose them anyway.
    let io_channel_id = result.io_channel_id;
    let user_channel_id = result.user_channel_id;
    let mut stage = ActiveStage::new(result);
    // One long-lived instance per session: it holds key/button state and
    // suppresses no-op transitions, so rebuilding it per command would resend
    // held modifiers and lose auto-repeat suppression.
    let mut keys = Database::new();
    let mut batcher = FrameBatcher::new(width, height);
    let mut flush_at: Option<tokio::time::Instant> = None;

    let emit = |event: &RdpEvent| {
        let body = event_body(event);
        let _ = sink.send(body.clone());
        let mut mirrors = shared.mirrors.lock_or_recover();
        mirrors.retain(|mirror| mirror.send(body.clone()).is_ok());
    };

    enum Wake {
        Pdu(ironrdp_pdu::Action, BytesMut),
        Input(Vec<InputOp>),
        Flush,
    }

    let ending = 'session: loop {
        let deadline = flush_at;
        let wake = tokio::select! {
            // read_pdu is documented cancel-safe: buffered bytes survive a drop.
            pdu = framed.read_pdu() => match pdu {
                Ok((action, payload)) => Wake::Pdu(action, payload),
                Err(e) => break 'session Ending::Faulted(format!("rdp: connection lost: {e}")),
            },
            ops = input_rx.recv() => match ops {
                Some(ops) => Wake::Input(ops),
                // Every sender is gone, i.e. the RdpSession was dropped.
                None => break 'session Ending::Graceful("client closed the session".to_owned()),
            },
            () = async move {
                match deadline {
                    Some(at) => tokio::time::sleep_until(at).await,
                    // No pending rects: park forever rather than waking 60
                    // times a second on an idle desktop.
                    None => core::future::pending().await,
                }
            } => Wake::Flush,
        };

        let outputs = match wake {
            Wake::Pdu(action, payload) => {
                let mut image = shared.image.lock_or_recover();
                match stage.process(&mut image, action, &payload) {
                    Ok(outputs) => outputs,
                    Err(e) => {
                        break 'session Ending::Faulted(session_error("rdp: protocol error", &e))
                    }
                }
            }
            Wake::Input(ops) => {
                // Keep the fastpath processor's idea of the cursor position in
                // step, so a pointer bitmap arriving later lands where the
                // mouse actually is.
                if let Some(pos) = ops.iter().rev().find_map(|op| match op {
                    InputOp::Op(Operation::MouseMove(pos)) => Some(*pos),
                    _ => None,
                }) {
                    stage.update_mouse_pos(pos.x, pos.y);
                }
                let events = apply_input(&mut keys, ops);
                if events.is_empty() {
                    // The batch changed no state (e.g. a move to the same
                    // pixel); nothing to send.
                    continue;
                }
                // One PDU per MAX_FASTPATH_EVENTS. Over that,
                // `process_fastpath_input` returns Err and this arm would end
                // the session - see MAX_FASTPATH_EVENTS for why that is
                // reachable from ordinary use.
                let mut image = shared.image.lock_or_recover();
                let mut collected = Vec::new();
                let mut failure = None;
                for chunk in events.chunks(MAX_FASTPATH_EVENTS) {
                    match stage.process_fastpath_input(&mut image, chunk) {
                        // Extended in chunk order, so the `ResponseFrame`s are
                        // written to the wire in the order the user typed them.
                        Ok(outputs) => collected.extend(outputs),
                        Err(e) => {
                            failure = Some(session_error("rdp: encoding input failed", &e));
                            break;
                        }
                    }
                }
                drop(image);
                if let Some(message) = failure {
                    break 'session Ending::Faulted(message);
                }
                collected
            }
            Wake::Flush => {
                flush(&mut batcher, &shared.image, &mut transport);
                flush_at = None;
                continue;
            }
        };

        // Outputs are drained OUTSIDE the select above, and that is load
        // bearing: `Framed::write_all` is NOT cancel-safe - it may have
        // partially written the buffer and a later call restarts from the
        // beginning (`ironrdp-async` framed.rs:213-221), which would corrupt
        // the stream. It must never sit in a losing `select!` branch. Only
        // `read_pdu` / `read_by_hint` / `read_exact` are documented cancel-safe.
        // Do not move this write into the select.
        //
        // `ActiveStageOutput` is matched exhaustively on purpose: unlike the
        // error kinds it is not `#[non_exhaustive]`, so a version bump that adds
        // a variant should fail the build rather than silently drop it.
        for output in outputs {
            match output {
                // Must go back out or the server stops sending updates.
                ActiveStageOutput::ResponseFrame(frame) => {
                    if let Err(e) = framed.write_all(&frame).await {
                        break 'session Ending::Faulted(format!("rdp: write failed: {e}"));
                    }
                }
                // One rect per update, and IronRDP has already unioned every
                // bitmap rect from the same PDU into its bounding box
                // (`fast_path.rs:297-300`) - so a single update can cover much
                // more than actually changed, and the win here comes from
                // coalescing across updates in time, not from packing many
                // rects into one batch. The batch format stays multi-rect
                // because it costs nothing and the collapse rule still applies.
                ActiveStageOutput::GraphicsUpdate(rect) => {
                    // Drop the all-zero sentinel before converting: inclusive
                    // bounds would turn it into a phantom 1x1 update at the
                    // origin. See `frame::is_empty_sentinel`.
                    if frame::is_empty_sentinel(&rect) {
                        log::trace!("rdp: dropping empty graphics-update sentinel");
                        continue;
                    }
                    let was_empty = batcher.is_empty();
                    batcher.push(Rect::from_inclusive(&rect));
                    if was_empty && !batcher.is_empty() {
                        flush_at = Some(tokio::time::Instant::now() + FLUSH_WINDOW);
                    }
                }
                ActiveStageOutput::PointerDefault => emit(&RdpEvent::PointerDefault),
                ActiveStageOutput::PointerHidden => emit(&RdpEvent::PointerHidden),
                ActiveStageOutput::PointerPosition { x, y } => {
                    emit(&RdpEvent::PointerPosition { x, y });
                }
                // Unreachable with POINTER_SOFTWARE_RENDERING: the cursor is
                // composited into the framebuffer and arrives as a
                // GraphicsUpdate instead. Handing the bitmap to the frontend
                // for a hardware cursor is RDP-12, deferred.
                ActiveStageOutput::PointerBitmap(pointer) => {
                    log::trace!(
                        "rdp: ignoring pointer bitmap {}x{} (software rendering is on)",
                        pointer.width,
                        pointer.height
                    );
                }
                ActiveStageOutput::Terminate(reason) => {
                    break 'session Ending::Graceful(reason.description());
                }
                ActiveStageOutput::DeactivateAll(mut activation) => {
                    log::info!("rdp: DeactivateAll, re-running the activation sequence");
                    // Bounded, unlike every earlier version of this. The
                    // sequence starts in `CapabilitiesExchange`, whose
                    // `next_pdu_hint()` is `Some(&X224_HINT)`
                    // (`ironrdp-connector-0.9.0` connection_activation.rs:52-84),
                    // so the first step awaits a read that a server which sent
                    // `ServerDeactivateAll` and then went quiet will never
                    // satisfy. Without a deadline that parks the task here
                    // forever: no PDU reads, no input drain, no `error`, no
                    // `disconnected`, and `rdp_list_sessions` still saying
                    // `alive: true` - a hang indistinguishable from an idle
                    // session, which is worse than a crash. Every other leg of
                    // the connection is bounded; this was the only hole.
                    let reactivated = match tokio::time::timeout(
                        HANDSHAKE_TIMEOUT,
                        reactivate(&mut framed, &mut activation),
                    )
                    .await
                    {
                        Ok(result) => result,
                        Err(_) => {
                            break 'session Ending::Faulted(format!(
                                "rdp: the server stopped responding during the \
                                 deactivation-reactivation sequence (no progress in {}s)",
                                HANDSHAKE_TIMEOUT.as_secs()
                            ))
                        }
                    };
                    let Reactivation {
                        width: new_width,
                        height: new_height,
                        share_id,
                        server_pointer,
                        software_pointer,
                    } = match reactivated {
                        Ok(values) => values,
                        Err(e) => break 'session Ending::Faulted(e),
                    };
                    // Framebuffer, dims and batcher, validated together.
                    if let Err(e) = apply_reactivation(&shared, &mut batcher, new_width, new_height)
                    {
                        break 'session Ending::Faulted(e);
                    }
                    stage.set_fastpath_processor(
                        fast_path::ProcessorBuilder {
                            io_channel_id,
                            user_channel_id,
                            share_id,
                            enable_server_pointer: server_pointer,
                            pointer_software_rendering: software_pointer,
                            // `compression_type: None` in build_config, so no
                            // decompressor was in use before either.
                            bulk_decompressor: None,
                        }
                        .build(),
                    );
                    stage.set_share_id(share_id);
                    stage.set_enable_server_pointer(server_pointer);
                    flush_at = None;
                    (width, height) = (new_width, new_height);
                    emit(&RdpEvent::Resize { width, height });
                    // Known and accepted: `ActiveStage::process` appends
                    // processor updates AFTER the x224 outputs, so a
                    // `GraphicsUpdate` carrying old-framebuffer coordinates can
                    // still be in `outputs` behind us and will land in the
                    // already-resized batcher. It gets clipped to the new
                    // framebuffer and the server repaints, so the worst case is
                    // a transient artifact rather than bad geometry.
                }
                // UDP sideband transport is out of scope; the server falls back
                // to the TCP connection when the client never establishes it.
                ActiveStageOutput::MultitransportRequest(pdu) => {
                    log::debug!(
                        "rdp: ignoring multitransport request id={} protocol={:?}",
                        pdu.request_id,
                        pdu.requested_protocol
                    );
                }
                // Informational network measurements. The x224 processor
                // answers RTT probes itself; nothing to do with these.
                ActiveStageOutput::AutoDetect(request) => {
                    log::debug!("rdp: autodetect result {request:?}");
                }
            }
        }
    };

    shared.alive.store(false, Ordering::Release);
    // Ship whatever was pending so the last frame before a disconnect is not
    // lost, then report the ending.
    flush(&mut batcher, &shared.image, &mut transport);
    let reason = match ending {
        Ending::Graceful(reason) => reason,
        Ending::Faulted(message) => {
            emit(&RdpEvent::Error {
                message: message.clone(),
            });
            message
        }
    };
    log::info!("rdp: session ended: {reason}");
    emit(&RdpEvent::Disconnected { reason });
}

/// Feed one input batch through the session's key/button state, expanding
/// `ReleaseAll` markers in place.
///
/// A batch is split into runs around each marker rather than applied wholesale,
/// so ordering survives: releasing everything and then pressing a key in the
/// same batch must not release the key that was just pressed.
fn apply_input(
    keys: &mut Database,
    ops: Vec<InputOp>,
) -> Vec<ironrdp_pdu::input::fast_path::FastPathInputEvent> {
    let mut out = Vec::with_capacity(ops.len());
    let mut run: Vec<Operation> = Vec::new();
    for item in ops {
        match item {
            InputOp::Op(op) => run.push(op),
            InputOp::ReleaseAll => {
                if !run.is_empty() {
                    out.extend(keys.apply(core::mem::take(&mut run)));
                }
                out.extend(keys.release_all());
            }
        }
    }
    if !run.is_empty() {
        out.extend(keys.apply(run));
    }
    out
}

/// Encode and ship whatever the batcher accumulated. No-op when nothing was
/// dirty.
fn flush(
    batcher: &mut FrameBatcher,
    image: &Mutex<DecodedImage>,
    transport: &mut dyn FrameTransport,
) {
    let Some(batch) = batcher.take() else {
        return;
    };
    let bytes = {
        let image = image.lock_or_recover();
        let (width, height) = (image.width(), image.height());
        encode_batch(
            FrameBuffer {
                data: image.data(),
                width,
                height,
            },
            &batch,
        )
    };
    // `encode_batch` drops rects the framebuffer can no longer back, which for
    // a batch caught mid-reactivation can leave nothing. Do not ship a
    // rect-less header the frontend would have to treat as corrupt.
    if bytes.len() <= HEADER_LEN {
        return;
    }
    if transport.deliver(bytes).is_err() {
        // Not fatal, and in practice not reachable either - see
        // `ChannelTransport::deliver` on why `Channel::send` cannot report a
        // frontend that has stopped collecting. Left in place so the seam has
        // one, rather than swallowing an error a pull transport would care
        // about.
        log::debug!("rdp: frame sink reported itself gone");
    }
}

/// What the server told us in the `Finalized` state of a reactivation.
///
/// The pointer flags are re-read rather than assumed unchanged: the server
/// renegotiates capabilities, so it may have changed its mind about them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Reactivation {
    width: u16,
    height: u16,
    share_id: u32,
    server_pointer: bool,
    software_pointer: bool,
}

/// Drive a Deactivation-Reactivation sequence to completion.
///
/// Has no internal deadline on purpose - the caller wraps it in one, because
/// the natural budget is the same `HANDSHAKE_TIMEOUT` the rest of the
/// activation sequence gets and there is no reason for this to invent a second
/// one. Not busy-spinning either: `Finalized` and `Consumed` both make `step`
/// return `Err`, so the loop cannot run hot.
async fn reactivate(
    framed: &mut TlsFramed,
    activation: &mut ConnectionActivationSequence,
) -> Result<Reactivation, String> {
    let mut buf = WriteBuf::new();
    loop {
        if let ConnectionActivationState::Finalized {
            desktop_size,
            share_id,
            enable_server_pointer,
            pointer_software_rendering,
            ..
        } = activation.connection_activation_state()
        {
            return Ok(Reactivation {
                width: desktop_size.width,
                height: desktop_size.height,
                share_id,
                server_pointer: enable_server_pointer,
                software_pointer: pointer_software_rendering,
            });
        }
        ironrdp_tokio::single_sequence_step(framed, activation, &mut buf)
            .await
            .map_err(|e| format!("rdp: reactivation step failed: {e}"))?;
    }
}

/// Adopt a new desktop size after a reactivation: rebuild the framebuffer,
/// publish the new dims, and drop whatever the batcher had accumulated.
///
/// Split out from the `DeactivateAll` arm because it is the stateful half -
/// three pieces of shared state that have to move together - and because it is
/// the only part of the reactivation path testable without a live TLS stream.
/// The three `ActiveStage` calls that follow it in the arm are single
/// delegating setters with no logic of their own.
///
/// Rejects a zero axis for the same reason `connect` does: `DecodedImage::new`
/// would build an empty framebuffer and the session would look alive while
/// being incapable of ever producing a frame.
fn apply_reactivation(
    shared: &Shared,
    batcher: &mut FrameBatcher,
    width: u16,
    height: u16,
) -> Result<(), String> {
    if width == 0 || height == 0 {
        return Err(format!(
            "rdp: the server reactivated with an unusable desktop size of {width}x{height}"
        ));
    }
    {
        let mut image = shared.image.lock_or_recover();
        *image = DecodedImage::new(PixelFormat::RgbA32, width, height);
    }
    // Whatever had accumulated describes a framebuffer that no longer exists.
    // The new one is blank and the server repaints it, so the next deltas are
    // already correct - no point shipping a black keyframe first.
    batcher.resize(width, height);
    *shared.dims.lock_or_recover() = (width, height);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::frame::RECT_LEN;
    use super::*;
    use ironrdp_pdu::input::fast_path::{FastPathInput, FastPathInputEvent};

    /// The frontend reads these tags and fields by name, so the serialised
    /// shape is the contract. `rename_all_fields` is what turns
    /// `desktop_width` into `desktopWidth`; without it the frontend silently
    /// reads `undefined`.
    #[test]
    fn event_field_names_are_camel_case() {
        let json = |event: &RdpEvent| serde_json::to_string(event).expect("serialize");

        assert_eq!(
            json(&RdpEvent::Connected {
                desktop_width: 1280,
                desktop_height: 800,
                server_fingerprint: "AA:BB".into(),
            }),
            r#"{"type":"connected","desktopWidth":1280,"desktopHeight":800,"serverFingerprint":"AA:BB"}"#
        );
        assert_eq!(
            json(&RdpEvent::CertPrompt {
                prompt_id: "rdp-cert-1".into(),
                fingerprint: "AA:BB".into(),
                host: "win.example.com".into(),
                subject: "CN=WIN-HOST".into(),
                issuer: "CN=WIN-HOST".into(),
            }),
            r#"{"type":"certPrompt","promptId":"rdp-cert-1","fingerprint":"AA:BB","host":"win.example.com","subject":"CN=WIN-HOST","issuer":"CN=WIN-HOST"}"#
        );
        assert_eq!(
            json(&RdpEvent::Resize {
                width: 1920,
                height: 1080
            }),
            r#"{"type":"resize","width":1920,"height":1080}"#
        );
        assert_eq!(
            json(&RdpEvent::PointerDefault),
            r#"{"type":"pointerDefault"}"#
        );
        assert_eq!(
            json(&RdpEvent::PointerHidden),
            r#"{"type":"pointerHidden"}"#
        );
        assert_eq!(
            json(&RdpEvent::PointerPosition { x: 7, y: 9 }),
            r#"{"type":"pointerPosition","x":7,"y":9}"#
        );
        assert_eq!(
            json(&RdpEvent::Disconnected {
                reason: "user initiated disconnect".into()
            }),
            r#"{"type":"disconnected","reason":"user initiated disconnect"}"#
        );
        assert_eq!(
            json(&RdpEvent::Error {
                message: "rdp: write failed".into()
            }),
            r#"{"type":"error","message":"rdp: write failed"}"#
        );
    }

    /// NLA is not optional: falling back to the legacy graphical-login path
    /// would join every static channel before authentication.
    #[test]
    fn config_enforces_nla_and_software_pointer() {
        let config = build_config(
            &RdpOpenInput {
                host: "win.example.com".into(),
                port: 3389,
                username: "admin".into(),
                domain: Some("CORP".into()),
                credential: super::super::RdpCredential::Keychain {
                    service: "tervia-rdp".into(),
                    account: "abc::password".into(),
                },
                width: 1280,
                height: 800,
                expected_cert_fingerprint: None,
            },
            "secret",
        );
        assert!(!config.enable_tls, "no legacy TLS-only downgrade");
        assert!(config.enable_credssp, "NLA required");
        assert!(
            config.enable_server_pointer,
            "pointer PDUs must be processed or there is no cursor at all"
        );
        assert!(
            config.pointer_software_rendering,
            "the cursor must be composited into the framebuffer"
        );
        assert!(config.compression_type.is_none());
        assert_eq!(config.domain.as_deref(), Some("CORP"));
        assert_eq!(config.desktop_size.width, 1280);
        assert_eq!(config.desktop_size.height, 800);
        // The resolved plaintext is what reaches CredSSP, never the reference.
        assert!(matches!(
            config.credentials,
            Credentials::UsernamePassword { ref password, .. } if password == "secret"
        ));
    }

    /// An NLA rejection is the most common real failure, and IronRDP renders it
    /// as the single word "CredSSP" unless the source chain is walked. This
    /// pins the walking, not IronRDP's wording.
    #[test]
    fn error_flattening_recovers_a_hidden_cause() {
        #[derive(Debug)]
        struct Inner;
        impl core::fmt::Display for Inner {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("the user name or password is incorrect")
            }
        }
        impl core::error::Error for Inner {}

        #[derive(Debug)]
        struct Outer(Inner);
        impl core::fmt::Display for Outer {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                // Exactly what ConnectorErrorKind::Credssp does: drop the cause.
                f.write_str("CredSSP")
            }
        }
        impl core::error::Error for Outer {
            fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
                Some(&self.0)
            }
        }

        let outer = Outer(Inner);
        assert_eq!(
            outer.to_string(),
            "CredSSP",
            "the lossy Display we work around"
        );
        assert_eq!(
            flatten(&outer, core::error::Error::source(&outer)),
            "CredSSP: the user name or password is incorrect"
        );
    }

    /// `n` distinct key presses. Distinct because `Database` suppresses no-op
    /// transitions, so repeating a scancode would emit nothing; distinct keys
    /// give exactly one fastpath event each. Codes 0..256 are plain and
    /// 256..512 carry the extended flag, which is the full width of the
    /// keyboard bit array.
    fn distinct_key_presses(n: usize) -> Vec<InputOp> {
        (0..n)
            .map(|i| {
                let extended = i >= 256;
                let code = u8::try_from(i % 256).expect("masked into range");
                InputOp::Op(Operation::KeyPressed(ironrdp_input::Scancode::from_u8(
                    extended, code,
                )))
            })
            .collect()
    }

    /// Chunk the way the `Wake::Input` arm does, so these tests exercise the
    /// same split the session task performs.
    fn chunks_of(events: &[FastPathInputEvent]) -> Vec<&[FastPathInputEvent]> {
        events.chunks(MAX_FASTPATH_EVENTS).collect()
    }

    /// A batch bigger than one PDU must split, not fail. Before chunking this
    /// was an `Ending::Faulted`, i.e. `error` + `disconnected` and the tab
    /// gone - not a dropped batch.
    #[test]
    fn oversized_input_batch_is_chunked_not_fatal() {
        let mut keys = Database::new();
        let events = apply_input(&mut keys, distinct_key_presses(300));
        assert_eq!(events.len(), 300, "one event per distinct key press");

        let chunks = chunks_of(&events);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].len(), MAX_FASTPATH_EVENTS);
        assert_eq!(chunks[1].len(), 300 - MAX_FASTPATH_EVENTS);

        // Order must survive the split, or keystrokes arrive transposed.
        let rejoined: Vec<FastPathInputEvent> =
            chunks.iter().flat_map(|c| c.iter().cloned()).collect();
        assert_eq!(rejoined, events, "chunks cover the input exactly, in order");

        for (i, chunk) in chunks.iter().enumerate() {
            assert!(
                FastPathInput::new(chunk.to_vec()).is_ok(),
                "chunk {i} must be encodable"
            );
        }
    }

    /// The boundary. The `is_err` on 256 is the oracle for
    /// `MAX_FASTPATH_EVENTS` itself: if upstream ever moves the cap, this fails
    /// rather than the constant silently drifting out of step.
    #[test]
    fn chunk_boundary_is_255() {
        let mut keys = Database::new();
        let exact = apply_input(&mut keys, distinct_key_presses(MAX_FASTPATH_EVENTS));
        assert_eq!(exact.len(), 255);
        assert_eq!(chunks_of(&exact).len(), 1, "255 still fits one PDU");
        assert!(FastPathInput::new(exact.clone()).is_ok());

        let mut keys = Database::new();
        let over = apply_input(&mut keys, distinct_key_presses(MAX_FASTPATH_EVENTS + 1));
        assert_eq!(over.len(), 256);
        let chunks = chunks_of(&over);
        assert_eq!(chunks.len(), 2, "256 needs two");
        assert_eq!((chunks[0].len(), chunks[1].len()), (255, 1));
        assert!(
            FastPathInput::new(over).is_err(),
            "unchunked, 256 events are rejected - this is the bug the chunking fixes"
        );
    }

    /// `releaseAll` can blow the cap on its own, with no oversized batch from
    /// the caller: it releases everything currently held, and "everything" is
    /// bounded only by the 512-bit keyboard array.
    #[test]
    fn release_all_alone_can_exceed_the_cap() {
        let mut keys = Database::new();
        // Press 300 keys, chunked the way the session task would.
        let pressed = apply_input(&mut keys, distinct_key_presses(300));
        assert_eq!(pressed.len(), 300);

        // Now one single-item batch. This is the whole input from the caller.
        let released = apply_input(&mut keys, vec![InputOp::ReleaseAll]);
        assert_eq!(
            released.len(),
            300,
            "release_all emits one event per held key"
        );
        assert!(
            FastPathInput::new(released.clone()).is_err(),
            "a lone releaseAll would have killed the session"
        );

        let chunks = chunks_of(&released);
        assert_eq!(chunks.len(), 2);
        for chunk in &chunks {
            assert!(FastPathInput::new(chunk.to_vec()).is_ok());
        }
    }

    /// A framebuffer of `width` x `height` with a recognisable fill, wrapped in
    /// the shared state the session task and the command layer both touch.
    fn shared_fixture(width: u16, height: u16) -> Arc<Shared> {
        Arc::new(Shared {
            image: Mutex::new(DecodedImage::new(PixelFormat::RgbA32, width, height)),
            mirrors: Arc::new(Mutex::new(Vec::new())),
            dims: Mutex::new((width, height)),
            alive: AtomicBool::new(true),
        })
    }

    /// A session with no network behind it. Everything `RdpSession` needs is
    /// constructible: the input channel's receiver is simply dropped, and there
    /// is no task. Enough to exercise `keyframe`, `add_mirror_sink`, `info` and
    /// `close`'s event, which are otherwise only reachable through a real
    /// connect.
    fn session_fixture(shared: Arc<Shared>, primary: EventSink) -> Arc<RdpSession> {
        let (input_tx, _input_rx) = mpsc::unbounded_channel::<Vec<InputOp>>();
        Arc::new(RdpSession {
            input_tx,
            task: tokio::sync::Mutex::new(None),
            exit_signal: Mutex::new(None),
            shared,
            primary,
            host: "win.example.com".to_owned(),
            username: "admin".to_owned(),
            fingerprint: "AA:BB".to_owned(),
            created_at_ms: 1,
        })
    }

    /// Records what a sink received, in order, tagging each payload by kind so
    /// the connected-then-keyframe ordering is checkable.
    #[derive(Default)]
    struct Recorder {
        seen: Mutex<Vec<(&'static str, String, usize)>>,
    }

    fn recording(recorder: &Arc<Recorder>) -> EventSink {
        let recorder = Arc::clone(recorder);
        EventSink::new(move |body| {
            let entry = match body {
                InvokeResponseBody::Json(json) => ("json", json, 0),
                InvokeResponseBody::Raw(bytes) => ("raw", String::new(), bytes.len()),
            };
            recorder.seen.lock_or_recover().push(entry);
            Ok(())
        })
    }

    /// The stateful half of a reactivation: framebuffer, dims and batcher have
    /// to move together, and stale rects describing the old framebuffer must go.
    #[test]
    fn reactivation_rebuilds_the_framebuffer_and_clears_stale_rects() {
        let shared = shared_fixture(1280, 800);
        let mut batcher = FrameBatcher::new(1280, 800);
        // A rect that only makes sense at the old size.
        batcher.push(Rect {
            x: 1000,
            y: 700,
            w: 200,
            h: 80,
        });
        assert!(!batcher.is_empty());

        apply_reactivation(&shared, &mut batcher, 640, 480).expect("valid size");

        assert_eq!(*shared.dims.lock_or_recover(), (640, 480), "dims published");
        {
            let image = shared.image.lock_or_recover();
            assert_eq!((image.width(), image.height()), (640, 480));
            assert_eq!(
                image.data().len(),
                640 * 480 * 4,
                "the framebuffer was rebuilt, not resized in place"
            );
        }
        assert!(
            batcher.is_empty(),
            "rects describing the old framebuffer are dropped, not carried over"
        );

        // The new batcher really is at the new size: a rect valid only at the
        // old one is now clipped away entirely.
        batcher.push(Rect {
            x: 1000,
            y: 700,
            w: 200,
            h: 80,
        });
        assert!(
            batcher.is_empty(),
            "out-of-bounds rects are dropped at the new size"
        );
    }

    /// A server that reactivates to a zero axis has to fail the session, for the
    /// same reason `connect` refuses one: nothing panics, but the session would
    /// sit at `alive: true` forever and never produce a frame.
    #[test]
    fn reactivation_refuses_an_unusable_size() {
        let shared = shared_fixture(1280, 800);
        let mut batcher = FrameBatcher::new(1280, 800);

        for (w, h) in [(0, 480), (640, 0), (0, 0)] {
            let err = apply_reactivation(&shared, &mut batcher, w, h)
                .expect_err("a zero axis must be refused");
            assert!(err.contains("unusable desktop size"), "got: {err}");
        }
        // And it left the old state untouched rather than half-applying.
        assert_eq!(*shared.dims.lock_or_recover(), (1280, 800));
        assert_eq!(shared.image.lock_or_recover().width(), 1280);
    }

    /// A fresh mirror needs the size before the pixels, then one whole frame.
    #[test]
    fn mirror_sink_is_primed_with_connected_then_keyframe() {
        let shared = shared_fixture(8, 4);
        let session = session_fixture(shared, EventSink::new(|_| Ok(())));

        let recorder = Arc::new(Recorder::default());
        assert!(
            session.add_mirror_sink(recording(&recorder)),
            "a live session reports alive"
        );

        let seen = recorder.seen.lock_or_recover().clone();
        assert_eq!(seen.len(), 2, "exactly connected + keyframe");
        assert_eq!(seen[0].0, "json", "the size must arrive before the pixels");
        assert!(seen[0].1.contains(r#""type":"connected""#));
        assert!(seen[0].1.contains(r#""desktopWidth":8"#));
        assert!(seen[0].1.contains(r#""desktopHeight":4"#));
        assert!(seen[0].1.contains(r#""serverFingerprint":"AA:BB""#));
        assert_eq!(seen[1].0, "raw", "then one full-framebuffer keyframe");
        assert_eq!(
            seen[1].2,
            HEADER_LEN + RECT_LEN + 8 * 4 * 4,
            "header + one rect + every pixel"
        );
    }

    /// The bound exists because each extra sink costs a full copy of every
    /// batch. Oldest out.
    #[test]
    fn mirror_sinks_are_bounded() {
        let shared = shared_fixture(4, 4);
        let session = session_fixture(Arc::clone(&shared), EventSink::new(|_| Ok(())));

        for _ in 0..MAX_MIRROR_SINKS + 3 {
            session.add_mirror_sink(EventSink::new(|_| Ok(())));
        }
        assert_eq!(
            shared.mirrors.lock_or_recover().len(),
            MAX_MIRROR_SINKS,
            "the list never grows past the bound"
        );
    }

    /// `add_mirror_sink` reports liveness, which is how an attaching consumer
    /// learns it just attached to a corpse.
    #[test]
    fn mirror_sink_reports_a_dead_session() {
        let shared = shared_fixture(4, 4);
        shared.alive.store(false, Ordering::Release);
        let session = session_fixture(shared, EventSink::new(|_| Ok(())));
        assert!(!session.add_mirror_sink(EventSink::new(|_| Ok(()))));
    }

    /// `close` aborts the task, so `run`'s tail never emits. The event has to
    /// come from `close` itself or a locally-closed session would end silently -
    /// and mirrors have no other way to find out.
    #[test]
    fn close_emits_disconnected_to_primary_and_mirrors() {
        let shared = shared_fixture(4, 4);
        let primary = Arc::new(Recorder::default());
        let session = session_fixture(Arc::clone(&shared), recording(&primary));

        let mirror = Arc::new(Recorder::default());
        session.add_mirror_sink(recording(&mirror));
        // Drop the priming events so only the close is left.
        mirror.seen.lock_or_recover().clear();
        primary.seen.lock_or_recover().clear();

        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime")
            .block_on(Arc::clone(&session).close());

        for (who, recorder) in [("primary", &primary), ("mirror", &mirror)] {
            let seen = recorder.seen.lock_or_recover().clone();
            assert_eq!(seen.len(), 1, "{who} got exactly one event");
            assert_eq!(seen[0].0, "json");
            assert!(
                seen[0].1.contains(r#""type":"disconnected""#),
                "{who} got: {}",
                seen[0].1
            );
        }
        assert!(
            !shared.alive.load(Ordering::Acquire),
            "and the session is marked dead"
        );
    }

    /// A kind whose Display already embeds its cause must not print it twice.
    #[test]
    fn error_flattening_does_not_duplicate() {
        #[derive(Debug)]
        struct Cause;
        impl core::fmt::Display for Cause {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("server requires CredSSP")
            }
        }
        impl core::error::Error for Cause {}

        struct Head;
        impl core::fmt::Display for Head {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("negotiation failure: server requires CredSSP")
            }
        }

        assert_eq!(
            flatten(&Head, Some(&Cause)),
            "negotiation failure: server requires CredSSP"
        );
    }
}

/// Live tests against a real RDP server. Network, real credentials, real
/// certificate - so every one is `#[ignore]`d and reads its inputs from the
/// environment; `cargo test` stays hermetic.
///
/// ```text
/// TERVIA_RDP_HOST      required
/// TERVIA_RDP_USERNAME  required
/// TERVIA_RDP_PASSWORD  required
/// TERVIA_RDP_PORT      default 3389
/// TERVIA_RDP_DOMAIN    optional
/// TERVIA_RDP_FP        optional. Set  => exercises the pinned path.
///                                Unset => exercises the first-connect prompt,
///                                which the harness auto-confirms.
/// TERVIA_RDP_WIDTH     default 1280
/// TERVIA_RDP_HEIGHT    default 800
/// ```
///
/// Run with `cargo test --release rdp_live -- --ignored --nocapture`.
///
/// Kept here rather than in `src-tauri/tests/` because an integration test only
/// sees the crate's public API, and `session::connect` is deliberately private;
/// the SSH module's live tests (`ssh::session::chain_tests`) sit in the same
/// place for the same reason.
#[cfg(test)]
mod rdp_live {
    use super::*;
    use crate::modules::rdp::frame;
    use std::sync::atomic::AtomicUsize;

    fn env_opt(key: &str) -> Option<String> {
        std::env::var(key).ok().filter(|v| !v.is_empty())
    }

    /// Input plus the resolved plaintext. These tests call `session::connect`
    /// directly, below the keychain lookup that `rdp_open` does, so they pass
    /// the password in the way the dialog's Test button would.
    fn live_input(tag: &str, fingerprint: Option<String>) -> Option<(RdpOpenInput, String)> {
        let (Some(host), Some(username), Some(password)) = (
            env_opt("TERVIA_RDP_HOST"),
            env_opt("TERVIA_RDP_USERNAME"),
            env_opt("TERVIA_RDP_PASSWORD"),
        ) else {
            eprintln!(
                "[{tag}] skipped: set TERVIA_RDP_HOST + TERVIA_RDP_USERNAME + TERVIA_RDP_PASSWORD"
            );
            return None;
        };
        let input = RdpOpenInput {
            host,
            port: env_opt("TERVIA_RDP_PORT")
                .and_then(|v| v.parse().ok())
                .unwrap_or(3389),
            username,
            domain: env_opt("TERVIA_RDP_DOMAIN"),
            credential: super::super::RdpCredential::Inline {
                password: password.clone(),
            },
            width: env_opt("TERVIA_RDP_WIDTH")
                .and_then(|v| v.parse().ok())
                .unwrap_or(1280),
            height: env_opt("TERVIA_RDP_HEIGHT")
                .and_then(|v| v.parse().ok())
                .unwrap_or(800),
            expected_cert_fingerprint: fingerprint,
        };
        Some((input, password))
    }

    fn live_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("live test runtime")
    }

    /// What the harness saw on the session channel.
    #[derive(Default)]
    struct Observed {
        frames: AtomicUsize,
        /// First raw batch, kept for header validation.
        first_frame: Mutex<Option<Vec<u8>>>,
        events: Mutex<Vec<String>>,
    }

    /// A channel that records everything and auto-confirms a `certPrompt`, so
    /// the first-connect path can run unattended.
    fn recording_sink(observed: Arc<Observed>) -> EventSink {
        EventSink::new(move |body| {
            match body {
                InvokeResponseBody::Raw(bytes) => {
                    observed.frames.fetch_add(1, Ordering::Relaxed);
                    let mut first = observed.first_frame.lock_or_recover();
                    if first.is_none() {
                        *first = Some(bytes);
                    }
                }
                InvokeResponseBody::Json(json) => {
                    eprintln!("[rdp_live] event {json}");
                    observed.events.lock_or_recover().push(json.clone());
                    // Stand in for the confirmation dialog.
                    if let Some(prompt_id) = prompt_id_of(&json) {
                        eprintln!("[rdp_live] auto-confirming cert prompt {prompt_id}");
                        if let Some(tx) = tls::take_pending_cert(&prompt_id) {
                            let _ = tx.send(true);
                        }
                    }
                }
            }
            Ok(())
        })
    }

    /// Pull `promptId` out of a `certPrompt` event without pulling in a JSON
    /// value type just for the tests.
    fn prompt_id_of(json: &str) -> Option<String> {
        if !json.contains(r#""type":"certPrompt""#) {
            return None;
        }
        let rest = json.split(r#""promptId":""#).nth(1)?;
        Some(rest.split('"').next()?.to_owned())
    }

    /// The happy path: connect, reach the active stage, receive real dirty-rect
    /// batches, send input, and shut down.
    #[test]
    #[ignore]
    fn connects_and_streams_frames() {
        let Some((input, password)) = live_input("rdp_live", env_opt("TERVIA_RDP_FP")) else {
            return;
        };
        let host = input.host.clone();
        let observed = Arc::new(Observed::default());
        let sink = recording_sink(Arc::clone(&observed));

        live_runtime().block_on(async move {
            let session = connect(input, password, sink)
                .await
                .expect("connect failed");
            let (width, height) = session.dims();
            assert!(
                width > 0 && height > 0,
                "the server reported a desktop size"
            );
            let info = session.info(1);
            assert_eq!(info.host, host);
            assert!(info.alive, "the session must be live right after connect");
            assert_eq!(
                info.server_fingerprint.len(),
                32 * 3 - 1,
                "a SHA-256 fingerprint is 32 colon-separated hex pairs"
            );
            eprintln!("[rdp_live] {width}x{height} fp={}", info.server_fingerprint);

            // A snapshot is available immediately, before any update arrives.
            let keyframe = session.keyframe();
            check_keyframe(&keyframe, width, height);

            // Nudge the desktop so it has something to repaint, then wait for
            // the server to actually send it.
            session
                .send_input(vec![
                    InputOp::Op(Operation::MouseMove(ironrdp_input::MousePosition {
                        x: width / 2,
                        y: height / 2,
                    })),
                    InputOp::Op(Operation::KeyPressed(ironrdp_input::Scancode::from_u16(
                        0x001D,
                    ))),
                    InputOp::ReleaseAll,
                ])
                .expect("queueing input failed");

            let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
            while observed.frames.load(Ordering::Relaxed) == 0
                && tokio::time::Instant::now() < deadline
            {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            let frames = observed.frames.load(Ordering::Relaxed);
            assert!(frames > 0, "no frame batch arrived within 20s");
            eprintln!("[rdp_live] {frames} batch(es) received");

            let batch = observed
                .first_frame
                .lock_or_recover()
                .clone()
                .expect("a batch was recorded");
            check_batch_header(&batch, width, height);

            let events = observed.events.lock_or_recover().clone();
            assert!(
                events.iter().any(|e| e.contains(r#""type":"connected""#)),
                "a connected event must be emitted"
            );

            session.close().await;
            eprintln!("[rdp_live] OK");
        });
    }

    /// The security core: a pinned fingerprint that does not match must abort
    /// the TLS handshake, so `connect_finalize` - and therefore CredSSP, and
    /// therefore the credential - never runs.
    #[test]
    #[ignore]
    fn mismatched_fingerprint_aborts_before_credentials() {
        let bogus = "00:".repeat(31) + "00";
        let Some((input, password)) = live_input("rdp_live_mismatch", Some(bogus.clone())) else {
            return;
        };
        let observed = Arc::new(Observed::default());
        let sink = recording_sink(Arc::clone(&observed));

        live_runtime().block_on(async move {
            let Err(error) = connect(input, password, sink).await else {
                panic!("a mismatched pin must fail the connect");
            };
            eprintln!("[rdp_live_mismatch] {error}");
            assert!(
                error.contains("certificate mismatch"),
                "the error must name the mismatch, got: {error}"
            );
            assert!(
                error.contains(&bogus),
                "the error must quote the expected fingerprint so it can be compared"
            );
            let events = observed.events.lock_or_recover().clone();
            assert!(
                !events.iter().any(|e| e.contains(r#""type":"connected""#)),
                "nothing may report a successful connect"
            );
            assert!(
                !events.iter().any(|e| e.contains(r#""type":"certPrompt""#)),
                "a pinned connect must never fall back to prompting"
            );
        });
    }

    fn check_keyframe(bytes: &[u8], width: u16, height: u16) {
        check_batch_header(bytes, width, height);
        assert_eq!(bytes[5], 1, "a snapshot is a keyframe");
        assert_eq!(
            u16::from_le_bytes([bytes[6], bytes[7]]),
            1,
            "a keyframe carries exactly one rect"
        );
        assert_eq!(
            &bytes[frame::HEADER_LEN..frame::HEADER_LEN + frame::RECT_LEN],
            &[
                0,
                0,
                0,
                0,
                width.to_le_bytes()[0],
                width.to_le_bytes()[1],
                height.to_le_bytes()[0],
                height.to_le_bytes()[1],
            ],
            "the keyframe rect covers the whole framebuffer"
        );
    }

    fn check_batch_header(bytes: &[u8], width: u16, height: u16) {
        assert!(bytes.len() > frame::HEADER_LEN, "a batch has a full header");
        assert_eq!(&bytes[0..4], &frame::FRAME_MAGIC);
        assert_eq!(bytes[4], frame::FRAME_VERSION);
        assert!(bytes[5] <= 1, "kind is delta or keyframe");
        let rects = usize::from(u16::from_le_bytes([bytes[6], bytes[7]]));
        assert!(rects > 0, "a shipped batch always has at least one rect");
        assert_eq!(u16::from_le_bytes([bytes[8], bytes[9]]), width);
        assert_eq!(u16::from_le_bytes([bytes[10], bytes[11]]), height);
        let payload_len = usize::try_from(u32::from_le_bytes([
            bytes[12], bytes[13], bytes[14], bytes[15],
        ]))
        .expect("payload length fits usize");
        assert_eq!(
            bytes.len(),
            frame::HEADER_LEN + rects * frame::RECT_LEN + payload_len,
            "the header must account for every byte"
        );

        // Every rect must be in bounds and its rows must add up.
        let mut expected = 0usize;
        for i in 0..rects {
            let at = frame::HEADER_LEN + i * frame::RECT_LEN;
            let read = |off: usize| u16::from_le_bytes([bytes[at + off], bytes[at + off + 1]]);
            let (x, y, w, h) = (read(0), read(2), read(4), read(6));
            assert!(w > 0 && h > 0, "rect {i} has a real extent");
            assert!(
                u32::from(x) + u32::from(w) <= u32::from(width),
                "rect {i} fits horizontally"
            );
            assert!(
                u32::from(y) + u32::from(h) <= u32::from(height),
                "rect {i} fits vertically"
            );
            expected += usize::from(w) * usize::from(h) * 4;
        }
        assert_eq!(expected, payload_len, "rect table and payload agree");
    }
}
