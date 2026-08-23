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
    /// The session ended, for this reason. Always the last event.
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
    fn deliver(&mut self, bytes: Vec<u8>) -> Result<(), TransportGone> {
        {
            // Prune sinks whose webview went away, exactly as the SSH pump's
            // fan does, so dead mirrors do not cost a clone per frame forever.
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
        let _ = sink.send(InvokeResponseBody::Raw(keyframe));
        // Bound the live sink count: a buggy caller could call rdp_attach in a
        // loop, and every extra sink costs a full frame clone per batch. Evict
        // the oldest.
        const MAX_MIRROR_SINKS: usize = 4;
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
    pub async fn close(self: Arc<Self>) {
        self.shared.alive.store(false, Ordering::Release);
        if let Some(task) = self.task.lock().await.take() {
            task.abort();
        }
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
/// `connect_finalize` run CredSSP and send credentials.
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
    // certificate, so this is a separate extraction from the fingerprint.
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

    let (width, height) = (result.desktop_size.width, result.desktop_size.height);
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
    let task = tokio::spawn(async move {
        let _exit_tx = exit_tx;
        run(result, framed, input_rx, task_shared, sink, transport).await;
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
                let mut image = shared.image.lock_or_recover();
                match stage.process_fastpath_input(&mut image, &events) {
                    Ok(outputs) => outputs,
                    Err(e) => {
                        break 'session Ending::Faulted(session_error(
                            "rdp: encoding input failed",
                            &e,
                        ))
                    }
                }
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
                    let reactivated = reactivate(&mut framed, &mut activation).await;
                    let (new_width, new_height, share_id, server_pointer, software_pointer) =
                        match reactivated {
                            Ok(values) => values,
                            Err(e) => break 'session Ending::Faulted(e),
                        };
                    {
                        let mut image = shared.image.lock_or_recover();
                        *image = DecodedImage::new(PixelFormat::RgbA32, new_width, new_height);
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
                    // Whatever had accumulated describes a framebuffer that no
                    // longer exists. The new one is blank and the server
                    // repaints it, so the next deltas are already correct - no
                    // point shipping a black keyframe first.
                    batcher.resize(new_width, new_height);
                    flush_at = None;
                    (width, height) = (new_width, new_height);
                    *shared.dims.lock_or_recover() = (width, height);
                    emit(&RdpEvent::Resize { width, height });
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
        // Not fatal: a mirror sink may still be attached, and the session is
        // worth keeping alive for it.
        log::debug!("rdp: frame sink is gone");
    }
}

/// Drive a Deactivation-Reactivation sequence to completion.
///
/// Returns `(width, height, share_id, enable_server_pointer,
/// pointer_software_rendering)` from the `Finalized` state.
async fn reactivate(
    framed: &mut TlsFramed,
    activation: &mut ConnectionActivationSequence,
) -> Result<(u16, u16, u32, bool, bool), String> {
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
            return Ok((
                desktop_size.width,
                desktop_size.height,
                share_id,
                enable_server_pointer,
                pointer_software_rendering,
            ));
        }
        ironrdp_tokio::single_sequence_step(framed, activation, &mut buf)
            .await
            .map_err(|e| format!("rdp: reactivation step failed: {e}"))?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
