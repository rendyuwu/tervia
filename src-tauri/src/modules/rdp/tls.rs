//! TLS for the RDP connect sequence, with certificate trust-on-first-use.
//!
//! `ironrdp-tls` cannot host this. Its `upgrade()` hardcodes an internal
//! `NoCertificateVerification` and the `danger` module holding it is private,
//! so there is no callback seam to hang a real check on. We therefore drive
//! `tokio_rustls::TlsConnector` ourselves and inject [`TofuVerifier`]. The two
//! things that crate still gives us - `negotiated()` and
//! `extract_tls_server_public_key()` - are public and both still used, the
//! latter because CredSSP binds to the server's SubjectPublicKey rather than to
//! the whole certificate.
//!
//! # Where the check happens
//!
//! [`TofuVerifier::verify_server_cert`] runs *inside* the TLS handshake, which
//! is strictly before `ironrdp_tokio::connect_finalize` starts CredSSP. So a
//! rejection here means no credential of any kind has crossed the wire: not the
//! password, not the NTLM response. That is the whole point of doing it in the
//! verifier instead of as a post-handshake comparison.
//!
//! # Fingerprint format
//!
//! Colon-separated uppercase hex of the SHA-256 digest over the leaf's DER
//! bytes, e.g. `AB:CD:...:EF`. Same text `openssl x509 -fingerprint -sha256`
//! prints and the same grouping the Windows certificate dialog shows, so a user
//! can compare it against the server out of band by eye.
//!
//! # What the fingerprint is keyed to
//!
//! Nothing here derives a storage key from the address. The caller passes
//! `expected_cert_fingerprint` in and the frontend stores it on the *saved
//! connection*. One machine is `host:3389` dialled directly and
//! `127.0.0.1:<ephemeral>` through an SSH tunnel; keying by authority would make
//! that look like two different servers, and a fresh ephemeral port would look
//! like an unknown host on every connect. The `ServerName` handed to rustls is
//! therefore cosmetic - the verifier compares a fingerprint, never a hostname.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{pki_types, DigitallySignedStruct, SignatureScheme};
use tokio::net::TcpStream;

use crate::modules::lockext::LockExt as _;

use super::session::RdpEvent;
use super::EventSink;

/// How long the handshake waits for the user's first-connect decision before
/// treating silence as a rejection, so a forgotten dialog cannot hold a TCP
/// connection (and a parked worker thread) open for good. Matches the SSH
/// module's `HOSTKEY_CONFIRM_TIMEOUT`.
pub(super) const CERT_CONFIRM_TIMEOUT: Duration = Duration::from_secs(120);

static CERT_PROMPT_SEQ: AtomicU64 = AtomicU64::new(1);

/// Pending first-connect certificate confirmations, keyed by an opaque prompt
/// id. The verifier parks a `Sender` here and blocks on its `Receiver`; the
/// `rdp_confirm_cert` command resolves it. A process-global map keeps the
/// command decoupled from the in-flight handshake, exactly as the SSH module's
/// `pending_host_keys()` does.
fn pending_certs() -> &'static Mutex<HashMap<String, std::sync::mpsc::Sender<bool>>> {
    static P: OnceLock<Mutex<HashMap<String, std::sync::mpsc::Sender<bool>>>> = OnceLock::new();
    P.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Resolve a pending certificate prompt. Returns the parked sender for the
/// command to fire with the user's decision; `None` if it already timed out or
/// was answered.
pub(super) fn take_pending_cert(prompt_id: &str) -> Option<std::sync::mpsc::Sender<bool>> {
    pending_certs().lock_or_recover().remove(prompt_id)
}

/// What the verifier observed, read back by the connect path to build the
/// `connected` event or a specific error message.
#[derive(Debug, Default)]
pub(super) struct CertReport {
    /// Fingerprint the server actually presented, whether or not it matched.
    pub seen: Option<String>,
    /// RFC 4514 subject / issuer of the leaf, for the confirmation dialog.
    pub subject: String,
    pub issuer: String,
    /// `(expected, seen)` when the leaf did not match the pinned fingerprint.
    /// Reported verbatim so the user can compare both values.
    pub mismatch: Option<(String, String)>,
    /// Set to the seen fingerprint when the user - or a confirm timeout -
    /// refused a brand-new certificate.
    pub rejected: Option<String>,
}

/// SHA-256 over the leaf's DER bytes, colon-separated uppercase hex.
pub(super) fn fingerprint_sha256(der: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, der);
    // Two uppercase hex nibbles per byte, no per-byte allocation.
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(digest.as_ref().len() * 3);
    for (i, byte) in digest.as_ref().iter().copied().enumerate() {
        if i > 0 {
            out.push(':');
        }
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0F)]));
    }
    out
}

/// Compare two fingerprints the way a human would paste them: case- and
/// separator-insensitive, so a value copied from `openssl` (lowercase, colons),
/// from `certutil` (uppercase, spaces) or from our own store all match.
pub(super) fn fingerprints_match(a: &str, b: &str) -> bool {
    let norm = |s: &str| -> String {
        s.chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .flat_map(char::to_uppercase)
            .collect()
    };
    let (a, b) = (norm(a), norm(b));
    !a.is_empty() && a == b
}

/// RFC 4514 subject and issuer of a DER leaf, for the confirmation dialog.
/// Unparseable certificates get placeholders rather than failing the connect:
/// the fingerprint is what the trust decision rests on, and these two strings
/// are only there to give the user something recognisable to look at.
pub(super) fn certificate_names(der: &[u8]) -> (String, String) {
    use x509_cert::der::Decode as _;
    match x509_cert::Certificate::from_der(der) {
        Ok(cert) => (
            cert.tbs_certificate.subject.to_string(),
            cert.tbs_certificate.issuer.to_string(),
        ),
        Err(_) => ("<unparseable>".to_owned(), "<unparseable>".to_owned()),
    }
}

/// Certificate verifier implementing the pin-or-ask policy.
///
/// * `expected` set and the leaf matches -> `Ok`.
/// * `expected` set and the leaf does not -> `Err`, aborting the handshake.
/// * `expected` absent (first connect) -> emit `certPrompt` and block this
///   callback until `rdp_confirm_cert` answers. Accept -> `Ok`; reject or
///   timeout -> `Err`.
pub(super) struct TofuVerifier {
    expected: Option<String>,
    report: Arc<Mutex<CertReport>>,
    /// Where `certPrompt` goes. Only used on the no-pin path.
    sink: EventSink,
    /// Correlates the emitted prompt with the `rdp_confirm_cert` answer.
    prompt_id: String,
    /// Host label shown in the confirmation dialog.
    host: String,
    /// Receiver for the user's decision, taken once on the first callback.
    /// `Mutex` because `verify_server_cert` only gets `&self`.
    decision: Mutex<Option<std::sync::mpsc::Receiver<bool>>>,
    /// Signature-verification algorithms of the active crypto provider (ring).
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}

// `ServerCertVerifier` requires `Debug` and `Channel` does not implement it.
impl core::fmt::Debug for TofuVerifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TofuVerifier")
            .field("pinned", &self.expected.is_some())
            .field("prompt_id", &self.prompt_id)
            .field("host", &self.host)
            .finish_non_exhaustive()
    }
}

impl ServerCertVerifier for TofuVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &pki_types::CertificateDer<'_>,
        _intermediates: &[pki_types::CertificateDer<'_>],
        _server_name: &pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let seen = fingerprint_sha256(end_entity.as_ref());
        let (subject, issuer) = certificate_names(end_entity.as_ref());
        {
            let mut report = self.report.lock_or_recover();
            report.seen = Some(seen.clone());
            report.subject = subject.clone();
            report.issuer = issuer.clone();
        }

        if let Some(expected) = &self.expected {
            if fingerprints_match(expected, &seen) {
                log::info!("rdp: server certificate pinned ok fingerprint={seen}");
                return Ok(ServerCertVerified::assertion());
            }
            log::warn!("rdp: server certificate mismatch expected={expected} got={seen}");
            self.report.lock_or_recover().mismatch = Some((expected.clone(), seen));
            // Failing here aborts the handshake, so `connect_finalize` never
            // runs and no credential is sent. The connect path turns the
            // recorded mismatch into a specific error string.
            return Err(rustls::Error::General(
                "rdp: server certificate does not match the pinned fingerprint".to_owned(),
            ));
        }

        // First connect: pause the handshake and make the user verify the
        // fingerprint out of band. Trusting silently would let a first-connect
        // MITM harvest the NTLM exchange that CredSSP is about to run.
        let Some(rx) = self.decision.lock_or_recover().take() else {
            log::warn!("rdp: no certificate confirmation channel; refusing unknown certificate");
            self.report.lock_or_recover().rejected = Some(seen);
            return Err(rustls::Error::General(
                "rdp: server certificate not trusted (no confirmation channel)".to_owned(),
            ));
        };
        let _ = self.sink.send(super::event_body(&RdpEvent::CertPrompt {
            prompt_id: self.prompt_id.clone(),
            fingerprint: seen.clone(),
            host: self.host.clone(),
            subject,
            issuer,
        }));

        if await_decision(&rx) {
            log::info!("rdp: user confirmed new server certificate fingerprint={seen}");
            return Ok(ServerCertVerified::assertion());
        }
        log::warn!("rdp: user rejected/aborted new server certificate fingerprint={seen}");
        // Drop the prompt if we got here by timing out rather than by an answer.
        let _ = take_pending_cert(&self.prompt_id);
        self.report.lock_or_recover().rejected = Some(seen);
        Err(rustls::Error::General(
            "rdp: server certificate was not confirmed".to_owned(),
        ))
    }

    /// Verified for real, not asserted.
    ///
    /// `ironrdp-tls`'s own verifier returns `Ok` unconditionally here, and so
    /// did the 5a spike. That makes a pinned fingerprint nearly worthless: the
    /// leaf certificate is public, so an attacker who replays it completes the
    /// handshake without ever holding its private key. Checking the
    /// ServerKeyExchange signature is what proves the peer owns the key the
    /// fingerprint identifies.
    ///
    /// Cost: we no longer advertise the SHA-1 signature schemes `ironrdp-tls`
    /// lists, because the ring provider cannot verify them (see
    /// `supported_verify_schemes`). A Windows host old enough to sign only with
    /// SHA-1 - Server 2008 R2 and earlier, long out of support - would fail the
    /// handshake instead of being silently accepted.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &pki_types::CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &pki_types::CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // Exactly what the provider can actually verify, so a server never
        // picks a scheme `verify_tls1x_signature` would then reject.
        self.algorithms.supported_schemes()
    }
}

/// Wait for the UI's answer from inside rustls's **synchronous**
/// `verify_server_cert` callback.
///
/// This is the awkward part of the design, so the reasoning is spelled out:
///
/// * The callback is sync and runs inside the TLS handshake future, i.e. on a
///   worker of `rdp_runtime()`. `Handle::block_on` there panics outright, and
///   any scheme that awaits a future needing *this* runtime to progress would
///   be a cycle.
/// * A plain `std::sync::mpsc` receive has no waker and needs no executor. The
///   matching `Sender` is fired by `rdp_confirm_cert`, a Tauri command running
///   on *Tauri's* runtime, never on `rdp_runtime()`. The producer is therefore
///   always schedulable while this consumer is parked, so there is no cycle and
///   no deadlock - the only ways out are an answer or the timeout, and both are
///   bounded.
/// * Blocking a worker outright would still starve the runtime: with two
///   workers, two concurrent first-connects would stall every other session's
///   active-stage loop for up to `CERT_CONFIRM_TIMEOUT`. `block_in_place` hands
///   this worker's remaining tasks to a replacement thread first, so the park
///   costs a thread rather than throughput.
/// * `block_in_place` panics on a current-thread runtime, so the flavor is
///   checked. Outside a runtime entirely (unit tests) it falls through to the
///   plain blocking receive.
fn await_decision(rx: &std::sync::mpsc::Receiver<bool>) -> bool {
    let wait = || matches!(rx.recv_timeout(CERT_CONFIRM_TIMEOUT), Ok(true));
    match tokio::runtime::Handle::try_current() {
        Ok(handle)
            if matches!(
                handle.runtime_flavor(),
                tokio::runtime::RuntimeFlavor::MultiThread
            ) =>
        {
            tokio::task::block_in_place(wait)
        }
        _ => wait(),
    }
}

/// Build the verifier for one connect. When nothing is pinned, parks a
/// confirmation channel keyed by the returned prompt id (resolved by
/// `rdp_confirm_cert`). Returns the verifier, the shared report, the prompt id
/// and whether a confirmation round-trip is possible - the caller needs the
/// last one to widen its connect timeout.
pub(super) fn build_verifier(
    expected: Option<String>,
    sink: EventSink,
    host: String,
) -> (Arc<TofuVerifier>, Arc<Mutex<CertReport>>, String, bool) {
    let report = Arc::new(Mutex::new(CertReport::default()));
    let needs_confirm = expected.is_none();
    let prompt_id = format!(
        "rdp-cert-{}",
        CERT_PROMPT_SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let decision = if needs_confirm {
        let (tx, rx) = std::sync::mpsc::channel::<bool>();
        pending_certs()
            .lock_or_recover()
            .insert(prompt_id.clone(), tx);
        Some(rx)
    } else {
        None
    };
    let verifier = Arc::new(TofuVerifier {
        expected,
        report: Arc::clone(&report),
        sink,
        prompt_id: prompt_id.clone(),
        host,
        decision: Mutex::new(decision),
        algorithms: provider().signature_verification_algorithms,
    });
    (verifier, report, prompt_id, needs_confirm)
}

/// Drop a prompt that was parked but never consumed, e.g. because the handshake
/// failed before the verifier ran. Without this the one-shot leaks in
/// `pending_certs()` for the process's lifetime.
pub(super) fn drop_pending_cert(prompt_id: &str) {
    let _ = take_pending_cert(prompt_id);
}

/// The ring crypto provider. `rustls` here is built with `default-features =
/// false, features = ["ring"]`, so the aws-lc-rs default - which needs NASM at
/// build time on Windows - is never linked. Built once: the provider carries
/// static algorithm tables, and `default_provider()` allocates them each call.
fn provider() -> &'static rustls::crypto::CryptoProvider {
    static P: OnceLock<rustls::crypto::CryptoProvider> = OnceLock::new();
    P.get_or_init(rustls::crypto::ring::default_provider)
}

/// Upgrade a live TCP stream to TLS with `verifier` in charge of trust.
///
/// `server_name` is passed through to rustls for SNI only; the verifier ignores
/// it (see the module docs on tunnelled connections).
pub(super) async fn upgrade(
    tcp: TcpStream,
    server_name: &str,
    verifier: Arc<TofuVerifier>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    use tokio::io::AsyncWriteExt as _;

    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider().clone()))
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("rdp: rustls protocol versions: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    // CredSSP does not survive a resumed session; `ironrdp-tls` disables
    // resumption for the same reason.
    config.resumption = rustls::client::Resumption::disabled();
    // Deliberately no `KeyLogFile`: it would dump TLS secrets to whatever
    // `SSLKEYLOGFILE` points at, which is not a capability a shipped remote
    // desktop client should carry.

    let dns = pki_types::ServerName::try_from(server_name.to_owned())
        .map_err(|e| format!("rdp: invalid server name {server_name:?}: {e}"))?;

    let mut tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(dns, tcp)
        .await
        .map_err(|e| format!("rdp: tls handshake failed: {e}"))?;
    // Force the handshake to complete so `peer_certificates()` is populated.
    tls.flush()
        .await
        .map_err(|e| format!("rdp: tls flush failed: {e}"))?;

    Ok(tls)
}

/// Turn a failed TLS upgrade into a specific, user-actionable message using the
/// verifier's structured report, falling back to the raw rustls text.
pub(super) fn upgrade_error(report: &Mutex<CertReport>, raw: String) -> String {
    let report = report.lock_or_recover();
    if let Some(seen) = report.rejected.clone() {
        return format!(
            "rdp: server certificate not trusted: {seen} was not confirmed; \
             the connection was aborted before any credential was sent."
        );
    }
    if let Some((expected, seen)) = report.mismatch.clone() {
        return format!(
            "rdp: server certificate mismatch: expected={expected} server={seen}. \
             The server presented a different certificate than the one recorded on the last \
             successful connect, and the connection was aborted before any credential was sent. \
             If the certificate was rotated legitimately, edit the saved connection and clear \
             the recorded fingerprint before reconnecting; otherwise this could be a \
             man-in-the-middle attack."
        );
    }
    raw
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact text a user compares by eye, so the shape is pinned:
    /// uppercase hex, colon separated, 32 bytes, no prefix.
    #[test]
    fn fingerprint_shape_is_openssl_compatible() {
        // SHA-256 of the empty input.
        let fp = fingerprint_sha256(b"");
        assert_eq!(
            fp,
            "E3:B0:C4:42:98:FC:1C:14:9A:FB:F4:C8:99:6F:B9:24:27:AE:41:E4:64:9B:93:4C:A4:95:99:1B:78:52:B8:55"
        );
        assert_eq!(fp.len(), 32 * 3 - 1);
        assert_eq!(fp.matches(':').count(), 31);
        assert!(
            fp.chars().all(|c| c.is_ascii_hexdigit() || c == ':'),
            "no lowercase and no other separators"
        );
    }

    #[test]
    fn fingerprint_is_stable_and_input_sensitive() {
        let a = fingerprint_sha256(b"leaf-der-bytes");
        assert_eq!(a, fingerprint_sha256(b"leaf-der-bytes"));
        assert_ne!(a, fingerprint_sha256(b"leaf-der-byte"));
    }

    /// A value pasted from `openssl` (lowercase) or `certutil` (spaces) must
    /// still match what we stored, or a legitimate reconnect looks like a MITM.
    #[test]
    fn comparison_ignores_case_and_separators() {
        let stored = fingerprint_sha256(b"x");
        assert!(fingerprints_match(&stored, &stored));
        assert!(fingerprints_match(&stored.to_lowercase(), &stored));
        assert!(fingerprints_match(&stored.replace(':', " "), &stored));
        assert!(fingerprints_match(&stored.replace(':', ""), &stored));
        assert!(!fingerprints_match(&fingerprint_sha256(b"y"), &stored));
    }

    /// An empty or separator-only value must never match anything - otherwise a
    /// blank saved fingerprint would silently disable the pin.
    #[test]
    fn empty_never_matches() {
        let stored = fingerprint_sha256(b"x");
        assert!(!fingerprints_match("", &stored));
        assert!(!fingerprints_match(":::", &stored));
        assert!(!fingerprints_match("", ""));
    }

    #[test]
    fn unparseable_certificate_still_yields_labels() {
        let (subject, issuer) = certificate_names(b"not a certificate");
        assert_eq!(subject, "<unparseable>");
        assert_eq!(issuer, "<unparseable>");
    }

    /// The prompt registry hands a parked sender out exactly once, so a second
    /// `rdp_confirm_cert` for the same prompt cannot re-answer it.
    #[test]
    fn pending_prompts_resolve_once() {
        let (tx, rx) = std::sync::mpsc::channel::<bool>();
        let id = format!(
            "rdp-cert-test-{}",
            CERT_PROMPT_SEQ.fetch_add(1, Ordering::Relaxed)
        );
        pending_certs().lock_or_recover().insert(id.clone(), tx);

        let taken = take_pending_cert(&id).expect("first take yields the sender");
        assert!(
            take_pending_cert(&id).is_none(),
            "a prompt is answerable once"
        );
        taken.send(true).expect("receiver still alive");
        assert!(rx.recv().expect("decision"), "the answer arrives verbatim");
    }
}
