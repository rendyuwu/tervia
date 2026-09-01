//! Interactive SSH client sessions.
//!
//! Mirrors the local PTY module's command shape (`ssh_open`/`ssh_write`/
//! `ssh_resize`/`ssh_close`) so the frontend can swap a local PTY for a
//! remote shell with minimal plumbing. Auth supports the local ssh-agent (the
//! private key stays inside the agent; Tervia only ever sees signatures), a
//! private key, or a password.
//! Host-key handling: SHA-256 fingerprint pinning. The first connect to
//! a new host is trust-on-first-use (the seen fingerprint is reported to the
//! frontend, which persists it as `lastFingerprint` in the connection store).
//! Every later connect passes that fingerprint as `expected_fingerprint`; a
//! mismatch aborts the handshake with a "host key mismatch / possible MITM"
//! error (see `session::HostKeyVerifier`). To re-trust a legitimately rotated
//! key the user clears the saved fingerprint on the connection.

mod session;
pub mod sftp;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};

use russh::keys::ssh_key::PrivateKey;
use serde::{Deserialize, Serialize};
use tauri::ipc::Channel;
use tokio::runtime::Runtime;

pub use session::SshEvent;
use session::SshSession;

/// Shared tokio runtime for every SSH session. russh is async-first; driving
/// it from per-session executors would duplicate thread pools. A single
/// multi-thread runtime keeps overhead flat.
fn ssh_runtime() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("tervia-ssh")
            .build()
            .expect("init ssh tokio runtime")
    })
}

pub struct SshState {
    /// `pub(crate)` so the sibling `sftp` module can look up an existing
    /// session by id to issue file-system commands. `Arc`-wrapped so the
    /// janitor task spawned per session can hold a handle for eviction
    /// after the pump task exits on remote disconnect.
    pub(crate) sessions: Arc<tokio::sync::RwLock<HashMap<u32, Arc<SshSession>>>>,
    next_id: AtomicU32,
}

impl Default for SshState {
    fn default() -> Self {
        Self {
            sessions: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            next_id: AtomicU32::new(1),
        }
    }
}

/// One hop in a ProxyJump chain. Resolved on the frontend (the chain is walked
/// from saved connections and each hop's secrets are read from the keychain),
/// then passed in connect order so the backend just dials them in sequence.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SshJumpHop {
    /// Saved-connection id this hop came from, so the backend can echo it back
    /// in `JumpConnected` and the frontend pins the fingerprint on the right row.
    pub connection_id: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    /// Authenticate this hop through the local ssh-agent. Takes precedence over
    /// the two fields below, which are then absent.
    #[serde(default)]
    pub use_agent: bool,
    pub password: Option<String>,
    pub private_key: Option<String>,
    pub private_key_passphrase: Option<String>,
    pub expected_fingerprint: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SshOpenInput {
    pub host: String,
    pub port: u16,
    pub user: String,
    /// Authenticate through the local ssh-agent: the agent signs the handshake
    /// and the private key never reaches Tervia. One of this, `password` or
    /// `private_key` must be set.
    #[serde(default)]
    pub use_agent: bool,
    /// Plain password.
    pub password: Option<String>,
    /// PEM-encoded private key text (OpenSSH or PKCS8). Optional passphrase
    /// in `private_key_passphrase`.
    pub private_key: Option<String>,
    pub private_key_passphrase: Option<String>,
    /// SHA256 fingerprint ("SHA256:...") of the server key recorded by a
    /// previous successful connect. When set, the handshake fails fast if
    /// the server presents a different key, blocking silent MITM on saved
    /// connections. `None` on first connect (TOFU) and on dialog-time
    /// test connections for brand-new hosts.
    pub expected_fingerprint: Option<String>,
    /// ProxyJump chain in connect order (publicly-reachable entry host first;
    /// the hop closest to the target last). Empty/absent = direct connection.
    #[serde(default)]
    pub jumps: Vec<SshJumpHop>,
    pub cols: u16,
    pub rows: u16,
}

/// One key the local ssh-agent is holding. Read-only: the agent never hands out
/// the private half, so this is everything Tervia can know about it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SshAgentKey {
    /// Wire algorithm name, e.g. `ssh-ed25519`.
    pub algorithm: String,
    /// The comment the key was added with, usually `user@machine`. Often empty.
    pub comment: String,
    /// `SHA256:...`, the same form `ssh-add -l` prints.
    pub fingerprint: String,
}

/// Keys currently loaded in the local ssh-agent. Backs the connection dialog's
/// agent panel: with no field to fill in, "is the agent up and does it hold a
/// key" IS the validation for agent auth, so it is answered before saving
/// rather than at dial time.
#[tauri::command]
pub async fn ssh_agent_keys() -> Result<Vec<SshAgentKey>, String> {
    ssh_runtime()
        .spawn(async {
            let (_agent, keys) = session::agent_keys().await?;
            Ok::<_, String>(
                keys.iter()
                    .map(|k| SshAgentKey {
                        algorithm: k.algorithm().to_string(),
                        comment: k.comment().to_string(),
                        fingerprint: k.fingerprint(russh::keys::HashAlg::Sha256).to_string(),
                    })
                    .collect(),
            )
        })
        .await
        .map_err(|e| format!("ssh agent task join failed: {e}"))?
}

/// What a pasted private key can be described as without dialing anything.
/// Filled by `ssh_key_inspect` so a saved key carries its algorithm and
/// fingerprint from the moment it is imported.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SshKeyInfo {
    /// `false` means the caller must ask for a passphrase and call again: the
    /// key is readable, but its container hides everything below.
    pub parsed: bool,
    pub encrypted: bool,
    /// Wire algorithm name, e.g. `ssh-ed25519`, `ecdsa-sha2-nistp256`.
    pub key_type: Option<String>,
    /// `SHA256:...`, the same form `ssh-keygen -lf` prints.
    pub fingerprint: Option<String>,
    /// The `.pub` line: `ssh-ed25519 AAAA... comment`, minus the comment when
    /// that is not readable (see below).
    pub public_key: Option<String>,
    /// Absent for an encrypted `openssh-key-v1` key inspected without its
    /// passphrase: that container keeps the public half in cleartext but seals
    /// the comment inside the private section. Pass the passphrase to get it.
    pub comment: Option<String>,
}

/// Header-level shape of pasted key text, decided before any parse attempt.
/// Four of these variants are dead ends inside russh, and without this step
/// every one of them surfaces as the same `Could not read key`, which tells the
/// user nothing about which of their key files to try next.
#[derive(Debug)]
enum KeyFormat {
    /// `openssh-key-v1`. The container keeps the public half in cleartext next
    /// to the encrypted private section, so metadata needs no passphrase.
    OpenSsh,
    /// Any other container russh accepts: PKCS#1, PKCS#8, PuTTY `.ppk`.
    /// `encrypted` comes from the header (`ENCRYPTED PRIVATE KEY`, `DEK-Info:`,
    /// PuTTY's `Encryption:`); these formats seal the public half away too, so
    /// `true` means nothing at all is knowable until the passphrase arrives.
    Other {
        encrypted: bool,
    },
    /// A `.pub` / `authorized_keys` line, or a PEM public block.
    PublicKey,
    /// russh has no DSA branch and our build leaves its `dsa` feature off.
    Dsa,
    /// SEC1. russh matches the label but routes it to the PKCS#8 decoder,
    /// which is a different encoding, so it fails with a misleading error.
    Sec1,
    /// PKCS#1 under a PEM cipher russh does not implement (only AES-128-CBC is
    /// wired up; AES-256 and 3DES fall through to the DER decoder).
    UnsupportedPemCipher,
    Unknown,
}

/// Algorithm names as they appear at the start of a `.pub` line.
const PUBLIC_KEY_PREFIXES: &[&str] = &[
    "ssh-rsa",
    "ssh-dss",
    "ssh-ed25519",
    "ssh-ed448",
    "ecdsa-sha2-",
    "sk-ssh-ed25519",
    "sk-ecdsa-sha2-",
];

/// A PKCS#1 block sealed with a PEM cipher names it in a `DEK-Info:` header.
/// russh only builds a decryptor for AES-128-CBC.
fn pkcs1_cipher(text: &str) -> KeyFormat {
    for line in text.lines().map(str::trim) {
        if let Some(cipher) = line.strip_prefix("DEK-Info:") {
            return if cipher.trim_start().starts_with("AES-128-CBC,") {
                KeyFormat::Other { encrypted: true }
            } else {
                KeyFormat::UnsupportedPemCipher
            };
        }
    }
    KeyFormat::Other { encrypted: false }
}

/// Classifies `text`, and also hands back the slice of it the winning marker
/// actually starts at. That slice - not the full paste - is what the caller
/// must feed to the real parser: `ssh_key::PrivateKey::from_openssh` (behind
/// `KeyFormat::OpenSsh`) only understands one encapsulated PEM message and
/// takes the label of whichever `-----BEGIN ...-----` line it meets first, so
/// if an earlier public-key block's own label rides along, the *real* key's
/// closing `-----END-----` no longer matches it and a good private key comes
/// back unreadable. Trimming the paste down to "the winning marker onward"
/// avoids that regardless of what came before it.
fn classify(text: &str) -> (KeyFormat, &str) {
    // A private-key marker anywhere in the paste wins, even over a public-key
    // marker earlier in the text - bare `.pub` line or PEM block alike: a user
    // pasting both halves out of one file listing, or a PEM-reencoded public
    // half (`ssh-keygen -e`) pasted above their real key, should get the
    // private key, not a "that is a public key" bounce. So a public-key label
    // only sets a pending verdict and keeps scanning; every other label is
    // still a dead end the moment it is seen, same as before.
    let mut pending_public = false;
    // Walked one line at a time via `split_once`, rather than `text.lines()`,
    // so `rest` stays a real slice of `text` running from the current line to
    // the paste's end - exactly what a winning marker further down needs to
    // hand back, with no byte-index arithmetic of our own.
    let mut rest = text;
    while !rest.is_empty() {
        let (line, after) = rest.split_once('\n').unwrap_or((rest, ""));
        let trimmed = line.trim();
        if trimmed.starts_with("PuTTY-User-Key-File-") {
            let encrypted = rest.lines().any(|l| {
                l.trim()
                    .strip_prefix("Encryption:")
                    .is_some_and(|v| v.trim() != "none")
            });
            return (KeyFormat::Other { encrypted }, rest);
        }
        if let Some(label) = trimmed
            .strip_prefix("-----BEGIN ")
            .and_then(|l| l.strip_suffix("-----"))
        {
            match label {
                "OPENSSH PRIVATE KEY" => return (KeyFormat::OpenSsh, rest),
                "DSA PRIVATE KEY" => return (KeyFormat::Dsa, rest),
                "EC PRIVATE KEY" => return (KeyFormat::Sec1, rest),
                "ENCRYPTED PRIVATE KEY" => return (KeyFormat::Other { encrypted: true }, rest),
                "PRIVATE KEY" => return (KeyFormat::Other { encrypted: false }, rest),
                "RSA PRIVATE KEY" => return (pkcs1_cipher(rest), rest),
                "PUBLIC KEY" | "RSA PUBLIC KEY" | "SSH2 PUBLIC KEY" => pending_public = true,
                _ => return (KeyFormat::Unknown, rest),
            }
        }
        rest = after;
    }
    if pending_public {
        return (KeyFormat::PublicKey, text);
    }

    // No BEGIN marker and no PuTTY header anywhere: the only shapes left are
    // a bare `.pub` / authorized_keys line and the RFC 4716 public format
    // (which spells its delimiters with four dashes and spaces, not
    // `-----BEGIN `), and both are only ever public keys.
    let Some(first) = text.lines().map(str::trim).find(|l| !l.is_empty()) else {
        return (KeyFormat::Unknown, text);
    };
    if PUBLIC_KEY_PREFIXES.iter().any(|p| first.starts_with(p))
        || first.starts_with("---- BEGIN SSH2 PUBLIC KEY ----")
    {
        return (KeyFormat::PublicKey, text);
    }
    (KeyFormat::Unknown, text)
}

/// Everything `SshKeyInfo` can say about a key. Also runs on a still-encrypted
/// `openssh-key-v1` handle, where the public half is cleartext.
///
/// Fallible, and deliberately the only way a parsed key becomes an `SshKeyInfo`:
/// the DSA refusal below has to hold at every one of `ssh_key_inspect_inner`'s
/// returns, and living here means a future fifth return cannot quietly skip it.
/// There is no infallible constructor left to reach for, so forgetting the check
/// is a type error at the new call site rather than a silent hole.
fn key_info(key: &PrivateKey, encrypted: bool) -> Result<SshKeyInfo, String> {
    // The container format cannot answer "is this DSA?", so `classify` cannot
    // be where this is decided: it only sees DSA when a PEM `DSA PRIVATE KEY`
    // label spells it out, and a modern `ssh-keygen -t dsa` writes
    // `openssh-key-v1` instead - which classifies as `OpenSsh`, parses
    // perfectly well, and reported `ssh-dss` with a real fingerprint and public
    // half for a key that can never authenticate (russh is built without its
    // `dsa` feature - see `KeyFormat::Dsa`), leaving the user to discover that
    // at dial time instead. So the guard is on the parsed algorithm, and it is
    // checked before any of the key's facts are read.
    if key.algorithm().is_dsa() {
        return Err(ERR_DSA.into());
    }
    let comment = key.comment().trim();
    Ok(SshKeyInfo {
        parsed: true,
        encrypted,
        key_type: Some(key.algorithm().to_string()),
        fingerprint: Some(key.fingerprint(russh::keys::HashAlg::Sha256).to_string()),
        public_key: key.public_key().to_openssh().ok(),
        comment: (!comment.is_empty()).then(|| comment.to_string()),
    })
}

/// The container sealed the public half away, so nothing is knowable yet. Not
/// an `Err`: the caller prompts for the passphrase and calls again.
fn needs_passphrase() -> SshKeyInfo {
    SshKeyInfo {
        parsed: false,
        encrypted: true,
        key_type: None,
        fingerprint: None,
        public_key: None,
        comment: None,
    }
}

// One message per dead end. russh answers every unreadable key with the same
// `Could not read key` and a wrong passphrase with a raw `Unpad Error`, neither
// of which tells the user which of their key files to reach for next. None of
// these ever interpolate the key body or the passphrase.
const ERR_EMPTY: &str = "ssh: no key text - paste a private key or pick a key file";
const ERR_PUBLIC_KEY: &str =
    "ssh: that is a public key. Paste the private key instead - the same file, without the \
     .pub suffix";
const ERR_DSA: &str =
    "ssh: DSA keys are not supported (OpenSSH disables them too). Generate an Ed25519 key: \
     ssh-keygen -t ed25519";
const ERR_SEC1: &str =
    "ssh: this is a SEC1 \"EC PRIVATE KEY\" file, which Tervia cannot read. Rewrite it in \
     OpenSSH format: ssh-keygen -p -f <keyfile>";
const ERR_PEM_CIPHER: &str =
    "ssh: this PEM key is sealed with a cipher Tervia cannot read (only AES-128-CBC). Rewrite \
     it in OpenSSH format: ssh-keygen -p -f <keyfile>";
const ERR_UNKNOWN: &str =
    "ssh: unrecognised key format. Expected a \"-----BEGIN ... PRIVATE KEY-----\" block or a \
     PuTTY .ppk; the text may also be truncated";
const ERR_OPENSSH_BODY: &str =
    "ssh: could not read this OpenSSH private key - the block looks truncated or altered";
const ERR_UNREADABLE: &str =
    "ssh: could not read this private key - the block looks truncated, altered, or uses an \
     unsupported cipher";
const ERR_WRONG_PASSPHRASE: &str = "ssh: wrong passphrase for this private key";
const ERR_PASSPHRASE_OR_CORRUPT: &str =
    "ssh: wrong passphrase for this private key, or the encrypted block is truncated or corrupt";

/// Describe a private key the user just pasted or picked, without connecting.
/// Backs the vault's key editor, which stores the algorithm, fingerprint and
/// `.pub` line next to the secret so a saved key stays identifiable later.
///
/// Rust rather than the frontend for two reasons: nothing in the JS tree parses
/// an SSH key, and `crypto.subtle` is undefined at the bundled app's
/// `http://tauri.localhost` origin (it is secure-context only), so a JS
/// implementation would work under `tauri dev` and fail only in the release
/// bundle - the most expensive place to find out.
///
/// Async because unlocking a key runs bcrypt-pbkdf, and the round count comes
/// from the key file's own header: a hand-edited key can make that take as long
/// as it likes, which on a sync command is a frozen WebView2 window.
#[tauri::command]
pub async fn ssh_key_inspect(
    pem: String,
    passphrase: Option<String>,
) -> Result<SshKeyInfo, String> {
    tauri::async_runtime::spawn_blocking(move || ssh_key_inspect_inner(&pem, passphrase.as_deref()))
        .await
        .map_err(|e| format!("ssh_key_inspect join error: {e}"))?
}

fn ssh_key_inspect_inner(pem: &str, passphrase: Option<&str>) -> Result<SshKeyInfo, String> {
    let text = pem.trim();
    if text.is_empty() {
        return Err(ERR_EMPTY.into());
    }
    let pass = passphrase.filter(|p| !p.is_empty());

    // `key_text` is `text` trimmed down to "the winning marker onward" - see
    // `classify`'s own doc comment for why the two can differ and why the
    // parse below must use `key_text`, not `text`.
    let (format, key_text) = classify(text);
    let encrypted = match format {
        KeyFormat::PublicKey => return Err(ERR_PUBLIC_KEY.into()),
        KeyFormat::Dsa => return Err(ERR_DSA.into()),
        KeyFormat::Sec1 => return Err(ERR_SEC1.into()),
        KeyFormat::UnsupportedPemCipher => return Err(ERR_PEM_CIPHER.into()),
        KeyFormat::Unknown => return Err(ERR_UNKNOWN.into()),
        // openssh-key-v1 declares its cipher inside the container and parses
        // either way, so here the parse is what decides `encrypted`.
        KeyFormat::OpenSsh => {
            let key =
                PrivateKey::from_openssh(key_text).map_err(|_| ERR_OPENSSH_BODY.to_string())?;
            if !key.is_encrypted() {
                return key_info(&key, false);
            }
            return match pass {
                // Decrypting proves the passphrase before dial time, and is
                // also the only route to the comment: the container keeps the
                // public half in cleartext but seals the comment away with the
                // private one.
                Some(pass) => key
                    .decrypt(pass)
                    .map_err(|_| ERR_WRONG_PASSPHRASE.to_string())
                    .and_then(|open| key_info(&open, true)),
                // The public half is cleartext here, so the algorithm is
                // knowable without the passphrase - which means a DSA key is
                // refused now rather than being reported and deferred.
                None => key_info(&key, true),
            };
        }
        KeyFormat::Other { encrypted } => encrypted,
    };

    if encrypted && pass.is_none() {
        return Ok(needs_passphrase());
    }
    match russh::keys::decode_secret_key(key_text, pass) {
        Ok(key) => key_info(&key, encrypted),
        // Backstop for a container that did not announce its encryption in a
        // header spelling `classify` recognises.
        Err(russh::keys::Error::KeyIsEncrypted) if pass.is_none() => Ok(needs_passphrase()),
        // PKCS#8's own truncation does surface as a distinct DER error, but
        // PKCS#1 under AES-128-CBC - the other format that reaches this
        // branch - fails a truncated body and a wrong passphrase identically
        // (both trip the same padding error). `encrypted` alone cannot tell
        // which format this was, so splitting on the crate's error variant
        // would be right for one and confidently wrong for the other. Name
        // both possibilities instead of picking.
        Err(_) if encrypted => Err(ERR_PASSPHRASE_OR_CORRUPT.into()),
        Err(_) => Err(ERR_UNREADABLE.into()),
    }
}

#[tauri::command]
pub async fn ssh_open(
    state: tauri::State<'_, SshState>,
    input: SshOpenInput,
    on_event: Channel<SshEvent>,
) -> Result<u32, String> {
    let rt = ssh_runtime();
    let session = rt
        .spawn(session::connect(input, on_event))
        .await
        .map_err(|e| format!("ssh task join failed: {e}"))?
        .map_err(|e| {
            log::error!("ssh_open failed: {e}");
            e
        })?;
    let id = state.next_id.fetch_add(1, Ordering::Relaxed);
    // Take the exit receiver before handing the Arc to the map so the
    // janitor can wait for the pump task to finish without racing another
    // caller for the slot. Receiver fires on normal exit (Eof/Close, peer
    // hangup) and on pump abort (because the oneshot Sender is then dropped),
    // so explicit close paths also wake the janitor; it just no-ops on the
    // already-removed id.
    let exit_signal = session.take_exit_signal();
    let sessions_handle = state.sessions.clone();
    state.sessions.write().await.insert(id, session);
    if let Some(rx) = exit_signal {
        rt.spawn(async move {
            let _ = rx.await;
            sessions_handle.write().await.remove(&id);
            log::info!("ssh session id={id} evicted after pump exit");
        });
    }
    log::info!("ssh opened id={id}");
    Ok(id)
}

#[tauri::command]
pub async fn ssh_write(
    state: tauri::State<'_, SshState>,
    id: u32,
    data: String,
) -> Result<(), String> {
    let session = state
        .sessions
        .read()
        .await
        .get(&id)
        .cloned()
        .ok_or_else(|| {
            log::warn!("ssh_write: unknown id={id}");
            "no session".to_string()
        })?;
    session.write(data.as_bytes()).await
}

#[tauri::command]
pub async fn ssh_resize(
    state: tauri::State<'_, SshState>,
    id: u32,
    cols: u16,
    rows: u16,
) -> Result<(), String> {
    let session = state
        .sessions
        .read()
        .await
        .get(&id)
        .cloned()
        .ok_or_else(|| {
            log::warn!("ssh_resize: unknown id={id}");
            "no session".to_string()
        })?;
    session.resize(cols, rows).await
}

#[tauri::command]
pub async fn ssh_close(state: tauri::State<'_, SshState>, id: u32) -> Result<(), String> {
    let session = state.sessions.write().await.remove(&id);
    if let Some(s) = session {
        s.close().await;
        log::info!("ssh closed id={id}");
    } else {
        log::debug!("ssh_close: unknown id={id}");
    }
    Ok(())
}

/// `ssh -L`: bind `127.0.0.1:local_port` on this machine and tunnel every
/// connection to `remote_host:remote_port` as resolved from the SERVER, over
/// the live session `id` (so a ProxyJump chain applies for free). `local_port`
/// 0 picks a free port; the bound port is returned for the caller to report.
///
/// No close command on purpose: forwards are declared on the saved connection
/// and re-opened on every connect, so the session's own teardown is the only
/// lifecycle they need.
#[tauri::command]
pub async fn ssh_forward_open(
    state: tauri::State<'_, SshState>,
    id: u32,
    local_port: u16,
    remote_host: String,
    remote_port: u16,
) -> Result<u16, String> {
    let remote_host = remote_host.trim().to_string();
    if remote_host.is_empty() {
        return Err("ssh: port forward needs a remote host".into());
    }
    if remote_port == 0 {
        return Err("ssh: port forward needs a remote port".into());
    }
    let session = state
        .sessions
        .read()
        .await
        .get(&id)
        .cloned()
        .ok_or_else(|| {
            log::warn!("ssh_forward_open: unknown id={id}");
            "no session".to_string()
        })?;
    // Bind and accept on the SSH runtime, not tauri's: the listener and the
    // russh channels it feeds must be driven by the same reactor.
    ssh_runtime()
        .spawn(async move {
            session
                .open_forward(local_port, remote_host, remote_port)
                .await
        })
        .await
        .map_err(|e| format!("ssh forward task join failed: {e}"))?
}

/// Answer a first-connect `HostKeyPrompt`. `accept = true` lets the paused
/// handshake proceed (and the connection pins the fingerprint on success);
/// `accept = false` aborts the connect before any credential is sent. Called
/// by the frontend confirmation dialog. No-op (Err) if the prompt already
/// timed out or was answered.
#[tauri::command]
pub fn ssh_confirm_host_key(prompt_id: String, accept: bool) -> Result<(), String> {
    match session::take_pending_host_key(&prompt_id) {
        Some(tx) => {
            // Receiver may already be gone if the connect timed out; ignore.
            let _ = tx.send(accept);
            Ok(())
        }
        None => Err("ssh: unknown or already-answered host-key prompt".into()),
    }
}

/// Metadata for one live SSH session, returned by `ssh_list_sessions`. Lets the
/// remote-access bridge enumerate SSH tabs the GUI has open (they live here, not
/// in the PTY daemon) before attaching to mirror them.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SshSessionInfo {
    pub id: u32,
    pub host: String,
    pub user: String,
    pub cols: u16,
    pub rows: u16,
    pub alive: bool,
    pub created_at_ms: u64,
}

#[tauri::command]
pub async fn ssh_list_sessions(
    state: tauri::State<'_, SshState>,
) -> Result<Vec<SshSessionInfo>, String> {
    let map = state.sessions.read().await;
    let mut out = Vec::with_capacity(map.len());
    for (id, s) in map.iter() {
        let (host, user, cols, rows, alive, created_at_ms) = s.mirror_info();
        out.push(SshSessionInfo {
            id: *id,
            host,
            user,
            cols,
            rows,
            alive,
            created_at_ms,
        });
    }
    Ok(out)
}

/// Attach an additional event sink to an existing SSH session so a second
/// consumer (the remote-access bridge) mirrors its output + writes input via
/// `ssh_write`. Replays the recent ring on attach. Returns `alive`.
#[tauri::command]
pub async fn ssh_attach(
    state: tauri::State<'_, SshState>,
    id: u32,
    on_event: Channel<SshEvent>,
) -> Result<bool, String> {
    let session = state
        .sessions
        .read()
        .await
        .get(&id)
        .cloned()
        .ok_or_else(|| {
            log::warn!("ssh_attach: unknown id={id}");
            "no session".to_string()
        })?;
    Ok(session.add_mirror_sink(on_event))
}

/// Single-quote a value for a POSIX shell so a remote-supplied path can never
/// break out of its argument. `cwd` reaches us from the remote shell's OSC 7
/// escape, i.e. it is attacker-controlled if the host is compromised.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Last non-empty line of a remote command's stdout.
///
/// sshd runs an exec request through the user's login shell, and bash sources
/// `~/.bashrc` on that path, so anything an rc file echoes (a greeting, nvm /
/// conda / direnv chatter) is prepended to the output we asked for. Every value
/// we read back is single-line, so the last line is the answer.
fn last_line(s: &str) -> &str {
    s.lines()
        .rev()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("")
}

/// `git status` for the repo containing `cwd` on the remote, so Source Control
/// follows the machine you are working on instead of the local workspace. The
/// caller picks `cwd` (the folder the Remote tree is browsing, else the SSH
/// terminal's OSC 7 cwd); empty means the remote login directory.
///
/// Read-only by design: it reuses the existing porcelain parsers but skips the
/// numstat / line-count enrichment, which reads the LOCAL disk. `added`,
/// `removed` and `binary` therefore stay at their defaults for remote entries.
#[tauri::command]
pub async fn ssh_git_status(
    state: tauri::State<'_, SshState>,
    id: u32,
    cwd: String,
) -> Result<crate::modules::git::commands::GitStatus, String> {
    use crate::modules::git::commands::{parse_branch_header, parse_porcelain_v1, GitStatus};

    let session = state
        .sessions
        .read()
        .await
        .get(&id)
        .cloned()
        .ok_or_else(|| "no session".to_string())?;

    let not_a_repo = || GitStatus {
        is_repo: false,
        root: None,
        branch: None,
        upstream: None,
        ahead: 0,
        behind: 0,
        changes: Vec::new(),
    };

    let cd = if cwd.is_empty() {
        String::new()
    } else {
        format!("-C {} ", shell_quote(&cwd))
    };
    // No `2>/dev/null`: stderr arrives on its own channel, so it cannot mix into
    // stdout, and dropping it is what made every failure look like "no repo".
    let root = match session
        .exec_capture(&format!("git {cd}rev-parse --show-toplevel"))
        .await
    {
        Ok(s) => s,
        // The one expected failure. Anything else (git not on sshd's PATH,
        // dubious ownership, a cwd that no longer exists, exec denied) is a real
        // error the user needs to read, not a silent empty panel.
        //
        // Matching on git's English text is safe here: we send no env, so an
        // sshd exec channel runs in the C locale and git does not translate.
        Err(e) if e.contains("not a git repository") => return Ok(not_a_repo()),
        Err(e) => return Err(e),
    };
    let root = last_line(&root);
    if root.is_empty() {
        return Ok(not_a_repo());
    }

    let raw = session
        .exec_capture(&format!(
            "git -C {} status --porcelain=v1 --branch -z --untracked-files=all",
            shell_quote(root)
        ))
        .await?;
    // `--branch` always emits a header, so this is only reachable when the
    // remote git was killed by a signal: russh reports that as ExitSignal, not
    // ExitStatus, so `exit` stays 0 and we get a successful-looking empty read.
    if raw.is_empty() {
        return Ok(not_a_repo());
    }
    // The `--branch` header is the first -z record; the rest are file entries.
    let (header, entries) = raw.split_once('\0').unwrap_or((raw.as_str(), ""));
    // Same rc-noise guard as the root above, so a chatty ~/.bashrc can't be
    // parsed as the branch name.
    let header = last_line(header);
    let (branch, upstream, ahead, behind) = parse_branch_header(header);
    Ok(GitStatus {
        is_repo: true,
        root: Some(root.to_string()),
        branch,
        upstream,
        ahead,
        behind,
        // `root.join(rel)` on a Windows host yields a mixed separator, which
        // the parser's `to_forward` normalizes back to a POSIX path.
        changes: parse_porcelain_v1(std::path::Path::new(root), entries),
    })
}

/// Run one whitelisted git subcommand in `cwd` on the remote and return its
/// stdout; a non-zero exit is an `Err` carrying the remote's stderr.
///
/// The counterpart to `git_run`, taking the identical argument vector, so the
/// Source Control panel drives a remote repository through the same code path
/// as a local one instead of a parallel remote-only implementation. Every
/// argument is single-quoted before it reaches the remote shell, and the
/// subcommand is held to the same list as the local runner.
#[tauri::command]
pub async fn ssh_git(
    state: tauri::State<'_, SshState>,
    id: u32,
    cwd: String,
    args: Vec<String>,
) -> Result<String, String> {
    crate::modules::git::commands::check_args(&args)?;
    let session = state
        .sessions
        .read()
        .await
        .get(&id)
        .cloned()
        .ok_or_else(|| "no session".to_string())?;

    let mut cmd = String::from("git");
    if !cwd.is_empty() {
        cmd.push_str(" -C ");
        cmd.push_str(&shell_quote(&cwd));
    }
    for a in &args {
        cmd.push(' ');
        cmd.push_str(&shell_quote(a));
    }
    session.exec_capture(&cmd).await
}

#[cfg(test)]
mod tests {
    use super::{
        last_line, shell_quote, ssh_key_inspect_inner, ERR_OPENSSH_BODY, ERR_PASSPHRASE_OR_CORRUPT,
        ERR_UNREADABLE, ERR_WRONG_PASSPHRASE,
    };

    /// `ssh-keygen -t ed25519 -N '' -C tervia-test@localhost`.
    const PLAIN_ED25519: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCpiSS98IJopmYjIYYYws9TOgU3Ea4xkeK/EOt/MFC7DgAAAJgXJ7ZJFye2
SQAAAAtzc2gtZWQyNTUxOQAAACCpiSS98IJopmYjIYYYws9TOgU3Ea4xkeK/EOt/MFC7Dg
AAAEDH4z8V4hBdxn69onazIThdJ8CfUxtV6E2q/d90hwg0NamJJL3wgmimZiMhhhjCz1M6
BTcRrjGR4r8Q638wULsOAAAAFXRlcnZpYS10ZXN0QGxvY2FsaG9zdA==
-----END OPENSSH PRIVATE KEY-----
";

    /// Same generator, `-N 'correct horse' -C locked@localhost`. Sealed with
    /// aes256-ctr + bcrypt, i.e. what `ssh-keygen` writes today.
    const LOCKED_ED25519: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCwylXWi+
kiYmMux9+mAHW7AAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIIV04PSMQuoltd8p
xWSst9WNSgq6TbtLy8n97mOwx0fCAAAAoPWSFxWm0Yr2fDdXJIGaXhv574j3UhPQn3/aPd
fS9FItOIt5N/GdGWGlAmky6lVGOYgGn4/UvCO9fqbbPjiviHZTu+RLlfn1sJQMW8v/5Y9T
qnNmSdmyWZ6SzYQKSVg3Zs20dzS/AZE8Q6O6vMvTR75vPl9ROvzNQZo9bkPuuuwW+A3tth
wjku8Bjzhc/ZHJ8MP4SAn9x5GySFuup/SKJ+E=
-----END OPENSSH PRIVATE KEY-----
";

    const LOCKED_PASSPHRASE: &str = "correct horse";

    /// The `.pub` half of `LOCKED_ED25519`, as the file on disk holds it.
    const LOCKED_PUB: &str = "ssh-ed25519 \
AAAAC3NzaC1lZDI1NTE5AAAAIIV04PSMQuoltd8pxWSst9WNSgq6TbtLy8n97mOwx0fC locked@localhost
";

    /// `ssh-keygen -e -m PKCS8` (or `openssl pkey -pubout`) over an unrelated
    /// Ed25519 key: SubjectPublicKeyInfo, the PEM shape a user gets from
    /// re-encoding their `.pub` file, not just the bare `ssh-ed25519 ...` line.
    const PEM_PUBLIC_KEY: &str = "\
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAbs85KIUTamLr4OvfDmLEO74OpTXKm6pyFFCLdlLhYd4=
-----END PUBLIC KEY-----
";

    /// `openssl rsa -in key.pem -RSAPublicKey_out`: PKCS#1's own public form,
    /// distinct from the SubjectPublicKeyInfo one above.
    const PEM_RSA_PUBLIC_KEY: &str = "\
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAx1AI3he4sbMMg+T8xX7bwAdu2DWL6hQVhETToDeqJcWEORq/NDk0
tjQNeoXC/RCerKA8XycykuF3Zezyr/+1qHhhUeOl2S+so65R9IH+LCzbp2sZFqG+
qhEOb19emMcmlO7z1pmCfYx0dxuBqOJjIMS+tKr84+enWSaHyHet/aoMjUOXTJTO
nqtJeMrRZZM7htLsycZ2bLkykuOfSfN0axbymKPz2EpOZ7O124PxzMfZIFSbaQjf
zab6fud4hufXIrVuI6/hXANa/NxXQe1NG1YdFGy6O58Uh09hWxphRR66AJCWMfwf
1O6JanFfHZGdO8dHMevhjJOoDl1LjjNY+wIDAQAB
-----END RSA PUBLIC KEY-----
";

    /// The five-dash `-----BEGIN SSH2 PUBLIC KEY-----` spelling `classify`
    /// matches in its main scan - distinct from the real RFC 4716 delimiter
    /// (`---- BEGIN SSH2 PUBLIC KEY ----`, four dashes with a space) that only
    /// the no-BEGIN-marker fallback recognises. Body content is never parsed
    /// for a `PublicKey` verdict, so any base64-shaped filler is fine.
    const PEM_SSH2_PUBLIC_KEY: &str = "\
-----BEGIN SSH2 PUBLIC KEY-----
Comment: \"locked@localhost\"
AAAAC3NzaC1lZDI1NTE5AAAAIIV04PSMQuoltd8pxWSst9WNSgq6TbtLy8n97mOwx0fC
-----END SSH2 PUBLIC KEY-----
";

    /// `openssl pkcs8 -topk8 -v2 aes-256-cbc` over an Ed25519 key. PKCS#8 seals
    /// the public half too, which is what makes it the `parsed: false` case.
    const LOCKED_PKCS8: &str = "\
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIGbMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAgwfFRyLE9zWAICCAAw
DAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEELjoxHK6zugwvcWrUOvS+BgEQL2v
mK+rW02yV3neLVo54432BYqBtEx0YS330rlSCGuoCr/xtFkRhVmIomUdBkLAHLaW
NFLh6spvancYRsI2aeg=
-----END ENCRYPTED PRIVATE KEY-----
";

    /// Unlike `LOCKED_PKCS8` above, this one's passphrase is known, so a test
    /// can prove a successful decrypt rather than only the locked state.
    /// `openssl genpkey -algorithm ed25519 | openssl pkcs8 -topk8 -v2 \
    /// aes-256-cbc -passout pass:"correct horse"`.
    const PKCS8_WITH_PASSPHRASE: &str = "\
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIGbMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAikhE7BR4YNCAICCAAw
DAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEKIjpvTXc999fuVotdE2JkMEQMCP
ofFkAiIlNcNnazc463ZNbpAlYoNR+P8z5ZoTM4HIZKbYN5Mv52sNyVzkTsRR+Gm5
KNd5sJnk8aPMfCfuMgw=
-----END ENCRYPTED PRIVATE KEY-----
";

    const PKCS8_PASSPHRASE: &str = "correct horse";

    /// `PKCS8_WITH_PASSPHRASE` with its last body line cut - a paste stopped
    /// short before the `-----END` marker.
    const PKCS8_TRUNCATED: &str = "\
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIGbMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAikhE7BR4YNCAICCAAw
DAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEKIjpvTXc999fuVotdE2JkMEQMCP
ofFkAiIlNcNnazc463ZNbpAlYoNR+P8z5ZoTM4HIZKbYN5Mv52sNyVzkTsRR+Gm5
-----END ENCRYPTED PRIVATE KEY-----
";

    /// `openssl ecparam -name prime256v1 -genkey`: SEC1, not PKCS#8.
    const SEC1_EC: &str = "\
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIF+Z87dQ+QZ7HKVouBriKFkmgwSQkFmU07SO7mw0mP4/oAoGCCqGSM49
AwEHoUQDQgAErb3d6eqMzYQ2LKS02m6gajVJ/Rioqr8Ua03ulJiJUsWO7xqYtppl
j5UVz/3hnNtMPH5LS8Ch+X/SqvjoyTix5A==
-----END EC PRIVATE KEY-----
";

    /// `openssl dsaparam -genkey 1024` then `openssl pkey -traditional`.
    const DSA_KEY: &str = "\
-----BEGIN DSA PRIVATE KEY-----
MIIBygIBAAKBgQCwOgKbIx8T+tWvMkuiqFapRCtwsOA2/ZlI+GeZQNxSPtCgNnTu
5glKxTjc05dmpX/oMMRVLJ0hcw/wHNeg7M3GW2zTEgMNTfF9t06s8X20tgFbuH9a
TqSb7ysMX/VERF+//dQuDIi454V1BWAaClUHekFtxhjbxHdpi/6tAIImbQIdALJV
3k0qGonFe97i3IRYsLSqXJVsEBdM2NDIhLECgYAJWCRBRT01gP57qNyTV8RoZMnb
4370twOlDyW2AIrc92QODU1UGIvcQIR0QddGAPRogxRZdHXJiH01pux3DAqfjebv
5WT5HN7sxTqz3aOCMmkPwpKlt7QwGgRPY1QKPgT9hPtEGg6Sr2HpKMS3W6Qmriw2
e2zta+WiCVDqhYd9lwKBgF3FTTUClJ2mWFPNxp+b7fnv00wbiCU5jxCuUB2kJPhg
D/yuNSIgX20n7qqEjVIcmmPKBpATO6l2qAfULsdHtXTuDXapAg2cNSax1VnIVnwy
uBL9s7PvVY1A2gLfCEIMmm1TgQev0OKPkH9IU/SKbA3aD+sHLEKMzZAoA7kw+7Lm
AhwCeWeDtuExuzPD2Rg81xs9YHAnUA1ZGBDZniIh
-----END DSA PRIVATE KEY-----
";

    /// The shape a modern `ssh-keygen -t dsa -N ''` actually writes:
    /// `openssh-key-v1` carrying `ssh-dss`, NOT the PEM `DSA_KEY` above. This is
    /// the reachable DSA case - it classifies as `OpenSsh`, parses, and was
    /// reported with full facts until the guard moved onto the algorithm.
    /// `-C dsa-plain@tervia`, OpenSSH 9.6p1.
    const DSA_OPENSSH: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABsQAAAAdzc2gtZH
NzAAAAgQCh0uAznz/kP76VCW0co1cEdLQyl2RFapJztA+v+098InkCxp12YDnv0oXd3CPu
SFT344Ncy96GaaHJ40xJSktAay5XQJzQ/Ilthf7TRqgs2ozxPVkua9mtD84g81nsrn/mQK
Ojg+RcVew1r0E8AK26SE6WTzJ7JYF9QpDreKmUyQAAABUAgMSrJyqPBBbDkdIDojnB8Pza
CZMAAACALUyQt1mYIEdhKyIhJXYO3oVTptIcP9kYD6Mm8CED6EwH7LVmvESIdBMJCy7CiE
TTRGImWKd//R0WjABMyuhtKoZBlQSiEbi5WsjlCyL9Z28j+OPwPakYSt7dw43qb0CMJvtO
5bKcy2ZGhV2XM9DChBk5D3ZX42Y3VU63kf2qrdsAAACAaTywEM2QbW94Xi8Y/wVUEIzr9C
Kv52MsFs7swPWWcGCWwtEylesSWeyWVJP4Ic/lK1czJNIpRDIxOJ8TrxJUaQqu7BK0KyG/
CJqRwjyR1R3++2RlcvqFATsMnziOsKuiCxlEiiQVcKy4Jrb7lKH1JdOREiRumvjp8hunYH
Bo3XgAAAHo42Id0uNiHdIAAAAHc3NoLWRzcwAAAIEAodLgM58/5D++lQltHKNXBHS0Mpdk
RWqSc7QPr/tPfCJ5AsaddmA579KF3dwj7khU9+ODXMvehmmhyeNMSUpLQGsuV0Cc0PyJbY
X+00aoLNqM8T1ZLmvZrQ/OIPNZ7K5/5kCjo4PkXFXsNa9BPACtukhOlk8yeyWBfUKQ63ip
lMkAAAAVAIDEqycqjwQWw5HSA6I5wfD82gmTAAAAgC1MkLdZmCBHYSsiISV2Dt6FU6bSHD
/ZGA+jJvAhA+hMB+y1ZrxEiHQTCQsuwohE00RiJlinf/0dFowATMrobSqGQZUEohG4uVrI
5Qsi/WdvI/jj8D2pGEre3cON6m9AjCb7TuWynMtmRoVdlzPQwoQZOQ92V+NmN1VOt5H9qq
3bAAAAgGk8sBDNkG1veF4vGP8FVBCM6/Qir+djLBbO7MD1lnBglsLRMpXrElnsllST+CHP
5StXMyTSKUQyMTifE68SVGkKruwStCshvwiakcI8kdUd/vtkZXL6hQE7DJ84jrCrogsZRI
okFXCsuCa2+5Sh9SXTkRIkbpr46fIbp2BwaN14AAAAFCeiDXchxHP4t75NntWOFFHFjj+c
AAAAEGRzYS1wbGFpbkB0ZXJ2aWEBAgM=
-----END OPENSSH PRIVATE KEY-----
";

    /// Same generator, `-N hunter2 -C dsa-enc@tervia`. Sealed with aes256-ctr +
    /// bcrypt, so the private section is unreadable but the `ssh-dss` public
    /// half is not - which is exactly why this one has to be refused without a
    /// passphrase rather than reported and deferred.
    const DSA_OPENSSH_LOCKED: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABA0EOyftK
clfaEu5B/FvGK/AAAAGAAAAAEAAAGyAAAAB3NzaC1kc3MAAACBAMUSV3Cr8et+GRDhR2+q
He3JARPPYMrZm1U/yUoopEuvRcJegg1+GLbecmpAGenmLQo13n7Oo30DY0sPRN+OgR/2z0
GtbXjBG1x8D0t5XdZao1wHepL8+6sI+fwAfAOvTRi0DR73+s49uAYvfB3M2B5vdm+s/NmV
FUqY+SaUmxOtAAAAFQCWl4GxBy2YkQrQpi9igWGFgbC1FQAAAIA+PnKWINPPl0koriJHBb
9U7pN0r1lyEr5IrkG1V6TmrgyTtGpvDN5+sU1ccHZth3DvU0ExD5OPRBpltDi2+65h4eLg
sFphMUcQzr7+A2myjAHAyrpIBIVSV5xrRJ0CbHz6s3cPWffP/hgwb8EL+KTueCVeRc5dcY
BFjKw+JJYhAwAAAIEAt4oRSEuTmwI++Hb/fzEZ1ROc/tyfvMVt8Frk8njIcUlIPXxF+Ru8
WSOTZRBZdLBIwRgbekA0rPrGfSNRzz7G2fk/wHVBiOKvdD8HiUUyP7IrRMwH1npoVKGRd8
U0uPEm31zsOFiok0Z03qPuEuT7TUQryeeZcVEXJxykp7u+6vIAAAHw35RbSdLAAzvNWdPQ
k7tE2tpKy+CvdFlzx90gAxTVCoWvnnX2q3hXl9SbAlNmolKLHagUBaKfAZWBPthjtcYJcU
/9pSP/QlvxUWM0Iat4ZWg4YUSpSGjMx/U9GxpN2EBkBx8Yv1ABw8TiyX+baSpS8sqOAQh3
WLQ1R7TXoQyv4NoAK7HcKWIwAOJS00YTBOf1vXLqaX/nwUeNdBKqjbob2WwmLM1/iVO9EB
UPIBpbzwu0obfh/9AKPfqLEsETcY04uSr5kpsngx6G3fUYkRWTW/K4DwCOZiQgpjcqTT2Z
uXVWaXGuCK8KI51HbXCoKu9NX6dZHD6bnDqtcLT2NrsDeEIJFxnyld8V9IghPt7TKsUPgx
ZHQGc5BjfBDHwEY7ANHi8GqDbF5i4GBYAKMiCVRZY4udI2kU1P6ROgYCnThfJBEIGSBwHQ
4OaUoHB9sRFLDC0prg/SEnXc+OomXMAZL00sHKiJguQWVQJMF9/wlRhZt4nmNUWuEQnvgZ
rEaioGlMcmehAGRKgTcRqivSXnt0kCJYelBOTOGxG53h7lnFAOpGU8yolyMnP1Vi4xNYlk
DA1Sjyjb6sHqJmJF6w2tgFyJJM5jQkcp31ELgHRP7S0Ip2qn7ylryzlXa0QvVID7QnhX3W
f+ibVfSVYFrOr5Wg==
-----END OPENSSH PRIVATE KEY-----
";

    const DSA_OPENSSH_PASSPHRASE: &str = "hunter2";

    /// A DSA key in the one container that reaches `decode_secret_key`:
    /// `openssl genpkey -genparam -algorithm DSA` then `openssl genpkey
    /// -paramfile`, i.e. unencrypted PKCS#8, which `classify` calls
    /// `Other { encrypted: false }`.
    const DSA_PKCS8: &str = "\
-----BEGIN PRIVATE KEY-----
MIIBSgIBADCCASsGByqGSM44BAEwggEeAoGBAJktnRHPslx0V9BrjjtSycz+7Odz
NMbv/MBynDzlIbLpx1J9WokI2xKU5eEHhfgwKZQbUETRBKG8cxcjxKk2Xqg7OINI
MQPtmooAws98kzvDYJ3pWh/KWYVIvx3ymDjH/5T1IOImkbibGR8VIf9Wk88kq3sk
xda8pdLQZydDK+3BAhUAtPxmLCeChPFSmhKtMc9BjYRi3RECgYBPHBL0ng+XcRTu
oawx9HBs6ZRfw80iP5lSGJCnwmVxxEYFhk4v4alqr6Pw7Em06Ztggi0nXKIjbfHZ
AKfC4wSnzqDi9+o+uIJ8odjI70948hH/bL8GJR/yO7cL6KiZfuE0f8L/grHOauZ+
+HhE+149VI8lvOhVL2LmGmoawky17AQWAhQFQ8W3FJqzDvpYkXcKLYgSYZtRaQ==
-----END PRIVATE KEY-----
";

    /// The negative control for the DSA refusals, generated by the same
    /// `ssh-keygen` in the same batch as `DSA_OPENSSH`: `-t ed25519 -N ''
    /// -C ed-neg@tervia`. Without it, a guard that refused every
    /// `openssh-key-v1` key would pass the DSA tests just as well.
    const ED25519_CONTROL: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACC5x3v+LqbeU+Aqw0+h3FZ6Qxme9fLMj7azlYjEUZ8SqgAAAJC4XCe1uFwn
tQAAAAtzc2gtZWQyNTUxOQAAACC5x3v+LqbeU+Aqw0+h3FZ6Qxme9fLMj7azlYjEUZ8Sqg
AAAEBZuBdpyWDn7eNJdlZASctO6ttvCdtTK5CnbOPKJbePcLnHe/4upt5T4CrDT6HcVnpD
GZ718syPtrOViMRRnxKqAAAADWVkLW5lZ0B0ZXJ2aWE=
-----END OPENSSH PRIVATE KEY-----
";

    /// Header-only fixture: the cipher name in `DEK-Info` is rejected before
    /// anything reads the body, so the body here is deliberately not a key.
    const PEM_3DES: &str = "\
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,9F2A1B3C4D5E6F70

Ym9ndXMgYm9keSwgbmV2ZXIgcmVhY2hlZA==
-----END RSA PRIVATE KEY-----
";

    #[test]
    fn plain_openssh_key_reports_type_fingerprint_and_public_key() {
        let info = ssh_key_inspect_inner(PLAIN_ED25519, None).expect("plain key parses");
        assert!(info.parsed);
        assert!(!info.encrypted);
        assert_eq!(info.key_type.as_deref(), Some("ssh-ed25519"));
        assert_eq!(
            info.fingerprint.as_deref(),
            Some("SHA256:pIbp0wpphTpwY1ZzG103sjQDjaI+c8CicInkWVfKNiQ")
        );
        assert_eq!(info.comment.as_deref(), Some("tervia-test@localhost"));
        let pub_key = info.public_key.expect("public key rendered");
        assert!(pub_key.starts_with("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5"));
        assert!(pub_key.ends_with("tervia-test@localhost"));
    }

    /// The load-bearing behaviour: `openssh-key-v1` stores the public half in
    /// cleartext, so type, fingerprint and `.pub` line all read out of an
    /// encrypted key. That is what lets the vault import one without unlocking
    /// it. The comment is the exception - it sits inside the encrypted section.
    #[test]
    fn locked_openssh_key_reports_metadata_without_a_passphrase() {
        let info = ssh_key_inspect_inner(LOCKED_ED25519, None).expect("locked key still parses");
        assert!(info.parsed);
        assert!(info.encrypted);
        assert_eq!(info.key_type.as_deref(), Some("ssh-ed25519"));
        assert_eq!(
            info.fingerprint.as_deref(),
            Some("SHA256:dbLm8WcA5UjVznFwZUkhFoL/umm2mBsxo6H46sYI3yc")
        );
        assert_eq!(info.comment, None);
        // Same key material as the `.pub` file on disk, just without its
        // trailing comment.
        let expected = LOCKED_PUB.trim().replace(" locked@localhost", "");
        assert_eq!(info.public_key.as_deref(), Some(expected.as_str()));
    }

    /// With the passphrase the comment comes back too, so an import that starts
    /// locked and then unlocks ends up with the full record.
    #[test]
    fn locked_openssh_key_accepts_the_right_passphrase() {
        let info = ssh_key_inspect_inner(LOCKED_ED25519, Some(LOCKED_PASSPHRASE))
            .expect("right passphrase unlocks");
        assert!(info.parsed);
        assert!(info.encrypted);
        assert_eq!(info.key_type.as_deref(), Some("ssh-ed25519"));
        assert_eq!(
            info.fingerprint.as_deref(),
            Some("SHA256:dbLm8WcA5UjVznFwZUkhFoL/umm2mBsxo6H46sYI3yc")
        );
        assert_eq!(info.comment.as_deref(), Some("locked@localhost"));
        assert_eq!(info.public_key.as_deref(), Some(LOCKED_PUB.trim()));
    }

    /// russh surfaces a bad passphrase as a bare `Unpad Error`. Say what is
    /// actually wrong, and do not echo the secret that was tried.
    #[test]
    fn wrong_passphrase_says_so_and_leaks_nothing() {
        let err = ssh_key_inspect_inner(LOCKED_ED25519, Some("hunter2"))
            .expect_err("wrong passphrase is an error");
        assert!(err.contains("passphrase"), "{err}");
        assert!(!err.contains("Unpad"), "{err}");
        assert!(!err.contains("hunter2"), "{err}");
    }

    /// PKCS#8 encrypts the public half along with everything else, so there is
    /// nothing to report yet. `parsed: false` tells the editor to prompt rather
    /// than to show a failure.
    #[test]
    fn locked_pkcs8_asks_for_a_passphrase_instead_of_failing() {
        let info = ssh_key_inspect_inner(LOCKED_PKCS8, None).expect("not an error, just locked");
        assert!(!info.parsed);
        assert!(info.encrypted);
        assert_eq!(info.key_type, None);
        assert_eq!(info.fingerprint, None);
        assert_eq!(info.public_key, None);
    }

    #[test]
    fn public_key_paste_gets_its_own_message() {
        let err = ssh_key_inspect_inner(LOCKED_PUB, None).expect_err("a .pub is not a key");
        assert!(err.contains("public key"), "{err}");
        assert!(err.contains(".pub"), "{err}");
    }

    #[test]
    fn dsa_key_gets_its_own_message() {
        let err = ssh_key_inspect_inner(DSA_KEY, None).expect_err("dsa is unsupported");
        assert!(err.contains("DSA"), "{err}");
    }

    /// The `decode_secret_key` path, which is the only route a PKCS#8 or `.ppk`
    /// DSA key could take. It never reaches the algorithm guard: russh is built
    /// without its `dsa` feature, so the decoder rejects the DSA OID outright
    /// (`Unknown key algorithm: 1.2.840.10040.4.1`) and this surfaces as the
    /// generic `ERR_UNREADABLE` rather than the DSA message. Pinned anyway, for
    /// the invariant that actually matters and that holds either way: the key is
    /// refused, and the refusal describes none of its facts. If russh ever gains
    /// a DSA branch this key starts parsing, `key_info` catches it, and the
    /// assertions below still pass - the message simply gets better.
    #[test]
    fn pkcs8_dsa_key_is_refused_and_describes_nothing() {
        let err = ssh_key_inspect_inner(DSA_PKCS8, None).expect_err("dsa never parses here");
        assert!(!err.contains("ssh-dss"), "{err}");
        assert!(!err.contains("SHA256:"), "{err}");
    }

    /// The reachable DSA case, and the one a human hand test caught: a modern
    /// `ssh-keygen -t dsa` writes `openssh-key-v1`, not PEM, so the container
    /// says `OpenSsh`, the parse succeeds, and only the parsed algorithm can
    /// refuse it. Before the guard moved off the header this reported `ssh-dss`
    /// with a real fingerprint for a key russh cannot authenticate with.
    #[test]
    fn openssh_dsa_key_is_refused_not_described() {
        let err = ssh_key_inspect_inner(DSA_OPENSSH, None).expect_err("dsa is unsupported");
        assert!(err.contains("DSA"), "{err}");
        // The facts that used to leak. None of them may reach the caller.
        assert!(!err.contains("ssh-dss"), "{err}");
        assert!(!err.contains("SHA256:"), "{err}");
    }

    /// Case 3: `openssh-key-v1` keeps the public half in cleartext, so the
    /// algorithm is knowable with no passphrase - which means this must refuse
    /// here rather than hand back `ssh-dss` facts and defer the failure to the
    /// passphrase round (or, worse, to dial time).
    #[test]
    fn locked_openssh_dsa_key_is_refused_without_a_passphrase() {
        let err = ssh_key_inspect_inner(DSA_OPENSSH_LOCKED, None)
            .expect_err("a locked dsa key is still dsa");
        assert!(err.contains("DSA"), "{err}");
        assert!(!err.contains("ssh-dss"), "{err}");
    }

    /// Case 2: the same key with the right passphrase. The decrypt succeeds, so
    /// this return is only reached after a valid parse - and it must still
    /// refuse rather than reward the correct passphrase with a saved record.
    #[test]
    fn locked_openssh_dsa_key_is_refused_with_the_right_passphrase() {
        let err = ssh_key_inspect_inner(DSA_OPENSSH_LOCKED, Some(DSA_OPENSSH_PASSPHRASE))
            .expect_err("the right passphrase does not make dsa supported");
        assert!(err.contains("DSA"), "{err}");
        assert!(!err.contains("passphrase"), "{err}");
    }

    /// The negative control, without which every test above would also pass
    /// against a guard that simply refused everything. Same `ssh-keygen`, same
    /// batch, same container as `DSA_OPENSSH` - only the algorithm differs, and
    /// this one still reports its full facts.
    #[test]
    fn a_non_dsa_key_from_the_same_batch_still_inspects() {
        let info = ssh_key_inspect_inner(ED25519_CONTROL, None).expect("ed25519 is supported");
        assert!(info.parsed);
        assert!(!info.encrypted);
        assert_eq!(info.key_type.as_deref(), Some("ssh-ed25519"));
        assert_eq!(
            info.fingerprint.as_deref(),
            Some("SHA256:dkFoCH+fQkAnq3M7uANqfFkEpS3N3AzFrQMgh63AvcE")
        );
        assert_eq!(info.comment.as_deref(), Some("ed-neg@tervia"));
        assert_eq!(
            info.public_key.as_deref(),
            Some(
                "ssh-ed25519 \
                 AAAAC3NzaC1lZDI1NTE5AAAAILnHe/4upt5T4CrDT6HcVnpDGZ718syPtrOViMRRnxKq \
                 ed-neg@tervia"
            )
        );
    }

    #[test]
    fn sec1_ec_key_gets_its_own_message() {
        let err = ssh_key_inspect_inner(SEC1_EC, None).expect_err("sec1 is unsupported");
        assert!(err.contains("SEC1"), "{err}");
        assert!(err.contains("ssh-keygen -p"), "{err}");
    }

    #[test]
    fn unsupported_pem_cipher_gets_its_own_message() {
        let err = ssh_key_inspect_inner(PEM_3DES, None).expect_err("only aes-128-cbc is wired up");
        assert!(err.contains("AES-128-CBC"), "{err}");
    }

    /// Arbitrary pasted text reaches this command, and `panic = "abort"` turns
    /// any panic into a process kill rather than a rejected promise.
    #[test]
    fn junk_input_errors_without_panicking() {
        for junk in [
            "",
            "   \n\t\n ",
            "hello",
            "\u{1f600}\u{4e2d}\u{6587}",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----\nbm90IGEga2V5\n-----END OPENSSH PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----\n!!!!\n-----END PRIVATE KEY-----",
            "PuTTY-User-Key-File-9: ssh-ed25519",
        ] {
            let Err(err) = ssh_key_inspect_inner(junk, None) else {
                panic!("expected an error for {junk:?}");
            };
            assert!(err.starts_with("ssh: "), "{err}");
        }
    }

    /// Distinct inputs must not collapse back onto one message - that
    /// indistinguishability is the whole reason this command classifies.
    #[test]
    fn every_dead_end_has_a_distinct_message() {
        let mut msgs: Vec<String> = [LOCKED_PUB, DSA_KEY, SEC1_EC, PEM_3DES, "junk", ""]
            .iter()
            .map(|k| ssh_key_inspect_inner(k, None).expect_err("dead end"))
            .collect();
        let total = msgs.len();
        msgs.sort();
        msgs.dedup();
        assert_eq!(msgs.len(), total, "duplicate message: {msgs:?}");
    }

    /// The bug this guards: a truncated PKCS#8 block paired with the
    /// *correct* passphrase used to be told "wrong passphrase" forever,
    /// because `decode_secret_key` folds parsing and decrypting into one
    /// call. The widened message must name truncation/corruption as a
    /// possibility and must not collapse onto the plain wrong-passphrase
    /// message used elsewhere.
    #[test]
    fn truncated_pkcs8_with_the_right_passphrase_names_truncation_too() {
        // Sanity check: the untruncated key with its real passphrase parses,
        // so the truncated case below is testing truncation, not a typo.
        ssh_key_inspect_inner(PKCS8_WITH_PASSPHRASE, Some(PKCS8_PASSPHRASE))
            .expect("full key with its real passphrase parses");

        let err = ssh_key_inspect_inner(PKCS8_TRUNCATED, Some(PKCS8_PASSPHRASE))
            .expect_err("a truncated block is still unreadable, even with the right passphrase");
        assert!(
            err.contains("truncated") || err.contains("corrupt"),
            "{err}"
        );
        assert!(err.contains("passphrase"), "{err}");
        assert_ne!(err, ERR_WRONG_PASSPHRASE);
        assert_eq!(err, ERR_PASSPHRASE_OR_CORRUPT);
    }

    /// The other bug this guards: `classify` used to sniff only the first
    /// line, so a public key pasted ahead of its own private key made the
    /// private key unreachable. A private-key marker anywhere in the paste
    /// must win - but a paste that really is only a public key must still be
    /// refused, so both directions of the fix are checked here.
    #[test]
    fn public_key_line_does_not_shadow_a_following_private_key() {
        let err = ssh_key_inspect_inner(LOCKED_PUB, None).expect_err("a lone .pub is not a key");
        assert!(err.contains("public key"), "{err}");

        let pasted_both = format!("{LOCKED_PUB}{LOCKED_ED25519}");
        let info = ssh_key_inspect_inner(&pasted_both, None)
            .expect("the private key after the public line must still parse");
        assert!(info.parsed);
        assert!(info.encrypted);
        assert_eq!(info.key_type.as_deref(), Some("ssh-ed25519"));
        assert_eq!(
            info.fingerprint.as_deref(),
            Some("SHA256:dbLm8WcA5UjVznFwZUkhFoL/umm2mBsxo6H46sYI3yc")
        );
    }

    /// The PEM-block counterpart to the test above. The comment on `classify`
    /// claims a private-key marker anywhere in the paste wins "even over a
    /// public-key line earlier in the text", but the old scan returned on the
    /// first `-----BEGIN ...-----` it saw - so a PEM public-key block (say,
    /// from `ssh-keygen -e -m PKCS8`) pasted ahead of the real private key
    /// still bounced with the public-key message, never reaching the private
    /// key below it. This is the gap the bare-`.pub`-line test above does not
    /// cover.
    #[test]
    fn pem_public_key_block_does_not_shadow_a_following_private_key() {
        let err = ssh_key_inspect_inner(PEM_PUBLIC_KEY, None)
            .expect_err("a lone PEM public key is not a key");
        assert!(err.contains("public key"), "{err}");

        let pasted_both = format!("{PEM_PUBLIC_KEY}{LOCKED_ED25519}");
        let info = ssh_key_inspect_inner(&pasted_both, None)
            .expect("the private key after the PEM public block must still parse");
        assert!(info.parsed);
        assert!(info.encrypted);
        assert_eq!(info.key_type.as_deref(), Some("ssh-ed25519"));
        assert_eq!(
            info.fingerprint.as_deref(),
            Some("SHA256:dbLm8WcA5UjVznFwZUkhFoL/umm2mBsxo6H46sYI3yc")
        );
    }

    /// Every PEM public-key label `classify` recognises - not just the one
    /// used above - must still be refused with the public-key message when it
    /// really is the only thing pasted.
    #[test]
    fn every_pem_public_key_label_alone_gets_the_public_key_message() {
        for pem in [PEM_PUBLIC_KEY, PEM_RSA_PUBLIC_KEY, PEM_SSH2_PUBLIC_KEY] {
            let err =
                ssh_key_inspect_inner(pem, None).expect_err("a PEM public-key block is not a key");
            assert!(err.contains("public key"), "{pem}: {err}");
        }
    }

    /// Both dead ends read "truncated or altered" in similar words, and
    /// `every_dead_end_has_a_distinct_message` above never exercises this
    /// pair: `ERR_OPENSSH_BODY` comes from `from_openssh` failing before any
    /// passphrase is involved, `ERR_UNREADABLE` from `decode_secret_key`
    /// failing on an unencrypted, non-OpenSSH format.
    #[test]
    fn openssh_body_and_unreadable_are_distinct_and_both_reachable() {
        let openssh_err = ssh_key_inspect_inner(
            "-----BEGIN OPENSSH PRIVATE KEY-----\nbm90IGEga2V5\n-----END OPENSSH PRIVATE KEY-----",
            None,
        )
        .expect_err("garbage openssh-v1 body");
        let unreadable_err = ssh_key_inspect_inner(
            "-----BEGIN PRIVATE KEY-----\n!!!!\n-----END PRIVATE KEY-----",
            None,
        )
        .expect_err("garbage pkcs8 body");
        assert_eq!(openssh_err, ERR_OPENSSH_BODY);
        assert_eq!(unreadable_err, ERR_UNREADABLE);
        assert_ne!(openssh_err, unreadable_err);
    }

    /// The rc-noise guard: a chatty remote `~/.bashrc` prepends its own output
    /// to every `ssh host cmd` capture, so the value we want is the last line.
    #[test]
    fn last_line_survives_rc_chatter() {
        assert_eq!(last_line("/home/u/app"), "/home/u/app");
        assert_eq!(
            last_line("Welcome!\nnvm loaded\n/home/u/app\n"),
            "/home/u/app"
        );
        assert_eq!(last_line("/home/u/app\n\n"), "/home/u/app");
        assert_eq!(last_line("  /home/u/app  "), "/home/u/app");
        assert_eq!(last_line(""), "");
        assert_eq!(last_line("\n \n"), "");
        // A branch header behind a greeting still parses as the header.
        assert_eq!(
            last_line("motd\n## main...origin/main"),
            "## main...origin/main"
        );
    }

    /// `cwd` reaches us from the remote shell's OSC 7, i.e. it is untrusted.
    #[test]
    fn shell_quote_blocks_injection() {
        assert_eq!(shell_quote("/home/u/app"), "'/home/u/app'");
        assert_eq!(
            shell_quote("/tmp/x'; rm -rf ~ ;'"),
            r"'/tmp/x'\''; rm -rf ~ ;'\'''"
        );
    }
}
