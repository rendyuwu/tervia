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

fn classify(text: &str) -> KeyFormat {
    let Some(first) = text.lines().map(str::trim).find(|l| !l.is_empty()) else {
        return KeyFormat::Unknown;
    };
    if PUBLIC_KEY_PREFIXES.iter().any(|p| first.starts_with(p))
        // RFC 4716 spells its delimiters with four dashes and spaces.
        || first.starts_with("---- BEGIN SSH2 PUBLIC KEY ----")
    {
        return KeyFormat::PublicKey;
    }
    if first.starts_with("PuTTY-User-Key-File-") {
        let encrypted = text.lines().any(|l| {
            l.trim()
                .strip_prefix("Encryption:")
                .is_some_and(|v| v.trim() != "none")
        });
        return KeyFormat::Other { encrypted };
    }
    for line in text.lines().map(str::trim) {
        let Some(label) = line
            .strip_prefix("-----BEGIN ")
            .and_then(|l| l.strip_suffix("-----"))
        else {
            continue;
        };
        return match label {
            "OPENSSH PRIVATE KEY" => KeyFormat::OpenSsh,
            "DSA PRIVATE KEY" => KeyFormat::Dsa,
            "EC PRIVATE KEY" => KeyFormat::Sec1,
            "ENCRYPTED PRIVATE KEY" => KeyFormat::Other { encrypted: true },
            "PRIVATE KEY" => KeyFormat::Other { encrypted: false },
            "RSA PRIVATE KEY" => pkcs1_cipher(text),
            "PUBLIC KEY" | "RSA PUBLIC KEY" | "SSH2 PUBLIC KEY" => KeyFormat::PublicKey,
            _ => KeyFormat::Unknown,
        };
    }
    KeyFormat::Unknown
}

/// Everything `SshKeyInfo` can say about a key. Also runs on a still-encrypted
/// `openssh-key-v1` handle, where the public half is cleartext.
fn key_info(key: &PrivateKey, encrypted: bool) -> SshKeyInfo {
    let comment = key.comment().trim();
    SshKeyInfo {
        parsed: true,
        encrypted,
        key_type: Some(key.algorithm().to_string()),
        fingerprint: Some(key.fingerprint(russh::keys::HashAlg::Sha256).to_string()),
        public_key: key.public_key().to_openssh().ok(),
        comment: (!comment.is_empty()).then(|| comment.to_string()),
    }
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

    let encrypted = match classify(text) {
        KeyFormat::PublicKey => return Err(ERR_PUBLIC_KEY.into()),
        KeyFormat::Dsa => return Err(ERR_DSA.into()),
        KeyFormat::Sec1 => return Err(ERR_SEC1.into()),
        KeyFormat::UnsupportedPemCipher => return Err(ERR_PEM_CIPHER.into()),
        KeyFormat::Unknown => return Err(ERR_UNKNOWN.into()),
        // openssh-key-v1 declares its cipher inside the container and parses
        // either way, so here the parse is what decides `encrypted`.
        KeyFormat::OpenSsh => {
            let key = PrivateKey::from_openssh(text).map_err(|_| ERR_OPENSSH_BODY.to_string())?;
            if !key.is_encrypted() {
                return Ok(key_info(&key, false));
            }
            return match pass {
                // Decrypting proves the passphrase before dial time, and is
                // also the only route to the comment: the container keeps the
                // public half in cleartext but seals the comment away with the
                // private one.
                Some(pass) => key
                    .decrypt(pass)
                    .map(|open| key_info(&open, true))
                    .map_err(|_| ERR_WRONG_PASSPHRASE.to_string()),
                None => Ok(key_info(&key, true)),
            };
        }
        KeyFormat::Other { encrypted } => encrypted,
    };

    if encrypted && pass.is_none() {
        return Ok(needs_passphrase());
    }
    match russh::keys::decode_secret_key(text, pass) {
        Ok(key) => Ok(key_info(&key, encrypted)),
        // Backstop for a container that did not announce its encryption in a
        // header spelling `classify` recognises.
        Err(russh::keys::Error::KeyIsEncrypted) if pass.is_none() => Ok(needs_passphrase()),
        // Only reachable with a passphrase supplied, so it is the one thing
        // left to blame.
        Err(_) if encrypted => Err(ERR_WRONG_PASSPHRASE.into()),
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
    use super::{last_line, shell_quote, ssh_key_inspect_inner};

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
