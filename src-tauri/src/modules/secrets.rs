//! Secret storage with platform-appropriate backends.
//!
//! - macOS: Keychain via the `keyring` crate. No relevant size limit.
//! - Windows: DPAPI-encrypted file in the app's local data dir. Earlier
//!   builds used the Credential Manager via `keyring`, but its CredentialBlob
//!   is capped at 2560 bytes; too small for an RSA private key body, which
//!   made SSH "Create" fail after "Test connection". DPAPI's
//!   `CryptProtectData` is bound to the current user's logon (same trust
//!   model) and has no relevant size limit. Pre-existing Credential Manager
//!   entries are read as a fallback so password-only connections keep
//!   working without forced migration.
//! - Linux: file in the app's local data dir, mode 0600. The default
//!   `keyring` backend on Linux is the Secret Service over D-Bus, which
//!   silently fails on systems without gnome-keyring/kwallet (and when the
//!   "login" collection is not created). For an app shipped via
//!   AppImage/deb/rpm we cannot assume a keyring daemon exists. The file
//!   backend is what Brave/Chromium fall back to; mode 0600 provides the
//!   isolation the secret-service collection would have.
//!
//! The frontend talks to `secrets_get`, `secrets_set`, `secrets_delete`,
//! `secrets_get_all` and `secrets_copy` with no platform branching in JS.
//!
//! All commands take `&AppHandle` so the data directory is resolved once via
//! Tauri's path API.
//!
//! Every value this module holds lives in a `Zeroizing` container, so a store
//! map, a decrypted buffer or a returned secret is scrubbed when it drops
//! rather than merely freed. No decrypted store is retained between calls:
//! each read loads the file and drops it again.

use std::sync::Mutex;

use serde::Deserialize;
use tauri::AppHandle;
use zeroize::Zeroizing;

#[cfg(any(target_os = "linux", target_os = "windows"))]
use std::collections::HashMap;
#[cfg(any(target_os = "linux", target_os = "windows"))]
use std::fs;
#[cfg(any(target_os = "linux", target_os = "windows"))]
use std::path::PathBuf;
#[cfg(any(target_os = "linux", target_os = "windows"))]
use std::sync::MutexGuard;
#[cfg(any(target_os = "linux", target_os = "windows"))]
use tauri::Manager;

/// The store as it lives in memory. `Zeroizing` so a map dropped at the end of
/// a read or a commit scrubs every value instead of merely freeing it.
#[cfg(any(target_os = "linux", target_os = "windows"))]
type SecretMap = HashMap<String, Zeroizing<String>>;

#[derive(Default)]
pub struct SecretsState {
    /// One writer at a time, and the read-modify-write a mutation performs.
    /// NOT a cache: nothing is behind this lock but the right to be that
    /// writer. Every write stages through the one temp path
    /// `atomic_write` derives from the target, so two concurrent writers
    /// would fight over a single staging file - see [`commit_store`].
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    store_lock: Mutex<()>,
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    _phantom: Mutex<()>,
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn key(service: &str, account: &str) -> String {
    format!("{}::{}", service, account)
}

#[cfg(target_os = "linux")]
fn store_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_local_data_dir().map_err(|e| e.to_string())?;
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.join("secrets.json"))
}

#[cfg(target_os = "windows")]
fn store_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_local_data_dir().map_err(|e| e.to_string())?;
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.join("secrets.bin"))
}

#[cfg(target_os = "linux")]
fn read_store(app: &AppHandle) -> Result<SecretMap, String> {
    let path = store_path(app)?;
    if !path.exists() {
        return Ok(SecretMap::new());
    }
    let bytes = Zeroizing::new(fs::read(&path).map_err(|e| e.to_string())?);
    serde_json::from_slice::<SecretMap>(&bytes).map_err(|e| e.to_string())
}

#[cfg(target_os = "linux")]
fn write_store(app: &AppHandle, map: &SecretMap) -> Result<(), String> {
    let path = store_path(app)?;
    let bytes = Zeroizing::new(serde_json::to_vec(map).map_err(|e| e.to_string())?);
    // 0600: only the owning user can read or write the secrets file. The temp
    // is created with that mode up front so the plaintext is never briefly
    // world-readable on disk.
    crate::modules::fs::atomic::atomic_write_mode(&path, &bytes, 0o600).map_err(|e| e.to_string())
}

#[cfg(target_os = "windows")]
fn dpapi_protect(plain: &[u8]) -> Result<Vec<u8>, String> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    let input = CRYPT_INTEGER_BLOB {
        cbData: plain.len() as u32,
        pbData: plain.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };

    // SAFETY: input.pbData covers plain.len() bytes for the call.
    // CryptProtectData allocates a fresh output buffer we free with
    // LocalFree below.
    let ok = unsafe {
        CryptProtectData(
            &input,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err("dpapi: CryptProtectData failed".into());
    }
    let bytes =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        LocalFree(output.pbData as *mut _);
    }
    Ok(bytes)
}

#[cfg(target_os = "windows")]
fn dpapi_unprotect(cipher: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    let input = CRYPT_INTEGER_BLOB {
        cbData: cipher.len() as u32,
        pbData: cipher.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };

    let ok = unsafe {
        CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err("dpapi: CryptUnprotectData failed".into());
    }
    let bytes = Zeroizing::new(unsafe {
        std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec()
    });
    unsafe {
        LocalFree(output.pbData as *mut _);
    }
    Ok(bytes)
}

#[cfg(target_os = "windows")]
fn read_store(app: &AppHandle) -> Result<SecretMap, String> {
    let path = store_path(app)?;
    if !path.exists() {
        return Ok(SecretMap::new());
    }
    let cipher = fs::read(&path).map_err(|e| e.to_string())?;
    if cipher.is_empty() {
        return Ok(SecretMap::new());
    }
    let plain = dpapi_unprotect(&cipher)?;
    serde_json::from_slice::<SecretMap>(&plain).map_err(|e| e.to_string())
}

#[cfg(target_os = "windows")]
fn write_store(app: &AppHandle, map: &SecretMap) -> Result<(), String> {
    let path = store_path(app)?;
    let plain = Zeroizing::new(serde_json::to_vec(map).map_err(|e| e.to_string())?);
    let cipher = dpapi_protect(&plain)?;
    crate::modules::fs::atomic::atomic_write(&path, &cipher).map_err(|e| e.to_string())
}

/// Take the store lock, RECOVERING a poisoned one.
///
/// Recovering is safe here only because nothing is behind this lock but the
/// right to be the one writer: the cached map a panicking mutation could once
/// leave half-changed no longer exists, and the file a panic unwound past
/// never took the change. Failing every later acquisition instead would cost
/// the rest of the session's secrets, READS included: [`with_store`] takes
/// this same lock, so one panic in a write would make every later
/// `secrets_get` answer with an opaque poison string. The flag is cleared once
/// it has been handled, or every call for the life of the process would keep
/// reporting a panic that has already been absorbed.
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn lock_store(lock: &Mutex<()>) -> MutexGuard<'_, ()> {
    lock.lock().unwrap_or_else(|poisoned| {
        lock.clear_poison();
        poisoned.into_inner()
    })
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn with_store<F, R>(app: &AppHandle, state: &SecretsState, f: F) -> Result<R, String>
where
    F: FnOnce(&SecretMap) -> R,
{
    // The lock is held across the read, not for a cache: a write renames over
    // the target, and on Windows opening a file mid-rename can fail with a
    // sharing violation. Reads and writes stay serialised, as they were when
    // the cache served them.
    let _guard = lock_store(&state.store_lock);
    Ok(f(&read_store(app)?))
}

/// Read the store, mutate it and write it back as ONE step, with the store
/// lock held ACROSS the disk write.
///
/// The lock spanning the write is not tidiness, it is the fix for a delete that
/// could not work at all. `hosts/store.ts`'s `deleteHost` fans out one
/// `secrets_delete` per account the host owns (three for an SSH row, one for RDP),
/// and each is a separate async command, so they run concurrently. Every write
/// here stages through the ONE fixed temp path `atomic_write` derives from the
/// target (`.secrets.json.tervia.tmp` / `.secrets.bin.tervia.tmp`), so two
/// concurrent writers share a single temp file: whichever `fs::rename` lands
/// first consumes it, and the next one fails with `os error 2`, "The system
/// cannot find the file specified". That is precisely the error SSH host delete
/// reported, and precisely why RDP host delete, which makes one call, worked.
///
/// Blocking under a `std::sync::Mutex` from an async command body, deliberately:
/// the critical section contains no `.await`, so it cannot deadlock a worker, and
/// every one of these commands already did its file read, DPAPI call or Keychain
/// call inline.
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn commit_store<F, R>(app: &AppHandle, state: &SecretsState, f: F) -> Result<R, String>
where
    F: FnOnce(&mut SecretMap) -> R,
{
    commit_locked(
        &state.store_lock,
        || read_store(app),
        |map| write_store(app, map),
        f,
    )
}

/// [`commit_store`] with the two `AppHandle` steps as parameters.
///
/// Split out to be testable AT ALL: `src-tauri` has no `[dev-dependencies]`, so
/// `tauri::test::mock_app()` is unavailable and an `AppHandle` cannot be
/// constructed. What has to be pinned down is the ORDERING - load, mutate,
/// write while still holding the lock - and every part of that ordering is
/// here rather than in the wrapper.
///
/// No rollback: the file is the only state, so a failed write leaves nothing in
/// memory claiming a change the disk did not take.
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn commit_locked<L, W, F, R>(lock: &Mutex<()>, load: L, write: W, f: F) -> Result<R, String>
where
    L: FnOnce() -> Result<SecretMap, String>,
    W: FnOnce(&SecretMap) -> Result<(), String>,
    F: FnOnce(&mut SecretMap) -> R,
{
    let _guard = lock_store(lock);
    let mut map = load()?;
    let out = f(&mut map);
    write(&map)?;
    Ok(out)
}

#[cfg(target_os = "macos")]
fn entry(service: &str, account: &str) -> Result<keyring::Entry, String> {
    keyring::Entry::new(service, account).map_err(|e| e.to_string())
}

// Backward compat: earlier Windows builds wrote to the Credential Manager
// via `keyring`. Read those entries as a fallback so existing password-auth
// connections keep working without migration. Clear them on `set`/`delete`
// so the file store wins.
#[cfg(target_os = "windows")]
fn legacy_keyring_get(service: &str, account: &str) -> Option<String> {
    keyring::Entry::new(service, account)
        .ok()
        .and_then(|e| e.get_password().ok())
}

#[cfg(target_os = "windows")]
fn legacy_keyring_delete(service: &str, account: &str) {
    if let Ok(e) = keyring::Entry::new(service, account) {
        let _ = e.delete_credential();
    }
}

/// Where one secret comes from: a keychain reference the host process resolves
/// itself, or a plaintext the caller is holding.
///
/// Internally tagged, so serde rejects a payload with neither arm and cannot
/// accept both. The same wire shape as `rdp::RdpCredential`, which is not
/// reused only because its inline arm spells the field `password` and that
/// name is already on the RDP wire; there is nothing to gain from changing it.
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum SecretSource {
    /// Read the value out of the OS keychain in the host process. Same
    /// `service` / `account` pair [`secrets_get`] takes.
    Keychain { service: String, account: String },
    /// Plaintext straight from the caller.
    ///
    /// This exists for ONE case: the host editor's Test button, where the user
    /// has just typed a credential that is not saved yet, so there is no
    /// reference to send. Never use it for a saved connection - that would put
    /// the secret back in the webview.
    Inline { value: String },
}

// Hand-written so a stray `log::debug!("{input:?}")` - or anything else that
// formats an input carrying one - cannot print the value.
impl core::fmt::Debug for SecretSource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Keychain { service, account } => f
                .debug_struct("Keychain")
                .field("service", service)
                .field("account", account)
                .finish(),
            Self::Inline { .. } => f
                .debug_struct("Inline")
                .field("value", &"<redacted>")
                .finish(),
        }
    }
}

impl SecretSource {
    /// The plaintext this source names. `None` when nothing is stored, or an
    /// empty string is - which is exactly the state an absent field used to
    /// arrive in, because `sshInlineCredentials` mapped `""` to `undefined`
    /// before it ever reached the wire. So `has_credential` still refuses the
    /// same inputs it refuses today.
    pub(crate) fn resolve(
        &self,
        app: &AppHandle,
        state: &SecretsState,
    ) -> Result<Option<Zeroizing<String>>, String> {
        Ok(match self {
            Self::Keychain { service, account } => read_secret(app, state, service, account)?,
            Self::Inline { value } => Some(Zeroizing::new(value.clone())),
        }
        .filter(|v| !v.is_empty()))
    }
}

/// Read one secret, doing the per-platform keychain-or-fallback work.
///
/// The single implementation behind both [`secrets_get`] (the IPC surface the
/// frontend uses) and the in-process callers that must NOT round-trip a
/// plaintext through the webview: `rdp::rdp_open`, which resolves a credential
/// reference and hands the password straight to CredSSP, `ssh::ssh_open`,
/// which does the same for every hop of a connect, and [`secrets_copy`], which
/// moves one between accounts. Two copies of this would drift, and the
/// Windows Credential Manager fallback below is exactly the kind of thing that
/// silently stops being applied in the copy nobody edits.
///
/// The value comes back in a `Zeroizing<String>`, so a caller that drops it
/// scrubs it. `Zeroizing<T>` is `repr(transparent)` and serialises as its
/// inner value, so [`secrets_get`] puts the identical bytes on the IPC wire.
///
/// Blocking: a small file read plus one DPAPI call on Windows, a Keychain call
/// on macOS. `secrets_get` has always done this inline in its async body; the
/// callers here do the same rather than paying a `spawn_blocking` hop.
pub(crate) fn read_secret(
    app: &AppHandle,
    state: &SecretsState,
    service: &str,
    account: &str,
) -> Result<Option<Zeroizing<String>>, String> {
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    {
        let k = key(service, account);
        let hit = with_store(app, state, |m| m.get(&k).cloned())?;
        if hit.is_some() {
            return Ok(hit);
        }
        #[cfg(target_os = "windows")]
        {
            Ok(legacy_keyring_get(service, account).map(Zeroizing::new))
        }
        #[cfg(target_os = "linux")]
        {
            Ok(None)
        }
    }
    #[cfg(target_os = "macos")]
    {
        let _ = (app, state);
        let e = entry(service, account)?;
        match e.get_password() {
            Ok(v) => Ok(Some(Zeroizing::new(v))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(err) => Err(err.to_string()),
        }
    }
}

#[tauri::command]
pub async fn secrets_get(
    app: AppHandle,
    state: tauri::State<'_, SecretsState>,
    service: String,
    account: String,
) -> Result<Option<Zeroizing<String>>, String> {
    read_secret(&app, &state, &service, &account)
}

/// Write several secrets as ONE store commit.
///
/// On Linux and Windows a commit reads, serialises and atomically rewrites the
/// whole store, so N separate [`write_secret`] calls cost N full rewrites. A
/// backup import writes roughly three accounts per connection, which is where
/// that became the dominant cost. macOS has no store file: the Keychain is
/// per-entry, so the loop there is the honest shape.
///
/// All-or-nothing on Linux and Windows: one failed rewrite writes no entry at
/// all, which is what `backup/apply.ts` already reports ("no stored
/// credentials could be written to the keychain", one line for the batch).
pub(crate) fn write_secrets(
    app: &AppHandle,
    state: &SecretsState,
    entries: &[(&str, &str, &str)],
) -> Result<(), String> {
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    {
        // Store and file under ONE lock acquisition: see `commit_store`. Two
        // concurrent writers used to stage into the same temp file and the second
        // `rename` failed with `os error 2`.
        commit_store(app, state, |m| {
            for (service, account, password) in entries {
                m.insert(
                    key(service, account),
                    Zeroizing::new((*password).to_owned()),
                );
            }
        })?;
        #[cfg(target_os = "windows")]
        {
            // Stale Credential Manager entries from an earlier build would
            // shadow updates on read; delete them so the file store wins.
            // After the commit: a failed write must not clear the old value.
            for (service, account, _) in entries {
                legacy_keyring_delete(service, account);
            }
        }
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        let _ = (app, state);
        for (service, account, password) in entries {
            entry(service, account)?
                .set_password(password)
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}

/// Write one secret, doing the per-platform keychain-or-fallback work.
///
/// The counterpart of [`read_secret`], and split out for the same reason: the
/// in-process callers that must NOT round-trip a plaintext through the webview
/// need the identical write path, and the Windows Credential Manager cleanup
/// it inherits from [`write_secrets`] is exactly the kind of step that quietly
/// stops happening in a second copy. The remaining in-process caller is
/// [`secrets_copy`]; `backup::backup_apply_secrets` writes its whole batch
/// through [`write_secrets`] instead.
///
/// Blocking, on the same terms as [`read_secret`].
pub(crate) fn write_secret(
    app: &AppHandle,
    state: &SecretsState,
    service: &str,
    account: &str,
    password: &str,
) -> Result<(), String> {
    write_secrets(app, state, &[(service, account, password)])
}

#[tauri::command]
pub async fn secrets_set(
    app: AppHandle,
    state: tauri::State<'_, SecretsState>,
    service: String,
    account: String,
    password: String,
) -> Result<(), String> {
    write_secret(&app, &state, &service, &account, &password)
}

#[tauri::command]
pub async fn secrets_delete(
    app: AppHandle,
    state: tauri::State<'_, SecretsState>,
    service: String,
    account: String,
) -> Result<(), String> {
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    {
        let k = key(&service, &account);
        // An account that is not there is still a success - `HashMap::remove`
        // removing nothing is not an error - so the failure this used to report
        // was never about the secret. It was the fan-out: `deleteHost` calls this
        // three times at once for an SSH host and once for an RDP one, and two
        // unlocked writes raced over one staging temp file. See `commit_store`.
        commit_store(&app, &state, |m| {
            m.remove(&k);
        })?;
        #[cfg(target_os = "windows")]
        {
            legacy_keyring_delete(&service, &account);
        }
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        let _ = (app, state);
        let e = entry(&service, &account)?;
        match e.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(err) => Err(err.to_string()),
        }
    }
}

/// Batch read for the cold-boot fan-out (one IPC roundtrip).
#[tauri::command]
pub async fn secrets_get_all(
    app: AppHandle,
    state: tauri::State<'_, SecretsState>,
    service: String,
    accounts: Vec<String>,
) -> Result<Vec<Option<Zeroizing<String>>>, String> {
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    {
        let primary = with_store(&app, &state, |m| {
            accounts
                .iter()
                .map(|a| m.get(&key(&service, a)).cloned())
                .collect::<Vec<_>>()
        })?;
        #[cfg(target_os = "windows")]
        {
            Ok(primary
                .into_iter()
                .zip(accounts.iter())
                .map(|(v, a)| v.or_else(|| legacy_keyring_get(&service, a).map(Zeroizing::new)))
                .collect())
        }
        #[cfg(target_os = "linux")]
        {
            Ok(primary)
        }
    }
    #[cfg(target_os = "macos")]
    {
        let _ = (app, state);
        Ok(accounts
            .into_iter()
            .map(|a| {
                keyring::Entry::new(&service, &a)
                    .ok()
                    .and_then(|e| e.get_password().ok())
                    .map(Zeroizing::new)
            })
            .collect())
    }
}

/// Whether a copy would be from an entry to itself.
///
/// BOTH halves, which is the whole reason this is named rather than inline.
/// Converting an inline host credential to a vault identity copies
/// `<id>::password` from `tervia-hosts` to `tervia-vault` - the same account
/// name on a different service - so an account-only comparison would report
/// that copy as already done and leave the vault entry empty.
fn same_entry(from: (&str, &str), to: (&str, &str)) -> bool {
    from == to
}

/// What a copy does with whatever the source turned out to hold.
enum CopyPlan<'a> {
    /// Nothing to give, so nothing to write.
    Nothing,
    /// The source has a value and the destination already IS the source.
    AlreadyThere,
    /// Write this value to the destination.
    Write(&'a str),
}

/// Decide a copy from what the source holds. No I/O in it, so every one of the
/// four decisions is reachable from a test.
///
/// Split out for the reason [`same_entry`] was split out of the same body:
/// [`secrets_copy`] itself cannot be driven from a test at all, because its
/// first act is a keychain read and CI has no keychain, while every decision
/// it makes is here.
///
/// An empty string counts as nothing to give, and that one is an invariant
/// rather than a preference: the JS layer never persists one (it trims and
/// deletes on blank - see `writeSecret` in `hosts/store.ts` and
/// `vault/store.ts`), so writing `""` here would manufacture a
/// `hasPassword: true` over an account that holds nothing.
fn plan_copy<'a>(value: Option<&'a str>, from: (&str, &str), to: (&str, &str)) -> CopyPlan<'a> {
    match value {
        None => CopyPlan::Nothing,
        Some("") => CopyPlan::Nothing,
        Some(_) if same_entry(from, to) => CopyPlan::AlreadyThere,
        Some(v) => CopyPlan::Write(v),
    }
}

/// Copy one secret from one account to another WITHOUT its plaintext entering
/// the webview.
///
/// Deliberately cross-service, which is why it takes four arguments rather than
/// the three a same-service copy would need. Duplicating a host moves
/// `tervia-hosts :: <src>::password` to `tervia-hosts :: <copy>::password`;
/// converting an inline credential to a vault identity moves
/// `tervia-hosts :: <host>::password` to `tervia-vault :: <identity>::password`.
/// Neither may read the value back first, and for an RDP password that is an
/// invariant rather than a preference - it is the reason a duplicated RDP host
/// used to get no password at all.
///
/// `Ok(false)` means there was nothing at the source (absent, or an empty
/// string, which is treated as absent) and NOTHING was written. `Ok(true)`
/// means the source had a value and it now sits at the destination too.
///
/// The boolean answers "did the source have something to give", NOT "does the
/// destination own a secret now". Those agree whenever the destination starts
/// empty - `duplicateHost`'s destination is always a brand-new id - but a
/// caller converting onto an id that may already hold a secret
/// (`convertHostToVault` in src/modules/hosts/credentialMove.ts, for one) cannot
/// read `Ok(false)` as "nothing there anymore": this function never clears the
/// destination. Its only writes are the one above and, on the legacy Windows
/// Credential Manager fallback inside [`write_secret`], a delete of a *stale
/// entry for the destination account*, never a clear triggered by an empty or
/// missing source.
///
/// Source and destination being the same entry skips only the WRITE, not the
/// read: the answer still has to say whether anything is there, and writing a
/// value back over itself costs a whole-store rewrite on Linux and Windows for
/// no change.
#[tauri::command]
pub async fn secrets_copy(
    app: AppHandle,
    state: tauri::State<'_, SecretsState>,
    from_service: String,
    from_account: String,
    to_service: String,
    to_account: String,
) -> Result<bool, String> {
    let value = read_secret(&app, &state, &from_service, &from_account)?;
    match plan_copy(
        value.as_deref().map(String::as_str),
        (&from_service, &from_account),
        (&to_service, &to_account),
    ) {
        CopyPlan::Nothing => Ok(false),
        CopyPlan::AlreadyThere => Ok(true),
        CopyPlan::Write(v) => {
            write_secret(&app, &state, &to_service, &to_account, v)?;
            Ok(true)
        }
    }
}

/// What `commit_locked` guarantees, exercised without an `AppHandle`.
///
/// The bug these exist for is not hypothetical and was not visible in a diff:
/// three `secrets_delete` calls fan out from one SSH host delete, all three wrote
/// the file unlocked, all three staged through the same temp path, and the second
/// `fs::rename` failed with `os error 2` - so SSH host delete could never
/// complete while RDP host delete, which makes one call, always did.
///
/// The file is a fake here rather than the real one, because what has to hold
/// is an ORDERING - one writer inside the write at a time, the write seeing the
/// mutation, every call reading the file afresh - and a temp file only makes
/// the first of those observable as a crash on one platform.
#[cfg(all(test, any(target_os = "linux", target_os = "windows")))]
mod commit_tests {
    use super::{commit_locked, SecretMap};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use zeroize::Zeroizing;

    /// A stand-in for the secrets file that also records the thing the real one
    /// could only express as a failed rename: how many writers were inside the
    /// write at the same time.
    #[derive(Default)]
    struct FakeFile {
        inside: AtomicUsize,
        overlaps: AtomicUsize,
        loads: AtomicUsize,
        contents: Mutex<SecretMap>,
    }

    impl FakeFile {
        fn load(&self) -> Result<SecretMap, String> {
            self.loads.fetch_add(1, Ordering::SeqCst);
            Ok(self.contents.lock().expect("test disk").clone())
        }

        fn write(&self, map: &SecretMap) -> Result<(), String> {
            // Entering while another writer is in here is exactly the state that
            // made two `fs::rename` calls fight over one staging temp.
            if self.inside.fetch_add(1, Ordering::SeqCst) > 0 {
                self.overlaps.fetch_add(1, Ordering::SeqCst);
            }
            // Wide enough that an unlocked implementation overlaps every run
            // rather than most runs.
            std::thread::sleep(std::time::Duration::from_millis(20));
            *self.contents.lock().expect("test disk") = map.clone();
            self.inside.fetch_sub(1, Ordering::SeqCst);
            Ok(())
        }

        fn get(&self, k: &str) -> Option<String> {
            self.contents
                .lock()
                .expect("test disk")
                .get(k)
                .map(|v| v.to_string())
        }
    }

    fn fake_file() -> FakeFile {
        let file = FakeFile::default();
        *file.contents.lock().expect("test disk") = ["password", "privateKey", "keyPassphrase"]
            .into_iter()
            .map(|f| {
                (
                    format!("tervia-hosts::h-1::{f}"),
                    Zeroizing::new(format!("secret-{f}")),
                )
            })
            .collect();
        file
    }

    // The reproduction, as close to `deleteHost`'s fan-out as a unit test gets:
    // one host, its three accounts, three concurrent deletes.
    #[test]
    fn concurrent_deletes_never_overlap_in_the_write_and_all_three_land() {
        let lock = Arc::new(Mutex::new(()));
        let file = Arc::new(fake_file());

        let handles: Vec<_> = ["password", "privateKey", "keyPassphrase"]
            .into_iter()
            .map(|field| {
                let lock = Arc::clone(&lock);
                let file = Arc::clone(&file);
                std::thread::spawn(move || {
                    let k = format!("tervia-hosts::h-1::{field}");
                    commit_locked(
                        &lock,
                        || file.load(),
                        |m| file.write(m),
                        |m| {
                            m.remove(&k);
                        },
                    )
                })
            })
            .collect();
        for h in handles {
            h.join().expect("thread").expect("delete");
        }

        assert_eq!(file.overlaps.load(Ordering::SeqCst), 0, "writes overlapped");
        // The lost-update half: the write that lands LAST must not carry an
        // account an earlier caller removed. Reading the file afresh inside the
        // same lock is what makes that hold now that no map outlives a commit.
        assert!(
            file.contents.lock().expect("test disk").is_empty(),
            "the file kept an account a concurrent delete had removed",
        );
    }

    #[test]
    fn the_write_sees_the_mutation_rather_than_the_map_before_it() {
        let lock = Mutex::new(());
        let file = fake_file();
        commit_locked(
            &lock,
            || file.load(),
            |m| file.write(m),
            |m| {
                m.insert(
                    "tervia-hosts::h-2::password".into(),
                    Zeroizing::new("added".into()),
                );
                m.remove("tervia-hosts::h-1::password");
            },
        )
        .expect("commit");
        assert_eq!(
            file.get("tervia-hosts::h-2::password").as_deref(),
            Some("added")
        );
        assert!(file.get("tervia-hosts::h-1::password").is_none());
    }

    /// A panic in the mutation poisons the lock, and it is a WRITE that holds
    /// it - so what a poison nobody handles costs is the rest of the session's
    /// secrets, reads included: `with_store` takes this same lock.
    #[test]
    fn a_panic_in_the_mutation_leaves_the_store_usable() {
        let lock = Mutex::new(());
        let file = fake_file();
        let died = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            commit_locked(
                &lock,
                || file.load(),
                |m| file.write(m),
                |m| {
                    m.remove("tervia-hosts::h-1::password");
                    panic!("the mutation panicked");
                },
            )
        }));
        assert!(died.is_err(), "the mutation was supposed to panic");
        // The panic unwound past the write, so the file never took the removal
        // - and no cached map is left holding one either.
        assert_eq!(
            file.get("tervia-hosts::h-1::password").as_deref(),
            Some("secret-password"),
        );

        // The next call still gets the lock. An unrecovered poison would fail
        // every later read as well as every later write.
        commit_locked(&lock, || file.load(), |m| file.write(m), |_| {})
            .expect("a commit after the panic");
        assert_eq!(
            file.get("tervia-hosts::h-1::password").as_deref(),
            Some("secret-password"),
            "the commit after the panic carried a removal that never happened",
        );
    }

    /// The inverse of the cache this replaced: nothing is retained, so a value
    /// another writer put in the file is seen by the next call rather than
    /// shadowed for the life of the process.
    #[test]
    fn every_call_reads_the_file_so_a_change_made_elsewhere_is_never_missed() {
        let lock = Mutex::new(());
        let file = fake_file();
        for _ in 0..2 {
            commit_locked(&lock, || file.load(), |m| file.write(m), |_| {}).expect("commit");
        }
        file.contents.lock().expect("test disk").insert(
            "tervia-hosts::h-9::password".into(),
            Zeroizing::new("from-elsewhere".into()),
        );
        let seen = commit_locked(
            &lock,
            || file.load(),
            |m| file.write(m),
            |m| m.get("tervia-hosts::h-9::password").map(|v| v.to_string()),
        )
        .expect("commit");
        assert_eq!(file.loads.load(Ordering::SeqCst), 3);
        assert_eq!(seen.as_deref(), Some("from-elsewhere"));
    }
}

#[cfg(test)]
mod tests {
    use super::{plan_copy, same_entry, CopyPlan, SecretSource};

    /// The internally-tagged spelling is the whole contract between
    /// `vault/resolve.ts` and serde. A typo there fails only at runtime, in
    /// production, on a connect.
    #[test]
    fn a_keychain_reference_deserializes_from_the_wire_shape() {
        let parsed = serde_json::from_str::<SecretSource>(
            r#"{"kind":"keychain","service":"tervia-hosts","account":"h-1::password"}"#,
        )
        .expect("a keychain reference");
        match parsed {
            SecretSource::Keychain { service, account } => {
                assert_eq!(
                    (service.as_str(), account.as_str()),
                    ("tervia-hosts", "h-1::password")
                );
            }
            other => panic!("expected Keychain, got {other:?}"),
        }

        let parsed = serde_json::from_str::<SecretSource>(r#"{"kind":"inline","value":"pw"}"#)
            .expect("an inline value");
        match parsed {
            SecretSource::Inline { value } => assert_eq!(value, "pw"),
            other => panic!("expected Inline, got {other:?}"),
        }

        // Neither arm named: refused rather than defaulted to one of them.
        assert!(serde_json::from_str::<SecretSource>(r#"{"service":"s","account":"a"}"#).is_err());
        assert!(serde_json::from_str::<SecretSource>(r#"{"kind":"whatever"}"#).is_err());
    }

    // The only part of `secrets_copy` reachable without an `AppHandle`, and the
    // part with a wrong version that compiles: comparing accounts alone. Under
    // that version convert-to-vault - same account name, different service -
    // reports success and writes nothing.
    #[test]
    fn same_entry_compares_the_service_as_well_as_the_account() {
        let src = ("tervia-hosts", "h-1::password");
        assert!(same_entry(src, ("tervia-hosts", "h-1::password")));
        assert!(!same_entry(src, ("tervia-vault", "h-1::password")));
        assert!(!same_entry(src, ("tervia-hosts", "h-2::password")));
        assert!(!same_entry(src, ("tervia-hosts", "h-1::privateKey")));
    }

    /// The plan a copy takes, as one word per decision so all four can be
    /// asserted together: a mutation then shows which decision moved and, just
    /// as importantly, that the other three did not.
    fn planned<'a>(value: Option<&'a str>, from: (&str, &str), to: (&str, &str)) -> &'a str {
        match plan_copy(value, from, to) {
            CopyPlan::Nothing => "nothing",
            CopyPlan::AlreadyThere => "already there",
            CopyPlan::Write(v) => v,
        }
    }

    #[test]
    fn a_copy_is_planned_from_what_the_source_holds() {
        // Converting an inline host credential to a vault identity: same
        // account name, different service.
        let from = ("tervia-hosts", "h-1::password");
        let to = ("tervia-vault", "h-1::password");
        assert_eq!(
            [
                planned(None, from, to),
                // Nothing to give, not a password of length zero: writing it
                // would claim a stored secret over an empty account.
                planned(Some(""), from, to),
                planned(Some("hunter2"), from, from),
                planned(Some("hunter2"), from, to),
            ],
            ["nothing", "nothing", "already there", "hunter2"],
        );
    }
}
