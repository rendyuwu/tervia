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

use std::sync::Mutex;

use tauri::AppHandle;

#[cfg(any(target_os = "linux", target_os = "windows"))]
use std::collections::HashMap;
#[cfg(any(target_os = "linux", target_os = "windows"))]
use std::fs;
#[cfg(any(target_os = "linux", target_os = "windows"))]
use std::path::PathBuf;
#[cfg(any(target_os = "linux", target_os = "windows"))]
use tauri::Manager;

#[derive(Default)]
pub struct SecretsState {
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    cache: Mutex<Option<HashMap<String, String>>>,
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
fn read_store(app: &AppHandle) -> Result<HashMap<String, String>, String> {
    let path = store_path(app)?;
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let bytes = fs::read(&path).map_err(|e| e.to_string())?;
    serde_json::from_slice::<HashMap<String, String>>(&bytes).map_err(|e| e.to_string())
}

#[cfg(target_os = "linux")]
fn write_store(app: &AppHandle, map: &HashMap<String, String>) -> Result<(), String> {
    let path = store_path(app)?;
    let bytes = serde_json::to_vec(map).map_err(|e| e.to_string())?;
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
fn dpapi_unprotect(cipher: &[u8]) -> Result<Vec<u8>, String> {
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
    let bytes =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        LocalFree(output.pbData as *mut _);
    }
    Ok(bytes)
}

#[cfg(target_os = "windows")]
fn read_store(app: &AppHandle) -> Result<HashMap<String, String>, String> {
    let path = store_path(app)?;
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let cipher = fs::read(&path).map_err(|e| e.to_string())?;
    if cipher.is_empty() {
        return Ok(HashMap::new());
    }
    let plain = dpapi_unprotect(&cipher)?;
    serde_json::from_slice::<HashMap<String, String>>(&plain).map_err(|e| e.to_string())
}

#[cfg(target_os = "windows")]
fn write_store(app: &AppHandle, map: &HashMap<String, String>) -> Result<(), String> {
    let path = store_path(app)?;
    let plain = serde_json::to_vec(map).map_err(|e| e.to_string())?;
    let cipher = dpapi_protect(&plain)?;
    crate::modules::fs::atomic::atomic_write(&path, &cipher).map_err(|e| e.to_string())
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn with_store<F, R>(app: &AppHandle, state: &SecretsState, f: F) -> Result<R, String>
where
    F: FnOnce(&mut HashMap<String, String>) -> R,
{
    let mut guard = state.cache.lock().map_err(|e| e.to_string())?;
    if guard.is_none() {
        *guard = Some(read_store(app)?);
    }
    let map = guard.as_mut().expect("cache initialized above");
    Ok(f(map))
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

/// Read one secret, doing the per-platform keychain-or-fallback work.
///
/// The single implementation behind both [`secrets_get`] (the IPC surface the
/// frontend uses) and the in-process callers that must NOT round-trip a
/// plaintext through the webview: `rdp::rdp_open`, which resolves a credential
/// reference and hands the password straight to CredSSP, and [`secrets_copy`],
/// which moves one between accounts. Two copies of this would drift, and the
/// Windows Credential Manager fallback below is exactly the kind of thing that
/// silently stops being applied in the copy nobody edits.
///
/// Blocking: a small file read plus one DPAPI call on Windows, a Keychain call
/// on macOS. `secrets_get` has always done this inline in its async body; the
/// callers here do the same rather than paying a `spawn_blocking` hop.
pub(crate) fn read_secret(
    app: &AppHandle,
    state: &SecretsState,
    service: &str,
    account: &str,
) -> Result<Option<String>, String> {
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    {
        let k = key(service, account);
        let hit = with_store(app, state, |m| m.get(&k).cloned())?;
        if hit.is_some() {
            return Ok(hit);
        }
        #[cfg(target_os = "windows")]
        {
            Ok(legacy_keyring_get(service, account))
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
            Ok(v) => Ok(Some(v)),
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
) -> Result<Option<String>, String> {
    read_secret(&app, &state, &service, &account)
}

/// Write one secret, doing the per-platform keychain-or-fallback work.
///
/// The counterpart of [`read_secret`], and split out for the same reason: the
/// in-process callers that must NOT round-trip a plaintext through the webview
/// need the identical write path, and the Windows Credential Manager cleanup
/// below is exactly the kind of step that quietly stops happening in a second
/// copy. The in-process callers are `backup::backup_apply_secrets`, which takes
/// credentials straight out of a decrypted backup into the keychain, and
/// [`secrets_copy`].
///
/// Blocking, on the same terms as [`read_secret`].
pub(crate) fn write_secret(
    app: &AppHandle,
    state: &SecretsState,
    service: &str,
    account: &str,
    password: &str,
) -> Result<(), String> {
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    {
        let k = key(service, account);
        // Mutate and snapshot under one lock acquisition so a concurrent
        // writer cannot slip an update between, which would leave the on-disk
        // file lagging the in-memory cache (lost-update race).
        let snapshot = with_store(app, state, |m| {
            m.insert(k, password.to_owned());
            m.clone()
        })?;
        write_store(app, &snapshot)?;
        #[cfg(target_os = "windows")]
        {
            // Stale Credential Manager entry from an earlier build would
            // shadow updates on read; delete it so the file store wins.
            legacy_keyring_delete(service, account);
        }
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        let _ = (app, state);
        let e = entry(service, account)?;
        e.set_password(password).map_err(|e| e.to_string())
    }
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
        let snapshot = with_store(&app, &state, |m| {
            m.remove(&k);
            m.clone()
        })?;
        write_store(&app, &snapshot)?;
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
) -> Result<Vec<Option<String>>, String> {
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
                .map(|(v, a)| v.or_else(|| legacy_keyring_get(&service, a)))
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

/// Copy one secret from one account to another WITHOUT its plaintext entering
/// the webview.
///
/// Deliberately cross-service, which is why it takes four arguments rather than
/// the three a same-service copy would need. Duplicating a host moves
/// `tervia-hosts :: <src>::password` to `tervia-hosts :: <copy>::password`;
/// converting an inline credential to a vault identity moves
/// `tervia-hosts :: <host>::password` to `tervia-vault :: <identity>::password`.
/// Neither may read the value back first, and for an RDP password that is a
/// Phase 5 invariant rather than a preference - it is the reason a duplicated
/// RDP host used to get no password at all.
///
/// `Ok(false)` means there was nothing at the source and NOTHING was written.
/// That distinction is load-bearing rather than tidy: an account holding the
/// empty string is indistinguishable from a real one to every `has*` flag in the
/// app, so inventing one here would leave a record advertising a credential the
/// user never set, on a layer that never reads a secret back to correct itself.
/// The caller reads the boolean as "does the destination own this secret now",
/// which is exactly the flag it has to persist.
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
    let Some(value) = read_secret(&app, &state, &from_service, &from_account)? else {
        return Ok(false);
    };
    if !same_entry((&from_service, &from_account), (&to_service, &to_account)) {
        write_secret(&app, &state, &to_service, &to_account, &value)?;
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::same_entry;

    // The only part of `secrets_copy` reachable without an `AppHandle`, and the
    // part with a wrong version that compiles: comparing accounts alone. Under
    // that version 6e's convert-to-vault - same account name, different service
    // - reports success and writes nothing.
    #[test]
    fn same_entry_compares_the_service_as_well_as_the_account() {
        let src = ("tervia-hosts", "h-1::password");
        assert!(same_entry(src, ("tervia-hosts", "h-1::password")));
        assert!(!same_entry(src, ("tervia-vault", "h-1::password")));
        assert!(!same_entry(src, ("tervia-hosts", "h-2::password")));
        assert!(!same_entry(src, ("tervia-hosts", "h-1::privateKey")));
    }
}
