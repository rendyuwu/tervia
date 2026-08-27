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

/// Mutate the cached store and the file it came from as ONE step, with the cache
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
/// The lost-update race is the same interleaving one step earlier, and the reason
/// `copyHostSecrets` was already written sequentially: each caller used to
/// snapshot the map after its own mutation and write that snapshot unlocked, so
/// the snapshot written LAST could still carry a key an earlier caller had
/// removed - the file then disagreeing with the cache until the next launch.
///
/// The cache is ROLLED BACK when the write fails, so a caller that reports an
/// error has not also left the in-memory view claiming a change the disk never
/// took: without it a failed clear reads as "secret gone" for the rest of the
/// session and the secret reappears on the next launch.
///
/// Blocking under a `std::sync::Mutex` from an async command body, deliberately:
/// the critical section contains no `.await`, so it cannot deadlock a worker, and
/// every one of these commands already did its file read, DPAPI call or Keychain
/// call inline.
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn commit_store<F, R>(app: &AppHandle, state: &SecretsState, f: F) -> Result<R, String>
where
    F: FnOnce(&mut HashMap<String, String>) -> R,
{
    commit_cached(
        &state.cache,
        || read_store(app),
        |map| write_store(app, map),
        f,
    )
}

/// [`commit_store`] with the two `AppHandle` steps as parameters.
///
/// Split out to be testable AT ALL: `src-tauri` has no `[dev-dependencies]`, so
/// `tauri::test::mock_app()` is unavailable and an `AppHandle` cannot be
/// constructed (handoff gap 16). What has to be pinned down is the ORDERING -
/// load once, mutate, write while still holding the lock, restore on failure -
/// and every part of that ordering is here rather than in the wrapper.
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn commit_cached<L, W, F, R>(
    cache: &Mutex<Option<HashMap<String, String>>>,
    load: L,
    write: W,
    f: F,
) -> Result<R, String>
where
    L: FnOnce() -> Result<HashMap<String, String>, String>,
    W: FnOnce(&HashMap<String, String>) -> Result<(), String>,
    F: FnOnce(&mut HashMap<String, String>) -> R,
{
    let mut guard = cache.lock().map_err(|e| e.to_string())?;
    if guard.is_none() {
        *guard = Some(load()?);
    }
    let map = guard.as_mut().expect("cache initialized above");
    let previous = map.clone();
    let out = f(map);
    if let Err(e) = write(map) {
        *map = previous;
        return Err(e);
    }
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
        // Cache and file under ONE lock acquisition: see `commit_store`. Two
        // concurrent writers used to stage into the same temp file and the second
        // `rename` failed with `os error 2`.
        commit_store(app, state, |m| {
            m.insert(k, password.to_owned());
        })?;
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
/// `Ok(false)` means there was nothing at the source (absent, or an empty
/// string, which is treated as absent) and NOTHING was written. `Ok(true)`
/// means the source had a value and it now sits at the destination too.
///
/// The boolean answers "did the source have something to give", NOT "does the
/// destination own a secret now". Those agree whenever the destination starts
/// empty - `duplicateHost`'s destination is always a brand-new id - but a
/// caller converting onto an id that may already hold a secret (6e's
/// convert-to-vault, for one) cannot read `Ok(false)` as "nothing there
/// anymore": this function never clears the destination. Its only writes are
/// the one above and, on the legacy Windows Credential Manager fallback
/// inside [`write_secret`], a delete of a *stale entry for the destination
/// account*, never a clear triggered by an empty or missing source.
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
    // An empty string is treated the same as no entry at all: the JS layer
    // never persists one (it trims and deletes on blank - see `writeSecret`
    // in `hosts/store.ts` and `vault/store.ts`), so writing "" here would only
    // manufacture a `hasPassword: true` over an account that holds nothing.
    if value.is_empty() {
        return Ok(false);
    }
    if !same_entry((&from_service, &from_account), (&to_service, &to_account)) {
        write_secret(&app, &state, &to_service, &to_account, &value)?;
    }
    Ok(true)
}

/// What `commit_cached` guarantees, exercised without an `AppHandle`.
///
/// The bug these exist for is not hypothetical and was not visible in a diff:
/// three `secrets_delete` calls fan out from one SSH host delete, all three wrote
/// the file unlocked, all three staged through the same temp path, and the second
/// `fs::rename` failed with `os error 2` - so SSH host delete could never
/// complete while RDP host delete, which makes one call, always did.
///
/// The write is a closure here rather than the real file, because what has to
/// hold is an ORDERING - one writer inside the write at a time, the write seeing
/// the mutation, the cache restored when the write fails - and a temp file only
/// makes the first of those observable as a crash on one platform.
#[cfg(all(test, any(target_os = "linux", target_os = "windows")))]
mod commit_tests {
    use super::commit_cached;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    /// A stand-in for the secrets file that records the thing the real one could
    /// only express as a failed rename: how many writers were inside the write at
    /// the same time.
    #[derive(Default)]
    struct FakeFile {
        inside: AtomicUsize,
        overlaps: AtomicUsize,
        written: Mutex<HashMap<String, String>>,
    }

    impl FakeFile {
        fn write(&self, map: &HashMap<String, String>) -> Result<(), String> {
            // Entering while another writer is in here is exactly the state that
            // made two `fs::rename` calls fight over one staging temp.
            if self.inside.fetch_add(1, Ordering::SeqCst) > 0 {
                self.overlaps.fetch_add(1, Ordering::SeqCst);
            }
            // Wide enough that an unlocked implementation overlaps every run
            // rather than most runs.
            std::thread::sleep(std::time::Duration::from_millis(20));
            *self.written.lock().expect("test disk") = map.clone();
            self.inside.fetch_sub(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn seeded() -> HashMap<String, String> {
        ["password", "privateKey", "keyPassphrase"]
            .into_iter()
            .map(|f| (format!("tervia-hosts::h-1::{f}"), format!("secret-{f}")))
            .collect()
    }

    // The reproduction, as close to `deleteHost`'s fan-out as a unit test gets:
    // one host, its three accounts, three concurrent deletes.
    #[test]
    fn concurrent_deletes_never_overlap_in_the_write_and_all_three_land() {
        let cache = Arc::new(Mutex::new(Some(seeded())));
        let file = Arc::new(FakeFile::default());

        let handles: Vec<_> = ["password", "privateKey", "keyPassphrase"]
            .into_iter()
            .map(|field| {
                let cache = Arc::clone(&cache);
                let file = Arc::clone(&file);
                std::thread::spawn(move || {
                    let k = format!("tervia-hosts::h-1::{field}");
                    commit_cached(
                        &cache,
                        || panic!("the cache is already loaded"),
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
        // The lost-update half: the last snapshot written must not carry an
        // account an earlier caller removed.
        assert!(
            file.written.lock().expect("test disk").is_empty(),
            "the file kept an account a concurrent delete had removed: {:?}",
            file.written.lock().expect("test disk"),
        );
        assert!(cache
            .lock()
            .expect("cache")
            .as_ref()
            .expect("loaded")
            .is_empty());
    }

    #[test]
    fn the_write_sees_the_mutation_rather_than_the_map_before_it() {
        let cache = Mutex::new(Some(seeded()));
        let seen = Mutex::new(HashMap::new());
        commit_cached(
            &cache,
            || panic!("the cache is already loaded"),
            |m| {
                *seen.lock().expect("seen") = m.clone();
                Ok(())
            },
            |m| {
                m.insert("tervia-hosts::h-2::password".into(), "added".into());
                m.remove("tervia-hosts::h-1::password");
            },
        )
        .expect("commit");
        let seen = seen.lock().expect("seen");
        assert_eq!(
            seen.get("tervia-hosts::h-2::password").map(String::as_str),
            Some("added")
        );
        assert!(!seen.contains_key("tervia-hosts::h-1::password"));
    }

    #[test]
    fn a_failed_write_leaves_the_cache_exactly_as_it_was() {
        let cache = Mutex::new(Some(seeded()));
        let err = commit_cached(
            &cache,
            || panic!("the cache is already loaded"),
            |_| Err("dpapi: CryptProtectData failed".to_string()),
            |m| {
                m.remove("tervia-hosts::h-1::password");
            },
        )
        .expect_err("the write failed, so the commit must fail");
        assert_eq!(err, "dpapi: CryptProtectData failed");
        // Otherwise a clear that failed reads as done for the rest of the
        // session, and the secret comes back on the next launch.
        assert_eq!(
            cache
                .lock()
                .expect("cache")
                .as_ref()
                .expect("loaded")
                .get("tervia-hosts::h-1::password")
                .map(String::as_str),
            Some("secret-password"),
        );
    }

    #[test]
    fn the_file_is_read_once_and_then_served_from_the_cache() {
        let cache = Mutex::new(None);
        let loads = AtomicUsize::new(0);
        let load = || {
            loads.fetch_add(1, Ordering::SeqCst);
            Ok(seeded())
        };
        for _ in 0..2 {
            commit_cached(&cache, load, |_| Ok(()), |m| m.clear()).expect("commit");
        }
        assert_eq!(loads.load(Ordering::SeqCst), 1);
    }
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
