//! Passphrase-encrypted blobs for the connection backup (SSH menu -> Export
//! connections).
//!
//! An exported backup carries the credentials that live in the OS keychain -
//! SSH passwords and private keys, RDP passwords - so it can never be written
//! as plaintext: the file ends up on a USB stick, in Downloads, or in a synced
//! folder. This module is the whole crypto surface; everything above it in JS
//! handles only the already-sealed blob.
//!
//! Two format generations live here, and the difference is not only what is
//! sealed but WHO touches the plaintext:
//!
//! - **v1** (`tervia-ssh-connections`, SSH only) sealed just the credential
//!   block. `backup_open` hands that plaintext back to JS, which writes it to
//!   the keychain with `secrets_set`. Kept for reading old files only.
//! - **v2** (`tervia-connections`) seals the WHOLE payload - both connection
//!   inventories and every credential - and the plaintext never leaves this
//!   process. On export, JS passes keychain REFERENCES and
//!   [`backup_seal_payload`] reads the values itself. On import,
//!   [`backup_open_payload`] returns only the connection metadata and parks the
//!   credentials here behind a handle; JS validates the metadata, says which
//!   ids survived, and [`backup_apply_secrets`] writes those straight to the
//!   keychain. That is the same property `rdp_open`'s keychain reference
//!   exists to protect, extended to the backup path.
//!
//! Not solved here: the decrypted plaintext is ordinary `String`/`serde_json`
//! data and is dropped unscrubbed, same as every other secret in the process
//! (tracked as RDP-20, the `SecretsState` cache, which is the larger link in
//! that chain).
//!
//! This lives in the host process rather than the webview because
//! `crypto.subtle` is gated to secure contexts and the app origin is plain
//! http (same reason `crypto.randomUUID` is unavailable - see
//! `modules/ai/lib/httpProxy.ts`).
//!
//! Construction: PBKDF2-HMAC-SHA256 over the passphrase with a random 16-byte
//! salt, then AES-256-GCM with a random 12-byte nonce. Salt and nonce are
//! generated per seal and stored beside the ciphertext; neither is secret.
//! GCM's authentication tag is what makes a wrong passphrase, a truncated
//! file, or a flipped byte all fail closed as "wrong passphrase or corrupt
//! file" rather than yielding garbage that the importer would try to parse.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ring::{
    aead::{self, BoundKey, Nonce, NonceSequence, UnboundKey, AES_256_GCM, NONCE_LEN},
    error::Unspecified,
    pbkdf2,
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{LazyLock, Mutex};
use tauri::AppHandle;

use crate::modules::secrets::{read_secret, write_secret, SecretsState};

/// Deliberately high: the passphrase is user-chosen and the file is offline,
/// so an attacker gets unlimited guesses. OWASP's 2023 floor for
/// PBKDF2-HMAC-SHA256 is 600k. Stored in the envelope rather than hardcoded on
/// the read path so raising it later still opens older backups.
const PBKDF2_ITERATIONS: u32 = 600_000;
const SALT_LEN: usize = 16;

#[derive(Serialize, Deserialize)]
pub struct SealedBlob {
    /// Named so a future format change is a value check, not a guess.
    pub kdf: String,
    pub iterations: u32,
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
}

/// `ring`'s sealing API consumes a nonce sequence; we seal exactly one message
/// per key, so the sequence yields our single random nonce and then refuses.
/// Refusing matters: reusing a nonce under the same key breaks GCM completely.
struct OneNonce(Option<[u8; NONCE_LEN]>);

impl NonceSequence for OneNonce {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        self.0
            .take()
            .map(Nonce::assume_unique_for_key)
            .ok_or(Unspecified)
    }
}

fn derive_key(passphrase: &str, salt: &[u8], iterations: u32) -> Result<[u8; 32], String> {
    let iters =
        NonZeroU32::new(iterations).ok_or_else(|| "backup: iteration count is zero".to_string())?;
    let mut key = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iters,
        salt,
        passphrase.as_bytes(),
        &mut key,
    );
    Ok(key)
}

/// Encrypt `plaintext` under `passphrase`. Returns the blob to embed in the
/// export file. An empty passphrase is refused here rather than in the UI so
/// the guarantee holds no matter which caller reaches this.
///
/// Not a command: v2 exports go through [`backup_seal_payload`], which is the
/// only caller, so there is no reason to expose a general-purpose encrypt-this
/// entry point to the webview.
fn seal_blob(plaintext: String, passphrase: &str) -> Result<SealedBlob, String> {
    if passphrase.is_empty() {
        return Err("backup: a passphrase is required".into());
    }
    let rng = SystemRandom::new();
    let mut salt = [0u8; SALT_LEN];
    rng.fill(&mut salt)
        .map_err(|_| "backup: random salt failed".to_string())?;
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill(&mut nonce)
        .map_err(|_| "backup: random nonce failed".to_string())?;

    let key = derive_key(passphrase, &salt, PBKDF2_ITERATIONS)?;
    let unbound = UnboundKey::new(&AES_256_GCM, &key).map_err(|_| "backup: bad key".to_string())?;
    let mut sealing = aead::SealingKey::new(unbound, OneNonce(Some(nonce)));

    // seal_in_place_append_tag appends the 16-byte auth tag, so `buf` ends up
    // as ciphertext||tag - which is exactly what open_in_place expects back.
    let mut buf = plaintext.into_bytes();
    sealing
        .seal_in_place_append_tag(aead::Aad::empty(), &mut buf)
        .map_err(|_| "backup: encryption failed".to_string())?;

    Ok(SealedBlob {
        kdf: "pbkdf2-hmac-sha256".into(),
        iterations: PBKDF2_ITERATIONS,
        salt: B64.encode(salt),
        nonce: B64.encode(nonce),
        ciphertext: B64.encode(&buf),
    })
}

/// Decrypt a blob produced by [`seal_blob`]. Every failure below - wrong
/// passphrase, tampered ciphertext, truncated file - is reported with the same
/// message on purpose: distinguishing them tells an attacker which guess was
/// closer, and none of them is separately actionable for the user.
fn open_blob(blob: SealedBlob, passphrase: &str) -> Result<String, String> {
    if blob.kdf != "pbkdf2-hmac-sha256" {
        return Err(format!(
            "backup: unsupported key derivation \"{}\"",
            blob.kdf
        ));
    }
    let salt = B64
        .decode(&blob.salt)
        .map_err(|_| "backup: malformed salt".to_string())?;
    let nonce_bytes = B64
        .decode(&blob.nonce)
        .map_err(|_| "backup: malformed nonce".to_string())?;
    let mut buf = B64
        .decode(&blob.ciphertext)
        .map_err(|_| "backup: malformed ciphertext".to_string())?;
    let nonce: [u8; NONCE_LEN] = nonce_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "backup: malformed nonce".to_string())?;

    let key = derive_key(passphrase, &salt, blob.iterations)?;
    let unbound = UnboundKey::new(&AES_256_GCM, &key).map_err(|_| "backup: bad key".to_string())?;
    let mut opening = aead::OpeningKey::new(unbound, OneNonce(Some(nonce)));

    let plain = opening
        .open_in_place(aead::Aad::empty(), &mut buf)
        .map_err(|_| "backup: wrong passphrase, or the file is corrupt".to_string())?;
    String::from_utf8(plain.to_vec())
        .map_err(|_| "backup: decrypted data is not valid UTF-8".into())
}

/// Decrypt the credential block of a **v1** (`tervia-ssh-connections`) file.
///
/// The only remaining reason plaintext credentials cross into the webview: a v1
/// file's sealed block is the credential map itself, and the importer on the JS
/// side is what writes it to the keychain. v2 files never reach this - see
/// [`backup_open_payload`].
#[tauri::command]
pub async fn backup_open(blob: SealedBlob, passphrase: String) -> Result<String, String> {
    open_blob(blob, &passphrase)
}

/// Where one secret lives in the keychain, and where it belongs inside the
/// sealed payload.
///
/// The same shape on the way out and the way back in. `group`, `id` and `field`
/// are the three levels of the path inside the payload JSON and are supplied by
/// the caller verbatim, so this module holds no knowledge of either protocol's
/// field names - `password` versus `privateKey`, `secrets` versus `rdpSecrets`
/// are all decided in `src/modules/ssh/backupFile.ts`.
#[derive(Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SecretRef {
    /// Top-level key of the payload object, e.g. `secrets` or `rdpSecrets`.
    group: String,
    /// Connection id: the second level.
    id: String,
    /// Field name: the third level, e.g. `password`.
    field: String,
    service: String,
    account: String,
}

/// Insert `values` into `payload` at each ref's `group`/`id`/`field` path.
///
/// Refuses to write into a group the payload already carries. That guard is not
/// theoretical bookkeeping: the caller sends `{"connections": [...]}` and names
/// its own group strings, so a typo of `connections` would otherwise replace the
/// entire inventory with a credential map and the export would look successful.
fn merge_secrets(payload: &str, values: &[(SecretRef, String)]) -> Result<String, String> {
    let mut root: Map<String, Value> = serde_json::from_str(payload)
        .map_err(|_| "backup: the payload is not a JSON object".to_string())?;
    for (r, _) in values {
        if root.contains_key(&r.group) {
            return Err(format!(
                "backup: the payload already carries a \"{}\" key",
                r.group
            ));
        }
    }
    for (r, value) in values {
        let group = root
            .entry(r.group.clone())
            .or_insert_with(|| Value::Object(Map::new()));
        let Some(group) = group.as_object_mut() else {
            continue;
        };
        let entry = group
            .entry(r.id.clone())
            .or_insert_with(|| Value::Object(Map::new()));
        if let Some(entry) = entry.as_object_mut() {
            entry.insert(r.field.clone(), Value::String(value.clone()));
        }
    }
    serde_json::to_string(&Value::Object(root)).map_err(|e| e.to_string())
}

/// Seal a v2 payload, reading every credential out of the keychain here rather
/// than taking it from the caller.
///
/// `payload` is the connection inventory as JSON; `refs` say which keychain
/// entries to fold into it. A reference that resolves to nothing is skipped, not
/// an error - a connection whose password was never saved is ordinary.
#[tauri::command]
pub async fn backup_seal_payload(
    app: AppHandle,
    state: tauri::State<'_, SecretsState>,
    payload: String,
    refs: Vec<SecretRef>,
    passphrase: String,
) -> Result<SealedBlob, String> {
    if passphrase.is_empty() {
        return Err("backup: a passphrase is required".into());
    }
    let mut values: Vec<(SecretRef, String)> = Vec::new();
    for r in refs {
        // A keychain read that FAILS is propagated rather than skipped: an
        // export that silently omits a credential is worse than one that
        // refuses, because the file looks complete until the day it is needed.
        if let Some(v) = read_secret(&app, &state, &r.service, &r.account)? {
            if !v.is_empty() {
                values.push((r, v));
            }
        }
    }
    let plaintext = merge_secrets(&payload, &values)?;
    seal_blob(plaintext, &passphrase)
}

/// Credentials decrypted out of a v2 backup, waiting for the importer to say
/// which connection ids survived validation.
struct Held {
    groups: Map<String, Value>,
}

/// Parked payloads, oldest first.
///
/// Process-global rather than Tauri-managed state so the whole v2 import path
/// stays inside this module. The cap is what bounds the damage if a caller ever
/// fails to release: an abandoned import holds its credentials until four more
/// imports have run, not until the app exits.
static HELD: LazyLock<Mutex<Vec<(u32, Held)>>> = LazyLock::new(|| Mutex::new(Vec::new()));
static NEXT_HANDLE: AtomicU32 = AtomicU32::new(1);
const MAX_HELD: usize = 4;

fn hold(groups: Map<String, Value>) -> Result<u32, String> {
    let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    let mut store = HELD.lock().map_err(|_| POISONED.to_string())?;
    while store.len() >= MAX_HELD {
        store.remove(0);
    }
    store.push((handle, Held { groups }));
    Ok(handle)
}

fn release(handle: u32) -> Result<(), String> {
    let mut store = HELD.lock().map_err(|_| POISONED.to_string())?;
    store.retain(|(h, _)| *h != handle);
    Ok(())
}

const POISONED: &str = "backup: the import store is poisoned";

/// The value one ref points at, or `None` when nothing usable is parked there.
fn pick(groups: &Map<String, Value>, r: &SecretRef) -> Option<String> {
    groups
        .get(&r.group)?
        .get(&r.id)?
        .get(&r.field)?
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

/// Split the named groups out of a decrypted payload. Returns the remainder as
/// JSON plus the groups that were removed.
fn split_groups(plain: &str, groups: &[String]) -> Result<(String, Map<String, Value>), String> {
    let mut root: Map<String, Value> = serde_json::from_str(plain)
        .map_err(|_| "backup: the decrypted payload is not a JSON object".to_string())?;
    let mut taken = Map::new();
    for g in groups {
        if let Some(v) = root.remove(g) {
            taken.insert(g.clone(), v);
        }
    }
    let rest = serde_json::to_string(&Value::Object(root)).map_err(|e| e.to_string())?;
    Ok((rest, taken))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenedPayload {
    /// Pass to [`backup_apply_secrets`], then to [`backup_release`].
    handle: u32,
    /// The payload with every requested group removed: connection metadata
    /// only, safe to hand to the webview's validator.
    payload: String,
}

/// Open a v2 payload: return the metadata, park the credentials.
///
/// The two-step shape exists so validation can stay on the JS side, where the
/// trust-boundary rules for an imported connection already live, without the
/// credentials having to travel with it. `groups` names the payload keys to
/// withhold.
#[tauri::command]
pub async fn backup_open_payload(
    blob: SealedBlob,
    passphrase: String,
    groups: Vec<String>,
) -> Result<OpenedPayload, String> {
    let plain = open_blob(blob, &passphrase)?;
    let (payload, taken) = split_groups(&plain, &groups)?;
    Ok(OpenedPayload {
        handle: hold(taken)?,
        payload,
    })
}

/// Write the parked credentials the importer asked for into the keychain.
///
/// Returns one flag per ref, in order, saying whether anything was actually
/// stored - which is what lets the importer report "imported without stored
/// credentials" without ever seeing the credentials.
#[tauri::command]
pub async fn backup_apply_secrets(
    app: AppHandle,
    state: tauri::State<'_, SecretsState>,
    handle: u32,
    refs: Vec<SecretRef>,
) -> Result<Vec<bool>, String> {
    // Copy out under the lock and write outside it: a keychain write is a file
    // write plus, on Windows, a DPAPI call, and holding a process-global mutex
    // across that would serialize every concurrent import behind the slowest.
    let values: Vec<Option<String>> = {
        let store = HELD.lock().map_err(|_| POISONED.to_string())?;
        let held = store
            .iter()
            .find(|(h, _)| *h == handle)
            .map(|(_, v)| v)
            .ok_or_else(|| "backup: that import is no longer open".to_string())?;
        refs.iter().map(|r| pick(&held.groups, r)).collect()
    };

    let mut written = Vec::with_capacity(refs.len());
    for (r, value) in refs.iter().zip(values) {
        match value {
            Some(v) => {
                write_secret(&app, &state, &r.service, &r.account, &v)?;
                written.push(true);
            }
            None => written.push(false),
        }
    }
    Ok(written)
}

/// Drop a parked payload. Releasing an unknown or already-released handle is
/// deliberately not an error: the importer calls this from a `finally`, which
/// also runs on the path where opening itself failed.
#[tauri::command]
pub async fn backup_release(handle: u32) -> Result<(), String> {
    release(handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seal(pt: &str, pw: &str) -> SealedBlob {
        seal_blob(pt.into(), pw).expect("seal")
    }
    fn open(b: SealedBlob, pw: &str) -> Result<String, String> {
        open_blob(b, pw)
    }
    fn secret_ref(group: &str, id: &str, field: &str) -> SecretRef {
        SecretRef {
            group: group.into(),
            id: id.into(),
            field: field.into(),
            service: "tervia-ssh".into(),
            account: format!("{id}::{field}"),
        }
    }

    #[test]
    fn round_trips() {
        let pt = r#"{"c-1":{"password":"hunter2"}}"#;
        assert_eq!(
            open(seal(pt, "correct horse"), "correct horse").unwrap(),
            pt
        );
    }

    #[test]
    fn wrong_passphrase_fails_closed() {
        // The whole point of the auth tag: a bad passphrase must not yield
        // plausible-looking bytes for the importer to parse.
        let err = open(seal("secret", "right"), "wrong").unwrap_err();
        assert!(err.contains("wrong passphrase"), "unexpected error: {err}");
    }

    #[test]
    fn tampered_ciphertext_fails_closed() {
        let mut b = seal("secret", "pw");
        let mut raw = B64.decode(&b.ciphertext).unwrap();
        raw[0] ^= 0x01;
        b.ciphertext = B64.encode(&raw);
        assert!(open(b, "pw").is_err());
    }

    #[test]
    fn empty_passphrase_is_refused() {
        assert!(seal_blob("x".into(), "").is_err());
    }

    #[test]
    fn salt_and_nonce_differ_per_seal() {
        // Same plaintext and passphrase must never produce the same bytes, or
        // two exports would reveal that nothing changed between them.
        let (a, b) = (seal("same", "pw"), seal("same", "pw"));
        assert_ne!(a.salt, b.salt);
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn unicode_survives() {
        let pt = "kunci rahasia — ✓ 日本語";
        assert_eq!(open(seal(pt, "pw"), "pw").unwrap(), pt);
    }

    // --- v2 payload assembly ---------------------------------------------

    #[test]
    fn merge_places_each_secret_at_its_path() {
        let merged = merge_secrets(
            r#"{"connections":[{"id":"c-1"}],"rdpConnections":[]}"#,
            &[
                (secret_ref("secrets", "c-1", "password"), "hunter2".into()),
                (secret_ref("secrets", "c-1", "privateKey"), "KEY".into()),
                (secret_ref("rdpSecrets", "r-1", "password"), "rdp-pw".into()),
            ],
        )
        .unwrap();
        let v: Value = serde_json::from_str(&merged).unwrap();
        assert_eq!(v["secrets"]["c-1"]["password"], "hunter2");
        assert_eq!(v["secrets"]["c-1"]["privateKey"], "KEY");
        assert_eq!(v["rdpSecrets"]["r-1"]["password"], "rdp-pw");
        // The inventory the caller sent must come through untouched.
        assert_eq!(v["connections"][0]["id"], "c-1");
        assert!(v["rdpConnections"].as_array().unwrap().is_empty());
    }

    #[test]
    fn merge_refuses_to_overwrite_an_existing_key() {
        // The failure this prevents: a group named `connections` would replace
        // the whole inventory with a credential map, and the export would still
        // report success.
        let err = merge_secrets(
            r#"{"connections":[{"id":"c-1"}]}"#,
            &[(
                secret_ref("connections", "c-1", "password"),
                "pw".to_string(),
            )],
        )
        .unwrap_err();
        assert!(err.contains("already carries"), "unexpected error: {err}");
    }

    #[test]
    fn merge_rejects_a_payload_that_is_not_an_object() {
        assert!(merge_secrets("[1,2]", &[]).is_err());
        assert!(merge_secrets("not json", &[]).is_err());
    }

    #[test]
    fn merge_with_no_refs_is_a_passthrough() {
        // The shape of an export with no credentials saved anywhere: still a
        // valid v2 payload, just with no secret groups in it.
        let out = merge_secrets(r#"{"connections":[],"rdpConnections":[]}"#, &[]).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert!(v.get("secrets").is_none());
    }

    // --- v2 import: split, pick, park ------------------------------------

    #[test]
    fn split_withholds_only_the_named_groups() {
        let sealed_plain = merge_secrets(
            r#"{"connections":[{"id":"c-1","host":"example.com"}],"rdpConnections":[]}"#,
            &[(secret_ref("secrets", "c-1", "password"), "hunter2".into())],
        )
        .unwrap();
        let (rest, taken) =
            split_groups(&sealed_plain, &["secrets".into(), "rdpSecrets".into()]).unwrap();
        // What goes to the webview: metadata, no credentials.
        assert!(rest.contains("example.com"));
        assert!(!rest.contains("hunter2"), "credential leaked into {rest}");
        assert_eq!(taken["secrets"]["c-1"]["password"], "hunter2");
        // A group the file never had is simply absent, not an error.
        assert!(taken.get("rdpSecrets").is_none());
    }

    #[test]
    fn split_rejects_a_non_object_payload() {
        assert!(split_groups("[]", &["secrets".into()]).is_err());
    }

    #[test]
    fn pick_finds_a_value_and_refuses_anything_else() {
        let (_, groups) = split_groups(
            r#"{"secrets":{"c-1":{"password":"pw","privateKey":"","keyPassphrase":7}}}"#,
            &["secrets".into()],
        )
        .unwrap();
        assert_eq!(
            pick(&groups, &secret_ref("secrets", "c-1", "password")),
            Some("pw".to_string())
        );
        // An empty string is "no credential", not a credential of length zero:
        // storing it would set the hasPassword flag on a connection that then
        // fails the backend's "no credentials" guard at dial time.
        assert_eq!(
            pick(&groups, &secret_ref("secrets", "c-1", "privateKey")),
            None
        );
        // A non-string is junk from a hand-edited file.
        assert_eq!(
            pick(&groups, &secret_ref("secrets", "c-1", "keyPassphrase")),
            None
        );
        assert_eq!(
            pick(&groups, &secret_ref("secrets", "c-2", "password")),
            None
        );
        assert_eq!(
            pick(&groups, &secret_ref("rdpSecrets", "c-1", "password")),
            None
        );
    }

    /// `HELD` is process-global, so the two tests that assert on its contents
    /// have to take turns: cargo runs tests in parallel, and one test's inserts
    /// would otherwise evict the other's handle before it looked for it.
    static PARK_GUARD: Mutex<()> = Mutex::new(());

    #[test]
    fn a_released_handle_is_gone_and_releasing_twice_is_fine() {
        let _guard = PARK_GUARD.lock().unwrap();
        let mut groups = Map::new();
        groups.insert("secrets".into(), Value::Object(Map::new()));
        let handle = hold(groups).unwrap();
        assert!(HELD.lock().unwrap().iter().any(|(h, _)| *h == handle));
        release(handle).unwrap();
        assert!(!HELD.lock().unwrap().iter().any(|(h, _)| *h == handle));
        release(handle).unwrap();
    }

    #[test]
    fn the_park_evicts_the_oldest_rather_than_growing() {
        // An importer that never releases must not accumulate credentials for
        // the process's lifetime.
        let _guard = PARK_GUARD.lock().unwrap();
        let handles: Vec<u32> = (0..MAX_HELD + 2)
            .map(|_| hold(Map::new()).unwrap())
            .collect();
        let store = HELD.lock().unwrap();
        assert!(store.len() <= MAX_HELD);
        let newest = handles.last().copied().unwrap();
        assert!(store.iter().any(|(h, _)| *h == newest));
        let oldest = handles[0];
        assert!(!store.iter().any(|(h, _)| *h == oldest));
    }

    #[test]
    fn a_v2_export_leaks_no_metadata() {
        // Exit-gate item 5: nothing greppable in the file. The envelope JS
        // writes around this blob carries only kind/version/exportedAt.
        let plain = merge_secrets(
            r#"{"connections":[{"id":"c-1","host":"vps.example.com","user":"root","port":22}],"rdpConnections":[]}"#,
            &[(secret_ref("secrets", "c-1", "password"), "hunter2".into())],
        )
        .unwrap();
        let blob = seal(&plain, "pw");
        for needle in ["vps.example.com", "root", "hunter2"] {
            assert!(
                !blob.ciphertext.contains(needle),
                "{needle} is readable in the sealed blob"
            );
        }
        assert_eq!(open(blob, "pw").unwrap(), plain);
    }
}
