//! Everything the remote sees is sealed here, and nothing here talks to the
//! remote.
//!
//! PURE, in the same sense `src-tauri/src/modules/sync/model.rs` is: no
//! network, no filesystem, no keychain. It takes a passphrase or a keyfile and
//! returns bytes.
//!
//! The chain, top to bottom:
//!
//! ```text
//! passphrase + random salt, PBKDF2-HMAC-SHA256 @ 600000  ->  key-encryption key
//! root key (32 random bytes), AES-256-GCM under the KEK  ->  wrapped, in the keyfile
//! root key, HKDF-SHA256 Expand with two labels           ->  data key, name key
//! data key, AES-256-GCM with a fresh nonce               ->  each record
//! name key, HMAC-SHA256                                  ->  each object name
//! ```
//!
//! ONE WRAPPED ROOT, TWO DERIVED SUBKEYS, rather than two independently
//! wrapped keys: the keyfile then holds one blob, and changing the passphrase
//! rewraps one thing. `ring::hkdf` rather than a hand-rolled HMAC
//! construction, because it is a named primitive in a dependency this crate
//! already pins, so there is no ad-hoc crypto for a reviewer to verify.
//!
//! WHY THE NAME KEY EXISTS AT ALL: an object's name is a path segment on
//! somebody else's storage. Deriving it from the record's `kind` and `id`
//! directly would publish the whole inventory's shape in the file listing.
//! HMAC under a key the remote does not have makes the listing opaque while
//! keeping the name deterministic, so two devices independently compute the
//! same name for the same record.
//!
//! NO PATHS HERE. The layout `<prefix>/v1/keyfile` and `<prefix>/v1/obj/<name>`
//! belongs to the provider; this module produces the `<name>` half and the
//! keyfile struct and builds no path.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ring::{
    aead::NONCE_LEN,
    hkdf, hmac, pbkdf2,
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use std::num::NonZeroU32;

use crate::modules::aesgcm::{open_with_key, seal_with_key};
use crate::modules::sync::model::WIRE_VERSION;

/// Deliberately high, on the same grounds as the backup's: the passphrase is
/// user-chosen and the keyfile sits on storage an attacker may hold, so they
/// get unlimited offline guesses. Stored in the keyfile rather than hardcoded
/// on the read path, so raising it later still opens older keyfiles.
const PBKDF2_ITERATIONS: u32 = 600_000;
const SALT_LEN: usize = 16;
const KDF_NAME: &str = "pbkdf2-hmac-sha256";

/// The two HKDF labels. DISTINCT is the whole requirement - they are what make
/// the two subkeys independent - and they are spelled out rather than built
/// from a shared stem so a refactor cannot accidentally collapse them.
const DATA_LABEL: &[u8] = b"tervia-sync-record-key";
const NAME_LABEL: &[u8] = b"tervia-sync-object-name-key";

/// One message for every way opening can fail.
///
/// Wrong passphrase, a flipped byte, a truncated field, base64 that is not
/// base64: all the same sentence, because distinguishing them tells an
/// attacker which guess was closer and none of them is separately actionable.
/// The string is spelled here as well as in
/// `src-tauri/src/modules/aesgcm.rs` because the two must MATCH, and
/// [`a_wrong_passphrase_and_a_corrupt_keyfile_are_indistinguishable`] is what
/// notices when they stop.
const OPAQUE_FAILURE: &str = "sync: wrong passphrase, or the file is corrupt";
const PREFIX: &str = "sync";

/// The two working keys, held only in memory and never serialized.
///
/// Both halves are 32 random-derived bytes, so SWAPPING them breaks nothing
/// observable while silently discarding the separation this design paid for.
/// That is what [`each_path_uses_its_own_subkey`] exists to pin.
///
/// NO `Debug`, deliberately: a derived one prints key material, and the one
/// place that would happen is a log line or a panic message written by
/// somebody who did not think about it.
pub struct SyncKeys {
    data: [u8; 32],
    name: [u8; 32],
}

/// What sits at the root of the remote, and the only thing a second device
/// needs besides the passphrase.
///
/// Every field is `pub` because the provider has to serialize this to the
/// remote verbatim. None of it is secret: the salt and nonce are public by
/// construction, and `wrapped` is the root key under a passphrase-derived key.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Keyfile {
    /// Checked, not assumed, the same way `kdf` is.
    pub v: u32,
    pub kdf: String,
    pub iterations: u32,
    pub salt: String,
    pub nonce: String,
    pub wrapped: String,
}

/// One sealed record, as it is stored. The nonce is per record and public.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SealedRecord {
    pub nonce: String,
    pub ciphertext: String,
}

/// HKDF-Expand the root into one labelled subkey.
///
/// Expand rather than Extract-then-Expand because the root is already 32
/// uniformly random bytes from the system RNG, which is exactly the input
/// `Prk` wants. Extract would add a step that buys nothing here.
fn subkey(root: &[u8; 32], label: &[u8]) -> Result<[u8; 32], String> {
    let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, root);
    let mut out = [0u8; 32];
    prk.expand(&[label], hkdf::HKDF_SHA256)
        .and_then(|okm| okm.fill(&mut out))
        .map_err(|_| "sync: key expansion failed".to_string())?;
    Ok(out)
}

fn expand_root(root: &[u8; 32]) -> Result<SyncKeys, String> {
    Ok(SyncKeys {
        data: subkey(root, DATA_LABEL)?,
        name: subkey(root, NAME_LABEL)?,
    })
}

fn derive_kek(passphrase: &str, salt: &[u8], iterations: u32) -> Result<[u8; 32], String> {
    let iters =
        NonZeroU32::new(iterations).ok_or_else(|| "sync: iteration count is zero".to_string())?;
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

/// Mint a brand new root key and wrap it under `passphrase`.
///
/// Returns both halves because the caller that creates a keyfile also wants to
/// start using it: making it re-open what it just wrote would run PBKDF2 twice
/// for nothing.
///
/// An empty passphrase is refused HERE rather than in a caller, so the
/// guarantee holds no matter which caller reaches this - the same placement
/// `seal_blob` in `src-tauri/src/modules/backup.rs` uses.
pub fn new_keyfile(passphrase: &str) -> Result<(Keyfile, SyncKeys), String> {
    if passphrase.is_empty() {
        return Err("sync: a passphrase is required".into());
    }
    let rng = SystemRandom::new();
    let mut salt = [0u8; SALT_LEN];
    rng.fill(&mut salt)
        .map_err(|_| "sync: random salt failed".to_string())?;
    let mut root = [0u8; 32];
    rng.fill(&mut root)
        .map_err(|_| "sync: random root key failed".to_string())?;

    let kek = derive_kek(passphrase, &salt, PBKDF2_ITERATIONS)?;
    let (nonce, wrapped) = seal_with_key(&kek, &root)?;

    Ok((
        Keyfile {
            v: WIRE_VERSION,
            kdf: KDF_NAME.into(),
            iterations: PBKDF2_ITERATIONS,
            salt: B64.encode(salt),
            nonce: B64.encode(nonce),
            wrapped: B64.encode(&wrapped),
        },
        expand_root(&root)?,
    ))
}

/// Unwrap the root key out of a keyfile and expand it.
///
/// `v` and `kdf` are checked BEFORE anything is derived, and those two
/// failures are the only ones here that name what went wrong: an unreadable
/// keyfile version is a "this device runs an older build" message, not a
/// guessing oracle.
pub fn open_keyfile(kf: &Keyfile, passphrase: &str) -> Result<SyncKeys, String> {
    if kf.v != WIRE_VERSION {
        return Err(format!(
            "sync: unsupported keyfile version {}, expected {WIRE_VERSION}",
            kf.v
        ));
    }
    if kf.kdf != KDF_NAME {
        return Err(format!("sync: unsupported key derivation \"{}\"", kf.kdf));
    }
    let salt = B64.decode(&kf.salt).map_err(|_| OPAQUE_FAILURE)?;
    let wrapped = B64.decode(&kf.wrapped).map_err(|_| OPAQUE_FAILURE)?;
    let nonce = decode_nonce(&kf.nonce)?;

    let kek = derive_kek(passphrase, &salt, kf.iterations)?;
    let root: [u8; 32] = open_with_key(&kek, &nonce, wrapped, PREFIX)?
        .as_slice()
        .try_into()
        .map_err(|_| OPAQUE_FAILURE)?;
    expand_root(&root)
}

fn decode_nonce(encoded: &str) -> Result<[u8; NONCE_LEN], String> {
    B64.decode(encoded)
        .ok()
        .and_then(|b| <[u8; NONCE_LEN]>::try_from(b.as_slice()).ok())
        .ok_or_else(|| OPAQUE_FAILURE.to_string())
}

/// Seal one record's JSON under the data key.
///
/// A FRESH RANDOM NONCE PER CALL, drawn inside
/// `src-tauri/src/modules/aesgcm.rs`. `OneNonce` guarantees one use per key
/// INSTANCE and cannot guarantee this: the same data key seals every record in
/// the inventory, so a constant nonce here would be reuse across the whole
/// inventory rather than within one file.
pub fn seal_record(keys: &SyncKeys, plaintext: &str) -> Result<SealedRecord, String> {
    let (nonce, buf) = seal_with_key(&keys.data, plaintext.as_bytes())?;
    Ok(SealedRecord {
        nonce: B64.encode(nonce),
        ciphertext: B64.encode(&buf),
    })
}

pub fn open_record(keys: &SyncKeys, sealed: SealedRecord) -> Result<String, String> {
    let nonce = decode_nonce(&sealed.nonce)?;
    let buf = B64.decode(&sealed.ciphertext).map_err(|_| OPAQUE_FAILURE)?;
    let plain = open_with_key(&keys.data, &nonce, buf, PREFIX)?;
    String::from_utf8(plain).map_err(|_| OPAQUE_FAILURE.to_string())
}

/// The remote's name for one record: `hex(HMAC-SHA256(name_key, kind:id))`.
///
/// Deterministic, so two devices name the same record the same way without
/// talking; keyed, so the name reveals neither the kind nor the id to whoever
/// can list the storage.
///
/// Hex rather than base64 because the result is a path segment, and base64's
/// alphabet includes `/`. The encoding is one fold, not a dependency.
pub fn object_name(keys: &SyncKeys, kind: &str, id: &str) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, &keys.name);
    let tag = hmac::sign(&key, format!("{kind}:{id}").as_bytes());
    tag.as_ref().iter().fold(String::new(), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One keyfile plus its keys, for tests that do not care about the
    /// passphrase.
    fn fresh() -> (Keyfile, SyncKeys) {
        new_keyfile("correct horse").expect("new keyfile")
    }

    #[test]
    fn the_same_plaintext_seals_differently_every_time() {
        // A constant nonce under one data key would be reuse across the WHOLE
        // inventory, not within one file, which is why this is asserted here
        // and not left to `OneNonce`.
        let (_, keys) = fresh();
        let a = seal_record(&keys, "the same record").unwrap();
        let b = seal_record(&keys, "the same record").unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
        assert_eq!(open_record(&keys, a).unwrap(), "the same record");
        assert_eq!(open_record(&keys, b).unwrap(), "the same record");
    }

    #[test]
    fn the_two_subkeys_differ() {
        // An HKDF label typo collapses them, and every other test in this file
        // still passes. Reach, stated honestly: this also passes for any
        // construction where the two differ, including one that never calls
        // HKDF at all.
        let (_, keys) = fresh();
        assert_ne!(keys.data, keys.name);
    }

    #[test]
    fn each_path_uses_its_own_subkey() {
        // Built by hand with known distinct halves, because swapping the two
        // inside this module passes every other test here unchanged.
        let straight = SyncKeys {
            data: [1u8; 32],
            name: [2u8; 32],
        };
        let swapped = SyncKeys {
            data: [2u8; 32],
            name: [1u8; 32],
        };
        // Only the DATA key is allowed to open a record sealed under it.
        let sealed = seal_record(&straight, "payload").unwrap();
        assert!(open_record(&swapped, sealed).is_err());
        // Only the NAME key is allowed to name an object.
        assert_ne!(
            object_name(&straight, "host", "h-1"),
            object_name(&swapped, "host", "h-1")
        );
    }

    #[test]
    fn a_keyfile_reopened_with_its_passphrase_yields_the_same_keys() {
        // The second-device path: nothing travels but the keyfile and the
        // passphrase, and both halves have to come back identical or a record
        // sealed on one device is unreadable on the other.
        let (kf, first) = fresh();
        let second = open_keyfile(&kf, "correct horse").unwrap();
        let sealed = seal_record(&first, "shared record").unwrap();
        assert_eq!(open_record(&second, sealed).unwrap(), "shared record");
        assert_eq!(
            object_name(&first, "key", "k-1"),
            object_name(&second, "key", "k-1")
        );
    }

    #[test]
    fn a_record_does_not_open_under_a_different_keyfile() {
        let (_, mine) = fresh();
        let (_, theirs) = fresh();
        let sealed = seal_record(&mine, "mine").unwrap();
        assert!(open_record(&theirs, sealed).is_err());
    }

    #[test]
    fn a_wrong_passphrase_and_a_corrupt_keyfile_are_indistinguishable() {
        // `.err()` rather than `.unwrap_err()`, which would need `SyncKeys` to
        // be `Debug` - see the struct for why it deliberately is not.
        let (kf, _) = fresh();
        let wrong = open_keyfile(&kf, "not the passphrase")
            .err()
            .expect("a wrong passphrase must fail");

        let mut corrupt = kf.clone();
        let mut raw = B64.decode(&corrupt.wrapped).unwrap();
        raw[0] ^= 0x01;
        corrupt.wrapped = B64.encode(&raw);
        let tampered = open_keyfile(&corrupt, "correct horse")
            .err()
            .expect("a corrupt keyfile must fail");

        assert_eq!(wrong, tampered, "the two failures are distinguishable");
        // And it says `sync`, not `backup` - the reason the prefix is a
        // parameter rather than a literal shared between the two paths.
        assert!(wrong.starts_with("sync:"), "unexpected error: {wrong}");
        assert!(!wrong.contains("backup"), "unexpected error: {wrong}");
    }

    #[test]
    fn a_keyfile_from_a_build_this_one_does_not_know_is_refused() {
        let (kf, _) = fresh();

        let mut newer = kf.clone();
        newer.v = WIRE_VERSION + 1;
        assert!(open_keyfile(&newer, "correct horse").is_err());

        let mut other_kdf = kf;
        other_kdf.kdf = "argon2id".into();
        assert!(open_keyfile(&other_kdf, "correct horse").is_err());
    }

    #[test]
    fn a_sealed_record_leaks_none_of_its_plaintext() {
        // Needle discipline, as `a_sealed_export_leaks_no_metadata` in
        // `src-tauri/src/modules/backup.rs` established it: every needle is a
        // run of five or more characters drawn ENTIRELY from the base64
        // alphabet. A needle carrying a `.` could only fire if the encoding
        // itself broke, which reads as coverage without being any, and a short
        // run turns up in base64 output by chance.
        let needles = ["vpsalpha", "svcdeploy", "hunter2", "54321"];
        let plain = r#"{"id":"h-1","host":"vpsalpha.example.com","port":54321,"user":"svcdeploy","password":"hunter2"}"#;
        // Negative assertions pass for free when a needle is simply absent, so
        // a dropped field would read as coverage instead of a hole.
        for needle in needles {
            assert!(
                plain.contains(needle),
                "{needle} is missing from the fixture"
            );
        }

        let (_, keys) = fresh();
        let sealed = seal_record(&keys, plain).unwrap();
        // Collected rather than asserted one at a time, so a leak names every
        // needle it exposed instead of stopping at the first.
        let leaked: Vec<&str> = needles
            .into_iter()
            .filter(|n| sealed.ciphertext.contains(n) || sealed.nonce.contains(n))
            .collect();
        assert!(
            leaked.is_empty(),
            "readable in the sealed record: {leaked:?}"
        );
        assert_eq!(open_record(&keys, sealed).unwrap(), plain);
    }

    #[test]
    fn an_object_name_hides_what_it_was_built_from() {
        let (_, keys) = fresh();
        let name = object_name(&keys, "identity", "i-deadbeef");
        assert!(!name.contains("identity"), "the kind leaked into {name}");
        assert!(!name.contains("i-deadbeef"), "the id leaked into {name}");
        // Deterministic, or two devices would file one record twice.
        assert_eq!(name, object_name(&keys, "identity", "i-deadbeef"));
        // And keyed, or the storage's listing would be the same for everybody.
        let (_, other) = fresh();
        assert_ne!(name, object_name(&other, "identity", "i-deadbeef"));
    }

    #[test]
    fn an_empty_passphrase_is_refused() {
        assert!(new_keyfile("").is_err());
    }
}
