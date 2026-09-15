//! AES-256-GCM under a key the caller already holds.
//!
//! A LEAF on purpose, rather than a pair of functions inside
//! `src-tauri/src/modules/backup.rs` where they started. That module imports
//! `tauri::AppHandle` and the keychain out of
//! `src-tauri/src/modules/secrets.rs`, so it is a command module, not a crypto
//! primitive. `src-tauri/src/modules/sync/crypto.rs` needs the same sealing
//! and must not inherit either dependency, so the shared half sits BELOW both
//! instead of inside one of them. The diff is the same either way - the code
//! moves - and this direction also leaves the backup path independently
//! compilable.
//!
//! What stays out here: key derivation. The backup path derives its key from
//! a user passphrase with PBKDF2, the sync path unwraps a random root key and
//! expands it with HKDF, and neither belongs to the other. This module takes
//! the 32 bytes and nothing else.
//!
//! Named `aesgcm` rather than `aead` because
//! `src-tauri/src/modules/sync/crypto.rs` also imports `ring::aead`, and two
//! things called `aead` one `use` line apart is an hour nobody needs to spend.

use ring::{
    aead::{self, BoundKey, Nonce, NonceSequence, UnboundKey, AES_256_GCM, NONCE_LEN},
    error::Unspecified,
    rand::{SecureRandom, SystemRandom},
};

/// `ring`'s sealing API consumes a nonce sequence; we seal exactly one message
/// per key INSTANCE, so the sequence yields our single random nonce and then
/// refuses. Refusing matters: reusing a nonce under the same key breaks GCM
/// completely.
///
/// Note the scope of that guarantee - one use per instance, not one use per
/// key. A caller that seals many messages under one long-lived key is
/// responsible for a fresh nonce per message; this type cannot see across its
/// own construction.
pub(crate) struct OneNonce(Option<[u8; NONCE_LEN]>);

impl NonceSequence for OneNonce {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        self.0
            .take()
            .map(Nonce::assume_unique_for_key)
            .ok_or(Unspecified)
    }
}

/// Seal `plaintext` under `key` with a freshly drawn random nonce. Returns the
/// nonce and `ciphertext || tag`; the caller stores both.
///
/// The nonce is drawn HERE rather than taken as a parameter so no caller can
/// supply a constant one, which is the single mistake that turns AES-GCM into
/// a stream cipher with a published keystream.
///
/// Failures here are unreachable in practice - a dead system RNG, or a key
/// that is not 32 bytes, which the signature already prevents - so they carry
/// no caller prefix: there is nothing for a user to tell apart.
pub(crate) fn seal_with_key(
    key: &[u8; 32],
    plaintext: &[u8],
) -> Result<([u8; NONCE_LEN], Vec<u8>), String> {
    let mut nonce = [0u8; NONCE_LEN];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| "aes-gcm: random nonce failed".to_string())?;

    let unbound = UnboundKey::new(&AES_256_GCM, key).map_err(|_| "aes-gcm: bad key".to_string())?;
    let mut sealing = aead::SealingKey::new(unbound, OneNonce(Some(nonce)));

    // seal_in_place_append_tag appends the 16-byte auth tag, so `buf` ends up
    // as ciphertext||tag - which is exactly what open_in_place expects back.
    let mut buf = plaintext.to_vec();
    sealing
        .seal_in_place_append_tag(aead::Aad::empty(), &mut buf)
        .map_err(|_| "aes-gcm: encryption failed".to_string())?;
    Ok((nonce, buf))
}

/// Open what [`seal_with_key`] produced. `buf` is `ciphertext || tag`.
///
/// Every authenticated failure - wrong key, tampered ciphertext, truncated
/// input - is reported with ONE message on purpose: distinguishing them tells
/// an attacker which guess was closer, and none of them is separately
/// actionable for the user.
///
/// `prefix` is why that message is a parameter rather than a shared literal.
/// Indistinguishability is required WITHIN one path; sharing wording across
/// paths is not, and a shared literal would answer a wrong sync passphrase
/// with a sentence about a backup file.
pub(crate) fn open_with_key(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    mut buf: Vec<u8>,
    prefix: &str,
) -> Result<Vec<u8>, String> {
    let unbound = UnboundKey::new(&AES_256_GCM, key).map_err(|_| format!("{prefix}: bad key"))?;
    let mut opening = aead::OpeningKey::new(unbound, OneNonce(Some(*nonce)));
    let plain = opening
        .open_in_place(aead::Aad::empty(), &mut buf)
        .map_err(|_| format!("{prefix}: wrong passphrase, or the file is corrupt"))?;
    Ok(plain.to_vec())
}
