// What this form is allowed to tell the user about where a secret goes.
//
// One string in one place because three copies of this sentence had drifted into
// naming a keychain on the two platforms that do not have one. What `secrets.rs`
// actually does:
//
// - macOS: the Keychain, through the `keyring` crate.
// - Windows: a DPAPI-encrypted file in the app's local data dir. The Credential
//   Manager was dropped because its CredentialBlob caps at 2560 bytes, which
//   truncated RSA private key bodies.
// - Linux: `serde_json::to_vec` and an atomic write at mode 0600. Plaintext on
//   disk, no keyring, no encryption - the Secret Service backend fails silently
//   on a box with no gnome-keyring or kwallet, and an AppImage cannot assume one.
//
// The sentence says WHERE the value goes, and never how well it is protected.
// That is the rule rather than a stylistic preference: a user who believes their
// private key is encrypted at rest on Linux makes different decisions about what
// they paste into this form, and nothing here makes a secret safer than it was.

/**
 * Where a secret written from this editor actually ends up, per platform.
 *
 * Reads as the parenthetical or the tail of a sentence, so a caller supplies its
 * own subject ("The password is stored outside Tervia's settings file: …").
 */
export const SECRET_STORE_LOCATIONS =
  "the macOS Keychain, a DPAPI-encrypted file on Windows, a mode-0600 plaintext file on Linux";
