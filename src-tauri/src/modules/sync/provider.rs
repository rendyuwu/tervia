//! The boundary between what sync MEANS and where the bytes go.
//!
//! A provider sees keys and bytes. It knows nothing about hosts, vaults,
//! forwards, envelopes or the object layout - the layer above composes the key
//! it receives. That is what lets a second backend land as one file and one
//! line without touching anything in `src-tauri/src/modules/sync/model.rs` or
//! `src-tauri/src/modules/sync/crypto.rs`.
//!
//! NOTHING HERE OPENS A SOCKET. The trait is a shape; the one implementation
//! behind it lives in `src-tauri/src/modules/sync/providers/s3.rs`.
//!
//! WHY THE FUTURES ARE BOXED BY HAND. `Arc<dyn SyncProvider>` needs the trait
//! to be dyn-compatible, and a native `async fn` in a trait is not. The usual
//! answer is a proc macro that generates exactly the signatures written out
//! below. It is not taken here: its only route into this tree is through two
//! plugins that declare it for the BSD-family and Linux targets only, so
//! promoting it would newly compile it on half the bundle matrix. Four
//! hand-written signatures cost four lines, no manifest edit and no lockfile
//! change.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde_json::Value;

/// What a backend can do that the layer above has to branch on.
///
/// One field today, and a struct rather than a bare `bool` so the second
/// capability is an added field rather than a changed signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    /// Whether a conditional write is honoured, so the caller may use
    /// compare-and-swap instead of last-write-wins.
    ///
    /// A STORED USER TOGGLE, not a probe. Probing would mean writing a
    /// throwaway object into the user's bucket during setup, and a rejection
    /// can come back for reasons other than the one being probed. Set wrong it
    /// degrades to last-write-wins, which is the normal path for backends that
    /// have no conditional write at all; it does not lose data.
    pub cas: bool,
}

/// One object's bytes and the etag the remote gave them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Object {
    pub bytes: Vec<u8>,
    pub etag: String,
}

/// One row of a listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub key: String,
    pub etag: String,
    /// Unix MILLISECONDS, matching `Envelope::updated_at` in
    /// `src-tauri/src/modules/sync/model.rs`.
    ///
    /// The wire format it is parsed from is seconds-with-a-fraction, so the
    /// conversion is arithmetic and not a cast. Getting that wrong puts every
    /// remote stamp a thousandfold below every local one, and `ordering_key`
    /// in that same module reads a smaller stamp as "the remote is older" -
    /// so the remote would lose every merge it took part in, silently.
    ///
    /// `None` when the remote gave none, which orders below any stamp.
    pub modified_at: Option<u64>,
}

/// Why a provider call failed.
///
/// A typed enum rather than a `String`, for the reason `MergeError` in
/// `src-tauri/src/modules/sync/model.rs` already gives: the caller has to tell
/// dispositions apart, and string-matching for that gets decided once every
/// call site is already written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderError {
    /// The conditional write was rejected because the etag did not match.
    /// Pull, merge, retry. Never shown to the user.
    ///
    /// DISTINGUISHABLE FROM A NETWORK FAILURE BY CONSTRUCTION, which matters
    /// because a caller that mistook one for the other would either spin or
    /// discard an edit. `Transport` is produced only by `transport_error` and
    /// this variant only by `classify`, and `classify` never sees a transport
    /// failure because a transport failure has no status to classify.
    PreconditionFailed,
    /// A conflicting operation landed during the upload. Nothing is yet known
    /// about the remote state: re-read the etag and retry. NOT the same
    /// disposition as [`ProviderError::PreconditionFailed`], which already
    /// tells the caller its copy is stale.
    Conflict,
    /// A conditional write named a key that is gone, reached by racing a
    /// delete.
    ///
    /// NOT what a get on a missing key produces - that is `Ok(None)`. The
    /// asymmetry is deliberate and is documented at both sites: a missing key
    /// is the ordinary answer when reading and an anomaly when writing
    /// conditionally.
    NotFound,
    /// The SSRF guard, an unsupported scheme, or a redirect that was refused
    /// rather than followed.
    Blocked(String),
    /// A response the provider understood as a failure but has no specific
    /// disposition for. `code` is the remote's own error code when the body
    /// carried one.
    Remote { status: u16, code: Option<String> },
    /// The request never completed: a timeout, a refused connection, a broken
    /// stream.
    Transport(String),
    /// A response body that did not decode or did not parse.
    Malformed(String),
    /// Well-formed data that violates the protocol contract - today, a
    /// continuation token identical to the one that produced the page, which
    /// is a listing that never terminates.
    ///
    /// Distinct from [`ProviderError::Malformed`] because the body decoded and
    /// parsed fine, so "the server is broken" and "the bytes are corrupt" stay
    /// separable.
    Protocol(String),
    /// Not a response at all: an unknown provider id, or a configuration that
    /// will not deserialize or does not name a usable endpoint. Produced while
    /// building a provider or a request, never by a response mapper.
    Config(String),
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PreconditionFailed => write!(f, "sync: the remote copy changed first"),
            Self::Conflict => write!(f, "sync: a conflicting write landed during the upload"),
            Self::NotFound => write!(f, "sync: the object named by the condition is gone"),
            Self::Blocked(why) => write!(f, "sync: {why}"),
            Self::Remote { status, code } => match code {
                Some(code) => write!(f, "sync: the remote answered {status} ({code})"),
                None => write!(f, "sync: the remote answered {status}"),
            },
            Self::Transport(why) => write!(f, "sync: {why}"),
            Self::Malformed(why) => write!(f, "sync: {why}"),
            Self::Protocol(why) => write!(f, "sync: {why}"),
            Self::Config(why) => write!(f, "sync: {why}"),
        }
    }
}

/// Five verbs over keys and bytes. Everything a backend has to supply.
///
/// NO METHOD YIELDS A `'static` FUTURE, which constrains the scheduler that
/// will drive this: it cannot hand `provider.get(&key)` straight to a task
/// spawner, and has to move the `Arc` and an owned key into the async block
/// instead. Recorded here so that is discovered by reading rather than by a
/// compiler error. The proc macro this file declines generates the same bound,
/// so it is not a cost of writing the signatures out.
pub trait SyncProvider: Send + Sync {
    /// A stable id, matching the one [`build`] dispatches on.
    fn id(&self) -> &'static str;

    fn capabilities(&self) -> Caps;

    /// The object at `key`, or `Ok(None)` when there is none.
    ///
    /// A MISSING KEY IS NOT AN ERROR HERE. Callers read a key that may legally
    /// not exist yet - the keyfile on a fresh remote, an object another device
    /// has not pushed - so folding that into the error path would make every
    /// call site unwrap the ordinary case out of a failure.
    fn get<'a>(
        &'a self,
        key: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Object>, ProviderError>> + Send + 'a>>;

    /// Store `bytes` at `key` and answer with the new etag.
    ///
    /// `if_match` asks for a conditional write. It is HONOURED ONLY WHEN
    /// [`Caps::cas`] is set, so a caller may pass it unconditionally and a
    /// backend that cannot do it degrades to last-write-wins rather than
    /// failing.
    ///
    /// A missing key IS an error here - see [`ProviderError::NotFound`] - and
    /// that asymmetry with `get` is deliberate.
    fn put<'a>(
        &'a self,
        key: &'a str,
        bytes: Vec<u8>,
        if_match: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = Result<String, ProviderError>> + Send + 'a>>;

    /// Every object under `prefix`, following pagination to the end.
    fn list<'a>(
        &'a self,
        prefix: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Entry>, ProviderError>> + Send + 'a>>;

    /// Remove `key`. Removing something that is already gone is not an error.
    ///
    /// NO CONDITIONAL ARGUMENT. Conditional delete is not reliably implemented
    /// across the self-hosted servers this has to work against, and nothing on
    /// the calling path needs it.
    fn delete<'a>(
        &'a self,
        key: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
}

/// The provider named by `id`, configured from `cfg`.
///
/// A BARE MATCH AND NOT A REGISTRY TYPE. An id-to-constructor map would be a
/// table with one row, and a config enum with one variant per backend would be
/// that same table wearing a different hat - the next backend would then edit a
/// shared type instead of adding a line here. A `serde_json::Value` keeps the
/// "one file plus one line" property literally true.
///
/// THE PRICE OF THAT SEAM, stated rather than hidden: a config-shape mismatch
/// moves from compile time to run time. The caller sends this from the
/// frontend, so each config struct carries camelCase field names and refuses
/// unknown fields, which turns a renamed or misspelled field into a loud error
/// at the first call rather than a silently defaulted one.
///
/// NO CALLER YET, by design. The command that selects a provider arrives with
/// the path that uses it; this exists so that command never has to learn
/// provider ids.
pub fn build(id: &str, cfg: Value) -> Result<Arc<dyn SyncProvider>, ProviderError> {
    match id {
        "s3" => {
            let cfg = serde_json::from_value(cfg).map_err(|e| {
                ProviderError::Config(format!("the s3 configuration is not usable: {e}"))
            })?;
            Ok(Arc::new(super::providers::s3::S3Provider::new(cfg)?))
        }
        other => Err(ProviderError::Config(format!(
            "unknown sync provider \"{other}\""
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn s3_config() -> Value {
        json!({
            "endpoint": "https://storage.example",
            "region": "us-east-1",
            "bucket": "tervia",
            "cas": true,
            "accessKeyId": "test-access-key",
            "secretAccessKey": "test-secret",
        })
    }

    #[test]
    fn a_known_id_with_a_good_config_builds_something_behind_the_trait() {
        let provider = build("s3", s3_config()).expect("s3 builds");
        assert_eq!(provider.id(), "s3");
        assert!(provider.capabilities().cas);
    }

    #[test]
    fn an_unknown_id_is_a_config_error_and_names_the_id() {
        // `.err()` rather than `.unwrap_err()`, which would need the trait
        // object to be `Debug` - the same shape the crypto tests use for
        // `SyncKeys`, and for the same reason: nothing behind this port needs a
        // derived formatter and one would print a configuration.
        let err = build("dropbox", json!({}))
            .err()
            .expect("an unknown id must fail");
        assert!(
            matches!(&err, ProviderError::Config(m) if m.contains("dropbox")),
            "unexpected: {err:?}"
        );
    }

    #[test]
    fn a_config_that_will_not_deserialize_is_a_config_error() {
        // A missing field, a field of the wrong type, and - the one the seam
        // exists to catch - a camelCase name misspelled. Without the refusal
        // of unknown fields the last of these would deserialize by DEFAULTING
        // the real field, and the provider would sign every request with an
        // empty access key.
        let mut missing = s3_config();
        missing.as_object_mut().unwrap().remove("bucket");

        let mut wrong_type = s3_config();
        wrong_type["cas"] = json!("yes");

        let mut misspelled = s3_config();
        let obj = misspelled.as_object_mut().unwrap();
        let secret = obj.remove("secretAccessKey").unwrap();
        obj.insert("secretAccesKey".into(), secret);

        for cfg in [missing, wrong_type, misspelled] {
            let err = build("s3", cfg.clone())
                .err()
                .unwrap_or_else(|| panic!("{cfg} must be refused"));
            assert!(
                matches!(err, ProviderError::Config(_)),
                "{cfg} gave {err:?}"
            );
        }
    }

    #[test]
    fn an_endpoint_that_is_not_a_usable_url_is_refused_at_build_time() {
        // Refused HERE rather than at the first request, so a provider that
        // exists is a provider that can sign. The scheme check is part of it:
        // a file URL would parse and then be signed as though it had a host.
        for endpoint in ["not a url", "ftp://storage.example", "https://"] {
            let mut cfg = s3_config();
            cfg["endpoint"] = json!(endpoint);
            let err = build("s3", cfg)
                .err()
                .unwrap_or_else(|| panic!("{endpoint} must be refused"));
            assert!(
                matches!(err, ProviderError::Config(_)),
                "{endpoint} gave {err:?}"
            );
        }
    }

    #[test]
    fn the_error_type_tells_a_stale_etag_from_a_network_failure() {
        // The two a caller must never confuse: one means "pull, merge, retry",
        // the other means "the request did not happen". They are different
        // variants, so no string comparison decides it.
        assert_ne!(
            ProviderError::PreconditionFailed,
            ProviderError::Transport("connection reset".into())
        );
        assert_ne!(ProviderError::PreconditionFailed, ProviderError::Conflict);
        assert_ne!(ProviderError::NotFound, ProviderError::Conflict);
    }

    #[test]
    fn every_variant_says_sync_and_none_of_them_is_empty() {
        // A message that does not name the subsystem is one a user reads
        // without knowing which part of the app produced it, and an empty one
        // is worse. Every variant, so a new one cannot be added without a
        // sentence.
        for err in [
            ProviderError::PreconditionFailed,
            ProviderError::Conflict,
            ProviderError::NotFound,
            ProviderError::Blocked("blocked: link-local address".into()),
            ProviderError::Remote {
                status: 500,
                code: Some("InternalError".into()),
            },
            ProviderError::Remote {
                status: 503,
                code: None,
            },
            ProviderError::Transport("timed out".into()),
            ProviderError::Malformed("the listing did not decode".into()),
            ProviderError::Protocol("the listing never terminates".into()),
            ProviderError::Config("unknown sync provider".into()),
        ] {
            let text = err.to_string();
            assert!(text.starts_with("sync: "), "{err:?} said {text}");
            assert!(text.len() > "sync: ".len(), "{err:?} said {text}");
        }
    }
}
