//! The S3 provider: Amazon S3 and the S3-compatible servers people self-host.
//!
//! SPLIT PURE FROM IMPURE, and that split is the spine of this file rather than
//! a tidiness preference. This crate has no `[dev-dependencies]` and therefore
//! no HTTP mock, so a behaviour that lives in an async method body cannot be
//! tested at all. Everything that decides anything - which URL, which headers,
//! which error, which page - is a plain function taking values and returning
//! values. What is left is four method bodies that call a builder, send, and
//! hand the result to a mapper.
//!
//! Four things sit on the pure side that would otherwise hide in the shell:
//!
//! - [`transport_error`], the only producer of `ProviderError::Transport`, so
//!   the error taxonomy is reachable from a test without a network.
//! - [`classify_get`] and [`classify_put`] rather than one classifier: a
//!   function returning an error can never express "a missing key is the
//!   ordinary answer", so `get`'s 404 branch would have landed in the shell,
//!   which is the exact placement this split exists to prevent.
//! - [`accumulate`], which holds the append-and-continue decision for `list`
//!   including the case a server that repeats a continuation token forever
//!   falls into.
//! - the body decode. `reqwest` is built here without its `charset` feature, so
//!   `Response::text` takes its lossy branch and a non-UTF-8 body silently
//!   becomes replacement characters instead of failing. Every body is read as
//!   bytes and stays bytes; [`parse_list`] decodes strictly, and [`classify`]
//!   decodes lossily only in the one arm that reads an error code - so a
//!   successful fetch of a sealed envelope never allocates a mangled second
//!   copy of it.
//!
//! REDIRECTS ARE REFUSED, NOT RE-GUARDED. `ssrf_redirect_policy` in
//! `src-tauri/src/modules/net.rs` exists because `reqwest` follows 3xx by
//! default, and for a SIGNED request following one is worse than an SSRF risk:
//! `host` is part of the canonical request, so a redirect to another host
//! guarantees a signature rejection that reads exactly like a bad secret key -
//! the failure mode the vectors in
//! `src-tauri/src/modules/sync/providers/sigv4.rs` exist to prevent. The client
//! here is built to follow none at all, which is strictly stronger, and a
//! region redirect is surfaced as a refusal naming the status.
//!
//! NO `Content-Type` IS SENT, on any verb including `put`. A typeless object
//! defaults to a binary media type, which is what a sealed envelope is, and
//! nothing on the sync path ever reads a content type back. A PRESENT
//! `Content-Type` must be signed, so sending one would add a fourth signed
//! header and a fourth way to get the canonical request wrong, for no reader.
//! The signer handles a signed content type regardless - one of its vectors
//! carries one - so this is a decision about what is sent, not a gap in what
//! can be signed.

use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, SystemTime};

use serde::Deserialize;

use super::sigv4;
use crate::modules::sync::provider::{Caps, Entry, Object, ProviderError, SyncProvider};

/// The service name that goes into the credential scope. Fixed by the
/// protocol, not by the vendor: every S3-compatible server signs under it.
const SERVICE: &str = "s3";

/// Generous next to the five seconds `client` in
/// `src-tauri/src/modules/net.rs` gives the preview pill, because that one is
/// tuned for a reachability ping and this one carries an object body over
/// whatever link the user's remote is on.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Everything the provider needs, and nothing it can supply for the user.
///
/// FOUR PROPERTIES, EACH DELIBERATE:
///
/// - NO `Default` IMPL. Every field is required at construction, so there is no
///   code path that can supply an endpoint or a bucket the user did not type.
///   That makes a shipped default unrepresentable rather than merely
///   un-grepped, which is what the source-text test below is a backstop over
///   and not a substitute for.
/// - NO DERIVED `Debug`. A reflexive one puts `secret_access_key` into any log
///   line or panic message that formats the config. The same reason `SyncKeys`
///   in `src-tauri/src/modules/sync/crypto.rs` has none.
/// - CAMELCASE FIELD NAMES AND NO UNKNOWN FIELDS. This arrives as JSON from the
///   frontend, so the wire names are camelCase, and a renamed or misspelled
///   field is a loud error at the first call rather than a silently defaulted
///   one.
/// - NO `prefix` FIELD. The object layout belongs to the sync layer above the
///   provider, which composes the key a provider receives.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct S3Config {
    /// Typed by the user. Scheme and host, optionally a port and a base path
    /// for a server behind a reverse proxy.
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    /// Whether this endpoint honours a conditional write. A user toggle, not a
    /// probe - see `Caps` in `src-tauri/src/modules/sync/provider.rs`.
    pub cas: bool,
    pub access_key_id: String,
    pub secret_access_key: String,
}

/// A request the shell only has to send: nothing left to decide.
#[derive(Clone, PartialEq, Eq)]
pub struct SignedRequest {
    pub method: &'static str,
    pub url: String,
    /// In a fixed order: the three signed headers, the authorization, then any
    /// unsigned extras. Fixed so a test can assert the whole map.
    pub headers: Vec<(String, String)>,
}

/// HAND-WRITTEN AND REDACTING, for the same reason [`S3Config`] derives none.
/// The `Authorization` value carries the access key id and the request's
/// signature, and a derived formatter would put both into whatever log line or
/// assertion message ever formats a request. Written rather than omitted
/// because `assert_eq!` needs one, and an assertion that cannot print its two
/// sides is worse than a redacted one.
impl std::fmt::Debug for SignedRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let headers: Vec<(&str, &str)> = self
            .headers
            .iter()
            .map(|(n, v)| {
                let shown = if n == "authorization" {
                    "<redacted>"
                } else {
                    v.as_str()
                };
                (n.as_str(), shown)
            })
            .collect();
        f.debug_struct("SignedRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &headers)
            .finish()
    }
}

/// The endpoint, taken apart once.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Endpoint {
    /// Scheme and authority, no trailing slash.
    base: String,
    /// The `host` header value, carrying a port only when it is not the
    /// scheme's default - which is exactly when the canonical request must
    /// carry one too.
    host: String,
    /// A base path for a server mounted under one, `""` otherwise. Part of
    /// every signed path.
    prefix: String,
}

/// Take the endpoint apart, or say why it cannot be used.
///
/// Refused HERE and at construction rather than at the first request, so a
/// provider that exists is a provider that can sign. The scheme check is part
/// of that: several URL spellings parse happily and then have no host to put in
/// the canonical request.
fn endpoint(cfg: &S3Config) -> Result<Endpoint, ProviderError> {
    let bad = |why: String| ProviderError::Config(why);
    let parsed = url::Url::parse(cfg.endpoint.trim())
        .map_err(|e| bad(format!("the sync endpoint is not a url: {e}")))?;
    match parsed.scheme() {
        "http" | "https" => {}
        other => return Err(bad(format!("unsupported sync endpoint scheme \"{other}\""))),
    }
    let host = parsed
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| bad("the sync endpoint names no host".to_string()))?;
    let host = match parsed.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    let prefix = parsed.path().trim_end_matches('/').to_string();
    // A base path the url parser already had to escape would be escaped a
    // SECOND time on the way into the signed path, since the percent itself is
    // not an unreserved character. Signed and sent would still agree, so there
    // is no rejected signature to notice - the request would simply address a
    // path nobody has. Refused rather than repaired, because the repair is a
    // guess at what the user meant.
    if prefix.contains('%') {
        return Err(bad(format!(
            "the sync endpoint's path must be plain, and \"{prefix}\" is escaped"
        )));
    }
    Ok(Endpoint {
        base: format!("{}://{host}", parsed.scheme()),
        host,
        prefix,
    })
}

/// Every path this provider signs, refusing the one shape that cannot survive
/// the trip.
///
/// THE SIGNED PATH AND THE SENT PATH HAVE TO BE THE SAME STRING. The canonical
/// request takes the path verbatim - the signer deliberately does not
/// normalize, because the service does not either - but the URL is reparsed by
/// the http client under the WHATWG rules, and those REMOVE a `.` or `..`
/// segment. A key carrying one would therefore be signed as written and sent
/// collapsed, and the answer is a rejected signature: the one failure that
/// reads exactly like a wrong secret key.
///
/// Refusing is the only option that leaves no gap. Encoding does not help - the
/// same rules decode a percent-escaped dot before collapsing it - and
/// normalizing here would sign a path the caller did not ask for.
fn checked_path(path: String) -> Result<String, ProviderError> {
    if path
        .split('/')
        .any(|segment| segment == "." || segment == "..")
    {
        return Err(ProviderError::Config(format!(
            "a sync path may not carry a \".\" or \"..\" segment, and \"{path}\" does"
        )));
    }
    Ok(path)
}

/// One request's worth of signing context.
///
/// A struct because the four builders otherwise pass the same five values
/// positionally, and a mix-up between `region` and the service name would
/// compile and then fail as a rejected signature.
struct Signing<'a> {
    cfg: &'a S3Config,
    endpoint: Endpoint,
    now: SystemTime,
}

impl<'a> Signing<'a> {
    fn new(cfg: &'a S3Config, now: SystemTime) -> Result<Self, ProviderError> {
        Ok(Self {
            endpoint: endpoint(cfg)?,
            cfg,
            now,
        })
    }

    /// The path of one object, unencoded. Exactly one separator between each
    /// part, whatever trailing slashes the endpoint carried.
    fn path(&self, key: &str) -> Result<String, ProviderError> {
        checked_path(format!(
            "{}/{}/{key}",
            self.endpoint.prefix, self.cfg.bucket
        ))
    }

    /// The path of the bucket itself, which is what a listing addresses.
    fn bucket_path(&self) -> Result<String, ProviderError> {
        checked_path(format!("{}/{}", self.endpoint.prefix, self.cfg.bucket))
    }

    /// Sign one request.
    ///
    /// `extra` headers are sent but NOT signed, which is deliberate for the one
    /// caller that uses it: signing the condition would make an unconditional
    /// and a suppressed-conditional put differ in their signature, and the
    /// service requires only the host and the `x-amz-*` headers to be signed
    /// anyway.
    fn sign(
        &self,
        method: &'static str,
        path: &str,
        query: &[(&str, &str)],
        payload_hash: &str,
        extra: &[(&str, &str)],
    ) -> SignedRequest {
        let (amz_date, date) = sigv4::amz_date(self.now);
        let canonical_query = sigv4::canonical_query(query);

        // The three S3 signs on EVERY verb. The suite's generic-service vectors
        // sign only two of them, which is why a signer that reproduces those
        // can still be rejected on every real request.
        let signed: [(&str, &str); 3] = [
            ("host", &self.endpoint.host),
            ("x-amz-content-sha256", payload_hash),
            ("x-amz-date", &amz_date),
        ];
        let canonical =
            sigv4::canonical_request(method, path, &canonical_query, &signed, payload_hash);
        let scope = sigv4::SigningScope {
            access_key_id: &self.cfg.access_key_id,
            secret_access_key: &self.cfg.secret_access_key,
            date: &date,
            region: &self.cfg.region,
            service: SERVICE,
        };
        let authorization = sigv4::authorization_header(
            &scope,
            &amz_date,
            &sigv4::signed_headers(&signed),
            &canonical,
        );

        let mut headers: Vec<(String, String)> = signed
            .iter()
            .map(|(n, v)| ((*n).to_string(), (*v).to_string()))
            .collect();
        headers.push(("authorization".to_string(), authorization));
        headers.extend(extra.iter().map(|(n, v)| (n.to_string(), v.to_string())));

        let encoded = sigv4::uri_encode(path, false);
        let url = if canonical_query.is_empty() {
            format!("{}{encoded}", self.endpoint.base)
        } else {
            format!("{}{encoded}?{canonical_query}", self.endpoint.base)
        };
        SignedRequest {
            method,
            url,
            headers,
        }
    }
}

/// Where one object lives, as a URL.
///
/// Path style, which is the addressing every S3-compatible server supports;
/// virtual-host style would put the bucket in the hostname and require a
/// wildcard certificate the self-hosted case rarely has.
pub fn object_url(cfg: &S3Config, key: &str) -> Result<String, ProviderError> {
    let signing = Signing::new(cfg, SystemTime::UNIX_EPOCH)?;
    Ok(format!(
        "{}{}",
        signing.endpoint.base,
        sigv4::uri_encode(&signing.path(key)?, false)
    ))
}

pub fn build_get(
    cfg: &S3Config,
    key: &str,
    now: SystemTime,
) -> Result<SignedRequest, ProviderError> {
    let signing = Signing::new(cfg, now)?;
    Ok(signing.sign(
        "GET",
        &signing.path(key)?,
        &[],
        sigv4::EMPTY_PAYLOAD_SHA256,
        &[],
    ))
}

pub fn build_delete(
    cfg: &S3Config,
    key: &str,
    now: SystemTime,
) -> Result<SignedRequest, ProviderError> {
    let signing = Signing::new(cfg, now)?;
    Ok(signing.sign(
        "DELETE",
        &signing.path(key)?,
        &[],
        sigv4::EMPTY_PAYLOAD_SHA256,
        &[],
    ))
}

/// Which etag, if any, actually rides as a condition.
///
/// ONE DEFINITION, TWO READERS: the builder that attaches the header and the
/// shell that has to tell the response mapper what was sent. Two spellings of
/// the same predicate would have to stay in step, and the symptom of their
/// drifting is a 404 read as the wrong disposition.
fn condition<'a>(cfg: &S3Config, if_match: Option<&'a str>) -> Option<&'a str> {
    if_match.filter(|_| cfg.cas)
}

/// A put, conditional only when the user said this endpoint can do it.
///
/// THE TOGGLE GATES THE CONDITION HERE rather than at the call site, so a
/// caller may pass `if_match` unconditionally and an endpoint that cannot
/// honour it degrades to last-write-wins instead of failing. Setting the toggle
/// wrong therefore costs a weaker guarantee, never a lost record.
pub fn build_put(
    cfg: &S3Config,
    key: &str,
    bytes: &[u8],
    if_match: Option<&str>,
    now: SystemTime,
) -> Result<SignedRequest, ProviderError> {
    let signing = Signing::new(cfg, now)?;
    let payload_hash = sigv4::sha256_hex(bytes);
    let extra: Vec<(&str, &str)> = match condition(cfg, if_match) {
        Some(etag) => vec![("if-match", etag)],
        None => Vec::new(),
    };
    Ok(signing.sign("PUT", &signing.path(key)?, &[], &payload_hash, &extra))
}

pub fn build_list(
    cfg: &S3Config,
    prefix: &str,
    continuation: Option<&str>,
    now: SystemTime,
) -> Result<SignedRequest, ProviderError> {
    let signing = Signing::new(cfg, now)?;
    let mut query: Vec<(&str, &str)> = vec![("list-type", "2"), ("prefix", prefix)];
    if let Some(token) = continuation {
        query.push(("continuation-token", token));
    }
    Ok(signing.sign(
        "GET",
        &signing.bucket_path()?,
        &query,
        sigv4::EMPTY_PAYLOAD_SHA256,
        &[],
    ))
}

// --- response mapping -----------------------------------------------------

/// The shared base: a status the caller has already decided is a failure,
/// turned into a disposition.
///
/// Three statuses get their own answer. A stale-etag rejection and a
/// mid-upload conflict are NOT the same thing - after the first the caller
/// knows its copy is stale, after the second it knows nothing at all - and a
/// redirect is refused rather than followed, so the 3xx that a region mismatch
/// produces is surfaced as a refusal rather than chased into a signature
/// rejection.
///
/// TAKES BYTES AND DECODES ONLY WHERE IT HAS TO, which is the last arm. A
/// sealed envelope is not text, and a lossy decode of one allocates a second
/// full copy of the object on a path that never reads it.
pub fn classify(status: u16, body: &[u8]) -> ProviderError {
    match status {
        412 => ProviderError::PreconditionFailed,
        409 => ProviderError::Conflict,
        300..=399 => ProviderError::Blocked(format!(
            "blocked: the remote answered {status}, which this client neither follows nor reads"
        )),
        _ => ProviderError::Remote {
            status,
            code: error_code(&String::from_utf8_lossy(body)),
        },
    }
}

/// A get's outcome. `Ok(None)` means the key is simply not there.
pub fn classify_get(status: u16, body: &[u8]) -> Result<Option<()>, ProviderError> {
    match status {
        200..=299 => Ok(Some(())),
        404 => Ok(None),
        _ => Err(classify(status, body)),
    }
}

/// A put's outcome.
///
/// `conditional` is needed because a status alone cannot tell a conditional put
/// from an unconditional one, and a missing key means something different in
/// each: under a condition it is a key that was deleted from under the caller,
/// and without one it is an ordinary remote failure.
pub fn classify_put(status: u16, body: &[u8], conditional: bool) -> Result<(), ProviderError> {
    match status {
        200..=299 => Ok(()),
        404 if conditional => Err(ProviderError::NotFound),
        _ => Err(classify(status, body)),
    }
}

/// The three failure shapes a request can have before it ever gets a status.
///
/// Pure, taking the booleans rather than the error, because this is the ONLY
/// producer of `ProviderError::Transport` and one of the producers of
/// `ProviderError::Blocked`: leaving it in the shell left the whole taxonomy
/// untestable.
pub fn transport_error(
    is_redirect: bool,
    is_timeout: bool,
    is_connect: bool,
    message: String,
) -> ProviderError {
    if is_redirect {
        // Not a transport failure: the client was told to go somewhere else
        // and refused, which is the guard working.
        return ProviderError::Blocked(format!("blocked: a redirect was refused ({message})"));
    }
    if is_timeout {
        return ProviderError::Transport(format!("the remote did not answer in time ({message})"));
    }
    if is_connect {
        return ProviderError::Transport(format!("the remote could not be reached ({message})"));
    }
    ProviderError::Transport(message)
}

/// An etag with its quoting removed, because servers differ on it.
pub fn normalize_etag(raw: &str) -> String {
    raw.trim()
        .trim_start_matches("W/")
        .trim_matches('"')
        .to_string()
}

/// The remote's own error code, when the body carried one.
fn error_code(body: &str) -> Option<String> {
    tag_text(body, "Code")
}

/// The five predefined XML entities, expanded.
///
/// `&amp;` LAST, or an escaped entity would be double-expanded: a literal
/// ampersand-l-t written as five characters would come back as a less-than
/// sign rather than as the four characters it names.
fn unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// The text of the first `tag` element in `xml`.
fn tag_text(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(unescape(&xml[start..end]))
}

/// The inner text of every `tag` element in `xml`, in order.
fn blocks<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(at) = rest.find(&open) {
        let from = at + open.len();
        let Some(len) = rest[from..].find(&close) else {
            break;
        };
        out.push(&rest[from..from + len]);
        rest = &rest[from + len + close.len()..];
    }
    out
}

/// One page of a listing: its rows, and the token for the next page.
///
/// A HAND SCAN AND NOT AN XML CRATE, matching the shape already chosen for the
/// other protocol this port will carry. The grammar consumed here is four
/// element names in a document the remote generates.
///
/// ITS DISCRIMINATOR IS THE ROOT ELEMENT, and that is the load-bearing part.
/// Keying on a row element instead would read an HTML error page and a
/// legitimately empty bucket as the same thing, and an empty listing where the
/// remote actually holds objects is a silent "your inventory is empty" that a
/// merge reads as a pile of deletes.
pub fn parse_list(bytes: &[u8]) -> Result<(Vec<Entry>, Option<String>), ProviderError> {
    let body = std::str::from_utf8(bytes)
        .map_err(|e| ProviderError::Malformed(format!("the listing did not decode: {e}")))?;
    if !body.contains("<ListBucketResult") {
        return Err(ProviderError::Malformed(
            "the listing carried no ListBucketResult element".to_string(),
        ));
    }

    let mut entries = Vec::new();
    for row in blocks(body, "Contents") {
        let key = tag_text(row, "Key").ok_or_else(|| {
            ProviderError::Malformed("a listing row carried no Key element".to_string())
        })?;
        // AN ABSENT ETAG IS REFUSED RATHER THAN DEFAULTED, because the empty
        // string is not an etag and would be handed straight back as a
        // condition on the next write - where it fails every conditional put,
        // silently and permanently. Same rule the object read applies.
        let etag = tag_text(row, "ETag")
            .map(|e| normalize_etag(&e))
            .filter(|e| !e.is_empty())
            .ok_or_else(|| {
                ProviderError::Malformed(format!("the listing row for \"{key}\" carried no etag"))
            })?;
        entries.push(Entry {
            key,
            etag,
            modified_at: tag_text(row, "LastModified")
                .as_deref()
                .and_then(sigv4::parse_iso8601_utc),
        });
    }

    let truncated = tag_text(body, "IsTruncated")
        .map(|v| v.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    // A PAGE THAT SAYS IT IS TRUNCATED AND THEN NAMES NO TOKEN IS A PROTOCOL
    // FAILURE, not the end of the listing. Reading it as the end is the
    // silent-loss shape the root-element check guards the empty case against:
    // a partial inventory returned as a complete one, which the merge above
    // reads as every absent record having been deleted.
    let next = if truncated {
        Some(
            tag_text(body, "NextContinuationToken")
                .filter(|t| !t.is_empty())
                .ok_or_else(|| {
                    ProviderError::Protocol(
                        "the listing said it was truncated and then named no continuation token"
                            .to_string(),
                    )
                })?,
        )
    } else {
        None
    };
    Ok((entries, next))
}

/// Fold one page into the accumulated listing, and say whether to ask for
/// another.
///
/// TAKES `prev`, THE TOKEN THAT PRODUCED THIS PAGE, because that is the only
/// way to notice a server handing back the same token forever - the
/// accumulated rows carry no token history. That case is `Protocol` and not
/// `Malformed`: the body decoded and parsed fine, and the server is the thing
/// that is broken.
pub fn accumulate(
    acc: &mut Vec<Entry>,
    prev: Option<&str>,
    page: (Vec<Entry>, Option<String>),
) -> Result<Option<String>, ProviderError> {
    let (entries, next) = page;
    acc.extend(entries);
    match next {
        None => Ok(None),
        Some(token) if Some(token.as_str()) == prev => Err(ProviderError::Protocol(
            "the listing repeated its continuation token, which never terminates".to_string(),
        )),
        Some(token) => Ok(Some(token)),
    }
}

// --- the shell ------------------------------------------------------------

/// What a send came back with, before anything is decided about it.
struct RawResponse {
    status: u16,
    etag: Option<String>,
    body: Vec<u8>,
}

pub struct S3Provider {
    cfg: S3Config,
    client: reqwest::Client,
    /// Set once the endpoint has PASSED the SSRF guard, and never otherwise.
    ///
    /// The guard resolves the host, so re-running it per object would put a DNS
    /// lookup in front of every request in an inventory-sized listing, and the
    /// endpoint cannot change without a new provider.
    ///
    /// ONLY THE PASS IS CACHED. The guard answers with the same error type for
    /// a link-local address and for a name that simply did not resolve, so
    /// caching a failure would let one attempt made on a dropped network
    /// poison the provider for the life of the process - and report it as a
    /// security refusal, which sends the user looking for a policy that does
    /// not exist. A refusal is not cached, so the next call asks again.
    endpoint_allowed: tokio::sync::OnceCell<()>,
}

/// Which disposition a refusal from the SSRF guard is.
///
/// Keyed on the guard's OWN vocabulary: it prefixes a refusal with `blocked:`
/// and says so in plain words for a resolution that did not answer. A dropped
/// network is a transport failure, not a policy decision, and the two want
/// opposite things from the caller - one is worth retrying, the other never is.
fn guard_failure(why: String) -> ProviderError {
    if why.starts_with("blocked:") {
        ProviderError::Blocked(why)
    } else {
        ProviderError::Transport(why)
    }
}

impl S3Provider {
    pub fn new(cfg: S3Config) -> Result<Self, ProviderError> {
        // Fail here rather than at the first request, so a provider that exists
        // is one that can sign.
        endpoint(&cfg)?;
        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| {
                ProviderError::Config(format!("the sync http client could not be built: {e}"))
            })?;
        Ok(Self {
            cfg,
            client,
            endpoint_allowed: tokio::sync::OnceCell::new(),
        })
    }

    async fn allowed(&self) -> Result<(), ProviderError> {
        if self.endpoint_allowed.initialized() {
            return Ok(());
        }
        crate::modules::net::reject_metadata_ssrf(&self.cfg.endpoint)
            .await
            .map_err(guard_failure)?;
        // Two first calls racing here both run the guard and both set this.
        // That costs one extra resolution and cannot disagree, which is
        // cheaper than the lock that would prevent it.
        let _ = self.endpoint_allowed.set(());
        Ok(())
    }

    async fn send(
        &self,
        req: SignedRequest,
        body: Option<Vec<u8>>,
    ) -> Result<RawResponse, ProviderError> {
        let method = match req.method {
            "GET" => reqwest::Method::GET,
            "PUT" => reqwest::Method::PUT,
            "DELETE" => reqwest::Method::DELETE,
            other => {
                return Err(ProviderError::Config(format!(
                    "unsupported sync http method \"{other}\""
                )))
            }
        };
        let mut builder = self.client.request(method, &req.url);
        for (name, value) in &req.headers {
            builder = builder.header(name, value);
        }
        if let Some(body) = body {
            builder = builder.body(body);
        }
        let resp = builder.send().await.map_err(from_reqwest)?;
        let status = resp.status().as_u16();
        let etag = resp
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(normalize_etag);
        let body = resp.bytes().await.map_err(from_reqwest)?.to_vec();
        Ok(RawResponse { status, etag, body })
    }
}

fn from_reqwest(e: reqwest::Error) -> ProviderError {
    transport_error(
        e.is_redirect(),
        e.is_timeout(),
        e.is_connect(),
        e.to_string(),
    )
}

impl SyncProvider for S3Provider {
    fn id(&self) -> &'static str {
        "s3"
    }

    fn capabilities(&self) -> Caps {
        Caps { cas: self.cfg.cas }
    }

    fn get<'a>(
        &'a self,
        key: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Object>, ProviderError>> + Send + 'a>> {
        Box::pin(async move {
            self.allowed().await?;
            let req = build_get(&self.cfg, key, SystemTime::now())?;
            let raw = self.send(req, None).await?;
            if classify_get(raw.status, &raw.body)?.is_none() {
                return Ok(None);
            }
            // SYMMETRIC WITH `put`, which refuses the same absence. An empty
            // string is not an etag, and handing one back would have the
            // caller send `If-Match:` with nothing after it - a condition that
            // fails every conditional write, silently and forever.
            let etag = raw.etag.ok_or_else(|| {
                ProviderError::Malformed("the remote returned an object with no etag".to_string())
            })?;
            Ok(Some(Object {
                etag,
                bytes: raw.body,
            }))
        })
    }

    fn put<'a>(
        &'a self,
        key: &'a str,
        bytes: Vec<u8>,
        if_match: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = Result<String, ProviderError>> + Send + 'a>> {
        Box::pin(async move {
            self.allowed().await?;
            // The same predicate `build_put` applies, through the same
            // function, so the mapper is told what was actually sent rather
            // than what was asked for.
            let conditional = condition(&self.cfg, if_match).is_some();
            let req = build_put(&self.cfg, key, &bytes, if_match, SystemTime::now())?;
            let raw = self.send(req, Some(bytes)).await?;
            classify_put(raw.status, &raw.body, conditional)?;
            raw.etag.ok_or_else(|| {
                ProviderError::Malformed(
                    "the remote stored the object but returned no etag".to_string(),
                )
            })
        })
    }

    fn list<'a>(
        &'a self,
        prefix: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Entry>, ProviderError>> + Send + 'a>> {
        Box::pin(async move {
            self.allowed().await?;
            let mut entries: Vec<Entry> = Vec::new();
            let mut token: Option<String> = None;
            loop {
                let req = build_list(&self.cfg, prefix, token.as_deref(), SystemTime::now())?;
                let raw = self.send(req, None).await?;
                if !(200..300).contains(&raw.status) {
                    // Not `classify_get`: a missing BUCKET is a real failure,
                    // where a missing object is the ordinary answer.
                    return Err(classify(raw.status, &raw.body));
                }
                let page = parse_list(&raw.body)?;
                match accumulate(&mut entries, token.as_deref(), page)? {
                    None => return Ok(entries),
                    next => token = next,
                }
            }
        })
    }

    fn delete<'a>(
        &'a self,
        key: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>> {
        Box::pin(async move {
            self.allowed().await?;
            let req = build_delete(&self.cfg, key, SystemTime::now())?;
            let raw = self.send(req, None).await?;
            if (200..300).contains(&raw.status) {
                return Ok(());
            }
            // A delete answers with no content whether or not the key was
            // there, and a server that reports the absence instead means the
            // same thing: gone. A missing BUCKET does not - that is a
            // configuration error, and swallowing it would have every delete
            // against a mistyped bucket report success. `list` distinguishes
            // exactly the same pair.
            let missing_bucket = error_code(&String::from_utf8_lossy(&raw.body))
                .is_some_and(|code| code == "NoSuchBucket");
            if raw.status == 404 && !missing_bucket {
                return Ok(());
            }
            Err(classify(raw.status, &raw.body))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed instant, so every signature below is reproducible.
    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    /// 2015-08-30T12:36:00Z, the same instant the signing vectors use, so a
    /// failure here and a failure there are comparable by eye.
    const NOW: u64 = 1_440_938_160;

    fn cfg() -> S3Config {
        S3Config {
            endpoint: "https://storage.example".to_string(),
            region: "us-east-1".to_string(),
            bucket: "tervia".to_string(),
            cas: true,
            access_key_id: "test-access-key".to_string(),
            secret_access_key: "test-secret".to_string(),
        }
    }

    fn header<'a>(req: &'a SignedRequest, name: &str) -> Option<&'a str> {
        req.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    fn names(req: &SignedRequest) -> Vec<&str> {
        req.headers.iter().map(|(n, _)| n.as_str()).collect()
    }

    fn all(cfg: &S3Config) -> Vec<SignedRequest> {
        vec![
            build_get(cfg, "v1/obj/abc", at(NOW)).unwrap(),
            build_put(cfg, "v1/obj/abc", b"sealed", None, at(NOW)).unwrap(),
            build_delete(cfg, "v1/obj/abc", at(NOW)).unwrap(),
            build_list(cfg, "v1/obj/", None, at(NOW)).unwrap(),
        ]
    }

    // --- the S3-specific signing the generic vectors cannot reach ----------

    #[test]
    fn every_verb_signs_exactly_the_three_headers_s3_requires_and_no_content_type() {
        // The published suite signs a generic service over two headers. S3
        // additionally requires the payload hash to be SENT and SIGNED on every
        // verb, so a signer that reproduces the suite can still be rejected on
        // every real request. This is that gap.
        for req in all(&cfg()) {
            assert_eq!(
                names(&req),
                vec![
                    "host",
                    "x-amz-content-sha256",
                    "x-amz-date",
                    "authorization"
                ],
                "{} {}",
                req.method,
                req.url
            );
            let authorization = header(&req, "authorization").unwrap();
            assert!(
                authorization.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date,"),
                "{} signed the wrong set: {authorization}",
                req.method
            );
            assert!(
                authorization.starts_with("AWS4-HMAC-SHA256 Credential=test-access-key/20150830/us-east-1/s3/aws4_request,"),
                "{} built the wrong scope: {authorization}",
                req.method
            );
            assert_eq!(header(&req, "host"), Some("storage.example"));
            assert_eq!(header(&req, "x-amz-date"), Some("20150830T123600Z"));
            // Sending one would add a fourth signed header and a fourth way to
            // get the canonical request wrong, for no reader.
            assert!(
                !names(&req).iter().any(|n| n.contains("content-type")),
                "{} sent a content type",
                req.method
            );
        }
    }

    #[test]
    fn the_bodyless_verbs_carry_the_empty_payload_hash_and_a_put_carries_its_own() {
        let cfg = cfg();
        for req in [
            build_get(&cfg, "k", at(NOW)).unwrap(),
            build_delete(&cfg, "k", at(NOW)).unwrap(),
            build_list(&cfg, "", None, at(NOW)).unwrap(),
        ] {
            assert_eq!(
                header(&req, "x-amz-content-sha256"),
                Some(sigv4::EMPTY_PAYLOAD_SHA256),
                "{}",
                req.method
            );
        }
        let body = b"a sealed envelope";
        let put = build_put(&cfg, "k", body, None, at(NOW)).unwrap();
        assert_eq!(
            header(&put, "x-amz-content-sha256"),
            Some(sigv4::sha256_hex(body).as_str())
        );
        // And it is not silently the empty hash, which is the way this goes
        // wrong.
        assert_ne!(
            header(&put, "x-amz-content-sha256"),
            Some(sigv4::EMPTY_PAYLOAD_SHA256)
        );
    }

    /// The `Authorization` value each builder produces, for the fixture above
    /// at the fixed instant above.
    ///
    /// A REGRESSION PIN, AND AN INDEPENDENT ONE. These were not read back out
    /// of this implementation: they were computed from the protocol definition
    /// by a separate program, so a defect shared between the signer and its own
    /// output cannot hide in them. That matters because the published vectors
    /// sign a GENERIC service over two headers with a literal date, and every
    /// other test here asserts on header NAMES and substrings. Change the path
    /// fed to the canonical request without changing the URL - double-encode
    /// it, normalize it, prepend something - and every one of those still
    /// passes while every real request comes back rejected. This is what
    /// notices.
    const PINNED: [(&str, &str); 4] = [
        (
            "GET",
            "AWS4-HMAC-SHA256 Credential=test-access-key/20150830/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=dadd4c9692aa157d45a5dd808edb9b3e9c439c891c0489c08dca8214bc7ee296",
        ),
        (
            "PUT",
            "AWS4-HMAC-SHA256 Credential=test-access-key/20150830/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=7fb6b37b8d723dede555c98b5769e39b962c130d8885b26fade1a8007f34c47f",
        ),
        (
            "DELETE",
            "AWS4-HMAC-SHA256 Credential=test-access-key/20150830/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=eb54ad3eee6d519a7dcb507945e6b9a1df769b2b747fc5e81a9d4e86b0376fdd",
        ),
        (
            "LIST",
            "AWS4-HMAC-SHA256 Credential=test-access-key/20150830/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=e9c6e0d3b200cf024261a2b32de44fffcfafb444899a3884a621f876814b3d79",
        ),
    ];

    #[test]
    fn every_builder_still_produces_the_signature_it_was_pinned_at() {
        for (req, (label, expected)) in all(&cfg()).into_iter().zip(PINNED) {
            assert_eq!(
                header(&req, "authorization"),
                Some(expected),
                "{label} no longer signs what it was pinned at"
            );
        }
    }

    #[test]
    fn the_url_that_is_sent_carries_the_path_that_was_signed() {
        // THE SEAM THE PURE HALF CANNOT SEE ON ITS OWN. The canonical request
        // takes the path verbatim, but the http client reparses this URL, and
        // that parse has rules of its own. Asserting on the signer's output
        // alone would pass while the two disagree, and the symptom is a
        // rejected signature rather than anything about paths.
        let cfg = cfg();
        for key in ["v1/obj/abc", "v1/obj/aa%bb", "caf\u{e9}/obj", "a//b", ""] {
            let req = build_get(&cfg, key, at(NOW)).unwrap();
            let parsed = url::Url::parse(&req.url).expect("the builder produced a url");
            assert_eq!(
                parsed.path(),
                sigv4::uri_encode(&format!("/tervia/{key}"), false),
                "\"{key}\" survived signing but not the parse"
            );
        }
    }

    #[test]
    fn a_dot_segment_is_refused_rather_than_signed_and_then_collapsed() {
        // The parse above REMOVES a `.` or `..` segment, and decodes a
        // percent-escaped one first, so neither passing it through nor
        // encoding it keeps the two halves equal. Refusing is the only answer
        // that leaves no gap, and the key arrives here composed from a
        // user-typed prefix.
        let cfg = cfg();
        for key in ["v1/../obj/abc", "v1/./obj", "..", ".", "v1/obj/.."] {
            for built in [
                build_get(&cfg, key, at(NOW)),
                build_delete(&cfg, key, at(NOW)),
                build_put(&cfg, key, b"x", None, at(NOW)),
            ] {
                let err = built
                    .err()
                    .unwrap_or_else(|| panic!("\"{key}\" must be refused"));
                assert!(
                    matches!(err, ProviderError::Config(_)),
                    "\"{key}\" gave {err:?}"
                );
            }
            assert!(object_url(&cfg, key).is_err(), "\"{key}\" built a url");
        }
        // And an ordinary key still builds, so the guard is not simply
        // refusing everything.
        assert!(build_get(&cfg, "v1/obj/abc", at(NOW)).is_ok());
        // Nor is a dot INSIDE a segment a dot segment.
        assert!(build_get(&cfg, "v1/obj/a.b", at(NOW)).is_ok());
    }

    #[test]
    fn an_endpoint_whose_path_is_already_escaped_is_refused() {
        // It would be escaped a second time on the way into the signed path,
        // and because signed and sent would still AGREE there is no rejected
        // signature to notice - the request would quietly address a path
        // nobody has.
        let mut spaced = cfg();
        spaced.endpoint = "https://storage.example/my path/".to_string();
        let err =
            build_get(&spaced, "k", at(NOW)).expect_err("an escaped endpoint path must be refused");
        assert!(matches!(err, ProviderError::Config(_)), "{err:?}");
    }

    #[test]
    fn a_non_default_port_rides_into_the_host_header_and_a_default_one_does_not() {
        // The canonical request must carry the port exactly when the URL does,
        // and a self-hosted server on a non-standard port is the common case.
        let mut ported = cfg();
        ported.endpoint = "https://storage.example:9000".to_string();
        assert_eq!(
            header(&build_get(&ported, "k", at(NOW)).unwrap(), "host"),
            Some("storage.example:9000")
        );

        let mut default_port = cfg();
        default_port.endpoint = "https://storage.example:443".to_string();
        assert_eq!(
            header(&build_get(&default_port, "k", at(NOW)).unwrap(), "host"),
            Some("storage.example")
        );
    }

    #[test]
    fn a_list_asks_for_the_second_listing_version_and_sorts_its_query() {
        let req = build_list(&cfg(), "v1/obj/", Some("tok/en"), at(NOW)).unwrap();
        // Sorted by the ENCODED key, and the token percent encoded because a
        // continuation token is opaque and may carry anything.
        assert_eq!(
            req.url,
            "https://storage.example/tervia?continuation-token=tok%2Fen&list-type=2&prefix=v1%2Fobj%2F"
        );
        assert_eq!(
            build_list(&cfg(), "v1/obj/", None, at(NOW)).unwrap().url,
            "https://storage.example/tervia?list-type=2&prefix=v1%2Fobj%2F"
        );
    }

    // --- compare-and-swap gating ------------------------------------------

    #[test]
    fn the_condition_rides_only_when_the_endpoint_was_told_it_can_honour_it() {
        let capable = cfg();
        let mut incapable = cfg();
        incapable.cas = false;

        let with = build_put(&capable, "k", b"body", Some("etag-1"), at(NOW)).unwrap();
        assert_eq!(header(&with, "if-match"), Some("etag-1"));

        // Suppressed, and byte-identical to the unconditional call - which is
        // the real claim: the condition is not signed, so suppressing it must
        // not perturb anything else.
        let suppressed = build_put(&incapable, "k", b"body", Some("etag-1"), at(NOW)).unwrap();
        let unconditional = build_put(&incapable, "k", b"body", None, at(NOW)).unwrap();
        assert_eq!(suppressed, unconditional);
        assert!(header(&suppressed, "if-match").is_none());

        // And the capable config with no condition asked for carries none
        // either, so the toggle alone does not add one.
        assert!(build_put(&capable, "k", b"body", None, at(NOW))
            .unwrap()
            .headers
            .iter()
            .all(|(n, _)| n != "if-match"));
    }

    // --- error taxonomy ---------------------------------------------------

    #[test]
    fn a_stale_etag_and_a_mid_upload_conflict_are_different_dispositions() {
        assert_eq!(classify(412, b""), ProviderError::PreconditionFailed);
        assert_eq!(
            classify(
                409,
                b"<Error><Code>ConditionalRequestConflict</Code></Error>"
            ),
            ProviderError::Conflict
        );
        assert_ne!(classify(412, b""), classify(409, b""));
    }

    #[test]
    fn nothing_but_412_is_ever_a_stale_etag() {
        // Over the whole range, because the way this goes wrong is a range arm
        // written a little too wide and a caller then retrying a merge it never
        // needed to do.
        for status in 100u16..=599 {
            let err = classify(status, b"");
            if status == 412 {
                assert_eq!(err, ProviderError::PreconditionFailed);
            } else {
                assert_ne!(err, ProviderError::PreconditionFailed, "{status}");
            }
        }
    }

    #[test]
    fn a_redirect_is_a_refusal_rather_than_a_remote_failure() {
        // The client follows none, so a region redirect arrives as a 3xx
        // RESPONSE. Reporting it as an ordinary remote failure would hide why
        // the request is going nowhere.
        for status in [301u16, 302, 307, 308] {
            assert!(
                matches!(classify(status, b""), ProviderError::Blocked(_)),
                "{status}"
            );
        }
    }

    #[test]
    fn an_error_body_contributes_its_code_and_a_bodyless_one_does_not() {
        assert_eq!(
            classify(403, b"<Error><Code>SignatureDoesNotMatch</Code></Error>"),
            ProviderError::Remote {
                status: 403,
                code: Some("SignatureDoesNotMatch".to_string()),
            }
        );
        assert_eq!(
            classify(500, b""),
            ProviderError::Remote {
                status: 500,
                code: None,
            }
        );
    }

    #[test]
    fn the_three_transport_shapes_are_distinct_and_a_refused_redirect_is_not_one() {
        let redirect = transport_error(true, false, false, "too many redirects".to_string());
        let timeout = transport_error(false, true, false, "operation timed out".to_string());
        let connect = transport_error(false, false, true, "connection refused".to_string());
        let other = transport_error(false, false, false, "body stream ended".to_string());

        assert!(
            matches!(redirect, ProviderError::Blocked(_)),
            "a refused redirect is the guard working, not a transport failure: {redirect:?}"
        );
        assert!(matches!(timeout, ProviderError::Transport(_)));
        assert!(matches!(connect, ProviderError::Transport(_)));
        assert_ne!(timeout, connect);
        assert_ne!(timeout, other);
        assert_ne!(connect, other);
    }

    #[test]
    fn a_missing_key_reads_as_absent_when_getting_and_as_a_failure_when_writing_conditionally() {
        assert_eq!(classify_get(404, b""), Ok(None));
        assert_eq!(classify_get(200, b""), Ok(Some(())));
        assert_eq!(classify_put(404, b"", true), Err(ProviderError::NotFound));
        // Without a condition a 404 is an ordinary remote failure, because
        // nothing was raced.
        assert_ne!(classify_put(404, b"", false), Err(ProviderError::NotFound));
        assert_eq!(classify_put(204, b"", false), Ok(()));
        // A body that is not text at all reaches these on the failure path, so
        // nothing here may assume a decode succeeded.
        assert_eq!(
            classify_get(500, &[0xff, 0xfe]),
            Err(ProviderError::Remote {
                status: 500,
                code: None
            })
        );
    }

    #[test]
    fn an_etag_loses_its_quoting_however_the_server_spelled_it() {
        for raw in ["\"abc123\"", "abc123", "W/\"abc123\"", "  \"abc123\" "] {
            assert_eq!(normalize_etag(raw), "abc123", "{raw}");
        }
    }

    // --- listing ----------------------------------------------------------

    /// A listing shaped the way a real one is, entity-escaped etags included.
    fn listing(rows: &str, truncated: bool, next: &str) -> String {
        let tail = if truncated {
            format!("<IsTruncated>true</IsTruncated><NextContinuationToken>{next}</NextContinuationToken>")
        } else {
            "<IsTruncated>false</IsTruncated>".to_string()
        };
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <ListBucketResult xmlns=\"http://s3.example/doc/2006-03-01/\">\
             <Name>tervia</Name><KeyCount>2</KeyCount>{rows}{tail}</ListBucketResult>"
        )
    }

    const ROWS: &str = "<Contents><Key>v1/obj/aa&amp;bb</Key>\
         <LastModified>2009-10-12T17:50:30.123Z</LastModified>\
         <ETag>&quot;9b2cf5&quot;</ETag><Size>42</Size></Contents>\
         <Contents><Key>v1/keyfile</Key>\
         <LastModified>2024-02-29T00:00:00Z</LastModified>\
         <ETag>&quot;0f1e2d&quot;</ETag><Size>310</Size></Contents>";

    #[test]
    fn a_listing_yields_each_key_with_its_etag_and_a_millisecond_stamp() {
        let (entries, next) = parse_list(listing(ROWS, false, "").as_bytes()).unwrap();
        assert_eq!(next, None);
        assert_eq!(
            entries,
            vec![
                Entry {
                    // The escaped ampersand comes back as one character, or a
                    // key with one in it would name a different object.
                    key: "v1/obj/aa&bb".to_string(),
                    etag: "9b2cf5".to_string(),
                    modified_at: Some(1_255_369_830_123),
                },
                Entry {
                    key: "v1/keyfile".to_string(),
                    etag: "0f1e2d".to_string(),
                    modified_at: Some(1_709_164_800_000),
                },
            ]
        );
    }

    #[test]
    fn an_empty_prefix_is_an_empty_listing_and_not_an_error() {
        let (entries, next) = parse_list(listing("", false, "").as_bytes()).unwrap();
        assert!(entries.is_empty());
        assert_eq!(next, None);
    }

    #[test]
    fn a_body_that_is_not_a_listing_is_refused_rather_than_read_as_empty() {
        // The failure this exists for: an empty list where the remote holds
        // objects is a silent "your inventory is empty", which a merge reads as
        // a pile of deletes. None of the row elements appears in either of
        // these, so keying on one of those would call both of them empty.
        for body in [
            "<html><body><h1>502 Bad Gateway</h1></body></html>",
            "",
            "<Error><Code>AccessDenied</Code></Error>",
        ] {
            assert!(
                matches!(
                    parse_list(body.as_bytes()),
                    Err(ProviderError::Malformed(_))
                ),
                "{body}"
            );
        }
        // And bytes that are not text at all.
        assert!(matches!(
            parse_list(&[0xff, 0xfe, 0x00, 0x01]),
            Err(ProviderError::Malformed(_))
        ));
    }

    #[test]
    fn a_truncated_listing_carries_its_continuation_token_and_a_complete_one_does_not() {
        let (_, next) = parse_list(listing(ROWS, true, "page-2").as_bytes()).unwrap();
        assert_eq!(next, Some("page-2".to_string()));
        let (_, none) = parse_list(listing(ROWS, false, "page-2").as_bytes()).unwrap();
        assert_eq!(none, None);
    }

    #[test]
    fn a_row_missing_its_key_or_its_etag_is_refused() {
        // An absent etag defaulted to the empty string is worse than a refusal:
        // it is handed back as a condition on the next write, where it fails
        // every conditional put and says nothing about why.
        for rows in [
            "<Contents><ETag>&quot;abc&quot;</ETag></Contents>",
            "<Contents><Key>v1/obj/abc</Key></Contents>",
            "<Contents><Key>v1/obj/abc</Key><ETag></ETag></Contents>",
            "<Contents><Key>v1/obj/abc</Key><ETag>&quot;&quot;</ETag></Contents>",
        ] {
            assert!(
                matches!(
                    parse_list(listing(rows, false, "").as_bytes()),
                    Err(ProviderError::Malformed(_))
                ),
                "{rows}"
            );
        }
    }

    #[test]
    fn a_page_that_claims_truncation_and_names_no_token_is_refused() {
        // THE PARTIAL-LOSS SHAPE, which the root-element check does not reach
        // because these bodies carry the root element perfectly well. Read as
        // the end of the listing, a truncated first page becomes a complete
        // inventory, and the merge above reads every record it omits as a
        // delete. `Protocol` and not `Malformed`: the body parsed fine, the
        // server is what is broken.
        for tail in [
            "<IsTruncated>true</IsTruncated>",
            "<IsTruncated>true</IsTruncated><NextContinuationToken></NextContinuationToken>",
        ] {
            let body =
                format!("<ListBucketResult><Name>tervia</Name>{ROWS}{tail}</ListBucketResult>");
            let got = parse_list(body.as_bytes());
            assert!(matches!(got, Err(ProviderError::Protocol(_))), "{got:?}");
        }
    }

    fn entry(key: &str) -> Entry {
        Entry {
            key: key.to_string(),
            etag: "e".to_string(),
            modified_at: None,
        }
    }

    #[test]
    fn pages_append_stop_and_refuse_to_spin() {
        let mut acc = Vec::new();

        // Page one asks for another.
        let next = accumulate(&mut acc, None, (vec![entry("a")], Some("p2".into()))).unwrap();
        assert_eq!(next, Some("p2".to_string()));

        // Page two APPENDS rather than replacing, and ends the listing.
        let next = accumulate(&mut acc, Some("p2"), (vec![entry("b")], None)).unwrap();
        assert_eq!(next, None);
        assert_eq!(
            acc.iter().map(|e| e.key.as_str()).collect::<Vec<_>>(),
            vec!["a", "b"]
        );

        // A server handing back the token it was just given is a listing that
        // never terminates. `Protocol` and not `Malformed`: the body decoded
        // and parsed perfectly well.
        let spinning = accumulate(&mut acc, Some("p2"), (vec![entry("c")], Some("p2".into())));
        assert!(
            matches!(spinning, Err(ProviderError::Protocol(_))),
            "{spinning:?}"
        );
    }

    // --- boundaries -------------------------------------------------------

    #[tokio::test]
    async fn the_metadata_endpoints_are_refused_before_any_request_is_built() {
        // Both answered without DNS: the first is an IP literal, the second is
        // refused by name. `#[tokio::test]` rather than a plain one because the
        // guard is async and routes through a blocking task even for a literal.
        for endpoint in [
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/",
        ] {
            let mut cfg = cfg();
            cfg.endpoint = endpoint.to_string();
            let provider = S3Provider::new(cfg).expect("the url itself is well formed");
            let err = provider.get("v1/keyfile").await.unwrap_err();
            assert!(
                matches!(err, ProviderError::Blocked(_)),
                "{endpoint} gave {err:?}"
            );
        }
    }

    #[test]
    fn a_name_that_did_not_resolve_is_a_transport_failure_and_not_a_refusal() {
        // The guard answers a link-local address and an unreachable DNS server
        // with the same error TYPE, and only one of them is a policy decision.
        // Reporting a dropped network as "blocked" sends the user looking for
        // a setting that does not exist - and, because only a PASS is cached,
        // the same call has to be able to succeed later.
        assert!(matches!(
            guard_failure("blocked: link-local / cloud-metadata address".to_string()),
            ProviderError::Blocked(_)
        ));
        assert!(matches!(
            guard_failure("blocked: cloud metadata endpoint".to_string()),
            ProviderError::Blocked(_)
        ));
        for transient in [
            "dns resolve failed: failed to lookup address information",
            "dns task failed: task panicked",
        ] {
            assert!(
                matches!(
                    guard_failure(transient.to_string()),
                    ProviderError::Transport(_)
                ),
                "{transient}"
            );
        }
    }

    #[test]
    fn an_object_url_joins_its_parts_with_exactly_one_separator() {
        let bare = cfg();
        let mut trailing = cfg();
        trailing.endpoint = "https://storage.example/".to_string();
        for cfg in [&bare, &trailing] {
            assert_eq!(
                object_url(cfg, "v1/obj/abc").unwrap(),
                "https://storage.example/tervia/v1/obj/abc"
            );
        }

        // A server mounted under a base path keeps it, and the signed path
        // carries it too or the signature would not match the URL.
        let mut mounted = cfg();
        mounted.endpoint = "https://storage.example/s3/".to_string();
        assert_eq!(
            object_url(&mounted, "v1/obj/abc").unwrap(),
            "https://storage.example/s3/tervia/v1/obj/abc"
        );
        assert_eq!(
            build_get(&mounted, "v1/obj/abc", at(NOW)).unwrap().url,
            "https://storage.example/s3/tervia/v1/obj/abc"
        );

        // A non-ASCII key segment, which reaches here because the layer above
        // composes the key from a user-typed prefix.
        assert_eq!(
            object_url(&bare, "caf\u{e9}/obj").unwrap(),
            "https://storage.example/tervia/caf%C3%A9/obj"
        );
    }

    #[test]
    fn this_file_ships_no_vendor_endpoint_and_no_credential() {
        // A BACKSTOP OVER A GREP-ABLE SUBSET, not the guarantee. The guarantee
        // is that `S3Config` has no `Default` impl, which makes a defaulted
        // endpoint unrepresentable rather than merely absent today.
        //
        // One assumption, stated because it would otherwise be silent AND
        // checked because stating it is not enough: the test module is this
        // file's last item, so splitting at the first configuration attribute
        // leaves exactly the shipped half. A test-only helper marked anywhere
        // above it would shrink the scanned region and every needle below would
        // pass over almost nothing.
        //
        // Checked by NAMING THE LAST SHIPPED ITEM rather than by a byte floor.
        // A floor is a guess that has to be revised whenever either half grows,
        // and it answers "is this big enough" when the question is "does this
        // reach the end". The trait implementation is the last thing before the
        // test module, so a split that lands before it loses that name.
        //
        // Reading one's own source is a new pattern in this tree - the existing
        // uses embed shell scripts.
        //
        // Deliberately NOT checking the names of particular self-hosted servers
        // or a loopback address: both appear in truthful prose about what this
        // provider supports.
        let source = include_str!("s3.rs");
        let shipped = source
            .split_once("#[cfg(test)]")
            .expect("the test module is still marked")
            .0;
        assert!(
            shipped.contains("impl SyncProvider for S3Provider"),
            "the split landed before the last shipped item, so {} of {} bytes went unscanned",
            source.len() - shipped.len(),
            source.len()
        );
        for needle in ["amazonaws.com", "AKIA", "ASIA"] {
            assert!(
                !shipped.contains(needle),
                "the shipped half of this file carries {needle}"
            );
        }
    }
}
