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
//!   becomes replacement characters instead of failing. Bodies are read as
//!   bytes and decoded inside [`parse_list`].
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRequest {
    pub method: &'static str,
    pub url: String,
    /// In a fixed order: the three signed headers, the authorization, then any
    /// unsigned extras. Fixed so a test can assert the whole map.
    pub headers: Vec<(String, String)>,
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
    Ok(Endpoint {
        base: format!("{}://{host}", parsed.scheme()),
        host,
        prefix: parsed.path().trim_end_matches('/').to_string(),
    })
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
    fn path(&self, key: &str) -> String {
        format!("{}/{}/{key}", self.endpoint.prefix, self.cfg.bucket)
    }

    /// The path of the bucket itself, which is what a listing addresses.
    fn bucket_path(&self) -> String {
        format!("{}/{}", self.endpoint.prefix, self.cfg.bucket)
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
        sigv4::uri_encode(&signing.path(key), false)
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
        &signing.path(key),
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
        &signing.path(key),
        &[],
        sigv4::EMPTY_PAYLOAD_SHA256,
        &[],
    ))
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
    let condition = if_match.filter(|_| cfg.cas);
    let extra: Vec<(&str, &str)> = match condition {
        Some(etag) => vec![("if-match", etag)],
        None => Vec::new(),
    };
    Ok(signing.sign("PUT", &signing.path(key), &[], &payload_hash, &extra))
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
        &signing.bucket_path(),
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
pub fn classify(status: u16, body: &str) -> ProviderError {
    match status {
        412 => ProviderError::PreconditionFailed,
        409 => ProviderError::Conflict,
        300..=399 => ProviderError::Blocked(format!(
            "blocked: the remote answered {status}, a redirect this client does not follow"
        )),
        _ => ProviderError::Remote {
            status,
            code: error_code(body),
        },
    }
}

/// A get's outcome. `Ok(None)` means the key is simply not there.
pub fn classify_get(status: u16, body: &str) -> Result<Option<()>, ProviderError> {
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
pub fn classify_put(status: u16, body: &str, conditional: bool) -> Result<(), ProviderError> {
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
        entries.push(Entry {
            key,
            etag: tag_text(row, "ETag")
                .map(|e| normalize_etag(&e))
                .unwrap_or_default(),
            modified_at: tag_text(row, "LastModified")
                .as_deref()
                .and_then(sigv4::parse_iso8601_utc),
        });
    }

    let truncated = tag_text(body, "IsTruncated")
        .map(|v| v.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let next = truncated
        .then(|| tag_text(body, "NextContinuationToken"))
        .flatten();
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
    /// The SSRF verdict for this endpoint, resolved on the first call and kept.
    ///
    /// `reject_metadata_ssrf` resolves the host, so re-running it per object
    /// would put a DNS lookup in front of every request in an inventory-sized
    /// listing. The endpoint cannot change without a new provider.
    endpoint_allowed: tokio::sync::OnceCell<Result<(), String>>,
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
        self.endpoint_allowed
            .get_or_init(|| crate::modules::net::reject_metadata_ssrf(&self.cfg.endpoint))
            .await
            .clone()
            .map_err(ProviderError::Blocked)
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
            if classify_get(raw.status, &String::from_utf8_lossy(&raw.body))?.is_none() {
                return Ok(None);
            }
            Ok(Some(Object {
                etag: raw.etag.unwrap_or_default(),
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
            // The same gate `build_put` applies, so the mapper is told what was
            // actually sent rather than what was asked for.
            let conditional = if_match.is_some() && self.cfg.cas;
            let req = build_put(&self.cfg, key, &bytes, if_match, SystemTime::now())?;
            let raw = self.send(req, Some(bytes)).await?;
            classify_put(raw.status, &String::from_utf8_lossy(&raw.body), conditional)?;
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
                    return Err(classify(raw.status, &String::from_utf8_lossy(&raw.body)));
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
            // A delete answers with no content whether or not the key was
            // there, and a server that reports the absence instead means the
            // same thing: gone.
            if raw.status == 404 || (200..300).contains(&raw.status) {
                return Ok(());
            }
            Err(classify(raw.status, &String::from_utf8_lossy(&raw.body)))
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
        assert_eq!(classify(412, ""), ProviderError::PreconditionFailed);
        assert_eq!(
            classify(
                409,
                "<Error><Code>ConditionalRequestConflict</Code></Error>"
            ),
            ProviderError::Conflict
        );
        assert_ne!(classify(412, ""), classify(409, ""));
    }

    #[test]
    fn nothing_but_412_is_ever_a_stale_etag() {
        // Over the whole range, because the way this goes wrong is a range arm
        // written a little too wide and a caller then retrying a merge it never
        // needed to do.
        for status in 100u16..=599 {
            let err = classify(status, "");
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
                matches!(classify(status, ""), ProviderError::Blocked(_)),
                "{status}"
            );
        }
    }

    #[test]
    fn an_error_body_contributes_its_code_and_a_bodyless_one_does_not() {
        assert_eq!(
            classify(403, "<Error><Code>SignatureDoesNotMatch</Code></Error>"),
            ProviderError::Remote {
                status: 403,
                code: Some("SignatureDoesNotMatch".to_string()),
            }
        );
        assert_eq!(
            classify(500, ""),
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
        assert_eq!(classify_get(404, ""), Ok(None));
        assert_eq!(classify_get(200, ""), Ok(Some(())));
        assert_eq!(classify_put(404, "", true), Err(ProviderError::NotFound));
        // Without a condition a 404 is an ordinary remote failure, because
        // nothing was raced.
        assert_ne!(classify_put(404, "", false), Err(ProviderError::NotFound));
        assert_eq!(classify_put(204, "", false), Ok(()));
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
    fn a_row_with_no_key_is_refused() {
        let rows = "<Contents><ETag>&quot;abc&quot;</ETag></Contents>";
        assert!(matches!(
            parse_list(listing(rows, false, "").as_bytes()),
            Err(ProviderError::Malformed(_))
        ));
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
        // Two assumptions it makes, stated because they are silent otherwise:
        // the test module is this file's last item, so splitting at the first
        // configuration attribute leaves exactly the shipped half; and reading
        // one's own source is a new pattern in this tree - the existing uses
        // embed shell scripts.
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
            shipped.len() > 1000,
            "the split landed somewhere unexpected"
        );
        for needle in ["amazonaws.com", "AKIA", "ASIA"] {
            assert!(
                !shipped.contains(needle),
                "the shipped half of this file carries {needle}"
            );
        }
    }
}
