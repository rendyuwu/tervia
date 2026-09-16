//! The WebDAV provider: Nextcloud, ownCloud, sabre/dav, Apache's `mod_dav`,
//! and anything else that speaks the protocol.
//!
//! SPLIT PURE FROM IMPURE, for the reason
//! `src-tauri/src/modules/sync/providers/s3.rs` states in its own header and
//! that has not changed: this crate has no `[dev-dependencies]` and therefore
//! no HTTP mock, so a behaviour that lives in an async method body cannot be
//! tested at all. Everything that decides anything - which URL, which headers,
//! which error, which rows - is a plain function taking values and returning
//! values, and what is left is five method bodies plus a send.
//!
//! THE FIRST BACKEND WITH NO CONDITIONAL WRITE. `capabilities` answers
//! `cas: false` as a CONSTANT rather than as a configuration field, because
//! there is no protocol guarantee here for a user to know the answer to: a
//! WebDAV server may or may not honour a conditional write and nothing in the
//! protocol says which. The trait's own contract makes that safe to express by
//! omission - a backend that cannot honour `if_match` degrades to
//! last-write-wins - so this file takes the argument and binds it to `_`, and
//! no request builder below accepts an etag at all. The conditional header is
//! therefore unreachable from this file rather than merely unused, which is a
//! stronger property than a branch and is checked by reading this file's own
//! source at the bottom.
//!
//! A COLLECTION HAS TO EXIST BEFORE ANYTHING CAN BE STORED IN IT, which is the
//! one structural difference from the other backend. S3 has no directories, so
//! the first write of a fresh remote succeeds; a WebDAV server refuses a PUT
//! whose parent collection does not exist and answers 409. Since the very
//! first thing the layer above does with a fresh remote is mint a keyfile, that
//! 409 is not an edge case - it is the ordinary first run. So `put` creates the
//! missing ancestors, shallowest first, and retries exactly once. A 409 that
//! survives that retry is a parent that is not a collection at all, and it is
//! reported as a refusal naming the parent rather than as the retry-and-hope
//! disposition a bare conflict carries.
//!
//! REDIRECTS ARE REFUSED. The client follows none, which matters more here than
//! it does for a signed protocol: this one puts the user's password in every
//! request, in a reversible encoding, and a server that redirects a plain-HTTP
//! request to somewhere else would otherwise have that password sent to
//! whatever host it named. A refused redirect arrives as an ordinary response
//! carrying a 3xx status - the client does not error on one - so it is caught
//! by status rather than by a transport branch.
//!
//! ONE `Content-Type` IS SENT, on the listing only. The other backend sends
//! none on any verb because a present content type has to be signed there;
//! nothing here signs anything, so that reason does not carry over and the two
//! cases are decided on their own merits. A listing's request body is XML and a
//! server is entitled to refuse an unlabelled one. A stored object is a sealed
//! envelope, which has no meaningful media type and whose type nothing on the
//! sync path ever reads back, so a put sends none and lets the server pick.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::Deserialize;

use super::sigv4;
use crate::modules::sync::provider::{Caps, Entry, Object, ProviderError, SyncProvider};

/// The same value the other backend picked, and for the same reason: this
/// carries an object body over whatever link the user's remote is on, where the
/// reachability ping in `src-tauri/src/modules/net.rs` is tuned for a ping.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Asking for three properties by name rather than for all of them, so the
/// response is three elements per row instead of whatever the server chooses to
/// keep about a file.
const PROPFIND_BODY: &str = concat!(
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
    "<propfind xmlns=\"DAV:\"><prop>",
    "<getetag/><getlastmodified/><resourcetype/>",
    "</prop></propfind>"
);

/// Only the listing carries a body, and only the listing labels one.
const XML_CONTENT_TYPE: &str = "application/xml; charset=\"utf-8\"";

/// One level down and no further. The object namespace the layer above composes
/// is flat, and an unbounded depth is refused by default on at least one common
/// server - so asking for it would be a failure on some remotes in exchange for
/// rows nobody reads.
const LIST_DEPTH: &str = "1";

/// Everything the provider needs, and nothing it can supply for the user.
///
/// THE SAME FOUR PROPERTIES the other backend's configuration justifies, for
/// the same reasons: no `Default` impl, so no code path can supply an endpoint
/// the user did not type; no derived `Debug`, so `password` cannot reach a log
/// line or a panic message; camelCase field names because this arrives as JSON
/// from the frontend; and no unknown fields, so a stale or misspelled key is a
/// loud error at the first call rather than a silently defaulted one.
///
/// NO `cas` FIELD, which is that last property doing work rather than an
/// omission. A frontend that sends one - because it was copied from the other
/// provider's form, say - is refused by name instead of having the key quietly
/// ignored while the user believes conditional writes are on.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WebDavConfig {
    /// Typed by the user: the collection their files hang off, which on a
    /// typical server is a per-user path under a dav mount point.
    pub endpoint: String,
    pub username: String,
    pub password: String,
}

/// A request the shell only has to send: nothing left to decide.
#[derive(Clone, PartialEq, Eq)]
pub struct DavRequest {
    pub method: &'static str,
    pub url: String,
    /// The authorization first, then any extras, in a fixed order so a test can
    /// assert the whole list.
    pub headers: Vec<(String, String)>,
}

/// HAND-WRITTEN AND REDACTING, for the reason [`WebDavConfig`] derives none.
/// The `Authorization` value here is the user's password in a REVERSIBLE
/// encoding, so a derived formatter would put a recoverable secret into
/// whatever log line or assertion message ever formats a request. Written
/// rather than omitted because `assert_eq!` needs one, and an assertion that
/// cannot print its two sides is worse than a redacted one.
impl std::fmt::Debug for DavRequest {
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
        f.debug_struct("DavRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &headers)
            .finish()
    }
}

/// The endpoint, taken apart once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// Scheme and authority, no trailing slash.
    base: String,
    /// The base path the user's dav mount sits at, `""` when it sits at the
    /// root. Every request path starts with it.
    path: String,
}

/// Take the endpoint apart, or say why it cannot be used.
///
/// Refused HERE and at construction rather than at the first request, so a
/// provider that exists is a provider that can address something. No `host`
/// field falls out of this, where the other backend's version produces one:
/// that one is a signed header, and nothing here signs anything.
fn endpoint(cfg: &WebDavConfig) -> Result<Endpoint, ProviderError> {
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
    let path = parsed.path().trim_end_matches('/').to_string();
    // A base path the url parser already had to escape would be escaped a
    // SECOND time on the way into every request url, since the percent itself
    // is not an unreserved character - so the request would address a path
    // nobody has. Refused rather than repaired, because the repair is a guess
    // at what the user meant.
    if path.contains('%') {
        return Err(bad(format!(
            "the sync endpoint's path must be plain, and \"{path}\" is escaped"
        )));
    }
    Ok(Endpoint {
        base: format!("{}://{host}", parsed.scheme()),
        path,
    })
}

/// The server-side path of one key, unencoded. Exactly one separator between
/// the base path and the key, whatever trailing slashes the endpoint carried.
fn object_path(ep: &Endpoint, key: &str) -> String {
    format!("{}/{key}", ep.path)
}

/// Where one object lives, as a URL.
pub fn object_url(ep: &Endpoint, key: &str) -> String {
    format!(
        "{}{}",
        ep.base,
        sigv4::uri_encode(&object_path(ep, key), false)
    )
}

/// The `Authorization` value.
///
/// PLAIN CREDENTIALS IN A REVERSIBLE ENCODING, which is what this scheme is and
/// is why the frontend warns when the endpoint is not a secure one. Nothing
/// about the encoding is a secret and nothing here pretends otherwise.
pub fn basic_auth(username: &str, password: &str) -> String {
    format!("Basic {}", B64.encode(format!("{username}:{password}")))
}

/// The collections that have to exist before `key` can be stored, shallowest
/// first.
///
/// SHALLOWEST FIRST AND ONE AT A TIME because a server will not create the
/// intermediate collections of a deep request for you - that is stated
/// normatively for the create-collection verb - so the ladder has to be walked
/// rung by rung. A key at the root names no collection and produces none.
pub fn ancestors(key: &str) -> Vec<String> {
    let segments: Vec<&str> = key.split('/').filter(|s| !s.is_empty()).collect();
    let mut out = Vec::new();
    let mut so_far = String::new();
    for segment in segments.iter().take(segments.len().saturating_sub(1)) {
        if !so_far.is_empty() {
            so_far.push('/');
        }
        so_far.push_str(segment);
        out.push(so_far.clone());
    }
    out
}

fn request(method: &'static str, url: String, auth: &str, extra: &[(&str, &str)]) -> DavRequest {
    let mut headers = vec![("authorization".to_string(), auth.to_string())];
    headers.extend(extra.iter().map(|(n, v)| (n.to_string(), v.to_string())));
    DavRequest {
        method,
        url,
        headers,
    }
}

pub fn build_get(ep: &Endpoint, auth: &str, key: &str) -> DavRequest {
    request("GET", object_url(ep, key), auth, &[])
}

/// A put, with no condition and no way to express one.
///
/// NO `if_match` PARAMETER, which is the decision this whole provider rests on
/// made unrepresentable rather than merely unused. The trait says a conditional
/// write is honoured only when the backend reports that capability, and this
/// one reports it as false, so a caller may pass a condition and get
/// last-write-wins instead of a failure.
pub fn build_put(ep: &Endpoint, auth: &str, key: &str) -> DavRequest {
    request("PUT", object_url(ep, key), auth, &[])
}

pub fn build_delete(ep: &Endpoint, auth: &str, key: &str) -> DavRequest {
    request("DELETE", object_url(ep, key), auth, &[])
}

pub fn build_propfind(ep: &Endpoint, auth: &str, prefix: &str) -> DavRequest {
    request(
        "PROPFIND",
        object_url(ep, prefix),
        auth,
        &[("depth", LIST_DEPTH), ("content-type", XML_CONTENT_TYPE)],
    )
}

pub fn build_mkcol(ep: &Endpoint, auth: &str, collection: &str) -> DavRequest {
    request("MKCOL", object_url(ep, collection), auth, &[])
}

// --- response mapping -----------------------------------------------------

/// The shared base: a status the caller has already decided is a failure,
/// turned into a disposition.
///
/// Two answers of its own. A 409 that reaches here is a conflict the caller
/// should re-read and retry - the one 409 this provider produces on its own
/// account is intercepted before it gets here, by the put ladder. And a 3xx is
/// a redirect the client refused rather than followed, which arrives as a
/// status because a refusing client returns the response rather than erroring
/// on it.
///
/// NO ERROR CODE IS READ OUT OF THE BODY, where the other backend reads one:
/// that protocol defines a machine-readable code element that every server
/// fills in, and this one's error bodies are an optional element that most
/// servers answer with a human-readable page instead. A `None` code is honest;
/// a code scraped out of an HTML page would not be.
pub fn classify(status: u16) -> ProviderError {
    match status {
        409 => ProviderError::Conflict,
        300..=399 => ProviderError::Blocked(format!(
            "blocked: the remote answered {status}, which this client neither follows nor reads"
        )),
        _ => ProviderError::Remote { status, code: None },
    }
}

/// A get's outcome. `Ok(None)` means the key is simply not there.
///
/// An authentication failure is NOT that: it goes to `classify` and comes back
/// as a remote failure naming its status, so a wrong password is reported as a
/// wrong password rather than as an empty remote.
pub fn classify_get(status: u16) -> Result<Option<()>, ProviderError> {
    match status {
        200..=299 => Ok(Some(())),
        404 => Ok(None),
        _ => Err(classify(status)),
    }
}

/// A put's outcome. `Ok(None)` means the parent collections are missing and the
/// caller should make them.
///
/// `retried` is needed because a status alone cannot tell the two calls apart,
/// and a 409 means something different in each. Before the ladder it is a
/// missing parent, which is the ordinary first write against a fresh remote.
/// After the ladder the parents exist, so the only reading left is that one of
/// them is not a collection at all - an ordinary file where a directory was
/// expected. That is not something a retry fixes, so it is reported as a
/// refusal naming the parent rather than as a conflict, whose documented
/// disposition is to re-read and try again.
pub fn classify_put(status: u16, key: &str, retried: bool) -> Result<Option<()>, ProviderError> {
    match status {
        200..=299 => Ok(Some(())),
        409 if !retried => Ok(None),
        409 => {
            let parent = ancestors(key).pop().unwrap_or_else(|| "/".to_string());
            Err(ProviderError::Blocked(format!(
                "blocked: \"{parent}\" exists but is not a collection, so \"{key}\" cannot be stored under it"
            )))
        }
        _ => Err(classify(status)),
    }
}

/// A listing's outcome. `Ok(None)` means the collection is not there, which
/// this provider reads as an empty inventory.
///
/// THAT MAPPING IS A REAL WEAKENING AND IS TAKEN DELIBERATELY. The other
/// backend refuses exactly this, because its protocol tells a missing container
/// apart from an empty one by its error code and only the first is a real
/// failure. Here there is no such code, so a mistyped base path and an empty
/// collection are indistinguishable at this layer.
///
/// What makes it safe is one layer up rather than an argument at this one: the
/// layer above writes a keyfile before any listing can run, through the put
/// ladder, so by the time this is ever reached the base path has already been
/// proven reachable and writable. A 404 here therefore means nothing has been
/// pushed yet, which is precisely the empty case.
///
/// The residue, named rather than argued away: a user who edits their prefix
/// after a successful setup, to another value under the same reachable base
/// path, gets an empty inventory instead of an error - which is also the
/// correct reading of a genuinely fresh prefix.
pub fn classify_list(status: u16) -> Result<Option<()>, ProviderError> {
    match status {
        200..=299 => Ok(Some(())),
        404 => Ok(None),
        _ => Err(classify(status)),
    }
}

/// A delete's outcome. Removing something already gone is not an error.
///
/// A MULTI-STATUS IS A FAILURE HERE even though it is a success status.
/// It reports a per-resource outcome for a request that touched several, and
/// every delete this provider issues names exactly one non-collection - so a
/// multi-status means the server did something other than what was asked, and
/// reading it as success would report a delete that did not happen.
pub fn classify_delete(status: u16) -> Result<(), ProviderError> {
    match status {
        207 => Err(classify(status)),
        200..=299 => Ok(()),
        404 => Ok(()),
        _ => Err(classify(status)),
    }
}

/// A collection creation's outcome.
///
/// A 405 IS SUCCESS, which reads wrong and is not. The verb may only be run
/// against a url that maps to nothing, so a server answers 405 when the
/// collection is already there - which is the state the caller wanted. It is
/// also what two devices racing the same first write see, one each, and both
/// may proceed.
///
/// A 409 IS NOT A CONFLICT TO RETRY, which is why this does not fall through to
/// the shared mapper for it. The ladder is walked shallowest first, so by the
/// time a rung is attempted every rung above it has already succeeded - and the
/// only reading left for a refusal is that the parent is an ordinary file where
/// a collection was needed. Nothing about trying again changes that, so it is
/// reported as a refusal naming the parent. Without this the case is reached
/// BEFORE the put that would have said so, for any prefix whose non-collection
/// is not the deepest one.
pub fn classify_mkcol(status: u16, collection: &str) -> Result<(), ProviderError> {
    match status {
        201 | 405 => Ok(()),
        409 => {
            let parent = ancestors(collection)
                .pop()
                .unwrap_or_else(|| "/".to_string());
            Err(ProviderError::Blocked(format!(
                "blocked: \"{parent}\" exists but is not a collection, so \"{collection}\" cannot be created under it"
            )))
        }
        _ => Err(classify(status)),
    }
}

/// The failure shapes a request can have before it ever gets a status.
///
/// Pure, taking the booleans rather than the error, because this is the ONLY
/// producer of `ProviderError::Transport` here: leaving it in the shell would
/// leave that half of the taxonomy untestable.
///
/// NO REDIRECT BRANCH, unlike the other backend's version. A client built to
/// follow no redirect does not error on one - it hands the 3xx back as an
/// ordinary response - so the refusal is a status and is classified as one.
pub fn transport_error(is_timeout: bool, is_connect: bool, message: String) -> ProviderError {
    if is_timeout {
        return ProviderError::Transport(format!("the remote did not answer in time ({message})"));
    }
    if is_connect {
        return ProviderError::Transport(format!("the remote could not be reached ({message})"));
    }
    ProviderError::Transport(message)
}

/// An etag with its quoting and its weak marker removed, because servers differ
/// on both.
pub fn normalize_etag(raw: &str) -> String {
    raw.trim()
        .trim_start_matches("W/")
        .trim_matches('"')
        .to_string()
}

// --- the hand scan --------------------------------------------------------
//
// A HAND SCAN AND NOT AN XML CRATE, matching the shape the other backend
// already chose and for the same reason: the grammar consumed here is six
// element names in a document the remote generates.
//
// IT MATCHES ON THE LOCAL NAME, which is the one thing that cannot be copied
// from the other backend. That protocol's listing carries no namespace
// prefixes, so searching for a literal `<Key>` is exact; a multi-status body
// has prefixes and the server picks them - one common server emits `D:href`
// and `lp1:getetag` in the same document, others emit `d:href`, and a body
// with a default namespace and no prefixes at all is legal too.
//
// The ceiling, named: matching a local name across namespaces means an element
// from some other namespace sharing a local name would be read. In a
// multi-status body that is not a shape any server produces, and closing it
// properly means a namespace-resolving parser, which is a dependency this tree
// has decided against.

/// One `<`-delimited tag, located.
struct Tag<'a> {
    /// Byte offset of the `<`.
    at: usize,
    /// Byte offset just past the `>`.
    end: usize,
    /// Everything after the last `:` of the element name, so the server's
    /// choice of prefix does not reach any caller.
    name: &'a str,
    closing: bool,
    self_closing: bool,
}

/// Every element tag in `xml`, in order, ignoring declarations and comments.
fn tags(xml: &str) -> Vec<Tag<'_>> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while let Some(rel) = xml[cursor..].find('<') {
        let at = cursor + rel;
        let Some(rel_end) = xml[at..].find('>') else {
            break;
        };
        let end = at + rel_end + 1;
        let inner = &xml[at + 1..end - 1];
        cursor = end;
        // A declaration, a comment or a processing instruction names no
        // element.
        if inner.starts_with('!') || inner.starts_with('?') {
            continue;
        }
        let closing = inner.starts_with('/');
        let self_closing = !closing && inner.ends_with('/');
        let raw = inner
            .trim_start_matches('/')
            .split(|c: char| c.is_ascii_whitespace() || c == '/')
            .next()
            .unwrap_or("");
        if raw.is_empty() {
            continue;
        }
        out.push(Tag {
            at,
            end,
            name: raw.rsplit(':').next().unwrap_or(raw),
            closing,
            self_closing,
        });
    }
    out
}

/// The inner text of every element whose local name is `name`, in order.
///
/// A self-closing element yields the empty string rather than being skipped,
/// so a property the server declined to supply is visible as empty rather than
/// as absent - which is the distinction the status gate below is built on.
fn local_name_blocks<'a>(xml: &'a str, name: &str) -> Vec<&'a str> {
    let tags = tags(xml);
    let mut out = Vec::new();
    let mut i = 0;
    while i < tags.len() {
        let open = &tags[i];
        if open.closing || open.name != name {
            i += 1;
            continue;
        }
        if open.self_closing {
            out.push("");
            i += 1;
            continue;
        }
        let mut depth = 1usize;
        let mut j = i + 1;
        while j < tags.len() {
            let tag = &tags[j];
            if tag.name == name && !tag.self_closing {
                if tag.closing {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                } else {
                    depth += 1;
                }
            }
            j += 1;
        }
        if j == tags.len() {
            // Unterminated: stop rather than returning a block whose end was
            // guessed.
            break;
        }
        out.push(&xml[open.end..tags[j].at]);
        i = j + 1;
    }
    out
}

/// The inner text of the first element whose local name is `name`.
fn local_name_text<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    local_name_blocks(xml, name).into_iter().next()
}

/// Unix MILLISECONDS from the date format a listing's modification time is
/// spelled in, or `None`.
///
/// A DIFFERENT FORMAT FROM THE OTHER BACKEND'S, and reusing that one's parser
/// here would return `None` on every row rather than a wrong instant - which
/// sounds harmless and is not. A row with no stamp is never a candidate for the
/// expiry pass, so expired tombstones would never be pruned from a remote and
/// would accumulate without bound, and an expired remote tombstone would be
/// applied here where the other backend reports it for the user to resolve.
/// Two devices sharing one prefix would then disagree about a delete.
///
/// ONLY THE FIXED-WIDTH FORM IS READ, which is a deliberate narrowing of the
/// general HTTP rule that a recipient accepts three date formats. This value is
/// not an HTTP header field: the protocol defines it as the fixed-width form
/// and names no other, so a compliant generator has one spelling. Against that,
/// the two obsolete parsers are some twenty-five lines whose failure mode is
/// `None` - the conservative direction, since a row with no stamp is never
/// mistaken for expired. If a real server is ever found emitting one, this is
/// additive.
///
/// Shares the era arithmetic in
/// `src-tauri/src/modules/sync/providers/sigv4.rs` rather than carrying a
/// second copy of it.
pub fn parse_http_date(s: &str) -> Option<u64> {
    let s = s.trim();
    let b = s.as_bytes();
    // `Sun, 06 Nov 1994 08:49:37 GMT` and nothing else: every separator is at a
    // fixed offset and the whole thing is exactly this long.
    if b.len() != 29
        || b[3] != b','
        || b[4] != b' '
        || b[7] != b' '
        || b[11] != b' '
        || b[16] != b' '
        || b[19] != b':'
        || b[22] != b':'
        || b[25] != b' '
        || &s[26..] != "GMT"
    {
        return None;
    }
    let num = |from: usize, to: usize| -> Option<u32> {
        let part = s.get(from..to)?;
        if !part.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        part.parse().ok()
    };
    // The day name is not checked. It is redundant with the date beside it, and
    // a recipient is told to ignore it rather than to validate it.
    let day = num(5, 7)?;
    let month = match &s[8..11] {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let year = num(12, 16)? as i64;
    let hour = num(17, 19)?;
    let minute = num(20, 22)?;
    let second = num(23, 25)?;
    if !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let secs = sigv4::days_from_civil(year, month, day) * 86_400
        + hour as i64 * 3600
        + minute as i64 * 60
        + second as i64;
    if secs < 0 {
        return None;
    }
    Some(secs as u64 * 1000)
}

/// The path half of an `href`, which a server may spell as a whole URL or as an
/// absolute path.
///
/// Both spellings are handled per row even though a server has to pick one and
/// stay with it across a response, because handling both costs nothing and
/// relying on that consistency buys nothing.
fn href_path(href: &str) -> String {
    // UNESCAPED FIRST, BEFORE ANYTHING PARSES IT. The XML escaping is the outer
    // layer: an ampersand in a name reaches this as five characters, and a url
    // parser handed those would keep them.
    let href = unescape(href.trim());
    match url::Url::parse(&href) {
        Ok(url) => url.path().to_string(),
        // Not a whole URL, so it is the absolute-path spelling - which may
        // carry a query the path does not include.
        Err(_) => href.split('?').next().unwrap_or(&href).to_string(),
    }
}

fn segments(path: &str) -> Vec<&str> {
    path.split('/').filter(|s| !s.is_empty()).collect()
}

/// The five predefined XML entities, expanded.
///
/// `&amp;` LAST, or an escaped entity would be double-expanded: a literal
/// ampersand-l-t written as five characters would come back as a less-than sign
/// rather than as the four characters it names.
///
/// A SECOND COPY OF THE OTHER BACKEND'S, kept rather than shared for the reason
/// `src-tauri/src/modules/sync/providers/sigv4.rs` gives about its own hex fold:
/// the two sit behind a boundary whose whole stated property is that a backend
/// is one file reachable through one dispatch arm, and a helper reaching across
/// that boundary would be the first thing to make adding a third backend touch
/// a second one.
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

/// Whether a status line carries a success code.
fn is_ok_status(line: &str) -> bool {
    line.split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .is_some_and(|code| (200..300).contains(&code))
}

/// One property of one row, read ONLY from a group the server reported success
/// for.
///
/// THE GATE IS THE POINT OF THIS FUNCTION. A property the server will not
/// supply comes back as an EMPTY element inside a group whose own status is a
/// failure - which is routine for an etag on a collection - so a scan of the
/// whole row would find the empty one and store an empty etag. That failure is
/// permanent and silent: the empty etag stored by one pull equals the empty
/// etag the next pull reads, so the record is skipped on every later pull even
/// after its contents change, for the life of the prefix.
///
/// Gated on success rather than on "not missing", because a server may decline
/// a property with a forbidden status just as readily as with a missing one.
///
/// THE VALUE IS UNESCAPED, and an etag is the reason that is not optional. A
/// server is free to escape a quotation mark in a text node and at least one
/// common one does, so the listing would carry an etag spelled differently from
/// the one the same server puts in a response HEADER - and those two are
/// compared against each other by the layer above. Storing the escaped spelling
/// makes that comparison fail on every row forever, which turns every pull into
/// a full download of the whole inventory.
fn prop_of(row: &str, name: &str) -> Option<String> {
    for group in local_name_blocks(row, "propstat") {
        let Some(status) = local_name_text(group, "status") else {
            continue;
        };
        if !is_ok_status(status) {
            continue;
        }
        let Some(props) = local_name_text(group, "prop") else {
            continue;
        };
        if let Some(value) = local_name_text(props, name) {
            return Some(unescape(value));
        }
    }
    None
}

fn is_collection(row: &str) -> bool {
    local_name_blocks(row, "resourcetype")
        .iter()
        .any(|kind| !local_name_blocks(kind, "collection").is_empty())
}

/// The rows of a listing.
///
/// `request_path` is the server-side path that was asked for, and is read only
/// for its SEGMENT COUNT: a child of the requested collection has exactly one
/// segment more. Counting separators rather than comparing the two paths as
/// strings is what makes the self-entry every listing contains drop out, and it
/// survives the server spelling the user's prefix with a different escaping
/// than we sent, since the number of separators is invariant under any legal
/// one. A trailing slash on a collection stops mattering for the same reason.
///
/// `prefix` is the key prefix as the caller asked for it, ending in a
/// separator, and the key of a row is that prefix plus the row's last segment
/// TAKEN VERBATIM. Not decoded: the names the layer above composes are hex, so
/// no server escapes one, and the other half of the key comes from the request
/// rather than from the response - so a decoder here would be code that
/// provably never changes a byte. The residue, named: this couples the provider
/// to the naming scheme one layer up, and if that scheme ever emits a character
/// needing an escape, this is where it is noticed.
///
/// ITS DISCRIMINATOR IS THE ROOT ELEMENT, and that is the load-bearing part.
/// Keying on a row element instead would read an HTML error page and a
/// legitimately empty collection as the same thing. An empty listing where the
/// remote actually holds objects is a silent "your inventory is empty": every
/// remote record reads as one this device alone has, so the pass re-uploads the
/// whole inventory over whatever is already there and reports nothing wrong.
pub fn parse_multistatus(
    bytes: &[u8],
    request_path: &str,
    prefix: &str,
) -> Result<Vec<Entry>, ProviderError> {
    let body = std::str::from_utf8(bytes)
        .map_err(|e| ProviderError::Malformed(format!("the listing did not decode: {e}")))?;
    let Some(inside) = local_name_text(body, "multistatus") else {
        return Err(ProviderError::Malformed(
            "the listing carried no multistatus element".to_string(),
        ));
    };

    let depth = segments(request_path).len();
    let mut entries = Vec::new();
    for row in local_name_blocks(inside, "response") {
        let href = local_name_text(row, "href").ok_or_else(|| {
            ProviderError::Malformed("a listing row carried no href element".to_string())
        })?;
        let path = href_path(href);
        let found = segments(&path);
        if found.len() != depth + 1 {
            continue;
        }
        // A belt beside the segment count: the requested collection's own entry
        // is already gone by depth, and a nested collection cannot appear at
        // this depth in a flat namespace, but neither of those is this
        // provider's to guarantee.
        if is_collection(row) {
            continue;
        }
        // A MEMBER THE SERVER WOULD NOT DESCRIBE AT ALL is skipped, where a
        // member it described badly is refused below. The two are different
        // shapes and want opposite answers: a row carrying an href and a bare
        // status, with no property groups whatsoever, is what a server sends
        // for a file it could not stat - a permissions refusal, a broken link -
        // and refusing the whole listing over one of those would strand the
        // entire prefix on every pull while every other row was readable. A row
        // that DOES carry property groups and still yields no usable etag is a
        // server contradicting itself, and that is refused.
        if local_name_blocks(row, "propstat").is_empty() {
            continue;
        }
        let key = format!("{prefix}{}", found[found.len() - 1]);
        // AN ABSENT OR EMPTY ETAG IS REFUSED RATHER THAN DEFAULTED, the same
        // rule the object read applies: the empty string is not an etag, and
        // storing one makes the row match itself forever.
        let etag = prop_of(row, "getetag")
            .map(|e| normalize_etag(&e))
            .filter(|e| !e.is_empty())
            .ok_or_else(|| {
                ProviderError::Malformed(format!("the listing row for \"{key}\" carried no etag"))
            })?;
        entries.push(Entry {
            key,
            etag,
            modified_at: prop_of(row, "getlastmodified")
                .as_deref()
                .and_then(parse_http_date),
        });
    }
    Ok(entries)
}

// --- the shell ------------------------------------------------------------

/// What a send came back with, before anything is decided about it.
struct RawResponse {
    status: u16,
    etag: Option<String>,
    body: Vec<u8>,
}

pub struct WebDavProvider {
    /// The endpoint as the user typed it, which is what the guard below reads.
    endpoint_url: String,
    endpoint: Endpoint,
    /// Computed once at construction, so the password is not carried around in
    /// a second, plainer form for the life of the provider.
    auth: String,
    client: reqwest::Client,
    /// Set once the endpoint has PASSED the guard, and never otherwise.
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
    /// not exist.
    endpoint_allowed: tokio::sync::OnceCell<()>,
}

/// Which disposition a refusal from the guard is.
///
/// Keyed on the guard's OWN vocabulary: it prefixes a refusal with `blocked:`
/// and says so in plain words for a resolution that did not answer. A dropped
/// network is a transport failure, not a policy decision, and the two want
/// opposite things from the caller.
fn guard_failure(why: String) -> ProviderError {
    if why.starts_with("blocked:") {
        ProviderError::Blocked(why)
    } else {
        ProviderError::Transport(why)
    }
}

impl WebDavProvider {
    pub fn new(cfg: WebDavConfig) -> Result<Self, ProviderError> {
        // Fail here rather than at the first request, so a provider that exists
        // is one that can address something.
        let endpoint = endpoint(&cfg)?;
        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| {
                ProviderError::Config(format!("the sync http client could not be built: {e}"))
            })?;
        Ok(Self {
            auth: basic_auth(&cfg.username, &cfg.password),
            endpoint_url: cfg.endpoint,
            endpoint,
            client,
            endpoint_allowed: tokio::sync::OnceCell::new(),
        })
    }

    async fn allowed(&self) -> Result<(), ProviderError> {
        if self.endpoint_allowed.initialized() {
            return Ok(());
        }
        crate::modules::net::reject_metadata_ssrf(&self.endpoint_url)
            .await
            .map_err(guard_failure)?;
        // Two first calls racing here both run the guard and both set this.
        // That costs one extra resolution and cannot disagree, which is cheaper
        // than the lock that would prevent it.
        let _ = self.endpoint_allowed.set(());
        Ok(())
    }

    async fn send(
        &self,
        req: DavRequest,
        body: Option<&[u8]>,
    ) -> Result<RawResponse, ProviderError> {
        let method = match req.method {
            "GET" => reqwest::Method::GET,
            "PUT" => reqwest::Method::PUT,
            "DELETE" => reqwest::Method::DELETE,
            // Not in the http crate's table of standard methods, so they are
            // built from their bytes. Both are upper-case ASCII tokens, which
            // is the only shape that construction can refuse.
            name @ ("PROPFIND" | "MKCOL") => {
                reqwest::Method::from_bytes(name.as_bytes()).map_err(|e| {
                    ProviderError::Config(format!("the {name} method could not be built: {e}"))
                })?
            }
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
            builder = builder.body(body.to_vec());
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
    transport_error(e.is_timeout(), e.is_connect(), e.to_string())
}

impl SyncProvider for WebDavProvider {
    fn id(&self) -> &'static str {
        "webdav"
    }

    /// A CONSTANT, not a stored toggle. The other backend asks the user because
    /// the servers behind it disagree and only the user knows which one they
    /// run; here there is no protocol guarantee for the user to report.
    fn capabilities(&self) -> Caps {
        Caps { cas: false }
    }

    fn get<'a>(
        &'a self,
        key: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Object>, ProviderError>> + Send + 'a>> {
        Box::pin(async move {
            self.allowed().await?;
            let raw = self
                .send(build_get(&self.endpoint, &self.auth, key), None)
                .await?;
            if classify_get(raw.status)?.is_none() {
                return Ok(None);
            }
            // SYMMETRIC WITH `put`, which refuses the same absence. An empty
            // string is not an etag, and handing one back would have the row
            // match itself on every later pull.
            let etag = raw.etag.ok_or_else(|| {
                ProviderError::Malformed("the remote returned an object with no etag".to_string())
            })?;
            Ok(Some(Object {
                etag,
                bytes: raw.body,
            }))
        })
    }

    /// `_if_match` is taken and dropped. See [`build_put`]: this backend cannot
    /// express a condition, reports that through its capabilities, and degrades
    /// to last-write-wins rather than failing a caller that passes one.
    fn put<'a>(
        &'a self,
        key: &'a str,
        bytes: Vec<u8>,
        _if_match: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = Result<String, ProviderError>> + Send + 'a>> {
        Box::pin(async move {
            self.allowed().await?;
            let first = self
                .send(
                    build_put(&self.endpoint, &self.auth, key),
                    Some(bytes.as_slice()),
                )
                .await?;
            let stored = match classify_put(first.status, key, false)? {
                Some(()) => first,
                None => {
                    // The parents are missing, which is the ordinary first write
                    // against a fresh remote. One rung at a time, shallowest
                    // first, then exactly one more attempt.
                    for collection in ancestors(key) {
                        let made = self
                            .send(build_mkcol(&self.endpoint, &self.auth, &collection), None)
                            .await?;
                        classify_mkcol(made.status, &collection)?;
                    }
                    let again = self
                        .send(
                            build_put(&self.endpoint, &self.auth, key),
                            Some(bytes.as_slice()),
                        )
                        .await?;
                    classify_put(again.status, key, true)?;
                    again
                }
            };
            stored.etag.ok_or_else(|| {
                ProviderError::Malformed(
                    "the remote stored the object but returned no etag".to_string(),
                )
            })
        })
    }

    /// ONE REQUEST, WITH NO PAGINATION TO FOLLOW. This protocol has no
    /// continuation token, so there is no page to accumulate and no
    /// never-terminating listing to guard against.
    fn list<'a>(
        &'a self,
        prefix: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Entry>, ProviderError>> + Send + 'a>> {
        Box::pin(async move {
            self.allowed().await?;
            let raw = self
                .send(
                    build_propfind(&self.endpoint, &self.auth, prefix),
                    Some(PROPFIND_BODY.as_bytes()),
                )
                .await?;
            if classify_list(raw.status)?.is_none() {
                return Ok(Vec::new());
            }
            parse_multistatus(&raw.body, &object_path(&self.endpoint, prefix), prefix)
        })
    }

    fn delete<'a>(
        &'a self,
        key: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>> {
        Box::pin(async move {
            self.allowed().await?;
            let raw = self
                .send(build_delete(&self.endpoint, &self.auth, key), None)
                .await?;
            classify_delete(raw.status)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> WebDavConfig {
        WebDavConfig {
            endpoint: "https://cloud.example/remote.php/dav/files/rendi".to_string(),
            username: "rendi".to_string(),
            password: "hunter2".to_string(),
        }
    }

    fn ep() -> Endpoint {
        endpoint(&cfg()).expect("the test endpoint parses")
    }

    fn header<'a>(req: &'a DavRequest, name: &str) -> Option<&'a str> {
        req.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    // --- the endpoint and the urls ----------------------------------------

    #[test]
    fn an_endpoint_that_is_not_a_usable_url_is_refused() {
        for bad in [
            "not a url",
            "ftp://dav.example",
            "https://",
            "https://cloud.example/dav%20files",
        ] {
            let mut cfg = cfg();
            cfg.endpoint = bad.to_string();
            let err = endpoint(&cfg)
                .err()
                .unwrap_or_else(|| panic!("{bad} must be refused"));
            assert!(
                matches!(err, ProviderError::Config(_)),
                "{bad} gave {err:?}"
            );
        }
    }

    #[test]
    fn an_object_url_joins_the_base_path_and_the_key_with_one_separator() {
        assert_eq!(
            object_url(&ep(), "tervia/v1/obj/ab12"),
            "https://cloud.example/remote.php/dav/files/rendi/tervia/v1/obj/ab12"
        );

        // A mount at the root, and an endpoint whose trailing slash the user
        // typed: neither may double or drop a separator.
        let mut bare = cfg();
        bare.endpoint = "https://cloud.example/".to_string();
        assert_eq!(
            object_url(&endpoint(&bare).unwrap(), "v1/keyfile"),
            "https://cloud.example/v1/keyfile"
        );

        // A non-ASCII segment, which reaches here because the layer above
        // composes the key from a user-typed prefix.
        assert_eq!(
            object_url(&ep(), "caf\u{e9}/obj"),
            "https://cloud.example/remote.php/dav/files/rendi/caf%C3%A9/obj"
        );
    }

    #[test]
    fn basic_auth_is_the_pair_joined_by_a_colon_and_encoded() {
        // Hand-computed: `u:p` is the three bytes 0x75 0x3a 0x70, which pack
        // into `dTpw`.
        assert_eq!(basic_auth("u", "p"), "Basic dTpw");
    }

    // --- the collection ladder --------------------------------------------

    #[test]
    fn ancestors_are_every_parent_collection_shallowest_first() {
        assert_eq!(
            ancestors("tervia/v1/obj/ab12"),
            vec!["tervia", "tervia/v1", "tervia/v1/obj"]
        );
        // The empty-user-prefix spelling the layer above produces.
        assert_eq!(ancestors("v1/keyfile"), vec!["v1"]);
        // A key at the root names no collection, so nothing is created.
        assert!(ancestors("keyfile").is_empty());
    }

    // --- the request builders ---------------------------------------------

    #[test]
    fn every_request_carries_the_credential_and_only_the_listing_carries_a_type() {
        let auth = basic_auth("rendi", "hunter2");
        let ep = ep();

        let put = build_put(&ep, &auth, "tervia/v1/obj/ab12");
        assert_eq!(put.method, "PUT");
        assert_eq!(header(&put, "authorization"), Some(auth.as_str()));
        // A sealed envelope has no meaningful media type and nothing reads one
        // back, so the server picks its default.
        assert_eq!(header(&put, "content-type"), None);

        let propfind = build_propfind(&ep, &auth, "tervia/v1/obj/");
        assert_eq!(propfind.method, "PROPFIND");
        assert_eq!(header(&propfind, "depth"), Some("1"));
        assert_eq!(
            header(&propfind, "content-type"),
            Some("application/xml; charset=\"utf-8\"")
        );

        for req in [
            build_get(&ep, &auth, "tervia/v1/keyfile"),
            build_delete(&ep, &auth, "tervia/v1/obj/ab12"),
            build_mkcol(&ep, &auth, "tervia/v1"),
        ] {
            assert_eq!(header(&req, "authorization"), Some(auth.as_str()));
        }
    }

    #[test]
    fn a_formatted_request_does_not_print_the_credential() {
        let auth = basic_auth("rendi", "hunter2");
        let printed = format!("{:?}", build_get(&ep(), &auth, "tervia/v1/keyfile"));
        assert!(printed.contains("<redacted>"), "{printed}");
        assert!(!printed.contains(&auth), "{printed}");
    }

    // --- status mapping ---------------------------------------------------

    #[test]
    fn a_missing_object_is_the_ordinary_answer_and_an_unauthorized_one_is_not() {
        assert_eq!(classify_get(404), Ok(None));
        assert_eq!(classify_get(200), Ok(Some(())));
        let err = classify_get(401).expect_err("401 is a failure");
        assert!(
            matches!(err, ProviderError::Remote { status: 401, .. }),
            "{err:?}"
        );
    }

    #[test]
    fn a_missing_collection_lists_as_empty() {
        assert_eq!(classify_list(404), Ok(None));
        // A listing answers multi-status, which is a success code.
        assert_eq!(classify_list(207), Ok(Some(())));
        assert!(classify_list(403).is_err());
    }

    #[test]
    fn deleting_something_already_gone_is_not_an_error_but_a_partial_delete_is() {
        assert_eq!(classify_delete(404), Ok(()));
        assert_eq!(classify_delete(204), Ok(()));
        assert!(classify_delete(207).is_err());
    }

    #[test]
    fn a_collection_that_already_exists_is_a_created_collection() {
        assert_eq!(classify_mkcol(201, "tervia/v1"), Ok(()));
        assert_eq!(classify_mkcol(405, "tervia/v1"), Ok(()));

        // A rung refused after every rung above it succeeded can only mean the
        // parent is an ordinary file, and that must NOT come back as the
        // retry-and-hope disposition: the ladder is walked before the put that
        // would otherwise be the one to say so, so for any prefix whose
        // non-collection is not the deepest ancestor this is the only place the
        // user is told what is actually wrong.
        let err = classify_mkcol(409, "tervia/v1").expect_err("a refused rung is a failure");
        assert!(
            matches!(&err, ProviderError::Blocked(m) if m.contains("tervia")),
            "{err:?}"
        );
        assert_ne!(err, ProviderError::Conflict);
    }

    #[test]
    fn a_conflict_means_make_the_parents_once_and_then_means_the_parent_is_a_file() {
        let key = "tervia/v1/obj/ab12";
        assert_eq!(classify_put(409, key, false), Ok(None));
        assert_eq!(classify_put(201, key, false), Ok(Some(())));
        assert_eq!(classify_put(204, key, true), Ok(Some(())));
        assert!(classify_put(507, key, false).is_err());

        // After the ladder the disposition must NOT be the retry one: the
        // parents exist, so a conflict means one of them is not a collection.
        let err = classify_put(409, key, true).expect_err("a second conflict is a failure");
        assert!(
            matches!(&err, ProviderError::Blocked(m) if m.contains("tervia/v1/obj")),
            "{err:?}"
        );
    }

    #[test]
    fn a_refused_redirect_arrives_as_a_status_and_not_as_a_transport_failure() {
        // The client follows none, and a client that follows none does not
        // error on one - it hands the response back with its 3xx status.
        for status in [302, 307] {
            assert!(
                matches!(classify(status), ProviderError::Blocked(_)),
                "{status} was not refused"
            );
        }
        // Every shape that never got a status is a transport failure, and none
        // of them is a policy refusal.
        for (timeout, connect, why) in [
            (true, false, "timed out"),
            (false, true, "connection refused"),
            (false, false, "the stream broke"),
        ] {
            assert!(
                matches!(
                    transport_error(timeout, connect, why.to_string()),
                    ProviderError::Transport(_)
                ),
                "{why}"
            );
        }
        // The guard's own vocabulary decides its disposition: a refusal is a
        // policy decision, a resolution that did not answer is a dropped
        // network worth retrying.
        assert!(matches!(
            guard_failure("blocked: link-local / cloud-metadata address".to_string()),
            ProviderError::Blocked(_)
        ));
        assert!(matches!(
            guard_failure("dns resolve failed: no such host".to_string()),
            ProviderError::Transport(_)
        ));
    }

    // --- the date ---------------------------------------------------------

    #[test]
    fn the_listing_date_format_parses_to_milliseconds() {
        assert_eq!(
            parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(784_111_777_000)
        );
        assert_eq!(
            parse_http_date("Mon, 12 Jan 1998 09:25:56 GMT"),
            Some(884_597_156_000)
        );
    }

    #[test]
    fn the_obsolete_date_formats_and_a_nonsense_one_are_refused() {
        for bad in [
            // The two obsolete spellings, deliberately not read.
            "Sunday, 06-Nov-94 08:49:37 GMT",
            "Sun Nov  6 08:49:37 1994",
            // A zone that is not the one the format fixes.
            "Sun, 06 Nov 1994 08:49:37 UTC",
            "Sun, 06 Nov 1994 08:49:37 +0000",
            "Sun, 06 Xyz 1994 08:49:37 GMT",
            "Sun, 06 Nov 1994 08:49:6a GMT",
            "",
        ] {
            assert_eq!(parse_http_date(bad), None, "{bad} was read as a date");
        }
    }

    // --- the listing ------------------------------------------------------

    /// One row of a fixture, before a namespace spelling is chosen for it.
    struct Row {
        href: &'static str,
        etag: &'static str,
        modified: &'static str,
        collection: bool,
    }

    fn file(href: &'static str, etag: &'static str) -> Row {
        Row {
            href,
            etag,
            modified: "Mon, 12 Jan 1998 09:25:56 GMT",
            collection: false,
        }
    }

    /// A listing body in one of the namespace spellings a server may choose:
    /// `"D"` and `"d"` for a prefixed document, `""` for a default namespace
    /// with no prefixes at all.
    fn fixture(ns: &str, rows: &[Row]) -> String {
        let (decl, p) = if ns.is_empty() {
            (" xmlns=\"DAV:\"".to_string(), String::new())
        } else {
            (format!(" xmlns:{ns}=\"DAV:\""), format!("{ns}:"))
        };
        let mut out = format!("<?xml version=\"1.0\"?><{p}multistatus{decl}>");
        for row in rows {
            let kind = if row.collection {
                format!("<{p}collection/>")
            } else {
                String::new()
            };
            out.push_str(&format!(
                "<{p}response><{p}href>{}</{p}href><{p}propstat><{p}prop>\
                 <{p}getetag>{}</{p}getetag><{p}getlastmodified>{}</{p}getlastmodified>\
                 <{p}resourcetype>{kind}</{p}resourcetype>\
                 </{p}prop><{p}status>HTTP/1.1 200 OK</{p}status></{p}propstat></{p}response>",
                row.href, row.etag, row.modified
            ));
        }
        out.push_str(&format!("</{p}multistatus>"));
        out
    }

    const REQUEST_PATH: &str = "/remote.php/dav/files/rendi/tervia/v1/obj/";
    const PREFIX: &str = "tervia/v1/obj/";

    fn parse(body: &str) -> Result<Vec<Entry>, ProviderError> {
        parse_multistatus(body.as_bytes(), REQUEST_PATH, PREFIX)
    }

    #[test]
    fn the_namespace_prefix_a_server_chose_does_not_reach_the_result() {
        let rows = || {
            vec![
                Row {
                    href: "/remote.php/dav/files/rendi/tervia/v1/obj/",
                    etag: "\"self\"",
                    modified: "Mon, 12 Jan 1998 09:25:56 GMT",
                    collection: true,
                },
                file("/remote.php/dav/files/rendi/tervia/v1/obj/ab12", "\"one\""),
                file(
                    "/remote.php/dav/files/rendi/tervia/v1/obj/cd34",
                    "W/\"two\"",
                ),
            ]
        };
        let expected = vec![
            Entry {
                key: "tervia/v1/obj/ab12".to_string(),
                etag: "one".to_string(),
                modified_at: Some(884_597_156_000),
            },
            Entry {
                key: "tervia/v1/obj/cd34".to_string(),
                etag: "two".to_string(),
                modified_at: Some(884_597_156_000),
            },
        ];
        // Byte-identical across all three spellings, and the requested
        // collection's own entry is in none of them.
        for ns in ["D", "d", ""] {
            assert_eq!(parse(&fixture(ns, &rows())).unwrap(), expected, "ns {ns:?}");
        }
    }

    #[test]
    fn a_trailing_slash_on_a_row_does_not_change_its_key() {
        // Named by the issue this file answers. Discharged by the segment
        // count rather than by a case of its own: empty segments are dropped,
        // so only the requested collection's own entry can carry one at all.
        let with = fixture(
            "d",
            &[file(
                "/remote.php/dav/files/rendi/tervia/v1/obj/ab12/",
                "\"x\"",
            )],
        );
        let without = fixture(
            "d",
            &[file(
                "/remote.php/dav/files/rendi/tervia/v1/obj/ab12",
                "\"x\"",
            )],
        );
        let rows = parse(&with).unwrap();
        // Not vacuous: both sides really produced the row, rather than both
        // producing nothing.
        assert_eq!(rows.len(), 1);
        assert_eq!(rows, parse(&without).unwrap());
    }

    #[test]
    fn an_href_spelled_as_a_whole_url_or_carrying_a_query_yields_the_same_key() {
        let path = fixture(
            "d",
            &[file(
                "/remote.php/dav/files/rendi/tervia/v1/obj/ab12",
                "\"x\"",
            )],
        );
        let absolute = fixture(
            "d",
            &[file(
                "https://cloud.example/remote.php/dav/files/rendi/tervia/v1/obj/ab12",
                "\"x\"",
            )],
        );
        let queried = fixture(
            "d",
            &[file(
                "/remote.php/dav/files/rendi/tervia/v1/obj/ab12?v=2",
                "\"x\"",
            )],
        );
        let expected = parse(&path).unwrap();
        assert_eq!(expected.len(), 1);
        assert_eq!(parse(&absolute).unwrap(), expected);
        assert_eq!(parse(&queried).unwrap(), expected);
    }

    #[test]
    fn an_escaped_value_is_expanded_before_it_is_stored() {
        // At least one common server escapes a quotation mark in a text node,
        // and the same server puts the unescaped spelling in a response HEADER.
        // Those two are compared against each other one layer up, so storing
        // the escaped form would make the comparison fail on every row forever
        // and turn every pull into a full download of the inventory.
        let body = "<?xml version=\"1.0\"?><d:multistatus xmlns:d=\"DAV:\"><d:response>\
             <d:href>/remote.php/dav/files/rendi/tervia/v1/obj/ab12</d:href>\
             <d:propstat><d:prop><d:getetag>&quot;66a1f2&quot;</d:getetag></d:prop>\
             <d:status>HTTP/1.1 200 OK</d:status></d:propstat>\
             </d:response></d:multistatus>";
        let entries = parse(body).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].etag, "66a1f2");
    }

    #[test]
    fn a_member_the_server_would_not_describe_is_skipped_rather_than_fatal() {
        // A row carrying an href and a bare status, with no property groups at
        // all, is what a server sends for a member it could not stat. Refusing
        // the listing over one of those would strand the whole prefix on every
        // pull while every other row was perfectly readable.
        let body = "<?xml version=\"1.0\"?><D:multistatus xmlns:D=\"DAV:\"><D:response>\
             <D:href>/remote.php/dav/files/rendi/tervia/v1/obj/bad1</D:href>\
             <D:status>HTTP/1.1 403 Forbidden</D:status></D:response><D:response>\
             <D:href>/remote.php/dav/files/rendi/tervia/v1/obj/ab12</D:href>\
             <D:propstat><D:prop><D:getetag>\"good\"</D:getetag></D:prop>\
             <D:status>HTTP/1.1 200 OK</D:status></D:propstat>\
             </D:response></D:multistatus>";
        let entries = parse(body).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key, "tervia/v1/obj/ab12");
    }

    #[test]
    fn a_collection_sitting_among_the_objects_is_not_one_of_them() {
        // Not the requested collection's own entry, which the segment count
        // already drops - a nested one, at the same depth as the objects,
        // which somebody made in the file browser. Read as an object it would
        // be fetched and then quarantined on every pull.
        let body = fixture(
            "d",
            &[
                Row {
                    href: "/remote.php/dav/files/rendi/tervia/v1/obj/notes/",
                    etag: "\"dir\"",
                    modified: "Mon, 12 Jan 1998 09:25:56 GMT",
                    collection: true,
                },
                file("/remote.php/dav/files/rendi/tervia/v1/obj/ab12", "\"one\""),
            ],
        );
        let entries = parse(&body).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key, "tervia/v1/obj/ab12");
    }

    /// A row carrying two property groups: one the server refused, holding an
    /// empty value, and one it answered, holding the real one.
    fn two_group_row(failing_status: &str) -> String {
        format!(
            "<?xml version=\"1.0\"?><d:multistatus xmlns:d=\"DAV:\"><d:response>\
             <d:href>/remote.php/dav/files/rendi/tervia/v1/obj/ab12</d:href>\
             <d:propstat><d:prop><d:getetag/></d:prop>\
             <d:status>{failing_status}</d:status></d:propstat>\
             <d:propstat><d:prop><d:getetag>\"real\"</d:getetag>\
             <d:getlastmodified>Mon, 12 Jan 1998 09:25:56 GMT</d:getlastmodified></d:prop>\
             <d:status>HTTP/1.1 200 OK</d:status></d:propstat>\
             </d:response></d:multistatus>"
        )
    }

    #[test]
    fn a_property_is_read_only_from_a_group_the_server_answered() {
        // The refused group holds an empty etag. Storing that would make the
        // row match itself on every later pull, so the record would be skipped
        // forever even after its contents changed.
        for status in ["HTTP/1.1 404 Not Found", "HTTP/1.1 403 Forbidden"] {
            let entries = parse(&two_group_row(status)).unwrap();
            assert_eq!(entries.len(), 1, "{status}");
            assert_eq!(entries[0].etag, "real", "{status}");
            assert_eq!(entries[0].modified_at, Some(884_597_156_000), "{status}");
        }
    }

    #[test]
    fn a_row_whose_only_answer_is_a_refusal_is_malformed_rather_than_empty() {
        let body = "<?xml version=\"1.0\"?><d:multistatus xmlns:d=\"DAV:\"><d:response>\
             <d:href>/remote.php/dav/files/rendi/tervia/v1/obj/ab12</d:href>\
             <d:propstat><d:prop><d:getetag/></d:prop>\
             <d:status>HTTP/1.1 403 Forbidden</d:status></d:propstat>\
             </d:response></d:multistatus>";
        let err = parse(body).expect_err("an etagless row is refused");
        assert!(
            matches!(&err, ProviderError::Malformed(m) if m.contains("ab12")),
            "{err:?}"
        );
    }

    #[test]
    fn a_body_that_is_not_a_listing_is_malformed_and_an_empty_listing_is_not() {
        // An error page read as an empty inventory is a pile of deletes.
        let page = b"<html><body><h1>404 Not Found</h1></body></html>";
        let err = parse_multistatus(page, REQUEST_PATH, PREFIX)
            .expect_err("an html page is not a listing");
        assert!(matches!(err, ProviderError::Malformed(_)), "{err:?}");

        // A collection holding nothing still answers with its own entry.
        let only_self = fixture(
            "d",
            &[Row {
                href: "/remote.php/dav/files/rendi/tervia/v1/obj/",
                etag: "\"self\"",
                modified: "Mon, 12 Jan 1998 09:25:56 GMT",
                collection: true,
            }],
        );
        assert_eq!(parse(&only_self).unwrap(), vec![]);
    }

    #[test]
    fn a_listing_row_with_no_href_is_malformed() {
        let body = "<?xml version=\"1.0\"?><d:multistatus xmlns:d=\"DAV:\"><d:response>\
             <d:propstat><d:prop><d:getetag>\"x\"</d:getetag></d:prop>\
             <d:status>HTTP/1.1 200 OK</d:status></d:propstat>\
             </d:response></d:multistatus>";
        assert!(matches!(parse(body), Err(ProviderError::Malformed(_))));
    }

    // --- the guard --------------------------------------------------------

    #[tokio::test]
    async fn the_metadata_service_is_refused_before_a_socket_is_opened() {
        // Offline by construction: the first is an IP literal, so resolving it
        // opens nothing, and the second is refused by name before resolution.
        for endpoint in [
            "http://169.254.169.254/dav",
            "http://metadata.google.internal/dav",
        ] {
            let mut cfg = cfg();
            cfg.endpoint = endpoint.to_string();
            let provider = WebDavProvider::new(cfg).expect("the endpoint parses");
            let err = provider
                .get("tervia/v1/keyfile")
                .await
                .expect_err("the guard must refuse");
            assert!(
                matches!(err, ProviderError::Blocked(_)),
                "{endpoint} gave {err:?}"
            );
        }
    }

    // --- what this file ships ---------------------------------------------

    /// The shipped half of this file: everything before the test module.
    ///
    /// One assumption, stated because it would otherwise be silent AND checked
    /// because stating it is not enough: the test module is this file's last
    /// item, so splitting at the first configuration attribute leaves exactly
    /// the shipped half. A test-only helper marked anywhere above it would
    /// shrink the scanned region and every needle below would pass over almost
    /// nothing.
    ///
    /// Checked by NAMING THE LAST SHIPPED ITEM rather than by a byte floor. A
    /// floor is a guess that has to be revised whenever either half grows, and
    /// it answers "is this big enough" when the question is "does this reach
    /// the end".
    fn shipped() -> &'static str {
        let source = include_str!("webdav.rs");
        let shipped = source
            .split_once("#[cfg(test)]")
            .expect("the test module is still marked")
            .0;
        assert!(
            shipped.contains("impl SyncProvider for WebDavProvider"),
            "the split landed before the last shipped item, so {} of {} bytes went unscanned",
            source.len() - shipped.len(),
            source.len()
        );
        shipped
    }

    #[test]
    fn this_file_cannot_send_a_conditional_header() {
        // The capability is reported false, so a conditional write would be
        // ignored by the caller anyway. This is the stronger claim: the header
        // is not reachable from this file at all, in any spelling.
        let lowered = shipped().to_ascii_lowercase();
        assert!(
            !lowered.contains("if-match"),
            "the shipped half of this file names the conditional header"
        );
    }

    #[test]
    fn this_file_ships_no_default_host_and_no_credential() {
        // A BACKSTOP OVER A GREP-ABLE SUBSET, not the guarantee. The guarantee
        // is that the configuration has no `Default` impl, which makes a
        // defaulted endpoint unrepresentable rather than merely absent today -
        // and that is the first needle.
        //
        // Deliberately NOT checking the names of particular self-hosted
        // servers: they appear in truthful prose about what this provider
        // supports. A registrable top-level domain does not, because every
        // address in this file's prose uses a reserved one.
        for needle in ["impl Default", ".com", ".net", ".org", ".io"] {
            assert!(
                !shipped().contains(needle),
                "the shipped half of this file carries {needle}"
            );
        }
    }
}
