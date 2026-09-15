//! AWS Signature Version 4, and the two calendar conversions the S3 provider
//! needs.
//!
//! PURE, in the same sense `src-tauri/src/modules/sync/model.rs` is: no
//! network, no filesystem, no clock. [`amz_date`] takes the instant as an
//! argument rather than reading `SystemTime::now` itself, which is the whole
//! reason every request this module signs is reproducible from a test.
//!
//! WRITTEN HERE RATHER THAN PULLED IN, and that is a smaller claim than it
//! sounds. What SigV4 actually is: four chained HMAC-SHA256 calls over a
//! canonical spelling of the request. The spelling is the part worth getting
//! wrong, and the published test suite pins it exactly, so a hand-rolled signer
//! with the suite behind it is checkable in a way a wrapper around a large SDK
//! is not. `ring` is already this crate's crypto backend and supplies both
//! primitives.
//!
//! THE SIGNER DOES NOT NORMALIZE THE REQUEST URI, and that is deliberate rather
//! than missing. S3 does not normalize either, so collapsing a `.` or a `..`
//! segment here would produce a canonical request the service never computed
//! and a signature it rejects. The suite's own `normalize-path` group therefore
//! does NOT apply to an S3 signer and none of its seven cases is used below;
//! `the_canonical_uri_is_the_path_byte_for_byte` pins the opposite property, so
//! adding normalization reddens rather than silently breaking every request.

use std::time::{SystemTime, UNIX_EPOCH};

use ring::{digest, hmac};

/// The algorithm token, which opens the string to sign and the header alike.
const ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// SHA-256 of the empty string, which is the payload hash of every bodyless
/// request.
///
/// Named once rather than recomputed per call, because S3 requires
/// `x-amz-content-sha256` on EVERY verb and three of the four this provider
/// sends carry no body at all.
pub const EMPTY_PAYLOAD_SHA256: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Lowercase hex, which is what every hash and signature in SigV4 is spelled
/// in.
///
/// The same fold `object_name` in `src-tauri/src/modules/sync/crypto.rs` uses.
/// Kept as two copies rather than a shared helper: that one produces a path
/// segment and this one produces a signature component, and they have no
/// reason to move together.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// SHA-256 of `bytes`, hex encoded.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(digest::digest(&digest::SHA256, bytes).as_ref())
}

/// AWS's percent encoding: unreserved characters pass, everything else becomes
/// a percent triplet with UPPERCASE hex digits.
///
/// Two details that are easy to get wrong and that the suite catches. The hex
/// digits are uppercase while every hash is lowercase, so one `hex` helper
/// cannot serve both. And `~` is UNRESERVED here, where several URL encoders
/// escape it.
///
/// `encode_slash` is false for a path, where the separators have to survive,
/// and true for a query component, where a `/` inside a value is data.
pub fn uri_encode(s: &str, encode_slash: bool) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b'/' if !encode_slash => out.push('/'),
            _ => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

/// The headers as the canonical request spells them: names lowercased, values
/// trimmed and their internal whitespace runs collapsed, sorted by name.
///
/// Done HERE rather than expected of the caller, so no builder can produce a
/// canonical request whose header block disagrees with its own
/// `SignedHeaders` list. That disagreement is invisible locally and arrives as
/// a 403 that reads exactly like a wrong secret key.
fn prepared(headers: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = headers
        .iter()
        .map(|(n, v)| {
            (
                n.to_ascii_lowercase(),
                v.split_whitespace().collect::<Vec<_>>().join(" "),
            )
        })
        .collect();
    out.sort();
    out
}

/// The `SignedHeaders` value for a header set: lowercased names, sorted,
/// semicolon separated.
pub fn signed_headers(headers: &[(&str, &str)]) -> String {
    prepared(headers)
        .into_iter()
        .map(|(n, _)| n)
        .collect::<Vec<_>>()
        .join(";")
}

/// The canonical query string: every key and value percent encoded, then the
/// pairs sorted BY THEIR ENCODED FORM and joined.
///
/// Encoding before sorting because the ordering is defined over the bytes that
/// travel. Nothing here pins that, and it is worth saying so rather than
/// implying otherwise: the two orders differ only for keys that straddle a
/// percent escape, and nothing this provider sends is one.
pub fn canonical_query(params: &[(&str, &str)]) -> String {
    let mut pairs: Vec<(String, String)> = params
        .iter()
        .map(|(k, v)| (uri_encode(k, true), uri_encode(v, true)))
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// The canonical request, which is what actually gets hashed and signed.
///
/// `query` is already canonical - see [`canonical_query`] - because a builder
/// needs that same string for the URL it sends, and computing it twice is how
/// the two drift.
///
/// An empty `path` canonicalizes to `/`, which is what the service expects for
/// a request against the bucket root.
pub fn canonical_request(
    method: &str,
    path: &str,
    query: &str,
    headers: &[(&str, &str)],
    payload_hash: &str,
) -> String {
    let prepared = prepared(headers);
    let mut out = String::new();
    out.push_str(method);
    out.push('\n');
    out.push_str(&uri_encode(if path.is_empty() { "/" } else { path }, false));
    out.push('\n');
    out.push_str(query);
    out.push('\n');
    for (name, value) in &prepared {
        out.push_str(name);
        out.push(':');
        out.push_str(value);
        out.push('\n');
    }
    out.push('\n');
    out.push_str(
        &prepared
            .iter()
            .map(|(n, _)| n.as_str())
            .collect::<Vec<_>>()
            .join(";"),
    );
    out.push('\n');
    out.push_str(payload_hash);
    out
}

/// The string to sign, which binds the canonical request to an instant and a
/// scope.
pub fn string_to_sign(amz_date: &str, credential_scope: &str, canonical_request: &str) -> String {
    format!(
        "{ALGORITHM}\n{amz_date}\n{credential_scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    )
}

/// The four chained HMACs that turn a long-lived secret into a key good for one
/// day, one region and one service.
///
/// NO INDEPENDENT ORACLE EXISTS for this value. The published suite holds the
/// final signature and HMAC is one-way, so nothing outside an implementation
/// implies the 32-byte intermediate. Its correctness is carried transitively by
/// the four vectors below, which cannot pass if any link in this chain is
/// wrong.
pub fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> [u8; 32] {
    let mut acc = format!("AWS4{secret}").into_bytes();
    for part in [date, region, service, "aws4_request"] {
        let key = hmac::Key::new(hmac::HMAC_SHA256, &acc);
        acc = hmac::sign(&key, part.as_bytes()).as_ref().to_vec();
    }
    let mut out = [0u8; 32];
    // HMAC-SHA256 is 32 bytes by definition, so this cannot be short.
    out.copy_from_slice(&acc);
    out
}

/// Everything a signature needs that is not the request itself.
///
/// A struct rather than five more parameters on [`authorization_header`],
/// because the four builders in `src-tauri/src/modules/sync/providers/s3.rs`
/// each pass the same five values and a positional mix-up between `region` and
/// `service` would compile.
///
/// NO DERIVED `Debug`, for the reason `SyncKeys` in
/// `src-tauri/src/modules/sync/crypto.rs` has none: a reflexive one prints
/// `secret_access_key` into whatever log line or panic message formats it.
pub struct SigningScope<'a> {
    pub access_key_id: &'a str,
    pub secret_access_key: &'a str,
    /// The `YYYYMMDD` half of the timestamp, from [`amz_date`].
    pub date: &'a str,
    pub region: &'a str,
    pub service: &'a str,
}

impl SigningScope<'_> {
    /// `<date>/<region>/<service>/aws4_request`, which appears both in the
    /// string to sign and in the `Credential` component of the header.
    pub fn credential_scope(&self) -> String {
        format!(
            "{}/{}/{}/aws4_request",
            self.date, self.region, self.service
        )
    }
}

/// The complete `Authorization` value for one request.
pub fn authorization_header(
    scope: &SigningScope,
    amz_date: &str,
    signed_headers: &str,
    canonical_request: &str,
) -> String {
    let credential_scope = scope.credential_scope();
    let to_sign = string_to_sign(amz_date, &credential_scope, canonical_request);
    let key = signing_key(
        scope.secret_access_key,
        scope.date,
        scope.region,
        scope.service,
    );
    let signature =
        hex(hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &key), to_sign.as_bytes()).as_ref());
    format!(
        "{ALGORITHM} Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
        scope.access_key_id
    )
}

// --- the calendar ---------------------------------------------------------
//
// TWO FORMATS, NOT INVERSES, which is why there is no round-trip test between
// them. `amz_date` emits ISO 8601 BASIC at second precision, which is what
// `x-amz-date` requires. `parse_iso8601_utc` reads ISO 8601 EXTENDED with an
// optional fractional part, which is what the `LastModified` element of a
// listing carries, and answers in MILLISECONDS to match `Envelope::updated_at`
// in `src-tauri/src/modules/sync/model.rs`.
//
// The name is not `parse_http_date` deliberately: an HTTP date is the RFC 7231
// form that the `Last-Modified` HEADER carries, which is a different spelling
// of a different field.
//
// This is the only hand-rolled civil arithmetic in the diff, and the signing
// vectors take their timestamp as a literal string, so nothing else in this
// file exercises it.

/// Civil date from a day count since the epoch, by the usual era arithmetic.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Day count since the epoch from a civil date. The inverse of
/// [`civil_from_days`].
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (if m > 2 { m - 3 } else { m + 9 }) as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `("20150830T123600Z", "20150830")` for an instant: the `x-amz-date` value
/// and the date half the credential scope needs.
///
/// A clock set BEFORE the epoch signs as the epoch rather than panicking. That
/// request will be refused by the service for being far outside its clock skew
/// window, which is a better outcome than a crash and is the only honest one
/// available - a machine whose clock reads 1969 cannot sign anything the
/// service will accept.
pub fn amz_date(at: SystemTime) -> (String, String) {
    let secs = at
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (y, m, d) = civil_from_days((secs / 86_400) as i64);
    let rem = secs % 86_400;
    let date = format!("{y:04}{m:02}{d:02}");
    let stamp = format!(
        "{date}T{:02}{:02}{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    );
    (stamp, date)
}

/// Unix MILLISECONDS from an ISO 8601 extended UTC timestamp, or `None`.
///
/// Strict about shape: the separators are checked at fixed offsets and the
/// trailing `Z` is required, so an RFC 7231 HTTP date is refused rather than
/// mis-parsed into a plausible-looking instant.
///
/// The fractional field is optional and is read to millisecond resolution,
/// padded when shorter and truncated when longer.
///
/// ONE THING IT DOES NOT CHECK, said out loud: the day is bounded at 31 rather
/// than against the month's real length, so an impossible date such as a
/// thirty-first of February resolves into the following month instead of
/// failing. The value is a sort input with no other reader, so a nonsense
/// stamp and a nonsense-but-adjacent stamp are the same outcome, and no server
/// emits one.
pub fn parse_iso8601_utc(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || *b.last()? != b'Z'
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
    let year = num(0, 4)? as i64;
    let month = num(5, 7)?;
    let day = num(8, 10)?;
    let hour = num(11, 13)?;
    let minute = num(14, 16)?;
    let second = num(17, 19)?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }

    let millis = match b[19] {
        b'Z' if b.len() == 20 => 0u64,
        b'.' => {
            let frac = s.get(20..s.len() - 1)?;
            if frac.is_empty() || !frac.bytes().all(|c| c.is_ascii_digit()) {
                return None;
            }
            let mut digits: String = frac.chars().take(3).collect();
            while digits.len() < 3 {
                digits.push('0');
            }
            digits.parse::<u64>().ok()?
        }
        _ => return None,
    };

    let secs = days_from_civil(year, month, day) * 86_400
        + hour as i64 * 3600
        + minute as i64 * 60
        + second as i64;
    if secs < 0 {
        return None;
    }
    Some(secs as u64 * 1000 + millis)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- the published vectors --------------------------------------------
    //
    // Copied once, at authoring time, out of a mirror of the AWS Signature
    // Version 4 test suite and embedded below as constants. NOTHING IS FETCHED
    // AT TEST TIME. The suite's own archive no longer resolves at the address
    // that historically served it, so the values are pinned here instead of
    // being read from a download that may or may not answer.
    //
    // Every case uses the suite's fixed credentials, region and service, and
    // its fixed timestamp, which is why the calendar below needs separate
    // coverage.

    const ACCESS_KEY_ID: &str = "AKIDEXAMPLE";
    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    const REGION: &str = "us-east-1";
    const SERVICE: &str = "service";
    const DATE: &str = "20150830";
    const AMZ_DATE: &str = "20150830T123600Z";

    struct Vector {
        name: &'static str,
        method: &'static str,
        path: &'static str,
        /// Already canonical. The one case with a query builds it through
        /// [`canonical_query`] instead, so the sorting is exercised rather
        /// than assumed.
        query: &'static str,
        headers: &'static [(&'static str, &'static str)],
        payload: &'static [u8],
        creq: &'static str,
        sts: &'static str,
        authz: &'static str,
    }

    const HOST: (&str, &str) = ("Host", "example.amazonaws.com");
    const STAMP: (&str, &str) = ("X-Amz-Date", AMZ_DATE);

    fn vectors() -> Vec<Vector> {
        vec![
            Vector {
                name: "get-vanilla",
                method: "GET",
                path: "/",
                query: "",
                headers: &[HOST, STAMP],
                payload: b"",
                creq: "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                sts: "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\nbb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63",
                authz: "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
            },
            Vector {
                name: "get-vanilla-query-order-key-case",
                method: "GET",
                path: "/",
                query: "Param1=value1&Param2=value2",
                headers: &[HOST, STAMP],
                payload: b"",
                creq: "GET\n/\nParam1=value1&Param2=value2\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                sts: "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n816cd5b414d056048ba4f7c5386d6e0533120fb1fcfa93762cf0fc39e2cf19e0",
                authz: "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500",
            },
            Vector {
                // A non-empty body, and the case that proves a signed
                // `Content-Type` works even though the provider sends none.
                name: "post-x-www-form-urlencoded",
                method: "POST",
                path: "/",
                query: "",
                headers: &[
                    ("Content-Type", "application/x-www-form-urlencoded"),
                    HOST,
                    STAMP,
                ],
                payload: b"Param1=value1",
                creq: "POST\n/\n\ncontent-type:application/x-www-form-urlencoded\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\ncontent-type;host;x-amz-date\n9095672bbd1f56dfc5b65f3e153adc8731a4a654192329106275f4c7b24d0b6e",
                sts: "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n42a5e5bb34198acb3e84da4f085bb7927f2bc277ca766e6d19c73c2154021281",
                authz: "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=ff11897932ad3f4e8b18135d722051e5ac45fc38421b1da7b9d196a0fe09473a",
            },
            Vector {
                // The ONLY non-ASCII coverage `uri_encode` gets, and it is
                // reachable in production: an object name is hex, but the key
                // a provider receives is composed by the layer above from a
                // user-typed prefix and rides through the same encoder.
                name: "get-utf8",
                method: "GET",
                path: "/\u{1234}",
                query: "",
                headers: &[HOST, STAMP],
                payload: b"",
                creq: "GET\n/%E1%88%B4\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                sts: "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n2a0a97d02205e45ce2e994789806b19270cfbbb0921b278ccf58f5249ac42102",
                authz: "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=8318018e0b0f223aa2bbf98705b62bb787dc9c0e678f255a891fd03141be5d85",
            },
        ]
    }

    #[test]
    fn every_vector_reproduces_its_canonical_request_string_to_sign_and_header() {
        let scope = SigningScope {
            access_key_id: ACCESS_KEY_ID,
            secret_access_key: SECRET,
            date: DATE,
            region: REGION,
            service: SERVICE,
        };
        for v in vectors() {
            let creq =
                canonical_request(v.method, v.path, v.query, v.headers, &sha256_hex(v.payload));
            assert_eq!(creq, v.creq, "{}: canonical request", v.name);
            assert_eq!(
                string_to_sign(AMZ_DATE, &scope.credential_scope(), &creq),
                v.sts,
                "{}: string to sign",
                v.name
            );
            assert_eq!(
                authorization_header(&scope, AMZ_DATE, &signed_headers(v.headers), &creq),
                v.authz,
                "{}: authorization header",
                v.name
            );
        }
    }

    #[test]
    fn the_query_case_really_sorts_rather_than_taking_the_order_it_was_given() {
        // The vector above carries an ALREADY canonical query, so on its own
        // it proves nothing about the sorting. This is the same case's real
        // input, in the order the suite sends it.
        assert_eq!(
            canonical_query(&[("Param2", "value2"), ("Param1", "value1")]),
            "Param1=value1&Param2=value2"
        );
    }

    #[test]
    fn the_canonical_uri_is_the_path_byte_for_byte() {
        // S3 does not normalize the request URI. A signer that collapsed these
        // segments would compute a canonical request the service never
        // computed, and every request would come back 403 - which reads
        // exactly like a wrong secret key. This test is what fails the moment
        // anybody "fixes" the signer by adding normalization.
        let path = "/bucket/a//b/../c/./d";
        let creq = canonical_request(
            "GET",
            path,
            "",
            &[("Host", "storage.example")],
            EMPTY_PAYLOAD_SHA256,
        );
        assert_eq!(creq.lines().nth(1).unwrap(), path);
    }

    #[test]
    fn the_empty_payload_constant_is_the_hash_it_claims_to_be() {
        assert_eq!(sha256_hex(b""), EMPTY_PAYLOAD_SHA256);
    }

    // --- the calendar -----------------------------------------------------

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + std::time::Duration::from_secs(secs)
    }

    #[test]
    fn amz_date_spells_the_awkward_instants_correctly() {
        // The epoch itself, a leap day, a year-2000 leap day (the century
        // divisible by 400, which the naive rule gets wrong), and the day
        // after a century NON-leap year's February (2100, which the naive
        // rule also gets wrong, in the other direction).
        for (secs, stamp, date) in [
            (0u64, "19700101T000000Z", "19700101"),
            (1_709_210_096, "20240229T123456Z", "20240229"),
            (951_868_799, "20000229T235959Z", "20000229"),
            (4_107_542_401, "21000301T000001Z", "21000301"),
            (1_440_938_160, "20150830T123600Z", "20150830"),
        ] {
            assert_eq!(
                amz_date(at(secs)),
                (stamp.to_string(), date.to_string()),
                "{secs}"
            );
        }
    }

    #[test]
    fn parse_iso8601_utc_answers_in_milliseconds() {
        // Exact values, not a round trip: the round trip would never have seen
        // the fractional field and a missing multiplication by a thousand
        // would have cancelled out.
        for (text, want) in [
            ("2009-10-12T17:50:30.000Z", 1_255_369_830_000u64),
            ("2009-10-12T17:50:30Z", 1_255_369_830_000),
            ("2024-02-29T00:00:00Z", 1_709_164_800_000),
            // A NON-ZERO fraction, so the thousand is not the only thing
            // making the number look right.
            ("2009-10-12T17:50:30.123Z", 1_255_369_830_123),
            // Shorter and longer fractions, padded and truncated.
            ("2009-10-12T17:50:30.5Z", 1_255_369_830_500),
            ("2009-10-12T17:50:30.123456Z", 1_255_369_830_123),
            ("1970-01-01T00:00:00Z", 0),
        ] {
            assert_eq!(parse_iso8601_utc(text), Some(want), "{text}");
        }
    }

    #[test]
    fn parse_iso8601_utc_refuses_what_it_is_not_for() {
        for text in [
            // An RFC 7231 HTTP date, which is the `Last-Modified` HEADER's
            // format. The name `parse_http_date` would have implied this one
            // parses; it does not, and it must not guess.
            "Mon, 12 Oct 2009 17:50:30 GMT",
            // The basic form `amz_date` emits. These two are not inverses.
            "20150830T123600Z",
            // A local time with no zone, an offset that is not UTC, and junk
            // in the fractional field.
            "2009-10-12T17:50:30",
            "2009-10-12T17:50:30+07:00",
            "2009-10-12T17:50:30.Z",
            "2009-10-12T17:50:30.abcZ",
            // Out of range in each component.
            "2009-13-12T17:50:30Z",
            "2009-10-00T17:50:30Z",
            "2009-10-12T24:50:30Z",
            "2009-10-12T17:60:30Z",
            "",
        ] {
            assert_eq!(parse_iso8601_utc(text), None, "{text}");
        }
    }

    #[test]
    fn the_two_calendar_directions_agree_where_they_overlap() {
        // Not a round trip between the two PUBLIC functions, which read
        // different formats - this is the shared arithmetic underneath them,
        // across four centuries of leap-year edges.
        for (y, m, d) in [
            (1970, 1, 1),
            (1969, 12, 31),
            (2000, 2, 29),
            (2024, 2, 29),
            (2100, 3, 1),
            (2100, 2, 28),
            (1900, 3, 1),
        ] {
            assert_eq!(civil_from_days(days_from_civil(y, m, d)), (y, m, d));
        }
    }
}
