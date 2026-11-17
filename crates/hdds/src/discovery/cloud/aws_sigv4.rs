// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! AWS Signature Version 4 request signing (header-based authorization).
//!
//! This is the whole authentication layer of the AWS Cloud Map backend:
//! every control-plane and data-plane call is a `POST /` carrying an
//! `application/x-amz-json-1.1` body and an `Authorization: AWS4-HMAC-SHA256`
//! header computed here.
//!
//! The implementation follows the "Signature Version 4 signing process"
//! rules and is pinned by the official AWS SigV4 test suite
//! (`aws-sig-v4-test-suite`, published by AWS in `awslabs/aws-c-auth` and
//! vendored by the AWS SDKs): the fixtures under `tests` below carry the
//! canonical request, the string to sign and the final signature AWS
//! publishes for each case, so a canonicalisation mistake fails a test
//! instead of failing silently against a real account.
//!
//! Scope of the canonicalisation implemented here, stated honestly:
//!
//! * header names are lower-cased, values trimmed and their internal
//!   whitespace runs collapsed to a single space; several headers with the
//!   same name are joined with `,` in the order they were given;
//! * the path is URI-encoded once with `/` preserved (every request this
//!   crate signs targets `/`, so path normalisation - `.`/`..` collapsing,
//!   the S3 double-encoding exception - is deliberately NOT implemented);
//! * the query string is passed through verbatim by the caller (every
//!   request this crate signs has an empty query string);
//! * multi-line header values (obsolete HTTP line folding) are not
//!   supported; `reqwest` cannot emit them.

// `AwsCredentials::with_session_token` and the `SignedRequest` fields
// other than `signature` and `headers` exist for the known-answer tests
// and for the fake endpoint's verifier (`test_support::fake_aws`), which
// are compiled under `cfg(test)`. Keeping them non-`pub` at module level
// and stating that here is more honest than widening the module's
// visibility, or dropping the intermediate strings the AWS vectors are
// compared against, to make a dead-code warning disappear.
// Narrow on purpose (same idiom as `sha256.rs`): a test build still
// reports anything genuinely dead here.
#![cfg_attr(not(test), allow(dead_code))]

use super::sha256;

/// A resolved set of AWS credentials.
///
/// `Debug` is manual: an access key id identifies an account and is
/// routinely logged, but the secret and the session token are the two
/// values that must never reach a log line.
#[derive(Clone)]
pub struct AwsCredentials {
    /// `AKIA...` / `ASIA...` access key id.
    pub access_key_id: String,
    /// Secret access key. Never rendered by `Debug`.
    pub secret_access_key: String,
    /// STS session token, present for every temporary credential.
    pub session_token: Option<String>,
}

impl AwsCredentials {
    /// Long-lived credentials (no session token).
    pub fn new(access_key_id: impl Into<String>, secret_access_key: impl Into<String>) -> Self {
        Self {
            access_key_id: access_key_id.into(),
            secret_access_key: secret_access_key.into(),
            session_token: None,
        }
    }

    /// Temporary credentials with their STS session token.
    pub fn with_session_token(mut self, token: impl Into<String>) -> Self {
        self.session_token = Some(token.into());
        self
    }
}

impl std::fmt::Debug for AwsCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsCredentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Everything the signing produced, so a test can assert the intermediate
/// strings and not only the final header.
#[derive(Debug, Clone)]
pub struct SignedRequest {
    /// The canonical request, exactly as hashed.
    pub canonical_request: String,
    /// The string to sign, exactly as HMAC'd.
    pub string_to_sign: String,
    /// `;`-joined lower-case names of the signed headers.
    pub signed_headers: String,
    /// Lower-case hex signature.
    pub signature: String,
    /// Full `Authorization` header value.
    pub authorization: String,
    /// The complete header set to send: what the caller passed, plus the
    /// headers the signer added (`x-amz-date`, `x-amz-security-token`),
    /// plus `authorization`.
    pub headers: Vec<(String, String)>,
}

/// URI-encode per RFC 3986 with the AWS unreserved set.
///
/// `encode_slash = false` is the path form (a `/` stays a `/`);
/// `true` is the query-component / STS form.
pub(crate) fn uri_encode(input: &str, encode_slash: bool) -> String {
    let mut result = String::with_capacity(input.len() * 3);
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            b'/' if !encode_slash => result.push('/'),
            _ => {
                result.push('%');
                result.push_str(&format!("{:02X}", byte));
            }
        }
    }
    result
}

/// Canonical form of one header value: trimmed, internal whitespace runs
/// collapsed to a single space.
///
/// The AWS rule says "convert sequential spaces to a single space"; the
/// published `get-header-value-trim` fixture collapses them inside quotes
/// too (`"a   b   c"` -> `"a b c"`), so no quote tracking is done here.
fn canonical_header_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut pending_space = false;
    for ch in value.trim().chars() {
        if ch == ' ' || ch == '\t' {
            pending_space = true;
            continue;
        }
        if pending_space {
            out.push(' ');
            pending_space = false;
        }
        out.push(ch);
    }
    out
}

/// Group headers by lower-case name, joining repeats with `,` in the order
/// they were given, and sort by name.
///
/// Returns the canonical-headers block and the `;`-joined signed header
/// list.
fn canonical_headers(headers: &[(String, String)]) -> (String, String) {
    let mut grouped: Vec<(String, Vec<String>)> = Vec::with_capacity(headers.len());
    for (name, value) in headers {
        let name = name.trim().to_ascii_lowercase();
        let value = canonical_header_value(value);
        match grouped.iter_mut().find(|(key, _)| *key == name) {
            Some((_, values)) => values.push(value),
            None => grouped.push((name, vec![value])),
        }
    }
    grouped.sort_by(|a, b| a.0.cmp(&b.0));

    let mut block = String::new();
    for (name, values) in &grouped {
        block.push_str(name);
        block.push(':');
        block.push_str(&values.join(","));
        block.push('\n');
    }
    let signed: Vec<&str> = grouped.iter().map(|(name, _)| name.as_str()).collect();
    (block, signed.join(";"))
}

/// Derive the signing key: the four-step HMAC chain over the scope.
fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> [u8; 32] {
    let k_secret = format!("AWS4{}", secret);
    let k_date = sha256::hmac(k_secret.as_bytes(), date.as_bytes());
    let k_region = sha256::hmac(&k_date, region.as_bytes());
    let k_service = sha256::hmac(&k_region, service.as_bytes());
    sha256::hmac(&k_service, b"aws4_request")
}

/// What a caller hands the signer.
///
/// `headers` must already contain `host`; everything else the protocol
/// needs (`content-type`, `x-amz-target`) is the caller's business. The
/// signer adds `x-amz-date` when absent and `x-amz-security-token` when
/// the credentials carry one, because both are part of the signature.
#[derive(Debug, Clone)]
pub struct SigningRequest<'a> {
    /// HTTP method, upper-case.
    pub method: &'a str,
    /// Request path, starting with `/`.
    pub path: &'a str,
    /// Canonical query string (already sorted and encoded), or empty.
    pub query: &'a str,
    /// Headers in caller order; names are case-insensitive.
    pub headers: Vec<(String, String)>,
    /// Request body, hashed into the canonical request.
    pub body: &'a [u8],
    /// AWS region of the endpoint, e.g. `eu-west-3`.
    pub region: &'a str,
    /// AWS signing service name, e.g. `servicediscovery`.
    pub service: &'a str,
    /// `YYYYMMDDTHHMMSSZ`.
    pub datetime: &'a str,
    /// `YYYYMMDD`, the date part of `datetime`.
    pub date: &'a str,
}

/// Sign a request, returning every intermediate string plus the header set
/// to send.
pub fn sign(credentials: &AwsCredentials, request: &SigningRequest<'_>) -> SignedRequest {
    let mut headers = request.headers.clone();
    if !headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("x-amz-date"))
    {
        headers.push(("x-amz-date".to_string(), request.datetime.to_string()));
    }
    if let Some(token) = credentials.session_token.as_ref() {
        if !headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("x-amz-security-token"))
        {
            headers.push(("x-amz-security-token".to_string(), token.clone()));
        }
    }

    let payload_hash = sha256::hex(&sha256::hash(request.body));
    let (header_block, signed_headers) = canonical_headers(&headers);
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        request.method,
        uri_encode(request.path, false),
        request.query,
        header_block,
        signed_headers,
        payload_hash
    );

    let scope = format!(
        "{}/{}/{}/aws4_request",
        request.date, request.region, request.service
    );
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        request.datetime,
        scope,
        sha256::hex(&sha256::hash(canonical_request.as_bytes()))
    );

    let key = signing_key(
        &credentials.secret_access_key,
        request.date,
        request.region,
        request.service,
    );
    let signature = sha256::hex(&sha256::hmac(&key, string_to_sign.as_bytes()));
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        credentials.access_key_id, scope, signed_headers, signature
    );

    let mut final_headers = headers;
    final_headers.push(("authorization".to_string(), authorization.clone()));

    SignedRequest {
        canonical_request,
        string_to_sign,
        signed_headers,
        signature,
        authorization,
        headers: final_headers,
    }
}

/// Content type of every AWS JSON 1.1 protocol call.
pub const JSON_CONTENT_TYPE: &str = "application/x-amz-json-1.1";

/// One AWS JSON 1.1 `POST /` call, before signing.
#[derive(Debug, Clone)]
pub struct JsonPost<'a> {
    /// Endpoint authority (`servicediscovery.eu-west-3.amazonaws.com`, or
    /// `127.0.0.1:41234` for a hermetic fake), exactly as the HTTP stack
    /// will send it in the `Host` header.
    pub host: &'a str,
    /// `X-Amz-Target` operation name.
    pub target: &'a str,
    /// JSON request body.
    pub body: &'a [u8],
    /// AWS region of the endpoint.
    pub region: &'a str,
    /// AWS signing service name.
    pub service: &'a str,
    /// `YYYYMMDDTHHMMSSZ`.
    pub datetime: &'a str,
    /// `YYYYMMDD`.
    pub date: &'a str,
}

/// Sign an AWS JSON 1.1 `POST /` call and return the headers to send.
pub fn sign_json_post(credentials: &AwsCredentials, call: &JsonPost<'_>) -> SignedRequest {
    let request = SigningRequest {
        method: "POST",
        path: "/",
        query: "",
        headers: vec![
            ("host".to_string(), call.host.to_string()),
            ("content-type".to_string(), JSON_CONTENT_TYPE.to_string()),
            ("x-amz-target".to_string(), call.target.to_string()),
        ],
        body: call.body,
        region: call.region,
        service: call.service,
        datetime: call.datetime,
        date: call.date,
    };
    sign(credentials, &request)
}

/// Render a Unix timestamp as the SigV4 pair `(YYYYMMDDTHHMMSSZ, YYYYMMDD)`.
///
/// The calendar itself lives in `core::civil_time`, shared with the RFC 5424
/// audit export: SigV4 and syslog need the same six integers and differ only
/// in how they punctuate them.
///
/// A timestamp past `crate::core::civil_time::MAX_FORMATTABLE_UNIX_SECONDS` saturates there; see that
/// module for why saturating is the only answer that is neither a wrap nor a
/// hang.
pub fn format_timestamp(unix_seconds: u64) -> (String, String) {
    let t = crate::core::civil_time::civil_from_unix_seconds(unix_seconds);
    let date = format!("{:04}{:02}{:02}", t.year, t.month, t.day);
    let datetime = format!("{}T{:02}{:02}{:02}Z", date, t.hour, t.minute, t.second);
    (datetime, date)
}

/// The current UTC time as the SigV4 pair `(YYYYMMDDTHHMMSSZ, YYYYMMDD)`.
///
/// A clock before the Unix epoch renders as the epoch; SigV4 would refuse
/// such a request anyway (15-minute skew window), and the error AWS
/// returns then names the `x-amz-date` we sent.
pub fn utc_now() -> (String, String) {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_timestamp(seconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Official AWS SigV4 test-suite fixtures.
    //
    // Source: the `aws-sig-v4-test-suite` published by AWS
    // (github.com/awslabs/aws-c-auth, tests/aws-sig-v4-test-suite),
    // vendored verbatim by botocore under
    // tests/unit/auth/aws4_testsuite/. Each case ships a `.creq`
    // (canonical request), a `.sts` (string to sign) and an `.authz`
    // (Authorization header); the credentials and clock the suite signs
    // with are fixed by its runner (botocore tests/unit/auth/test_sigv4.py:
    // ACCESS_KEY, SECRET_KEY, DATE, SERVICE, REGION).
    //
    // Copied from those files, never typed from memory.
    // ------------------------------------------------------------------

    const SUITE_ACCESS_KEY: &str = "AKIDEXAMPLE";
    // @audit-ok: the AWS test suite's published example secret, not a credential.
    const SUITE_SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    const SUITE_DATETIME: &str = "20150830T123600Z";
    const SUITE_DATE: &str = "20150830";
    const SUITE_REGION: &str = "us-east-1";
    const SUITE_SERVICE: &str = "service";
    const SUITE_HOST: &str = "example.amazonaws.com";

    struct SuiteCase {
        name: &'static str,
        method: &'static str,
        headers: &'static [(&'static str, &'static str)],
        body: &'static [u8],
        session_token: Option<&'static str>,
        canonical_request: &'static str,
        string_to_sign: &'static str,
        authorization: &'static str,
    }

    const SUITE: &[SuiteCase] = &[
        SuiteCase {
            name: "get-vanilla",
            method: "GET",
            headers: &[("Host", SUITE_HOST), ("X-Amz-Date", SUITE_DATETIME)],
            body: b"",
            session_token: None,
            canonical_request: "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            string_to_sign: "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\nbb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63",
            authorization: "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
        },
        SuiteCase {
            name: "get-header-value-trim",
            method: "GET",
            headers: &[
                ("Host", SUITE_HOST),
                ("My-Header1", " value1"),
                ("My-Header2", " \"a   b   c\""),
                ("X-Amz-Date", SUITE_DATETIME),
            ],
            body: b"",
            session_token: None,
            canonical_request: "GET\n/\n\nhost:example.amazonaws.com\nmy-header1:value1\nmy-header2:\"a b c\"\nx-amz-date:20150830T123600Z\n\nhost;my-header1;my-header2;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            string_to_sign: "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\na726db9b0df21c14f559d0a978e563112acb1b9e05476f0a6a1c7d68f28605c7",
            authorization: "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;my-header1;my-header2;x-amz-date, Signature=acc3ed3afb60bb290fc8d2dd0098b9911fcaa05412b367055dee359757a9c736",
        },
        SuiteCase {
            name: "get-header-key-duplicate",
            method: "GET",
            headers: &[
                ("Host", SUITE_HOST),
                ("My-Header1", "value2"),
                ("My-Header1", "value2"),
                ("My-Header1", "value1"),
                ("X-Amz-Date", SUITE_DATETIME),
            ],
            body: b"",
            session_token: None,
            canonical_request: "GET\n/\n\nhost:example.amazonaws.com\nmy-header1:value2,value2,value1\nx-amz-date:20150830T123600Z\n\nhost;my-header1;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            string_to_sign: "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\ndc7f04a3abfde8d472b0ab1a418b741b7c67174dad1551b4117b15527fbe966c",
            authorization: "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;my-header1;x-amz-date, Signature=c9d5ea9f3f72853aea855b47ea873832890dbdd183b4468f858259531a5138ea",
        },
        SuiteCase {
            name: "get-header-value-order",
            method: "GET",
            headers: &[
                ("Host", SUITE_HOST),
                ("My-Header1", "value4"),
                ("My-Header1", "value1"),
                ("My-Header1", "value3"),
                ("My-Header1", "value2"),
                ("X-Amz-Date", SUITE_DATETIME),
            ],
            body: b"",
            session_token: None,
            canonical_request: "GET\n/\n\nhost:example.amazonaws.com\nmy-header1:value4,value1,value3,value2\nx-amz-date:20150830T123600Z\n\nhost;my-header1;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            string_to_sign: "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n31ce73cd3f3d9f66977ad3dd957dc47af14df92fcd8509f59b349e9137c58b86",
            authorization: "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;my-header1;x-amz-date, Signature=08c7e5a9acfcfeb3ab6b2185e75ce8b1deb5e634ec47601a50643f830c755c01",
        },
        SuiteCase {
            name: "post-vanilla",
            method: "POST",
            headers: &[("Host", SUITE_HOST), ("X-Amz-Date", SUITE_DATETIME)],
            body: b"",
            session_token: None,
            canonical_request: "POST\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            string_to_sign: "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n553f88c9e4d10fc9e109e2aeb65f030801b70c2f6468faca261d401ae622fc87",
            authorization: "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b",
        },
        SuiteCase {
            name: "post-x-www-form-urlencoded",
            method: "POST",
            headers: &[
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("Host", SUITE_HOST),
                ("X-Amz-Date", SUITE_DATETIME),
            ],
            body: b"Param1=value1",
            session_token: None,
            canonical_request: "POST\n/\n\ncontent-type:application/x-www-form-urlencoded\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\ncontent-type;host;x-amz-date\n9095672bbd1f56dfc5b65f3e153adc8731a4a654192329106275f4c7b24d0b6e",
            string_to_sign: "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n42a5e5bb34198acb3e84da4f085bb7927f2bc277ca766e6d19c73c2154021281",
            authorization: "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=ff11897932ad3f4e8b18135d722051e5ac45fc38421b1da7b9d196a0fe09473a",
        },
        SuiteCase {
            // The session token is NOT in the request the suite signs: the
            // signer must add `x-amz-security-token` itself, which is
            // exactly what the published canonical request shows.
            name: "get-vanilla-with-session-token",
            method: "GET",
            headers: &[("Host", SUITE_HOST), ("X-Amz-Date", SUITE_DATETIME)],
            body: b"",
            session_token: Some(
                "6e86291e8372ff2a2260956d9b8aae1d763fbf315fa00fa31553b73ebf194267",
            ),
            canonical_request: "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\nx-amz-security-token:6e86291e8372ff2a2260956d9b8aae1d763fbf315fa00fa31553b73ebf194267\n\nhost;x-amz-date;x-amz-security-token\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            string_to_sign: "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n067b36aa60031588cea4a4cde1f21215227a047690c72247f1d70b32fbbfad2b",
            authorization: "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date;x-amz-security-token, Signature=07ec1639c89043aa0e3e2de82b96708f198cceab042d4a97044c66dd9f74e7f8",
        },
    ];

    /// The canonical request, the string to sign AND the Authorization
    /// header must match the values AWS publishes, for every fixture.
    ///
    /// This is the ONE oracle in the AWS backend that shares no code with
    /// the hermetic fake: the fake's verifier calls this same signer, so a
    /// symmetric canonicalisation bug would pass both sides of an
    /// end-to-end test. It cannot pass this one.
    #[test]
    fn sigv4_matches_the_official_aws_test_suite_vectors() {
        for case in SUITE {
            let mut credentials = AwsCredentials::new(SUITE_ACCESS_KEY, SUITE_SECRET_KEY);
            if let Some(token) = case.session_token {
                credentials = credentials.with_session_token(token);
            }
            let request = SigningRequest {
                method: case.method,
                path: "/",
                query: "",
                headers: case
                    .headers
                    .iter()
                    .map(|(name, value)| (name.to_string(), value.to_string()))
                    .collect(),
                body: case.body,
                region: SUITE_REGION,
                service: SUITE_SERVICE,
                datetime: SUITE_DATETIME,
                date: SUITE_DATE,
            };
            let signed = sign(&credentials, &request);
            assert_eq!(
                signed.canonical_request, case.canonical_request,
                "canonical request mismatch for {}",
                case.name
            );
            assert_eq!(
                signed.string_to_sign, case.string_to_sign,
                "string to sign mismatch for {}",
                case.name
            );
            assert_eq!(
                signed.authorization, case.authorization,
                "authorization mismatch for {}",
                case.name
            );
        }
    }

    /// A one-character difference in the secret must move the signature:
    /// the suite comparison above would still pass if `sign` ignored the
    /// key and returned a constant derived from the canonical request.
    #[test]
    fn sigv4_signature_depends_on_the_secret_key() {
        let request = SigningRequest {
            method: "POST",
            path: "/",
            query: "",
            headers: vec![("host".to_string(), SUITE_HOST.to_string())],
            body: b"{}",
            region: SUITE_REGION,
            service: SUITE_SERVICE,
            datetime: SUITE_DATETIME,
            date: SUITE_DATE,
        };
        let good = sign(
            &AwsCredentials::new(SUITE_ACCESS_KEY, SUITE_SECRET_KEY),
            &request,
        );
        let bad = sign(
            &AwsCredentials::new(SUITE_ACCESS_KEY, "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEz"),
            &request,
        );
        assert_eq!(good.canonical_request, bad.canonical_request);
        assert_ne!(good.signature, bad.signature);
    }

    /// The AWS docs' published signing-key derivation vector.
    #[test]
    fn signing_key_matches_the_aws_docs_vector() {
        let key = signing_key(
            // @audit-ok: AWS documentation test vector, not a credential.
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20150830",
            "us-east-1",
            "iam",
        );
        assert_eq!(
            sha256::hex(&key),
            "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
        );
    }

    #[test]
    fn uri_encode_follows_the_aws_unreserved_set() {
        assert_eq!(uri_encode("/foo/bar", false), "/foo/bar");
        assert_eq!(uri_encode("/foo/bar", true), "%2Ffoo%2Fbar");
        assert_eq!(uri_encode("hello world", true), "hello%20world");
        assert_eq!(uri_encode("-_.~AZaz09", true), "-_.~AZaz09");
        assert_eq!(uri_encode("a+b=c", true), "a%2Bb%3Dc");
    }

    #[test]
    fn canonical_headers_collapse_internal_whitespace_and_join_repeats() {
        assert_eq!(canonical_header_value("  a   b  c  "), "a b c");
        assert_eq!(canonical_header_value("\"a\tb\""), "\"a b\"");
        let (block, signed) = canonical_headers(&[
            ("Z-Last".to_string(), "1".to_string()),
            ("A-First".to_string(), " x  y ".to_string()),
            ("a-first".to_string(), "z".to_string()),
        ]);
        assert_eq!(block, "a-first:x y,z\nz-last:1\n");
        assert_eq!(signed, "a-first;z-last");
    }

    /// The pair the signer stamps on every request, against timestamps
    /// rendered independently by `date -u`, including the suite's own clock.
    #[test]
    fn timestamp_formatting_matches_utc_known_epochs() {
        assert_eq!(
            format_timestamp(0),
            ("19700101T000000Z".to_string(), "19700101".to_string())
        );
        assert_eq!(
            format_timestamp(1_440_938_160),
            (SUITE_DATETIME.to_string(), SUITE_DATE.to_string())
        );
        assert_eq!(
            format_timestamp(1_700_000_000),
            ("20231114T221320Z".to_string(), "20231114".to_string())
        );
        // 2024-02-29, the leap day the naive year/month walk gets wrong.
        assert_eq!(
            format_timestamp(1_709_208_000),
            ("20240229T120000Z".to_string(), "20240229".to_string())
        );
        let (datetime, date) = utc_now();
        assert_eq!(datetime.len(), 16);
        assert_eq!(date.len(), 8);
        assert!(datetime.starts_with(&date));
        assert!(datetime.ends_with('Z'));
    }

    /// The day count the walk consumes, measured at the top of the input
    /// domain: the raw quotient overflows every 32-bit width, the saturated
    /// one does not, and the rendering stays a legal SigV4 date either way.
    #[test]
    fn a_timestamp_past_year_9999_saturates_instead_of_wrapping() {
        // The unsaturated quotient, which would be narrowed.
        let raw_days = u64::MAX / 86_400;
        assert_eq!(raw_days, 213_503_982_334_601);
        assert!(u32::try_from(raw_days).is_err());
        assert!(raw_days > u64::from(u32::MAX));

        // The saturated one, which is what the walk sees.
        let capped_days = crate::core::civil_time::MAX_FORMATTABLE_UNIX_SECONDS / 86_400;
        assert_eq!(capped_days, 2_932_896);
        assert!(u32::try_from(capped_days).is_ok());

        // 9999-12-31T23:59:59Z, per `date -u -d @253402300799`.
        let last = ("99991231T235959Z".to_string(), "99991231".to_string());
        assert_eq!(
            format_timestamp(crate::core::civil_time::MAX_FORMATTABLE_UNIX_SECONDS),
            last
        );
        assert_eq!(
            format_timestamp(crate::core::civil_time::MAX_FORMATTABLE_UNIX_SECONDS + 1),
            last
        );
        assert_eq!(format_timestamp(u64::MAX), last);

        // Whatever it is handed, the pair it renders is still the shape the
        // signer splices into a credential scope: 8 digits and 16 characters.
        for seconds in [0, 1, u64::MAX / 2, u64::MAX - 1, u64::MAX] {
            let (datetime, date) = format_timestamp(seconds);
            assert_eq!(date.len(), 8, "date width at {}", seconds);
            assert_eq!(datetime.len(), 16, "datetime width at {}", seconds);
            assert!(date.chars().all(|c| c.is_ascii_digit()));
        }
    }

    /// A JSON 1.1 call carries the three protocol headers, and the
    /// signature covers all of them.
    #[test]
    fn sign_json_post_signs_host_content_type_and_target() {
        let signed = sign_json_post(
            &AwsCredentials::new(SUITE_ACCESS_KEY, SUITE_SECRET_KEY),
            &JsonPost {
                host: "servicediscovery.eu-west-3.amazonaws.com",
                target: "Route53AutoNaming_v20170314.RegisterInstance",
                body: b"{}",
                region: "eu-west-3",
                service: "servicediscovery",
                datetime: SUITE_DATETIME,
                date: SUITE_DATE,
            },
        );
        assert_eq!(
            signed.signed_headers,
            "content-type;host;x-amz-date;x-amz-target"
        );
        assert!(signed
            .canonical_request
            .contains("x-amz-target:Route53AutoNaming_v20170314.RegisterInstance"));
        assert!(signed
            .string_to_sign
            .contains("eu-west-3/servicediscovery/aws4_request"));
        assert!(signed
            .headers
            .iter()
            .any(|(name, value)| name == "authorization" && value == &signed.authorization));
    }

    /// The two values a log line must never carry.
    #[test]
    fn credentials_debug_redacts_the_secret_and_the_session_token() {
        let creds = AwsCredentials::new("AKIAEXAMPLE", "super-secret-value")
            .with_session_token("session-secret-value");
        let rendered = format!("{:?}", creds);
        assert!(rendered.contains("AKIAEXAMPLE"));
        assert!(!rendered.contains("super-secret-value"), "{}", rendered);
        assert!(!rendered.contains("session-secret-value"), "{}", rendered);
    }
}
