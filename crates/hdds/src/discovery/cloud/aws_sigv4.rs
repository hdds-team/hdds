// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::sha256;

/// AWS credentials
#[derive(Debug, Clone)]
pub struct AwsCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
}

/// Hex-encode bytes
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// URI-encode a string per AWS rules (RFC 3986 with / not encoded in paths)
fn uri_encode(input: &str, encode_slash: bool) -> String {
    let mut result = String::with_capacity(input.len() * 2);
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
            | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            b'/' if !encode_slash => {
                result.push('/');
            }
            _ => {
                result.push('%');
                result.push_str(&format!("{:02X}", byte));
            }
        }
    }
    result
}

/// Build the canonical request string for AWS SigV4
fn canonical_request(
    method: &str,
    path: &str,
    query_string: &str,
    headers: &[(String, String)],
    signed_headers: &str,
    payload_hash: &str,
) -> String {
    let mut canonical_headers = String::new();
    for (name, value) in headers {
        canonical_headers.push_str(&format!("{}:{}\n", name.to_lowercase(), value.trim()));
    }

    format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method,
        uri_encode(path, false),
        query_string,
        canonical_headers,
        signed_headers,
        payload_hash,
    )
}

/// Build the string to sign
fn string_to_sign(
    datetime: &str,
    date: &str,
    region: &str,
    service: &str,
    canonical_request_hash: &str,
) -> String {
    format!(
        "AWS4-HMAC-SHA256\n{}\n{}/{}/{}/aws4_request\n{}",
        datetime, date, region, service, canonical_request_hash
    )
}

/// Derive the signing key: HMAC chain
fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> [u8; 32] {
    let k_secret = format!("AWS4{}", secret);
    let k_date = sha256::hmac(k_secret.as_bytes(), date.as_bytes());
    let k_region = sha256::hmac(&k_date, region.as_bytes());
    let k_service = sha256::hmac(&k_region, service.as_bytes());
    sha256::hmac(&k_service, b"aws4_request")
}

/// Sign a request and return the Authorization header value.
///
/// Returns (authorization_header, x_amz_date, x_amz_content_sha256).
#[allow(clippy::too_many_arguments)]
pub fn sign_request(
    credentials: &AwsCredentials,
    method: &str,
    url_path: &str,
    query_string: &str,
    headers: &mut Vec<(String, String)>,
    body: &[u8],
    region: &str,
    service: &str,
    datetime: &str,  // "20260213T120000Z"
    date: &str,      // "20260213"
) -> String {
    let payload_hash = hex_encode(&sha256::hash(body));

    // Add required headers if not present
    let has_content_sha = headers.iter().any(|(k, _)| k == "x-amz-content-sha256");
    if !has_content_sha {
        headers.push(("x-amz-content-sha256".to_string(), payload_hash.clone()));
    }
    let has_date = headers.iter().any(|(k, _)| k == "x-amz-date");
    if !has_date {
        headers.push(("x-amz-date".to_string(), datetime.to_string()));
    }
    if let Some(ref token) = credentials.session_token {
        let has_token = headers.iter().any(|(k, _)| k == "x-amz-security-token");
        if !has_token {
            headers.push(("x-amz-security-token".to_string(), token.clone()));
        }
    }

    // Sort headers by lowercase name
    headers.sort_by(|a, b| a.0.to_lowercase().cmp(&b.0.to_lowercase()));

    // Build signed headers list
    let signed_headers: Vec<String> = headers.iter().map(|(k, _)| k.to_lowercase()).collect();
    let signed_headers_str = signed_headers.join(";");

    // Build canonical request
    let creq = canonical_request(
        method,
        url_path,
        query_string,
        headers,
        &signed_headers_str,
        &payload_hash,
    );

    let creq_hash = hex_encode(&sha256::hash(creq.as_bytes()));

    // Build string to sign
    let sts = string_to_sign(datetime, date, region, service, &creq_hash);

    // Derive signing key and sign
    let key = signing_key(&credentials.secret_access_key, date, region, service);
    let signature = hex_encode(&sha256::hmac(&key, sts.as_bytes()));

    format!(
        "AWS4-HMAC-SHA256 Credential={}/{}/{}/{}/aws4_request, SignedHeaders={}, Signature={}",
        credentials.access_key_id, date, region, service, signed_headers_str, signature
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uri_encode() {
        assert_eq!(uri_encode("/foo/bar", false), "/foo/bar");
        assert_eq!(uri_encode("/foo/bar", true), "%2Ffoo%2Fbar");
        assert_eq!(uri_encode("hello world", true), "hello%20world");
    }

    #[test]
    fn test_signing_key_derivation() {
        // @audit-ok: AWS SigV4 test vector from docs.aws.amazon.com
        let key = signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", // @audit-ok: AWS test vector
            "20150830",
            "us-east-1",
            "iam",
        );
        let hex_key = hex_encode(&key);
        assert_eq!(
            hex_key,
            "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
        );
    }

    #[test]
    fn test_sign_request_produces_authorization() {
        let creds = AwsCredentials {
            access_key_id: "AKIDEXAMPLE".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_string(), // @audit-ok: AWS test vector
            session_token: None,
        };

        let mut headers = vec![
            ("host".to_string(), "servicediscovery.us-east-1.amazonaws.com".to_string()),
            ("content-type".to_string(), "application/x-amz-json-1.1".to_string()),
            ("x-amz-target".to_string(), "Route53AutoNaming_v20170314.RegisterInstance".to_string()),
        ];

        let body = b"{}";
        let auth = sign_request(
            &creds,
            "POST",
            "/",
            "",
            &mut headers,
            body,
            "us-east-1",
            "servicediscovery",
            "20260213T120000Z",
            "20260213",
        );

        assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260213/us-east-1/servicediscovery/aws4_request"));
        assert!(auth.contains("SignedHeaders="));
        assert!(auth.contains("Signature="));
    }
}
