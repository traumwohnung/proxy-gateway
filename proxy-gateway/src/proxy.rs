use crate::rotator::Rotator;
use crate::tunnel;

use anyhow::Result;
use base64::Engine;
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};

pub async fn run_proxy(
    bind_addr: &str,
    rotator: Arc<Rotator>,
    api_key: Option<String>,
) -> Result<()> {
    let listener = TcpListener::bind(bind_addr).await?;
    let api_key: Arc<Option<String>> = Arc::new(api_key);

    info!("Proxy gateway listening on {bind_addr}");
    info!("Available proxy sets: {:?}", rotator.set_names());
    for name in rotator.set_names() {
        if let Some(count) = rotator.set_info(name) {
            info!("  set '{}': {} proxies", name, count);
        }
    }
    info!("Usage: Proxy-Authorization: Basic base64(<json>:)");
    info!("  The username is a single base64-encoded JSON object with three required keys:");
    info!("    meta    : flat object with string/number values");
    info!("    minutes : integer 0–1440 (0 = rotate every request)");
    info!("    set     : proxy set name (alphanumeric)");
    info!(r#"  Example: base64({{"meta":{{"app":"myapp"}},"minutes":5,"set":"residential"}}:)"#);
    if api_key.is_some() {
        info!("API endpoints enabled: GET /api/sessions, GET /api/sessions/:username_b64");
    } else {
        info!("API endpoints disabled (no api_key configured)");
    }

    loop {
        let (stream, peer) = listener.accept().await?;
        debug!("Accepted connection from {peer}");

        let rotator = Arc::clone(&rotator);
        let api_key = Arc::clone(&api_key);
        tokio::spawn(async move {
            let io = TokioIo::new(stream);

            let result = http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .serve_connection(
                    io,
                    service_fn(move |req| {
                        let rotator = Arc::clone(&rotator);
                        let api_key = Arc::clone(&api_key);
                        async move { handle_request(req, rotator, peer, api_key).await }
                    }),
                )
                .with_upgrades()
                .await;

            if let Err(e) = result {
                let msg = format!("{e}");
                if msg.contains("incomplete")
                    || msg.contains("connection closed")
                    || msg.contains("early eof")
                {
                    debug!("Connection finished: {e}");
                } else {
                    error!("Connection error: {e}");
                }
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Proxy-Authorization parsing
// ---------------------------------------------------------------------------

/// Parsed proxy authorization, decoded from the single base64-JSON username.
#[derive(Debug)]
struct ProxyAuth {
    set_name: String,
    affinity_minutes: u16,
    /// The raw base64 username string — used as the affinity map key.
    /// Because it encodes all three fields, identical inputs always produce the
    /// same key, giving stable session affinity.
    username_b64: String,
    /// The decoded `meta` sub-object.
    metadata: serde_json::Map<String, serde_json::Value>,
}

/// Public parsed fields from a username, returned by `parse_proxy_auth_value_for_verify`.
pub struct ParsedUsername {
    pub set_name: String,
    pub affinity_minutes: u16,
    pub metadata: serde_json::Map<String, serde_json::Value>,
}

/// Parse a raw base64 username string directly (no Basic auth wrapper).
/// Used by the verify endpoint which receives the username directly in the path.
pub fn parse_proxy_auth_value_for_verify(username_b64: &str) -> Result<ParsedUsername, String> {
    // Reconstruct a fake Basic auth header value so we can reuse the full parser.
    use base64::Engine;
    let faked = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!(
            "{}:",
            String::from_utf8(
                base64::engine::general_purpose::STANDARD
                    .decode(username_b64)
                    .map_err(|_| "Invalid base64 in username")?
            )
            .map_err(|_| "Invalid UTF-8 in username")?
        ))
    );
    let auth = parse_proxy_auth_value(&faked)?;
    Ok(ParsedUsername {
        set_name: auth.set_name,
        affinity_minutes: auth.affinity_minutes,
        metadata: auth.metadata,
    })
}

/// Extract and parse the Proxy-Authorization header from a request.
fn parse_proxy_auth(req: &Request<Incoming>) -> Result<ProxyAuth, String> {
    let header_val = req
        .headers()
        .get("proxy-authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or("Missing Proxy-Authorization header")?;

    parse_proxy_auth_value(header_val)
}

/// Parse a Proxy-Authorization header value.
///
/// The username is a base64-encoded JSON object (password is unused):
///
/// ```text
/// Basic base64({"meta":{...},"minutes":5,"set":"residential"}:)
/// ```
///
/// Rules:
///   - Must be a JSON object with exactly three keys: `meta`, `minutes`, `set`.
///   - `meta`    : flat JSON object; values must be strings or numbers
///                 (no booleans, nulls, arrays, or nested objects).
///   - `minutes` : integer 0..=1440.
///   - `set`     : non-empty alphanumeric string.
///   - No extra keys are allowed.
fn parse_proxy_auth_value(header_val: &str) -> Result<ProxyAuth, String> {
    let b64 = header_val
        .strip_prefix("Basic ")
        .ok_or("Proxy-Authorization must be Basic auth")?;

    let decoded_bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| "Invalid base64 in Proxy-Authorization")?;
    let decoded_str =
        String::from_utf8(decoded_bytes).map_err(|_| "Invalid UTF-8 in Proxy-Authorization")?;

    // Strip the Basic-auth ":password" suffix to get the raw username JSON.
    // Use rfind(':') — the separator colon is always the last one, since the
    // JSON itself contains colons inside key-value pairs.
    let username_json = match decoded_str.rfind(':') {
        Some(idx) => &decoded_str[..idx],
        None => decoded_str.as_str(),
    };

    if username_json.is_empty() {
        return Err("Empty username in Proxy-Authorization".to_string());
    }

    // Parse as JSON.
    let value: serde_json::Value = serde_json::from_str(username_json)
        .map_err(|e| format!("Username is not valid JSON: {e}"))?;

    let obj = match value {
        serde_json::Value::Object(map) => map,
        _ => {
            return Err(
                r#"Username JSON must be an object, e.g. {"meta":{...},"minutes":5,"set":"residential"}"#
                    .to_string(),
            )
        }
    };

    // Require exactly the three expected keys — no more, no less.
    let expected_keys = ["meta", "minutes", "set"];
    for key in expected_keys {
        if !obj.contains_key(key) {
            return Err(format!(
                "Username JSON is missing required key '{}'. Required keys: 'meta', 'minutes', 'set'.",
                key
            ));
        }
    }
    if obj.len() != 3 {
        let extra: Vec<&str> = obj
            .keys()
            .map(String::as_str)
            .filter(|k| !expected_keys.contains(k))
            .collect();
        return Err(format!(
            "Username JSON has unexpected keys: {:?}. Only 'meta', 'minutes', 'set' are allowed.",
            extra
        ));
    }

    // Validate `set`.
    let set_name = match obj.get("set") {
        Some(serde_json::Value::String(s)) => s.clone(),
        _ => return Err("'set' must be a string".to_string()),
    };
    if set_name.is_empty() || !set_name.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(format!(
            "Invalid proxy set name '{}'. Must be non-empty and alphanumeric only.",
            set_name
        ));
    }

    // Validate `minutes`.
    let minutes: u16 = match obj.get("minutes") {
        Some(serde_json::Value::Number(n)) => n
            .as_u64()
            .and_then(|v| u16::try_from(v).ok())
            .ok_or_else(|| "'minutes' must be an integer 0–1440".to_string())?,
        _ => return Err("'minutes' must be an integer 0–1440".to_string()),
    };
    if minutes > 1440 {
        return Err(format!(
            "'minutes' {} exceeds maximum of 1440 (24 hours).",
            minutes
        ));
    }

    // Validate `meta`.
    let meta_obj = match obj.get("meta") {
        Some(serde_json::Value::Object(m)) => m.clone(),
        _ => return Err("'meta' must be a JSON object".to_string()),
    };
    for (key, val) in &meta_obj {
        match val {
            serde_json::Value::String(_) | serde_json::Value::Number(_) => {}
            serde_json::Value::Bool(_) => {
                return Err(format!(
                    "'meta.{}' has a boolean value. Only string and number values are allowed.",
                    key
                ));
            }
            serde_json::Value::Null => {
                return Err(format!(
                    "'meta.{}' has a null value. Only string and number values are allowed.",
                    key
                ));
            }
            serde_json::Value::Array(_) => {
                return Err(format!(
                    "'meta.{}' has an array value. Only string and number values are allowed.",
                    key
                ));
            }
            serde_json::Value::Object(_) => {
                return Err(format!(
                    "'meta.{}' has a nested object value. Only string and number values are allowed.",
                    key
                ));
            }
        }
    }

    Ok(ProxyAuth {
        set_name,
        affinity_minutes: minutes,
        username_b64: b64.to_string(),
        metadata: meta_obj,
    })
}

// ---------------------------------------------------------------------------
// Request handling
// ---------------------------------------------------------------------------

async fn handle_request(
    req: Request<Incoming>,
    rotator: Arc<Rotator>,
    peer: SocketAddr,
    api_key: Arc<Option<String>>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    if req.method() != Method::CONNECT {
        let path = req.uri().path();
        if path.starts_with("/api/") {
            return Ok(handle_api_request(&req, &rotator, &api_key).await);
        }
    }

    match handle_request_inner(req, rotator, peer).await {
        Ok(resp) => Ok(resp),
        Err(e) => {
            error!("Request handling error: {e:#}");
            Ok(error_response(
                StatusCode::BAD_GATEWAY,
                format!("Proxy error: {e:#}"),
            ))
        }
    }
}

async fn handle_request_inner(
    req: Request<Incoming>,
    rotator: Arc<Rotator>,
    peer: SocketAddr,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    let client_ip = peer.ip();

    let auth = match parse_proxy_auth(&req) {
        Ok(auth) => auth,
        Err(msg) => {
            warn!(
                method = %req.method(),
                uri = %req.uri(),
                client = %client_ip,
                "Auth error: {msg}"
            );
            return Ok(proxy_auth_error(&format!(
                r#"{}. Expected: Basic base64({{"meta":{{...}},"minutes":<0-1440>,"set":"<proxyset>"}}:). Available sets: {:?}"#,
                msg,
                rotator.set_names()
            )));
        }
    };

    let upstream = match rotator.next_proxy(
        &auth.set_name,
        auth.affinity_minutes,
        &auth.username_b64,
        auth.metadata,
    ) {
        Some(p) => p,
        None => {
            warn!(
                method = %req.method(),
                uri = %req.uri(),
                set = %auth.set_name,
                "Unknown proxy set"
            );
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                format!(
                    "Unknown proxy set '{}'. Available: {:?}",
                    auth.set_name,
                    rotator.set_names()
                ),
            ));
        }
    };

    info!(
        method = %req.method(),
        uri = %req.uri(),
        set = %auth.set_name,
        minutes = auth.affinity_minutes,
        upstream = %format!("{}:{}", upstream.host, upstream.port),
        client = %client_ip,
        "Routing request"
    );

    if req.method() == Method::CONNECT {
        handle_connect(req, &upstream).await
    } else {
        handle_http(req, &upstream).await
    }
}

// ---------------------------------------------------------------------------
// CONNECT
// ---------------------------------------------------------------------------

async fn handle_connect(
    req: Request<Incoming>,
    upstream: &crate::rotator::ResolvedProxy,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    let target_authority = req
        .uri()
        .authority()
        .map(|a| a.to_string())
        .unwrap_or_else(|| req.uri().to_string());

    let upstream = upstream.clone();
    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let io = TokioIo::new(upgraded);

                if let Err(e) = tunnel::handle_connect(io, target_authority, &upstream).await {
                    error!("Tunnel error: {e:#}");
                }
            }
            Err(e) => {
                error!("Upgrade failed: {e}");
            }
        }
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(empty_body())
        .unwrap())
}

// ---------------------------------------------------------------------------
// Plain HTTP forwarding
// ---------------------------------------------------------------------------

async fn handle_http(
    req: Request<Incoming>,
    upstream: &crate::rotator::ResolvedProxy,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    let method = req.method().to_string();
    let uri = req.uri().to_string();

    let headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .filter(|(k, _)| k.as_str() != "proxy-authorization")
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let body_bytes = req.collect().await?.to_bytes().to_vec();

    let response_bytes =
        tunnel::forward_http(&method, &uri, &headers, &body_bytes, upstream).await?;

    parse_raw_response(&response_bytes)
}

fn parse_raw_response(raw: &[u8]) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(raw.len());

    let header_section = &raw[..header_end];
    let body_start = std::cmp::min(header_end + 4, raw.len());
    let body = &raw[body_start..];

    let header_str = String::from_utf8_lossy(header_section);
    let mut lines = header_str.lines();

    let status_line = lines.next().unwrap_or("HTTP/1.1 502 Bad Gateway");
    let parts: Vec<&str> = status_line.splitn(3, ' ').collect();
    let status_code = parts
        .get(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(502);

    let mut builder = Response::builder()
        .status(StatusCode::from_u16(status_code).unwrap_or(StatusCode::BAD_GATEWAY));

    for line in lines {
        if let Some((key, value)) = line.split_once(": ") {
            builder = builder.header(key, value);
        } else if let Some((key, value)) = line.split_once(':') {
            builder = builder.header(key.trim(), value.trim());
        }
    }

    let body = Full::new(Bytes::copy_from_slice(body))
        .map_err(|never| match never {})
        .boxed();

    Ok(builder.body(body).unwrap())
}

// ---------------------------------------------------------------------------
// API routing
// ---------------------------------------------------------------------------

async fn handle_api_request(
    req: &Request<Incoming>,
    rotator: &Rotator,
    api_key: &Option<String>,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    use crate::api;

    let path = req.uri().path();

    if req.method() != Method::GET {
        return api::json_response(
            StatusCode::METHOD_NOT_ALLOWED,
            r#"{"error":"Only GET is allowed"}"#,
        );
    }

    if path == "/api/openapi.json" {
        return api::openapi_spec();
    }

    let expected_key = match api_key {
        Some(key) => key,
        None => {
            return api::json_response(
                StatusCode::NOT_FOUND,
                r#"{"error":"API not enabled (API_KEY env var not set)"}"#,
            );
        }
    };

    let auth_ok = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|token| token == expected_key)
        .unwrap_or(false);

    if !auth_ok {
        return api::unauthorized_response();
    }

    if path == "/api/sessions" {
        api::list_sessions(rotator)
    } else if let Some(raw) = path.strip_prefix("/api/sessions/") {
        let username_b64 = percent_decode(raw);
        // POST .../rotate — force-rotate the session's upstream proxy
        if req.method() == Method::POST && username_b64.ends_with("/rotate") {
            let key = username_b64.trim_end_matches("/rotate");
            return api::force_rotate(rotator, key);
        }
        api::get_session(rotator, &username_b64)
    } else if let Some(raw) = path.strip_prefix("/api/verify/") {
        let username_b64 = percent_decode(raw);
        api::verify_username(rotator, &username_b64).await
    } else {
        api::json_response(StatusCode::NOT_FOUND, r#"{"error":"Not found"}"#)
    }
}

/// Minimal percent-decoding for URL path segments (handles %XX sequences).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = char::from(bytes[i + 1]).to_digit(16);
            let lo = char::from(bytes[i + 2]).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push(char::from((h * 16 + l) as u8));
                i += 3;
                continue;
            }
        }
        out.push(char::from(bytes[i]));
        i += 1;
    }
    out
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn empty_body() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn error_response(status: StatusCode, message: String) -> Response<BoxBody<Bytes, hyper::Error>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .body(
            Full::new(Bytes::from(message))
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}

fn proxy_auth_error(message: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
    Response::builder()
        .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
        .header("Proxy-Authenticate", "Basic realm=\"proxy-gateway\"")
        .header("Content-Type", "text/plain")
        .body(
            Full::new(Bytes::from(message.to_string()))
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    /// Wrap a JSON string as a Basic auth header value (username = json, password = "").
    fn auth_header(username_json: &str) -> String {
        let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{username_json}:"));
        format!("Basic {encoded}")
    }

    /// Build a valid username JSON string from parts.
    fn make_username(set: &str, minutes: u64, meta_json: &str) -> String {
        format!(r#"{{"meta":{meta_json},"minutes":{minutes},"set":"{set}"}}"#)
    }

    // -----------------------------------------------------------------------
    // Valid cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_valid_basic() {
        let u = make_username("residential", 5, r#"{"app":"myapp","user":"alice"}"#);
        let auth = parse_proxy_auth_value(&auth_header(&u)).unwrap();
        assert_eq!(auth.set_name, "residential");
        assert_eq!(auth.affinity_minutes, 5);
        assert_eq!(
            auth.metadata["app"],
            serde_json::Value::String("myapp".to_string())
        );
        assert_eq!(
            auth.metadata["user"],
            serde_json::Value::String("alice".to_string())
        );
    }

    #[test]
    fn test_valid_mixed_meta_values() {
        let u = make_username("datacenter", 10, r#"{"count":42,"name":"test"}"#);
        let auth = parse_proxy_auth_value(&auth_header(&u)).unwrap();
        assert_eq!(auth.affinity_minutes, 10);
        assert_eq!(auth.metadata["count"], serde_json::Value::Number(42.into()));
    }

    #[test]
    fn test_valid_empty_meta() {
        let u = make_username("residential", 0, "{}");
        let auth = parse_proxy_auth_value(&auth_header(&u)).unwrap();
        assert_eq!(auth.affinity_minutes, 0);
        assert!(auth.metadata.is_empty());
    }

    #[test]
    fn test_valid_zero_minutes() {
        let u = make_username("datacenter", 0, r#"{"k":"v"}"#);
        let auth = parse_proxy_auth_value(&auth_header(&u)).unwrap();
        assert_eq!(auth.affinity_minutes, 0);
    }

    #[test]
    fn test_valid_max_minutes() {
        let u = make_username("residential", 1440, r#"{"k":"v"}"#);
        let auth = parse_proxy_auth_value(&auth_header(&u)).unwrap();
        assert_eq!(auth.affinity_minutes, 1440);
    }

    #[test]
    fn test_meta_any_key_order_accepted() {
        // Keys in any order should be fine now
        let u = make_username("residential", 5, r#"{"z":"last","a":"first","m":"mid"}"#);
        assert!(parse_proxy_auth_value(&auth_header(&u)).is_ok());
    }

    #[test]
    fn test_outer_keys_any_order_accepted() {
        // Outer keys in any order are fine — presence check only
        let u = r#"{"set":"residential","meta":{},"minutes":5}"#;
        assert!(parse_proxy_auth_value(&auth_header(u)).is_ok());
        let u2 = r#"{"minutes":5,"set":"residential","meta":{}}"#;
        assert!(parse_proxy_auth_value(&auth_header(u2)).is_ok());
    }

    #[test]
    fn test_username_b64_is_stable() {
        let u = make_username("residential", 5, r#"{"app":"myapp"}"#);
        let a = parse_proxy_auth_value(&auth_header(&u)).unwrap();
        let b = parse_proxy_auth_value(&auth_header(&u)).unwrap();
        assert_eq!(a.username_b64, b.username_b64);
    }

    // -----------------------------------------------------------------------
    // Outer object structure
    // -----------------------------------------------------------------------

    #[test]
    fn test_not_basic_auth() {
        assert!(parse_proxy_auth_value("Bearer token123").is_err());
    }

    #[test]
    fn test_empty_username() {
        assert!(parse_proxy_auth_value(&auth_header("")).is_err());
    }

    #[test]
    fn test_not_json_object() {
        assert!(parse_proxy_auth_value(&auth_header("hello")).is_err());
        assert!(parse_proxy_auth_value(&auth_header("[1,2,3]")).is_err());
    }

    #[test]
    fn test_missing_key_set() {
        let u = r#"{"meta":{},"minutes":5}"#;
        assert!(parse_proxy_auth_value(&auth_header(u)).is_err());
    }

    #[test]
    fn test_missing_key_minutes() {
        let u = r#"{"meta":{},"set":"residential"}"#;
        assert!(parse_proxy_auth_value(&auth_header(u)).is_err());
    }

    #[test]
    fn test_missing_key_meta() {
        let u = r#"{"minutes":5,"set":"residential"}"#;
        assert!(parse_proxy_auth_value(&auth_header(u)).is_err());
    }

    #[test]
    fn test_extra_key_rejected() {
        let u = r#"{"extra":"x","meta":{},"minutes":5,"set":"residential"}"#;
        assert!(parse_proxy_auth_value(&auth_header(u)).is_err());
    }

    // -----------------------------------------------------------------------
    // `set` validation
    // -----------------------------------------------------------------------

    #[test]
    fn test_set_empty_rejected() {
        let u = r#"{"meta":{},"minutes":5,"set":""}"#;
        assert!(parse_proxy_auth_value(&auth_header(u)).is_err());
    }

    #[test]
    fn test_set_non_alphanumeric_rejected() {
        let u = r#"{"meta":{},"minutes":5,"set":"resi-dential"}"#;
        assert!(parse_proxy_auth_value(&auth_header(u)).is_err());
    }

    #[test]
    fn test_set_not_string_rejected() {
        let u = r#"{"meta":{},"minutes":5,"set":123}"#;
        assert!(parse_proxy_auth_value(&auth_header(u)).is_err());
    }

    // -----------------------------------------------------------------------
    // `minutes` validation
    // -----------------------------------------------------------------------

    #[test]
    fn test_minutes_too_high() {
        let u = make_username("residential", 1441, r#"{"k":"v"}"#);
        assert!(parse_proxy_auth_value(&auth_header(&u)).is_err());
    }

    #[test]
    fn test_minutes_float_rejected() {
        let u = r#"{"meta":{},"minutes":5.5,"set":"residential"}"#;
        assert!(parse_proxy_auth_value(&auth_header(u)).is_err());
    }

    #[test]
    fn test_minutes_string_rejected() {
        let u = r#"{"meta":{},"minutes":"5","set":"residential"}"#;
        assert!(parse_proxy_auth_value(&auth_header(u)).is_err());
    }

    // -----------------------------------------------------------------------
    // `meta` validation
    // -----------------------------------------------------------------------

    #[test]
    fn test_meta_nested_object_rejected() {
        let u = make_username("residential", 5, r#"{"a":{"b":1}}"#);
        let err = parse_proxy_auth_value(&auth_header(&u)).unwrap_err();
        assert!(err.contains("nested object"), "got: {err}");
    }

    #[test]
    fn test_meta_array_rejected() {
        let u = make_username("residential", 5, r#"{"a":[1,2,3]}"#);
        let err = parse_proxy_auth_value(&auth_header(&u)).unwrap_err();
        assert!(err.contains("array"), "got: {err}");
    }

    #[test]
    fn test_meta_boolean_rejected() {
        let u = make_username("residential", 5, r#"{"flag":true}"#);
        let err = parse_proxy_auth_value(&auth_header(&u)).unwrap_err();
        assert!(err.contains("boolean"), "got: {err}");
    }

    #[test]
    fn test_meta_null_rejected() {
        let u = make_username("residential", 5, r#"{"key":null}"#);
        let err = parse_proxy_auth_value(&auth_header(&u)).unwrap_err();
        assert!(err.contains("null"), "got: {err}");
    }

    #[test]
    fn test_meta_not_object_rejected() {
        let u = r#"{"meta":"notanobject","minutes":5,"set":"residential"}"#;
        assert!(parse_proxy_auth_value(&auth_header(u)).is_err());
    }

    // -----------------------------------------------------------------------
    // percent_decode
    // -----------------------------------------------------------------------

    #[test]
    fn test_percent_decode_plus_slash_equals() {
        // Base64 chars that get percent-encoded in URLs
        assert_eq!(percent_decode("abc%2Bdef"), "abc+def");
        assert_eq!(percent_decode("abc%2Fdef"), "abc/def");
        assert_eq!(percent_decode("abc%3Ddef"), "abc=def");
        assert_eq!(percent_decode("plain"), "plain");
        assert_eq!(percent_decode(""), "");
    }
}
