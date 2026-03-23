//! API endpoint handlers and OpenAPI spec generation.
//!
//! Each public handler function is annotated with `#[utoipa::path]` to generate
//! the OpenAPI documentation. These are the real handlers called from `proxy.rs`.

use crate::rotator::{ApiError, Rotator, SessionInfo, VerifyResult};
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::{Response, StatusCode};

// ---------------------------------------------------------------------------
// Handlers — called from proxy::handle_api_request
// ---------------------------------------------------------------------------

/// List all active sessions
///
/// Returns all currently active sticky sessions across all proxy sets.
/// Sessions with 0 minutes (no affinity) are not tracked and won't appear here.
#[utoipa::path(
    get,
    path = "/api/sessions",
    responses(
        (status = 200, description = "List of active sessions", body = Vec<SessionInfo>),
        (status = 401, description = "Invalid or missing API key", body = ApiError),
    ),
    security(
        ("bearer" = [])
    )
)]
pub fn list_sessions(rotator: &Rotator) -> Response<BoxBody<Bytes, hyper::Error>> {
    let sessions = rotator.list_sessions();
    let json = serde_json::to_string(&sessions).unwrap_or_else(|_| "[]".to_string());
    json_response(StatusCode::OK, &json)
}

/// Get session by username
///
/// Returns details of a specific active session identified by its full username
/// in the format `<proxyset>-<minutes>-<base64json>`.
#[utoipa::path(
    get,
    path = "/api/sessions/{username}",
    params(
        ("username" = String, Path, description = "Full username in format <proxyset>-<minutes>-<base64json>", example = "residential-5-eyJhcHAiOiJteWFwcCIsInVzZXIiOiJhbGljZSJ9"),
    ),
    responses(
        (status = 200, description = "Session found", body = SessionInfo),
        (status = 401, description = "Invalid or missing API key", body = ApiError),
        (status = 404, description = "No active session for this username", body = ApiError),
    ),
    security(
        ("bearer" = [])
    )
)]
pub fn get_session(rotator: &Rotator, username: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
    if username.is_empty() {
        return json_response(
            StatusCode::BAD_REQUEST,
            r#"{"error":"Username is required"}"#,
        );
    }
    match rotator.get_session(username) {
        Some(info) => {
            let json = serde_json::to_string(&info).unwrap_or_else(|_| "{}".to_string());
            json_response(StatusCode::OK, &json)
        }
        None => json_response(
            StatusCode::NOT_FOUND,
            &format!(r#"{{"error":"No active session for '{}'"}}  "#, username),
        ),
    }
}

/// Force-rotate a session's upstream proxy
///
/// Immediately reassigns the upstream proxy for an existing session via
/// least-used selection and resets the session TTL. The session ID, metadata,
/// and affinity duration are preserved. Use this to escape a bad or slow proxy
/// without losing session continuity.
#[utoipa::path(
    post,
    path = "/api/sessions/{username}/rotate",
    params(
        ("username" = String, Path, description = "Percent-encoded base64 username of the session to rotate"),
    ),
    responses(
        (status = 200, description = "Session rotated — returns updated session info", body = SessionInfo),
        (status = 401, description = "Invalid or missing API key", body = ApiError),
        (status = 404, description = "No active session for this username", body = ApiError),
    ),
    security(
        ("bearer" = [])
    )
)]
pub fn force_rotate(rotator: &Rotator, username: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
    if username.is_empty() {
        return json_response(
            StatusCode::BAD_REQUEST,
            r#"{"error":"Username is required"}"#,
        );
    }
    match rotator.force_rotate(username) {
        Some(info) => {
            let json = serde_json::to_string(&info).unwrap_or_else(|_| "{}".to_string());
            json_response(StatusCode::OK, &json)
        }
        None => json_response(
            StatusCode::NOT_FOUND,
            &format!(r#"{{"error":"No active session for '{}'"}}  "#, username),
        ),
    }
}

/// Verify a proxy username
///
/// Parses the username, checks the proxy set exists, picks an upstream proxy,
/// connects through it, and returns the outbound IP. This is a pre-flight check
/// that runs before any session is created — it does not create affinity entries.
///
/// The username is the percent-encoded base64 string in the path.
#[utoipa::path(
    get,
    path = "/api/verify/{username}",
    params(
        ("username" = String, Path, description = "Percent-encoded base64 username to verify"),
    ),
    responses(
        (status = 200, description = "Verification result (check ok field)", body = VerifyResult),
        (status = 401, description = "Invalid or missing API key", body = ApiError),
    ),
    security(
        ("bearer" = [])
    )
)]
pub async fn verify_username(
    rotator: &Rotator,
    username_b64: &str,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    use crate::proxy::parse_proxy_auth_value_for_verify;

    // 1. Parse the username JSON.
    let auth = match parse_proxy_auth_value_for_verify(username_b64) {
        Ok(a) => a,
        Err(e) => {
            let result = VerifyResult {
                ok: false,
                proxy_set: String::new(),
                minutes: 0,
                metadata: serde_json::Map::new(),
                upstream: String::new(),
                ip: String::new(),
                error: Some(format!("Invalid username: {e}")),
            };
            return json_response(StatusCode::OK, &serde_json::to_string(&result).unwrap());
        }
    };

    // 2. Check the proxy set exists and pick a proxy without creating a session.
    let upstream = match rotator.pick_any(&auth.set_name) {
        Some(p) => p,
        None => {
            let result = VerifyResult {
                ok: false,
                proxy_set: auth.set_name.clone(),
                minutes: auth.affinity_minutes,
                metadata: auth.metadata,
                upstream: String::new(),
                ip: String::new(),
                error: Some(format!(
                    "Unknown proxy set '{}'. Available: {:?}",
                    auth.set_name,
                    rotator.set_names()
                )),
            };
            return json_response(StatusCode::OK, &serde_json::to_string(&result).unwrap());
        }
    };

    let upstream_addr = format!("{}:{}", upstream.host, upstream.port);

    // 3. Fetch the outbound IP through the proxy.
    let ip = fetch_ip_through_proxy(&upstream).await;

    match ip {
        Ok(ip) => {
            let result = VerifyResult {
                ok: true,
                proxy_set: auth.set_name,
                minutes: auth.affinity_minutes,
                metadata: auth.metadata,
                upstream: upstream_addr,
                ip,
                error: None,
            };
            json_response(StatusCode::OK, &serde_json::to_string(&result).unwrap())
        }
        Err(e) => {
            let result = VerifyResult {
                ok: false,
                proxy_set: auth.set_name,
                minutes: auth.affinity_minutes,
                metadata: auth.metadata,
                upstream: upstream_addr,
                ip: String::new(),
                error: Some(format!("Proxy connectivity check failed: {e}")),
            };
            json_response(StatusCode::OK, &serde_json::to_string(&result).unwrap())
        }
    }
}

/// Fetch the outbound IP via api.ipify.org through the given upstream proxy.
async fn fetch_ip_through_proxy(
    upstream: &crate::rotator::ResolvedProxy,
) -> anyhow::Result<String> {
    let raw = crate::tunnel::forward_http(
        "GET",
        "http://api.ipify.org/?format=text",
        &[("Host".to_string(), "api.ipify.org".to_string())],
        &[],
        upstream,
    )
    .await?;

    // forward_http returns a raw HTTP response — extract the body after \r\n\r\n
    let sep = b"\r\n\r\n";
    let body_start = raw
        .windows(sep.len())
        .position(|w| w == sep)
        .map(|p| p + sep.len())
        .unwrap_or(raw.len());
    let ip = String::from_utf8_lossy(&raw[body_start..])
        .trim()
        .to_string();

    if ip.is_empty() {
        anyhow::bail!("Empty response from ip check");
    }
    Ok(ip)
}

/// Get the OpenAPI spec
///
/// Returns the OpenAPI 3.1 JSON specification for this API.
/// This endpoint is publicly accessible (no authentication required).
pub fn openapi_spec() -> Response<BoxBody<Bytes, hyper::Error>> {
    json_response(StatusCode::OK, &openapi_json())
}

// ---------------------------------------------------------------------------
// OpenAPI spec generation
// ---------------------------------------------------------------------------

#[derive(utoipa::OpenApi)]
#[openapi(
    info(
        title = "Proxy Gateway API",
        version = "0.7.0",
        description = "API for inspecting active proxy sessions in proxy-gateway.\n\nAuthenticate with `Authorization: Bearer <api_key>` where `api_key` is set via the `API_KEY` environment variable.",
    ),
    paths(
        list_sessions,
        get_session,
        force_rotate,
        verify_username,
    ),
    components(
        schemas(SessionInfo, ApiError, VerifyResult),
    ),
    modifiers(&SecurityAddon),
)]
pub struct ApiDoc;

/// Generate the OpenAPI JSON spec as a pretty-printed string.
pub fn openapi_json() -> String {
    use utoipa::OpenApi;
    ApiDoc::openapi()
        .to_pretty_json()
        .unwrap_or_else(|e| panic!("Failed to serialize OpenAPI spec: {e}"))
}

struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer",
                utoipa::openapi::security::SecurityScheme::Http(
                    utoipa::openapi::security::HttpBuilder::new()
                        .scheme(utoipa::openapi::security::HttpAuthScheme::Bearer)
                        .bearer_format("API Key")
                        .description(Some(
                            "API key set via the API_KEY environment variable. Pass as: Authorization: Bearer <api_key>",
                        ))
                        .build(),
                ),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub fn json_response(status: StatusCode, body: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(
            Full::new(Bytes::from(body.to_string()))
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}

pub fn unauthorized_response() -> Response<BoxBody<Bytes, hyper::Error>> {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("Content-Type", "application/json")
        .header("WWW-Authenticate", "Bearer")
        .body(
            Full::new(Bytes::from(r#"{"error":"Invalid or missing API key"}"#))
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openapi_spec_is_valid_json() {
        let json = openapi_json();
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("OpenAPI spec should be valid JSON");

        assert!(parsed["openapi"].as_str().unwrap().starts_with("3.1"));
        assert_eq!(
            parsed["info"]["title"].as_str().unwrap(),
            "Proxy Gateway API"
        );
        assert!(parsed["paths"]["/api/sessions"].is_object());
        assert!(parsed["paths"]["/api/sessions/{username}"].is_object());
        assert!(parsed["components"]["schemas"]["SessionInfo"].is_object());
        assert!(parsed["components"]["schemas"]["ApiError"].is_object());

        // Verify the new fields appear in the SessionInfo schema.
        let session_props = &parsed["components"]["schemas"]["SessionInfo"]["properties"];
        assert!(
            session_props["session_id"].is_object(),
            "SessionInfo should have session_id field"
        );
        assert!(
            session_props["metadata"].is_object(),
            "SessionInfo should have metadata field"
        );
        assert!(
            session_props["username"].is_object(),
            "SessionInfo should still have username field"
        );
    }
}
