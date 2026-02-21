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

pub async fn run_proxy(bind_addr: &str, rotator: Arc<Rotator>) -> Result<()> {
    let listener = TcpListener::bind(bind_addr).await?;

    info!("Proxy rotator listening on {bind_addr}");
    info!("Available proxy sets: {:?}", rotator.set_names());
    for name in rotator.set_names() {
        if let Some((count, affinity)) = rotator.set_info(name) {
            info!(
                "  set '{}': {} proxies, affinity={}s",
                name, count, affinity
            );
        }
    }
    info!("Usage: Proxy-Authorization: Basic base64(proxy_set_name:)");

    loop {
        let (stream, peer) = listener.accept().await?;
        debug!("Accepted connection from {peer}");

        let rotator = Arc::clone(&rotator);
        tokio::spawn(async move {
            let io = TokioIo::new(stream);

            let result = http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .serve_connection(
                    io,
                    service_fn(move |req| {
                        let rotator = Arc::clone(&rotator);
                        async move { handle_request(req, rotator, peer).await }
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

/// Parse the Proxy-Authorization header.
/// Format: `Basic base64(proxy_set_name:)`
/// The username is the proxy set name, password is unused (empty).
fn parse_proxy_set_name(req: &Request<Incoming>) -> Option<String> {
    let header_val = req
        .headers()
        .get("proxy-authorization")
        .and_then(|v| v.to_str().ok())?;

    let b64 = header_val.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    let decoded_str = String::from_utf8(decoded).ok()?;

    // Standard Basic auth: split on first ':'
    let username = match decoded_str.find(':') {
        Some(idx) => &decoded_str[..idx],
        None => decoded_str.as_str(),
    };

    if username.is_empty() {
        return None;
    }

    Some(username.to_string())
}

// ---------------------------------------------------------------------------
// Request handling
// ---------------------------------------------------------------------------

async fn handle_request(
    req: Request<Incoming>,
    rotator: Arc<Rotator>,
    peer: SocketAddr,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
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

    // Parse the proxy set name from Proxy-Authorization.
    let set_name = match parse_proxy_set_name(&req) {
        Some(name) => name,
        None => {
            // If there's only one proxy set, use it as default.
            let names = rotator.set_names();
            if names.len() == 1 {
                names[0].to_string()
            } else {
                warn!(
                    method = %req.method(),
                    uri = %req.uri(),
                    "Missing or empty Proxy-Authorization username"
                );
                return Ok(proxy_auth_error(&format!(
                    "Proxy-Authorization required. Available sets: {:?}",
                    rotator.set_names()
                )));
            }
        }
    };

    // Resolve the next upstream proxy.
    let upstream = match rotator.next_proxy(&set_name, client_ip) {
        Some(p) => p,
        None => {
            warn!(
                method = %req.method(),
                uri = %req.uri(),
                set = %set_name,
                "Unknown proxy set"
            );
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                format!(
                    "Unknown proxy set '{}'. Available: {:?}",
                    set_name,
                    rotator.set_names()
                ),
            ));
        }
    };

    info!(
        method = %req.method(),
        uri = %req.uri(),
        set = %set_name,
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

    // Collect headers, stripping our Proxy-Authorization.
    let headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .filter(|(k, _)| k.as_str() != "proxy-authorization")
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let body_bytes = req.collect().await?.to_bytes().to_vec();

    let response_bytes = tunnel::forward_http(&method, &uri, &headers, &body_bytes, upstream).await?;

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
        .header("Proxy-Authenticate", "Basic realm=\"proxy-rotator\"")
        .header("Content-Type", "text/plain")
        .body(
            Full::new(Bytes::from(message.to_string()))
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}
