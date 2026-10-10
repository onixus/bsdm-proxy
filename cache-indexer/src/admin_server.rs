//! HTTP admin server: /metrics, /health, /api/search, /api/events

use crate::metrics::IndexerMetrics;
use crate::search_api::SearchApi;
use prometheus::{Encoder, TextEncoder};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

/// Default host for the admin listener (`METRICS_BIND`). `0.0.0.0` keeps the
/// pre-1.0 behaviour (containers / k8s reach the Search API over the network);
/// set `METRICS_BIND=127.0.0.1` on hosts where only local clients need it.
const DEFAULT_BIND_HOST: &str = "0.0.0.0";
/// Default cap on concurrent admin connections (`INDEXER_HTTP_MAX_CONNECTIONS`).
const DEFAULT_MAX_CONNECTIONS: usize = 256;
/// Default deadline to receive a full request and to send the response
/// (`INDEXER_HTTP_READ_TIMEOUT_MS`).
const DEFAULT_READ_TIMEOUT_MS: u64 = 10_000;
/// Max request head size; larger heads are rejected with 400.
const MAX_HEADER_BYTES: usize = 64 * 1024;

/// Listener limits for the admin / Search API server (AS-13).
#[derive(Clone, Debug)]
pub struct AdminServerLimits {
    pub bind_host: String,
    pub max_connections: usize,
    pub read_timeout: Duration,
}

impl AdminServerLimits {
    pub fn from_env() -> Self {
        let bind_host = std::env::var("METRICS_BIND")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| DEFAULT_BIND_HOST.to_string());
        let max_connections = std::env::var("INDEXER_HTTP_MAX_CONNECTIONS")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(DEFAULT_MAX_CONNECTIONS)
            .max(1);
        let read_timeout_ms = std::env::var("INDEXER_HTTP_READ_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(DEFAULT_READ_TIMEOUT_MS)
            .max(1);
        Self {
            bind_host,
            max_connections,
            read_timeout: Duration::from_millis(read_timeout_ms),
        }
    }

    fn bind_addr(&self, port: u16) -> String {
        // Bare IPv6 literals need brackets in `host:port` form.
        if self.bind_host.contains(':') && !self.bind_host.starts_with('[') {
            format!("[{}]:{port}", self.bind_host)
        } else {
            format!("{}:{port}", self.bind_host)
        }
    }
}

pub async fn run_admin_server(
    port: u16,
    metrics: Arc<IndexerMetrics>,
    search_api: Option<Arc<SearchApi>>,
) {
    let limits = AdminServerLimits::from_env();
    let bind_addr = limits.bind_addr(port);
    let listener = match TcpListener::bind(&bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind cache-indexer admin on {bind_addr}: {e}");
            return;
        }
    };
    let extras = match &search_api {
        Some(_) => ", /api/search, /api/events",
        None => "",
    };
    info!(
        "cache-indexer admin on {bind_addr} (/metrics, /health{extras}; max_connections={}, read_timeout={:?})",
        limits.max_connections, limits.read_timeout
    );
    serve(listener, limits, metrics, search_api).await;
}

async fn serve(
    listener: TcpListener,
    limits: AdminServerLimits,
    metrics: Arc<IndexerMetrics>,
    search_api: Option<Arc<SearchApi>>,
) {
    let conn_limit = Arc::new(Semaphore::new(limits.max_connections));
    let timeout = limits.read_timeout;
    loop {
        let Ok((mut socket, peer)) = listener.accept().await else {
            continue;
        };
        let Ok(permit) = conn_limit.clone().try_acquire_owned() else {
            // Shed instead of queueing: idle clients cannot starve the server.
            debug!("admin: connection limit reached, dropping {peer}");
            continue;
        };
        let metrics = metrics.clone();
        let search_api = search_api.clone();
        tokio::spawn(async move {
            let _permit = permit;
            // Authenticate ingest by its headers before buffering up to 4 MiB
            // of body: unauthenticated clients get 401 without the upload.
            let api = search_api.clone();
            let wants_body = move |header: &str| body_allowed(header, api.as_deref());
            let request =
                match tokio::time::timeout(timeout, read_request(&mut socket, wants_body)).await {
                    Ok(Some(r)) => r,
                    Ok(None) => return,
                    Err(_) => {
                        debug!("admin: read timeout from {peer}");
                        return;
                    }
                };
            let response = match request {
                Ok((header, body)) => {
                    handle_request(&header, &body, &metrics, search_api.as_deref()).await
                }
                Err(()) => http_response(400, "text/plain", b"bad request", None),
            };
            let _ = tokio::time::timeout(timeout, socket.write_all(&response)).await;
        });
    }
}

/// Whether the body of the request with this `header` should be read: only
/// for an authorized `POST /api/events` (the only route that uses a body).
fn body_allowed(header: &str, search_api: Option<&SearchApi>) -> bool {
    let mut request_line = header.lines().next().unwrap_or("").split_whitespace();
    let method = request_line.next().unwrap_or("");
    let path = request_line.next().unwrap_or("");
    if method != "POST" || !path.starts_with("/api/events") {
        return false;
    }
    let auth = header
        .lines()
        .skip(1)
        .take_while(|line| !line.is_empty())
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("authorization")
                .then(|| value.trim())
        });
    search_api.is_some_and(|api| api.is_ingest_authorized(auth))
}

/// Reads one request head and, when `wants_body(head)` allows it, the body.
/// `None` = client closed before sending anything; `Some(Err(()))` =
/// malformed / oversized head.
async fn read_request<S>(
    socket: &mut S,
    wants_body: impl Fn(&str) -> bool,
) -> Option<Result<(String, Vec<u8>), ()>>
where
    S: AsyncRead + Unpin,
{
    let mut buf = vec![0u8; MAX_HEADER_BYTES];
    let mut n = 0usize;
    let (header_end, content_length) = loop {
        let m = socket.read(&mut buf[n..]).await.unwrap_or(0);
        if m == 0 {
            if n == 0 {
                return None;
            }
            return Some(Err(()));
        }
        n += m;
        if let Some(v) = parse_header_end_and_cl(&buf[..n]) {
            break v;
        }
        if n == buf.len() {
            return Some(Err(()));
        }
    };
    let header = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    if !wants_body(&header) {
        return Some(Ok((header, Vec::new())));
    }
    let mut body = buf[header_end..n].to_vec();
    while body.len() < content_length {
        let mut chunk = vec![0u8; 64 * 1024];
        let m = socket.read(&mut chunk).await.unwrap_or(0);
        if m == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..m]);
    }
    body.truncate(content_length);
    Some(Ok((header, body)))
}

fn parse_header_end_and_cl(buf: &[u8]) -> Option<(usize, usize)> {
    let header_end = find_header_end(buf)?;
    let header = std::str::from_utf8(&buf[..header_end]).ok()?;
    let mut content_length = 0usize;
    for line in header.lines().skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some(v) = line
            .strip_prefix("Content-Length:")
            .or_else(|| line.strip_prefix("content-length:"))
        {
            content_length = v.trim().parse().unwrap_or(0);
        }
    }
    // Cap POST body for ingest to 4 MiB
    Some((header_end, content_length.min(4 * 1024 * 1024)))
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

async fn handle_request(
    header: &str,
    body: &[u8],
    metrics: &IndexerMetrics,
    search_api: Option<&SearchApi>,
) -> Vec<u8> {
    let mut lines = header.lines();
    let Some(request_line) = lines.next() else {
        return http_response(400, "text/plain", b"bad request", None);
    };
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path_query = parts.next().unwrap_or("/");

    let mut auth: Option<String> = None;
    let mut origin: Option<String> = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some(value) = line
            .strip_prefix("Authorization: ")
            .or_else(|| line.strip_prefix("authorization: "))
        {
            auth = Some(value.trim().to_string());
        } else if let Some(value) = line
            .strip_prefix("Origin: ")
            .or_else(|| line.strip_prefix("origin: "))
        {
            origin = Some(value.trim().to_string());
        }
    }
    let origin = origin.as_deref();

    // CORS preflight for Admin Console (browser origin often differs from Search :8080).
    if method == "OPTIONS" {
        return http_response(204, "text/plain", b"", origin);
    }

    if method == "GET" && path_query.starts_with("/metrics") {
        let encoder = TextEncoder::new();
        let mut buffer = Vec::new();
        if encoder
            .encode(&metrics.registry().gather(), &mut buffer)
            .is_err()
        {
            return http_response(500, "text/plain", b"encode error", origin);
        }
        return http_response(
            200,
            "text/plain; version=0.0.4; charset=utf-8",
            &buffer,
            origin,
        );
    }

    if method == "GET" && path_query.starts_with("/health") {
        return http_response(200, "application/json", br#"{"status":"ok"}"#, origin);
    }

    if method == "GET" && path_query.starts_with("/api/search") {
        let Some(api) = search_api else {
            return http_response(
                404,
                "application/json",
                br#"{"error":"search api disabled"}"#,
                origin,
            );
        };
        if !api.is_authorized(auth.as_deref()) {
            return http_response(
                401,
                "application/json",
                br#"{"error":"unauthorized"}"#,
                origin,
            );
        }
        let query = parse_query_string(path_query);
        return match api.handle_get(&query).await {
            Ok((code, content_type, body)) => http_response(code, &content_type, &body, origin),
            Err(e) => {
                warn!("search api error: {e}");
                let msg = format!(r#"{{"error":"{}"}}"#, escape_json(&e.to_string()));
                http_response(500, "application/json", msg.as_bytes(), origin)
            }
        };
    }

    if method == "POST" && path_query.starts_with("/api/events") {
        let Some(api) = search_api else {
            return http_response(
                404,
                "application/json",
                br#"{"error":"ingest api disabled"}"#,
                origin,
            );
        };
        if !api.is_ingest_authorized(auth.as_deref()) {
            return http_response(
                401,
                "application/json",
                br#"{"error":"unauthorized"}"#,
                origin,
            );
        }
        return match api.handle_ingest(body).await {
            Ok((code, content_type, body)) => http_response(code, &content_type, &body, origin),
            Err(e) => {
                warn!("ingest api error: {e}");
                let msg = format!(r#"{{"error":"{}"}}"#, escape_json(&e.to_string()));
                http_response(400, "application/json", msg.as_bytes(), origin)
            }
        };
    }

    http_response(404, "text/plain", b"not found", origin)
}

fn parse_query_string(path_query: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let Some(qs) = path_query.split('?').nth(1) else {
        return map;
    };
    for pair in qs.split('&') {
        let mut kv = pair.splitn(2, '=');
        let key = kv.next().unwrap_or("");
        let value = kv.next().unwrap_or("");
        if !key.is_empty() {
            map.insert(percent_decode(key), percent_decode(value));
        }
    }
    map
}

fn percent_decode(s: &str) -> String {
    let mut out = String::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) =
                u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16)
            {
                out.push(byte as char);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out.replace('+', " ")
}

fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Reflect browser Origin for Admin Console cross-port calls (e.g. :9090 → :8080).
/// Only allow http(s) localhost / 127.0.0.1 / [::1] with optional port — not `*` or arbitrary subdomains.
fn cors_origin_allowed(origin: &str) -> bool {
    let o = origin.trim();
    if o.is_empty() {
        return false;
    }
    for prefix in &[
        "http://localhost",
        "https://localhost",
        "http://127.0.0.1",
        "https://127.0.0.1",
        "http://[::1]",
        "https://[::1]",
    ] {
        if let Some(rest) = o.strip_prefix(prefix) {
            // Must either be exact end of string or followed by port separator ':'
            if rest.is_empty() || rest.starts_with(':') {
                return true;
            }
        }
    }
    false
}

fn http_response(
    status_code: u16,
    content_type: &str,
    body: &[u8],
    origin: Option<&str>,
) -> Vec<u8> {
    let status = match status_code {
        200 => "200 OK",
        202 => "202 Accepted",
        204 => "204 No Content",
        400 => "400 Bad Request",
        401 => "401 Unauthorized",
        404 => "404 Not Found",
        500 => "500 Internal Server Error",
        _ => "500 Internal Server Error",
    };
    let mut header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: strict-origin-when-cross-origin\r\n",
        body.len()
    );
    if let Some(o) = origin.filter(|o| cors_origin_allowed(o)) {
        header.push_str(&format!("Access-Control-Allow-Origin: {o}\r\n"));
        header.push_str("Access-Control-Allow-Credentials: true\r\n");
        header.push_str("Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n");
        header.push_str("Access-Control-Allow-Headers: Authorization, Content-Type, Accept\r\n");
        header.push_str("Access-Control-Max-Age: 86400\r\n");
        header.push_str("Vary: Origin\r\n");
    }
    header.push_str("\r\n");
    let mut out = header.into_bytes();
    out.extend_from_slice(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_search_query() {
        let q = parse_query_string("/api/search?domain=example.com&limit=10");
        assert_eq!(q.get("domain").map(String::as_str), Some("example.com"));
        assert_eq!(q.get("limit").map(String::as_str), Some("10"));
    }

    #[test]
    fn finds_header_end() {
        let req = b"POST /api/events HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}";
        let (end, cl) = parse_header_end_and_cl(req).unwrap();
        assert_eq!(cl, 2);
        assert!(end > 10);
    }

    fn test_limits(max_connections: usize, timeout_ms: u64) -> AdminServerLimits {
        AdminServerLimits {
            bind_host: "127.0.0.1".into(),
            max_connections,
            read_timeout: Duration::from_millis(timeout_ms),
        }
    }

    async fn spawn_server(limits: AdminServerLimits) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let metrics = Arc::new(IndexerMetrics::new().unwrap());
        tokio::spawn(serve(listener, limits, metrics, None));
        addr
    }

    async fn get_health(addr: std::net::SocketAddr) -> String {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        // Head split across two writes must still be parsed.
        s.write_all(b"GET /health HTTP/1.1\r\n").await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        s.write_all(b"Host: x\r\n\r\n").await.unwrap();
        let mut out = String::new();
        tokio::time::timeout(Duration::from_secs(2), s.read_to_string(&mut out))
            .await
            .unwrap()
            .unwrap();
        out
    }

    #[test]
    fn bind_addr_defaults_and_ipv6() {
        let mut l = test_limits(1, 1);
        assert_eq!(l.bind_addr(8080), "127.0.0.1:8080");
        l.bind_host = "::1".into();
        assert_eq!(l.bind_addr(8080), "[::1]:8080");
        l.bind_host = "[::]".into();
        assert_eq!(l.bind_addr(8080), "[::]:8080");
        assert_eq!(DEFAULT_BIND_HOST, "0.0.0.0");
    }

    /// AS-13: silent clients are disconnected after the read timeout, and
    /// over-limit connections are shed while the server keeps serving.
    #[tokio::test]
    async fn idle_connections_time_out_and_limit_is_enforced() {
        let addr = spawn_server(test_limits(2, 300)).await;
        let mut idle1 = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut idle2 = tokio::net::TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut over = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut b = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_millis(200), over.read(&mut b))
            .await
            .expect("over-limit connection must be closed immediately")
            .unwrap_or(0);
        assert_eq!(n, 0);

        for s in [&mut idle1, &mut idle2] {
            let n = tokio::time::timeout(Duration::from_secs(2), s.read(&mut b))
                .await
                .expect("idle connection survived the read timeout")
                .unwrap_or(0);
            assert_eq!(n, 0);
        }
        let resp = get_health(addr).await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
    }

    fn token_api(token: &str) -> Arc<SearchApi> {
        let store = Arc::new(crate::store::EventStore::Memory(
            crate::store::MemoryStore::new(10),
        ));
        Arc::new(SearchApi::new(
            store,
            crate::search_api::SearchApiConfig {
                api_token: Some(token.to_string()),
                ingest_token: Some(token.to_string()),
                max_limit: 10,
                default_days: 1,
            },
        ))
    }

    #[test]
    fn body_is_read_only_for_authorized_ingest() {
        let api = token_api("tok");
        let post =
            |auth: &str| format!("POST /api/events HTTP/1.1\r\nContent-Length: 2\r\n{auth}\r\n");
        assert!(body_allowed(
            &post("Authorization: Bearer tok\r\n"),
            Some(&api)
        ));
        assert!(body_allowed(
            &post("authorization:Bearer tok\r\n"),
            Some(&api)
        ));
        assert!(!body_allowed(
            &post("Authorization: Bearer nope\r\n"),
            Some(&api)
        ));
        assert!(!body_allowed(&post(""), Some(&api)));
        assert!(!body_allowed(&post("Authorization: Bearer tok\r\n"), None));
        assert!(!body_allowed(
            "GET /api/events HTTP/1.1\r\nAuthorization: Bearer tok\r\n\r\n",
            Some(&api)
        ));
    }

    /// Unauthenticated ingest is answered 401 from the headers alone, without
    /// waiting for (or buffering) the announced body.
    #[tokio::test]
    async fn unauthenticated_ingest_is_rejected_before_body() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let metrics = Arc::new(IndexerMetrics::new().unwrap());
        tokio::spawn(serve(
            listener,
            test_limits(4, 5_000),
            metrics,
            Some(token_api("tok")),
        ));
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(b"POST /api/events HTTP/1.1\r\nContent-Length: 4000000\r\n\r\n")
            .await
            .unwrap();
        let mut out = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), s.read_to_end(&mut out))
            .await
            .expect("401 must not wait for the 4 MB body")
            .unwrap();
        assert!(
            out.starts_with(b"HTTP/1.1 401"),
            "{:?}",
            String::from_utf8_lossy(&out)
        );
    }

    #[tokio::test]
    async fn trickled_body_is_cut_off_by_read_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let metrics = Arc::new(IndexerMetrics::new().unwrap());
        tokio::spawn(serve(
            listener,
            test_limits(4, 300),
            metrics,
            Some(token_api("tok")),
        ));
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(
            b"POST /api/events HTTP/1.1\r\nAuthorization: Bearer tok\r\nContent-Length: 1000\r\n\r\n{",
        )
            .await
            .unwrap();
        let mut out = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), s.read_to_end(&mut out))
            .await
            .expect("slow body was not cut off")
            .unwrap();
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn oversized_head_is_rejected() {
        let addr = spawn_server(test_limits(4, 2_000)).await;
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut head = b"GET /health HTTP/1.1\r\nX-Pad: ".to_vec();
        head.extend(std::iter::repeat_n(b'a', MAX_HEADER_BYTES));
        let _ = s.write_all(&head).await;
        let mut out = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), s.read_to_end(&mut out)).await;
        assert!(
            out.starts_with(b"HTTP/1.1 400"),
            "{:?}",
            String::from_utf8_lossy(&out)
        );
    }

    #[test]
    fn cors_origin_validation_allows_safe_local_origins() {
        assert!(cors_origin_allowed("http://localhost"));
        assert!(cors_origin_allowed("http://localhost:3000"));
        assert!(cors_origin_allowed("https://localhost:9090"));
        assert!(cors_origin_allowed("http://127.0.0.1"));
        assert!(cors_origin_allowed("http://127.0.0.1:8080"));
        assert!(cors_origin_allowed("http://[::1]:9090"));
    }

    #[test]
    fn cors_origin_validation_rejects_subdomain_spoofing() {
        assert!(!cors_origin_allowed("http://localhost.evil.com"));
        assert!(!cors_origin_allowed("http://localhost.attacker.io:3000"));
        assert!(!cors_origin_allowed("http://127.0.0.1.attacker.com"));
        assert!(!cors_origin_allowed("https://127.0.0.1.fake.org"));
        assert!(!cors_origin_allowed("http://evil.com"));
        assert!(!cors_origin_allowed(""));
    }
}
