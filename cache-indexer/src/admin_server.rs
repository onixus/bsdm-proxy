//! HTTP admin server: /metrics, /health, /api/search

use crate::metrics::IndexerMetrics;
use crate::search_api::SearchApi;
use prometheus::{Encoder, TextEncoder};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{error, info, warn};

pub async fn run_admin_server(
    port: u16,
    metrics: Arc<IndexerMetrics>,
    search_api: Option<Arc<SearchApi>>,
) {
    let bind_addr = format!("0.0.0.0:{port}");
    let listener = match TcpListener::bind(&bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind cache-indexer admin on {bind_addr}: {e}");
            return;
        }
    };
    let search_note = if search_api.is_some() {
        ", /api/search"
    } else {
        ""
    };
    info!("cache-indexer admin on {bind_addr} (/metrics, /health{search_note})");

    loop {
        let Ok((mut socket, _)) = listener.accept().await else {
            continue;
        };
        let metrics = metrics.clone();
        let search_api = search_api.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            let n = socket.read(&mut buf).await.unwrap_or(0);
            if n == 0 {
                return;
            }
            let req = String::from_utf8_lossy(&buf[..n]);
            let response = handle_request(&req, &metrics, search_api.as_deref()).await;
            let _ = socket.write_all(&response).await;
        });
    }
}

async fn handle_request(
    req: &str,
    metrics: &IndexerMetrics,
    search_api: Option<&SearchApi>,
) -> Vec<u8> {
    let mut lines = req.lines();
    let Some(request_line) = lines.next() else {
        return http_response(400, "text/plain", b"bad request");
    };
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path_query = parts.next().unwrap_or("/");

    let mut auth: Option<String> = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some(value) = line.strip_prefix("Authorization: ") {
            auth = Some(value.trim().to_string());
        }
    }

    if method == "GET" && path_query.starts_with("/metrics") {
        let encoder = TextEncoder::new();
        let mut buffer = Vec::new();
        if encoder
            .encode(&metrics.registry().gather(), &mut buffer)
            .is_err()
        {
            return http_response(500, "text/plain", b"encode error");
        }
        return http_response(200, "text/plain; version=0.0.4; charset=utf-8", &buffer);
    }

    if method == "GET" && path_query.starts_with("/health") {
        return http_response(200, "application/json", br#"{"status":"ok"}"#);
    }

    if method == "GET" && path_query.starts_with("/api/search") {
        let Some(api) = search_api else {
            return http_response(
                404,
                "application/json",
                br#"{"error":"search api disabled"}"#,
            );
        };
        if !api.is_authorized(auth.as_deref()) {
            return http_response(401, "application/json", br#"{"error":"unauthorized"}"#);
        }
        let query = parse_query_string(path_query);
        match api.handle_get(&query).await {
            Ok((code, content_type, body)) => http_response(code, &content_type, &body),
            Err(e) => {
                warn!("search api error: {e}");
                let msg = format!(r#"{{"error":"{}"}}"#, escape_json(&e.to_string()));
                http_response(500, "application/json", msg.as_bytes())
            }
        }
    } else {
        http_response(404, "text/plain", b"not found")
    }
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

fn http_response(status_code: u16, content_type: &str, body: &[u8]) -> Vec<u8> {
    let status = match status_code {
        200 => "200 OK",
        400 => "400 Bad Request",
        401 => "401 Unauthorized",
        404 => "404 Not Found",
        500 => "500 Internal Server Error",
        _ => "500 Internal Server Error",
    };
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
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
}
