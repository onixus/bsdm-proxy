//! HTTP admin server: /metrics, /health, /api/search, /api/events

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
    let extras = match &search_api {
        Some(_) => ", /api/search, /api/events",
        None => "",
    };
    info!("cache-indexer admin on {bind_addr} (/metrics, /health{extras})");

    loop {
        let Ok((mut socket, _)) = listener.accept().await else {
            continue;
        };
        let metrics = metrics.clone();
        let search_api = search_api.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 64 * 1024];
            let n = socket.read(&mut buf).await.unwrap_or(0);
            if n == 0 {
                return;
            }
            let (header_end, content_length) = match parse_header_end_and_cl(&buf[..n]) {
                Some(v) => v,
                None => {
                    let _ = socket
                        .write_all(&http_response(400, "text/plain", b"bad request"))
                        .await;
                    return;
                }
            };
            let mut body = if header_end < n {
                buf[header_end..n].to_vec()
            } else {
                Vec::new()
            };
            while body.len() < content_length {
                let mut chunk = vec![0u8; 64 * 1024];
                let m = socket.read(&mut chunk).await.unwrap_or(0);
                if m == 0 {
                    break;
                }
                body.extend_from_slice(&chunk[..m]);
                if body.len() >= content_length {
                    break;
                }
            }
            if body.len() > content_length {
                body.truncate(content_length);
            }
            let header = String::from_utf8_lossy(&buf[..header_end.min(n)]);
            let response = handle_request(&header, &body, &metrics, search_api.as_deref()).await;
            let _ = socket.write_all(&response).await;
        });
    }
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
        return match api.handle_get(&query).await {
            Ok((code, content_type, body)) => http_response(code, &content_type, &body),
            Err(e) => {
                warn!("search api error: {e}");
                let msg = format!(r#"{{"error":"{}"}}"#, escape_json(&e.to_string()));
                http_response(500, "application/json", msg.as_bytes())
            }
        };
    }

    if method == "POST" && path_query.starts_with("/api/events") {
        let Some(api) = search_api else {
            return http_response(
                404,
                "application/json",
                br#"{"error":"ingest api disabled"}"#,
            );
        };
        if !api.is_ingest_authorized(auth.as_deref()) {
            return http_response(401, "application/json", br#"{"error":"unauthorized"}"#);
        }
        return match api.handle_ingest(body).await {
            Ok((code, content_type, body)) => http_response(code, &content_type, &body),
            Err(e) => {
                warn!("ingest api error: {e}");
                let msg = format!(r#"{{"error":"{}"}}"#, escape_json(&e.to_string()));
                http_response(400, "application/json", msg.as_bytes())
            }
        };
    }

    http_response(404, "text/plain", b"not found")
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
        202 => "202 Accepted",
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

    #[test]
    fn finds_header_end() {
        let req = b"POST /api/events HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}";
        let (end, cl) = parse_header_end_and_cl(req).unwrap();
        assert_eq!(cl, 2);
        assert!(end > 10);
    }
}
