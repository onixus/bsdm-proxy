//! Reverse-proxy Search/Ingest API onto the control plane for same-origin Admin Console.
//!
//! Env:
//! - `SEARCH_UPSTREAM_URL` — base URL of cache-indexer (default `http://127.0.0.1:8080`,
//!   compose: `http://cache-indexer:8080`).
//! - When unset and upstream is unreachable, handlers return 502 with a clear body.

use bytes::Bytes;
use hyper::{HeaderMap, Method, Response, StatusCode};
use tracing::{debug, warn};

use crate::http_types::{full, Body};

fn upstream_base() -> String {
    std::env::var("SEARCH_UPSTREAM_URL")
        .ok()
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "http://127.0.0.1:8080".to_string())
}

/// Forward GET `/api/search*` and POST `/api/events` to cache-indexer.
pub async fn proxy_search_request(
    method: &Method,
    path: &str,
    query: &str,
    headers: &HeaderMap,
    body: Bytes,
) -> Response<Body> {
    let base = upstream_base();
    let url = if query.is_empty() {
        format!("{base}{path}")
    } else {
        format!("{base}{path}?{query}")
    };

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("search proxy client build failed: {e}");
            return err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "search proxy client error",
            );
        }
    };

    let mut req = match *method {
        Method::GET => client.get(&url),
        Method::POST => client.post(&url).body(body.to_vec()),
        Method::OPTIONS => client.request(reqwest::Method::OPTIONS, &url),
        _ => {
            return err_json(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
        }
    };

    if let Some(auth) = headers.get(hyper::header::AUTHORIZATION) {
        if let Ok(v) = auth.to_str() {
            req = req.header(reqwest::header::AUTHORIZATION, v);
        }
    }
    if let Some(ct) = headers.get(hyper::header::CONTENT_TYPE) {
        if let Ok(v) = ct.to_str() {
            req = req.header(reqwest::header::CONTENT_TYPE, v);
        }
    }
    // Propagate Origin so cache-indexer CORS still works for non-same-origin callers.
    if let Some(origin) = headers.get(hyper::header::ORIGIN) {
        if let Ok(v) = origin.to_str() {
            req = req.header(reqwest::header::ORIGIN, v);
        }
    }

    debug!(%url, method = %method, "search upstream proxy");
    match req.send().await {
        Ok(resp) => {
            let status =
                StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let content_type = resp
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/json")
                .to_string();
            // Reflect a subset of CORS headers if upstream set them.
            let acao = resp
                .headers()
                .get(reqwest::header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            match resp.bytes().await {
                Ok(bytes) => {
                    let mut builder = Response::builder()
                        .status(status)
                        .header(hyper::header::CONTENT_TYPE, content_type);
                    if let Some(o) = acao {
                        builder = builder.header(hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN, o);
                    }
                    builder
                        .body(full(bytes))
                        .unwrap_or_else(|_| err_json(StatusCode::BAD_GATEWAY, "response build"))
                }
                Err(e) => {
                    warn!("search upstream body error: {e}");
                    err_json(StatusCode::BAD_GATEWAY, "search upstream body error")
                }
            }
        }
        Err(e) => {
            warn!(%url, "search upstream unreachable: {e}");
            err_json(
                StatusCode::BAD_GATEWAY,
                &format!(
                    "search upstream unreachable ({base}): set SEARCH_UPSTREAM_URL or start cache-indexer"
                ),
            )
        }
    }
}

fn err_json(status: StatusCode, msg: &str) -> Response<Body> {
    let body = format!(r#"{{"error":"{}"}}"#, msg.replace('"', "'"));
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(full(Bytes::from(body)))
        .unwrap_or_else(|_| Response::new(full(Bytes::from_static(b"{\"error\":\"internal\"}"))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_upstream() {
        std::env::remove_var("SEARCH_UPSTREAM_URL");
        assert!(upstream_base().contains("8080"));
    }
}
