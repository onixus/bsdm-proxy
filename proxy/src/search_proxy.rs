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

/// Credential the proxy presents to cache-indexer: `SEARCH_UPSTREAM_TOKEN`,
/// falling back to `SEARCH_API_TOKEN` for co-located installs that share one env.
fn upstream_token() -> Option<String> {
    pick_upstream_token(
        std::env::var("SEARCH_UPSTREAM_TOKEN").ok(),
        std::env::var("SEARCH_API_TOKEN").ok(),
    )
}

fn pick_upstream_token(explicit: Option<String>, shared: Option<String>) -> Option<String> {
    explicit
        .filter(|t| !t.trim().is_empty())
        .or_else(|| shared.filter(|t| !t.trim().is_empty()))
        .map(|t| t.trim().to_string())
}

/// Forward GET `/api/search*` and POST `/api/events` to cache-indexer.
pub async fn proxy_search_request(
    method: &Method,
    path: &str,
    query: &str,
    headers: &HeaderMap,
    body: Bytes,
) -> Response<Body> {
    proxy_search_to(
        &upstream_base(),
        upstream_token(),
        method,
        path,
        query,
        headers,
        body,
    )
    .await
}

async fn proxy_search_to(
    base: &str,
    upstream_token: Option<String>,
    method: &Method,
    path: &str,
    query: &str,
    headers: &HeaderMap,
    body: Bytes,
) -> Response<Body> {
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

    // The caller's Authorization is the control-plane token — never hand it to
    // a neighbouring service. The proxy authenticates to cache-indexer with
    // its own credential instead.
    if let Some(token) = upstream_token {
        req = req.bearer_auth(token);
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
                        .header(hyper::header::CONTENT_TYPE, content_type)
                        .header("X-Content-Type-Options", "nosniff")
                        .header("X-Frame-Options", "DENY")
                        .header("Referrer-Policy", "no-referrer");
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
        .header(
            hyper::header::CONTENT_TYPE,
            "application/json; charset=utf-8",
        )
        .header("X-Content-Type-Options", "nosniff")
        .header("X-Frame-Options", "DENY")
        .header("Referrer-Policy", "no-referrer")
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

    #[test]
    fn upstream_token_prefers_explicit_and_ignores_blank() {
        let s = |v: &str| Some(v.to_string());
        assert_eq!(pick_upstream_token(s("a"), s("b")), s("a"));
        assert_eq!(pick_upstream_token(s("  "), s("b")), s("b"));
        assert_eq!(pick_upstream_token(None, None), None);
    }

    /// P1-D: the control-plane token of the caller must not reach cache-indexer;
    /// only the proxy's own upstream credential is sent.
    #[tokio::test]
    async fn client_authorization_is_not_forwarded() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let n = sock.read(&mut buf).await.unwrap();
            sock.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}")
                .await
                .unwrap();
            String::from_utf8_lossy(&buf[..n]).to_ascii_lowercase()
        });

        let mut headers = HeaderMap::new();
        headers.insert(
            hyper::header::AUTHORIZATION,
            "Bearer control-plane-secret".parse().unwrap(),
        );
        let resp = proxy_search_to(
            &format!("http://{addr}"),
            Some("indexer-token".to_string()),
            &Method::GET,
            "/api/search",
            "q=x",
            &headers,
            Bytes::new(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let seen = server.await.unwrap();
        assert!(!seen.contains("control-plane-secret"), "{seen}");
        assert!(
            seen.contains("authorization: bearer indexer-token"),
            "{seen}"
        );
    }
}
