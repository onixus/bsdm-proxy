use super::*;
use crate::cache_key::http_cache_key;

impl ProxyService {
    #[inline]
    pub(crate) fn generate_cache_key(&self, method: &str, url: &str) -> Arc<str> {
        http_cache_key(method, url)
    }

    /// Host of an absolute URL, or `"unknown"` when it has none.
    ///
    /// Runs on every request (metrics labels, ACL matching, policy-cache keys,
    /// analytics events). A full `Url::parse` for that is an outsized cost, so
    /// plain ASCII authorities — effectively all real traffic — are sliced out
    /// directly and anything else falls back to the real parser, which keeps
    /// IDNA/punycode, percent escapes and IPv6 literals byte-identical.
    #[inline]
    pub(super) fn extract_domain(url_str: &str) -> String {
        if let Some(domain) = Self::extract_domain_fast(url_str) {
            return domain;
        }
        url::Url::parse(url_str)
            .ok()
            .and_then(|u| u.host().map(|h| h.to_string()))
            .unwrap_or_else(|| "unknown".to_string())
    }

    /// Slice the host out of `scheme://[userinfo@]host[:port]/...`.
    ///
    /// Returns `None` — deferring to `Url::parse` — for any authority that is
    /// not a straightforward ASCII `[a-zA-Z0-9.-]` hostname, which is exactly
    /// the set where the URL spec's host parser does more than lowercase.
    pub(super) fn extract_domain_fast(url_str: &str) -> Option<String> {
        let after_scheme = url_str.split_once("://")?.1;
        let authority = after_scheme
            .split(['/', '?', '#'])
            .next()
            .filter(|a| !a.is_empty())?;
        // Strip userinfo; the last '@' wins, as in the URL spec.
        let host_port = match authority.rsplit_once('@') {
            Some((_, host_port)) => host_port,
            None => authority,
        };
        // IPv6 literals ("[::1]") keep their brackets and normalization rules.
        if host_port.starts_with('[') {
            return None;
        }
        let host = host_port.split(':').next().filter(|h| !h.is_empty())?;

        let plain = host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
            && !host.starts_with('.')
            && !host.ends_with('.')
            && !host.contains("..");
        if !plain {
            return None;
        }

        Some(host.to_ascii_lowercase())
    }

    /// Borrowed header value — no copy. Use this whenever the value is only read
    /// while `req` is still alive.
    #[inline]
    pub(super) fn request_header<'a>(req: &'a Request<Incoming>, name: &str) -> Option<&'a str> {
        req.headers().get(name).and_then(|v| v.to_str().ok())
    }

    /// Owned header value, for callers that outlive the borrow of `req`.
    pub(super) fn request_header_str(req: &Request<Incoming>, name: &str) -> Option<String> {
        Self::request_header(req, name).map(str::to_string)
    }

    pub(super) fn finish_request_metrics(
        guard: &mut Option<RequestMetricsGuard>,
        fast_scope: &mut Option<FastRequestScope>,
        status: u16,
        request_size: usize,
        response_size: usize,
    ) {
        if let Some(g) = guard.take() {
            g.finish(status, request_size, response_size);
        } else if let Some(scope) = fast_scope.take() {
            scope.finish(status);
        }
    }

    pub(super) fn headers_map_from_response(
        response: &Response<Incoming>,
    ) -> HashMap<String, String> {
        Self::headers_map(response.headers())
    }

    pub(super) fn headers_map_from_parts(
        parts: &hyper::http::request::Parts,
    ) -> HashMap<String, String> {
        Self::headers_map(&parts.headers)
    }

    fn headers_map(headers: &hyper::HeaderMap) -> HashMap<String, String> {
        let mut map = HashMap::with_capacity(headers.len());
        for (name, value) in headers.iter() {
            if let Ok(value) = value.to_str() {
                map.insert(name.as_str().to_string(), value.to_string());
            }
        }
        map
    }

    pub(super) fn apply_response_headers(
        headers_map: &HashMap<String, String>,
        resp: &mut Response<Body>,
    ) {
        for (key, value) in headers_map {
            if let (Ok(name), Ok(val)) = (
                HeaderName::from_bytes(key.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                resp.headers_mut().insert(name, val);
            }
        }
    }

    pub(super) fn attach_x_cache_status(resp: &mut Response<Body>, label: &str) {
        if let Ok(val) = HeaderValue::from_str(label) {
            resp.headers_mut().insert("x-cache-status", val);
        }
    }
}

/// Forward/MITM request: the `Host` header must name the same origin as the
/// request target. ACL, destination checks and the cache key are all computed
/// from the URI authority, while the upstream connection would forward the
/// client's `Host` verbatim — a mismatch lets a client fetch one vhost on a
/// shared IP/CDN and have it cached (and policy-checked) as another.
///
/// Comparison is case-insensitive with the scheme's default port filled in.
/// Requests without `Host` (HTTP/2 `:authority`) are left as is; the client
/// derives `Host` from the URI.
pub(crate) fn check_host_matches_authority(
    uri: &hyper::Uri,
    headers: &hyper::HeaderMap,
) -> Result<(), &'static str> {
    let Some(uri_host) = uri.host() else {
        return Ok(());
    };
    let default_port = if uri.scheme_str() == Some("https") {
        443
    } else {
        80
    };
    let uri_port = uri.port_u16().unwrap_or(default_port);

    let mut values = headers.get_all(hyper::header::HOST).iter();
    let Some(host) = values.next() else {
        return Ok(());
    };
    if values.next().is_some() {
        return Err("multiple Host headers");
    }
    let host = host.to_str().map_err(|_| "invalid Host header")?.trim();

    let (name, port) = if let Some(rest) = host.strip_prefix('[') {
        // IPv6 literal: "[::1]" or "[::1]:8080".
        let (addr, after) = rest.split_once(']').ok_or("invalid Host header")?;
        let port = match after.strip_prefix(':') {
            Some(p) => Some(p),
            None if after.is_empty() => None,
            None => return Err("invalid Host header"),
        };
        (&host[..addr.len() + 2], port)
    } else {
        match host.rsplit_once(':') {
            Some((name, port)) => (name, Some(port)),
            None => (host, None),
        }
    };
    let port = match port {
        Some(p) => p.parse::<u16>().map_err(|_| "invalid Host header")?,
        None => default_port,
    };

    let same_name = name
        .trim_end_matches('.')
        .eq_ignore_ascii_case(uri_host.trim_end_matches('.'));
    if same_name && port == uri_port {
        Ok(())
    } else {
        Err("Host header does not match the request target")
    }
}

#[cfg(test)]
mod host_check_tests {
    use super::check_host_matches_authority;

    fn check(uri: &str, hosts: &[&str]) -> Result<(), &'static str> {
        let uri: hyper::Uri = uri.parse().unwrap();
        let mut headers = hyper::HeaderMap::new();
        for h in hosts {
            headers.append(hyper::header::HOST, h.parse().unwrap());
        }
        check_host_matches_authority(&uri, &headers)
    }

    #[test]
    fn matching_host_is_accepted() {
        assert!(check("http://a.test/x", &["a.test"]).is_ok());
        assert!(check("http://a.test/x", &["A.Test"]).is_ok());
        assert!(check("http://a.test/x", &["a.test:80"]).is_ok());
        assert!(check("http://a.test:8080/x", &["a.test:8080"]).is_ok());
        assert!(check("https://a.test/x", &["a.test:443"]).is_ok());
        assert!(check("https://a.test/x", &["a.test."]).is_ok());
        assert!(check("http://[::1]:8080/x", &["[::1]:8080"]).is_ok());
        // No Host (HTTP/2) and origin-form URIs are not judged here.
        assert!(check("http://a.test/x", &[]).is_ok());
        assert!(check("/x", &["b.test"]).is_ok());
    }

    #[test]
    fn mismatching_host_is_rejected() {
        assert!(check("http://a.test/x", &["b.test"]).is_err());
        assert!(check("http://a.test/x", &["a.test:8080"]).is_err());
        assert!(check("https://a.test/x", &["a.test:80"]).is_err());
        assert!(check("http://a.test:8080/x", &["a.test"]).is_err());
        assert!(check("http://[::1]/x", &["[::2]"]).is_err());
        assert!(check("http://a.test/x", &["a.test:abc"]).is_err());
        assert!(check("http://a.test/x", &["a.test", "a.test"]).is_err());
        assert!(check("http://a.test/x", &["a.test.evil.test"]).is_err());
    }
}

/// Default cap for a buffered request body: large enough for ordinary uploads,
/// small enough that a handful of concurrent streams cannot OOM the proxy.
pub(crate) const DEFAULT_MAX_REQUEST_BODY_BYTES: usize = 64 * 1024 * 1024;

/// `MAX_REQUEST_BODY_BYTES` (bytes, > 0); invalid or zero values fall back to
/// the default so a typo cannot silently disable the limit.
pub(crate) fn max_request_body_bytes_from_env() -> usize {
    parse_max_request_body_bytes(std::env::var("MAX_REQUEST_BODY_BYTES").ok().as_deref())
}

fn parse_max_request_body_bytes(raw: Option<&str>) -> usize {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None => DEFAULT_MAX_REQUEST_BODY_BYTES,
        Some(v) => match v.parse::<usize>() {
            Ok(n) if n > 0 => n,
            _ => {
                tracing::warn!(
                    value = v,
                    "MAX_REQUEST_BODY_BYTES is invalid; using the default {}",
                    DEFAULT_MAX_REQUEST_BODY_BYTES
                );
                DEFAULT_MAX_REQUEST_BODY_BYTES
            }
        },
    }
}

/// Buffers a request body through the DLP scanner with a hard size cap. The
/// cap is enforced while streaming, so an oversized (or endless chunked) body
/// is rejected after at most `max` bytes are held.
pub(crate) async fn collect_request_body<B>(
    body: B,
    dlp: Arc<crate::dlp::DlpEngine>,
    max: usize,
) -> Result<Bytes, Box<dyn std::error::Error + Send + Sync>>
where
    B: hyper::body::Body<Data = Bytes>,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
{
    let dlp_body = crate::dlp::DlpBodyStream::new(body, dlp);
    let limited = http_body_util::Limited::new(dlp_body, max);
    http_body_util::BodyExt::collect(limited)
        .await
        .map(|c| c.to_bytes())
}

pub(crate) fn is_body_too_large(err: &(dyn std::error::Error + Send + Sync + 'static)) -> bool {
    err.downcast_ref::<http_body_util::LengthLimitError>()
        .is_some()
}

pub(crate) fn payload_too_large_response() -> Response<Body> {
    let mut resp = Response::new(full(Bytes::from_static(b"413 Payload Too Large")));
    *resp.status_mut() = StatusCode::PAYLOAD_TOO_LARGE;
    resp
}

#[cfg(test)]
mod body_limit_tests {
    use super::*;

    #[test]
    fn max_body_env_parsing() {
        assert_eq!(
            parse_max_request_body_bytes(None),
            DEFAULT_MAX_REQUEST_BODY_BYTES
        );
        assert_eq!(parse_max_request_body_bytes(Some("1024")), 1024);
        assert_eq!(
            parse_max_request_body_bytes(Some("0")),
            DEFAULT_MAX_REQUEST_BODY_BYTES
        );
        assert_eq!(
            parse_max_request_body_bytes(Some("lots")),
            DEFAULT_MAX_REQUEST_BODY_BYTES
        );
    }

    #[tokio::test]
    async fn body_within_limit_is_collected() {
        let dlp = Arc::new(crate::dlp::DlpEngine::disabled());
        let body = http_body_util::Full::new(Bytes::from_static(b"hello"));
        assert_eq!(collect_request_body(body, dlp, 5).await.unwrap(), "hello");
    }

    #[tokio::test]
    async fn oversized_body_is_rejected_as_too_large() {
        let dlp = Arc::new(crate::dlp::DlpEngine::disabled());
        let body = http_body_util::Full::new(Bytes::from(vec![0u8; 6]));
        let err = collect_request_body(body, dlp, 5).await.unwrap_err();
        assert!(is_body_too_large(err.as_ref()));
    }

    #[tokio::test]
    async fn streamed_body_is_cut_off_at_the_limit() {
        // Chunked body without a size hint: the limit must apply while streaming.
        let (mut tx, body) =
            http_body_util::channel::Channel::<Bytes, std::convert::Infallible>::new(4);
        tokio::spawn(async move {
            for _ in 0..100 {
                if tx.send_data(Bytes::from(vec![0u8; 1024])).await.is_err() {
                    break;
                }
            }
        });
        let dlp = Arc::new(crate::dlp::DlpEngine::disabled());
        let err = collect_request_body(body, dlp, 10 * 1024)
            .await
            .unwrap_err();
        assert!(is_body_too_large(err.as_ref()));
    }
}

/// Placeholder for credential-bearing header values in analytics events.
pub(crate) const REDACTED_HEADER_VALUE: &str = "[REDACTED]";

/// Request headers for an analytics event. Events go to Kafka/ClickHouse and
/// are readable far more widely than the proxy itself, so credentials —
/// proxy/origin `Authorization`, cookies, API keys and anything named like a
/// token or secret — are replaced by [`REDACTED_HEADER_VALUE`].
pub(crate) fn event_request_headers(headers: &hyper::HeaderMap) -> HashMap<String, String> {
    headers
        .iter()
        .filter_map(|(k, v)| {
            let name = k.as_str();
            if is_credential_header(name) {
                return Some((name.to_string(), REDACTED_HEADER_VALUE.to_string()));
            }
            v.to_str().ok().map(|s| (name.to_string(), s.to_string()))
        })
        .collect()
}

pub(crate) fn is_credential_header(name: &str) -> bool {
    // `HeaderName` is always lowercase.
    matches!(
        name,
        "authorization" | "proxy-authorization" | "cookie" | "set-cookie"
    ) || [
        "auth", "token", "secret", "api-key", "apikey", "password", "session",
    ]
    .iter()
    .any(|needle| name.contains(needle))
}

#[cfg(test)]
mod event_header_tests {
    use super::*;

    #[test]
    fn credentials_are_redacted_in_event_headers() {
        let mut h = hyper::HeaderMap::new();
        h.insert(
            "proxy-authorization",
            "Basic YWxpY2U6c2VjcmV0".parse().unwrap(),
        );
        h.insert("authorization", "Bearer sk-live-123".parse().unwrap());
        h.insert("cookie", "sid=abc".parse().unwrap());
        h.insert("x-api-key", "k-1".parse().unwrap());
        h.insert("x-auth-token", "t-1".parse().unwrap());
        h.insert("x-goog-api-key", "g-1".parse().unwrap());
        h.insert("user-agent", "curl/8".parse().unwrap());
        let ev = event_request_headers(&h);
        for k in [
            "proxy-authorization",
            "authorization",
            "cookie",
            "x-api-key",
            "x-auth-token",
        ] {
            assert_eq!(
                ev.get(k).map(String::as_str),
                Some(REDACTED_HEADER_VALUE),
                "{k}"
            );
        }
        assert_eq!(ev.get("user-agent").map(String::as_str), Some("curl/8"));
        let joined = format!("{ev:?}");
        assert!(!joined.contains("sk-live") && !joined.contains("YWxpY2U6"));
    }
}
