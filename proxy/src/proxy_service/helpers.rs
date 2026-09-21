use super::*;
use base64::engine::general_purpose;
use base64::Engine;
use hyper::header::AUTHORIZATION;
use crate::cache_key::http_cache_key;

impl ProxyService {
    #[inline]
    pub(crate) fn generate_cache_key(&self, method: &str, url: &str) -> Arc<str> {
        http_cache_key(method, url)
    }

    /// Host of an absolute URL, or `"unknown"` when it has none.
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

    pub(super) fn extract_domain_fast(url_str: &str) -> Option<String> {
        let after_scheme = url_str.split_once("://")?.1;
        let authority = after_scheme
            .split(['/', '?', '#'])
            .next()
            .filter(|a| !a.is_empty())?;
        let host_port = match authority.rsplit_once('@') {
            Some((_, host_port)) => host_port,
            None => authority,
        };
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

    #[inline]
    pub(super) fn request_header<'a>(
        req: &'a Request<Incoming>,
        name: &str,
    ) -> Option<&'a str> {
        req.headers().get(name).and_then(|v| v.to_str().ok())
    }

    pub(super) fn request_header_str(req: &Request<Incoming>, name: &str) -> Option<String> {
        Self::request_header(req, name).map(str::to_string)
    }

    pub(super) fn extract_user_info(
        req: &Request<Incoming>,
    ) -> (Option<String>, Option<String>) {
        if let Some(auth_header) = req.headers().get(AUTHORIZATION) {
            if let Ok(auth_str) = auth_header.to_str() {
                if let Some(encoded) = auth_str.strip_prefix("Basic ") {
                    if let Ok(decoded_bytes) = general_purpose::STANDARD.decode(encoded) {
                        if let Ok(credentials) = String::from_utf8(decoded_bytes) {
                            if let Some((username, _)) = credentials.split_once(':') {
                                return (Some(username.to_string()), Some(username.to_string()));
                            }
                        }
                    }
                }
            }
        }
        (None, None)
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
