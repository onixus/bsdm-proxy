//! Connection-specific ("hop-by-hop") header handling.
//!
//! These fields describe a single transport connection, not the end-to-end
//! message, so a proxy must consume them and must not pass them to the next
//! hop (RFC 9110 §7.6.1, RFC 7230 §6.1). Forwarding them is not cosmetic:
//!
//! * `Proxy-Authorization` carries the *client's* credentials for this proxy.
//!   With the Basic backend that is `base64(user:password)`; relaying it would
//!   hand every origin server a working corporate login.
//! * `Transfer-Encoding` describes framing that the proxy has already undone
//!   by buffering the body. Re-emitting it next to the `Content-Length` the
//!   client sends is the classic CL.TE request-smuggling desync.

use hyper::header::{HeaderMap, HeaderName, CONNECTION};

/// Connection-specific field names, lowercase for case-insensitive comparison.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

/// Whether `name` is a connection-specific field that must not cross a hop.
pub(crate) fn is_hop_by_hop(name: &str) -> bool {
    HOP_BY_HOP
        .iter()
        .any(|known| name.eq_ignore_ascii_case(known))
}

/// Remove every connection-specific header from an outbound request.
///
/// `Connection` may itself *nominate* further field names as hop-by-hop for
/// this message only, so those are collected and dropped before `Connection`
/// is removed. A sender that lists a header there and a proxy that forwards it
/// anyway is another way to smuggle state past an inspecting hop.
pub(crate) fn strip_hop_by_hop_request_headers(headers: &mut HeaderMap) {
    let nominated: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|token| HeaderName::from_bytes(token.trim().as_bytes()).ok())
        .collect();

    for name in nominated {
        headers.remove(&name);
    }
    for name in HOP_BY_HOP {
        // `remove` drops every value bound to the name, not just the first.
        headers.remove(*name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::{HeaderValue, AUTHORIZATION, PROXY_AUTHORIZATION};

    fn header_map(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(
                HeaderName::from_bytes(name.as_bytes()).expect("valid header name"),
                HeaderValue::from_str(value).expect("valid header value"),
            );
        }
        headers
    }

    #[test]
    fn proxy_credentials_never_reach_the_next_hop() {
        let mut headers = header_map(&[
            ("proxy-authorization", "Basic dXNlcjpwYXNzd29yZA=="),
            ("host", "example.com"),
        ]);
        strip_hop_by_hop_request_headers(&mut headers);
        assert!(headers.get(PROXY_AUTHORIZATION).is_none());
        // End-to-end headers are untouched.
        assert_eq!(headers.get("host").unwrap(), "example.com");
    }

    /// `Authorization` is end-to-end: it addresses the origin, not this proxy,
    /// so stripping it would break upstream auth.
    #[test]
    fn origin_authorization_is_preserved() {
        let mut headers = header_map(&[
            ("authorization", "Bearer token"),
            ("proxy-authorization", "Basic c2VjcmV0"),
        ]);
        strip_hop_by_hop_request_headers(&mut headers);
        assert_eq!(headers.get(AUTHORIZATION).unwrap(), "Bearer token");
        assert!(headers.get(PROXY_AUTHORIZATION).is_none());
    }

    #[test]
    fn framing_headers_are_dropped_so_the_body_is_reframed_once() {
        let mut headers = header_map(&[
            ("transfer-encoding", "chunked"),
            ("te", "trailers"),
            ("upgrade", "websocket"),
            ("keep-alive", "timeout=5"),
            ("proxy-connection", "keep-alive"),
        ]);
        strip_hop_by_hop_request_headers(&mut headers);
        assert!(headers.is_empty(), "left over: {headers:?}");
    }

    #[test]
    fn connection_nominated_fields_are_dropped_with_it() {
        let mut headers = header_map(&[
            ("connection", "x-internal-token, close"),
            ("x-internal-token", "smuggled"),
            ("x-kept", "visible"),
        ]);
        strip_hop_by_hop_request_headers(&mut headers);
        assert!(headers.get("connection").is_none());
        assert!(
            headers.get("x-internal-token").is_none(),
            "a field nominated by Connection must not cross the hop"
        );
        assert_eq!(headers.get("x-kept").unwrap(), "visible");
    }

    #[test]
    fn every_value_of_a_repeated_header_is_removed() {
        let mut headers = header_map(&[
            ("proxy-authorization", "Basic first"),
            ("proxy-authorization", "Basic second"),
        ]);
        strip_hop_by_hop_request_headers(&mut headers);
        assert_eq!(headers.get_all(PROXY_AUTHORIZATION).iter().count(), 0);
    }

    #[test]
    fn matching_is_case_insensitive() {
        assert!(is_hop_by_hop("Proxy-Authorization"));
        assert!(is_hop_by_hop("TRANSFER-ENCODING"));
        assert!(is_hop_by_hop("te"));
        assert!(!is_hop_by_hop("authorization"));
        assert!(!is_hop_by_hop("content-length"));
    }
}
