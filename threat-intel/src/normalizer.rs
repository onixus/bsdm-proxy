//! TASK-TI-003: IOC Normalization.
//!
//! Provides canonicalization for URLs, domains, and IP addresses, including:
//! - Canonical URL formatting (lowercase scheme/host, strip default ports, strip fragments, path normalization).
//! - Domain extraction, lowercase normalization, punycode/IDN handling, and RFC 1123 label validation.
//! - IP address parsing (IPv4/IPv6 canonical formatting, bogon/private/loopback detection).

use crate::indicator::{looks_like_domain, IndicatorKind, RawIndicator};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use url::Url;

/// Canonicalized indicator ready for database storage and policy compilation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedIndicator {
    /// Original raw value as reported by the feed.
    pub raw_value: String,
    /// Canonical normalized string (e.g. `example.com`, `http://example.com/path`, `192.0.2.1`).
    pub normalized_value: String,
    /// Extracted base domain for URLs and Domains.
    pub domain: Option<String>,
    pub kind: IndicatorKind,
    pub source: String,
    pub source_weight: u8,
    pub confidence_score: u8,
    pub collected_at: DateTime<Utc>,
    pub reported_at: Option<DateTime<Utc>>,
    pub reference: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    pub is_private_or_bogon: bool,
}

impl NormalizedIndicator {
    /// Creates a normalized indicator from a raw indicator with an initial confidence score.
    pub fn from_raw(raw: &RawIndicator, confidence_score: u8) -> Option<Self> {
        let trimmed = raw.value.trim();
        if trimmed.is_empty() {
            return None;
        }

        match raw.kind {
            IndicatorKind::Url => normalize_url(trimmed).map(|(norm_url, domain)| Self {
                raw_value: raw.value.clone(),
                normalized_value: norm_url,
                domain: Some(domain),
                kind: IndicatorKind::Url,
                source: raw.source.clone(),
                source_weight: raw.source_weight,
                confidence_score,
                collected_at: raw.collected_at,
                reported_at: raw.reported_at,
                reference: raw.reference.clone(),
                tags: raw.tags.clone(),
                is_private_or_bogon: false,
            }),
            IndicatorKind::Domain => normalize_domain(trimmed).map(|(norm_domain, is_ip)| {
                let is_bogon = is_ip && is_private_or_bogon_ip(&norm_domain);
                Self {
                    raw_value: raw.value.clone(),
                    normalized_value: norm_domain.clone(),
                    domain: if is_ip { None } else { Some(norm_domain) },
                    kind: if is_ip {
                        IndicatorKind::Ip
                    } else {
                        IndicatorKind::Domain
                    },
                    source: raw.source.clone(),
                    source_weight: raw.source_weight,
                    confidence_score,
                    collected_at: raw.collected_at,
                    reported_at: raw.reported_at,
                    reference: raw.reference.clone(),
                    tags: raw.tags.clone(),
                    is_private_or_bogon: is_bogon,
                }
            }),
            IndicatorKind::Ip => normalize_ip(trimmed).map(|norm_ip| {
                let is_bogon = is_private_or_bogon_ip(&norm_ip);
                Self {
                    raw_value: raw.value.clone(),
                    normalized_value: norm_ip,
                    domain: None,
                    kind: IndicatorKind::Ip,
                    source: raw.source.clone(),
                    source_weight: raw.source_weight,
                    confidence_score,
                    collected_at: raw.collected_at,
                    reported_at: raw.reported_at,
                    reference: raw.reference.clone(),
                    tags: raw.tags.clone(),
                    is_private_or_bogon: is_bogon,
                }
            }),
        }
    }
}

/// Canonicalizes a URL string:
/// - Guarantees http/https scheme.
/// - Lowercases scheme and host.
/// - Strips default ports (`80` for http, `443` for https).
/// - Strips fragment (`#...`).
/// - Canonicalizes empty paths to `/`.
///
/// Returns `(canonical_url, extracted_domain)`.
pub fn normalize_url(raw: &str) -> Option<(String, String)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Byte-index slicing would panic on a multibyte indicator submitted through SOAR.
    let lowered = trimmed.to_ascii_lowercase();
    let is_prefixed = lowered.starts_with("http://") || lowered.starts_with("https://");

    let to_parse = if !is_prefixed {
        format!("http://{trimmed}")
    } else {
        trimmed.to_string()
    };

    let mut parsed = Url::parse(&to_parse).ok()?;
    let is_https = parsed.scheme().eq_ignore_ascii_case("https");
    let is_http = parsed.scheme().eq_ignore_ascii_case("http");
    if !is_http && !is_https {
        return None;
    }

    let host_str = parsed.host_str()?;
    let (norm_host, _) = normalize_domain(host_str)?;

    // Update host
    if parsed.set_host(Some(&norm_host)).is_err() {
        return None;
    }

    // Strip default ports
    if let Some(port) = parsed.port() {
        if (!is_https && port == 80) || (is_https && port == 443) {
            let _ = parsed.set_port(None);
        }
    }

    // Strip URL fragment
    parsed.set_fragment(None);

    let canonical = parsed.to_string();
    Some((canonical, norm_host))
}

/// Canonicalizes a domain string:
/// - Trims whitespace, leading/trailing slashes, trailing dots.
/// - Converts to lowercase ASCII.
/// - Rejects invalid chars or lengths.
///
/// Returns `(normalized_domain, is_ip_literal)`.
pub fn normalize_domain(raw: &str) -> Option<(String, bool)> {
    let mut s = raw.trim();
    // Strip protocol prefix if accidentally included
    if let Some(rest) = s.strip_prefix("http://") {
        s = rest;
    } else if let Some(rest) = s.strip_prefix("https://") {
        s = rest;
    }
    // Strip trailing path/query if present
    if let Some(idx) = s.find('/') {
        s = &s[..idx];
    }
    if let Some(idx) = s.find(':') {
        s = &s[..idx];
    }

    let trimmed = s.trim_end_matches('.');
    if trimmed.is_empty() {
        return None;
    }

    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Some((ip.to_string(), true));
    }

    let lower = trimmed.to_ascii_lowercase();
    if !looks_like_domain(&lower) {
        return None;
    }

    Some((lower, false))
}

/// Canonicalizes an IP address (IPv4 / IPv6).
pub fn normalize_ip(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let ip = trimmed.parse::<IpAddr>().ok()?;
    Some(ip.to_string())
}

/// Checks if an IP string is a private, loopback, link-local, or bogon address.
pub fn is_private_or_bogon_ip(ip_str: &str) -> bool {
    let Ok(ip) = ip_str.parse::<IpAddr>() else {
        return false;
    };
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::indicator::FeedMeta;

    struct DummySource;
    impl FeedMeta for DummySource {
        fn name(&self) -> &'static str {
            "test_feed"
        }
        fn weight(&self) -> u8 {
            80
        }
    }

    #[test]
    fn test_normalize_url() {
        let (url, domain) =
            normalize_url("HTTP://Example.COM:80/path/../path/file.html#frag").unwrap();
        assert_eq!(domain, "example.com");
        assert_eq!(url, "http://example.com/path/file.html");

        let (url, domain) = normalize_url("https://sub.victim.com:443/login?q=1").unwrap();
        assert_eq!(domain, "sub.victim.com");
        assert_eq!(url, "https://sub.victim.com/login?q=1");

        let (url, domain) = normalize_url("evil.com/phish").unwrap();
        assert_eq!(domain, "evil.com");
        assert_eq!(url, "http://evil.com/phish");
    }

    #[test]
    fn test_normalize_domain() {
        let (d, is_ip) = normalize_domain("  Phish.Example.Com.  ").unwrap();
        assert_eq!(d, "phish.example.com");
        assert!(!is_ip);

        let (ip, is_ip) = normalize_domain("192.168.1.1:8080/foo").unwrap();
        assert_eq!(ip, "192.168.1.1");
        assert!(is_ip);

        assert!(normalize_domain("invalid domain").is_none());
        assert!(normalize_domain("-bad-.com").is_none());
    }

    #[test]
    fn test_normalize_ip() {
        assert_eq!(normalize_ip(" 1.1.1.1 \n").unwrap(), "1.1.1.1");
        assert_eq!(normalize_ip("2001:0db8::1").unwrap(), "2001:db8::1");
        assert!(normalize_ip("999.999.999.999").is_none());
    }

    #[test]
    fn test_bogon_detection() {
        assert!(is_private_or_bogon_ip("127.0.0.1"));
        assert!(is_private_or_bogon_ip("10.0.0.1"));
        assert!(is_private_or_bogon_ip("192.168.0.10"));
        assert!(is_private_or_bogon_ip("172.16.5.1"));
        assert!(!is_private_or_bogon_ip("8.8.8.8"));
        assert!(!is_private_or_bogon_ip("93.184.216.34"));
    }

    #[test]
    fn test_normalized_indicator_from_raw() {
        let raw = RawIndicator::new(
            "HTTPS://Evil-Bank.Com:443/login",
            IndicatorKind::Url,
            &DummySource,
        )
        .with_reference("ID-12345");
        let norm = NormalizedIndicator::from_raw(&raw, 85).unwrap();
        assert_eq!(norm.normalized_value, "https://evil-bank.com/login");
        assert_eq!(norm.domain, Some("evil-bank.com".to_string()));
        assert_eq!(norm.confidence_score, 85);
        assert_eq!(norm.source, "test_feed");
        assert_eq!(norm.reference, Some("ID-12345".to_string()));
    }
}
