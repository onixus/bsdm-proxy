//! HTTP cache freshness: `Cache-Control`, validators, and negative caching.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::cache::{CacheConfig, CACHEABLE_METHODS};

/// Parsed subset of `Cache-Control` relevant to the proxy cache.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CacheControlDirectives {
    pub no_store: bool,
    pub no_cache: bool,
    pub max_age: Option<u64>,
    pub s_maxage: Option<u64>,
    pub private: bool,
}

/// Whether an upstream response may be stored and with what metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheStoreDecision {
    pub store: bool,
    pub ttl: Duration,
    pub is_negative: bool,
    pub must_revalidate: bool,
    pub etag: Option<Arc<str>>,
    pub last_modified: Option<Arc<str>>,
}

impl CacheStoreDecision {
    pub fn bypass() -> Self {
        Self {
            store: false,
            ttl: Duration::ZERO,
            is_negative: false,
            must_revalidate: false,
            etag: None,
            last_modified: None,
        }
    }
}

/// `x-cache-status` for upstream MISS before cache insert completes (#111).
pub fn miss_x_cache_status_header(streaming: bool, precheck: &CacheStoreDecision) -> &'static str {
    if !precheck.store {
        return "BYPASS";
    }
    if precheck.is_negative {
        return if streaming {
            "NEGATIVE-MISS-STREAMING"
        } else {
            "NEGATIVE-MISS"
        };
    }
    if streaming {
        "MISS-STREAMING"
    } else {
        "MISS"
    }
}

/// Prometheus / internal label (underscores).
///
/// The `X-Cache-Status` header values come from a closed set, so the mapping is
/// a match returning `&'static str` — no allocation on the request path. Any
/// value outside the set still translates correctly, just with a copy.
pub fn cache_status_metric_label(header_label: &str) -> Cow<'static, str> {
    match header_label {
        "HIT" => Cow::Borrowed("HIT"),
        "MISS" => Cow::Borrowed("MISS"),
        "BYPASS" => Cow::Borrowed("BYPASS"),
        "MISS-STREAMING" => Cow::Borrowed("MISS_STREAMING"),
        "NEGATIVE-MISS" => Cow::Borrowed("NEGATIVE_MISS"),
        "NEGATIVE-MISS-STREAMING" => Cow::Borrowed("NEGATIVE_MISS_STREAMING"),
        "NEGATIVE-HIT" => Cow::Borrowed("NEGATIVE_HIT"),
        "L2-HIT" => Cow::Borrowed("L2_HIT"),
        "REVALIDATED" => Cow::Borrowed("REVALIDATED"),
        "COALESCED-HIT" => Cow::Borrowed("COALESCED_HIT"),
        "LLM-MISS-STREAMING" => Cow::Borrowed("LLM_MISS_STREAMING"),
        other => Cow::Owned(other.replace('-', "_")),
    }
}

pub fn parse_cache_control(value: &str) -> CacheControlDirectives {
    let mut directives = CacheControlDirectives::default();
    for part in value.split(',') {
        let token = part.trim();
        if token.is_empty() {
            continue;
        }
        let (name, arg) = token
            .split_once('=')
            .map(|(n, v)| (n.trim().to_ascii_lowercase(), Some(v.trim())))
            .unwrap_or((token.to_ascii_lowercase(), None));

        match name.as_str() {
            "no-store" => directives.no_store = true,
            "no-cache" => directives.no_cache = true,
            "private" => directives.private = true,
            "max-age" => {
                if let Some(v) = arg.and_then(|s| s.parse::<u64>().ok()) {
                    directives.max_age = Some(v);
                }
            }
            "s-maxage" => {
                if let Some(v) = arg.and_then(|s| s.parse::<u64>().ok()) {
                    directives.s_maxage = Some(v);
                }
            }
            _ => {}
        }
    }
    directives
}

pub fn header_value<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

pub fn header_value_slice<'a>(headers: &'a [(Arc<str>, Arc<str>)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_ref())
}

fn is_negative_status(status: u16) -> bool {
    matches!(status, 403 | 404)
}

pub fn content_length(headers: &HashMap<String, String>) -> Option<usize> {
    header_value(headers, "content-length").and_then(|v| v.parse::<usize>().ok())
}

/// Pre-check cacheability from headers before the body is known (streaming MISS).
pub fn evaluate_store_precheck(
    method: &str,
    status: u16,
    headers: &HashMap<String, String>,
    config: &CacheConfig,
) -> CacheStoreDecision {
    let size_hint = content_length(headers).unwrap_or(0);
    evaluate_store(method, status, headers, size_hint, config)
}

/// Decide whether to store a response and compute freshness metadata.
pub fn evaluate_store(
    method: &str,
    status: u16,
    headers: &HashMap<String, String>,
    body_size: usize,
    config: &CacheConfig,
) -> CacheStoreDecision {
    if !CACHEABLE_METHODS.contains(&method) {
        return CacheStoreDecision::bypass();
    }
    if body_size > config.max_body_size {
        return CacheStoreDecision::bypass();
    }

    let cache_control = header_value(headers, "cache-control")
        .map(parse_cache_control)
        .unwrap_or_default();

    if cache_control.no_store {
        return CacheStoreDecision::bypass();
    }

    // Shared caches must not store private responses unless explicitly allowed.
    if cache_control.private {
        return CacheStoreDecision::bypass();
    }

    let negative = is_negative_status(status);
    if negative {
        if !config.negative_cache_enabled {
            return CacheStoreDecision::bypass();
        }
    } else if !crate::cache::CACHEABLE_STATUS_CODES.contains(&status) {
        return CacheStoreDecision::bypass();
    }

    let (ttl, must_revalidate) = if negative {
        (config.negative_cache_ttl, false)
    } else if config.honor_cache_control {
        (
            ttl_from_directives(&cache_control, config.default_ttl),
            cache_control.no_cache,
        )
    } else {
        (config.default_ttl, false)
    };

    let etag = header_value(headers, "etag").map(Arc::from);
    let last_modified = header_value(headers, "last-modified").map(Arc::from);

    CacheStoreDecision {
        store: true,
        ttl,
        is_negative: negative,
        must_revalidate,
        etag,
        last_modified,
    }
}

fn ttl_from_directives(directives: &CacheControlDirectives, default_ttl: Duration) -> Duration {
    if let Some(age) = directives.s_maxage.or(directives.max_age) {
        return Duration::from_secs(age);
    }
    default_ttl
}

pub fn refresh_ttl_from_headers(
    headers: &HashMap<String, String>,
    default_ttl: Duration,
) -> Duration {
    let cache_control = header_value(headers, "cache-control")
        .map(parse_cache_control)
        .unwrap_or_default();
    ttl_from_directives(&cache_control, default_ttl)
}

pub fn has_validators(cached: &crate::cache::CachedResponse) -> bool {
    cached.etag.is_some() || cached.last_modified.is_some()
}

pub fn needs_revalidation(cached: &crate::cache::CachedResponse) -> bool {
    cached.must_revalidate || cached.is_expired()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn default_config() -> CacheConfig {
        CacheConfig {
            negative_cache_enabled: true,
            negative_cache_ttl: Duration::from_secs(120),
            honor_cache_control: true,
            ..CacheConfig::default()
        }
    }

    #[test]
    fn parse_cache_control_directives() {
        let cc = parse_cache_control("private, max-age=3600, no-cache, s-maxage=7200");
        assert!(cc.private);
        assert!(cc.no_cache);
        assert_eq!(cc.max_age, Some(3600));
        assert_eq!(cc.s_maxage, Some(7200));
        assert!(!cc.no_store);
    }

    #[test]
    fn no_store_bypasses_cache() {
        let h = headers(&[("Cache-Control", "no-store")]);
        let decision = evaluate_store("GET", 200, &h, 100, &default_config());
        assert!(!decision.store);
    }

    #[test]
    fn max_age_sets_ttl() {
        let h = headers(&[("Cache-Control", "max-age=600")]);
        let decision = evaluate_store("GET", 200, &h, 100, &default_config());
        assert!(decision.store);
        assert_eq!(decision.ttl, Duration::from_secs(600));
        assert!(!decision.is_negative);
    }

    #[test]
    fn s_maxage_overrides_max_age() {
        let h = headers(&[("Cache-Control", "max-age=600, s-maxage=300")]);
        let decision = evaluate_store("GET", 200, &h, 100, &default_config());
        assert_eq!(decision.ttl, Duration::from_secs(300));
    }

    #[test]
    fn negative_404_cached_when_enabled() {
        let h = headers(&[]);
        let decision = evaluate_store("GET", 404, &h, 0, &default_config());
        assert!(decision.store);
        assert!(decision.is_negative);
        assert_eq!(decision.ttl, Duration::from_secs(120));
    }

    #[test]
    fn negative_403_cached_when_enabled() {
        let h = headers(&[]);
        let decision = evaluate_store("GET", 403, &h, 0, &default_config());
        assert!(decision.store);
        assert!(decision.is_negative);
    }

    #[test]
    fn negative_disabled_bypasses() {
        let mut config = default_config();
        config.negative_cache_enabled = false;
        let h = headers(&[]);
        let decision = evaluate_store("GET", 404, &h, 0, &config);
        assert!(!decision.store);
    }

    #[test]
    fn no_cache_sets_must_revalidate() {
        let h = headers(&[("Cache-Control", "no-cache"), ("ETag", "\"abc\"")]);
        let decision = evaluate_store("GET", 200, &h, 100, &default_config());
        assert!(decision.store);
        assert!(decision.must_revalidate);
        assert_eq!(decision.etag.as_deref(), Some("\"abc\""));
    }

    #[test]
    fn private_response_not_stored() {
        let h = headers(&[("Cache-Control", "private, max-age=3600")]);
        let decision = evaluate_store("GET", 200, &h, 100, &default_config());
        assert!(!decision.store);
    }

    #[test]
    fn miss_x_cache_status_header_streaming() {
        let store = CacheStoreDecision {
            store: true,
            ttl: Duration::from_secs(60),
            is_negative: false,
            must_revalidate: false,
            etag: None,
            last_modified: None,
        };
        assert_eq!(miss_x_cache_status_header(true, &store), "MISS-STREAMING");
        assert_eq!(
            cache_status_metric_label("MISS-STREAMING"),
            "MISS_STREAMING"
        );
    }

    #[test]
    fn metric_labels_cover_every_miss_header_without_allocating() {
        for header in [
            "HIT",
            "MISS",
            "BYPASS",
            "MISS-STREAMING",
            "NEGATIVE-MISS",
            "NEGATIVE-MISS-STREAMING",
            "NEGATIVE-HIT",
            "L2-HIT",
            "REVALIDATED",
            "COALESCED-HIT",
            "LLM-MISS-STREAMING",
        ] {
            let label = cache_status_metric_label(header);
            assert!(
                matches!(label, Cow::Borrowed(_)),
                "{header} should map to a static label"
            );
            assert_eq!(label, header.replace('-', "_"));
        }
    }

    #[test]
    fn unknown_metric_labels_still_translate() {
        let label = cache_status_metric_label("SOME-NEW-STATUS");
        assert!(matches!(label, Cow::Owned(_)));
        assert_eq!(label, "SOME_NEW_STATUS");
    }
}
