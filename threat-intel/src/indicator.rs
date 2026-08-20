//! IOC value types shared by every feed source.
//!
//! Full normalization (punycode, URL canonicalization, cross-run deduplication)
//! is TASK-TI-003 and deliberately not implemented here: the collector keeps the
//! feed value as published and only trims obvious transport noise.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IndicatorKind {
    Url,
    Domain,
    Ip,
}

impl IndicatorKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            IndicatorKind::Url => "url",
            IndicatorKind::Domain => "domain",
            IndicatorKind::Ip => "ip",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawIndicator {
    pub value: String,
    pub kind: IndicatorKind,
    /// Feed that published the indicator (`source.name()`).
    pub source: String,
    /// Source reputation weight from the collector spec, carried through for the
    /// scoring engine (TASK-TI-010).
    pub source_weight: u8,
    /// When the collector observed the value in the feed.
    pub collected_at: DateTime<Utc>,
    /// Publication timestamp reported by the feed, when it provides one.
    pub reported_at: Option<DateTime<Utc>>,
    /// Feed-specific reference (report link, entry id) for audit.
    pub reference: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

impl RawIndicator {
    pub fn new(value: impl Into<String>, kind: IndicatorKind, source: &dyn FeedMeta) -> Self {
        Self {
            value: value.into(),
            kind,
            source: source.name().to_string(),
            source_weight: source.weight(),
            collected_at: Utc::now(),
            reported_at: None,
            reference: None,
            tags: Vec::new(),
        }
    }

    pub fn with_reference(mut self, reference: impl Into<String>) -> Self {
        let reference = reference.into();
        if !reference.is_empty() {
            self.reference = Some(reference);
        }
        self
    }

    pub fn with_reported_at(mut self, reported_at: Option<DateTime<Utc>>) -> Self {
        self.reported_at = reported_at;
        self
    }

    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }
}

/// The parts of a source a [`RawIndicator`] needs to attribute itself.
pub trait FeedMeta {
    fn name(&self) -> &'static str;
    fn weight(&self) -> u8;
}

/// True for syntactically valid IPv4/IPv6 literals.
pub fn is_ip_literal(value: &str) -> bool {
    value.parse::<IpAddr>().is_ok()
}

/// Cheap sanity check for feed-published hostnames. This is not normalization —
/// it only rejects values that clearly are not domains so obvious junk lines do
/// not reach storage.
pub fn looks_like_domain(value: &str) -> bool {
    if value.is_empty() || value.len() > 253 || is_ip_literal(value) {
        return false;
    }
    if !value.contains('.') || value.starts_with('.') || value.ends_with('.') {
        return false;
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_ip_literals() {
        assert!(is_ip_literal("203.0.113.7"));
        assert!(is_ip_literal("2001:db8::1"));
        assert!(!is_ip_literal("example.com"));
    }

    #[test]
    fn filters_obvious_non_domains() {
        assert!(looks_like_domain("login.example.com"));
        assert!(looks_like_domain("xn--80ak6aa92e.com"));
        assert!(!looks_like_domain("example"));
        assert!(!looks_like_domain("203.0.113.7"));
        assert!(!looks_like_domain("-bad.example.com"));
        assert!(!looks_like_domain("http://example.com/a"));
        assert!(!looks_like_domain(""));
    }
}
