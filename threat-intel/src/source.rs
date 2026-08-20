//! Feed source plugin contract.
//!
//! A source is a pure description of *where* a feed lives plus a *parser* for
//! its payload. Fetching, scheduling, retrying, deduplication and metrics stay
//! in the framework, which keeps sources trivial to add and to unit-test, and
//! guarantees the collector only ever performs `GET` requests against feed
//! endpoints — never against the indicators themselves.

use crate::indicator::{FeedMeta, RawIndicator};

#[derive(Debug, thiserror::Error)]
pub enum FeedError {
    #[error("transport error: {0}")]
    Transport(String),
    #[error("unexpected HTTP status {0}")]
    Status(u16),
    #[error("response exceeds {limit} bytes")]
    TooLarge { limit: usize },
    #[error("parse error: {0}")]
    Parse(String),
    #[error("feed returned no usable indicators")]
    Empty,
}

impl FeedError {
    /// Retrying a transport hiccup or a 5xx makes sense; a malformed payload or
    /// a 4xx will fail the same way on the next attempt.
    pub fn is_retryable(&self) -> bool {
        match self {
            FeedError::Transport(_) => true,
            FeedError::Status(code) => *code >= 500 || *code == 429,
            FeedError::TooLarge { .. } | FeedError::Parse(_) | FeedError::Empty => false,
        }
    }

    /// Stable label for the `result` metric dimension.
    pub fn metric_label(&self) -> &'static str {
        match self {
            FeedError::Transport(_) => "transport_error",
            FeedError::Status(_) => "http_error",
            FeedError::TooLarge { .. } => "too_large",
            FeedError::Parse(_) => "parse_error",
            FeedError::Empty => "empty",
        }
    }
}

/// One threat feed the collector knows how to ingest.
pub trait FeedSource: Send + Sync {
    /// Stable identifier used in config, metrics labels and output file names.
    fn name(&self) -> &'static str;

    /// Endpoint the collector fetches. Must be `http`/`https`.
    fn url(&self) -> &str;

    /// Source reputation weight from the collector spec (0–100).
    fn weight(&self) -> u8;

    /// `Accept` header the feed expects.
    fn accept(&self) -> &'static str {
        "text/plain, */*"
    }

    /// Turn a fetched payload into indicators.
    fn parse(&self, body: &str) -> Result<Vec<RawIndicator>, FeedError>;
}

impl<T: FeedSource + ?Sized> FeedMeta for T {
    fn name(&self) -> &'static str {
        FeedSource::name(self)
    }

    fn weight(&self) -> u8 {
        FeedSource::weight(self)
    }
}

/// Drop repeats inside a single fetch, preserving feed order.
pub fn dedupe_batch(mut indicators: Vec<RawIndicator>) -> Vec<RawIndicator> {
    let mut seen = std::collections::HashSet::new();
    indicators.retain(|ind| seen.insert((ind.kind, ind.value.clone())));
    indicators
}

/// Strip a CSV field of surrounding quotes and whitespace.
pub(crate) fn unquote(field: &str) -> &str {
    field
        .trim()
        .trim_start_matches('"')
        .trim_end_matches('"')
        .trim()
}

/// Split one CSV record, honouring double-quoted fields (feeds quote URLs that
/// contain commas).
pub(crate) fn split_csv(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for ch in line.chars() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => fields.push(std::mem::take(&mut current)),
            _ => current.push(ch),
        }
    }
    fields.push(current);
    fields
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::indicator::IndicatorKind;
    use chrono::Utc;

    fn ind(value: &str, kind: IndicatorKind) -> RawIndicator {
        RawIndicator {
            value: value.into(),
            kind,
            source: "test".into(),
            source_weight: 50,
            collected_at: Utc::now(),
            reported_at: None,
            reference: None,
            tags: Vec::new(),
        }
    }

    #[test]
    fn dedupes_by_kind_and_value() {
        let out = dedupe_batch(vec![
            ind("example.com", IndicatorKind::Domain),
            ind("example.com", IndicatorKind::Domain),
            ind("example.com", IndicatorKind::Url),
        ]);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn splits_quoted_csv_fields() {
        let fields = split_csv(r#"1,"http://a.example/x,y",online,"tag,tag2""#);
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[1], "http://a.example/x,y");
        assert_eq!(fields[3], "tag,tag2");
    }

    #[test]
    fn classifies_retryable_errors() {
        assert!(FeedError::Transport("timeout".into()).is_retryable());
        assert!(FeedError::Status(503).is_retryable());
        assert!(FeedError::Status(429).is_retryable());
        assert!(!FeedError::Status(404).is_retryable());
        assert!(!FeedError::Parse("bad".into()).is_retryable());
    }
}
