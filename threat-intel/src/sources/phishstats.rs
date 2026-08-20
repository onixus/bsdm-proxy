//! PhishStats scored CSV feed: `Date,Score,URL,IP`.

use crate::indicator::{is_ip_literal, IndicatorKind, RawIndicator};
use crate::source::{split_csv, unquote, FeedError, FeedSource};
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};

const DEFAULT_URL: &str = "https://phishstats.info/phish_score.csv";

pub struct PhishStats {
    url: String,
}

impl PhishStats {
    pub fn new(url: Option<String>) -> Self {
        Self {
            url: url.unwrap_or_else(|| DEFAULT_URL.to_string()),
        }
    }
}

impl FeedSource for PhishStats {
    fn name(&self) -> &'static str {
        "phishstats"
    }

    fn url(&self) -> &str {
        &self.url
    }

    fn weight(&self) -> u8 {
        80
    }

    fn parse(&self, body: &str) -> Result<Vec<RawIndicator>, FeedError> {
        let mut out = Vec::new();
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields = split_csv(line);
            if fields.len() < 3 {
                continue;
            }
            let reported_at = parse_timestamp(unquote(&fields[0]));
            let score = unquote(&fields[1]).to_string();
            let url = unquote(&fields[2]);
            if !url.starts_with("http://") && !url.starts_with("https://") {
                continue;
            }
            let tags = if score.is_empty() {
                Vec::new()
            } else {
                vec![format!("phishstats_score:{score}")]
            };
            out.push(
                RawIndicator::new(url, IndicatorKind::Url, self)
                    .with_reported_at(reported_at)
                    .with_tags(tags),
            );

            // The fourth column carries the resolved address at report time.
            if let Some(ip) = fields.get(3).map(|f| unquote(f)) {
                if is_ip_literal(ip) {
                    out.push(
                        RawIndicator::new(ip, IndicatorKind::Ip, self)
                            .with_reported_at(reported_at)
                            .with_reference(url),
                    );
                }
            }
        }

        if out.is_empty() {
            return Err(FeedError::Empty);
        }
        Ok(out)
    }
}

fn parse_timestamp(raw: &str) -> Option<DateTime<Utc>> {
    if raw.is_empty() {
        return None;
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(raw) {
        return Some(dt.with_timezone(&Utc));
    }
    NaiveDateTime::parse_from_str(raw, "%Y-%m-%d %H:%M:%S")
        .ok()
        .and_then(|naive| Utc.from_local_datetime(&naive).single())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = concat!(
        "#Date,Score,URL,IP\n",
        "\"2026-08-19 10:11:12\",\"7.20\",\"https://a.example/login?a=1,2\",\"203.0.113.7\"\n",
        "\"2026-08-19 10:12:00\",\"5.00\",\"http://b.example/\",\"unknown\"\n",
        "garbage line\n",
    );

    #[test]
    fn parses_urls_and_resolved_ips() {
        let source = PhishStats::new(None);
        let out = source.parse(SAMPLE).unwrap();
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].value, "https://a.example/login?a=1,2");
        assert_eq!(out[0].kind, IndicatorKind::Url);
        assert_eq!(out[0].tags, vec!["phishstats_score:7.20"]);
        assert!(out[0].reported_at.is_some());
        assert_eq!(out[1].value, "203.0.113.7");
        assert_eq!(out[1].kind, IndicatorKind::Ip);
        assert_eq!(
            out[1].reference.as_deref(),
            Some("https://a.example/login?a=1,2")
        );
        assert_eq!(out[2].value, "http://b.example/");
    }

    #[test]
    fn parses_rfc3339_timestamps() {
        assert!(parse_timestamp("2026-08-19T10:11:12Z").is_some());
        assert!(parse_timestamp("nonsense").is_none());
        assert!(parse_timestamp("").is_none());
    }
}
