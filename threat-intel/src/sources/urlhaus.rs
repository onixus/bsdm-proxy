//! URLhaus recent-URLs CSV feed (abuse.ch).
//!
//! Columns: `id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter`.

use crate::indicator::{IndicatorKind, RawIndicator};
use crate::source::{split_csv, unquote, FeedError, FeedSource};
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};

const DEFAULT_URL: &str = "https://urlhaus.abuse.ch/downloads/csv_recent/";

pub struct UrlHaus {
    url: String,
}

impl UrlHaus {
    pub fn new(url: Option<String>) -> Self {
        Self {
            url: url.unwrap_or_else(|| DEFAULT_URL.to_string()),
        }
    }
}

impl FeedSource for UrlHaus {
    fn name(&self) -> &'static str {
        "urlhaus"
    }

    fn url(&self) -> &str {
        &self.url
    }

    fn weight(&self) -> u8 {
        70
    }

    fn parse(&self, body: &str) -> Result<Vec<RawIndicator>, FeedError> {
        let mut out = Vec::new();
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields = split_csv(line);
            if fields.len() < 4 {
                continue;
            }
            let url = unquote(&fields[2]);
            if !url.starts_with("http://") && !url.starts_with("https://") {
                continue;
            }
            // Offline entries stay out of the collector; enforcement should not
            // grow on URLs the feed already retired.
            let status = unquote(&fields[3]).to_ascii_lowercase();
            if status == "offline" {
                continue;
            }

            let mut tags: Vec<String> = Vec::new();
            if let Some(threat) = fields.get(5).map(|f| unquote(f)) {
                if !threat.is_empty() {
                    tags.push(format!("threat:{threat}"));
                }
            }
            if let Some(raw_tags) = fields.get(6).map(|f| unquote(f)) {
                tags.extend(
                    raw_tags
                        .split(',')
                        .map(str::trim)
                        .filter(|t| !t.is_empty())
                        .map(str::to_string),
                );
            }

            let reference = fields.get(7).map(|f| unquote(f)).unwrap_or_default();
            out.push(
                RawIndicator::new(url, IndicatorKind::Url, self)
                    .with_reported_at(parse_timestamp(unquote(&fields[1])))
                    .with_reference(reference)
                    .with_tags(tags),
            );
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
        "# Dump generated\n",
        "# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n",
        "\"1\",\"2026-08-19 10:00:00\",\"http://a.example/x.bin\",\"online\",\"\",",
        "\"malware_download\",\"elf,mirai\",\"https://urlhaus.abuse.ch/url/1/\",\"reporter\"\n",
        "\"2\",\"2026-08-18 09:00:00\",\"http://b.example/y.bin\",\"offline\",\"\",",
        "\"malware_download\",\"\",\"https://urlhaus.abuse.ch/url/2/\",\"reporter\"\n",
    );

    #[test]
    fn keeps_online_urls_with_threat_tags() {
        let source = UrlHaus::new(None);
        let out = source.parse(SAMPLE).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].value, "http://a.example/x.bin");
        assert_eq!(out[0].kind, IndicatorKind::Url);
        assert_eq!(out[0].tags, vec!["threat:malware_download", "elf", "mirai"]);
        assert_eq!(
            out[0].reference.as_deref(),
            Some("https://urlhaus.abuse.ch/url/1/")
        );
        assert!(out[0].reported_at.is_some());
    }

    #[test]
    fn all_offline_entries_yield_empty_error() {
        let source = UrlHaus::new(None);
        let body = concat!(
            "# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n",
            "\"2\",\"2026-08-18 09:00:00\",\"http://b.example/y.bin\",\"offline\",\"\",",
            "\"malware_download\",\"\",\"https://urlhaus.abuse.ch/url/2/\",\"reporter\"\n",
        );
        assert!(matches!(source.parse(body), Err(FeedError::Empty)));
    }
}
