//! Phishing.Database domain list: one hostname per line.

use crate::indicator::{looks_like_domain, IndicatorKind, RawIndicator};
use crate::source::{FeedError, FeedSource};

const DEFAULT_URL: &str = concat!(
    "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/",
    "phishing-domains-ACTIVE.txt"
);

pub struct PhishingDatabase {
    url: String,
}

impl PhishingDatabase {
    pub fn new(url: Option<String>) -> Self {
        Self {
            url: url.unwrap_or_else(|| DEFAULT_URL.to_string()),
        }
    }
}

impl FeedSource for PhishingDatabase {
    fn name(&self) -> &'static str {
        "phishing_database"
    }

    fn url(&self) -> &str {
        &self.url
    }

    fn weight(&self) -> u8 {
        75
    }

    fn parse(&self, body: &str) -> Result<Vec<RawIndicator>, FeedError> {
        let mut out = Vec::new();
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // Some variants of the list ship in hosts-file form
            // (`0.0.0.0 evil.example`); take the hostname column.
            let candidate = line.split_whitespace().next_back().unwrap_or(line);
            let candidate = candidate.trim_end_matches('.').to_ascii_lowercase();
            if looks_like_domain(&candidate) {
                out.push(RawIndicator::new(candidate, IndicatorKind::Domain, self));
            }
        }

        if out.is_empty() {
            return Err(FeedError::Empty);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_and_hosts_style_lines() {
        let source = PhishingDatabase::new(None);
        let body = "# list\nEvil.Example.COM\n0.0.0.0 bad.example\nlocalhost\n\n";
        let out = source.parse(body).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].value, "evil.example.com");
        assert_eq!(out[0].kind, IndicatorKind::Domain);
        assert_eq!(out[1].value, "bad.example");
    }

    #[test]
    fn empty_feed_is_an_error() {
        let source = PhishingDatabase::new(None);
        assert!(matches!(source.parse("\n#\n"), Err(FeedError::Empty)));
    }
}
