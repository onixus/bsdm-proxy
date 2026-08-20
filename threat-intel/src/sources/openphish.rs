//! OpenPhish community feed: one phishing URL per line.

use crate::indicator::{IndicatorKind, RawIndicator};
use crate::source::{FeedError, FeedSource};

const DEFAULT_URL: &str = "https://openphish.com/feed.txt";

pub struct OpenPhish {
    url: String,
}

impl OpenPhish {
    pub fn new(url: Option<String>) -> Self {
        Self {
            url: url.unwrap_or_else(|| DEFAULT_URL.to_string()),
        }
    }
}

impl FeedSource for OpenPhish {
    fn name(&self) -> &'static str {
        "openphish"
    }

    fn url(&self) -> &str {
        &self.url
    }

    fn weight(&self) -> u8 {
        90
    }

    fn parse(&self, body: &str) -> Result<Vec<RawIndicator>, FeedError> {
        let indicators: Vec<RawIndicator> = body
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .filter(|line| line.starts_with("http://") || line.starts_with("https://"))
            .map(|line| RawIndicator::new(line, IndicatorKind::Url, self))
            .collect();

        if indicators.is_empty() {
            return Err(FeedError::Empty);
        }
        Ok(indicators)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_url_lines_and_skips_noise() {
        let source = OpenPhish::new(None);
        let body = "# comment\nhttps://a.example/login\n\n  http://b.example/verify \nnot-a-url\n";
        let out = source.parse(body).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].value, "https://a.example/login");
        assert_eq!(out[1].value, "http://b.example/verify");
        assert_eq!(out[0].kind, IndicatorKind::Url);
        assert_eq!(out[0].source, "openphish");
        assert_eq!(out[0].source_weight, 90);
    }

    #[test]
    fn empty_feed_is_an_error() {
        let source = OpenPhish::new(None);
        assert!(matches!(source.parse("# nothing\n"), Err(FeedError::Empty)));
    }
}
