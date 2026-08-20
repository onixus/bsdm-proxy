//! Built-in feed sources and the registry that turns config names into plugins.

mod openphish;
mod phishing_database;
mod phishstats;
mod urlhaus;

pub use openphish::OpenPhish;
pub use phishing_database::PhishingDatabase;
pub use phishstats::PhishStats;
pub use urlhaus::UrlHaus;

use crate::source::FeedSource;

/// Names accepted by `TI_SOURCES`, in the order they are collected by default.
pub const KNOWN_SOURCES: [&str; 4] = ["openphish", "phishstats", "phishing_database", "urlhaus"];

/// Build the enabled plugins. `url_override` supplies a per-source endpoint from
/// configuration (`TI_<SOURCE>_URL`), which also makes the sources testable
/// against a local fixture server.
pub fn build(
    names: &[String],
    url_override: &dyn Fn(&str) -> Option<String>,
) -> Result<Vec<Box<dyn FeedSource>>, String> {
    let mut sources: Vec<Box<dyn FeedSource>> = Vec::with_capacity(names.len());
    for name in names {
        let url = url_override(name);
        let source: Box<dyn FeedSource> = match name.as_str() {
            "openphish" => Box::new(OpenPhish::new(url)),
            "phishstats" => Box::new(PhishStats::new(url)),
            "phishing_database" => Box::new(PhishingDatabase::new(url)),
            "urlhaus" => Box::new(UrlHaus::new(url)),
            other => {
                return Err(format!(
                    "unknown feed source '{other}' (known: {})",
                    KNOWN_SOURCES.join(", ")
                ))
            }
        };
        sources.push(source);
    }
    Ok(sources)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_every_known_source() {
        let names: Vec<String> = KNOWN_SOURCES.iter().map(|s| s.to_string()).collect();
        let sources = build(&names, &|_| None).expect("known sources build");
        assert_eq!(sources.len(), KNOWN_SOURCES.len());
        for source in &sources {
            assert!(source.url().starts_with("https://"), "{}", source.name());
            assert!(source.weight() > 0 && source.weight() <= 100);
        }
    }

    #[test]
    fn rejects_unknown_source() {
        let err = match build(&["nope".to_string()], &|_| None) {
            Ok(_) => panic!("unknown source must be rejected"),
            Err(err) => err,
        };
        assert!(err.contains("unknown feed source"));
    }

    #[test]
    fn applies_url_override() {
        let sources = build(&["openphish".to_string()], &|name| {
            (name == "openphish").then(|| "http://127.0.0.1:9/feed.txt".to_string())
        })
        .unwrap();
        assert_eq!(sources[0].url(), "http://127.0.0.1:9/feed.txt");
    }
}
