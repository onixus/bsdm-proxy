//! Secondary index: Cache-Tag / Surrogate-Key → L1 cache keys.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

/// Parse CDN cache tags from response headers (`Cache-Tag`, `Surrogate-Key`).
pub fn parse_cache_tags(headers: &[(Arc<str>, Arc<str>)]) -> Vec<String> {
    let mut tags = Vec::new();
    for (name, value) in headers {
        let parts: Vec<&str> = if name.eq_ignore_ascii_case("cache-tag") {
            value
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect()
        } else if name.eq_ignore_ascii_case("surrogate-key") {
            value.split_whitespace().filter(|s| !s.is_empty()).collect()
        } else {
            continue;
        };
        for t in parts {
            if !tags.iter().any(|x| x == t) {
                tags.push(t.to_string());
            }
        }
    }
    tags
}

#[derive(Debug, Default)]
pub struct TagIndex {
    by_tag: RwLock<HashMap<String, HashSet<Arc<str>>>>,
    by_key: RwLock<HashMap<Arc<str>, Vec<String>>>,
}

impl TagIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn index(&self, key: &Arc<str>, tags: &[String]) {
        let old = {
            let mut by_key = self.by_key.write().expect("tag index lock");
            if tags.is_empty() {
                by_key.remove(key)
            } else {
                by_key.insert(key.clone(), tags.to_vec())
            }
        };

        let mut by_tag = self.by_tag.write().expect("tag index lock");
        if let Some(old_tags) = old {
            for t in old_tags {
                if let Some(set) = by_tag.get_mut(&t) {
                    set.remove(key);
                    if set.is_empty() {
                        by_tag.remove(&t);
                    }
                }
            }
        }
        for t in tags {
            by_tag.entry(t.clone()).or_default().insert(key.clone());
        }
    }

    pub fn unindex(&self, key: &Arc<str>) {
        let tags = {
            let mut by_key = self.by_key.write().expect("tag index lock");
            by_key.remove(key)
        };
        let Some(tags) = tags else {
            return;
        };
        let mut by_tag = self.by_tag.write().expect("tag index lock");
        for t in tags {
            if let Some(set) = by_tag.get_mut(&t) {
                set.remove(key);
                if set.is_empty() {
                    by_tag.remove(&t);
                }
            }
        }
    }

    pub fn clear(&self) {
        self.by_tag.write().expect("tag index lock").clear();
        self.by_key.write().expect("tag index lock").clear();
    }

    pub fn keys_for_tag(&self, tag: &str) -> Vec<Arc<str>> {
        self.by_tag
            .read()
            .expect("tag index lock")
            .get(tag)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn tag_count(&self) -> usize {
        self.by_tag.read().expect("tag index lock").len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cache_tag_header() {
        let headers: Arc<[(Arc<str>, Arc<str>)]> =
            Arc::from([(Arc::from("Cache-Tag"), Arc::from("product-42, catalog"))]);
        let tags = parse_cache_tags(&headers);
        assert_eq!(tags, vec!["product-42", "catalog"]);
    }

    #[test]
    fn parses_surrogate_key() {
        let headers: Arc<[(Arc<str>, Arc<str>)]> =
            Arc::from([(Arc::from("Surrogate-Key"), Arc::from("page article-9"))]);
        let tags = parse_cache_tags(&headers);
        assert_eq!(tags, vec!["page", "article-9"]);
    }

    #[test]
    fn index_and_lookup() {
        let idx = TagIndex::new();
        let k1: Arc<str> = Arc::from("GET|http://a/");
        let k2: Arc<str> = Arc::from("GET|http://b/");
        idx.index(&k1, &["t1".into(), "shared".into()]);
        idx.index(&k2, &["shared".into()]);
        assert_eq!(idx.keys_for_tag("t1").len(), 1);
        assert_eq!(idx.keys_for_tag("shared").len(), 2);
        idx.unindex(&k1);
        assert!(idx.keys_for_tag("t1").is_empty());
        assert_eq!(idx.keys_for_tag("shared").len(), 1);
    }
}
