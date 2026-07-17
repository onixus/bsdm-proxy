//! Sharded L1 HTTP cache — reduces lock contention under multi-worker load.

use crate::cache::CachedResponse;
use crate::tag_index::{parse_cache_tags, TagIndex};
use quick_cache::sync::Cache;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

/// Sharded in-memory L1 cache (one `quick_cache` per shard).
#[derive(Debug)]
pub struct HttpL1Cache {
    shards: Vec<Cache<Arc<str>, CachedResponse>>,
    shard_mask: usize,
    per_shard_capacity: usize,
    tag_index: TagIndex,
}

impl HttpL1Cache {
    pub fn new(total_capacity: usize, shard_count: usize) -> Self {
        let shards_n = shard_count.max(1).next_power_of_two();
        let per_shard = (total_capacity / shards_n).max(1);
        let shards = (0..shards_n).map(|_| Cache::new(per_shard)).collect();
        Self {
            shards,
            shard_mask: shards_n - 1,
            per_shard_capacity: per_shard,
            tag_index: TagIndex::new(),
        }
    }

    #[inline]
    fn shard_index(&self, key: &str) -> usize {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut hasher);
        (hasher.finish() as usize) & self.shard_mask
    }

    #[inline]
    fn shard(&self, key: &str) -> &Cache<Arc<str>, CachedResponse> {
        &self.shards[self.shard_index(key)]
    }

    pub fn get(&self, key: &Arc<str>) -> Option<CachedResponse> {
        self.shard(key).get(key)
    }

    pub fn insert(&self, key: Arc<str>, value: CachedResponse) {
        let tags = parse_cache_tags(&value.headers);
        self.tag_index.unindex(&key);
        self.tag_index.index(&key, &tags);
        self.shard(&key).insert(key, value);
    }

    pub fn remove(&self, key: &Arc<str>) -> Option<CachedResponse> {
        self.tag_index.unindex(key);
        self.shard(key).remove(key).map(|(_, v)| v)
    }

    /// Drop every L1 entry. Returns the number of entries before clear.
    pub fn clear(&self) -> usize {
        let before = self.len();
        for shard in &self.shards {
            shard.clear();
        }
        self.tag_index.clear();
        before
    }

    /// Remove all L1 entries indexed under `tag`. Returns count removed.
    pub fn purge_tag(&self, tag: &str) -> usize {
        let keys = self.keys_for_tag(tag);
        let mut removed = 0;
        for key in keys {
            if self.remove(&key).is_some() {
                removed += 1;
            }
        }
        removed
    }

    pub fn keys_for_tag(&self, tag: &str) -> Vec<Arc<str>> {
        self.tag_index.keys_for_tag(tag)
    }

    pub fn tag_count(&self) -> usize {
        self.tag_index.tag_count()
    }

    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| s.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn weight(&self) -> u64 {
        self.shards.iter().map(|s| s.weight()).sum()
    }

    pub fn capacity(&self) -> usize {
        self.per_shard_capacity * self.shards.len()
    }

    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache_body::CachedBody;
    use crate::cache_compress::BodyEncoding;
    use bytes::Bytes;
    use std::time::{Duration, SystemTime};

    fn sample_entry(body: &str) -> CachedResponse {
        CachedResponse {
            status: 200,
            headers: Arc::from([]),
            body: CachedBody::inline(Bytes::copy_from_slice(body.as_bytes())),
            body_encoding: BodyEncoding::Raw,
            uncompressed_len: body.len(),
            cached_at: SystemTime::now(),
            ttl: Duration::from_secs(60),
            etag: None,
            last_modified: None,
            is_negative: false,
            must_revalidate: false,
        }
    }

    fn tagged_entry(tag: &str) -> CachedResponse {
        let mut e = sample_entry("x");
        e.headers = Arc::from([(Arc::from("cache-tag"), Arc::from(tag))]);
        e
    }

    #[test]
    fn shards_distribute_keys() {
        let cache = HttpL1Cache::new(100, 8);
        assert_eq!(cache.shard_count(), 8);
        for i in 0..50 {
            let key = Arc::from(format!("http://example.com/{i}"));
            cache.insert(Arc::clone(&key), sample_entry("x"));
        }
        assert_eq!(cache.len(), 50);
    }

    #[test]
    fn purge_tag_removes_matching_entries() {
        let cache = HttpL1Cache::new(100, 4);
        let k1: Arc<str> = Arc::from("k1");
        let k2: Arc<str> = Arc::from("k2");
        let k3: Arc<str> = Arc::from("k3");
        cache.insert(k1.clone(), tagged_entry("product-42"));
        cache.insert(k2.clone(), tagged_entry("product-42, other"));
        cache.insert(k3.clone(), tagged_entry("other"));
        assert_eq!(cache.purge_tag("product-42"), 2);
        assert!(cache.get(&k1).is_none());
        assert!(cache.get(&k2).is_none());
        assert!(cache.get(&k3).is_some());
    }
}
