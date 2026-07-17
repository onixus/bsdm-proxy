//! Sharded L1 HTTP cache — reduces lock contention under multi-worker load.

use crate::cache::CachedResponse;
use quick_cache::sync::Cache;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

/// Sharded in-memory L1 cache (one `quick_cache` per shard).
#[derive(Debug)]
pub struct HttpL1Cache {
    shards: Vec<Cache<Arc<str>, CachedResponse>>,
    shard_mask: usize,
    per_shard_capacity: usize,
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
        self.shard(&key).insert(key, value);
    }

    pub fn remove(&self, key: &Arc<str>) -> Option<CachedResponse> {
        self.shard(key).remove(key).map(|(_, v)| v)
    }

    /// Drop every L1 entry. Returns the number of entries before clear.
    pub fn clear(&self) -> usize {
        let before = self.len();
        for shard in &self.shards {
            shard.clear();
        }
        before
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
}
