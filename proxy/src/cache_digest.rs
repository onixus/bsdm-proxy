//! Cache digest (Bloom filter) for hierarchy peer optimization.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

const DEFAULT_BIT_COUNT: usize = 65_536;
const DEFAULT_HASH_COUNT: u8 = 4;

/// Fixed-size Bloom filter over cache keys (SHA-256 hex strings or URLs).
#[derive(Clone, Debug)]
pub struct CacheDigest {
    bits: Vec<u8>,
    bit_count: usize,
    hash_count: u8,
}

impl CacheDigest {
    pub fn new(bit_count: usize, hash_count: u8) -> Self {
        let byte_len = bit_count.div_ceil(8);
        Self {
            bits: vec![0u8; byte_len],
            bit_count,
            hash_count,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_BIT_COUNT, DEFAULT_HASH_COUNT)
    }

    pub fn bit_count(&self) -> usize {
        self.bit_count
    }

    pub fn insert(&mut self, key: &str) {
        for seed in 0..self.hash_count {
            let index = Self::hash_index(key, seed, self.bit_count);
            let byte = index / 8;
            let bit = index % 8;
            self.bits[byte] |= 1 << bit;
        }
    }

    pub fn might_contain(&self, key: &str) -> bool {
        for seed in 0..self.hash_count {
            let index = Self::hash_index(key, seed, self.bit_count);
            let byte = index / 8;
            let bit = index % 8;
            if self.bits[byte] & (1 << bit) == 0 {
                return false;
            }
        }
        true
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.bits.clone()
    }

    pub fn from_bytes(bytes: &[u8], bit_count: usize, hash_count: u8) -> Option<Self> {
        let byte_len = bit_count.div_ceil(8);
        if bytes.len() != byte_len {
            return None;
        }
        Some(Self {
            bits: bytes.to_vec(),
            bit_count,
            hash_count,
        })
    }

    pub fn encode_base64(&self) -> String {
        B64.encode(self.to_bytes())
    }

    pub fn decode_base64(encoded: &str, bit_count: usize, hash_count: u8) -> Option<Self> {
        let bytes = B64.decode(encoded).ok()?;
        Self::from_bytes(&bytes, bit_count, hash_count)
    }

    fn hash_index(key: &str, seed: u8, bit_count: usize) -> usize {
        let mut hasher = Sha256::new();
        hasher.update([seed]);
        hasher.update(key.as_bytes());
        let digest = hasher.finalize();
        let value = u64::from_le_bytes(digest[..8].try_into().expect("8 bytes"));
        (value as usize) % bit_count
    }
}

#[derive(Clone)]
pub struct DigestRegistry {
    local: Arc<RwLock<CacheDigest>>,
    remote: Arc<RwLock<HashMap<String, RemoteDigest>>>,
    bit_count: usize,
    hash_count: u8,
    remote_ttl: Duration,
}

#[derive(Clone)]
struct RemoteDigest {
    digest: CacheDigest,
    updated_at: Instant,
}

impl DigestRegistry {
    pub fn new(bit_count: usize, hash_count: u8, remote_ttl: Duration) -> Self {
        Self {
            local: Arc::new(RwLock::new(CacheDigest::new(bit_count, hash_count))),
            remote: Arc::new(RwLock::new(HashMap::new())),
            bit_count,
            hash_count,
            remote_ttl,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(
            DEFAULT_BIT_COUNT,
            DEFAULT_HASH_COUNT,
            Duration::from_secs(300),
        )
    }

    pub async fn insert_cache_key(&self, cache_key: &str) {
        self.local.write().await.insert(cache_key);
    }

    pub async fn local_snapshot_base64(&self) -> String {
        self.local.read().await.encode_base64()
    }

    pub async fn update_remote(&self, peer_id: &str, digest_b64: &str) {
        let Some(digest) = CacheDigest::decode_base64(digest_b64, self.bit_count, self.hash_count)
        else {
            return;
        };
        self.remote.write().await.insert(
            peer_id.to_string(),
            RemoteDigest {
                digest,
                updated_at: Instant::now(),
            },
        );
    }

    pub async fn peer_might_have_url(&self, peer_id: &str, cache_key: &str) -> Option<bool> {
        let remote = self.remote.read().await;
        let entry = remote.get(peer_id)?;
        if entry.updated_at.elapsed() > self.remote_ttl {
            return None;
        }
        Some(entry.digest.might_contain(cache_key))
    }

    pub async fn prune_stale_remote(&self) {
        let mut remote = self.remote.write().await;
        remote.retain(|_, entry| entry.updated_at.elapsed() <= self.remote_ttl);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bloom_insert_and_query() {
        let mut digest = CacheDigest::with_defaults();
        digest.insert("abc123");
        assert!(digest.might_contain("abc123"));
        assert!(!digest.might_contain("missing-key"));
    }

    #[test]
    fn bloom_roundtrip_bytes() {
        let mut original = CacheDigest::new(1024, 3);
        original.insert("key-one");
        original.insert("key-two");
        let restored =
            CacheDigest::from_bytes(&original.to_bytes(), original.bit_count(), 3).unwrap();
        assert!(restored.might_contain("key-one"));
        assert!(!restored.might_contain("key-three"));
    }

    #[test]
    fn bloom_base64_roundtrip() {
        let mut digest = CacheDigest::with_defaults();
        digest.insert("digest-key");
        let encoded = digest.encode_base64();
        let decoded =
            CacheDigest::decode_base64(&encoded, digest.bit_count(), DEFAULT_HASH_COUNT).unwrap();
        assert!(decoded.might_contain("digest-key"));
    }

    #[tokio::test]
    async fn registry_tracks_remote_digest() {
        let registry = DigestRegistry::with_defaults();
        registry.insert_cache_key("local-key").await;
        let snapshot = registry.local_snapshot_base64().await;

        registry.update_remote("peer-1", &snapshot).await;
        assert_eq!(
            registry.peer_might_have_url("peer-1", "local-key").await,
            Some(true)
        );
        assert_eq!(
            registry.peer_might_have_url("peer-1", "absent").await,
            Some(false)
        );
    }
}
