//! HTTP cache key generation (shared by proxy and ICP server).

use sha2::{Digest, Sha256};
use std::sync::Arc;

/// Deterministic cache key from HTTP method and URL.
pub fn http_cache_key(method: &str, url: &str) -> Arc<str> {
    let mut hasher = Sha256::new();
    hasher.update(method.as_bytes());
    hasher.update(b":");
    hasher.update(url.as_bytes());
    hex::encode(hasher.finalize()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_inputs_produce_same_key() {
        let a = http_cache_key("GET", "http://example.com/a");
        let b = http_cache_key("GET", "http://example.com/a");
        assert_eq!(a, b);
    }

    #[test]
    fn different_methods_differ() {
        let get = http_cache_key("GET", "http://example.com/a");
        let head = http_cache_key("HEAD", "http://example.com/a");
        assert_ne!(get, head);
    }
}
