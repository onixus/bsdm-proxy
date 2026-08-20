//! HTTP cache key generation (shared by proxy and ICP server).

use sha2::{Digest, Sha256};
use std::sync::Arc;

const HEX: &[u8; 16] = b"0123456789abcdef";

/// SHA-256 digest length in hex characters.
pub const CACHE_KEY_LEN: usize = 64;

/// Deterministic cache key from HTTP method and URL.
///
/// The digest stays SHA-256: cache keys travel between nodes over ICP, HTCP and
/// cache digests, so the algorithm is wire format, not an implementation detail.
/// The hex encoding is written into a stack buffer so building the key costs a
/// single allocation (the `Arc<str>`) instead of one for an intermediate
/// `String` plus one for the `Arc`.
pub fn http_cache_key(method: &str, url: &str) -> Arc<str> {
    let mut hasher = Sha256::new();
    hasher.update(method.as_bytes());
    hasher.update(b":");
    hasher.update(url.as_bytes());
    let digest = hasher.finalize();

    let mut hex = [0u8; CACHE_KEY_LEN];
    for (i, byte) in digest.iter().enumerate() {
        hex[i * 2] = HEX[(byte >> 4) as usize];
        hex[i * 2 + 1] = HEX[(byte & 0x0f) as usize];
    }

    // SAFETY-free: every byte written above is an ASCII hex digit.
    debug_assert!(hex.is_ascii());
    Arc::from(std::str::from_utf8(&hex).unwrap_or_default())
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

    #[test]
    fn key_is_lowercase_hex_of_expected_length() {
        let key = http_cache_key("GET", "http://example.com/a");
        assert_eq!(key.len(), CACHE_KEY_LEN);
        assert!(key.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(!key.bytes().any(|b| b.is_ascii_uppercase()));
    }

    #[test]
    fn matches_reference_sha256_hex() {
        // Wire-format guard: peers (ICP / HTCP / cache digests) must agree on
        // this exact encoding, so pin it against an independent hex encoder.
        let mut hasher = Sha256::new();
        hasher.update(b"GET");
        hasher.update(b":");
        hasher.update(b"http://example.com/a");
        let expected = hex::encode(hasher.finalize());
        assert_eq!(
            http_cache_key("GET", "http://example.com/a").as_ref(),
            expected
        );
    }
}
