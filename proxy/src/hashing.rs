//! Fast non-cryptographic hashing for hot-path shard selection.
//!
//! These helpers are **only** used to pick a shard index. Shard selection never
//! decides a policy outcome and every shard is individually bounded, so a weak
//! hash cannot be turned into anything worse than uneven shard occupancy — the
//! same worst case as a single unsharded map. Map lookups inside a shard keep
//! the standard SipHash `RandomState`, which is what protects the attacker-
//! controlled keys (domains, URLs) from hash-flooding.

/// FxHash-style multiply/rotate mixer (the rustc hasher), 64-bit variant.
const SEED: u64 = 0x51_7c_c1_b7_27_22_0a_95;

#[inline]
fn mix(hash: u64, word: u64) -> u64 {
    (hash.rotate_left(5) ^ word).wrapping_mul(SEED)
}

/// Hash a byte slice for shard selection. Consumes 8 bytes per round.
#[inline]
pub fn fx_hash_bytes(bytes: &[u8]) -> u64 {
    let mut hash = 0u64;
    let mut chunks = bytes.chunks_exact(8);
    for chunk in &mut chunks {
        let word = u64::from_le_bytes(chunk.try_into().unwrap_or([0; 8]));
        hash = mix(hash, word);
    }
    let rest = chunks.remainder();
    if !rest.is_empty() {
        let mut tail = [0u8; 8];
        tail[..rest.len()].copy_from_slice(rest);
        hash = mix(hash, u64::from_le_bytes(tail));
    }
    mix(hash, bytes.len() as u64)
}

/// Hash a string for shard selection.
#[inline]
pub fn fx_hash_str(value: &str) -> u64 {
    fx_hash_bytes(value.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_deterministic() {
        assert_eq!(fx_hash_str("example.com"), fx_hash_str("example.com"));
    }

    #[test]
    fn distinct_inputs_mostly_differ() {
        assert_ne!(fx_hash_str("a.example.com"), fx_hash_str("b.example.com"));
        assert_ne!(fx_hash_str(""), fx_hash_str("x"));
    }

    #[test]
    fn tail_bytes_are_mixed_in() {
        // Inputs sharing an 8-byte prefix must not collapse to the same hash.
        assert_ne!(fx_hash_str("abcdefghi"), fx_hash_str("abcdefghj"));
    }

    #[test]
    fn length_is_mixed_in() {
        // Zero-extension of a short tail must not alias a longer key.
        assert_ne!(fx_hash_bytes(&[1, 0]), fx_hash_bytes(&[1]));
    }

    #[test]
    fn spreads_across_power_of_two_shards() {
        let mask = 15usize;
        let mut seen = [0usize; 16];
        for i in 0..4096 {
            let key = format!("{:064x}", i);
            seen[(fx_hash_str(&key) as usize) & mask] += 1;
        }
        // Every shard should get a share; perfectly uniform would be 256 each.
        assert!(seen.iter().all(|&n| n > 128), "uneven spread: {seen:?}");
    }
}
