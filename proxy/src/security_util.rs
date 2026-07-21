//! Small security helper utilities shared across control-plane APIs and auth caching.

/// Constant-time equality check for secrets (bearer tokens, password hashes).
///
/// Ordinary `==` on `&[u8]`/`&str` short-circuits at the first differing byte, which
/// lets an attacker who can measure response timing recover a secret one byte at a
/// time by repeated guessing. This compares every byte regardless of where the first
/// mismatch occurs.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_secrets_match() {
        assert!(constant_time_eq(b"secret-token", b"secret-token"));
    }

    #[test]
    fn different_secrets_do_not_match() {
        assert!(!constant_time_eq(b"secret-token", b"wrong-token!!"));
    }

    #[test]
    fn different_lengths_do_not_match() {
        assert!(!constant_time_eq(b"short", b"much-longer-token"));
    }

    #[test]
    fn empty_secrets_match() {
        assert!(constant_time_eq(b"", b""));
    }
}
