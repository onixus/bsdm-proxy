//! Security helper utilities shared across proxy core, control-plane APIs, and auth.

use std::net::IpAddr;

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

/// Checks whether `domain` matches `target_or_suffix` as an exact host or as a subdomain.
///
/// Ensures a strict dot boundary so that `notexample.com` will **not** match `example.com`.
pub fn safe_subdomain_matches(domain: &str, target_or_suffix: &str) -> bool {
    let d = domain.trim().trim_end_matches('.');
    let s = target_or_suffix
        .trim()
        .trim_start_matches('.')
        .trim_end_matches('.');
    if d.eq_ignore_ascii_case(s) {
        return true;
    }
    if d.len() > s.len() + 1 && d.to_ascii_lowercase().ends_with(&s.to_ascii_lowercase()) {
        let boundary_idx = d.len() - s.len() - 1;
        return d.as_bytes()[boundary_idx] == b'.';
    }
    false
}

/// Identifies Cloud Instance Metadata Service (IMDS) endpoints.
///
/// Blocks AWS, Azure, GCP, OpenStack, and Alibaba metadata addresses:
/// - `169.254.0.0/16` (IPv4 Link-Local / IMDS)
/// - `fe80::/10` (IPv6 Link-Local)
/// - `metadata.google.internal`, `instance-data`
/// - `100.100.100.200` (Alibaba Cloud IMDS)
pub fn is_cloud_metadata_host(host: &str) -> bool {
    let clean = host
        .trim()
        .trim_matches('[')
        .trim_matches(']')
        .trim_end_matches('.');
    if clean.eq_ignore_ascii_case("metadata.google.internal")
        || clean.eq_ignore_ascii_case("instance-data")
        || clean.eq_ignore_ascii_case("metadata")
    {
        return true;
    }
    if let Ok(ip) = clean.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                // 169.254.0.0/16 (Link Local / IMDS)
                if octets[0] == 169 && octets[1] == 254 {
                    return true;
                }
                // 100.100.100.200 (Alibaba Cloud IMDS)
                if octets == [100, 100, 100, 200] {
                    return true;
                }
            }
            IpAddr::V6(ipv6) => {
                let segments = ipv6.segments();
                // fe80::/10 (Link-Local)
                if (segments[0] & 0xffc0) == 0xfe80 {
                    return true;
                }
            }
        }
    }
    false
}

/// Identifies loopback destinations (127.0.0.0/8, ::1, localhost).
pub fn is_loopback_host(host: &str) -> bool {
    let clean = host
        .trim()
        .trim_matches('[')
        .trim_matches(']')
        .trim_end_matches('.');
    if clean.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Ok(ip) = clean.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(ipv4) => ipv4.is_loopback() || ipv4.is_unspecified(),
            IpAddr::V6(ipv6) => ipv6.is_loopback() || ipv6.is_unspecified(),
        };
    }
    false
}

/// Validates whether a requested destination host and port is allowed by SSRF / network policy.
pub fn is_destination_allowed(
    host: &str,
    port: u16,
    block_metadata: bool,
    block_loopback: bool,
    allowed_ports: Option<&[u16]>,
) -> Result<(), &'static str> {
    if block_metadata && is_cloud_metadata_host(host) {
        return Err("cloud metadata destination blocked by security policy");
    }
    if block_loopback && is_loopback_host(host) {
        return Err("loopback destination blocked by security policy");
    }
    if let Some(ports) = allowed_ports {
        if !ports.contains(&port) {
            return Err("destination port blocked by security policy");
        }
    }
    Ok(())
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

    #[test]
    fn safe_subdomain_matching() {
        assert!(safe_subdomain_matches("example.com", "example.com"));
        assert!(safe_subdomain_matches("sub.example.com", "example.com"));
        assert!(safe_subdomain_matches("api.v1.example.com", "example.com"));
        assert!(safe_subdomain_matches("sub.example.com.", ".example.com"));

        // Must reject substring / suffix collisions without dot boundary
        assert!(!safe_subdomain_matches("notexample.com", "example.com"));
        assert!(!safe_subdomain_matches("fake-example.com", "example.com"));
        assert!(!safe_subdomain_matches(
            "example.com.evil.com",
            "example.com"
        ));
    }

    #[test]
    fn cloud_metadata_detection() {
        assert!(is_cloud_metadata_host("169.254.169.254"));
        assert!(is_cloud_metadata_host("169.254.169.253"));
        assert!(is_cloud_metadata_host("169.254.1.1"));
        assert!(is_cloud_metadata_host("metadata.google.internal"));
        assert!(is_cloud_metadata_host("metadata.google.internal."));
        assert!(is_cloud_metadata_host("instance-data"));
        assert!(is_cloud_metadata_host("100.100.100.200"));
        assert!(is_cloud_metadata_host("[fe80::1]"));

        assert!(!is_cloud_metadata_host("8.8.8.8"));
        assert!(!is_cloud_metadata_host("example.com"));
        assert!(!is_cloud_metadata_host("google.com"));
    }

    #[test]
    fn loopback_detection() {
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("localhost."));
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("127.0.0.2"));
        assert!(is_loopback_host("0.0.0.0"));
        assert!(is_loopback_host("::1"));
        assert!(is_loopback_host("[::1]"));

        assert!(!is_loopback_host("example.com"));
        assert!(!is_loopback_host("1.1.1.1"));
    }

    #[test]
    fn destination_allowed_validation() {
        assert!(is_destination_allowed("example.com", 443, true, true, None).is_ok());
        assert!(is_destination_allowed("169.254.169.254", 80, true, false, None).is_err());
        assert!(is_destination_allowed("127.0.0.1", 8080, false, true, None).is_err());
        assert!(
            is_destination_allowed("example.com", 22, false, false, Some(&[443, 8443])).is_err()
        );
        assert!(
            is_destination_allowed("example.com", 443, false, false, Some(&[443, 8443])).is_ok()
        );
    }
}
