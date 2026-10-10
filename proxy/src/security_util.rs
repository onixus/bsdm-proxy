//! Security helper utilities shared across proxy core, control-plane APIs, and auth.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

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
        return is_cloud_metadata_ip(ip);
    }
    false
}

/// IPv4-mapped (`::ffff:a.b.c.d`) and IPv4-compatible (`::a.b.c.d`) IPv6
/// addresses reach the embedded IPv4 host, so they are judged as that host.
fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let seg = v6.segments();
                // ::a.b.c.d (IPv4-compatible) and 64:ff9b::a.b.c.d (NAT64
                // well-known prefix, RFC 6052) both reach the embedded IPv4.
                let compat = seg[..6].iter().all(|s| *s == 0) && !(seg[6] == 0 && seg[7] <= 1);
                let nat64 = seg[0] == 0x64 && seg[1] == 0xff9b && seg[2..6].iter().all(|s| *s == 0);
                if compat || nat64 {
                    IpAddr::V4(std::net::Ipv4Addr::new(
                        (seg[6] >> 8) as u8,
                        seg[6] as u8,
                        (seg[7] >> 8) as u8,
                        seg[7] as u8,
                    ))
                } else {
                    IpAddr::V6(v6)
                }
            }
        },
        v4 => v4,
    }
}

/// AWS IMDS over IPv6 (Nitro): `fd00:ec2::254`.
const AWS_IMDS_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254);

/// IP-level metadata check, applied both to literals and to resolved addresses.
pub fn is_cloud_metadata_ip(ip: IpAddr) -> bool {
    match canonical_ip(ip) {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            // 169.254.0.0/16 (Link Local / IMDS), 100.100.100.200 (Alibaba Cloud IMDS)
            (octets[0] == 169 && octets[1] == 254) || octets == [100, 100, 100, 200]
        }
        IpAddr::V6(ipv6) => {
            // fe80::/10 (Link-Local) and AWS IPv6 IMDS
            (ipv6.segments()[0] & 0xffc0) == 0xfe80 || ipv6 == AWS_IMDS_V6
        }
    }
}

/// IP-level loopback/unspecified check (the proxy host itself).
pub fn is_loopback_ip(ip: IpAddr) -> bool {
    match canonical_ip(ip) {
        IpAddr::V4(ipv4) => ipv4.is_loopback() || ipv4.is_unspecified(),
        IpAddr::V6(ipv6) => ipv6.is_loopback() || ipv6.is_unspecified(),
    }
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
        return is_loopback_ip(ip);
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

/// Destination policy applied to *resolved* socket addresses, right before a
/// connection is opened. The string checks above only see what the client
/// wrote; a hostname with an A record of 127.0.0.1 / 169.254.169.254 (or
/// `nip.io`-style names, decimal IPs resolved by libc) passes them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ResolvedDestinationPolicy {
    pub block_metadata: bool,
    pub block_loopback: bool,
}

impl ResolvedDestinationPolicy {
    pub fn check(&self, addr: &SocketAddr) -> Result<(), &'static str> {
        let ip = addr.ip();
        if self.block_metadata && is_cloud_metadata_ip(ip) {
            return Err("cloud metadata destination blocked by security policy");
        }
        if self.block_loopback && is_loopback_ip(ip) {
            return Err("loopback destination blocked by security policy");
        }
        Ok(())
    }

    /// Fails if *any* address is blocked: a name that mixes a public and a
    /// forbidden address is treated as hostile rather than filtered.
    pub fn check_all(&self, addrs: &[SocketAddr]) -> Result<(), &'static str> {
        addrs.iter().try_for_each(|a| self.check(a))
    }

    /// Resolve `host:port` and return only addresses that passed the policy.
    pub async fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
        if addrs.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "destination did not resolve",
            ));
        }
        self.check_all(&addrs)
            .map_err(|reason| std::io::Error::new(std::io::ErrorKind::PermissionDenied, reason))?;
        Ok(addrs)
    }
}

/// DNS resolver for the upstream `HttpConnector` that enforces
/// [`ResolvedDestinationPolicy`] on every lookup, so the connection can only
/// go to addresses that were checked (no check-then-resolve gap).
#[derive(Clone, Debug)]
pub struct SsrfGuardResolver {
    policy: ResolvedDestinationPolicy,
}

impl SsrfGuardResolver {
    pub fn new(policy: ResolvedDestinationPolicy) -> Self {
        Self { policy }
    }
}

impl tower_service::Service<hyper_util::client::legacy::connect::dns::Name> for SsrfGuardResolver {
    type Response = std::vec::IntoIter<SocketAddr>;
    type Error = std::io::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: hyper_util::client::legacy::connect::dns::Name) -> Self::Future {
        let policy = self.policy;
        Box::pin(async move {
            // HttpConnector overrides the port of each returned address with the
            // URI port, so 0 here is fine.
            policy.resolve(name.as_str(), 0).await.map(Vec::into_iter)
        })
    }
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
    fn ipv4_mapped_and_aws_v6_metadata_are_blocked() {
        assert!(is_cloud_metadata_host("[::ffff:169.254.169.254]"));
        assert!(is_cloud_metadata_host("::ffff:a9fe:a9fe"));
        assert!(is_cloud_metadata_host("[fd00:ec2::254]"));
        assert!(is_cloud_metadata_host("[64:ff9b::a9fe:a9fe]"));
        assert!(is_loopback_host("64:ff9b::7f00:1"));
        assert!(is_destination_allowed("[::ffff:169.254.169.254]", 80, true, false, None).is_err());
        assert!(is_loopback_host("[::ffff:127.0.0.1]"));
        assert!(is_loopback_host("::127.0.0.1"));
        assert!(!is_loopback_host("::ffff:8.8.8.8"));
        assert!(!is_cloud_metadata_host("[2001:db8::1]"));
    }

    #[test]
    fn resolved_policy_checks_addresses() {
        let policy = ResolvedDestinationPolicy {
            block_metadata: true,
            block_loopback: true,
        };
        let a = |s: &str| s.parse::<SocketAddr>().unwrap();
        assert!(policy.check(&a("93.184.216.34:80")).is_ok());
        assert!(policy.check(&a("10.0.0.5:80")).is_ok());
        assert!(policy.check(&a("169.254.169.254:80")).is_err());
        assert!(policy.check(&a("[::ffff:169.254.169.254]:80")).is_err());
        assert!(policy.check(&a("127.0.0.1:6379")).is_err());
        assert!(policy.check(&a("[::1]:9090")).is_err());
        assert!(policy.check(&a("0.0.0.0:80")).is_err());
        // One bad address poisons the whole answer.
        assert!(policy
            .check_all(&[a("93.184.216.34:80"), a("127.0.0.1:80")])
            .is_err());
        let open = ResolvedDestinationPolicy::default();
        assert!(open.check(&a("127.0.0.1:80")).is_ok());
    }

    #[tokio::test]
    async fn resolve_rejects_names_pointing_at_loopback() {
        let policy = ResolvedDestinationPolicy {
            block_metadata: true,
            block_loopback: true,
        };
        // `localhost` resolves via the hosts file, no network needed.
        let err = policy.resolve("localhost", 80).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(policy.resolve("127.0.0.1", 80).await.is_err());
        let open = ResolvedDestinationPolicy::default();
        assert!(!open.resolve("127.0.0.1", 80).await.unwrap().is_empty());
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
