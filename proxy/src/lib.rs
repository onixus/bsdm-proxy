//! BSDM-Proxy library

pub mod acl;
pub mod auth;
pub mod cache;
pub mod cache_compress;
pub mod cache_key;
pub mod categorization;
pub mod hierarchy;
pub mod hierarchy_config;
pub mod http_types;
pub mod icp;
pub mod l2_cache;
pub mod metrics;
pub mod peer_fetch;
pub mod peers;
pub mod pipeline;
pub mod proxy_service;
pub mod rate_limit;
pub mod selection;
pub mod server;
pub mod tls;
pub mod upstream;

// Re-export commonly used types
pub use acl::{AclAction, AclDecision, AclEngine, AclRule};
pub use auth::{AuthBackend, AuthConfig, AuthManager, UserInfo};
pub use cache::{CacheConfig, CachedResponse};
pub use cache_compress::{BodyEncoding, CompressionConfig};
pub use cache_key::http_cache_key;
pub use categorization::{CategorizationConfig, CategorizationEngine, Category};
pub use hierarchy::{HierarchyConfig, HierarchyManager, HierarchyResult};
pub use hierarchy_config::{
    build_hierarchy_manager, icp_server_bind_addr, load_hierarchy_config, should_start_icp_server,
};
pub use icp::{IcpClient, IcpMessage, IcpOpcode, IcpServer};
pub use l2_cache::{L2CacheConfig, RedisL2Cache};
pub use metrics::{Metrics, RequestMetricsGuard};
pub use peer_fetch::{fetch_via_peer, PeerFetchError};
pub use peers::{CachePeer, PeerConfig, PeerRegistry, PeerType};
pub use pipeline::CacheEvent;
pub use proxy_service::{ProxyPolicy, ProxyService};
pub use rate_limit::{RateLimitConfig, RateLimitViolation, RateLimiter};
pub use selection::{parse_strategy, SelectionStrategy};
pub use server::{handle_connection, metrics_server, wait_shutdown_signal};
pub use tls::CertCache;
pub use upstream::{build_upstream_https_connector, UpstreamTlsConfig};

// Conditional re-exports based on features
#[cfg(feature = "auth-ldap")]
pub use auth::LdapConfig;

#[cfg(feature = "auth-ntlm")]
pub use auth::NtlmConfig;

#[cfg(test)]
mod tests {
    use super::parse_strategy;

    #[test]
    fn hierarchy_modules_are_linked() {
        assert_eq!(parse_strategy("round-robin").name(), "round-robin");
        assert_eq!(parse_strategy("weighted").name(), "weighted");
    }
}
