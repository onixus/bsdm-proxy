//! BSDM-Proxy library

pub mod acl;
pub mod acl_api;
pub mod acl_config;
pub mod amneziawg;
pub mod auth;
#[cfg(any(feature = "auth-ntlm", feature = "auth-kerberos"))]
pub mod auth_sspi;
pub mod cache;
pub mod cache_body;
pub mod cache_compress;
pub mod cache_digest;
pub mod cache_freshness;
pub mod cache_key;
pub mod casb;
pub mod categorization;
pub mod control_api;
#[cfg(feature = "grpc")]
pub mod control_grpc;
pub mod dlp;
pub mod ebpf;
pub mod hierarchy;
pub mod hierarchy_config;
pub mod htcp;
pub mod http_types;
pub mod icap;
pub mod icp;
pub mod l2_cache;
pub mod metrics;
pub mod miss_coalesce;
pub mod peer_discovery;
pub mod peer_fetch;
pub mod peers;
pub mod perf;
pub mod pipeline;
pub mod policy_cache;
pub mod proxy_service;
pub mod rate_limit;
pub mod reverse_proxy;
pub mod security_util;
pub mod selection;
pub mod semantic_cache;
pub mod server;
pub mod session;
pub mod sharded_cache;
pub mod streaming_miss;
pub mod tag_index;
pub mod threat_score_cache;
pub mod tls;
pub mod upstream;
#[cfg(feature = "wasm")]
pub mod wasm_host;

// Re-export commonly used types
pub use acl::{AclAction, AclDecision, AclEngine, AclEngineHandle, AclRule};
pub use acl_api::{AclApiConfig, AclApiState};
pub use acl_config::{load_acl_engine_from_file, parse_acl_action, save_acl_engine_to_file};
#[cfg(feature = "auth-kerberos")]
pub use auth::KerberosConfig;
#[cfg(feature = "auth-ntlm")]
pub use auth::NtlmConfig;
pub use auth::{AuthBackend, AuthConfig, AuthManager, ConnAuthCache, ProxyAuthOutcome, UserInfo};
pub use bsdm_events::CacheEvent;
pub use cache::{CacheConfig, CachedResponse};
pub use cache_body::{ensure_private_spill_dir, CachedBody};
pub use cache_compress::{BodyEncoding, CompressionConfig};
pub use cache_digest::DigestRegistry;
pub use cache_key::http_cache_key;
pub use categorization::{CategorizationConfig, CategorizationEngine, Category};
pub use control_api::ControlApiState;
pub use ebpf::{EbpfStats, EbpfXdpConfig, EbpfXdpManager, XdpMode};
pub use hierarchy::{HierarchyConfig, HierarchyManager, HierarchyResult};
pub use hierarchy_config::{
    build_hierarchy_manager, htcp_peer_port, htcp_server_bind_addr, icp_server_bind_addr,
    load_hierarchy_config, reload_static_peers, should_start_htcp_server, should_start_icp_server,
    HierarchyReloadReport, HierarchySetup, PeerConfigSource,
};
pub use htcp::{HtcpClient, HtcpOpcode, HtcpServer};
pub use icp::{IcpClient, IcpMessage, IcpOpcode, IcpServer};
pub use l2_cache::{L2CacheConfig, RedisL2Cache};
pub use metrics::{FastRequestScope, Metrics, RequestMetricsGuard};
pub use peer_discovery::{run_peer_discovery, PeerDiscoveryConfig};
pub use peer_fetch::{fetch_via_peer, PeerFetchError, PeerTlsConfig};
pub use peers::{CachePeer, PeerConfig, PeerRegistry, PeerType, ReplaceStaticStats};
pub use perf::{bind_http_listeners, PerfConfig};
pub use pipeline::{dispatch_cache_event, new_event_id, HttpEventPipeline};
#[cfg(feature = "kafka")]
pub use pipeline::{flush_kafka, KafkaEventPipeline};
pub use policy_cache::{PolicyCacheConfig, PolicyDecisionCache};
pub use proxy_service::{ProxyPolicy, ProxyService};
pub use rate_limit::{extract_api_key, RateLimitConfig, RateLimitViolation, RateLimiter};
pub use reverse_proxy::{OidcConfig, ReverseProxyConfig};
pub use selection::{parse_strategy, SelectionStrategy};
pub use semantic_cache::{
    content_cache_key, normalize_llm_body, SemanticCacheConfig, SemanticIndex,
};
pub use server::{handle_connection, metrics_server, wait_shutdown_signal};
pub use session::{SessionCorrelation, SessionCorrelator};
pub use sharded_cache::HttpL1Cache;
pub use tag_index::{parse_cache_tags, TagIndex};
pub use threat_score_cache::{ThreatScoreCache, ThreatScoreConfig, ThreatScoreHit};
pub use tls::CertCache;
pub use upstream::{
    build_upstream_https_connector, UpstreamClientHandle, UpstreamTlsConfig, UpstreamTlsSnapshot,
};

// Conditional re-exports based on features
#[cfg(feature = "auth-ldap")]
pub use auth::LdapConfig;

#[cfg(test)]
mod tests {
    use super::parse_strategy;

    #[test]
    fn hierarchy_modules_are_linked() {
        assert_eq!(parse_strategy("round-robin").name(), "round-robin");
        assert_eq!(parse_strategy("weighted").name(), "weighted");
    }
}
