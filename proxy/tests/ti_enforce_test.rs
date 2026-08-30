use arc_swap::ArcSwap;
use bsdm_proxy::{
    AclAction, AclEngine, AclEngineHandle, AclRule, AclRuleType, CacheConfig, CertCache, Metrics,
    MitmCircuitBreaker, MitmCircuitBreakerConfig, PerfConfig, PinningRegistry, PolicyCacheConfig,
    PolicyDecisionCache, PolicyMode, ProxyPolicy, ProxyService, RateLimitConfig, ThreatScoreCache,
    ThreatScoreConfig, TiEnforceConfig, TiEnforceMatcher, UpstreamTlsConfig,
};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

const ENFORCE_FEED_JSON: &str = r#"{
    "generated_at": "2026-08-29T00:00:00Z",
    "mode": "enforce",
    "domain_count": 2,
    "domains": ["malware-c2.com", "internal-tool.phish.com"],
    "feeds": {
        "malware-c2.com": "urlhaus",
        "internal-tool.phish.com": "phishing-database"
    }
}"#;

const SHADOW_FEED_JSON: &str = r#"{
    "generated_at": "2026-08-29T00:00:00Z",
    "mode": "shadow",
    "domain_count": 1,
    "domains": ["malware-c2.com"],
    "feeds": {
        "malware-c2.com": "urlhaus"
    }
}"#;

fn make_test_service(
    acl_rules: Vec<AclRule>,
    ti_matcher: Arc<TiEnforceMatcher>,
    metrics: Arc<Metrics>,
) -> ProxyService {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut acl_engine = AclEngine::new(AclAction::Allow);
    if !acl_rules.is_empty() {
        acl_engine.load_rules(acl_rules);
    }
    let acl_handle = Arc::new(AclEngineHandle::shared(Arc::new(ArcSwap::from_pointee(
        acl_engine,
    ))));

    let pinning_registry = Arc::new(PinningRegistry::from_entries(Vec::new()).unwrap());
    let mitm_circuit_breaker = Arc::new(MitmCircuitBreaker::new(
        MitmCircuitBreakerConfig::default(),
        None,
    ));

    let proxy_policy = ProxyPolicy {
        policy_mode: PolicyMode::Sni,
        mitm_categories: vec![],
        pinning_registry,
        mitm_circuit_breaker,
        acl_engine: Some(acl_handle),
        categorization: None,
    };

    let policy_cache = Arc::new(PolicyDecisionCache::new(PolicyCacheConfig {
        ttl: Duration::from_secs(60),
        max_keys: 100,
    }));

    let key_pair = rcgen::KeyPair::generate().unwrap();
    let cert_cache = CertCache::from_pem(key_pair.serialize_pem().as_bytes(), b"").unwrap();

    ProxyService::new(
        cert_cache,
        CacheConfig::default(),
        None,
        #[cfg(feature = "kafka")]
        None,
        None,
        metrics,
        false,
        None,
        &proxy_policy,
        None,
        None,
        RateLimitConfig::default(),
        UpstreamTlsConfig::default(),
        PerfConfig::default(),
        policy_cache,
        Arc::new(ThreatScoreCache::new(ThreatScoreConfig::default())),
        None,
        ti_matcher,
    )
}

#[tokio::test]
async fn test_ti_enforce_blocks_matching_domain() {
    let metrics = Arc::new(Metrics::new().unwrap());
    let ti_matcher = Arc::new(TiEnforceMatcher::new(
        TiEnforceConfig {
            enabled: true,
            configured_posture: bsdm_proxy::ti_enforce::EnforcementPosture::Enforce,
            feed_path: std::path::PathBuf::from("/var/lib/threat_domains.json"),
            reload_interval: Duration::from_secs(300),
        },
        None,
        Some(metrics.clone()),
    ));

    ti_matcher
        .load_from_str(
            ENFORCE_FEED_JSON,
            Some(Path::new("/var/lib/threat_domains.json")),
        )
        .unwrap();

    let service = make_test_service(vec![], ti_matcher, metrics.clone());

    let (blocking, _categories, threat_sources) = service
        .check_policy(
            "http://malware-c2.com/payload",
            "malware-c2.com",
            None,
            &[],
            "10.0.0.1",
        )
        .await;

    assert!(
        blocking.is_some(),
        "request to malware domain should be blocked"
    );
    let decision = blocking.unwrap();
    assert_eq!(decision.action, AclAction::Deny);
    assert_eq!(decision.rule_id.as_deref(), Some("ti:urlhaus"));
    assert!(decision.reason.contains("urlhaus"));
    assert!(threat_sources.contains(&"urlhaus".to_string()));

    // Verify subdomains are also blocked
    let (sub_blocking, _categories, _threats) = service
        .check_policy(
            "http://botnet.malware-c2.com/c2",
            "botnet.malware-c2.com",
            None,
            &[],
            "10.0.0.1",
        )
        .await;
    assert!(
        sub_blocking.is_some(),
        "subdomain of malware domain should be blocked"
    );

    // Check metric increment
    assert_eq!(
        metrics
            .ti_enforce_blocked_total
            .with_label_values(&["urlhaus"])
            .get(),
        2.0
    );
}

#[tokio::test]
async fn test_allowlist_precedence_over_ti_feed() {
    let metrics = Arc::new(Metrics::new().unwrap());
    let ti_matcher = Arc::new(TiEnforceMatcher::new(
        TiEnforceConfig {
            enabled: true,
            configured_posture: bsdm_proxy::ti_enforce::EnforcementPosture::Enforce,
            feed_path: std::path::PathBuf::from("/var/lib/threat_domains.json"),
            reload_interval: Duration::from_secs(300),
        },
        None,
        Some(metrics.clone()),
    ));

    ti_matcher
        .load_from_str(
            ENFORCE_FEED_JSON,
            Some(Path::new("/var/lib/threat_domains.json")),
        )
        .unwrap();

    // Explicit Allow rule for internal-tool.phish.com
    let allow_rule = AclRule {
        id: "corp-allow-internal-tool".to_string(),
        name: "Allow Internal Tool".to_string(),
        enabled: true,
        priority: 100,
        action: AclAction::Allow,
        rule_type: AclRuleType::Domain("internal-tool.phish.com".to_string()),
        redirect_url: None,
        comment: None,
    };

    let service = make_test_service(vec![allow_rule], ti_matcher, metrics.clone());

    let (blocking, _categories, _threat_sources) = service
        .check_policy(
            "http://internal-tool.phish.com/dashboard",
            "internal-tool.phish.com",
            None,
            &[],
            "10.0.0.1",
        )
        .await;

    // Corporate explicit allowlist MUST win over TI block
    assert!(
        blocking.is_none(),
        "explicit ACL allow rule must take precedence over TI feed"
    );

    // No TI enforce block metric should have been recorded for phishing-database
    assert_eq!(
        metrics
            .ti_enforce_blocked_total
            .with_label_values(&["phishing-database"])
            .get(),
        0.0
    );
}

#[tokio::test]
async fn test_shadow_mode_does_not_block() {
    let metrics = Arc::new(Metrics::new().unwrap());
    let ti_matcher = Arc::new(TiEnforceMatcher::new(
        TiEnforceConfig {
            enabled: true,
            configured_posture: bsdm_proxy::ti_enforce::EnforcementPosture::Shadow,
            feed_path: std::path::PathBuf::from("/var/lib/threat_domains.json.shadow"),
            reload_interval: Duration::from_secs(300),
        },
        None,
        Some(metrics.clone()),
    ));

    ti_matcher
        .load_from_str(
            SHADOW_FEED_JSON,
            Some(Path::new("/var/lib/threat_domains.json.shadow")),
        )
        .unwrap();

    assert_eq!(
        ti_matcher.effective_mode(),
        bsdm_proxy::ti_enforce::EffectiveMode::ShadowOnly
    );

    let service = make_test_service(vec![], ti_matcher, metrics.clone());

    let (blocking, _categories, _threat_sources) = service
        .check_policy(
            "http://malware-c2.com/payload",
            "malware-c2.com",
            None,
            &[],
            "10.0.0.1",
        )
        .await;

    // Shadow mode must NOT block traffic
    assert!(
        blocking.is_none(),
        "shadow mode must never block traffic on the data plane"
    );

    assert_eq!(
        metrics
            .ti_enforce_blocked_total
            .with_label_values(&["urlhaus"])
            .get(),
        0.0
    );
}
