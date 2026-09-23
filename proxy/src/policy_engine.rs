//! Data-plane policy evaluation.
//!
//! Keeps request-time ACL, categorization, threat-intel and ML score checks
//! separate from the HTTP proxy orchestration. The engine is intentionally
//! synchronous: request-time policy evaluation only reads in-memory state.

use crate::acl::{AclAction, AclDecision, AclEngine, AclEngineHandle, AclRuleType};
use crate::categorization::CategorizationEngine;
use crate::metrics::Metrics;
use crate::policy_cache::PolicyDecisionCache;
use crate::threat_score_cache::ThreatScoreCache;
use crate::ti_enforce::TiEnforceMatcher;
use arc_swap::ArcSwapOption;
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::fmt::Write as _;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tracing::{debug, info};

const INLINE_ACL_CATEGORIES: usize = 8;
const SCOPE_SEP: char = '\u{1e}';

thread_local! {
    /// Dependency-aware destination key reused across policy cache probes.
    static POLICY_SCOPE_SCRATCH: RefCell<String> = const { RefCell::new(String::new()) };
}

/// Result of a single data-plane policy evaluation.
#[derive(Debug)]
pub struct PolicyEvaluation {
    pub blocking: Option<AclDecision>,
    pub categories: Vec<String>,
    pub threat_sources: Vec<String>,
}

/// ACL inputs that can change a decision for the same destination domain.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct AclCacheDimensions {
    principal: bool,
    url: bool,
    client_ip: bool,
    time: bool,
}

/// Cached metadata for one immutable ACL snapshot.
///
/// `AclEngineHandle` publishes a fresh `Arc<AclEngine>` on every mutation. By
/// retaining that Arc here we can detect snapshot changes with `Arc::ptr_eq`
/// and scan rule types once per reload instead of once per request.
struct AclProfile {
    engine: Arc<AclEngine>,
    dimensions: AclCacheDimensions,
}

fn scan_acl_dimensions(engine: &AclEngine) -> AclCacheDimensions {
    let mut dimensions = AclCacheDimensions::default();
    for rule in engine.rules().iter().filter(|rule| rule.enabled) {
        match &rule.rule_type {
            AclRuleType::UrlPrefix(_) | AclRuleType::Regex(_) => dimensions.url = true,
            AclRuleType::IpRange { .. } => dimensions.client_ip = true,
            AclRuleType::TimeWindow { .. } => dimensions.time = true,
            AclRuleType::Principal { .. } => dimensions.principal = true,
            AclRuleType::Domain(_) | AclRuleType::Category(_) => {}
        }
    }
    dimensions
}

fn current_minute_bucket() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() / 60)
        .unwrap_or(0)
}

fn acl_action_label(action: AclAction) -> &'static str {
    match action {
        AclAction::Allow => "allow",
        AclAction::Deny => "deny",
        AclAction::Redirect => "redirect",
    }
}

/// Build borrowed category names without allocating in the common case.
fn with_category_refs<R>(categories: &[String], f: impl FnOnce(&[&str]) -> R) -> R {
    if categories.len() <= INLINE_ACL_CATEGORIES {
        let mut inline = [""; INLINE_ACL_CATEGORIES];
        for (slot, category) in inline.iter_mut().zip(categories) {
            *slot = category.as_str();
        }
        f(&inline[..categories.len()])
    } else {
        let refs: Vec<&str> = categories.iter().map(String::as_str).collect();
        f(&refs)
    }
}

/// Read-mostly policy engine used by the proxy hot path.
///
/// All network/background refresh work stays in the owning components. This
/// type only coordinates their in-memory request-time lookups.
pub struct PolicyEngine {
    acl_engine: Option<Arc<AclEngineHandle>>,
    acl_profile: ArcSwapOption<AclProfile>,
    categorization: Option<Arc<CategorizationEngine>>,
    policy_cache: Arc<PolicyDecisionCache>,
    threat_score_cache: Arc<ThreatScoreCache>,
    ti_enforce: Arc<TiEnforceMatcher>,
    metrics: Arc<Metrics>,
}

impl PolicyEngine {
    pub fn new(
        acl_engine: Option<Arc<AclEngineHandle>>,
        categorization: Option<Arc<CategorizationEngine>>,
        policy_cache: Arc<PolicyDecisionCache>,
        threat_score_cache: Arc<ThreatScoreCache>,
        ti_enforce: Arc<TiEnforceMatcher>,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            acl_engine,
            acl_profile: ArcSwapOption::empty(),
            categorization,
            policy_cache,
            threat_score_cache,
            ti_enforce,
            metrics,
        }
    }

    pub fn policy_cache(&self) -> Arc<PolicyDecisionCache> {
        self.policy_cache.clone()
    }

    pub fn ti_enforce(&self) -> &Arc<TiEnforceMatcher> {
        &self.ti_enforce
    }

    pub fn categorize_url(&self, url: &str) -> (Vec<String>, Vec<String>) {
        let Some(engine) = &self.categorization else {
            return (Vec::new(), Vec::new());
        };
        let start = Instant::now();
        let result = engine.categorize_local(url);
        if result.categories.is_empty() && engine.online_enrichment_enabled() {
            engine.schedule_online_enrichment(url);
            self.metrics.record_categorization_online_enrich_scheduled();
        }
        let categories: Vec<String> = result
            .categories
            .iter()
            .map(crate::categorization::Category::acl_name)
            .filter(|name| !name.is_empty())
            .collect();
        let threat_sources = if result.source != "unknown" && !categories.is_empty() {
            vec![result.source.clone()]
        } else {
            Vec::new()
        };
        self.metrics.record_categorization_lookup(
            &result.source,
            result.cached,
            &categories,
            start.elapsed().as_secs_f64(),
        );
        (categories, threat_sources)
    }

    fn cached_acl_dimensions(&self, engine: &Arc<AclEngine>) -> AclCacheDimensions {
        let cached = self.acl_profile.load();
        if let Some(profile) = cached.as_ref() {
            if Arc::ptr_eq(&profile.engine, engine) {
                return profile.dimensions;
            }
        }

        let dimensions = scan_acl_dimensions(engine);
        self.acl_profile.store(Some(Arc::new(AclProfile {
            engine: engine.clone(),
            dimensions,
        })));
        dimensions
    }

    #[allow(clippy::too_many_arguments)]
    fn with_cache_scope<R>(
        &self,
        dimensions: AclCacheDimensions,
        url: &str,
        domain: &str,
        username: Option<&str>,
        groups: &[&str],
        client_ip: &str,
        f: impl FnOnce(Option<&str>, &str, &[&str]) -> R,
    ) -> R {
        let cache_username = if dimensions.principal {
            username
        } else {
            None
        };
        let cache_groups = if dimensions.principal { groups } else { &[] };
        let vary_url = self.categorization.is_some() || dimensions.url;
        if !vary_url && !dimensions.client_ip && !dimensions.time {
            return f(cache_username, domain, cache_groups);
        }

        POLICY_SCOPE_SCRATCH.with(|scratch| {
            let mut key = scratch.borrow_mut();
            key.clear();
            key.push_str(domain);

            if vary_url {
                // The full URL can be attacker-controlled and very large. A
                // cryptographic digest keeps cache keys bounded without making
                // policy correctness depend on a weak hot-path hash.
                let digest = Sha256::digest(url.as_bytes());
                key.push(SCOPE_SEP);
                key.push('u');
                key.push(':');
                const HEX: &[u8; 16] = b"0123456789abcdef";
                for byte in digest {
                    key.push(HEX[(byte >> 4) as usize] as char);
                    key.push(HEX[(byte & 0x0f) as usize] as char);
                }
            }
            if dimensions.client_ip {
                key.push(SCOPE_SEP);
                key.push('i');
                key.push(':');
                key.push_str(client_ip);
            }
            if dimensions.time {
                key.push(SCOPE_SEP);
                key.push('t');
                key.push(':');
                let _ = write!(key, "{}", current_minute_bucket());
            }
            f(cache_username, &key, cache_groups)
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn check_acl(
        &self,
        acl_engine: Option<&AclEngine>,
        dimensions: AclCacheDimensions,
        url: &str,
        domain: &str,
        category_names: &[String],
        username: Option<&str>,
        groups: &[&str],
        client_ip: &str,
    ) -> (Option<AclDecision>, bool) {
        let Some(acl_engine) = acl_engine else {
            return (None, false);
        };

        let parsed_client_ip = if dimensions.client_ip {
            client_ip.parse::<IpAddr>().ok()
        } else {
            None
        };
        let eval_start = Instant::now();
        let decision = with_category_refs(category_names, |category_refs| {
            acl_engine.check_access(
                url,
                domain,
                category_refs,
                username,
                groups,
                parsed_client_ip,
            )
        });

        self.metrics
            .acl_eval_duration_seconds
            .observe(eval_start.elapsed().as_secs_f64());
        let action_label = acl_action_label(decision.action);
        self.metrics
            .acl_decisions_total
            .with_label_values(&[action_label])
            .inc();
        if let Some(rule_id) = &decision.rule_id {
            self.metrics
                .acl_rules_matched_total
                .with_label_values(&[rule_id])
                .inc();
        }

        let explicit_allow = decision.action == AclAction::Allow && decision.rule_id.is_some();
        if decision.action == AclAction::Allow {
            (None, explicit_allow)
        } else {
            info!("ACL {} for {}: {}", decision.action, url, decision.reason);
            self.metrics
                .record_categorization_blocked(category_names, action_label);
            (Some(decision), false)
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn evaluate_static_policy(
        &self,
        acl_engine: Option<&AclEngine>,
        dimensions: AclCacheDimensions,
        url: &str,
        domain: &str,
        username: Option<&str>,
        groups: &[&str],
        client_ip: &str,
    ) -> (Option<AclDecision>, Vec<String>, Vec<String>) {
        let (category_names, mut threat_sources) = self.categorize_url(url);
        let (mut blocking, explicit_allow) = self.check_acl(
            acl_engine,
            dimensions,
            url,
            domain,
            &category_names,
            username,
            groups,
            client_ip,
        );
        if !explicit_allow && blocking.is_none() {
            if let Some(hit) = self.ti_enforce.match_domain(domain) {
                blocking = Some(AclDecision::deny(
                    format!("ti:{}", hit.feed),
                    format!(
                        "Threat intelligence feed match ({}): {}",
                        hit.feed, hit.indicator
                    ),
                ));
                threat_sources.push(hit.feed.clone());
                self.metrics.record_ti_enforce_blocked(&hit.feed);
            }
        }
        (blocking, category_names, threat_sources)
    }

    #[allow(clippy::too_many_arguments)]
    fn evaluate_with_acl(
        &self,
        acl_engine: Option<&AclEngine>,
        dimensions: AclCacheDimensions,
        url: &str,
        domain: &str,
        username: Option<&str>,
        groups: &[&str],
        client_ip: &str,
    ) -> PolicyEvaluation {
        let policy_active =
            acl_engine.is_some() || self.categorization.is_some() || self.ti_enforce.enabled();
        let cache_enabled = policy_active && self.policy_cache.enabled();

        let (mut blocking, category_names, mut threat_sources) = if cache_enabled {
            self.with_cache_scope(
                dimensions,
                url,
                domain,
                username,
                groups,
                client_ip,
                |cache_username, cache_domain, cache_groups| {
                    if let Some(hit) =
                        self.policy_cache
                            .lookup(cache_username, cache_domain, cache_groups)
                    {
                        self.metrics.policy_cache_hit_total.inc();
                        debug!("Policy cache hit for {:?} @ {}", username, domain);
                        return (hit.blocking, hit.categories, hit.threat_sources);
                    }

                    let result = self.evaluate_static_policy(
                        acl_engine,
                        dimensions,
                        url,
                        domain,
                        username,
                        groups,
                        client_ip,
                    );
                    // Cache only stable ACL/categorization/TI state. ML scores
                    // are client-specific and replaced asynchronously; storing
                    // them here can block another client or outlive a refresh.
                    self.policy_cache.store(
                        cache_username,
                        cache_domain,
                        cache_groups,
                        result.1.clone(),
                        result.2.clone(),
                        result.0.clone(),
                    );
                    result
                },
            )
        } else {
            self.evaluate_static_policy(
                acl_engine,
                dimensions,
                url,
                domain,
                username,
                groups,
                client_ip,
            )
        };

        // Dynamic ML posture is deliberately evaluated after the static cache
        // on every request against the current lock-free score snapshot.
        self.threat_score_cache.apply_to_policy(
            domain,
            client_ip,
            &mut threat_sources,
            &mut blocking,
        );

        PolicyEvaluation {
            blocking,
            categories: category_names,
            threat_sources,
        }
    }

    pub fn evaluate(
        &self,
        url: &str,
        domain: &str,
        username: Option<&str>,
        groups: &[&str],
        client_ip: &str,
    ) -> PolicyEvaluation {
        let Some(handle) = &self.acl_engine else {
            return self.evaluate_with_acl(
                None,
                AclCacheDimensions::default(),
                url,
                domain,
                username,
                groups,
                client_ip,
            );
        };

        let snapshot = handle.load();
        let engine: &Arc<AclEngine> = &*snapshot;
        let dimensions = self.cached_acl_dimensions(engine);
        self.evaluate_with_acl(
            Some(engine.as_ref()),
            dimensions,
            url,
            domain,
            username,
            groups,
            client_ip,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::{AclRule, AclRuleType};
    use crate::policy_cache::PolicyCacheConfig;
    use crate::threat_score_cache::{ThreatScoreConfig, ThreatScoreHit};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    fn rule(id: &str, rule_type: AclRuleType) -> AclRule {
        AclRule {
            id: id.to_string(),
            name: id.to_string(),
            enabled: true,
            priority: 100,
            action: AclAction::Deny,
            rule_type,
            redirect_url: None,
            comment: None,
        }
    }

    fn test_engine(rules: Vec<AclRule>, threat_scores: ThreatScoreCache) -> PolicyEngine {
        let mut acl = AclEngine::new(AclAction::Allow);
        acl.load_rules(rules);
        PolicyEngine::new(
            Some(Arc::new(AclEngineHandle::new(acl))),
            None,
            Arc::new(PolicyDecisionCache::new(PolicyCacheConfig {
                ttl: Duration::from_secs(300),
                max_keys: 100,
            })),
            Arc::new(threat_scores),
            Arc::new(TiEnforceMatcher::disabled()),
            Arc::new(Metrics::new().expect("metrics")),
        )
    }

    #[test]
    fn url_rules_do_not_reuse_a_block_for_another_path() {
        let engine = test_engine(
            vec![rule(
                "admin",
                AclRuleType::UrlPrefix("https://example.test/admin".to_string()),
            )],
            ThreatScoreCache::new(ThreatScoreConfig::default()),
        );

        let blocked = engine.evaluate(
            "https://example.test/admin/users",
            "example.test",
            Some("alice"),
            &[],
            "10.0.0.1",
        );
        assert_eq!(
            blocked.blocking.as_ref().map(|decision| decision.action),
            Some(AclAction::Deny)
        );

        let allowed = engine.evaluate(
            "https://example.test/public",
            "example.test",
            Some("alice"),
            &[],
            "10.0.0.1",
        );
        assert!(allowed.blocking.is_none());
    }

    #[test]
    fn ip_rules_do_not_reuse_a_block_for_another_client() {
        let engine = test_engine(
            vec![rule(
                "blocked-ip",
                AclRuleType::IpRange {
                    start: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    end: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                },
            )],
            ThreatScoreCache::new(ThreatScoreConfig::default()),
        );

        assert!(engine
            .evaluate(
                "https://example.test/",
                "example.test",
                Some("alice"),
                &[],
                "10.0.0.1",
            )
            .blocking
            .is_some());
        assert!(engine
            .evaluate(
                "https://example.test/",
                "example.test",
                Some("alice"),
                &[],
                "10.0.0.2",
            )
            .blocking
            .is_none());
    }

    #[test]
    fn client_specific_ml_block_does_not_poison_static_policy_cache() {
        let threat_scores = ThreatScoreCache::new(ThreatScoreConfig {
            enabled: true,
            poll_url: String::new(),
            poll_interval: Duration::from_secs(60),
            cache_ttl: Duration::from_secs(300),
            warn_threshold: 0.7,
            block_threshold: 0.9,
        });
        threat_scores.replace_hits_for_test(vec![ThreatScoreHit {
            score: 0.95,
            severity: "critical".to_string(),
            model: "client-risk".to_string(),
            entity_type: "client_ip".to_string(),
            entity_id: "10.0.0.1".to_string(),
        }]);
        let engine = test_engine(Vec::new(), threat_scores);

        let risky = engine.evaluate(
            "https://example.test/",
            "example.test",
            Some("alice"),
            &[],
            "10.0.0.1",
        );
        assert_eq!(
            risky.blocking.as_ref().map(|decision| decision.action),
            Some(AclAction::Deny)
        );

        let clean = engine.evaluate(
            "https://example.test/",
            "example.test",
            Some("alice"),
            &[],
            "10.0.0.2",
        );
        assert!(clean.blocking.is_none());
    }

    #[test]
    fn rule_dimension_scan_ignores_disabled_rules() {
        let mut disabled = rule(
            "disabled-url",
            AclRuleType::UrlPrefix("https://example.test/private".to_string()),
        );
        disabled.enabled = false;
        let mut acl = AclEngine::new(AclAction::Allow);
        acl.load_rules(vec![
            disabled,
            AclRule {
                id: "admins".to_string(),
                name: "admins".to_string(),
                enabled: true,
                priority: 10,
                action: AclAction::Allow,
                rule_type: AclRuleType::Principal {
                    user: None,
                    group: Some("admins".to_string()),
                },
                redirect_url: None,
                comment: None,
            },
        ]);
        assert_eq!(
            scan_acl_dimensions(&acl),
            AclCacheDimensions {
                principal: true,
                ..AclCacheDimensions::default()
            }
        );
    }
}
