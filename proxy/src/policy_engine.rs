//! Data-plane policy evaluation.
//!
//! Keeps request-time ACL, categorization, threat-intel and ML score checks
//! separate from the HTTP proxy orchestration. The engine is intentionally
//! synchronous: request-time policy evaluation only reads in-memory state.

use crate::acl::{AclAction, AclDecision, AclEngineHandle};
use crate::categorization::CategorizationEngine;
use crate::metrics::Metrics;
use crate::policy_cache::PolicyDecisionCache;
use crate::threat_score_cache::ThreatScoreCache;
use crate::ti_enforce::TiEnforceMatcher;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info};

/// Result of a single data-plane policy evaluation.
#[derive(Debug)]
pub struct PolicyEvaluation {
    pub blocking: Option<AclDecision>,
    pub categories: Vec<String>,
    pub threat_sources: Vec<String>,
}

/// Read-mostly policy engine used by the proxy hot path.
///
/// All network/background refresh work stays in the owning components. This
/// type only coordinates their in-memory request-time lookups.
pub struct PolicyEngine {
    acl_engine: Option<Arc<AclEngineHandle>>,
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

    fn check_acl(
        &self,
        url: &str,
        domain: &str,
        category_names: &[String],
        username: Option<&str>,
        groups: &[&str],
        client_ip: &str,
    ) -> (Option<AclDecision>, bool) {
        let Some(acl_engine) = &self.acl_engine else {
            return (None, false);
        };

        let eval_start = Instant::now();
        let category_refs: Vec<&str> = category_names.iter().map(String::as_str).collect();
        let decision = acl_engine.check_access(
            url,
            domain,
            &category_refs,
            username,
            groups,
            client_ip.parse::<IpAddr>().ok(),
        );

        self.metrics
            .acl_eval_duration_seconds
            .observe(eval_start.elapsed().as_secs_f64());
        let action_label = decision.action.to_string();
        self.metrics
            .acl_decisions_total
            .with_label_values(&[&action_label])
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
                .record_categorization_blocked(category_names, &action_label);
            (Some(decision), false)
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
        let policy_active =
            self.acl_engine.is_some() || self.categorization.is_some() || self.ti_enforce.enabled();
        let mut from_cache = false;
        let (mut blocking, category_names, mut threat_sources) =
            if policy_active && self.policy_cache.enabled() {
                if let Some(hit) = self.policy_cache.lookup(username, domain, groups) {
                    from_cache = true;
                    self.metrics.policy_cache_hit_total.inc();
                    debug!("Policy cache hit for {:?} @ {}", username, domain);
                    (hit.blocking, hit.categories, hit.threat_sources)
                } else {
                    let (category_names, mut threat_sources) = self.categorize_url(url);
                    let (mut blocking, explicit_allow) =
                        self.check_acl(url, domain, &category_names, username, groups, client_ip);
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
            } else {
                let (category_names, mut threat_sources) = self.categorize_url(url);
                let (mut blocking, explicit_allow) =
                    self.check_acl(url, domain, &category_names, username, groups, client_ip);
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
            };

        self.threat_score_cache.apply_to_policy(
            domain,
            client_ip,
            &mut threat_sources,
            &mut blocking,
        );

        if policy_active && self.policy_cache.enabled() && !from_cache {
            self.policy_cache.store(
                username,
                domain,
                groups,
                category_names.clone(),
                threat_sources.clone(),
                blocking.clone(),
            );
        }

        PolicyEvaluation {
            blocking,
            categories: category_names,
            threat_sources,
        }
    }
}
