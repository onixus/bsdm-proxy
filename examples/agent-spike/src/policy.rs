//! Local policy model and evaluation (Agent Contract v0.1 subset).

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalPolicy {
    pub policy_version: String,
    pub policy_mode: String,
    pub mitm_categories: HashSet<String>,
    pub sni_deny_patterns: Vec<String>,
    pub pinning_exceptions: HashSet<String>,
}

impl Default for LocalPolicy {
    fn default() -> Self {
        Self {
            policy_version: "v0.1-offline".to_string(),
            policy_mode: "selective-mitm".to_string(),
            mitm_categories: ["malware", "phishing", "illegal-content"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            sni_deny_patterns: vec!["*.evil.com".to_string(), "badsite.test".to_string()],
            pinning_exceptions: [".slack.com", ".teams.microsoft.com", ".zoom.us"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }
}

/// Control-plane `GET /api/v1/agent/policy` payload.
#[derive(Debug, Clone, Deserialize)]
pub struct RemotePolicyDto {
    pub policy_version: String,
    pub policy_mode: String,
    #[serde(default)]
    pub mitm_categories: Vec<String>,
    #[serde(default)]
    pub pinning_exceptions: Vec<String>,
    #[serde(default)]
    pub sni_deny_patterns: Vec<String>,
    #[serde(default)]
    pub sni_rules: Vec<SniRuleDto>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SniRuleDto {
    pub pattern: String,
    #[serde(default)]
    pub action: String,
}

impl LocalPolicy {
    /// Map control-plane JSON onto the on-device engine.
    pub fn from_remote(dto: RemotePolicyDto) -> Self {
        let mut sni_deny = dto.sni_deny_patterns;
        if sni_deny.is_empty() {
            for rule in &dto.sni_rules {
                let action = rule.action.to_ascii_lowercase();
                if action.is_empty() || action == "deny" {
                    sni_deny.push(rule.pattern.clone());
                }
            }
        }
        if sni_deny.is_empty() {
            sni_deny = LocalPolicy::default().sni_deny_patterns;
        }
        Self {
            policy_version: dto.policy_version,
            policy_mode: dto.policy_mode,
            mitm_categories: dto.mitm_categories.into_iter().collect(),
            sni_deny_patterns: sni_deny,
            pinning_exceptions: dto.pinning_exceptions.into_iter().collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalDecision {
    Allow,
    Deny { reason: String },
    BypassMitm { reason: String },
    InspectMitm { category: String },
}

/// Evaluate domain against an in-memory policy (pure, sync).
pub fn evaluate_domain(policy: &LocalPolicy, domain: &str) -> LocalDecision {
    let domain_lower = domain.to_ascii_lowercase();

    for pattern in &policy.sni_deny_patterns {
        if pattern.starts_with("*.") {
            let suffix = &pattern[1..];
            if domain_lower.ends_with(suffix) {
                return LocalDecision::Deny {
                    reason: format!("SNI pattern match: {pattern}"),
                };
            }
        } else if domain_lower == *pattern {
            return LocalDecision::Deny {
                reason: format!("SNI exact match: {pattern}"),
            };
        }
    }

    if policy.pinning_exceptions.iter().any(|exc| {
        if exc.starts_with('.') {
            domain_lower.ends_with(exc) || domain_lower == exc.trim_start_matches('.')
        } else {
            domain_lower == *exc
        }
    }) {
        return LocalDecision::BypassMitm {
            reason: "certificate_pinning_exception".to_string(),
        };
    }

    match policy.policy_mode.as_str() {
        "sni" => LocalDecision::Allow,
        "full-mitm" => LocalDecision::InspectMitm {
            category: "full-mitm-default".to_string(),
        },
        _ => {
            if policy.mitm_categories.contains("phishing") && domain_lower.contains("phish") {
                LocalDecision::InspectMitm {
                    category: "phishing".to_string(),
                }
            } else {
                LocalDecision::Allow
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluates_sni_deny_wildcard_and_exact() {
        let policy = LocalPolicy::default();
        assert!(matches!(
            evaluate_domain(&policy, "sub.evil.com"),
            LocalDecision::Deny { .. }
        ));
        assert!(matches!(
            evaluate_domain(&policy, "badsite.test"),
            LocalDecision::Deny { .. }
        ));
        assert_eq!(evaluate_domain(&policy, "google.com"), LocalDecision::Allow);
    }

    #[test]
    fn evaluates_pinning_exception_suffix() {
        let policy = LocalPolicy::default();
        assert_eq!(
            evaluate_domain(&policy, "hooks.slack.com"),
            LocalDecision::BypassMitm {
                reason: "certificate_pinning_exception".to_string()
            }
        );
        assert_eq!(
            evaluate_domain(&policy, "slack.com"),
            LocalDecision::BypassMitm {
                reason: "certificate_pinning_exception".to_string()
            }
        );
    }

    #[test]
    fn evaluates_selective_mitm_phishing_heuristic() {
        let policy = LocalPolicy::default();
        assert_eq!(
            evaluate_domain(&policy, "login-phish.example"),
            LocalDecision::InspectMitm {
                category: "phishing".to_string()
            }
        );
    }

    #[test]
    fn maps_remote_policy_with_sni_rules() {
        let dto = RemotePolicyDto {
            policy_version: "v0.1.0".into(),
            policy_mode: "sni".into(),
            mitm_categories: vec!["malware".into()],
            pinning_exceptions: vec![".zoom.us".into()],
            sni_deny_patterns: vec![],
            sni_rules: vec![SniRuleDto {
                pattern: "*.bad.example".into(),
                action: "deny".into(),
            }],
        };
        let policy = LocalPolicy::from_remote(dto);
        assert_eq!(policy.policy_version, "v0.1.0");
        assert_eq!(policy.policy_mode, "sni");
        assert!(policy.sni_deny_patterns.contains(&"*.bad.example".into()));
        assert!(policy.pinning_exceptions.contains(".zoom.us"));
        assert_eq!(
            evaluate_domain(&policy, "x.bad.example"),
            LocalDecision::Deny {
                reason: "SNI pattern match: *.bad.example".into()
            }
        );
        assert_eq!(
            evaluate_domain(&policy, "phish-test.com"),
            LocalDecision::Allow
        );
    }

    #[test]
    fn prefers_flat_sni_deny_patterns_over_rules() {
        let dto = RemotePolicyDto {
            policy_version: "v9".into(),
            policy_mode: "selective-mitm".into(),
            mitm_categories: vec![],
            pinning_exceptions: vec![],
            sni_deny_patterns: vec!["only.flat".into()],
            sni_rules: vec![SniRuleDto {
                pattern: "from.rules".into(),
                action: "deny".into(),
            }],
        };
        let policy = LocalPolicy::from_remote(dto);
        assert_eq!(policy.sni_deny_patterns, vec!["only.flat".to_string()]);
    }
}
