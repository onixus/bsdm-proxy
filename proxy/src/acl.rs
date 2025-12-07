//! Access Control List (ACL) module
//!
//! Provides flexible access control with multiple rule types:
//! - Domain-based rules
//! - URL pattern matching
//! - Regex-based rules
//! - Category-based filtering
//! - Time-based access control
//! - User/group-based rules

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// ACL action to take
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AclAction {
    /// Allow the request
    Allow,
    /// Deny the request
    Deny,
    /// Redirect to another URL
    Redirect,
}

impl std::fmt::Display for AclAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AclAction::Allow => write!(f, "allow"),
            AclAction::Deny => write!(f, "deny"),
            AclAction::Redirect => write!(f, "redirect"),
        }
    }
}

/// ACL rule type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AclRuleType {
    /// Exact domain match
    Domain(String),
    /// URL prefix match
    UrlPrefix(String),
    /// Regex pattern
    Regex(String),
    /// Category-based
    Category(String),
    /// IP address range
    IpRange { start: IpAddr, end: IpAddr },
    /// Time-based (cron-like)
    TimeWindow { start: String, end: String },
    /// User or group
    Principal { user: Option<String>, group: Option<String> },
}

/// ACL rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclRule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub priority: u32,
    pub action: AclAction,
    pub rule_type: AclRuleType,
    pub redirect_url: Option<String>,
    pub comment: Option<String>,
}

/// ACL decision result
#[derive(Debug, Clone)]
pub struct AclDecision {
    pub action: AclAction,
    pub rule_id: Option<String>,
    pub redirect_url: Option<String>,
    pub reason: String,
}

impl AclDecision {
    pub fn allow(reason: impl Into<String>) -> Self {
        Self {
            action: AclAction::Allow,
            rule_id: None,
            redirect_url: None,
            reason: reason.into(),
        }
    }

    pub fn deny(rule_id: String, reason: impl Into<String>) -> Self {
        Self {
            action: AclAction::Deny,
            rule_id: Some(rule_id),
            redirect_url: None,
            reason: reason.into(),
        }
    }

    pub fn redirect(rule_id: String, url: String, reason: impl Into<String>) -> Self {
        Self {
            action: AclAction::Redirect,
            rule_id: Some(rule_id),
            redirect_url: Some(url),
            reason: reason.into(),
        }
    }
}

/// ACL engine
pub struct AclEngine {
    rules: Vec<AclRule>,
    default_action: AclAction,
    regex_cache: HashMap<String, Regex>,
}

impl AclEngine {
    pub fn new(default_action: AclAction) -> Self {
        info!("ACL engine initialized with default action: {}", default_action);
        Self {
            rules: Vec::new(),
            default_action,
            regex_cache: HashMap::new(),
        }
    }

    /// Add ACL rule
    pub fn add_rule(&mut self, rule: AclRule) {
        info!("Adding ACL rule: {} (priority: {})", rule.name, rule.priority);
        self.rules.push(rule);
        self.rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Load rules from configuration
    pub fn load_rules(&mut self, rules: Vec<AclRule>) {
        info!("Loading {} ACL rules", rules.len());
        self.rules = rules;
        self.rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Check if request is allowed
    pub fn check_access(
        &mut self,
        url: &str,
        domain: &str,
        category: Option<&str>,
        user: Option<&str>,
        client_ip: Option<IpAddr>,
    ) -> AclDecision {
        debug!("ACL check: url={}, domain={}, category={:?}, user={:?}", 
               url, domain, category, user);

        // Check each rule in priority order
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            if self.matches_rule(rule, url, domain, category, user, client_ip) {
                debug!("Matched ACL rule: {} ({})", rule.name, rule.id);
                
                return match rule.action {
                    AclAction::Allow => AclDecision::allow(format!("Rule: {}", rule.name)),
                    AclAction::Deny => AclDecision::deny(
                        rule.id.clone(),
                        format!("Blocked by rule: {}", rule.name),
                    ),
                    AclAction::Redirect => AclDecision::redirect(
                        rule.id.clone(),
                        rule.redirect_url.clone().unwrap_or_default(),
                        format!("Redirected by rule: {}", rule.name),
                    ),
                };
            }
        }

        // No rules matched, use default action
        match self.default_action {
            AclAction::Allow => AclDecision::allow("Default policy: allow"),
            AclAction::Deny => AclDecision::deny(
                "default".to_string(),
                "Default policy: deny",
            ),
            AclAction::Redirect => AclDecision::redirect(
                "default".to_string(),
                "about:blank".to_string(),
                "Default policy: redirect",
            ),
        }
    }

    /// Check if rule matches
    fn matches_rule(
        &mut self,
        rule: &AclRule,
        url: &str,
        domain: &str,
        category: Option<&str>,
        user: Option<&str>,
        client_ip: Option<IpAddr>,
    ) -> bool {
        match &rule.rule_type {
            AclRuleType::Domain(pattern) => self.match_domain(domain, pattern),
            AclRuleType::UrlPrefix(prefix) => url.starts_with(prefix),
            AclRuleType::Regex(pattern) => self.match_regex(url, pattern),
            AclRuleType::Category(cat) => {
                category.map(|c| c == cat).unwrap_or(false)
            }
            AclRuleType::IpRange { start, end } => {
                if let Some(ip) = client_ip {
                    self.ip_in_range(ip, *start, *end)
                } else {
                    false
                }
            }
            AclRuleType::TimeWindow { start: _, end: _ } => {
                // TODO: Implement time-based matching
                true
            }
            AclRuleType::Principal { user: rule_user, group: _ } => {
                if let Some(u) = user {
                    rule_user.as_ref().map(|ru| ru == u).unwrap_or(false)
                } else {
                    false
                }
            }
        }
    }

    /// Match domain pattern (supports wildcards)
    fn match_domain(&self, domain: &str, pattern: &str) -> bool {
        if pattern.starts_with("*.") {
            // Wildcard subdomain match
            let suffix = &pattern[2..];
            domain.ends_with(suffix) || domain == suffix
        } else if pattern.starts_with('*') {
            // Wildcard suffix match
            domain.ends_with(&pattern[1..])
        } else {
            // Exact match
            domain == pattern
        }
    }

    /// Match regex pattern
    fn match_regex(&mut self, text: &str, pattern: &str) -> bool {
        let regex = self.regex_cache.entry(pattern.to_string())
            .or_insert_with(|| {
                Regex::new(pattern).unwrap_or_else(|e| {
                    warn!("Invalid regex pattern '{}': {}", pattern, e);
                    Regex::new("(?!)")
                        .expect("Failed to create never-matching regex")
                })
            });
        
        regex.is_match(text)
    }

    /// Check if IP is in range
    fn ip_in_range(&self, ip: IpAddr, start: IpAddr, end: IpAddr) -> bool {
        match (ip, start, end) {
            (IpAddr::V4(ip), IpAddr::V4(start), IpAddr::V4(end)) => {
                let ip_num = u32::from(ip);
                let start_num = u32::from(start);
                let end_num = u32::from(end);
                ip_num >= start_num && ip_num <= end_num
            }
            (IpAddr::V6(ip), IpAddr::V6(start), IpAddr::V6(end)) => {
                let ip_num = u128::from(ip);
                let start_num = u128::from(start);
                let end_num = u128::from(end);
                ip_num >= start_num && ip_num <= end_num
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_matching() {
        let mut engine = AclEngine::new(AclAction::Allow);
        
        // Exact match
        assert!(engine.match_domain("example.com", "example.com"));
        assert!(!engine.match_domain("test.com", "example.com"));
        
        // Wildcard subdomain
        assert!(engine.match_domain("www.example.com", "*.example.com"));
        assert!(engine.match_domain("api.example.com", "*.example.com"));
        assert!(engine.match_domain("example.com", "*.example.com"));
        assert!(!engine.match_domain("example.org", "*.example.com"));
    }

    #[test]
    fn test_url_prefix() {
        let mut engine = AclEngine::new(AclAction::Allow);
        
        engine.add_rule(AclRule {
            id: "test1".to_string(),
            name: "Block admin".to_string(),
            enabled: true,
            priority: 100,
            action: AclAction::Deny,
            rule_type: AclRuleType::UrlPrefix("https://example.com/admin".to_string()),
            redirect_url: None,
            comment: None,
        });
        
        let decision = engine.check_access(
            "https://example.com/admin/users",
            "example.com",
            None,
            None,
            None,
        );
        
        assert_eq!(decision.action, AclAction::Deny);
    }

    #[test]
    fn test_category_based() {
        let mut engine = AclEngine::new(AclAction::Allow);
        
        engine.add_rule(AclRule {
            id: "cat1".to_string(),
            name: "Block adult content".to_string(),
            enabled: true,
            priority: 100,
            action: AclAction::Deny,
            rule_type: AclRuleType::Category("adult".to_string()),
            redirect_url: None,
            comment: None,
        });
        
        let decision = engine.check_access(
            "https://example.com",
            "example.com",
            Some("adult"),
            None,
            None,
        );
        
        assert_eq!(decision.action, AclAction::Deny);
    }

    #[test]
    fn test_priority_ordering() {
        let mut engine = AclEngine::new(AclAction::Deny);
        
        // Lower priority (allow)
        engine.add_rule(AclRule {
            id: "low".to_string(),
            name: "Allow all".to_string(),
            enabled: true,
            priority: 10,
            action: AclAction::Allow,
            rule_type: AclRuleType::Domain("*.example.com".to_string()),
            redirect_url: None,
            comment: None,
        });
        
        // Higher priority (deny)
        engine.add_rule(AclRule {
            id: "high".to_string(),
            name: "Deny admin".to_string(),
            enabled: true,
            priority: 100,
            action: AclAction::Deny,
            rule_type: AclRuleType::Domain("admin.example.com".to_string()),
            redirect_url: None,
            comment: None,
        });
        
        // Should match high priority deny rule
        let decision = engine.check_access(
            "https://admin.example.com",
            "admin.example.com",
            None,
            None,
            None,
        );
        
        assert_eq!(decision.action, AclAction::Deny);
        assert_eq!(decision.rule_id.unwrap(), "high");
    }
}
