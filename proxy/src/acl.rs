//! Access Control List (ACL) module
//!
//! Provides flexible access control with multiple rule types:
//! - Domain-based rules
//! - URL pattern matching
//! - Regex-based rules
//! - Category-based filtering
//! - Time-based access control
//! - User/group-based rules

use chrono::Timelike;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use tracing::{debug, info, warn};

/// Minutes since midnight for time-window matching (0–1439).
pub(crate) fn minutes_since_midnight(hour: u32, minute: u32) -> u32 {
    hour * 60 + minute
}

/// Parse `HH:MM` (24h) into minutes since midnight.
pub(crate) fn parse_hhmm(value: &str) -> Option<u32> {
    let (hour, minute) = value.split_once(':')?;
    let hour: u32 = hour.trim().parse().ok()?;
    let minute: u32 = minute.trim().parse().ok()?;
    if hour > 23 || minute > 59 {
        return None;
    }
    Some(minutes_since_midnight(hour, minute))
}

/// Whether `now` (minutes since midnight) falls in `[start, end]` (supports overnight windows).
pub(crate) fn time_in_window(start: &str, end: &str, now: u32) -> bool {
    let Some(start_min) = parse_hhmm(start) else {
        warn!("Invalid TimeWindow start: {}", start);
        return false;
    };
    let Some(end_min) = parse_hhmm(end) else {
        warn!("Invalid TimeWindow end: {}", end);
        return false;
    };

    if start_min <= end_min {
        now >= start_min && now <= end_min
    } else {
        now >= start_min || now <= end_min
    }
}

fn local_minutes_now() -> u32 {
    let now = chrono::Local::now();
    minutes_since_midnight(now.hour(), now.minute())
}

/// Match LDAP `memberOf` DN or plain group name against rule group.
pub(crate) fn group_matches(member_group: &str, rule_group: &str) -> bool {
    if member_group.eq_ignore_ascii_case(rule_group) {
        return true;
    }
    for part in member_group.split(',') {
        let part = part.trim();
        if let Some(cn) = part
            .strip_prefix("cn=")
            .or_else(|| part.strip_prefix("CN="))
        {
            if cn.eq_ignore_ascii_case(rule_group) {
                return true;
            }
        }
    }
    false
}

/// ACL action to take
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
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
    Principal {
        user: Option<String>,
        group: Option<String>,
    },
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
        info!(
            "ACL engine initialized with default action: {}",
            default_action
        );
        Self {
            rules: Vec::new(),
            default_action,
            regex_cache: HashMap::new(),
        }
    }

    /// Add ACL rule
    pub fn add_rule(&mut self, rule: AclRule) {
        info!(
            "Adding ACL rule: {} (priority: {})",
            rule.name, rule.priority
        );
        self.rules.push(rule);
        self.rules.sort_by_key(|b| std::cmp::Reverse(b.priority));
    }

    /// Load rules from configuration
    pub fn load_rules(&mut self, rules: Vec<AclRule>) {
        info!("Loading {} ACL rules", rules.len());
        self.rules = rules;
        self.rules.sort_by_key(|b| std::cmp::Reverse(b.priority));
    }

    /// Check if request is allowed
    pub fn check_access(
        &mut self,
        url: &str,
        domain: &str,
        categories: &[&str],
        user: Option<&str>,
        groups: &[&str],
        client_ip: Option<IpAddr>,
    ) -> AclDecision {
        debug!(
            "ACL check: url={}, domain={}, categories={:?}, user={:?}, groups={:?}",
            url, domain, categories, user, groups
        );

        // Check each rule in priority order
        let rules: Vec<AclRule> = self
            .rules
            .iter()
            .filter(|rule| rule.enabled)
            .cloned()
            .collect();

        for rule in rules {
            if self.matches_rule(&rule, url, domain, categories, user, groups, client_ip) {
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
            AclAction::Deny => AclDecision::deny("default".to_string(), "Default policy: deny"),
            AclAction::Redirect => AclDecision::redirect(
                "default".to_string(),
                "about:blank".to_string(),
                "Default policy: redirect",
            ),
        }
    }

    /// Check if rule matches
    #[allow(clippy::too_many_arguments)]
    fn matches_rule(
        &mut self,
        rule: &AclRule,
        url: &str,
        domain: &str,
        categories: &[&str],
        user: Option<&str>,
        groups: &[&str],
        client_ip: Option<IpAddr>,
    ) -> bool {
        match &rule.rule_type {
            AclRuleType::Domain(pattern) => self.match_domain(domain, pattern),
            AclRuleType::UrlPrefix(prefix) => url.starts_with(prefix),
            AclRuleType::Regex(pattern) => self.match_regex(url, pattern),
            AclRuleType::Category(cat) => categories.iter().any(|c| *c == cat),
            AclRuleType::IpRange { start, end } => {
                if let Some(ip) = client_ip {
                    self.ip_in_range(ip, *start, *end)
                } else {
                    false
                }
            }
            AclRuleType::TimeWindow { start, end } => {
                time_in_window(start, end, local_minutes_now())
            }
            AclRuleType::Principal {
                user: rule_user,
                group: rule_group,
            } => Self::match_principal(rule_user, rule_group, user, groups),
        }
    }

    fn match_principal(
        rule_user: &Option<String>,
        rule_group: &Option<String>,
        user: Option<&str>,
        groups: &[&str],
    ) -> bool {
        let user_match = rule_user.as_ref().zip(user).is_some_and(|(ru, u)| ru == u);

        let group_match = rule_group
            .as_ref()
            .is_some_and(|rg| groups.iter().any(|g| group_matches(g, rg)));

        match (rule_user.is_some(), rule_group.is_some()) {
            (true, true) => user_match || group_match,
            (true, false) => user_match,
            (false, true) => group_match,
            (false, false) => false,
        }
    }

    /// Match domain pattern (supports wildcards)
    fn match_domain(&self, domain: &str, pattern: &str) -> bool {
        if let Some(suffix) = pattern.strip_prefix("*.") {
            // Wildcard subdomain match
            domain.ends_with(suffix) || domain == suffix
        } else if let Some(suffix) = pattern.strip_prefix('*') {
            // Wildcard suffix match
            domain.ends_with(suffix)
        } else {
            // Exact match
            domain == pattern
        }
    }

    /// Match regex pattern
    fn match_regex(&mut self, text: &str, pattern: &str) -> bool {
        let regex = self
            .regex_cache
            .entry(pattern.to_string())
            .or_insert_with(|| {
                Regex::new(pattern).unwrap_or_else(|e| {
                    warn!("Invalid regex pattern '{}': {}", pattern, e);
                    #[allow(clippy::invalid_regex)]
                    Regex::new("(?!)").expect("Failed to create never-matching regex")
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
        let engine = AclEngine::new(AclAction::Allow);

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
            &[],
            None,
            &[],
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
            &["adult"],
            None,
            &[],
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
            &[],
            None,
            &[],
            None,
        );

        assert_eq!(decision.action, AclAction::Deny);
        assert_eq!(decision.rule_id.unwrap(), "high");
    }

    #[test]
    fn test_time_window_matching() {
        assert!(time_in_window(
            "09:00",
            "17:00",
            minutes_since_midnight(12, 0)
        ));
        assert!(!time_in_window(
            "09:00",
            "17:00",
            minutes_since_midnight(8, 59)
        ));
        assert!(time_in_window(
            "09:00",
            "17:00",
            minutes_since_midnight(17, 0)
        ));
        assert!(time_in_window(
            "22:00",
            "06:00",
            minutes_since_midnight(23, 0)
        ));
        assert!(time_in_window(
            "22:00",
            "06:00",
            minutes_since_midnight(5, 30)
        ));
        assert!(!time_in_window(
            "22:00",
            "06:00",
            minutes_since_midnight(12, 0)
        ));
    }

    #[test]
    fn test_group_matching_ldap_cn() {
        assert!(group_matches(
            "cn=admins,ou=groups,dc=example,dc=com",
            "admins"
        ));
        assert!(group_matches("admins", "admins"));
        assert!(!group_matches(
            "cn=users,ou=groups,dc=example,dc=com",
            "admins"
        ));
    }

    #[test]
    fn test_principal_group_rule() {
        let mut engine = AclEngine::new(AclAction::Deny);

        engine.add_rule(AclRule {
            id: "admins-allow".to_string(),
            name: "Allow admins".to_string(),
            enabled: true,
            priority: 200,
            action: AclAction::Allow,
            rule_type: AclRuleType::Principal {
                user: None,
                group: Some("admins".to_string()),
            },
            redirect_url: None,
            comment: None,
        });

        let decision = engine.check_access(
            "https://example.com",
            "example.com",
            &[],
            Some("alice"),
            &["cn=admins,ou=groups,dc=corp,dc=local"],
            None,
        );
        assert_eq!(decision.action, AclAction::Allow);

        let decision = engine.check_access(
            "https://example.com",
            "example.com",
            &[],
            Some("bob"),
            &["cn=users,ou=groups,dc=corp,dc=local"],
            None,
        );
        assert_eq!(decision.action, AclAction::Deny);
    }

    #[test]
    fn test_principal_user_rule() {
        let mut engine = AclEngine::new(AclAction::Deny);

        engine.add_rule(AclRule {
            id: "alice-allow".to_string(),
            name: "Allow alice".to_string(),
            enabled: true,
            priority: 100,
            action: AclAction::Allow,
            rule_type: AclRuleType::Principal {
                user: Some("alice".to_string()),
                group: None,
            },
            redirect_url: None,
            comment: None,
        });

        let decision = engine.check_access(
            "https://example.com",
            "example.com",
            &[],
            Some("alice"),
            &[],
            None,
        );
        assert_eq!(decision.action, AclAction::Allow);
    }
}
