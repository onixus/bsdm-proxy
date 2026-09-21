//! Policy-decision analytics event construction.
//!
//! Keeps the data-plane decision result separate from HTTP proxy orchestration.
//! This module only converts a policy decision plus request metadata into the
//! existing analytics event shape.

use crate::acl::{AclAction, AclDecision};
use crate::pipeline::{new_event_id, CacheEvent};
use crate::policy_engine::PolicyEvaluation;
use crate::session::{resolve_location, SessionCorrelator};
use std::collections::HashMap;
use std::time::{Instant, SystemTime};

pub(crate) struct PolicyEventContext<'a> {
    pub(crate) url: &'a str,
    pub(crate) method: &'a str,
    pub(crate) cache_key: &'a str,
    pub(crate) user_id: &'a Option<String>,
    pub(crate) username: &'a Option<String>,
    pub(crate) user_agent: Option<&'a str>,
    pub(crate) client_ip: &'a str,
    pub(crate) domain: &'a str,
    pub(crate) request_start: Instant,
    pub(crate) decision_source: &'a str,
}

#[inline]
pub(crate) fn effective_decision_source<'a>(decision: &AclDecision, fallback: &'a str) -> &'a str {
    if decision
        .rule_id
        .as_ref()
        .is_some_and(|rule_id| rule_id.starts_with("ti:"))
    {
        "threat_intel"
    } else {
        fallback
    }
}

pub(crate) fn build_policy_event(
    sessions: &SessionCorrelator,
    decision: &AclDecision,
    policy: &PolicyEvaluation,
    context: &PolicyEventContext<'_>,
) -> Option<CacheEvent> {
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()?;
    let decision_source = effective_decision_source(decision, context.decision_source);
    let status = match decision.action {
        AclAction::Deny => 403,
        AclAction::Redirect => 302,
        AclAction::Allow => 200,
    };
    let event_id = new_event_id();
    let redirect_url = decision
        .redirect_url
        .as_deref()
        .map(|location| resolve_location(context.url, location));
    let correlation = sessions.begin_request(
        context.client_ip,
        context.username.as_deref(),
        context.user_agent,
        context.url,
    );
    sessions.note_redirect(
        context.client_ip,
        &event_id,
        status,
        context.url,
        redirect_url.as_deref(),
    );

    Some(CacheEvent {
        url: context.url.to_string(),
        method: context.method.to_string(),
        status,
        cache_key: context.cache_key.to_string(),
        cache_status: "BLOCKED".to_string(),
        timestamp: timestamp.as_secs(),
        headers: HashMap::new(),
        user_id: context.user_id.clone(),
        username: context.username.clone(),
        client_ip: context.client_ip.to_string(),
        domain: context.domain.to_string(),
        response_size: 0,
        request_duration_ms: context.request_start.elapsed().as_millis() as u64,
        content_type: None,
        user_agent: context.user_agent.map(str::to_string),
        categories: policy.categories.clone(),
        threat_sources: policy.threat_sources.clone(),
        acl_action: Some(decision.action.to_string()),
        acl_rule_id: decision.rule_id.clone(),
        acl_reason: Some(decision.reason.clone()),
        session_id: correlation.session_id,
        parent_event_id: correlation.parent_event_id,
        redirect_url,
        dlp_violation: None,
        casb_alert: None,
        decision_source: Some(decision_source.to_string()),
        bypass_reason: None,
        threat_shadow_match: None,
        event_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::AclDecision;
    use std::time::Duration;

    fn correlator() -> SessionCorrelator {
        SessionCorrelator::new(Duration::from_secs(60), Duration::from_secs(30), 1000, 1000)
    }

    fn evaluation(decision: AclDecision) -> PolicyEvaluation {
        PolicyEvaluation {
            blocking: Some(decision),
            categories: vec!["malware".to_string()],
            threat_sources: vec!["urlhaus".to_string()],
        }
    }

    fn context<'a>(url: &'a str, user_id: &'a Option<String>) -> PolicyEventContext<'a> {
        PolicyEventContext {
            url,
            method: "GET",
            cache_key: "GET:example",
            user_id,
            username: user_id,
            user_agent: Some("curl/8"),
            client_ip: "10.0.0.1",
            domain: "malware-c2.com",
            request_start: Instant::now(),
            decision_source: "url",
        }
    }

    #[test]
    fn ti_rule_id_overrides_the_fallback_source() {
        let decision = AclDecision::deny("ti:urlhaus".to_string(), "feed match");
        assert_eq!(effective_decision_source(&decision, "url"), "threat_intel");
        assert_eq!(effective_decision_source(&decision, "sni"), "threat_intel");
    }

    #[test]
    fn non_ti_rule_id_keeps_the_fallback_source() {
        let decision = AclDecision::deny("rule-42".to_string(), "blocked by policy");
        assert_eq!(effective_decision_source(&decision, "url"), "url");
        assert_eq!(effective_decision_source(&decision, "sni"), "sni");
    }

    #[test]
    fn missing_rule_id_keeps_the_fallback_source() {
        let decision = AclDecision::allow("default allow");
        assert_eq!(effective_decision_source(&decision, "url"), "url");
    }

    /// Only a `ti:` *prefix* marks a threat-intel block. A rule id that merely
    /// contains the marker must not be relabelled, or an operator-authored rule
    /// would be misattributed to a feed in the analytics pipeline.
    #[test]
    fn ti_marker_must_be_a_prefix_not_a_substring() {
        let decision = AclDecision::deny("corp:anti:urlhaus".to_string(), "local rule");
        assert_eq!(effective_decision_source(&decision, "url"), "url");
    }

    #[test]
    fn deny_builds_a_blocked_event_carrying_policy_metadata() {
        let sessions = correlator();
        let decision = AclDecision::deny("ti:urlhaus".to_string(), "feed match");
        let policy = evaluation(decision.clone());
        let user = Some("alice".to_string());
        let event = build_policy_event(
            &sessions,
            &decision,
            &policy,
            &context("http://malware-c2.com/payload", &user),
        )
        .expect("event is built");

        assert_eq!(event.status, 403);
        assert_eq!(event.cache_status, "BLOCKED");
        assert_eq!(event.response_size, 0);
        assert_eq!(event.acl_action.as_deref(), Some("deny"));
        assert_eq!(event.acl_rule_id.as_deref(), Some("ti:urlhaus"));
        assert_eq!(event.acl_reason.as_deref(), Some("feed match"));
        // The TI prefix must win over the "url" fallback in the context.
        assert_eq!(event.decision_source.as_deref(), Some("threat_intel"));
        // Categories and threat sources come from the evaluation, not the decision.
        assert_eq!(event.categories, vec!["malware".to_string()]);
        assert_eq!(event.threat_sources, vec!["urlhaus".to_string()]);
        assert_eq!(event.username.as_deref(), Some("alice"));
        assert_eq!(event.client_ip, "10.0.0.1");
        assert_eq!(event.domain, "malware-c2.com");
        assert!(event.redirect_url.is_none());
        assert!(!event.event_id.is_empty());
    }

    #[test]
    fn redirect_builds_a_302_with_an_absolute_location() {
        let sessions = correlator();
        let decision = AclDecision::redirect(
            "rule-7".to_string(),
            "/blocked.html".to_string(),
            "coaching page",
        );
        let policy = evaluation(decision.clone());
        let no_user: Option<String> = None;
        let event = build_policy_event(
            &sessions,
            &decision,
            &policy,
            &context("http://malware-c2.com/payload", &no_user),
        )
        .expect("event is built");

        assert_eq!(event.status, 302);
        // A relative Location is resolved against the request URL.
        assert_eq!(
            event.redirect_url.as_deref(),
            Some("http://malware-c2.com/blocked.html")
        );
        assert_eq!(event.decision_source.as_deref(), Some("url"));
    }

    #[test]
    fn allow_builds_a_200_event() {
        let sessions = correlator();
        let decision = AclDecision::allow("explicit allowlist");
        let policy = evaluation(decision.clone());
        let no_user: Option<String> = None;
        let event = build_policy_event(
            &sessions,
            &decision,
            &policy,
            &context("http://malware-c2.com/payload", &no_user),
        )
        .expect("event is built");

        assert_eq!(event.status, 200);
        assert_eq!(event.acl_action.as_deref(), Some("allow"));
        assert!(event.redirect_url.is_none());
    }
}
