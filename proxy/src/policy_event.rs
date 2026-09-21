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

pub struct PolicyEventContext<'a> {
    pub url: &'a str,
    pub method: &'a str,
    pub cache_key: &'a str,
    pub user_id: &'a Option<String>,
    pub username: &'a Option<String>,
    pub user_agent: Option<&'a str>,
    pub client_ip: &'a str,
    pub domain: &'a str,
    pub request_start: Instant,
    pub decision_source: &'a str,
}

#[inline]
pub fn effective_decision_source<'a>(
    decision: &AclDecision,
    fallback: &'a str,
) -> &'a str {
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

pub fn build_policy_event(
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
