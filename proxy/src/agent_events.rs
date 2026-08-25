//! Agent telemetry batch ingest (Agent Contract v0.1 `POST /api/v1/agent/events`).
//!
//! Lab path: validate → metrics (`local-agent`) → optional Kafka/HTTP pipeline
//! → bounded recent ring for smoke/debug.

use crate::metrics::Metrics;
#[cfg(feature = "kafka")]
use crate::pipeline::KafkaEventPipeline;
use crate::pipeline::{new_event_id, CacheEvent, HttpEventPipeline};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;

pub const MAX_BATCH: usize = 100;
pub const MAX_RECENT: usize = 200;

/// One local-policy decision from an on-device agent.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct AgentEventItem {
    pub domain: String,
    /// `allow` | `deny` | `bypass` | `inspect`
    pub action: String,
    #[serde(default)]
    pub decision_source: Option<String>,
    #[serde(default)]
    pub timestamp: Option<u64>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub policy_version: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentEventBatch {
    pub device_id: String,
    #[serde(default)]
    pub events: Vec<AgentEventItem>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecentAgentEvent {
    pub device_id: String,
    pub domain: String,
    pub action: String,
    pub decision_source: String,
    pub timestamp: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<String>,
    pub event_id: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum BatchError {
    EmptyDeviceId,
    EmptyBatch,
    BatchTooLarge { got: usize },
    InvalidEvent { index: usize, message: String },
}

impl BatchError {
    pub fn message(&self) -> String {
        match self {
            BatchError::EmptyDeviceId => "device_id must not be empty".into(),
            BatchError::EmptyBatch => "events must not be empty".into(),
            BatchError::BatchTooLarge { got } => {
                format!("events batch too large ({got} > {MAX_BATCH})")
            }
            BatchError::InvalidEvent { index, message } => {
                format!("events[{index}]: {message}")
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct IngestReport {
    pub accepted: usize,
    pub enqueued: usize,
}

/// Bounded recent buffer + optional pipeline handles.
#[derive(Clone)]
pub struct AgentEventIngestor {
    recent: Arc<RwLock<VecDeque<RecentAgentEvent>>>,
    #[cfg(feature = "kafka")]
    kafka: Option<Arc<KafkaEventPipeline>>,
    http: Option<Arc<HttpEventPipeline>>,
}

impl Default for AgentEventIngestor {
    fn default() -> Self {
        Self::memory_only()
    }
}

impl AgentEventIngestor {
    pub fn memory_only() -> Self {
        Self {
            recent: Arc::new(RwLock::new(VecDeque::with_capacity(MAX_RECENT))),
            #[cfg(feature = "kafka")]
            kafka: None,
            http: None,
        }
    }

    pub fn with_pipelines(
        #[cfg(feature = "kafka")] kafka: Option<Arc<KafkaEventPipeline>>,
        http: Option<Arc<HttpEventPipeline>>,
    ) -> Self {
        Self {
            recent: Arc::new(RwLock::new(VecDeque::with_capacity(MAX_RECENT))),
            #[cfg(feature = "kafka")]
            kafka,
            http,
        }
    }

    pub fn recent_snapshot(&self, limit: usize) -> Vec<RecentAgentEvent> {
        let limit = limit.clamp(1, MAX_RECENT);
        let recent = self.recent.read().expect("agent events buffer lock");
        recent.iter().take(limit).cloned().collect()
    }

    /// Validate and ingest a batch. Returns accepted count and how many were
    /// handed to Kafka/HTTP (0 when no pipeline).
    pub fn ingest(
        &self,
        batch: AgentEventBatch,
        metrics: &Metrics,
    ) -> Result<IngestReport, BatchError> {
        validate_batch(&batch)?;
        let device_id = batch.device_id.trim().to_string();
        let accepted = batch.events.len();
        let mut enqueued = 0usize;

        for item in batch.events {
            let (cache_event, recent) = to_events(&device_id, &item);
            metrics.record_policy_decision_source(recent.decision_source.as_str());
            info!(
                device_id = %recent.device_id,
                domain = %recent.domain,
                action = %recent.action,
                decision_source = %recent.decision_source,
                reason = ?recent.reason,
                "Agent local-policy event ingested"
            );

            let pipeline_ok = self.try_enqueue(cache_event, metrics);
            if pipeline_ok {
                enqueued += 1;
            }
            self.push_recent(recent);
        }

        Ok(IngestReport { accepted, enqueued })
    }

    fn try_enqueue(&self, event: CacheEvent, metrics: &Metrics) -> bool {
        #[cfg(feature = "kafka")]
        if let Some(kafka) = &self.kafka {
            kafka.try_enqueue(event, metrics);
            return true;
        }
        if let Some(http) = &self.http {
            http.try_enqueue(event, metrics);
            return true;
        }
        false
    }

    fn push_recent(&self, event: RecentAgentEvent) {
        let mut recent = self.recent.write().expect("agent events buffer lock");
        if recent.len() >= MAX_RECENT {
            recent.pop_back();
        }
        recent.push_front(event);
    }
}

pub fn validate_batch(batch: &AgentEventBatch) -> Result<(), BatchError> {
    if batch.device_id.trim().is_empty() {
        return Err(BatchError::EmptyDeviceId);
    }
    if batch.events.is_empty() {
        return Err(BatchError::EmptyBatch);
    }
    if batch.events.len() > MAX_BATCH {
        return Err(BatchError::BatchTooLarge {
            got: batch.events.len(),
        });
    }
    for (index, item) in batch.events.iter().enumerate() {
        if item.domain.trim().is_empty() {
            return Err(BatchError::InvalidEvent {
                index,
                message: "domain must not be empty".into(),
            });
        }
        if item.domain.len() > 253 {
            return Err(BatchError::InvalidEvent {
                index,
                message: "domain too long".into(),
            });
        }
        let action = item.action.to_ascii_lowercase();
        if !matches!(action.as_str(), "allow" | "deny" | "bypass" | "inspect") {
            return Err(BatchError::InvalidEvent {
                index,
                message: "action must be allow|deny|bypass|inspect".into(),
            });
        }
        if let Some(src) = &item.decision_source {
            let s = src.to_ascii_lowercase();
            if !matches!(
                s.as_str(),
                "local-agent" | "dns" | "sni" | "mitm" | "pinning-bypass"
            ) {
                return Err(BatchError::InvalidEvent {
                    index,
                    message: "unsupported decision_source".into(),
                });
            }
        }
    }
    Ok(())
}

fn normalize_action(action: &str) -> String {
    action.to_ascii_lowercase()
}

fn normalize_source(src: Option<&str>) -> String {
    match src.map(|s| s.to_ascii_lowercase()) {
        Some(s) if !s.is_empty() => s,
        _ => "local-agent".into(),
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn action_to_status_and_acl(action: &str) -> (u16, Option<String>, Option<String>) {
    match action {
        "deny" => (403, Some("deny".into()), Some("agent local deny".into())),
        "bypass" => (200, None, None),
        "inspect" => (200, None, None),
        _ => (200, None, None),
    }
}

pub fn to_events(device_id: &str, item: &AgentEventItem) -> (CacheEvent, RecentAgentEvent) {
    let action = normalize_action(&item.action);
    let decision_source = normalize_source(item.decision_source.as_deref());
    let timestamp = item.timestamp.filter(|t| *t > 0).unwrap_or_else(unix_now);
    let domain = item.domain.trim().to_ascii_lowercase();
    let event_id = new_event_id();
    let (status, acl_action, acl_reason) = action_to_status_and_acl(&action);
    let bypass_reason = if action == "bypass" {
        item.reason.clone().or_else(|| Some("agent_bypass".into()))
    } else {
        None
    };
    let url = format!("https://{domain}/");
    let cache_event = CacheEvent {
        url: url.clone(),
        method: "CONNECT".into(),
        status,
        cache_key: format!("agent:{device_id}:{domain}:{timestamp}"),
        cache_status: "AGENT".into(),
        timestamp,
        headers: Default::default(),
        user_id: None,
        username: None,
        client_ip: device_id.to_string(),
        domain: domain.clone(),
        response_size: 0,
        request_duration_ms: 0,
        content_type: None,
        user_agent: Some(format!("bsdm-agent/{device_id}")),
        categories: vec![],
        threat_sources: vec![],
        acl_action,
        acl_rule_id: item.policy_version.clone(),
        acl_reason: item.reason.clone().or(acl_reason),
        session_id: format!("agent:{device_id}"),
        parent_event_id: None,
        redirect_url: None,
        dlp_violation: None,
        casb_alert: None,
        decision_source: Some(decision_source.clone()),
        bypass_reason,
        threat_shadow_match: None,
        event_id: event_id.clone(),
    };
    let recent = RecentAgentEvent {
        device_id: device_id.to_string(),
        domain,
        action,
        decision_source,
        timestamp,
        reason: item.reason.clone(),
        policy_version: item.policy_version.clone(),
        event_id,
    };
    (cache_event, recent)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_batch() -> AgentEventBatch {
        AgentEventBatch {
            device_id: "dev-1".into(),
            events: vec![
                AgentEventItem {
                    domain: "badsite.test".into(),
                    action: "deny".into(),
                    decision_source: Some("local-agent".into()),
                    timestamp: Some(1_700_000_000),
                    reason: Some("SNI exact match".into()),
                    policy_version: Some("v0.1.0".into()),
                },
                AgentEventItem {
                    domain: "slack.com".into(),
                    action: "bypass".into(),
                    decision_source: None,
                    timestamp: None,
                    reason: Some("certificate_pinning_exception".into()),
                    policy_version: None,
                },
            ],
        }
    }

    #[test]
    fn validates_and_ingests_memory_only() {
        let metrics = Metrics::new().unwrap();
        let ingestor = AgentEventIngestor::memory_only();
        let report = ingestor.ingest(sample_batch(), &metrics).unwrap();
        assert_eq!(report.accepted, 2);
        assert_eq!(report.enqueued, 0);
        let recent = ingestor.recent_snapshot(10);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].domain, "slack.com"); // last pushed is front
        assert_eq!(recent[1].domain, "badsite.test");
        assert_eq!(recent[1].action, "deny");
    }

    #[test]
    fn rejects_bad_action() {
        let batch = AgentEventBatch {
            device_id: "d".into(),
            events: vec![AgentEventItem {
                domain: "x.test".into(),
                action: "drop".into(),
                decision_source: None,
                timestamp: None,
                reason: None,
                policy_version: None,
            }],
        };
        assert!(matches!(
            validate_batch(&batch),
            Err(BatchError::InvalidEvent { .. })
        ));
    }

    #[test]
    fn maps_to_cache_event() {
        let item = &sample_batch().events[0];
        let (ev, recent) = to_events("dev-1", item);
        assert_eq!(ev.decision_source.as_deref(), Some("local-agent"));
        assert_eq!(ev.domain, "badsite.test");
        assert_eq!(ev.status, 403);
        assert_eq!(recent.action, "deny");
        assert!(!ev.event_id.is_empty());
    }
}
