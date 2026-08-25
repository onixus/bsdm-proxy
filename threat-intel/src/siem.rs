//! TASK-TI-030: Enterprise SIEM Integration.
//!
//! Provides formatting and export of threat intelligence detections and IOC lifecycle
//! events into industry-standard SIEM formats:
//! - CEF (Common Event Format - ArcSight / QRadar / Sentinel / Splunk)
//! - ECS (Elastic Common Schema JSON - Elastic Security / Wazuh)
//! - Syslog RFC 5424 formatted messages

use crate::indicator::IndicatorKind;
use crate::storage::StoredIndicator;
use chrono::Utc;
use serde::{Deserialize, Serialize};

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SiemEventAction {
    Detected,
    Blocked,
    Unblocked,
    Expired,
}

#[allow(dead_code)]
impl SiemEventAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            SiemEventAction::Detected => "ioc_detected",
            SiemEventAction::Blocked => "ioc_blocked",
            SiemEventAction::Unblocked => "ioc_unblocked",
            SiemEventAction::Expired => "ioc_expired",
        }
    }
}

/// Structured SIEM event payload.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemEvent {
    pub timestamp: chrono::DateTime<Utc>,
    pub action: SiemEventAction,
    pub indicator_value: String,
    pub indicator_kind: IndicatorKind,
    pub domain: Option<String>,
    pub confidence_score: u8,
    pub source: String,
    pub severity: u8, // 1..10 scale for CEF
    pub message: String,
    pub tags: Vec<String>,
}

#[allow(dead_code)]
impl SiemEvent {
    pub fn from_stored(indicator: &StoredIndicator, action: SiemEventAction) -> Self {
        let severity = ((indicator.confidence_score as f32 / 10.0).round() as u8).clamp(1, 10);
        let message = format!(
            "Threat IOC [{}] from feed [{}] with confidence {}/100",
            indicator.normalized_value, indicator.source, indicator.confidence_score
        );

        Self {
            timestamp: Utc::now(),
            action,
            indicator_value: indicator.normalized_value.clone(),
            indicator_kind: indicator.kind,
            domain: indicator.domain.clone(),
            confidence_score: indicator.confidence_score,
            source: indicator.source.clone(),
            severity,
            message,
            tags: indicator.tags.clone(),
        }
    }

    /// Formats the event into Common Event Format (CEF) string:
    /// `CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]`
    pub fn to_cef(&self) -> String {
        let tags_str = self.tags.join(",");
        let mut extensions = vec![
            format!("act={}", self.action.as_str()),
            format!("cs1={}", self.source),
            "cs1Label=ThreatSource".to_string(),
            format!("cn1={}", self.confidence_score),
            "cn1Label=ConfidenceScore".to_string(),
            format!("msg={}", escape_cef_extension(&self.message)),
        ];

        match self.indicator_kind {
            IndicatorKind::Url => {
                extensions.push(format!(
                    "request={}",
                    escape_cef_extension(&self.indicator_value)
                ));
            }
            IndicatorKind::Domain => {
                extensions.push(format!(
                    "dhost={}",
                    escape_cef_extension(&self.indicator_value)
                ));
            }
            IndicatorKind::Ip => {
                extensions.push(format!("dst={}", self.indicator_value));
            }
        }

        if let Some(domain) = &self.domain {
            extensions.push(format!("shost={}", escape_cef_extension(domain)));
        }
        if !tags_str.is_empty() {
            extensions.push(format!("cs2={}", escape_cef_extension(&tags_str)));
            extensions.push("cs2Label=Tags".to_string());
        }

        format!(
            "CEF:0|BSDM-Proxy|ThreatIntel|0.9.13|{}|{}|{}|{}",
            self.action.as_str().to_uppercase(),
            escape_cef_header(&self.message),
            self.severity,
            extensions.join(" ")
        )
    }

    /// Formats the event into Elastic Common Schema (ECS) JSON format.
    pub fn to_ecs_json(&self) -> serde_json::Value {
        serde_json::json!({
            "@timestamp": self.timestamp.to_rfc3339(),
            "event": {
                "kind": "alert",
                "category": ["threat", "network"],
                "type": ["indicator"],
                "action": self.action.as_str(),
                "severity": self.severity * 10, // 0..100 in ECS
                "dataset": "threat_intel"
            },
            "threat": {
                "indicator": {
                    "type": self.indicator_kind.as_str(),
                    "value": self.indicator_value,
                    "confidence": self.confidence_score,
                    "provider": self.source,
                    "description": self.message
                }
            },
            "rule": {
                "name": "BSDM Threat Intelligence Feed",
                "ruleset": "bsdm_threat_intel"
            },
            "tags": self.tags
        })
    }

    /// Formats the event into RFC 5424 Syslog line.
    pub fn to_syslog_rfc5424(&self, hostname: &str) -> String {
        let ts = self.timestamp.to_rfc3339();
        let cef = self.to_cef();
        // PRI 134 = Facility local0 (16) * 8 + Severity Info (6)
        format!("<134>1 {} {} bsdm-threat-intel - - - {}", ts, hostname, cef)
    }
}

#[allow(dead_code)]
fn escape_cef_header(s: &str) -> String {
    s.replace('\\', "\\\\").replace('|', "\\|")
}

#[allow(dead_code)]
fn escape_cef_extension(s: &str) -> String {
    s.replace('\\', "\\\\").replace('=', "\\=")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_indicator() -> StoredIndicator {
        StoredIndicator {
            id: 1,
            value: "http://phish-bank.com/login".into(),
            normalized_value: "http://phish-bank.com/login".into(),
            domain: Some("phish-bank.com".into()),
            kind: IndicatorKind::Url,
            source: "openphish".into(),
            source_weight: 90,
            confidence_score: 95,
            collected_at: Utc::now(),
            reported_at: None,
            expires_at: Utc::now() + chrono::Duration::days(7),
            reference: Some("REF-123".into()),
            tags: vec!["phishing".into(), "banking".into()],
            is_bogon: false,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            hit_count: 3,
        }
    }

    #[test]
    fn test_cef_formatting() {
        let ind = sample_indicator();
        let event = SiemEvent::from_stored(&ind, SiemEventAction::Detected);
        let cef = event.to_cef();

        assert!(cef.starts_with("CEF:0|BSDM-Proxy|ThreatIntel|0.9.13|IOC_DETECTED|"));
        assert!(cef.contains("cs1=openphish"));
        assert!(cef.contains("cn1=95"));
        assert!(cef.contains("request=http://phish-bank.com/login"));
        assert!(cef.contains("shost=phish-bank.com"));
    }

    #[test]
    fn test_ecs_formatting() {
        let ind = sample_indicator();
        let event = SiemEvent::from_stored(&ind, SiemEventAction::Blocked);
        let ecs = event.to_ecs_json();

        assert_eq!(ecs["event"]["action"], "ioc_blocked");
        assert_eq!(ecs["threat"]["indicator"]["type"], "url");
        assert_eq!(ecs["threat"]["indicator"]["confidence"], 95);
        assert_eq!(ecs["threat"]["indicator"]["provider"], "openphish");
    }

    #[test]
    fn test_syslog_rfc5424() {
        let ind = sample_indicator();
        let event = SiemEvent::from_stored(&ind, SiemEventAction::Detected);
        let syslog = event.to_syslog_rfc5424("proxy-node-01");

        assert!(syslog.starts_with("<134>1 "));
        assert!(syslog.contains("proxy-node-01 bsdm-threat-intel"));
        assert!(syslog.contains("CEF:0|BSDM-Proxy|ThreatIntel|"));
    }
}
