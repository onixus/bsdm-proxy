//! SIEM-friendly webhook JSON envelope.

use chrono::{DateTime, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AlertPayload {
    pub version: u8,
    pub source: String,
    pub alert_id: String,
    pub rule: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub fired_at: String,
    pub window_secs: u64,
    pub value: f64,
    pub labels: BTreeMap<String, String>,
    pub fingerprint: String,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub rule: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub value: f64,
    pub labels: BTreeMap<String, String>,
}

impl Finding {
    pub fn fingerprint(&self) -> String {
        fingerprint_for(&self.rule, &self.labels)
    }

    pub fn into_payload(
        self,
        source: &str,
        window_secs: u64,
        fired_at: DateTime<Utc>,
    ) -> AlertPayload {
        let fingerprint = self.fingerprint();
        AlertPayload {
            version: 1,
            source: source.to_string(),
            alert_id: uuid::Uuid::new_v4().to_string(),
            rule: self.rule,
            severity: self.severity,
            title: self.title,
            description: self.description,
            fired_at: fired_at.to_rfc3339(),
            window_secs,
            value: self.value,
            labels: self.labels,
            fingerprint,
        }
    }
}

pub fn fingerprint_for(rule: &str, labels: &BTreeMap<String, String>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(rule.as_bytes());
    hasher.update(b"|");
    for (k, v) in labels {
        hasher.update(k.as_bytes());
        hasher.update(b"=");
        hasher.update(v.as_bytes());
        hasher.update(b";");
    }
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_stable() {
        let mut labels = BTreeMap::new();
        labels.insert("client_ip".into(), "10.0.0.1".into());
        labels.insert("username".into(), "alice".into());
        let a = fingerprint_for("blocked_burst", &labels);
        let b = fingerprint_for("blocked_burst", &labels);
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn payload_serializes() {
        let mut labels = BTreeMap::new();
        labels.insert("domain".into(), "evil.example".into());
        let finding = Finding {
            rule: "domain_burst".into(),
            severity: "warning".into(),
            title: "burst".into(),
            description: "too many".into(),
            value: 99.0,
            labels,
        };
        let payload = finding.into_payload("test", 300, Utc::now());
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"version\":1"));
        assert!(json.contains("domain_burst"));
    }
}
