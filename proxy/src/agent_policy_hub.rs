//! Agent policy versioning and push (long-poll + SSE).
//!
//! Control plane rebuilds the Agent Contract policy document and notifies
//! subscribers when pinning is reloaded or operators call policy push.

use crate::device_registry::agent_policy_document;
use crate::pinning::PinningRegistry;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static PUSH_SEQ: AtomicU64 = AtomicU64::new(0);
use tokio::sync::Notify;
use tracing::info;

/// Snapshot of the current agent policy payload.
#[derive(Debug, Clone)]
pub struct PolicySnapshot {
    pub version: String,
    pub document: Value,
    pub pushed_at: u64,
    pub reason: String,
}

/// Broadcast hub for policy pull/watch/stream.
#[derive(Clone)]
pub struct PolicyHub {
    state: Arc<RwLock<PolicySnapshot>>,
    notify: Arc<Notify>,
}

impl PolicyHub {
    pub fn new(initial: PolicySnapshot) -> Self {
        Self {
            state: Arc::new(RwLock::new(initial)),
            notify: Arc::new(Notify::new()),
        }
    }

    /// Build initial snapshot from runtime env + pinning registry.
    pub fn from_runtime(pinning: &PinningRegistry) -> Self {
        let doc = agent_policy_document(
            crate::policy_config::configured_policy_mode().as_str(),
            &crate::policy_config::configured_mitm_categories(),
            &pinning.active_domains(),
        );
        let snap = snapshot_from_document(doc, "startup");
        Self::new(snap)
    }

    pub fn snapshot(&self) -> PolicySnapshot {
        self.state.read().expect("policy hub lock").clone()
    }

    /// Replace current policy and wake waiters / SSE subscribers.
    pub fn publish(&self, mut document: Value, reason: &str) -> PolicySnapshot {
        let snap = {
            let version = content_version(&document);
            document["policy_version"] = Value::String(version.clone());
            document["push_reason"] = Value::String(reason.to_string());
            document["pushed_at"] = Value::Number(unix_now().into());
            PolicySnapshot {
                version,
                document,
                pushed_at: unix_now(),
                reason: reason.to_string(),
            }
        };
        {
            let mut guard = self.state.write().expect("policy hub lock");
            *guard = snap.clone();
        }
        info!(
            policy_version = %snap.version,
            reason = %snap.reason,
            "Agent policy published (push)"
        );
        self.notify.notify_waiters();
        snap
    }

    /// Rebuild document from env + pinning and publish.
    pub fn publish_from_runtime(&self, pinning: &PinningRegistry, reason: &str) -> PolicySnapshot {
        let doc = agent_policy_document(
            crate::policy_config::configured_policy_mode().as_str(),
            &crate::policy_config::configured_mitm_categories(),
            &pinning.active_domains(),
        );
        self.publish(doc, reason)
    }

    /// Wait until `policy_version` differs from `since`, or timeout.
    /// Returns `(snapshot, changed)`.
    pub async fn wait_change(
        &self,
        since: Option<&str>,
        timeout: Duration,
    ) -> (PolicySnapshot, bool) {
        let deadline = Instant::now() + timeout;
        loop {
            let snap = self.snapshot();
            let changed = match since {
                None => true,
                Some(v) if v.is_empty() => true,
                Some(v) => v != snap.version,
            };
            if changed {
                return (snap, true);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return (snap, false);
            }
            tokio::select! {
                _ = self.notify.notified() => continue,
                _ = tokio::time::sleep(remaining) => {
                    return (self.snapshot(), false);
                }
            }
        }
    }

    /// Clone of the notify handle for SSE loops.
    pub fn notify_handle(&self) -> Arc<Notify> {
        self.notify.clone()
    }
}

fn snapshot_from_document(mut document: Value, reason: &str) -> PolicySnapshot {
    let version = content_version(&document);
    document["policy_version"] = Value::String(version.clone());
    document["push_reason"] = Value::String(reason.to_string());
    document["pushed_at"] = Value::Number(unix_now().into());
    PolicySnapshot {
        version,
        document,
        pushed_at: unix_now(),
        reason: reason.to_string(),
    }
}

/// Stable short version from policy body (excluding volatile fields).
fn content_version(document: &Value) -> String {
    let mut hasher = Sha256::new();
    // Hash the substantive fields only.
    if let Some(mode) = document.get("policy_mode") {
        hasher.update(mode.to_string().as_bytes());
    }
    if let Some(cats) = document.get("mitm_categories") {
        hasher.update(cats.to_string().as_bytes());
    }
    if let Some(pin) = document.get("pinning_exceptions") {
        hasher.update(pin.to_string().as_bytes());
    }
    if let Some(sni) = document.get("sni_deny_patterns") {
        hasher.update(sni.to_string().as_bytes());
    }
    // Monotonic counter so consecutive publishes always advance version.
    hasher.update(unix_now().to_le_bytes());
    hasher.update(PUSH_SEQ.fetch_add(1, Ordering::Relaxed).to_le_bytes());
    let digest = hasher.finalize();
    format!("v{}", hex::encode(&digest[..8]))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn publish_wakes_waiter() {
        let hub = PolicyHub::new(snapshot_from_document(
            serde_json::json!({
                "policy_mode": "selective-mitm",
                "mitm_categories": ["malware"],
                "pinning_exceptions": [],
                "sni_deny_patterns": ["*.evil.com"],
            }),
            "test",
        ));
        let since = hub.snapshot().version;
        let since_wait = since.clone();
        let hub2 = hub.clone();
        let waiter = tokio::spawn(async move {
            hub2.wait_change(Some(&since_wait), Duration::from_secs(2))
                .await
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        hub.publish(
            serde_json::json!({
                "policy_mode": "sni",
                "mitm_categories": [],
                "pinning_exceptions": [".slack.com"],
                "sni_deny_patterns": ["badsite.test"],
            }),
            "unit-test",
        );
        let (snap, changed) = waiter.await.unwrap();
        assert!(changed);
        assert_ne!(snap.version, since);
        assert_eq!(snap.document["policy_mode"], "sni");
    }

    #[tokio::test]
    async fn timeout_without_change() {
        let hub = PolicyHub::new(snapshot_from_document(
            serde_json::json!({
                "policy_mode": "selective-mitm",
                "mitm_categories": [],
                "pinning_exceptions": [],
                "sni_deny_patterns": [],
            }),
            "test",
        ));
        let since = hub.snapshot().version;
        let (snap, changed) = hub
            .wait_change(Some(&since), Duration::from_millis(50))
            .await;
        assert!(!changed);
        assert_eq!(snap.version, since);
    }
}
