//! TASK-TI-031: SOAR Integration & Automated Response Engine.
//!
//! Provides automated security orchestration, investigation, and incident containment:
//! - Automated blocking (`block_indicator`) with high priority and custom TTL.
//! - Automated unblocking / exception whitelisting (`unblock_indicator`).
//! - Full IOC investigation and lineage lookup (`investigate_indicator`).

use crate::config::EnforcementMode;
use crate::indicator::IndicatorKind;
use crate::normalizer::NormalizedIndicator;
use crate::storage::{SqliteStorage, StorageError, StoredIndicator};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoarBlockRequest {
    pub indicator: String,
    pub kind: IndicatorKind,
    pub reason: String,
    pub ttl_secs: Option<i64>,
    pub operator: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoarUnblockRequest {
    pub indicator: String,
    pub kind: Option<IndicatorKind>,
    pub reason: String,
    pub operator: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoarInvestigationResult {
    pub query: String,
    pub found: bool,
    pub indicator: Option<StoredIndicator>,
    pub is_active: bool,
    pub queried_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoarActionResponse {
    pub success: bool,
    pub action: String,
    pub indicator: String,
    pub message: String,
    /// Enforcement mode the collector runs in: `shadow` or `enforce`.
    #[serde(default = "shadow_mode_label")]
    pub mode: String,
    /// `false` in shadow mode: the indicator only reaches the `.shadow`
    /// artifact and never blocks traffic (issue #330).
    #[serde(default)]
    pub enforced: bool,
    pub timestamp: DateTime<Utc>,
}

fn shadow_mode_label() -> String {
    EnforcementMode::Shadow.as_str().to_string()
}

/// Executes an automated SOAR block action.
pub fn execute_soar_block(
    storage: &SqliteStorage,
    req: SoarBlockRequest,
    mode: EnforcementMode,
) -> Result<SoarActionResponse, StorageError> {
    // Default 30 days; clamped so a client-supplied TTL cannot overflow the
    // expiry timestamp or expire the indicator on insert.
    let ttl_secs = req.ttl_secs.unwrap_or(86400 * 30).clamp(60, 86400 * 365);
    let mut tags = vec!["soar_blocked".to_string(), "manual_containment".to_string()];
    if !mode.is_enforce() {
        tags.push("shadow".to_string());
    }
    let raw = crate::indicator::RawIndicator {
        value: req.indicator.clone(),
        kind: req.kind,
        source: format!("soar:{}", req.operator.as_deref().unwrap_or("auto")),
        source_weight: 100,
        collected_at: Utc::now(),
        reported_at: Some(Utc::now()),
        reference: Some(req.reason.clone()),
        tags,
    };

    let norm = match NormalizedIndicator::from_raw(&raw, 100) {
        Some(n) => n,
        None => {
            return Ok(SoarActionResponse {
                success: false,
                action: "block".into(),
                indicator: req.indicator,
                message: "Failed to normalize indicator value".into(),
                mode: mode.as_str().to_string(),
                enforced: false,
                timestamp: Utc::now(),
            });
        }
    };

    let stats = storage.upsert_batch(&[norm], ttl_secs)?;

    let message = if mode.is_enforce() {
        format!(
            "Indicator blocked successfully (inserted: {}, updated: {}, ttl: {}s)",
            stats.inserted, stats.updated, ttl_secs
        )
    } else {
        format!(
            "Shadow mode: indicator accepted for observation only, it reaches the '.shadow' \
             artifact and blocks nothing (inserted: {}, updated: {}, ttl: {}s). Set \
             TI_ENFORCEMENT_MODE=enforce to block.",
            stats.inserted, stats.updated, ttl_secs
        )
    };

    Ok(SoarActionResponse {
        success: true,
        action: "block".into(),
        indicator: req.indicator,
        message,
        mode: mode.as_str().to_string(),
        enforced: mode.is_enforce(),
        timestamp: Utc::now(),
    })
}

/// Executes an automated SOAR unblock action.
pub fn execute_soar_unblock(
    storage: &SqliteStorage,
    req: SoarUnblockRequest,
    mode: EnforcementMode,
) -> Result<SoarActionResponse, StorageError> {
    // Delete indicator or mark as expired
    let purged = storage.purge_indicator(&req.indicator, req.kind)?;

    Ok(SoarActionResponse {
        success: purged > 0,
        action: "unblock".into(),
        indicator: req.indicator,
        message: if purged > 0 {
            format!("Indicator removed from active threats (records purged: {purged})")
        } else {
            "Indicator not found in active threats".to_string()
        },
        mode: mode.as_str().to_string(),
        enforced: mode.is_enforce(),
        timestamp: Utc::now(),
    })
}

/// Investigates an indicator against threat storage.
pub fn execute_soar_investigation(
    storage: &SqliteStorage,
    query: &str,
    kind: Option<IndicatorKind>,
) -> Result<SoarInvestigationResult, StorageError> {
    let ind = storage.query_indicator(query, kind)?;
    let now = Utc::now();
    let is_active = ind.as_ref().map(|i| i.expires_at > now).unwrap_or(false);

    Ok(SoarInvestigationResult {
        query: query.to_string(),
        found: ind.is_some(),
        indicator: ind,
        is_active,
        queried_at: now,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_soar_block_unblock_investigate() {
        let storage = SqliteStorage::in_memory().unwrap();

        // 1. Investigate non-existent
        let res1 = execute_soar_investigation(&storage, "malicious-domain.test", None).unwrap();
        assert!(!res1.found);

        // 2. Block domain
        let block_res = execute_soar_block(
            &storage,
            SoarBlockRequest {
                indicator: "malicious-domain.test".into(),
                kind: IndicatorKind::Domain,
                reason: "Active C2 beacon observed in SIEM".into(),
                ttl_secs: Some(3600),
                operator: Some("soc_analyst_1".into()),
            },
            EnforcementMode::Enforce,
        )
        .unwrap();
        assert!(block_res.success);
        assert!(block_res.enforced);
        assert_eq!(block_res.mode, "enforce");

        // 3. Investigate again
        let res2 = execute_soar_investigation(&storage, "malicious-domain.test", None).unwrap();
        assert!(res2.found);
        assert!(res2.is_active);
        let ind = res2.indicator.unwrap();
        assert_eq!(ind.confidence_score, 100);
        assert_eq!(ind.source, "soar:soc_analyst_1");

        // 4. Unblock
        let unblock_res = execute_soar_unblock(
            &storage,
            SoarUnblockRequest {
                indicator: "malicious-domain.test".into(),
                kind: Some(IndicatorKind::Domain),
                reason: "False positive confirmed".into(),
                operator: Some("soc_analyst_1".into()),
            },
            EnforcementMode::Enforce,
        )
        .unwrap();
        assert!(unblock_res.success);

        // 5. Investigate after unblock
        let res3 = execute_soar_investigation(&storage, "malicious-domain.test", None).unwrap();
        assert!(!res3.found);
    }

    #[test]
    fn shadow_block_is_accepted_but_not_enforced() {
        let storage = SqliteStorage::in_memory().unwrap();

        let res = execute_soar_block(
            &storage,
            SoarBlockRequest {
                indicator: "shadow-block.test".into(),
                kind: IndicatorKind::Domain,
                reason: "Suspected C2".into(),
                ttl_secs: Some(3600),
                operator: Some("soc_analyst_1".into()),
            },
            EnforcementMode::Shadow,
        )
        .unwrap();

        assert!(res.success);
        assert!(!res.enforced, "shadow block must never claim enforcement");
        assert_eq!(res.mode, "shadow");

        let stored = execute_soar_investigation(&storage, "shadow-block.test", None)
            .unwrap()
            .indicator
            .expect("indicator must be observable in shadow storage");
        assert!(stored.tags.iter().any(|t| t == "shadow"));
    }
}
