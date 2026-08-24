//! MITM Circuit Breaker for per-domain TLS handshake failure rate protection (ADR-0007).
//!
//! If the TLS handshake or certificate generation failure rate for a domain exceeds
//! a configured threshold (e.g. 5% over 60 seconds with a minimum sample size), the
//! circuit breaker trips and automatically falls back to blind CONNECT (no MITM) for that
//! domain until manually reset or end of cooldown. Every trip and reset event is logged
//! to an audit trail.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

const DEFAULT_FAILURE_RATE: f64 = 0.05; // 5%
const DEFAULT_MIN_SAMPLES: usize = 5;
const DEFAULT_WINDOW_SECS: u64 = 60;
const DEFAULT_COOLDOWN_SECS: u64 = 0; // 0 = permanent until manual reset

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitmCircuitBreakerConfig {
    pub enabled: bool,
    pub failure_rate_threshold: f64,
    pub min_samples: usize,
    pub window_secs: u64,
    pub cooldown_secs: u64,
}

impl Default for MitmCircuitBreakerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            failure_rate_threshold: DEFAULT_FAILURE_RATE,
            min_samples: DEFAULT_MIN_SAMPLES,
            window_secs: DEFAULT_WINDOW_SECS,
            cooldown_secs: DEFAULT_COOLDOWN_SECS,
        }
    }
}

impl MitmCircuitBreakerConfig {
    pub fn from_env() -> Self {
        let enabled = std::env::var("MITM_CIRCUIT_BREAKER_ENABLED")
            .map(|v| v.trim() != "false" && v.trim() != "0")
            .unwrap_or(true);
        let failure_rate_threshold = std::env::var("MITM_CIRCUIT_BREAKER_FAILURE_RATE")
            .ok()
            .and_then(|v| v.parse::<f64>().ok())
            .filter(|&rate| rate > 0.0 && rate <= 1.0)
            .unwrap_or(DEFAULT_FAILURE_RATE);
        let min_samples = std::env::var("MITM_CIRCUIT_BREAKER_MIN_SAMPLES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|&n| n >= 1)
            .unwrap_or(DEFAULT_MIN_SAMPLES);
        let window_secs = std::env::var("MITM_CIRCUIT_BREAKER_WINDOW_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|&s| s >= 1)
            .unwrap_or(DEFAULT_WINDOW_SECS);
        let cooldown_secs = std::env::var("MITM_CIRCUIT_BREAKER_COOLDOWN_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_COOLDOWN_SECS);

        Self {
            enabled,
            failure_rate_threshold,
            min_samples,
            window_secs,
            cooldown_secs,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TrippedInfo {
    pub domain: String,
    pub tripped_at_unix: u64,
    pub failure_rate: f64,
    pub failure_count: usize,
    pub total_samples: usize,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct MitmCircuitBreakerStatus {
    pub enabled: bool,
    pub failure_rate_threshold: f64,
    pub min_samples: usize,
    pub window_secs: u64,
    pub cooldown_secs: u64,
    pub audit_path: Option<String>,
    pub tripped_count: usize,
    pub tripped_domains: Vec<TrippedInfo>,
}

#[derive(Debug, Serialize)]
pub struct BreakerResetReport {
    pub status: &'static str,
    pub reset_domains: Vec<String>,
    pub actor: String,
    pub reason: String,
    pub audited_at: Option<String>,
}

#[derive(Debug)]
struct Sample {
    at: Instant,
    success: bool,
}

#[derive(Debug)]
enum DomainState {
    Closed,
    Tripped {
        tripped_at: Instant,
        info: TrippedInfo,
    },
}

#[derive(Debug)]
struct DomainTracker {
    samples: VecDeque<Sample>,
    state: DomainState,
}

impl DomainTracker {
    fn new() -> Self {
        Self {
            samples: VecDeque::new(),
            state: DomainState::Closed,
        }
    }

    fn prune(&mut self, cutoff: Instant) {
        while let Some(front) = self.samples.front() {
            if front.at < cutoff {
                self.samples.pop_front();
            } else {
                break;
            }
        }
    }
}

#[derive(Debug, Serialize)]
struct BreakerAuditRecord<'a> {
    timestamp_unix: u64,
    actor: &'a str,
    change_reason: &'a str,
    action: &'a str,
    domain: &'a str,
    failure_rate: Option<f64>,
    failure_count: Option<usize>,
    total_samples: Option<usize>,
    source_path: &'a str,
}

pub struct MitmCircuitBreaker {
    config: MitmCircuitBreakerConfig,
    audit_path: Option<PathBuf>,
    trackers: RwLock<HashMap<String, DomainTracker>>,
}

impl MitmCircuitBreaker {
    pub fn from_env() -> Self {
        let config = MitmCircuitBreakerConfig::from_env();
        let audit_path = std::env::var("PINNING_AUDIT_LOG_PATH")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var("PINNING_EXCEPTIONS_PATH")
                    .ok()
                    .filter(|v| !v.trim().is_empty())
                    .map(|p| PathBuf::from(format!("{p}.audit.jsonl")))
            });
        Self::new(config, audit_path)
    }

    pub fn new(config: MitmCircuitBreakerConfig, audit_path: Option<PathBuf>) -> Self {
        Self {
            config,
            audit_path,
            trackers: RwLock::new(HashMap::new()),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    pub fn config(&self) -> &MitmCircuitBreakerConfig {
        &self.config
    }

    pub fn audit_path(&self) -> Option<String> {
        self.audit_path.as_deref().map(|p| p.display().to_string())
    }

    /// Check if a domain (or its parent domain wildcard) is currently tripped.
    pub fn is_tripped(&self, domain: &str) -> bool {
        if !self.config.enabled {
            return false;
        }
        let normalized = normalize_domain_key(domain);
        let now = Instant::now();
        let cooldown = self.config.cooldown_secs;

        let trackers = match self.trackers.read() {
            Ok(t) => t,
            Err(poisoned) => poisoned.into_inner(),
        };

        // Check exact match and parent domain suffixes
        for (tracked_domain, tracker) in trackers.iter() {
            if domain_matches(&normalized, tracked_domain) {
                if let DomainState::Tripped { tripped_at, .. } = &tracker.state {
                    if cooldown > 0 && now.duration_since(*tripped_at).as_secs() >= cooldown {
                        // Cooldown elapsed, allow attempt
                        continue;
                    }
                    return true;
                }
            }
        }
        false
    }

    /// Record an attempt outcome (success or failure) for a domain.
    pub fn record_attempt(&self, domain: &str, success: bool, failure_detail: &str) {
        if !self.config.enabled {
            return;
        }
        let domain_key = normalize_domain_key(domain);
        let now = Instant::now();
        let cutoff = now
            .checked_sub(Duration::from_secs(self.config.window_secs))
            .unwrap_or(now);

        let mut trackers = match self.trackers.write() {
            Ok(t) => t,
            Err(poisoned) => poisoned.into_inner(),
        };

        let tracker = trackers
            .entry(domain_key.clone())
            .or_insert_with(DomainTracker::new);

        // If cooldown elapsed on a tripped domain, reset it back to closed
        if let DomainState::Tripped { tripped_at, .. } = &tracker.state {
            if self.config.cooldown_secs > 0
                && now.duration_since(*tripped_at).as_secs() >= self.config.cooldown_secs
            {
                tracker.state = DomainState::Closed;
                tracker.samples.clear();
            } else {
                // Still tripped, don't record further samples
                return;
            }
        }

        tracker.prune(cutoff);
        tracker.samples.push_back(Sample { at: now, success });

        let total = tracker.samples.len();
        if total < self.config.min_samples {
            return;
        }

        let failures = tracker.samples.iter().filter(|s| !s.success).count();
        let rate = failures as f64 / total as f64;

        if rate >= self.config.failure_rate_threshold {
            let reason = format!(
                "TLS failure rate {:.1}% ({}/{}) exceeded {:.1}% threshold in {}s window: {}",
                rate * 100.0,
                failures,
                total,
                self.config.failure_rate_threshold * 100.0,
                self.config.window_secs,
                failure_detail
            );
            let info = TrippedInfo {
                domain: domain_key.clone(),
                tripped_at_unix: unix_now(),
                failure_rate: rate,
                failure_count: failures,
                total_samples: total,
                reason: reason.clone(),
            };

            warn!(
                domain = %domain_key,
                failure_rate = rate,
                failures,
                total,
                "MITM circuit breaker TRIPPED; domain switched to blind CONNECT"
            );

            tracker.state = DomainState::Tripped {
                tripped_at: now,
                info,
            };

            // Write audit record
            if let Some(audit_path) = &self.audit_path {
                let _ = append_breaker_audit(
                    audit_path,
                    "system:circuit-breaker",
                    &reason,
                    "circuit_breaker_tripped",
                    &domain_key,
                    Some(rate),
                    Some(failures),
                    Some(total),
                );
            }
        }
    }

    /// Reset circuit breaker for a domain pattern ("*" or specific domain).
    pub fn reset(
        &self,
        domain_pattern: &str,
        actor: &str,
        change_reason: &str,
    ) -> Result<BreakerResetReport, String> {
        validate_audit_text("actor", actor, 128)?;
        validate_audit_text("reason", change_reason, 512)?;

        let mut trackers = match self.trackers.write() {
            Ok(t) => t,
            Err(poisoned) => poisoned.into_inner(),
        };

        let mut reset_domains = Vec::new();
        let pattern_norm = domain_pattern.trim().to_ascii_lowercase();

        if pattern_norm == "*" {
            for (domain, tracker) in trackers.iter_mut() {
                if matches!(tracker.state, DomainState::Tripped { .. }) {
                    tracker.state = DomainState::Closed;
                    tracker.samples.clear();
                    reset_domains.push(domain.clone());
                }
            }
        } else {
            let key = normalize_domain_key(&pattern_norm);
            if let Some(tracker) = trackers.get_mut(&key) {
                if matches!(tracker.state, DomainState::Tripped { .. }) {
                    tracker.state = DomainState::Closed;
                    tracker.samples.clear();
                    reset_domains.push(key.clone());
                }
            }
        }

        if let Some(audit_path) = &self.audit_path {
            for domain in &reset_domains {
                let _ = append_breaker_audit(
                    audit_path,
                    actor,
                    change_reason,
                    "circuit_breaker_reset",
                    domain,
                    None,
                    None,
                    None,
                );
            }
        }

        info!(
            actor = %actor,
            reason = %change_reason,
            reset_count = reset_domains.len(),
            "MITM circuit breaker reset"
        );

        Ok(BreakerResetReport {
            status: "reset",
            reset_domains,
            actor: actor.to_string(),
            reason: change_reason.to_string(),
            audited_at: self.audit_path(),
        })
    }

    /// Get snapshot of circuit breaker status and tripped domains.
    pub fn status(&self) -> MitmCircuitBreakerStatus {
        let trackers = match self.trackers.read() {
            Ok(t) => t,
            Err(poisoned) => poisoned.into_inner(),
        };

        let mut tripped = Vec::new();
        for tracker in trackers.values() {
            if let DomainState::Tripped { info, .. } = &tracker.state {
                tripped.push(info.clone());
            }
        }
        tripped.sort_by(|a, b| a.domain.cmp(&b.domain));

        MitmCircuitBreakerStatus {
            enabled: self.config.enabled,
            failure_rate_threshold: self.config.failure_rate_threshold,
            min_samples: self.config.min_samples,
            window_secs: self.config.window_secs,
            cooldown_secs: self.config.cooldown_secs,
            audit_path: self.audit_path(),
            tripped_count: tripped.len(),
            tripped_domains: tripped,
        }
    }
}

fn normalize_domain_key(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn domain_matches(target: &str, tracked: &str) -> bool {
    if tracked.starts_with('.') {
        target == tracked.trim_start_matches('.') || target.ends_with(tracked)
    } else {
        target == tracked
    }
}

fn validate_audit_text(field: &str, value: &str, max: usize) -> Result<(), String> {
    if value.trim().is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(format!("{field} must be 1..={max} printable characters"));
    }
    Ok(())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[allow(clippy::too_many_arguments)]
fn append_breaker_audit(
    audit_path: &Path,
    actor: &str,
    change_reason: &str,
    action: &str,
    domain: &str,
    failure_rate: Option<f64>,
    failure_count: Option<usize>,
    total_samples: Option<usize>,
) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(audit_path)
        .map_err(|e| format!("open audit log {}: {e}", audit_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
    }

    serde_json::to_writer(
        &mut file,
        &BreakerAuditRecord {
            timestamp_unix: unix_now(),
            actor,
            change_reason,
            action,
            domain,
            failure_rate,
            failure_count,
            total_samples,
            source_path: "mitm-circuit-breaker",
        },
    )
    .map_err(|e| format!("serialize audit record: {e}"))?;
    file.write_all(b"\n")
        .map_err(|e| format!("write audit log {}: {e}", audit_path.display()))?;
    let _ = file.sync_data();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn breaker_trips_when_failure_rate_exceeded() {
        let unique = format!("test-breaker-{}", unix_now());
        let audit = std::env::temp_dir().join(format!("{unique}.audit.jsonl"));
        let config = MitmCircuitBreakerConfig {
            enabled: true,
            failure_rate_threshold: 0.20, // 20%
            min_samples: 5,
            window_secs: 60,
            cooldown_secs: 0,
        };
        let breaker = MitmCircuitBreaker::new(config, Some(audit.clone()));

        assert!(!breaker.is_tripped("api.example.com"));

        // 4 successes, 1 failure -> 1/5 = 20% >= 20% -> trips
        breaker.record_attempt("api.example.com", true, "ok");
        breaker.record_attempt("api.example.com", true, "ok");
        breaker.record_attempt("api.example.com", true, "ok");
        breaker.record_attempt("api.example.com", true, "ok");
        assert!(!breaker.is_tripped("api.example.com"));

        breaker.record_attempt("api.example.com", false, "handshake_failed");
        assert!(breaker.is_tripped("api.example.com"));

        let status = breaker.status();
        assert_eq!(status.tripped_count, 1);
        assert_eq!(status.tripped_domains[0].domain, "api.example.com");
        assert_eq!(status.tripped_domains[0].failure_count, 1);
        assert_eq!(status.tripped_domains[0].total_samples, 5);

        // Audit log exists
        let audit_content = std::fs::read_to_string(&audit).unwrap();
        assert!(audit_content.contains(r#""action":"circuit_breaker_tripped""#));
        assert!(audit_content.contains(r#""domain":"api.example.com""#));

        // Reset
        let report = breaker
            .reset("api.example.com", "operator-bob", "certs updated")
            .unwrap();
        assert_eq!(report.reset_domains, vec!["api.example.com"]);
        assert!(!breaker.is_tripped("api.example.com"));

        let audit_content_after = std::fs::read_to_string(&audit).unwrap();
        assert!(audit_content_after.contains(r#""action":"circuit_breaker_reset""#));

        let _ = std::fs::remove_file(audit);
    }

    #[test]
    fn breaker_does_not_trip_below_min_samples() {
        let config = MitmCircuitBreakerConfig {
            enabled: true,
            failure_rate_threshold: 0.05,
            min_samples: 10,
            window_secs: 60,
            cooldown_secs: 0,
        };
        let breaker = MitmCircuitBreaker::new(config, None);

        // 3 failures out of 3 samples (100%), but total samples < 10
        breaker.record_attempt("sub.example.com", false, "fail");
        breaker.record_attempt("sub.example.com", false, "fail");
        breaker.record_attempt("sub.example.com", false, "fail");

        assert!(!breaker.is_tripped("sub.example.com"));
    }

    #[test]
    fn wildcards_and_parent_domains_match() {
        let config = MitmCircuitBreakerConfig {
            enabled: true,
            failure_rate_threshold: 0.10,
            min_samples: 2,
            window_secs: 60,
            cooldown_secs: 0,
        };
        let breaker = MitmCircuitBreaker::new(config, None);

        breaker.record_attempt(".pinned.com", false, "fail");
        breaker.record_attempt(".pinned.com", false, "fail");

        assert!(breaker.is_tripped("pinned.com"));
        assert!(breaker.is_tripped("sub.pinned.com"));
        assert!(breaker.is_tripped("deep.sub.pinned.com"));
        assert!(!breaker.is_tripped("other.com"));
    }
}
