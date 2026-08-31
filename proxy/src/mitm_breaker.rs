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
/// Upper bound on the number of per-domain trackers kept in memory. Without it a
/// client looping `CONNECT <random>.attacker.tld:443` grows the map without limit.
const DEFAULT_MAX_DOMAINS: usize = 10_000;
/// Smallest cap accepted from the environment; below this the breaker cannot keep
/// a meaningful window for a real client population.
const MIN_MAX_DOMAINS: usize = 128;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitmCircuitBreakerConfig {
    pub enabled: bool,
    pub failure_rate_threshold: f64,
    pub min_samples: usize,
    pub window_secs: u64,
    pub cooldown_secs: u64,
    pub max_domains: usize,
}

impl Default for MitmCircuitBreakerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            failure_rate_threshold: DEFAULT_FAILURE_RATE,
            min_samples: DEFAULT_MIN_SAMPLES,
            window_secs: DEFAULT_WINDOW_SECS,
            cooldown_secs: DEFAULT_COOLDOWN_SECS,
            max_domains: DEFAULT_MAX_DOMAINS,
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
        let max_domains = std::env::var("MITM_CIRCUIT_BREAKER_MAX_DOMAINS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .map(|n| n.max(MIN_MAX_DOMAINS))
            .unwrap_or(DEFAULT_MAX_DOMAINS);

        Self {
            enabled,
            failure_rate_threshold,
            min_samples,
            window_secs,
            cooldown_secs,
            max_domains,
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
    pub max_domains: usize,
    pub audit_path: Option<String>,
    pub tracked_domains: usize,
    pub evicted_domains_total: u64,
    pub evicted_tripped_domains_total: u64,
    pub dropped_attempts_total: u64,
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
    last_seen: Instant,
}

impl DomainTracker {
    fn new(now: Instant) -> Self {
        Self {
            samples: VecDeque::new(),
            state: DomainState::Closed,
            last_seen: now,
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

    /// A tracker is evictable once it carries no state worth keeping: not tripped
    /// and with no sample left inside the current window.
    fn is_evictable(&self, cutoff: Instant) -> bool {
        matches!(self.state, DomainState::Closed)
            && self.samples.iter().all(|sample| sample.at < cutoff)
    }
}

/// Bounded map of per-domain trackers.
///
/// `is_tripped` runs on every MITM CONNECT, so it is a single `HashMap` lookup:
/// keys are exact hostnames, normalized by [`normalize_domain_key`].
#[derive(Debug, Default)]
struct BreakerState {
    trackers: HashMap<String, DomainTracker>,
    evicted_total: u64,
    evicted_tripped_total: u64,
    dropped_attempts_total: u64,
}

impl BreakerState {
    /// Free capacity when the tracker map is full.
    ///
    /// Each sweep frees 10% of the cap, so its cost is amortised over the
    /// following `max_domains / 10` inserts instead of being paid per request.
    /// The tiers exist so that a `CONNECT` flood evicts its own throwaway
    /// trackers before it can flush a domain the breaker is actually measuring.
    /// Returns `true` when there is room for a new tracker.
    fn make_room(&mut self, max_domains: usize, cutoff: Instant) -> bool {
        if self.trackers.len() < max_domains {
            return true;
        }

        let target = max_domains - (max_domains / 10).max(1);

        // Tier 1: closed trackers with no sample left inside the window — nothing
        // is lost, least recently seen first.
        self.evict_until(
            target,
            |tracker| tracker.is_evictable(cutoff),
            |tracker| (0, tracker.last_seen),
        );
        if self.trackers.len() < max_domains {
            return true;
        }

        // Tier 2: under a flood every tracker still holds a live sample. Evict
        // closed trackers with the fewest samples first, which targets the flood's
        // own one-sample entries ahead of a domain sitting on a partial failure
        // streak; last_seen breaks ties.
        self.evict_until(
            target,
            |tracker| matches!(tracker.state, DomainState::Closed),
            |tracker| (tracker.samples.len(), tracker.last_seen),
        );
        if self.trackers.len() < max_domains {
            return true;
        }

        // Tier 3: the map is full of tripped domains. Trips are cheap to re-earn
        // (the next failures re-trip the domain) but an unbounded map is not, and
        // without this the sweep above would run on every request forever. Evict
        // the least recently seen trips and count them separately so operators can
        // see that a bypass was dropped under pressure.
        let before = self.evicted_total;
        self.evict_until(target, |_| true, |tracker| (0, tracker.last_seen));
        self.evicted_tripped_total += self.evicted_total - before;

        self.trackers.len() < max_domains
    }

    /// Drop trackers matching `evictable`, ordered by `rank` ascending, until the
    /// map is at or below `target`.
    fn evict_until<K: Ord>(
        &mut self,
        target: usize,
        evictable: impl Fn(&DomainTracker) -> bool,
        rank: impl Fn(&DomainTracker) -> K,
    ) {
        if self.trackers.len() <= target {
            return;
        }
        let mut candidates: Vec<(K, String)> = self
            .trackers
            .iter()
            .filter(|(_, tracker)| evictable(tracker))
            .map(|(key, tracker)| (rank(tracker), key.clone()))
            .collect();
        candidates.sort_by(|a, b| a.0.cmp(&b.0));

        for (_, key) in candidates {
            if self.trackers.len() <= target {
                break;
            }
            if self.trackers.remove(&key).is_some() {
                self.evicted_total += 1;
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

const NUM_SHARDS: usize = 32;

fn shard_index(key: &str) -> usize {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in key.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    (h as usize) % NUM_SHARDS
}

pub struct MitmCircuitBreaker {
    config: MitmCircuitBreakerConfig,
    audit_path: Option<PathBuf>,
    shards: Vec<RwLock<BreakerState>>,
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
        let mut shards = Vec::with_capacity(NUM_SHARDS);
        for _ in 0..NUM_SHARDS {
            shards.push(RwLock::new(BreakerState::default()));
        }
        Self {
            config,
            audit_path,
            shards,
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
        let idx = shard_index(&normalized);

        let shard = match self.shards[idx].read() {
            Ok(t) => t,
            Err(poisoned) => poisoned.into_inner(),
        };

        // Keys are exact hostnames, so this is a single lookup — no scan.
        shard
            .trackers
            .get(&normalized)
            .is_some_and(|tracker| is_active_trip(tracker, now, cooldown))
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
        let idx = shard_index(&domain_key);
        let max_per_shard = (self.config.max_domains / NUM_SHARDS).max(1);

        let mut shard = match self.shards[idx].write() {
            Ok(t) => t,
            Err(poisoned) => poisoned.into_inner(),
        };

        if !shard.trackers.contains_key(&domain_key) {
            // Cap the tracker map: an attacker looping CONNECT on random hosts must
            // not be able to grow it without limit. When nothing can be evicted the
            // sample is dropped — the breaker stops learning new domains rather than
            // growing, and existing trips keep working.
            if !shard.make_room(max_per_shard, cutoff) {
                shard.dropped_attempts_total += 1;
                warn!(
                    domain = %domain_key,
                    max_domains = max_per_shard,
                    dropped_attempts_total = shard.dropped_attempts_total,
                    "MITM circuit breaker tracker shard is full; attempt not recorded"
                );
                return;
            }
            shard
                .trackers
                .insert(domain_key.clone(), DomainTracker::new(now));
        }

        let tracker = shard
            .trackers
            .get_mut(&domain_key)
            .expect("tracker inserted above");
        tracker.last_seen = now;

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

        let mut reset_domains = Vec::new();
        let pattern_norm = domain_pattern.trim().to_ascii_lowercase();

        if pattern_norm == "*" {
            for shard_lock in &self.shards {
                let mut shard = match shard_lock.write() {
                    Ok(t) => t,
                    Err(poisoned) => poisoned.into_inner(),
                };
                for (domain, tracker) in shard.trackers.iter_mut() {
                    if matches!(tracker.state, DomainState::Tripped { .. }) {
                        tracker.state = DomainState::Closed;
                        tracker.samples.clear();
                        reset_domains.push(domain.clone());
                    }
                }
            }
        } else {
            let key = normalize_domain_key(&pattern_norm);
            let idx = shard_index(&key);
            let mut shard = match self.shards[idx].write() {
                Ok(t) => t,
                Err(poisoned) => poisoned.into_inner(),
            };
            if let Some(tracker) = shard.trackers.get_mut(&key) {
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
        let mut tripped = Vec::new();
        let mut tracked_domains = 0;
        let mut evicted_domains_total = 0;
        let mut evicted_tripped_domains_total = 0;
        let mut dropped_attempts_total = 0;

        for shard_lock in &self.shards {
            let shard = match shard_lock.read() {
                Ok(t) => t,
                Err(poisoned) => poisoned.into_inner(),
            };
            tracked_domains += shard.trackers.len();
            evicted_domains_total += shard.evicted_total;
            evicted_tripped_domains_total += shard.evicted_tripped_total;
            dropped_attempts_total += shard.dropped_attempts_total;

            for tracker in shard.trackers.values() {
                if let DomainState::Tripped { info, .. } = &tracker.state {
                    tripped.push(info.clone());
                }
            }
        }
        tripped.sort_by(|a, b| a.domain.cmp(&b.domain));

        MitmCircuitBreakerStatus {
            enabled: self.config.enabled,
            failure_rate_threshold: self.config.failure_rate_threshold,
            min_samples: self.config.min_samples,
            window_secs: self.config.window_secs,
            cooldown_secs: self.config.cooldown_secs,
            max_domains: self.config.max_domains,
            audit_path: self.audit_path(),
            tracked_domains,
            evicted_domains_total,
            evicted_tripped_domains_total,
            dropped_attempts_total,
            tripped_count: tripped.len(),
            tripped_domains: tripped,
        }
    }
}

/// A tracker counts as tripped only while its cooldown (when configured) has not
/// elapsed; afterwards `record_attempt` closes it again on the next attempt.
fn is_active_trip(tracker: &DomainTracker, now: Instant, cooldown_secs: u64) -> bool {
    match &tracker.state {
        DomainState::Tripped { tripped_at, .. } => {
            cooldown_secs == 0 || now.duration_since(*tripped_at).as_secs() < cooldown_secs
        }
        DomainState::Closed => false,
    }
}

/// Canonical tracker key: an exact, lowercase hostname.
///
/// Leading dots are stripped as well as trailing ones. The only producer of keys
/// is `record_attempt`, fed from the client-supplied CONNECT authority, so a key
/// such as `.example.com` would let a client trip a parent-domain wildcard and
/// force blind-CONNECT for every host under it. Keys are exact hostnames instead,
/// which also keeps the lookup in `is_tripped` O(1).
fn normalize_domain_key(domain: &str) -> String {
    domain.trim().trim_matches('.').to_ascii_lowercase()
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
            max_domains: DEFAULT_MAX_DOMAINS,
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
            max_domains: DEFAULT_MAX_DOMAINS,
        };
        let breaker = MitmCircuitBreaker::new(config, None);

        // 3 failures out of 3 samples (100%), but total samples < 10
        breaker.record_attempt("sub.example.com", false, "fail");
        breaker.record_attempt("sub.example.com", false, "fail");
        breaker.record_attempt("sub.example.com", false, "fail");

        assert!(!breaker.is_tripped("sub.example.com"));
    }

    #[test]
    fn tracker_map_is_bounded_and_evicts_idle_domains() {
        let config = MitmCircuitBreakerConfig {
            enabled: true,
            failure_rate_threshold: 0.10,
            min_samples: 2,
            // Window of 0s is not accepted from env, but here it lets every sample
            // fall out of the window immediately so trackers become evictable.
            window_secs: 1,
            cooldown_secs: 0,
            max_domains: MIN_MAX_DOMAINS,
        };
        let breaker = MitmCircuitBreaker::new(config, None);

        // Simulate `CONNECT <n>.attacker.tld:443` in a loop: far more unique
        // domains than the cap.
        for n in 0..(MIN_MAX_DOMAINS * 4) {
            breaker.record_attempt(&format!("host{n}.attacker.tld"), true, "ok");
        }

        let status = breaker.status();
        assert!(
            status.tracked_domains <= MIN_MAX_DOMAINS,
            "tracker map grew past the cap: {}",
            status.tracked_domains
        );
        assert!(
            status.evicted_domains_total > 0,
            "expected idle trackers to be evicted"
        );
    }

    #[test]
    fn tripped_domains_survive_pressure_from_new_domains() {
        let config = MitmCircuitBreakerConfig {
            enabled: true,
            failure_rate_threshold: 0.10,
            min_samples: 2,
            window_secs: 1,
            cooldown_secs: 0,
            max_domains: MIN_MAX_DOMAINS,
        };
        let breaker = MitmCircuitBreaker::new(config, None);

        breaker.record_attempt("victim.example.com", false, "fail");
        breaker.record_attempt("victim.example.com", false, "fail");
        assert!(breaker.is_tripped("victim.example.com"));

        for n in 0..(MIN_MAX_DOMAINS * 4) {
            breaker.record_attempt(&format!("host{n}.attacker.tld"), true, "ok");
        }

        // The flood is made of closed trackers, so tiers 1 and 2 free all the room
        // needed and the trip never becomes an eviction candidate.
        assert!(breaker.is_tripped("victim.example.com"));
        assert_eq!(breaker.status().tripped_count, 1);
    }

    #[test]
    fn client_supplied_dots_cannot_create_a_parent_domain_wildcard() {
        let config = MitmCircuitBreakerConfig {
            enabled: true,
            failure_rate_threshold: 0.10,
            min_samples: 2,
            window_secs: 60,
            cooldown_secs: 0,
            max_domains: DEFAULT_MAX_DOMAINS,
        };
        let breaker = MitmCircuitBreaker::new(config, None);

        // `CONNECT .pinned.com:443` must trip that exact host only; it must not
        // become a wildcard that bypasses MITM for every host under pinned.com.
        breaker.record_attempt(".pinned.com", false, "fail");
        breaker.record_attempt(".pinned.com", false, "fail");

        assert!(breaker.is_tripped("pinned.com"));
        assert!(!breaker.is_tripped("sub.pinned.com"));
        assert!(!breaker.is_tripped("deep.sub.pinned.com"));
        assert!(!breaker.is_tripped("other.com"));

        let status = breaker.status();
        assert_eq!(status.tripped_count, 1);
        assert_eq!(status.tripped_domains[0].domain, "pinned.com");
    }

    #[test]
    fn flood_evicts_its_own_trackers_before_a_domain_under_measurement() {
        let config = MitmCircuitBreakerConfig {
            enabled: true,
            failure_rate_threshold: 0.90,
            // High enough that the victim never trips: it stays Closed with live
            // samples, which is exactly the state tier 2 must protect.
            min_samples: 50,
            window_secs: 600,
            cooldown_secs: 0,
            max_domains: MIN_MAX_DOMAINS,
        };
        let breaker = MitmCircuitBreaker::new(config, None);

        for _ in 0..10 {
            breaker.record_attempt("victim.example.com", false, "fail");
        }

        for n in 0..(MIN_MAX_DOMAINS * 4) {
            breaker.record_attempt(&format!("host{n}.attacker.tld"), true, "ok");
        }

        let status = breaker.status();
        assert!(status.tracked_domains <= MIN_MAX_DOMAINS);
        assert!(
            status.evicted_domains_total > 0,
            "the flood must evict its own trackers"
        );
        assert_eq!(
            status.dropped_attempts_total, 0,
            "eviction must keep making room instead of dropping attempts"
        );

        // The victim's failure history must have survived the flood: 40 more
        // failures reach min_samples only if the first 10 are still counted.
        for _ in 0..40 {
            breaker.record_attempt("victim.example.com", false, "fail");
        }
        assert!(
            breaker.is_tripped("victim.example.com"),
            "the flood flushed the samples the breaker was measuring"
        );
    }

    #[test]
    fn a_map_full_of_trips_still_makes_room() {
        let config = MitmCircuitBreakerConfig {
            enabled: true,
            failure_rate_threshold: 0.10,
            min_samples: 2,
            window_secs: 600,
            cooldown_secs: 0,
            max_domains: MIN_MAX_DOMAINS,
        };
        let breaker = MitmCircuitBreaker::new(config, None);

        // A client can trip a domain at will by aborting its own handshake, so the
        // map must stay bounded even when every tracker is tripped.
        for n in 0..(MIN_MAX_DOMAINS * 2) {
            let domain = format!("host{n}.attacker.tld");
            breaker.record_attempt(&domain, false, "fail");
            breaker.record_attempt(&domain, false, "fail");
        }

        let status = breaker.status();
        assert!(
            status.tracked_domains <= MIN_MAX_DOMAINS,
            "tracker map grew past the cap: {}",
            status.tracked_domains
        );
        assert!(
            status.evicted_tripped_domains_total > 0,
            "expected tier-3 eviction of the oldest trips"
        );
        assert_eq!(
            status.dropped_attempts_total, 0,
            "tier 3 must keep making room instead of dropping attempts"
        );
    }
}
