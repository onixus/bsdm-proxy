//! Prometheus metrics for the threat intelligence collector.

use prometheus::{HistogramOpts, HistogramVec, IntCounterVec, IntGaugeVec, Opts, Registry};
use std::sync::Arc;

pub struct CollectorMetrics {
    registry: Registry,
    /// Completed fetch cycles by outcome (`ok`, `parse_error`, `http_error`, …).
    pub fetches: IntCounterVec,
    /// Retried attempts, per source.
    pub retries: IntCounterVec,
    /// Indicators accepted, per source and IOC kind.
    pub indicators: IntCounterVec,
    /// Indicators dropped as intra-batch duplicates or over the per-fetch cap.
    pub dropped: IntCounterVec,
    /// Size of the latest snapshot, per source.
    pub last_batch_size: IntGaugeVec,
    /// Unix timestamp of the last successful collection, per source.
    pub last_success_timestamp: IntGaugeVec,
    /// Wall-clock duration of a collection cycle, per source.
    pub fetch_duration: HistogramVec,
    /// Sink write failures, per source.
    pub sink_errors: IntCounterVec,
    /// Current count of active indicators in storage.
    pub stored_indicators: IntGaugeVec,
    /// Total count of expired indicators purged.
    pub purged_expired: prometheus::IntCounter,
    /// Number of domains exported to the RPZ zone file.
    pub rpz_records: prometheus::IntGauge,
    /// `mode` label carries `shadow`/`enforce`; exactly one series is 1.
    pub enforcement_mode: IntGaugeVec,
    /// SOAR block actions by enforcement mode (`shadow`, `enforce`).
    pub soar_blocks: IntCounterVec,
    /// SOAR unblock / false-positive resolution actions.
    pub soar_unblocks: IntCounterVec,
    /// Emergency DNS RPZ zone rollback operations.
    pub rpz_rollbacks: prometheus::IntCounter,
    /// ML reputation and anomaly evaluation requests.
    pub ml_evaluations: IntCounterVec,
}

impl CollectorMetrics {
    pub fn new() -> Result<Arc<Self>, Box<dyn std::error::Error>> {
        let registry = Registry::new();
        let fetches = IntCounterVec::new(
            Opts::new(
                "threat_intel_fetches_total",
                "Feed collection cycles by outcome",
            ),
            &["source", "result"],
        )?;
        let retries = IntCounterVec::new(
            Opts::new("threat_intel_retries_total", "Retried feed fetch attempts"),
            &["source"],
        )?;
        let indicators = IntCounterVec::new(
            Opts::new(
                "threat_intel_indicators_total",
                "Indicators accepted from feeds",
            ),
            &["source", "kind"],
        )?;
        let dropped = IntCounterVec::new(
            Opts::new(
                "threat_intel_indicators_dropped_total",
                "Indicators dropped as duplicates or over the per-fetch cap",
            ),
            &["source", "reason"],
        )?;
        let last_batch_size = IntGaugeVec::new(
            Opts::new(
                "threat_intel_last_batch_indicators",
                "Indicators in the latest snapshot of a source",
            ),
            &["source"],
        )?;
        let last_success_timestamp = IntGaugeVec::new(
            Opts::new(
                "threat_intel_last_success_timestamp_seconds",
                "Unix time of the last successful collection of a source",
            ),
            &["source"],
        )?;
        let fetch_duration = HistogramVec::new(
            HistogramOpts::new(
                "threat_intel_fetch_duration_seconds",
                "Duration of a feed collection cycle",
            )
            .buckets(vec![0.05, 0.25, 1.0, 5.0, 15.0, 60.0, 300.0]),
            &["source"],
        )?;
        let sink_errors = IntCounterVec::new(
            Opts::new(
                "threat_intel_sink_errors_total",
                "Failures writing collector output",
            ),
            &["source"],
        )?;
        let stored_indicators = IntGaugeVec::new(
            Opts::new(
                "threat_intel_stored_indicators",
                "Active indicators currently in SQLite storage",
            ),
            &["kind"],
        )?;
        let purged_expired = prometheus::IntCounter::new(
            "threat_intel_purged_expired_total",
            "Total expired indicators purged from storage",
        )?;
        let rpz_records = prometheus::IntGauge::new(
            "threat_intel_rpz_records_total",
            "Number of domains compiled into the DNS RPZ zone",
        )?;
        // A gauge rather than a counter: the question a monitor has to answer is
        // "is this installation enforcing right now", which no amount of block
        // counters can express — an enforcing collector nobody calls stays at 0.
        let enforcement_mode = prometheus::IntGaugeVec::new(
            Opts::new(
                "threat_intel_enforcement_mode",
                "1 for the active enforcement mode, 0 for the others (ADR 0008)",
            ),
            &["mode"],
        )?;
        let soar_blocks = IntCounterVec::new(
            Opts::new(
                "threat_intel_soar_blocks_total",
                "SOAR block actions by enforcement mode",
            ),
            &["mode"],
        )?;
        let soar_unblocks = IntCounterVec::new(
            Opts::new(
                "threat_intel_soar_unblocks_total",
                "SOAR unblock / false-positive actions by enforcement mode",
            ),
            &["mode"],
        )?;
        let rpz_rollbacks = prometheus::IntCounter::new(
            "threat_intel_rpz_rollbacks_total",
            "Emergency DNS RPZ zone rollback operations",
        )?;
        let ml_evaluations = IntCounterVec::new(
            Opts::new(
                "threat_intel_ml_evaluations_total",
                "ML reputation, homoglyph, and anomaly evaluations",
            ),
            &["endpoint"],
        )?;

        registry.register(Box::new(fetches.clone()))?;
        registry.register(Box::new(retries.clone()))?;
        registry.register(Box::new(indicators.clone()))?;
        registry.register(Box::new(dropped.clone()))?;
        registry.register(Box::new(last_batch_size.clone()))?;
        registry.register(Box::new(last_success_timestamp.clone()))?;
        registry.register(Box::new(fetch_duration.clone()))?;
        registry.register(Box::new(sink_errors.clone()))?;
        registry.register(Box::new(stored_indicators.clone()))?;
        registry.register(Box::new(purged_expired.clone()))?;
        registry.register(Box::new(rpz_records.clone()))?;
        registry.register(Box::new(soar_blocks.clone()))?;
        registry.register(Box::new(soar_unblocks.clone()))?;
        registry.register(Box::new(rpz_rollbacks.clone()))?;
        registry.register(Box::new(ml_evaluations.clone()))?;
        registry.register(Box::new(enforcement_mode.clone()))?;

        Ok(Arc::new(Self {
            registry,
            fetches,
            retries,
            indicators,
            dropped,
            last_batch_size,
            last_success_timestamp,
            fetch_duration,
            sink_errors,
            stored_indicators,
            purged_expired,
            rpz_records,
            enforcement_mode,
            soar_blocks,
            soar_unblocks,
            rpz_rollbacks,
            ml_evaluations,
        }))
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }
}
