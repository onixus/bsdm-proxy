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

        registry.register(Box::new(fetches.clone()))?;
        registry.register(Box::new(retries.clone()))?;
        registry.register(Box::new(indicators.clone()))?;
        registry.register(Box::new(dropped.clone()))?;
        registry.register(Box::new(last_batch_size.clone()))?;
        registry.register(Box::new(last_success_timestamp.clone()))?;
        registry.register(Box::new(fetch_duration.clone()))?;
        registry.register(Box::new(sink_errors.clone()))?;

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
        }))
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }
}
