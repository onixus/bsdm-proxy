//! Prometheus metrics for alert-worker.

use prometheus::{
    Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, Opts, Registry,
};
use std::sync::Arc;

pub struct WorkerMetrics {
    registry: Registry,
    pub evaluations: IntCounter,
    pub findings: IntCounterVec,
    pub webhook_sent: IntCounter,
    pub webhook_errors: IntCounter,
    pub dedupe_suppressed: IntCounter,
    pub clickhouse_errors: IntCounter,
    /// Per-rule ClickHouse query latency (successful queries).
    pub clickhouse_query_seconds: HistogramVec,
    /// Failures broken down by rule and error kind (timeout/http/transport/parse).
    pub clickhouse_query_errors: IntCounterVec,
    /// Successful queries slower than `ALERT_CLICKHOUSE_SLOW_QUERY_MS`.
    pub clickhouse_slow_queries: IntCounterVec,
    /// Cycles aborted early because ClickHouse kept failing.
    pub cycles_degraded: IntCounter,
    /// Wall-clock duration of a full evaluation cycle.
    pub cycle_duration_seconds: Histogram,
    /// Unix timestamp of the last cycle that completed without query failures.
    pub last_success_timestamp: IntGauge,
    /// 1 while ClickHouse is considered degraded (backoff active), else 0.
    pub clickhouse_degraded: IntGauge,
}

impl WorkerMetrics {
    pub fn new() -> Result<Arc<Self>, Box<dyn std::error::Error>> {
        let registry = Registry::new();
        let evaluations = IntCounter::with_opts(Opts::new(
            "alert_worker_evaluations_total",
            "Completed rule evaluation cycles",
        ))?;
        let findings = IntCounterVec::new(
            Opts::new(
                "alert_worker_findings_total",
                "Findings produced before dedupe",
            ),
            &["rule"],
        )?;
        let webhook_sent = IntCounter::with_opts(Opts::new(
            "alert_worker_webhook_sent_total",
            "Successful webhook deliveries",
        ))?;
        let webhook_errors = IntCounter::with_opts(Opts::new(
            "alert_worker_webhook_errors_total",
            "Failed webhook deliveries",
        ))?;
        let dedupe_suppressed = IntCounter::with_opts(Opts::new(
            "alert_worker_dedupe_suppressed_total",
            "Findings suppressed by fingerprint cooldown",
        ))?;
        let clickhouse_errors = IntCounter::with_opts(Opts::new(
            "alert_worker_clickhouse_errors_total",
            "ClickHouse query failures",
        ))?;

        let clickhouse_query_seconds = HistogramVec::new(
            HistogramOpts::new(
                "alert_worker_clickhouse_query_seconds",
                "ClickHouse rule query latency in seconds",
            )
            .buckets(vec![
                0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0,
            ]),
            &["rule"],
        )?;
        let clickhouse_query_errors = IntCounterVec::new(
            Opts::new(
                "alert_worker_clickhouse_query_errors_total",
                "ClickHouse query failures by rule and error kind",
            ),
            &["rule", "kind"],
        )?;
        let clickhouse_slow_queries = IntCounterVec::new(
            Opts::new(
                "alert_worker_clickhouse_slow_queries_total",
                "Successful ClickHouse queries above the slow-query threshold",
            ),
            &["rule"],
        )?;
        let cycles_degraded = IntCounter::with_opts(Opts::new(
            "alert_worker_cycles_degraded_total",
            "Evaluation cycles aborted early due to consecutive ClickHouse failures",
        ))?;
        let cycle_duration_seconds = Histogram::with_opts(
            HistogramOpts::new(
                "alert_worker_cycle_duration_seconds",
                "Wall-clock duration of a full evaluation cycle",
            )
            .buckets(vec![
                0.05, 0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0,
            ]),
        )?;
        let last_success_timestamp = IntGauge::with_opts(Opts::new(
            "alert_worker_last_success_timestamp_seconds",
            "Unix timestamp of the last evaluation cycle without query failures",
        ))?;
        let clickhouse_degraded = IntGauge::with_opts(Opts::new(
            "alert_worker_clickhouse_degraded",
            "1 while ClickHouse is degraded and poll backoff is active, else 0",
        ))?;

        registry.register(Box::new(evaluations.clone()))?;
        registry.register(Box::new(findings.clone()))?;
        registry.register(Box::new(webhook_sent.clone()))?;
        registry.register(Box::new(webhook_errors.clone()))?;
        registry.register(Box::new(dedupe_suppressed.clone()))?;
        registry.register(Box::new(clickhouse_errors.clone()))?;
        registry.register(Box::new(clickhouse_query_seconds.clone()))?;
        registry.register(Box::new(clickhouse_query_errors.clone()))?;
        registry.register(Box::new(clickhouse_slow_queries.clone()))?;
        registry.register(Box::new(cycles_degraded.clone()))?;
        registry.register(Box::new(cycle_duration_seconds.clone()))?;
        registry.register(Box::new(last_success_timestamp.clone()))?;
        registry.register(Box::new(clickhouse_degraded.clone()))?;

        Ok(Arc::new(Self {
            registry,
            evaluations,
            findings,
            webhook_sent,
            webhook_errors,
            dedupe_suppressed,
            clickhouse_errors,
            clickhouse_query_seconds,
            clickhouse_query_errors,
            clickhouse_slow_queries,
            cycles_degraded,
            cycle_duration_seconds,
            last_success_timestamp,
            clickhouse_degraded,
        }))
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus::Encoder;

    fn gathered(metrics: &WorkerMetrics) -> String {
        let mut buf = Vec::new();
        prometheus::TextEncoder::new()
            .encode(&metrics.registry().gather(), &mut buf)
            .unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn latency_and_health_series_are_exported() {
        let metrics = WorkerMetrics::new().unwrap();
        metrics
            .clickhouse_query_seconds
            .with_label_values(&["blocked_burst"])
            .observe(0.42);
        metrics
            .clickhouse_query_errors
            .with_label_values(&["blocked_burst", "timeout"])
            .inc();
        metrics
            .clickhouse_slow_queries
            .with_label_values(&["blocked_burst"])
            .inc();
        metrics.cycle_duration_seconds.observe(1.5);
        metrics.last_success_timestamp.set(1_700_000_000);
        metrics.clickhouse_degraded.set(1);

        let text = gathered(&metrics);
        assert!(text.contains("alert_worker_clickhouse_query_seconds_bucket"));
        assert!(text.contains(
            "alert_worker_clickhouse_query_errors_total{kind=\"timeout\",rule=\"blocked_burst\"} 1"
        ));
        assert!(text.contains("alert_worker_clickhouse_slow_queries_total"));
        assert!(text.contains("alert_worker_cycle_duration_seconds_sum 1.5"));
        assert!(text.contains("alert_worker_last_success_timestamp_seconds 1700000000"));
        assert!(text.contains("alert_worker_clickhouse_degraded 1"));
    }
}
