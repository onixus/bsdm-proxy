//! Prometheus metrics for alert-worker.

use prometheus::{IntCounter, IntCounterVec, Opts, Registry};
use std::sync::Arc;

pub struct WorkerMetrics {
    registry: Registry,
    pub evaluations: IntCounter,
    pub findings: IntCounterVec,
    pub webhook_sent: IntCounter,
    pub webhook_errors: IntCounter,
    pub dedupe_suppressed: IntCounter,
    pub clickhouse_errors: IntCounter,
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

        registry.register(Box::new(evaluations.clone()))?;
        registry.register(Box::new(findings.clone()))?;
        registry.register(Box::new(webhook_sent.clone()))?;
        registry.register(Box::new(webhook_errors.clone()))?;
        registry.register(Box::new(dedupe_suppressed.clone()))?;
        registry.register(Box::new(clickhouse_errors.clone()))?;

        Ok(Arc::new(Self {
            registry,
            evaluations,
            findings,
            webhook_sent,
            webhook_errors,
            dedupe_suppressed,
            clickhouse_errors,
        }))
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }
}
