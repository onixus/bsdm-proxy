//! Prometheus metrics for ml-worker.

use prometheus::{IntCounter, IntGauge, Opts, Registry, TextEncoder, Encoder};
use std::sync::Arc;

#[derive(Clone)]
pub struct WorkerMetrics {
    pub registry: Arc<Registry>,
    pub cycles: IntCounter,
    pub features_written: IntCounter,
    pub scores_written: IntCounter,
    pub webhooks_sent: IntCounter,
    pub errors: IntCounter,
    pub last_cycle_features: IntGauge,
}

impl WorkerMetrics {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let registry = Registry::new();
        let cycles = IntCounter::with_opts(Opts::new(
            "bsdm_ml_worker_cycles_total",
            "Completed extract/score cycles",
        ))?;
        let features_written = IntCounter::with_opts(Opts::new(
            "bsdm_ml_worker_features_written_total",
            "Rows inserted into entity_features",
        ))?;
        let scores_written = IntCounter::with_opts(Opts::new(
            "bsdm_ml_worker_scores_written_total",
            "Rows inserted into ml_scores",
        ))?;
        let webhooks_sent = IntCounter::with_opts(Opts::new(
            "bsdm_ml_worker_webhooks_sent_total",
            "Webhook POSTs for high scores",
        ))?;
        let errors = IntCounter::with_opts(Opts::new(
            "bsdm_ml_worker_errors_total",
            "Failed cycles or CH/webhook errors",
        ))?;
        let last_cycle_features = IntGauge::with_opts(Opts::new(
            "bsdm_ml_worker_last_cycle_features",
            "Feature rows in the last successful cycle",
        ))?;
        registry.register(Box::new(cycles.clone()))?;
        registry.register(Box::new(features_written.clone()))?;
        registry.register(Box::new(scores_written.clone()))?;
        registry.register(Box::new(webhooks_sent.clone()))?;
        registry.register(Box::new(errors.clone()))?;
        registry.register(Box::new(last_cycle_features.clone()))?;
        Ok(Self {
            registry: Arc::new(registry),
            cycles,
            features_written,
            scores_written,
            webhooks_sent,
            errors,
            last_cycle_features,
        })
    }

    pub fn encode(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut buf = Vec::new();
        TextEncoder::new().encode(&self.registry.gather(), &mut buf)?;
        Ok(String::from_utf8(buf)?)
    }
}
