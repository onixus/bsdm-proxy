//! Prometheus metrics for cache-indexer backends.

use prometheus::{CounterVec, Histogram, HistogramOpts, Opts, Registry};
use std::time::Instant;

#[derive(Clone)]
#[allow(dead_code)]
pub struct IndexerMetrics {
    registry: Registry,
    pub inserts_total: CounterVec,
    pub insert_errors_total: CounterVec,
    pub batch_duration_seconds: Histogram,
}

#[allow(dead_code)]
impl IndexerMetrics {
    pub fn new() -> Result<Self, prometheus::Error> {
        let registry = Registry::new();
        let inserts_total = CounterVec::new(
            Opts::new(
                "cache_indexer_inserts_total",
                "Cache events successfully indexed per backend",
            ),
            &["backend"],
        )?;
        let insert_errors_total = CounterVec::new(
            Opts::new(
                "cache_indexer_insert_errors_total",
                "Cache indexer insert failures per backend",
            ),
            &["backend"],
        )?;
        let batch_duration_seconds = Histogram::with_opts(HistogramOpts::new(
            "cache_indexer_batch_duration_seconds",
            "Time spent flushing a Kafka batch to a backend",
        ))?;

        registry.register(Box::new(inserts_total.clone()))?;
        registry.register(Box::new(insert_errors_total.clone()))?;
        registry.register(Box::new(batch_duration_seconds.clone()))?;

        Ok(Self {
            registry,
            inserts_total,
            insert_errors_total,
            batch_duration_seconds,
        })
    }

    pub fn record_success(&self, backend: &str, count: usize, started: Instant) {
        self.inserts_total
            .with_label_values(&[backend])
            .inc_by(count as f64);
        self.batch_duration_seconds
            .observe(started.elapsed().as_secs_f64());
    }

    pub fn record_error(&self, backend: &str) {
        self.insert_errors_total.with_label_values(&[backend]).inc();
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }
}
