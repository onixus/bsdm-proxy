//! Prometheus metrics for cache-indexer backends.

use prometheus::{
    CounterVec, Histogram, HistogramOpts, IntCounter, IntGauge, Opts, Registry,
};
use std::time::Instant;

#[derive(Clone)]
#[allow(dead_code)]
pub struct IndexerMetrics {
    registry: Registry,
    pub inserts_total: CounterVec,
    pub insert_errors_total: CounterVec,
    pub batch_duration_seconds: Histogram,
    pub sqlite_writer_queue_depth: IntGauge,
    pub sqlite_writer_saturation_total: IntCounter,
    pub sqlite_writer_errors_total: IntCounter,
    pub sqlite_writer_batch_events: Histogram,
    pub sqlite_writer_batch_requests: Histogram,
    pub sqlite_writer_commit_duration_seconds: Histogram,
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
            "Time spent flushing an event batch to a backend",
        ))?;
        let sqlite_writer_queue_depth = IntGauge::new(
            "cache_indexer_sqlite_writer_queue_depth",
            "SQLite write requests waiting in the bounded writer queue",
        )?;
        let sqlite_writer_saturation_total = IntCounter::new(
            "cache_indexer_sqlite_writer_saturation_total",
            "SQLite writes that encountered a full writer queue and had to wait",
        )?;
        let sqlite_writer_errors_total = IntCounter::new(
            "cache_indexer_sqlite_writer_errors_total",
            "SQLite writer transaction failures",
        )?;
        let sqlite_writer_batch_events = Histogram::with_opts(
            HistogramOpts::new(
                "cache_indexer_sqlite_writer_batch_events",
                "Number of events committed by one SQLite writer transaction",
            )
            .buckets(vec![1.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1_000.0, 5_000.0]),
        )?;
        let sqlite_writer_batch_requests = Histogram::with_opts(
            HistogramOpts::new(
                "cache_indexer_sqlite_writer_batch_requests",
                "Number of queued ingest requests coalesced into one SQLite transaction",
            )
            .buckets(vec![1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0]),
        )?;
        let sqlite_writer_commit_duration_seconds = Histogram::with_opts(
            HistogramOpts::new(
                "cache_indexer_sqlite_writer_commit_duration_seconds",
                "Time spent executing and committing a SQLite writer transaction",
            )
            .buckets(vec![
                0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0,
                2.5, 5.0,
            ]),
        )?;

        registry.register(Box::new(inserts_total.clone()))?;
        registry.register(Box::new(insert_errors_total.clone()))?;
        registry.register(Box::new(batch_duration_seconds.clone()))?;
        registry.register(Box::new(sqlite_writer_queue_depth.clone()))?;
        registry.register(Box::new(sqlite_writer_saturation_total.clone()))?;
        registry.register(Box::new(sqlite_writer_errors_total.clone()))?;
        registry.register(Box::new(sqlite_writer_batch_events.clone()))?;
        registry.register(Box::new(sqlite_writer_batch_requests.clone()))?;
        registry.register(Box::new(sqlite_writer_commit_duration_seconds.clone()))?;

        Ok(Self {
            registry,
            inserts_total,
            insert_errors_total,
            batch_duration_seconds,
            sqlite_writer_queue_depth,
            sqlite_writer_saturation_total,
            sqlite_writer_errors_total,
            sqlite_writer_batch_events,
            sqlite_writer_batch_requests,
            sqlite_writer_commit_duration_seconds,
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

    pub fn set_sqlite_writer_queue_depth(&self, depth: usize) {
        self.sqlite_writer_queue_depth.set(depth as i64);
    }

    pub fn record_sqlite_writer_saturation(&self) {
        self.sqlite_writer_saturation_total.inc();
    }

    pub fn record_sqlite_writer_batch(
        &self,
        requests: usize,
        events: usize,
        started: Instant,
        success: bool,
    ) {
        self.sqlite_writer_batch_requests.observe(requests as f64);
        self.sqlite_writer_batch_events.observe(events as f64);
        self.sqlite_writer_commit_duration_seconds
            .observe(started.elapsed().as_secs_f64());
        if !success {
            self.sqlite_writer_errors_total.inc();
        }
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }
}
