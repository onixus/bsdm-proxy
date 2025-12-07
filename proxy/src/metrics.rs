//! Prometheus metrics for BSDM-Proxy
//!
//! Comprehensive metrics collection for monitoring proxy performance:
//! - Request counters (total, by method, by status)
//! - Cache statistics (hits, misses, hit rate)
//! - Latency histograms (request duration, cache lookup, upstream)
//! - Upstream connection pool metrics
//! - Memory usage and cache size

use prometheus::{
    Counter, CounterVec, Encoder, Gauge, Histogram, HistogramOpts, HistogramVec, Opts, Registry,
    TextEncoder,
};
use std::sync::Arc;

/// Global metrics registry
#[derive(Clone)]
pub struct Metrics {
    pub registry: Registry,

    // Request metrics
    pub requests_total: CounterVec,
    pub requests_in_flight: Gauge,
    pub request_duration_seconds: HistogramVec,
    pub request_size_bytes: Histogram,
    pub response_size_bytes: Histogram,

    // Cache metrics
    pub cache_hits_total: Counter,
    pub cache_misses_total: Counter,
    pub cache_bypasses_total: Counter,
    pub cache_entries: Gauge,
    pub cache_size_bytes: Gauge,
    pub cache_evictions_total: Counter,
    pub cache_lookup_duration_seconds: Histogram,

    // Upstream metrics
    pub upstream_requests_total: CounterVec,
    pub upstream_duration_seconds: HistogramVec,
    pub upstream_errors_total: CounterVec,
    pub upstream_connections_active: Gauge,
    pub upstream_connections_created: Counter,

    // System metrics
    pub kafka_events_sent: Counter,
    pub kafka_send_errors: Counter,
    pub tls_handshakes_total: CounterVec,
}

impl Metrics {
    /// Create new metrics registry with all metrics registered
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let registry = Registry::new();

        // Request metrics
        let requests_total = CounterVec::new(
            Opts::new("bsdm_proxy_requests_total", "Total number of HTTP requests"),
            &["method", "status", "cache_status"],
        )?;
        registry.register(Box::new(requests_total.clone()))?;

        let requests_in_flight = Gauge::new(
            "bsdm_proxy_requests_in_flight",
            "Number of requests currently being processed",
        )?;
        registry.register(Box::new(requests_in_flight.clone()))?;

        let request_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "bsdm_proxy_request_duration_seconds",
                "HTTP request duration in seconds",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ]),
            &["method", "cache_status"],
        )?;
        registry.register(Box::new(request_duration_seconds.clone()))?;

        let request_size_bytes = Histogram::with_opts(HistogramOpts::new(
            "bsdm_proxy_request_size_bytes",
            "HTTP request size in bytes",
        )
        .buckets(vec![
            100.0, 1000.0, 10000.0, 100000.0, 1000000.0, 10000000.0,
        ]))?;
        registry.register(Box::new(request_size_bytes.clone()))?;

        let response_size_bytes = Histogram::with_opts(HistogramOpts::new(
            "bsdm_proxy_response_size_bytes",
            "HTTP response size in bytes",
        )
        .buckets(vec![
            100.0, 1000.0, 10000.0, 100000.0, 1000000.0, 10000000.0,
        ]))?;
        registry.register(Box::new(response_size_bytes.clone()))?;

        // Cache metrics
        let cache_hits_total =
            Counter::new("bsdm_proxy_cache_hits_total", "Total number of cache hits")?;
        registry.register(Box::new(cache_hits_total.clone()))?;

        let cache_misses_total = Counter::new(
            "bsdm_proxy_cache_misses_total",
            "Total number of cache misses",
        )?;
        registry.register(Box::new(cache_misses_total.clone()))?;

        let cache_bypasses_total = Counter::new(
            "bsdm_proxy_cache_bypasses_total",
            "Total number of cache bypasses",
        )?;
        registry.register(Box::new(cache_bypasses_total.clone()))?;

        let cache_entries = Gauge::new(
            "bsdm_proxy_cache_entries",
            "Current number of entries in cache",
        )?;
        registry.register(Box::new(cache_entries.clone()))?;

        let cache_size_bytes =
            Gauge::new("bsdm_proxy_cache_size_bytes", "Current cache size in bytes")?;
        registry.register(Box::new(cache_size_bytes.clone()))?;

        let cache_evictions_total = Counter::new(
            "bsdm_proxy_cache_evictions_total",
            "Total number of cache evictions",
        )?;
        registry.register(Box::new(cache_evictions_total.clone()))?;

        let cache_lookup_duration_seconds = Histogram::with_opts(HistogramOpts::new(
            "bsdm_proxy_cache_lookup_duration_seconds",
            "Cache lookup duration in seconds",
        )
        .buckets(vec![0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01]))?;
        registry.register(Box::new(cache_lookup_duration_seconds.clone()))?;

        // Upstream metrics
        let upstream_requests_total = CounterVec::new(
            Opts::new(
                "bsdm_proxy_upstream_requests_total",
                "Total upstream requests",
            ),
            &["host", "status"],
        )?;
        registry.register(Box::new(upstream_requests_total.clone()))?;

        let upstream_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "bsdm_proxy_upstream_duration_seconds",
                "Upstream request duration in seconds",
            )
            .buckets(vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]),
            &["host"],
        )?;
        registry.register(Box::new(upstream_duration_seconds.clone()))?;

        let upstream_errors_total = CounterVec::new(
            Opts::new("bsdm_proxy_upstream_errors_total", "Total upstream errors"),
            &["host", "error_type"],
        )?;
        registry.register(Box::new(upstream_errors_total.clone()))?;

        let upstream_connections_active = Gauge::new(
            "bsdm_proxy_upstream_connections_active",
            "Number of active upstream connections",
        )?;
        registry.register(Box::new(upstream_connections_active.clone()))?;

        let upstream_connections_created = Counter::new(
            "bsdm_proxy_upstream_connections_created_total",
            "Total upstream connections created",
        )?;
        registry.register(Box::new(upstream_connections_created.clone()))?;

        // System metrics
        let kafka_events_sent = Counter::new(
            "bsdm_proxy_kafka_events_sent_total",
            "Total Kafka events sent",
        )?;
        registry.register(Box::new(kafka_events_sent.clone()))?;

        let kafka_send_errors = Counter::new(
            "bsdm_proxy_kafka_send_errors_total",
            "Total Kafka send errors",
        )?;
        registry.register(Box::new(kafka_send_errors.clone()))?;

        let tls_handshakes_total = CounterVec::new(
            Opts::new("bsdm_proxy_tls_handshakes_total", "Total TLS handshakes"),
            &["status"],
        )?;
        registry.register(Box::new(tls_handshakes_total.clone()))?;

        Ok(Metrics {
            registry,
            requests_total,
            requests_in_flight,
            request_duration_seconds,
            request_size_bytes,
            response_size_bytes,
            cache_hits_total,
            cache_misses_total,
            cache_bypasses_total,
            cache_entries,
            cache_size_bytes,
            cache_evictions_total,
            cache_lookup_duration_seconds,
            upstream_requests_total,
            upstream_duration_seconds,
            upstream_errors_total,
            upstream_connections_active,
            upstream_connections_created,
            kafka_events_sent,
            kafka_send_errors,
            tls_handshakes_total,
        })
    }

    /// Export metrics in Prometheus text format
    pub fn export(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer)?;
        Ok(buffer)
    }

    /// Get cache hit rate (0.0 to 1.0)
    pub fn cache_hit_rate(&self) -> f64 {
        let hits = self.cache_hits_total.get();
        let misses = self.cache_misses_total.get();
        let total = hits + misses;
        if total == 0.0 {
            0.0
        } else {
            hits / total
        }
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new().expect("Failed to create metrics")
    }
}

/// Helper to record request metrics with RAII pattern
pub struct RequestMetricsGuard {
    metrics: Arc<Metrics>,
    start: std::time::Instant,
    method: String,
    cache_status: String,
}

impl RequestMetricsGuard {
    pub fn new(metrics: Arc<Metrics>, method: String) -> Self {
        metrics.requests_in_flight.inc();
        Self {
            metrics,
            start: std::time::Instant::now(),
            method,
            cache_status: "unknown".to_string(),
        }
    }

    pub fn set_cache_status(&mut self, status: &str) {
        self.cache_status = status.to_string();
    }

    pub fn finish(self, status_code: u16, response_size: usize) {
        let duration = self.start.elapsed().as_secs_f64();
        self.metrics.requests_in_flight.dec();
        self.metrics
            .requests_total
            .with_label_values(&[
                &self.method,
                &status_code.to_string(),
                &self.cache_status,
            ])
            .inc();
        self.metrics
            .request_duration_seconds
            .with_label_values(&[&self.method, &self.cache_status])
            .observe(duration);
        self.metrics
            .response_size_bytes
            .observe(response_size as f64);
    }
}
