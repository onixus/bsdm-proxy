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
    pub cache_coalesced_total: Counter,
    pub semantic_cache_exact_hits_total: Counter,
    pub semantic_cache_similar_hits_total: Counter,
    pub semantic_cache_vector_errors_total: Counter,
    pub cache_bypasses_total: Counter,
    pub cache_entries: Gauge,
    pub cache_size_bytes: Gauge,
    #[allow(dead_code)]
    pub cache_evictions_total: Counter,
    pub cache_lookup_duration_seconds: Histogram,

    // L2 Redis cache metrics
    pub cache_l2_hits_total: Counter,
    pub cache_l2_misses_total: Counter,
    pub cache_l2_errors_total: Counter,

    // Upstream metrics
    pub upstream_requests_total: CounterVec,
    pub upstream_duration_seconds: HistogramVec,
    pub upstream_errors_total: CounterVec,
    pub upstream_connections_active: Gauge,
    pub upstream_connections_created: Counter,

    // System metrics
    pub kafka_events_sent: Counter,
    pub kafka_send_errors: Counter,
    pub kafka_queue_dropped_total: Counter,
    pub tls_handshakes_total: CounterVec,

    // ACL metrics
    pub acl_decisions_total: CounterVec,
    pub acl_rules_matched_total: CounterVec,
    pub acl_eval_duration_seconds: Histogram,
    pub policy_cache_hit_total: Counter,

    // Rate limit metrics
    pub rate_limit_rejected_total: CounterVec,

    /// Requests that used the lightweight metrics fast path (no histograms).
    pub requests_fast_total: Counter,

    // Hierarchy metrics (M2)
    pub hierarchy_resolutions_total: CounterVec,
    pub hierarchy_peer_requests_total: CounterVec,
    pub hierarchy_icp_queries_total: CounterVec,
    pub hierarchy_digest_skipped_total: Counter,
    pub hierarchy_lookup_duration_seconds: Histogram,

    // Categorization metrics (M4 / #105)
    /// Lookups on the hot path: `source` = ut1|custom|cache|unknown|none, `result` = hit|miss.
    pub categorization_lookups_total: CounterVec,
    pub categorization_cache_hits_total: Counter,
    pub categorization_cache_misses_total: Counter,
    pub categorization_duration_seconds: Histogram,
    /// Category labels observed on a lookup (local DB / cache hit).
    pub categorization_category_total: CounterVec,
    /// Policy deny/redirect while URL had these categories.
    pub categorization_blocked_total: CounterVec,
    /// Background URLhaus/PhishTank enrich tasks scheduled.
    pub categorization_online_enrich_scheduled_total: Counter,
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

        let request_size_bytes = Histogram::with_opts(
            HistogramOpts::new(
                "bsdm_proxy_request_size_bytes",
                "HTTP request size in bytes",
            )
            .buckets(vec![
                100.0, 1000.0, 10000.0, 100000.0, 1000000.0, 10000000.0,
            ]),
        )?;
        registry.register(Box::new(request_size_bytes.clone()))?;

        let response_size_bytes = Histogram::with_opts(
            HistogramOpts::new(
                "bsdm_proxy_response_size_bytes",
                "HTTP response size in bytes",
            )
            .buckets(vec![
                100.0, 1000.0, 10000.0, 100000.0, 1000000.0, 10000000.0,
            ]),
        )?;
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

        let cache_coalesced_total = Counter::new(
            "bsdm_proxy_cache_coalesced_total",
            "Cache MISSes served from a coalesced in-flight fill (singleflight waiters)",
        )?;
        registry.register(Box::new(cache_coalesced_total.clone()))?;

        let semantic_cache_exact_hits_total = Counter::new(
            "bsdm_proxy_semantic_cache_exact_hits_total",
            "LLM POST exact content-hash cache hits",
        )?;
        registry.register(Box::new(semantic_cache_exact_hits_total.clone()))?;

        let semantic_cache_similar_hits_total = Counter::new(
            "bsdm_proxy_semantic_cache_similar_hits_total",
            "LLM POST near-neighbor semantic cache hits (local or vector backend)",
        )?;
        registry.register(Box::new(semantic_cache_similar_hits_total.clone()))?;

        let semantic_cache_vector_errors_total = Counter::new(
            "bsdm_proxy_semantic_cache_vector_errors_total",
            "Semantic embed / vector backend errors (insert or search)",
        )?;
        registry.register(Box::new(semantic_cache_vector_errors_total.clone()))?;

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

        let cache_lookup_duration_seconds = Histogram::with_opts(
            HistogramOpts::new(
                "bsdm_proxy_cache_lookup_duration_seconds",
                "Cache lookup duration in seconds",
            )
            .buckets(vec![0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01]),
        )?;
        registry.register(Box::new(cache_lookup_duration_seconds.clone()))?;

        let cache_l2_hits_total = Counter::new(
            "bsdm_proxy_cache_l2_hits_total",
            "Total Redis L2 cache hits",
        )?;
        registry.register(Box::new(cache_l2_hits_total.clone()))?;

        let cache_l2_misses_total = Counter::new(
            "bsdm_proxy_cache_l2_misses_total",
            "Total Redis L2 cache misses",
        )?;
        registry.register(Box::new(cache_l2_misses_total.clone()))?;

        let cache_l2_errors_total = Counter::new(
            "bsdm_proxy_cache_l2_errors_total",
            "Total Redis L2 cache errors",
        )?;
        registry.register(Box::new(cache_l2_errors_total.clone()))?;

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

        let kafka_queue_dropped_total = Counter::new(
            "bsdm_proxy_kafka_queue_dropped_total",
            "Kafka events dropped because the in-memory queue was full",
        )?;
        registry.register(Box::new(kafka_queue_dropped_total.clone()))?;

        let tls_handshakes_total = CounterVec::new(
            Opts::new("bsdm_proxy_tls_handshakes_total", "Total TLS handshakes"),
            &["status"],
        )?;
        registry.register(Box::new(tls_handshakes_total.clone()))?;

        let acl_decisions_total = CounterVec::new(
            Opts::new("bsdm_proxy_acl_decisions_total", "Total ACL decisions"),
            &["action"],
        )?;
        registry.register(Box::new(acl_decisions_total.clone()))?;

        let acl_rules_matched_total = CounterVec::new(
            Opts::new("bsdm_proxy_acl_rules_matched_total", "ACL rules matched"),
            &["rule_id"],
        )?;
        registry.register(Box::new(acl_rules_matched_total.clone()))?;

        let acl_eval_duration_seconds = Histogram::with_opts(
            HistogramOpts::new(
                "bsdm_proxy_acl_eval_duration_seconds",
                "ACL evaluation duration in seconds",
            )
            .buckets(vec![0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01]),
        )?;
        registry.register(Box::new(acl_eval_duration_seconds.clone()))?;

        let policy_cache_hit_total = Counter::new(
            "bsdm_proxy_policy_cache_hit_total",
            "Policy decision cache hits (ACL+categorization skipped)",
        )?;
        registry.register(Box::new(policy_cache_hit_total.clone()))?;

        let rate_limit_rejected_total = CounterVec::new(
            Opts::new(
                "bsdm_proxy_rate_limit_rejected_total",
                "Total requests rejected by rate limiting",
            ),
            &["limit_type"],
        )?;
        registry.register(Box::new(rate_limit_rejected_total.clone()))?;

        let requests_fast_total = Counter::new(
            "bsdm_proxy_requests_fast_total",
            "HTTP requests completed on the lightweight metrics fast path",
        )?;
        registry.register(Box::new(requests_fast_total.clone()))?;

        let hierarchy_resolutions_total = CounterVec::new(
            Opts::new(
                "bsdm_proxy_hierarchy_resolutions_total",
                "Hierarchy source resolution outcomes",
            ),
            &["result"],
        )?;
        registry.register(Box::new(hierarchy_resolutions_total.clone()))?;

        let hierarchy_peer_requests_total = CounterVec::new(
            Opts::new(
                "bsdm_proxy_hierarchy_peer_requests_total",
                "HTTP fetches to parent/sibling cache peers",
            ),
            &["peer_type", "outcome"],
        )?;
        registry.register(Box::new(hierarchy_peer_requests_total.clone()))?;

        let hierarchy_icp_queries_total = CounterVec::new(
            Opts::new(
                "bsdm_proxy_hierarchy_icp_queries_total",
                "ICP UDP queries to sibling caches",
            ),
            &["outcome"],
        )?;
        registry.register(Box::new(hierarchy_icp_queries_total.clone()))?;

        let hierarchy_digest_skipped_total = Counter::new(
            "bsdm_proxy_hierarchy_digest_skipped_icp_total",
            "Sibling ICP/HTCP queries skipped by cache digest filter",
        )?;
        registry.register(Box::new(hierarchy_digest_skipped_total.clone()))?;

        let hierarchy_lookup_duration_seconds = Histogram::with_opts(
            HistogramOpts::new(
                "bsdm_proxy_hierarchy_lookup_duration_seconds",
                "Time to resolve hierarchy source (ICP + parent selection)",
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]),
        )?;
        registry.register(Box::new(hierarchy_lookup_duration_seconds.clone()))?;

        let categorization_lookups_total = CounterVec::new(
            Opts::new(
                "bsdm_proxy_categorization_lookups_total",
                "URL categorization lookups on the hot path",
            ),
            &["source", "result"],
        )?;
        registry.register(Box::new(categorization_lookups_total.clone()))?;

        let categorization_cache_hits_total = Counter::new(
            "bsdm_proxy_categorization_cache_hits_total",
            "In-memory categorization cache hits",
        )?;
        registry.register(Box::new(categorization_cache_hits_total.clone()))?;

        let categorization_cache_misses_total = Counter::new(
            "bsdm_proxy_categorization_cache_misses_total",
            "In-memory categorization cache misses",
        )?;
        registry.register(Box::new(categorization_cache_misses_total.clone()))?;

        let categorization_duration_seconds = Histogram::with_opts(
            HistogramOpts::new(
                "bsdm_proxy_categorization_duration_seconds",
                "Hot-path categorize_local duration in seconds",
            )
            .buckets(vec![
                0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05,
            ]),
        )?;
        registry.register(Box::new(categorization_duration_seconds.clone()))?;

        let categorization_category_total = CounterVec::new(
            Opts::new(
                "bsdm_proxy_categorization_category_total",
                "Categories returned by categorization lookups",
            ),
            &["category"],
        )?;
        registry.register(Box::new(categorization_category_total.clone()))?;

        let categorization_blocked_total = CounterVec::new(
            Opts::new(
                "bsdm_proxy_categorization_blocked_total",
                "ACL deny/redirect decisions with categorized URLs",
            ),
            &["category", "action"],
        )?;
        registry.register(Box::new(categorization_blocked_total.clone()))?;

        let categorization_online_enrich_scheduled_total = Counter::new(
            "bsdm_proxy_categorization_online_enrich_scheduled_total",
            "Background URLhaus/PhishTank enrichment tasks scheduled",
        )?;
        registry.register(Box::new(
            categorization_online_enrich_scheduled_total.clone(),
        ))?;

        Ok(Metrics {
            registry,
            requests_total,
            requests_in_flight,
            request_duration_seconds,
            request_size_bytes,
            response_size_bytes,
            cache_hits_total,
            cache_misses_total,
            cache_coalesced_total,
            semantic_cache_exact_hits_total,
            semantic_cache_similar_hits_total,
            semantic_cache_vector_errors_total,
            cache_bypasses_total,
            cache_entries,
            cache_size_bytes,
            cache_evictions_total,
            cache_lookup_duration_seconds,
            cache_l2_hits_total,
            cache_l2_misses_total,
            cache_l2_errors_total,
            upstream_requests_total,
            upstream_duration_seconds,
            upstream_errors_total,
            upstream_connections_active,
            upstream_connections_created,
            kafka_events_sent,
            kafka_send_errors,
            kafka_queue_dropped_total,
            tls_handshakes_total,
            acl_decisions_total,
            acl_rules_matched_total,
            acl_eval_duration_seconds,
            policy_cache_hit_total,
            rate_limit_rejected_total,
            requests_fast_total,
            hierarchy_resolutions_total,
            hierarchy_peer_requests_total,
            hierarchy_icp_queries_total,
            hierarchy_digest_skipped_total,
            hierarchy_lookup_duration_seconds,
            categorization_lookups_total,
            categorization_cache_hits_total,
            categorization_cache_misses_total,
            categorization_duration_seconds,
            categorization_category_total,
            categorization_blocked_total,
            categorization_online_enrich_scheduled_total,
        })
    }

    pub fn record_categorization_lookup(
        &self,
        source: &str,
        from_cache: bool,
        categories: &[String],
        duration_secs: f64,
    ) {
        let result = if categories.is_empty() { "miss" } else { "hit" };
        self.categorization_lookups_total
            .with_label_values(&[source, result])
            .inc();
        if from_cache {
            self.categorization_cache_hits_total.inc();
        } else {
            self.categorization_cache_misses_total.inc();
        }
        self.categorization_duration_seconds.observe(duration_secs);
        for cat in categories {
            self.categorization_category_total
                .with_label_values(&[cat])
                .inc();
        }
    }

    pub fn record_categorization_blocked(&self, categories: &[String], action: &str) {
        if categories.is_empty() {
            self.categorization_blocked_total
                .with_label_values(&["none", action])
                .inc();
            return;
        }
        for cat in categories {
            self.categorization_blocked_total
                .with_label_values(&[cat, action])
                .inc();
        }
    }

    pub fn record_categorization_online_enrich_scheduled(&self) {
        self.categorization_online_enrich_scheduled_total.inc();
    }

    pub fn record_hierarchy_resolution(&self, result: &str) {
        self.hierarchy_resolutions_total
            .with_label_values(&[result])
            .inc();
    }

    pub fn record_hierarchy_peer_request(&self, peer_type: &str, outcome: &str) {
        self.hierarchy_peer_requests_total
            .with_label_values(&[peer_type, outcome])
            .inc();
    }

    pub fn record_hierarchy_icp_query(&self, outcome: &str) {
        self.hierarchy_icp_queries_total
            .with_label_values(&[outcome])
            .inc();
    }

    pub fn record_hierarchy_digest_skip(&self) {
        self.hierarchy_digest_skipped_total.inc();
    }

    pub fn observe_hierarchy_lookup(&self, duration_secs: f64) {
        self.hierarchy_lookup_duration_seconds
            .observe(duration_secs);
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

    pub fn finish(self, status_code: u16, request_size: usize, response_size: usize) {
        let duration = self.start.elapsed().as_secs_f64();
        self.metrics.requests_in_flight.dec();
        self.metrics
            .requests_total
            .with_label_values(&[&self.method, &status_code.to_string(), &self.cache_status])
            .inc();
        self.metrics
            .request_duration_seconds
            .with_label_values(&[&self.method, &self.cache_status])
            .observe(duration);
        self.metrics.request_size_bytes.observe(request_size as f64);
        self.metrics
            .response_size_bytes
            .observe(response_size as f64);
    }
}

/// Lightweight in-flight tracking without per-request histograms.
pub struct FastRequestScope {
    metrics: Arc<Metrics>,
}

impl FastRequestScope {
    pub fn begin(metrics: Arc<Metrics>) -> Self {
        metrics.requests_in_flight.inc();
        Self { metrics }
    }

    pub fn finish_cache_hit(self) {
        self.metrics.requests_in_flight.dec();
        self.metrics.cache_hits_total.inc();
        self.metrics.requests_fast_total.inc();
    }

    pub fn finish(self, status_code: u16) {
        self.metrics.requests_in_flight.dec();
        let _ = status_code;
        self.metrics.requests_fast_total.inc();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hierarchy_metrics_exported() {
        let m = Metrics::new().unwrap();
        m.record_hierarchy_resolution("parent_hit");
        m.record_hierarchy_icp_query("hit");
        m.record_hierarchy_peer_request("parent", "hit");
        let out = String::from_utf8(m.export().unwrap()).unwrap();
        assert!(out.contains("bsdm_proxy_hierarchy_resolutions_total"));
        assert!(out.contains("bsdm_proxy_hierarchy_icp_queries_total"));
        assert!(out.contains("bsdm_proxy_hierarchy_peer_requests_total"));
        assert!(out.contains("parent_hit"));
    }

    #[test]
    fn categorization_metrics_exported() {
        let m = Metrics::new().unwrap();
        m.record_categorization_lookup("ut1", false, &["malware".to_string()], 0.0002);
        m.record_categorization_lookup("cache", true, &["news".to_string()], 0.00005);
        m.record_categorization_blocked(&["malware".to_string()], "deny");
        m.record_categorization_online_enrich_scheduled();
        let out = String::from_utf8(m.export().unwrap()).unwrap();
        assert!(out.contains("bsdm_proxy_categorization_lookups_total"));
        assert!(out.contains("bsdm_proxy_categorization_cache_hits_total"));
        assert!(out.contains("bsdm_proxy_categorization_duration_seconds"));
        assert!(out.contains("bsdm_proxy_categorization_blocked_total"));
        assert!(out.contains("bsdm_proxy_categorization_online_enrich_scheduled_total"));
        assert!(out.contains(r#"category="malware""#));
    }
}
