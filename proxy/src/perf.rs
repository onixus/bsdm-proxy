//! Runtime performance tuning (env-driven, no DPDK).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::warn;

/// Deterministic 1-in-N sampler.
///
/// Replaces a per-request `rand::random()` draw: a relaxed `fetch_add` is a
/// single uncontended atomic instruction, and counting instead of sampling
/// makes the rate exact rather than merely expected.
#[derive(Debug, Default)]
struct Sampler {
    counter: AtomicU64,
}

impl Sampler {
    /// `true` for one call in every `rate` (and always when `rate` is 0 or 1).
    #[inline]
    fn admits(&self, rate: u32) -> bool {
        if rate <= 1 {
            return true;
        }
        self.counter
            .fetch_add(1, Ordering::Relaxed)
            .is_multiple_of(u64::from(rate))
    }
}

/// Performance-related settings loaded once at startup.
#[derive(Debug, Clone)]
pub struct PerfConfig {
    /// When true, serve L1/L2 cache hits (HIT, REVALIDATED, NEGATIVE_HIT) before ACL/categorization (#100).
    pub fast_cache_hit: bool,
    /// Number of accept loops bound with SO_REUSEPORT (Linux).
    pub worker_count: usize,
    /// hyper http1 preserve_header_case + title_case_headers.
    pub http_preserve_header_case: bool,
    /// Emit 1 of N cache events to Kafka (0 = all events).
    pub kafka_sample_rate: u32,
    /// Record detailed request histograms for 1 of N requests (0 = all).
    pub metrics_sample_rate: u32,
    /// Stream upstream MISS bodies to the client while buffering for cache (#94).
    pub streaming_miss_enabled: bool,
    /// Collapse concurrent identical GET/HEAD MISSes into one upstream fetch.
    pub miss_coalesce_enabled: bool,
    /// Shared counters backing the two 1-in-N samplers below.
    samplers: Arc<Samplers>,
}

#[derive(Debug, Default)]
struct Samplers {
    kafka: Sampler,
    metrics: Sampler,
}

impl PerfConfig {
    pub fn from_env() -> Self {
        let fast_cache_hit =
            env_bool("PERF_FAST_CACHE_HIT", false) || env_bool("BSM_PERF_MODE", false);

        let worker_count = std::env::var("WORKER_COUNT")
            .ok()
            .and_then(|s| s.parse().ok())
            .filter(|&n| n > 0)
            .unwrap_or(1);

        let http_preserve_header_case = std::env::var("HTTP_PRESERVE_HEADER_CASE")
            .map(|v| env_truthy(&v))
            .unwrap_or(true);

        let kafka_sample_rate = std::env::var("KAFKA_SAMPLE_RATE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let metrics_sample_rate = std::env::var("METRICS_SAMPLE_RATE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let streaming_miss_enabled = env_bool("STREAMING_MISS_ENABLED", true);
        let miss_coalesce_enabled = env_bool("MISS_COALESCE_ENABLED", true);

        Self {
            fast_cache_hit,
            worker_count,
            http_preserve_header_case,
            kafka_sample_rate,
            metrics_sample_rate,
            streaming_miss_enabled,
            miss_coalesce_enabled,
            samplers: Arc::default(),
        }
    }

    /// Whether to record full Prometheus histograms for this request.
    #[inline]
    pub fn record_detailed_metrics(&self) -> bool {
        self.samplers.metrics.admits(self.metrics_sample_rate)
    }

    /// Bench/lab: skip ACL+categorization when serving from cache (HIT / REVALIDATED / NEGATIVE_HIT / L2_HIT).
    pub fn skip_policy_on_cache_serve(&self) -> bool {
        self.fast_cache_hit
    }

    /// Whether to enqueue a cache event to Kafka.
    #[inline]
    pub fn should_emit_kafka_event(&self) -> bool {
        self.samplers.kafka.admits(self.kafka_sample_rate)
    }
}

impl Default for PerfConfig {
    fn default() -> Self {
        Self::from_env()
    }
}

fn env_truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn env_bool(key: &str, default: bool) -> bool {
    std::env::var(key)
        .map(|v| env_truthy(&v))
        .unwrap_or(default)
}

/// Bind one or more listeners. Uses SO_REUSEPORT when `worker_count > 1` (Unix).
pub async fn bind_http_listeners(
    port: u16,
    worker_count: usize,
) -> Result<Vec<TcpListener>, std::io::Error> {
    let addr: SocketAddr = format!("0.0.0.0:{}", port)
        .parse()
        .expect("valid bind addr");

    if worker_count <= 1 {
        let listener = TcpListener::bind(addr).await?;
        return Ok(vec![listener]);
    }

    #[cfg(unix)]
    {
        use tokio::net::TcpSocket;
        let mut listeners = Vec::with_capacity(worker_count);
        for i in 0..worker_count {
            let socket = TcpSocket::new_v4()?;
            socket.set_reuseaddr(true)?;
            if let Err(e) = socket.set_reuseport(true) {
                warn!(
                    "SO_REUSEPORT unavailable (worker {}): {} — falling back to single listener",
                    i, e
                );
                if listeners.is_empty() {
                    let listener = TcpListener::bind(addr).await?;
                    return Ok(vec![listener]);
                }
                break;
            }
            socket.bind(addr)?;
            let listener = socket.listen(4096)?;
            listeners.push(listener);
        }
        if listeners.is_empty() {
            let listener = TcpListener::bind(addr).await?;
            Ok(vec![listener])
        } else {
            Ok(listeners)
        }
    }

    #[cfg(not(unix))]
    {
        let _ = worker_count;
        warn!("WORKER_COUNT > 1 ignored on non-Unix platforms");
        let listener = TcpListener::bind(addr).await?;
        Ok(vec![listener])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kafka_sample_zero_means_always() {
        let cfg = PerfConfig {
            fast_cache_hit: false,
            worker_count: 1,
            http_preserve_header_case: true,
            kafka_sample_rate: 0,
            metrics_sample_rate: 0,
            streaming_miss_enabled: true,
            miss_coalesce_enabled: true,
            samplers: Arc::default(),
        };
        assert!(cfg.should_emit_kafka_event());
        assert!(cfg.record_detailed_metrics());
    }

    #[test]
    fn kafka_sample_rate_never_zero_when_n_is_one() {
        let cfg = PerfConfig {
            fast_cache_hit: false,
            worker_count: 1,
            http_preserve_header_case: true,
            kafka_sample_rate: 1,
            metrics_sample_rate: 0,
            streaming_miss_enabled: true,
            miss_coalesce_enabled: true,
            samplers: Arc::default(),
        };
        assert!(cfg.should_emit_kafka_event());
    }

    #[test]
    fn sampler_admits_exactly_one_in_n() {
        let sampler = Sampler::default();
        let admitted = (0..1_000).filter(|_| sampler.admits(4)).count();
        assert_eq!(admitted, 250);
    }

    #[test]
    fn sampler_admits_everything_for_zero_and_one() {
        let sampler = Sampler::default();
        assert!((0..100).all(|_| sampler.admits(0)));
        assert!((0..100).all(|_| sampler.admits(1)));
    }

    #[test]
    fn sampled_config_drops_the_expected_share() {
        let cfg = PerfConfig {
            fast_cache_hit: false,
            worker_count: 1,
            http_preserve_header_case: true,
            kafka_sample_rate: 10,
            metrics_sample_rate: 0,
            streaming_miss_enabled: true,
            miss_coalesce_enabled: true,
            samplers: Arc::default(),
        };
        let emitted = (0..1_000).filter(|_| cfg.should_emit_kafka_event()).count();
        assert_eq!(emitted, 100);
        // The two samplers are independent counters.
        assert!(cfg.record_detailed_metrics());
    }
}
