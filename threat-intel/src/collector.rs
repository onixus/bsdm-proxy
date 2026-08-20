//! Scheduling and error handling around the feed source plugins.

use crate::config::Config;
use crate::http::FeedHttpClient;
use crate::indicator::RawIndicator;
use crate::metrics::CollectorMetrics;
use crate::sink::{CollectionReport, IndicatorSink, SourceReport};
use crate::source::{dedupe_batch, FeedError, FeedSource};
use chrono::Utc;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tracing::{info, warn};

/// Everything a collection task needs, shared across per-source tasks.
pub struct Collector {
    config: Config,
    http: FeedHttpClient,
    sink: Arc<dyn IndicatorSink>,
    metrics: Arc<CollectorMetrics>,
    report: Mutex<CollectionReport>,
}

impl Collector {
    pub fn new(
        config: Config,
        http: FeedHttpClient,
        sink: Arc<dyn IndicatorSink>,
        metrics: Arc<CollectorMetrics>,
    ) -> Self {
        Self {
            config,
            http,
            sink,
            metrics,
            report: Mutex::new(CollectionReport::default()),
        }
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Fetch, parse and persist one source. A failing source never aborts the
    /// run: the error is recorded and the next cycle retries it.
    pub async fn collect(&self, source: &dyn FeedSource) -> Result<usize, FeedError> {
        let name = source.name();
        let started = Instant::now();
        let mut attempts = 0u32;

        let outcome = loop {
            attempts += 1;
            match self.attempt(source).await {
                Ok(indicators) => break Ok(indicators),
                Err(err) => {
                    if attempts >= self.config.max_attempts || !err.is_retryable() {
                        break Err(err);
                    }
                    let delay = self.config.backoff_for(attempts);
                    warn!(
                        source = name,
                        attempt = attempts,
                        backoff_secs = delay.as_secs(),
                        "feed fetch failed, retrying: {err}"
                    );
                    self.metrics.retries.with_label_values(&[name]).inc();
                    tokio::time::sleep(delay).await;
                }
            }
        };

        let elapsed = started.elapsed();
        self.metrics
            .fetch_duration
            .with_label_values(&[name])
            .observe(elapsed.as_secs_f64());

        let result = match outcome {
            Ok(indicators) => {
                let count = indicators.len();
                for indicator in &indicators {
                    self.metrics
                        .indicators
                        .with_label_values(&[name, indicator.kind.as_str()])
                        .inc();
                }
                if let Err(e) = self.sink.write_batch(name, &indicators) {
                    self.metrics.sink_errors.with_label_values(&[name]).inc();
                    warn!(source = name, "failed to write snapshot: {e}");
                    Err(FeedError::Parse(format!("sink write failed: {e}")))
                } else {
                    self.metrics
                        .last_batch_size
                        .with_label_values(&[name])
                        .set(count as i64);
                    self.metrics
                        .last_success_timestamp
                        .with_label_values(&[name])
                        .set(Utc::now().timestamp());
                    info!(
                        source = name,
                        indicators = count,
                        attempts,
                        duration_ms = elapsed.as_millis() as u64,
                        "collected feed"
                    );
                    Ok(count)
                }
            }
            Err(err) => Err(err),
        };

        let (status, indicators, error) = match &result {
            Ok(count) => ("ok", *count, None),
            Err(err) => (err.metric_label(), 0, Some(err.to_string())),
        };
        self.metrics
            .fetches
            .with_label_values(&[name, status])
            .inc();
        if let Err(err) = &result {
            warn!(source = name, attempts, "feed collection failed: {err}");
        }

        self.record(SourceReport {
            source: name.to_string(),
            url: source.url().to_string(),
            status,
            indicators,
            duration_ms: elapsed.as_millis(),
            attempts,
            finished_at: Utc::now(),
            error,
        });

        result
    }

    async fn attempt(&self, source: &dyn FeedSource) -> Result<Vec<RawIndicator>, FeedError> {
        let body = self.http.fetch(source).await?;
        let parsed = source.parse(&body)?;
        Ok(self.post_process(source.name(), parsed))
    }

    /// Intra-batch dedupe plus the per-fetch cap that keeps a runaway feed from
    /// filling the disk.
    fn post_process(&self, name: &str, parsed: Vec<RawIndicator>) -> Vec<RawIndicator> {
        let parsed_len = parsed.len();
        let mut indicators = dedupe_batch(parsed);
        let duplicates = parsed_len - indicators.len();
        if duplicates > 0 {
            self.metrics
                .dropped
                .with_label_values(&[name, "duplicate"])
                .inc_by(duplicates as u64);
        }
        if indicators.len() > self.config.max_indicators_per_fetch {
            let overflow = indicators.len() - self.config.max_indicators_per_fetch;
            warn!(
                source = name,
                cap = self.config.max_indicators_per_fetch,
                dropped = overflow,
                "feed exceeded the per-fetch indicator cap"
            );
            indicators.truncate(self.config.max_indicators_per_fetch);
            self.metrics
                .dropped
                .with_label_values(&[name, "over_cap"])
                .inc_by(overflow as u64);
        }
        indicators
    }

    fn record(&self, entry: SourceReport) {
        let snapshot = {
            let mut report = match self.report.lock() {
                Ok(report) => report,
                Err(poisoned) => poisoned.into_inner(),
            };
            report.record(entry);
            report.clone()
        };
        if let Err(e) = self.sink.write_report(&snapshot) {
            warn!("failed to write collector report: {e}");
        }
    }

    pub fn report(&self) -> CollectionReport {
        match self.report.lock() {
            Ok(report) => report.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

/// Collect every source once, sequentially, so a one-shot run has a
/// deterministic exit code: `Ok(())` only when every source succeeded.
pub async fn run_once(
    collector: Arc<Collector>,
    sources: Vec<Box<dyn FeedSource>>,
) -> Result<(), String> {
    let mut failed = Vec::new();
    for source in &sources {
        if collector.collect(source.as_ref()).await.is_err() {
            failed.push(source.name());
        }
    }

    let report = collector.report();
    let total: usize = report.sources.iter().map(|s| s.indicators).sum();
    info!(
        sources = report.sources.len(),
        indicators = total,
        failed = failed.len(),
        "one-shot collection finished"
    );

    if failed.is_empty() {
        Ok(())
    } else {
        Err(format!("sources failed: {}", failed.join(", ")))
    }
}

/// Spawn one scheduled task per source. Sources run independently so a slow or
/// broken feed cannot delay the others.
pub fn spawn_scheduled(
    collector: Arc<Collector>,
    sources: Vec<Box<dyn FeedSource>>,
) -> Vec<tokio::task::JoinHandle<()>> {
    let interval = collector.config().poll_interval;
    sources
        .into_iter()
        .map(|source| {
            let collector = collector.clone();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(interval);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    ticker.tick().await;
                    let _ = collector.collect(source.as_ref()).await;
                }
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::indicator::{IndicatorKind, RawIndicator};
    use crate::sink::JsonlFileSink;
    use std::path::PathBuf;
    use std::time::Duration;

    struct StaticSource {
        url: String,
    }

    impl FeedSource for StaticSource {
        fn name(&self) -> &'static str {
            "openphish"
        }
        fn url(&self) -> &str {
            &self.url
        }
        fn weight(&self) -> u8 {
            90
        }
        fn parse(&self, body: &str) -> Result<Vec<RawIndicator>, FeedError> {
            let out: Vec<RawIndicator> = body
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| RawIndicator::new(l.trim(), IndicatorKind::Url, self))
                .collect();
            if out.is_empty() {
                return Err(FeedError::Empty);
            }
            Ok(out)
        }
    }

    fn test_config(dir: &std::path::Path, cap: usize) -> Config {
        Config {
            sources: vec!["openphish".into()],
            poll_interval: Duration::from_secs(900),
            http_timeout: Duration::from_secs(5),
            max_attempts: 1,
            retry_backoff: Duration::from_secs(1),
            max_body_bytes: 1024 * 1024,
            max_indicators_per_fetch: cap,
            output_dir: PathBuf::from(dir),
            user_agent: "test".into(),
            metrics_port: 0,
            run_once: true,
        }
    }

    fn collector(dir: &std::path::Path, cap: usize) -> Collector {
        let sink = Arc::new(JsonlFileSink::new(dir).unwrap());
        Collector::new(
            test_config(dir, cap),
            FeedHttpClient::new(Duration::from_secs(5), 1024 * 1024, "test").unwrap(),
            sink,
            CollectorMetrics::new().unwrap(),
        )
    }

    /// Minimal HTTP server serving one fixed body, so the collector path can be
    /// exercised without reaching a real feed.
    async fn serve(body: &'static str, status_line: &'static str) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = vec![0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let response = format!(
                    "{status_line}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });
        format!("http://{addr}/feed.txt")
    }

    #[tokio::test]
    async fn collects_writes_snapshot_and_report() {
        let dir = tempfile::tempdir().unwrap();
        let collector = collector(dir.path(), 100);
        let url = serve(
            "https://a.example/\nhttps://b.example/\n",
            "HTTP/1.1 200 OK",
        )
        .await;
        let source = StaticSource { url };

        let count = collector.collect(&source).await.unwrap();
        assert_eq!(count, 2);

        let snapshot = std::fs::read_to_string(dir.path().join("openphish.jsonl")).unwrap();
        assert_eq!(snapshot.lines().count(), 2);

        let report = collector.report();
        assert_eq!(report.sources.len(), 1);
        assert_eq!(report.sources[0].status, "ok");
        assert_eq!(report.sources[0].attempts, 1);
        assert!(dir.path().join("report.json").exists());
    }

    #[tokio::test]
    async fn http_error_is_recorded_without_panicking() {
        let dir = tempfile::tempdir().unwrap();
        let collector = collector(dir.path(), 100);
        let url = serve("nope", "HTTP/1.1 503 Service Unavailable").await;
        let source = StaticSource { url };

        let err = collector.collect(&source).await.unwrap_err();
        assert!(matches!(err, FeedError::Status(503)));
        let report = collector.report();
        assert_eq!(report.sources[0].status, "http_error");
        assert!(report.sources[0].error.is_some());
        assert!(!dir.path().join("openphish.jsonl").exists());
    }

    #[tokio::test]
    async fn enforces_dedupe_and_per_fetch_cap() {
        let dir = tempfile::tempdir().unwrap();
        let collector = collector(dir.path(), 2);
        let url = serve(
            "https://a.example/\nhttps://a.example/\nhttps://b.example/\nhttps://c.example/\n",
            "HTTP/1.1 200 OK",
        )
        .await;
        let source = StaticSource { url };

        let count = collector.collect(&source).await.unwrap();
        assert_eq!(count, 2);
        let snapshot = std::fs::read_to_string(dir.path().join("openphish.jsonl")).unwrap();
        assert_eq!(snapshot.lines().count(), 2);
    }
}
