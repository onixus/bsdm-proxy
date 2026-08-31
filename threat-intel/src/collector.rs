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
    storage: Option<crate::storage::SqliteStorage>,
    metrics: Arc<CollectorMetrics>,
    report: Mutex<CollectionReport>,
}

impl Collector {
    pub fn new(
        config: Config,
        http: FeedHttpClient,
        sink: Arc<dyn IndicatorSink>,
        storage: Option<crate::storage::SqliteStorage>,
        metrics: Arc<CollectorMetrics>,
    ) -> Self {
        Self {
            config,
            http,
            sink,
            storage,
            metrics,
            report: Mutex::new(CollectionReport::default()),
        }
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    #[allow(dead_code)]
    pub fn storage(&self) -> Option<&crate::storage::SqliteStorage> {
        self.storage.as_ref()
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

    /// Performs post-collection storage maintenance: purging expired entries,
    /// updating Prometheus gauges, and compiling the DNS RPZ zone / ACL lists.
    pub fn sync_storage_and_exports(&self) {
        let Some(storage) = &self.storage else {
            return;
        };

        let now_ts = Utc::now().timestamp();
        if let Ok(purged) = storage.purge_expired(now_ts) {
            if purged > 0 {
                self.metrics.purged_expired.inc_by(purged as u64);
                info!(purged, "purged expired threat indicators from storage");
            }
        }

        if let Ok(active_urls) =
            storage.list_active(0, Some(crate::indicator::IndicatorKind::Url), 1_000_000)
        {
            self.metrics
                .stored_indicators
                .with_label_values(&["url"])
                .set(active_urls.len() as i64);
        }
        if let Ok(active_domains) =
            storage.list_active(0, Some(crate::indicator::IndicatorKind::Domain), 1_000_000)
        {
            self.metrics
                .stored_indicators
                .with_label_values(&["domain"])
                .set(active_domains.len() as i64);
        }
        if let Ok(active_ips) =
            storage.list_active(0, Some(crate::indicator::IndicatorKind::Ip), 1_000_000)
        {
            self.metrics
                .stored_indicators
                .with_label_values(&["ip"])
                .set(active_ips.len() as i64);
        }

        if !self.config.rpz_enabled {
            return;
        }

        let mode = self.config.enforcement_mode;
        // Shadow mode still compiles artifacts, but only under the `.shadow`
        // name that dns-sinkhole and the proxy never load (issue #330).
        let rpz_path = self.config.rpz_artifact_path();
        let acl_path = self.config.acl_artifact_path();

        // Enforcement artifacts never inherit indicators that SOAR accepted while
        // shadow mode was in force (ADR 0008 §4).
        match storage.list_active_domain_sources(
            self.config.min_confidence_score,
            100_000,
            mode.is_enforce(),
        ) {
            Ok(pairs) => {
                let domains: Vec<String> = pairs.iter().map(|(d, _)| d.clone()).collect();
                let feeds: std::collections::BTreeMap<String, String> = pairs.into_iter().collect();
                let domain_count = domains.len();
                let rpz_config = crate::rpz::RpzConfig {
                    shadow_mode: !mode.is_enforce(),
                    ..crate::rpz::RpzConfig::default()
                };
                if let Err(e) = crate::rpz::write_rpz_file(&rpz_path, &domains, &rpz_config) {
                    warn!("failed to compile DNS RPZ zone file: {e}");
                } else {
                    self.metrics.rpz_records.set(domain_count as i64);
                    info!(
                        domains = domain_count,
                        path = %rpz_path.display(),
                        mode = mode.as_str(),
                        "generated DNS RPZ zone file"
                    );

                    if mode.is_enforce() {
                        if let Some(reload_url) = &self.config.sinkhole_reload_url {
                            let url = reload_url.clone();
                            tokio::spawn(async move {
                                let client = reqwest::Client::new();
                                match client
                                    .post(&url)
                                    .timeout(std::time::Duration::from_secs(5))
                                    .send()
                                    .await
                                {
                                    Ok(resp) if resp.status().is_success() => {
                                        info!(%url, "DNS sinkhole zone reload triggered successfully");
                                    }
                                    Ok(resp) => {
                                        warn!(%url, status = %resp.status(), "DNS sinkhole zone reload returned error status");
                                    }
                                    Err(e) => {
                                        warn!(%url, err = %e, "failed to trigger DNS sinkhole zone reload");
                                    }
                                }
                            });
                        }
                    }
                }

                if let Err(e) = crate::rpz::export_proxy_acl_feed(&acl_path, domains, mode, feeds) {
                    warn!("failed to export Proxy ACL threat feed: {e}");
                } else {
                    info!(
                        path = %acl_path.display(),
                        mode = mode.as_str(),
                        "exported Proxy ACL threat feed"
                    );
                }
            }
            Err(e) => warn!("failed to query active domains for RPZ: {e}"),
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

    collector.sync_storage_and_exports();

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
                    collector.sync_storage_and_exports();
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
            sqlite_path: PathBuf::from(dir).join("ioc.db"),
            storage_enabled: true,
            ioc_ttl_secs: 3600,
            min_confidence_score: 75,
            rpz_enabled: true,
            rpz_output_path: PathBuf::from(dir).join("threats.rpz"),
            acl_export_path: PathBuf::from(dir).join("threat_domains.json"),
            soar_default_confidence: 90,
            soar_max_confidence: 100,
            enforcement_mode: crate::config::EnforcementMode::Shadow,
            user_agent: "test".into(),
            metrics_port: 0,
            run_once: true,
            siem_syslog_addr: None,
            siem_syslog_protocol: "udp".into(),
            siem_file_path: None,
            siem_format: "cef".into(),
            sinkhole_reload_url: None,
        }
    }

    fn collector(dir: &std::path::Path, cap: usize) -> Collector {
        let storage = crate::storage::SqliteStorage::new(dir.join("ioc.db")).unwrap();
        let file_sink = Box::new(JsonlFileSink::new(dir).unwrap());
        let sqlite_sink = Box::new(crate::sink::SqliteSink::new(storage.clone(), 3600));
        let sink = Arc::new(crate::sink::CompositeSink::new(vec![
            file_sink,
            sqlite_sink,
        ]));
        Collector::new(
            test_config(dir, cap),
            FeedHttpClient::new(Duration::from_secs(5), 1024 * 1024, "test").unwrap(),
            sink,
            Some(storage),
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
