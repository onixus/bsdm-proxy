//! End-to-end pipeline test for Threat Intelligence collector, normalization,
//! SQLite storage, DNS RPZ compilation, and Proxy ACL feed export.

use std::sync::Arc;
use std::time::Duration;
use threat_intel::collector::{self, Collector};
use threat_intel::config::{Config, EnforcementMode};
use threat_intel::http::FeedHttpClient;
use threat_intel::indicator::IndicatorKind;
use threat_intel::metrics::CollectorMetrics;
use threat_intel::sink::{CompositeSink, JsonlFileSink, SqliteSink};
use threat_intel::source::FeedSource;
use threat_intel::storage::SqliteStorage;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn mock_http_server(body: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = vec![0u8; 1024];
            let _ = socket.read(&mut buf).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes()).await;
        }
    });
    format!("http://{addr}/feed.txt")
}

struct TestFeedSource {
    url: String,
}

impl FeedSource for TestFeedSource {
    fn name(&self) -> &'static str {
        "test_phish_feed"
    }
    fn url(&self) -> &str {
        &self.url
    }
    fn weight(&self) -> u8 {
        85
    }
    fn parse(
        &self,
        body: &str,
    ) -> Result<Vec<threat_intel::indicator::RawIndicator>, threat_intel::source::FeedError> {
        let mut res = Vec::new();
        for line in body.lines().map(str::trim).filter(|l| !l.is_empty()) {
            let kind = if line.starts_with("http://") || line.starts_with("https://") {
                IndicatorKind::Url
            } else if threat_intel::indicator::is_ip_literal(line) {
                IndicatorKind::Ip
            } else {
                IndicatorKind::Domain
            };
            res.push(threat_intel::indicator::RawIndicator::new(line, kind, self));
        }
        Ok(res)
    }
}

fn pipeline_config(
    output_dir: &std::path::Path,
    mode: EnforcementMode,
) -> Config {
    Config {
        sources: vec!["test_phish_feed".into()],
        poll_interval: Duration::from_secs(900),
        http_timeout: Duration::from_secs(5),
        max_attempts: 1,
        retry_backoff: Duration::from_secs(1),
        max_body_bytes: 1024 * 1024,
        max_indicators_per_fetch: 1000,
        output_dir: output_dir.to_path_buf(),
        sqlite_path: output_dir.join("ioc.db"),
        storage_enabled: true,
        ioc_ttl_secs: 7 * 86400,
        min_confidence_score: 75,
        rpz_enabled: true,
        rpz_output_path: output_dir.join("threats.rpz"),
        acl_export_path: output_dir.join("threat_domains.json"),
        enforcement_mode: mode,
        user_agent: "test".into(),
        metrics_port: 0,
        run_once: true,
    }
}

#[tokio::test]
async fn test_full_threat_intel_pipeline() {
    let temp_dir = tempfile::tempdir().unwrap();
    let output_dir = temp_dir.path().to_path_buf();
    let sqlite_path = output_dir.join("ioc.db");
    let rpz_path = output_dir.join("threats.rpz");
    let acl_path = output_dir.join("threat_domains.json");

    // Feed containing URLs, domains, and private bogon IPs
    let feed_content = r#"
https://evil-phish.com/login.php
http://MALWARE-DROPPER.ORG:80/payload.exe#fragment
10.0.0.1
185.220.101.5
phish.target-bank.net
"#;

    let feed_url = mock_http_server(feed_content).await;

    // Enforcement pipeline: artifacts land under their plain names.
    let config = pipeline_config(&output_dir, EnforcementMode::Enforce);

    let metrics = CollectorMetrics::new().unwrap();
    let storage = SqliteStorage::new(&sqlite_path).unwrap();
    let file_sink = Box::new(JsonlFileSink::new(&output_dir).unwrap());
    let sqlite_sink = Box::new(SqliteSink::new(storage.clone(), config.ioc_ttl_secs));
    let composite_sink = Arc::new(CompositeSink::new(vec![file_sink, sqlite_sink]));
    let http = FeedHttpClient::new(Duration::from_secs(5), 1024 * 1024, "test").unwrap();

    let collector = Arc::new(Collector::new(
        config,
        http,
        composite_sink,
        Some(storage.clone()),
        metrics.clone(),
    ));

    let sources: Vec<Box<dyn FeedSource>> = vec![Box::new(TestFeedSource { url: feed_url })];

    // Execute one-shot collection
    let run_res = collector::run_once(collector, sources).await;
    assert!(run_res.is_ok(), "Pipeline run failed: {:?}", run_res);

    // 1. Verify JSONL file snapshot
    let jsonl_file = output_dir.join("test_phish_feed.jsonl");
    assert!(jsonl_file.exists());
    let jsonl_content = std::fs::read_to_string(&jsonl_file).unwrap();
    assert!(jsonl_content.contains("https://evil-phish.com/login.php"));

    // 2. Verify report.json
    let report_file = output_dir.join("report.json");
    assert!(report_file.exists());
    let report_json = std::fs::read_to_string(&report_file).unwrap();
    assert!(report_json.contains("\"status\": \"ok\""));

    // 3. Verify SQLite storage contents
    let ind_url = storage
        .query_indicator("https://evil-phish.com/login.php", Some(IndicatorKind::Url))
        .unwrap()
        .expect("URL indicator missing from SQLite");
    assert_eq!(ind_url.domain, Some("evil-phish.com".to_string()));
    assert_eq!(ind_url.confidence_score, 85);
    assert_eq!(ind_url.hit_count, 1);

    // Check normalized URL without default port and fragment
    let ind_url2 = storage
        .query_indicator(
            "http://malware-dropper.org/payload.exe",
            Some(IndicatorKind::Url),
        )
        .unwrap()
        .expect("Normalized URL missing from SQLite");
    assert_eq!(ind_url2.domain, Some("malware-dropper.org".to_string()));

    // Bogon IP 10.0.0.1 must be dropped from active lookup
    let bogon = storage
        .query_indicator("10.0.0.1", Some(IndicatorKind::Ip))
        .unwrap();
    assert!(
        bogon.is_none(),
        "Private bogon IP 10.0.0.1 must not be active in storage"
    );

    // Public IP 185.220.101.5 must be present
    let public_ip = storage
        .query_indicator("185.220.101.5", Some(IndicatorKind::Ip))
        .unwrap();
    assert!(
        public_ip.is_some(),
        "Public IP 185.220.101.5 must be stored"
    );

    // 4. Verify DNS RPZ zone compilation
    assert!(rpz_path.exists(), "RPZ zone file was not generated");
    let rpz_content = std::fs::read_to_string(&rpz_path).unwrap();
    assert!(rpz_content.contains("$TTL 300"));
    assert!(rpz_content.contains("evil-phish.com CNAME ."));
    assert!(rpz_content.contains("*.evil-phish.com CNAME ."));
    assert!(rpz_content.contains("malware-dropper.org CNAME ."));
    assert!(rpz_content.contains("phish.target-bank.net CNAME ."));

    // 5. Verify Proxy ACL threat feed export
    assert!(acl_path.exists(), "Proxy ACL threat feed was not generated");
    let acl_content = std::fs::read_to_string(&acl_path).unwrap();
    let acl_json: serde_json::Value = serde_json::from_str(&acl_content).unwrap();
    assert!(acl_json["domain_count"].as_u64().unwrap() >= 3);
    let domains = acl_json["domains"].as_array().unwrap();
    let domain_strs: Vec<&str> = domains.iter().map(|d| d.as_str().unwrap()).collect();
    assert!(domain_strs.contains(&"evil-phish.com"));
    assert!(domain_strs.contains(&"malware-dropper.org"));
    assert!(domain_strs.contains(&"phish.target-bank.net"));
}

/// Issue #330: the default (shadow) mode must never produce an artifact that
/// `dns-sinkhole` or the proxy ACL loader can pick up, including indicators
/// pushed through the SOAR block API.
#[tokio::test]
async fn shadow_mode_writes_only_shadow_artifacts() {
    let temp_dir = tempfile::tempdir().unwrap();
    let output_dir = temp_dir.path().to_path_buf();
    let sqlite_path = output_dir.join("ioc.db");

    let feed_url = mock_http_server("https://evil-phish.com/login.php\n").await;
    let config = pipeline_config(&output_dir, EnforcementMode::Shadow);

    let metrics = CollectorMetrics::new().unwrap();
    let storage = SqliteStorage::new(&sqlite_path).unwrap();
    let file_sink = Box::new(JsonlFileSink::new(&output_dir).unwrap());
    let sqlite_sink = Box::new(SqliteSink::new(storage.clone(), config.ioc_ttl_secs));
    let composite_sink = Arc::new(CompositeSink::new(vec![file_sink, sqlite_sink]));
    let http = FeedHttpClient::new(Duration::from_secs(5), 1024 * 1024, "test").unwrap();

    // SOAR containment requested by an analyst while the collector is in shadow.
    let soar = threat_intel::soar::execute_soar_block(
        &storage,
        threat_intel::soar::SoarBlockRequest {
            indicator: "soar-shadow.test".into(),
            kind: IndicatorKind::Domain,
            reason: "SOC triage".into(),
            ttl_secs: Some(3600),
            operator: Some("soc1".into()),
        },
        EnforcementMode::Shadow,
    )
    .unwrap();
    assert!(!soar.enforced);
    assert_eq!(soar.mode, "shadow");

    let collector = Arc::new(Collector::new(
        config,
        http,
        composite_sink,
        Some(storage.clone()),
        metrics.clone(),
    ));
    let sources: Vec<Box<dyn FeedSource>> = vec![Box::new(TestFeedSource { url: feed_url })];
    collector::run_once(collector, sources).await.unwrap();

    // No enforcement artifact exists at all.
    assert!(
        !output_dir.join("threats.rpz").exists(),
        "shadow mode must not write an enforceable RPZ zone"
    );
    assert!(
        !output_dir.join("threat_domains.json").exists(),
        "shadow mode must not write an enforceable proxy ACL feed"
    );

    // Shadow artifacts exist and are labelled as observe-only.
    let rpz = std::fs::read_to_string(output_dir.join("threats.rpz.shadow")).unwrap();
    assert!(rpz.contains("SHADOW MODE"));
    assert!(rpz.contains("evil-phish.com CNAME ."));

    let acl_raw = std::fs::read_to_string(output_dir.join("threat_domains.json.shadow")).unwrap();
    let acl: serde_json::Value = serde_json::from_str(&acl_raw).unwrap();
    assert_eq!(acl["mode"], "shadow");
    let domains: Vec<&str> = acl["domains"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d.as_str().unwrap())
        .collect();
    assert!(domains.contains(&"evil-phish.com"));
    // The SOAR indicator is observable only in the shadow export.
    assert!(domains.contains(&"soar-shadow.test"));
    assert_eq!(acl["feeds"]["evil-phish.com"], "test_phish_feed");
    assert_eq!(acl["feeds"]["soar-shadow.test"], "soar:soc1");
}
