//! End-to-End integration test suite for Threat Intelligence Data-Plane Enforcement & Shadow Mode.

use bsdm_proxy_e2e::{proxy_test_guard, HarnessConfig, ProxyHarness};
use std::collections::HashMap;
use std::io::Write;

fn create_threat_json(
    path: &std::path::Path,
    mode: &str,
    domains: &[&str],
    feed_name: &str,
) -> std::io::Result<()> {
    let mut feeds = HashMap::new();
    for d in domains {
        feeds.insert(d.to_string(), feed_name.to_string());
    }
    let json = serde_json::json!({
        "generated_at": "2026-08-31T12:00:00Z",
        "mode": mode,
        "domain_count": domains.len(),
        "domains": domains,
        "feeds": feeds,
    });
    let mut file = std::fs::File::create(path)?;
    file.write_all(json.to_string().as_bytes())?;
    file.sync_all()?;
    Ok(())
}

#[tokio::test]
async fn test_threat_intel_shadow_mode_e2e() {
    let _guard = proxy_test_guard().await;
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let shadow_path = temp_dir.path().join("threat_domains.json.shadow");

    create_threat_json(
        &shadow_path,
        "shadow",
        &["127.0.0.1", "phish-test.example"],
        "openphish",
    )
    .expect("write shadow json");

    let mut extra_env = HashMap::new();
    extra_env.insert("TI_ENFORCEMENT_MODE".to_string(), "shadow".to_string());
    extra_env.insert(
        "TI_SHADOW_FEED_PATH".to_string(),
        shadow_path.to_string_lossy().to_string(),
    );
    extra_env.insert("TI_SHADOW_RELOAD_SECS".to_string(), "10".to_string());
    extra_env.insert(
        "EVENT_SINK_URL".to_string(),
        "http://127.0.0.1:9099/events".to_string(),
    );

    let harness = ProxyHarness::start(HarnessConfig {
        extra_env,
        ..Default::default()
    })
    .await
    .expect("start proxy");

    // In shadow mode, the proxy MUST NOT block the request even if the domain is in the threat feed
    let client = harness.proxy_client().expect("proxy client");

    let target_url = harness.upstream_url("/get");
    let resp = client.get(&target_url).send().await.expect("send request");

    // Shadow mode never blocks — status 200 from mock upstream
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // Give a brief moment for async event pipeline dispatch
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Verify shadow match metric was registered
    let metrics = reqwest::Client::new()
        .get(harness.metrics_url("/metrics"))
        .send()
        .await
        .expect("metrics request")
        .text()
        .await
        .expect("metrics text");

    assert!(metrics.contains("bsdm_proxy_ti_shadow_matches_total"));
}

#[tokio::test]
async fn test_threat_intel_enforce_mode_and_triple_gate_e2e() {
    let _guard = proxy_test_guard().await;
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let enforce_path = temp_dir.path().join("threat_domains.json");

    create_threat_json(&enforce_path, "enforce", &["127.0.0.1"], "urlhaus")
        .expect("write enforce json");

    let mut extra_env = HashMap::new();
    extra_env.insert("TI_ENFORCEMENT_MODE".to_string(), "enforce".to_string());
    extra_env.insert(
        "TI_ENFORCE_FEED_PATH".to_string(),
        enforce_path.to_string_lossy().to_string(),
    );
    extra_env.insert("TI_ENFORCE_RELOAD_SECS".to_string(), "10".to_string());

    let harness = ProxyHarness::start(HarnessConfig {
        extra_env,
        ..Default::default()
    })
    .await
    .expect("start proxy");

    let client = harness.proxy_client().expect("proxy client");

    // 1. Blocked domain in enforcement mode -> 403 Forbidden
    let blocked_url = harness.upstream_url("/malware");
    let resp = client.get(&blocked_url).send().await.expect("send request");

    assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN);
    let body = resp.text().await.expect("resp body");
    assert!(body.contains("Threat intelligence feed match"));

    // 2. Metrics reflect TI enforcement blocking
    let metrics = reqwest::Client::new()
        .get(harness.metrics_url("/metrics"))
        .send()
        .await
        .expect("metrics request")
        .text()
        .await
        .expect("metrics text");

    assert!(metrics.contains("bsdm_proxy_ti_enforce_blocked_total"));
}

#[tokio::test]
async fn test_threat_intel_triple_gate_safety_fallback_e2e() {
    let _guard = proxy_test_guard().await;
    let temp_dir = tempfile::tempdir().expect("tempdir");
    // File has .shadow in the name, but TI_ENFORCEMENT_MODE is accidentally set to enforce
    let fake_enforce_path = temp_dir.path().join("threat_domains.json.shadow");

    create_threat_json(&fake_enforce_path, "shadow", &["127.0.0.1"], "phishstats")
        .expect("write shadow json");

    let mut extra_env = HashMap::new();
    extra_env.insert("TI_ENFORCEMENT_MODE".to_string(), "enforce".to_string());
    extra_env.insert(
        "TI_ENFORCE_FEED_PATH".to_string(),
        fake_enforce_path.to_string_lossy().to_string(),
    );

    let harness = ProxyHarness::start(HarnessConfig {
        extra_env,
        ..Default::default()
    })
    .await
    .expect("start proxy");

    let client = harness.proxy_client().expect("proxy client");

    // Triple-Gate MUST fail-safe and refuse to block because path ends in .shadow
    let test_url = harness.upstream_url("/get");
    let resp = client.get(&test_url).send().await.expect("send request");

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}
