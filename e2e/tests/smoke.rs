//! Smoke tests — fast critical-path checks against a live proxy process.

use bsdm_proxy_e2e::{proxy_test_guard, HarnessConfig, ProxyHarness};

#[tokio::test]
async fn smoke_health_endpoint() {
    let _guard = proxy_test_guard().await;
    let harness = ProxyHarness::start(HarnessConfig::default())
        .await
        .expect("start proxy");

    let client = reqwest::Client::new();
    let health: serde_json::Value = client
        .get(harness.metrics_url("/health"))
        .send()
        .await
        .expect("health request")
        .json()
        .await
        .expect("health json");

    assert_eq!(health["status"], "ok");

    let ready: serde_json::Value = client
        .get(harness.metrics_url("/ready"))
        .send()
        .await
        .expect("ready request")
        .json()
        .await
        .expect("ready json");

    assert_eq!(ready["status"], "ready");
}

#[tokio::test]
async fn smoke_metrics_endpoint() {
    let _guard = proxy_test_guard().await;
    let harness = ProxyHarness::start(HarnessConfig::default())
        .await
        .expect("start proxy");

    let body = reqwest::Client::new()
        .get(harness.metrics_url("/metrics"))
        .send()
        .await
        .expect("metrics request")
        .text()
        .await
        .expect("metrics body");

    assert!(body.contains("bsdm_proxy_requests_in_flight"));
    assert!(body.contains("bsdm_proxy_cache_entries"));
}

#[tokio::test]
async fn smoke_proxy_forwards_http() {
    let _guard = proxy_test_guard().await;
    let harness = ProxyHarness::start(HarnessConfig::default())
        .await
        .expect("start proxy");

    let client = harness.proxy_client().expect("proxy client");
    let url = harness.upstream_url("/smoke");

    let body = client
        .get(&url)
        .send()
        .await
        .expect("proxied GET")
        .text()
        .await
        .expect("response body");

    assert_eq!(body, "upstream:/smoke");
}

#[tokio::test]
async fn smoke_unknown_metrics_route_returns_404() {
    let _guard = proxy_test_guard().await;
    let harness = ProxyHarness::start(HarnessConfig::default())
        .await
        .expect("start proxy");

    let status = reqwest::Client::new()
        .get(harness.metrics_url("/unknown-route"))
        .send()
        .await
        .expect("unknown route request")
        .status();

    assert_eq!(status, reqwest::StatusCode::NOT_FOUND);
}
