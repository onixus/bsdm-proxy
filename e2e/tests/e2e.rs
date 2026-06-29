//! End-to-end tests — auth, ACL, cache, CONNECT tunnel.

use bsdm_proxy_e2e::{
    connect_via_proxy, ensure_test_ca, proxy_test_guard, spawn_mock_https_upstream,
    test_ca_cert_path, wait_for_tcp, workspace_path, HarnessConfig, ProxyHarness,
};
use std::net::SocketAddr;

#[tokio::test]
async fn e2e_cache_hit_on_repeat_request() {
    let _guard = proxy_test_guard().await;
    let harness = ProxyHarness::start(HarnessConfig::default())
        .await
        .expect("start proxy");

    let client = harness.proxy_client().expect("proxy client");
    let url = harness.upstream_url("/cache-me");

    let first = client
        .get(&url)
        .send()
        .await
        .expect("first GET")
        .headers()
        .get("x-cache-status")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    assert_ne!(first.as_deref(), Some("HIT"));

    let second = client.get(&url).send().await.expect("second GET");

    assert_eq!(
        second
            .headers()
            .get("x-cache-status")
            .and_then(|v| v.to_str().ok()),
        Some("HIT")
    );
}

#[tokio::test]
async fn e2e_auth_requires_proxy_authorization() {
    let _guard = proxy_test_guard().await;
    let harness = ProxyHarness::start(HarnessConfig {
        auth_enabled: true,
        ..Default::default()
    })
    .await
    .expect("start proxy");

    let url = harness.upstream_url("/protected");
    let unauth = harness
        .proxy_client()
        .expect("proxy client")
        .get(&url)
        .send()
        .await
        .expect("unauthenticated request");

    assert_eq!(
        unauth.status(),
        reqwest::StatusCode::PROXY_AUTHENTICATION_REQUIRED
    );

    let authed = harness
        .proxy_auth_client("alice", "secret")
        .expect("auth client")
        .get(&url)
        .send()
        .await
        .expect("authenticated request");

    assert_eq!(authed.status(), reqwest::StatusCode::OK);
    assert_eq!(authed.text().await.expect("body"), "upstream:/protected");
}

#[tokio::test]
async fn e2e_acl_denies_blocked_domain() {
    let _guard = proxy_test_guard().await;
    let harness = ProxyHarness::start(HarnessConfig {
        acl_enabled: true,
        acl_rules_path: Some(workspace_path("config/acl-rules.test.json")),
        ..Default::default()
    })
    .await
    .expect("start proxy");

    let client = harness.proxy_client().expect("proxy client");
    let blocked_url = "http://blocked.test/forbidden";

    let response = client
        .get(blocked_url)
        .send()
        .await
        .expect("blocked request");

    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn e2e_acl_allows_non_blocked_domain() {
    let _guard = proxy_test_guard().await;
    let harness = ProxyHarness::start(HarnessConfig {
        acl_enabled: true,
        acl_rules_path: Some(workspace_path("config/acl-rules.test.json")),
        ..Default::default()
    })
    .await
    .expect("start proxy");

    let client = harness.proxy_client().expect("proxy client");
    let url = harness.upstream_url("/allowed");

    let response = client.get(&url).send().await.expect("allowed request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
async fn e2e_connect_tunnel_establishes_tcp_path() {
    let _guard = proxy_test_guard().await;
    let harness = ProxyHarness::start(HarnessConfig {
        mitm_enabled: false,
        ..Default::default()
    })
    .await
    .expect("start proxy");

    let (echo_port, _echo_task) = bsdm_proxy_e2e::spawn_tcp_echo_server()
        .await
        .expect("echo server");
    let target = SocketAddr::from(([127, 0, 0, 1], echo_port));

    let echoed = connect_via_proxy(harness.proxy_port, target)
        .await
        .expect("CONNECT tunnel");

    assert_eq!(echoed, "ping");
}

#[tokio::test]
async fn e2e_auth_and_acl_combined() {
    let _guard = proxy_test_guard().await;
    let harness = ProxyHarness::start(HarnessConfig {
        auth_enabled: true,
        acl_enabled: true,
        acl_rules_path: Some(workspace_path("config/acl-rules.test.json")),
        ..Default::default()
    })
    .await
    .expect("start proxy");

    let blocked_url = "http://blocked.test/combined";
    let authed = harness
        .proxy_auth_client("bob", "pass")
        .expect("auth client")
        .get(blocked_url)
        .send()
        .await
        .expect("authenticated blocked request");

    assert_eq!(authed.status(), reqwest::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn e2e_upstream_tls_accepts_test_ca() {
    let _guard = proxy_test_guard().await;
    ensure_test_ca().expect("write test ca");
    let upstream = spawn_mock_https_upstream(8443)
        .await
        .expect("spawn https upstream");
    wait_for_tcp(upstream.port)
        .await
        .expect("wait for upstream");

    let ca_pem = std::fs::read(test_ca_cert_path()).expect("read ca");
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(&ca_pem).expect("parse ca"))
        .build()
        .expect("client");

    let url = format!("https://127.0.0.1:{}/direct-tls", upstream.port);
    let response = client.get(&url).send().await.expect("direct tls get");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response.text().await.expect("body"),
        "upstream-tls:/direct-tls"
    );
}

#[tokio::test]
async fn e2e_mitm_https_with_self_signed_ca() {
    let _guard = proxy_test_guard().await;
    let harness = ProxyHarness::start(HarnessConfig {
        mitm_enabled: true,
        https_upstream_port: Some(8443),
        upstream_ca_cert: true,
        ..Default::default()
    })
    .await
    .expect("start proxy with MITM");

    let client = harness.proxy_mitm_client().expect("MITM client");
    let url = harness.mitm_upstream_url("/mitm-test");

    let response = client.get(&url).send().await.expect("MITM HTTPS GET");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response.text().await.expect("body"),
        "upstream-tls:/mitm-test"
    );
}
