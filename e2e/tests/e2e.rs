//! End-to-end tests — auth, ACL, cache, CONNECT tunnel.

use bsdm_proxy_e2e::{
    connect_via_proxy, ensure_test_ca, proxy_test_guard, spawn_mock_https_upstream,
    test_ca_cert_path, wait_for_tcp, workspace_path, HarnessConfig, ProxyHarness,
};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

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

    assert!(
        matches!(first.as_deref(), Some("MISS") | Some("MISS-STREAMING")),
        "expected MISS on first request, got {:?}",
        first
    );

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
async fn e2e_acl_denied_connect_emits_policy_event() {
    let _guard = proxy_test_guard().await;
    let sink = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind event sink");
    let sink_port = sink.local_addr().expect("sink address").port();
    let (event_tx, event_rx) = tokio::sync::oneshot::channel();
    let sink_task = tokio::spawn(async move {
        let (mut stream, _) = sink.accept().await.expect("accept event");
        let mut request = Vec::new();
        let body = loop {
            let mut chunk = [0_u8; 4096];
            let read = stream.read(&mut chunk).await.expect("read event");
            assert!(read > 0, "event sink request ended before body");
            request.extend_from_slice(&chunk[..read]);
            let Some(header_end) = request.windows(4).position(|w| w == b"\r\n\r\n") else {
                continue;
            };
            let header_end = header_end + 4;
            let headers = std::str::from_utf8(&request[..header_end]).expect("event headers");
            let content_length = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(str::trim)
                        .and_then(|value| value.parse::<usize>().ok())
                })
                .expect("content length");
            if request.len() >= header_end + content_length {
                break request[header_end..header_end + content_length].to_vec();
            }
        };
        stream
            .write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n")
            .await
            .expect("reply to event");
        event_tx.send(body).expect("send captured event");
    });

    let harness = ProxyHarness::start(HarnessConfig {
        acl_enabled: true,
        acl_rules_path: Some(workspace_path("config/acl-rules.test.json")),
        extra_env: [(
            "EVENT_SINK_URL".to_string(),
            format!("http://127.0.0.1:{sink_port}/api/events"),
        )]
        .into(),
        ..Default::default()
    })
    .await
    .expect("start proxy");

    let mut proxy = TcpStream::connect(("127.0.0.1", harness.proxy_port))
        .await
        .expect("connect to proxy");
    proxy
        .write_all(
            b"CONNECT blocked.test:443 HTTP/1.1\r\nHost: blocked.test:443\r\nUser-Agent: e2e-connect\r\n\r\n",
        )
        .await
        .expect("write CONNECT");
    let mut response = [0_u8; 1024];
    let read = proxy
        .read(&mut response)
        .await
        .expect("read CONNECT response");
    assert!(
        std::str::from_utf8(&response[..read])
            .expect("CONNECT response text")
            .starts_with("HTTP/1.1 403"),
        "CONNECT should be denied"
    );

    let body = tokio::time::timeout(Duration::from_secs(5), event_rx)
        .await
        .expect("policy event timeout")
        .expect("policy event channel");
    let event: bsdm_events::CacheEvent =
        serde_json::from_slice(&body).expect("deserialize policy event");
    assert_eq!(event.method, "CONNECT");
    assert_eq!(event.cache_status, "BLOCKED");
    assert_eq!(event.decision_source.as_deref(), Some("sni"));
    assert_eq!(event.acl_action.as_deref(), Some("deny"));
    assert_eq!(event.acl_rule_id.as_deref(), Some("block-test-domain"));
    assert!(event.acl_reason.is_some());

    sink_task.await.expect("event sink task");
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
    let mut extra_env = std::collections::HashMap::new();
    // Force full MITM so this test actually exercises TLS termination (not tunnel).
    extra_env.insert("POLICY_MODE".to_string(), "full-mitm".to_string());
    extra_env.insert("DEPLOYMENT_PROFILE".to_string(), "test".to_string());
    extra_env.insert("ALLOW_FULL_MITM".to_string(), "true".to_string());

    let harness = ProxyHarness::start(HarnessConfig {
        mitm_enabled: true,
        https_upstream_port: Some(8443),
        upstream_ca_cert: true,
        extra_env,
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

    let metrics = reqwest::Client::new()
        .get(harness.metrics_url("/metrics"))
        .send()
        .await
        .expect("metrics")
        .text()
        .await
        .expect("metrics body");
    assert!(
        metrics.contains("bsdm_proxy_policy_decision_source_total") && metrics.contains("mitm"),
        "full-mitm CONNECT should record decision_source=mitm"
    );
}

/// #272: POLICY_MODE=sni must tunnel HTTPS — never TLS-terminate even with MITM_ENABLED.
#[tokio::test]
async fn e2e_policy_mode_sni_never_terminates_tls() {
    let _guard = proxy_test_guard().await;
    let mut extra_env = std::collections::HashMap::new();
    extra_env.insert("POLICY_MODE".to_string(), "sni".to_string());
    extra_env.insert("DEPLOYMENT_PROFILE".to_string(), "production".to_string());
    // Even with MITM flag + categories that would decrypt under selective-mitm:
    extra_env.insert(
        "MITM_CATEGORIES".to_string(),
        "malware,phishing,illegal-content".to_string(),
    );

    let harness = ProxyHarness::start(HarnessConfig {
        mitm_enabled: true,
        https_upstream_port: Some(8445),
        upstream_ca_cert: true,
        extra_env,
        ..Default::default()
    })
    .await
    .expect("start proxy POLICY_MODE=sni");

    let metrics_before = reqwest::Client::new()
        .get(harness.metrics_url("/metrics"))
        .send()
        .await
        .expect("metrics before")
        .text()
        .await
        .expect("metrics before body");

    let client = harness.proxy_mitm_client().expect("HTTPS client via proxy");
    let url = harness.mitm_upstream_url("/sni-mode-no-mitm");
    let response = client
        .get(&url)
        .send()
        .await
        .expect("HTTPS GET via sni mode");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response.text().await.expect("body"),
        "upstream-tls:/sni-mode-no-mitm"
    );

    let metrics_after = reqwest::Client::new()
        .get(harness.metrics_url("/metrics"))
        .send()
        .await
        .expect("metrics after")
        .text()
        .await
        .expect("metrics after body");

    let mitm_before = metric_counter(
        &metrics_before,
        "bsdm_proxy_policy_decision_source_total",
        "mitm",
    );
    let mitm_after = metric_counter(
        &metrics_after,
        "bsdm_proxy_policy_decision_source_total",
        "mitm",
    );
    let sni_before = metric_counter(
        &metrics_before,
        "bsdm_proxy_policy_decision_source_total",
        "sni",
    );
    let sni_after = metric_counter(
        &metrics_after,
        "bsdm_proxy_policy_decision_source_total",
        "sni",
    );

    assert_eq!(
        mitm_after, mitm_before,
        "POLICY_MODE=sni must not increment decision_source=mitm (before={mitm_before} after={mitm_after})"
    );
    assert!(
        sni_after > sni_before,
        "POLICY_MODE=sni CONNECT should record decision_source=sni (before={sni_before} after={sni_after})"
    );

    // Runtime surface: /api/config (or health-adjacent) should advertise sni if exposed.
    let config = reqwest::Client::new()
        .get(harness.metrics_url("/api/config"))
        .send()
        .await;
    if let Ok(resp) = config {
        if resp.status().is_success() {
            if let Ok(v) = resp.json::<serde_json::Value>().await {
                if let Some(mode) = v.get("policy_mode").and_then(|m| m.as_str()) {
                    assert_eq!(mode, "sni", "runtime policy_mode must report sni");
                }
            }
        }
    }
}

fn metric_counter(body: &str, name: &str, source: &str) -> f64 {
    // Match: bsdm_proxy_policy_decision_source_total{source="mitm"} 1
    let needle = format!("{name}{{source=\"{source}\"}}");
    for line in body.lines() {
        if line.starts_with(&needle) || line.contains(&needle) {
            if let Some(val) = line.split_whitespace().last() {
                if let Ok(n) = val.parse::<f64>() {
                    return n;
                }
            }
        }
    }
    0.0
}

#[tokio::test]
async fn e2e_selective_mitm_pinning_bypass_fallback() {
    let _guard = proxy_test_guard().await;

    let mut extra_env = std::collections::HashMap::new();
    extra_env.insert("PINNING_EXCEPTIONS".to_string(), "127.0.0.1".to_string());

    let harness = ProxyHarness::start(HarnessConfig {
        mitm_enabled: true,
        https_upstream_port: Some(8444),
        upstream_ca_cert: true,
        extra_env,
        ..Default::default()
    })
    .await
    .expect("start proxy with pinning exception");

    let client = harness.proxy_mitm_client().expect("MITM client");
    let url = harness.mitm_upstream_url("/direct-tls");

    let response = client.get(&url).send().await.expect("pinning bypass GET");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response.text().await.expect("body"),
        "upstream-tls:/direct-tls"
    );
}

#[tokio::test]
async fn e2e_mitm_circuit_breaker_and_pinning_control_api() {
    let _guard = proxy_test_guard().await;

    let mut extra_env = std::collections::HashMap::new();
    extra_env.insert(
        "MITM_CIRCUIT_BREAKER_ENABLED".to_string(),
        "true".to_string(),
    );
    extra_env.insert(
        "MITM_CIRCUIT_BREAKER_MIN_SAMPLES".to_string(),
        "2".to_string(),
    );
    extra_env.insert(
        "MITM_CIRCUIT_BREAKER_FAILURE_RATE".to_string(),
        "0.5".to_string(),
    );

    let harness = ProxyHarness::start(HarnessConfig {
        mitm_enabled: true,
        extra_env,
        ..Default::default()
    })
    .await
    .expect("start proxy");

    let client = reqwest::Client::new();

    // 1. Check GET /api/mitm/circuit-breaker
    let breaker_status_url = harness.metrics_url("/api/mitm/circuit-breaker");
    let resp = client
        .get(&breaker_status_url)
        .send()
        .await
        .expect("get breaker status");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let status_json: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(status_json["enabled"], true);
    assert_eq!(status_json["tripped_count"], 0);

    // 2. Add pinning exception via POST /api/pinning/exceptions
    let add_exception_url = harness.metrics_url("/api/pinning/exceptions");
    let add_payload = serde_json::json!({
        "actor": "sec-ops",
        "change_reason": "e2e pinning test",
        "exception": {
            "domain": "pinned-e2e.example.com",
            "reason": "app certificate pinning",
            "owner": "qa",
            "ticket": "E2E-1"
        }
    });
    let add_resp = client
        .post(&add_exception_url)
        .json(&add_payload)
        .send()
        .await
        .expect("add pinning exception");
    assert_eq!(add_resp.status(), reqwest::StatusCode::OK);

    // 3. Verify GET /api/pinning/exceptions returns the new domain
    let list_exceptions_url = harness.metrics_url("/api/pinning/exceptions");
    let list_resp = client
        .get(&list_exceptions_url)
        .send()
        .await
        .expect("list exceptions");
    assert_eq!(list_resp.status(), reqwest::StatusCode::OK);
    let list_json: serde_json::Value = list_resp.json().await.expect("json");
    assert!(list_json["exceptions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["domain"] == "pinned-e2e.example.com"));

    // 4. Test POST /api/mitm/circuit-breaker/reset
    let reset_url = harness.metrics_url("/api/mitm/circuit-breaker/reset");
    let reset_payload = serde_json::json!({
        "domain": "*",
        "actor": "operator-e2e",
        "reason": "clean test reset"
    });
    let reset_resp = client
        .post(&reset_url)
        .json(&reset_payload)
        .send()
        .await
        .expect("reset circuit breaker");
    assert_eq!(reset_resp.status(), reqwest::StatusCode::OK);
}
