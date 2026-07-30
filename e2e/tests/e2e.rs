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
