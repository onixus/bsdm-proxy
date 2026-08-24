//! End-to-end tests for AmneziaWG (AWG) Server API, Agent Tunnel Provisioning,
//! Domain-Based Split Routing, PAC Generation, and Hardened UI Server.

use agent_spike::router::{RouteRule, RouteTable, RouteTarget};
use agent_spike::ui_server::{run_ui_server, UiServerState};
use bsdm_proxy_e2e::{proxy_test_guard, HarnessConfig, ProxyHarness};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tempfile::NamedTempFile;
use tokio::sync::RwLock;

#[tokio::test]
async fn e2e_amneziawg_server_config_and_psk_generation() {
    let _guard = proxy_test_guard().await;

    let mut extra_env = HashMap::new();
    extra_env.insert(
        "CONTROL_API_TOKEN".to_string(),
        "test_control_token_123".to_string(),
    );

    let harness = ProxyHarness::start(HarnessConfig {
        extra_env,
        ..Default::default()
    })
    .await
    .expect("start proxy");

    let client = reqwest::Client::new();
    let base_url = format!("http://127.0.0.1:{}", harness.metrics_port);

    // 1. Test POST /api/amneziawg/generate-psk
    let psk_resp = client
        .post(format!("{base_url}/api/amneziawg/generate-psk"))
        .bearer_auth("test_control_token_123")
        .send()
        .await
        .expect("send generate-psk");

    assert_eq!(psk_resp.status(), reqwest::StatusCode::OK);
    let psk_json: serde_json::Value = psk_resp.json().await.expect("parse psk json");
    let psk_str = psk_json
        .get("preshared_key")
        .and_then(|v| v.as_str())
        .expect("psk string");
    assert!(!psk_str.is_empty());
    assert_eq!(psk_str.len(), 44); // 32 bytes base64 encoded

    // 2. Test POST /api/amneziawg/generate-keys
    let keys_resp = client
        .post(format!("{base_url}/api/amneziawg/generate-keys"))
        .bearer_auth("test_control_token_123")
        .send()
        .await
        .expect("send generate-keys");

    assert_eq!(keys_resp.status(), reqwest::StatusCode::OK);
    let keys_json: serde_json::Value = keys_resp.json().await.expect("parse keys json");
    let priv_k = keys_json.get("private_key").unwrap().as_str().unwrap();
    let pub_k = keys_json.get("public_key").unwrap().as_str().unwrap();

    // 3. Test POST /api/amneziawg/config
    let config_payload = serde_json::json!({
        "enabled": true,
        "listen_port": 51820,
        "private_key": priv_k,
        "public_key": pub_k,
        "address": "10.8.0.1/24",
        "obfuscation": {
            "jc": 7,
            "jmin": 60,
            "jmax": 90,
            "s1": 25,
            "s2": 35,
            "h1": 10000001,
            "h2": 20000002,
            "h3": 30000003,
            "h4": 40000004
        },
        "peers": []
    });

    let set_resp = client
        .post(format!("{base_url}/api/amneziawg/config"))
        .bearer_auth("test_control_token_123")
        .json(&config_payload)
        .send()
        .await
        .expect("send amneziawg config");

    assert_eq!(set_resp.status(), reqwest::StatusCode::OK);

    // 4. Test GET /api/amneziawg/config
    let get_resp = client
        .get(format!("{base_url}/api/amneziawg/config"))
        .bearer_auth("test_control_token_123")
        .send()
        .await
        .expect("get amneziawg config");

    assert_eq!(get_resp.status(), reqwest::StatusCode::OK);
    let get_json: serde_json::Value = get_resp.json().await.expect("parse get config json");
    assert_eq!(get_json.get("listen_port").unwrap().as_u64(), Some(51820));
    assert_eq!(
        get_json
            .get("obfuscation")
            .unwrap()
            .get("jc")
            .unwrap()
            .as_u64(),
        Some(7)
    );
}

#[tokio::test]
async fn e2e_agent_enrollment_with_tunnel_and_lifecycle() {
    let _guard = proxy_test_guard().await;

    let mut extra_env = HashMap::new();
    extra_env.insert(
        "CONTROL_API_TOKEN".to_string(),
        "test_control_token_123".to_string(),
    );

    let harness = ProxyHarness::start(HarnessConfig {
        extra_env,
        ..Default::default()
    })
    .await
    .expect("start proxy");

    let client = reqwest::Client::new();
    let base_url = format!("http://127.0.0.1:{}", harness.metrics_port);

    // 1. Enroll agent with capability "tunnel"
    let enroll_payload = serde_json::json!({
        "device_id": "e2e-agent-dev-01",
        "device_name": "E2E Workstation",
        "device_type": "desktop",
        "platform": "macos",
        "capabilities": ["tunnel", "metrics"]
    });

    let enroll_resp = client
        .post(format!("{base_url}/api/v1/agent/enroll"))
        .bearer_auth("test_control_token_123")
        .json(&enroll_payload)
        .send()
        .await
        .expect("send enroll");

    assert_eq!(enroll_resp.status(), reqwest::StatusCode::OK);
    let enroll_json: serde_json::Value = enroll_resp.json().await.expect("parse enroll json");

    let device_token = enroll_json
        .get("device_token")
        .and_then(|v| v.as_str())
        .expect("device token");
    assert!(!device_token.is_empty());

    let tunnel_config = enroll_json.get("tunnel_config");
    assert!(
        tunnel_config.is_some(),
        "expected tunnel_config in enroll response"
    );

    // 2. Fetch tunnel config in .conf format via GET /api/v1/agent/tunnel/config?format=conf
    let conf_resp = client
        .get(format!(
            "{base_url}/api/v1/agent/tunnel/config?device_id=e2e-agent-dev-01&format=conf"
        ))
        .bearer_auth(device_token)
        .send()
        .await
        .expect("fetch conf format");

    assert_eq!(conf_resp.status(), reqwest::StatusCode::OK);
    let conf_text = conf_resp.text().await.expect("read conf text");
    assert!(conf_text.contains("[Interface]"));
    assert!(conf_text.contains("PrivateKey ="));
    assert!(conf_text.contains("Address ="));
    assert!(conf_text.contains("[Peer]"));
    assert!(conf_text.contains("PublicKey ="));

    // 3. Fetch tunnel config in JSON format via GET /api/v1/agent/tunnel/config?format=json
    let json_resp = client
        .get(format!(
            "{base_url}/api/v1/agent/tunnel/config?device_id=e2e-agent-dev-01&format=json"
        ))
        .bearer_auth(device_token)
        .send()
        .await
        .expect("fetch json format");

    assert_eq!(json_resp.status(), reqwest::StatusCode::OK);
    let json_val: serde_json::Value = json_resp.json().await.expect("read json val");
    assert!(json_val.get("client_private_key").is_some());
    assert!(json_val.get("server_public_key").is_some());

    // 4. Revoke agent device via POST /api/v1/devices/{id}/revoke
    let revoke_resp = client
        .post(format!("{base_url}/api/v1/devices/e2e-agent-dev-01/revoke"))
        .bearer_auth("test_control_token_123")
        .send()
        .await
        .expect("send revoke");

    assert_eq!(revoke_resp.status(), reqwest::StatusCode::OK);

    // 5. Subsequent requests with revoked token must fail with 401 Unauthorized
    let rejected_resp = client
        .get(format!(
            "{base_url}/api/v1/agent/tunnel/config?device_id=e2e-agent-dev-01&format=conf"
        ))
        .bearer_auth(device_token)
        .send()
        .await
        .expect("fetch with revoked token");

    assert_eq!(
        rejected_resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "revoked device token must be rejected"
    );
}

#[tokio::test]
async fn e2e_agent_ui_server_and_dynamic_pac_routing() {
    let _guard = proxy_test_guard().await;

    let harness = ProxyHarness::start(HarnessConfig::default())
        .await
        .expect("start proxy");

    // Spawn embedded UI & PAC server on an ephemeral loopback port
    let tmp_routes = NamedTempFile::new().unwrap();
    let tmp_conf = NamedTempFile::new().unwrap();
    let routes = Arc::new(RwLock::new(RouteTable::default_corporate()));

    let ui_state = Arc::new(UiServerState {
        routes: routes.clone(),
        routes_path: tmp_routes.path().to_path_buf(),
        conf_path: tmp_conf.path().to_path_buf(),
        control_url: format!("http://127.0.0.1:{}", harness.metrics_port),
        proxy_authority: format!("127.0.0.1:{}", harness.proxy_port),
        tunnel_active: Arc::new(RwLock::new(false)),
        device_id: "e2e-ui-agent-dev".to_string(),
    });

    // Find free port for UI server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind free port");
    let ui_port = listener.local_addr().unwrap().port();
    drop(listener);

    let bind_addr = SocketAddr::from(([127, 0, 0, 1], ui_port));
    tokio::spawn(async move {
        let _ = run_ui_server(bind_addr, ui_state).await;
    });

    // Wait for UI server to become available
    tokio::time::sleep(Duration::from_millis(150)).await;
    let client = reqwest::Client::new();
    let ui_base = format!("http://127.0.0.1:{ui_port}");

    // 1. Test GET / (HTML Dashboard & Security Headers)
    let home_resp = client
        .get(format!("{ui_base}/"))
        .send()
        .await
        .expect("fetch ui home");

    assert_eq!(home_resp.status(), reqwest::StatusCode::OK);
    let csp = home_resp
        .headers()
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok());
    assert!(csp.is_some(), "CSP header must be present");
    assert_eq!(
        home_resp
            .headers()
            .get("x-frame-options")
            .and_then(|v| v.to_str().ok()),
        Some("DENY")
    );

    // 2. Test GET /proxy.pac
    let pac_resp = client
        .get(format!("{ui_base}/proxy.pac"))
        .send()
        .await
        .expect("fetch proxy.pac");

    assert_eq!(pac_resp.status(), reqwest::StatusCode::OK);
    let pac_text = pac_resp.text().await.expect("read pac text");
    assert!(pac_text.contains("FindProxyForURL"));
    assert!(pac_text.contains(&format!("PROXY 127.0.0.1:{}", harness.proxy_port)));

    // 3. Test CSRF rejection on POST /api/routes without X-BSDM-Request header
    let new_rule = RouteRule {
        id: "e2e-custom-rule".to_string(),
        pattern: "*.e2e-corp.internal".to_string(),
        target: RouteTarget::Proxy,
        enabled: true,
        comment: Some("E2E Custom Route Rule".to_string()),
    };

    let csrf_reject_resp = client
        .post(format!("{ui_base}/api/routes"))
        .json(&new_rule)
        .send()
        .await
        .expect("send unauthenticated mutation");

    assert_eq!(
        csrf_reject_resp.status(),
        reqwest::StatusCode::FORBIDDEN,
        "mutation without X-BSDM-Request header must be rejected"
    );

    // 4. Test authorized mutation with X-BSDM-Request: 1 header
    let valid_mutation_resp = client
        .post(format!("{ui_base}/api/routes"))
        .header("X-BSDM-Request", "1")
        .json(&new_rule)
        .send()
        .await
        .expect("send authorized mutation");

    assert_eq!(valid_mutation_resp.status(), reqwest::StatusCode::OK);

    // 5. Verify dynamic /proxy.pac reflects the newly added rule
    let updated_pac_resp = client
        .get(format!("{ui_base}/proxy.pac"))
        .send()
        .await
        .expect("fetch updated pac");

    assert_eq!(updated_pac_resp.status(), reqwest::StatusCode::OK);
    let updated_pac_text = updated_pac_resp.text().await.expect("read updated pac");
    assert!(
        updated_pac_text.contains("dnsDomainIs(host, '.e2e-corp.internal')"),
        "dynamically added domain rule must be compiled into PAC"
    );
}
