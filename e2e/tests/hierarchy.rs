//! Hierarchy E2E — parent fetch and sibling ICP hit.

use bsdm_proxy_e2e::{
    hierarchy_child_with_parent_env, hierarchy_child_with_sibling_env, hierarchy_icp_server_env,
    proxy_client_for_port, proxy_test_guard, reserve_udp_port, spawn_mock_upstream, wait_for_tcp,
    HarnessConfig, ProxyHarness,
};

#[tokio::test]
async fn e2e_hierarchy_parent_fetch_on_child_miss() {
    let _guard = proxy_test_guard().await;
    let upstream = spawn_mock_upstream().await.expect("spawn upstream");
    wait_for_tcp(upstream.port)
        .await
        .expect("wait for upstream");

    let parent = ProxyHarness::start(HarnessConfig {
        mitm_enabled: false,
        extra_env: hierarchy_icp_server_env(reserve_udp_port().expect("reserve parent ICP port")),
        ..Default::default()
    })
    .await
    .expect("start parent proxy");

    let mut child_env = hierarchy_child_with_parent_env(parent.proxy_port);
    child_env.insert("ICP_SERVER_ENABLED".into(), "false".into());

    let child = ProxyHarness::start(HarnessConfig {
        mitm_enabled: false,
        extra_env: child_env,
        ..Default::default()
    })
    .await
    .expect("start child proxy");

    let url = format!("http://127.0.0.1:{}/hierarchy-parent", upstream.port);
    let client = proxy_client_for_port(child.proxy_port).expect("child client");

    let body = client
        .get(&url)
        .send()
        .await
        .expect("child request via parent")
        .text()
        .await
        .expect("response body");

    assert_eq!(body, "upstream:/hierarchy-parent");
}

#[tokio::test]
async fn e2e_hierarchy_sibling_icp_hit() {
    let _guard = proxy_test_guard().await;
    let upstream = spawn_mock_upstream().await.expect("spawn upstream");
    wait_for_tcp(upstream.port)
        .await
        .expect("wait for upstream");

    let sibling_icp = reserve_udp_port().expect("reserve sibling ICP port");
    let sibling = ProxyHarness::start(HarnessConfig {
        mitm_enabled: false,
        extra_env: hierarchy_icp_server_env(sibling_icp),
        ..Default::default()
    })
    .await
    .expect("start sibling proxy");

    let url = format!("http://127.0.0.1:{}/hierarchy-sibling", upstream.port);

    proxy_client_for_port(sibling.proxy_port)
        .expect("sibling client")
        .get(&url)
        .send()
        .await
        .expect("warm sibling cache");

    let child = ProxyHarness::start(HarnessConfig {
        mitm_enabled: false,
        extra_env: hierarchy_child_with_sibling_env(sibling.proxy_port, sibling_icp),
        ..Default::default()
    })
    .await
    .expect("start child proxy");

    let body = proxy_client_for_port(child.proxy_port)
        .expect("child client")
        .get(&url)
        .send()
        .await
        .expect("child request via sibling ICP")
        .text()
        .await
        .expect("response body");

    assert_eq!(body, "upstream:/hierarchy-sibling");
}

#[tokio::test]
async fn e2e_hierarchy_parent_serves_cached_response_to_child() {
    let _guard = proxy_test_guard().await;
    let upstream = spawn_mock_upstream().await.expect("spawn upstream");
    wait_for_tcp(upstream.port)
        .await
        .expect("wait for upstream");

    let parent = ProxyHarness::start(HarnessConfig {
        mitm_enabled: false,
        extra_env: hierarchy_icp_server_env(reserve_udp_port().expect("reserve parent ICP port")),
        ..Default::default()
    })
    .await
    .expect("start parent proxy");

    let url = format!("http://127.0.0.1:{}/hierarchy-cached", upstream.port);

    let parent_client = proxy_client_for_port(parent.proxy_port).expect("parent client");
    parent_client
        .get(&url)
        .send()
        .await
        .expect("warm parent cache");
    let second = parent_client
        .get(&url)
        .send()
        .await
        .expect("parent cache hit");
    assert_eq!(
        second
            .headers()
            .get("x-cache-status")
            .and_then(|v| v.to_str().ok()),
        Some("HIT")
    );

    let mut child_env = hierarchy_child_with_parent_env(parent.proxy_port);
    child_env.insert("ICP_SERVER_ENABLED".into(), "false".into());

    let child = ProxyHarness::start(HarnessConfig {
        mitm_enabled: false,
        extra_env: child_env,
        ..Default::default()
    })
    .await
    .expect("start child proxy");

    let body = proxy_client_for_port(child.proxy_port)
        .expect("child client")
        .get(&url)
        .send()
        .await
        .expect("child fetch via parent")
        .text()
        .await
        .expect("response body");

    assert_eq!(body, "upstream:/hierarchy-cached");
}
