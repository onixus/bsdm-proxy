//! HTTP Archive Top 1k median page load — cache behaviour at realistic sizes.

use bsdm_proxy_e2e::{expand_device, load_profile, proxy_test_guard, HarnessConfig, ProxyHarness};

#[tokio::test]
async fn e2e_httparchive_desktop_page_cold_then_warm() {
    let _guard = proxy_test_guard().await;
    let profile = load_profile().expect("load httparchive profile");
    let resources = expand_device(&profile, "desktop").expect("expand desktop");
    assert_eq!(resources.len(), 71);

    let harness = ProxyHarness::start(HarnessConfig {
        httparchive_device: Some("desktop".to_string()),
        extra_env: [("MAX_CACHE_BODY_SIZE".to_string(), "10485760".to_string())]
            .into_iter()
            .collect(),
        ..Default::default()
    })
    .await
    .expect("start proxy");

    let client = harness.proxy_client().expect("proxy client");

    for resource in &resources {
        let url = harness.upstream_url(&resource.path);
        let resp = client.get(&url).send().await.expect("cold GET");
        let cache = resp
            .headers()
            .get("x-cache-status")
            .and_then(|v| v.to_str().ok());
        assert_ne!(cache, Some("HIT"), "first load for {}", resource.path);
    }

    let mut warm_hits = 0usize;
    let mut total_bytes = 0usize;
    for resource in &resources {
        let url = harness.upstream_url(&resource.path);
        let resp = client.get(&url).send().await.expect("warm GET");
        if resp
            .headers()
            .get("x-cache-status")
            .and_then(|v| v.to_str().ok())
            == Some("HIT")
        {
            warm_hits += 1;
        }
        total_bytes += resp.bytes().await.expect("body").len();
    }

    assert_eq!(warm_hits, resources.len());
    let expected_bytes: usize = resources.iter().map(|r| r.size_bytes).sum();
    assert_eq!(total_bytes, expected_bytes);
}

#[tokio::test]
async fn e2e_httparchive_mobile_page_load() {
    let _guard = proxy_test_guard().await;
    let profile = load_profile().expect("load httparchive profile");
    let resources = expand_device(&profile, "mobile").expect("expand mobile");
    assert_eq!(resources.len(), 66);

    let harness = ProxyHarness::start(HarnessConfig {
        httparchive_device: Some("mobile".to_string()),
        ..Default::default()
    })
    .await
    .expect("start proxy");

    let client = harness.proxy_client().expect("proxy client");
    let mut total = 0usize;
    for resource in &resources {
        let url = harness.upstream_url(&resource.path);
        let resp = client.get(&url).send().await.expect("GET");
        total += resp.bytes().await.expect("body").len();
    }
    let expected: usize = resources.iter().map(|r| r.size_bytes).sum();
    assert_eq!(total, expected);
}
