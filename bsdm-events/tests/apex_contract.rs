use std::path::PathBuf;

use serde_json::Value;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

#[test]
fn apex_contract_maps_cache_event_without_replacing_native_schema() {
    let root = root();
    let manifest: Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("apex-contract/manifest.json")).unwrap(),
    )
    .unwrap();

    assert_eq!(manifest["apex_contract_version"], "1.0");
    assert_eq!(manifest["canonical"]["commit"], "878d138c560cd4106ab0d6cccde804ddc3e5ae1d");
    assert_eq!(manifest["system"], "bsdm-proxy");
    assert_eq!(manifest["namespace"], "bsdm-proxy");
    assert_eq!(
        manifest["identity"]["trust_unsigned_role_header"],
        Value::Bool(false)
    );

    let event = manifest["boundaries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["name"] == "cache-event-v1")
        .expect("cache-event-v1 boundary");
    assert_eq!(event["event_type"], "apex.bsdm-proxy.cache_event.v1");
    assert_eq!(event["payload_contract"], "bsdm-events/src/lib.rs");

    let agent = manifest["boundaries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["name"] == "agent-api-v1")
        .expect("agent-api-v1 boundary");
    let paths = agent["paths"].as_array().expect("agent paths");
    assert!(paths.iter().all(|entry| {
        entry
            .as_str()
            .is_some_and(|value| value.contains(" /api/v1/agent/"))
    }));
    let agent_doc =
        std::fs::read_to_string(root.join("docs/architecture/agent-contract.md")).unwrap();
    assert!(agent_doc.contains("/api/v1/agent/*"));

    // The APEX adapter relies on a producer-stable id so retries remain
    // idempotent. Keep the native schema independent; only require the field.
    let source = std::fs::read_to_string(root.join("bsdm-events/src/lib.rs")).unwrap();
    assert!(source.contains("pub event_id: String"));
    assert!(source.contains("pub struct CacheEvent"));
}