use serde_json::Value;
use std::{fs, path::PathBuf};

fn manifest() -> Value {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let raw = fs::read_to_string(root.join("apex-contract").join("manifest.json"))
        .expect("apex-contract/manifest.json must exist at repository root");
    serde_json::from_str(&raw).expect("apex-contract/manifest.json must be valid JSON")
}

#[test]
fn apex_contract_keeps_gateway_analytics_out_of_proxy_authority() {
    let m = manifest();
    assert_eq!(m["apex_contract_version"], "1.0");
    assert_eq!(m["canonical"]["repo"], "onixus/unified-platform");
    assert_eq!(m["system"], "bsdm-proxy");
    assert_eq!(m["namespace"], "bsdm-proxy");
    assert_eq!(m["role"], "secure-web-gateway");

    assert_eq!(m["ownership"]["gateway_is_source_of_truth"], false);
    assert_eq!(m["ownership"]["clickhouse_is_transactional_source"], false);
    assert_eq!(m["identity"]["owning_service_authorizes_mutations"], true);
    assert_eq!(m["identity"]["trust_unsigned_role_header"], false);
}

#[test]
fn apex_contract_versions_real_bsdm_boundaries_independently_of_kafka() {
    let m = manifest();

    let boundaries = m["boundaries"].as_array().expect("boundaries array");
    let cache = boundaries
        .iter()
        .find(|item| item["name"] == "cache-event-v1")
        .expect("cache-event-v1 boundary");
    assert_eq!(cache["event_type"], "apex.bsdm-proxy.cache_event.v1");
    assert_eq!(cache["payload_contract"], "bsdm-events/src/lib.rs");

    let agent = boundaries
        .iter()
        .find(|item| item["name"] == "agent-api-v1")
        .expect("agent-api-v1 boundary");
    assert!(agent["paths"]
        .as_array()
        .expect("agent paths")
        .iter()
        .all(|entry| entry.as_str().is_some_and(|value| value.contains(" /api/v1/agent/"))));

    let resources = m["resources"]["mappings"]
        .as_array()
        .expect("resources.mappings array");
    assert!(resources.iter().any(|item| {
        item["kind"] == "event"
            && item["urn_prefix"] == "urn:apex:event:bsdm-proxy:"
    }));
    assert!(resources.iter().any(|item| {
        item["kind"] == "evidence"
            && item["urn_prefix"] == "urn:apex:evidence:bsdm-proxy:"
    }));
}
