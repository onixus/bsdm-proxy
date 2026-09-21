use serde_json::Value;
use std::{fs, path::PathBuf};

fn manifest() -> Value {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let raw = fs::read_to_string(root.join("apex-contract.json"))
        .expect("apex-contract.json must exist at repository root");
    serde_json::from_str(&raw).expect("apex-contract.json must be valid JSON")
}

#[test]
fn apex_contract_keeps_gateway_analytics_out_of_proxy_authority() {
    let m = manifest();
    assert_eq!(m["contract"]["version"], "1.0");
    assert_eq!(m["system"]["id"], "bsdm-proxy");
    assert_eq!(m["system"]["namespace"], "bsdm-proxy");
    assert_eq!(m["system"]["role"], "secure-web-gateway");

    assert_eq!(m["ownership"]["gateway_is_source_of_truth"], false);
    assert_eq!(m["ownership"]["clickhouse_is_transactional_source"], false);
    assert_eq!(m["identity"]["owning_service_authorizes_mutations"], true);
    assert_eq!(m["identity"]["production_trusts_unsigned_role_header"], false);
}

#[test]
fn apex_contract_versions_bsdm_events_independently_of_kafka() {
    let m = manifest();
    let event_types = m["integration"]["event_types"]
        .as_array()
        .expect("event_types array");
    assert!(
        event_types
            .iter()
            .any(|item| item == "apex.bsdm-proxy.gateway.v1")
    );

    let resources = m["resources"].as_array().expect("resources array");
    assert!(resources.iter().any(|item| {
        item["kind"] == "event"
            && item["urn_prefix"] == "urn:apex:event:bsdm-proxy:"
    }));
    assert!(resources.iter().any(|item| {
        item["kind"] == "evidence"
            && item["urn_prefix"] == "urn:apex:evidence:bsdm-proxy:"
    }));
}
