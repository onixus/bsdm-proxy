//! Shared cache event schema for the Kafka → OpenSearch pipeline.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// HTTP cache / policy event emitted by proxy and indexed by cache-indexer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CacheEvent {
    pub url: String,
    pub method: String,
    pub status: u16,
    pub cache_key: String,
    #[serde(default)]
    pub cache_status: String,
    pub timestamp: u64,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub headers: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    pub client_ip: String,
    pub domain: String,
    pub response_size: u64,
    pub request_duration_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub categories: Vec<String>,
    /// Feed identifiers: shallalist, urlhaus, phishtank, custom, cache, multiple.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub threat_sources: Vec<String>,
    /// ACL decision when request was denied or redirected: deny, redirect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acl_action: Option<String>,
    #[serde(default)]
    pub event_id: String,
}

/// Stable OpenSearch document id for idempotent indexing.
pub fn document_id(event: &CacheEvent) -> String {
    if !event.event_id.is_empty() {
        return event.event_id.clone();
    }

    format!(
        "{}:{}:{}:{}",
        event.timestamp, event.request_duration_ms, event.client_ip, event.cache_key
    )
}

/// OpenSearch index mappings for `http-cache` documents.
pub fn index_mappings() -> serde_json::Value {
    serde_json::json!({
        "properties": {
            "url": {
                "type": "text",
                "fields": {
                    "keyword": {
                        "type": "keyword",
                        "ignore_above": 256
                    }
                }
            },
            "method": { "type": "keyword" },
            "status": { "type": "short" },
            "cache_key": { "type": "keyword" },
            "cache_status": { "type": "keyword" },
            "timestamp": { "type": "date", "format": "epoch_second" },
            "headers": { "type": "object" },
            "user_id": { "type": "keyword" },
            "username": { "type": "keyword" },
            "client_ip": { "type": "ip" },
            "domain": { "type": "keyword" },
            "response_size": { "type": "long" },
            "request_duration_ms": { "type": "long" },
            "content_type": { "type": "keyword" },
            "user_agent": {
                "type": "text",
                "fields": {
                    "keyword": {
                        "type": "keyword",
                        "ignore_above": 256
                    }
                }
            },
            "categories": { "type": "keyword" },
            "threat_sources": { "type": "keyword" },
            "acl_action": { "type": "keyword" },
            "event_id": { "type": "keyword" }
        }
    })
}

/// Index template body for `http-cache*` indices.
pub fn index_template_body(index_pattern: &str) -> serde_json::Value {
    serde_json::json!({
        "index_patterns": [index_pattern],
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0
            },
            "mappings": index_mappings()
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_id_prefers_event_id() {
        let event = CacheEvent {
            url: "https://example.com".to_string(),
            method: "GET".to_string(),
            status: 200,
            cache_key: "abc".to_string(),
            cache_status: "HIT".to_string(),
            timestamp: 1,
            headers: HashMap::new(),
            user_id: None,
            username: None,
            client_ip: "127.0.0.1".to_string(),
            domain: "example.com".to_string(),
            response_size: 0,
            request_duration_ms: 5,
            content_type: None,
            user_agent: None,
            categories: vec![],
            threat_sources: vec![],
            acl_action: None,
            event_id: "evt-1".to_string(),
        };
        assert_eq!(document_id(&event), "evt-1");
    }

    #[test]
    fn deserializes_legacy_proxy_payload() {
        let json = r#"{
            "url": "https://example.com",
            "method": "GET",
            "status": 200,
            "cache_key": "key",
            "cache_status": "MISS",
            "timestamp": 1700000000,
            "client_ip": "10.0.0.1",
            "domain": "example.com",
            "response_size": 100,
            "request_duration_ms": 10,
            "categories": ["malware"],
            "event_id": "evt-legacy"
        }"#;
        let event: CacheEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.categories, vec!["malware"]);
        assert!(event.threat_sources.is_empty());
        assert!(event.acl_action.is_none());
    }

    #[test]
    fn serializes_policy_event_fields() {
        let event = CacheEvent {
            url: "https://evil.com".to_string(),
            method: "GET".to_string(),
            status: 403,
            cache_key: "k".to_string(),
            cache_status: "BLOCKED".to_string(),
            timestamp: 1,
            headers: HashMap::new(),
            user_id: None,
            username: Some("alice".to_string()),
            client_ip: "10.0.0.2".to_string(),
            domain: "evil.com".to_string(),
            response_size: 0,
            request_duration_ms: 3,
            content_type: None,
            user_agent: None,
            categories: vec!["malware".to_string()],
            threat_sources: vec!["urlhaus".to_string()],
            acl_action: Some("deny".to_string()),
            event_id: "evt-block".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"acl_action\":\"deny\""));
        assert!(json.contains("\"threat_sources\":[\"urlhaus\"]"));
    }
}
