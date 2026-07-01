mod clickhouse;
mod kafka;
mod opensearch;

use bsdm_events::{DEFAULT_ISM_DELETE_DAYS, DEFAULT_ISM_HOT_DAYS, DEFAULT_ISM_POLICY_ID};
use clickhouse::{load_config_from_env, ClickHouseIndexer};
use opensearch::OpenSearchIndexer;
use tracing::info;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IndexerBackend {
    OpenSearch,
    ClickHouse,
}

fn parse_backend_name(name: &str) -> IndexerBackend {
    match name.to_ascii_lowercase().as_str() {
        "clickhouse" | "ch" => IndexerBackend::ClickHouse,
        _ => IndexerBackend::OpenSearch,
    }
}

fn parse_backend() -> IndexerBackend {
    parse_backend_name(
        &std::env::var("INDEXER_BACKEND").unwrap_or_else(|_| "opensearch".to_string()),
    )
}

fn parse_env_u32(name: &str, default: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn parse_env_bool(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(default)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,cache_indexer=info".into()),
        )
        .init();

    let kafka_brokers = std::env::var("KAFKA_BROKERS").unwrap_or_else(|_| "kafka:9092".to_string());
    let kafka_topic = std::env::var("KAFKA_TOPIC").unwrap_or_else(|_| "cache-events".to_string());
    let kafka_group =
        std::env::var("KAFKA_GROUP_ID").unwrap_or_else(|_| "cache-indexer-group".to_string());
    let backend = parse_backend();

    info!("Starting cache-indexer (backend={:?})", backend);
    info!("Kafka brokers: {}", kafka_brokers);
    info!("Kafka topic: {}", kafka_topic);
    info!("Kafka group: {}", kafka_group);

    match backend {
        IndexerBackend::ClickHouse => {
            let ch_config = load_config_from_env();
            info!("ClickHouse URL: {}", ch_config.url);
            info!(
                "ClickHouse table: {}.{}",
                ch_config.database, ch_config.table
            );
            let indexer =
                ClickHouseIndexer::new(&kafka_brokers, &kafka_topic, &kafka_group, ch_config)
                    .await?;
            indexer.run().await
        }
        IndexerBackend::OpenSearch => {
            let opensearch_url = std::env::var("OPENSEARCH_URL")
                .unwrap_or_else(|_| "http://opensearch:9200".to_string());
            let opensearch_username = std::env::var("OPENSEARCH_USERNAME").ok();
            let opensearch_password = std::env::var("OPENSEARCH_PASSWORD").ok();
            let ssl_verify = std::env::var("OPENSEARCH_SSL_VERIFY")
                .unwrap_or_else(|_| "true".to_string())
                .parse::<bool>()
                .unwrap_or(true);
            let index_name =
                std::env::var("OPENSEARCH_INDEX").unwrap_or_else(|_| "http-cache".to_string());
            let ism_enabled = parse_env_bool("OPENSEARCH_ISM_ENABLED", true);
            let ism_policy_id = std::env::var("OPENSEARCH_ISM_POLICY_ID")
                .unwrap_or_else(|_| DEFAULT_ISM_POLICY_ID.to_string());
            let ism_hot_days = parse_env_u32("OPENSEARCH_ISM_HOT_DAYS", DEFAULT_ISM_HOT_DAYS);
            let ism_delete_days =
                parse_env_u32("OPENSEARCH_ISM_DELETE_DAYS", DEFAULT_ISM_DELETE_DAYS);

            info!("OpenSearch URL: {}", opensearch_url);
            info!("SSL verification: {}", ssl_verify);
            info!("OpenSearch index: {}", index_name);
            info!(
                "OpenSearch ISM: enabled={}, policy={}, hot={}d, delete={}d",
                ism_enabled, ism_policy_id, ism_hot_days, ism_delete_days
            );

            let indexer = OpenSearchIndexer::new(
                &kafka_brokers,
                &opensearch_url,
                opensearch_username,
                opensearch_password,
                ssl_verify,
                &kafka_topic,
                &kafka_group,
                &index_name,
                ism_enabled,
                ism_policy_id,
                ism_hot_days,
                ism_delete_days,
            )
            .await?;
            indexer.run().await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsdm_events::{document_id, CacheEvent};
    use std::collections::HashMap;

    fn sample_event(event_id: &str) -> CacheEvent {
        CacheEvent {
            url: "https://example.com".to_string(),
            method: "GET".to_string(),
            status: 200,
            cache_key: "abc123".to_string(),
            cache_status: "HIT".to_string(),
            timestamp: 1700000001,
            headers: HashMap::new(),
            user_id: None,
            username: None,
            client_ip: "127.0.0.1".to_string(),
            domain: "example.com".to_string(),
            response_size: 100,
            request_duration_ms: 5,
            content_type: None,
            user_agent: None,
            categories: vec!["malware".to_string()],
            threat_sources: vec!["urlhaus".to_string()],
            acl_action: None,
            event_id: event_id.to_string(),
        }
    }

    #[test]
    fn document_id_prefers_event_id() {
        assert_eq!(document_id(&sample_event("evt-unique-1")), "evt-unique-1");
    }

    #[test]
    fn document_id_differs_for_same_second_and_cache_key() {
        let base = sample_event("");
        let mut other = base.clone();
        other.request_duration_ms = 9;
        assert_ne!(document_id(&base), document_id(&other));
    }

    #[test]
    fn deserializes_categories_from_proxy_event() {
        let json_data = r#"{
            "url": "https://example.com",
            "method": "GET",
            "status": 200,
            "cache_key": "key123",
            "timestamp": 1700000000,
            "headers": {},
            "cache_status": "MISS",
            "client_ip": "10.0.0.1",
            "domain": "example.com",
            "response_size": 512,
            "request_duration_ms": 42,
            "categories": ["phishing", "malware"],
            "threat_sources": ["phishtank"],
            "acl_action": "deny",
            "event_id": "evt-proxy-1"
        }"#;

        let event: CacheEvent = serde_json::from_str(json_data).unwrap();
        assert_eq!(event.categories, vec!["phishing", "malware"]);
        assert_eq!(event.threat_sources, vec!["phishtank"]);
        assert_eq!(event.acl_action.as_deref(), Some("deny"));
        assert_eq!(event.event_id, "evt-proxy-1");
    }

    #[test]
    fn parse_env_bool_defaults() {
        assert!(parse_env_bool("MISSING_VAR", true));
        assert!(!parse_env_bool("MISSING_VAR", false));
    }

    #[test]
    fn parse_backend_variants() {
        assert_eq!(parse_backend_name("clickhouse"), IndexerBackend::ClickHouse);
        assert_eq!(parse_backend_name("ch"), IndexerBackend::ClickHouse);
        assert_eq!(parse_backend_name("opensearch"), IndexerBackend::OpenSearch);
    }
}
