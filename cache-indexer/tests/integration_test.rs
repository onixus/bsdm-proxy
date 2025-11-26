use serde_json::json;
use std::collections::HashMap;

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
    struct CacheEvent {
        url: String,
        method: String,
        status: u16,
        cache_key: String,
        timestamp: u64,
        headers: HashMap<String, String>,
        body: String,
    }

    #[test]
    fn test_cache_event_serialization() {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());

        let event = CacheEvent {
            url: "https://example.com/api".to_string(),
            method: "GET".to_string(),
            status: 200,
            cache_key: "abc123".to_string(),
            timestamp: 1234567890,
            headers,
            body: "test body".to_string(),
        };

        let json_str = serde_json::to_string(&event).unwrap();
        assert!(json_str.contains("https://example.com/api"));
        assert!(json_str.contains("GET"));
        assert!(json_str.contains("200"));
    }

    #[test]
    fn test_cache_event_deserialization() {
        let json_data = r#"{
            "url": "https://example.com",
            "method": "POST",
            "status": 201,
            "cache_key": "key123",
            "timestamp": 9876543210,
            "headers": {"X-Custom": "value"},
            "body": "response body"
        }"#;

        let event: CacheEvent = serde_json::from_str(json_data).unwrap();
        assert_eq!(event.url, "https://example.com");
        assert_eq!(event.method, "POST");
        assert_eq!(event.status, 201);
        assert_eq!(event.cache_key, "key123");
    }

    #[test]
    fn test_opensearch_index_mapping() {
        let mapping = json!({
            "mappings": {
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
                    "timestamp": { "type": "date", "format": "epoch_second" },
                    "headers": { "type": "object" },
                    "body": { "type": "text" }
                }
            }
        });

        assert!(mapping["mappings"]["properties"]["url"]["type"].is_string());
        assert_eq!(mapping["mappings"]["properties"]["method"]["type"], "keyword");
        assert_eq!(mapping["mappings"]["properties"]["status"]["type"], "short");
    }

    #[test]
    fn test_bulk_action_format() {
        let index_name = "http-cache";
        let cache_key = "test-key-123";

        let action = json!({
            "index": {
                "_index": index_name,
                "_id": cache_key
            }
        });

        assert_eq!(action["index"]["_index"], "http-cache");
        assert_eq!(action["index"]["_id"], "test-key-123");
    }

    #[test]
    fn test_ndjson_format() {
        let mut lines: Vec<String> = Vec::new();

        let action = json!({"index": {"_index": "test"}});
        let document = json!({"field": "value"});

        lines.push(serde_json::to_string(&action).unwrap());
        lines.push(serde_json::to_string(&document).unwrap());

        let ndjson = lines.join("\n") + "\n";

        assert!(ndjson.contains("{\"index\":"));
        assert!(ndjson.contains("{\"field\":"));
        assert!(ndjson.ends_with("\n"));
        assert_eq!(ndjson.matches('\n').count(), 2);
    }

    #[test]
    fn test_batch_processing() {
        let batch_size = 50;
        let mut batch: Vec<CacheEvent> = Vec::new();

        for i in 0..30 {
            batch.push(CacheEvent {
                url: format!("https://example.com/api/{}", i),
                method: "GET".to_string(),
                status: 200,
                cache_key: format!("key-{}", i),
                timestamp: 1234567890 + i,
                headers: HashMap::new(),
                body: String::new(),
            });
        }

        assert_eq!(batch.len(), 30);
        assert!(batch.len() < batch_size);
    }

    #[test]
    fn test_empty_batch_handling() {
        let batch: Vec<CacheEvent> = Vec::new();
        assert!(batch.is_empty());
    }

    #[test]
    fn test_event_timestamp_validation() {
        let event = CacheEvent {
            url: "https://test.com".to_string(),
            method: "GET".to_string(),
            status: 200,
            cache_key: "key".to_string(),
            timestamp: 1700000000, // Nov 2023
            headers: HashMap::new(),
            body: String::new(),
        };

        // Timestamp should be after 2020
        assert!(event.timestamp > 1577836800);
    }

    #[test]
    fn test_status_code_ranges() {
        let success_codes = vec![200, 201, 204];
        let redirect_codes = vec![301, 302, 307];
        let client_error_codes = vec![400, 401, 404];
        let server_error_codes = vec![500, 502, 503];

        for code in success_codes {
            assert!(code >= 200 && code < 300);
        }
        for code in redirect_codes {
            assert!(code >= 300 && code < 400);
        }
        for code in client_error_codes {
            assert!(code >= 400 && code < 500);
        }
        for code in server_error_codes {
            assert!(code >= 500 && code < 600);
        }
    }
}
