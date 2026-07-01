use bsdm_events::CacheEvent;
use std::collections::HashMap;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clickhouse_row_mapping() {
        let event = CacheEvent {
            url: "https://example.com/api".to_string(),
            method: "GET".to_string(),
            status: 200,
            cache_key: "abc123".to_string(),
            cache_status: "MISS".to_string(),
            timestamp: 1234567890,
            headers: HashMap::new(),
            user_id: None,
            username: Some("alice".to_string()),
            client_ip: "10.0.0.1".to_string(),
            domain: "example.com".to_string(),
            response_size: 128,
            request_duration_ms: 12,
            content_type: Some("application/json".to_string()),
            user_agent: None,
            categories: vec!["malware".to_string()],
            threat_sources: vec!["urlhaus".to_string()],
            acl_action: None,
            event_id: "evt-1".to_string(),
        };

        let row = bsdm_events::cache_event_to_row(&event);
        assert_eq!(row.event_id, "evt-1");
        assert_eq!(row.username.as_deref(), Some("alice"));
        let lines = bsdm_events::json_each_row_lines(&[event]).unwrap();
        assert!(lines.contains("\"domain\":\"example.com\""));
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
            cache_status: "MISS".to_string(),
            timestamp: 1234567890,
            headers,
            user_id: None,
            username: Some("alice".to_string()),
            client_ip: "10.0.0.1".to_string(),
            domain: "example.com".to_string(),
            response_size: 128,
            request_duration_ms: 12,
            content_type: Some("application/json".to_string()),
            user_agent: None,
            categories: vec!["malware".to_string()],
            threat_sources: vec!["urlhaus".to_string()],
            acl_action: None,
            event_id: "evt-1".to_string(),
        };

        let json_str = serde_json::to_string(&event).unwrap();
        assert!(json_str.contains("https://example.com/api"));
        assert!(json_str.contains("\"threat_sources\":[\"urlhaus\"]"));
    }

    #[test]
    fn test_cache_event_deserialization() {
        let json_data = r#"{
            "url": "https://example.com",
            "method": "POST",
            "status": 201,
            "cache_key": "key123",
            "cache_status": "MISS",
            "timestamp": 9876543210,
            "headers": {"X-Custom": "value"},
            "client_ip": "10.0.0.2",
            "domain": "example.com",
            "response_size": 64,
            "request_duration_ms": 8,
            "event_id": "evt-2"
        }"#;

        let event: CacheEvent = serde_json::from_str(json_data).unwrap();
        assert_eq!(event.url, "https://example.com");
        assert_eq!(event.method, "POST");
        assert_eq!(event.status, 201);
        assert_eq!(event.cache_key, "key123");
    }

    #[test]
    fn test_clickhouse_row_has_policy_fields() {
        let event = CacheEvent {
            url: "https://blocked.example".to_string(),
            method: "GET".to_string(),
            status: 403,
            cache_key: "k".to_string(),
            cache_status: "BLOCKED".to_string(),
            timestamp: 1,
            headers: HashMap::new(),
            user_id: None,
            username: Some("bob".to_string()),
            client_ip: "10.0.0.3".to_string(),
            domain: "blocked.example".to_string(),
            response_size: 0,
            request_duration_ms: 2,
            content_type: None,
            user_agent: None,
            categories: vec!["malware".to_string()],
            threat_sources: vec!["shallalist".to_string()],
            acl_action: Some("deny".to_string()),
            event_id: "evt-block".to_string(),
        };

        let row = bsdm_events::cache_event_to_row(&event);
        assert_eq!(row.acl_action.as_deref(), Some("deny"));
        assert_eq!(row.threat_sources, vec!["shallalist"]);
    }

    #[test]
    fn test_batch_processing_logic() {
        let mut batch: Vec<CacheEvent> = Vec::new();

        for i in 0..5 {
            batch.push(CacheEvent {
                url: format!("https://example{i}.com"),
                method: "GET".to_string(),
                status: 200,
                cache_key: format!("key{i}"),
                cache_status: "MISS".to_string(),
                timestamp: 1234567890 + i,
                headers: HashMap::new(),
                user_id: None,
                username: None,
                client_ip: "127.0.0.1".to_string(),
                domain: format!("example{i}.com"),
                response_size: 0,
                request_duration_ms: i,
                content_type: None,
                user_agent: None,
                categories: vec![],
                threat_sources: vec![],
                acl_action: None,
                event_id: format!("evt-{i}"),
            });
        }

        assert_eq!(batch.len(), 5);
    }

    #[test]
    fn test_empty_batch_handling() {
        let batch: Vec<CacheEvent> = Vec::new();
        assert!(batch.is_empty());
    }

    #[test]
    fn test_policy_event_fields() {
        let event = CacheEvent {
            url: "https://blocked.example".to_string(),
            method: "GET".to_string(),
            status: 403,
            cache_key: "k".to_string(),
            cache_status: "BLOCKED".to_string(),
            timestamp: 1,
            headers: HashMap::new(),
            user_id: None,
            username: Some("bob".to_string()),
            client_ip: "10.0.0.3".to_string(),
            domain: "blocked.example".to_string(),
            response_size: 0,
            request_duration_ms: 2,
            content_type: None,
            user_agent: None,
            categories: vec!["malware".to_string()],
            threat_sources: vec!["shallalist".to_string()],
            acl_action: Some("deny".to_string()),
            event_id: "evt-block".to_string(),
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"acl_action\":\"deny\""));
        assert!(json.contains("\"cache_status\":\"BLOCKED\""));
    }
}
