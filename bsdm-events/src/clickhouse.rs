//! `CacheEvent` → ClickHouse `http_cache` row mapping (JSONEachRow INSERT).

use crate::{document_id, CacheEvent};
use chrono::{TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;

/// Row shape for `bsdm.http_cache` (`scripts/clickhouse/http_cache.sql`).
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct HttpCacheRow {
    pub event_id: String,
    pub ts: String,
    pub url: String,
    pub method: String,
    pub status: u16,
    pub cache_key: String,
    pub cache_status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    pub client_ip: String,
    pub domain: String,
    pub response_size: u64,
    pub request_duration_ms: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    pub user_agent: String,
    pub categories: Vec<String>,
    pub threat_sources: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acl_action: Option<String>,
    pub session_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_url: Option<String>,
    pub headers: String,
}

/// Map proxy `CacheEvent` JSON to a ClickHouse JSONEachRow document.
pub fn cache_event_to_row(event: &CacheEvent) -> HttpCacheRow {
    HttpCacheRow {
        event_id: if event.event_id.is_empty() {
            document_id(event)
        } else {
            event.event_id.clone()
        },
        ts: epoch_secs_to_clickhouse_ts(event.timestamp),
        url: event.url.clone(),
        method: event.method.clone(),
        status: event.status,
        cache_key: event.cache_key.clone(),
        cache_status: event.cache_status.clone(),
        user_id: event.user_id.clone(),
        username: event.username.clone(),
        client_ip: normalize_ipv4(&event.client_ip),
        domain: event.domain.clone(),
        response_size: event.response_size,
        request_duration_ms: event.request_duration_ms.min(u32::MAX as u64) as u32,
        content_type: event.content_type.clone(),
        user_agent: event.user_agent.clone().unwrap_or_default(),
        categories: event.categories.clone(),
        threat_sources: event.threat_sources.clone(),
        acl_action: event.acl_action.clone(),
        session_id: event.session_id.clone(),
        parent_event_id: event.parent_event_id.clone(),
        redirect_url: event.redirect_url.clone(),
        headers: headers_json(&event.headers),
    }
}

/// Serialize events as newline-delimited JSON for `INSERT ... FORMAT JSONEachRow`.
pub fn json_each_row_lines(events: &[CacheEvent]) -> Result<String, serde_json::Error> {
    let mut lines = String::new();
    for event in events {
        let row = cache_event_to_row(event);
        lines.push_str(&serde_json::to_string(&row)?);
        lines.push('\n');
    }
    Ok(lines)
}

fn epoch_secs_to_clickhouse_ts(secs: u64) -> String {
    let dt = Utc
        .timestamp_opt(secs as i64, 0)
        .single()
        .unwrap_or_else(|| Utc.timestamp_opt(0, 0).unwrap());
    format!(
        "{}.{:03}",
        dt.format("%Y-%m-%d %H:%M:%S"),
        dt.timestamp_subsec_millis()
    )
}

fn headers_json(headers: &HashMap<String, String>) -> String {
    if headers.is_empty() {
        return "{}".to_string();
    }
    serde_json::to_string(headers).unwrap_or_else(|_| "{}".to_string())
}

fn normalize_ipv4(ip: &str) -> String {
    ip.parse::<Ipv4Addr>()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| "0.0.0.0".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn sample_event() -> CacheEvent {
        CacheEvent {
            url: "https://example.com/path".to_string(),
            method: "GET".to_string(),
            status: 200,
            cache_key: "key1".to_string(),
            cache_status: "MISS".to_string(),
            timestamp: 1_700_000_001,
            headers: HashMap::from([("X-Test".to_string(), "1".to_string())]),
            user_id: Some("uid".to_string()),
            username: Some("alice".to_string()),
            client_ip: "10.0.0.5".to_string(),
            domain: "example.com".to_string(),
            response_size: 4096,
            request_duration_ms: 42,
            content_type: Some("text/html".to_string()),
            user_agent: Some("curl/8".to_string()),
            categories: vec!["news".to_string()],
            threat_sources: vec!["ut1".to_string()],
            acl_action: Some("allow".to_string()),
            session_id: "sess-abc".to_string(),
            parent_event_id: Some("evt-parent".to_string()),
            redirect_url: Some("https://example.com/next".to_string()),
            event_id: "evt-ch-1".to_string(),
        }
    }

    #[test]
    fn row_maps_fields() {
        let row = cache_event_to_row(&sample_event());
        assert_eq!(row.event_id, "evt-ch-1");
        assert_eq!(row.ts, "2023-11-14 22:13:21.000");
        assert_eq!(row.client_ip, "10.0.0.5");
        assert_eq!(row.request_duration_ms, 42);
        assert_eq!(row.session_id, "sess-abc");
        assert_eq!(row.parent_event_id.as_deref(), Some("evt-parent"));
        assert_eq!(
            row.redirect_url.as_deref(),
            Some("https://example.com/next")
        );
        assert_eq!(row.headers, r#"{"X-Test":"1"}"#);
    }

    #[test]
    fn invalid_ipv4_falls_back_to_zero() {
        let mut event = sample_event();
        event.client_ip = "::1".to_string();
        assert_eq!(cache_event_to_row(&event).client_ip, "0.0.0.0");
    }

    #[test]
    fn json_each_row_produces_ndjson() {
        let lines = json_each_row_lines(&[sample_event()]).unwrap();
        assert!(lines.ends_with('\n'));
        assert!(lines.contains("\"event_id\":\"evt-ch-1\""));
        let parsed: HttpCacheRow = serde_json::from_str(lines.trim()).unwrap();
        assert_eq!(parsed.domain, "example.com");
    }
}
