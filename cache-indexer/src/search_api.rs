//! REST Search API (`/api/search`) and HTTP ingest (`/api/events`).

use crate::store::{EventStore, SearchQuery};
use bsdm_events::CacheEvent;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::warn;

#[derive(Clone)]
pub struct SearchApiConfig {
    pub api_token: Option<String>,
    pub ingest_token: Option<String>,
    pub max_limit: u32,
    pub default_days: u32,
}

impl SearchApiConfig {
    pub fn from_env() -> Self {
        let api_token = std::env::var("SEARCH_API_TOKEN")
            .ok()
            .filter(|t| !t.is_empty());
        let ingest_token = std::env::var("INGEST_API_TOKEN")
            .ok()
            .filter(|t| !t.is_empty())
            .or_else(|| api_token.clone());
        let max_limit = std::env::var("SEARCH_API_MAX_LIMIT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10_000);
        let default_days = std::env::var("SEARCH_API_DEFAULT_DAYS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30);
        Self {
            api_token,
            ingest_token,
            max_limit,
            default_days,
        }
    }
}

pub struct SearchApi {
    store: Arc<EventStore>,
    config: SearchApiConfig,
}

impl SearchApi {
    pub fn new(store: Arc<EventStore>, config: SearchApiConfig) -> Self {
        Self { store, config }
    }

    pub fn is_authorized(&self, auth_header: Option<&str>) -> bool {
        check_bearer(self.config.api_token.as_deref(), auth_header)
    }

    pub fn is_ingest_authorized(&self, auth_header: Option<&str>) -> bool {
        check_bearer(self.config.ingest_token.as_deref(), auth_header)
    }

    pub async fn handle_get(
        &self,
        query: &HashMap<String, String>,
    ) -> Result<(u16, String, Vec<u8>), Box<dyn std::error::Error>> {
        let domain = sanitize_filter(query.get("domain").map(String::as_str).unwrap_or(""));
        let username = sanitize_filter(query.get("username").map(String::as_str).unwrap_or(""));
        let session_id = sanitize_filter(query.get("session_id").map(String::as_str).unwrap_or(""));
        let limit = query
            .get("limit")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(1000)
            .min(self.config.max_limit);
        let days = query
            .get("days")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(self.config.default_days);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let from = query
            .get("from")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(now.saturating_sub(u64::from(days) * 86_400));
        let to = query
            .get("to")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(now);

        let format = query.get("format").map(String::as_str).unwrap_or("json");
        let search = SearchQuery {
            from_ts: from,
            to_ts: to,
            domain,
            username,
            session_id: session_id.clone(),
            limit,
            session_timeline: !session_id.is_empty(),
        };

        let hits = self
            .store
            .search(&search)
            .await
            .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;
        if format == "csv" {
            let csv = hits_to_csv(&hits);
            return Ok((200, "text/csv; charset=utf-8".to_string(), csv.into_bytes()));
        }

        let rows: Vec<serde_json::Value> = hits.iter().map(|h| h.to_json()).collect();
        let json = serde_json::to_string(&rows)?;
        Ok((200, "application/json".to_string(), json.into_bytes()))
    }

    pub async fn handle_ingest(
        &self,
        body: &[u8],
    ) -> Result<(u16, String, Vec<u8>), Box<dyn std::error::Error>> {
        let events = parse_ingest_body(body)?;
        if events.is_empty() {
            return Ok((
                400,
                "application/json".into(),
                br#"{"error":"no events"}"#.to_vec(),
            ));
        }
        let n = events.len();
        self.store
            .insert_batch(&events)
            .await
            .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;
        let msg = format!(r#"{{"accepted":{n}}}"#);
        Ok((202, "application/json".into(), msg.into_bytes()))
    }
}

fn check_bearer(expected: Option<&str>, auth_header: Option<&str>) -> bool {
    let Some(expected) = expected else {
        return true;
    };
    auth_header
        .and_then(|v| v.strip_prefix("Bearer "))
        .is_some_and(|token| token == expected)
}

fn sanitize_filter(value: &str) -> String {
    if value.len() > 256 {
        return String::new();
    }
    if value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || ".@_-%".contains(c))
    {
        value.to_string()
    } else {
        warn!("search filter rejected (invalid chars): {value}");
        String::new()
    }
}

pub fn parse_ingest_body(body: &[u8]) -> Result<Vec<CacheEvent>, Box<dyn std::error::Error>> {
    let text = std::str::from_utf8(body)?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    if trimmed.starts_with('[') {
        return Ok(serde_json::from_str(trimmed)?);
    }
    if trimmed.starts_with('{') {
        // Single object or {"events":[...]}
        let v: serde_json::Value = serde_json::from_str(trimmed)?;
        if let Some(arr) = v.get("events").and_then(|e| e.as_array()) {
            let mut out = Vec::with_capacity(arr.len());
            for item in arr {
                out.push(serde_json::from_value(item.clone())?);
            }
            return Ok(out);
        }
        return Ok(vec![serde_json::from_value(v)?]);
    }
    // NDJSON
    let mut out = Vec::new();
    for line in trimmed.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        out.push(serde_json::from_str(line)?);
    }
    Ok(out)
}

fn hits_to_csv(hits: &[crate::store::SearchHit]) -> String {
    let headers = [
        "ts",
        "username",
        "client_ip",
        "url",
        "method",
        "status",
        "cache_status",
        "domain",
        "event_id",
        "session_id",
        "parent_event_id",
        "redirect_url",
    ];
    let mut out = headers.join(",");
    out.push('\n');
    for (i, h) in hits.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        let row = [
            h.ts.to_string(),
            h.username.clone().unwrap_or_default(),
            h.client_ip.clone(),
            h.url.clone(),
            h.method.clone(),
            h.status.to_string(),
            h.cache_status.clone(),
            h.domain.clone(),
            h.event_id.clone(),
            h.session_id.clone(),
            h.parent_event_id.clone().unwrap_or_default(),
            h.redirect_url.clone().unwrap_or_default(),
        ];
        out.push_str(
            &row.iter()
                .map(|v| {
                    if v.contains(',') || v.contains('"') {
                        format!("\"{}\"", v.replace('"', "\"\""))
                    } else {
                        v.clone()
                    }
                })
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_accepts_domain() {
        assert_eq!(sanitize_filter("example.com"), "example.com");
    }

    #[test]
    fn sanitize_rejects_sqlish() {
        assert_eq!(sanitize_filter("foo' OR 1=1"), "");
    }

    #[test]
    fn parse_single_and_array() {
        let one = br#"{"url":"https://a/","method":"GET","status":200,"cache_key":"k","timestamp":1,"client_ip":"1.1.1.1","domain":"a","response_size":0,"request_duration_ms":1,"event_id":"e1"}"#;
        assert_eq!(parse_ingest_body(one).unwrap().len(), 1);
        let arr = format!("[{}]", std::str::from_utf8(one).unwrap());
        assert_eq!(parse_ingest_body(arr.as_bytes()).unwrap().len(), 1);
    }
}
