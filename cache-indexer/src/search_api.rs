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
        let decision_source = sanitize_filter(
            query
                .get("decision_source")
                .map(String::as_str)
                .unwrap_or(""),
        );
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

        let offset = query
            .get("offset")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0);
        let order = query
            .get("order")
            .map(String::as_str)
            .unwrap_or("desc")
            .to_ascii_lowercase();
        let envelope = query
            .get("envelope")
            .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false);

        let format = query.get("format").map(String::as_str).unwrap_or("json");
        let search = SearchQuery {
            from_ts: from,
            to_ts: to,
            domain,
            username,
            session_id: session_id.clone(),
            decision_source,
            offset,
            limit,
            order,
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
        let json = if envelope {
            serde_json::to_string(&serde_json::json!({
                "count": rows.len(),
                "offset": offset,
                "limit": limit,
                "hits": rows,
            }))?
        } else {
            serde_json::to_string(&rows)?
        };
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

fn search_api_fail_closed() -> bool {
    // Mirror proxy control-plane posture: production fails closed unless lab override.
    let allow_insecure = std::env::var("SEARCH_API_ALLOW_INSECURE")
        .or_else(|_| std::env::var("CONTROL_API_ALLOW_INSECURE"))
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false);
    if allow_insecure {
        return false;
    }
    let profile = std::env::var("DEPLOYMENT_PROFILE").unwrap_or_else(|_| "production".to_string());
    matches!(profile.to_ascii_lowercase().as_str(), "production" | "prod")
}

fn check_bearer(expected: Option<&str>, auth_header: Option<&str>) -> bool {
    match expected {
        Some(expected) => auth_header
            .and_then(|v| v.strip_prefix("Bearer "))
            .is_some_and(|token| constant_time_eq(token.as_bytes(), expected.as_bytes())),
        None => !search_api_fail_closed(),
    }
}

/// Compares secrets without an early exit on the first differing byte, so
/// response timing does not leak a token prefix (AS-16). Mirrors
/// `bsdm_proxy::security_util::constant_time_eq`; only the length is revealed.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    std::hint::black_box(diff) == 0
}

/// Escapes one CSV cell (RFC 4180) and neutralises spreadsheet formulas
/// (AS-17): a cell starting with `= + - @`, TAB or CR is prefixed with `'`
/// so Excel/LibreOffice/Sheets treat it as text; cells containing `,` `"`
/// CR or LF are quoted so injected line breaks cannot forge report rows.
fn csv_field(value: &str) -> String {
    let needs_guard = value
        .chars()
        .next()
        .is_some_and(|c| matches!(c, '=' | '+' | '-' | '@' | '\t' | '\r'));
    let guarded = if needs_guard {
        format!("'{value}")
    } else {
        value.to_string()
    };
    if guarded.contains([',', '"', '\r', '\n']) {
        format!("\"{}\"", guarded.replace('"', "\"\""))
    } else {
        guarded
    }
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
        "decision_source",
        "acl_action",
        "acl_rule_id",
        "acl_reason",
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
            h.decision_source.clone().unwrap_or_default(),
            h.acl_action.clone().unwrap_or_default(),
            h.acl_rule_id.clone().unwrap_or_default(),
            h.acl_reason.clone().unwrap_or_default(),
        ];
        out.push_str(
            &row.iter()
                .map(|v| csv_field(v))
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

    #[test]
    fn bearer_check_uses_exact_token_match() {
        assert!(check_bearer(Some("s3cret"), Some("Bearer s3cret")));
        assert!(!check_bearer(Some("s3cret"), Some("Bearer s3cre")));
        assert!(!check_bearer(Some("s3cret"), Some("Bearer s3cret0")));
        assert!(!check_bearer(Some("s3cret"), Some("Bearer S3cret")));
        assert!(!check_bearer(Some("s3cret"), Some("s3cret")));
        assert!(!check_bearer(Some("s3cret"), None));
        assert!(constant_time_eq(b"", b""));
        assert!(!constant_time_eq(b"a", b""));
    }

    #[test]
    fn csv_field_neutralises_formulas_and_line_breaks() {
        assert_eq!(csv_field("alice"), "alice");
        assert_eq!(csv_field(""), "");
        assert_eq!(
            csv_field("=HYPERLINK(\"http://x\")"),
            "\"'=HYPERLINK(\"\"http://x\"\")\""
        );
        assert_eq!(csv_field("+1"), "'+1");
        assert_eq!(csv_field("-2+3"), "'-2+3");
        assert_eq!(csv_field("@SUM(A1)"), "'@SUM(A1)");
        assert_eq!(csv_field("\tx"), "'\tx");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("evil\r\n1,forged"), "\"evil\r\n1,forged\"");
        assert_eq!(csv_field("\rx"), "\"'\rx\"");
        assert_eq!(csv_field("a\nb"), "\"a\nb\"");
        // Mid-cell operators are harmless and left alone.
        assert_eq!(csv_field("a=b"), "a=b");
    }

    #[tokio::test]
    async fn csv_export_escapes_injected_username() {
        let memory = Arc::new(EventStore::Memory(crate::store::MemoryStore::new(100)));
        let api = SearchApi::new(memory.clone(), SearchApiConfig::from_env());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let event = format!(
            r#"{{"url":"https://a/","method":"GET","status":200,"cache_key":"k","timestamp":{now},"client_ip":"1.1.1.1","domain":"a","response_size":0,"request_duration_ms":1,"event_id":"e1","username":"=cmd|' /C calc'!A0\n9,forged"}}"#
        );
        api.handle_ingest(event.as_bytes()).await.unwrap();
        let mut query = HashMap::new();
        query.insert("format".to_string(), "csv".to_string());
        let (status, _, body) = api.handle_get(&query).await.unwrap();
        assert_eq!(status, 200);
        let csv = String::from_utf8(body).unwrap();
        assert!(
            csv.contains("\"'=cmd|' /C calc'!A0\n9,forged\""),
            "unexpected CSV: {csv}"
        );
        assert!(!csv.contains(",=cmd"));
    }

    #[tokio::test]
    async fn envelope_response_format() {
        let memory = Arc::new(EventStore::Memory(crate::store::MemoryStore::new(100)));
        let api = SearchApi::new(memory, SearchApiConfig::from_env());

        let mut query = HashMap::new();
        query.insert("envelope".to_string(), "true".to_string());
        query.insert("limit".to_string(), "50".to_string());

        let (status, content_type, body) = api.handle_get(&query).await.unwrap();
        assert_eq!(status, 200);
        assert_eq!(content_type, "application/json");

        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["count"], 0);
        assert_eq!(json["offset"], 0);
        assert_eq!(json["limit"], 50);
        assert!(json["hits"].is_array());
    }
}
