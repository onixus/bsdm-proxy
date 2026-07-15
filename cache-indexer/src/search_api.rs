//! REST Search API over ClickHouse (`/api/search` on cache-indexer admin port).

use crate::clickhouse::ClickHouseWriter;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::warn;

#[derive(Clone)]
pub struct SearchApiConfig {
    pub api_token: Option<String>,
    pub max_limit: u32,
    pub default_days: u32,
}

impl SearchApiConfig {
    pub fn from_env() -> Self {
        let api_token = std::env::var("SEARCH_API_TOKEN")
            .ok()
            .filter(|t| !t.is_empty());
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
            max_limit,
            default_days,
        }
    }
}

pub struct SearchApi {
    clickhouse: Arc<ClickHouseWriter>,
    config: SearchApiConfig,
    table_fqn: String,
}

impl SearchApi {
    pub fn new(clickhouse: Arc<ClickHouseWriter>, config: SearchApiConfig) -> Self {
        let table_fqn = format!("{}.{}", clickhouse.database(), clickhouse.table());
        Self {
            clickhouse,
            config,
            table_fqn,
        }
    }

    pub fn is_authorized(&self, auth_header: Option<&str>) -> bool {
        let Some(expected) = &self.config.api_token else {
            return true;
        };
        auth_header
            .and_then(|v| v.strip_prefix("Bearer "))
            .is_some_and(|token| token == expected)
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
        let order = if session_id.is_empty() {
            "ts DESC"
        } else {
            // Session timeline: chronological redirect chain
            "ts ASC"
        };

        let sql = format!(
            "SELECT ts, username, client_ip, url, method, status, cache_status, domain, \
             event_id, session_id, parent_event_id, redirect_url \
             FROM {table} \
             WHERE ts >= fromUnixTimestamp({{from:UInt32}}) \
               AND ts <= fromUnixTimestamp({{to:UInt32}}) \
               AND (length({{domain:String}}) = 0 OR domain = {{domain:String}}) \
               AND (length({{username:String}}) = 0 OR username = {{username:String}}) \
               AND (length({{session_id:String}}) = 0 OR session_id = {{session_id:String}}) \
             ORDER BY {order} \
             LIMIT {{limit:UInt32}} \
             FORMAT JSONEachRow",
            table = self.table_fqn,
            order = order
        );

        let params = vec![
            ("from", from.to_string()),
            ("to", to.to_string()),
            ("domain", domain),
            ("username", username),
            ("session_id", session_id),
            ("limit", limit.to_string()),
        ];

        let body = self.clickhouse.query_with_params(&sql, &params).await?;

        if format == "csv" {
            let csv = json_each_row_to_csv(&body)?;
            return Ok((200, "text/csv; charset=utf-8".to_string(), csv.into_bytes()));
        }

        let json = if body.trim().is_empty() {
            "[]".to_string()
        } else {
            let rows: Vec<serde_json::Value> = body
                .lines()
                .filter(|l| !l.trim().is_empty())
                .filter_map(|line| serde_json::from_str(line).ok())
                .collect();
            serde_json::to_string(&rows)?
        };

        Ok((200, "application/json".to_string(), json.into_bytes()))
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

fn json_each_row_to_csv(ndjson: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut lines = ndjson.lines().filter(|l| !l.trim().is_empty());
    let Some(first) = lines.next() else {
        return Ok(String::new());
    };
    let row: serde_json::Map<String, serde_json::Value> = serde_json::from_str(first)?;
    let headers: Vec<&str> = row.keys().map(String::as_str).collect();
    let mut out = headers.join(",");
    out.push('\n');
    out.push_str(&csv_row(&row, &headers));
    for line in lines {
        let row: serde_json::Map<String, serde_json::Value> = serde_json::from_str(line)?;
        out.push('\n');
        out.push_str(&csv_row(&row, &headers));
    }
    Ok(out)
}

fn csv_row(row: &serde_json::Map<String, serde_json::Value>, headers: &[&str]) -> String {
    headers
        .iter()
        .map(|h| {
            let v = row.get(*h).map(value_to_csv).unwrap_or_default();
            if v.contains(',') || v.contains('"') {
                format!("\"{}\"", v.replace('"', "\"\""))
            } else {
                v
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn value_to_csv(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
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
    fn csv_from_ndjson() {
        let ndjson = "{\"domain\":\"a.com\",\"status\":200}\n";
        let csv = json_each_row_to_csv(ndjson).unwrap();
        assert!(csv.contains("domain,status"));
        assert!(csv.contains("a.com,200"));
    }
}
