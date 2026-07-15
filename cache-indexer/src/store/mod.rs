//! Pluggable event stores for Lite (memory/sqlite) and full (ClickHouse).

mod memory;
mod sqlite;

pub use memory::MemoryStore;
pub use sqlite::SqliteStore;

use bsdm_events::CacheEvent;
use std::sync::Arc;

use crate::clickhouse::ClickHouseWriter;

#[derive(Debug, Clone)]
pub struct SearchQuery {
    pub from_ts: u64,
    pub to_ts: u64,
    pub domain: String,
    pub username: String,
    pub session_id: String,
    pub limit: u32,
    pub session_timeline: bool,
}

#[derive(Debug, Clone)]
pub struct SearchHit {
    pub ts: u64,
    pub username: Option<String>,
    pub client_ip: String,
    pub url: String,
    pub method: String,
    pub status: u16,
    pub cache_status: String,
    pub domain: String,
    pub event_id: String,
    pub session_id: String,
    pub parent_event_id: Option<String>,
    pub redirect_url: Option<String>,
}

impl SearchHit {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "ts": self.ts,
            "username": self.username,
            "client_ip": self.client_ip,
            "url": self.url,
            "method": self.method,
            "status": self.status,
            "cache_status": self.cache_status,
            "domain": self.domain,
            "event_id": self.event_id,
            "session_id": self.session_id,
            "parent_event_id": self.parent_event_id,
            "redirect_url": self.redirect_url,
        })
    }
}

pub enum EventStore {
    Memory(MemoryStore),
    Sqlite(SqliteStore),
    ClickHouse(Arc<ClickHouseWriter>),
}

impl EventStore {
    pub fn backend_name(&self) -> &'static str {
        match self {
            Self::Memory(_) => "memory",
            Self::Sqlite(_) => "sqlite",
            Self::ClickHouse(_) => "clickhouse",
        }
    }

    pub async fn insert_batch(
        &self,
        events: &[CacheEvent],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match self {
            Self::Memory(s) => {
                s.insert_batch(events);
                Ok(())
            }
            Self::Sqlite(s) => s.insert_batch(events),
            Self::ClickHouse(w) => w
                .insert_batch(events)
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() }),
        }
    }

    pub async fn search(
        &self,
        query: &SearchQuery,
    ) -> Result<Vec<SearchHit>, Box<dyn std::error::Error + Send + Sync>> {
        match self {
            Self::Memory(s) => Ok(s.search(query)),
            Self::Sqlite(s) => s.search(query),
            Self::ClickHouse(w) => search_clickhouse(w, query).await,
        }
    }
}

async fn search_clickhouse(
    writer: &ClickHouseWriter,
    query: &SearchQuery,
) -> Result<Vec<SearchHit>, Box<dyn std::error::Error + Send + Sync>> {
    let table = format!("{}.{}", writer.database(), writer.table());
    let order = if query.session_timeline {
        "ts ASC"
    } else {
        "ts DESC"
    };
    let sql = format!(
        "SELECT toUnixTimestamp(ts) AS ts, username, toString(client_ip) AS client_ip, url, method, status, \
         cache_status, domain, event_id, session_id, parent_event_id, redirect_url \
         FROM {table} \
         WHERE ts >= fromUnixTimestamp({{from:UInt32}}) \
           AND ts <= fromUnixTimestamp({{to:UInt32}}) \
           AND (length({{domain:String}}) = 0 OR domain = {{domain:String}}) \
           AND (length({{username:String}}) = 0 OR username = {{username:String}}) \
           AND (length({{session_id:String}}) = 0 OR session_id = {{session_id:String}}) \
         ORDER BY {order} \
         LIMIT {{limit:UInt32}} \
         FORMAT JSONEachRow"
    );
    let params = vec![
        ("from", query.from_ts.to_string()),
        ("to", query.to_ts.to_string()),
        ("domain", query.domain.clone()),
        ("username", query.username.clone()),
        ("session_id", query.session_id.clone()),
        ("limit", query.limit.to_string()),
    ];
    let body = writer
        .query_with_params(&sql, &params)
        .await
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?;
    parse_search_ndjson(&body)
}

pub fn parse_search_ndjson(
    body: &str,
) -> Result<Vec<SearchHit>, Box<dyn std::error::Error + Send + Sync>> {
    let mut out = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(line)?;
        out.push(SearchHit {
            ts: json_u64(&v, "ts").unwrap_or(0),
            username: json_opt_string(&v, "username"),
            client_ip: json_string(&v, "client_ip"),
            url: json_string(&v, "url"),
            method: json_string(&v, "method"),
            status: json_u64(&v, "status").unwrap_or(0) as u16,
            cache_status: json_string(&v, "cache_status"),
            domain: json_string(&v, "domain"),
            event_id: json_string(&v, "event_id"),
            session_id: json_string(&v, "session_id"),
            parent_event_id: json_opt_string(&v, "parent_event_id"),
            redirect_url: json_opt_string(&v, "redirect_url"),
        });
    }
    Ok(out)
}

fn json_string(v: &serde_json::Value, key: &str) -> String {
    v.get(key)
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string()
}

fn json_opt_string(v: &serde_json::Value, key: &str) -> Option<String> {
    match v.get(key) {
        Some(serde_json::Value::Null) | None => None,
        Some(serde_json::Value::String(s)) if s.is_empty() => None,
        Some(serde_json::Value::String(s)) => Some(s.clone()),
        Some(other) => Some(other.to_string()),
    }
}

fn json_u64(v: &serde_json::Value, key: &str) -> Option<u64> {
    v.get(key).and_then(|x| {
        x.as_u64()
            .or_else(|| x.as_i64().map(|i| i as u64))
            .or_else(|| x.as_str().and_then(|s| s.parse().ok()))
    })
}

pub fn open_from_env() -> Result<Arc<EventStore>, Box<dyn std::error::Error + Send + Sync>> {
    let kind = std::env::var("INDEX_STORE")
        .unwrap_or_else(|_| "clickhouse".into())
        .to_ascii_lowercase();
    match kind.as_str() {
        "memory" => {
            let max = env_usize("SQLITE_MAX_ROWS", 100_000);
            Ok(Arc::new(EventStore::Memory(MemoryStore::new(max))))
        }
        "sqlite" => {
            let path = std::env::var("SQLITE_PATH")
                .unwrap_or_else(|_| "/var/lib/cache-indexer/events.db".into());
            let max = env_usize("SQLITE_MAX_ROWS", 1_000_000);
            Ok(Arc::new(EventStore::Sqlite(SqliteStore::open(&path, max)?)))
        }
        "clickhouse" => Err("clickhouse store is bootstrapped separately".into()),
        other => Err(format!("unknown INDEX_STORE={other} (memory|sqlite|clickhouse)").into()),
    }
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(default)
}
