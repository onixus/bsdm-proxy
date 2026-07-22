//! SQLite-backed event store for Lite analytics.

use crate::store::{SearchHit, SearchQuery};
use bsdm_events::{document_id, CacheEvent};
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::Mutex;

pub struct SqliteStore {
    conn: Mutex<Connection>,
    max_rows: usize,
}

impl SqliteStore {
    pub fn open(
        path: &str,
        max_rows: usize,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        if path != ":memory:" {
            if let Some(parent) = Path::new(path).parent() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS events (
              event_id TEXT PRIMARY KEY,
              ts INTEGER NOT NULL,
              domain TEXT NOT NULL,
              username TEXT,
              client_ip TEXT NOT NULL,
              url TEXT NOT NULL,
              method TEXT NOT NULL,
              status INTEGER NOT NULL,
              cache_status TEXT NOT NULL,
              session_id TEXT NOT NULL DEFAULT '',
              parent_event_id TEXT,
              redirect_url TEXT,
              payload TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
            CREATE INDEX IF NOT EXISTS idx_events_domain_ts ON events(domain, ts);
            CREATE INDEX IF NOT EXISTS idx_events_user_ts ON events(username, ts);
            CREATE INDEX IF NOT EXISTS idx_events_session_ts ON events(session_id, ts);
            "#,
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
            max_rows: max_rows.max(1),
        })
    }

    pub fn insert_batch(
        &self,
        events: &[CacheEvent],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut conn = self.conn.lock().expect("sqlite lock");
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                r#"
                INSERT INTO events (
                  event_id, ts, domain, username, client_ip, url, method, status,
                  cache_status, session_id, parent_event_id, redirect_url, payload
                ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)
                ON CONFLICT(event_id) DO UPDATE SET
                  ts=excluded.ts,
                  domain=excluded.domain,
                  username=excluded.username,
                  client_ip=excluded.client_ip,
                  url=excluded.url,
                  method=excluded.method,
                  status=excluded.status,
                  cache_status=excluded.cache_status,
                  session_id=excluded.session_id,
                  parent_event_id=excluded.parent_event_id,
                  redirect_url=excluded.redirect_url,
                  payload=excluded.payload
                "#,
            )?;
            for event in events {
                let mut e = event.clone();
                if e.event_id.is_empty() {
                    e.event_id = document_id(&e);
                }
                let payload = serde_json::to_string(&e)?;
                stmt.execute(params![
                    e.event_id,
                    e.timestamp as i64,
                    e.domain,
                    e.username,
                    e.client_ip,
                    e.url,
                    e.method,
                    e.status as i64,
                    e.cache_status,
                    e.session_id,
                    e.parent_event_id,
                    e.redirect_url,
                    payload,
                ])?;
            }
        }
        tx.commit()?;
        drop(conn);

        let conn = self.conn.lock().expect("sqlite lock");
        let count: i64 = conn.query_row("SELECT count(*) FROM events", [], |r| r.get(0))?;
        if count as usize > self.max_rows {
            let excess = count as usize - self.max_rows;
            conn.execute(
                "DELETE FROM events WHERE event_id IN (
                   SELECT event_id FROM events ORDER BY ts ASC LIMIT ?1
                 )",
                params![excess as i64],
            )?;
        }
        Ok(())
    }

    pub fn search(
        &self,
        query: &SearchQuery,
    ) -> Result<Vec<SearchHit>, Box<dyn std::error::Error + Send + Sync>> {
        let order = if query.session_timeline {
            "ts ASC"
        } else {
            "ts DESC"
        };
        let sql = format!(
            "SELECT ts, username, client_ip, url, method, status, cache_status, domain, \
             event_id, session_id, parent_event_id, redirect_url \
             FROM events \
             WHERE ts >= ?1 AND ts <= ?2 \
               AND (?3 = '' OR domain = ?3) \
               AND (?4 = '' OR username = ?4) \
               AND (?5 = '' OR session_id = ?5) \
             ORDER BY {order} \
             LIMIT ?6"
        );
        let conn = self.conn.lock().expect("sqlite lock");
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(
            params![
                query.from_ts as i64,
                query.to_ts as i64,
                query.domain,
                query.username,
                query.session_id,
                query.limit as i64,
            ],
            |row| {
                Ok(SearchHit {
                    ts: row.get::<_, i64>(0)? as u64,
                    username: row.get(1)?,
                    client_ip: row.get(2)?,
                    url: row.get(3)?,
                    method: row.get(4)?,
                    status: row.get::<_, i64>(5)? as u16,
                    cache_status: row.get(6)?,
                    domain: row.get(7)?,
                    event_id: row.get(8)?,
                    session_id: row.get(9)?,
                    parent_event_id: row.get(10)?,
                    redirect_url: row.get(11)?,
                })
            },
        )?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn sample(domain: &str, ts: u64, id: &str) -> CacheEvent {
        CacheEvent {
            url: format!("https://{domain}/"),
            method: "GET".into(),
            status: 200,
            cache_key: "k".into(),
            cache_status: "HIT".into(),
            timestamp: ts,
            headers: HashMap::new(),
            user_id: None,
            username: Some("bob".into()),
            client_ip: "10.0.0.2".into(),
            domain: domain.into(),
            response_size: 2,
            request_duration_ms: 2,
            content_type: None,
            user_agent: None,
            categories: vec![],
            threat_sources: vec![],
            acl_action: None,
            session_id: "sess".into(),
            parent_event_id: None,
            redirect_url: None,
            dlp_violation: None,
            casb_alert: None,
            event_id: id.into(),
        }
    }

    #[test]
    fn sqlite_roundtrip() {
        let store = SqliteStore::open(":memory:", 100).unwrap();
        store
            .insert_batch(&[sample("ex.com", 50, "e1"), sample("other.com", 60, "e2")])
            .unwrap();
        let hits = store
            .search(&SearchQuery {
                from_ts: 0,
                to_ts: 100,
                domain: "ex.com".into(),
                username: String::new(),
                session_id: String::new(),
                limit: 10,
                session_timeline: false,
            })
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].event_id, "e1");
    }
}
