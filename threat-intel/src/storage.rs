//! TASK-TI-002: IOC Storage & SQLite Persistence.
//!
//! Provides durable storage and indexing for normalized IOCs with:
//! - Multi-feed deduplication and occurrence counting (`hit_count`).
//! - Multi-source correlation scoring.
//! - Fast exact and domain lookups.
//! - Time-To-Live (TTL) expiration and background purging.
//! - Collection run history and feed health tracking.

use crate::indicator::IndicatorKind;
use crate::normalizer::NormalizedIndicator;
use crate::scorer::{calculate_confidence, ScoringInput};
use crate::sink::SourceReport;
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, Mutex};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("SQLite database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("Serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Storage mutex poisoned")]
    Poisoned,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredIndicator {
    pub id: i64,
    pub value: String,
    pub normalized_value: String,
    pub domain: Option<String>,
    pub kind: IndicatorKind,
    pub source: String,
    pub source_weight: u8,
    pub confidence_score: u8,
    pub collected_at: DateTime<Utc>,
    pub reported_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    pub reference: Option<String>,
    pub tags: Vec<String>,
    pub is_bogon: bool,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub hit_count: u32,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct StorageStats {
    pub inserted: usize,
    pub updated: usize,
    pub dropped_bogon: usize,
}

#[derive(Clone)]
pub struct SqliteStorage {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteStorage {
    /// Opens or creates a SQLite database at the specified path and runs migrations.
    pub fn new(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let conn = Connection::open(path)?;
        let storage = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        storage.init_schema()?;
        Ok(storage)
    }

    /// Creates an in-memory SQLite database (ideal for tests and ephemeral runs).
    #[allow(dead_code)]
    pub fn in_memory() -> Result<Self, StorageError> {
        let conn = Connection::open_in_memory()?;
        let storage = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        storage.init_schema()?;
        Ok(storage)
    }

    fn init_schema(&self) -> Result<(), StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::Poisoned)?;

        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;

            CREATE TABLE IF NOT EXISTS indicators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                value TEXT NOT NULL,
                normalized_value TEXT NOT NULL,
                domain TEXT,
                kind TEXT NOT NULL,
                source TEXT NOT NULL,
                source_weight INTEGER NOT NULL,
                confidence_score INTEGER NOT NULL,
                collected_at INTEGER NOT NULL,
                reported_at INTEGER,
                expires_at INTEGER NOT NULL,
                reference TEXT,
                tags TEXT NOT NULL DEFAULT '[]',
                is_bogon INTEGER NOT NULL DEFAULT 0,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                hit_count INTEGER NOT NULL DEFAULT 1
            );

            CREATE UNIQUE INDEX IF NOT EXISTS idx_indicators_unique 
                ON indicators (normalized_value, kind, source);

            CREATE INDEX IF NOT EXISTS idx_indicators_norm 
                ON indicators (normalized_value, kind);

            CREATE INDEX IF NOT EXISTS idx_indicators_domain 
                ON indicators (domain);

            CREATE INDEX IF NOT EXISTS idx_indicators_expires 
                ON indicators (expires_at);

            CREATE INDEX IF NOT EXISTS idx_indicators_confidence 
                ON indicators (confidence_score);

            CREATE TABLE IF NOT EXISTS sources (
                name TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                weight INTEGER NOT NULL,
                last_collected_at INTEGER,
                last_status TEXT,
                last_error TEXT
            );

            CREATE TABLE IF NOT EXISTS collection_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT NOT NULL,
                indicators_count INTEGER NOT NULL,
                duration_ms INTEGER NOT NULL,
                status TEXT NOT NULL,
                finished_at INTEGER NOT NULL,
                error TEXT
            );
            "#,
        )?;

        Ok(())
    }

    /// Upsert a batch of normalized indicators into SQLite.
    pub fn upsert_batch(
        &self,
        indicators: &[NormalizedIndicator],
        ttl_secs: i64,
    ) -> Result<StorageStats, StorageError> {
        let mut conn = self.conn.lock().map_err(|_| StorageError::Poisoned)?;
        let tx = conn.transaction()?;
        let mut stats = StorageStats::default();

        let now = Utc::now();
        let now_ts = now.timestamp();
        let expires_ts = now_ts + ttl_secs;

        for ind in indicators {
            if ind.is_private_or_bogon {
                stats.dropped_bogon += 1;
                continue;
            }

            let tags_json = serde_json::to_string(&ind.tags)?;
            let kind_str = ind.kind.as_str();
            let reported_ts = ind.reported_at.map(|dt| dt.timestamp());

            // Check if this normalized value already exists from other sources to calculate correlation
            let existing_sources_count: usize = tx.query_row(
                "SELECT COUNT(DISTINCT source) FROM indicators WHERE normalized_value = ?1 AND kind = ?2",
                params![ind.normalized_value, kind_str],
                |row| row.get(0),
            ).unwrap_or(0);

            let total_sources = (existing_sources_count + 1).max(1);
            let confidence = calculate_confidence(&ScoringInput {
                source_weight: ind.source_weight,
                source_count: total_sources,
                reported_or_collected_at: ind.reported_at.unwrap_or(ind.collected_at),
                tags: ind.tags.clone(),
            });

            let exists: bool = tx
                .query_row(
                    "SELECT 1 FROM indicators WHERE normalized_value = ?1 AND kind = ?2 AND source = ?3",
                    params![ind.normalized_value, kind_str, ind.source],
                    |_| Ok(true),
                )
                .unwrap_or(false);

            // Upsert into indicators table
            tx.execute(
                r#"
                INSERT INTO indicators (
                    value, normalized_value, domain, kind, source, source_weight,
                    confidence_score, collected_at, reported_at, expires_at, reference,
                    tags, is_bogon, first_seen, last_seen, hit_count
                ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, 1
                )
                ON CONFLICT(normalized_value, kind, source) DO UPDATE SET
                    value = excluded.value,
                    domain = excluded.domain,
                    source_weight = excluded.source_weight,
                    confidence_score = excluded.confidence_score,
                    collected_at = excluded.collected_at,
                    reported_at = excluded.reported_at,
                    expires_at = excluded.expires_at,
                    reference = excluded.reference,
                    tags = excluded.tags,
                    last_seen = excluded.last_seen,
                    hit_count = indicators.hit_count + 1
                "#,
                params![
                    ind.raw_value,
                    ind.normalized_value,
                    ind.domain,
                    kind_str,
                    ind.source,
                    ind.source_weight,
                    confidence,
                    ind.collected_at.timestamp(),
                    reported_ts,
                    expires_ts,
                    ind.reference,
                    tags_json,
                    ind.is_private_or_bogon as i32,
                    ind.collected_at.timestamp(),
                    now_ts,
                ],
            )?;

            if exists {
                stats.updated += 1;
            } else {
                stats.inserted += 1;
            }
        }

        tx.commit()?;
        Ok(stats)
    }

    /// Query an exact indicator from storage.
    #[allow(dead_code)]
    pub fn query_indicator(
        &self,
        value: &str,
        kind: Option<IndicatorKind>,
    ) -> Result<Option<StoredIndicator>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::Poisoned)?;
        let mut sql = String::from(
            r#"
            SELECT id, value, normalized_value, domain, kind, source, source_weight,
                   confidence_score, collected_at, reported_at, expires_at, reference,
                   tags, is_bogon, first_seen, last_seen, hit_count
            FROM indicators
            WHERE (normalized_value = ?1 OR value = ?1)
            "#,
        );
        if let Some(k) = kind {
            sql.push_str(&format!(" AND kind = '{}'", k.as_str()));
        }
        sql.push_str(" ORDER BY confidence_score DESC LIMIT 1");

        let result = conn
            .query_row(&sql, params![value], Self::row_to_indicator)
            .optional()?;

        Ok(result)
    }

    /// List active (non-expired) indicators exceeding `min_confidence`.
    pub fn list_active(
        &self,
        min_confidence: u8,
        kind: Option<IndicatorKind>,
        limit: usize,
    ) -> Result<Vec<StoredIndicator>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::Poisoned)?;
        let now_ts = Utc::now().timestamp();

        let mut sql = String::from(
            r#"
            SELECT id, value, normalized_value, domain, kind, source, source_weight,
                   confidence_score, collected_at, reported_at, expires_at, reference,
                   tags, is_bogon, first_seen, last_seen, hit_count
            FROM indicators
            WHERE expires_at > ?1 AND confidence_score >= ?2
            "#,
        );

        if let Some(k) = kind {
            sql.push_str(&format!(" AND kind = '{}'", k.as_str()));
        }
        sql.push_str(" ORDER BY confidence_score DESC, hit_count DESC LIMIT ?3");

        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(
            params![now_ts, min_confidence, limit as i64],
            Self::row_to_indicator,
        )?;

        let mut indicators = Vec::new();
        for ind in rows {
            indicators.push(ind?);
        }
        Ok(indicators)
    }

    /// List unique active domains for DNS RPZ zone generation.
    pub fn list_active_domains(
        &self,
        min_confidence: u8,
        limit: usize,
    ) -> Result<Vec<String>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::Poisoned)?;
        let now_ts = Utc::now().timestamp();

        let mut stmt = conn.prepare(
            r#"
            SELECT domain
            FROM indicators
            WHERE domain IS NOT NULL 
              AND domain != ''
              AND expires_at > ?1 
              AND confidence_score >= ?2
            GROUP BY domain
            ORDER BY MAX(confidence_score) DESC, COUNT(*) DESC
            LIMIT ?3
            "#,
        )?;

        let rows = stmt.query_map(params![now_ts, min_confidence, limit as i64], |row| {
            row.get::<_, String>(0)
        })?;

        let mut domains = Vec::new();
        for d in rows {
            domains.push(d?);
        }
        Ok(domains)
    }

    /// Delete all expired indicators from database.
    pub fn purge_expired(&self, now_timestamp: i64) -> Result<usize, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::Poisoned)?;
        let purged = conn.execute(
            "DELETE FROM indicators WHERE expires_at <= ?1",
            params![now_timestamp],
        )?;
        Ok(purged)
    }

    /// Delete a specific indicator by value and optional kind (for SOAR unblock actions).
    pub fn purge_indicator(
        &self,
        value: &str,
        kind: Option<IndicatorKind>,
    ) -> Result<usize, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::Poisoned)?;
        let mut sql =
            String::from("DELETE FROM indicators WHERE (normalized_value = ?1 OR value = ?1)");
        if let Some(k) = kind {
            sql.push_str(&format!(" AND kind = '{}'", k.as_str()));
        }
        let purged = conn.execute(&sql, params![value])?;
        Ok(purged)
    }

    /// Count total active indicators.
    #[allow(dead_code)]
    pub fn count_active(&self) -> Result<usize, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::Poisoned)?;
        let now_ts = Utc::now().timestamp();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM indicators WHERE expires_at > ?1",
            params![now_ts],
            |row| row.get(0),
        )?;
        Ok(count as usize)
    }

    /// Record a completed collection run into `collection_history` and update `sources`.
    pub fn record_run(&self, report: &SourceReport) -> Result<(), StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::Poisoned)?;

        conn.execute(
            r#"
            INSERT INTO sources (name, url, weight, last_collected_at, last_status, last_error)
            VALUES (?1, ?2, 80, ?3, ?4, ?5)
            ON CONFLICT(name) DO UPDATE SET
                url = excluded.url,
                last_collected_at = excluded.last_collected_at,
                last_status = excluded.last_status,
                last_error = excluded.last_error
            "#,
            params![
                report.source,
                report.url,
                report.finished_at.timestamp(),
                report.status,
                report.error,
            ],
        )?;

        conn.execute(
            r#"
            INSERT INTO collection_history (
                source, indicators_count, duration_ms, status, finished_at, error
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
            params![
                report.source,
                report.indicators as i64,
                report.duration_ms as i64,
                report.status,
                report.finished_at.timestamp(),
                report.error,
            ],
        )?;

        Ok(())
    }

    fn row_to_indicator(row: &rusqlite::Row) -> rusqlite::Result<StoredIndicator> {
        let kind_str: String = row.get(4)?;
        let kind = match kind_str.as_str() {
            "url" => IndicatorKind::Url,
            "ip" => IndicatorKind::Ip,
            _ => IndicatorKind::Domain,
        };

        let tags_str: String = row.get(12)?;
        let tags: Vec<String> = serde_json::from_str(&tags_str).unwrap_or_default();

        let collected_ts: i64 = row.get(8)?;
        let reported_ts: Option<i64> = row.get(9)?;
        let expires_ts: i64 = row.get(10)?;
        let first_seen_ts: i64 = row.get(14)?;
        let last_seen_ts: i64 = row.get(15)?;

        Ok(StoredIndicator {
            id: row.get(0)?,
            value: row.get(1)?,
            normalized_value: row.get(2)?,
            domain: row.get(3)?,
            kind,
            source: row.get(5)?,
            source_weight: row.get(6)?,
            confidence_score: row.get(7)?,
            collected_at: DateTime::from_timestamp(collected_ts, 0).unwrap_or_else(Utc::now),
            reported_at: reported_ts.and_then(|ts| DateTime::from_timestamp(ts, 0)),
            expires_at: DateTime::from_timestamp(expires_ts, 0).unwrap_or_else(Utc::now),
            reference: row.get(11)?,
            tags,
            is_bogon: row.get::<_, i32>(13)? != 0,
            first_seen: DateTime::from_timestamp(first_seen_ts, 0).unwrap_or_else(Utc::now),
            last_seen: DateTime::from_timestamp(last_seen_ts, 0).unwrap_or_else(Utc::now),
            hit_count: row.get(16)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::indicator::{FeedMeta, RawIndicator};

    struct TestFeed;
    impl FeedMeta for TestFeed {
        fn name(&self) -> &'static str {
            "openphish"
        }
        fn weight(&self) -> u8 {
            85
        }
    }

    #[test]
    fn test_sqlite_upsert_and_query() {
        let storage = SqliteStorage::in_memory().unwrap();
        let raw1 = RawIndicator::new(
            "https://evil.example.com/phish",
            IndicatorKind::Url,
            &TestFeed,
        );
        let raw2 = RawIndicator::new("192.168.1.1", IndicatorKind::Ip, &TestFeed); // bogon
        let raw3 = RawIndicator::new("malware-domain.com", IndicatorKind::Domain, &TestFeed);

        let norm1 = NormalizedIndicator::from_raw(&raw1, 85).unwrap();
        let norm2 = NormalizedIndicator::from_raw(&raw2, 85).unwrap();
        let norm3 = NormalizedIndicator::from_raw(&raw3, 85).unwrap();

        let stats = storage
            .upsert_batch(&[norm1.clone(), norm2, norm3], 3600)
            .unwrap();
        assert_eq!(stats.inserted, 2);
        assert_eq!(stats.dropped_bogon, 1);

        // Query by normalized value
        let res = storage
            .query_indicator("https://evil.example.com/phish", Some(IndicatorKind::Url))
            .unwrap();
        assert!(res.is_some());
        let ind = res.unwrap();
        assert_eq!(ind.domain, Some("evil.example.com".to_string()));
        assert_eq!(ind.confidence_score, 85);
        assert_eq!(ind.hit_count, 1);

        // Re-inserting the same indicator increases hit_count
        let stats2 = storage.upsert_batch(&[norm1], 3600).unwrap();
        assert_eq!(stats2.updated, 1);

        let res2 = storage
            .query_indicator("https://evil.example.com/phish", None)
            .unwrap()
            .unwrap();
        assert_eq!(res2.hit_count, 2);
    }

    #[test]
    fn test_list_active_and_domains() {
        let storage = SqliteStorage::in_memory().unwrap();
        let raw1 = RawIndicator::new("phish.test.org", IndicatorKind::Domain, &TestFeed);
        let raw2 = RawIndicator::new("http://sub.victim.net/login", IndicatorKind::Url, &TestFeed);

        let norm1 = NormalizedIndicator::from_raw(&raw1, 90).unwrap();
        let norm2 = NormalizedIndicator::from_raw(&raw2, 80).unwrap();

        storage.upsert_batch(&[norm1, norm2], 3600).unwrap();

        let active = storage.list_active(80, None, 10).unwrap();
        assert_eq!(active.len(), 2);

        let domains = storage.list_active_domains(80, 10).unwrap();
        assert_eq!(domains.len(), 2);
        assert!(domains.contains(&"phish.test.org".to_string()));
        assert!(domains.contains(&"sub.victim.net".to_string()));
    }

    #[test]
    fn test_purge_expired() {
        let storage = SqliteStorage::in_memory().unwrap();
        let raw = RawIndicator::new("temp-threat.com", IndicatorKind::Domain, &TestFeed);
        let norm = NormalizedIndicator::from_raw(&raw, 80).unwrap();

        // Expire immediately (-10 seconds)
        storage.upsert_batch(&[norm], -10).unwrap();

        let purged = storage.purge_expired(Utc::now().timestamp()).unwrap();
        assert_eq!(purged, 1);

        assert_eq!(storage.count_active().unwrap(), 0);
    }
}
