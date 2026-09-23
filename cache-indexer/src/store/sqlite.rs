//! SQLite-backed event store for Lite analytics.

use crate::metrics::IndexerMetrics;
use crate::store::{SearchHit, SearchQuery};
use bsdm_events::{document_id, CacheEvent};
use rusqlite::{params, Connection, OpenFlags};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};
use tracing::{error, info};

const DEFAULT_WRITE_QUEUE_CAPACITY: usize = 64;
const DEFAULT_BATCH_MAX_EVENTS: usize = 500;
const DEFAULT_BUSY_TIMEOUT_MS: u64 = 5_000;

static NEXT_MEMORY_DATABASE: AtomicU64 = AtomicU64::new(1);

type StoreResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct WriteRequest {
    events: Vec<CacheEvent>,
    completed: oneshot::Sender<Result<(), String>>,
}

pub struct SqliteStore {
    writer: mpsc::Sender<WriteRequest>,
    reader: Arc<Mutex<Connection>>,
    metrics: Arc<IndexerMetrics>,
    queue_capacity: usize,
    _writer_task: tokio::task::JoinHandle<()>,
}

impl SqliteStore {
    pub async fn open(
        path: &str,
        max_rows: usize,
        metrics: Arc<IndexerMetrics>,
    ) -> StoreResult<Self> {
        let queue_capacity = env_usize("SQLITE_WRITE_QUEUE_CAPACITY", DEFAULT_WRITE_QUEUE_CAPACITY);
        let max_batch_events = env_usize("SQLITE_BATCH_MAX_EVENTS", DEFAULT_BATCH_MAX_EVENTS);
        let busy_timeout = Duration::from_millis(env_u64(
            "SQLITE_BUSY_TIMEOUT_MS",
            DEFAULT_BUSY_TIMEOUT_MS,
        ));
        let max_rows = max_rows.max(1);
        let path = path.to_string();

        let (writer_connection, reader_connection, initial_rows) =
            tokio::task::spawn_blocking(move || initialize_connections(&path, busy_timeout))
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                    e.to_string().into()
                })??;

        let (writer, receiver) = mpsc::channel(queue_capacity);
        let writer_metrics = Arc::clone(&metrics);
        let writer_task = tokio::task::spawn_blocking(move || {
            run_writer(
                writer_connection,
                receiver,
                max_rows,
                max_batch_events,
                initial_rows,
                writer_metrics,
            );
        });

        info!(
            queue_capacity,
            max_batch_events,
            max_rows,
            initial_rows,
            "SQLite writer actor started"
        );

        Ok(Self {
            writer,
            reader: Arc::new(Mutex::new(reader_connection)),
            metrics,
            queue_capacity,
            _writer_task: writer_task,
        })
    }

    pub async fn insert_batch(&self, events: &[CacheEvent]) -> StoreResult<()> {
        if events.is_empty() {
            return Ok(());
        }

        let (completed, result) = oneshot::channel();
        let request = WriteRequest {
            events: events.to_vec(),
            completed,
        };

        if self.writer.capacity() == 0 {
            self.metrics.record_sqlite_writer_saturation();
        }
        self.writer
            .send(request)
            .await
            .map_err(|_| "SQLite writer task stopped")?;
        self.metrics.set_sqlite_writer_queue_depth(
            self.queue_capacity.saturating_sub(self.writer.capacity()),
        );

        match result.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(e.into()),
            Err(_) => Err("SQLite writer task stopped before acknowledging the batch".into()),
        }
    }

    pub async fn search(&self, query: &SearchQuery) -> StoreResult<Vec<SearchHit>> {
        let reader = Arc::clone(&self.reader);
        let query = query.clone();
        let result = tokio::task::spawn_blocking(move || -> Result<Vec<SearchHit>, String> {
            let connection = reader
                .lock()
                .map_err(|_| "SQLite reader lock poisoned".to_string())?;
            search_connection(&connection, &query).map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?;

        result.map_err(Into::into)
    }
}

fn initialize_connections(
    path: &str,
    busy_timeout: Duration,
) -> StoreResult<(Connection, Connection, usize)> {
    if path != ":memory:" && !path.starts_with("file:") {
        if let Some(parent) = Path::new(path).parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
    }

    let target = if path == ":memory:" {
        let id = NEXT_MEMORY_DATABASE.fetch_add(1, Ordering::Relaxed);
        format!(
            "file:bsdm-proxy-events-{}-{id}?mode=memory&cache=shared",
            std::process::id()
        )
    } else {
        path.to_string()
    };

    let writer = open_connection(&target)?;
    writer.busy_timeout(busy_timeout)?;
    initialize_schema(&writer)?;
    let initial_rows = row_count(&writer)?;

    let reader = open_connection(&target)?;
    reader.busy_timeout(busy_timeout)?;
    reader.execute_batch("PRAGMA query_only=ON;")?;

    Ok((writer, reader, initial_rows))
}

fn open_connection(target: &str) -> Result<Connection, rusqlite::Error> {
    if target.starts_with("file:") {
        Connection::open_with_flags(
            target,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_URI,
        )
    } else {
        Connection::open(target)
    }
}

fn run_writer(
    mut connection: Connection,
    mut receiver: mpsc::Receiver<WriteRequest>,
    max_rows: usize,
    max_batch_events: usize,
    mut tracked_rows: usize,
    metrics: Arc<IndexerMetrics>,
) {
    while let Some(first) = receiver.blocking_recv() {
        let mut requests = vec![first];
        let mut event_count = requests[0].events.len();

        while event_count < max_batch_events {
            match receiver.try_recv() {
                Ok(request) => {
                    event_count = event_count.saturating_add(request.events.len());
                    requests.push(request);
                }
                Err(mpsc::error::TryRecvError::Empty)
                | Err(mpsc::error::TryRecvError::Disconnected) => break,
            }
        }
        metrics.set_sqlite_writer_queue_depth(receiver.len());

        let started = Instant::now();
        let result = write_requests(&mut connection, &requests, max_rows, &mut tracked_rows)
            .map_err(|e| e.to_string());
        metrics.record_sqlite_writer_batch(
            requests.len(),
            event_count,
            started,
            result.is_ok(),
        );

        if let Err(ref e) = result {
            error!(
                error = %e,
                requests = requests.len(),
                events = event_count,
                "SQLite writer transaction failed"
            );
        }
        for request in requests {
            let _ = request.completed.send(result.clone());
        }
    }

    metrics.set_sqlite_writer_queue_depth(0);
    info!("SQLite writer actor stopped after draining its queue");
}

fn write_requests(
    connection: &mut Connection,
    requests: &[WriteRequest],
    max_rows: usize,
    tracked_rows: &mut usize,
) -> StoreResult<()> {
    let transaction = connection.transaction()?;
    let mut inserted_rows = 0usize;
    {
        let mut insert_statement = transaction.prepare(
            r#"
            INSERT INTO events (
              event_id, ts, domain, username, client_ip, url, method, status,
              cache_status, session_id, parent_event_id, redirect_url, decision_source,
              acl_action, acl_rule_id, acl_reason, payload
            ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)
            ON CONFLICT(event_id) DO NOTHING
            "#,
        )?;
        let mut update_statement = transaction.prepare(
            r#"
            UPDATE events SET
              ts=?2,
              domain=?3,
              username=?4,
              client_ip=?5,
              url=?6,
              method=?7,
              status=?8,
              cache_status=?9,
              session_id=?10,
              parent_event_id=?11,
              redirect_url=?12,
              decision_source=?13,
              acl_action=?14,
              acl_rule_id=?15,
              acl_reason=?16,
              payload=?17
            WHERE event_id=?1
            "#,
        )?;

        for request in requests {
            for event in &request.events {
                let normalized;
                let event = if event.event_id.is_empty() {
                    let mut value = event.clone();
                    value.event_id = document_id(&value);
                    normalized = value;
                    &normalized
                } else {
                    event
                };
                let payload = serde_json::to_string(event)?;
                let inserted = insert_statement.execute(params![
                    event.event_id.as_str(),
                    event.timestamp as i64,
                    event.domain.as_str(),
                    event.username.as_deref(),
                    event.client_ip.as_str(),
                    event.url.as_str(),
                    event.method.as_str(),
                    event.status as i64,
                    event.cache_status.as_str(),
                    event.session_id.as_str(),
                    event.parent_event_id.as_deref(),
                    event.redirect_url.as_deref(),
                    event.decision_source.as_deref(),
                    event.acl_action.as_deref(),
                    event.acl_rule_id.as_deref(),
                    event.acl_reason.as_deref(),
                    payload.as_str(),
                ])?;
                if inserted == 0 {
                    update_statement.execute(params![
                        event.event_id.as_str(),
                        event.timestamp as i64,
                        event.domain.as_str(),
                        event.username.as_deref(),
                        event.client_ip.as_str(),
                        event.url.as_str(),
                        event.method.as_str(),
                        event.status as i64,
                        event.cache_status.as_str(),
                        event.session_id.as_str(),
                        event.parent_event_id.as_deref(),
                        event.redirect_url.as_deref(),
                        event.decision_source.as_deref(),
                        event.acl_action.as_deref(),
                        event.acl_rule_id.as_deref(),
                        event.acl_reason.as_deref(),
                        payload.as_str(),
                    ])?;
                } else {
                    inserted_rows = inserted_rows.saturating_add(inserted);
                }
            }
        }
    }

    // The actor is the only writer, so an exact startup COUNT plus the number
    // of successful INSERTs is enough to maintain the row count without a
    // full-table scan after every transaction. Conflicting event IDs take the
    // UPDATE path and do not change the tracked count.
    let rows_after_upsert = tracked_rows.saturating_add(inserted_rows);
    let rows_after_commit = if rows_after_upsert > max_rows {
        let excess = rows_after_upsert - max_rows;
        transaction.execute(
            "DELETE FROM events WHERE event_id IN (
               SELECT event_id FROM events ORDER BY ts ASC LIMIT ?1
             )",
            params![i64::try_from(excess).unwrap_or(i64::MAX)],
        )?;
        max_rows
    } else {
        rows_after_upsert
    };

    transaction.commit()?;
    *tracked_rows = rows_after_commit;
    Ok(())
}

fn row_count(connection: &Connection) -> Result<usize, rusqlite::Error> {
    let count: i64 = connection.query_row("SELECT count(*) FROM events", [], |row| row.get(0))?;
    Ok(usize::try_from(count).unwrap_or(usize::MAX))
}

fn search_connection(connection: &Connection, query: &SearchQuery) -> StoreResult<Vec<SearchHit>> {
    let order = if query.session_timeline || query.order.eq_ignore_ascii_case("asc") {
        "ts ASC"
    } else {
        "ts DESC"
    };
    let sql = format!(
        "SELECT ts, username, client_ip, url, method, status, cache_status, domain, \
         event_id, session_id, parent_event_id, redirect_url, decision_source, \
         acl_action, acl_rule_id, acl_reason \
         FROM events \
         WHERE ts >= ?1 AND ts <= ?2 \
           AND (?3 = '' OR domain = ?3) \
           AND (?4 = '' OR username = ?4) \
           AND (?5 = '' OR session_id = ?5) \
           AND (?6 = '' OR decision_source = ?6) \
         ORDER BY {order} \
         LIMIT ?7 OFFSET ?8"
    );
    let mut statement = connection.prepare(&sql)?;
    let rows = statement.query_map(
        params![
            query.from_ts as i64,
            query.to_ts as i64,
            query.domain.as_str(),
            query.username.as_str(),
            query.session_id.as_str(),
            query.decision_source.as_str(),
            query.limit as i64,
            query.offset as i64,
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
                decision_source: row.get(12)?,
                acl_action: row.get(13)?,
                acl_rule_id: row.get(14)?,
                acl_reason: row.get(15)?,
            })
        },
    )?;
    let mut output = Vec::new();
    for row in rows {
        output.push(row?);
    }
    Ok(output)
}

fn initialize_schema(connection: &Connection) -> StoreResult<()> {
    connection.execute_batch(
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
              decision_source TEXT,
              acl_action TEXT,
              acl_rule_id TEXT,
              acl_reason TEXT,
              payload TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
            CREATE INDEX IF NOT EXISTS idx_events_domain_ts ON events(domain, ts);
            CREATE INDEX IF NOT EXISTS idx_events_user_ts ON events(username, ts);
            CREATE INDEX IF NOT EXISTS idx_events_session_ts ON events(session_id, ts);
            "#,
    )?;
    if !has_column(connection, "events", "decision_source")? {
        connection.execute("ALTER TABLE events ADD COLUMN decision_source TEXT", [])?;
    }
    for column in ["acl_action", "acl_rule_id", "acl_reason"] {
        if !has_column(connection, "events", column)? {
            connection.execute(&format!("ALTER TABLE events ADD COLUMN {column} TEXT"), [])?;
        }
    }
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_decision_source_ts
         ON events(decision_source, ts)",
        [],
    )?;
    Ok(())
}

fn has_column(
    connection: &Connection,
    table: &str,
    column: &str,
) -> Result<bool, rusqlite::Error> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let names = statement.query_map([], |row| row.get::<_, String>(1))?;
    for name in names {
        if name? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|&value| value > 0)
        .unwrap_or(default)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|&value| value > 0)
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::task::JoinSet;

    fn sample(domain: &str, ts: u64, id: &str, decision_source: Option<&str>) -> CacheEvent {
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
            acl_rule_id: None,
            acl_reason: None,
            session_id: "sess".into(),
            parent_event_id: None,
            redirect_url: None,
            dlp_violation: None,
            casb_alert: None,
            decision_source: decision_source.map(str::to_string),
            bypass_reason: None,
            threat_shadow_match: None,
            event_id: id.into(),
        }
    }

    fn metrics() -> Arc<IndexerMetrics> {
        Arc::new(IndexerMetrics::new().unwrap())
    }

    fn query() -> SearchQuery {
        SearchQuery {
            from_ts: 0,
            to_ts: 10_000,
            domain: String::new(),
            username: String::new(),
            session_id: String::new(),
            decision_source: String::new(),
            offset: 0,
            limit: 10_000,
            order: "asc".into(),
            session_timeline: false,
        }
    }

    fn temporary_database(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "bsdm-proxy-{name}-{}-{nonce}.db",
            std::process::id()
        ))
    }

    fn remove_database(path: &Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sqlite_roundtrip() {
        let store = SqliteStore::open(":memory:", 100, metrics())
            .await
            .unwrap();
        store
            .insert_batch(&[
                sample("ex.com", 50, "e1", Some("mitm")),
                sample("other.com", 60, "e2", Some("sni")),
            ])
            .await
            .unwrap();
        let mut search = query();
        search.domain = "ex.com".into();
        search.decision_source = "mitm".into();
        let hits = store.search(&search).await.unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].event_id, "e1");
        assert_eq!(hits[0].decision_source.as_deref(), Some("mitm"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_writes_are_serialized_and_visible() {
        let metrics = metrics();
        let store = Arc::new(
            SqliteStore::open(":memory:", 1_000, Arc::clone(&metrics))
                .await
                .unwrap(),
        );
        let mut tasks = JoinSet::new();
        for index in 0..32u64 {
            let store = Arc::clone(&store);
            tasks.spawn(async move {
                let event = sample(
                    &format!("{index}.example"),
                    index,
                    &format!("e-{index}"),
                    None,
                );
                store.insert_batch(&[event]).await.unwrap();
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }

        let hits = store.search(&query()).await.unwrap();
        assert_eq!(hits.len(), 32);
        assert!(metrics.sqlite_writer_batch_events.get_sample_count() > 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn prunes_oldest_rows_inside_writer_transaction() {
        let store = SqliteStore::open(":memory:", 2, metrics()).await.unwrap();
        store
            .insert_batch(&[
                sample("one.example", 1, "e1", None),
                sample("two.example", 2, "e2", None),
                sample("three.example", 3, "e3", None),
            ])
            .await
            .unwrap();

        let hits = store.search(&query()).await.unwrap();
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].event_id, "e2");
        assert_eq!(hits[1].event_id, "e3");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn upserts_do_not_prune_other_live_rows_at_capacity() {
        let store = SqliteStore::open(":memory:", 2, metrics()).await.unwrap();
        store
            .insert_batch(&[
                sample("one.example", 1, "e1", None),
                sample("two.example", 2, "e2", None),
            ])
            .await
            .unwrap();

        for timestamp in 3..20 {
            store
                .insert_batch(&[sample("one.example", timestamp, "e1", None)])
                .await
                .unwrap();
        }

        let hits = store.search(&query()).await.unwrap();
        assert_eq!(hits.len(), 2);
        assert!(hits.iter().any(|hit| hit.event_id == "e1"));
        assert!(hits.iter().any(|hit| hit.event_id == "e2"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn migrates_existing_database_with_decision_source() {
        let path = temporary_database("migration");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE events (
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
                 );",
            )
            .unwrap();
        drop(connection);

        let store = SqliteStore::open(path.to_str().unwrap(), 100, metrics())
            .await
            .unwrap();
        store
            .insert_batch(&[sample(
                "ex.com",
                50,
                "e1",
                Some("pinning-bypass"),
            )])
            .await
            .unwrap();
        let mut search = query();
        search.decision_source = "pinning-bypass".into();
        let hits = store.search(&search).await.unwrap();
        assert_eq!(hits.len(), 1);

        drop(store);
        tokio::time::sleep(Duration::from_millis(10)).await;
        remove_database(&path);
    }
}
