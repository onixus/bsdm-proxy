//! In-memory ring buffer event store (Lite / tests).

use crate::store::{SearchHit, SearchQuery};
use bsdm_events::{document_id, CacheEvent};
use std::collections::VecDeque;
use std::sync::Mutex;

pub struct MemoryStore {
    max_rows: usize,
    rows: Mutex<VecDeque<CacheEvent>>,
}

impl MemoryStore {
    pub fn new(max_rows: usize) -> Self {
        Self {
            max_rows: max_rows.max(1),
            rows: Mutex::new(VecDeque::new()),
        }
    }

    pub fn insert_batch(&self, events: &[CacheEvent]) {
        let mut guard = self.rows.lock().expect("memory store lock");
        for event in events {
            let mut e = event.clone();
            if e.event_id.is_empty() {
                e.event_id = document_id(&e);
            }
            guard.push_back(e);
            while guard.len() > self.max_rows {
                guard.pop_front();
            }
        }
    }

    pub fn search(&self, query: &SearchQuery) -> Vec<SearchHit> {
        let guard = self.rows.lock().expect("memory store lock");
        let mut hits: Vec<SearchHit> = guard
            .iter()
            .filter(|e| e.timestamp >= query.from_ts && e.timestamp <= query.to_ts)
            .filter(|e| query.domain.is_empty() || e.domain == query.domain)
            .filter(|e| {
                query.username.is_empty()
                    || e.username.as_deref().unwrap_or("") == query.username.as_str()
            })
            .filter(|e| query.session_id.is_empty() || e.session_id == query.session_id)
            .map(event_to_hit)
            .collect();
        if query.session_timeline {
            hits.sort_by_key(|h| h.ts);
        } else {
            hits.sort_by_key(|h| std::cmp::Reverse(h.ts));
        }
        hits.truncate(query.limit as usize);
        hits
    }
}

fn event_to_hit(e: &CacheEvent) -> SearchHit {
    SearchHit {
        ts: e.timestamp,
        username: e.username.clone(),
        client_ip: e.client_ip.clone(),
        url: e.url.clone(),
        method: e.method.clone(),
        status: e.status,
        cache_status: e.cache_status.clone(),
        domain: e.domain.clone(),
        event_id: if e.event_id.is_empty() {
            document_id(e)
        } else {
            e.event_id.clone()
        },
        session_id: e.session_id.clone(),
        parent_event_id: e.parent_event_id.clone(),
        redirect_url: e.redirect_url.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn sample(domain: &str, ts: u64) -> CacheEvent {
        CacheEvent {
            url: format!("https://{domain}/"),
            method: "GET".into(),
            status: 200,
            cache_key: "k".into(),
            cache_status: "MISS".into(),
            timestamp: ts,
            headers: HashMap::new(),
            user_id: None,
            username: Some("alice".into()),
            client_ip: "10.0.0.1".into(),
            domain: domain.into(),
            response_size: 1,
            request_duration_ms: 1,
            content_type: None,
            user_agent: None,
            categories: vec![],
            threat_sources: vec![],
            acl_action: None,
            session_id: "s1".into(),
            parent_event_id: None,
            redirect_url: None,
            event_id: format!("e-{ts}"),
        }
    }

    #[test]
    fn filters_and_limits() {
        let store = MemoryStore::new(100);
        store.insert_batch(&[sample("a.com", 100), sample("b.com", 200)]);
        let hits = store.search(&SearchQuery {
            from_ts: 0,
            to_ts: 1000,
            domain: "a.com".into(),
            username: String::new(),
            session_id: String::new(),
            limit: 10,
            session_timeline: false,
        });
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].domain, "a.com");
    }

    #[test]
    fn rings_at_max() {
        let store = MemoryStore::new(2);
        store.insert_batch(&[sample("a.com", 1), sample("a.com", 2), sample("a.com", 3)]);
        let hits = store.search(&SearchQuery {
            from_ts: 0,
            to_ts: 100,
            domain: String::new(),
            username: String::new(),
            session_id: String::new(),
            limit: 10,
            session_timeline: true,
        });
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].ts, 2);
        assert_eq!(hits[1].ts, 3);
    }
}
