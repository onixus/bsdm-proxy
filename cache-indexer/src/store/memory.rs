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
            .filter(|e| {
                query.decision_source.is_empty()
                    || e.decision_source.as_deref().unwrap_or("") == query.decision_source.as_str()
            })
            .map(event_to_hit)
            .collect();
        if query.session_timeline || query.order.eq_ignore_ascii_case("asc") {
            hits.sort_by_key(|h| h.ts);
        } else {
            hits.sort_by_key(|h| std::cmp::Reverse(h.ts));
        }
        let skip = query.offset as usize;
        let take = query.limit as usize;
        if skip >= hits.len() {
            return Vec::new();
        }
        hits.into_iter().skip(skip).take(take).collect()
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
        decision_source: e.decision_source.clone(),
        acl_action: e.acl_action.clone(),
        acl_rule_id: e.acl_rule_id.clone(),
        acl_reason: e.acl_reason.clone(),
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
            acl_rule_id: None,
            acl_reason: None,
            session_id: "s1".into(),
            parent_event_id: None,
            redirect_url: None,
            dlp_violation: None,
            casb_alert: None,
            decision_source: None,
            bypass_reason: None,
            threat_shadow_match: None,
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
            decision_source: String::new(),
            offset: 0,
            limit: 10,
            order: "desc".into(),
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
            decision_source: String::new(),
            offset: 0,
            limit: 10,
            order: "desc".into(),
            session_timeline: true,
        });
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].ts, 2);
        assert_eq!(hits[1].ts, 3);
    }

    #[test]
    fn filters_by_decision_source() {
        let store = MemoryStore::new(10);
        let mut mitm = sample("a.com", 1);
        mitm.decision_source = Some("mitm".into());
        let mut sni = sample("b.com", 2);
        sni.decision_source = Some("sni".into());
        store.insert_batch(&[mitm, sni]);

        let hits = store.search(&SearchQuery {
            from_ts: 0,
            to_ts: 100,
            domain: String::new(),
            username: String::new(),
            session_id: String::new(),
            decision_source: "mitm".into(),
            offset: 0,
            limit: 10,
            order: "desc".into(),
            session_timeline: false,
        });
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].domain, "a.com");
        assert_eq!(hits[0].decision_source.as_deref(), Some("mitm"));
    }

    #[test]
    fn exposes_acl_decision_details() {
        let store = MemoryStore::new(10);
        let mut blocked = sample("blocked.example", 1);
        blocked.status = 403;
        blocked.cache_status = "BLOCKED".into();
        blocked.acl_action = Some("deny".into());
        blocked.acl_rule_id = Some("deny-malware".into());
        blocked.acl_reason = Some("malware category denied".into());
        store.insert_batch(&[blocked]);

        let hits = store.search(&SearchQuery {
            from_ts: 0,
            to_ts: 100,
            domain: String::new(),
            username: String::new(),
            session_id: String::new(),
            decision_source: String::new(),
            offset: 0,
            limit: 10,
            order: "desc".into(),
            session_timeline: false,
        });
        assert_eq!(hits[0].acl_action.as_deref(), Some("deny"));
        assert_eq!(hits[0].acl_rule_id.as_deref(), Some("deny-malware"));
        assert_eq!(
            hits[0].acl_reason.as_deref(),
            Some("malware category denied")
        );
    }

    #[test]
    fn pagination_and_sorting() {
        let store = MemoryStore::new(10);
        store.insert_batch(&[
            sample("a.com", 10),
            sample("b.com", 20),
            sample("c.com", 30),
        ]);

        let asc_page1 = store.search(&SearchQuery {
            from_ts: 0,
            to_ts: 100,
            domain: String::new(),
            username: String::new(),
            session_id: String::new(),
            decision_source: String::new(),
            offset: 0,
            limit: 2,
            order: "asc".into(),
            session_timeline: false,
        });
        assert_eq!(asc_page1.len(), 2);
        assert_eq!(asc_page1[0].ts, 10);
        assert_eq!(asc_page1[1].ts, 20);

        let asc_page2 = store.search(&SearchQuery {
            from_ts: 0,
            to_ts: 100,
            domain: String::new(),
            username: String::new(),
            session_id: String::new(),
            decision_source: String::new(),
            offset: 2,
            limit: 2,
            order: "asc".into(),
            session_timeline: false,
        });
        assert_eq!(asc_page2.len(), 1);
        assert_eq!(asc_page2[0].ts, 30);
    }
}
