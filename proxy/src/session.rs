//! Soft browsing sessions and HTTP redirect-chain correlation for analytics events.
//!
//! - `session_id`: same client IP + principal + User-Agent within an idle window
//! - `parent_event_id`: links a follow-up request to a prior 3xx (or ACL redirect)
//!   whose `Location` matched this request URL

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use url::Url;

/// Correlation fields attached to a single emitted `CacheEvent`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCorrelation {
    pub session_id: String,
    pub parent_event_id: Option<String>,
}

#[derive(Clone)]
struct SessionEntry {
    session_id: String,
    last_seen: Instant,
}

#[derive(Clone)]
struct PendingRedirect {
    event_id: String,
    expires_at: Instant,
}

/// In-process correlator (per proxy node). Best-effort; not shared across replicas.
pub struct SessionCorrelator {
    sessions: Mutex<HashMap<String, SessionEntry>>,
    redirects: Mutex<HashMap<String, PendingRedirect>>,
    idle: Duration,
    redirect_ttl: Duration,
    max_sessions: usize,
    max_redirects: usize,
}

impl Default for SessionCorrelator {
    fn default() -> Self {
        Self::from_env()
    }
}

impl SessionCorrelator {
    pub fn from_env() -> Self {
        let idle_secs = std::env::var("SESSION_IDLE_SECONDS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1_800);
        let redirect_ttl_secs = std::env::var("SESSION_REDIRECT_TTL_SECONDS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60);
        let max_sessions = std::env::var("SESSION_MAX_KEYS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(50_000);
        let max_redirects = std::env::var("SESSION_MAX_REDIRECTS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(20_000);
        Self::new(
            Duration::from_secs(idle_secs.max(60)),
            Duration::from_secs(redirect_ttl_secs.max(5)),
            max_sessions.max(100),
            max_redirects.max(100),
        )
    }

    pub fn new(
        idle: Duration,
        redirect_ttl: Duration,
        max_sessions: usize,
        max_redirects: usize,
    ) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            redirects: Mutex::new(HashMap::new()),
            idle,
            redirect_ttl,
            max_sessions,
            max_redirects,
        }
    }

    /// Resolve soft session and optional redirect parent for an incoming request.
    pub fn begin_request(
        &self,
        client_ip: &str,
        username: Option<&str>,
        user_agent: Option<&str>,
        request_url: &str,
    ) -> SessionCorrelation {
        let session_id = self.get_or_create_session(client_ip, username, user_agent);
        let parent_event_id = self.take_pending_redirect(client_ip, request_url);
        SessionCorrelation {
            session_id,
            parent_event_id,
        }
    }

    /// After the event id is known, register a redirect hop when the response is 3xx (or ACL 302).
    pub fn note_redirect(
        &self,
        client_ip: &str,
        event_id: &str,
        status: u16,
        request_url: &str,
        location: Option<&str>,
    ) {
        if !is_redirect_status(status) {
            return;
        }
        let Some(loc) = location.filter(|s| !s.is_empty()) else {
            return;
        };
        let absolute = resolve_location(request_url, loc);
        let key = redirect_key(client_ip, &absolute);
        let mut map = self.redirects.lock().unwrap_or_else(|e| e.into_inner());
        self.evict_expired_redirects(&mut map);
        if map.len() >= self.max_redirects {
            // Drop arbitrary old entry to keep bound.
            if let Some(k) = map.keys().next().cloned() {
                map.remove(&k);
            }
        }
        map.insert(
            key,
            PendingRedirect {
                event_id: event_id.to_string(),
                expires_at: Instant::now() + self.redirect_ttl,
            },
        );
    }

    fn get_or_create_session(
        &self,
        client_ip: &str,
        username: Option<&str>,
        user_agent: Option<&str>,
    ) -> String {
        let key = session_key(client_ip, username, user_agent);
        let now = Instant::now();
        let mut map = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = map.get_mut(&key) {
            if now.duration_since(entry.last_seen) <= self.idle {
                entry.last_seen = now;
                return entry.session_id.clone();
            }
        }
        self.evict_idle_sessions(&mut map, now);
        if map.len() >= self.max_sessions {
            if let Some(k) = map.keys().next().cloned() {
                map.remove(&k);
            }
        }
        let session_id = new_session_id();
        map.insert(
            key,
            SessionEntry {
                session_id: session_id.clone(),
                last_seen: now,
            },
        );
        session_id
    }

    fn take_pending_redirect(&self, client_ip: &str, request_url: &str) -> Option<String> {
        let key = redirect_key(client_ip, request_url);
        let mut map = self.redirects.lock().unwrap_or_else(|e| e.into_inner());
        self.evict_expired_redirects(&mut map);
        map.remove(&key).map(|p| p.event_id)
    }

    fn evict_idle_sessions(&self, map: &mut HashMap<String, SessionEntry>, now: Instant) {
        map.retain(|_, e| now.duration_since(e.last_seen) <= self.idle);
    }

    fn evict_expired_redirects(&self, map: &mut HashMap<String, PendingRedirect>) {
        let now = Instant::now();
        map.retain(|_, p| p.expires_at > now);
    }
}

pub fn is_redirect_status(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

pub fn header_ci<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

pub fn resolve_location(request_url: &str, location: &str) -> String {
    let loc = location.trim();
    if loc.starts_with("http://") || loc.starts_with("https://") {
        return normalize_url(loc);
    }
    if let Ok(base) = Url::parse(request_url) {
        if let Ok(joined) = base.join(loc) {
            return normalize_url(joined.as_str());
        }
    }
    normalize_url(loc)
}

fn normalize_url(raw: &str) -> String {
    let Ok(mut url) = Url::parse(raw) else {
        return raw.trim_end_matches('#').to_string();
    };
    url.set_fragment(None);
    if let Some(host) = url.host_str().map(|h| h.to_ascii_lowercase()) {
        let _ = url.set_host(Some(&host));
    }
    url.to_string()
}

fn session_key(client_ip: &str, username: Option<&str>, user_agent: Option<&str>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(client_ip.as_bytes());
    hasher.update(b"\0");
    hasher.update(username.unwrap_or("").as_bytes());
    hasher.update(b"\0");
    hasher.update(user_agent.unwrap_or("").as_bytes());
    hex::encode(hasher.finalize())
}

fn redirect_key(client_ip: &str, url: &str) -> String {
    format!("{}\0{}", client_ip, normalize_url(url))
}

fn new_session_id() -> String {
    hex::encode(rand::random::<u128>().to_be_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn same_client_reuses_session() {
        let c = SessionCorrelator::new(
            Duration::from_secs(60),
            Duration::from_secs(30),
            1000,
            1000,
        );
        let a = c.begin_request("10.0.0.1", Some("alice"), Some("curl/8"), "https://a.com/");
        let b = c.begin_request("10.0.0.1", Some("alice"), Some("curl/8"), "https://b.com/");
        assert_eq!(a.session_id, b.session_id);
        assert!(a.parent_event_id.is_none());
    }

    #[test]
    fn different_ua_new_session() {
        let c = SessionCorrelator::new(
            Duration::from_secs(60),
            Duration::from_secs(30),
            1000,
            1000,
        );
        let a = c.begin_request("10.0.0.1", Some("alice"), Some("curl/8"), "https://a.com/");
        let b = c.begin_request("10.0.0.1", Some("alice"), Some("Firefox"), "https://a.com/");
        assert_ne!(a.session_id, b.session_id);
    }

    #[test]
    fn idle_expiry_creates_new_session() {
        let c = SessionCorrelator::new(
            Duration::from_millis(30),
            Duration::from_secs(30),
            1000,
            1000,
        );
        let a = c.begin_request("10.0.0.1", None, Some("ua"), "https://a.com/");
        thread::sleep(Duration::from_millis(50));
        let b = c.begin_request("10.0.0.1", None, Some("ua"), "https://a.com/");
        assert_ne!(a.session_id, b.session_id);
    }

    #[test]
    fn redirect_chain_links_parent() {
        let c = SessionCorrelator::new(
            Duration::from_secs(60),
            Duration::from_secs(30),
            1000,
            1000,
        );
        let first = c.begin_request(
            "10.0.0.2",
            Some("bob"),
            Some("Mozilla"),
            "https://old.example/go",
        );
        c.note_redirect(
            "10.0.0.2",
            "evt-redir-1",
            302,
            "https://old.example/go",
            Some("https://new.example/landing"),
        );
        let second = c.begin_request(
            "10.0.0.2",
            Some("bob"),
            Some("Mozilla"),
            "https://new.example/landing",
        );
        assert_eq!(first.session_id, second.session_id);
        assert_eq!(second.parent_event_id.as_deref(), Some("evt-redir-1"));
    }

    #[test]
    fn relative_location_resolved() {
        let abs = resolve_location("https://example.com/a/b", "../c");
        assert_eq!(abs, "https://example.com/c");
    }

    #[test]
    fn redirect_status_detection() {
        assert!(is_redirect_status(302));
        assert!(is_redirect_status(301));
        assert!(!is_redirect_status(200));
        assert!(!is_redirect_status(404));
    }
}
