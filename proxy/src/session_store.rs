//! Global Distributed Session Store (Redis + In-Memory Fallback).

use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::{debug, warn};

/// Thread-safe global session store supporting multi-cluster Redis sync with in-memory fallback.
#[derive(Clone)]
pub struct GlobalSessionStore {
    local_sessions: Arc<RwLock<HashMap<String, String>>>,
    redis_conn: Option<ConnectionManager>,
    key_prefix: String,
    ttl_secs: u64,
}

impl GlobalSessionStore {
    /// Creates a new `GlobalSessionStore`.
    pub fn new(redis_conn: Option<ConnectionManager>) -> Self {
        let ttl_secs = std::env::var("REDIS_SESSION_TTL")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(86400); // Default: 24h

        let key_prefix =
            std::env::var("REDIS_SESSION_PREFIX").unwrap_or_else(|_| "bsdm:session:".to_string());

        Self {
            local_sessions: Arc::new(RwLock::new(HashMap::new())),
            redis_conn,
            key_prefix,
            ttl_secs,
        }
    }

    /// Check if Redis connection is active.
    pub fn is_redis_connected(&self) -> bool {
        self.redis_conn.is_some()
    }

    fn redis_key(&self, session_id: &str) -> String {
        format!("{}{}", self.key_prefix, session_id)
    }

    /// Retrieve a username associated with `session_id`.
    pub async fn get_session(&self, session_id: &str) -> Option<String> {
        // 1. Try local cache first
        if let Some(user) = self.local_sessions.read().unwrap().get(session_id).cloned() {
            return Some(user);
        }

        // 2. Try Redis if connected
        if let Some(ref conn) = self.redis_conn {
            let mut conn = conn.clone();
            let key = self.redis_key(session_id);
            match conn.get::<_, Option<String>>(&key).await {
                Ok(Some(username)) => {
                    // Populate local cache
                    self.local_sessions
                        .write()
                        .unwrap()
                        .insert(session_id.to_string(), username.clone());
                    return Some(username);
                }
                Ok(None) => debug!("Session {} not found in Redis", session_id),
                Err(e) => warn!("Redis get_session failed for {}: {}", session_id, e),
            }
        }

        None
    }

    /// Store a new session ID for `username` and return the generated session ID.
    pub async fn create_session(&self, username: String) -> String {
        let mut bytes = [0u8; 32];
        rand::fill(&mut bytes);
        let session_id = hex::encode(bytes);

        // Always update local memory
        self.local_sessions
            .write()
            .unwrap()
            .insert(session_id.clone(), username.clone());

        // Update Redis if connected
        if let Some(ref conn) = self.redis_conn {
            let mut conn = conn.clone();
            let key = self.redis_key(&session_id);
            if let Err(e) = conn
                .set_ex::<_, _, ()>(&key, &username, self.ttl_secs)
                .await
            {
                warn!("Redis create_session failed for {}: {}", session_id, e);
            }
        }

        session_id
    }

    /// Remove a session by ID.
    pub async fn remove_session(&self, session_id: &str) -> bool {
        let mut removed = self
            .local_sessions
            .write()
            .unwrap()
            .remove(session_id)
            .is_some();

        if let Some(ref conn) = self.redis_conn {
            let mut conn = conn.clone();
            let key = self.redis_key(session_id);
            match conn.del::<_, u32>(&key).await {
                Ok(count) => {
                    if count > 0 {
                        removed = true;
                    }
                }
                Err(e) => warn!("Redis remove_session failed for {}: {}", session_id, e),
            }
        }

        removed
    }

    /// Count total active local sessions.
    pub fn session_count(&self) -> usize {
        self.local_sessions.read().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_in_memory_session_store() {
        let store = GlobalSessionStore::new(None);
        assert!(!store.is_redis_connected());

        let session_id = store.create_session("alice".to_string()).await;
        assert_eq!(store.session_count(), 1);

        let user = store.get_session(&session_id).await;
        assert_eq!(user, Some("alice".to_string()));

        let removed = store.remove_session(&session_id).await;
        assert!(removed);
        assert_eq!(store.get_session(&session_id).await, None);
    }
}
