//! Request coalescing (singleflight) for concurrent cacheable MISSes.
//!
//! Parallel identical GET/HEAD misses share one upstream fetch: the leader fills L1,
//! followers wait and serve the stored response as `COALESCED-HIT`.

use crate::cache::CachedResponse;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::watch;

#[derive(Clone, Default)]
pub struct MissFlightMap {
    inner: Arc<Mutex<HashMap<Arc<str>, Arc<Flight>>>>,
}

struct Flight {
    tx: watch::Sender<FlightState>,
}

#[derive(Clone)]
enum FlightState {
    Pending,
    Done(Option<CachedResponse>),
}

pub enum CoalesceJoin {
    /// This request should fetch upstream; call [`MissFlightPermit::complete`] when done.
    Leader(MissFlightPermit),
    /// Wait for the leader; [`MissFlightWait::wait`] returns a stored response or `None`.
    Follower(MissFlightWait),
}

pub struct MissFlightPermit {
    map: MissFlightMap,
    key: Arc<str>,
    disarmed: bool,
}

pub struct MissFlightWait {
    rx: watch::Receiver<FlightState>,
}

impl MissFlightMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Join an in-flight miss for `key`, or become the leader.
    pub fn join(&self, key: &Arc<str>) -> CoalesceJoin {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(flight) = guard.get(key) {
            return CoalesceJoin::Follower(MissFlightWait {
                rx: flight.tx.subscribe(),
            });
        }
        let (tx, _rx) = watch::channel(FlightState::Pending);
        let flight = Arc::new(Flight { tx });
        guard.insert(key.clone(), flight);
        CoalesceJoin::Leader(MissFlightPermit {
            map: self.clone(),
            key: key.clone(),
            disarmed: false,
        })
    }

    /// Publish outcome and remove the flight (idempotent).
    pub fn complete(&self, key: &Arc<str>, result: Option<CachedResponse>) {
        let flight = {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            guard.remove(key)
        };
        if let Some(flight) = flight {
            let _ = flight.tx.send(FlightState::Done(result));
        }
    }

    #[cfg(test)]
    fn inflight_len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

impl MissFlightPermit {
    /// Hand responsibility to miss-completion (streaming path); Drop will not finish.
    pub fn disarm(mut self) {
        self.disarmed = true;
    }

    pub fn complete(mut self, result: Option<CachedResponse>) {
        self.disarmed = true;
        self.map.complete(&self.key, result);
    }

    pub fn key(&self) -> &Arc<str> {
        &self.key
    }
}

impl Drop for MissFlightPermit {
    fn drop(&mut self) {
        if !self.disarmed {
            self.map.complete(&self.key, None);
        }
    }
}

impl MissFlightWait {
    pub async fn wait(mut self) -> Option<CachedResponse> {
        loop {
            let state = self.rx.borrow().clone();
            match state {
                FlightState::Done(result) => return result,
                FlightState::Pending => {
                    if self.rx.changed().await.is_err() {
                        return None;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::time::{Duration, SystemTime};

    fn sample_cached(marker: &'static str) -> CachedResponse {
        CachedResponse {
            status: 200,
            headers: Arc::from([]),
            body: crate::cache_body::CachedBody::inline(Bytes::from_static(marker.as_bytes())),
            body_encoding: crate::cache_compress::BodyEncoding::Raw,
            uncompressed_len: marker.len(),
            cached_at: SystemTime::now(),
            ttl: Duration::from_secs(60),
            etag: None,
            last_modified: None,
            is_negative: false,
            must_revalidate: false,
        }
    }

    #[tokio::test]
    async fn leader_and_follower_share_result() {
        let map = MissFlightMap::new();
        let key: Arc<str> = Arc::from("k1");
        let CoalesceJoin::Leader(permit) = map.join(&key) else {
            panic!("expected leader");
        };
        let CoalesceJoin::Follower(wait) = map.join(&key) else {
            panic!("expected follower");
        };
        assert_eq!(map.inflight_len(), 1);

        let cached = sample_cached("body");
        let wait_task = tokio::spawn(async move { wait.wait().await });
        permit.complete(Some(cached.clone()));

        let got = wait_task.await.unwrap().unwrap();
        assert_eq!(got.status, 200);
        assert_eq!(got.stored_body_bytes(), Bytes::from_static(b"body"));
        assert_eq!(map.inflight_len(), 0);
    }

    #[tokio::test]
    async fn empty_complete_unblocks_follower() {
        let map = MissFlightMap::new();
        let key: Arc<str> = Arc::from("k2");
        let CoalesceJoin::Leader(permit) = map.join(&key) else {
            panic!("expected leader");
        };
        let CoalesceJoin::Follower(wait) = map.join(&key) else {
            panic!("expected follower");
        };
        let wait_task = tokio::spawn(async move { wait.wait().await });
        permit.complete(None);
        assert!(wait_task.await.unwrap().is_none());
    }

    #[tokio::test]
    async fn drop_permit_unblocks_followers() {
        let map = MissFlightMap::new();
        let key: Arc<str> = Arc::from("k3");
        let CoalesceJoin::Leader(permit) = map.join(&key) else {
            panic!("expected leader");
        };
        let CoalesceJoin::Follower(wait) = map.join(&key) else {
            panic!("expected follower");
        };
        let wait_task = tokio::spawn(async move { wait.wait().await });
        drop(permit);
        assert!(wait_task.await.unwrap().is_none());
        assert_eq!(map.inflight_len(), 0);
    }
}
