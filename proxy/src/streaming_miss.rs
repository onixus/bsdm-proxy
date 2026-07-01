//! Streaming cache MISS: tee upstream response frames to the client while buffering for L1.

use bytes::{Bytes, BytesMut};
use http_body::{Body, Frame, SizeHint};
use hyper::body::Incoming;
use std::future::poll_fn;
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll};
use tokio::sync::mpsc;

type FrameResult = Result<Frame<Bytes>, hyper::Error>;

/// Buffers upstream body frames and forwards them unchanged to the client.
///
/// Upstream is drained in a background task so L1 storage completes once the
/// origin response is fully received, even if the client has not read the body yet.
pub struct TeeMissBody {
    rx: mpsc::Receiver<FrameResult>,
    finished: bool,
}

impl TeeMissBody {
    pub fn new(
        upstream: Incoming,
        attempt_cache: bool,
        max_body: usize,
        on_complete: impl FnOnce(Bytes, bool) + Send + 'static,
    ) -> Self {
        Self::from_upstream(upstream, attempt_cache, max_body, on_complete)
    }

    #[cfg(test)]
    fn from_upstream<B>(
        upstream: B,
        attempt_cache: bool,
        max_body: usize,
        on_complete: impl FnOnce(Bytes, bool) + Send + 'static,
    ) -> Self
    where
        B: Body<Data = Bytes, Error = hyper::Error> + Unpin + Send + 'static,
    {
        spawn_upstream_drain(upstream, attempt_cache, max_body, on_complete)
    }

    #[cfg(not(test))]
    fn from_upstream(
        upstream: Incoming,
        attempt_cache: bool,
        max_body: usize,
        on_complete: impl FnOnce(Bytes, bool) + Send + 'static,
    ) -> Self {
        spawn_upstream_drain(upstream, attempt_cache, max_body, on_complete)
    }
}

fn spawn_upstream_drain<B>(
    upstream: B,
    attempt_cache: bool,
    max_body: usize,
    on_complete: impl FnOnce(Bytes, bool) + Send + 'static,
) -> TeeMissBody
where
    B: Body<Data = Bytes, Error = hyper::Error> + Unpin + Send + 'static,
{
    let (tx, rx) = mpsc::channel::<FrameResult>(16);
    let on_complete = Mutex::new(Some(Box::new(on_complete)));

    tokio::spawn(async move {
        let mut upstream = upstream;
        let mut acc = BytesMut::new();
        let mut attempt_cache = attempt_cache;
        let mut client_gone = false;

        loop {
            let frame = poll_fn(|cx| Pin::new(&mut upstream).poll_frame(cx)).await;
            match frame {
                Some(Ok(frame)) => {
                    if let Some(chunk) = frame.data_ref() {
                        if attempt_cache {
                            if acc.len() + chunk.len() > max_body {
                                attempt_cache = false;
                                acc.clear();
                            } else {
                                acc.extend_from_slice(chunk);
                            }
                        }
                    }

                    if !client_gone {
                        let forward = if let Some(chunk) = frame.data_ref() {
                            Frame::data(chunk.clone())
                        } else if frame.is_trailers() {
                            match frame.into_trailers() {
                                Ok(trailers) => Frame::trailers(trailers),
                                Err(_) => {
                                    client_gone = true;
                                    continue;
                                }
                            }
                        } else {
                            continue;
                        };

                        if tx.send(Ok(forward)).await.is_err() {
                            client_gone = true;
                        }
                    }
                }
                Some(Err(e)) => {
                    let _ = tx.send(Err(e)).await;
                    break;
                }
                None => break,
            }
        }

        if let Ok(mut slot) = on_complete.lock() {
            if let Some(on_complete) = slot.take() {
                let body = if attempt_cache {
                    acc.freeze()
                } else {
                    Bytes::new()
                };
                on_complete(body, attempt_cache);
            }
        }
    });

    TeeMissBody {
        rx,
        finished: false,
    }
}

impl Body for TeeMissBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.finished {
            return Poll::Ready(None);
        }

        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(frame)) => Poll::Ready(Some(frame)),
            Poll::Ready(None) => {
                self.finished = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.finished
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::{combinators::MapErr, BodyExt, Full};
    use std::convert::Infallible;
    use std::sync::{Arc, Mutex};

    type TestUpstream = MapErr<Full<Bytes>, fn(Infallible) -> hyper::Error>;

    fn test_upstream(payload: Bytes) -> TestUpstream {
        Full::new(payload).map_err(|e: Infallible| match e {})
    }

    #[tokio::test]
    async fn tees_chunks_and_completes() {
        let payload = Bytes::from_static(b"hello-stream");
        let upstream = test_upstream(payload.clone());
        let seen = Arc::new(Mutex::new((Bytes::new(), false)));
        let seen2 = seen.clone();

        let body = TeeMissBody::from_upstream(upstream, true, 1024, move |buf, cached| {
            *seen2.lock().unwrap() = (buf, cached);
        });

        let collected = body.collect().await.expect("collect").to_bytes();
        assert_eq!(collected, payload);

        let (buf, cached) = seen.lock().unwrap().clone();
        assert!(cached);
        assert_eq!(buf, payload);
    }

    #[tokio::test]
    async fn disables_cache_when_max_exceeded() {
        let payload = Bytes::from_static(b"0123456789");
        let upstream = test_upstream(payload.clone());
        let seen = Arc::new(Mutex::new(false));
        let seen2 = seen.clone();

        let body = TeeMissBody::from_upstream(upstream, true, 4, move |_buf, cached| {
            *seen2.lock().unwrap() = cached;
        });

        let collected = body.collect().await.expect("collect").to_bytes();
        assert_eq!(collected, payload);
        assert!(!*seen.lock().unwrap());
    }

    #[tokio::test]
    async fn caches_before_client_drains_body() {
        let payload = Bytes::from_static(b"cache-on-headers");
        let upstream = test_upstream(payload.clone());
        let cached = Arc::new(Mutex::new(false));
        let cached2 = cached.clone();

        let _body = TeeMissBody::from_upstream(upstream, true, 1024, move |_buf, stored| {
            *cached2.lock().unwrap() = stored;
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(*cached.lock().unwrap());
    }
}
