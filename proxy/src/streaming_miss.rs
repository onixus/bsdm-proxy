//! Streaming cache MISS: tee upstream response frames to the client while buffering for L1.

use bytes::{Bytes, BytesMut};
use http_body::{Body, Frame, SizeHint};
use hyper::body::Incoming;
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll};

type MissCompleteFn = Box<dyn FnOnce(Bytes, bool) + Send>;
type MissCompleteSlot = Mutex<Option<MissCompleteFn>>;

/// Buffers upstream body frames and forwards them unchanged to the client.
pub struct TeeMissBody<B> {
    upstream: B,
    acc: BytesMut,
    attempt_cache: bool,
    max_body: usize,
    finished: bool,
    on_complete: MissCompleteSlot,
}

impl<B> TeeMissBody<B>
where
    B: Body<Data = Bytes, Error = hyper::Error> + Unpin,
{
    pub fn new(
        upstream: B,
        attempt_cache: bool,
        max_body: usize,
        on_complete: impl FnOnce(Bytes, bool) + Send + 'static,
    ) -> Self {
        Self {
            upstream,
            acc: BytesMut::new(),
            attempt_cache,
            max_body,
            finished: false,
            on_complete: Mutex::new(Some(Box::new(on_complete))),
        }
    }
}

impl<B> Body for TeeMissBody<B>
where
    B: Body<Data = Bytes, Error = hyper::Error> + Unpin,
{
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.finished {
            return Poll::Ready(None);
        }

        let this = self.as_mut().get_mut();
        match Pin::new(&mut this.upstream).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(chunk) = frame.data_ref() {
                    if this.attempt_cache {
                        if this.acc.len() + chunk.len() > this.max_body {
                            this.attempt_cache = false;
                            this.acc.clear();
                        } else {
                            this.acc.extend_from_slice(chunk);
                        }
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => {
                this.finished = true;
                let body = if this.attempt_cache {
                    std::mem::take(&mut this.acc).freeze()
                } else {
                    Bytes::new()
                };
                let cached = this.attempt_cache;
                if let Ok(mut slot) = this.on_complete.lock() {
                    if let Some(on_complete) = slot.take() {
                        on_complete(body, cached);
                    }
                }
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.finished || self.upstream.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.upstream.size_hint()
    }
}

pub type StreamingMissBody = TeeMissBody<Incoming>;

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::{BodyExt, Full};
    use std::convert::Infallible;
    use std::sync::{Arc, Mutex};

    fn test_upstream(payload: Bytes) -> impl Body<Data = Bytes, Error = hyper::Error> + Unpin {
        Full::new(payload).map_err(|e: Infallible| match e {})
    }

    #[tokio::test]
    async fn tees_chunks_and_completes() {
        let payload = Bytes::from_static(b"hello-stream");
        let upstream = test_upstream(payload.clone());
        let seen = Arc::new(Mutex::new((Bytes::new(), false)));
        let seen2 = seen.clone();

        let body = TeeMissBody::new(upstream, true, 1024, move |buf, cached| {
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

        let body = TeeMissBody::new(upstream, true, 4, move |_buf, cached| {
            *seen2.lock().unwrap() = cached;
        });

        let collected = body.collect().await.expect("collect").to_bytes();
        assert_eq!(collected, payload);
        assert!(!*seen.lock().unwrap());
    }
}
