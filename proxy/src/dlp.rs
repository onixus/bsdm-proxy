use aho_corasick::{AhoCorasick, MatchKind};
use bytes::Bytes;
use http_body::{Body, Frame};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

#[derive(Debug, Clone)]
pub struct DlpViolation {
    pub category: &'static str,
    pub detail: String,
}

impl std::fmt::Display for DlpViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DLP Violation: {} ({})", self.category, self.detail)
    }
}

impl std::error::Error for DlpViolation {}

/// DLP Engine configured with patterns to detect data leaks.
#[derive(Clone)]
pub struct DlpEngine {
    ac: Arc<AhoCorasick>,
    patterns: Arc<Vec<(&'static str, &'static str)>>,
}

impl DlpEngine {
    pub fn new() -> Self {
        // High-entropy secrets and standard PII markers for v1
        let patterns = vec![
            ("sk-ant-api", "Anthropic API Key"),
            ("sk-proj-", "OpenAI Project Key"),
            ("ghp_", "GitHub Personal Access Token"),
            ("xoxb-", "Slack Bot Token"),
            // Simplified CC and SSN markers for demonstration purposes
            ("BEGIN RSA PRIVATE KEY", "RSA Private Key"),
            ("BEGIN OPENSSH PRIVATE KEY", "OpenSSH Private Key"),
        ];

        let ac = AhoCorasick::builder()
            .match_kind(MatchKind::Standard)
            .build(patterns.iter().map(|(k, _)| k))
            .expect("Failed to build DLP AhoCorasick automaton");

        Self {
            ac: Arc::new(ac),
            patterns: Arc::new(patterns),
        }
    }

    /// Scans a byte chunk for DLP violations.
    pub fn scan_chunk(&self, chunk: &[u8]) -> Option<DlpViolation> {
        if let Some(mat) = self.ac.find(chunk) {
            let p = &self.patterns[mat.pattern()];
            return Some(DlpViolation {
                category: p.1,
                detail: p.0.to_string(),
            });
        }
        None
    }
}

impl Default for DlpEngine {
    fn default() -> Self {
        Self::new()
    }
}
pin_project_lite::pin_project! {
    /// A hyper Body wrapper that scans streamed chunks for DLP violations.
    pub struct DlpBodyStream<B> {
        #[pin]
        inner: B,
        engine: Arc<DlpEngine>,
        violation: Option<DlpViolation>,
    }
}

impl<B> DlpBodyStream<B> {
    pub fn new(inner: B, engine: Arc<DlpEngine>) -> Self {
        Self {
            inner,
            engine,
            violation: None,
        }
    }

    pub fn take_violation(&mut self) -> Option<DlpViolation> {
        self.violation.take()
    }
}

impl<B> Body for DlpBodyStream<B>
where
    B: Body<Data = Bytes>,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
{
    type Data = Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.project();

        match this.inner.poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    if let Some(violation) = this.engine.scan_chunk(data) {
                        tracing::warn!("DLP Blocked Request Stream: {}", violation);
                        *this.violation = Some(violation.clone());
                        return Poll::Ready(Some(Err(Box::new(violation))));
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e.into()))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}
