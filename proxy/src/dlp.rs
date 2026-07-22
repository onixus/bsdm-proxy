use aho_corasick::{AhoCorasick, MatchKind};
use bytes::Bytes;
use http_body::{Body, Frame};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use arc_swap::ArcSwap;

#[derive(Debug, Clone)]
pub struct DlpViolation {
    pub category: String,
    pub detail: String,
}

impl std::fmt::Display for DlpViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DLP Violation: {} ({})", self.category, self.detail)
    }
}

impl std::error::Error for DlpViolation {}

struct DlpState {
    ac: AhoCorasick,
    patterns: Vec<(String, String)>,
}

/// DLP Engine configured with patterns to detect data leaks.
#[derive(Clone)]
pub struct DlpEngine {
    state: Arc<ArcSwap<DlpState>>,
}

impl DlpEngine {
    pub fn new() -> Self {
        let patterns: Vec<(String, String)> = vec![
            ("sk-ant-api".into(), "Anthropic API Key".into()),
            ("sk-proj-".into(), "OpenAI Project Key".into()),
            ("ghp_".into(), "GitHub Personal Access Token".into()),
            ("xoxb-".into(), "Slack Bot Token".into()),
            ("BEGIN RSA PRIVATE KEY".into(), "RSA Private Key".into()),
            ("BEGIN OPENSSH PRIVATE KEY".into(), "OpenSSH Private Key".into()),
        ];
        
        let ac = AhoCorasick::builder()
            .match_kind(MatchKind::Standard)
            .build(patterns.iter().map(|(k, _)| k))
            .expect("Failed to build DLP AhoCorasick automaton");

        Self {
            state: Arc::new(ArcSwap::from_pointee(DlpState { ac, patterns })),
        }
    }

    pub fn get_patterns(&self) -> Vec<(String, String)> {
        self.state.load().patterns.clone()
    }

    pub fn set_patterns(&self, new_patterns: Vec<(String, String)>) {
        if new_patterns.is_empty() {
            let ac = AhoCorasick::builder().build(Vec::<&str>::new()).unwrap();
            self.state.store(Arc::new(DlpState { ac, patterns: vec![] }));
            return;
        }
        let ac = AhoCorasick::builder()
            .match_kind(MatchKind::Standard)
            .build(new_patterns.iter().map(|(k, _)| k))
            .expect("Failed to build DLP AhoCorasick automaton");
        self.state.store(Arc::new(DlpState { ac, patterns: new_patterns }));
    }

    /// Scans a byte chunk for DLP violations.
    pub fn scan_chunk(&self, chunk: &[u8]) -> Option<DlpViolation> {
        let state = self.state.load();
        if let Some(mat) = state.ac.find(chunk) {
            let p = &state.patterns[mat.pattern()];
            return Some(DlpViolation {
                category: p.1.clone(),
                detail: p.0.clone(),
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
