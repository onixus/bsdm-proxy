use aho_corasick::{AhoCorasick, MatchKind};
use arc_swap::ArcSwap;
use bytes::Bytes;
use http_body::{Body, Frame};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

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
    enabled: bool,
}

/// DLP Engine configured with patterns to detect data leaks.
///
/// # Enablement (`DLP_ENABLED`)
/// Experimental native DLP is **off by default** (`DLP_ENABLED=false` / unset).
/// Set `DLP_ENABLED=true` to load the built-in signature set at startup.
/// Patterns can still be changed at runtime via control API (`POST /api/security/dlp`).
#[derive(Clone)]
pub struct DlpEngine {
    state: Arc<ArcSwap<DlpState>>,
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

fn empty_state() -> DlpState {
    let ac = AhoCorasick::builder()
        .build(Vec::<&str>::new())
        .expect("empty AhoCorasick");
    DlpState {
        ac,
        patterns: vec![],
        enabled: false,
    }
}

fn default_patterns() -> Vec<(String, String)> {
    vec![
        ("sk-ant-api".into(), "Anthropic API Key".into()),
        ("sk-proj-".into(), "OpenAI Project Key".into()),
        ("ghp_".into(), "GitHub Personal Access Token".into()),
        ("github_pat_".into(), "GitHub Fine-Grained Token".into()),
        ("glpat-".into(), "GitLab Personal Access Token".into()),
        ("xoxb-".into(), "Slack Bot Token".into()),
        ("xoxp-".into(), "Slack User Token".into()),
        ("AKIA".into(), "AWS Access Key ID".into()),
        ("AIzaSy".into(), "Google Cloud API Key".into()),
        ("sk_live_".into(), "Stripe Live Secret Key".into()),
        ("rk_live_".into(), "Stripe Restricted Key".into()),
        ("BEGIN RSA PRIVATE KEY".into(), "RSA Private Key".into()),
        (
            "BEGIN OPENSSH PRIVATE KEY".into(),
            "OpenSSH Private Key".into(),
        ),
        ("BEGIN PRIVATE KEY".into(), "PKCS#8 Private Key".into()),
        ("BEGIN EC PRIVATE KEY".into(), "EC Private Key".into()),
        ("BEGIN DSA PRIVATE KEY".into(), "DSA Private Key".into()),
    ]
}

fn state_from_patterns(patterns: Vec<(String, String)>) -> DlpState {
    if patterns.is_empty() {
        return empty_state();
    }
    let ac = AhoCorasick::builder()
        .match_kind(MatchKind::Standard)
        .build(patterns.iter().map(|(k, _)| k))
        .expect("Failed to build DLP AhoCorasick automaton");
    DlpState {
        ac,
        patterns,
        enabled: true,
    }
}

impl DlpEngine {
    /// Construct from environment: `DLP_ENABLED=true` loads built-in signatures.
    pub fn from_env() -> Self {
        if env_flag("DLP_ENABLED") {
            Self::with_default_patterns()
        } else {
            Self::disabled()
        }
    }

    /// Always-on engine with built-in signature set (tests / explicit enable).
    pub fn with_default_patterns() -> Self {
        Self {
            state: Arc::new(ArcSwap::from_pointee(state_from_patterns(
                default_patterns(),
            ))),
        }
    }

    /// No patterns, scan is a no-op. Preferred pilot default.
    pub fn disabled() -> Self {
        Self {
            state: Arc::new(ArcSwap::from_pointee(empty_state())),
        }
    }

    /// Back-compat alias: historically `new()` always loaded default patterns.
    /// Prefer [`from_env`] / [`disabled`] / [`with_default_patterns`].
    pub fn new() -> Self {
        Self::from_env()
    }

    pub fn is_enabled(&self) -> bool {
        let s = self.state.load();
        s.enabled && !s.patterns.is_empty()
    }

    pub fn get_patterns(&self) -> Vec<(String, String)> {
        self.state.load().patterns.clone()
    }

    pub fn set_patterns(&self, new_patterns: Vec<(String, String)>) {
        self.state
            .store(Arc::new(state_from_patterns(new_patterns)));
    }

    /// Scans a byte chunk for DLP violations. No-op when disabled / empty.
    pub fn scan_chunk(&self, chunk: &[u8]) -> Option<DlpViolation> {
        let state = self.state.load();
        if !state.enabled || state.patterns.is_empty() {
            return None;
        }
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
        Self::from_env()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_engine_does_not_match() {
        let engine = DlpEngine::disabled();
        assert!(!engine.is_enabled());
        assert!(engine.scan_chunk(b"sk-ant-api-xxx").is_none());
    }

    #[test]
    fn default_patterns_detect_signature() {
        let engine = DlpEngine::with_default_patterns();
        assert!(engine.is_enabled());
        let v = engine.scan_chunk(b"header sk-ant-api-123 footer").unwrap();
        assert_eq!(v.detail, "sk-ant-api");

        let aws = engine.scan_chunk(b"AWS_KEY=AKIAIOSFODNN7EXAMPLE").unwrap();
        assert_eq!(aws.category, "AWS Access Key ID");

        let gcp = engine.scan_chunk(b"api_key=AIzaSyD-sample-key").unwrap();
        assert_eq!(gcp.category, "Google Cloud API Key");

        let stripe = engine.scan_chunk(b"sk_live_51Abcdef123456").unwrap();
        assert_eq!(stripe.category, "Stripe Live Secret Key");

        let pkcs8 = engine.scan_chunk(b"-----BEGIN PRIVATE KEY-----").unwrap();
        assert_eq!(pkcs8.category, "PKCS#8 Private Key");
    }

    #[test]
    fn set_patterns_empty_disables_scan() {
        let engine = DlpEngine::with_default_patterns();
        engine.set_patterns(vec![]);
        assert!(!engine.is_enabled());
        assert!(engine.scan_chunk(b"sk-ant-api-xxx").is_none());
    }
}
