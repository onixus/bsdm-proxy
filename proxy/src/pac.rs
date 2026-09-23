//! Built-in PAC/WPAD server.
//!
//! The listener is intentionally separate from the authenticated control plane:
//! browsers must be able to download the PAC file before they know how to reach
//! the proxy. Set `PAC_PROXY=host:port` to enable it.

use crate::http_types::{empty, full, Body};
use crate::Metrics;
use bytes::Bytes;
use hyper::body::Incoming;
use hyper::header::{
    ALLOW, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, EXPIRES, PRAGMA,
    X_CONTENT_TYPE_OPTIONS,
};
use hyper::http::uri::Authority;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use prometheus::{IntCounterVec, IntGauge, Opts, Registry};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Mutex, RwLock};
use tokio::time::MissedTickBehavior;
use tracing::{debug, info, warn};

const DEFAULT_PAC_PORT: u16 = 9091;
const DEFAULT_RELOAD_INTERVAL_SECS: u64 = 5;
const PAC_CONTENT_TYPE: &str = "application/x-ns-proxy-autoconfig; charset=utf-8";

#[derive(Debug, Clone)]
struct PacConfig {
    bind: SocketAddr,
    proxy: String,
    bypass_file: Option<PathBuf>,
    reload_interval: Duration,
}

impl PacConfig {
    fn from_env() -> Result<Option<Self>, String> {
        let Some(proxy) = std::env::var("PAC_PROXY")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
        else {
            return Ok(None);
        };
        let proxy = validate_proxy_authority(&proxy)?;

        let port = parse_env_u16("PAC_PORT", DEFAULT_PAC_PORT)?;
        let bind = std::env::var("PAC_BIND")
            .unwrap_or_else(|_| format!("0.0.0.0:{port}"))
            .parse::<SocketAddr>()
            .map_err(|error| format!("PAC_BIND must be an IP:port socket address: {error}"))?;
        if bind.port() == 0 {
            return Err("PAC_BIND port must be greater than zero".to_string());
        }

        let bypass_file = std::env::var("PAC_BYPASS_FILE")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .map(PathBuf::from);
        let reload_secs = parse_env_u64(
            "PAC_RELOAD_INTERVAL_SECONDS",
            DEFAULT_RELOAD_INTERVAL_SECS,
        )?
        .max(1);

        Ok(Some(Self {
            bind,
            proxy,
            bypass_file,
            reload_interval: Duration::from_secs(reload_secs),
        }))
    }
}

fn parse_env_u16(key: &str, default: u16) -> Result<u16, String> {
    match std::env::var(key) {
        Ok(value) => value
            .parse::<u16>()
            .map_err(|error| format!("{key} must be an integer: {error}"))
            .and_then(|value| {
                if value == 0 {
                    Err(format!("{key} must be greater than zero"))
                } else {
                    Ok(value)
                }
            }),
        Err(_) => Ok(default),
    }
}

fn parse_env_u64(key: &str, default: u64) -> Result<u64, String> {
    match std::env::var(key) {
        Ok(value) => value
            .parse::<u64>()
            .map_err(|error| format!("{key} must be an integer: {error}")),
        Err(_) => Ok(default),
    }
}

fn validate_proxy_authority(value: &str) -> Result<String, String> {
    if value.contains('@') {
        return Err("PAC_PROXY must not contain user information".to_string());
    }
    let authority = Authority::from_str(value)
        .map_err(|error| format!("PAC_PROXY must be host:port: {error}"))?;
    if authority.host().is_empty() || authority.port_u16().is_none() {
        return Err("PAC_PROXY must include a host and numeric port".to_string());
    }
    if authority.port_u16() == Some(0) {
        return Err("PAC_PROXY port must be greater than zero".to_string());
    }
    Ok(authority.as_str().to_string())
}

#[derive(Clone)]
struct PacMetrics {
    requests: IntCounterVec,
    reloads: IntCounterVec,
    bypass_domains: IntGauge,
}

impl PacMetrics {
    fn new(registry: &Registry) -> io::Result<Self> {
        let requests = IntCounterVec::new(
            Opts::new(
                "bsdm_proxy_pac_requests_total",
                "PAC server HTTP requests by route and response status",
            ),
            &["route", "status"],
        )
        .map_err(metric_error)?;
        let reloads = IntCounterVec::new(
            Opts::new(
                "bsdm_proxy_pac_reloads_total",
                "PAC bypass-list reload attempts by result",
            ),
            &["result"],
        )
        .map_err(metric_error)?;
        let bypass_domains = IntGauge::new(
            "bsdm_proxy_pac_bypass_domains",
            "Number of active PAC bypass domains",
        )
        .map_err(metric_error)?;

        registry
            .register(Box::new(requests.clone()))
            .map_err(metric_error)?;
        registry
            .register(Box::new(reloads.clone()))
            .map_err(metric_error)?;
        registry
            .register(Box::new(bypass_domains.clone()))
            .map_err(metric_error)?;

        Ok(Self {
            requests,
            reloads,
            bypass_domains,
        })
    }
}

fn metric_error(error: prometheus::Error) -> io::Error {
    io::Error::other(format!("PAC metric registration failed: {error}"))
}

#[derive(Clone)]
struct PacDocument {
    body: Bytes,
    source_digest: Option<[u8; 32]>,
    domain_count: usize,
}

struct PacState {
    config: PacConfig,
    document: RwLock<PacDocument>,
    reload_lock: Mutex<()>,
    last_reload_error: Mutex<Option<String>>,
    metrics: PacMetrics,
}

impl PacState {
    fn new(config: PacConfig, registry: &Registry) -> io::Result<Self> {
        let metrics = PacMetrics::new(registry)?;
        let body = Bytes::from(render_pac(&config.proxy, &[]));
        Ok(Self {
            config,
            document: RwLock::new(PacDocument {
                body,
                source_digest: None,
                domain_count: 0,
            }),
            reload_lock: Mutex::new(()),
            last_reload_error: Mutex::new(None),
            metrics,
        })
    }

    async fn reload_bypass_file(&self) {
        let Some(path) = self.config.bypass_file.as_ref() else {
            return;
        };
        let _guard = self.reload_lock.lock().await;

        let content = match tokio::fs::read_to_string(path).await {
            Ok(content) => content,
            Err(error) => {
                self.record_reload_error(
                    "io_error",
                    format!("failed to read {}: {error}", path.display()),
                )
                .await;
                return;
            }
        };

        let mut digest = [0_u8; 32];
        digest.copy_from_slice(&Sha256::digest(content.as_bytes()));
        if self.document.read().await.source_digest == Some(digest) {
            self.clear_reload_error().await;
            self.metrics
                .reloads
                .with_label_values(&["unchanged"])
                .inc();
            return;
        }

        let domains = match parse_bypass_domains(&content) {
            Ok(domains) => domains,
            Err(invalid_lines) => {
                self.record_reload_error(
                    "invalid",
                    format!(
                        "{} contains {invalid_lines} invalid non-comment line(s); keeping last-known-good PAC",
                        path.display()
                    ),
                )
                .await;
                return;
            }
        };

        let domain_count = domains.len();
        let body = Bytes::from(render_pac(&self.config.proxy, &domains));
        {
            let mut document = self.document.write().await;
            *document = PacDocument {
                body,
                source_digest: Some(digest),
                domain_count,
            };
        }
        self.metrics.bypass_domains.set(domain_count as i64);
        self.metrics
            .reloads
            .with_label_values(&["changed"])
            .inc();
        self.clear_reload_error().await;
        info!(
            path = %path.display(),
            domains = domain_count,
            "PAC bypass list reloaded"
        );
    }

    async fn record_reload_error(&self, result: &'static str, message: String) {
        self.metrics.reloads.with_label_values(&[result]).inc();
        let mut last_error = self.last_reload_error.lock().await;
        if last_error.as_deref() != Some(message.as_str()) {
            warn!(error = %message, "PAC bypass list reload failed");
            *last_error = Some(message);
        }
    }

    async fn clear_reload_error(&self) {
        let mut last_error = self.last_reload_error.lock().await;
        if last_error.take().is_some() {
            info!("PAC bypass list reload recovered");
        }
    }

    async fn body(&self) -> Bytes {
        self.document.read().await.body.clone()
    }
}

/// Start the PAC listener when `PAC_PROXY` is configured.
///
/// Configuration and bind failures are returned to the caller so an explicitly
/// enabled PAC endpoint never fails silently. Runtime connection failures are
/// logged by the detached listener task.
pub async fn start_pac_server(
    metrics: Arc<Metrics>,
    shutdown_rx: watch::Receiver<bool>,
) -> io::Result<()> {
    let Some(config) = PacConfig::from_env()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?
    else {
        info!("PAC server disabled (set PAC_PROXY=host:port to enable)");
        return Ok(());
    };

    let listener = TcpListener::bind(config.bind).await.map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("failed to bind PAC listener {}: {error}", config.bind),
        )
    })?;
    let state = Arc::new(PacState::new(config, &metrics.registry)?);
    state.reload_bypass_file().await;

    let bind = listener.local_addr()?;
    info!(
        bind = %bind,
        proxy = %state.config.proxy,
        bypass_file = %state
            .config
            .bypass_file
            .as_deref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "<none>".to_string()),
        reload_seconds = state.config.reload_interval.as_secs(),
        "PAC server listening on /proxy.pac and /wpad.dat"
    );

    tokio::spawn(run_pac_server(listener, state, shutdown_rx));
    Ok(())
}

async fn run_pac_server(
    listener: TcpListener,
    state: Arc<PacState>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let mut reload_interval = tokio::time::interval(state.config.reload_interval);
    reload_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // The first interval tick is immediate; the initial load already happened
    // before this task was spawned, so consume it once.
    reload_interval.tick().await;

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, peer)) => {
                        let state = state.clone();
                        tokio::spawn(async move {
                            serve_pac_connection(stream, state, peer).await;
                        });
                    }
                    Err(error) => warn!(error = %error, "PAC listener accept failed"),
                }
            }
            _ = reload_interval.tick(), if state.config.bypass_file.is_some() => {
                state.reload_bypass_file().await;
            }
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    debug!("PAC server stopped");
                    break;
                }
            }
        }
    }
}

async fn serve_pac_connection(stream: TcpStream, state: Arc<PacState>, peer: SocketAddr) {
    let io = TokioIo::new(stream);
    let service = service_fn(move |request: Request<Incoming>| {
        let state = state.clone();
        async move { Ok::<_, Infallible>(handle_pac_request(request, state).await) }
    });

    if let Err(error) = http1::Builder::new().serve_connection(io, service).await {
        debug!(peer = %peer, error = %error, "PAC HTTP connection closed with error");
    }
}

async fn handle_pac_request<B>(request: Request<B>, state: Arc<PacState>) -> Response<Body> {
    let route = match request.uri().path() {
        "/proxy.pac" => "proxy.pac",
        "/wpad.dat" => "wpad.dat",
        "/health" => "health",
        _ => "other",
    };
    let is_head = request.method() == Method::HEAD;

    let response = if request.method() != Method::GET && !is_head {
        method_not_allowed()
    } else {
        match route {
            "proxy.pac" | "wpad.dat" => pac_response(state.body().await, is_head),
            "health" => text_response(StatusCode::OK, Bytes::from_static(b"ok\n"), is_head),
            _ => text_response(
                StatusCode::NOT_FOUND,
                Bytes::from_static(b"not found\n"),
                is_head,
            ),
        }
    };

    state
        .metrics
        .requests
        .with_label_values(&[route, response.status().as_str()])
        .inc();
    response
}

fn pac_response(payload: Bytes, head: bool) -> Response<Body> {
    let content_length = payload.len().to_string();
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, PAC_CONTENT_TYPE)
        .header(CONTENT_LENGTH, content_length)
        .header(CACHE_CONTROL, "no-cache, no-store, must-revalidate")
        .header(PRAGMA, "no-cache")
        .header(EXPIRES, "0")
        .header(X_CONTENT_TYPE_OPTIONS, "nosniff")
        .body(if head { empty() } else { full(payload) })
        .unwrap_or_else(internal_response_error)
}

fn text_response(status: StatusCode, payload: Bytes, head: bool) -> Response<Body> {
    let content_length = payload.len().to_string();
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(CONTENT_LENGTH, content_length)
        .header(CACHE_CONTROL, "no-store")
        .header(X_CONTENT_TYPE_OPTIONS, "nosniff")
        .body(if head { empty() } else { full(payload) })
        .unwrap_or_else(internal_response_error)
}

fn method_not_allowed() -> Response<Body> {
    Response::builder()
        .status(StatusCode::METHOD_NOT_ALLOWED)
        .header(ALLOW, "GET, HEAD")
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(CACHE_CONTROL, "no-store")
        .body(full(Bytes::from_static(b"method not allowed\n")))
        .unwrap_or_else(internal_response_error)
}

fn internal_response_error(error: hyper::http::Error) -> Response<Body> {
    warn!(error = %error, "failed to build PAC HTTP response");
    let mut response = Response::new(full(Bytes::from_static(b"internal error\n")));
    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    response
}

fn parse_bypass_domains(content: &str) -> Result<Vec<String>, usize> {
    let mut domains = BTreeSet::new();
    let mut invalid_lines = 0_usize;

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let candidate = line
            .split_once('#')
            .map_or(line, |(value, _)| value)
            .trim();
        if candidate.is_empty() {
            continue;
        }

        match normalize_domain(candidate) {
            Some(domain) => {
                domains.insert(domain);
            }
            None => invalid_lines += 1,
        }
    }

    if invalid_lines == 0 {
        Ok(domains.into_iter().collect())
    } else {
        Err(invalid_lines)
    }
}

fn normalize_domain(candidate: &str) -> Option<String> {
    let candidate = candidate
        .strip_prefix("*.")
        .or_else(|| candidate.strip_prefix('.'))
        .unwrap_or(candidate)
        .trim_end_matches('.');
    if candidate.is_empty() || !candidate.is_ascii() || candidate.len() > 253 {
        return None;
    }

    let domain = candidate.to_ascii_lowercase();
    let valid = domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
    });
    valid.then_some(domain)
}

fn render_pac(proxy: &str, domains: &[String]) -> String {
    // JSON serialization is used for both values so a future relaxation of the
    // input grammar cannot turn configuration into executable JavaScript.
    let proxy_json = serde_json::to_string(proxy).unwrap_or_else(|_| "\"invalid\"".to_string());
    let domains_json = serde_json::to_string(domains).unwrap_or_else(|_| "[]".to_string());

    format!(
        r#"// Generated by BSDM-Proxy. Configure with PAC_PROXY and PAC_BYPASS_FILE.
function FindProxyForURL(url, host) {{
    host = (host || "").toLowerCase();
    if (host.length > 1 && host.charAt(host.length - 1) === ".") {{
        host = host.substring(0, host.length - 1);
    }}

    // Local names and special-use local domains never leave the client network.
    if (isPlainHostName(host) || host === "localhost" ||
        dnsDomainIs(host, ".localhost") || dnsDomainIs(host, ".local")) {{
        return "DIRECT";
    }}

    // IPv6 loopback, unique-local and link-local literals.
    var literalHost = host;
    if (literalHost.charAt(0) === "[" && literalHost.charAt(literalHost.length - 1) === "]") {{
        literalHost = literalHost.substring(1, literalHost.length - 1);
    }}
    if (literalHost === "::1" || shExpMatch(literalHost, "fc*:*  ") ||
        shExpMatch(literalHost, "fd*:*") || shExpMatch(literalHost, "fe8*:*") ||
        shExpMatch(literalHost, "fe9*:*") || shExpMatch(literalHost, "fea*:*") ||
        shExpMatch(literalHost, "feb*:*") ) {{
        return "DIRECT";
    }}

    // Resolve once and keep RFC1918, loopback, link-local and CGNAT IPv4 direct.
    var resolved = dnsResolve(host);
    if (resolved && resolved.indexOf(".") !== -1 &&
        (isInNet(resolved, "10.0.0.0", "255.0.0.0") ||
         isInNet(resolved, "172.16.0.0", "255.240.0.0") ||
         isInNet(resolved, "192.168.0.0", "255.255.0.0") ||
         isInNet(resolved, "127.0.0.0", "255.0.0.0") ||
         isInNet(resolved, "169.254.0.0", "255.255.0.0") ||
         isInNet(resolved, "100.64.0.0", "255.192.0.0"))) {{
        return "DIRECT";
    }}

    var bypassDomains = {domains_json};
    for (var i = 0; i < bypassDomains.length; i++) {{
        var domain = bypassDomains[i];
        if (host === domain ||
            (host.length > domain.length &&
             host.substring(host.length - domain.length - 1) === "." + domain)) {{
            return "DIRECT";
        }}
    }}

    // Deliberately no DIRECT fallback: proxy failure must not silently bypass policy.
    return "PROXY " + {proxy_json};
}}
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use prometheus::Registry;

    fn test_state(proxy: &str, bypass_file: Option<PathBuf>) -> Arc<PacState> {
        let config = PacConfig {
            bind: "127.0.0.1:9091".parse().expect("socket address"),
            proxy: validate_proxy_authority(proxy).expect("proxy authority"),
            bypass_file,
            reload_interval: Duration::from_secs(5),
        };
        Arc::new(PacState::new(config, &Registry::new()).expect("PAC state"))
    }

    #[test]
    fn proxy_authority_requires_host_and_port() {
        assert_eq!(
            validate_proxy_authority("proxy.example:3128").expect("valid authority"),
            "proxy.example:3128"
        );
        assert!(validate_proxy_authority("proxy.example").is_err());
        assert!(validate_proxy_authority("http://proxy.example:3128").is_err());
        assert!(validate_proxy_authority("user@proxy.example:3128").is_err());
        assert!(validate_proxy_authority("proxy.example:3128; DIRECT").is_err());
    }

    #[test]
    fn bypass_parser_normalizes_sorts_and_deduplicates() {
        let domains = parse_bypass_domains(
            "\n# comment\nOZON.RU\n*.example.com.\n.example.com\n; another comment\n",
        )
        .expect("valid bypass file");
        assert_eq!(domains, vec!["example.com", "ozon.ru"]);
    }

    #[test]
    fn bypass_parser_rejects_unicode_and_javascript_input() {
        let invalid = parse_bypass_domains(
            "пример.рф\nexample.com\"; return \"DIRECT\n-bad.example\nbad_.example\n",
        )
        .expect_err("invalid entries must reject the whole reload");
        assert_eq!(invalid, 4);

        let punycode = parse_bypass_domains("xn--e1afmkfd.xn--p1ai\n")
            .expect("punycode must be accepted");
        assert_eq!(punycode, vec!["xn--e1afmkfd.xn--p1ai"]);
    }

    #[test]
    fn rendered_pac_matches_exact_domains_and_subdomains() {
        let pac = render_pac(
            "proxy.example:3128",
            &["example.com".to_string(), "ozon.ru".to_string()],
        );
        assert!(pac.contains("var bypassDomains = [\"example.com\",\"ozon.ru\"]"));
        assert!(pac.contains("host === domain"));
        assert!(pac.contains("\".\" + domain"));
        assert!(pac.contains("return \"PROXY \" + \"proxy.example:3128\""));
        assert!(!pac.contains("PROXY proxy.example:3128; DIRECT"));
        assert!(pac.contains("192.168.0.0"));
        assert!(pac.contains("dnsDomainIs(host, \".local\")"));
    }

    #[tokio::test]
    async fn reload_is_atomic_and_keeps_last_known_good_on_invalid_input() {
        let file = tempfile::NamedTempFile::new().expect("tempfile");
        std::fs::write(file.path(), "example.com\n").expect("write initial bypass");
        let state = test_state("proxy.example:3128", Some(file.path().to_path_buf()));
        state.reload_bypass_file().await;
        assert_eq!(state.document.read().await.domain_count, 1);
        let initial_body = state.body().await;

        std::fs::write(file.path(), "bad domain\n").expect("write invalid bypass");
        state.reload_bypass_file().await;
        assert_eq!(state.document.read().await.domain_count, 1);
        assert_eq!(state.body().await, initial_body);

        std::fs::write(file.path(), "ozon.ru\nvseinstrumenti.ru\n")
            .expect("write replacement bypass");
        state.reload_bypass_file().await;
        let body = String::from_utf8(state.body().await.to_vec()).expect("PAC utf8");
        assert_eq!(state.document.read().await.domain_count, 2);
        assert!(body.contains("ozon.ru"));
        assert!(body.contains("vseinstrumenti.ru"));
        assert!(!body.contains("example.com"));
    }

    #[tokio::test]
    async fn endpoints_serve_pac_wpad_health_and_head() {
        let state = test_state("proxy.example:3128", None);

        for path in ["/proxy.pac", "/wpad.dat"] {
            let request = Request::builder()
                .method(Method::GET)
                .uri(path)
                .body(())
                .expect("request");
            let response = handle_pac_request(request, state.clone()).await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.headers().get(CONTENT_TYPE).expect("content type"),
                PAC_CONTENT_TYPE
            );
            let body = response
                .into_body()
                .collect()
                .await
                .expect("body")
                .to_bytes();
            assert!(String::from_utf8_lossy(&body).contains("FindProxyForURL"));
        }

        let head = Request::builder()
            .method(Method::HEAD)
            .uri("/proxy.pac")
            .body(())
            .expect("request");
        let response = handle_pac_request(head, state.clone()).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_ne!(
            response
                .headers()
                .get(CONTENT_LENGTH)
                .expect("content length"),
            "0"
        );
        assert!(response
            .into_body()
            .collect()
            .await
            .expect("head body")
            .to_bytes()
            .is_empty());

        let health = Request::builder()
            .method(Method::GET)
            .uri("/health")
            .body(())
            .expect("request");
        assert_eq!(
            handle_pac_request(health, state.clone()).await.status(),
            StatusCode::OK
        );

        let post = Request::builder()
            .method(Method::POST)
            .uri("/proxy.pac")
            .body(())
            .expect("request");
        assert_eq!(
            handle_pac_request(post, state).await.status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
    }
}
