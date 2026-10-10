//! Upstream HTTP(S) client TLS configuration and hot-reloadable client pool.

use arc_swap::ArcSwap;
use hyper_rustls::ConfigBuilderExt;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use serde::Serialize;
use std::io::Cursor;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::info;

use crate::http_types::Body;
use crate::security_util::{ResolvedDestinationPolicy, SsrfGuardResolver};

/// TCP connector whose DNS answers pass the SSRF destination policy (AS-01).
pub type GuardedHttpConnector = HttpConnector<SsrfGuardResolver>;

pub type UpstreamHttpClient =
    hyper_util::client::legacy::Client<hyper_rustls::HttpsConnector<GuardedHttpConnector>, Body>;

/// Default TCP connect deadline for upstream origins (`UPSTREAM_CONNECT_TIMEOUT_MS`).
pub const DEFAULT_UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Default deadline for upstream response headers (`UPSTREAM_RESPONSE_TIMEOUT_MS`).
pub const DEFAULT_UPSTREAM_RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone, Debug)]
pub struct UpstreamTlsConfig {
    /// Negotiate HTTP/2 via ALPN on TLS upstream connections.
    pub http2_enabled: bool,
    /// Optional PEM CA bundle path (`UPSTREAM_CA_CERT`).
    pub ca_cert_path: Option<String>,
    /// TCP connect deadline (`UPSTREAM_CONNECT_TIMEOUT_MS`, default 10 s,
    /// `0` disables). Bounds black-holed origins (AS-22).
    pub connect_timeout: Option<Duration>,
    /// Deadline from sending the request to receiving response headers
    /// (`UPSTREAM_RESPONSE_TIMEOUT_MS`, default 60 s, `0` disables). Body
    /// streaming is not covered, so large downloads are unaffected.
    pub response_timeout: Option<Duration>,
    /// Checked against every resolved upstream address before connecting
    /// (`BLOCK_CLOUD_METADATA`, `BLOCK_LOOPBACK_FORWARDING`).
    pub destination_policy: ResolvedDestinationPolicy,
}

impl Default for UpstreamTlsConfig {
    fn default() -> Self {
        Self {
            http2_enabled: false,
            ca_cert_path: None,
            connect_timeout: Some(DEFAULT_UPSTREAM_CONNECT_TIMEOUT),
            response_timeout: Some(DEFAULT_UPSTREAM_RESPONSE_TIMEOUT),
            destination_policy: ResolvedDestinationPolicy {
                block_metadata: true,
                block_loopback: false,
            },
        }
    }
}

/// Reads a millisecond timeout from `key`: unset/invalid → `default`, `0` → disabled.
fn env_timeout_ms(key: &str, default: Duration) -> Option<Duration> {
    match std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
    {
        Some(0) => None,
        Some(ms) => Some(Duration::from_millis(ms)),
        None => Some(default),
    }
}

impl UpstreamTlsConfig {
    pub fn from_env() -> Self {
        let http2_enabled = std::env::var("UPSTREAM_HTTP2_ENABLED")
            .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false);
        let ca_cert_path = std::env::var("UPSTREAM_CA_CERT")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        Self {
            http2_enabled,
            ca_cert_path,
            connect_timeout: env_timeout_ms(
                "UPSTREAM_CONNECT_TIMEOUT_MS",
                DEFAULT_UPSTREAM_CONNECT_TIMEOUT,
            ),
            response_timeout: env_timeout_ms(
                "UPSTREAM_RESPONSE_TIMEOUT_MS",
                DEFAULT_UPSTREAM_RESPONSE_TIMEOUT,
            ),
            destination_policy: crate::security_defaults::resolved_destination_policy_from_env(),
        }
    }
}

/// Error from [`UpstreamClientHandle::request`].
#[derive(Debug)]
pub enum UpstreamRequestError {
    /// Connect / TLS / protocol failure reported by the Hyper client.
    Client(hyper_util::client::legacy::Error),
    /// No response headers within the configured response timeout.
    Timeout(Duration),
}

impl std::fmt::Display for UpstreamRequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Client(e) => write!(f, "{e}"),
            Self::Timeout(d) => write!(f, "upstream response timeout after {}ms", d.as_millis()),
        }
    }
}

impl std::error::Error for UpstreamRequestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Client(e) => Some(e),
            Self::Timeout(_) => None,
        }
    }
}

/// Observable snapshot for control-plane GET / reload responses.
#[derive(Clone, Debug, Serialize)]
pub struct UpstreamTlsSnapshot {
    pub http2_enabled: bool,
    pub ca_cert_path: Option<String>,
    pub custom_ca: bool,
    pub reloaded_at_unix: u64,
}

impl UpstreamTlsSnapshot {
    fn from_config(config: &UpstreamTlsConfig) -> Self {
        Self {
            http2_enabled: config.http2_enabled,
            ca_cert_path: config.ca_cert_path.clone(),
            custom_ca: config.ca_cert_path.is_some(),
            reloaded_at_unix: unix_now(),
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Plain TCP connector under the TLS layer. Single construction point so the
/// resolver (SSRF guard) and socket options live in one place.
fn build_http_connector(config: &UpstreamTlsConfig) -> GuardedHttpConnector {
    // IP-literal hosts bypass the resolver inside HttpConnector; those are
    // covered by the string check in `check_destination_security`.
    let mut http =
        HttpConnector::new_with_resolver(SsrfGuardResolver::new(config.destination_policy));
    // HttpConnector won't enforce scheme; HttpsConnector handles https.
    http.enforce_http(false);
    http.set_connect_timeout(config.connect_timeout);
    http
}

pub fn build_upstream_https_connector(
    config: &UpstreamTlsConfig,
) -> Result<
    hyper_rustls::HttpsConnector<GuardedHttpConnector>,
    Box<dyn std::error::Error + Send + Sync>,
> {
    let tls_config = if let Some(path) = &config.ca_cert_path {
        let pem = std::fs::read(path)
            .map_err(|e| format!("failed to read UPSTREAM_CA_CERT {path}: {e}"))?;
        let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls_pemfile::certs(&mut Cursor::new(pem))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .map(|cert| cert.into_owned())
                .collect();
        if certs.is_empty() {
            return Err(format!("no certificates found in UPSTREAM_CA_CERT {path}").into());
        }
        let mut roots = rustls::RootCertStore::empty();
        let (added, _) = roots.add_parsable_certificates(certs);
        if added == 0 {
            return Err(format!("failed to parse any CA certificates from {path}").into());
        }
        info!("Upstream TLS: trusting custom CA from {path} ({added} certs)");
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    } else {
        rustls::ClientConfig::builder()
            .with_webpki_roots()
            .with_no_client_auth()
    };

    if config.http2_enabled {
        info!("Upstream TLS: HTTP/2 ALPN enabled (UPSTREAM_HTTP2_ENABLED)");
        Ok(hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .wrap_connector(build_http_connector(config)))
    } else {
        Ok(hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_or_http()
            .enable_http1()
            .wrap_connector(build_http_connector(config)))
    }
}

pub fn build_upstream_http_client(
    config: &UpstreamTlsConfig,
) -> Result<UpstreamHttpClient, Box<dyn std::error::Error + Send + Sync>> {
    let https = build_upstream_https_connector(config)?;
    Ok(
        hyper_util::client::legacy::Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(32)
            .build(https),
    )
}

/// Shared hot-reloadable upstream Hyper client (connection pool rebuilt on reload).
#[derive(Clone)]
pub struct UpstreamClientHandle {
    client: Arc<ArcSwap<UpstreamHttpClient>>,
    snapshot: Arc<ArcSwap<UpstreamTlsSnapshot>>,
    response_timeout: Arc<ArcSwap<Option<Duration>>>,
}

impl UpstreamClientHandle {
    pub fn new(
        config: UpstreamTlsConfig,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let client = build_upstream_http_client(&config)?;
        let snapshot = UpstreamTlsSnapshot::from_config(&config);
        Ok(Self {
            client: Arc::new(ArcSwap::from_pointee(client)),
            snapshot: Arc::new(ArcSwap::from_pointee(snapshot)),
            response_timeout: Arc::new(ArcSwap::from_pointee(config.response_timeout)),
        })
    }

    /// Sends `req` upstream, bounded by the response timeout (AS-22): fails
    /// with [`UpstreamRequestError::Timeout`] if response headers do not
    /// arrive in time, so a stalled origin cannot pin the request forever.
    pub async fn request(
        &self,
        req: hyper::Request<Body>,
    ) -> Result<hyper::Response<hyper::body::Incoming>, UpstreamRequestError> {
        let client = self.client.load_full();
        let fut = client.request(req);
        match **self.response_timeout.load() {
            Some(limit) => match tokio::time::timeout(limit, fut).await {
                Ok(res) => res.map_err(UpstreamRequestError::Client),
                Err(_) => Err(UpstreamRequestError::Timeout(limit)),
            },
            None => fut.await.map_err(UpstreamRequestError::Client),
        }
    }

    pub fn load(&self) -> arc_swap::Guard<Arc<UpstreamHttpClient>> {
        self.client.load()
    }

    pub fn snapshot(&self) -> Arc<UpstreamTlsSnapshot> {
        self.snapshot.load_full()
    }

    /// Re-read `UPSTREAM_CA_CERT` / `UPSTREAM_HTTP2_ENABLED` and swap the client pool.
    pub fn reload_from_env(&self) -> Result<UpstreamTlsSnapshot, String> {
        let config = UpstreamTlsConfig::from_env();
        let client = build_upstream_http_client(&config).map_err(|e| e.to_string())?;
        let snapshot = UpstreamTlsSnapshot::from_config(&config);
        self.client.store(Arc::new(client));
        self.response_timeout
            .store(Arc::new(config.response_timeout));
        self.snapshot.store(Arc::new(snapshot.clone()));
        info!(
            "Upstream TLS reloaded (http2={}, custom_ca={})",
            snapshot.http2_enabled, snapshot.custom_ca
        );
        Ok(snapshot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, Once, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn ensure_crypto_provider() {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    #[test]
    fn upstream_tls_config_defaults_http2_off() {
        let _g = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("UPSTREAM_HTTP2_ENABLED");
        std::env::remove_var("UPSTREAM_CA_CERT");
        let cfg = UpstreamTlsConfig::from_env();
        assert!(!cfg.http2_enabled);
        assert!(cfg.ca_cert_path.is_none());
    }

    #[test]
    fn upstream_tls_config_parses_http2_flag() {
        let _g = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("UPSTREAM_HTTP2_ENABLED", "true");
        let cfg = UpstreamTlsConfig::from_env();
        assert!(cfg.http2_enabled);
        std::env::remove_var("UPSTREAM_HTTP2_ENABLED");
    }

    #[test]
    fn builds_connector_with_and_without_http2() {
        ensure_crypto_provider();
        let _ = build_upstream_https_connector(&UpstreamTlsConfig::default()).unwrap();
        let _ = build_upstream_https_connector(&UpstreamTlsConfig {
            http2_enabled: true,
            ..UpstreamTlsConfig::default()
        })
        .unwrap();
    }

    #[test]
    fn reload_swaps_snapshot_from_env() {
        ensure_crypto_provider();
        let _g = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("UPSTREAM_CA_CERT");
        std::env::remove_var("UPSTREAM_HTTP2_ENABLED");
        let handle = UpstreamClientHandle::new(UpstreamTlsConfig::default()).unwrap();
        assert!(!handle.snapshot().http2_enabled);

        std::env::set_var("UPSTREAM_HTTP2_ENABLED", "true");
        let snap = handle.reload_from_env().unwrap();
        std::env::remove_var("UPSTREAM_HTTP2_ENABLED");
        assert!(snap.http2_enabled);
        assert!(handle.snapshot().http2_enabled);
        assert!(!snap.custom_ca);
    }

    #[test]
    fn upstream_timeouts_default_and_parse_from_env() {
        let _g = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("UPSTREAM_CONNECT_TIMEOUT_MS");
        std::env::remove_var("UPSTREAM_RESPONSE_TIMEOUT_MS");
        let cfg = UpstreamTlsConfig::from_env();
        assert_eq!(cfg.connect_timeout, Some(DEFAULT_UPSTREAM_CONNECT_TIMEOUT));
        assert_eq!(
            cfg.response_timeout,
            Some(DEFAULT_UPSTREAM_RESPONSE_TIMEOUT)
        );

        std::env::set_var("UPSTREAM_CONNECT_TIMEOUT_MS", "1500");
        std::env::set_var("UPSTREAM_RESPONSE_TIMEOUT_MS", "0");
        let cfg = UpstreamTlsConfig::from_env();
        assert_eq!(cfg.connect_timeout, Some(Duration::from_millis(1500)));
        assert_eq!(cfg.response_timeout, None);

        std::env::set_var("UPSTREAM_CONNECT_TIMEOUT_MS", "garbage");
        let cfg = UpstreamTlsConfig::from_env();
        assert_eq!(cfg.connect_timeout, Some(DEFAULT_UPSTREAM_CONNECT_TIMEOUT));
        std::env::remove_var("UPSTREAM_CONNECT_TIMEOUT_MS");
        std::env::remove_var("UPSTREAM_RESPONSE_TIMEOUT_MS");
    }

    fn get(url: &str) -> hyper::Request<Body> {
        hyper::Request::builder()
            .uri(url)
            .body(crate::http_types::empty())
            .unwrap()
    }

    /// AS-22: an origin that accepts the connection but never answers is cut
    /// off by the response timeout instead of hanging forever.
    #[tokio::test]
    async fn request_times_out_on_stalled_origin() {
        ensure_crypto_provider();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((sock, _)) = listener.accept().await {
                held.push(sock); // read nothing, answer nothing
            }
        });
        let handle = UpstreamClientHandle::new(UpstreamTlsConfig {
            response_timeout: Some(Duration::from_millis(200)),
            ..UpstreamTlsConfig::default()
        })
        .unwrap();
        let started = std::time::Instant::now();
        let err = handle
            .request(get(&format!("http://{addr}/")))
            .await
            .unwrap_err();
        assert!(matches!(err, UpstreamRequestError::Timeout(_)), "{err}");
        assert!(err.to_string().contains("timeout after 200ms"));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    /// AS-01: a hostname that resolves to loopback is refused by the resolver
    /// even though the URI never names 127.0.0.1.
    #[tokio::test]
    async fn guarded_resolver_refuses_names_resolving_to_loopback() {
        ensure_crypto_provider();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = UpstreamClientHandle::new(UpstreamTlsConfig {
            destination_policy: ResolvedDestinationPolicy {
                block_metadata: true,
                block_loopback: true,
            },
            ..UpstreamTlsConfig::default()
        })
        .unwrap();
        let err = handle
            .request(get(&format!("http://localhost:{port}/")))
            .await
            .unwrap_err();
        let chain = format!("{:?}", err);
        assert!(chain.contains("loopback destination blocked"), "{chain}");
    }

    #[tokio::test]
    async fn request_returns_response_from_responsive_origin() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        ensure_crypto_provider();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let _ = sock
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .await;
            }
        });
        let handle = UpstreamClientHandle::new(UpstreamTlsConfig {
            response_timeout: Some(Duration::from_secs(5)),
            ..UpstreamTlsConfig::default()
        })
        .unwrap();
        let resp = handle
            .request(get(&format!("http://{addr}/")))
            .await
            .unwrap();
        assert_eq!(resp.status(), hyper::StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn request_reports_connect_failure_as_client_error() {
        ensure_crypto_provider();
        // Bind then drop to get a (very likely) closed local port.
        let addr = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let handle = UpstreamClientHandle::new(UpstreamTlsConfig::default()).unwrap();
        let err = handle
            .request(get(&format!("http://{addr}/")))
            .await
            .unwrap_err();
        assert!(matches!(err, UpstreamRequestError::Client(_)), "{err}");
    }

    #[test]
    fn reload_rejects_missing_ca_file() {
        ensure_crypto_provider();
        let _g = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let handle = UpstreamClientHandle::new(UpstreamTlsConfig::default()).unwrap();
        std::env::set_var("UPSTREAM_CA_CERT", "/nonexistent/upstream-ca.pem");
        let err = handle.reload_from_env().unwrap_err();
        std::env::remove_var("UPSTREAM_CA_CERT");
        assert!(err.contains("failed to read") || err.contains("UPSTREAM_CA_CERT"));
        // Previous client remains usable.
        assert!(!handle.snapshot().custom_ca);
    }
}
