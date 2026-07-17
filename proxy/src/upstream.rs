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

pub type UpstreamHttpClient =
    hyper_util::client::legacy::Client<hyper_rustls::HttpsConnector<HttpConnector>, Body>;

#[derive(Clone, Debug, Default)]
pub struct UpstreamTlsConfig {
    /// Negotiate HTTP/2 via ALPN on TLS upstream connections.
    pub http2_enabled: bool,
    /// Optional PEM CA bundle path (`UPSTREAM_CA_CERT`).
    pub ca_cert_path: Option<String>,
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

pub fn build_upstream_https_connector(
    config: &UpstreamTlsConfig,
) -> Result<hyper_rustls::HttpsConnector<HttpConnector>, Box<dyn std::error::Error + Send + Sync>> {
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
            .build())
    } else {
        Ok(hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_or_http()
            .enable_http1()
            .build())
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
        })
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
            ca_cert_path: None,
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
