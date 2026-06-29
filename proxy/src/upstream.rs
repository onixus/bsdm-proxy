//! Upstream HTTP(S) client TLS configuration.

use hyper_rustls::ConfigBuilderExt;
use hyper_util::client::legacy::connect::HttpConnector;
use std::io::Cursor;
use tracing::info;

#[derive(Clone, Debug, Default)]
pub struct UpstreamTlsConfig {
    /// Negotiate HTTP/2 via ALPN on TLS upstream connections.
    pub http2_enabled: bool,
}

impl UpstreamTlsConfig {
    pub fn from_env() -> Self {
        let http2_enabled = std::env::var("UPSTREAM_HTTP2_ENABLED")
            .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false);
        Self { http2_enabled }
    }
}

pub fn build_upstream_https_connector(
    config: &UpstreamTlsConfig,
) -> Result<hyper_rustls::HttpsConnector<HttpConnector>, Box<dyn std::error::Error>> {
    let tls_config = if let Ok(path) = std::env::var("UPSTREAM_CA_CERT") {
        let pem = std::fs::read(&path)
            .map_err(|e| format!("failed to read UPSTREAM_CA_CERT {path}: {e}"))?;
        let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls_pemfile::certs(&mut Cursor::new(pem))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .map(|cert| cert.into_owned())
                .collect();
        let mut roots = rustls::RootCertStore::empty();
        roots.add_parsable_certificates(certs);
        info!("Upstream TLS: trusting custom CA from UPSTREAM_CA_CERT");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_tls_config_defaults_http2_off() {
        std::env::remove_var("UPSTREAM_HTTP2_ENABLED");
        let cfg = UpstreamTlsConfig::from_env();
        assert!(!cfg.http2_enabled);
    }

    #[test]
    fn upstream_tls_config_parses_http2_flag() {
        std::env::set_var("UPSTREAM_HTTP2_ENABLED", "true");
        let cfg = UpstreamTlsConfig::from_env();
        assert!(cfg.http2_enabled);
        std::env::remove_var("UPSTREAM_HTTP2_ENABLED");
    }

    #[test]
    fn builds_connector_with_and_without_http2() {
        let _ = build_upstream_https_connector(&UpstreamTlsConfig::default()).unwrap();
        let _ = build_upstream_https_connector(&UpstreamTlsConfig {
            http2_enabled: true,
        })
        .unwrap();
    }
}
