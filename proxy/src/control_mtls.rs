//! Optional mTLS listener for agent control-plane APIs.
//!
//! Keeps plain HTTP metrics/control (`METRICS_PORT`) for Prometheus and Admin Console.
//! When enabled, agents can speak HTTPS + client certificate on
//! `CONTROL_MTLS_BIND` (default `0.0.0.0:9443`).

use crate::tls::CertCache;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use sha2::{Digest, Sha256};
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, warn};

/// Environment-driven mTLS control plane settings.
#[derive(Debug, Clone)]
pub struct ControlMtlsConfig {
    pub enabled: bool,
    pub bind: String,
    /// Server certificate PEM path (optional — falls back to CA-signed leaf).
    pub cert_file: Option<PathBuf>,
    pub key_file: Option<PathBuf>,
    /// Client CA PEM (defaults to `./certs/ca.crt` or `/certs/ca.crt`).
    pub client_ca_file: Option<PathBuf>,
    /// Hostname / SAN for auto-generated server leaf when cert files unset.
    pub server_name: String,
    /// If true, peer cert SHA-256 must match an enrolled non-revoked device.
    pub require_enrolled_fingerprint: bool,
    /// If true (default when mTLS enabled), reject fingerprints on the agent CRL.
    pub check_crl: bool,
}

impl ControlMtlsConfig {
    pub fn from_env() -> Self {
        let enabled = env_flag("CONTROL_MTLS_ENABLED");
        let bind =
            std::env::var("CONTROL_MTLS_BIND").unwrap_or_else(|_| "0.0.0.0:9443".to_string());
        let cert_file = env_path("CONTROL_MTLS_CERT_FILE");
        let key_file = env_path("CONTROL_MTLS_KEY_FILE");
        let client_ca_file = env_path("CONTROL_MTLS_CLIENT_CA_FILE");
        let server_name = std::env::var("CONTROL_MTLS_SERVER_NAME")
            .unwrap_or_else(|_| "control.bsdm.local".to_string());
        let require_enrolled_fingerprint = env_flag("CONTROL_MTLS_REQUIRE_ENROLLED");
        // Default: check CRL when mTLS is on, unless explicitly disabled.
        let check_crl = if std::env::var("CONTROL_MTLS_CHECK_CRL").is_ok() {
            env_flag("CONTROL_MTLS_CHECK_CRL")
        } else {
            enabled
        };
        Self {
            enabled,
            bind,
            cert_file,
            key_file,
            client_ca_file,
            server_name,
            require_enrolled_fingerprint,
            check_crl,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if self.bind.trim().is_empty() {
            return Err("CONTROL_MTLS_BIND must not be empty when mTLS enabled".into());
        }
        let has_cert = self.cert_file.is_some();
        let has_key = self.key_file.is_some();
        if has_cert != has_key {
            return Err(
                "CONTROL_MTLS_CERT_FILE and CONTROL_MTLS_KEY_FILE must be set together".into(),
            );
        }
        Ok(())
    }
}

/// Build a rustls server config that **requires** a client certificate
/// signed by the configured client CA (proxy/agent CA by default).
pub fn build_mtls_server_config(
    cert_cache: &CertCache,
    config: &ControlMtlsConfig,
) -> Result<Arc<ServerConfig>, String> {
    config.validate()?;

    let client_ca_pem = load_client_ca_pem(config, cert_cache)?;
    let mut roots = RootCertStore::empty();
    let ca_certs = parse_certs(&client_ca_pem)?;
    for cert in ca_certs {
        roots
            .add(cert)
            .map_err(|e| format!("add client CA to trust store: {e}"))?;
    }
    if roots.is_empty() {
        return Err("client CA trust store is empty".into());
    }

    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|e| format!("client cert verifier: {e}"))?;

    let (cert_chain, key) = load_server_identity(cert_cache, config)?;

    let mut server_config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(cert_chain, key)
        .map_err(|e| format!("server config: {e}"))?;
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    info!(
        bind = %config.bind,
        server_name = %config.server_name,
        require_enrolled = config.require_enrolled_fingerprint,
        "Control plane agent mTLS server config ready (client cert required)"
    );
    Ok(Arc::new(server_config))
}

/// SHA-256 hex fingerprint of the leaf certificate DER (matches enroll response).
pub fn cert_fingerprint_sha256(der: &[u8]) -> String {
    hex::encode(Sha256::digest(der))
}

fn load_client_ca_pem(
    config: &ControlMtlsConfig,
    cert_cache: &CertCache,
) -> Result<Vec<u8>, String> {
    if let Some(path) = &config.client_ca_file {
        return std::fs::read(path).map_err(|e| format!("read CONTROL_MTLS_CLIENT_CA_FILE: {e}"));
    }
    for candidate in ["./certs/ca.crt", "/certs/ca.crt"] {
        if let Ok(bytes) = std::fs::read(candidate) {
            if !bytes.is_empty() {
                return Ok(bytes);
            }
        }
    }
    // Ephemeral/in-memory CA from CertCache.
    let pem = cert_cache.ca_cert_pem();
    if pem.trim().is_empty() {
        return Err(
            "CONTROL_MTLS_CLIENT_CA_FILE unset and no ./certs/ca.crt (or CertCache CA)".into(),
        );
    }
    warn!("CONTROL_MTLS_CLIENT_CA_FILE unset — using proxy CertCache CA PEM for client trust");
    Ok(pem.into_bytes())
}

fn load_server_identity(
    cert_cache: &CertCache,
    config: &ControlMtlsConfig,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String> {
    if let (Some(cert_path), Some(key_path)) = (&config.cert_file, &config.key_file) {
        let cert_pem =
            std::fs::read(cert_path).map_err(|e| format!("read CONTROL_MTLS_CERT_FILE: {e}"))?;
        let key_pem =
            std::fs::read(key_path).map_err(|e| format!("read CONTROL_MTLS_KEY_FILE: {e}"))?;
        let mut chain = parse_certs(&cert_pem)?;
        // Append CA so clients can build chain when leaf is intermediate-less.
        if let Ok(ca) = load_client_ca_pem(config, cert_cache) {
            chain.extend(parse_certs(&ca)?);
        }
        let key = parse_private_key(&key_pem)?;
        return Ok((chain, key));
    }

    // Auto leaf signed by proxy CA for CONTROL_MTLS_SERVER_NAME.
    let (cert_pem, key_pem) = cert_cache
        .server_identity_pem(&config.server_name)
        .map_err(|e| format!("generate control mTLS server identity: {e}"))?;
    let mut chain = parse_certs(&cert_pem)?;
    chain.extend(parse_certs(cert_cache.ca_cert_pem().as_bytes())?);
    let key = parse_private_key(&key_pem)?;
    info!(
        server_name = %config.server_name,
        "CONTROL_MTLS server cert auto-issued by proxy CA"
    );
    Ok((chain, key))
}

fn parse_certs(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, String> {
    let mut reader = Cursor::new(pem);
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("parse certs PEM: {e}"))
        .map(|v| v.into_iter().map(|c| c.into_owned()).collect())
}

fn parse_private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, String> {
    let mut reader = Cursor::new(pem);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| format!("parse key PEM: {e}"))?
        .ok_or_else(|| "no private key in PEM".into())
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var(name)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::KeyPair;

    #[test]
    fn disabled_config_validates() {
        let cfg = ControlMtlsConfig {
            enabled: false,
            bind: String::new(),
            cert_file: None,
            key_file: None,
            client_ca_file: None,
            server_name: "x".into(),
            require_enrolled_fingerprint: false,
            check_crl: false,
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn builds_mtls_config_from_ephemeral_ca() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca_key = KeyPair::generate().unwrap();
        let cache = CertCache::from_pem(ca_key.serialize_pem().as_bytes(), b"").unwrap();
        let cfg = ControlMtlsConfig {
            enabled: true,
            bind: "127.0.0.1:9443".into(),
            cert_file: None,
            key_file: None,
            client_ca_file: None,
            server_name: "control.test.local".into(),
            require_enrolled_fingerprint: false,
            check_crl: true,
        };
        let server = build_mtls_server_config(&cache, &cfg).unwrap();
        assert!(!server.alpn_protocols.is_empty());
    }

    #[test]
    fn fingerprint_is_64_hex() {
        let fp = cert_fingerprint_sha256(b"not-a-real-cert-der");
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
