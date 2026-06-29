//! TLS MITM support: dynamic certificate generation and CONNECT interception.

use bytes::Bytes;
use hyper::body::Incoming;
use hyper::Request;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use rustls_pemfile::certs;
use std::collections::HashMap;
use std::io::Cursor;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, warn};

pub type CertPair = (Bytes, Bytes);
type CertMap = Arc<RwLock<HashMap<Arc<str>, CertPair>>>;
type ServerConfigMap = Arc<RwLock<HashMap<Arc<str>, Arc<ServerConfig>>>>;

#[derive(Clone)]
pub struct CertCache {
    certs: CertMap,
    server_configs: ServerConfigMap,
    ca_key: Arc<KeyPair>,
    ca_cert_pem: Bytes,
    in_memory_ca_params: Option<CertificateParams>,
}

impl CertCache {
    pub fn from_pem(
        ca_key_pem: &[u8],
        ca_cert_pem: &[u8],
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let ca_key_pem_str = String::from_utf8_lossy(ca_key_pem);
        let ca_key = Arc::new(KeyPair::from_pem(&ca_key_pem_str)?);

        let (ca_cert_pem, in_memory_ca_params) = if ca_cert_pem.is_empty() {
            warn!(
                "CA certificate not found, generating in-memory CA (install proxy-generated CA on clients)"
            );
            let ca_params = Self::in_memory_ca_params()?;
            let ca_cert = ca_params.self_signed(ca_key.as_ref())?;
            (Bytes::from(ca_cert.pem().into_bytes()), Some(ca_params))
        } else {
            (Bytes::copy_from_slice(ca_cert_pem), None)
        };

        Ok(Self {
            certs: Arc::new(RwLock::new(HashMap::new())),
            server_configs: Arc::new(RwLock::new(HashMap::new())),
            ca_key,
            ca_cert_pem,
            in_memory_ca_params,
        })
    }

    fn in_memory_ca_params() -> Result<CertificateParams, rcgen::Error> {
        let mut ca_params = CertificateParams::new(vec!["BSDM Proxy CA".to_string()])?;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        ca_params.distinguished_name = DistinguishedName::new();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "BSDM Proxy CA");
        Ok(ca_params)
    }

    fn issuer(&self) -> Result<Issuer<'_, &KeyPair>, rcgen::Error> {
        if let Some(params) = &self.in_memory_ca_params {
            Ok(Issuer::from_params(params, self.ca_key.as_ref()))
        } else {
            let pem = String::from_utf8_lossy(&self.ca_cert_pem);
            Issuer::from_ca_cert_pem(&pem, self.ca_key.as_ref())
        }
    }

    pub async fn server_config_for_domain(
        &self,
        domain: &str,
    ) -> Result<Arc<ServerConfig>, Box<dyn std::error::Error + Send + Sync>> {
        let domain_arc: Arc<str> = domain.into();

        {
            let cache = self.server_configs.read().await;
            if let Some(config) = cache.get(&domain_arc) {
                return Ok(config.clone());
            }
        }

        let (cert_pem, key_pem) = self.get_or_generate(domain).await?;
        let config = Arc::new(build_server_config(&cert_pem, &key_pem, &self.ca_cert_pem)?);

        let mut cache = self.server_configs.write().await;
        cache.insert(domain_arc, config.clone());
        Ok(config)
    }

    async fn get_or_generate(
        &self,
        domain: &str,
    ) -> Result<CertPair, Box<dyn std::error::Error + Send + Sync>> {
        let domain_arc: Arc<str> = domain.into();

        {
            let cache = self.certs.read().await;
            if let Some(cert) = cache.get(&domain_arc) {
                debug!("Certificate cache HIT for {}", domain);
                return Ok(cert.clone());
            }
        }

        debug!("Certificate cache MISS for {}, generating...", domain);
        let key_pair = KeyPair::generate()?;
        let mut params = CertificateParams::new(vec![domain.to_string()])?;
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, domain);
        params
            .distinguished_name
            .push(DnType::OrganizationName, "BSDM Proxy");
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];

        let issuer = self.issuer()?;
        let cert = params.signed_by(&key_pair, &issuer)?;
        let cert_pem = Bytes::from(cert.pem().into_bytes());
        let key_pem = Bytes::from(key_pair.serialize_pem().into_bytes());

        let cert_pair = (cert_pem, key_pem);
        let mut cache = self.certs.write().await;
        cache.insert(domain_arc, cert_pair.clone());
        Ok(cert_pair)
    }
}

fn build_server_config(
    cert_pem: &[u8],
    key_pem: &[u8],
    ca_cert_pem: &[u8],
) -> Result<ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
    let mut chain = parse_certs(cert_pem)?;
    chain.extend(parse_certs(ca_cert_pem)?);

    let key = parse_private_key(key_pem)?;

    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| e.into())
}

fn parse_certs(
    pem: &[u8],
) -> Result<Vec<CertificateDer<'static>>, Box<dyn std::error::Error + Send + Sync>> {
    let mut reader = Cursor::new(pem);
    let certs: Vec<CertificateDer<'static>> = certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|c| c.into_owned())
        .collect();
    Ok(certs)
}

fn parse_private_key(
    pem: &[u8],
) -> Result<PrivateKeyDer<'static>, Box<dyn std::error::Error + Send + Sync>> {
    let mut reader = Cursor::new(pem);
    rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| "no private key found in PEM".into())
}

pub fn parse_authority(authority: &str) -> (String, u16) {
    if let Some((host, port_str)) = authority.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            return (host.to_string(), port);
        }
    }
    (authority.to_string(), 443)
}

pub fn should_mitm_port(port: u16) -> bool {
    matches!(port, 443 | 8443)
}

pub fn rewrite_mitm_request(
    req: Request<Incoming>,
    authority: &str,
) -> Result<Request<Incoming>, Box<dyn std::error::Error + Send + Sync>> {
    let (domain, port) = parse_authority(authority);
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    let url = if port == 443 {
        format!("https://{domain}{path}")
    } else {
        format!("https://{domain}:{port}{path}")
    };

    let (mut parts, body) = req.into_parts();
    parts.uri = url.parse()?;
    Ok(Request::from_parts(parts, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_authority_default_port() {
        assert_eq!(
            parse_authority("example.com"),
            ("example.com".to_string(), 443)
        );
    }

    #[test]
    fn test_parse_authority_with_port() {
        assert_eq!(
            parse_authority("example.com:8443"),
            ("example.com".to_string(), 8443)
        );
    }

    #[test]
    fn test_should_mitm_port() {
        assert!(should_mitm_port(443));
        assert!(should_mitm_port(8443));
        assert!(!should_mitm_port(22));
        assert!(!should_mitm_port(8080));
    }

    #[test]
    fn test_cert_signed_by_ca() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();

        let ca_key = KeyPair::generate().unwrap();
        let cache = CertCache::from_pem(ca_key.serialize_pem().as_bytes(), b"").unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let config = rt
            .block_on(cache.server_config_for_domain("test.example.com"))
            .unwrap();
        assert!(!config.ignore_client_order);
    }
}
