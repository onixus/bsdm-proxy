//! TLS MITM support: dynamic certificate generation and CONNECT interception.

use bytes::Bytes;
use chrono::Datelike;
use hyper::body::Incoming;
use hyper::Request;
use rcgen::{
    date_time_ymd, BasicConstraints, CertificateParams, CertificateRevocationListParams,
    CertificateSigningRequestParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyIdMethod, KeyPair, KeyUsagePurpose, RevocationReason, RevokedCertParams, SanType,
    SerialNumber,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use rustls_pemfile::certs;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Cursor;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::agent_ocsp;

pub type CertPair = (Bytes, Bytes);

/// Upper bound on entries in each MITM cache. Both maps are keyed by SNI, so an
/// unbounded map grows with every unique hostname a client asks for.
const DEFAULT_CERT_CACHE_MAX_ENTRIES: usize = 10_000;
const MIN_CERT_CACHE_MAX_ENTRIES: usize = 128;

struct CachedCert {
    pair: CertPair,
    created: Instant,
}

type CertMap = Arc<RwLock<HashMap<Arc<str>, CachedCert>>>;

struct CachedServerConfig {
    config: Arc<ServerConfig>,
    /// When the OCSP staple was generated (for TTL refresh).
    stapled_at: Instant,
}

type ServerConfigMap = Arc<RwLock<HashMap<Arc<str>, CachedServerConfig>>>;

fn cert_cache_max_entries() -> usize {
    std::env::var("MITM_CERT_CACHE_MAX_ENTRIES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .map(|n| n.max(MIN_CERT_CACHE_MAX_ENTRIES))
        .unwrap_or(DEFAULT_CERT_CACHE_MAX_ENTRIES)
}

/// Evict the oldest entries when a cache is at capacity.
///
/// A single sweep frees 10% of the cap, so the sort cost is amortised over the
/// following `max / 10` inserts instead of being paid on every cache miss.
fn evict_oldest<V>(cache: &mut HashMap<Arc<str>, V>, max: usize, stamp: impl Fn(&V) -> Instant) {
    if cache.len() < max {
        return;
    }
    let target = max - (max / 10).max(1);
    let mut entries: Vec<(Instant, Arc<str>)> = cache
        .iter()
        .map(|(key, value)| (stamp(value), key.clone()))
        .collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    for (_, key) in entries {
        if cache.len() <= target {
            break;
        }
        cache.remove(&key);
    }
    warn!(
        entries = cache.len(),
        max, "MITM certificate cache at capacity; evicted oldest entries"
    );
}

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

    /// Load CA for proxy startup. When MITM is off, missing CA files are allowed.
    pub async fn load_for_startup(mitm_enabled: bool) -> Result<Self, Box<dyn std::error::Error>> {
        async fn read_key() -> std::io::Result<Vec<u8>> {
            tokio::fs::read("/certs/ca.key")
                .await
                .or_else(|_| std::fs::read("./certs/ca.key"))
        }

        async fn read_cert() -> Vec<u8> {
            tokio::fs::read("/certs/ca.crt")
                .await
                .or_else(|_| std::fs::read("./certs/ca.crt"))
                .unwrap_or_default()
        }

        if mitm_enabled {
            let ca_key = read_key().await.map_err(|e| {
                format!("MITM enabled but CA key not found at /certs/ca.key or ./certs/ca.key: {e}")
            })?;
            let ca_cert = read_cert().await;
            return Self::from_pem(&ca_key, &ca_cert);
        }

        match read_key().await {
            Ok(ca_key) => {
                let ca_cert = read_cert().await;
                Self::from_pem(&ca_key, &ca_cert)
            }
            Err(_) => {
                warn!("MITM disabled and no CA key on disk; using ephemeral in-memory CA");
                let key_pair = KeyPair::generate()?;
                Self::from_pem(key_pair.serialize_pem().as_bytes(), b"")
            }
        }
    }

    fn in_memory_ca_params() -> Result<CertificateParams, rcgen::Error> {
        let mut ca_params = CertificateParams::new(vec!["BSDM Proxy CA".to_string()])?;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::CrlSign,
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
        let refresh = ocsp_staple_refresh_secs();

        {
            let cache = self.server_configs.read().await;
            if let Some(entry) = cache.get(&domain_arc) {
                if entry.stapled_at.elapsed().as_secs() < refresh {
                    return Ok(entry.config.clone());
                }
            }
        }

        let (cert_pem, key_pem) = self.get_or_generate(domain).await?;
        let ocsp = if ocsp_stapling_enabled() {
            match agent_ocsp::staple_good_for_leaf_pem(self, &cert_pem) {
                Ok(der) => {
                    debug!(
                        domain,
                        staple_len = der.len(),
                        "OCSP staple attached to MITM leaf"
                    );
                    Some(der)
                }
                Err(e) => {
                    warn!(domain, error = %e, "OCSP stapling failed; serving without staple");
                    None
                }
            }
        } else {
            None
        };
        let config = Arc::new(build_server_config(
            &cert_pem,
            &key_pem,
            &self.ca_cert_pem,
            ocsp.as_deref(),
        )?);

        let max_entries = cert_cache_max_entries();
        let mut cache = self.server_configs.write().await;
        // Only an insert can grow the map. The staple-refresh path replaces an
        // existing key, so evicting there would drop other domains' configs on
        // every refresh once the working set reaches the cap.
        if !cache.contains_key(&domain_arc) {
            evict_oldest(&mut cache, max_entries, |entry| entry.stapled_at);
        }
        cache.insert(
            domain_arc,
            CachedServerConfig {
                config: config.clone(),
                stapled_at: Instant::now(),
            },
        );
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
                return Ok(cert.pair.clone());
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
        let max_entries = cert_cache_max_entries();
        let mut cache = self.certs.write().await;
        if !cache.contains_key(&domain_arc) {
            evict_oldest(&mut cache, max_entries, |entry| entry.created);
        }
        cache.insert(
            domain_arc,
            CachedCert {
                pair: cert_pair.clone(),
                created: Instant::now(),
            },
        );
        Ok(cert_pair)
    }

    /// PEM of the configured MITM/agent CA certificate.
    pub fn ca_cert_pem(&self) -> String {
        String::from_utf8_lossy(&self.ca_cert_pem).into_owned()
    }

    /// PKCS#8 DER of the CA private key (for OCSP response signing).
    pub fn ca_key_pkcs8_der(&self) -> Vec<u8> {
        self.ca_key.serialize_der()
    }

    /// Issue a server leaf for `name` signed by the proxy CA (sync).
    /// Used for control-plane mTLS when `CONTROL_MTLS_CERT_FILE` is unset.
    pub fn server_identity_pem(&self, name: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
        let key_pair = KeyPair::generate().map_err(|e| format!("server key: {e}"))?;
        let mut params =
            CertificateParams::new(vec![name.to_string()]).map_err(|e| format!("params: {e}"))?;
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, name);
        params
            .distinguished_name
            .push(DnType::OrganizationName, "BSDM Control");
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let issuer = self.issuer().map_err(|e| format!("issuer: {e}"))?;
        let cert = params
            .signed_by(&key_pair, &issuer)
            .map_err(|e| format!("sign server leaf: {e}"))?;
        Ok((
            cert.pem().into_bytes(),
            key_pair.serialize_pem().into_bytes(),
        ))
    }

    /// Sign an agent client certificate from a PEM CSR (Agent Contract mTLS enroll).
    ///
    /// Subject/SAN are **bound by the control plane** to `device_id` /
    /// `user_identity` / `platform` — CSR subject is not trusted as identity.
    pub fn sign_agent_client_csr(
        &self,
        csr_pem: &str,
        device_id: &str,
        user_identity: Option<&str>,
        platform: &str,
        validity_days: u32,
    ) -> Result<AgentClientCert, String> {
        if device_id.trim().is_empty() {
            return Err("device_id required for client cert".into());
        }
        let csr = CertificateSigningRequestParams::from_pem(csr_pem.trim())
            .map_err(|e| format!("invalid CSR: {e}"))?;

        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, device_id);
        params
            .distinguished_name
            .push(DnType::OrganizationName, "BSDM Agent");
        params
            .distinguished_name
            .push(DnType::OrganizationalUnitName, platform);
        if let Some(upn) = user_identity.filter(|u| !u.trim().is_empty()) {
            // Prefer RFC822 SAN when identity looks like an email; otherwise CN-only.
            if upn.contains('@') {
                let email = upn
                    .try_into()
                    .map_err(|e| format!("user_identity email SAN: {e}"))?;
                params.subject_alt_names.push(SanType::Rfc822Name(email));
            }
        }
        // URI SAN: stable device identity reference (not a network endpoint).
        let device_uri = format!("urn:bsdm:device:{device_id}");
        let uri = device_uri
            .as_str()
            .try_into()
            .map_err(|e| format!("device URI SAN: {e}"))?;
        params.subject_alt_names.push(SanType::URI(uri));
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.is_ca = IsCa::NoCa;

        // Stable serial for CRL (big-endian hex of random u64).
        let serial_u64 = rand::random::<u64>() | 1;
        params.serial_number = Some(SerialNumber::from(serial_u64));
        let serial_hex = format!("{serial_u64:016x}");

        // Validity window via rcgen helpers (avoid depending on `time` crate directly).
        let days = validity_days.clamp(1, 825);
        let now = chrono::Utc::now();
        let start = now - chrono::Duration::minutes(5);
        let end = now + chrono::Duration::days(i64::from(days));
        params.not_before =
            rcgen::date_time_ymd(start.year(), start.month() as u8, start.day().max(1) as u8);
        params.not_after =
            rcgen::date_time_ymd(end.year(), end.month() as u8, end.day().max(1) as u8);

        let csr_params = CertificateSigningRequestParams {
            params,
            public_key: csr.public_key,
        };
        let issuer = self.issuer().map_err(|e| format!("CA issuer: {e}"))?;
        let cert = csr_params
            .signed_by(&issuer)
            .map_err(|e| format!("sign client cert: {e}"))?;
        let cert_pem = cert.pem();
        let fingerprint_sha256 = hex::encode(Sha256::digest(cert.der()));
        let subject = format!("CN={device_id}, OU={platform}, O=BSDM Agent");
        Ok(AgentClientCert {
            client_cert_pem: cert_pem,
            ca_cert_pem: self.ca_cert_pem(),
            subject,
            fingerprint_sha256,
            serial_hex,
            not_after_unix: end.timestamp().max(0) as u64,
            validity_days: days,
        })
    }

    /// Build a CA-signed X.509 CRL PEM for revoked agent serials.
    ///
    /// Requires issuer key usage to allow CRL signing (in-memory CA includes
    /// `CrlSign`; file CAs without it return an error — use JSON CRL instead).
    pub fn sign_agent_crl_pem(
        &self,
        revoked: &[(String, u64)],
        crl_number: u64,
    ) -> Result<String, String> {
        // (serial_hex, revoked_at_unix)
        let now = chrono::Utc::now();
        let this_update = date_time_ymd(now.year(), now.month() as u8, now.day().max(1) as u8);
        let next = now + chrono::Duration::days(7);
        let next_update = date_time_ymd(next.year(), next.month() as u8, next.day().max(1) as u8);

        let mut revoked_certs = Vec::with_capacity(revoked.len());
        for (serial_hex, revoked_at) in revoked {
            let serial_bytes = hex::decode(serial_hex.trim())
                .map_err(|e| format!("invalid serial hex {serial_hex}: {e}"))?;
            if serial_bytes.is_empty() {
                continue;
            }
            let revoked_dt = chrono::DateTime::from_timestamp(*revoked_at as i64, 0).unwrap_or(now);
            let revocation_time = date_time_ymd(
                revoked_dt.year(),
                revoked_dt.month() as u8,
                revoked_dt.day().max(1) as u8,
            );
            revoked_certs.push(RevokedCertParams {
                serial_number: SerialNumber::from(serial_bytes),
                revocation_time,
                reason_code: Some(RevocationReason::CessationOfOperation),
                invalidity_date: None,
            });
        }

        let params = CertificateRevocationListParams {
            this_update,
            next_update,
            crl_number: SerialNumber::from(crl_number.max(1)),
            issuing_distribution_point: None,
            revoked_certs,
            key_identifier_method: KeyIdMethod::Sha256,
        };
        let issuer = self.issuer().map_err(|e| format!("CA issuer: {e}"))?;
        let crl = params
            .signed_by(&issuer)
            .map_err(|e| format!("sign CRL: {e}"))?;
        crl.pem().map_err(|e| format!("CRL PEM: {e}"))
    }
}

/// Client certificate bundle returned from agent mTLS enroll.
#[derive(Debug, Clone)]
pub struct AgentClientCert {
    pub client_cert_pem: String,
    pub ca_cert_pem: String,
    pub subject: String,
    pub fingerprint_sha256: String,
    /// Certificate serial as lowercase hex (for X.509 CRL entries).
    pub serial_hex: String,
    pub not_after_unix: u64,
    pub validity_days: u32,
}

/// Whether data-plane MITM TLS should staple OCSP responses.
/// Default **on**. Disable: `TLS_OCSP_STAPLING=0` / `false`.
pub fn ocsp_stapling_enabled() -> bool {
    match std::env::var("TLS_OCSP_STAPLING") {
        Ok(v) => {
            let t = v.trim();
            !(t == "0"
                || t.eq_ignore_ascii_case("false")
                || t.eq_ignore_ascii_case("no")
                || t.eq_ignore_ascii_case("off"))
        }
        Err(_) => true,
    }
}

/// How long a cached `ServerConfig` (and its staple) is reused.
/// Default 900s. Env: `TLS_OCSP_STAPLE_REFRESH_SECS`.
pub fn ocsp_staple_refresh_secs() -> u64 {
    std::env::var("TLS_OCSP_STAPLE_REFRESH_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(900)
        .clamp(60, 24 * 3600)
}

fn build_server_config(
    cert_pem: &[u8],
    key_pem: &[u8],
    ca_cert_pem: &[u8],
    ocsp_der: Option<&[u8]>,
) -> Result<ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
    let mut chain = parse_certs(cert_pem)?;
    chain.extend(parse_certs(ca_cert_pem)?);

    let key = parse_private_key(key_pem)?;

    let builder = ServerConfig::builder().with_no_client_auth();
    match ocsp_der {
        Some(ocsp) if !ocsp.is_empty() => builder
            .with_single_cert_with_ocsp(chain, key, ocsp.to_vec())
            .map_err(|e| e.into()),
        _ => builder.with_single_cert(chain, key).map_err(|e| e.into()),
    }
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
    rustls_pemfile::private_key(&mut reader)?.ok_or_else(|| "no private key found in PEM".into())
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
    fn evict_oldest_frees_capacity_and_drops_oldest_first() {
        let mut cache: HashMap<Arc<str>, Instant> = HashMap::new();
        let base = Instant::now();
        let max = MIN_CERT_CACHE_MAX_ENTRIES;
        for n in 0..max {
            let key: Arc<str> = format!("host{n:04}.example.com").into();
            cache.insert(key, base + std::time::Duration::from_millis(n as u64));
        }

        evict_oldest(&mut cache, max, |stamp| *stamp);

        assert!(cache.len() < max, "eviction must free capacity");
        assert!(
            !cache.contains_key("host0000.example.com"),
            "oldest entry must be evicted first"
        );
        let newest: Arc<str> = format!("host{:04}.example.com", max - 1).into();
        assert!(cache.contains_key(&newest), "newest entry must be kept");
    }

    #[tokio::test]
    async fn cert_cache_stays_bounded_across_unique_sni() {
        let key_pair = KeyPair::generate().unwrap();
        let cache = CertCache::from_pem(key_pair.serialize_pem().as_bytes(), b"").unwrap();

        // Far more unique hostnames than the floor cap, as a client looping
        // CONNECT on random SNI would produce.
        std::env::set_var(
            "MITM_CERT_CACHE_MAX_ENTRIES",
            MIN_CERT_CACHE_MAX_ENTRIES.to_string(),
        );
        for n in 0..(MIN_CERT_CACHE_MAX_ENTRIES + 32) {
            cache
                .get_or_generate(&format!("host{n}.attacker.tld"))
                .await
                .unwrap();
        }
        std::env::remove_var("MITM_CERT_CACHE_MAX_ENTRIES");

        let entries = cache.certs.read().await.len();
        assert!(
            entries <= MIN_CERT_CACHE_MAX_ENTRIES,
            "certificate cache grew past the cap: {entries}"
        );
    }

    #[tokio::test]
    async fn load_for_startup_without_ca_when_mitm_disabled() {
        let dir = std::env::temp_dir().join(format!("bsdm-proxy-ca-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        let result = CertCache::load_for_startup(false).await;
        std::env::set_current_dir(prev).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(result.is_ok());
    }

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

    #[test]
    fn mitm_server_config_ocsp_staple() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let ca_key = KeyPair::generate().unwrap();
        let cache = CertCache::from_pem(ca_key.serialize_pem().as_bytes(), b"").unwrap();
        let (cert_pem, _key_pem) = cache.server_identity_pem("staple.example.com").unwrap();
        let staple = agent_ocsp::staple_good_for_leaf_pem(&cache, &cert_pem).unwrap();
        assert!(!staple.is_empty());
        use der::Decode;
        let resp = x509_ocsp::OcspResponse::from_der(&staple).unwrap();
        assert_eq!(
            resp.response_status,
            x509_ocsp::OcspResponseStatus::Successful
        );
        // Building ServerConfig with staple must succeed.
        let cfg = build_server_config(
            &cert_pem,
            &_key_pem,
            cache.ca_cert_pem().as_bytes(),
            Some(&staple),
        )
        .unwrap();
        assert!(!cfg.ignore_client_order);
    }

    #[test]
    fn signs_agent_client_cert_from_csr() {
        let ca_key = KeyPair::generate().unwrap();
        let cache = CertCache::from_pem(ca_key.serialize_pem().as_bytes(), b"").unwrap();

        let agent_key = KeyPair::generate().unwrap();
        let mut csr_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        csr_params.distinguished_name = DistinguishedName::new();
        csr_params
            .distinguished_name
            .push(DnType::CommonName, "csr-placeholder");
        let csr = csr_params.serialize_request(&agent_key).unwrap();
        let csr_pem = csr.pem().unwrap();

        let signed = cache
            .sign_agent_client_csr(
                &csr_pem,
                "laptop-mtls-001",
                Some("alice@corp.example"),
                "macos",
                90,
            )
            .unwrap();
        assert!(signed.client_cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(signed.ca_cert_pem.contains("BEGIN CERTIFICATE"));
        assert_eq!(signed.fingerprint_sha256.len(), 64);
        assert_eq!(signed.serial_hex.len(), 16);
        assert!(signed.subject.contains("laptop-mtls-001"));
        assert!(signed.not_after_unix > 0);

        // X.509 CRL with this serial
        let pem = cache
            .sign_agent_crl_pem(&[(signed.serial_hex.clone(), 1_700_000_000)], 2)
            .unwrap();
        assert!(pem.contains("X509 CRL") || pem.contains("BEGIN X509 CRL"));
    }
}
