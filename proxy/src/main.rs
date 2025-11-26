use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose};
use pingora::http::ResponseHeader;
use pingora::prelude::*;
use pingora_cache::{CacheKey, CachePhase};
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result as PingoraResult;
use pingora_proxy::http_proxy_service;
use pingora_proxy::{ProxyHttp, Session};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

type CertPair = (Vec<u8>, Vec<u8>);
type CertMap = Arc<RwLock<HashMap<String, CertPair>>>;

#[allow(dead_code)]
#[derive(Clone)]
struct CertCache {
    certs: CertMap,
    ca_cert: Arc<Certificate>,
    ca_key: Arc<KeyPair>,
}

#[allow(dead_code)]
impl CertCache {
    fn new(_ca_cert_pem: Vec<u8>, ca_key_pem: Vec<u8>) -> Self {
        let ca_key = Arc::new(
            KeyPair::from_pem(&String::from_utf8_lossy(&ca_key_pem)).expect("CA key parse failed"),
        );

        let mut ca_params = CertificateParams::new(vec!["BSDM Proxy CA".to_string()])
            .expect("Failed to create CA params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        ca_params.distinguished_name = DistinguishedName::new();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "BSDM Proxy CA");

        let ca_cert = Arc::new(
            ca_params
                .self_signed(&ca_key)
                .expect("CA cert instance failed"),
        );

        Self {
            certs: Arc::new(RwLock::new(HashMap::new())),
            ca_cert,
            ca_key,
        }
    }

    async fn get_or_generate(&self, domain: &str) -> PingoraResult<CertPair> {
        {
            let cache = self.certs.read().await;
            if let Some(cert) = cache.get(domain) {
                return Ok(cert.clone());
            }
        }
        let (cert_pem, key_pem) = self.generate_ca_signed_cert(domain)?;
        let mut cache = self.certs.write().await;
        cache.insert(domain.to_string(), (cert_pem.clone(), key_pem.clone()));
        Ok((cert_pem, key_pem))
    }

    fn generate_ca_signed_cert(&self, domain: &str) -> PingoraResult<CertPair> {
        let key_pair = KeyPair::generate()
            .map_err(|e| Error::because(ErrorType::InternalError, "Key generation failed", e))?;

        let mut params =
            CertificateParams::new(vec![domain.to_string()]).expect("Failed to create cert params");
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, domain);
        params
            .distinguished_name
            .push(DnType::OrganizationName, "BSDM Proxy");

        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| Error::because(ErrorType::InternalError, "Cert generation failed", e))?;

        let cert_pem = cert.pem();

        let key_pem = key_pair.serialize_pem();

        Ok((cert_pem.into_bytes(), key_pem.into_bytes()))
    }
}

#[derive(Serialize)]
struct CacheEvent {
    url: String,
    method: String,
    status: u16,
    cache_key: String,
    timestamp: u64,
    headers: HashMap<String, String>,
    body: String,
    // New fields for user analytics
    user_id: Option<String>,
    username: Option<String>,
    client_ip: String,
    domain: String,
    response_size: u64,
    request_duration_ms: u64,
    content_type: Option<String>,
    user_agent: Option<String>,
}

struct ProxyContext {
    request_start: Instant,
    client_ip: String,
}

struct ProxyService {
    #[allow(dead_code)]
    cert_cache: CertCache,
    kafka_producer: Option<FutureProducer>,
}

impl ProxyService {
    fn new(cert_cache: CertCache, kafka_brokers: Option<String>) -> Self {
        let kafka_producer = kafka_brokers.and_then(|brokers| {
            ClientConfig::new()
                .set("bootstrap.servers", &brokers)
                .set("message.timeout.ms", "5000")
                .create()
                .ok()
        });
        Self {
            cert_cache,
            kafka_producer,
        }
    }

    async fn send_to_kafka(&self, event: CacheEvent) {
        if let Some(producer) = &self.kafka_producer {
            let payload = match serde_json::to_string(&event) {
                Ok(p) => p,
                Err(e) => {
                    error!("Failed to serialize cache event: {}", e);
                    return;
                }
            };
            let record = FutureRecord::to("cache-events")
                .payload(&payload)
                .key(&event.cache_key);
            if let Err((e, _)) = producer.send(record, Duration::from_secs(0)).await {
                warn!("Failed to send to Kafka: {}", e);
            }
        }
    }

    fn extract_domain(url_str: &str) -> String {
        url::Url::parse(url_str)
            .ok()
            .and_then(|u| u.host().map(|h| h.to_string()))
            .unwrap_or_else(|| "unknown".to_string())
    }

    fn extract_user_info(session: &Session) -> (Option<String>, Option<String>) {
        let req_header = session.req_header();
        
        // Try to extract from Authorization header (Basic Auth)
        if let Some(auth_header) = req_header.headers.get("authorization") {
            if let Ok(auth_str) = auth_header.to_str() {
                if let Some(encoded) = auth_str.strip_prefix("Basic ") {
                    // Use base64 0.22 API with engine
                    if let Ok(decoded_bytes) = general_purpose::STANDARD.decode(encoded) {
                        if let Ok(credentials) = String::from_utf8(decoded_bytes) {
                            if let Some((username, _)) = credentials.split_once(':') {
                                return (
                                    Some(username.to_string()),
                                    Some(username.to_string()),
                                );
                            }
                        }
                    }
                }
            }
        }
        
        (None, None)
    }
}

#[async_trait]
impl ProxyHttp for ProxyService {
    type CTX = ProxyContext;
    
    fn new_ctx(&self) -> Self::CTX {
        ProxyContext {
            request_start: Instant::now(),
            client_ip: "unknown".to_string(),
        }
    }
    
    async fn early_request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<()> {
        // Extract client IP from Pingora's SocketAddr enum
        ctx.client_ip = session.client_addr()
            .and_then(|addr| addr.as_inet())  // Get std::net::SocketAddr from enum
            .map(|std_addr| std_addr.ip().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        Ok(())
    }
    
    async fn upstream_peer(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> PingoraResult<Box<HttpPeer>> {
        let req_header = session.req_header();
        let host = req_header
            .uri
            .host()
            .or_else(|| req_header.headers.get("host")?.to_str().ok())
            .ok_or_else(|| Error::new(ErrorType::InvalidHTTPHeader))?;
        let port = req_header.uri.port_u16().unwrap_or(443);
        let peer = Box::new(HttpPeer::new((host, port), true, host.to_string()));
        Ok(peer)
    }
    
    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> PingoraResult<()> {
        upstream_request
            .insert_header("X-Forwarded-Proto", "https")
            .unwrap();
        Ok(())
    }
    
    async fn response_filter(
        &self,
        session: &mut Session,
        _upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<()> {
        let cache_phase = session.cache.phase();
        if matches!(cache_phase, CachePhase::Hit | CachePhase::Stale) {
            let req_header = session.req_header();
            let url = req_header.uri.to_string();
            let method = req_header.method.to_string();
            let domain = Self::extract_domain(&url);
            let (user_id, username) = Self::extract_user_info(session);
            
            if let Some(resp_header) = session.response_written() {
                let status = resp_header.status.as_u16();
                let mut hasher = Sha256::new();
                hasher.update(url.as_bytes());
                let cache_key = hex::encode(hasher.finalize());
                
                let mut headers = HashMap::new();
                for (name, value) in resp_header.headers.iter() {
                    if let Ok(v) = value.to_str() {
                        headers.insert(name.to_string(), v.to_string());
                    }
                }
                
                let content_type = resp_header
                    .headers
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                
                let user_agent = req_header
                    .headers
                    .get("user-agent")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                
                let response_size = resp_header
                    .headers
                    .get("content-length")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
                
                let request_duration_ms = ctx.request_start.elapsed().as_millis() as u64;
                
                let event = CacheEvent {
                    url,
                    method,
                    status,
                    cache_key,
                    timestamp: SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    headers,
                    body: String::new(),
                    user_id,
                    username,
                    client_ip: ctx.client_ip.clone(),
                    domain,
                    response_size,
                    request_duration_ms,
                    content_type,
                    user_agent,
                };
                
                self.send_to_kafka(event).await;
            }
        }
        Ok(())
    }
    
    fn should_serve_stale(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
        _error: Option<&Error>,
    ) -> bool {
        true
    }
    
    fn cache_key_callback(
        &self,
        session: &Session,
        _ctx: &mut Self::CTX,
    ) -> Result<CacheKey, Box<Error>> {
        let req_header = session.req_header();
        let uri = req_header.uri.to_string();
        let method = req_header.method.as_str();
        let cache_key = format!("{}-{}", method, uri);
        let mut hasher = Sha256::new();
        hasher.update(cache_key.as_bytes());
        let hash = hex::encode(hasher.finalize());
        Ok(CacheKey::new("", hash, ""))
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let ca_cert = std::fs::read("/certs/ca.crt").expect("Failed to read CA certificate");
    let ca_key = std::fs::read("/certs/ca.key").expect("Failed to read CA private key");
    let cert_cache = CertCache::new(ca_cert, ca_key);
    let kafka_brokers = std::env::var("KAFKA_BROKERS").ok();

    let mut server = Server::new(Some(Opt::default())).unwrap();
    server.bootstrap();

    let mut proxy_service = http_proxy_service(
        &server.configuration,
        ProxyService::new(cert_cache.clone(), kafka_brokers),
    );

    proxy_service
        .add_tls("0.0.0.0:1488", "/certs/server.crt", "/certs/server.key")
        .expect("Failed to add TLS listener");

    server.add_service(proxy_service);
    info!("BSDM-Proxy starting on port 1488");
    server.run_forever();
}
