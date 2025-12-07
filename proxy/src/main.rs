use base64::engine::general_purpose;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use quick_cache::sync::Cache;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

type CertPair = (Vec<u8>, Vec<u8>);
type CertMap = Arc<RwLock<HashMap<String, CertPair>>>;
type Body = http_body_util::Full<bytes::Bytes>;

/// Кешированный HTTP ответ
#[derive(Clone, Debug, Serialize, Deserialize)]
struct CachedResponse {
    status: u16,
    headers: HashMap<String, String>,
    body: bytes::Bytes,
    cached_at: SystemTime,
    ttl: Duration,
}

impl CachedResponse {
    fn is_expired(&self) -> bool {
        SystemTime::now()
            .duration_since(self.cached_at)
            .map(|age| age > self.ttl)
            .unwrap_or(true)
    }

    fn to_response(&self) -> Response<Body> {
        let mut response = Response::new(Body::new(self.body.clone()));
        *response.status_mut() = StatusCode::from_u16(self.status).unwrap_or(StatusCode::OK);

        for (key, value) in &self.headers {
            if let Ok(header_name) = hyper::header::HeaderName::from_bytes(key.as_bytes()) {
                if let Ok(header_value) = hyper::header::HeaderValue::from_str(value) {
                    response.headers_mut().insert(header_name, header_value);
                }
            }
        }

        response.headers_mut().insert(
            "x-cache-status",
            hyper::header::HeaderValue::from_static("HIT"),
        );

        response
    }
}

/// Менеджер сертификатов
#[derive(Clone)]
struct CertCache {
    certs: CertMap,
    ca_cert: Arc<Certificate>,
    ca_key: Arc<KeyPair>,
}

impl CertCache {
    fn new(ca_key_pem: Vec<u8>) -> Self {
        let ca_key = Arc::new(
            KeyPair::from_pem(&String::from_utf8_lossy(&ca_key_pem))
                .expect("CA key parse failed"),
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

    async fn get_or_generate(&self, domain: &str) -> Result<CertPair, Box<dyn std::error::Error>> {
        {
            let cache = self.certs.read().await;
            if let Some(cert) = cache.get(domain) {
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

        let cert = params.self_signed(&key_pair)?;
        let cert_pem = cert.pem().into_bytes();
        let key_pem = key_pair.serialize_pem().into_bytes();

        let mut cache = self.certs.write().await;
        cache.insert(domain.to_string(), (cert_pem.clone(), key_pem.clone()));
        Ok((cert_pem, key_pem))
    }
}

/// Событие для Kafka
#[derive(Serialize, Clone, Debug)]
struct CacheEvent {
    url: String,
    method: String,
    status: u16,
    cache_key: String,
    cache_status: String,
    timestamp: u64,
    headers: HashMap<String, String>,
    user_id: Option<String>,
    username: Option<String>,
    client_ip: String,
    domain: String,
    response_size: u64,
    request_duration_ms: u64,
    content_type: Option<String>,
    user_agent: Option<String>,
}

/// Конфигурация кеша
#[derive(Clone)]
struct CacheConfig {
    capacity: usize,
    default_ttl: Duration,
    cacheable_methods: Vec<String>,
    cacheable_status_codes: Vec<u16>,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            capacity: 10_000,
            default_ttl: Duration::from_secs(3600),
            cacheable_methods: vec!["GET".to_string(), "HEAD".to_string()],
            cacheable_status_codes: vec![200, 203, 204, 206, 300, 301, 404, 405, 410, 414, 501],
        }
    }
}

/// Главный прокси сервис
#[derive(Clone)]
struct ProxyService {
    cert_cache: CertCache,
    http_cache: Arc<Cache<String, CachedResponse>>,
    cache_config: CacheConfig,
    kafka_producer: Option<Arc<FutureProducer>>,
}

impl ProxyService {
    fn new(
        cert_cache: CertCache,
        cache_config: CacheConfig,
        kafka_brokers: Option<String>,
    ) -> Self {
        let kafka_producer = kafka_brokers.and_then(|brokers| {
            ClientConfig::new()
                .set("bootstrap.servers", &brokers)
                .set("message.timeout.ms", "5000")
                .set("compression.type", "snappy")
                .set("batch.size", "16384")
                .set("linger.ms", "10")
                .create()
                .ok()
                .map(Arc::new)
        });

        let http_cache = Arc::new(Cache::new(cache_config.capacity));

        Self {
            cert_cache,
            http_cache,
            cache_config,
            kafka_producer,
        }
    }

    fn generate_cache_key(&self, method: &str, url: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(format!("{}:{}", method, url));
        hex::encode(hasher.finalize())
    }

    fn is_cacheable(&self, method: &str, status: u16) -> bool {
        self.cache_config
            .cacheable_methods
            .contains(&method.to_string())
            && self.cache_config.cacheable_status_codes.contains(&status)
    }

    fn extract_domain(url_str: &str) -> String {
        url::Url::parse(url_str)
            .ok()
            .and_then(|u| u.host().map(|h| h.to_string()))
            .unwrap_or_else(|| "unknown".to_string())
    }

    fn extract_user_info(req: &Request<Incoming>) -> (Option<String>, Option<String>) {
        if let Some(auth_header) = req.headers().get("authorization") {
            if let Ok(auth_str) = auth_header.to_str() {
                if let Some(encoded) = auth_str.strip_prefix("Basic ") {
                    if let Ok(decoded_bytes) = general_purpose::STANDARD.decode(encoded) {
                        if let Ok(credentials) = String::from_utf8(decoded_bytes) {
                            if let Some((username, _)) = credentials.split_once(':') {
                                return (Some(username.to_string()), Some(username.to_string()));
                            }
                        }
                    }
                }
            }
        }
        (None, None)
    }

    async fn send_to_kafka(&self, event: CacheEvent) {
        if let Some(producer) = &self.kafka_producer {
            match serde_json::to_string(&event) {
                Ok(payload) => {
                    let record = FutureRecord::to("cache-events")
                        .payload(&payload)
                        .key(&event.cache_key);
                    if let Err((e, _)) = producer.send(record, Duration::from_secs(0)).await {
                        warn!("Failed to send to Kafka: {}", e);
                    }
                }
                Err(e) => error!("Failed to serialize cache event: {}", e),
            }
        }
    }

    async fn handle_connect(
        &self,
        authority: String,
        mut client_stream: TcpStream,
        client_ip: String,
        request_start: Instant,
    ) -> Result<(), Box<dyn std::error::Error>> {
        info!("CONNECT tunnel to: {}", authority);
        let mut upstream = TcpStream::connect(&authority).await?;
        let response = b"HTTP/1.1 200 Connection Established\r\n\r\n";
        client_stream.write_all(response).await?;

        let (mut client_read, mut client_write) = client_stream.split();
        let (mut upstream_read, mut upstream_write) = upstream.split();

        let client_to_upstream = async { tokio::io::copy(&mut client_read, &mut upstream_write).await };
        let upstream_to_client = async { tokio::io::copy(&mut upstream_read, &mut client_write).await };
        let (bytes_c2u, bytes_u2c) = tokio::try_join!(client_to_upstream, upstream_to_client)?;

        let duration_ms = request_start.elapsed().as_millis() as u64;
        let event = CacheEvent {
            url: format!("https://{}", authority),
            method: "CONNECT".to_string(),
            status: 200,
            cache_key: self.generate_cache_key("CONNECT", &authority),
            cache_status: "BYPASS".to_string(),
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_secs(),
            headers: HashMap::new(),
            user_id: None,
            username: None,
            client_ip,
            domain: authority.split(':').next().unwrap_or("unknown").to_string(),
            response_size: bytes_u2c,
            request_duration_ms: duration_ms,
            content_type: None,
            user_agent: None,
        };
        self.send_to_kafka(event).await;
        debug!("CONNECT tunnel closed: {} bytes C→U, {} bytes U→C", bytes_c2u, bytes_u2c);
        Ok(())
    }

    async fn handle_request(
        &self,
        req: Request<Incoming>,
        client_ip: String,
    ) -> Result<Response<Body>, Box<dyn std::error::Error + Send + Sync>> {
        let request_start = Instant::now();
        let method = req.method().to_string();
        let uri = req.uri().clone();
        let url = uri.to_string();
        let (user_id, username) = Self::extract_user_info(&req);
        let cache_key = self.generate_cache_key(&method, &url);

        if let Some(cached) = self.http_cache.get(&cache_key) {
            if !cached.is_expired() {
                info!("Cache HIT: {} {}", method, url);
                let event = CacheEvent {
                    url: url.clone(),
                    method: method.clone(),
                    status: cached.status,
                    cache_key: cache_key.clone(),
                    cache_status: "HIT".to_string(),
                    timestamp: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs(),
                    headers: cached.headers.clone(),
                    user_id: user_id.clone(),
                    username: username.clone(),
                    client_ip: client_ip.clone(),
                    domain: Self::extract_domain(&url),
                    response_size: cached.body.len() as u64,
                    request_duration_ms: request_start.elapsed().as_millis() as u64,
                    content_type: cached.headers.get("content-type").cloned(),
                    user_agent: None,
                };
                self.send_to_kafka(event).await;
                return Ok(cached.to_response());
            } else {
                debug!("Cache STALE: {} {}", method, url);
            }
        }

        info!("Cache MISS: {} {}", method, url);
        let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build_http();

        match client.request(req).await {
            Ok(response) => {
                let status = response.status();
                let headers: HashMap<String, String> = response
                    .headers()
                    .iter()
                    .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.to_string(), v.to_string())))
                    .collect();

                let body_bytes = hyper::body::to_bytes(response.into_body()).await?;
                let cache_status = if self.is_cacheable(&method, status.as_u16()) {
                    let cached_response = CachedResponse {
                        status: status.as_u16(),
                        headers: headers.clone(),
                        body: body_bytes.clone(),
                        cached_at: SystemTime::now(),
                        ttl: self.cache_config.default_ttl,
                    };
                    self.http_cache.insert(cache_key.clone(), cached_response);
                    "MISS".to_string()
                } else {
                    "BYPASS".to_string()
                };

                let event = CacheEvent {
                    url: url.clone(),
                    method: method.clone(),
                    status: status.as_u16(),
                    cache_key,
                    cache_status,
                    timestamp: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs(),
                    headers: headers.clone(),
                    user_id,
                    username,
                    client_ip,
                    domain: Self::extract_domain(&url),
                    response_size: body_bytes.len() as u64,
                    request_duration_ms: request_start.elapsed().as_millis() as u64,
                    content_type: headers.get("content-type").cloned(),
                    user_agent: None,
                };
                self.send_to_kafka(event).await;

                let mut resp = Response::new(Body::new(body_bytes));
                *resp.status_mut() = status;
                for (key, value) in headers {
                    if let Ok(header_name) = hyper::header::HeaderName::from_bytes(key.as_bytes()) {
                        if let Ok(header_value) = hyper::header::HeaderValue::from_str(&value) {
                            resp.headers_mut().insert(header_name, header_value);
                        }
                    }
                }
                Ok(resp)
            }
            Err(e) => {
                error!("Upstream error: {}", e);
                let mut response = Response::new(Body::new(bytes::Bytes::from("502 Bad Gateway")));
                *response.status_mut() = StatusCode::BAD_GATEWAY;
                Ok(response)
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,bsdm_proxy=debug".into()),
        )
        .init();

    let ca_key = tokio::fs::read("/certs/ca.key").await?;
    let cert_cache = CertCache::new(ca_key);
    let kafka_brokers = std::env::var("KAFKA_BROKERS").ok();
    let cache_capacity = std::env::var("CACHE_CAPACITY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10_000);
    let cache_ttl = std::env::var("CACHE_TTL_SECONDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(3600));

    let cache_config = CacheConfig {
        capacity: cache_capacity,
        default_ttl: cache_ttl,
        ..Default::default()
    };

    let service = Arc::new(ProxyService::new(cert_cache, cache_config, kafka_brokers));
    let http_port = std::env::var("HTTP_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1488);

    let listener = TcpListener::bind(format!("0.0.0.0:{}", http_port)).await?;
    info!("🚀 BSDM-Proxy listening on 0.0.0.0:{}", http_port);
    info!("📦 Cache: {} entries, TTL: {:?}", service.http_cache.capacity(), cache_config.default_ttl);

    loop {
        let (stream, addr) = listener.accept().await?;
        let service_clone = service.clone();
        let client_ip = addr.ip().to_string();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, addr, service_clone, client_ip).await {
                error!("Connection error from {}: {}", addr, e);
            }
        });
    }
}

async fn handle_connection(
    stream: TcpStream,
    addr: SocketAddr,
    service: Arc<ProxyService>,
    client_ip: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let io = TokioIo::new(stream);
    let svc = service_fn(move |req: Request<Incoming>| {
        let service = service.clone();
        let client_ip = client_ip.clone();
        let request_start = Instant::now();
        async move {
            if req.method() == Method::CONNECT {
                let authority = req.uri().authority().ok_or("Missing authority")?.as_str().to_string();
                tokio::spawn({
                    let service = service.clone();
                    async move {
                        match hyper::upgrade::on(req).await {
                            Ok(upgraded) => {
                                let stream = TokioIo::into_inner(upgraded);
                                let _ = service.handle_connect(authority, stream, client_ip, request_start).await;
                            }
                            Err(e) => error!("Upgrade failed: {}", e),
                        }
                    }
                });
                let response = Response::builder().status(StatusCode::OK).body(Body::new(bytes::Bytes::new()))?;
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(response);
            }
            service.handle_request(req, client_ip).await
        }
    });

    if let Err(e) = http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(io, svc)
        .with_upgrades()
        .await
    {
        error!("Connection error from {}: {}", addr, e);
    }
    Ok(())
}
