use base64::engine::general_purpose;
use bytes::Bytes;
use hyper::body::Incoming;
use hyper::header::{HeaderName, HeaderValue, AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
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
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::io::{copy_bidirectional, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

type CertPair = (Bytes, Bytes);
type CertMap = Arc<RwLock<HashMap<Arc<str>, CertPair>>>;
type Body = http_body_util::Full<Bytes>;

const CACHEABLE_METHODS: &[&str] = &["GET", "HEAD"];
const CACHEABLE_STATUS_CODES: &[u16] = &[200, 203, 204, 206, 300, 301, 404, 405, 410, 414, 501];
const CONNECT_RESPONSE: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";

/// Кешированный HTTP ответ (оптимизирован для быстрого клонирования)
#[derive(Clone, Debug)]
struct CachedResponse {
    status: u16,
    headers: Arc<[(Arc<str>, Arc<str>)]>,  // Arc для zero-copy clone
    body: Bytes,  // Bytes уже использует Arc внутри
    cached_at: SystemTime,
    ttl: Duration,
}

impl CachedResponse {
    #[inline]
    fn is_expired(&self) -> bool {
        SystemTime::now()
            .duration_since(self.cached_at)
            .map_or(true, |age| age > self.ttl)
    }

    fn to_response(&self) -> Response<Body> {
        let mut response = Response::new(Body::new(self.body.clone()));
        *response.status_mut() = StatusCode::from_u16(self.status).unwrap_or(StatusCode::OK);

        let headers_mut = response.headers_mut();
        for (key, value) in self.headers.iter() {
            if let (Ok(name), Ok(val)) = (
                HeaderName::from_bytes(key.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                headers_mut.insert(name, val);
            }
        }

        headers_mut.insert("x-cache-status", HeaderValue::from_static("HIT"));
        response
    }
}

/// Менеджер сертификатов (оптимизирован с Arc<str> ключами)
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
        let domain_arc: Arc<str> = domain.into();
        
        // Оптимизация: быстрая проверка с read lock
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

        let cert = params.self_signed(&key_pair)?;
        let cert_pem = Bytes::from(cert.pem().into_bytes());
        let key_pem = Bytes::from(key_pair.serialize_pem().into_bytes());

        let cert_pair = (cert_pem, key_pem);
        let mut cache = self.certs.write().await;
        cache.insert(domain_arc, cert_pair.clone());
        Ok(cert_pair)
    }
}

/// Событие для Kafka (оптимизировано для сериализации)
#[derive(Serialize, Clone, Debug)]
struct CacheEvent {
    url: Arc<str>,
    method: Arc<str>,
    status: u16,
    cache_key: Arc<str>,
    cache_status: &'static str,
    timestamp: u64,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    headers: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_id: Option<Arc<str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<Arc<str>>,
    client_ip: Arc<str>,
    domain: Arc<str>,
    response_size: u64,
    request_duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_type: Option<Arc<str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_agent: Option<Arc<str>>,
}

/// Конфигурация кеша
#[derive(Clone)]
struct CacheConfig {
    capacity: usize,
    default_ttl: Duration,
    max_body_size: usize,  // Новое: лимит размера body для кеширования
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            capacity: 10_000,
            default_ttl: Duration::from_secs(3600),
            max_body_size: 10 * 1024 * 1024,  // 10MB
        }
    }
}

/// Главный прокси сервис
#[derive(Clone)]
struct ProxyService {
    cert_cache: CertCache,
    http_cache: Arc<Cache<Arc<str>, CachedResponse>>,
    cache_config: CacheConfig,
    kafka_producer: Option<Arc<FutureProducer>>,
    http_client: hyper_util::client::legacy::Client<hyper_util::client::legacy::connect::HttpConnector, Body>,
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
                .set("batch.size", "32768")  // Увеличен для лучшего batching
                .set("linger.ms", "5")  // Уменьшен для меньшей задержки
                .set("acks", "0")  // Fire-and-forget для максимальной скорости
                .create()
                .ok()
                .map(Arc::new)
        });

        let http_cache = Arc::new(Cache::new(cache_config.capacity));
        
        // Переиспользуемый HTTP клиент с connection pooling
        let http_client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(32)
            .build_http();

        Self {
            cert_cache,
            http_cache,
            cache_config,
            kafka_producer,
            http_client,
        }
    }

    #[inline]
    fn generate_cache_key(&self, method: &str, url: &str) -> Arc<str> {
        let mut hasher = Sha256::new();
        hasher.update(method.as_bytes());
        hasher.update(b":");
        hasher.update(url.as_bytes());
        hex::encode(hasher.finalize()).into()
    }

    #[inline]
    fn is_cacheable(&self, method: &str, status: u16, body_size: usize) -> bool {
        CACHEABLE_METHODS.contains(&method)
            && CACHEABLE_STATUS_CODES.contains(&status)
            && body_size <= self.cache_config.max_body_size
    }

    #[inline]
    fn extract_domain(url_str: &str) -> Arc<str> {
        url::Url::parse(url_str)
            .ok()
            .and_then(|u| u.host().map(|h| h.to_string()))
            .unwrap_or_else(|| "unknown".to_string())
            .into()
    }

    fn extract_user_info(req: &Request<Incoming>) -> (Option<Arc<str>>, Option<Arc<str>>) {
        let auth_header = req.headers().get(AUTHORIZATION)?;
        let auth_str = auth_header.to_str().ok()?;
        let encoded = auth_str.strip_prefix("Basic ")?;
        let decoded_bytes = general_purpose::STANDARD.decode(encoded).ok()?;
        let credentials = String::from_utf8(decoded_bytes).ok()?;
        let (username, _) = credentials.split_once(':')?;
        let username_arc: Arc<str> = username.into();
        Some((Some(username_arc.clone()), Some(username_arc)))
    }

    // Асинхронная отправка в Kafka без блокировки
    fn send_to_kafka_async(&self, event: CacheEvent) {
        if let Some(producer) = self.kafka_producer.clone() {
            tokio::spawn(async move {
                match serde_json::to_string(&event) {
                    Ok(payload) => {
                        let record = FutureRecord::to("cache-events")
                            .payload(&payload)
                            .key(event.cache_key.as_ref());
                        if let Err((e, _)) = producer.send(record, Duration::ZERO).await {
                            warn!("Kafka send failed: {}", e);
                        }
                    }
                    Err(e) => error!("Event serialization failed: {}", e),
                }
            });
        }
    }

    async fn handle_connect(
        &self,
        authority: String,
        mut client_stream: TcpStream,
        client_ip: Arc<str>,
        request_start: Instant,
    ) -> Result<(), Box<dyn std::error::Error>> {
        info!("CONNECT tunnel to: {}", authority);
        
        let mut upstream = TcpStream::connect(&authority).await?;
        client_stream.write_all(CONNECT_RESPONSE).await?;

        // Оптимизация: copy_bidirectional вместо двух copy
        let (bytes_c2u, bytes_u2c) = copy_bidirectional(&mut client_stream, &mut upstream).await?;

        let duration_ms = request_start.elapsed().as_millis() as u64;
        let domain: Arc<str> = authority.split(':').next().unwrap_or("unknown").into();
        
        let event = CacheEvent {
            url: format!("https://{}", authority).into(),
            method: "CONNECT".into(),
            status: 200,
            cache_key: self.generate_cache_key("CONNECT", &authority),
            cache_status: "BYPASS",
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_secs(),
            headers: HashMap::new(),
            user_id: None,
            username: None,
            client_ip,
            domain,
            response_size: bytes_u2c,
            request_duration_ms: duration_ms,
            content_type: None,
            user_agent: None,
        };
        
        self.send_to_kafka_async(event);
        debug!("CONNECT closed: {}↑ {}↓", bytes_c2u, bytes_u2c);
        Ok(())
    }

    async fn handle_request(
        &self,
        req: Request<Incoming>,
        client_ip: Arc<str>,
    ) -> Result<Response<Body>, Box<dyn std::error::Error + Send + Sync>> {
        let request_start = Instant::now();
        let method: Arc<str> = req.method().as_str().into();
        let uri = req.uri().clone();
        let url: Arc<str> = uri.to_string().into();
        let (user_id, username) = Self::extract_user_info(&req).unwrap_or((None, None));
        let cache_key = self.generate_cache_key(&method, &url);

        // Проверка кеша
        if let Some(cached) = self.http_cache.get(&cache_key) {
            if !cached.is_expired() {
                info!("Cache HIT: {} {}", method, url);
                
                let event = CacheEvent {
                    url: url.clone(),
                    method: method.clone(),
                    status: cached.status,
                    cache_key: cache_key.clone(),
                    cache_status: "HIT",
                    timestamp: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs(),
                    headers: HashMap::new(),  // Пустой для экономии памяти
                    user_id: user_id.clone(),
                    username: username.clone(),
                    client_ip: client_ip.clone(),
                    domain: Self::extract_domain(&url),
                    response_size: cached.body.len() as u64,
                    request_duration_ms: request_start.elapsed().as_millis() as u64,
                    content_type: cached.headers.iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                        .map(|(_, v)| v.clone()),
                    user_agent: None,
                };
                
                self.send_to_kafka_async(event);
                return Ok(cached.to_response());
            }
        }

        info!("Cache MISS: {} {}", method, url);
        
        // Запрос к upstream с переиспользуемым клиентом
        match self.http_client.request(req).await {
            Ok(response) => {
                let status = response.status();
                let headers_map: HashMap<String, String> = response
                    .headers()
                    .iter()
                    .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.as_str().to_string(), v.to_string())))
                    .collect();

                let body_bytes = hyper::body::to_bytes(response.into_body()).await?;
                let body_size = body_bytes.len();
                
                let cache_status = if self.is_cacheable(&method, status.as_u16(), body_size) {
                    // Оптимизация: Arc для заголовков
                    let headers_arc: Arc<[(Arc<str>, Arc<str>)]> = headers_map
                        .iter()
                        .map(|(k, v)| (Arc::from(k.as_str()), Arc::from(v.as_str())))
                        .collect();
                    
                    let cached_response = CachedResponse {
                        status: status.as_u16(),
                        headers: headers_arc,
                        body: body_bytes.clone(),
                        cached_at: SystemTime::now(),
                        ttl: self.cache_config.default_ttl,
                    };
                    self.http_cache.insert(cache_key.clone(), cached_response);
                    "MISS"
                } else {
                    "BYPASS"
                };

                let event = CacheEvent {
                    url: url.clone(),
                    method: method.clone(),
                    status: status.as_u16(),
                    cache_key,
                    cache_status,
                    timestamp: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs(),
                    headers: headers_map.clone(),
                    user_id,
                    username,
                    client_ip,
                    domain: Self::extract_domain(&url),
                    response_size: body_size as u64,
                    request_duration_ms: request_start.elapsed().as_millis() as u64,
                    content_type: headers_map.get("content-type").map(|s| Arc::from(s.as_str())),
                    user_agent: headers_map.get("user-agent").map(|s| Arc::from(s.as_str())),
                };
                
                self.send_to_kafka_async(event);

                let mut resp = Response::new(Body::new(body_bytes));
                *resp.status_mut() = status;
                for (key, value) in headers_map {
                    if let (Ok(name), Ok(val)) = (
                        HeaderName::from_bytes(key.as_bytes()),
                        HeaderValue::from_str(&value),
                    ) {
                        resp.headers_mut().insert(name, val);
                    }
                }
                Ok(resp)
            }
            Err(e) => {
                error!("Upstream error: {}", e);
                let mut response = Response::new(Body::new(Bytes::from_static(b"502 Bad Gateway")));
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
    let max_body_size = std::env::var("MAX_CACHE_BODY_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10 * 1024 * 1024);  // 10MB default

    let cache_config = CacheConfig {
        capacity: cache_capacity,
        default_ttl: cache_ttl,
        max_body_size,
    };

    let service = Arc::new(ProxyService::new(cert_cache, cache_config, kafka_brokers));
    let http_port = std::env::var("HTTP_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1488);

    let listener = TcpListener::bind(format!("0.0.0.0:{}", http_port)).await?;
    info!("🚀 BSDM-Proxy v2.0 (optimized) on 0.0.0.0:{}", http_port);
    info!("📦 Cache: {} entries, TTL: {:?}, max body: {}MB", 
        service.http_cache.capacity(), 
        cache_config.default_ttl,
        max_body_size / 1024 / 1024
    );

    loop {
        let (stream, addr) = listener.accept().await?;
        let service_clone = service.clone();
        let client_ip: Arc<str> = addr.ip().to_string().into();
        
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
    client_ip: Arc<str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let io = TokioIo::new(stream);
    let svc = service_fn(move |req: Request<Incoming>| {
        let service = service.clone();
        let client_ip = client_ip.clone();
        let request_start = Instant::now();
        
        async move {
            if req.method() == Method::CONNECT {
                let authority = req.uri().authority()
                    .ok_or("Missing authority")?
                    .as_str()
                    .to_string();
                
                tokio::spawn({
                    let service = service.clone();
                    let client_ip = client_ip.clone();
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
                
                let response = Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::new(Bytes::new()))?;
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
