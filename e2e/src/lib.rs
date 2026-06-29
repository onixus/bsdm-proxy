//! Shared harness for BSDM-Proxy smoke and E2E tests.

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::CertificateDer;
use rustls::ServerConfig;
use rustls_pemfile::certs;
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::process::Child as TokioChild;
use tokio_rustls::TlsAcceptor;

#[derive(Clone, Debug, Default)]
pub struct HarnessConfig {
    pub auth_enabled: bool,
    pub acl_enabled: bool,
    pub acl_rules_path: Option<PathBuf>,
    pub categorization_enabled: bool,
    pub mitm_enabled: bool,
    /// When set, spawn HTTPS mock upstream on this port (for MITM tests on 443/8443).
    pub https_upstream_port: Option<u16>,
    /// Trust workspace test CA for upstream TLS (sets UPSTREAM_CA_CERT in proxy).
    pub upstream_ca_cert: bool,
    pub kafka_brokers: Option<String>,
}

pub struct ProxyHarness {
    pub proxy_port: u16,
    pub metrics_port: u16,
    pub upstream_port: u16,
    proxy_process: TokioChild,
    _upstream_task: tokio::task::JoinHandle<()>,
    _stderr_log: Option<PathBuf>,
}

static HARNESS_LOCK: AtomicUsize = AtomicUsize::new(0);

/// Serialize proxy process startup to avoid port/cert races between tests.
pub async fn proxy_test_guard() -> ProxyTestGuard {
    while HARNESS_LOCK
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    ProxyTestGuard
}

pub struct ProxyTestGuard;

impl Drop for ProxyTestGuard {
    fn drop(&mut self) {
        HARNESS_LOCK.store(0, Ordering::Release);
    }
}

impl ProxyHarness {
    pub async fn start(config: HarnessConfig) -> Result<Self> {
        let proxy_bin = proxy_binary()?;
        let workspace = workspace_path("");
        ensure_test_ca()?;

        let upstream_task = if let Some(port) = config.https_upstream_port {
            spawn_mock_https_upstream(port).await?
        } else {
            spawn_mock_upstream().await?
        };
        let upstream_port = upstream_task.port;
        wait_for_tcp(upstream_port).await?;
        let proxy_port = reserve_port()?;
        let metrics_port = reserve_port()?;

        let acl_rules_path = config
            .acl_rules_path
            .as_ref()
            .map(|p| p.to_string_lossy().to_string());

        let mut command = Command::new(&proxy_bin);
        command
            .current_dir(&workspace)
            .env("HTTP_PORT", proxy_port.to_string())
            .env("METRICS_PORT", metrics_port.to_string())
            .env("MITM_ENABLED", bool_env(config.mitm_enabled))
            .env("AUTH_ENABLED", bool_env(config.auth_enabled))
            .env("ACL_ENABLED", bool_env(config.acl_enabled))
            .env("ACL_DEFAULT_ACTION", "allow")
            .env(
                "CATEGORIZATION_ENABLED",
                bool_env(config.categorization_enabled),
            )
            .env(
                "RUST_LOG",
                if config.mitm_enabled {
                    "info,proxy=debug"
                } else {
                    "warn"
                },
            );

        if config.upstream_ca_cert {
            let ca_path = workspace.join("certs/ca.crt");
            let ca_path = ca_path.canonicalize().unwrap_or(ca_path);
            command.env("UPSTREAM_CA_CERT", ca_path.to_string_lossy().into_owned());
        }

        if let Some(path) = &acl_rules_path {
            command.env("ACL_RULES_PATH", path);
        }
        if let Some(brokers) = &config.kafka_brokers {
            command.env("KAFKA_BROKERS", brokers);
        }

        let stderr_log = if config.mitm_enabled {
            let log_dir = std::env::temp_dir();
            Some(log_dir.join(format!("bsdm-proxy-{proxy_port}.log")))
        } else {
            None
        };

        if let Some(log_path) = &stderr_log {
            let log_file = std::fs::File::create(log_path)?;
            command.stdout(Stdio::null()).stderr(log_file);
        } else {
            command.stdout(Stdio::null()).stderr(Stdio::null());
        }

        let proxy_process = tokio::process::Command::from(command)
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("spawn proxy binary at {}", proxy_bin.display()))?;

        wait_for_health(metrics_port, Duration::from_secs(20)).await?;
        wait_for_tcp(proxy_port).await?;

        Ok(Self {
            proxy_port,
            metrics_port,
            upstream_port,
            proxy_process,
            _upstream_task: upstream_task.handle,
            _stderr_log: stderr_log,
        })
    }

    pub fn metrics_url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{}", self.metrics_port, path)
    }

    pub fn upstream_url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{}", self.upstream_port, path)
    }

    pub fn proxy_client(&self) -> Result<reqwest::Client> {
        let proxy = reqwest::Proxy::http(format!("http://127.0.0.1:{}", self.proxy_port))?;
        reqwest::Client::builder()
            .proxy(proxy)
            .timeout(Duration::from_secs(10))
            .build()
            .context("build proxied HTTP client")
    }

    pub fn proxy_auth_client(&self, username: &str, password: &str) -> Result<reqwest::Client> {
        let token = STANDARD.encode(format!("{username}:{password}"));
        let proxy = reqwest::Proxy::http(format!("http://127.0.0.1:{}", self.proxy_port))?;
        reqwest::Client::builder()
            .proxy(proxy)
            .default_headers({
                let mut headers = reqwest::header::HeaderMap::new();
                headers.insert(
                    reqwest::header::PROXY_AUTHORIZATION,
                    format!("Basic {token}").parse().unwrap(),
                );
                headers
            })
            .timeout(Duration::from_secs(10))
            .build()
            .context("build authenticated proxied HTTP client")
    }

    /// HTTP client for MITM tests: trusts the workspace test CA (self-signed).
    pub fn proxy_mitm_client(&self) -> Result<reqwest::Client> {
        let ca_pem = std::fs::read(test_ca_cert_path()).context("read test CA certificate")?;
        let ca = reqwest::Certificate::from_pem(&ca_pem).context("parse test CA certificate")?;
        let proxy = reqwest::Proxy::all(format!("http://127.0.0.1:{}", self.proxy_port))?;
        reqwest::Client::builder()
            .add_root_certificate(ca)
            .proxy(proxy)
            .timeout(Duration::from_secs(10))
            .build()
            .context("build MITM proxied HTTPS client")
    }

    pub fn mitm_upstream_url(&self, path: &str) -> String {
        format!("https://127.0.0.1:{}{}", self.upstream_port, path)
    }
}

impl Drop for ProxyHarness {
    fn drop(&mut self) {
        let _ = self.proxy_process.start_kill();
    }
}

pub fn proxy_binary() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("BSDM_PROXY_BIN") {
        let path = PathBuf::from(path);
        if path.exists() {
            return Ok(path);
        }
        bail!("BSDM_PROXY_BIN points to missing file: {}", path.display());
    }
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_proxy") {
        return Ok(PathBuf::from(path));
    }

    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for profile in ["debug", "release"] {
        let path = manifest
            .join("..")
            .join("target")
            .join(profile)
            .join("proxy");
        if path.exists() {
            return Ok(path);
        }
    }

    bail!("proxy binary not found; run `cargo build -p bsdm-proxy --bin proxy` first")
}

pub fn test_ca_cert_path() -> PathBuf {
    workspace_path("certs/ca.crt")
}

pub fn workspace_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(relative)
}

pub async fn wait_for_health(metrics_port: u16, timeout: Duration) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()?;
    let url = format!("http://127.0.0.1:{metrics_port}/health");
    let deadline = Instant::now() + timeout;

    loop {
        if let Ok(resp) = client.get(&url).send().await {
            if resp.status().is_success() {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            bail!("timed out waiting for proxy health at {url}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

pub async fn wait_for_tcp(port: u16) -> Result<()> {
    let addr = format!("127.0.0.1:{port}");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if tokio::net::TcpStream::connect(&addr).await.is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("timed out waiting for TCP listener at {addr}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

pub struct UpstreamServer {
    pub port: u16,
    handle: tokio::task::JoinHandle<()>,
}

async fn spawn_mock_upstream() -> Result<UpstreamServer> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("bind mock upstream")?;
    let port = listener.local_addr()?.port();

    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let service = service_fn(|req: Request<Incoming>| async move {
                    let path = req.uri().path();
                    let body = format!("upstream:{path}");
                    Ok::<_, hyper::Error>(Response::new(Full::new(Bytes::from(body))))
                });
                let _ = http1::Builder::new().serve_connection(io, service).await;
            });
        }
    });

    Ok(UpstreamServer { port, handle })
}

pub async fn spawn_mock_https_upstream(port: u16) -> Result<UpstreamServer> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let ca_dir = workspace_path("certs");
    let ca_key_pem = std::fs::read_to_string(ca_dir.join("ca.key"))
        .context("read test CA key for HTTPS upstream")?;
    let ca_cert_pem = std::fs::read_to_string(ca_dir.join("ca.crt"))
        .context("read test CA cert for HTTPS upstream")?;

    let ca_key = KeyPair::from_pem(&ca_key_pem).context("parse test CA key")?;
    let issuer =
        Issuer::from_ca_cert_pem(&ca_cert_pem, &ca_key).context("create issuer from test CA")?;

    let server_key = KeyPair::generate().context("generate upstream TLS key")?;
    let mut params =
        CertificateParams::new(vec!["127.0.0.1".to_string()]).context("upstream cert params")?;
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "127.0.0.1");
    params.subject_alt_names = vec![rcgen::SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST))];
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];

    let cert = params
        .signed_by(&server_key, &issuer)
        .context("sign upstream TLS certificate")?;
    let server_config = build_rustls_server_config(cert.pem(), server_key.serialize_pem())?;
    let acceptor = TlsAcceptor::from(server_config);

    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
        .await
        .with_context(|| format!("bind HTTPS mock upstream on 127.0.0.1:{port}"))?;
    let bound_port = listener.local_addr()?.port();

    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls_stream) = acceptor.accept(stream).await else {
                    return;
                };
                let io = TokioIo::new(tls_stream);
                let service = service_fn(|req: Request<Incoming>| async move {
                    let path = req.uri().path();
                    let body = format!("upstream-tls:{path}");
                    Ok::<_, hyper::Error>(Response::new(Full::new(Bytes::from(body))))
                });
                let _ = http1::Builder::new().serve_connection(io, service).await;
            });
        }
    });

    Ok(UpstreamServer {
        port: bound_port,
        handle,
    })
}

fn build_rustls_server_config(cert_pem: String, key_pem: String) -> Result<Arc<ServerConfig>> {
    let mut chain: Vec<CertificateDer<'static>> = certs(&mut Cursor::new(cert_pem.as_bytes()))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|cert| cert.into_owned())
        .collect();
    let ca_pem = std::fs::read_to_string(test_ca_cert_path())?;
    chain.extend(
        certs(&mut Cursor::new(ca_pem.as_bytes()))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|cert| cert.into_owned()),
    );

    let key = rustls_pemfile::private_key(&mut Cursor::new(key_pem.as_bytes()))
        .context("parse upstream private key")?
        .ok_or_else(|| anyhow::anyhow!("no private key in upstream PEM"))?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .context("build upstream TLS server config")?;

    Ok(Arc::new(config))
}

pub async fn spawn_tcp_echo_server() -> Result<(u16, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("bind tcp echo server")?;
    let port = listener.local_addr()?.port();

    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = stream.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    Ok((port, handle))
}

pub async fn connect_via_proxy(proxy_port: u16, target: SocketAddr) -> Result<String> {
    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{proxy_port}"))
        .await
        .context("connect to proxy")?;

    let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .context("write CONNECT request")?;

    let mut response = vec![0u8; 1024];
    let n = stream
        .read(&mut response)
        .await
        .context("read CONNECT response")?;
    let response_text = String::from_utf8_lossy(&response[..n]).to_string();

    if !response_text.starts_with("HTTP/1.1 200") && !response_text.starts_with("HTTP/1.0 200") {
        bail!("unexpected CONNECT response: {response_text}");
    }

    stream
        .write_all(b"ping")
        .await
        .context("write tunneled payload")?;

    let mut payload = [0u8; 16];
    let n = stream
        .read(&mut payload)
        .await
        .context("read tunneled echo")?;

    Ok(String::from_utf8_lossy(&payload[..n]).to_string())
}

fn reserve_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").context("reserve port")?;
    Ok(listener.local_addr()?.port())
}

fn bool_env(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

pub fn ensure_test_ca() -> Result<()> {
    let dir = workspace_path("certs");
    std::fs::create_dir_all(&dir).context("create certs dir")?;
    if dir.join("ca.crt").exists() && dir.join("ca.key").exists() {
        return Ok(());
    }
    write_test_ca(&dir)
}

fn write_test_ca(dir: &Path) -> Result<()> {
    let key_pair = KeyPair::generate().context("generate CA key")?;
    let mut params =
        CertificateParams::new(vec!["BSDM Test CA".to_string()]).context("create CA params")?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "BSDM Test CA");

    let cert = params
        .self_signed(&key_pair)
        .context("self-sign test CA cert")?;

    let key_pem = key_pair.serialize_pem();
    let cert_pem = cert.pem();

    std::fs::write(dir.join("ca.key"), &key_pem)?;
    std::fs::write(dir.join("ca.crt"), &cert_pem)?;

    Ok(())
}
