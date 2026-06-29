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
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::process::Child as TokioChild;

#[derive(Clone, Debug, Default)]
pub struct HarnessConfig {
    pub auth_enabled: bool,
    pub acl_enabled: bool,
    pub acl_rules_path: Option<PathBuf>,
    pub categorization_enabled: bool,
    pub mitm_enabled: bool,
    pub kafka_brokers: Option<String>,
}

pub struct ProxyHarness {
    pub proxy_port: u16,
    pub metrics_port: u16,
    pub upstream_port: u16,
    proxy_process: TokioChild,
    _upstream_task: tokio::task::JoinHandle<()>,
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
        let upstream_task = spawn_mock_upstream().await?;
        let upstream_port = upstream_task.port;
        let proxy_port = reserve_port()?;
        let metrics_port = reserve_port()?;

        let workspace = workspace_path("");
        write_test_ca(&workspace.join("certs"))?;

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
            .env("RUST_LOG", "warn")
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        if let Some(path) = &acl_rules_path {
            command.env("ACL_RULES_PATH", path);
        }
        if let Some(brokers) = &config.kafka_brokers {
            command.env("KAFKA_BROKERS", brokers);
        }

        let proxy_process = tokio::process::Command::from(command)
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("spawn proxy binary at {}", proxy_bin.display()))?;

        wait_for_health(metrics_port, Duration::from_secs(20)).await?;

        Ok(Self {
            proxy_port,
            metrics_port,
            upstream_port,
            proxy_process,
            _upstream_task: upstream_task.handle,
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

struct UpstreamServer {
    port: u16,
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

fn write_test_ca(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).context("create certs dir")?;
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
