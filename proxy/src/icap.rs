//! Optional ICAP client (RFC 3507) for AV/URL sidecar adaptation.
//!
//! Env-gated (`ICAP_ENABLED`). Speaks ICAP over plain TCP (no TLS in PoC).
//! Hook points: REQMOD after request body collect (before upstream);
//! RESPMOD after buffered response body collect (streaming MISS skipped).
//!
//! See [docs/icap.md](../../docs/icap.md).

use bytes::Bytes;
use hyper_rustls::ConfigBuilderExt;
use rustls::pki_types::ServerName;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, info, warn};

pub enum IcapStream {
    Plain(TcpStream),
    Tls(tokio_rustls::client::TlsStream<TcpStream>),
}

impl AsyncRead for IcapStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            IcapStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            IcapStream::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for IcapStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            IcapStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            IcapStream::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            IcapStream::Plain(s) => Pin::new(s).poll_flush(cx),
            IcapStream::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            IcapStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            IcapStream::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Runtime configuration from environment.
#[derive(Debug, Clone)]
pub struct IcapConfig {
    pub enabled: bool,
    /// Full ICAP URI, e.g. `icap://127.0.0.1:1344/echo`
    pub url: String,
    pub timeout: Duration,
    pub fail_open: bool,
    pub reqmod: bool,
    pub respmod: bool,
    /// Max request/response body bytes sent to ICAP (0 = headers only / null-body).
    pub max_body_bytes: usize,
}

impl IcapConfig {
    pub fn from_env() -> Self {
        let enabled = env_bool("ICAP_ENABLED", false);
        let url =
            std::env::var("ICAP_URL").unwrap_or_else(|_| "icap://127.0.0.1:1344/echo".to_string());
        let timeout_ms = std::env::var("ICAP_TIMEOUT_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(5_000_u64);
        let fail_open = env_bool("ICAP_FAIL_OPEN", true);
        let reqmod = env_bool("ICAP_REQMOD", true);
        let respmod = env_bool("ICAP_RESPMOD", true);
        let max_body_bytes = std::env::var("ICAP_MAX_BODY_BYTES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1_048_576_usize);
        Self {
            enabled,
            url,
            timeout: Duration::from_millis(timeout_ms.max(1)),
            fail_open,
            reqmod,
            respmod,
            max_body_bytes,
        }
    }
}

fn env_bool(key: &str, default: bool) -> bool {
    std::env::var(key)
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(default)
}

#[derive(Debug, Clone)]
struct ParsedIcapUrl {
    host: String,
    port: u16,
    service_path: String,
    addr: SocketAddr,
    is_tls: bool,
}

fn parse_icap_url(url: &str) -> Result<ParsedIcapUrl, String> {
    let (rest, is_tls) =
        if let Some(r) = url.strip_prefix("icaps://").or_else(|| url.strip_prefix("ICAPS://")) {
            (r, true)
        } else if let Some(r) = url.strip_prefix("icap://").or_else(|| url.strip_prefix("ICAP://")) {
            (r, false)
        } else {
            return Err(format!("ICAP_URL must start with icap:// or icaps:// (got {url})"));
        };

    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    let (host, port) = if let Some((h, p)) = authority.rsplit_once(':') {
        let port: u16 = p
            .parse()
            .map_err(|_| format!("invalid ICAP port in {url}"))?;
        (h.to_string(), port)
    } else {
        (authority.to_string(), if is_tls { 11344 } else { 1344 })
    };
    let addr = resolve_host(&host, port)?;
    Ok(ParsedIcapUrl {
        host,
        port,
        service_path: if path.is_empty() { "/".into() } else { path },
        addr,
        is_tls,
    })
}

fn resolve_host(host: &str, port: u16) -> Result<SocketAddr, String> {
    use std::net::ToSocketAddrs;
    (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("resolve {host}:{port}: {e}"))?
        .next()
        .ok_or_else(|| format!("no addresses for {host}:{port}"))
}

/// Outcome of an ICAP adaptation call.
#[derive(Debug, Clone)]
pub enum IcapOutcome {
    /// 204 No Modifications (or equivalent allow).
    Allow,
    /// Encapsulated HTTP response — return to client (block / rewrite).
    HttpResponse {
        status: u16,
        headers: HashMap<String, String>,
        body: Bytes,
    },
}

/// Shared ICAP client handle.
#[derive(Clone)]
pub struct IcapClient {
    cfg: IcapConfig,
    parsed: ParsedIcapUrl,
}

impl IcapClient {
    pub fn from_config(cfg: IcapConfig) -> Result<Option<Self>, String> {
        if !cfg.enabled {
            return Ok(None);
        }
        let parsed = parse_icap_url(&cfg.url)?;
        info!(
            "ICAP enabled → {} (reqmod={}, respmod={}, fail_open={})",
            cfg.url, cfg.reqmod, cfg.respmod, cfg.fail_open
        );
        Ok(Some(Self { cfg, parsed }))
    }

    pub fn try_from_env() -> Option<Arc<Self>> {
        let cfg = IcapConfig::from_env();
        match Self::from_config(cfg) {
            Ok(Some(c)) => Some(Arc::new(c)),
            Ok(None) => None,
            Err(e) => {
                warn!("ICAP disabled: {e}");
                None
            }
        }
    }

    pub fn fail_open(&self) -> bool {
        self.cfg.fail_open
    }

    pub fn reqmod_enabled(&self) -> bool {
        self.cfg.reqmod
    }

    pub fn respmod_enabled(&self) -> bool {
        self.cfg.respmod
    }

    /// REQMOD: adapt client request before upstream fetch.
    pub async fn reqmod(
        &self,
        method: &str,
        url: &str,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> Result<IcapOutcome, String> {
        if !self.cfg.reqmod {
            return Ok(IcapOutcome::Allow);
        }
        let body = truncate_body(body, self.cfg.max_body_bytes);
        let http_req = encode_http_request(method, url, headers, &body)?;
        let mut msg = icap_head(
            "REQMOD",
            &self.parsed,
            &encapsulated_req(&http_req, body.is_empty()),
        );
        msg.extend_from_slice(&http_req);
        if !body.is_empty() {
            msg.extend_from_slice(&encode_chunked(&body));
        }
        self.exchange(&msg).await
    }

    /// RESPMOD: adapt upstream response before serving client (buffered path).
    pub async fn respmod(
        &self,
        req_method: &str,
        req_url: &str,
        req_headers: &HashMap<String, String>,
        status: u16,
        resp_headers: &HashMap<String, String>,
        body: &[u8],
    ) -> Result<IcapOutcome, String> {
        if !self.cfg.respmod {
            return Ok(IcapOutcome::Allow);
        }
        let body = truncate_body(body, self.cfg.max_body_bytes);
        let http_req = encode_http_request(req_method, req_url, req_headers, &[])?;
        let http_resp_hdr = encode_http_response_headers(status, resp_headers, body.len());
        let res_hdr_off = http_req.len();
        let body_off = res_hdr_off + http_resp_hdr.len();
        let enc = if body.is_empty() {
            format!("Encapsulated: req-hdr=0, res-hdr={res_hdr_off}, null-body={body_off}")
        } else {
            format!("Encapsulated: req-hdr=0, res-hdr={res_hdr_off}, res-body={body_off}")
        };
        let mut msg = icap_head("RESPMOD", &self.parsed, &enc);
        msg.extend_from_slice(&http_req);
        msg.extend_from_slice(&http_resp_hdr);
        if !body.is_empty() {
            msg.extend_from_slice(&encode_chunked(&body));
        }
        self.exchange(&msg).await
    }

    async fn exchange(&self, request: &[u8]) -> Result<IcapOutcome, String> {
        let result = tokio::time::timeout(self.cfg.timeout, self.exchange_inner(request)).await;
        match result {
            Ok(Ok(o)) => Ok(o),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(format!(
                "ICAP timeout after {}ms",
                self.cfg.timeout.as_millis()
            )),
        }
    }

    async fn exchange_inner(&self, request: &[u8]) -> Result<IcapOutcome, String> {
        debug!(
            "ICAP connect {} ({} bytes, is_tls={})",
            self.parsed.addr,
            request.len(),
            self.parsed.is_tls
        );
        let tcp_stream = TcpStream::connect(self.parsed.addr)
            .await
            .map_err(|e| format!("ICAP connect {}: {e}", self.parsed.addr))?;

        let mut stream = if self.parsed.is_tls {
            let tls_config = rustls::ClientConfig::builder()
                .with_webpki_roots()
                .with_no_client_auth();
            let connector = TlsConnector::from(Arc::new(tls_config));
            let domain = ServerName::try_from(self.parsed.host.clone())
                .map_err(|e| format!("Invalid ICAP TLS server name '{}': {e}", self.parsed.host))?
                .to_owned();
            let tls_stream = connector
                .connect(domain, tcp_stream)
                .await
                .map_err(|e| format!("ICAP TLS handshake failed: {e}"))?;
            IcapStream::Tls(tls_stream)
        } else {
            IcapStream::Plain(tcp_stream)
        };

        stream
            .write_all(request)
            .await
            .map_err(|e| format!("ICAP write: {e}"))?;

        let mut buf = Vec::with_capacity(4096);
        let mut tmp = [0u8; 8192];
        loop {
            let n = stream
                .read(&mut tmp)
                .await
                .map_err(|e| format!("ICAP read: {e}"))?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.len() > 16 << 20 {
                return Err("ICAP response too large".into());
            }
            if let Some(outcome) = try_parse_icap_response(&buf)? {
                return Ok(outcome);
            }
        }
        try_parse_icap_response(&buf)?.ok_or_else(|| "incomplete ICAP response".to_string())
    }
}

fn truncate_body(body: &[u8], max: usize) -> Vec<u8> {
    if max == 0 {
        Vec::new()
    } else if body.len() > max {
        body[..max].to_vec()
    } else {
        body.to_vec()
    }
}

fn icap_head(method: &str, parsed: &ParsedIcapUrl, encapsulated: &str) -> Vec<u8> {
    format!(
        "{method} icap://{}:{}{} ICAP/1.0\r\n\
         Host: {}:{}\r\n\
         Allow: 204\r\n\
         {encapsulated}\r\n\
         \r\n",
        parsed.host, parsed.port, parsed.service_path, parsed.host, parsed.port,
    )
    .into_bytes()
}

fn encapsulated_req(http_req: &[u8], null_body: bool) -> String {
    let n = http_req.len();
    if null_body {
        format!("Encapsulated: req-hdr=0, null-body={n}")
    } else {
        format!("Encapsulated: req-hdr=0, req-body={n}")
    }
}

fn encode_http_request(
    method: &str,
    url: &str,
    headers: &HashMap<String, String>,
    body: &[u8],
) -> Result<Vec<u8>, String> {
    let (path, host) = split_url(url)?;
    let mut out = format!("{method} {path} HTTP/1.1\r\n").into_bytes();
    let mut has_host = false;
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("host") {
            has_host = true;
        }
        if k.eq_ignore_ascii_case("content-length")
            || k.eq_ignore_ascii_case("transfer-encoding")
            || k.eq_ignore_ascii_case("proxy-connection")
            || k.eq_ignore_ascii_case("connection")
        {
            continue;
        }
        out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    if !has_host {
        out.extend_from_slice(format!("Host: {host}\r\n").as_bytes());
    }
    if !body.is_empty() {
        out.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    Ok(out)
}

fn encode_http_response_headers(
    status: u16,
    headers: &HashMap<String, String>,
    body_len: usize,
) -> Vec<u8> {
    let reason = http_reason(status);
    let mut out = format!("HTTP/1.1 {status} {reason}\r\n").into_bytes();
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("content-length")
            || k.eq_ignore_ascii_case("transfer-encoding")
            || k.eq_ignore_ascii_case("connection")
        {
            continue;
        }
        out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    if body_len > 0 {
        out.extend_from_slice(format!("Content-Length: {body_len}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out
}

fn encode_chunked(body: &[u8]) -> Vec<u8> {
    let mut out = format!("{:x}\r\n", body.len()).into_bytes();
    out.extend_from_slice(body);
    out.extend_from_slice(b"\r\n0\r\n\r\n");
    out
}

fn split_url(url: &str) -> Result<(String, String), String> {
    let u = url::Url::parse(url).map_err(|e| format!("url parse: {e}"))?;
    let host = u
        .host_str()
        .ok_or_else(|| "URL missing host".to_string())?
        .to_string();
    let host_port = match u.port() {
        Some(p) => format!("{host}:{p}"),
        None => host,
    };
    let path = if u.path().is_empty() {
        "/".to_string()
    } else {
        u.path().to_string()
    };
    let path_q = match u.query() {
        Some(q) => format!("{path}?{q}"),
        None => path,
    };
    Ok((path_q, host_port))
}

fn http_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        403 => "Forbidden",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "OK",
    }
}

fn try_parse_icap_response(buf: &[u8]) -> Result<Option<IcapOutcome>, String> {
    let Some(hdr_end) = find_header_end(buf) else {
        return Ok(None);
    };
    parse_after_headers(buf, hdr_end)
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn parse_after_headers(buf: &[u8], hdr_end: usize) -> Result<Option<IcapOutcome>, String> {
    let headers_raw = std::str::from_utf8(&buf[..hdr_end]).map_err(|e| format!("utf8: {e}"))?;
    let mut lines = headers_raw.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let mut parts = status_line.split_whitespace();
    let _proto = parts.next().unwrap_or("");
    let code: u16 = parts
        .next()
        .ok_or_else(|| format!("bad ICAP status: {status_line}"))?
        .parse()
        .map_err(|_| format!("bad ICAP status code: {status_line}"))?;

    let mut encapsulated = String::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case("Encapsulated") {
                encapsulated = v.trim().to_string();
            }
        }
    }

    if code == 204 {
        return Ok(Some(IcapOutcome::Allow));
    }
    if !(200..300).contains(&code) {
        return Err(format!("ICAP error status {code}"));
    }

    if encapsulated.is_empty() {
        return Ok(Some(IcapOutcome::Allow));
    }

    let has_res = encapsulated
        .split(',')
        .any(|p| p.trim().starts_with("res-hdr"));
    if !has_res {
        // Modified request only — PoC allows through (no request rewrite yet)
        return Ok(Some(IcapOutcome::Allow));
    }

    parse_encapsulated_http_response(&buf[hdr_end..])
}

fn parse_encapsulated_http_response(data: &[u8]) -> Result<Option<IcapOutcome>, String> {
    let Some(pos) = find_header_end(data) else {
        return Ok(None);
    };
    let hdr = std::str::from_utf8(&data[..pos]).map_err(|e| format!("utf8: {e}"))?;
    let rest = &data[pos..];
    finish_http_response(hdr, rest)
}

fn finish_http_response(hdr: &str, body_rest: &[u8]) -> Result<Option<IcapOutcome>, String> {
    let mut lines = hdr.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let mut sp = status_line.split_whitespace();
    let _http = sp.next();
    let status: u16 = sp
        .next()
        .ok_or_else(|| format!("bad HTTP status in ICAP: {status_line}"))?
        .parse()
        .map_err(|_| format!("bad HTTP code in ICAP: {status_line}"))?;

    let mut headers = HashMap::new();
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_string();
            let val = v.trim().to_string();
            if key.eq_ignore_ascii_case("content-length") {
                content_length = val.parse().ok();
            }
            if key.eq_ignore_ascii_case("transfer-encoding")
                && val.to_ascii_lowercase().contains("chunked")
            {
                chunked = true;
            }
            headers.insert(key.to_ascii_lowercase(), val);
        }
    }

    let body = if chunked {
        match decode_chunked(body_rest)? {
            Some(b) => b,
            None => return Ok(None),
        }
    } else if let Some(n) = content_length {
        if body_rest.len() < n {
            return Ok(None);
        }
        Bytes::copy_from_slice(&body_rest[..n])
    } else if body_rest.is_empty() {
        Bytes::new()
    } else {
        // ICAP often uses chunked framing even when HTTP headers omit TE
        match decode_chunked(body_rest)? {
            Some(b) => b,
            None => {
                if body_rest.len() >= 5 && body_rest.ends_with(b"0\r\n\r\n") {
                    return Ok(None);
                }
                Bytes::copy_from_slice(body_rest)
            }
        }
    };

    Ok(Some(IcapOutcome::HttpResponse {
        status,
        headers,
        body,
    }))
}

fn decode_chunked(data: &[u8]) -> Result<Option<Bytes>, String> {
    let mut out = Vec::new();
    let mut i = 0;
    loop {
        let Some(line_end) = data[i..].windows(2).position(|w| w == b"\r\n") else {
            return Ok(None);
        };
        let line =
            std::str::from_utf8(&data[i..i + line_end]).map_err(|e| format!("chunk: {e}"))?;
        let size = usize::from_str_radix(line.trim(), 16)
            .map_err(|_| format!("bad chunk size: {line}"))?;
        i += line_end + 2;
        if size == 0 {
            return Ok(Some(Bytes::from(out)));
        }
        if data.len() < i + size + 2 {
            return Ok(None);
        }
        out.extend_from_slice(&data[i..i + size]);
        i += size + 2;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn spawn_mock_icap() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 65536];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let resp = if req.contains("virus.example") || req.contains("EICAR") {
                        let http = concat!(
                            "HTTP/1.1 403 Forbidden\r\n",
                            "Content-Type: text/plain\r\n",
                            "Content-Length: 12\r\n",
                            "\r\n",
                            "blocked-icap"
                        );
                        let body_off = http.find("\r\n\r\n").unwrap() + 4;
                        format!(
                            "ICAP/1.0 200 OK\r\nEncapsulated: res-hdr=0, res-body={body_off}\r\n\r\n{http}"
                        )
                    } else {
                        "ICAP/1.0 204 No Modifications\r\n\r\n".to_string()
                    };
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn reqmod_allows_clean() {
        let addr = spawn_mock_icap().await;
        let cfg = IcapConfig {
            enabled: true,
            url: format!("icap://{}:{}/echo", addr.ip(), addr.port()),
            timeout: Duration::from_secs(2),
            fail_open: false,
            reqmod: true,
            respmod: false,
            max_body_bytes: 1024,
        };
        let client = IcapClient::from_config(cfg).unwrap().unwrap();
        let headers = HashMap::new();
        let out = client
            .reqmod("GET", "http://example.com/ok", &headers, b"")
            .await
            .unwrap();
        assert!(matches!(out, IcapOutcome::Allow));
    }

    #[tokio::test]
    async fn reqmod_blocks_virus_host() {
        let addr = spawn_mock_icap().await;
        let cfg = IcapConfig {
            enabled: true,
            url: format!("icap://{}:{}/av", addr.ip(), addr.port()),
            timeout: Duration::from_secs(2),
            fail_open: false,
            reqmod: true,
            respmod: false,
            max_body_bytes: 1024,
        };
        let client = IcapClient::from_config(cfg).unwrap().unwrap();
        let headers = HashMap::new();
        let out = client
            .reqmod("GET", "http://virus.example/eicar", &headers, b"")
            .await
            .unwrap();
        match out {
            IcapOutcome::HttpResponse { status, body, .. } => {
                assert_eq!(status, 403);
                assert_eq!(&body[..], b"blocked-icap");
            }
            other => panic!("expected block, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn respmod_allows_clean() {
        let addr = spawn_mock_icap().await;
        let cfg = IcapConfig {
            enabled: true,
            url: format!("icap://{}:{}/echo", addr.ip(), addr.port()),
            timeout: Duration::from_secs(2),
            fail_open: false,
            reqmod: false,
            respmod: true,
            max_body_bytes: 1024,
        };
        let client = IcapClient::from_config(cfg).unwrap().unwrap();
        let rh = HashMap::new();
        let mut resp_h = HashMap::new();
        resp_h.insert("content-type".into(), "text/plain".into());
        let out = client
            .respmod("GET", "http://example.com/", &rh, 200, &resp_h, b"hello")
            .await
            .unwrap();
        assert!(matches!(out, IcapOutcome::Allow));
    }

    #[test]
    fn parse_url_defaults_port() {
        let p = parse_icap_url("icap://127.0.0.1/srv_clamav").unwrap();
        assert_eq!(p.port, 1344);
        assert_eq!(p.service_path, "/srv_clamav");
        assert_eq!(p.is_tls, false);
    }

    #[test]
    fn parse_icaps_url_defaults_port() {
        let p = parse_icap_url("icaps://127.0.0.1/srv_clamav").unwrap();
        assert_eq!(p.port, 11344);
        assert_eq!(p.service_path, "/srv_clamav");
        assert_eq!(p.is_tls, true);
    }
}
