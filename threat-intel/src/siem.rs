//! TASK-TI-030: Enterprise SIEM Integration.
//!
//! Provides formatting and export of threat intelligence detections and IOC lifecycle
//! events into industry-standard SIEM formats:
//! - CEF (Common Event Format - ArcSight / QRadar / Sentinel / Splunk)
//! - ECS (Elastic Common Schema JSON - Elastic Security / Wazuh)
//! - Syslog RFC 5424 formatted messages

use crate::indicator::IndicatorKind;
use crate::storage::StoredIndicator;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Mutex;

use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SiemEventAction {
    Detected,
    Blocked,
    Unblocked,
    Expired,
}

impl SiemEventAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            SiemEventAction::Detected => "ioc_detected",
            SiemEventAction::Blocked => "ioc_blocked",
            SiemEventAction::Unblocked => "ioc_unblocked",
            SiemEventAction::Expired => "ioc_expired",
        }
    }
}

/// Supported SIEM event payload formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SiemFormat {
    #[default]
    Cef,
    EcsJson,
    SyslogRfc5424,
}

impl SiemFormat {
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "ecs" | "ecs_json" | "ecsjson" | "json" => Self::EcsJson,
            "syslog" | "rfc5424" | "syslog_rfc5424" => Self::SyslogRfc5424,
            _ => Self::Cef,
        }
    }
}

/// Network transport protocol for Syslog forwarding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SyslogProtocol {
    #[default]
    Udp,
    Tcp,
}

impl SyslogProtocol {
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "tcp" => Self::Tcp,
            _ => Self::Udp,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SiemError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Address resolution failed: {0}")]
    AddressResolution(String),
    #[error("Transport delivery error: {0}")]
    Transport(String),
    #[error("Configuration error: {0}")]
    Config(String),
}

/// Structured SIEM event payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemEvent {
    pub timestamp: chrono::DateTime<Utc>,
    pub action: SiemEventAction,
    pub indicator_value: String,
    pub indicator_kind: IndicatorKind,
    pub domain: Option<String>,
    pub confidence_score: u8,
    pub source: String,
    pub severity: u8, // 1..10 scale for CEF
    pub message: String,
    pub tags: Vec<String>,
}

impl SiemEvent {
    pub fn from_stored(indicator: &StoredIndicator, action: SiemEventAction) -> Self {
        let severity = ((indicator.confidence_score as f32 / 10.0).round() as u8).clamp(1, 10);
        let message = format!(
            "Threat IOC [{}] from feed [{}] with confidence {}/100",
            indicator.normalized_value, indicator.source, indicator.confidence_score
        );

        Self {
            timestamp: Utc::now(),
            action,
            indicator_value: indicator.normalized_value.clone(),
            indicator_kind: indicator.kind,
            domain: indicator.domain.clone(),
            confidence_score: indicator.confidence_score,
            source: indicator.source.clone(),
            severity,
            message,
            tags: indicator.tags.clone(),
        }
    }

    /// Formats the event into Common Event Format (CEF) string:
    /// `CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]`
    pub fn to_cef(&self) -> String {
        let tags_str = self.tags.join(",");
        let mut extensions = vec![
            format!("act={}", self.action.as_str()),
            format!("cs1={}", self.source),
            "cs1Label=ThreatSource".to_string(),
            format!("cn1={}", self.confidence_score),
            "cn1Label=ConfidenceScore".to_string(),
            format!("msg={}", escape_cef_extension(&self.message)),
        ];

        match self.indicator_kind {
            IndicatorKind::Url => {
                extensions.push(format!(
                    "request={}",
                    escape_cef_extension(&self.indicator_value)
                ));
            }
            IndicatorKind::Domain => {
                extensions.push(format!(
                    "dhost={}",
                    escape_cef_extension(&self.indicator_value)
                ));
            }
            IndicatorKind::Ip => {
                extensions.push(format!("dst={}", self.indicator_value));
            }
        }

        if let Some(domain) = &self.domain {
            extensions.push(format!("shost={}", escape_cef_extension(domain)));
        }
        if !tags_str.is_empty() {
            extensions.push(format!("cs2={}", escape_cef_extension(&tags_str)));
            extensions.push("cs2Label=Tags".to_string());
        }

        format!(
            "CEF:0|BSDM-Proxy|ThreatIntel|{}|{}|{}|{}|{}",
            env!("CARGO_PKG_VERSION"),
            self.action.as_str().to_uppercase(),
            escape_cef_header(&self.message),
            self.severity,
            extensions.join(" ")
        )
    }

    /// Formats the event into Elastic Common Schema (ECS) JSON format.
    pub fn to_ecs_json(&self) -> serde_json::Value {
        serde_json::json!({
            "@timestamp": self.timestamp.to_rfc3339(),
            "event": {
                "kind": "alert",
                "category": ["threat", "network"],
                "type": ["indicator"],
                "action": self.action.as_str(),
                "severity": self.severity * 10, // 0..100 in ECS
                "dataset": "threat_intel"
            },
            "threat": {
                "indicator": {
                    "type": self.indicator_kind.as_str(),
                    "value": self.indicator_value,
                    "confidence": self.confidence_score,
                    "provider": self.source,
                    "description": self.message
                }
            },
            "rule": {
                "name": "BSDM Threat Intelligence Feed",
                "ruleset": "bsdm_threat_intel"
            },
            "tags": self.tags
        })
    }

    /// Formats the event into RFC 5424 Syslog line.
    pub fn to_syslog_rfc5424(&self, hostname: &str) -> String {
        let ts = self.timestamp.to_rfc3339();
        let cef = self.to_cef();
        // PRI 134 = Facility local0 (16) * 8 + Severity Info (6)
        format!("<134>1 {} {} bsdm-threat-intel - - - {}", ts, hostname, cef)
    }

    /// Formats this event according to the requested [`SiemFormat`].
    pub fn format_as(&self, format: SiemFormat, hostname: &str) -> Result<String, SiemError> {
        match format {
            SiemFormat::Cef => Ok(self.to_cef()),
            SiemFormat::EcsJson => Ok(serde_json::to_string(&self.to_ecs_json())?),
            SiemFormat::SyslogRfc5424 => Ok(self.to_syslog_rfc5424(hostname)),
        }
    }
}

fn escape_cef_header(s: &str) -> String {
    s.replace('\\', "\\\\").replace('|', "\\|")
}

fn escape_cef_extension(s: &str) -> String {
    s.replace('\\', "\\\\").replace('=', "\\=")
}

/// Abstract delivery transport for SIEM events.
pub trait SiemTransport: Send + Sync {
    fn send_event(&self, event: &SiemEvent) -> Result<(), SiemError>;
}

/// Syslog network transport (UDP or TCP socket).
pub struct SyslogTransport {
    addr: String,
    protocol: SyslogProtocol,
    format: SiemFormat,
    hostname: String,
}

impl SyslogTransport {
    pub fn new(
        addr: impl Into<String>,
        protocol: SyslogProtocol,
        format: SiemFormat,
        hostname: impl Into<String>,
    ) -> Self {
        Self {
            addr: addr.into(),
            protocol,
            format,
            hostname: hostname.into(),
        }
    }

    fn resolve_target(&self) -> Result<SocketAddr, SiemError> {
        self.addr
            .to_socket_addrs()
            .map_err(|e| SiemError::AddressResolution(format!("{}: {}", self.addr, e)))?
            .next()
            .ok_or_else(|| {
                SiemError::AddressResolution(format!("could not resolve address {}", self.addr))
            })
    }

    fn send_udp(&self, formatted: &str) -> Result<(), SiemError> {
        let target = self.resolve_target()?;
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
        socket.send_to(formatted.as_bytes(), target)?;
        Ok(())
    }

    fn send_tcp(&self, formatted: &str) -> Result<(), SiemError> {
        let target = self.resolve_target()?;
        let timeout = Duration::from_secs(3);
        let mut stream = std::net::TcpStream::connect_timeout(&target, timeout)?;
        stream.set_write_timeout(Some(timeout))?;
        let payload = if formatted.ends_with('\n') {
            formatted.to_string()
        } else {
            format!("{}\n", formatted)
        };
        stream.write_all(payload.as_bytes())?;
        stream.flush()?;
        Ok(())
    }
}

impl SiemTransport for SyslogTransport {
    fn send_event(&self, event: &SiemEvent) -> Result<(), SiemError> {
        let formatted = event.format_as(self.format, &self.hostname)?;
        match self.protocol {
            SyslogProtocol::Udp => self.send_udp(&formatted),
            SyslogProtocol::Tcp => self.send_tcp(&formatted),
        }
    }
}

/// File sink transport that appends formatted SIEM events to disk.
pub struct FileSiemTransport {
    path: PathBuf,
    format: SiemFormat,
    hostname: String,
    write_lock: Mutex<()>,
}

impl FileSiemTransport {
    pub fn new(
        path: impl Into<PathBuf>,
        format: SiemFormat,
        hostname: impl Into<String>,
    ) -> Result<Self, SiemError> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        Ok(Self {
            path,
            format,
            hostname: hostname.into(),
            write_lock: Mutex::new(()),
        })
    }
}

impl SiemTransport for FileSiemTransport {
    fn send_event(&self, event: &SiemEvent) -> Result<(), SiemError> {
        let formatted = event.format_as(self.format, &self.hostname)?;
        let _guard = self.write_lock.lock().map_err(|_| {
            SiemError::Transport("failed to acquire write lock for SIEM file export".into())
        })?;

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;

        writeln!(file, "{}", formatted)?;
        file.flush()?;
        Ok(())
    }
}

/// Unified dispatcher that forwards SIEM events to multiple configured transports.
pub struct SiemDispatcher {
    transports: Vec<Box<dyn SiemTransport>>,
}

impl SiemDispatcher {
    pub fn new(transports: Vec<Box<dyn SiemTransport>>) -> Self {
        Self { transports }
    }

    pub fn is_empty(&self) -> bool {
        self.transports.is_empty()
    }

    pub fn add_transport(&mut self, transport: Box<dyn SiemTransport>) {
        self.transports.push(transport);
    }

    /// Dispatches an event to all configured transports.
    /// Returns `Ok(())` if all transports succeed, or reports errors.
    pub fn export_event(&self, event: &SiemEvent) -> Result<(), SiemError> {
        let mut first_error = None;
        for transport in &self.transports {
            if let Err(e) = transport.send_event(event) {
                tracing::warn!("SIEM transport error: {e}");
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }
        if let Some(err) = first_error {
            Err(err)
        } else {
            Ok(())
        }
    }

    /// Initializes a [`SiemDispatcher`] from environment variables:
    /// - `TI_SIEM_SYSLOG_ADDR`: e.g. "127.0.0.1:514"
    /// - `TI_SIEM_SYSLOG_PROTOCOL`: "udp" or "tcp" (default "udp")
    /// - `TI_SIEM_FILE_PATH`: e.g. "./data/threat-intel/siem_events.log"
    /// - `TI_SIEM_FORMAT`: "cef", "ecs", or "syslog" (default "cef")
    /// - `TI_SIEM_HOSTNAME`: local hostname override (default "bsdm-threat-intel")
    pub fn from_env() -> Result<Self, SiemError> {
        let mut transports: Vec<Box<dyn SiemTransport>> = Vec::new();
        let default_format = std::env::var("TI_SIEM_FORMAT")
            .ok()
            .map(|f| SiemFormat::parse(&f))
            .unwrap_or(SiemFormat::Cef);

        let hostname = std::env::var("TI_SIEM_HOSTNAME")
            .ok()
            .filter(|h| !h.trim().is_empty())
            .unwrap_or_else(|| "bsdm-threat-intel".to_string());

        if let Ok(syslog_addr) = std::env::var("TI_SIEM_SYSLOG_ADDR") {
            let addr = syslog_addr.trim().to_string();
            if !addr.is_empty() {
                let protocol = std::env::var("TI_SIEM_SYSLOG_PROTOCOL")
                    .ok()
                    .map(|p| SyslogProtocol::parse(&p))
                    .unwrap_or(SyslogProtocol::Udp);
                transports.push(Box::new(SyslogTransport::new(
                    addr,
                    protocol,
                    default_format,
                    &hostname,
                )));
            }
        }

        if let Ok(file_path_str) = std::env::var("TI_SIEM_FILE_PATH") {
            let file_path_str = file_path_str.trim();
            if !file_path_str.is_empty() {
                let file_transport =
                    FileSiemTransport::new(file_path_str, default_format, &hostname)?;
                transports.push(Box::new(file_transport));
            }
        }

        Ok(Self::new(transports))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::{TcpListener, UdpSocket};

    fn sample_indicator() -> StoredIndicator {
        StoredIndicator {
            id: 1,
            value: "http://phish-bank.com/login".into(),
            normalized_value: "http://phish-bank.com/login".into(),
            domain: Some("phish-bank.com".into()),
            kind: IndicatorKind::Url,
            source: "openphish".into(),
            source_weight: 90,
            confidence_score: 95,
            collected_at: Utc::now(),
            reported_at: None,
            expires_at: Utc::now() + chrono::Duration::days(7),
            reference: Some("REF-123".into()),
            tags: vec!["phishing".into(), "banking".into()],
            is_bogon: false,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            hit_count: 3,
        }
    }

    #[test]
    fn test_cef_formatting() {
        let ind = sample_indicator();
        let event = SiemEvent::from_stored(&ind, SiemEventAction::Detected);
        let cef = event.to_cef();

        let expected = format!(
            "CEF:0|BSDM-Proxy|ThreatIntel|{}|IOC_DETECTED|",
            env!("CARGO_PKG_VERSION")
        );
        assert!(cef.starts_with(&expected));
        assert!(cef.contains("cs1=openphish"));
        assert!(cef.contains("cn1=95"));
        assert!(cef.contains("request=http://phish-bank.com/login"));
        assert!(cef.contains("shost=phish-bank.com"));
    }

    #[test]
    fn test_ecs_formatting() {
        let ind = sample_indicator();
        let event = SiemEvent::from_stored(&ind, SiemEventAction::Blocked);
        let ecs = event.to_ecs_json();

        assert_eq!(ecs["event"]["action"], "ioc_blocked");
        assert_eq!(ecs["threat"]["indicator"]["type"], "url");
        assert_eq!(ecs["threat"]["indicator"]["confidence"], 95);
        assert_eq!(ecs["threat"]["indicator"]["provider"], "openphish");
    }

    #[test]
    fn test_syslog_rfc5424() {
        let ind = sample_indicator();
        let event = SiemEvent::from_stored(&ind, SiemEventAction::Detected);
        let syslog = event.to_syslog_rfc5424("proxy-node-01");

        assert!(syslog.starts_with("<134>1 "));
        assert!(syslog.contains("proxy-node-01 bsdm-threat-intel"));
        assert!(syslog.contains("CEF:0|BSDM-Proxy|ThreatIntel|"));
    }

    #[test]
    fn test_syslog_udp_transport() {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = receiver.local_addr().unwrap().port();
        let target_addr = format!("127.0.0.1:{}", port);

        let transport = SyslogTransport::new(
            target_addr,
            SyslogProtocol::Udp,
            SiemFormat::Cef,
            "test-host",
        );

        let ind = sample_indicator();
        let event = SiemEvent::from_stored(&ind, SiemEventAction::Detected);
        transport.send_event(&event).unwrap();

        let mut buf = [0u8; 2048];
        let (len, _) = receiver.recv_from(&mut buf).unwrap();
        let received = std::str::from_utf8(&buf[..len]).unwrap();

        let expected = format!(
            "CEF:0|BSDM-Proxy|ThreatIntel|{}|IOC_DETECTED|",
            env!("CARGO_PKG_VERSION")
        );
        assert!(received.starts_with(&expected));
        assert!(received.contains("openphish"));
    }

    #[test]
    fn test_syslog_tcp_transport() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let target_addr = format!("127.0.0.1:{}", port);

        let transport = SyslogTransport::new(
            target_addr,
            SyslogProtocol::Tcp,
            SiemFormat::SyslogRfc5424,
            "tcp-proxy-node",
        );

        let ind = sample_indicator();
        let event = SiemEvent::from_stored(&ind, SiemEventAction::Blocked);

        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut data = Vec::new();
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).unwrap();
            data.extend_from_slice(&buf[..n]);
            String::from_utf8(data).unwrap()
        });

        transport.send_event(&event).unwrap();
        let received = handle.join().unwrap();

        assert!(received.starts_with("<134>1 "));
        assert!(received.contains("tcp-proxy-node bsdm-threat-intel"));
        assert!(received.ends_with('\n'));
    }

    #[test]
    fn test_file_siem_transport_and_dispatcher() {
        let dir = tempfile::tempdir().unwrap();
        let log_file = dir.path().join("siem_events.log");

        let file_transport =
            FileSiemTransport::new(&log_file, SiemFormat::EcsJson, "file-host").unwrap();

        let dispatcher = SiemDispatcher::new(vec![Box::new(file_transport)]);
        assert!(!dispatcher.is_empty());

        let ind = sample_indicator();
        let event = SiemEvent::from_stored(&ind, SiemEventAction::Unblocked);

        dispatcher.export_event(&event).unwrap();

        let content = std::fs::read_to_string(&log_file).unwrap();
        assert!(!content.is_empty());
        let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(parsed["event"]["action"], "ioc_unblocked");
        assert_eq!(parsed["threat"]["indicator"]["provider"], "openphish");
    }
}
