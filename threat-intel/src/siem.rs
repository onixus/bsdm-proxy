//! TASK-TI-030: Enterprise SIEM Integration.
//!
//! Provides formatting and export of threat intelligence detections and IOC lifecycle
//! events into industry-standard SIEM formats:
//! - CEF (Common Event Format - ArcSight / QRadar / Sentinel / Splunk)
//! - ECS (Elastic Common Schema JSON - Elastic Security / Wazuh)
//! - Syslog RFC 5424 formatted messages

use crate::indicator::IndicatorKind;
use crate::normalizer::NormalizedIndicator;
use crate::storage::StoredIndicator;
use chrono::Utc;
use prometheus::IntCounterVec;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::path::PathBuf;
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::Mutex;
use std::thread::JoinHandle;
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
    pub const ALL: [SiemEventAction; 4] = [
        SiemEventAction::Detected,
        SiemEventAction::Blocked,
        SiemEventAction::Unblocked,
        SiemEventAction::Expired,
    ];

    /// Short name used in `TI_SIEM_EVENTS` and in the metric `action` label.
    pub fn name(&self) -> &'static str {
        match self {
            SiemEventAction::Detected => "detected",
            SiemEventAction::Blocked => "blocked",
            SiemEventAction::Unblocked => "unblocked",
            SiemEventAction::Expired => "expired",
        }
    }

    fn bit(&self) -> u8 {
        1 << (*self as u8)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            SiemEventAction::Detected => "ioc_detected",
            SiemEventAction::Blocked => "ioc_blocked",
            SiemEventAction::Unblocked => "ioc_unblocked",
            SiemEventAction::Expired => "ioc_expired",
        }
    }
}

/// Which [`SiemEventAction`]s are delivered (`TI_SIEM_EVENTS`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SiemEventFilter(u8);

impl Default for SiemEventFilter {
    fn default() -> Self {
        Self::all()
    }
}

impl SiemEventFilter {
    pub fn all() -> Self {
        Self(SiemEventAction::ALL.iter().fold(0, |m, a| m | a.bit()))
    }

    /// Parses a comma-separated list: `detected`, `blocked`, `unblocked`,
    /// `expired` (the `ioc_` prefixed wire names are accepted too) or `all`.
    /// An empty value selects everything; an unknown name is an error, so a
    /// typo cannot silently mute a class of events.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let mut mask = 0u8;
        for token in raw.split(',').map(|t| t.trim().to_ascii_lowercase()) {
            if token.is_empty() {
                continue;
            }
            if token == "all" {
                return Ok(Self::all());
            }
            let name = token.strip_prefix("ioc_").unwrap_or(&token);
            let action = SiemEventAction::ALL
                .into_iter()
                .find(|a| a.name() == name)
                .ok_or_else(|| {
                    format!(
                        "unknown SIEM event '{token}' (expected detected, blocked, unblocked, \
                         expired or all)"
                    )
                })?;
            mask |= action.bit();
        }
        Ok(if mask == 0 { Self::all() } else { Self(mask) })
    }

    pub fn allows(&self, action: SiemEventAction) -> bool {
        self.0 & action.bit() != 0
    }

    pub fn names(&self) -> Vec<&'static str> {
        SiemEventAction::ALL
            .into_iter()
            .filter(|a| self.allows(*a))
            .map(|a| a.name())
            .collect()
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

    /// Builds an event for an indicator that has not been read back from
    /// storage (a freshly inserted feed entry or a SOAR block).
    pub fn from_normalized(
        indicator: &NormalizedIndicator,
        confidence_score: u8,
        action: SiemEventAction,
    ) -> Self {
        let severity = ((confidence_score as f32 / 10.0).round() as u8).clamp(1, 10);
        Self {
            timestamp: Utc::now(),
            action,
            indicator_value: indicator.normalized_value.clone(),
            indicator_kind: indicator.kind,
            domain: indicator.domain.clone(),
            confidence_score,
            source: indicator.source.clone(),
            severity,
            message: format!(
                "Threat IOC [{}] from feed [{}] with confidence {}/100",
                indicator.normalized_value, indicator.source, confidence_score
            ),
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
///
/// The socket is opened on first use and reused; a failed TCP write drops the
/// connection and retries once on a fresh one, so a restarted collector does
/// not cost more than the event in flight.
pub struct SyslogTransport {
    addr: String,
    protocol: SyslogProtocol,
    format: SiemFormat,
    hostname: String,
    udp: Mutex<Option<(UdpSocket, SocketAddr)>>,
    tcp: Mutex<Option<TcpStream>>,
}

const SYSLOG_TCP_TIMEOUT: Duration = Duration::from_secs(3);

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
            udp: Mutex::new(None),
            tcp: Mutex::new(None),
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
        let mut slot = self
            .udp
            .lock()
            .map_err(|_| SiemError::Transport("syslog UDP socket lock poisoned".into()))?;
        if slot.is_none() {
            let target = self.resolve_target()?;
            let bind = if target.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            *slot = Some((UdpSocket::bind(bind)?, target));
        }
        let (socket, target) = slot.as_ref().expect("socket initialised above");
        if let Err(e) = socket.send_to(formatted.as_bytes(), *target) {
            // Re-resolve on the next event: the collector may have moved.
            *slot = None;
            return Err(e.into());
        }
        Ok(())
    }

    fn send_tcp(&self, formatted: &str) -> Result<(), SiemError> {
        let mut payload = formatted.to_string();
        if !payload.ends_with('\n') {
            payload.push('\n');
        }
        let mut slot = self
            .tcp
            .lock()
            .map_err(|_| SiemError::Transport("syslog TCP stream lock poisoned".into()))?;
        let reused = slot.is_some();
        for attempt in 0..2 {
            if slot.is_none() {
                let target = self.resolve_target()?;
                let stream = TcpStream::connect_timeout(&target, SYSLOG_TCP_TIMEOUT)?;
                stream.set_write_timeout(Some(SYSLOG_TCP_TIMEOUT))?;
                *slot = Some(stream);
            }
            let stream = slot.as_mut().expect("stream initialised above");
            match stream
                .write_all(payload.as_bytes())
                .and_then(|_| stream.flush())
            {
                Ok(()) => return Ok(()),
                Err(e) => {
                    *slot = None;
                    // Only a reused connection may have gone stale; a fresh
                    // one failing is a real delivery error.
                    if attempt == 1 || !reused {
                        return Err(e.into());
                    }
                }
            }
        }
        unreachable!("the second attempt always returns")
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

    /// Builds the transports configured by `TI_SIEM_SYSLOG_ADDR` and
    /// `TI_SIEM_FILE_PATH`; both may be set at once.
    pub fn from_config(config: &crate::config::Config) -> Result<Self, SiemError> {
        let format = SiemFormat::parse(&config.siem_format);
        let mut transports: Vec<Box<dyn SiemTransport>> = Vec::new();
        if let Some(addr) = &config.siem_syslog_addr {
            transports.push(Box::new(SyslogTransport::new(
                addr.clone(),
                SyslogProtocol::parse(&config.siem_syslog_protocol),
                format,
                &config.siem_hostname,
            )));
        }
        if let Some(path) = &config.siem_file_path {
            transports.push(Box::new(FileSiemTransport::new(
                path,
                format,
                &config.siem_hostname,
            )?));
        }
        Ok(Self::new(transports))
    }
}

/// Non-blocking front end for [`SiemDispatcher`].
///
/// Delivery runs on a dedicated thread behind a bounded queue, so a slow or
/// unreachable SIEM never stalls feed collection or a SOAR request. When the
/// queue is full the event is dropped and counted
/// (`threat_intel_siem_events_total{outcome="dropped"}`) rather than
/// buffered without bound: the first collection on an empty database can
/// produce hundreds of thousands of `detected` events.
pub struct SiemEmitter {
    filter: SiemEventFilter,
    outcomes: Option<IntCounterVec>,
    tx: Mutex<Option<SyncSender<SiemEvent>>>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl SiemEmitter {
    /// An emitter that accepts and discards everything.
    pub fn disabled() -> Self {
        Self {
            filter: SiemEventFilter(0),
            outcomes: None,
            tx: Mutex::new(None),
            worker: Mutex::new(None),
        }
    }

    /// Starts the delivery thread. An empty dispatcher yields
    /// [`SiemEmitter::disabled`], so callers can emit unconditionally.
    pub fn start(
        dispatcher: SiemDispatcher,
        filter: SiemEventFilter,
        queue_capacity: usize,
        outcomes: Option<IntCounterVec>,
    ) -> std::io::Result<Self> {
        if dispatcher.is_empty() {
            return Ok(Self::disabled());
        }
        let (tx, rx) = mpsc::sync_channel::<SiemEvent>(queue_capacity.max(1));
        let worker_outcomes = outcomes.clone();
        let worker = std::thread::Builder::new()
            .name("siem-dispatch".into())
            .spawn(move || {
                for event in rx {
                    let outcome = match dispatcher.export_event(&event) {
                        Ok(()) => "sent",
                        Err(_) => "failed",
                    };
                    if let Some(c) = &worker_outcomes {
                        c.with_label_values(&[event.action.name(), outcome]).inc();
                    }
                }
            })?;
        Ok(Self {
            filter,
            outcomes,
            tx: Mutex::new(Some(tx)),
            worker: Mutex::new(Some(worker)),
        })
    }

    pub fn is_enabled(&self) -> bool {
        self.tx.lock().map(|tx| tx.is_some()).unwrap_or(false)
    }

    pub fn wants(&self, action: SiemEventAction) -> bool {
        self.filter.allows(action) && self.is_enabled()
    }

    /// Queues `event` if its action is selected; never blocks.
    pub fn emit(&self, event: SiemEvent) {
        if !self.filter.allows(event.action) {
            return;
        }
        let Ok(guard) = self.tx.lock() else {
            return;
        };
        let Some(tx) = guard.as_ref() else {
            return;
        };
        let action = event.action;
        match tx.try_send(event) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                if let Some(c) = &self.outcomes {
                    c.with_label_values(&[action.name(), "dropped"]).inc();
                }
            }
            Err(TrySendError::Disconnected(_)) => {}
        }
    }

    /// Stops accepting events and waits for the queue to drain. Needed before
    /// a `TI_RUN_ONCE` process exits, otherwise queued events are lost.
    pub fn close(&self) {
        if let Ok(mut tx) = self.tx.lock() {
            tx.take();
        }
        let worker = self.worker.lock().ok().and_then(|mut w| w.take());
        if let Some(worker) = worker {
            let _ = worker.join();
        }
    }
}

impl Drop for SiemEmitter {
    fn drop(&mut self) {
        self.close();
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

    #[test]
    fn event_filter_parses_names_and_rejects_typos() {
        let all = SiemEventFilter::all();
        assert_eq!(SiemEventFilter::parse("").unwrap(), all);
        assert_eq!(SiemEventFilter::parse(" all ").unwrap(), all);

        let some = SiemEventFilter::parse("blocked, IOC_UNBLOCKED").unwrap();
        assert!(some.allows(SiemEventAction::Blocked));
        assert!(some.allows(SiemEventAction::Unblocked));
        assert!(!some.allows(SiemEventAction::Detected));
        assert!(!some.allows(SiemEventAction::Expired));
        assert_eq!(some.names(), vec!["blocked", "unblocked"]);

        let err = SiemEventFilter::parse("detected,blokced").unwrap_err();
        assert!(err.contains("blokced"), "{err}");
    }

    fn outcome(counter: &IntCounterVec, action: &str, outcome: &str) -> u64 {
        counter.with_label_values(&[action, outcome]).get()
    }

    fn outcomes_counter() -> IntCounterVec {
        IntCounterVec::new(
            prometheus::Opts::new("siem_events_test", "test"),
            &["action", "outcome"],
        )
        .unwrap()
    }

    #[test]
    fn emitter_delivers_selected_events_and_drains_on_close() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("siem.log");
        let dispatcher = SiemDispatcher::new(vec![Box::new(
            FileSiemTransport::new(&log, SiemFormat::Cef, "gw").unwrap(),
        )]);
        let counter = outcomes_counter();
        let emitter = SiemEmitter::start(
            dispatcher,
            SiemEventFilter::parse("blocked,expired").unwrap(),
            16,
            Some(counter.clone()),
        )
        .unwrap();
        assert!(emitter.wants(SiemEventAction::Blocked));
        assert!(!emitter.wants(SiemEventAction::Detected));

        let ind = sample_indicator();
        for action in SiemEventAction::ALL {
            emitter.emit(SiemEvent::from_stored(&ind, action));
        }
        emitter.close();

        let content = std::fs::read_to_string(&log).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2, "{content}");
        assert!(lines[0].contains("|IOC_BLOCKED|"));
        assert!(lines[1].contains("|IOC_EXPIRED|"));
        assert_eq!(outcome(&counter, "blocked", "sent"), 1);
        assert_eq!(outcome(&counter, "detected", "sent"), 0);

        // Closed: further events are ignored instead of panicking.
        emitter.emit(SiemEvent::from_stored(&ind, SiemEventAction::Blocked));
        assert!(!emitter.is_enabled());
    }

    /// Holds every delivery until the test releases it.
    struct GatedTransport {
        started: Mutex<mpsc::Sender<()>>,
        release: Mutex<mpsc::Receiver<()>>,
    }

    impl SiemTransport for GatedTransport {
        fn send_event(&self, _event: &SiemEvent) -> Result<(), SiemError> {
            let _ = self.started.lock().unwrap().send(());
            let _ = self.release.lock().unwrap().recv();
            Ok(())
        }
    }

    #[test]
    fn emitter_drops_and_counts_when_the_queue_is_full() {
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let dispatcher = SiemDispatcher::new(vec![Box::new(GatedTransport {
            started: Mutex::new(started_tx),
            release: Mutex::new(release_rx),
        })]);
        let counter = outcomes_counter();
        let emitter =
            SiemEmitter::start(dispatcher, SiemEventFilter::all(), 1, Some(counter.clone()))
                .unwrap();
        let event = SiemEvent::from_stored(&sample_indicator(), SiemEventAction::Detected);

        emitter.emit(event.clone()); // taken by the worker, which then blocks
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        emitter.emit(event.clone()); // fills the single queue slot
        emitter.emit(event.clone()); // no room: dropped, emit() must not block
        assert_eq!(outcome(&counter, "detected", "dropped"), 1);

        release_tx.send(()).unwrap();
        release_tx.send(()).unwrap();
        emitter.close();
        assert_eq!(outcome(&counter, "detected", "sent"), 2);
    }

    #[test]
    fn syslog_tcp_reuses_the_connection_and_reconnects_after_a_drop() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let transport =
            SyslogTransport::new(addr.to_string(), SyslogProtocol::Tcp, SiemFormat::Cef, "gw");
        let ind = sample_indicator();

        // First connection: read two events, then hang up.
        let server = std::thread::spawn(move || {
            let read_lines = |stream: TcpStream, n: usize| {
                let mut reader = std::io::BufReader::new(stream);
                (0..n)
                    .map(|_| {
                        let mut line = String::new();
                        std::io::BufRead::read_line(&mut reader, &mut line).unwrap();
                        line
                    })
                    .collect::<Vec<_>>()
            };
            let (first, _) = listener.accept().unwrap();
            let got = read_lines(first, 2);
            let (second, _) = listener.accept().unwrap();
            (got, read_lines(second, 1))
        });

        transport
            .send_event(&SiemEvent::from_stored(&ind, SiemEventAction::Detected))
            .unwrap();
        transport
            .send_event(&SiemEvent::from_stored(&ind, SiemEventAction::Blocked))
            .unwrap();
        // Let the server read both lines and close the first connection.
        std::thread::sleep(Duration::from_millis(200));
        // The first write into a peer-closed socket can still "succeed"; keep
        // sending until the transport notices and redials.
        let mut delivered = false;
        for _ in 0..3 {
            transport
                .send_event(&SiemEvent::from_stored(&ind, SiemEventAction::Expired))
                .unwrap();
            if server.is_finished() {
                delivered = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        assert!(delivered, "transport never reconnected");
        let (first, second) = server.join().unwrap();
        assert!(first[0].contains("|IOC_DETECTED|"));
        assert!(first[1].contains("|IOC_BLOCKED|"));
        assert!(second[0].contains("|IOC_EXPIRED|"));
    }
}
