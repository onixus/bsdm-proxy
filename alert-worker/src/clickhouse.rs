//! Minimal ClickHouse HTTP query client with latency and resource guards.

use crate::config::Config;
use reqwest::Client;
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// Classified query failure. `kind()` is a bounded Prometheus label value.
#[derive(Debug)]
pub enum QueryError {
    /// Client-side deadline (`ALERT_CLICKHOUSE_TIMEOUT_MS`) or server-side
    /// `max_execution_time` elapsed.
    Timeout(String),
    /// ClickHouse answered with a non-2xx status.
    Http { status: u16, body: String },
    /// Connect / TLS / read failure.
    Transport(String),
    /// Malformed JSONEachRow payload.
    Parse(String),
}

impl QueryError {
    pub fn kind(&self) -> &'static str {
        match self {
            QueryError::Timeout(_) => "timeout",
            QueryError::Http { .. } => "http",
            QueryError::Transport(_) => "transport",
            QueryError::Parse(_) => "parse",
        }
    }
}

impl std::fmt::Display for QueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QueryError::Timeout(msg) => write!(f, "timeout: {msg}"),
            QueryError::Http { status, body } => {
                write!(f, "HTTP {status}: {}", truncate(body, 512))
            }
            QueryError::Transport(msg) => write!(f, "transport: {msg}"),
            QueryError::Parse(msg) => write!(f, "parse: {msg}"),
        }
    }
}

impl std::error::Error for QueryError {}

/// Successful query result together with its measured wall-clock latency.
pub struct QueryOutcome {
    pub rows: Vec<serde_json::Value>,
    pub elapsed: Duration,
}

pub struct ClickHouseClient {
    client: Client,
    url: String,
    user: Option<String>,
    password: Option<String>,
    timeout: Duration,
    max_execution_secs: u64,
    max_result_rows: u64,
    query_guards: bool,
}

impl ClickHouseClient {
    pub fn new(config: &Config) -> Result<Self, Box<dyn std::error::Error>> {
        // No global timeout: every request carries its own deadline so that
        // `ping` and rule queries can be bounded independently.
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .build()?;
        Ok(Self {
            client,
            url: config.clickhouse_url.trim_end_matches('/').to_string(),
            user: config.clickhouse_user.clone(),
            password: config.clickhouse_password.clone(),
            timeout: config.clickhouse_timeout,
            max_execution_secs: config.clickhouse_max_execution_secs,
            max_result_rows: config.clickhouse_max_result_rows,
            query_guards: config.clickhouse_query_guards,
        })
    }

    pub async fn ping(&self) -> Result<(), Box<dyn std::error::Error>> {
        let ping_url = format!("{}/ping", self.url);
        let mut req = self.client.get(&ping_url).timeout(self.timeout);
        if let (Some(user), Some(password)) = (&self.user, &self.password) {
            req = req.basic_auth(user, Some(password));
        }
        let response = req.send().await?;
        if !response.status().is_success() {
            return Err(format!("ClickHouse ping failed: HTTP {}", response.status()).into());
        }
        if !self.query_guards {
            warn!(
                "ALERT_CLICKHOUSE_QUERY_GUARDS=false: server-side max_execution_time \
                 and readonly guards are not sent; only the client deadline applies"
            );
        }
        info!(
            timeout_ms = self.timeout.as_millis() as u64,
            max_execution_secs = self.max_execution_secs,
            max_result_rows = self.max_result_rows,
            "ClickHouse reachable at {}",
            self.url
        );
        Ok(())
    }

    /// Per-query settings sent as HTTP parameters. Rule SQL already carries its
    /// own `FORMAT JSONEachRow`.
    ///
    /// `readonly=2` rejects any INSERT/DDL that could reach the endpoint while
    /// still allowing these settings to be overridden; `max_execution_time`
    /// bounds server-side work, and `result_overflow_mode=break` truncates an
    /// oversized result set instead of failing the whole cycle. Empty when
    /// `ALERT_CLICKHOUSE_QUERY_GUARDS=false`, for ClickHouse users whose
    /// profile pins `readonly=1` and therefore rejects any setting override.
    fn query_settings(&self) -> Vec<(&'static str, String)> {
        if !self.query_guards {
            return Vec::new();
        }
        vec![
            ("readonly", "2".to_string()),
            ("max_execution_time", self.max_execution_secs.to_string()),
            ("max_result_rows", self.max_result_rows.to_string()),
            ("result_overflow_mode", "break".to_string()),
        ]
    }

    pub async fn query_json_each_row(&self, sql: &str) -> Result<QueryOutcome, QueryError> {
        let started = Instant::now();
        let mut req = self
            .client
            .post(&self.url)
            .timeout(self.timeout)
            .query(&[("query", sql)])
            .query(&self.query_settings())
            .body("");
        if let (Some(user), Some(password)) = (&self.user, &self.password) {
            req = req.basic_auth(user, Some(password));
        }
        let response = req.send().await.map_err(classify_reqwest_error)?;
        let status = response.status();
        let body = response.text().await.map_err(classify_reqwest_error)?;
        if !status.is_success() {
            return Err(classify_status(status.as_u16(), body));
        }
        let rows = parse_json_each_row(&body).map_err(|e| QueryError::Parse(e.to_string()))?;
        Ok(QueryOutcome {
            rows,
            elapsed: started.elapsed(),
        })
    }
}

fn classify_reqwest_error(err: reqwest::Error) -> QueryError {
    if err.is_timeout() {
        QueryError::Timeout(err.to_string())
    } else {
        QueryError::Transport(err.to_string())
    }
}

/// ClickHouse reports a server-side `max_execution_time` breach as
/// `TIMEOUT_EXCEEDED` (code 159) with HTTP 500 — count it as a timeout so the
/// latency guard reacts to it exactly like a client-side deadline.
fn classify_status(status: u16, body: String) -> QueryError {
    if body.contains("TIMEOUT_EXCEEDED") || body.contains("Code: 159") {
        return QueryError::Timeout(truncate(&body, 512));
    }
    QueryError::Http { status, body }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut cut = max;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}…", &s[..cut])
}

pub fn parse_json_each_row(
    body: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let mut rows = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        rows.push(serde_json::from_str(line)?);
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_json_each_row() {
        let body = r#"{"client_ip":"10.0.0.1","value":12}
{"client_ip":"10.0.0.2","value":3}
"#;
        let rows = parse_json_each_row(body).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["value"], 12);
    }

    #[test]
    fn server_side_timeout_is_classified_as_timeout() {
        let err = classify_status(
            500,
            "Code: 159. DB::Exception: Timeout exceeded: TIMEOUT_EXCEEDED".to_string(),
        );
        assert_eq!(err.kind(), "timeout");
    }

    #[test]
    fn other_server_errors_stay_http() {
        let err = classify_status(403, "Code: 497. Not enough privileges".to_string());
        assert_eq!(err.kind(), "http");
    }

    #[test]
    fn query_settings_are_read_only_and_bounded() {
        let mut config = Config::for_test();
        config.clickhouse_max_execution_secs = 7;
        config.clickhouse_max_result_rows = 1234;
        let client = ClickHouseClient::new(&config).unwrap();
        let settings = client.query_settings();
        let get = |k: &str| {
            settings
                .iter()
                .find(|(name, _)| *name == k)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(get("readonly"), Some("2"));
        assert_eq!(get("max_execution_time"), Some("7"));
        assert_eq!(get("max_result_rows"), Some("1234"));
        assert_eq!(get("result_overflow_mode"), Some("break"));
    }

    #[test]
    fn query_guards_can_be_disabled_for_readonly_profiles() {
        let mut config = Config::for_test();
        config.clickhouse_query_guards = false;
        let client = ClickHouseClient::new(&config).unwrap();
        assert!(client.query_settings().is_empty());
    }

    #[test]
    fn truncate_respects_char_boundaries() {
        let s = "ошибка ClickHouse";
        let out = truncate(s, 5);
        assert!(out.ends_with('…'));
        assert!(s.starts_with(out.trim_end_matches('…')));
    }
}
