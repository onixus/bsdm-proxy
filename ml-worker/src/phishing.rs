//! M5.3 lexical phishing scoring on domains.
//!
//! Combines URL/domain lexical heuristics with weak labels from PhishTank / UT1
//! (`categories`, `threat_sources` in `http_cache`).

use crate::config::Config;
use crate::scoring::{severity_for, ScoreResult};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const MODEL_PHISHING: &str = "phishing_lexical_v0";

/// Aggregated per-domain window from ClickHouse.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainPhishingFeatures {
    pub window_start: DateTime<Utc>,
    pub window_secs: u32,
    pub domain: String,
    pub request_count: u64,
    pub unique_urls: u64,
    pub weak_label_phishing: u64,
    pub weak_label_phishtank: u64,
    pub weak_label_ut1: u64,
    pub deny_count: u64,
    pub suspicious_path_hits: u64,
    pub avg_path_extra_len: f64,
    pub extracted_at: DateTime<Utc>,
}

/// Pure lexical signals derived from the domain string (computed in Rust).
#[derive(Debug, Clone, Serialize)]
pub struct LexicalSignals {
    pub domain_len: u64,
    pub hyphen_count: u64,
    pub digit_count: u64,
    pub subdomain_depth: u64,
    pub entropy: f64,
    pub suspicious_keyword: bool,
    pub is_ip_hostname: bool,
}

impl DomainPhishingFeatures {
    pub fn to_insert_json(&self, lexical: &LexicalSignals) -> serde_json::Value {
        serde_json::json!({
            "window_start": self.window_start.format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
            "window_secs": self.window_secs,
            "domain": self.domain,
            "request_count": self.request_count,
            "unique_urls": self.unique_urls,
            "weak_label_phishing": self.weak_label_phishing,
            "weak_label_phishtank": self.weak_label_phishtank,
            "weak_label_ut1": self.weak_label_ut1,
            "deny_count": self.deny_count,
            "suspicious_path_hits": self.suspicious_path_hits,
            "avg_path_extra_len": self.avg_path_extra_len,
            "domain_len": lexical.domain_len,
            "hyphen_count": lexical.hyphen_count,
            "digit_count": lexical.digit_count,
            "subdomain_depth": lexical.subdomain_depth,
            "entropy": lexical.entropy,
            "suspicious_keyword": if lexical.suspicious_keyword { 1 } else { 0 },
            "is_ip_hostname": if lexical.is_ip_hostname { 1 } else { 0 },
            "extracted_at": self.extracted_at.format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
        })
    }

    pub fn score_payload(&self, lexical: &LexicalSignals) -> serde_json::Value {
        serde_json::json!({
            "domain": self.domain,
            "request_count": self.request_count,
            "weak_labels": {
                "phishing_category": self.weak_label_phishing,
                "phishtank": self.weak_label_phishtank,
                "ut1": self.weak_label_ut1,
            },
            "lexical": lexical,
            "suspicious_path_hits": self.suspicious_path_hits,
            "avg_path_extra_len": self.avg_path_extra_len,
        })
    }
}

/// Shannon entropy (bits) over ASCII bytes of `s`.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    let bytes = s.as_bytes();
    for &b in bytes {
        freq[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    let mut entropy = 0.0_f64;
    for &c in freq.iter().filter(|&&x| x > 0) {
        let p = c as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

const SUSPICIOUS_KEYWORDS: &[&str] = &[
    "login",
    "signin",
    "verify",
    "secure",
    "account",
    "update",
    "banking",
    "password",
    "wallet",
    "confirm",
    "support",
    "paypal",
    "appleid",
    "microsoft",
];

/// Extract lexical signals from a hostname / domain label.
pub fn lexical_signals(domain: &str) -> LexicalSignals {
    let d = domain.trim().to_lowercase();
    let host = d.split('/').next().unwrap_or(&d);
    let host = host.split(':').next().unwrap_or(host);

    let domain_len = host.len() as u64;
    let hyphen_count = host.bytes().filter(|&b| b == b'-').count() as u64;
    let digit_count = host.bytes().filter(|b| b.is_ascii_digit()).count() as u64;
    let subdomain_depth = host.bytes().filter(|&b| b == b'.').count() as u64;

    let left_label = host.split('.').next().unwrap_or(host);
    let entropy = shannon_entropy(left_label);

    let suspicious_keyword = SUSPICIOUS_KEYWORDS
        .iter()
        .any(|kw| host.contains(kw) || left_label.contains(kw));

    let is_ip_hostname = looks_like_ipv4(host);

    LexicalSignals {
        domain_len,
        hyphen_count,
        digit_count,
        subdomain_depth,
        entropy,
        suspicious_keyword,
        is_ip_hostname,
    }
}

fn looks_like_ipv4(host: &str) -> bool {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| p.parse::<u8>().is_ok())
}

/// Lexical-only heuristic in \[0, 1\].
pub fn lexical_heuristic(lex: &LexicalSignals, path_hits: u64, request_count: u64) -> f64 {
    let mut s = 0.0_f64;
    if lex.domain_len > 30 {
        s += 0.12;
    }
    if lex.subdomain_depth >= 3 {
        s += 0.18;
    }
    let hyphen_ratio = if lex.domain_len > 0 {
        lex.hyphen_count as f64 / lex.domain_len as f64
    } else {
        0.0
    };
    if hyphen_ratio > 0.08 {
        s += 0.14;
    }
    let digit_ratio = if lex.domain_len > 0 {
        lex.digit_count as f64 / lex.domain_len as f64
    } else {
        0.0
    };
    if digit_ratio > 0.15 {
        s += 0.12;
    }
    if lex.entropy > 3.5 {
        s += 0.16;
    }
    if lex.suspicious_keyword {
        s += 0.22;
    }
    if lex.is_ip_hostname {
        s += 0.28;
    }
    let path_ratio = if request_count > 0 {
        path_hits as f64 / request_count as f64
    } else {
        0.0
    };
    if path_ratio > 0.3 {
        s += 0.15;
    }
    s.clamp(0.0, 1.0)
}

/// Phishing score blending weak labels (PhishTank / UT1 / category) with lexical heuristics.
pub fn phishing_lexical_v0(features: &DomainPhishingFeatures, lexical: &LexicalSignals) -> f64 {
    let req = features.request_count.max(1) as f64;
    let weak_hits = (features.weak_label_phishing
        + features.weak_label_phishtank
        + features.weak_label_ut1) as f64;
    let weak_ratio = (weak_hits / req).min(1.0);

    let lex = lexical_heuristic(
        lexical,
        features.suspicious_path_hits,
        features.request_count,
    );

    if weak_hits > 0.0 {
        // Weak labels from PhishTank / UT1 / phishing category are strong priors.
        let weak_score = 0.72 + 0.28 * weak_ratio;
        if features.weak_label_phishtank > 0 {
            return (0.65 * weak_score + 0.35 * lex).clamp(0.85, 1.0);
        }
        return (0.55 * weak_score + 0.45 * lex).clamp(0.75, 1.0);
    }

    lex
}

pub fn score_domain(features: &DomainPhishingFeatures, threshold: f64) -> ScoreResult {
    let lexical = lexical_signals(&features.domain);
    let score = phishing_lexical_v0(features, &lexical);
    let features_json = serde_json::to_string(&features.score_payload(&lexical))
        .unwrap_or_else(|_| "{}".into());

    ScoreResult {
        scored_at: Utc::now(),
        entity_type: "domain".to_string(),
        entity_id: features.domain.clone(),
        window_start: features.window_start,
        model: MODEL_PHISHING.to_string(),
        score,
        severity: severity_for(score, threshold).to_string(),
        features_json,
    }
}

/// SQL to aggregate domain windows with weak-label counts from `http_cache`.
pub fn extract_sql(config: &Config) -> String {
    let lookback = config.lookback.as_secs();
    let min_req = config.min_requests;
    let table = config.fq_source();

    format!(
        r#"
SELECT
  min(ts) AS window_start,
  toUInt32({lookback}) AS window_secs,
  domain,
  count() AS request_count,
  uniqExact(url) AS unique_urls,
  countIf(has(categories, 'phishing')) AS weak_label_phishing,
  countIf(has(threat_sources, 'phishtank')) AS weak_label_phishtank,
  countIf(has(threat_sources, 'ut1')) AS weak_label_ut1,
  countIf(acl_action = 'deny' OR cache_status = 'DENY') AS deny_count,
  countIf(
    match(lower(url), '(login|signin|verify|secure|account|update|banking|password|wallet|confirm)')
  ) AS suspicious_path_hits,
  avg(greatest(toInt64(length(url)) - toInt64(length(domain)) - 8, 0)) AS avg_path_extra_len,
  now64(3) AS extracted_at
FROM {table}
WHERE ts >= now() - INTERVAL {lookback} SECOND
  AND domain != ''
GROUP BY domain
HAVING request_count >= {min_req}
FORMAT JSONEachRow
"#
    )
}

pub fn features_from_row(
    row: &serde_json::Value,
) -> Result<DomainPhishingFeatures, Box<dyn std::error::Error>> {
    Ok(DomainPhishingFeatures {
        window_start: parse_ch_datetime(row.get("window_start"))?,
        window_secs: as_u64(row.get("window_secs"))? as u32,
        domain: as_string(row.get("domain"))?,
        request_count: as_u64(row.get("request_count"))?,
        unique_urls: as_u64(row.get("unique_urls"))?,
        weak_label_phishing: as_u64(row.get("weak_label_phishing"))?,
        weak_label_phishtank: as_u64(row.get("weak_label_phishtank"))?,
        weak_label_ut1: as_u64(row.get("weak_label_ut1"))?,
        deny_count: as_u64(row.get("deny_count"))?,
        suspicious_path_hits: as_u64(row.get("suspicious_path_hits"))?,
        avg_path_extra_len: as_f64(row.get("avg_path_extra_len")).unwrap_or(0.0),
        extracted_at: parse_ch_datetime(row.get("extracted_at")).unwrap_or_else(|_| Utc::now()),
    })
}

fn parse_ch_datetime(v: Option<&serde_json::Value>) -> Result<DateTime<Utc>, String> {
    let s = v
        .and_then(|x| x.as_str())
        .ok_or_else(|| "missing datetime".to_string())?;
    let normalized = if s.contains('T') {
        s.to_string()
    } else {
        s.replace(' ', "T") + "Z"
    };
    DateTime::parse_from_rfc3339(&normalized)
        .map(|dt| dt.with_timezone(&Utc))
        .or_else(|_| {
            chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.3f")
                .or_else(|_| chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S"))
                .map(|ndt| ndt.and_utc())
                .map_err(|e| e.to_string())
        })
}

fn as_string(v: Option<&serde_json::Value>) -> Result<String, String> {
    v.and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "expected string".into())
}

fn as_u64(v: Option<&serde_json::Value>) -> Result<u64, String> {
    match v {
        Some(serde_json::Value::Number(n)) => n
            .as_u64()
            .or_else(|| n.as_f64().map(|f| f as u64))
            .ok_or_else(|| "bad number".into()),
        Some(serde_json::Value::String(s)) => s.parse().map_err(|e| format!("{e}")),
        _ => Err("expected u64".into()),
    }
}

fn as_f64(v: Option<&serde_json::Value>) -> Result<f64, String> {
    match v {
        Some(serde_json::Value::Number(n)) => n.as_f64().ok_or_else(|| "bad float".into()),
        Some(serde_json::Value::String(s)) => s.parse().map_err(|e| format!("{e}")),
        _ => Err("expected f64".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn sample_domain(domain: &str, phishtank: u64, phishing_cat: u64) -> DomainPhishingFeatures {
        DomainPhishingFeatures {
            window_start: Utc.with_ymd_and_hms(2026, 7, 17, 12, 0, 0).unwrap(),
            window_secs: 300,
            domain: domain.to_string(),
            request_count: 20,
            unique_urls: 5,
            weak_label_phishing: phishing_cat,
            weak_label_phishtank: phishtank,
            weak_label_ut1: 0,
            deny_count: 0,
            suspicious_path_hits: 0,
            avg_path_extra_len: 10.0,
            extracted_at: Utc::now(),
        }
    }

    #[test]
    fn benign_domain_scores_low() {
        let f = sample_domain("github.com", 0, 0);
        let lex = lexical_signals(&f.domain);
        let s = phishing_lexical_v0(&f, &lex);
        assert!(s < 0.35, "score={s}");
    }

    #[test]
    fn phishtank_weak_label_scores_high() {
        let f = sample_domain("evil-phish-login.example", 5, 0);
        let lex = lexical_signals(&f.domain);
        let s = phishing_lexical_v0(&f, &lex);
        assert!(s >= 0.85, "score={s}");
    }

    #[test]
    fn suspicious_lexical_without_label() {
        let f = sample_domain("secure-login-verify-banking-update.tk", 0, 0);
        let lex = lexical_signals(&f.domain);
        assert!(lex.suspicious_keyword);
        let s = phishing_lexical_v0(&f, &lex);
        assert!(s >= 0.4, "score={s}");
    }

    #[test]
    fn ip_hostname_elevates_score() {
        let f = sample_domain("192.168.1.100", 0, 0);
        let lex = lexical_signals(&f.domain);
        assert!(lex.is_ip_hostname);
        let s = phishing_lexical_v0(&f, &lex);
        assert!(s >= 0.25, "score={s}");
    }

    #[test]
    fn entropy_increases_for_random_label() {
        let e1 = shannon_entropy("google");
        let e2 = shannon_entropy("x7k9mq2p");
        assert!(e2 > e1);
    }

    #[test]
    fn extract_sql_mentions_weak_labels() {
        let cfg = Config {
            clickhouse_url: "http://x".into(),
            clickhouse_database: "bsdm".into(),
            clickhouse_table: "http_cache".into(),
            features_table: "entity_features".into(),
            scores_table: "ml_scores".into(),
            phishing_features_table: "domain_phishing_features".into(),
            clickhouse_user: None,
            clickhouse_password: None,
            poll_interval: std::time::Duration::from_secs(60),
            lookback: std::time::Duration::from_secs(300),
            entity_types: vec!["domain".into()],
            min_requests: 5,
            model: MODEL_PHISHING.into(),
            score_threshold: 0.8,
            baseline_lookback: std::time::Duration::from_secs(86400),
            baseline_min_samples: 30,
            z_clip: 4.0,
            baseline_path: None,
            webhook_url: None,
            webhook_timeout: std::time::Duration::from_secs(10),
            metrics_port: 8091,
            source: "test".into(),
        };
        let sql = extract_sql(&cfg);
        assert!(sql.contains("weak_label_phishtank"));
        assert!(sql.contains("has(categories, 'phishing')"));
    }
}
