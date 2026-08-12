//! URL Categorization module
//!
//! Supports multiple categorization engines:
//! - UT1 Blacklists (Université Toulouse 1 — local category DB, Shallalist successor)
//! - URLhaus (malware URLs)
//! - PhishTank (phishing detection)
//! - Custom database
//! - Roskomnadzor registry (domain / URL / literal IP matching)

use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info, warn};
use url::Url;

static RKN_REQUIRED: AtomicBool = AtomicBool::new(false);
static RKN_READY: AtomicBool = AtomicBool::new(true);

/// Global readiness signal consumed by the metrics `/ready` endpoint.
///
/// The proxy is RKN-ready when RKN sync is disabled, or when a validated
/// registry (downloaded or last-known-good snapshot) is loaded.
pub fn rkn_global_ready() -> bool {
    !RKN_REQUIRED.load(Ordering::Relaxed) || RKN_READY.load(Ordering::Relaxed)
}

/// URL category
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Category {
    // Content categories (UT1 / legacy Shallalist layout)
    Adult,
    Gambling,
    Violence,
    Weapons,
    Drugs,
    Hacking,
    Malware,
    Phishing,
    Spyware,
    Adv, // Advertising
    Redirector,
    Tracker,
    // Safe categories
    News,
    Education,
    Finance,
    Shopping,
    Social,
    Entertainment,
    Sports,
    Technology,
    // Business
    Business,
    Government,
    Health,
    // Custom
    Custom(String),
    Unknown,
    // RKN
    Rkn,
}

impl std::fmt::Display for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Category::Custom(s) => write!(f, "custom:{}", s),
            _ => write!(f, "{:?}", self).map(|_| ()),
        }
    }
}

impl Category {
    /// Lowercase name used by ACL category rules.
    pub fn acl_name(&self) -> String {
        match self {
            Category::Custom(s) => s.clone(),
            Category::Unknown => String::new(),
            other => format!("{:?}", other).to_lowercase(),
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "adult" | "porn" => Category::Adult,
            "gambling" | "gamble" => Category::Gambling,
            "violence" | "aggressive" | "agressif" => Category::Violence,
            "weapons" | "warez" | "dangerous_material" => Category::Weapons,
            "drugs" | "alcohol" | "drogue" => Category::Drugs,
            "hacking" | "hacker" | "ddos" => Category::Hacking,
            "malware" | "virus" | "cryptojacking" | "stalkerware" => Category::Malware,
            "phishing" | "phish" => Category::Phishing,
            "spyware" | "spy" => Category::Spyware,
            "adv" | "advertising" | "ads" | "publicite" | "marketingware" => Category::Adv,
            "redirector" | "redirect" | "strict_redirector" | "strong_redirector" => {
                Category::Redirector
            }
            "tracker" | "tracking" => Category::Tracker,
            "news" | "press" => Category::News,
            "education" | "schools" | "child" | "liste_bu" => Category::Education,
            "finance" | "banking" | "bank" | "financial" => Category::Finance,
            "shopping" | "shops" => Category::Shopping,
            "social" | "socialnet" | "social_networks" => Category::Social,
            "entertainment" | "movies" | "music" | "games" | "manga" | "audio-video" => {
                Category::Entertainment
            }
            "sports" => Category::Sports,
            "technology" | "tech" | "ai" => Category::Technology,
            "business" | "jobsearch" => Category::Business,
            "government" | "military" | "arjel" => Category::Government,
            "health" | "medical" => Category::Health,
            "vpn" | "doh" | "residential-proxies" | "dynamic-dns" | "shortener" => {
                Category::Custom(s.to_string())
            }
            "fakenews" => Category::Custom("fakenews".to_string()),
            "rkn" => Category::Rkn,
            _ => Category::Custom(s.to_string()),
        }
    }
}

/// Domain suffix chain for local blacklist lookup (`www.foo.example.com` → `foo.example.com` → `example.com`).
fn domain_suffixes(domain: &str) -> Vec<String> {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let parts: Vec<&str> = domain.split('.').filter(|p| !p.is_empty()).collect();
    if parts.len() < 2 {
        return vec![domain];
    }
    (2..=parts.len())
        .rev()
        .map(|n| parts[parts.len() - n..].join("."))
        .collect()
}

/// RKN last-known-good registry snapshot persisted between restarts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct RknRegistrySnapshot {
    domains: HashSet<String>,
    urls: HashSet<String>,
    ips: HashSet<IpAddr>,
    revision: u64,
}

impl RknRegistrySnapshot {
    fn entry_count(&self) -> usize {
        self.domains.len() + self.urls.len() + self.ips.len()
    }

    fn validate(&self, min_entries: usize) -> Result<(), String> {
        let count = self.entry_count();
        if count < min_entries {
            return Err(format!(
                "RKN registry rejected: only {count} unique entries, minimum is {min_entries}"
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct RknMatch {
    pub match_type: &'static str,
    pub value: String,
    pub revision: u64,
}

fn normalize_rkn_url(raw: &str) -> Option<String> {
    let mut parsed = Url::parse(raw.trim()).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return None;
    }
    parsed.set_fragment(None);
    Some(parsed.to_string())
}

fn rkn_request_url_keys(parsed: &Url) -> Vec<String> {
    let mut full = parsed.clone();
    full.set_fragment(None);
    let full = full.to_string();

    let mut base = parsed.clone();
    base.set_fragment(None);
    base.set_query(None);
    let base = base.to_string();

    if full == base {
        vec![full]
    } else {
        vec![full, base]
    }
}

fn parse_rkn_dump(text: &str, min_entries: usize) -> Result<RknRegistrySnapshot, String> {
    let mut snapshot = RknRegistrySnapshot::default();
    let mut parsed_rows = 0usize;
    let mut malformed_urls = 0usize;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let mut parts = line.split(';');
        let ips_field = parts.next().unwrap_or("").trim();
        let domain_field = parts.next().unwrap_or("").trim();
        let url_field = parts.next().unwrap_or("").trim();

        if ips_field.eq_ignore_ascii_case("ip")
            || domain_field.eq_ignore_ascii_case("domain")
            || url_field.eq_ignore_ascii_case("url")
        {
            continue;
        }

        let has_url = !url_field.is_empty();
        let has_domain = !domain_field.is_empty();

        // URL-scoped registry records must stay URL-scoped. Adding their domain
        // to the domain set would recreate the old overblocking behaviour.
        if has_url {
            if let Some(url) = normalize_rkn_url(url_field) {
                snapshot.urls.insert(url);
                parsed_rows += 1;
            } else {
                malformed_urls += 1;
            }
        } else if has_domain {
            let mut domain = domain_field
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if let Some(stripped) = domain.strip_prefix("*.") {
                domain = stripped.to_string();
            }
            if !domain.is_empty() {
                snapshot.domains.insert(domain);
                parsed_rows += 1;
            }
        } else if !ips_field.is_empty() {
            // zapret-info often carries resolved IPs alongside domain/URL rows;
            // treating those as IP-wide blocks would overblock shared hosting.
            // Only IP-only rows become IP rules.
            for raw_ip in ips_field.split(|c| c == ',' || c == ' ' || c == '\t') {
                let raw_ip = raw_ip.trim();
                if raw_ip.is_empty() {
                    continue;
                }
                if let Ok(ip) = raw_ip.parse::<IpAddr>() {
                    snapshot.ips.insert(ip);
                    parsed_rows += 1;
                }
            }
        }
    }

    if parsed_rows == 0 {
        return Err("RKN registry rejected: no parseable records".to_string());
    }
    snapshot.validate(min_entries)?;

    if malformed_urls > 0 {
        warn!(
            malformed_urls,
            "RKN registry contained malformed URL records; ignored them"
        );
    }

    Ok(snapshot)
}

fn load_rkn_snapshot(path: &str, min_entries: usize) -> Result<RknRegistrySnapshot, String> {
    let content = std::fs::read(path)
        .map_err(|e| format!("Failed to read RKN snapshot {path}: {e}"))?;
    let snapshot: RknRegistrySnapshot = serde_json::from_slice(&content)
        .map_err(|e| format!("Failed to parse RKN snapshot {path}: {e}"))?;
    snapshot.validate(min_entries)?;
    Ok(snapshot)
}

fn persist_rkn_snapshot(path: &str, snapshot: &RknRegistrySnapshot) -> Result<(), String> {
    let path = std::path::Path::new(path);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create RKN snapshot directory: {e}"))?;
        }
    }

    let bytes = serde_json::to_vec(snapshot)
        .map_err(|e| format!("Failed to serialize RKN snapshot: {e}"))?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)
        .map_err(|e| format!("Failed to write RKN snapshot {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("Failed to replace RKN snapshot {}: {e}", path.display())
    })?;
    Ok(())
}

fn next_rkn_revision() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Categorization result
#[derive(Debug, Clone)]
pub struct CategorizationResult {
    pub url: String,
    pub domain: String,
    pub categories: HashSet<Category>,
    pub confidence: f32,
    pub source: String,
    pub cached: bool,
}

/// Cached category entry
#[derive(Clone)]
struct CategoryCache {
    categories: HashSet<Category>,
    /// Feed id for Kafka/CH (`ut1`, `phishtank`, `urlhaus`, …).
    source: String,
    cached_at: Instant,
    ttl: Duration,
}

impl CategoryCache {
    fn is_expired(&self) -> bool {
        self.cached_at.elapsed() > self.ttl
    }
}

/// Categorization engine configuration
#[derive(Debug, Clone)]
pub struct CategorizationConfig {
    pub enabled: bool,
    pub cache_ttl: Duration,
    pub ut1_enabled: bool,
    pub ut1_path: Option<String>,
    pub urlhaus_enabled: bool,
    pub urlhaus_api: String,
    pub phishtank_enabled: bool,
    pub phishtank_api: String,
    /// PhishTank `app_key` (optional but recommended for rate limits).
    pub phishtank_api_key: Option<String>,
    pub custom_db_enabled: bool,
    pub custom_db_path: Option<String>,
    pub rkn_sync_enabled: bool,
    pub rkn_sync_url: String,
    pub rkn_sync_interval_secs: u64,
    pub rkn_snapshot_path: Option<String>,
    pub rkn_min_entries: usize,
}

impl Default for CategorizationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cache_ttl: Duration::from_secs(3600),
            ut1_enabled: false,
            ut1_path: None,
            urlhaus_enabled: false,
            urlhaus_api: "https://urlhaus-api.abuse.ch/v1/url/".to_string(),
            phishtank_enabled: false,
            phishtank_api: "https://checkurl.phishtank.com/checkurl/".to_string(),
            phishtank_api_key: None,
            custom_db_enabled: false,
            custom_db_path: None,
            rkn_sync_enabled: false,
            rkn_sync_url: crate::runtime_config::DEFAULT_RKN_SYNC_URL.to_string(),
            rkn_sync_interval_secs: 86400,
            rkn_snapshot_path: Some("/var/lib/bsdm-proxy/rkn-registry.json".to_string()),
            rkn_min_entries: 1000,
        }
    }
}

/// Categorization engine
pub struct CategorizationEngine {
    config: CategorizationConfig,
    /// Sync lock: hot-path reads must not await (#104).
    cache: Arc<std::sync::RwLock<HashMap<String, CategoryCache>>>,
    local_db: Option<HashMap<String, HashSet<Category>>>,
    custom_db: Option<HashMap<String, HashSet<Category>>>,
    http_client: Client,
    rkn_registry: Arc<std::sync::RwLock<RknRegistrySnapshot>>,
}

impl CategorizationEngine {
    pub fn new(config: CategorizationConfig) -> Self {
        info!("Categorization engine initialized");

        RKN_REQUIRED.store(config.rkn_sync_enabled, Ordering::Relaxed);
        RKN_READY.store(!config.rkn_sync_enabled, Ordering::Relaxed);

        let mut engine = Self {
            config,
            cache: Arc::new(std::sync::RwLock::new(HashMap::new())),
            local_db: None,
            custom_db: None,
            http_client: Client::builder()
                .timeout(Duration::from_secs(5))
                .user_agent("bsdm-proxy/0.3.2 (+https://github.com/onixus/bsdm-proxy)")
                .build()
                .expect("Failed to create HTTP client"),
            rkn_registry: Arc::new(std::sync::RwLock::new(RknRegistrySnapshot::default())),
        };

        // Load UT1 blacklists if enabled
        if engine.config.ut1_enabled {
            if let Some(path) = engine.config.ut1_path.clone() {
                match engine.load_ut1_blacklists(&path) {
                    Ok(count) => info!("Loaded {} UT1 blacklist domain entries", count),
                    Err(e) => error!("Failed to load UT1 blacklists: {}", e),
                }
            }
        }

        // Load custom database if enabled
        if engine.config.custom_db_enabled {
            if let Some(path) = engine.config.custom_db_path.clone() {
                match engine.load_custom_db(&path) {
                    Ok(count) => info!("Loaded {} custom categories", count),
                    Err(e) => error!("Failed to load custom DB: {}", e),
                }
            }
        }

        // Load last-known-good RKN snapshot before accepting traffic.
        if engine.config.rkn_sync_enabled {
            if let Some(path) = engine.config.rkn_snapshot_path.as_deref() {
                match load_rkn_snapshot(path, engine.config.rkn_min_entries) {
                    Ok(snapshot) => {
                        let count = snapshot.entry_count();
                        let revision = snapshot.revision;
                        if let Ok(mut lock) = engine.rkn_registry.write() {
                            *lock = snapshot;
                            RKN_READY.store(true, Ordering::Relaxed);
                        }
                        info!(
                            count,
                            revision,
                            path,
                            "Loaded last-known-good RKN registry snapshot"
                        );
                    }
                    Err(e) => warn!("RKN last-known-good snapshot unavailable: {}", e),
                }
            }

            CategorizationEngine::schedule_rkn_sync(
                engine.rkn_registry.clone(),
                engine.cache.clone(),
                engine.config.rkn_sync_url.clone(),
                engine.config.rkn_sync_interval_secs,
                engine.config.rkn_snapshot_path.clone(),
                engine.config.rkn_min_entries,
            );
        }

        engine
    }

    /// Whether URLhaus / PhishTank lookups are configured.
    pub fn online_enrichment_enabled(&self) -> bool {
        self.config.urlhaus_enabled || self.config.phishtank_enabled
    }

    pub fn rkn_ready(&self) -> bool {
        if !self.config.rkn_sync_enabled {
            return true;
        }
        self.rkn_registry
            .read()
            .map(|r| r.entry_count() >= self.config.rkn_min_entries)
            .unwrap_or(false)
    }

    fn check_rkn(&self, parsed_url: &Url) -> Option<RknMatch> {
        let registry = self.rkn_registry.read().ok()?;

        for key in rkn_request_url_keys(parsed_url) {
            if registry.urls.contains(&key) {
                return Some(RknMatch {
                    match_type: "url",
                    value: key,
                    revision: registry.revision,
                });
            }
        }

        let domain = parsed_url.host_str().unwrap_or("");
        for suffix in domain_suffixes(domain) {
            if registry.domains.contains(&suffix) {
                return Some(RknMatch {
                    match_type: "domain",
                    value: suffix,
                    revision: registry.revision,
                });
            }
        }

        if let Ok(ip) = domain.parse::<IpAddr>() {
            if registry.ips.contains(&ip) {
                return Some(RknMatch {
                    match_type: "ip",
                    value: ip.to_string(),
                    revision: registry.revision,
                });
            }
        }

        None
    }

    /// Hot path: in-memory cache + local UT1/custom DB only (no HTTP). #104
    pub fn categorize_local(&self, url: &str) -> CategorizationResult {
        let parsed_url = match Url::parse(url) {
            Ok(u) => u,
            Err(e) => {
                warn!("Invalid URL '{}': {}", url, e);
                return self.create_result(url, url, HashSet::new(), "error", false);
            }
        };

        let domain = parsed_url.host_str().unwrap_or("").to_string();

        // Domain cache intentionally contains non-RKN categories only. RKN can
        // be URL-scoped, therefore it must be evaluated for every request.
        let (mut categories, mut source, cached) = if let Some(cached) = self.get_cached(&domain) {
            debug!("Category cache hit for: {}", domain);
            (cached.categories, cached.source, true)
        } else {
            let mut categories = HashSet::new();
            let mut source = "unknown".to_string();

            if self.config.ut1_enabled {
                if let Some(cats) = self.check_local_db(&domain) {
                    categories.extend(cats);
                    source = "ut1".to_string();
                }
            }

            if self.config.custom_db_enabled {
                if let Some(cats) = self.check_custom_db(&domain) {
                    categories.extend(cats);
                    source = if source == "unknown" {
                        "custom".to_string()
                    } else {
                        "multiple".to_string()
                    };
                }
            }

            if !categories.is_empty() {
                self.cache_categories(&domain, categories.clone(), &source);
            }
            (categories, source, false)
        };

        if self.config.rkn_sync_enabled {
            if let Some(rkn_match) = self.check_rkn(&parsed_url) {
                categories.insert(Category::Rkn);
                source = if source == "unknown" {
                    "rkn".to_string()
                } else {
                    "multiple".to_string()
                };
                info!(
                    rkn_match_type = rkn_match.match_type,
                    rkn_match = %rkn_match.value,
                    rkn_revision = rkn_match.revision,
                    request_url = %url,
                    "RKN registry match"
                );
            }
        }

        self.create_result(url, &domain, categories, &source, cached)
    }

    /// Spawn background URLhaus/PhishTank lookup when local DB had no match (#104).
    pub fn schedule_online_enrichment(self: &Arc<Self>, url: &str) {
        if !self.online_enrichment_enabled() {
            return;
        }
        let url = url.to_string();
        let engine = Arc::clone(self);
        tokio::spawn(async move {
            if let Err(e) = engine.enrich_online(&url).await {
                debug!("Online categorization enrichment failed for {}: {}", url, e);
            }
        });
    }

    /// Categorize URL (compat wrapper — local only; online enrichment is async).
    pub async fn categorize(&self, url: &str) -> CategorizationResult {
        self.categorize_local(url)
    }

    fn schedule_rkn_sync(
        rkn_registry: Arc<std::sync::RwLock<RknRegistrySnapshot>>,
        cache: Arc<std::sync::RwLock<HashMap<String, CategoryCache>>>,
        url: String,
        interval: u64,
        snapshot_path: Option<String>,
        min_entries: usize,
    ) {
        tokio::spawn(async move {
            let client = Client::builder()
                .timeout(Duration::from_secs(60))
                .user_agent("bsdm-proxy/RKN-Sync")
                .build()
                .unwrap_or_default();

            loop {
                info!("Starting RKN registry sync from {}", url);
                match client.get(&url).send().await {
                    Ok(response) if response.status().is_success() => {
                        match response.bytes().await {
                            Ok(bytes) => {
                                let (decoded, _, _) = encoding_rs::WINDOWS_1251.decode(&bytes);
                                match parse_rkn_dump(&decoded, min_entries) {
                                    Ok(mut snapshot) => {
                                        snapshot.revision = next_rkn_revision();
                                        let count = snapshot.entry_count();
                                        let domains = snapshot.domains.len();
                                        let urls = snapshot.urls.len();
                                        let ips = snapshot.ips.len();
                                        let revision = snapshot.revision;

                                        if let Some(path) = snapshot_path.as_deref() {
                                            if let Err(e) = persist_rkn_snapshot(path, &snapshot) {
                                                warn!("Failed to persist RKN last-known-good snapshot: {}", e);
                                            }
                                        }

                                        if let Ok(mut lock) = rkn_registry.write() {
                                            *lock = snapshot;
                                            RKN_READY.store(true, Ordering::Relaxed);
                                        }

                                        // Invalidate categorization cache on every registry revision.
                                        // RKN itself is never cached by domain, but this also prevents
                                        // stale source/category combinations after a feed transition.
                                        if let Ok(mut cache) = cache.write() {
                                            cache.clear();
                                        }

                                        info!(
                                            count,
                                            domains,
                                            urls,
                                            ips,
                                            revision,
                                            "Successfully synced validated RKN registry"
                                        );
                                    }
                                    Err(e) => {
                                        error!(
                                            "Rejected RKN registry update; keeping last-known-good data: {}",
                                            e
                                        );
                                    }
                                }
                            }
                            Err(e) => error!("Failed to read RKN registry response bytes: {}", e),
                        }
                    }
                    Ok(response) => {
                        error!("Failed to fetch RKN registry: HTTP {}", response.status());
                    }
                    Err(e) => {
                        error!("Failed to fetch RKN registry: {}", e);
                    }
                }
                tokio::time::sleep(Duration::from_secs(interval.max(60))).await;
            }
        });
    }

    async fn enrich_online(&self, url: &str) -> Result<(), String> {
        let parsed_url = Url::parse(url).map_err(|e| e.to_string())?;
        let domain = parsed_url.host_str().unwrap_or("").to_string();

        if self
            .get_cached(&domain)
            .is_some_and(|c| !c.categories.is_empty())
        {
            return Ok(());
        }

        let mut categories = HashSet::new();
        let mut source = "unknown";

        if self.config.urlhaus_enabled {
            if let Some(cats) = self.check_urlhaus(url).await {
                categories.extend(cats);
                source = "urlhaus";
            }
        }

        if self.config.phishtank_enabled {
            if let Some(cats) = self.check_phishtank(url).await {
                categories.extend(cats);
                source = if source == "unknown" {
                    "phishtank"
                } else {
                    "multiple"
                };
            }
        }

        if categories.is_empty() {
            return Ok(());
        }

        self.cache_categories(&domain, categories, source);
        debug!(
            "Online categorization enriched {} (source={})",
            domain, source
        );
        Ok(())
    }

    fn check_local_db(&self, domain: &str) -> Option<HashSet<Category>> {
        let db = self.local_db.as_ref()?;
        for suffix in domain_suffixes(domain) {
            if let Some(cats) = db.get(&suffix) {
                return Some(cats.clone());
            }
        }
        None
    }

    /// Check custom database
    fn check_custom_db(&self, domain: &str) -> Option<HashSet<Category>> {
        self.custom_db.as_ref()?.get(domain).cloned()
    }

    /// Check URLhaus API
    async fn check_urlhaus(&self, url: &str) -> Option<HashSet<Category>> {
        let response = self
            .http_client
            .post(&self.config.urlhaus_api)
            .form(&[("url", url)])
            .send()
            .await
            .ok()?;

        if response.status().is_success() {
            let data: serde_json::Value = response.json().await.ok()?;

            if data["query_status"] == "ok" {
                let mut cats = HashSet::new();
                cats.insert(Category::Malware);
                return Some(cats);
            }
        }

        None
    }

    /// Check PhishTank API (`app_key` when `PHISHTANK_API_KEY` is set).
    async fn check_phishtank(&self, url: &str) -> Option<HashSet<Category>> {
        let form = phishtank_form_fields(url, self.config.phishtank_api_key.as_deref());
        let response = self
            .http_client
            .post(&self.config.phishtank_api)
            .form(&form)
            .send()
            .await
            .ok()?;

        if response.status().is_success() {
            let data: serde_json::Value = response.json().await.ok()?;

            if data["results"]["in_database"].as_bool() == Some(true) {
                let mut cats = HashSet::new();
                cats.insert(Category::Phishing);
                return Some(cats);
            }
        }

        None
    }

    /// Load UT1 Blacklists (or legacy Shallalist layout: `category/domains`).
    ///
    /// UT1 official tarball extracts to `blacklists/<category>/domains`.
    fn load_ut1_blacklists(&mut self, path: &str) -> Result<usize, String> {
        let root = std::path::Path::new(path);
        if !root.exists() {
            return Err(format!("UT1 blacklist directory not found: {path}"));
        }

        let categories_dir = if root.join("blacklists").is_dir() {
            root.join("blacklists")
        } else {
            root.to_path_buf()
        };

        let mut db = HashMap::new();
        for entry in std::fs::read_dir(&categories_dir)
            .map_err(|e| format!("Failed to read {}: {e}", categories_dir.display()))?
        {
            let entry = entry.map_err(|e| format!("Failed to read entry: {e}"))?;
            if !entry.file_type().map_err(|e| e.to_string())?.is_dir() {
                continue;
            }
            let category_name = entry.file_name().to_string_lossy().to_string();
            let category = Category::from_str(&category_name);
            let domains_file = entry.path().join("domains");
            if !domains_file.is_file() {
                continue;
            }
            let content = std::fs::read_to_string(&domains_file)
                .map_err(|e| format!("Failed to read {}: {e}", domains_file.display()))?;
            for line in content.lines() {
                let domain = line.trim().to_ascii_lowercase();
                if domain.is_empty() || domain.starts_with('#') {
                    continue;
                }
                db.entry(domain)
                    .or_insert_with(HashSet::new)
                    .insert(category.clone());
            }
        }

        if db.is_empty() {
            return Err(format!(
                "No UT1 categories loaded under {} (expected <category>/domains)",
                categories_dir.display()
            ));
        }

        let count = db.len();
        self.local_db = Some(db);
        Ok(count)
    }

    /// Load custom database (JSON format)
    fn load_custom_db(&mut self, path: &str) -> Result<usize, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read custom DB: {}", e))?;

        let data: HashMap<String, Vec<String>> = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse custom DB JSON: {}", e))?;

        let mut db = HashMap::new();
        for (domain, cats) in data {
            let categories: HashSet<Category> =
                cats.iter().map(|c| Category::from_str(c)).collect();
            db.insert(domain, categories);
        }

        let count = db.len();
        self.custom_db = Some(db);
        Ok(count)
    }

    /// Get cached categories (sync hot path).
    fn get_cached(&self, domain: &str) -> Option<CategoryCache> {
        let cache = self.cache.read().ok()?;
        cache.get(domain).filter(|c| !c.is_expired()).cloned()
    }

    /// Cache categories (sync) with feed provenance for `threat_sources`.
    fn cache_categories(&self, domain: &str, mut categories: HashSet<Category>, source: &str) {
        // Never cache RKN by domain: registry records can be URL-specific.
        categories.remove(&Category::Rkn);
        if categories.is_empty() {
            return;
        }

        if let Ok(mut cache) = self.cache.write() {
            cache.insert(
                domain.to_string(),
                CategoryCache {
                    categories,
                    source: source.to_string(),
                    cached_at: Instant::now(),
                    ttl: self.config.cache_ttl,
                },
            );
        }
    }

    /// Create result
    fn create_result(
        &self,
        url: &str,
        domain: &str,
        categories: HashSet<Category>,
        source: &str,
        cached: bool,
    ) -> CategorizationResult {
        let confidence = if categories.is_empty() { 0.0 } else { 0.9 };

        CategorizationResult {
            url: url.to_string(),
            domain: domain.to_string(),
            categories,
            confidence,
            source: source.to_string(),
            cached,
        }
    }

    /// Clean expired cache entries.
    pub fn cleanup_cache(&self) {
        if let Ok(mut cache) = self.cache.write() {
            cache.retain(|_, entry| !entry.is_expired());
        }
    }
}

/// Form fields for PhishTank checkurl POST (`app_key` when API key is set).
pub(crate) fn phishtank_form_fields<'a>(
    url: &'a str,
    api_key: Option<&'a str>,
) -> Vec<(&'a str, &'a str)> {
    let mut form = vec![("url", url), ("format", "json")];
    if let Some(key) = api_key.filter(|k| !k.is_empty()) {
        form.push(("app_key", key));
    }
    form
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_category_from_str_ut1_names() {
        assert_eq!(Category::from_str("agressif"), Category::Violence);
        assert_eq!(Category::from_str("social_networks"), Category::Social);
        assert_eq!(Category::from_str("publicite"), Category::Adv);
    }

    #[test]
    fn test_domain_suffixes() {
        assert_eq!(
            domain_suffixes("www.evil.example.com"),
            vec![
                "www.evil.example.com".to_string(),
                "evil.example.com".to_string(),
                "example.com".to_string(),
            ]
        );
        assert_eq!(domain_suffixes("WWW.Example.COM."), vec!["www.example.com", "example.com"]);
    }

    #[test]
    fn test_rkn_parser_preserves_url_scope() {
        let dump = concat!(
            "ip;domain;url;date\n",
            "1.2.3.4;shared.example;https://shared.example/blocked;2026-01-01\n",
            ";whole.example;;2026-01-01\n",
            "5.6.7.8;;;2026-01-01\n",
        );
        let snapshot = parse_rkn_dump(dump, 3).unwrap();
        assert!(snapshot.urls.contains("https://shared.example/blocked"));
        assert!(!snapshot.domains.contains("shared.example"));
        assert!(snapshot.domains.contains("whole.example"));
        assert!(snapshot.ips.contains(&"5.6.7.8".parse().unwrap()));
        assert!(!snapshot.ips.contains(&"1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn test_rkn_parser_rejects_tiny_feed() {
        let dump = ";one.example;;\n";
        assert!(parse_rkn_dump(dump, 1000).is_err());
    }

    #[test]
    fn test_rkn_url_match_does_not_overblock_domain() {
        let config = CategorizationConfig {
            rkn_sync_enabled: true,
            rkn_min_entries: 1,
            rkn_snapshot_path: None,
            ..Default::default()
        };
        let engine = CategorizationEngine::new(config);
        {
            let mut registry = engine.rkn_registry.write().unwrap();
            registry.urls.insert("https://shared.example/blocked".to_string());
            registry.revision = 42;
        }

        let blocked = engine.categorize_local("https://shared.example/blocked");
        assert!(blocked.categories.contains(&Category::Rkn));

        let allowed = engine.categorize_local("https://shared.example/other");
        assert!(!allowed.categories.contains(&Category::Rkn));
    }

    #[test]
    fn test_rkn_snapshot_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rkn.json");
        let snapshot = RknRegistrySnapshot {
            domains: HashSet::from(["blocked.example".to_string()]),
            urls: HashSet::from(["https://shared.example/blocked".to_string()]),
            ips: HashSet::from(["203.0.113.7".parse().unwrap()]),
            revision: 77,
        };
        persist_rkn_snapshot(path.to_str().unwrap(), &snapshot).unwrap();
        let loaded = load_rkn_snapshot(path.to_str().unwrap(), 3).unwrap();
        assert_eq!(loaded.revision, 77);
        assert_eq!(loaded.entry_count(), 3);
    }

    #[test]
    fn test_load_ut1_blacklists_layout() {
        let dir = tempfile::tempdir().unwrap();
        let cat_dir = dir.path().join("blacklists").join("adult");
        std::fs::create_dir_all(&cat_dir).unwrap();
        std::fs::write(cat_dir.join("domains"), "blocked.example\n").unwrap();

        let mut engine = CategorizationEngine::new(CategorizationConfig::default());
        let count = engine
            .load_ut1_blacklists(dir.path().to_str().unwrap())
            .unwrap();
        assert_eq!(count, 1);
        assert_eq!(
            engine.check_local_db("www.blocked.example"),
            Some(HashSet::from([Category::Adult]))
        );
    }

    #[test]
    fn test_categorization_disabled() {
        let config = CategorizationConfig {
            enabled: false,
            ..Default::default()
        };

        let engine = CategorizationEngine::new(config);
        let result = engine.categorize_local("https://example.com");

        assert!(result.categories.is_empty());
    }

    #[test]
    fn test_categorize_local_ut1() {
        let dir = tempfile::tempdir().unwrap();
        let cat_dir = dir.path().join("blacklists").join("malware");
        std::fs::create_dir_all(&cat_dir).unwrap();
        std::fs::write(cat_dir.join("domains"), "evil.example\n").unwrap();

        let config = CategorizationConfig {
            ut1_enabled: true,
            ut1_path: Some(dir.path().to_string_lossy().into_owned()),
            ..Default::default()
        };

        let engine = CategorizationEngine::new(config);
        let result = engine.categorize_local("https://www.evil.example/path");
        assert!(result.categories.contains(&Category::Malware));
        assert_eq!(result.source, "ut1");
    }

    #[test]
    fn test_cache_preserves_source() {
        let config = CategorizationConfig::default();
        let engine = CategorizationEngine::new(config);

        let mut cats = HashSet::new();
        cats.insert(Category::Phishing);
        engine.cache_categories("phish.example", cats.clone(), "phishtank");

        let cached = engine.get_cached("phish.example").unwrap();
        assert_eq!(cached.categories, cats);
        assert_eq!(cached.source, "phishtank");

        let result = engine.categorize_local("https://phish.example/login");
        assert!(result.cached);
        assert_eq!(result.source, "phishtank");
        assert!(result.categories.contains(&Category::Phishing));
    }

    #[test]
    fn phishtank_form_includes_app_key_when_set() {
        let with_key = phishtank_form_fields("https://evil.test/", Some("secret-key"));
        assert!(with_key.contains(&("url", "https://evil.test/")));
        assert!(with_key.contains(&("format", "json")));
        assert!(with_key.contains(&("app_key", "secret-key")));

        let no_key = phishtank_form_fields("https://evil.test/", None);
        assert_eq!(no_key.len(), 2);
        assert!(!no_key.iter().any(|(k, _)| *k == "app_key"));

        let empty_key = phishtank_form_fields("https://evil.test/", Some(""));
        assert!(!empty_key.iter().any(|(k, _)| *k == "app_key"));
    }
}
