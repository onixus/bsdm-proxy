//! URL Categorization module
//!
//! Supports multiple categorization engines:
//! - UT1 Blacklists (Université Toulouse 1 — local category DB, Shallalist successor)
//! - URLhaus (malware URLs)
//! - PhishTank (phishing detection)
//! - Custom database

use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};
use url::Url;

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
            _ => Category::Custom(s.to_string()),
        }
    }
}

/// Domain suffix chain for local blacklist lookup (`www.foo.example.com` → `foo.example.com` → `example.com`).
fn domain_suffixes(domain: &str) -> Vec<String> {
    let domain = domain.trim().to_ascii_lowercase();
    let parts: Vec<&str> = domain.split('.').filter(|p| !p.is_empty()).collect();
    if parts.len() < 2 {
        return vec![domain];
    }
    (2..=parts.len())
        .rev()
        .map(|n| parts[parts.len() - n..].join("."))
        .collect()
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
}

impl CategorizationEngine {
    pub fn new(config: CategorizationConfig) -> Self {
        info!("Categorization engine initialized");

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

        engine
    }

    /// Whether URLhaus / PhishTank lookups are configured.
    pub fn online_enrichment_enabled(&self) -> bool {
        self.config.urlhaus_enabled || self.config.phishtank_enabled
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

        if let Some(cached) = self.get_cached(&domain) {
            debug!("Category cache hit for: {}", domain);
            return self.create_result(url, &domain, cached.categories, &cached.source, true);
        }

        let mut categories = HashSet::new();
        let mut source = "unknown";

        if self.config.ut1_enabled {
            if let Some(cats) = self.check_local_db(&domain) {
                categories.extend(cats);
                source = "ut1";
            }
        }

        if self.config.custom_db_enabled {
            if let Some(cats) = self.check_custom_db(&domain) {
                categories.extend(cats);
                source = if source == "unknown" {
                    "custom"
                } else {
                    "multiple"
                };
            }
        }

        if !categories.is_empty() {
            self.cache_categories(&domain, categories.clone(), source);
        }

        self.create_result(url, &domain, categories, source, false)
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
    fn cache_categories(&self, domain: &str, categories: HashSet<Category>, source: &str) {
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
