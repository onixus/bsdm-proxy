//! URL Categorization module
//!
//! Supports multiple categorization engines:
//! - Shallalist (open-source category database)
//! - URLhaus (malware URLs)
//! - PhishTank (phishing detection)
//! - Custom database

use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use url::Url;

/// URL category
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Category {
    // Content categories (Shallalist)
    Adult,
    Gambling,
    Violence,
    Weapons,
    Drugs,
    Hacking,
    Malware,
    Phishing,
    Spyware,
    Adv,          // Advertising
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
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "adult" | "porn" => Category::Adult,
            "gambling" | "gamble" => Category::Gambling,
            "violence" | "aggressive" => Category::Violence,
            "weapons" | "warez" => Category::Weapons,
            "drugs" | "alcohol" => Category::Drugs,
            "hacking" | "hacker" => Category::Hacking,
            "malware" | "virus" => Category::Malware,
            "phishing" | "phish" => Category::Phishing,
            "spyware" | "spy" => Category::Spyware,
            "adv" | "advertising" | "ads" => Category::Adv,
            "redirector" | "redirect" => Category::Redirector,
            "tracker" | "tracking" => Category::Tracker,
            "news" => Category::News,
            "education" | "schools" => Category::Education,
            "finance" | "banking" => Category::Finance,
            "shopping" | "shops" => Category::Shopping,
            "social" | "socialnet" => Category::Social,
            "entertainment" | "movies" | "music" => Category::Entertainment,
            "sports" => Category::Sports,
            "technology" | "tech" => Category::Technology,
            "business" => Category::Business,
            "government" | "military" => Category::Government,
            "health" | "medical" => Category::Health,
            _ => Category::Custom(s.to_string()),
        }
    }
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
    pub shallalist_enabled: bool,
    pub shallalist_path: Option<String>,
    pub urlhaus_enabled: bool,
    pub urlhaus_api: String,
    pub phishtank_enabled: bool,
    pub phishtank_api: String,
    pub custom_db_enabled: bool,
    pub custom_db_path: Option<String>,
}

impl Default for CategorizationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cache_ttl: Duration::from_secs(3600),
            shallalist_enabled: false,
            shallalist_path: None,
            urlhaus_enabled: false,
            urlhaus_api: "https://urlhaus-api.abuse.ch/v1/url/".to_string(),
            phishtank_enabled: false,
            phishtank_api: "https://checkurl.phishtank.com/checkurl/".to_string(),
            custom_db_enabled: false,
            custom_db_path: None,
        }
    }
}

/// Categorization engine
pub struct CategorizationEngine {
    config: CategorizationConfig,
    cache: Arc<RwLock<HashMap<String, CategoryCache>>>,
    shallalist: Option<HashMap<String, HashSet<Category>>>,
    custom_db: Option<HashMap<String, HashSet<Category>>>,
    http_client: Client,
}

impl CategorizationEngine {
    pub fn new(config: CategorizationConfig) -> Self {
        info!("Categorization engine initialized");
        
        let mut engine = Self {
            config,
            cache: Arc::new(RwLock::new(HashMap::new())),
            shallalist: None,
            custom_db: None,
            http_client: Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .expect("Failed to create HTTP client"),
        };

        // Load Shallalist if enabled
        if engine.config.shallalist_enabled {
            if let Some(path) = &engine.config.shallalist_path {
                match engine.load_shallalist(path) {
                    Ok(count) => info!("Loaded {} Shallalist entries", count),
                    Err(e) => error!("Failed to load Shallalist: {}", e),
                }
            }
        }

        // Load custom database if enabled
        if engine.config.custom_db_enabled {
            if let Some(path) = &engine.config.custom_db_path {
                match engine.load_custom_db(path) {
                    Ok(count) => info!("Loaded {} custom categories", count),
                    Err(e) => error!("Failed to load custom DB: {}", e),
                }
            }
        }

        engine
    }

    /// Categorize URL
    pub async fn categorize(&self, url: &str) -> CategorizationResult {
        let parsed_url = match Url::parse(url) {
            Ok(u) => u,
            Err(e) => {
                warn!("Invalid URL '{}': {}", url, e);
                return self.create_result(url, url, HashSet::new(), "error", false);
            }
        };

        let domain = parsed_url.host_str().unwrap_or("").to_string();
        
        // Check cache first
        if let Some(cached) = self.get_cached(&domain).await {
            debug!("Category cache hit for: {}", domain);
            return self.create_result(url, &domain, cached.categories, "cache", true);
        }

        // Try local databases first (faster)
        let mut categories = HashSet::new();
        let mut source = "unknown";

        // Check Shallalist
        if self.config.shallalist_enabled {
            if let Some(cats) = self.check_shallalist(&domain) {
                categories.extend(cats);
                source = "shallalist";
            }
        }

        // Check custom database
        if self.config.custom_db_enabled {
            if let Some(cats) = self.check_custom_db(&domain) {
                categories.extend(cats);
                source = if source == "unknown" { "custom" } else { "multiple" };
            }
        }

        // Check online services if no local match
        if categories.is_empty() {
            // Check URLhaus for malware
            if self.config.urlhaus_enabled {
                if let Some(cats) = self.check_urlhaus(url).await {
                    categories.extend(cats);
                    source = "urlhaus";
                }
            }

            // Check PhishTank for phishing
            if self.config.phishtank_enabled {
                if let Some(cats) = self.check_phishtank(url).await {
                    categories.extend(cats);
                    source = if source == "unknown" { "phishtank" } else { "multiple" };
                }
            }
        }

        // Cache result
        if !categories.is_empty() {
            self.cache_categories(&domain, categories.clone()).await;
        }

        self.create_result(url, &domain, categories, source, false)
    }

    /// Check Shallalist database
    fn check_shallalist(&self, domain: &str) -> Option<HashSet<Category>> {
        self.shallalist.as_ref()?.get(domain).cloned()
    }

    /// Check custom database
    fn check_custom_db(&self, domain: &str) -> Option<HashSet<Category>> {
        self.custom_db.as_ref()?.get(domain).cloned()
    }

    /// Check URLhaus API
    async fn check_urlhaus(&self, url: &str) -> Option<HashSet<Category>> {
        let response = self.http_client
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

    /// Check PhishTank API
    async fn check_phishtank(&self, url: &str) -> Option<HashSet<Category>> {
        let response = self.http_client
            .post(&self.config.phishtank_api)
            .form(&[
                ("url", url),
                ("format", "json"),
            ])
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

    /// Load Shallalist database
    fn load_shallalist(&mut self, path: &str) -> Result<usize, String> {
        // Shallalist format: category/domains
        // Example structure:
        // adult/domains:
        //   example.com
        //   test.com
        
        let mut db = HashMap::new();
        let categories_dir = std::path::Path::new(path);
        
        if !categories_dir.exists() {
            return Err(format!("Shallalist directory not found: {}", path));
        }

        // Read each category directory
        for entry in std::fs::read_dir(categories_dir)
            .map_err(|e| format!("Failed to read directory: {}", e))?
        {
            let entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
            let category_name = entry.file_name().to_string_lossy().to_string();
            let category = Category::from_str(&category_name);
            
            let domains_file = entry.path().join("domains");
            if domains_file.exists() {
                let content = std::fs::read_to_string(&domains_file)
                    .map_err(|e| format!("Failed to read domains file: {}", e))?;
                
                for line in content.lines() {
                    let domain = line.trim();
                    if !domain.is_empty() && !domain.starts_with('#') {
                        db.entry(domain.to_string())
                            .or_insert_with(HashSet::new)
                            .insert(category.clone());
                    }
                }
            }
        }

        let count = db.len();
        self.shallalist = Some(db);
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
            let categories: HashSet<Category> = cats.iter()
                .map(|c| Category::from_str(c))
                .collect();
            db.insert(domain, categories);
        }
        
        let count = db.len();
        self.custom_db = Some(db);
        Ok(count)
    }

    /// Get cached categories
    async fn get_cached(&self, domain: &str) -> Option<CategoryCache> {
        let cache = self.cache.read().await;
        cache.get(domain).filter(|c| !c.is_expired()).cloned()
    }

    /// Cache categories
    async fn cache_categories(&self, domain: &str, categories: HashSet<Category>) {
        let mut cache = self.cache.write().await;
        cache.insert(
            domain.to_string(),
            CategoryCache {
                categories,
                cached_at: Instant::now(),
                ttl: self.config.cache_ttl,
            },
        );
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

    /// Clean expired cache
    pub async fn cleanup_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.retain(|_, entry| !entry.is_expired());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_category_from_str() {
        assert_eq!(Category::from_str("adult"), Category::Adult);
        assert_eq!(Category::from_str("GAMBLING"), Category::Gambling);
        assert_eq!(Category::from_str("phishing"), Category::Phishing);
        assert_eq!(Category::from_str("news"), Category::News);
    }

    #[tokio::test]
    async fn test_categorization_disabled() {
        let config = CategorizationConfig {
            enabled: false,
            ..Default::default()
        };
        
        let engine = CategorizationEngine::new(config);
        let result = engine.categorize("https://example.com").await;
        
        assert!(result.categories.is_empty());
    }

    #[tokio::test]
    async fn test_cache() {
        let config = CategorizationConfig::default();
        let engine = CategorizationEngine::new(config);
        
        let mut cats = HashSet::new();
        cats.insert(Category::News);
        engine.cache_categories("example.com", cats.clone()).await;
        
        let cached = engine.get_cached("example.com").await;
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().categories, cats);
    }
}
