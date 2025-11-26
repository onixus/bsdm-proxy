use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use reqwest::Client;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Category {
    Social,
    Shopping,
    News,
    Entertainment,
    Adult,
    Gambling,
    Malware,
    Phishing,
    Productivity,
    Education,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Action {
    Allow,
    Block,
    Warn,
    Log,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryRule {
    pub domain: String,
    pub category: Category,
    pub action: Action,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryConfig {
    pub default_action: Action,
    pub cache_ttl: i64,
    pub rules: Vec<CategoryRule>,
    pub redis_url: Option<String>,
    pub external_apis: ExternalApis,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalApis {
    pub urlhaus: bool,
}

pub struct CategoryEngine {
    local_rules: Arc<RwLock<HashMap<String, (Category, Action)>>>,
    wildcard_rules: Arc<RwLock<Vec<(String, Category, Action)>>>,
    redis_client: Option<redis::Client>,
    http_client: Client,
    cache_ttl: i64,
    urlhaus_enabled: bool,
}

impl CategoryEngine {
    pub async fn new(config_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let config_str = tokio::fs::read_to_string(config_path).await?;
        let config: CategoryConfig = serde_json::from_str(&config_str)?;
        
        let mut local_rules = HashMap::new();
        let mut wildcard_rules = Vec::new();
        
        for rule in config.rules {
            if rule.domain.starts_with("*.") {
                wildcard_rules.push((rule.domain[2..].to_string(), rule.category, rule.action));
            } else {
                local_rules.insert(rule.domain, (rule.category, rule.action));
            }
        }
        
        let redis_client = config.redis_url
            .as_ref()
            .and_then(|url| redis::Client::open(url.as_str()).ok());
        
        Ok(Self {
            local_rules: Arc::new(RwLock::new(local_rules)),
            wildcard_rules: Arc::new(RwLock::new(wildcard_rules)),
            redis_client,
            http_client: Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()?,
            cache_ttl: config.cache_ttl,
            urlhaus_enabled: config.external_apis.urlhaus,
        })
    }
    
    pub async fn categorize(&self, domain: &str) -> (Category, Action) {
        // 1. Check local exact rules (highest priority)
        if let Some((cat, action)) = self.local_rules.read().await.get(domain) {
            return (cat.clone(), action.clone());
        }
        
        // 2. Check wildcard rules
        let wildcards = self.wildcard_rules.read().await;
        for (suffix, cat, action) in wildcards.iter() {
            if domain.ends_with(suffix) {
                return (cat.clone(), action.clone());
            }
        }
        drop(wildcards);
        
        // 3. Check Redis cache
        if let Some(ref client) = self.redis_client {
            if let Ok(mut conn) = client.get_async_connection().await {
                use redis::AsyncCommands;
                let cache_key = format!("cat:{}", domain);
                
                if let Ok(Some(cached)) = conn.get::<String, Option<String>>(cache_key).await {
                    if let Ok((cat, action)) = serde_json::from_str::<(Category, Action)>(&cached) {
                        return (cat, action);
                    }
                }
            }
        }
        
        // 4. Query external API (URLHaus)
        if self.urlhaus_enabled {
            if let Ok((ext_cat, _score)) = self.query_urlhaus(domain).await {
                let action = match ext_cat {
                    Category::Malware | Category::Phishing => Action::Block,
                    _ => Action::Log,
                };
                
                // Cache the result
                self.cache_result(domain, ext_cat.clone(), action.clone()).await;
                
                return (ext_cat, action);
            }
        }
        
        // Default: unknown category, allow by default
        (Category::Unknown, Action::Allow)
    }
    
    async fn query_urlhaus(&self, domain: &str) -> Result<(Category, f32), Box<dyn std::error::Error>> {
        let url = format!("https://urlhaus-api.abuse.ch/v1/host/{}", domain);
        
        let resp = self.http_client
            .post(&url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(format!("host={}", domain))
            .send()
            .await?;
        
        let json: serde_json::Value = resp.json().await?;
        
        if json["query_status"].as_str() == Some("ok") {
            let url_count = json["url_count"].as_u64().unwrap_or(0);
            if url_count > 0 {
                return Ok((Category::Malware, 0.95));
            }
        }
        
        Err("No threat found".into())
    }
    
    async fn cache_result(&self, domain: &str, category: Category, action: Action) {
        if let Some(ref client) = self.redis_client {
            if let Ok(mut conn) = client.get_async_connection().await {
                use redis::AsyncCommands;
                
                let cache_key = format!("cat:{}", domain);
                let value = serde_json::to_string(&(category, action)).unwrap();
                
                let _: Result<(), redis::RedisError> = conn
                    .set_ex(cache_key, value, self.cache_ttl as usize)
                    .await;
            }
        }
    }
    
    pub async fn add_rule(&self, domain: String, category: Category, action: Action) {
        let mut rules = self.local_rules.write().await;
        rules.insert(domain, (category, action));
    }
    
    pub async fn remove_rule(&self, domain: &str) {
        let mut rules = self.local_rules.write().await;
        rules.remove(domain);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_exact_match() {
        let mut rules = HashMap::new();
        rules.insert("facebook.com".to_string(), (Category::Social, Action::Block));
        
        let engine = CategoryEngine {
            local_rules: Arc::new(RwLock::new(rules)),
            wildcard_rules: Arc::new(RwLock::new(Vec::new())),
            redis_client: None,
            http_client: Client::new(),
            cache_ttl: 3600,
            urlhaus_enabled: false,
        };
        
        let (cat, action) = engine.categorize("facebook.com").await;
        assert_eq!(cat, Category::Social);
        assert!(matches!(action, Action::Block));
    }
    
    #[tokio::test]
    async fn test_wildcard_match() {
        let wildcards = vec![
            ("example.com".to_string(), Category::Adult, Action::Block)
        ];
        
        let engine = CategoryEngine {
            local_rules: Arc::new(RwLock::new(HashMap::new())),
            wildcard_rules: Arc::new(RwLock::new(wildcards)),
            redis_client: None,
            http_client: Client::new(),
            cache_ttl: 3600,
            urlhaus_enabled: false,
        };
        
        let (cat, action) = engine.categorize("subdomain.example.com").await;
        assert_eq!(cat, Category::Adult);
        assert!(matches!(action, Action::Block));
    }
}
