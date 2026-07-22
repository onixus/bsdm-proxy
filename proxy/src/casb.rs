use std::collections::HashSet;
use std::sync::{Arc, RwLock};

/// Cloud Access Security Broker (CASB) engine.
/// Identifies and intercepts traffic to Generative AI providers.
#[derive(Clone)]
pub struct CasbEngine {
    llm_domains: Arc<RwLock<HashSet<String>>>,
}

impl CasbEngine {
    pub fn new() -> Self {
        let mut llm_domains = HashSet::new();
        // Core OpenAI
        llm_domains.insert("api.openai.com".to_string());
        llm_domains.insert("chatgpt.com".to_string());
        // Core Anthropic
        llm_domains.insert("api.anthropic.com".to_string());
        llm_domains.insert("claude.ai".to_string());
        // Copilot
        llm_domains.insert("copilot.microsoft.com".to_string());

        Self {
            llm_domains: Arc::new(RwLock::new(llm_domains)),
        }
    }

    pub fn get_domains(&self) -> Vec<String> {
        let lock = self.llm_domains.read().unwrap();
        let mut domains: Vec<String> = lock.iter().cloned().collect();
        domains.sort();
        domains
    }

    pub fn set_domains(&self, new_domains: Vec<String>) {
        let mut lock = self.llm_domains.write().unwrap();
        lock.clear();
        for domain in new_domains {
            lock.insert(domain);
        }
    }
}

impl Default for CasbEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl CasbEngine {
    /// Returns true if the domain matches a monitored LLM provider.
    pub fn is_llm_provider(&self, domain: &str) -> bool {
        let lock = self.llm_domains.read().unwrap();
        lock.iter()
            .any(|d| domain == d || domain.ends_with(d))
    }
}
