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
        let lock = match self.llm_domains.read() {
            Ok(guard) => guard,
            Err(_) => return false,
        };
        lock.iter()
            .any(|d| crate::security_util::safe_subdomain_matches(domain, d))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_known_llm_providers() {
        let casb = CasbEngine::new();
        assert!(casb.is_llm_provider("chatgpt.com"));
        assert!(casb.is_llm_provider("api.openai.com"));
        assert!(casb.is_llm_provider("sub.chatgpt.com"));
        assert!(casb.is_llm_provider("claude.ai"));
        assert!(casb.is_llm_provider("api.anthropic.com"));
    }

    #[test]
    fn rejects_suffix_spoofing_without_dot() {
        let casb = CasbEngine::new();
        assert!(!casb.is_llm_provider("notclaude.ai"));
        assert!(!casb.is_llm_provider("fakechatgpt.com"));
        assert!(!casb.is_llm_provider("evil-openai.com"));
    }
}
