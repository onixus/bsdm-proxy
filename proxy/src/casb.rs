use std::collections::HashSet;

/// Cloud Access Security Broker (CASB) engine.
/// Identifies and intercepts traffic to Generative AI providers.
#[derive(Clone)]
pub struct CasbEngine {
    llm_domains: HashSet<&'static str>,
}

impl CasbEngine {
    pub fn new() -> Self {
        let mut llm_domains = HashSet::new();
        // Core OpenAI
        llm_domains.insert("api.openai.com");
        llm_domains.insert("chatgpt.com");
        // Core Anthropic
        llm_domains.insert("api.anthropic.com");
        llm_domains.insert("claude.ai");
        // Copilot
        llm_domains.insert("copilot.microsoft.com");

        Self { llm_domains }
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
        // Simple suffix match for CASB detection (e.g. chatgpt.com, api.openai.com)
        self.llm_domains
            .iter()
            .any(|&d| domain == d || domain.ends_with(d))
    }
}
