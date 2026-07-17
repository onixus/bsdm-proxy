//! LLM / semantic cache prep: content-addressable POST keys + optional local similarity index.
//!
//! Exact hits use a SHA-256 of method + URL + normalized JSON body.
//! Near-hits (opt-in) use a local hashing embedding + cosine similarity — a stand-in until
//! an external vector DB / embedding API is wired.

use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::info;

/// Runtime config for LLM / semantic caching.
#[derive(Debug, Clone)]
pub struct SemanticCacheConfig {
    pub enabled: bool,
    /// URL path prefixes (matched against path of absolute URL or path-absolute form).
    pub path_prefixes: Vec<String>,
    pub ttl: Duration,
    /// Cosine similarity threshold in `(0, 1]`. `1.0` disables near-hit lookup (exact only).
    pub similarity_threshold: f32,
    pub embed_dims: usize,
    pub max_index_entries: usize,
}

impl Default for SemanticCacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path_prefixes: default_prefixes(),
            ttl: Duration::from_secs(3600),
            similarity_threshold: 1.0,
            embed_dims: 64,
            max_index_entries: 10_000,
        }
    }
}

fn default_prefixes() -> Vec<String> {
    vec![
        "/v1/chat/completions".to_string(),
        "/v1/completions".to_string(),
        "/chat/completions".to_string(),
    ]
}

impl SemanticCacheConfig {
    pub fn from_env() -> Self {
        let enabled = std::env::var("SEMANTIC_CACHE_ENABLED")
            .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false);

        let path_prefixes = std::env::var("SEMANTIC_CACHE_PATH_PREFIXES")
            .ok()
            .map(|s| {
                s.split(',')
                    .map(str::trim)
                    .filter(|p| !p.is_empty())
                    .map(|p| {
                        if p.starts_with('/') {
                            p.to_string()
                        } else {
                            format!("/{p}")
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .filter(|v| !v.is_empty())
            .unwrap_or_else(default_prefixes);

        let ttl_secs = std::env::var("SEMANTIC_CACHE_TTL_SECONDS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(3600u64)
            .max(1);

        let similarity_threshold = std::env::var("SEMANTIC_CACHE_SIMILARITY")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1.0f32)
            .clamp(0.0, 1.0);

        let embed_dims = std::env::var("SEMANTIC_CACHE_EMBED_DIMS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(64usize)
            .clamp(8, 512);

        let max_index_entries = std::env::var("SEMANTIC_CACHE_MAX_INDEX")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10_000usize)
            .max(1);

        let cfg = Self {
            enabled,
            path_prefixes,
            ttl: Duration::from_secs(ttl_secs),
            similarity_threshold,
            embed_dims,
            max_index_entries,
        };
        if cfg.enabled {
            info!(
                "Semantic/LLM cache enabled (prefixes={:?}, ttl={}s, similarity={})",
                cfg.path_prefixes, ttl_secs, cfg.similarity_threshold
            );
        }
        cfg
    }

    pub fn applies(&self, method: &str, url: &str) -> bool {
        self.enabled
            && method.eq_ignore_ascii_case("POST")
            && path_matches(url, &self.path_prefixes)
    }

    pub fn near_hit_enabled(&self) -> bool {
        self.similarity_threshold < 1.0
    }
}

/// Match URL path against configured prefixes.
pub fn path_matches(url: &str, prefixes: &[String]) -> bool {
    let path = url_path(url);
    prefixes
        .iter()
        .any(|p| path == p.as_str() || path.starts_with(&format!("{p}/")))
}

fn url_path(url: &str) -> &str {
    if let Some(rest) = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
    {
        let path = rest.find('/').map(|i| &rest[i..]).unwrap_or("/");
        path.split('?').next().unwrap_or(path)
    } else {
        url.split('?').next().unwrap_or(url)
    }
}

/// Normalize LLM JSON body for stable exact-match keys (model + messages/prompt).
pub fn normalize_llm_body(body: &[u8]) -> Vec<u8> {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return body.to_vec();
    };
    let Some(obj) = value.as_object() else {
        return body.to_vec();
    };

    let mut out = serde_json::Map::new();
    if let Some(model) = obj.get("model") {
        out.insert("model".into(), model.clone());
    }
    if let Some(messages) = obj.get("messages") {
        out.insert("messages".into(), messages.clone());
    } else if let Some(prompt) = obj.get("prompt") {
        out.insert("prompt".into(), prompt.clone());
    } else {
        // Unknown shape — hash full body as-is.
        return body.to_vec();
    }
    // Intentionally omit temperature/stream/user for higher hit rate on identical prompts.
    serde_json::to_vec(&serde_json::Value::Object(out)).unwrap_or_else(|_| body.to_vec())
}

/// Content-addressable cache key for LLM POST.
pub fn content_cache_key(method: &str, url: &str, normalized_body: &[u8]) -> Arc<str> {
    let mut hasher = Sha256::new();
    hasher.update(method.as_bytes());
    hasher.update(b":");
    hasher.update(url.as_bytes());
    hasher.update(b":");
    hasher.update(normalized_body);
    hex::encode(hasher.finalize()).into()
}

/// Flatten message / prompt text for local embedding.
pub fn extract_embed_text(body: &[u8]) -> String {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return String::from_utf8_lossy(body).into_owned();
    };
    let mut parts = Vec::new();
    if let Some(model) = value.get("model").and_then(|v| v.as_str()) {
        parts.push(model.to_string());
    }
    if let Some(messages) = value.get("messages").and_then(|v| v.as_array()) {
        for msg in messages {
            if let Some(content) = msg.get("content") {
                match content {
                    serde_json::Value::String(s) => parts.push(s.clone()),
                    other => parts.push(other.to_string()),
                }
            }
        }
    } else if let Some(prompt) = value.get("prompt") {
        match prompt {
            serde_json::Value::String(s) => parts.push(s.clone()),
            other => parts.push(other.to_string()),
        }
    }
    if parts.is_empty() {
        String::from_utf8_lossy(body).into_owned()
    } else {
        parts.join("\n")
    }
}

/// Feature-hashing embedding (local PoC; replace with real embeddings later).
pub fn hash_embed(text: &str, dims: usize) -> Vec<f32> {
    let dims = dims.max(1);
    let mut vec = vec![0.0f32; dims];
    for token in text
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
    {
        let mut hasher = Sha256::new();
        hasher.update(token.to_ascii_lowercase().as_bytes());
        let digest = hasher.finalize();
        let idx = u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]) as usize % dims;
        let sign = if digest[4] & 1 == 0 { 1.0 } else { -1.0 };
        vec[idx] += sign;
    }
    let norm = vec.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 0.0 {
        for x in &mut vec {
            *x /= norm;
        }
    }
    vec
}

pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let mut dot = 0.0f32;
    for (x, y) in a.iter().zip(b.iter()) {
        dot += x * y;
    }
    dot.clamp(-1.0, 1.0)
}

struct IndexEntry {
    embedding: Vec<f32>,
    cache_key: Arc<str>,
}

/// In-memory similarity index (prep for external vector DB).
#[derive(Clone, Default)]
pub struct SemanticIndex {
    inner: Arc<Mutex<VecDeque<IndexEntry>>>,
    max_entries: usize,
}

impl SemanticIndex {
    pub fn new(max_entries: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(VecDeque::new())),
            max_entries: max_entries.max(1),
        }
    }

    pub fn insert(&self, embedding: Vec<f32>, cache_key: Arc<str>) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.retain(|e| e.cache_key != cache_key);
        guard.push_back(IndexEntry {
            embedding,
            cache_key,
        });
        while guard.len() > self.max_entries {
            guard.pop_front();
        }
    }

    pub fn find_similar(&self, embedding: &[f32], threshold: f32) -> Option<Arc<str>> {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut best: Option<(f32, Arc<str>)> = None;
        for entry in guard.iter() {
            let score = cosine_similarity(embedding, &entry.embedding);
            if score >= threshold && best.as_ref().map(|(s, _)| score > *s).unwrap_or(true) {
                best = Some((score, entry.cache_key.clone()));
            }
        }
        best.map(|(_, k)| k)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

/// Store decision for LLM responses (ignores typical no-store/private from API providers).
pub fn evaluate_llm_store(
    status: u16,
    body_size: usize,
    max_body_size: usize,
    ttl: Duration,
) -> crate::cache_freshness::CacheStoreDecision {
    use crate::cache_freshness::CacheStoreDecision;
    if status != 200 || body_size == 0 || body_size > max_body_size {
        return CacheStoreDecision::bypass();
    }
    CacheStoreDecision {
        store: true,
        ttl,
        is_negative: false,
        must_revalidate: false,
        etag: None,
        last_modified: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_prefix_matching() {
        let prefixes = default_prefixes();
        assert!(path_matches(
            "https://api.openai.com/v1/chat/completions",
            &prefixes
        ));
        assert!(path_matches("/v1/completions", &prefixes));
        assert!(!path_matches("https://api.openai.com/v1/models", &prefixes));
    }

    #[test]
    fn normalize_keeps_model_and_messages() {
        let body =
            br#"{"model":"gpt","messages":[{"role":"user","content":"hi"}],"temperature":0.9}"#;
        let norm = normalize_llm_body(body);
        let v: serde_json::Value = serde_json::from_slice(&norm).unwrap();
        assert_eq!(v["model"], "gpt");
        assert!(v.get("temperature").is_none());
        assert_eq!(v["messages"][0]["content"], "hi");
    }

    #[test]
    fn content_key_stable() {
        let body = br#"{"model":"m","messages":[{"role":"user","content":"x"}]}"#;
        let n = normalize_llm_body(body);
        let a = content_cache_key("POST", "https://x/v1/chat/completions", &n);
        let b = content_cache_key("POST", "https://x/v1/chat/completions", &n);
        assert_eq!(a, b);
    }

    #[test]
    fn similar_texts_score_high() {
        let a = hash_embed("hello world from the llm cache", 64);
        let b = hash_embed("hello world from the llm cache!", 64);
        assert!(cosine_similarity(&a, &b) > 0.5);
    }

    #[test]
    fn index_finds_near_neighbor() {
        let idx = SemanticIndex::new(10);
        let emb = hash_embed("the quick brown fox", 32);
        idx.insert(emb.clone(), Arc::from("key-1"));
        let hit = idx.find_similar(&emb, 0.99);
        assert_eq!(hit.as_deref(), Some("key-1"));
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn applies_only_to_post_prefixes() {
        let cfg = SemanticCacheConfig {
            enabled: true,
            ..Default::default()
        };
        assert!(cfg.applies("POST", "https://h/v1/chat/completions"));
        assert!(!cfg.applies("GET", "https://h/v1/chat/completions"));
    }
}
