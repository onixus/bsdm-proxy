//! LLM / semantic cache: content-addressable POST keys + pluggable similarity index.
//!
//! Exact hits use a SHA-256 of method + URL + normalized JSON body.
//! Near-hits (opt-in) use embeddings + cosine / vector search.
//! Backends: in-memory (default) or Qdrant HTTP (`SEMANTIC_VECTOR_BACKEND=qdrant`).

use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{info, warn};

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
    /// `local` (default) or `qdrant`.
    pub vector_backend: VectorBackendKind,
    /// Qdrant base URL, e.g. `http://127.0.0.1:6333`.
    pub vector_url: Option<String>,
    pub vector_collection: String,
    pub vector_api_key: Option<String>,
    /// `local` hash embed (default) or `http` remote embed API.
    pub embed_provider: EmbedProviderKind,
    /// POST JSON `{"text","dims"}` → `{"embedding":[...]}`.
    pub embed_url: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VectorBackendKind {
    Local,
    Qdrant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmbedProviderKind {
    Local,
    Http,
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
            vector_backend: VectorBackendKind::Local,
            vector_url: None,
            vector_collection: "bsdm_semantic".into(),
            vector_api_key: None,
            embed_provider: EmbedProviderKind::Local,
            embed_url: None,
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

fn env_flag(name: &str, default: bool) -> bool {
    std::env::var(name)
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(default)
}

fn env_opt(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

impl SemanticCacheConfig {
    pub fn from_env() -> Self {
        let enabled = env_flag("SEMANTIC_CACHE_ENABLED", false);

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

        let vector_backend = match std::env::var("SEMANTIC_VECTOR_BACKEND")
            .unwrap_or_else(|_| "local".into())
            .to_ascii_lowercase()
            .as_str()
        {
            "qdrant" => VectorBackendKind::Qdrant,
            _ => VectorBackendKind::Local,
        };
        let vector_url = env_opt("SEMANTIC_VECTOR_URL");
        let vector_collection =
            env_opt("SEMANTIC_VECTOR_COLLECTION").unwrap_or_else(|| "bsdm_semantic".into());
        let vector_api_key = env_opt("SEMANTIC_VECTOR_API_KEY");

        let embed_provider = match std::env::var("SEMANTIC_EMBED_PROVIDER")
            .unwrap_or_else(|_| "local".into())
            .to_ascii_lowercase()
            .as_str()
        {
            "http" => EmbedProviderKind::Http,
            _ => EmbedProviderKind::Local,
        };
        let embed_url = env_opt("SEMANTIC_EMBED_URL");

        let cfg = Self {
            enabled,
            path_prefixes,
            ttl: Duration::from_secs(ttl_secs),
            similarity_threshold,
            embed_dims,
            max_index_entries,
            vector_backend,
            vector_url,
            vector_collection,
            vector_api_key,
            embed_provider,
            embed_url,
        };
        if cfg.enabled {
            info!(
                "Semantic/LLM cache enabled (prefixes={:?}, ttl={}s, similarity={}, vector={:?}, embed={:?})",
                cfg.path_prefixes,
                ttl_secs,
                cfg.similarity_threshold,
                cfg.vector_backend,
                cfg.embed_provider
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

    /// Produce an embedding for near-hit indexing / search.
    pub async fn embed(&self, text: &str) -> Result<Vec<f32>, String> {
        match self.embed_provider {
            EmbedProviderKind::Local => Ok(hash_embed(text, self.embed_dims)),
            EmbedProviderKind::Http => {
                let url = self.embed_url.as_deref().ok_or_else(|| {
                    "SEMANTIC_EMBED_URL required for http embed provider".to_string()
                })?;
                let client = reqwest::Client::new();
                let resp = client
                    .post(url)
                    .json(&serde_json::json!({
                        "text": text,
                        "dims": self.embed_dims,
                    }))
                    .send()
                    .await
                    .map_err(|e| format!("embed HTTP: {e}"))?;
                if !resp.status().is_success() {
                    return Err(format!("embed HTTP status {}", resp.status()));
                }
                let body: serde_json::Value =
                    resp.json().await.map_err(|e| format!("embed JSON: {e}"))?;
                let arr = body
                    .get("embedding")
                    .and_then(|v| v.as_array())
                    .ok_or_else(|| "embed response missing embedding[]".to_string())?;
                let mut out = Vec::with_capacity(arr.len());
                for v in arr {
                    out.push(v.as_f64().unwrap_or(0.0) as f32);
                }
                if out.len() != self.embed_dims {
                    return Err(format!(
                        "embed dims mismatch: got {} want {}",
                        out.len(),
                        self.embed_dims
                    ));
                }
                Ok(out)
            }
        }
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
        return body.to_vec();
    }
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

/// Feature-hashing embedding (local PoC; replace with real embeddings via HTTP provider).
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

fn point_id_u64(cache_key: &str) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(cache_key.as_bytes());
    let digest = hasher.finalize();
    u64::from_le_bytes(digest[0..8].try_into().unwrap())
}

struct IndexEntry {
    embedding: Vec<f32>,
    cache_key: Arc<str>,
}

struct LocalIndex {
    inner: Mutex<VecDeque<IndexEntry>>,
    max_entries: usize,
}

impl LocalIndex {
    fn new(max_entries: usize) -> Self {
        Self {
            inner: Mutex::new(VecDeque::new()),
            max_entries: max_entries.max(1),
        }
    }

    fn insert(&self, embedding: Vec<f32>, cache_key: Arc<str>) {
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

    fn find_similar(&self, embedding: &[f32], threshold: f32) -> Option<Arc<str>> {
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

struct QdrantIndex {
    client: reqwest::Client,
    base_url: String,
    collection: String,
    api_key: Option<String>,
    dims: usize,
    ensure_once: Mutex<bool>,
}

impl QdrantIndex {
    fn new(cfg: &SemanticCacheConfig) -> Result<Self, String> {
        let base_url = cfg
            .vector_url
            .clone()
            .ok_or_else(|| "SEMANTIC_VECTOR_URL required for qdrant backend".to_string())?
            .trim_end_matches('/')
            .to_string();
        Ok(Self {
            client: reqwest::Client::new(),
            base_url,
            collection: cfg.vector_collection.clone(),
            api_key: cfg.vector_api_key.clone(),
            dims: cfg.embed_dims,
            ensure_once: Mutex::new(false),
        })
    }

    fn apply_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(key) = &self.api_key {
            req.header("api-key", key)
        } else {
            req
        }
    }

    async fn ensure_collection(&self) -> Result<(), String> {
        {
            let guard = self.ensure_once.lock().unwrap_or_else(|e| e.into_inner());
            if *guard {
                return Ok(());
            }
        }
        let url = format!("{}/collections/{}", self.base_url, self.collection);
        let req = self
            .apply_auth(self.client.put(&url))
            .json(&serde_json::json!({
                "vectors": {
                    "size": self.dims,
                    "distance": "Cosine"
                }
            }));
        let resp = req
            .send()
            .await
            .map_err(|e| format!("qdrant create collection: {e}"))?;
        // 200 OK or already exists (varies by version) — accept 2xx / 409
        if !(resp.status().is_success() || resp.status().as_u16() == 409) {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            // GET to check existence
            let get = self
                .apply_auth(self.client.get(&url))
                .send()
                .await
                .map_err(|e| format!("qdrant get collection: {e}"))?;
            if !get.status().is_success() {
                return Err(format!(
                    "qdrant ensure collection failed: create={status} body={body}"
                ));
            }
        }
        let mut guard = self.ensure_once.lock().unwrap_or_else(|e| e.into_inner());
        *guard = true;
        Ok(())
    }

    async fn upsert(&self, embedding: Vec<f32>, cache_key: Arc<str>) -> Result<(), String> {
        self.ensure_collection().await?;
        let url = format!(
            "{}/collections/{}/points?wait=true",
            self.base_url, self.collection
        );
        let id = point_id_u64(&cache_key);
        let req = self
            .apply_auth(self.client.put(&url))
            .json(&serde_json::json!({
                "points": [{
                    "id": id,
                    "vector": embedding,
                    "payload": { "cache_key": cache_key.as_ref() }
                }]
            }));
        let resp = req
            .send()
            .await
            .map_err(|e| format!("qdrant upsert: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!(
                "qdrant upsert status {} {}",
                resp.status(),
                resp.text().await.unwrap_or_default()
            ));
        }
        Ok(())
    }

    async fn search(&self, embedding: &[f32], threshold: f32) -> Result<Option<Arc<str>>, String> {
        self.ensure_collection().await?;
        let url = format!(
            "{}/collections/{}/points/search",
            self.base_url, self.collection
        );
        let req = self
            .apply_auth(self.client.post(&url))
            .json(&serde_json::json!({
                "vector": embedding,
                "limit": 1,
                "score_threshold": threshold,
                "with_payload": true
            }));
        let resp = req
            .send()
            .await
            .map_err(|e| format!("qdrant search: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!(
                "qdrant search status {} {}",
                resp.status(),
                resp.text().await.unwrap_or_default()
            ));
        }
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("qdrant search JSON: {e}"))?;
        let result = body
            .get("result")
            .and_then(|v| v.as_array())
            .and_then(|a| a.first());
        let Some(hit) = result else {
            return Ok(None);
        };
        let key = hit
            .pointer("/payload/cache_key")
            .and_then(|v| v.as_str())
            .map(Arc::<str>::from);
        Ok(key)
    }
}

enum IndexBackend {
    Local(LocalIndex),
    Qdrant(QdrantIndex),
}

/// Pluggable similarity index (local memory or Qdrant HTTP).
#[derive(Clone)]
pub struct SemanticIndex {
    backend: Arc<IndexBackend>,
}

impl Default for SemanticIndex {
    fn default() -> Self {
        Self::local(10_000)
    }
}

impl SemanticIndex {
    pub fn local(max_entries: usize) -> Self {
        Self {
            backend: Arc::new(IndexBackend::Local(LocalIndex::new(max_entries))),
        }
    }

    pub fn from_config(cfg: &SemanticCacheConfig) -> Self {
        match cfg.vector_backend {
            VectorBackendKind::Local => Self::local(cfg.max_index_entries),
            VectorBackendKind::Qdrant => match QdrantIndex::new(cfg) {
                Ok(q) => {
                    info!(
                        "Semantic vector backend: qdrant {} collection={}",
                        q.base_url, q.collection
                    );
                    Self {
                        backend: Arc::new(IndexBackend::Qdrant(q)),
                    }
                }
                Err(e) => {
                    warn!("Qdrant vector backend unavailable ({e}); falling back to local index");
                    Self::local(cfg.max_index_entries)
                }
            },
        }
    }

    pub async fn insert(&self, embedding: Vec<f32>, cache_key: Arc<str>) -> Result<(), String> {
        match self.backend.as_ref() {
            IndexBackend::Local(local) => {
                local.insert(embedding, cache_key);
                Ok(())
            }
            IndexBackend::Qdrant(q) => q.upsert(embedding, cache_key).await,
        }
    }

    pub async fn find_similar(
        &self,
        embedding: &[f32],
        threshold: f32,
    ) -> Result<Option<Arc<str>>, String> {
        match self.backend.as_ref() {
            IndexBackend::Local(local) => Ok(local.find_similar(embedding, threshold)),
            IndexBackend::Qdrant(q) => q.search(embedding, threshold).await,
        }
    }

    #[cfg(test)]
    fn len_local(&self) -> Option<usize> {
        match self.backend.as_ref() {
            IndexBackend::Local(local) => Some(local.len()),
            IndexBackend::Qdrant(_) => None,
        }
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

    #[tokio::test]
    async fn index_finds_near_neighbor() {
        let idx = SemanticIndex::local(10);
        let emb = hash_embed("the quick brown fox", 32);
        idx.insert(emb.clone(), Arc::from("key-1")).await.unwrap();
        let hit = idx.find_similar(&emb, 0.99).await.unwrap();
        assert_eq!(hit.as_deref(), Some("key-1"));
        assert_eq!(idx.len_local(), Some(1));
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

    #[tokio::test]
    async fn local_embed_provider() {
        let cfg = SemanticCacheConfig::default();
        let v = cfg.embed("hello").await.unwrap();
        assert_eq!(v.len(), cfg.embed_dims);
    }

    /// Wire-format unit test: Qdrant upsert/search JSON shape via httptest mock.
    #[tokio::test]
    async fn qdrant_backend_upsert_and_search() {
        use std::convert::Infallible;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let state = Arc::new(Mutex::new(Vec::<(u64, Vec<f32>, String)>::new()));
        let state_accept = state.clone();

        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let state = state_accept.clone();
                tokio::spawn(async move {
                    let io = hyper_util::rt::TokioIo::new(stream);
                    let service = hyper::service::service_fn(
                        move |req: hyper::Request<hyper::body::Incoming>| {
                            let state = state.clone();
                            async move {
                                let path = req.uri().path().to_string();
                                let method = req.method().clone();
                                let body = http_body_util::BodyExt::collect(req.into_body())
                                    .await
                                    .unwrap()
                                    .to_bytes();
                                let mut status = hyper::StatusCode::OK;
                                let mut resp_body = br#"{"result":true}"#.to_vec();

                                if method == hyper::Method::PUT
                                    && path.contains("/collections/")
                                    && !path.contains("/points")
                                {
                                    resp_body = br#"{"result":true}"#.to_vec();
                                } else if method == hyper::Method::GET
                                    && path.contains("/collections/")
                                {
                                    resp_body = br#"{"result":{"status":"green"}}"#.to_vec();
                                } else if method == hyper::Method::PUT && path.contains("/points") {
                                    let v: serde_json::Value =
                                        serde_json::from_slice(&body).unwrap();
                                    let p = &v["points"][0];
                                    let id = p["id"].as_u64().unwrap();
                                    let vec: Vec<f32> = p["vector"]
                                        .as_array()
                                        .unwrap()
                                        .iter()
                                        .map(|x| x.as_f64().unwrap() as f32)
                                        .collect();
                                    let key =
                                        p["payload"]["cache_key"].as_str().unwrap().to_string();
                                    state.lock().unwrap().push((id, vec, key));
                                } else if method == hyper::Method::POST && path.contains("/search")
                                {
                                    let v: serde_json::Value =
                                        serde_json::from_slice(&body).unwrap();
                                    let q: Vec<f32> = v["vector"]
                                        .as_array()
                                        .unwrap()
                                        .iter()
                                        .map(|x| x.as_f64().unwrap() as f32)
                                        .collect();
                                    let thr = v["score_threshold"].as_f64().unwrap_or(0.0) as f32;
                                    let guard = state.lock().unwrap();
                                    let mut best: Option<(f32, String)> = None;
                                    for (_id, emb, key) in guard.iter() {
                                        let score = cosine_similarity(&q, emb);
                                        if score >= thr
                                            && best
                                                .as_ref()
                                                .map(|(s, _)| score > *s)
                                                .unwrap_or(true)
                                        {
                                            best = Some((score, key.clone()));
                                        }
                                    }
                                    resp_body = if let Some((score, key)) = best {
                                        serde_json::json!({
                                            "result": [{
                                                "score": score,
                                                "payload": { "cache_key": key }
                                            }]
                                        })
                                        .to_string()
                                        .into_bytes()
                                    } else {
                                        br#"{"result":[]}"#.to_vec()
                                    };
                                } else {
                                    status = hyper::StatusCode::NOT_FOUND;
                                    resp_body = br#"{"status":{"error":"not found"}}"#.to_vec();
                                }

                                let resp = hyper::Response::builder()
                                    .status(status)
                                    .header("content-type", "application/json")
                                    .body(http_body_util::Full::new(bytes::Bytes::from(resp_body)))
                                    .unwrap();
                                Ok::<_, Infallible>(resp)
                            }
                        },
                    );
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service)
                        .await;
                });
            }
        });

        let cfg = SemanticCacheConfig {
            enabled: true,
            similarity_threshold: 0.9,
            embed_dims: 8,
            vector_backend: VectorBackendKind::Qdrant,
            vector_url: Some(format!("http://127.0.0.1:{port}")),
            vector_collection: "test".into(),
            ..Default::default()
        };
        let idx = SemanticIndex::from_config(&cfg);
        let emb = hash_embed("qdrant wire test", 8);
        idx.insert(emb.clone(), Arc::from("ck-1")).await.unwrap();
        let hit = idx.find_similar(&emb, 0.9).await.unwrap();
        assert_eq!(hit.as_deref(), Some("ck-1"));
    }
}
