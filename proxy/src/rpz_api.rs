//! File-backed RPZ management API for Admin Console (`/api/dns/*`).
//!
//! State directory (`DNS_RPZ_STATE_DIR`, default `./data/rpz` or
//! `/var/lib/bsdm-proxy/rpz`):
//! - `state.json` — lists metadata + custom rules
//! - `lists/<id>.txt` — raw list content
//! - compiled zone written to `DNS_SINKHOLE_ZONE_PATH` (or state_dir/compiled.rpz)
//!
//! After mutations we optionally POST `DNS_SINKHOLE_RELOAD_URL` (e.g.
//! `http://dns-sinkhole:8092/api/zone/reload`).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use hyper::{Method, Response, StatusCode};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::http_types::{full, Body};

fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RpzListFormat {
    #[serde(rename = "rpz-zone")]
    RpzZone,
    Hosts,
    #[serde(rename = "domain-list")]
    DomainList,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RpzAction {
    Nxdomain,
    Nodata,
    Passthru,
    Drop,
    Sinkhole,
}

impl RpzAction {
    fn as_api(&self) -> &'static str {
        match self {
            Self::Nxdomain => "NXDOMAIN",
            Self::Nodata => "NODATA",
            Self::Passthru => "PASSTHRU",
            Self::Drop => "DROP",
            Self::Sinkhole => "SINKHOLE",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RpzListSource {
    Upload,
    #[serde(rename = "url_feed")]
    UrlFeed,
    Inline,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpzList {
    pub id: String,
    pub name: String,
    pub description: String,
    pub source: RpzListSource,
    pub format: RpzListFormat,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(rename = "defaultAction")]
    pub default_action: RpzAction,
    #[serde(rename = "ruleCount")]
    pub rule_count: u64,
    pub active: bool,
    pub priority: i32,
    #[serde(rename = "lastUpdated")]
    pub last_updated: String,
    #[serde(rename = "syncError", skip_serializing_if = "Option::is_none")]
    pub sync_error: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpzRule {
    pub id: String,
    #[serde(rename = "listId")]
    pub list_id: String,
    #[serde(rename = "listName")]
    pub list_name: String,
    pub domain: String,
    pub action: RpzAction,
    #[serde(rename = "targetIp", skip_serializing_if = "Option::is_none")]
    pub target_ip: Option<String>,
    #[serde(rename = "targetCname", skip_serializing_if = "Option::is_none")]
    pub target_cname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsSinkholeConfig {
    pub enabled: bool,
    #[serde(rename = "defaultAction")]
    pub default_action: RpzAction,
    #[serde(rename = "sinkholeIpv4")]
    pub sinkhole_ipv4: String,
    #[serde(rename = "sinkholeIpv6")]
    pub sinkhole_ipv6: String,
    #[serde(rename = "sinkholeCname")]
    pub sinkhole_cname: String,
    #[serde(rename = "logBlocks")]
    pub log_blocks: bool,
    #[serde(rename = "wildcardMatching")]
    pub wildcard_matching: bool,
    #[serde(rename = "upstreamDns")]
    pub upstream_dns: Vec<String>,
    #[serde(rename = "dohEnabled")]
    pub doh_enabled: bool,
    #[serde(rename = "dohBind")]
    pub doh_bind: String,
    #[serde(rename = "dohPath")]
    pub doh_path: String,
    #[serde(rename = "dotEnabled")]
    pub dot_enabled: bool,
    #[serde(rename = "dotBind")]
    pub dot_bind: String,
}

impl Default for DnsSinkholeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_action: RpzAction::Sinkhole,
            sinkhole_ipv4: "127.0.0.1".into(),
            sinkhole_ipv6: "::1".into(),
            sinkhole_cname: String::new(),
            log_blocks: true,
            wildcard_matching: true,
            upstream_dns: vec!["1.1.1.1".into()],
            doh_enabled: false,
            doh_bind: "0.0.0.0:8443".into(),
            doh_path: "/dns-query".into(),
            dot_enabled: false,
            dot_bind: "0.0.0.0:853".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct RpzStateFile {
    lists: Vec<RpzList>,
    custom_rules: Vec<RpzRule>,
    config: DnsSinkholeConfig,
}

pub struct RpzApiState {
    inner: RwLock<RpzStateFile>,
    state_dir: PathBuf,
    zone_path: PathBuf,
    reload_url: Option<String>,
}

impl RpzApiState {
    pub fn from_env() -> Arc<Self> {
        let state_dir = std::env::var("DNS_RPZ_STATE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                let p = PathBuf::from("/var/lib/bsdm-proxy/rpz");
                if p.parent().is_some_and(|d| d.exists()) {
                    p
                } else {
                    PathBuf::from("./data/rpz")
                }
            });
        let zone_path = std::env::var("DNS_SINKHOLE_ZONE_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| state_dir.join("compiled.rpz"));
        let reload_url = std::env::var("DNS_SINKHOLE_RELOAD_URL")
            .ok()
            .filter(|s| !s.trim().is_empty());
        let state = Self::load_or_default(&state_dir);
        let api = Self {
            inner: RwLock::new(state.clone()),
            state_dir: state_dir.clone(),
            zone_path: zone_path.clone(),
            reload_url,
        };
        // Ensure compiled zone exists for dns-sinkhole first boot. Compile from
        // the state we just loaded rather than taking the lock: `blocking_read`
        // panics when `from_env` runs inside a Tokio runtime, which is exactly
        // how the proxy starts up (`#[tokio::main]` → `ControlApiState::from_env`).
        if let Err(e) = api.compile_zone(&state) {
            warn!("initial RPZ zone compile: {e}");
        }
        Arc::new(api)
    }

    fn load_or_default(dir: &Path) -> RpzStateFile {
        let path = dir.join("state.json");
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(s) = serde_json::from_str(&text) {
                return s;
            }
        }
        // Seed one list representing the on-disk zone if present
        let mut state = RpzStateFile {
            config: DnsSinkholeConfig::default(),
            ..Default::default()
        };
        let seed = PathBuf::from(
            std::env::var("DNS_SINKHOLE_ZONE_PATH")
                .unwrap_or_else(|_| "./examples/dns/blocklist.rpz".into()),
        );
        if let Ok(content) = std::fs::read_to_string(&seed) {
            let count = count_rules(&content);
            state.lists.push(RpzList {
                id: "local-zone".into(),
                name: "Local blocklist.rpz".into(),
                description: "Seeded from DNS_SINKHOLE_ZONE_PATH / compose mount".into(),
                source: RpzListSource::Upload,
                format: RpzListFormat::RpzZone,
                url: None,
                default_action: RpzAction::Sinkhole,
                rule_count: count,
                active: true,
                priority: 100,
                last_updated: now_rfc3339(),
                sync_error: None,
                tags: vec!["local".into(), "seed".into()],
            });
            let _ = std::fs::create_dir_all(dir.join("lists"));
            let _ = std::fs::write(dir.join("lists/local-zone.txt"), content);
        }
        state
    }

    async fn persist(&self, state: &RpzStateFile) -> Result<(), String> {
        std::fs::create_dir_all(&self.state_dir).map_err(|e| format!("create state dir: {e}"))?;
        std::fs::create_dir_all(self.state_dir.join("lists"))
            .map_err(|e| format!("create lists dir: {e}"))?;
        let path = self.state_dir.join("state.json");
        let tmp = self.state_dir.join("state.json.tmp");
        let text = serde_json::to_string_pretty(state).map_err(|e| e.to_string())?;
        std::fs::write(&tmp, format!("{text}\n")).map_err(|e| format!("write state tmp: {e}"))?;
        std::fs::rename(&tmp, &path).map_err(|e| format!("rename state: {e}"))?;
        self.compile_zone(state)?;
        self.trigger_reload().await;
        Ok(())
    }

    fn compile_zone(&self, state: &RpzStateFile) -> Result<(), String> {
        let mut out =
            String::from("; Generated by BSDM RPZ API — do not edit by hand\n$TTL 300\n\n");
        let mut lists: Vec<&RpzList> = state.lists.iter().filter(|l| l.active).collect();
        lists.sort_by_key(|l| std::cmp::Reverse(l.priority));
        for list in lists {
            out.push_str(&format!("; list {} ({})\n", list.id, list.name));
            let content_path = self
                .state_dir
                .join("lists")
                .join(format!("{}.txt", list.id));
            if let Ok(content) = std::fs::read_to_string(&content_path) {
                out.push_str(&normalize_list_content(
                    &content,
                    &list.format,
                    &list.default_action,
                ));
            }
            out.push('\n');
        }
        out.push_str("; custom rules\n");
        for rule in &state.custom_rules {
            out.push_str(&rule_to_zone_line(rule));
            out.push('\n');
        }
        if let Some(parent) = self.zone_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("zone parent: {e}"))?;
        }
        let tmp = self.zone_path.with_extension("rpz.tmp");
        std::fs::write(&tmp, out).map_err(|e| format!("write zone tmp: {e}"))?;
        std::fs::rename(&tmp, &self.zone_path).map_err(|e| format!("rename zone: {e}"))?;
        info!(path = %self.zone_path.display(), "compiled RPZ zone");
        Ok(())
    }

    async fn trigger_reload(&self) {
        let Some(url) = &self.reload_url else {
            return;
        };
        match reqwest::Client::new()
            .post(url)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {
                info!(%url, "dns-sinkhole zone reload ok");
            }
            Ok(r) => warn!(%url, status = %r.status(), "dns-sinkhole reload non-success"),
            Err(e) => warn!(%url, "dns-sinkhole reload failed: {e}"),
        }
    }

    pub async fn dispatch(
        &self,
        method: &Method,
        path: &str,
        query: &str,
        body: Bytes,
    ) -> Option<Response<Body>> {
        if !path.starts_with("/api/dns/") {
            return None;
        }
        Some(self.handle(method, path, query, body).await)
    }

    async fn handle(
        &self,
        method: &Method,
        path: &str,
        query: &str,
        body: Bytes,
    ) -> Response<Body> {
        // /api/dns/rpz/lists
        if path == "/api/dns/rpz/lists" {
            return match *method {
                Method::GET => self.list_lists().await,
                Method::POST => self.add_list(body).await,
                _ => method_not_allowed(),
            };
        }
        if let Some(rest) = path.strip_prefix("/api/dns/rpz/lists/") {
            if let Some(id) = rest.strip_suffix("/toggle") {
                if *method == Method::POST {
                    return self.toggle_list(id, body).await;
                }
            }
            if let Some(id) = rest.strip_suffix("/sync") {
                if *method == Method::POST {
                    return self.sync_list(id).await;
                }
            }
            if *method == Method::DELETE {
                return self.delete_list(rest).await;
            }
        }
        if path == "/api/dns/sinkhole/config" {
            return match *method {
                Method::GET => self.get_config().await,
                Method::PUT => self.put_config(body).await,
                _ => method_not_allowed(),
            };
        }
        if path == "/api/dns/rpz/test" && *method == Method::POST {
            return self.test_domain(query).await;
        }
        if path == "/api/dns/rpz/stats" && *method == Method::GET {
            return self.stats().await;
        }
        if path == "/api/dns/rpz/rules/custom" {
            return match *method {
                Method::GET => self.list_rules().await,
                Method::POST => self.add_rule(body).await,
                _ => method_not_allowed(),
            };
        }
        if let Some(id) = path.strip_prefix("/api/dns/rpz/rules/custom/") {
            if *method == Method::DELETE {
                return self.delete_rule(id).await;
            }
        }
        json_err(StatusCode::NOT_FOUND, "not found")
    }

    async fn list_lists(&self) -> Response<Body> {
        let g = self.inner.read().await;
        json_ok(&g.lists)
    }

    async fn add_list(&self, body: Bytes) -> Response<Body> {
        #[derive(Deserialize)]
        struct In {
            name: String,
            description: String,
            source: RpzListSource,
            format: RpzListFormat,
            url: Option<String>,
            content: Option<String>,
            #[serde(rename = "defaultAction")]
            default_action: RpzAction,
            priority: Option<i32>,
        }
        let input: In = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(e) => return json_err(StatusCode::BAD_REQUEST, &e.to_string()),
        };
        let id = format!("rpz-{}", now_millis());
        let mut content = input.content.unwrap_or_default();
        if content.is_empty() {
            if let Some(url) = &input.url {
                match fetch_url(url).await {
                    Ok(t) => content = t,
                    Err(e) => {
                        return json_err(StatusCode::BAD_GATEWAY, &format!("fetch feed: {e}"));
                    }
                }
            }
        }
        let rule_count = count_rules(&content);
        let list = RpzList {
            id: id.clone(),
            name: input.name,
            description: input.description,
            source: input.source,
            format: input.format.clone(),
            url: input.url,
            default_action: input.default_action,
            rule_count,
            active: true,
            priority: input.priority.unwrap_or(10),
            last_updated: now_rfc3339(),
            sync_error: None,
            tags: vec![format!("{:?}", input.format).to_lowercase()],
        };
        let mut g = self.inner.write().await;
        let _ = std::fs::create_dir_all(self.state_dir.join("lists"));
        if let Err(e) = std::fs::write(
            self.state_dir.join("lists").join(format!("{id}.txt")),
            &content,
        ) {
            return json_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string());
        }
        g.lists.insert(0, list.clone());
        if let Err(e) = self.persist(&g).await {
            return json_err(StatusCode::INTERNAL_SERVER_ERROR, &e);
        }
        json_ok(&list)
    }

    async fn toggle_list(&self, id: &str, body: Bytes) -> Response<Body> {
        #[derive(Deserialize)]
        struct In {
            active: bool,
        }
        let input: In = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(e) => return json_err(StatusCode::BAD_REQUEST, &e.to_string()),
        };
        let mut g = self.inner.write().await;
        let Some(list) = g.lists.iter_mut().find(|l| l.id == id) else {
            return json_err(StatusCode::NOT_FOUND, "list not found");
        };
        list.active = input.active;
        list.last_updated = now_rfc3339();
        if let Err(e) = self.persist(&g).await {
            return json_err(StatusCode::INTERNAL_SERVER_ERROR, &e);
        }
        json_ok(&serde_json::json!({"status":"ok"}))
    }

    async fn sync_list(&self, id: &str) -> Response<Body> {
        let mut g = self.inner.write().await;
        let Some(list) = g.lists.iter_mut().find(|l| l.id == id) else {
            return json_err(StatusCode::NOT_FOUND, "list not found");
        };
        let url = list.url.clone();
        if let Some(url) = url {
            match fetch_url(&url).await {
                Ok(content) => {
                    list.rule_count = count_rules(&content);
                    list.last_updated = now_rfc3339();
                    list.sync_error = None;
                    let _ = std::fs::write(
                        self.state_dir.join("lists").join(format!("{id}.txt")),
                        content,
                    );
                }
                Err(e) => {
                    list.sync_error = Some(e.clone());
                    list.last_updated = now_rfc3339();
                }
            }
        } else {
            list.last_updated = now_rfc3339();
        }
        let out = list.clone();
        if let Err(e) = self.persist(&g).await {
            return json_err(StatusCode::INTERNAL_SERVER_ERROR, &e);
        }
        json_ok(&out)
    }

    async fn delete_list(&self, id: &str) -> Response<Body> {
        let mut g = self.inner.write().await;
        let before = g.lists.len();
        g.lists.retain(|l| l.id != id);
        if g.lists.len() == before {
            return json_err(StatusCode::NOT_FOUND, "list not found");
        }
        let _ = std::fs::remove_file(self.state_dir.join("lists").join(format!("{id}.txt")));
        if let Err(e) = self.persist(&g).await {
            return json_err(StatusCode::INTERNAL_SERVER_ERROR, &e);
        }
        json_ok(&serde_json::json!({"status":"deleted"}))
    }

    async fn get_config(&self) -> Response<Body> {
        let g = self.inner.read().await;
        json_ok(&g.config)
    }

    async fn put_config(&self, body: Bytes) -> Response<Body> {
        let cfg: DnsSinkholeConfig = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(e) => return json_err(StatusCode::BAD_REQUEST, &e.to_string()),
        };
        let mut g = self.inner.write().await;
        g.config = cfg.clone();
        if let Err(e) = self.persist(&g).await {
            return json_err(StatusCode::INTERNAL_SERVER_ERROR, &e);
        }
        json_ok(&cfg)
    }

    async fn test_domain(&self, query: &str) -> Response<Body> {
        let domain = query
            .split('&')
            .find_map(|p| p.strip_prefix("domain="))
            .map(percent_decode)
            .unwrap_or_default()
            .to_ascii_lowercase();
        let g = self.inner.read().await;
        let start = std::time::Instant::now();
        // Scan custom rules then active list contents
        for rule in &g.custom_rules {
            if domain_matches(&domain, &rule.domain) {
                return json_ok(&serde_json::json!({
                    "domain": domain,
                    "matched": true,
                    "matchedRule": {
                        "domain": rule.domain,
                        "action": rule.action.as_api(),
                        "listId": rule.list_id,
                        "listName": rule.list_name,
                    },
                    "appliedAction": rule.action.as_api(),
                    "targetResponse": action_response(&rule.action, &g.config),
                    "durationMs": start.elapsed().as_secs_f64() * 1000.0,
                }));
            }
        }
        let mut lists: Vec<&RpzList> = g.lists.iter().filter(|l| l.active).collect();
        lists.sort_by_key(|l| std::cmp::Reverse(l.priority));
        for list in lists {
            let path = self
                .state_dir
                .join("lists")
                .join(format!("{}.txt", list.id));
            if let Ok(content) = std::fs::read_to_string(path) {
                if content_has_domain(&content, &domain) {
                    return json_ok(&serde_json::json!({
                        "domain": domain,
                        "matched": true,
                        "matchedRule": {
                            "domain": domain,
                            "action": list.default_action.as_api(),
                            "listId": list.id,
                            "listName": list.name,
                        },
                        "appliedAction": list.default_action.as_api(),
                        "targetResponse": action_response(&list.default_action, &g.config),
                        "durationMs": start.elapsed().as_secs_f64() * 1000.0,
                    }));
                }
            }
        }
        json_ok(&serde_json::json!({
            "domain": domain,
            "matched": false,
            "appliedAction": "PASSTHRU",
            "targetResponse": format!("Allowed (upstream {})", g.config.upstream_dns.first().cloned().unwrap_or_else(|| "1.1.1.1".into())),
            "durationMs": start.elapsed().as_secs_f64() * 1000.0,
        }))
    }

    async fn stats(&self) -> Response<Body> {
        let g = self.inner.read().await;
        let active: Vec<_> = g.lists.iter().filter(|l| l.active).collect();
        let total_rules: u64 =
            active.iter().map(|l| l.rule_count).sum::<u64>() + g.custom_rules.len() as u64;
        json_ok(&serde_json::json!({
            "totalLists": g.lists.len(),
            "activeLists": active.len(),
            "totalRules": total_rules,
            "blocked24h": 0,
            "dohQueries24h": 0,
            "dotQueries24h": 0,
            "topDomains": [],
        }))
    }

    async fn list_rules(&self) -> Response<Body> {
        let g = self.inner.read().await;
        json_ok(&g.custom_rules)
    }

    async fn add_rule(&self, body: Bytes) -> Response<Body> {
        #[derive(Deserialize)]
        struct In {
            domain: String,
            action: RpzAction,
            comment: Option<String>,
        }
        let input: In = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(e) => return json_err(StatusCode::BAD_REQUEST, &e.to_string()),
        };
        let rule = RpzRule {
            id: format!("rule-{}", now_millis()),
            list_id: "custom-inline".into(),
            list_name: "Custom Overrides".into(),
            domain: input
                .domain
                .trim()
                .trim_end_matches('.')
                .to_ascii_lowercase(),
            action: input.action,
            target_ip: None,
            target_cname: None,
            comment: input.comment,
            created_at: now_rfc3339(),
        };
        let mut g = self.inner.write().await;
        g.custom_rules.insert(0, rule.clone());
        if let Err(e) = self.persist(&g).await {
            return json_err(StatusCode::INTERNAL_SERVER_ERROR, &e);
        }
        json_ok(&rule)
    }

    async fn delete_rule(&self, id: &str) -> Response<Body> {
        let mut g = self.inner.write().await;
        let before = g.custom_rules.len();
        g.custom_rules.retain(|r| r.id != id);
        if g.custom_rules.len() == before {
            return json_err(StatusCode::NOT_FOUND, "rule not found");
        }
        if let Err(e) = self.persist(&g).await {
            return json_err(StatusCode::INTERNAL_SERVER_ERROR, &e);
        }
        json_ok(&serde_json::json!({"status":"deleted"}))
    }
}

fn json_ok<T: Serialize>(v: &T) -> Response<Body> {
    match serde_json::to_vec(v) {
        Ok(bytes) => Response::builder()
            .status(StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(full(Bytes::from(bytes)))
            .unwrap_or_else(|_| Response::new(full(Bytes::from_static(b"{}")))),
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

fn json_err(status: StatusCode, msg: &str) -> Response<Body> {
    let body = format!(r#"{{"error":"{}"}}"#, escape_json(msg));
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(full(Bytes::from(body)))
        .unwrap_or_else(|_| Response::new(full(Bytes::from_static(b"{\"error\":\"err\"}"))))
}

fn method_not_allowed() -> Response<Body> {
    json_err(StatusCode::METHOD_NOT_ALLOWED, "method not allowed")
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn count_rules(content: &str) -> u64 {
    content
        .lines()
        .filter(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with('#') && !t.starts_with(';') && !t.starts_with('$')
        })
        .count() as u64
}

fn normalize_list_content(content: &str, format: &RpzListFormat, action: &RpzAction) -> String {
    let mut out = String::new();
    for line in content.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') || t.starts_with(';') || t.starts_with('$') {
            continue;
        }
        match format {
            RpzListFormat::RpzZone => {
                out.push_str(t);
                out.push('\n');
            }
            RpzListFormat::Hosts => {
                // 0.0.0.0 domain or 127.0.0.1 domain
                let parts: Vec<&str> = t.split_whitespace().collect();
                if parts.len() >= 2 {
                    let dom = parts[1].trim_end_matches('.');
                    out.push_str(&domain_policy_line(dom, action));
                }
            }
            RpzListFormat::DomainList => {
                let dom = t
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .trim_end_matches('.');
                if !dom.is_empty() {
                    out.push_str(&domain_policy_line(dom, action));
                }
            }
        }
    }
    out
}

fn domain_policy_line(domain: &str, action: &RpzAction) -> String {
    match action {
        RpzAction::Passthru => format!("; passthru {domain}\n"),
        RpzAction::Sinkhole => format!("{domain}. CNAME .\n"),
        RpzAction::Nxdomain | RpzAction::Nodata | RpzAction::Drop => {
            format!("{domain}. CNAME .\n")
        }
    }
}

fn rule_to_zone_line(rule: &RpzRule) -> String {
    if rule.action == RpzAction::Passthru {
        return format!(
            "; passthru {} # {}",
            rule.domain,
            rule.comment.as_deref().unwrap_or("")
        );
    }
    format!("{}. CNAME .", rule.domain.trim_end_matches('.'))
}

fn domain_matches(q: &str, pattern: &str) -> bool {
    let p = pattern
        .trim()
        .trim_start_matches('*')
        .trim_start_matches('.')
        .to_ascii_lowercase();
    q == p || q.ends_with(&format!(".{p}"))
}

fn content_has_domain(content: &str, domain: &str) -> bool {
    for line in content.lines() {
        let t = line.trim().to_ascii_lowercase();
        if t.is_empty() || t.starts_with('#') || t.starts_with(';') {
            continue;
        }
        if t.contains(domain) {
            return true;
        }
    }
    false
}

fn action_response(action: &RpzAction, cfg: &DnsSinkholeConfig) -> String {
    match action {
        RpzAction::Sinkhole => format!("A {} / AAAA {}", cfg.sinkhole_ipv4, cfg.sinkhole_ipv6),
        RpzAction::Nxdomain => "NXDOMAIN (Name Error)".into(),
        RpzAction::Nodata => "NODATA".into(),
        RpzAction::Drop => "DROP".into(),
        RpzAction::Passthru => "PASSTHRU (Allowed to Upstream DNS)".into(),
    }
}

async fn fetch_url(url: &str) -> Result<String, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client.get(url).send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let text = resp.text().await.map_err(|e| e.to_string())?;
    // Cap feed size (8 MiB)
    if text.len() > 8 * 1024 * 1024 {
        return Err("feed too large".into());
    }
    Ok(text)
}

fn percent_decode(s: &str) -> String {
    let mut out = String::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(byte) =
                u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or(""), 16)
            {
                out.push(byte as char);
                i += 3;
                continue;
            }
        }
        if b[i] == b'+' {
            out.push(' ');
        } else {
            out.push(b[i] as char);
        }
        i += 1;
    }
    out
}
