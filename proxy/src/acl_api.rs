//! REST API for runtime ACL management on the metrics/admin port.

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header::AUTHORIZATION;
use hyper::{HeaderMap, Method, Request, Response, StatusCode};
use serde::Serialize;
use std::sync::Arc;
use tracing::{info, warn};

use crate::acl::{AclAction, AclEngineHandle, AclRule};
use crate::acl_config::{load_acl_engine_from_file, parse_acl_action, save_acl_engine_to_file};
use crate::http_types::{full, Body};
use crate::policy_cache::PolicyDecisionCache;

#[derive(Clone)]
pub struct AclApiConfig {
    pub default_action: AclAction,
    pub rules_path: Option<String>,
    pub api_token: Option<String>,
}

impl AclApiConfig {
    pub fn from_env(rules_path: Option<String>) -> Self {
        let default_action = std::env::var("ACL_DEFAULT_ACTION")
            .map(|v| parse_acl_action(&v))
            .unwrap_or(AclAction::Allow);
        let api_token = std::env::var("ACL_API_TOKEN")
            .ok()
            .filter(|t| !t.is_empty());
        Self {
            default_action,
            rules_path,
            api_token,
        }
    }
}

#[derive(Clone)]
pub struct AclApiState {
    engine: Arc<AclEngineHandle>,
    config: AclApiConfig,
    policy_cache: Option<Arc<PolicyDecisionCache>>,
}

impl AclApiState {
    pub fn new(
        engine: Arc<AclEngineHandle>,
        config: AclApiConfig,
        policy_cache: Option<Arc<PolicyDecisionCache>>,
    ) -> Self {
        Self {
            engine,
            config,
            policy_cache,
        }
    }

    pub async fn handle_request(&self, req: Request<Incoming>) -> Response<Body> {
        let (parts, body) = req.into_parts();
        let body = match BodyExt::collect(body).await {
            Ok(collected) => collected.to_bytes(),
            Err(e) => {
                warn!("Failed to read ACL API body: {}", e);
                Bytes::new()
            }
        };
        self.dispatch(&parts.method, parts.uri.path(), body, &parts.headers)
            .await
    }

    async fn dispatch(
        &self,
        method: &Method,
        path: &str,
        body: Bytes,
        headers: &HeaderMap,
    ) -> Response<Body> {
        if !self.is_authorized(headers) {
            return json_response(StatusCode::UNAUTHORIZED, r#"{"error":"unauthorized"}"#);
        }

        if let Some(id) = path.strip_prefix("/api/acl/rules/") {
            let id = percent_decode(id);
            return match *method {
                Method::PUT => self.update_rule_body(&id, body).await,
                Method::DELETE => self.delete_rule(&id).await,
                _ => json_response(
                    StatusCode::METHOD_NOT_ALLOWED,
                    r#"{"error":"method not allowed"}"#,
                ),
            };
        }

        match (method, path) {
            (&Method::GET, "/api/acl/rules") => self.list_rules().await,
            (&Method::POST, "/api/acl/rules") => self.add_rule_body(body).await,
            (&Method::POST, "/api/acl/reload") => self.reload_rules().await,
            (&Method::POST, "/api/acl/persist") => self.persist_rules().await,
            _ => json_response(StatusCode::NOT_FOUND, r#"{"error":"not found"}"#),
        }
    }

    fn is_authorized(&self, headers: &HeaderMap) -> bool {
        let Some(expected) = &self.config.api_token else {
            return true;
        };
        headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .is_some_and(|token| token == expected)
    }

    fn invalidate_policy_cache(&self) {
        if let Some(cache) = &self.policy_cache {
            cache.invalidate();
        }
    }

    async fn list_rules(&self) -> Response<Body> {
        let engine = self.engine.load();
        let payload = ListRulesResponse {
            count: engine.rule_count(),
            default_action: engine.default_action(),
            rules: engine.rules().to_vec(),
        };
        match serde_json::to_string(&payload) {
            Ok(body) => json_response(StatusCode::OK, &body),
            Err(e) => {
                warn!("Failed to serialize ACL rules: {}", e);
                json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    r#"{"error":"serialization failed"}"#,
                )
            }
        }
    }

    async fn add_rule_body(&self, body: Bytes) -> Response<Body> {
        let rule: AclRule = match serde_json::from_slice(&body) {
            Ok(rule) => rule,
            Err(e) => {
                warn!("Invalid ACL rule JSON: {}", e);
                return json_response(
                    StatusCode::BAD_REQUEST,
                    &format!(
                        r#"{{"error":"invalid json: {}"}}"#,
                        escape_json(&e.to_string())
                    ),
                );
            }
        };

        if rule.id.trim().is_empty() {
            return json_response(
                StatusCode::BAD_REQUEST,
                r#"{"error":"rule id is required"}"#,
            );
        }

        if self.engine.load().has_rule(&rule.id) {
            return json_response(
                StatusCode::CONFLICT,
                &format!(
                    r#"{{"error":"rule id already exists: {}"}}"#,
                    escape_json(&rule.id)
                ),
            );
        }

        info!("ACL API: adding rule {} ({})", rule.id, rule.name);
        self.engine.mutate(|engine| engine.add_rule(rule.clone()));
        self.invalidate_policy_cache();
        match serde_json::to_string(&rule) {
            Ok(body) => json_response(StatusCode::CREATED, &body),
            Err(_) => json_response(StatusCode::CREATED, r#"{"status":"created"}"#),
        }
    }

    async fn update_rule_body(&self, id: &str, body: Bytes) -> Response<Body> {
        let mut rule: AclRule = match serde_json::from_slice(&body) {
            Ok(rule) => rule,
            Err(e) => {
                return json_response(
                    StatusCode::BAD_REQUEST,
                    &format!(
                        r#"{{"error":"invalid json: {}"}}"#,
                        escape_json(&e.to_string())
                    ),
                );
            }
        };
        if rule.id.trim().is_empty() {
            rule.id = id.to_string();
        } else if rule.id != id {
            return json_response(
                StatusCode::BAD_REQUEST,
                r#"{"error":"path id must match rule.id"}"#,
            );
        }

        let mut updated = false;
        self.engine.mutate(|engine| {
            updated = engine.update_rule(rule.clone());
        });
        if !updated {
            return json_response(StatusCode::NOT_FOUND, r#"{"error":"rule not found"}"#);
        }
        self.invalidate_policy_cache();
        info!("ACL API: updated rule {id}");
        match serde_json::to_string(&rule) {
            Ok(body) => json_response(StatusCode::OK, &body),
            Err(_) => json_response(StatusCode::OK, r#"{"status":"updated"}"#),
        }
    }

    async fn delete_rule(&self, id: &str) -> Response<Body> {
        let mut removed = false;
        self.engine.mutate(|engine| {
            removed = engine.remove_rule(id);
        });
        if !removed {
            return json_response(StatusCode::NOT_FOUND, r#"{"error":"rule not found"}"#);
        }
        self.invalidate_policy_cache();
        info!("ACL API: deleted rule {id}");
        json_response(
            StatusCode::OK,
            &format!(r#"{{"status":"deleted","id":"{}"}}"#, escape_json(id)),
        )
    }

    async fn reload_rules(&self) -> Response<Body> {
        let Some(path) = &self.config.rules_path else {
            return json_response(
                StatusCode::BAD_REQUEST,
                r#"{"error":"ACL_RULES_PATH is not configured"}"#,
            );
        };

        match load_acl_engine_from_file(path, self.config.default_action) {
            Ok(loaded) => {
                let count = loaded.rule_count();
                self.engine.replace(loaded);
                self.invalidate_policy_cache();
                info!("ACL API: reloaded {} rules from {}", count, path);
                json_response(
                    StatusCode::OK,
                    &format!(r#"{{"status":"reloaded","count":{count}}}"#),
                )
            }
            Err(e) => {
                warn!("ACL API reload failed: {}", e);
                json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!(r#"{{"error":"{}"}}"#, escape_json(&e)),
                )
            }
        }
    }

    async fn persist_rules(&self) -> Response<Body> {
        let Some(path) = &self.config.rules_path else {
            return json_response(
                StatusCode::BAD_REQUEST,
                r#"{"error":"ACL_RULES_PATH is not configured"}"#,
            );
        };
        let engine = self.engine.load();
        match save_acl_engine_to_file(path, &engine) {
            Ok(()) => json_response(
                StatusCode::OK,
                &format!(
                    r#"{{"status":"persisted","count":{},"path":"{}"}}"#,
                    engine.rule_count(),
                    escape_json(path)
                ),
            ),
            Err(e) => json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(r#"{{"error":"{}"}}"#, escape_json(&e)),
            ),
        }
    }
}

#[derive(Serialize)]
struct ListRulesResponse {
    count: usize,
    default_action: AclAction,
    rules: Vec<AclRule>,
}

fn json_response(status: StatusCode, body: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json; charset=utf-8")
        .body(full(Bytes::from(body.to_string())))
        .unwrap_or_else(|_| Response::new(full(Bytes::from_static(b"500 Internal Server Error"))))
}

fn escape_json(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

fn percent_decode(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (from_hex(bytes[i + 1]), from_hex(bytes[i + 2])) {
                out.push((h << 4 | l) as char);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::{AclEngine, AclEngineHandle};
    use http_body_util::BodyExt;
    use hyper::body::Bytes;
    use hyper::{Method, StatusCode};

    fn test_state() -> AclApiState {
        let engine = Arc::new(AclEngineHandle::new(AclEngine::new(AclAction::Allow)));
        AclApiState::new(
            engine,
            AclApiConfig {
                default_action: AclAction::Allow,
                rules_path: None,
                api_token: None,
            },
            None,
        )
    }

    fn test_state_with_token() -> AclApiState {
        let engine = Arc::new(AclEngineHandle::new(AclEngine::new(AclAction::Allow)));
        AclApiState::new(
            engine,
            AclApiConfig {
                default_action: AclAction::Allow,
                rules_path: None,
                api_token: Some("secret-token".to_string()),
            },
            None,
        )
    }

    const SAMPLE_RULE: &[u8] = br#"{
            "id": "api-rule",
            "name": "API rule",
            "enabled": true,
            "priority": 50,
            "action": "deny",
            "rule_type": { "Domain": "blocked.test" },
            "redirect_url": null,
            "comment": null
        }"#;

    #[tokio::test]
    async fn list_rules_empty() {
        let state = test_state();
        let resp = state
            .dispatch(
                &Method::GET,
                "/api/acl/rules",
                Bytes::new(),
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["count"], 0);
    }

    #[tokio::test]
    async fn add_rule_via_api() {
        let state = test_state();
        let resp = state
            .dispatch(
                &Method::POST,
                "/api/acl/rules",
                Bytes::from_static(SAMPLE_RULE),
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        let list_resp = state
            .dispatch(
                &Method::GET,
                "/api/acl/rules",
                Bytes::new(),
                &HeaderMap::new(),
            )
            .await;
        let body = BodyExt::collect(list_resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["count"], 1);
    }

    #[tokio::test]
    async fn update_and_delete_rule() {
        let state = test_state();
        state
            .dispatch(
                &Method::POST,
                "/api/acl/rules",
                Bytes::from_static(SAMPLE_RULE),
                &HeaderMap::new(),
            )
            .await;

        let updated = br#"{
            "id": "api-rule",
            "name": "Updated",
            "enabled": false,
            "priority": 10,
            "action": "allow",
            "rule_type": { "Domain": "blocked.test" },
            "redirect_url": null,
            "comment": null
        }"#;
        let resp = state
            .dispatch(
                &Method::PUT,
                "/api/acl/rules/api-rule",
                Bytes::from_static(updated),
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = state
            .dispatch(
                &Method::DELETE,
                "/api/acl/rules/api-rule",
                Bytes::new(),
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let list_resp = state
            .dispatch(
                &Method::GET,
                "/api/acl/rules",
                Bytes::new(),
                &HeaderMap::new(),
            )
            .await;
        let body = BodyExt::collect(list_resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["count"], 0);
    }

    #[tokio::test]
    async fn duplicate_rule_returns_conflict() {
        let state = test_state();
        let rule_json = br#"{
            "id": "dup",
            "name": "dup",
            "enabled": true,
            "priority": 1,
            "action": "deny",
            "rule_type": { "Domain": "x.test" },
            "redirect_url": null,
            "comment": null
        }"#;
        let resp = state
            .dispatch(
                &Method::POST,
                "/api/acl/rules",
                Bytes::from_static(rule_json),
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp = state
            .dispatch(
                &Method::POST,
                "/api/acl/rules",
                Bytes::from_static(rule_json),
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn reload_without_path_returns_bad_request() {
        let state = test_state();
        let resp = state
            .dispatch(
                &Method::POST,
                "/api/acl/reload",
                Bytes::new(),
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn persist_without_path_returns_bad_request() {
        let state = test_state();
        let resp = state
            .dispatch(
                &Method::POST,
                "/api/acl/persist",
                Bytes::new(),
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn api_token_required_when_configured() {
        let state = test_state_with_token();
        let resp = state
            .dispatch(
                &Method::GET,
                "/api/acl/rules",
                Bytes::new(),
                &HeaderMap::new(),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            hyper::header::HeaderValue::from_static("Bearer secret-token"),
        );
        let resp = state
            .dispatch(&Method::GET, "/api/acl/rules", Bytes::new(), &headers)
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
