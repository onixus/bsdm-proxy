use crate::http_types::{empty, full, Body};
use base64::Engine;
use bytes::Bytes;
use hyper::header::{HeaderValue, LOCATION, SET_COOKIE};
use hyper::{Request, Response, StatusCode};
use rand::RngCore;
use std::collections::HashMap;
use std::env;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::error;

#[derive(Debug, Clone)]
pub struct OidcConfig {
    pub client_id: String,
    pub client_secret: String,
    pub issuer_url: String,
    pub redirect_uri: String,
}

impl OidcConfig {
    pub fn from_env() -> Option<Self> {
        let client_id = env::var("OIDC_CLIENT_ID").ok()?;
        let client_secret = env::var("OIDC_CLIENT_SECRET").ok()?;
        let issuer_url = env::var("OIDC_ISSUER_URL").ok()?;
        let redirect_uri = env::var("OIDC_REDIRECT_URI")
            .unwrap_or_else(|_| "http://localhost:1488/-/callback".to_string());

        Some(Self {
            client_id,
            client_secret,
            issuer_url,
            redirect_uri,
        })
    }
}

pub struct ReverseProxyConfig {
    pub upstream_url: String,
    pub oidc: Option<OidcConfig>,
    pub admin_group: Option<String>,
    pub sessions: RwLock<HashMap<String, String>>,
    pub states: RwLock<HashMap<String, u64>>,
}

impl ReverseProxyConfig {
    pub fn from_env() -> Option<Self> {
        let upstream_url = env::var("REVERSE_PROXY_UPSTREAM")
            .ok()
            .filter(|s| !s.is_empty())?;
        let oidc = OidcConfig::from_env();
        let admin_group = env::var("REVERSE_PROXY_ADMIN_GROUP")
            .ok()
            .filter(|s| !s.is_empty());

        Some(Self {
            upstream_url,
            oidc,
            admin_group,
            sessions: RwLock::new(HashMap::new()),
            states: RwLock::new(HashMap::new()),
        })
    }

    pub fn extract_session_cookie<B>(req: &Request<B>) -> Option<String> {
        req.headers().get("cookie").and_then(|val| {
            let val_str = val.to_str().ok()?;
            for part in val_str.split(';') {
                let part = part.trim();
                if let Some(stripped) = part.strip_prefix("bsdm_session=") {
                    return Some(stripped.to_string());
                }
            }
            None
        })
    }

    pub fn extract_oidc_state_cookie<B>(req: &Request<B>) -> Option<String> {
        req.headers().get("cookie").and_then(|val| {
            let val_str = val.to_str().ok()?;
            for part in val_str.split(';') {
                let part = part.trim();
                if let Some(stripped) = part.strip_prefix("bsdm_oidc_state=") {
                    return Some(stripped.to_string());
                }
            }
            None
        })
    }

    pub fn get_session(&self, session_id: &str) -> Option<String> {
        self.sessions.read().unwrap().get(session_id).cloned()
    }

    pub fn create_session(&self, username: String) -> String {
        let mut rng = rand::rng();
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let session_id = hex::encode(bytes);
        self.sessions
            .write()
            .unwrap()
            .insert(session_id.clone(), username);
        session_id
    }

    pub fn generate_state(&self) -> String {
        let mut rng = rand::rng();
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let state = hex::encode(bytes);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.states.write().unwrap().insert(state.clone(), now);
        state
    }

    pub fn verify_and_remove_state(&self, state: &str) -> bool {
        let mut states = self.states.write().unwrap();
        if let Some(created_at) = states.remove(state) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            // State valid for 10 minutes (600s)
            now.saturating_sub(created_at) <= 600
        } else {
            false
        }
    }

    pub fn handle_unauthenticated(&self, _req: &Request<hyper::body::Incoming>) -> Response<Body> {
        if let Some(oidc) = &self.oidc {
            let state = self.generate_state();
            let auth_url = format!(
                "{}/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid profile email&state={}",
                oidc.issuer_url.trim_end_matches('/'),
                oidc.client_id,
                oidc.redirect_uri,
                state
            );

            let state_cookie = format!(
                "bsdm_oidc_state={}; HttpOnly; Path=/; SameSite=Lax; Max-Age=600",
                state
            );

            Response::builder()
                .status(StatusCode::FOUND)
                .header(LOCATION, auth_url)
                .header(SET_COOKIE, HeaderValue::from_str(&state_cookie).unwrap())
                .body(empty())
                .unwrap()
        } else {
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(full(Bytes::from("401 Unauthorized (OIDC not configured)")))
                .unwrap()
        }
    }

    pub async fn handle_oidc_callback(
        &self,
        req: Request<hyper::body::Incoming>,
    ) -> Response<Body> {
        let Some(oidc) = &self.oidc else {
            return Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(full(Bytes::from("OIDC not configured")))
                .unwrap();
        };

        let query = req.uri().query().unwrap_or("");
        let mut code = None;
        let mut state_param = None;
        for param in query.split('&') {
            if let Some((k, v)) = param.split_once('=') {
                if k == "code" {
                    code = Some(v.to_string());
                } else if k == "state" {
                    state_param = Some(v.to_string());
                }
            }
        }

        let Some(code) = code else {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(full(Bytes::from("Missing code parameter")))
                .unwrap();
        };

        let Some(state_param) = state_param else {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(full(Bytes::from("Missing state parameter")))
                .unwrap();
        };

        let state_cookie = Self::extract_oidc_state_cookie(&req);
        if state_cookie.as_deref() != Some(&state_param)
            || !self.verify_and_remove_state(&state_param)
        {
            error!("OIDC CSRF state mismatch or expired state token");
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(full(Bytes::from("CSRF state mismatch or state expired")))
                .unwrap();
        }

        let token_url = format!("{}/token", oidc.issuer_url.trim_end_matches('/'));
        let client = reqwest::Client::new();
        let params = [
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", &oidc.redirect_uri),
            ("client_id", &oidc.client_id),
            ("client_secret", &oidc.client_secret),
        ];

        let res = match client.post(&token_url).form(&params).send().await {
            Ok(res) => res,
            Err(e) => {
                error!("Token exchange failed: {}", e);
                return Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(full(Bytes::from(format!("IDP Error: {}", e))))
                    .unwrap();
            }
        };

        if !res.status().is_success() {
            let status = res.status();
            let body = res.text().await.unwrap_or_default();
            error!("IDP returned error: {} - {}", status, body);
            return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(full(Bytes::from("IDP returned error")))
                .unwrap();
        }

        #[derive(serde::Deserialize)]
        struct TokenResponse {
            id_token: String,
        }

        let token_resp: TokenResponse = match res.json().await {
            Ok(tr) => tr,
            Err(e) => {
                error!("Failed to parse token response: {}", e);
                return Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(full(Bytes::from("Invalid response from IDP")))
                    .unwrap();
            }
        };

        let parts: Vec<&str> = token_resp.id_token.split('.').collect();
        if parts.len() != 3 {
            return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(full(Bytes::from("Invalid JWT")))
                .unwrap();
        }

        let payload_b64 = parts[1].replace('-', "+").replace('_', "/");
        let payload_b64 = match payload_b64.len() % 4 {
            2 => format!("{}==", payload_b64),
            3 => format!("{}=", payload_b64),
            _ => payload_b64,
        };

        let decoded = match base64::engine::general_purpose::STANDARD.decode(&payload_b64) {
            Ok(d) => d,
            Err(_) => {
                return Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(full(Bytes::from("Invalid JWT base64")))
                    .unwrap()
            }
        };

        #[derive(serde::Deserialize)]
        struct JwtPayload {
            iss: Option<String>,
            aud: Option<serde_json::Value>,
            email: Option<String>,
            sub: String,
            exp: Option<u64>,
        }

        let jwt: JwtPayload = match serde_json::from_slice(&decoded) {
            Ok(j) => j,
            Err(_) => {
                return Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(full(Bytes::from("Invalid JWT JSON")))
                    .unwrap()
            }
        };

        // Validate Issuer (iss)
        if let Some(iss) = &jwt.iss {
            if iss.trim_end_matches('/') != oidc.issuer_url.trim_end_matches('/') {
                error!(
                    "JWT issuer mismatch: got {}, expected {}",
                    iss, oidc.issuer_url
                );
                return Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body(full(Bytes::from("JWT issuer mismatch")))
                    .unwrap();
            }
        }

        // Validate Audience (aud)
        if let Some(aud) = &jwt.aud {
            let aud_matches = match aud {
                serde_json::Value::String(s) => s == &oidc.client_id,
                serde_json::Value::Array(arr) => arr
                    .iter()
                    .any(|v| v.as_str().map_or(false, |s| s == oidc.client_id)),
                _ => false,
            };
            if !aud_matches {
                error!("JWT audience mismatch: expected {}", oidc.client_id);
                return Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body(full(Bytes::from("JWT audience mismatch")))
                    .unwrap();
            }
        }

        // Validate Expiration (exp)
        if let Some(exp) = jwt.exp {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if exp <= now {
                error!("JWT expired: exp {} <= now {}", exp, now);
                return Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body(full(Bytes::from("JWT expired")))
                    .unwrap();
            }
        }

        let username = jwt.email.unwrap_or(jwt.sub);
        let session_id = self.create_session(username);
        let cookie_val = format!(
            "bsdm_session={}; HttpOnly; Path=/; SameSite=Lax",
            session_id
        );

        Response::builder()
            .status(StatusCode::FOUND)
            .header(LOCATION, "/")
            .header(SET_COOKIE, HeaderValue::from_str(&cookie_val).unwrap())
            .body(empty())
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oidc_state_generation_and_verification() {
        let config = ReverseProxyConfig {
            upstream_url: "http://127.0.0.1:8080".to_string(),
            oidc: Some(OidcConfig {
                client_id: "test-client".to_string(),
                client_secret: "secret".to_string(),
                issuer_url: "http://idp.example.com".to_string(),
                redirect_uri: "http://localhost:1488/-/callback".to_string(),
            }),
            admin_group: None,
            sessions: RwLock::new(HashMap::new()),
            states: RwLock::new(HashMap::new()),
        };

        let state = config.generate_state();
        assert!(!state.is_empty());
        assert!(config.verify_and_remove_state(&state));
        assert!(!config.verify_and_remove_state(&state)); // Cannot reuse state twice
    }

    #[test]
    fn oidc_extract_cookies() {
        let req = Request::builder()
            .header(
                "cookie",
                "other=1; bsdm_session=sess-123; bsdm_oidc_state=state-xyz",
            )
            .body(())
            .unwrap();

        let (parts, _) = req.into_parts();
        let dummy_req = Request::from_parts(parts, ());

        assert_eq!(
            ReverseProxyConfig::extract_session_cookie(&dummy_req),
            Some("sess-123".to_string())
        );
        assert_eq!(
            ReverseProxyConfig::extract_oidc_state_cookie(&dummy_req),
            Some("state-xyz".to_string())
        );
    }
}
