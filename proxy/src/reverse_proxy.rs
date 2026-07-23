use hyper::header::{HeaderValue, LOCATION, SET_COOKIE};
use hyper::{Request, Response, StatusCode};
use rand::RngCore;
use std::collections::HashMap;
use std::env;
use std::sync::RwLock;
use bytes::Bytes;
use base64::Engine;
use crate::http_types::{empty, full, Body};
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
}

impl ReverseProxyConfig {
    pub fn from_env() -> Option<Self> {
        let upstream_url = env::var("REVERSE_PROXY_UPSTREAM").ok().filter(|s| !s.is_empty())?;
        let oidc = OidcConfig::from_env();
        let admin_group = env::var("REVERSE_PROXY_ADMIN_GROUP").ok().filter(|s| !s.is_empty());

        Some(Self {
            upstream_url,
            oidc,
            admin_group,
            sessions: RwLock::new(HashMap::new()),
        })
    }

    pub fn extract_session_cookie(req: &Request<hyper::body::Incoming>) -> Option<String> {
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

    pub fn get_session(&self, session_id: &str) -> Option<String> {
        self.sessions.read().unwrap().get(session_id).cloned()
    }

    pub fn create_session(&self, username: String) -> String {
        let mut rng = rand::rng();
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let session_id = hex::encode(bytes);
        self.sessions.write().unwrap().insert(session_id.clone(), username);
        session_id
    }

    pub fn handle_unauthenticated(&self, _req: &Request<hyper::body::Incoming>) -> Response<Body> {
        if let Some(oidc) = &self.oidc {
            let state = "mock-state"; // In a real app, generate securely and store to prevent CSRF
            let auth_url = format!(
                "{}/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid profile email&state={}",
                oidc.issuer_url.trim_end_matches('/'),
                oidc.client_id,
                oidc.redirect_uri,
                state
            );
            Response::builder()
                .status(StatusCode::FOUND)
                .header(LOCATION, auth_url)
                .body(empty())
                .unwrap()
        } else {
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(full(Bytes::from("401 Unauthorized (OIDC not configured)")))
                .unwrap()
        }
    }

    pub async fn handle_oidc_callback(&self, req: Request<hyper::body::Incoming>) -> Response<Body> {
        let Some(oidc) = &self.oidc else {
            return Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(full(Bytes::from("OIDC not configured")))
                .unwrap();
        };

        let query = req.uri().query().unwrap_or("");
        let mut code = None;
        for param in query.split('&') {
            if let Some((k, v)) = param.split_once('=') {
                if k == "code" {
                    code = Some(v.to_string());
                }
            }
        }

        let Some(code) = code else {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(full(Bytes::from("Missing code parameter")))
                .unwrap();
        };

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

        // Simplistic JWT decoding without signature verification for now
        let parts: Vec<&str> = token_resp.id_token.split('.').collect();
        if parts.len() != 3 {
            return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(full(Bytes::from("Invalid JWT")))
                .unwrap();
        }

        let payload_b64 = parts[1].replace('-', "+").replace('_', "/");
        // Pad base64 if needed
        let payload_b64 = match payload_b64.len() % 4 {
            2 => format!("{}==", payload_b64),
            3 => format!("{}=", payload_b64),
            _ => payload_b64,
        };

        let decoded = match base64::engine::general_purpose::STANDARD.decode(&payload_b64) {
            Ok(d) => d,
            Err(_) => return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(full(Bytes::from("Invalid JWT base64")))
                .unwrap(),
        };

        #[derive(serde::Deserialize)]
        struct JwtPayload {
            email: Option<String>,
            sub: String,
        }

        let jwt: JwtPayload = match serde_json::from_slice(&decoded) {
            Ok(j) => j,
            Err(_) => return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(full(Bytes::from("Invalid JWT JSON")))
                .unwrap(),
        };

        let username = jwt.email.unwrap_or(jwt.sub);
        let session_id = self.create_session(username);
        let cookie_val = format!("bsdm_session={}; HttpOnly; Path=/; SameSite=Lax", session_id);

        Response::builder()
            .status(StatusCode::FOUND)
            .header(LOCATION, "/")
            .header(SET_COOKIE, HeaderValue::from_str(&cookie_val).unwrap())
            .body(empty())
            .unwrap()
    }
}
