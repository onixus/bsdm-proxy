//! Браузерный вход в reverse-proxy (IAP) и его сессии.
//!
//! Логика OIDC вынесена в [`crate::oidc`]; здесь — маршруты `/-/…`, cookie и
//! хранилище сессий. К forward-SWG плоскости данных (`Proxy-Authorization`)
//! этот модуль отношения не имеет.

use crate::http_types::{empty, full, Body};
use crate::oidc::{self, OidcRegistry, Provider};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::header::{HeaderValue, CONTENT_TYPE, LOCATION, SET_COOKIE};
use hyper::{Request, Response, StatusCode};
use std::collections::HashMap;
use std::env;
use std::sync::{Arc, RwLock};
use tracing::{error, warn};

pub const SESSION_COOKIE: &str = "bsdm_session";
pub const STATE_COOKIE: &str = "bsdm_oidc_state";

/// Сколько живёт незавершённый вход (state + PKCE verifier).
const STATE_TTL_SECONDS: u64 = 600;

/// Потолок на число одновременно начатых входов. Карта state пополняется любым
/// анонимным запросом, так что без предела это ручка для исчерпания памяти.
const MAX_PENDING_STATES: usize = 10_000;

/// Незавершённый вход. Живёт от редиректа на IdP до колбэка.
struct PendingAuth {
    provider_id: String,
    nonce: String,
    pkce_verifier: String,
    return_to: String,
    created_at: u64,
}

/// Выданная сессия.
#[derive(Clone)]
struct Session {
    username: String,
    expires_at: u64,
}

pub struct ReverseProxyConfig {
    pub upstream_url: String,
    pub oidc: Option<OidcRegistry>,
    pub admin_group: Option<String>,
    /// Ставить ли `Secure` на cookie. По умолчанию выводится из схемы
    /// redirect_uri: в проде это https, в лаборатории по http флаг сломал бы
    /// вход целиком.
    secure_cookies: bool,
    session_ttl: u64,
    sessions: RwLock<HashMap<String, Session>>,
    states: RwLock<HashMap<String, PendingAuth>>,
}

impl ReverseProxyConfig {
    pub fn from_env() -> Option<Self> {
        let upstream_url = env::var("REVERSE_PROXY_UPSTREAM")
            .ok()
            .filter(|s| !s.is_empty())?;
        let oidc = OidcRegistry::from_env();
        let admin_group = env::var("REVERSE_PROXY_ADMIN_GROUP")
            .ok()
            .filter(|s| !s.is_empty());

        let secure_cookies = match env::var("REVERSE_PROXY_SECURE_COOKIES") {
            Ok(v) => v.eq_ignore_ascii_case("true") || v == "1",
            Err(_) => oidc
                .as_ref()
                .map(|r| {
                    r.providers()
                        .iter()
                        .all(|p| p.redirect_uri.starts_with("https://"))
                })
                .unwrap_or(false),
        };

        let session_ttl = env::var("OIDC_SESSION_TTL_SECONDS")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|v| *v > 0)
            .unwrap_or(3600);

        if let Some(registry) = &oidc {
            for provider in registry.providers() {
                if provider.form_post && !secure_cookies {
                    // form_post приходит cross-site POST-ом, а такой запрос
                    // несёт cookie только при SameSite=None, который браузеры
                    // принимают исключительно вместе с Secure.
                    warn!(
                        provider = %provider.id,
                        "form_post provider needs Secure cookies: the state cookie will not \
                         survive the cross-site POST over plain HTTP"
                    );
                }
            }
        }

        Some(Self {
            upstream_url,
            oidc,
            admin_group,
            secure_cookies,
            session_ttl,
            sessions: RwLock::new(HashMap::new()),
            states: RwLock::new(HashMap::new()),
        })
    }

    // --- cookie ---

    fn extract_cookie<B>(req: &Request<B>, name: &str) -> Option<String> {
        let prefix = format!("{}=", name);
        req.headers().get("cookie").and_then(|val| {
            let val_str = val.to_str().ok()?;
            for part in val_str.split(';') {
                if let Some(stripped) = part.trim().strip_prefix(prefix.as_str()) {
                    return Some(stripped.to_string());
                }
            }
            None
        })
    }

    pub fn extract_session_cookie<B>(req: &Request<B>) -> Option<String> {
        Self::extract_cookie(req, SESSION_COOKIE)
    }

    pub fn extract_oidc_state_cookie<B>(req: &Request<B>) -> Option<String> {
        Self::extract_cookie(req, STATE_COOKIE)
    }

    fn cookie(&self, name: &str, value: &str, max_age: Option<u64>, cross_site: bool) -> String {
        let mut cookie = format!("{}={}; HttpOnly; Path=/", name, value);
        // SameSite=None требует Secure — без него браузер отбросит cookie.
        if cross_site && self.secure_cookies {
            cookie.push_str("; SameSite=None");
        } else {
            cookie.push_str("; SameSite=Lax");
        }
        if self.secure_cookies {
            cookie.push_str("; Secure");
        }
        if let Some(age) = max_age {
            cookie.push_str(&format!("; Max-Age={}", age));
        }
        cookie
    }

    fn expired_cookie(&self, name: &str) -> String {
        let mut cookie = format!("{}=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0", name);
        if self.secure_cookies {
            cookie.push_str("; Secure");
        }
        cookie
    }

    // --- сессии ---

    pub fn get_session(&self, session_id: &str) -> Option<String> {
        let now = oidc::now_secs();
        let expired = {
            let sessions = self.sessions.read().unwrap();
            match sessions.get(session_id) {
                Some(session) if session.expires_at > now => return Some(session.username.clone()),
                Some(_) => true,
                None => false,
            }
        };
        if expired {
            self.sessions.write().unwrap().remove(session_id);
        }
        None
    }

    pub fn create_session(&self, username: String) -> String {
        let session_id = oidc::random_token();
        let expires_at = oidc::now_secs().saturating_add(self.session_ttl);
        let mut sessions = self.sessions.write().unwrap();
        sessions.retain(|_, s| s.expires_at > oidc::now_secs());
        sessions.insert(
            session_id.clone(),
            Session {
                username,
                expires_at,
            },
        );
        session_id
    }

    pub fn drop_session(&self, session_id: &str) {
        self.sessions.write().unwrap().remove(session_id);
    }

    // --- state начатого входа ---

    /// Регистрирует начатый вход и возвращает его state.
    fn begin_auth(
        &self,
        provider_id: &str,
        nonce: String,
        pkce_verifier: String,
        return_to: String,
    ) -> String {
        let state = oidc::random_token();
        let now = oidc::now_secs();
        let mut states = self.states.write().unwrap();
        states.retain(|_, p| now.saturating_sub(p.created_at) <= STATE_TTL_SECONDS);
        if states.len() >= MAX_PENDING_STATES {
            // Чистка по сроку уже не помогает — отбрасываем самый старый, чтобы
            // карта не росла дальше.
            if let Some(oldest) = states
                .iter()
                .min_by_key(|(_, p)| p.created_at)
                .map(|(k, _)| k.clone())
            {
                states.remove(&oldest);
            }
        }
        states.insert(
            state.clone(),
            PendingAuth {
                provider_id: provider_id.to_string(),
                nonce,
                pkce_verifier,
                return_to,
                created_at: now,
            },
        );
        state
    }

    /// Извлекает начатый вход ровно один раз: повторное предъявление того же
    /// state не проходит.
    fn take_auth(&self, state: &str) -> Option<PendingAuth> {
        let pending = self.states.write().unwrap().remove(state)?;
        if oidc::now_secs().saturating_sub(pending.created_at) > STATE_TTL_SECONDS {
            return None;
        }
        Some(pending)
    }

    // --- маршруты ---

    /// Пути, которые обслуживает сам reverse-proxy и не проксирует наверх.
    pub fn is_auth_path(path: &str) -> bool {
        path == "/-/login"
            || path.starts_with("/-/login/")
            || path == "/-/callback"
            || path.starts_with("/-/callback/")
            || path == "/-/logout"
    }

    pub async fn handle_auth_route(&self, req: Request<hyper::body::Incoming>) -> Response<Body> {
        let path = req.uri().path().to_string();
        if path == "/-/logout" {
            return self.handle_logout(&req);
        }
        if path == "/-/callback" || path.starts_with("/-/callback/") {
            return self.handle_oidc_callback(req).await;
        }

        // /-/login или /-/login/{provider}
        let requested = path.strip_prefix("/-/login/").filter(|s| !s.is_empty());
        let return_to = req
            .uri()
            .query()
            .map(oidc::parse_form)
            .and_then(|q| q.get("return_to").cloned())
            .unwrap_or_else(|| "/".to_string());
        let return_to = sanitize_return_to(&return_to);

        match requested {
            Some(id) => self.start_login(id, &return_to).await,
            None => self.handle_login_page(&return_to).await,
        }
    }

    /// Точка входа для неаутентифицированного запроса к защищённому ресурсу.
    pub async fn handle_unauthenticated(
        &self,
        req: &Request<hyper::body::Incoming>,
    ) -> Response<Body> {
        let return_to = sanitize_return_to(
            req.uri()
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/"),
        );
        self.handle_login_page(&return_to).await
    }

    /// Один провайдер — уводим сразу на него; несколько — показываем выбор.
    async fn handle_login_page(&self, return_to: &str) -> Response<Body> {
        let Some(registry) = &self.oidc else {
            return text_response(
                StatusCode::UNAUTHORIZED,
                "401 Unauthorized (OIDC not configured)",
            );
        };

        let providers = registry.providers();
        match providers {
            [] => text_response(
                StatusCode::UNAUTHORIZED,
                "401 Unauthorized (no OIDC provider configured)",
            ),
            [only] => self.start_login(&only.id.clone(), return_to).await,
            many => login_page(many, return_to),
        }
    }

    async fn start_login(&self, provider_id: &str, return_to: &str) -> Response<Body> {
        let Some(registry) = &self.oidc else {
            return text_response(StatusCode::NOT_FOUND, "OIDC not configured");
        };
        let Some(provider) = registry.get(provider_id) else {
            return text_response(StatusCode::NOT_FOUND, "Unknown identity provider");
        };

        let nonce = oidc::random_token();
        let (verifier, challenge) = oidc::generate_pkce();
        let state = self.begin_auth(&provider.id, nonce.clone(), verifier, return_to.to_string());

        let auth_url = match registry
            .authorization_url(provider, &state, &nonce, &challenge)
            .await
        {
            Ok(url) => url,
            Err(e) => {
                error!(provider = %provider.id, "cannot build the authorization URL: {}", e);
                self.states.write().unwrap().remove(&state);
                return text_response(StatusCode::BAD_GATEWAY, "Identity provider unavailable");
            }
        };

        let state_cookie = self.cookie(
            STATE_COOKIE,
            &state,
            Some(STATE_TTL_SECONDS),
            provider.form_post,
        );

        let mut builder = Response::builder()
            .status(StatusCode::FOUND)
            .header(SET_COOKIE, header_value(&state_cookie));
        if let Ok(location) = HeaderValue::from_str(&auth_url) {
            builder = builder.header(LOCATION, location);
        } else {
            error!(provider = %provider.id, "authorization URL is not a valid header value");
            return text_response(StatusCode::BAD_GATEWAY, "Identity provider unavailable");
        }
        builder.body(empty()).unwrap()
    }

    fn handle_logout(&self, req: &Request<hyper::body::Incoming>) -> Response<Body> {
        if let Some(session_id) = Self::extract_session_cookie(req) {
            self.drop_session(&session_id);
        }
        Response::builder()
            .status(StatusCode::FOUND)
            .header(LOCATION, "/")
            .header(
                SET_COOKIE,
                header_value(&self.expired_cookie(SESSION_COOKIE)),
            )
            .header(SET_COOKIE, header_value(&self.expired_cookie(STATE_COOKIE)))
            .body(empty())
            .unwrap()
    }

    pub async fn handle_oidc_callback(
        &self,
        req: Request<hyper::body::Incoming>,
    ) -> Response<Body> {
        let Some(registry) = &self.oidc else {
            return text_response(StatusCode::NOT_FOUND, "OIDC not configured");
        };

        let state_cookie = Self::extract_oidc_state_cookie(&req);
        let is_form_post = req.method() == hyper::Method::POST;
        let query = req.uri().query().unwrap_or("").to_string();
        // Путь нужен после того, как тело будет вычитано, а `req` — поглощён.
        let path = req.uri().path().to_string();

        // Apple отдаёт колбэк POST-ом с form-urlencoded телом; остальные — GET
        // с query. Читаем то, что пришло.
        let params = if is_form_post {
            match req.into_body().collect().await {
                Ok(collected) => {
                    let bytes = collected.to_bytes();
                    // Тело колбэка — несколько сотен байт; всё, что заметно
                    // больше, к делу не относится.
                    if bytes.len() > 64 * 1024 {
                        return text_response(
                            StatusCode::BAD_REQUEST,
                            "Callback body is too large",
                        );
                    }
                    match std::str::from_utf8(&bytes) {
                        Ok(body) => oidc::parse_form(body),
                        Err(_) => {
                            return text_response(
                                StatusCode::BAD_REQUEST,
                                "Callback body is not valid UTF-8",
                            )
                        }
                    }
                }
                Err(e) => {
                    error!("cannot read the callback body: {}", e);
                    return text_response(StatusCode::BAD_REQUEST, "Cannot read the callback body");
                }
            }
        } else {
            oidc::parse_form(&query)
        };

        // IdP сообщает об отказе пользователя через error, а не через code.
        if let Some(err) = params.get("error") {
            warn!(
                "identity provider returned an error: {} ({})",
                err,
                params
                    .get("error_description")
                    .map(String::as_str)
                    .unwrap_or("-")
            );
            return text_response(StatusCode::UNAUTHORIZED, "Sign-in was not completed");
        }

        let (Some(code), Some(state)) = (params.get("code"), params.get("state")) else {
            return text_response(StatusCode::BAD_REQUEST, "Missing code or state parameter");
        };

        // Cookie сверяется до погашения state, чтобы чужой state нельзя было
        // сжечь посторонним запросом.
        if state_cookie.as_deref() != Some(state.as_str()) {
            error!("OIDC state cookie does not match the state parameter");
            return text_response(StatusCode::BAD_REQUEST, "CSRF state mismatch");
        }

        let Some(pending) = self.take_auth(state) else {
            error!("OIDC state is unknown or expired");
            return text_response(
                StatusCode::BAD_REQUEST,
                "CSRF state mismatch or state expired",
            );
        };

        let Some(provider) = registry.get(&pending.provider_id) else {
            error!(provider = %pending.provider_id, "provider disappeared mid-flow");
            return text_response(StatusCode::BAD_GATEWAY, "Unknown identity provider");
        };

        // Если колбэк пришёл на /-/callback/{id}, провайдер из пути обязан
        // совпасть с тем, под который выписывался state.
        if let Some(from_path) = path_provider(&path) {
            if from_path != provider.id {
                error!(
                    "callback path provider {} does not match the state provider {}",
                    from_path, provider.id
                );
                return text_response(StatusCode::BAD_REQUEST, "Provider mismatch");
            }
        }

        let claims = match registry
            .exchange_code(provider, code, &pending.nonce, &pending.pkce_verifier)
            .await
        {
            Ok(claims) => claims,
            Err(e) => {
                error!(provider = %provider.id, "OIDC sign-in failed: {}", e);
                // Наружу — без подробностей: колбэк не должен работать оракулом
                // по чужим токенам.
                return text_response(StatusCode::UNAUTHORIZED, "Sign-in failed");
            }
        };

        let session_id = self.create_session(claims.username());
        let session_cookie =
            self.cookie(SESSION_COOKIE, &session_id, Some(self.session_ttl), false);

        Response::builder()
            .status(StatusCode::FOUND)
            .header(LOCATION, header_value(&pending.return_to))
            .header(SET_COOKIE, header_value(&session_cookie))
            .header(SET_COOKIE, header_value(&self.expired_cookie(STATE_COOKIE)))
            .body(empty())
            .unwrap()
    }
}

fn path_provider(path: &str) -> Option<String> {
    path.strip_prefix("/-/callback/")
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

/// Допускает только относительный путь внутри этого хоста: всё остальное
/// превратило бы `?return_to=` в открытый редирект.
fn sanitize_return_to(candidate: &str) -> String {
    let trimmed = candidate.trim();
    if !trimmed.starts_with('/')
        || trimmed.starts_with("//")
        || trimmed.starts_with("/\\")
        || trimmed.contains(['\r', '\n'])
        || ReverseProxyConfig::is_auth_path(trimmed.split('?').next().unwrap_or(""))
    {
        return "/".to_string();
    }
    trimmed.to_string()
}

fn header_value(raw: &str) -> HeaderValue {
    HeaderValue::from_str(raw).unwrap_or_else(|_| HeaderValue::from_static("/"))
}

fn text_response(status: StatusCode, body: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(full(Bytes::from(body.to_string())))
        .unwrap()
}

/// Страница выбора провайдера. Простая и самодостаточная: у reverse-proxy нет
/// статики, а тянуть её с upstream до входа нельзя.
fn login_page(providers: &[Arc<Provider>], return_to: &str) -> Response<Body> {
    let mut buttons = String::new();
    for provider in providers {
        buttons.push_str(&format!(
            "<li><a class=\"btn\" href=\"/-/login/{id}?return_to={ret}\">Sign in with {name}</a></li>",
            id = html_escape(&provider.id),
            ret = url::form_urlencoded::byte_serialize(return_to.as_bytes()).collect::<String>(),
            name = html_escape(&provider.display_name),
        ));
    }

    let body = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
<title>Sign in</title><style>\
body{{font:16px/1.5 system-ui,sans-serif;margin:0;display:grid;place-items:center;min-height:100vh;background:#f6f7f9;color:#111}}\
main{{background:#fff;padding:2rem;border-radius:12px;box-shadow:0 1px 4px rgba(0,0,0,.12);min-width:18rem}}\
h1{{font-size:1.1rem;margin:0 0 1rem}}ul{{list-style:none;margin:0;padding:0}}li{{margin:.5rem 0}}\
.btn{{display:block;padding:.7rem 1rem;border:1px solid #d0d3d9;border-radius:8px;text-decoration:none;color:inherit;text-align:center}}\
.btn:hover{{background:#f0f2f5}}</style></head>\
<body><main><h1>Sign in to continue</h1><ul>{buttons}</ul></main></body></html>"
    );

    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .body(full(Bytes::from(body)))
        .unwrap()
}

fn html_escape(raw: &str) -> String {
    raw.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> ReverseProxyConfig {
        ReverseProxyConfig {
            upstream_url: "http://127.0.0.1:8080".to_string(),
            oidc: None,
            admin_group: None,
            secure_cookies: true,
            session_ttl: 3600,
            sessions: RwLock::new(HashMap::new()),
            states: RwLock::new(HashMap::new()),
        }
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

        assert_eq!(
            ReverseProxyConfig::extract_session_cookie(&req),
            Some("sess-123".to_string())
        );
        assert_eq!(
            ReverseProxyConfig::extract_oidc_state_cookie(&req),
            Some("state-xyz".to_string())
        );
    }

    #[test]
    fn sessions_expire() {
        let config = ReverseProxyConfig {
            session_ttl: 1,
            ..config()
        };
        let id = config.create_session("alice".into());
        assert_eq!(config.get_session(&id), Some("alice".into()));

        // Подкручиваем срок вместо ожидания.
        config
            .sessions
            .write()
            .unwrap()
            .get_mut(&id)
            .unwrap()
            .expires_at = oidc::now_secs().saturating_sub(1);
        assert_eq!(config.get_session(&id), None);
        // Протухшая запись не должна оставаться в карте.
        assert!(!config.sessions.read().unwrap().contains_key(&id));
    }

    #[test]
    fn logout_drops_the_session() {
        let config = config();
        let id = config.create_session("alice".into());
        config.drop_session(&id);
        assert_eq!(config.get_session(&id), None);
    }

    #[test]
    fn pending_state_carries_the_provider_and_verifier() {
        let config = config();
        let state = config.begin_auth("google", "n".into(), "v".into(), "/app".into());
        let pending = config.take_auth(&state).expect("state should be present");
        assert_eq!(pending.provider_id, "google");
        assert_eq!(pending.nonce, "n");
        assert_eq!(pending.pkce_verifier, "v");
        assert_eq!(pending.return_to, "/app");
        assert!(config.take_auth(&state).is_none());
    }

    #[test]
    fn expired_state_is_rejected() {
        let config = config();
        let state = config.begin_auth("google", "n".into(), "v".into(), "/".into());
        config
            .states
            .write()
            .unwrap()
            .get_mut(&state)
            .unwrap()
            .created_at = oidc::now_secs().saturating_sub(STATE_TTL_SECONDS + 1);
        assert!(config.take_auth(&state).is_none());
    }

    #[test]
    fn pending_states_are_capped() {
        let config = config();
        for _ in 0..(MAX_PENDING_STATES + 50) {
            config.begin_auth("google", "n".into(), "v".into(), "/".into());
        }
        assert!(config.states.read().unwrap().len() <= MAX_PENDING_STATES);
    }

    #[test]
    fn return_to_rejects_anything_but_a_local_path() {
        assert_eq!(sanitize_return_to("/app?x=1"), "/app?x=1");
        assert_eq!(sanitize_return_to("https://evil.test/"), "/");
        // Протокол-относительный URL — тоже уход на чужой хост.
        assert_eq!(sanitize_return_to("//evil.test/"), "/");
        assert_eq!(sanitize_return_to("/\\evil.test/"), "/");
        assert_eq!(sanitize_return_to("/app\r\nSet-Cookie: x=1"), "/");
        // Возврат на сам вход зациклил бы редирект.
        assert_eq!(sanitize_return_to("/-/login"), "/");
        assert_eq!(sanitize_return_to("/-/callback/google?code=1"), "/");
    }

    #[test]
    fn auth_paths_are_recognised() {
        assert!(ReverseProxyConfig::is_auth_path("/-/login"));
        assert!(ReverseProxyConfig::is_auth_path("/-/login/google"));
        assert!(ReverseProxyConfig::is_auth_path("/-/callback"));
        assert!(ReverseProxyConfig::is_auth_path("/-/callback/apple"));
        assert!(ReverseProxyConfig::is_auth_path("/-/logout"));
        assert!(!ReverseProxyConfig::is_auth_path("/-/health"));
        assert!(!ReverseProxyConfig::is_auth_path("/app"));
    }

    #[test]
    fn cross_site_cookies_need_samesite_none() {
        let config = config();
        let lax = config.cookie(STATE_COOKIE, "abc", Some(600), false);
        assert!(lax.contains("SameSite=Lax"));
        assert!(lax.contains("Secure"));

        let cross = config.cookie(STATE_COOKIE, "abc", Some(600), true);
        assert!(cross.contains("SameSite=None"));
        assert!(cross.contains("Secure"));

        // Без Secure на SameSite=None переходить нельзя: браузер отбросит cookie.
        let insecure = ReverseProxyConfig {
            secure_cookies: false,
            ..config
        };
        let cross = insecure.cookie(STATE_COOKIE, "abc", Some(600), true);
        assert!(cross.contains("SameSite=Lax"));
        assert!(!cross.contains("Secure"));
    }

    #[test]
    fn html_escaping_covers_provider_names() {
        assert_eq!(
            html_escape("<script>\"&\""),
            "&lt;script&gt;&quot;&amp;&quot;"
        );
    }

    #[test]
    fn callback_path_provider_is_extracted() {
        assert_eq!(path_provider("/-/callback/google"), Some("google".into()));
        assert_eq!(path_provider("/-/callback"), None);
        assert_eq!(path_provider("/-/callback/"), None);
    }
}
