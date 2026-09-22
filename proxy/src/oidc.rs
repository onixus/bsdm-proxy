//! OpenID Connect for the reverse-proxy IAP path.
//!
//! Замена прежней заготовки, которая строила эндпоинты как `{issuer}/authorize`
//! и `{issuer}/token`. Ни один из двух провайдеров, ради которых это писалось,
//! так не устроен: у Google issuer `https://accounts.google.com`, а authorize
//! живёт на `/o/oauth2/v2/auth` и token вообще на другом хосте
//! (`oauth2.googleapis.com`); у Apple это `/auth/authorize` и `/auth/token`.
//! Поэтому эндпоинты берутся из discovery-документа, а захардкоженные значения
//! остались только как fallback, если `.well-known` недоступен.
//!
//! Второе отличие — id_token теперь проверяется по подписи. Прежний код читал
//! payload через base64 и верил ему на слово: `iss`/`aud`/`exp` сверялись с
//! конфигом, но сам токен не был привязан к ключам IdP.
//!
//! Модуль ничего не знает про forward-SWG плоскость данных
//! (`Proxy-Authorization`) — он обслуживает только браузерный вход в
//! reverse-proxy.

use base64::Engine;
use std::collections::HashMap;
use std::env;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// Допуск на расхождение часов при проверке `exp` / `iat` / `nbf`.
const CLOCK_SKEW_SECONDS: u64 = 120;

/// Сколько держать discovery-документ и JWKS до перечитывания.
const METADATA_TTL: Duration = Duration::from_secs(3600);

/// Apple ограничивает срок жизни client_secret шестью месяцами; берём час —
/// секрет всё равно генерируется на каждый обмен кода.
const APPLE_CLIENT_SECRET_TTL_SECONDS: u64 = 3600;

/// Ошибки, которые видит вызывающий код. Текст уходит только в лог: наружу
/// отдаётся обобщённый ответ, чтобы не превращать эндпоинт в оракул.
#[derive(Debug)]
pub enum OidcError {
    Config(String),
    Network(String),
    Idp(String),
    Token(String),
}

impl std::fmt::Display for OidcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OidcError::Config(m) => write!(f, "config: {}", m),
            OidcError::Network(m) => write!(f, "network: {}", m),
            OidcError::Idp(m) => write!(f, "idp: {}", m),
            OidcError::Token(m) => write!(f, "token: {}", m),
        }
    }
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn b64url_decode(input: &str) -> Result<Vec<u8>, OidcError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(input.trim_end_matches('='))
        .map_err(|e| OidcError::Token(format!("base64url: {}", e)))
}

pub fn b64url_encode(input: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(input)
}

// --- Провайдеры -------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    Google,
    Apple,
    Generic,
}

impl ProviderKind {
    fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "google" => ProviderKind::Google,
            "apple" => ProviderKind::Apple,
            _ => ProviderKind::Generic,
        }
    }

    fn default_issuer(self) -> Option<&'static str> {
        match self {
            ProviderKind::Google => Some("https://accounts.google.com"),
            ProviderKind::Apple => Some("https://appleid.apple.com"),
            ProviderKind::Generic => None,
        }
    }

    /// Fallback на случай, когда discovery недоступен: значения из документации
    /// провайдеров. Для generic fallback'а нет — там без discovery не обойтись.
    fn fallback_endpoints(self) -> Option<Endpoints> {
        match self {
            ProviderKind::Google => Some(Endpoints {
                issuer: "https://accounts.google.com".into(),
                authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth".into(),
                token_endpoint: "https://oauth2.googleapis.com/token".into(),
                jwks_uri: "https://www.googleapis.com/oauth2/v3/certs".into(),
            }),
            ProviderKind::Apple => Some(Endpoints {
                issuer: "https://appleid.apple.com".into(),
                authorization_endpoint: "https://appleid.apple.com/auth/authorize".into(),
                token_endpoint: "https://appleid.apple.com/auth/token".into(),
                jwks_uri: "https://appleid.apple.com/auth/keys".into(),
            }),
            ProviderKind::Generic => None,
        }
    }

    fn default_scopes(self) -> &'static str {
        match self {
            // Apple принимает только name и email, и любой из них переводит
            // ответ в form_post.
            ProviderKind::Apple => "openid email name",
            _ => "openid email profile",
        }
    }

    fn default_display_name(self) -> &'static str {
        match self {
            ProviderKind::Google => "Google",
            ProviderKind::Apple => "Apple",
            ProviderKind::Generic => "SSO",
        }
    }
}

/// Чем подписан запрос к token endpoint.
#[derive(Clone)]
pub enum ClientCredential {
    /// Обычный `client_secret` из конфигурации.
    Secret(String),
    /// Apple не выдаёт статический секрет: его роль играет ES256-JWT,
    /// подписанный приватным ключом из `.p8`, со сроком жизни до полугода.
    AppleKey {
        team_id: String,
        key_id: String,
        pkcs8_der: Vec<u8>,
    },
}

impl std::fmt::Debug for ClientCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientCredential::Secret(_) => f.write_str("Secret(<redacted>)"),
            ClientCredential::AppleKey {
                team_id, key_id, ..
            } => f
                .debug_struct("AppleKey")
                .field("team_id", team_id)
                .field("key_id", key_id)
                .field("pkcs8_der", &"<redacted>")
                .finish(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoints {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
}

pub struct Provider {
    pub id: String,
    pub display_name: String,
    pub kind: ProviderKind,
    pub client_id: String,
    pub credential: ClientCredential,
    pub issuer_url: String,
    pub redirect_uri: String,
    pub scopes: String,
    /// Apple возвращает код POST-ом с `Content-Type: form-urlencoded`, когда
    /// запрошены scope `name`/`email`. Отсюда же следует `SameSite=None` для
    /// cookie со state: при cross-site POST браузер не пришлёт Lax-cookie.
    pub form_post: bool,
    /// Непустой список — вход разрешён только для этих доменов почты.
    pub allowed_domains: Vec<String>,
    endpoints: RwLock<Option<(Endpoints, Instant)>>,
    jwks: RwLock<Option<(Vec<Jwk>, Instant)>>,
}

impl Provider {
    /// Разбирает `OIDC_<ID>_*`. `id` нормализуется в нижний регистр, а в имени
    /// переменных — в верхний, с `-` → `_`.
    fn from_env(id: &str) -> Result<Self, OidcError> {
        let id = id.trim().to_ascii_lowercase();
        if id.is_empty() {
            return Err(OidcError::Config("empty provider id".into()));
        }
        let prefix = format!("OIDC_{}_", id.to_ascii_uppercase().replace('-', "_"));
        let var = |suffix: &str| env::var(format!("{}{}", prefix, suffix)).ok();
        let nonempty = |v: Option<String>| v.filter(|s| !s.trim().is_empty());

        let kind = nonempty(var("KIND"))
            .map(|k| ProviderKind::parse(&k))
            .unwrap_or_else(|| ProviderKind::parse(&id));

        let client_id = nonempty(var("CLIENT_ID"))
            .ok_or_else(|| OidcError::Config(format!("{}CLIENT_ID is required", prefix)))?;

        let issuer_url = nonempty(var("ISSUER_URL"))
            .or_else(|| kind.default_issuer().map(|s| s.to_string()))
            .ok_or_else(|| OidcError::Config(format!("{}ISSUER_URL is required", prefix)))?
            .trim_end_matches('/')
            .to_string();

        let credential = Self::credential_from_env(&prefix, kind, &nonempty, &var)?;

        let redirect_uri = nonempty(var("REDIRECT_URI"))
            .or_else(|| {
                nonempty(env::var("OIDC_REDIRECT_BASE").ok())
                    .map(|base| format!("{}/-/callback/{}", base.trim_end_matches('/'), id))
            })
            .ok_or_else(|| {
                OidcError::Config(format!(
                    "{}REDIRECT_URI or OIDC_REDIRECT_BASE is required",
                    prefix
                ))
            })?;

        let scopes = nonempty(var("SCOPES")).unwrap_or_else(|| kind.default_scopes().to_string());

        // Apple переходит на form_post сам, как только в scope есть name/email;
        // для остальных это опция.
        let form_post = nonempty(var("RESPONSE_MODE"))
            .map(|m| m.eq_ignore_ascii_case("form_post"))
            .unwrap_or_else(|| {
                kind == ProviderKind::Apple
                    && scopes
                        .split_whitespace()
                        .any(|s| s == "name" || s == "email")
            });

        let allowed_domains = nonempty(var("ALLOWED_DOMAINS"))
            .map(|v| {
                v.split(',')
                    .map(|s| s.trim().trim_start_matches('@').to_ascii_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        let display_name = nonempty(var("DISPLAY_NAME"))
            .unwrap_or_else(|| kind.default_display_name().to_string());

        Ok(Self {
            id,
            display_name,
            kind,
            client_id,
            credential,
            issuer_url,
            redirect_uri,
            scopes,
            form_post,
            allowed_domains,
            endpoints: RwLock::new(None),
            jwks: RwLock::new(None),
        })
    }

    fn credential_from_env(
        prefix: &str,
        kind: ProviderKind,
        nonempty: &impl Fn(Option<String>) -> Option<String>,
        var: &impl Fn(&str) -> Option<String>,
    ) -> Result<ClientCredential, OidcError> {
        if kind == ProviderKind::Apple {
            let team_id = nonempty(var("TEAM_ID")).ok_or_else(|| {
                OidcError::Config(format!("{}TEAM_ID is required for Apple", prefix))
            })?;
            let key_id = nonempty(var("KEY_ID")).ok_or_else(|| {
                OidcError::Config(format!("{}KEY_ID is required for Apple", prefix))
            })?;
            let pem = match nonempty(var("PRIVATE_KEY_FILE")) {
                Some(path) => std::fs::read_to_string(&path).map_err(|e| {
                    OidcError::Config(format!("{}PRIVATE_KEY_FILE {}: {}", prefix, path, e))
                })?,
                None => nonempty(var("PRIVATE_KEY")).ok_or_else(|| {
                    OidcError::Config(format!(
                        "{}PRIVATE_KEY_FILE or {}PRIVATE_KEY is required for Apple",
                        prefix, prefix
                    ))
                })?,
            };
            let pkcs8_der = parse_pkcs8_pem(&pem)
                .map_err(|e| OidcError::Config(format!("{}PRIVATE_KEY: {}", prefix, e)))?;
            return Ok(ClientCredential::AppleKey {
                team_id,
                key_id,
                pkcs8_der,
            });
        }

        let secret = nonempty(var("CLIENT_SECRET"))
            .ok_or_else(|| OidcError::Config(format!("{}CLIENT_SECRET is required", prefix)))?;
        Ok(ClientCredential::Secret(secret))
    }

    /// Discovery с кэшем. При недоступности `.well-known` для известных
    /// провайдеров берём задокументированные эндпоинты, чтобы вход не падал
    /// из-за одного сетевого сбоя.
    pub async fn endpoints(&self, client: &reqwest::Client) -> Result<Endpoints, OidcError> {
        if let Some((cached, fetched_at)) = self.endpoints.read().await.as_ref() {
            if fetched_at.elapsed() < METADATA_TTL {
                return Ok(cached.clone());
            }
        }

        let url = format!("{}/.well-known/openid-configuration", self.issuer_url);
        let fetched = match Self::fetch_discovery(client, &url).await {
            Ok(ep) => Some(ep),
            Err(e) => {
                warn!(provider = %self.id, "OIDC discovery failed: {}", e);
                None
            }
        };

        let endpoints = match fetched.or_else(|| self.kind.fallback_endpoints()) {
            Some(ep) => ep,
            None => {
                // Устаревший кэш лучше отказа: эндпоинты меняются редко.
                if let Some((cached, _)) = self.endpoints.read().await.as_ref() {
                    return Ok(cached.clone());
                }
                return Err(OidcError::Network(format!(
                    "discovery unavailable for provider {} and no fallback for a generic issuer",
                    self.id
                )));
            }
        };

        *self.endpoints.write().await = Some((endpoints.clone(), Instant::now()));
        Ok(endpoints)
    }

    async fn fetch_discovery(client: &reqwest::Client, url: &str) -> Result<Endpoints, OidcError> {
        #[derive(serde::Deserialize)]
        struct Doc {
            issuer: String,
            authorization_endpoint: String,
            token_endpoint: String,
            jwks_uri: String,
        }

        let res = client
            .get(url)
            .send()
            .await
            .map_err(|e| OidcError::Network(e.to_string()))?;
        if !res.status().is_success() {
            return Err(OidcError::Network(format!("HTTP {}", res.status())));
        }
        let doc: Doc = res
            .json()
            .await
            .map_err(|e| OidcError::Network(format!("bad discovery document: {}", e)))?;

        Ok(Endpoints {
            issuer: doc.issuer.trim_end_matches('/').to_string(),
            authorization_endpoint: doc.authorization_endpoint,
            token_endpoint: doc.token_endpoint,
            jwks_uri: doc.jwks_uri,
        })
    }

    /// JWKS с кэшем. `force` обходит кэш — нужен, когда в токене пришёл `kid`,
    /// которого нет в кэше: провайдеры ротируют ключи без предупреждения.
    async fn jwks(&self, client: &reqwest::Client, force: bool) -> Result<Vec<Jwk>, OidcError> {
        if !force {
            if let Some((cached, fetched_at)) = self.jwks.read().await.as_ref() {
                if fetched_at.elapsed() < METADATA_TTL {
                    return Ok(cached.clone());
                }
            }
        }

        let endpoints = self.endpoints(client).await?;
        let res = client
            .get(&endpoints.jwks_uri)
            .send()
            .await
            .map_err(|e| OidcError::Network(e.to_string()))?;
        if !res.status().is_success() {
            return Err(OidcError::Network(format!("JWKS HTTP {}", res.status())));
        }

        #[derive(serde::Deserialize)]
        struct JwkSet {
            keys: Vec<Jwk>,
        }
        let set: JwkSet = res
            .json()
            .await
            .map_err(|e| OidcError::Network(format!("bad JWKS: {}", e)))?;

        *self.jwks.write().await = Some((set.keys.clone(), Instant::now()));
        Ok(set.keys)
    }

    /// Секрет для token endpoint: у Apple он генерируется на каждый обмен.
    pub fn client_secret(&self) -> Result<String, OidcError> {
        match &self.credential {
            ClientCredential::Secret(s) => Ok(s.clone()),
            ClientCredential::AppleKey {
                team_id,
                key_id,
                pkcs8_der,
            } => apple_client_secret(team_id, key_id, pkcs8_der, &self.client_id),
        }
    }

    /// Пускать ли пользователя с такой почтой.
    pub fn domain_allowed(&self, email: Option<&str>) -> bool {
        if self.allowed_domains.is_empty() {
            return true;
        }
        let Some(email) = email else {
            return false;
        };
        let Some((_, domain)) = email.rsplit_once('@') else {
            return false;
        };
        let domain = domain.to_ascii_lowercase();
        self.allowed_domains.iter().any(|d| d == &domain)
    }
}

// --- Реестр провайдеров -----------------------------------------------------

pub struct OidcRegistry {
    providers: Vec<std::sync::Arc<Provider>>,
    http: reqwest::Client,
}

impl OidcRegistry {
    /// `OIDC_PROVIDERS=google,apple,corp`. Если переменной нет, но заданы
    /// старые `OIDC_CLIENT_ID`/`OIDC_ISSUER_URL`, собирается один generic
    /// провайдер `default` — чтобы существующие развёртывания не сломались.
    pub fn from_env() -> Option<Self> {
        let ids: Vec<String> = match env::var("OIDC_PROVIDERS") {
            Ok(v) if !v.trim().is_empty() => v.split(',').map(|s| s.trim().to_string()).collect(),
            _ => {
                return Self::legacy_from_env().map(|p| Self {
                    providers: vec![std::sync::Arc::new(p)],
                    http: Self::http_client(),
                })
            }
        };

        let mut providers = Vec::new();
        for id in ids {
            if id.is_empty() {
                continue;
            }
            match Provider::from_env(&id) {
                Ok(p) => {
                    debug!(
                        provider = %p.id,
                        kind = ?p.kind,
                        form_post = p.form_post,
                        "OIDC provider configured"
                    );
                    providers.push(std::sync::Arc::new(p));
                }
                // Один кривой провайдер не должен ронять остальные: он просто
                // не появится на странице входа, а причина уедет в лог.
                Err(e) => warn!(provider = %id, "OIDC provider skipped: {}", e),
            }
        }

        if providers.is_empty() {
            return None;
        }
        Some(Self {
            providers,
            http: Self::http_client(),
        })
    }

    fn http_client() -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default()
    }

    fn legacy_from_env() -> Option<Provider> {
        let client_id = env::var("OIDC_CLIENT_ID").ok().filter(|s| !s.is_empty())?;
        let client_secret = env::var("OIDC_CLIENT_SECRET")
            .ok()
            .filter(|s| !s.is_empty())?;
        let issuer_url = env::var("OIDC_ISSUER_URL").ok().filter(|s| !s.is_empty())?;
        let redirect_uri = env::var("OIDC_REDIRECT_URI")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "http://localhost:3128/-/callback".to_string());

        Some(Provider {
            id: "default".to_string(),
            display_name: env::var("OIDC_DISPLAY_NAME").unwrap_or_else(|_| "SSO".to_string()),
            kind: ProviderKind::Generic,
            client_id,
            credential: ClientCredential::Secret(client_secret),
            issuer_url: issuer_url.trim_end_matches('/').to_string(),
            redirect_uri,
            scopes: "openid email profile".to_string(),
            form_post: false,
            allowed_domains: Vec::new(),
            endpoints: RwLock::new(None),
            jwks: RwLock::new(None),
        })
    }

    pub fn providers(&self) -> &[std::sync::Arc<Provider>] {
        &self.providers
    }

    pub fn get(&self, id: &str) -> Option<&std::sync::Arc<Provider>> {
        self.providers.iter().find(|p| p.id == id)
    }

    pub fn http(&self) -> &reqwest::Client {
        &self.http
    }

    /// URL, на который уводим браузер, чтобы начать вход.
    pub async fn authorization_url(
        &self,
        provider: &Provider,
        state: &str,
        nonce: &str,
        pkce_challenge: &str,
    ) -> Result<String, OidcError> {
        let endpoints = provider.endpoints(&self.http).await?;

        let mut query = url::form_urlencoded::Serializer::new(String::new());
        query
            .append_pair("response_type", "code")
            .append_pair("client_id", &provider.client_id)
            .append_pair("redirect_uri", &provider.redirect_uri)
            .append_pair("scope", &provider.scopes)
            .append_pair("state", state)
            .append_pair("nonce", nonce)
            .append_pair("code_challenge", pkce_challenge)
            .append_pair("code_challenge_method", "S256");

        if provider.form_post {
            query.append_pair("response_mode", "form_post");
        }
        if provider.kind == ProviderKind::Google {
            // Без этого Google не отдаёт refresh_token и молча переиспользует
            // ранее выданное согласие; для IAP важнее предсказуемый экран
            // выбора аккаунта.
            query.append_pair("access_type", "online");
            if provider.allowed_domains.len() == 1 {
                query.append_pair("hd", &provider.allowed_domains[0]);
            }
        }

        let separator = if endpoints.authorization_endpoint.contains('?') {
            '&'
        } else {
            '?'
        };
        Ok(format!(
            "{}{}{}",
            endpoints.authorization_endpoint,
            separator,
            query.finish()
        ))
    }

    /// Обмен кода на токены и полная проверка id_token.
    pub async fn exchange_code(
        &self,
        provider: &Provider,
        code: &str,
        nonce: &str,
        pkce_verifier: &str,
    ) -> Result<IdentityClaims, OidcError> {
        let endpoints = provider.endpoints(&self.http).await?;
        let client_secret = provider.client_secret()?;

        let params = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", provider.redirect_uri.as_str()),
            ("client_id", provider.client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("code_verifier", pkce_verifier),
        ];

        let res = self
            .http
            .post(&endpoints.token_endpoint)
            .form(&params)
            .send()
            .await
            .map_err(|e| OidcError::Network(format!("token exchange: {}", e)))?;

        if !res.status().is_success() {
            let status = res.status();
            let body = res.text().await.unwrap_or_default();
            return Err(OidcError::Idp(format!(
                "token endpoint returned {}: {}",
                status,
                body.chars().take(512).collect::<String>()
            )));
        }

        #[derive(serde::Deserialize)]
        struct TokenResponse {
            id_token: String,
        }
        let token: TokenResponse = res
            .json()
            .await
            .map_err(|e| OidcError::Idp(format!("bad token response: {}", e)))?;

        self.verify_id_token(provider, &token.id_token, nonce).await
    }

    /// Проверка подписи и обязательных claim'ов id_token.
    pub async fn verify_id_token(
        &self,
        provider: &Provider,
        id_token: &str,
        nonce: &str,
    ) -> Result<IdentityClaims, OidcError> {
        let parts: Vec<&str> = id_token.split('.').collect();
        if parts.len() != 3 {
            return Err(OidcError::Token("id_token is not a three-part JWS".into()));
        }
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let signature = b64url_decode(parts[2])?;

        #[derive(serde::Deserialize)]
        struct Header {
            alg: String,
            kid: Option<String>,
        }
        let header: Header = serde_json::from_slice(&b64url_decode(parts[0])?)
            .map_err(|e| OidcError::Token(format!("bad JOSE header: {}", e)))?;

        if header.alg == "none" {
            return Err(OidcError::Token("id_token alg=none is rejected".into()));
        }

        // Ключ мог отротироваться после последнего похода за JWKS — в этом
        // случае один раз перечитываем набор, минуя кэш.
        let mut keys = provider.jwks(&self.http, false).await?;
        if !jwks_has_kid(&keys, header.kid.as_deref()) {
            keys = provider.jwks(&self.http, true).await?;
        }
        let jwk = select_jwk(&keys, header.kid.as_deref(), &header.alg).ok_or_else(|| {
            OidcError::Token(format!(
                "no JWKS key for kid={:?} alg={}",
                header.kid, header.alg
            ))
        })?;
        jwk.verify(&header.alg, signing_input.as_bytes(), &signature)?;

        let claims: RawClaims = serde_json::from_slice(&b64url_decode(parts[1])?)
            .map_err(|e| OidcError::Token(format!("bad claims: {}", e)))?;

        let endpoints = provider.endpoints(&self.http).await?;
        let expected_issuer = endpoints.issuer.trim_end_matches('/');
        if claims.iss.trim_end_matches('/') != expected_issuer {
            return Err(OidcError::Token(format!(
                "issuer mismatch: got {}, expected {}",
                claims.iss, expected_issuer
            )));
        }

        if !claims.audience_contains(&provider.client_id) {
            return Err(OidcError::Token(format!(
                "audience does not contain client_id {}",
                provider.client_id
            )));
        }

        // azp присутствует, когда aud — массив; он обязан совпадать с нашим
        // client_id, иначе токен выписан другому клиенту.
        if let Some(azp) = &claims.azp {
            if azp != &provider.client_id {
                return Err(OidcError::Token(format!("azp mismatch: {}", azp)));
            }
        }

        let now = now_secs();
        if claims.exp.saturating_add(CLOCK_SKEW_SECONDS) <= now {
            return Err(OidcError::Token(format!(
                "expired: exp {} <= now {}",
                claims.exp, now
            )));
        }
        if let Some(nbf) = claims.nbf {
            if nbf > now.saturating_add(CLOCK_SKEW_SECONDS) {
                return Err(OidcError::Token(format!("not yet valid: nbf {}", nbf)));
            }
        }
        if let Some(iat) = claims.iat {
            if iat > now.saturating_add(CLOCK_SKEW_SECONDS) {
                return Err(OidcError::Token(format!(
                    "issued in the future: iat {}",
                    iat
                )));
            }
        }

        // nonce привязывает токен к конкретной начатой сессии входа: без него
        // валидный чужой id_token того же клиента можно было бы переиграть.
        match &claims.nonce {
            Some(got) if got == nonce => {}
            Some(_) => return Err(OidcError::Token("nonce mismatch".into())),
            None => return Err(OidcError::Token("nonce claim is missing".into())),
        }

        if claims.email.is_some() && claims.email_verified == Some(false) {
            return Err(OidcError::Token("email is not verified".into()));
        }

        if !provider.domain_allowed(claims.email.as_deref()) {
            return Err(OidcError::Token(format!(
                "email domain is not allowed for provider {}",
                provider.id
            )));
        }

        Ok(IdentityClaims {
            subject: claims.sub,
            email: claims.email,
            name: claims.name,
            provider: provider.id.clone(),
            expires_at: claims.exp,
        })
    }
}

#[derive(Debug, Clone)]
pub struct IdentityClaims {
    pub subject: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub provider: String,
    pub expires_at: u64,
}

impl IdentityClaims {
    /// Имя, под которым пользователь виден дальше по стеку. Почта читаемее
    /// `sub`, но уникальна только внутри одного провайдера — отсюда префикс.
    pub fn username(&self) -> String {
        let local = self.email.clone().unwrap_or_else(|| self.subject.clone());
        format!("{}:{}", self.provider, local)
    }
}

#[derive(serde::Deserialize)]
struct RawClaims {
    iss: String,
    sub: String,
    aud: serde_json::Value,
    exp: u64,
    iat: Option<u64>,
    nbf: Option<u64>,
    nonce: Option<String>,
    azp: Option<String>,
    email: Option<String>,
    #[serde(default, deserialize_with = "de_lenient_bool")]
    email_verified: Option<bool>,
    name: Option<String>,
}

impl RawClaims {
    fn audience_contains(&self, client_id: &str) -> bool {
        match &self.aud {
            serde_json::Value::String(s) => s == client_id,
            serde_json::Value::Array(items) => items
                .iter()
                .any(|v| v.as_str().is_some_and(|s| s == client_id)),
            _ => false,
        }
    }
}

/// Apple присылает `email_verified` строкой `"true"`, Google — булевым.
fn de_lenient_bool<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    match Option::<serde_json::Value>::deserialize(deserializer)? {
        Some(serde_json::Value::Bool(b)) => Ok(Some(b)),
        Some(serde_json::Value::String(s)) => Ok(match s.as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        }),
        _ => Ok(None),
    }
}

// --- JWKS -------------------------------------------------------------------

#[derive(Debug, Clone, serde::Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub kid: Option<String>,
    pub alg: Option<String>,
    #[serde(rename = "use")]
    pub key_use: Option<String>,
    // RSA
    pub n: Option<String>,
    pub e: Option<String>,
    // EC
    pub crv: Option<String>,
    pub x: Option<String>,
    pub y: Option<String>,
}

impl Jwk {
    fn verify(&self, alg: &str, message: &[u8], signature: &[u8]) -> Result<(), OidcError> {
        use ring::signature;

        // Алгоритм берётся из заголовка токена, но должен совпадать с тем, на
        // что заявлен ключ: иначе RSA-ключ можно скормить HMAC-ветке.
        if let Some(key_alg) = &self.alg {
            if key_alg != alg {
                return Err(OidcError::Token(format!(
                    "alg mismatch: token says {}, key says {}",
                    alg, key_alg
                )));
            }
        }

        match alg {
            "RS256" | "RS384" | "RS512" => {
                let (n, e) = match (&self.n, &self.e) {
                    (Some(n), Some(e)) => (b64url_decode(n)?, b64url_decode(e)?),
                    _ => return Err(OidcError::Token("RSA JWK without n/e".into())),
                };
                let der = rsa_pkcs1_der(&n, &e);
                let params: &dyn signature::VerificationAlgorithm = match alg {
                    "RS256" => &signature::RSA_PKCS1_2048_8192_SHA256,
                    "RS384" => &signature::RSA_PKCS1_2048_8192_SHA384,
                    _ => &signature::RSA_PKCS1_2048_8192_SHA512,
                };
                signature::UnparsedPublicKey::new(params, &der)
                    .verify(message, signature)
                    .map_err(|_| OidcError::Token("id_token signature is invalid".into()))
            }
            "ES256" | "ES384" => {
                let (x, y) = match (&self.x, &self.y) {
                    (Some(x), Some(y)) => (b64url_decode(x)?, b64url_decode(y)?),
                    _ => return Err(OidcError::Token("EC JWK without x/y".into())),
                };
                let mut point = Vec::with_capacity(1 + x.len() + y.len());
                point.push(0x04);
                point.extend_from_slice(&x);
                point.extend_from_slice(&y);
                let params: &dyn signature::VerificationAlgorithm = if alg == "ES256" {
                    &signature::ECDSA_P256_SHA256_FIXED
                } else {
                    &signature::ECDSA_P384_SHA384_FIXED
                };
                signature::UnparsedPublicKey::new(params, &point)
                    .verify(message, signature)
                    .map_err(|_| OidcError::Token("id_token signature is invalid".into()))
            }
            other => Err(OidcError::Token(format!(
                "unsupported id_token algorithm {}",
                other
            ))),
        }
    }
}

fn jwks_has_kid(keys: &[Jwk], kid: Option<&str>) -> bool {
    match kid {
        Some(kid) => keys.iter().any(|k| k.kid.as_deref() == Some(kid)),
        None => !keys.is_empty(),
    }
}

fn select_jwk<'a>(keys: &'a [Jwk], kid: Option<&str>, alg: &str) -> Option<&'a Jwk> {
    let usable = |k: &Jwk| {
        k.key_use.as_deref().map(|u| u == "sig").unwrap_or(true)
            && k.alg.as_deref().map(|a| a == alg).unwrap_or(true)
    };
    if let Some(kid) = kid {
        return keys
            .iter()
            .find(|k| k.kid.as_deref() == Some(kid) && usable(k));
    }
    // Без kid однозначный выбор есть только когда подходящий ключ ровно один.
    let mut candidates = keys.iter().filter(|k| usable(k));
    let first = candidates.next()?;
    if candidates.next().is_some() {
        return None;
    }
    Some(first)
}

// --- DER / PEM --------------------------------------------------------------

fn der_len(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
        return;
    }
    let mut bytes = Vec::new();
    let mut remaining = len;
    while remaining > 0 {
        bytes.push((remaining & 0xff) as u8);
        remaining >>= 8;
    }
    bytes.reverse();
    out.push(0x80 | bytes.len() as u8);
    out.extend_from_slice(&bytes);
}

fn der_integer(raw: &[u8]) -> Vec<u8> {
    let mut value = raw;
    while value.len() > 1 && value[0] == 0 {
        value = &value[1..];
    }
    let mut body = Vec::with_capacity(value.len() + 1);
    // DER INTEGER знаковый: старший бит единицей означал бы отрицательное.
    if value.first().is_some_and(|b| b & 0x80 != 0) {
        body.push(0x00);
    }
    body.extend_from_slice(value);

    let mut out = vec![0x02];
    der_len(body.len(), &mut out);
    out.extend_from_slice(&body);
    out
}

/// `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }` —
/// именно эту форму (PKCS#1, не SPKI) ждёт ring для RSA_PKCS1_*.
fn rsa_pkcs1_der(n: &[u8], e: &[u8]) -> Vec<u8> {
    let mut inner = der_integer(n);
    inner.extend_from_slice(&der_integer(e));
    let mut out = vec![0x30];
    der_len(inner.len(), &mut out);
    out.extend_from_slice(&inner);
    out
}

/// Вытаскивает DER из PEM-блока `PRIVATE KEY` (формат Apple `.p8`).
fn parse_pkcs8_pem(pem: &str) -> Result<Vec<u8>, String> {
    let body: String = pem
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.starts_with("-----") && !l.is_empty())
        .collect();
    if body.is_empty() {
        return Err("no PEM body found".into());
    }
    base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .map_err(|e| format!("not valid base64: {}", e))
}

// --- Apple client_secret ----------------------------------------------------

/// Apple вместо статического секрета принимает ES256-JWT, подписанный ключом
/// из `.p8`: `iss` = Team ID, `sub` = Services ID, `aud` = appleid.apple.com.
fn apple_client_secret(
    team_id: &str,
    key_id: &str,
    pkcs8_der: &[u8],
    client_id: &str,
) -> Result<String, OidcError> {
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

    let rng = SystemRandom::new();
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8_der, &rng)
        .map_err(|e| {
            OidcError::Config(format!(
                "Apple private key is not a P-256 PKCS#8 key: {}",
                e
            ))
        })?;

    let now = now_secs();
    let header = serde_json::json!({ "alg": "ES256", "kid": key_id, "typ": "JWT" });
    let claims = serde_json::json!({
        "iss": team_id,
        "iat": now,
        "exp": now + APPLE_CLIENT_SECRET_TTL_SECONDS,
        "aud": "https://appleid.apple.com",
        "sub": client_id,
    });

    let signing_input = format!(
        "{}.{}",
        b64url_encode(header.to_string().as_bytes()),
        b64url_encode(claims.to_string().as_bytes())
    );
    let signature = key_pair
        .sign(&rng, signing_input.as_bytes())
        .map_err(|_| OidcError::Config("failed to sign the Apple client secret".into()))?;

    Ok(format!(
        "{}.{}",
        signing_input,
        b64url_encode(signature.as_ref())
    ))
}

// --- PKCE -------------------------------------------------------------------

/// Пара verifier/challenge по RFC 7636 (метод S256).
pub fn generate_pkce() -> (String, String) {
    use rand::RngCore;
    use ring::digest;

    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    let verifier = b64url_encode(&bytes);
    let challenge = b64url_encode(digest::digest(&digest::SHA256, verifier.as_bytes()).as_ref());
    (verifier, challenge)
}

pub fn random_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Разбирает `application/x-www-form-urlencoded` — и query, и тело form_post.
pub fn parse_form(input: &str) -> HashMap<String, String> {
    url::form_urlencoded::parse(input.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_integer_keeps_sign_bit_clear() {
        // Старший бит выставлен -> должен добавиться ведущий ноль.
        assert_eq!(
            der_integer(&[0x80, 0x01]),
            vec![0x02, 0x03, 0x00, 0x80, 0x01]
        );
        // Не выставлен -> ноль не нужен.
        assert_eq!(der_integer(&[0x7f, 0x01]), vec![0x02, 0x02, 0x7f, 0x01]);
        // Лишние ведущие нули срезаются.
        assert_eq!(der_integer(&[0x00, 0x00, 0x05]), vec![0x02, 0x01, 0x05]);
    }

    #[test]
    fn der_len_uses_long_form_past_127() {
        let mut short = Vec::new();
        der_len(127, &mut short);
        assert_eq!(short, vec![127]);

        let mut long = Vec::new();
        der_len(256, &mut long);
        assert_eq!(long, vec![0x82, 0x01, 0x00]);
    }

    #[test]
    fn rsa_der_is_a_sequence_of_two_integers() {
        let der = rsa_pkcs1_der(&[0x01, 0x02], &[0x01, 0x00, 0x01]);
        assert_eq!(der[0], 0x30);
        assert_eq!(der[1] as usize, der.len() - 2);
    }

    #[test]
    fn pkce_challenge_matches_rfc7636_example() {
        // RFC 7636, приложение B.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = b64url_encode(
            ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes()).as_ref(),
        );
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn generated_pkce_pair_is_consistent() {
        let (verifier, challenge) = generate_pkce();
        let expected = b64url_encode(
            ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes()).as_ref(),
        );
        assert_eq!(challenge, expected);
        assert!(verifier.len() >= 43 && verifier.len() <= 128);
    }

    #[test]
    fn audience_accepts_string_and_array() {
        let claims: RawClaims =
            serde_json::from_str(r#"{"iss":"https://x","sub":"1","aud":"client-a","exp":1}"#)
                .unwrap();
        assert!(claims.audience_contains("client-a"));
        assert!(!claims.audience_contains("client-b"));

        let claims: RawClaims = serde_json::from_str(
            r#"{"iss":"https://x","sub":"1","aud":["other","client-a"],"exp":1}"#,
        )
        .unwrap();
        assert!(claims.audience_contains("client-a"));
        assert!(!claims.audience_contains("client-c"));
    }

    #[test]
    fn email_verified_accepts_apples_string_form() {
        let claims: RawClaims = serde_json::from_str(
            r#"{"iss":"https://appleid.apple.com","sub":"1","aud":"a","exp":1,"email_verified":"true"}"#,
        )
        .unwrap();
        assert_eq!(claims.email_verified, Some(true));

        let claims: RawClaims = serde_json::from_str(
            r#"{"iss":"https://accounts.google.com","sub":"1","aud":"a","exp":1,"email_verified":false}"#,
        )
        .unwrap();
        assert_eq!(claims.email_verified, Some(false));
    }

    fn test_provider(kind: ProviderKind, domains: Vec<String>) -> Provider {
        Provider {
            id: "p".into(),
            display_name: "P".into(),
            kind,
            client_id: "client".into(),
            credential: ClientCredential::Secret("secret".into()),
            issuer_url: "https://issuer.example".into(),
            redirect_uri: "https://proxy.example/-/callback/p".into(),
            scopes: "openid email".into(),
            form_post: false,
            allowed_domains: domains,
            endpoints: RwLock::new(None),
            jwks: RwLock::new(None),
        }
    }

    #[test]
    fn domain_allowlist_is_enforced_only_when_configured() {
        let open = test_provider(ProviderKind::Generic, vec![]);
        assert!(open.domain_allowed(None));
        assert!(open.domain_allowed(Some("a@anywhere.test")));

        let limited = test_provider(ProviderKind::Google, vec!["corp.test".into()]);
        assert!(limited.domain_allowed(Some("a@corp.test")));
        assert!(limited.domain_allowed(Some("a@CORP.TEST")));
        assert!(!limited.domain_allowed(Some("a@evil.test")));
        // Суффикс чужого домена не должен проходить как поддомен.
        assert!(!limited.domain_allowed(Some("a@not-corp.test")));
        assert!(!limited.domain_allowed(None));
    }

    #[test]
    fn jwk_selection_requires_an_unambiguous_key() {
        let rsa = |kid: &str, alg: Option<&str>| Jwk {
            kty: "RSA".into(),
            kid: Some(kid.into()),
            alg: alg.map(|s| s.into()),
            key_use: Some("sig".into()),
            n: Some("AQAB".into()),
            e: Some("AQAB".into()),
            crv: None,
            x: None,
            y: None,
        };

        let keys = vec![rsa("a", Some("RS256")), rsa("b", Some("RS256"))];
        assert_eq!(
            select_jwk(&keys, Some("b"), "RS256").and_then(|k| k.kid.clone()),
            Some("b".into())
        );
        assert!(select_jwk(&keys, Some("zzz"), "RS256").is_none());
        // Два подходящих ключа и нет kid — выбирать наугад нельзя.
        assert!(select_jwk(&keys, None, "RS256").is_none());

        let single = vec![rsa("a", Some("RS256"))];
        assert!(select_jwk(&single, None, "RS256").is_some());
        assert!(select_jwk(&single, None, "ES256").is_none());
    }

    #[test]
    fn jwk_rejects_algorithm_substitution() {
        let key = Jwk {
            kty: "RSA".into(),
            kid: Some("a".into()),
            alg: Some("RS256".into()),
            key_use: Some("sig".into()),
            n: Some("AQAB".into()),
            e: Some("AQAB".into()),
            crv: None,
            x: None,
            y: None,
        };
        let err = key.verify("ES256", b"msg", b"sig").unwrap_err();
        assert!(matches!(err, OidcError::Token(m) if m.contains("alg mismatch")));
    }

    #[test]
    fn unsupported_and_none_algorithms_are_rejected() {
        let key = Jwk {
            kty: "oct".into(),
            kid: None,
            alg: None,
            key_use: None,
            n: None,
            e: None,
            crv: None,
            x: None,
            y: None,
        };
        assert!(matches!(
            key.verify("HS256", b"msg", b"sig"),
            Err(OidcError::Token(_))
        ));
    }

    #[test]
    fn parse_form_decodes_percent_and_plus() {
        let form = parse_form("code=abc%2Fdef&state=x+y");
        assert_eq!(form.get("code"), Some(&"abc/def".to_string()));
        assert_eq!(form.get("state"), Some(&"x y".to_string()));
    }

    #[test]
    fn pem_parser_strips_armour() {
        let pem = "-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----\n";
        assert_eq!(parse_pkcs8_pem(pem).unwrap(), vec![1, 2, 3]);
        assert!(parse_pkcs8_pem("-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----").is_err());
    }

    #[test]
    fn apple_client_secret_is_a_signed_es256_jwt() {
        use ring::rand::SystemRandom;
        use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();

        let secret =
            apple_client_secret("TEAM123", "KEY456", pkcs8.as_ref(), "com.example.svc").unwrap();
        let parts: Vec<&str> = secret.split('.').collect();
        assert_eq!(parts.len(), 3);

        let header: serde_json::Value =
            serde_json::from_slice(&b64url_decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], "KEY456");

        let claims: serde_json::Value =
            serde_json::from_slice(&b64url_decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["iss"], "TEAM123");
        assert_eq!(claims["sub"], "com.example.svc");
        assert_eq!(claims["aud"], "https://appleid.apple.com");
        assert!(claims["exp"].as_u64().unwrap() > claims["iat"].as_u64().unwrap());

        // Подпись должна проверяться тем же ключом.
        use ring::signature::KeyPair;
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap();
        let public = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_FIXED,
            key_pair.public_key().as_ref(),
        );
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        public
            .verify(signing_input.as_bytes(), &b64url_decode(parts[2]).unwrap())
            .unwrap();
    }

    #[test]
    fn apple_key_debug_does_not_leak_material() {
        let cred = ClientCredential::AppleKey {
            team_id: "TEAM".into(),
            key_id: "KEY".into(),
            pkcs8_der: vec![1, 2, 3],
        };
        let rendered = format!("{:?}", cred);
        assert!(rendered.contains("TEAM"));
        assert!(!rendered.contains("[1, 2, 3]"));

        let rendered = format!("{:?}", ClientCredential::Secret("hunter2".into()));
        assert!(!rendered.contains("hunter2"));
    }

    #[test]
    fn identity_username_is_namespaced_per_provider() {
        let claims = IdentityClaims {
            subject: "sub-1".into(),
            email: Some("a@corp.test".into()),
            name: None,
            provider: "google".into(),
            expires_at: 0,
        };
        assert_eq!(claims.username(), "google:a@corp.test");

        let no_email = IdentityClaims {
            email: None,
            ..claims
        };
        assert_eq!(no_email.username(), "google:sub-1");
    }

    // --- сквозная проверка id_token ---------------------------------------
    //
    // Подпись проверяется на ключе, сгенерированном здесь же: сеть не нужна,
    // потому что кэши discovery и JWKS заполняются напрямую. ES256 взят
    // потому, что ring умеет породить P-256 ключ в рантайме — иначе пришлось
    // бы класть приватный ключ в репозиторий.

    struct SigningKey {
        key_pair: ring::signature::EcdsaKeyPair,
        jwk: Jwk,
    }

    fn signing_key(kid: &str) -> SigningKey {
        use ring::rand::SystemRandom;
        use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap();

        // Несжатая точка: 0x04 || x || y, по 32 байта на координату.
        let point = key_pair.public_key().as_ref().to_vec();
        assert_eq!(point.len(), 65);
        let jwk = Jwk {
            kty: "EC".into(),
            kid: Some(kid.into()),
            alg: Some("ES256".into()),
            key_use: Some("sig".into()),
            n: None,
            e: None,
            crv: Some("P-256".into()),
            x: Some(b64url_encode(&point[1..33])),
            y: Some(b64url_encode(&point[33..])),
        };
        SigningKey { key_pair, jwk }
    }

    fn mint_id_token(key: &SigningKey, claims: serde_json::Value) -> String {
        let header = serde_json::json!({
            "alg": "ES256",
            "kid": key.jwk.kid.clone().unwrap(),
            "typ": "JWT",
        });
        let signing_input = format!(
            "{}.{}",
            b64url_encode(header.to_string().as_bytes()),
            b64url_encode(claims.to_string().as_bytes())
        );
        let signature = key
            .key_pair
            .sign(&ring::rand::SystemRandom::new(), signing_input.as_bytes())
            .unwrap();
        format!("{}.{}", signing_input, b64url_encode(signature.as_ref()))
    }

    async fn registry_with(provider: Provider, keys: Vec<Jwk>) -> OidcRegistry {
        let endpoints = Endpoints {
            issuer: provider.issuer_url.clone(),
            authorization_endpoint: format!("{}/authorize", provider.issuer_url),
            token_endpoint: format!("{}/token", provider.issuer_url),
            jwks_uri: format!("{}/jwks", provider.issuer_url),
        };
        *provider.endpoints.write().await = Some((endpoints, Instant::now()));
        *provider.jwks.write().await = Some((keys, Instant::now()));
        OidcRegistry {
            providers: vec![std::sync::Arc::new(provider)],
            http: OidcRegistry::http_client(),
        }
    }

    fn valid_claims(nonce: &str) -> serde_json::Value {
        serde_json::json!({
            "iss": "https://issuer.example",
            "sub": "subject-1",
            "aud": "client",
            "exp": now_secs() + 600,
            "iat": now_secs(),
            "nonce": nonce,
            "email": "user@corp.test",
            "email_verified": true,
        })
    }

    #[tokio::test]
    async fn valid_id_token_is_accepted() {
        let key = signing_key("k1");
        let registry = registry_with(
            test_provider(ProviderKind::Generic, vec![]),
            vec![key.jwk.clone()],
        )
        .await;
        let provider = registry.providers()[0].clone();

        let token = mint_id_token(&key, valid_claims("nonce-1"));
        let claims = registry
            .verify_id_token(&provider, &token, "nonce-1")
            .await
            .expect("a well-formed token should verify");

        assert_eq!(claims.subject, "subject-1");
        assert_eq!(claims.email.as_deref(), Some("user@corp.test"));
        assert_eq!(claims.username(), "p:user@corp.test");
    }

    #[tokio::test]
    async fn tampered_payload_is_rejected() {
        let key = signing_key("k1");
        let registry = registry_with(
            test_provider(ProviderKind::Generic, vec![]),
            vec![key.jwk.clone()],
        )
        .await;
        let provider = registry.providers()[0].clone();

        let token = mint_id_token(&key, valid_claims("nonce-1"));
        let parts: Vec<&str> = token.split('.').collect();

        // Подменяем sub, оставив подпись от исходного payload — ровно то, что
        // прежняя реализация пропускала, читая payload без проверки подписи.
        let forged_claims = serde_json::json!({
            "iss": "https://issuer.example",
            "sub": "admin",
            "aud": "client",
            "exp": now_secs() + 600,
            "nonce": "nonce-1",
            "email": "admin@corp.test",
        });
        let forged = format!(
            "{}.{}.{}",
            parts[0],
            b64url_encode(forged_claims.to_string().as_bytes()),
            parts[2]
        );

        let err = registry
            .verify_id_token(&provider, &forged, "nonce-1")
            .await
            .unwrap_err();
        assert!(matches!(err, OidcError::Token(m) if m.contains("signature")));
    }

    #[tokio::test]
    async fn token_from_a_foreign_key_is_rejected() {
        let ours = signing_key("k1");
        // Тот же kid, другой ключ: подпись не сойдётся.
        let theirs = signing_key("k1");
        let registry = registry_with(
            test_provider(ProviderKind::Generic, vec![]),
            vec![ours.jwk.clone()],
        )
        .await;
        let provider = registry.providers()[0].clone();

        let token = mint_id_token(&theirs, valid_claims("nonce-1"));
        assert!(registry
            .verify_id_token(&provider, &token, "nonce-1")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn claim_checks_reject_replay_and_misdirected_tokens() {
        let key = signing_key("k1");
        let registry = registry_with(
            test_provider(ProviderKind::Generic, vec![]),
            vec![key.jwk.clone()],
        )
        .await;
        let provider = registry.providers()[0].clone();

        let cases: Vec<(&str, serde_json::Value, &str)> = vec![
            (
                "nonce mismatch",
                valid_claims("other-nonce"),
                "nonce mismatch",
            ),
            (
                "missing nonce",
                serde_json::json!({
                    "iss": "https://issuer.example", "sub": "s", "aud": "client",
                    "exp": now_secs() + 600,
                }),
                "nonce claim is missing",
            ),
            (
                "expired",
                serde_json::json!({
                    "iss": "https://issuer.example", "sub": "s", "aud": "client",
                    "exp": now_secs() - CLOCK_SKEW_SECONDS - 10, "nonce": "nonce-1",
                }),
                "expired",
            ),
            (
                "wrong audience",
                serde_json::json!({
                    "iss": "https://issuer.example", "sub": "s", "aud": "someone-else",
                    "exp": now_secs() + 600, "nonce": "nonce-1",
                }),
                "audience",
            ),
            (
                "wrong issuer",
                serde_json::json!({
                    "iss": "https://evil.example", "sub": "s", "aud": "client",
                    "exp": now_secs() + 600, "nonce": "nonce-1",
                }),
                "issuer mismatch",
            ),
            (
                "azp for another client",
                serde_json::json!({
                    "iss": "https://issuer.example", "sub": "s", "aud": ["client"],
                    "azp": "other", "exp": now_secs() + 600, "nonce": "nonce-1",
                }),
                "azp mismatch",
            ),
            (
                "unverified email",
                serde_json::json!({
                    "iss": "https://issuer.example", "sub": "s", "aud": "client",
                    "exp": now_secs() + 600, "nonce": "nonce-1",
                    "email": "user@corp.test", "email_verified": false,
                }),
                "not verified",
            ),
        ];

        for (name, claims, expected) in cases {
            let token = mint_id_token(&key, claims);
            match registry.verify_id_token(&provider, &token, "nonce-1").await {
                Ok(_) => panic!("{}: token should have been rejected", name),
                Err(OidcError::Token(message)) => assert!(
                    message.contains(expected),
                    "{}: expected {:?} in {:?}",
                    name,
                    expected,
                    message
                ),
                Err(other) => panic!("{}: unexpected error {}", name, other),
            }
        }
    }

    #[tokio::test]
    async fn domain_allowlist_blocks_a_foreign_tenant() {
        let key = signing_key("k1");
        let registry = registry_with(
            test_provider(ProviderKind::Google, vec!["corp.test".into()]),
            vec![key.jwk.clone()],
        )
        .await;
        let provider = registry.providers()[0].clone();

        let outsider = serde_json::json!({
            "iss": "https://issuer.example", "sub": "s", "aud": "client",
            "exp": now_secs() + 600, "nonce": "nonce-1",
            "email": "user@other.test", "email_verified": true,
        });
        let token = mint_id_token(&key, outsider);
        let err = registry
            .verify_id_token(&provider, &token, "nonce-1")
            .await
            .unwrap_err();
        assert!(matches!(err, OidcError::Token(m) if m.contains("domain is not allowed")));
    }

    #[tokio::test]
    async fn alg_none_is_rejected_outright() {
        let key = signing_key("k1");
        let registry = registry_with(
            test_provider(ProviderKind::Generic, vec![]),
            vec![key.jwk.clone()],
        )
        .await;
        let provider = registry.providers()[0].clone();

        let header = serde_json::json!({ "alg": "none", "kid": "k1" });
        let token = format!(
            "{}.{}.",
            b64url_encode(header.to_string().as_bytes()),
            b64url_encode(valid_claims("nonce-1").to_string().as_bytes())
        );
        let err = registry
            .verify_id_token(&provider, &token, "nonce-1")
            .await
            .unwrap_err();
        assert!(matches!(err, OidcError::Token(m) if m.contains("alg=none")));
    }

    #[test]
    fn provider_kind_defaults_cover_google_and_apple() {
        assert_eq!(
            ProviderKind::Google
                .fallback_endpoints()
                .unwrap()
                .token_endpoint,
            "https://oauth2.googleapis.com/token"
        );
        assert_eq!(
            ProviderKind::Apple
                .fallback_endpoints()
                .unwrap()
                .authorization_endpoint,
            "https://appleid.apple.com/auth/authorize"
        );
        assert!(ProviderKind::Generic.fallback_endpoints().is_none());
    }
}
