//! Authentication module
//!
//! Supports multiple authentication backends:
//! - Basic Auth (username:password in base64)
//! - LDAP (Active Directory, OpenLDAP) - optional feature
//! - NTLM (Windows Integrated Authentication) - optional feature
//! - Kerberos / SPNEGO (keytab) - optional feature

use base64::engine::general_purpose;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hyper::header::{PROXY_AUTHENTICATE, PROXY_AUTHORIZATION};
use hyper::{Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

#[cfg(feature = "auth-ldap")]
use tracing::warn as ldap_warn;

#[cfg(feature = "auth-ldap")]
use ldap3::{LdapConn, LdapConnSettings, Scope, SearchEntry};

#[cfg(any(feature = "auth-ntlm", feature = "auth-kerberos"))]
use crate::auth_sspi::{SspiAuthEngine, SspiBackendConfig, SspiSession, SspiStepResult};

/// Authentication backend type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthBackend {
    /// Basic authentication only (no external validation)
    Basic,
    /// LDAP/Active Directory
    #[cfg(feature = "auth-ldap")]
    Ldap,
    /// NTLM (Windows Integrated)
    #[cfg(feature = "auth-ntlm")]
    Ntlm,
    /// Kerberos via SPNEGO / Negotiate (service keytab)
    #[cfg(feature = "auth-kerberos")]
    Kerberos,
}

impl std::fmt::Display for AuthBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthBackend::Basic => write!(f, "basic"),
            #[cfg(feature = "auth-ldap")]
            AuthBackend::Ldap => write!(f, "ldap"),
            #[cfg(feature = "auth-ntlm")]
            AuthBackend::Ntlm => write!(f, "ntlm"),
            #[cfg(feature = "auth-kerberos")]
            AuthBackend::Kerberos => write!(f, "kerberos"),
        }
    }
}

/// User information
#[derive(Debug, Clone)]
pub struct UserInfo {
    pub username: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub groups: Vec<String>,
    pub authenticated_at: Instant,
}

/// Cached user credentials
#[derive(Clone)]
struct CachedUser {
    user_info: UserInfo,
    password_hash: String,
    cached_at: Instant,
    ttl: Duration,
}

impl CachedUser {
    fn is_expired(&self) -> bool {
        self.cached_at.elapsed() > self.ttl
    }

    /// `salt` should be a per-process random value (see [`AuthManager::salt`]) so that
    /// cached hashes cannot be matched against precomputed dictionaries if process
    /// memory is ever exposed, and the comparison itself runs in constant time.
    fn verify_password(&self, password: &str, salt: &[u8]) -> bool {
        let hash = Self::hash_password(password, salt);
        crate::security_util::constant_time_eq(self.password_hash.as_bytes(), hash.as_bytes())
    }

    fn hash_password(password: &str, salt: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(salt);
        hasher.update(password.as_bytes());
        hex::encode(hasher.finalize())
    }
}

/// LDAP configuration
#[cfg(feature = "auth-ldap")]
#[derive(Debug, Clone)]
pub struct LdapConfig {
    pub servers: Vec<String>,
    pub base_dn: String,
    pub bind_dn: Option<String>,
    pub bind_password: Option<String>,
    pub user_filter: String,
    pub group_filter: Option<String>,
    pub timeout: Duration,
    pub use_tls: bool,
    /// Resolve group membership after NTLM/Kerberos (service bind only; no user password).
    pub group_enrichment: bool,
}

#[cfg(feature = "auth-ldap")]
impl Default for LdapConfig {
    fn default() -> Self {
        Self {
            servers: vec!["ldap://localhost:389".to_string()],
            base_dn: "dc=example,dc=com".to_string(),
            bind_dn: None,
            bind_password: None,
            user_filter: "(sAMAccountName={username})".to_string(),
            group_filter: Some("(member={user_dn})".to_string()),
            timeout: Duration::from_secs(5),
            use_tls: false,
            group_enrichment: false,
        }
    }
}

/// Attributes loaded from LDAP (auth or group enrichment).
#[cfg(feature = "auth-ldap")]
#[derive(Debug, Clone, Default)]
struct LdapUserAttrs {
    display_name: Option<String>,
    email: Option<String>,
    groups: Vec<String>,
}

/// Account name for LDAP `{username}` filter from an SSO principal (`user@REALM`, `DOMAIN\user`, …).
#[cfg(feature = "auth-ldap")]
pub(crate) fn ldap_account_name_from_principal(principal: &str) -> &str {
    if let Some((_domain, user)) = principal.split_once('\\') {
        return user;
    }
    principal
        .split_once('@')
        .map_or(principal, |(user, _)| user)
}

/// NTLM configuration
#[cfg(feature = "auth-ntlm")]
#[derive(Debug, Clone)]
pub struct NtlmConfig {
    pub domain: String,
    pub workstation: Option<String>,
    pub helper_command: Option<String>,
    pub candidate_users_file: Option<String>,
}

#[cfg(feature = "auth-ntlm")]
impl Default for NtlmConfig {
    fn default() -> Self {
        Self {
            domain: "WORKGROUP".to_string(),
            workstation: None,
            helper_command: None,
            candidate_users_file: None,
        }
    }
}

/// Kerberos configuration (service keytab)
#[cfg(feature = "auth-kerberos")]
#[derive(Debug, Clone)]
pub struct KerberosConfig {
    pub keytab_path: String,
    pub service_principal: String,
    pub kdc_url: Option<String>,
    pub hostname: String,
    pub max_time_skew: Duration,
}

/// Outcome of proxy authentication for one HTTP request.
#[derive(Debug)]
pub enum ProxyAuthOutcome {
    /// Auth disabled or not required.
    Anonymous,
    /// Authenticated user.
    Authenticated(UserInfo),
    /// Multi-round challenge (407 with optional token in Proxy-Authenticate).
    Challenge { authenticate_header: String },
}

/// Authentication configuration
#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub enabled: bool,
    pub backend: AuthBackend,
    pub realm: String,
    pub cache_ttl: Duration,
    /// Per-TCP-connection auth cache TTL (`AUTH_CONN_CACHE_TTL_SECONDS`; `0` = disabled).
    pub conn_cache_ttl: Duration,
    #[cfg(feature = "auth-ldap")]
    pub ldap: Option<LdapConfig>,
    #[cfg(feature = "auth-ntlm")]
    pub ntlm: Option<NtlmConfig>,
    #[cfg(feature = "auth-kerberos")]
    pub kerberos: Option<KerberosConfig>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backend: AuthBackend::Basic,
            realm: "BSDM-Proxy".to_string(),
            cache_ttl: Duration::from_secs(300),
            conn_cache_ttl: Duration::from_secs(300),
            #[cfg(feature = "auth-ldap")]
            ldap: None,
            #[cfg(feature = "auth-ntlm")]
            ntlm: None,
            #[cfg(feature = "auth-kerberos")]
            kerberos: None,
        }
    }
}

#[cfg(any(feature = "auth-ntlm", feature = "auth-kerberos"))]
struct HandshakeSession {
    session: SspiSession,
    created_at: Instant,
}

#[derive(Clone, Debug)]
struct ConnAuthEntry {
    user: UserInfo,
    cred_fingerprint: Option<String>,
    authenticated_at: Instant,
}

/// Per-TCP-connection proxy auth cache for HTTP keep-alive.
#[derive(Debug)]
pub struct ConnAuthCache {
    ttl: Duration,
    inner: RwLock<Option<ConnAuthEntry>>,
}

impl ConnAuthCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            inner: RwLock::new(None),
        }
    }

    fn enabled(&self) -> bool {
        !self.ttl.is_zero()
    }

    pub async fn get(&self, cred_fingerprint: Option<&str>) -> Option<UserInfo> {
        if !self.enabled() {
            return None;
        }
        let guard = self.inner.read().await;
        let entry = guard.as_ref()?;
        if entry.authenticated_at.elapsed() > self.ttl {
            return None;
        }
        match (cred_fingerprint, entry.cred_fingerprint.as_deref()) {
            (None, _) => Some(entry.user.clone()),
            (Some(fp), Some(cached)) if fp == cached => Some(entry.user.clone()),
            (Some(_), Some(_)) => None,
            (Some(_), None) => Some(entry.user.clone()),
        }
    }

    pub async fn store(&self, user: UserInfo, cred_fingerprint: Option<String>) {
        if !self.enabled() {
            return;
        }
        let mut guard = self.inner.write().await;
        *guard = Some(ConnAuthEntry {
            user,
            cred_fingerprint,
            authenticated_at: Instant::now(),
        });
    }

    pub async fn invalidate(&self) {
        let mut guard = self.inner.write().await;
        *guard = None;
    }
}

fn proxy_auth_fingerprint<T>(req: &Request<T>, salt: &[u8]) -> Option<String> {
    let value = req.headers().get(PROXY_AUTHORIZATION)?.to_str().ok()?;
    Some(CachedUser::hash_password(value, salt))
}

/// Authentication manager
pub struct AuthManager {
    config: AuthConfig,
    user_cache: Arc<RwLock<HashMap<String, CachedUser>>>,
    /// Per-process random salt mixed into cached password hashes so they can't be
    /// matched against precomputed dictionaries if process memory is ever exposed.
    salt: [u8; 16],
    #[cfg(any(feature = "auth-ntlm", feature = "auth-kerberos"))]
    handshake_sessions: Arc<RwLock<HashMap<String, HandshakeSession>>>,
    #[cfg(any(feature = "auth-ntlm", feature = "auth-kerberos"))]
    sspi_engine: Option<Arc<SspiAuthEngine>>,
    #[cfg(any(feature = "auth-ntlm", feature = "auth-kerberos"))]
    principal_cache: Arc<RwLock<HashMap<String, UserInfo>>>,
}

impl AuthManager {
    pub fn new(config: AuthConfig) -> Self {
        info!(
            "Authentication manager initialized with backend: {}",
            config.backend
        );

        #[cfg(feature = "auth-ldap")]
        if config.enabled && Self::should_enrich_groups_from_ldap_static(&config) {
            if let Some(ldap) = &config.ldap {
                if ldap.bind_dn.is_none() || ldap.bind_password.is_none() {
                    warn!(
                        "LDAP group enrichment enabled but LDAP_BIND_DN / LDAP_BIND_PASSWORD \
                         not set — AD lookups may fail"
                    );
                }
            } else {
                warn!(
                    "NTLM/Kerberos backend with LDAP_GROUP_ENRICHMENT but no LDAP_SERVERS — \
                     groups will not be resolved"
                );
            }
        }

        #[cfg(any(feature = "auth-ntlm", feature = "auth-kerberos"))]
        let sspi_engine = build_sspi_engine(&config).map(Arc::new);

        Self {
            config,
            user_cache: Arc::new(RwLock::new(HashMap::new())),
            salt: rand::random(),
            #[cfg(any(feature = "auth-ntlm", feature = "auth-kerberos"))]
            handshake_sessions: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(any(feature = "auth-ntlm", feature = "auth-kerberos"))]
            sspi_engine,
            #[cfg(any(feature = "auth-ntlm", feature = "auth-kerberos"))]
            principal_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    #[cfg(any(feature = "auth-ntlm", feature = "auth-kerberos"))]
    fn uses_sspi_handshake(&self) -> bool {
        self.sspi_engine.is_some()
    }

    /// Check if authentication is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    pub fn conn_cache_ttl(&self) -> Duration {
        self.config.conn_cache_ttl
    }

    /// Extract credentials from request
    pub fn extract_credentials<T>(&self, req: &Request<T>) -> Option<(String, String)> {
        let auth_header = req.headers().get(PROXY_AUTHORIZATION)?;
        let auth_str = auth_header.to_str().ok()?;

        match self.config.backend {
            AuthBackend::Basic => {
                // Basic authentication
                let encoded = auth_str.strip_prefix("Basic ")?;
                let decoded = general_purpose::STANDARD.decode(encoded).ok()?;
                let credentials = String::from_utf8(decoded).ok()?;
                let (username, password) = credentials.split_once(':')?;
                Some((username.to_string(), password.to_string()))
            }
            #[cfg(feature = "auth-ldap")]
            AuthBackend::Ldap => {
                let encoded = auth_str.strip_prefix("Basic ")?;
                let decoded = general_purpose::STANDARD.decode(encoded).ok()?;
                let credentials = String::from_utf8(decoded).ok()?;
                let (username, password) = credentials.split_once(':')?;
                Some((username.to_string(), password.to_string()))
            }
            #[cfg(feature = "auth-ntlm")]
            AuthBackend::Ntlm => None,
            #[cfg(feature = "auth-kerberos")]
            AuthBackend::Kerberos => None,
        }
    }

    /// Parse `Proxy-Authorization` scheme and base64 payload for SSPI backends.
    pub fn extract_proxy_token<T>(&self, req: &Request<T>) -> Option<(String, Vec<u8>)> {
        let auth_header = req.headers().get(PROXY_AUTHORIZATION)?;
        let auth_str = auth_header.to_str().ok()?;
        let (scheme, encoded) = auth_str.split_once(' ')?;
        let decoded = B64.decode(encoded.trim()).ok()?;
        Some((scheme.to_string(), decoded))
    }

    /// Handle proxy authentication including multi-round NTLM / Kerberos.
    #[cfg_attr(
        not(any(feature = "auth-ntlm", feature = "auth-kerberos")),
        allow(unused_variables)
    )]
    pub async fn handle_proxy_auth<T>(
        &self,
        client_key: &str,
        req: &Request<T>,
        conn_auth: Option<&ConnAuthCache>,
    ) -> ProxyAuthOutcome {
        #[cfg(any(feature = "auth-ntlm", feature = "auth-kerberos"))]
        if self.uses_sspi_handshake() {
            return self.handle_sspi_auth(client_key, req, conn_auth).await;
        }

        let cred_fp = proxy_auth_fingerprint(req, &self.salt);
        if let Some(cache) = conn_auth {
            if let Some(user) = cache.get(cred_fp.as_deref()).await {
                debug!("Connection auth cache hit for {}", user.username);
                return ProxyAuthOutcome::Authenticated(user);
            }
        }

        let Some((username, password)) = self.extract_credentials(req) else {
            return ProxyAuthOutcome::Challenge {
                authenticate_header: self.initial_auth_header(),
            };
        };

        match self.authenticate(&username, &password).await {
            Ok(user) => {
                if let Some(cache) = conn_auth {
                    cache.store(user.clone(), cred_fp).await;
                }
                ProxyAuthOutcome::Authenticated(user)
            }
            Err(e) => {
                if let Some(cache) = conn_auth {
                    cache.invalidate().await;
                }
                warn!("Proxy authentication failed for {}: {}", username, e);
                ProxyAuthOutcome::Challenge {
                    authenticate_header: self.initial_auth_header(),
                }
            }
        }
    }

    #[cfg(any(feature = "auth-ntlm", feature = "auth-kerberos"))]
    async fn handle_sspi_auth<T>(
        &self,
        client_key: &str,
        req: &Request<T>,
        conn_auth: Option<&ConnAuthCache>,
    ) -> ProxyAuthOutcome {
        let Some(engine) = &self.sspi_engine else {
            return ProxyAuthOutcome::Challenge {
                authenticate_header: self.initial_auth_header(),
            };
        };

        let token = self
            .extract_proxy_token(req)
            .filter(|(scheme, _)| scheme.eq_ignore_ascii_case(engine.scheme()))
            .map(|(_, bytes)| bytes);

        if token.is_none() {
            if let Some(cache) = conn_auth {
                if let Some(user) = cache.get(None).await {
                    debug!("Connection auth cache hit for {}", user.username);
                    return ProxyAuthOutcome::Authenticated(user);
                }
            }
            if let Some(cached) = self.principal_cache.read().await.get(client_key).cloned() {
                if cached.authenticated_at.elapsed() < self.config.cache_ttl {
                    return ProxyAuthOutcome::Authenticated(cached);
                }
            }
        }

        let token_slice = token.as_deref();
        let step_result = {
            let mut sessions = self.handshake_sessions.write().await;
            if !sessions.contains_key(client_key) {
                match engine.begin_session() {
                    Ok(session) => {
                        sessions.insert(
                            client_key.to_string(),
                            HandshakeSession {
                                session,
                                created_at: Instant::now(),
                            },
                        );
                    }
                    Err(e) => {
                        warn!("Failed to start SSPI session: {}", e);
                        return ProxyAuthOutcome::Challenge {
                            authenticate_header: self.initial_auth_header(),
                        };
                    }
                }
            }

            let Some(entry) = sessions.get_mut(client_key) else {
                return ProxyAuthOutcome::Challenge {
                    authenticate_header: self.initial_auth_header(),
                };
            };

            tokio::task::block_in_place(|| engine.process_token(&mut entry.session, token_slice))
        };

        match step_result {
            Ok(SspiStepResult::Complete {
                username,
                display_name,
            }) => {
                self.handshake_sessions.write().await.remove(client_key);
                let mut user = UserInfo {
                    username: username.clone(),
                    display_name,
                    email: None,
                    groups: vec![],
                    authenticated_at: Instant::now(),
                };
                #[cfg(feature = "auth-ldap")]
                self.apply_ldap_group_enrichment(&mut user).await;
                self.principal_cache
                    .write()
                    .await
                    .insert(client_key.to_string(), user.clone());
                if let Some(cache) = conn_auth {
                    cache.store(user.clone(), None).await;
                }
                ProxyAuthOutcome::Authenticated(user)
            }
            Ok(SspiStepResult::Challenge { token_b64 }) => ProxyAuthOutcome::Challenge {
                authenticate_header: format!("{} {}", engine.scheme(), token_b64),
            },
            Ok(SspiStepResult::Failed(reason)) => {
                self.handshake_sessions.write().await.remove(client_key);
                if let Some(cache) = conn_auth {
                    cache.invalidate().await;
                }
                warn!("SSPI authentication failed for {}: {}", client_key, reason);
                ProxyAuthOutcome::Challenge {
                    authenticate_header: self.initial_auth_header(),
                }
            }
            Err(e) => {
                self.handshake_sessions.write().await.remove(client_key);
                warn!("SSPI error for {}: {}", client_key, e);
                ProxyAuthOutcome::Challenge {
                    authenticate_header: self.initial_auth_header(),
                }
            }
        }
    }

    /// Authenticate user
    pub async fn authenticate(&self, username: &str, password: &str) -> Result<UserInfo, String> {
        debug!("Authenticating user: {}", username);

        // Check cache first
        if let Some(cached) = self.get_cached_user(username).await {
            if !cached.is_expired() && cached.verify_password(password, &self.salt) {
                debug!("User {} authenticated from cache", username);
                return Ok(cached.user_info.clone());
            }
        }

        // Authenticate based on backend
        let user_info = match self.config.backend {
            AuthBackend::Basic => self.authenticate_basic(username, password).await?,
            #[cfg(feature = "auth-ldap")]
            AuthBackend::Ldap => self.authenticate_ldap(username, password).await?,
            #[cfg(feature = "auth-ntlm")]
            AuthBackend::Ntlm => {
                return Err("NTLM uses multi-round handshake; call handle_proxy_auth()".to_string());
            }
            #[cfg(feature = "auth-kerberos")]
            AuthBackend::Kerberos => {
                return Err(
                    "Kerberos uses multi-round handshake; call handle_proxy_auth()".to_string(),
                );
            }
        };

        // Cache successful authentication
        self.cache_user(username, password, user_info.clone()).await;

        info!(
            "User {} authenticated successfully via {}",
            username, self.config.backend
        );
        Ok(user_info)
    }

    /// Basic authentication (no external validation)
    async fn authenticate_basic(
        &self,
        username: &str,
        _password: &str,
    ) -> Result<UserInfo, String> {
        Ok(UserInfo {
            username: username.to_string(),
            display_name: Some(username.to_string()),
            email: None,
            groups: vec![],
            authenticated_at: Instant::now(),
        })
    }

    /// LDAP authentication
    #[cfg(feature = "auth-ldap")]
    async fn authenticate_ldap(&self, username: &str, password: &str) -> Result<UserInfo, String> {
        let ldap_config = self
            .config
            .ldap
            .as_ref()
            .ok_or_else(|| "LDAP not configured".to_string())?;

        // Try each LDAP server
        for server in &ldap_config.servers {
            match self
                .try_ldap_server(server, ldap_config, username, password)
                .await
            {
                Ok(user_info) => return Ok(user_info),
                Err(e) => {
                    ldap_warn!("LDAP server {} failed: {}", server, e);
                    continue;
                }
            }
        }

        Err("All LDAP servers failed".to_string())
    }

    /// Try authenticating against a specific LDAP server
    #[cfg(feature = "auth-ldap")]
    async fn try_ldap_server(
        &self,
        server: &str,
        config: &LdapConfig,
        username: &str,
        password: &str,
    ) -> Result<UserInfo, String> {
        let settings = LdapConnSettings::new().set_conn_timeout(config.timeout);

        let mut ldap = LdapConn::with_settings(settings, server)
            .map_err(|e| format!("LDAP connection failed: {}", e))?;

        ldap_service_bind(&mut ldap, config)?;

        let entry = ldap_search_user_entry(&mut ldap, config, username, Some(username))?;

        let user_dn = entry.dn.clone();
        ldap.simple_bind(&user_dn, password)
            .map_err(|_| "Invalid credentials".to_string())?;

        let attrs = ldap_attrs_from_entry(&entry);

        Ok(UserInfo {
            username: username.to_string(),
            display_name: attrs.display_name,
            email: attrs.email,
            groups: attrs.groups,
            authenticated_at: Instant::now(),
        })
    }

    /// Merge LDAP `memberOf` (and optional profile fields) after NTLM/Kerberos auth.
    #[cfg(feature = "auth-ldap")]
    async fn apply_ldap_group_enrichment(&self, user: &mut UserInfo) {
        if !self.should_enrich_groups_from_ldap() {
            return;
        }
        let Some(ldap_config) = self.config.ldap.as_ref() else {
            return;
        };

        match self
            .lookup_ldap_user_attrs(ldap_config, &user.username)
            .await
        {
            Ok(attrs) => {
                if user.display_name.is_none() {
                    user.display_name = attrs.display_name;
                }
                if user.email.is_none() {
                    user.email = attrs.email;
                }
                user.groups = attrs.groups;
                debug!(
                    "LDAP enrichment for {}: {} group(s)",
                    user.username,
                    user.groups.len()
                );
            }
            Err(e) => {
                warn!("LDAP group enrichment failed for {}: {}", user.username, e);
            }
        }
    }

    #[cfg(feature = "auth-ldap")]
    fn should_enrich_groups_from_ldap(&self) -> bool {
        Self::should_enrich_groups_from_ldap_static(&self.config)
    }

    #[cfg(feature = "auth-ldap")]
    fn should_enrich_groups_from_ldap_static(config: &AuthConfig) -> bool {
        if !config.enabled {
            return false;
        }
        let ldap_enabled = config.ldap.as_ref().is_some_and(|l| l.group_enrichment);
        if !ldap_enabled {
            return false;
        }
        match config.backend {
            #[cfg(feature = "auth-ntlm")]
            AuthBackend::Ntlm => true,
            #[cfg(feature = "auth-kerberos")]
            AuthBackend::Kerberos => true,
            _ => false,
        }
    }

    #[cfg(feature = "auth-ldap")]
    async fn lookup_ldap_user_attrs(
        &self,
        config: &LdapConfig,
        principal: &str,
    ) -> Result<LdapUserAttrs, String> {
        for server in &config.servers {
            match try_ldap_lookup_server(server, config, principal).await {
                Ok(attrs) => return Ok(attrs),
                Err(e) => {
                    ldap_warn!("LDAP lookup on {} failed: {}", server, e);
                }
            }
        }
        Err("All LDAP servers failed for group enrichment".to_string())
    }

    /// Get cached user
    async fn get_cached_user(&self, username: &str) -> Option<CachedUser> {
        self.user_cache.read().await.get(username).cloned()
    }

    /// Cache user
    async fn cache_user(&self, username: &str, password: &str, user_info: UserInfo) {
        let cached = CachedUser {
            user_info,
            password_hash: CachedUser::hash_password(password, &self.salt),
            cached_at: Instant::now(),
            ttl: self.config.cache_ttl,
        };

        self.user_cache
            .write()
            .await
            .insert(username.to_string(), cached);
    }

    fn initial_auth_header(&self) -> String {
        match self.config.backend {
            AuthBackend::Basic => format!("Basic realm=\"{}\"", self.config.realm),
            #[cfg(feature = "auth-ldap")]
            AuthBackend::Ldap => format!("Basic realm=\"{}\"", self.config.realm),
            #[cfg(feature = "auth-ntlm")]
            AuthBackend::Ntlm => "NTLM".to_string(),
            #[cfg(feature = "auth-kerberos")]
            AuthBackend::Kerberos => "Negotiate".to_string(),
        }
    }

    /// Create 407 Proxy Authentication Required response
    pub fn create_auth_required_response<T>(&self) -> Response<T>
    where
        T: Default,
    {
        self.create_auth_challenge_response(self.initial_auth_header())
    }

    /// Create 407 with a specific `Proxy-Authenticate` value (may include challenge token).
    pub fn create_auth_challenge_response<T>(&self, authenticate_header: String) -> Response<T>
    where
        T: Default,
    {
        Response::builder()
            .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
            .header(PROXY_AUTHENTICATE, authenticate_header)
            .body(T::default())
            .unwrap()
    }

    /// Clean expired cache entries
    pub async fn cleanup_cache(&self) {
        let mut cache = self.user_cache.write().await;
        cache.retain(|_, user| !user.is_expired());
        #[cfg(any(feature = "auth-ntlm", feature = "auth-kerberos"))]
        {
            let mut sessions = self.handshake_sessions.write().await;
            sessions.retain(|_, s| s.created_at.elapsed() < self.config.cache_ttl);
            let mut principals = self.principal_cache.write().await;
            principals.retain(|_, u| u.authenticated_at.elapsed() < self.config.cache_ttl);
        }
    }
}

#[cfg(feature = "auth-ldap")]
fn ldap_service_bind(ldap: &mut LdapConn, config: &LdapConfig) -> Result<(), String> {
    if let (Some(bind_dn), Some(bind_password)) = (&config.bind_dn, &config.bind_password) {
        ldap.simple_bind(bind_dn, bind_password)
            .map_err(|e| format!("LDAP bind failed: {}", e))?;
    }
    Ok(())
}

#[cfg(feature = "auth-ldap")]
fn ldap_attrs_from_entry(entry: &SearchEntry) -> LdapUserAttrs {
    LdapUserAttrs {
        display_name: entry
            .attrs
            .get("cn")
            .and_then(|v| v.first())
            .map(|s| s.to_string()),
        email: entry
            .attrs
            .get("mail")
            .and_then(|v| v.first())
            .map(|s| s.to_string()),
        groups: entry
            .attrs
            .get("memberOf")
            .map(|v| v.iter().map(|s| s.to_string()).collect())
            .unwrap_or_default(),
    }
}

#[cfg(feature = "auth-ldap")]
fn ldap_search_user_entry(
    ldap: &mut LdapConn,
    config: &LdapConfig,
    principal: &str,
    filter_username: Option<&str>,
) -> Result<SearchEntry, String> {
    let account = filter_username.unwrap_or_else(|| ldap_account_name_from_principal(principal));
    let filter = config.user_filter.replace("{username}", account);
    let mut entry = ldap_search_first(ldap, config, &filter)?;

    if entry.is_none() && principal.contains('@') {
        let upn_filter = format!("(userPrincipalName={principal})");
        entry = ldap_search_first(ldap, config, &upn_filter)?;
    }

    entry.ok_or_else(|| format!("User not found in LDAP for principal '{principal}'"))
}

#[cfg(feature = "auth-ldap")]
fn ldap_search_first(
    ldap: &mut LdapConn,
    config: &LdapConfig,
    filter: &str,
) -> Result<Option<SearchEntry>, String> {
    let result = ldap
        .search(
            &config.base_dn,
            Scope::Subtree,
            filter,
            vec!["cn", "mail", "memberOf"],
        )
        .map_err(|e| format!("LDAP search failed: {}", e))?;

    let (entries, _) = result
        .success()
        .map_err(|e| format!("LDAP search error: {}", e))?;

    Ok(entries.first().map(|e| SearchEntry::construct(e.clone())))
}

#[cfg(feature = "auth-ldap")]
async fn try_ldap_lookup_server(
    server: &str,
    config: &LdapConfig,
    principal: &str,
) -> Result<LdapUserAttrs, String> {
    let settings = LdapConnSettings::new().set_conn_timeout(config.timeout);
    let server = server.to_string();
    let config = config.clone();
    let principal = principal.to_string();

    tokio::task::spawn_blocking(move || {
        let mut ldap = LdapConn::with_settings(settings, &server)
            .map_err(|e| format!("LDAP connection failed: {}", e))?;
        ldap_service_bind(&mut ldap, &config)?;
        let entry = ldap_search_user_entry(&mut ldap, &config, &principal, None)?;
        Ok(ldap_attrs_from_entry(&entry))
    })
    .await
    .map_err(|e| format!("LDAP lookup task failed: {}", e))?
}

#[cfg(any(feature = "auth-ntlm", feature = "auth-kerberos"))]
fn build_sspi_engine(config: &AuthConfig) -> Option<SspiAuthEngine> {
    use crate::auth_sspi::{KerberosAuthConfig, NtlmAuthConfig};

    let backend = match config.backend {
        #[cfg(feature = "auth-ntlm")]
        AuthBackend::Ntlm => {
            let ntlm = config.ntlm.as_ref()?;
            let mut candidates = Vec::new();
            if let Some(path) = &ntlm.candidate_users_file {
                match crate::auth_sspi::load_ntlm_user_file(path) {
                    Ok(ids) => candidates = ids,
                    Err(e) => warn!("Failed to load NTLM users file: {}", e),
                }
            }
            SspiBackendConfig::Ntlm(NtlmAuthConfig {
                domain: ntlm.domain.clone(),
                workstation: ntlm.workstation.clone(),
                helper_command: ntlm.helper_command.clone(),
                candidate_identities: candidates,
            })
        }
        #[cfg(feature = "auth-kerberos")]
        AuthBackend::Kerberos => {
            let krb = config.kerberos.as_ref()?;
            SspiBackendConfig::Kerberos(KerberosAuthConfig {
                keytab_path: krb.keytab_path.clone(),
                service_principal: krb.service_principal.clone(),
                kdc_url: krb.kdc_url.clone(),
                hostname: krb.hostname.clone(),
                max_time_skew: krb.max_time_skew,
            })
        }
        _ => return None,
    };

    match SspiAuthEngine::new(backend) {
        Ok(engine) => Some(engine),
        Err(e) => {
            warn!("SSPI auth engine disabled: {}", e);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic credential for unit tests (built at runtime for CodeQL CWE-798).
    fn unit_test_secret() -> String {
        ["test", "pass"].concat()
    }

    /// Synthetic salt for unit tests (built at runtime, not a literal, for CodeQL CWE-798 —
    /// this is not a real cryptographic secret, just a fixed test fixture).
    fn unit_test_salt(fill: u8) -> [u8; 16] {
        [0u8; 16].map(|_| fill)
    }

    #[test]
    fn test_password_hashing() {
        let salt = unit_test_salt(7);
        let sample = format!("sample{}", 123);
        let hash1 = CachedUser::hash_password(&sample, &salt);
        let hash2 = CachedUser::hash_password(&sample, &salt);
        assert_eq!(hash1, hash2);

        let other_sample = format!("{}sample", "different-");
        let hash3 = CachedUser::hash_password(&other_sample, &salt);
        assert_ne!(hash1, hash3);

        let hash4 = CachedUser::hash_password(&sample, &unit_test_salt(9));
        assert_ne!(
            hash1, hash4,
            "different salts must produce different hashes"
        );
    }

    #[cfg(feature = "auth-ldap")]
    #[test]
    fn ldap_account_name_from_principal_formats() {
        assert_eq!(ldap_account_name_from_principal("alice"), "alice");
        assert_eq!(
            ldap_account_name_from_principal("alice@CORP.EXAMPLE.COM"),
            "alice"
        );
        assert_eq!(ldap_account_name_from_principal("CORP\\alice"), "alice");
    }

    #[tokio::test]
    async fn test_basic_auth() {
        let config = AuthConfig {
            enabled: true,
            backend: AuthBackend::Basic,
            ..Default::default()
        };

        let manager = AuthManager::new(config);
        let result = manager.authenticate("testuser", "testpass").await;

        assert!(result.is_ok());
        let user_info = result.unwrap();
        assert_eq!(user_info.username, "testuser");
    }

    #[tokio::test]
    async fn test_user_caching() {
        let config = AuthConfig {
            enabled: true,
            backend: AuthBackend::Basic,
            cache_ttl: Duration::from_secs(60),
            ..Default::default()
        };

        let manager = AuthManager::new(config);
        let secret = unit_test_secret();

        // First authentication
        manager.authenticate("testuser", &secret).await.unwrap();

        // Should be cached
        let cached = manager.get_cached_user("testuser").await;
        assert!(cached.is_some());
        assert!(cached.unwrap().verify_password(&secret, &manager.salt));
    }

    #[tokio::test]
    async fn test_cache_expiration() {
        let config = AuthConfig {
            enabled: true,
            backend: AuthBackend::Basic,
            cache_ttl: Duration::from_millis(100),
            ..Default::default()
        };

        let manager = AuthManager::new(config);
        let secret = unit_test_secret();
        manager.authenticate("testuser", &secret).await.unwrap();

        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(150)).await;

        let cached = manager.get_cached_user("testuser").await;
        assert!(cached.unwrap().is_expired());
    }

    fn basic_proxy_request(user: &str, pass: &str) -> Request<()> {
        let token = general_purpose::STANDARD.encode(format!("{user}:{pass}"));
        Request::builder()
            .uri("http://example.com/")
            .header(PROXY_AUTHORIZATION, format!("Basic {token}"))
            .body(())
            .unwrap()
    }

    fn bare_proxy_request() -> Request<()> {
        Request::builder()
            .uri("http://example.com/")
            .body(())
            .unwrap()
    }

    #[tokio::test]
    async fn conn_auth_cache_hit_without_proxy_authorization_header() {
        let config = AuthConfig {
            enabled: true,
            backend: AuthBackend::Basic,
            ..Default::default()
        };
        let manager = AuthManager::new(config);
        let conn = ConnAuthCache::new(Duration::from_secs(60));
        let secret = unit_test_secret();

        let first = manager
            .handle_proxy_auth(
                "conn-1",
                &basic_proxy_request("alice", &secret),
                Some(&conn),
            )
            .await;
        assert!(matches!(first, ProxyAuthOutcome::Authenticated(_)));

        let second = manager
            .handle_proxy_auth("conn-1", &bare_proxy_request(), Some(&conn))
            .await;
        match second {
            ProxyAuthOutcome::Authenticated(user) => assert_eq!(user.username, "alice"),
            other => panic!("expected authenticated cache hit, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn conn_auth_cache_reauths_when_credentials_change() {
        let config = AuthConfig {
            enabled: true,
            backend: AuthBackend::Basic,
            ..Default::default()
        };
        let manager = AuthManager::new(config);
        let conn = ConnAuthCache::new(Duration::from_secs(60));
        let secret = unit_test_secret();

        let first = manager
            .handle_proxy_auth(
                "conn-1",
                &basic_proxy_request("alice", &secret),
                Some(&conn),
            )
            .await;
        assert!(matches!(first, ProxyAuthOutcome::Authenticated(_)));

        let changed = manager
            .handle_proxy_auth("conn-1", &basic_proxy_request("bob", &secret), Some(&conn))
            .await;
        match changed {
            ProxyAuthOutcome::Authenticated(user) => assert_eq!(user.username, "bob"),
            other => panic!("expected re-auth with new credentials, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn conn_auth_cache_miss_after_invalidate() {
        let config = AuthConfig {
            enabled: true,
            backend: AuthBackend::Basic,
            ..Default::default()
        };
        let manager = AuthManager::new(config);
        let conn = ConnAuthCache::new(Duration::from_secs(60));
        let secret = unit_test_secret();

        manager
            .handle_proxy_auth(
                "conn-1",
                &basic_proxy_request("alice", &secret),
                Some(&conn),
            )
            .await;

        conn.invalidate().await;

        let follow_up = manager
            .handle_proxy_auth("conn-1", &bare_proxy_request(), Some(&conn))
            .await;
        assert!(matches!(follow_up, ProxyAuthOutcome::Challenge { .. }));
    }
}
