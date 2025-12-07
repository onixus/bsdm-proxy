//! Authentication module
//!
//! Supports multiple authentication backends:
//! - Basic Auth (username:password in base64)
//! - LDAP (Active Directory, OpenLDAP)
//! - NTLM (Windows Integrated Authentication)

use base64::engine::general_purpose;
use base64::Engine;
use hyper::header::{HeaderValue, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION};
use hyper::{Request, Response, StatusCode};
use ldap3::{LdapConn, LdapConnSettings, Scope, SearchEntry};
use ntlm::Ntlm;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Authentication backend type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthBackend {
    /// Basic authentication only (no external validation)
    Basic,
    /// LDAP/Active Directory
    Ldap,
    /// NTLM (Windows Integrated)
    Ntlm,
}

impl std::fmt::Display for AuthBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthBackend::Basic => write!(f, "basic"),
            AuthBackend::Ldap => write!(f, "ldap"),
            AuthBackend::Ntlm => write!(f, "ntlm"),
        }
    }
}

/// User information
#[derive(Debug, Clone, Serialize, Deserialize)]
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

    fn verify_password(&self, password: &str) -> bool {
        let hash = Self::hash_password(password);
        self.password_hash == hash
    }

    fn hash_password(password: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hex::encode(hasher.finalize())
    }
}

/// LDAP configuration
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
}

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
        }
    }
}

/// NTLM configuration
#[derive(Debug, Clone)]
pub struct NtlmConfig {
    pub domain: String,
    pub workstation: Option<String>,
}

impl Default for NtlmConfig {
    fn default() -> Self {
        Self {
            domain: "WORKGROUP".to_string(),
            workstation: None,
        }
    }
}

/// Authentication configuration
#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub enabled: bool,
    pub backend: AuthBackend,
    pub realm: String,
    pub cache_ttl: Duration,
    pub ldap: Option<LdapConfig>,
    pub ntlm: Option<NtlmConfig>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backend: AuthBackend::Basic,
            realm: "BSDM-Proxy".to_string(),
            cache_ttl: Duration::from_secs(300),
            ldap: None,
            ntlm: None,
        }
    }
}

/// Authentication manager
pub struct AuthManager {
    config: AuthConfig,
    user_cache: Arc<RwLock<HashMap<String, CachedUser>>>,
    ntlm_challenges: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl AuthManager {
    pub fn new(config: AuthConfig) -> Self {
        info!("Authentication manager initialized with backend: {}", config.backend);
        Self {
            config,
            user_cache: Arc::new(RwLock::new(HashMap::new())),
            ntlm_challenges: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Check if authentication is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Extract credentials from request
    pub fn extract_credentials<T>(&self, req: &Request<T>) -> Option<(String, String)> {
        let auth_header = req.headers().get(PROXY_AUTHORIZATION)?;
        let auth_str = auth_header.to_str().ok()?;

        match self.config.backend {
            AuthBackend::Basic | AuthBackend::Ldap => {
                // Basic authentication
                let encoded = auth_str.strip_prefix("Basic ")?;
                let decoded = general_purpose::STANDARD.decode(encoded).ok()?;
                let credentials = String::from_utf8(decoded).ok()?;
                let (username, password) = credentials.split_once(':')?;
                Some((username.to_string(), password.to_string()))
            }
            AuthBackend::Ntlm => {
                // NTLM authentication (handled separately)
                None
            }
        }
    }

    /// Authenticate user
    pub async fn authenticate(&self, username: &str, password: &str) -> Result<UserInfo, String> {
        debug!("Authenticating user: {}", username);

        // Check cache first
        if let Some(cached) = self.get_cached_user(username).await {
            if !cached.is_expired() && cached.verify_password(password) {
                debug!("User {} authenticated from cache", username);
                return Ok(cached.user_info.clone());
            }
        }

        // Authenticate based on backend
        let user_info = match self.config.backend {
            AuthBackend::Basic => self.authenticate_basic(username, password).await?,
            AuthBackend::Ldap => self.authenticate_ldap(username, password).await?,
            AuthBackend::Ntlm => {
                return Err("NTLM requires challenge-response flow".to_string())
            }
        };

        // Cache successful authentication
        self.cache_user(username, password, user_info.clone()).await;

        info!("User {} authenticated successfully via {}", username, self.config.backend);
        Ok(user_info)
    }

    /// Basic authentication (no external validation)
    async fn authenticate_basic(&self, username: &str, _password: &str) -> Result<UserInfo, String> {
        Ok(UserInfo {
            username: username.to_string(),
            display_name: Some(username.to_string()),
            email: None,
            groups: vec![],
            authenticated_at: Instant::now(),
        })
    }

    /// LDAP authentication
    async fn authenticate_ldap(&self, username: &str, password: &str) -> Result<UserInfo, String> {
        let ldap_config = self.config.ldap.as_ref()
            .ok_or_else(|| "LDAP not configured".to_string())?;

        // Try each LDAP server
        for server in &ldap_config.servers {
            match self.try_ldap_server(server, ldap_config, username, password).await {
                Ok(user_info) => return Ok(user_info),
                Err(e) => {
                    warn!("LDAP server {} failed: {}", server, e);
                    continue;
                }
            }
        }

        Err("All LDAP servers failed".to_string())
    }

    /// Try authenticating against a specific LDAP server
    async fn try_ldap_server(
        &self,
        server: &str,
        config: &LdapConfig,
        username: &str,
        password: &str,
    ) -> Result<UserInfo, String> {
        // Connect to LDAP server
        let settings = LdapConnSettings::new()
            .set_conn_timeout(config.timeout);

        let mut ldap = LdapConn::with_settings(settings, server)
            .map_err(|e| format!("LDAP connection failed: {}", e))?;

        // Bind with service account if configured
        if let (Some(bind_dn), Some(bind_password)) = (&config.bind_dn, &config.bind_password) {
            ldap.simple_bind(bind_dn, bind_password)
                .map_err(|e| format!("LDAP bind failed: {}", e))?;
        }

        // Search for user
        let filter = config.user_filter.replace("{username}", username);
        let result = ldap
            .search(&config.base_dn, Scope::Subtree, &filter, vec!["cn", "mail", "memberOf"])
            .map_err(|e| format!("LDAP search failed: {}", e))?;

        let (entries, _) = result.success()
            .map_err(|e| format!("LDAP search error: {}", e))?;

        if entries.is_empty() {
            return Err("User not found".to_string());
        }

        let entry = SearchEntry::construct(entries[0].clone());
        let user_dn = entry.dn.clone();

        // Authenticate user by binding with their credentials
        ldap.simple_bind(&user_dn, password)
            .map_err(|_| "Invalid credentials".to_string())?;

        // Extract user information
        let display_name = entry.attrs.get("cn")
            .and_then(|v| v.first())
            .map(|s| s.to_string());

        let email = entry.attrs.get("mail")
            .and_then(|v| v.first())
            .map(|s| s.to_string());

        let groups = entry.attrs.get("memberOf")
            .map(|v| v.iter().map(|s| s.to_string()).collect())
            .unwrap_or_default();

        Ok(UserInfo {
            username: username.to_string(),
            display_name,
            email,
            groups,
            authenticated_at: Instant::now(),
        })
    }

    /// Get cached user
    async fn get_cached_user(&self, username: &str) -> Option<CachedUser> {
        self.user_cache.read().await.get(username).cloned()
    }

    /// Cache user
    async fn cache_user(&self, username: &str, password: &str, user_info: UserInfo) {
        let cached = CachedUser {
            user_info,
            password_hash: CachedUser::hash_password(password),
            cached_at: Instant::now(),
            ttl: self.config.cache_ttl,
        };

        self.user_cache.write().await.insert(username.to_string(), cached);
    }

    /// Create 407 Proxy Authentication Required response
    pub fn create_auth_required_response<T>(&self) -> Response<T>
    where
        T: Default,
    {
        let auth_header = match self.config.backend {
            AuthBackend::Basic | AuthBackend::Ldap => {
                format!("Basic realm=\"{}\"", self.config.realm)
            }
            AuthBackend::Ntlm => {
                "NTLM".to_string()
            }
        };

        Response::builder()
            .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
            .header(PROXY_AUTHENTICATE, auth_header)
            .body(T::default())
            .unwrap()
    }

    /// Clean expired cache entries
    pub async fn cleanup_cache(&self) {
        let mut cache = self.user_cache.write().await;
        cache.retain(|_, user| !user.is_expired());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hashing() {
        let hash1 = CachedUser::hash_password("password123");
        let hash2 = CachedUser::hash_password("password123");
        assert_eq!(hash1, hash2);

        let hash3 = CachedUser::hash_password("different");
        assert_ne!(hash1, hash3);
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
        
        // First authentication
        manager.authenticate("testuser", "password").await.unwrap();
        
        // Should be cached
        let cached = manager.get_cached_user("testuser").await;
        assert!(cached.is_some());
        assert!(cached.unwrap().verify_password("password"));
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
        manager.authenticate("testuser", "password").await.unwrap();
        
        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(150)).await;
        
        let cached = manager.get_cached_user("testuser").await;
        assert!(cached.unwrap().is_expired());
    }
}
