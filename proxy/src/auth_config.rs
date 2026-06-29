//! Load authentication configuration from environment variables.

use bsdm_proxy::{AuthBackend, AuthConfig};
use std::time::Duration;
use tracing::warn;

#[cfg(feature = "auth-ldap")]
use bsdm_proxy::LdapConfig;

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

fn parse_backend(value: &str) -> AuthBackend {
    match value.to_ascii_lowercase().as_str() {
        "ldap" => {
            #[cfg(feature = "auth-ldap")]
            {
                return AuthBackend::Ldap;
            }
            #[cfg(not(feature = "auth-ldap"))]
            {
                warn!(
                    "AUTH_BACKEND=ldap but proxy was built without auth-ldap feature, using basic"
                );
            }
        }
        "ntlm" => {
            #[cfg(feature = "auth-ntlm")]
            {
                return AuthBackend::Ntlm;
            }
            #[cfg(not(feature = "auth-ntlm"))]
            {
                warn!(
                    "AUTH_BACKEND=ntlm but proxy was built without auth-ntlm feature, using basic"
                );
            }
        }
        _ => {}
    }
    AuthBackend::Basic
}

#[cfg(feature = "auth-ldap")]
fn load_ldap_config(enabled: bool, backend: AuthBackend) -> Option<LdapConfig> {
    if !enabled || backend != AuthBackend::Ldap {
        return None;
    }

    let servers = std::env::var("LDAP_SERVERS")
        .unwrap_or_else(|_| "ldap://localhost:389".to_string())
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();

    let timeout_secs = std::env::var("LDAP_TIMEOUT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);

    Some(LdapConfig {
        servers,
        base_dn: std::env::var("LDAP_BASE_DN").unwrap_or_else(|_| "dc=example,dc=com".to_string()),
        bind_dn: std::env::var("LDAP_BIND_DN").ok(),
        bind_password: std::env::var("LDAP_BIND_PASSWORD").ok(),
        user_filter: std::env::var("LDAP_USER_FILTER")
            .unwrap_or_else(|_| "(sAMAccountName={username})".to_string()),
        group_filter: std::env::var("LDAP_GROUP_FILTER")
            .ok()
            .or_else(|| Some("(member={user_dn})".to_string())),
        timeout: Duration::from_secs(timeout_secs),
        use_tls: env_flag("LDAP_USE_TLS"),
    })
}

pub fn load_auth_config() -> AuthConfig {
    let enabled = env_flag("AUTH_ENABLED");
    let backend = std::env::var("AUTH_BACKEND")
        .map(|v| parse_backend(&v))
        .unwrap_or(AuthBackend::Basic);

    let realm = std::env::var("AUTH_REALM").unwrap_or_else(|_| "BSDM-Proxy".to_string());
    let cache_ttl_secs = std::env::var("AUTH_CACHE_TTL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300);

    AuthConfig {
        enabled,
        backend,
        realm,
        cache_ttl: Duration::from_secs(cache_ttl_secs),
        #[cfg(feature = "auth-ldap")]
        ldap: load_ldap_config(enabled, backend),
        #[cfg(feature = "auth-ntlm")]
        ntlm: {
            use bsdm_proxy::NtlmConfig;
            if enabled && backend == AuthBackend::Ntlm {
                Some(NtlmConfig {
                    domain: std::env::var("NTLM_DOMAIN")
                        .unwrap_or_else(|_| "WORKGROUP".to_string()),
                    workstation: std::env::var("NTLM_WORKSTATION").ok(),
                })
            } else {
                None
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_auth_disabled() {
        std::env::remove_var("AUTH_ENABLED");
        let config = load_auth_config();
        assert!(!config.enabled);
        assert_eq!(config.backend, AuthBackend::Basic);
    }
}
