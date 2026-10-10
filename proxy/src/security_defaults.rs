//! Production-safe defaults for control plane, metrics bind, and related APIs (#271).
//!
//! In `DEPLOYMENT_PROFILE=production` (the default):
//! - mutating control/ACL endpoints require a Bearer token
//! - missing `CONTROL_API_TOKEN` is a hard error unless `CONTROL_API_ALLOW_INSECURE=true`
//! - metrics bind address is configurable (`METRICS_BIND`, default `0.0.0.0` for containers)
//!
//! Lab/dev/test may set `CONTROL_API_ALLOW_INSECURE=true` or non-production
//! `DEPLOYMENT_PROFILE` to keep open local tooling.

use crate::policy_config::DeploymentProfile;
use tracing::{error, info, warn};

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

fn configured_deployment_profile() -> DeploymentProfile {
    std::env::var("DEPLOYMENT_PROFILE")
        .unwrap_or_else(|_| "production".to_string())
        .parse()
        .unwrap_or(DeploymentProfile::Production)
}

/// `DEPLOYMENT_PROFILE` is production (also when unset or unparsable).
pub(crate) fn is_production_profile() -> bool {
    configured_deployment_profile() == DeploymentProfile::Production
}

/// `BLOCK_CLOUD_METADATA` (default on; `0/false/no/off` disables).
pub(crate) fn block_cloud_metadata_from_env() -> bool {
    std::env::var("BLOCK_CLOUD_METADATA")
        .map(|v| {
            !matches!(
                v.to_ascii_lowercase().as_str(),
                "0" | "false" | "no" | "off"
            )
        })
        .unwrap_or(true)
}

/// `BLOCK_LOOPBACK_FORWARDING` (default on in production, off in lab profiles):
/// proxy users must not reach services bound to the proxy host's loopback
/// (Redis L2, control/metrics, threat-intel admin).
pub(crate) fn block_loopback_forwarding_from_env() -> bool {
    std::env::var("BLOCK_LOOPBACK_FORWARDING")
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or_else(|_| is_production_profile())
}

pub(crate) fn resolved_destination_policy_from_env(
) -> crate::security_util::ResolvedDestinationPolicy {
    crate::security_util::ResolvedDestinationPolicy {
        block_metadata: block_cloud_metadata_from_env(),
        block_loopback: block_loopback_forwarding_from_env(),
    }
}

/// Explicit lab override — never enable on a real pilot network.
pub fn control_api_allow_insecure() -> bool {
    env_flag("CONTROL_API_ALLOW_INSECURE")
}

/// Whether the control plane should fail closed when no token is configured.
///
/// Production defaults to true unless `CONTROL_API_ALLOW_INSECURE=true`.
/// Development/test default to false unless `CONTROL_API_REQUIRE_TOKEN=true`.
pub fn control_api_fail_closed() -> bool {
    if control_api_allow_insecure() {
        return false;
    }
    match configured_deployment_profile() {
        DeploymentProfile::Production => true,
        DeploymentProfile::Development | DeploymentProfile::Test => {
            env_flag("CONTROL_API_REQUIRE_TOKEN")
        }
    }
}

pub fn control_api_token_from_env() -> Option<String> {
    std::env::var("CONTROL_API_TOKEN")
        .ok()
        .filter(|t| !t.is_empty())
        .or_else(|| {
            std::env::var("ACL_API_TOKEN")
                .ok()
                .filter(|t| !t.is_empty())
        })
}

/// Validate control-plane token posture at process start.
///
/// Production without a token fails hard unless `CONTROL_API_ALLOW_INSECURE=true`.
pub fn validate_control_plane_security() -> Result<(), String> {
    let profile = configured_deployment_profile();
    let token = control_api_token_from_env();
    let allow_insecure = control_api_allow_insecure();
    let fail_closed = control_api_fail_closed();

    match (profile, token.is_some(), allow_insecure) {
        (DeploymentProfile::Production, false, false) => {
            error!(
                "CONTROL_API_TOKEN is required in DEPLOYMENT_PROFILE=production \
                 (set CONTROL_API_TOKEN or explicitly CONTROL_API_ALLOW_INSECURE=true for lab only)"
            );
            Err(
                "CONTROL_API_TOKEN is required in production; set the token or \
                 CONTROL_API_ALLOW_INSECURE=true (lab only)"
                    .to_string(),
            )
        }
        (DeploymentProfile::Production, false, true) => {
            warn!(
                "CONTROL_API_ALLOW_INSECURE=true with no CONTROL_API_TOKEN — \
                 mutating control APIs are open. Never use this on a pilot network."
            );
            Ok(())
        }
        (_, true, _) => {
            info!(
                "Control plane auth enabled (Bearer CONTROL_API_TOKEN/ACL_API_TOKEN), fail_closed={}",
                fail_closed
            );
            Ok(())
        }
        (DeploymentProfile::Development | DeploymentProfile::Test, false, _) => {
            if fail_closed {
                warn!(
                    "CONTROL_API_REQUIRE_TOKEN=true but no token configured — mutations return 401"
                );
            } else {
                warn!(
                    "CONTROL_API_TOKEN unset in {:?} — mutating control APIs are open (lab mode)",
                    profile
                );
            }
            Ok(())
        }
    }
}

/// Open-proxy guard (P1-04): in production a proxy without authentication
/// must restrict clients by ACL source IP, or the operator must opt in to an
/// anonymous proxy explicitly (`ALLOW_ANONYMOUS_PROXY=true`) — otherwise
/// `0.0.0.0:3128` with the MITM CA is an open proxy for anyone who reaches it.
pub fn validate_open_proxy_posture(
    auth_enabled: bool,
    has_client_ip_acl: bool,
) -> Result<(), String> {
    if auth_enabled || has_client_ip_acl {
        return Ok(());
    }
    if env_flag("ALLOW_ANONYMOUS_PROXY") {
        warn!("ALLOW_ANONYMOUS_PROXY=true: proxy accepts unauthenticated clients without a client-IP ACL");
        return Ok(());
    }
    match configured_deployment_profile() {
        DeploymentProfile::Production => {
            error!(
                "AUTH_ENABLED=false and no client-IP ACL rule in DEPLOYMENT_PROFILE=production \
                 (enable auth, add an IpRange ACL rule, or set ALLOW_ANONYMOUS_PROXY=true)"
            );
            Err(
                "refusing to start an open proxy in production: enable AUTH_ENABLED, add a \
                 client-IP (IpRange) ACL rule, or set ALLOW_ANONYMOUS_PROXY=true"
                    .to_string(),
            )
        }
        DeploymentProfile::Development | DeploymentProfile::Test => {
            warn!("AUTH_ENABLED=false and no client-IP ACL rule — open proxy (lab profile)");
            Ok(())
        }
    }
}

/// Basic proxy auth without a users file accepts *any* credentials (the
/// username is taken on trust). In production that is an identity-spoofing hole
/// — any client picks the username with the widest ACL and forges the audit
/// trail — so startup fails; lab profiles keep the warning.
pub fn validate_basic_auth_posture(
    auth_enabled: bool,
    backend_is_basic: bool,
    users_file_configured: bool,
) -> Result<(), String> {
    if !(auth_enabled && backend_is_basic && !users_file_configured) {
        return Ok(());
    }
    match configured_deployment_profile() {
        DeploymentProfile::Production => {
            error!(
                "AUTH_ENABLED=true with AUTH_BACKEND=basic requires BASIC_AUTH_USERS_FILE \
                 in DEPLOYMENT_PROFILE=production"
            );
            Err(
                "AUTH_ENABLED with AUTH_BACKEND=basic requires BASIC_AUTH_USERS_FILE in \
                 production (without it any credentials are accepted)"
                    .to_string(),
            )
        }
        DeploymentProfile::Development | DeploymentProfile::Test => {
            warn!(
                "AUTH_ENABLED with AUTH_BACKEND=basic but BASIC_AUTH_USERS_FILE is unset — \
                 any Proxy-Authorization credentials will be accepted (lab only). For pilot/production \
                 set BASIC_AUTH_USERS_FILE (see docs/getting-started/pilot-auth.md)"
            );
            Ok(())
        }
    }
}

/// Metrics/control listener bind host (not including port).
///
/// Default `0.0.0.0` for container port publishing. Bare-metal pilots should
/// prefer `127.0.0.1` or a private management IP and put Prometheus on the same
/// host/VPC, or terminate via an authenticated gateway.
pub fn metrics_bind_host() -> String {
    std::env::var("METRICS_BIND")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "0.0.0.0".to_string())
}

pub fn metrics_bind_addr(port: u16) -> String {
    format!("{}:{}", metrics_bind_host(), port)
}

/// Optional Bearer for `GET /metrics` scrape endpoint.
pub fn metrics_auth_token() -> Option<String> {
    std::env::var("METRICS_AUTH_TOKEN")
        .ok()
        .filter(|t| !t.is_empty())
        .or_else(|| {
            if env_flag("METRICS_REQUIRE_AUTH") {
                control_api_token_from_env()
            } else {
                None
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn production_requires_token_without_insecure_override() {
        let _g = env_lock().lock().unwrap();
        std::env::set_var("DEPLOYMENT_PROFILE", "production");
        std::env::remove_var("CONTROL_API_TOKEN");
        std::env::remove_var("ACL_API_TOKEN");
        std::env::remove_var("CONTROL_API_ALLOW_INSECURE");
        assert!(control_api_fail_closed());
        assert!(validate_control_plane_security().is_err());
        std::env::remove_var("DEPLOYMENT_PROFILE");
    }

    #[test]
    fn production_allows_insecure_override() {
        let _g = env_lock().lock().unwrap();
        std::env::set_var("DEPLOYMENT_PROFILE", "production");
        std::env::remove_var("CONTROL_API_TOKEN");
        std::env::remove_var("ACL_API_TOKEN");
        std::env::set_var("CONTROL_API_ALLOW_INSECURE", "true");
        assert!(!control_api_fail_closed());
        assert!(validate_control_plane_security().is_ok());
        std::env::remove_var("CONTROL_API_ALLOW_INSECURE");
        std::env::remove_var("DEPLOYMENT_PROFILE");
    }

    #[test]
    fn basic_auth_without_users_file_fails_in_production_only() {
        let _g = env_lock().lock().unwrap();
        std::env::set_var("DEPLOYMENT_PROFILE", "production");
        assert!(validate_basic_auth_posture(true, true, false).is_err());
        assert!(validate_basic_auth_posture(true, true, true).is_ok());
        assert!(validate_basic_auth_posture(false, true, false).is_ok());
        assert!(validate_basic_auth_posture(true, false, false).is_ok());
        std::env::remove_var("DEPLOYMENT_PROFILE");
        // Unset profile means production.
        assert!(validate_basic_auth_posture(true, true, false).is_err());
        std::env::set_var("DEPLOYMENT_PROFILE", "development");
        assert!(validate_basic_auth_posture(true, true, false).is_ok());
        std::env::remove_var("DEPLOYMENT_PROFILE");
    }

    #[test]
    fn open_proxy_refused_in_production_without_opt_in() {
        let _g = env_lock().lock().unwrap();
        std::env::set_var("DEPLOYMENT_PROFILE", "production");
        std::env::remove_var("ALLOW_ANONYMOUS_PROXY");
        assert!(validate_open_proxy_posture(false, false).is_err());
        assert!(validate_open_proxy_posture(true, false).is_ok());
        assert!(validate_open_proxy_posture(false, true).is_ok());
        std::env::set_var("ALLOW_ANONYMOUS_PROXY", "true");
        assert!(validate_open_proxy_posture(false, false).is_ok());
        std::env::remove_var("ALLOW_ANONYMOUS_PROXY");
        std::env::set_var("DEPLOYMENT_PROFILE", "development");
        assert!(validate_open_proxy_posture(false, false).is_ok());
        std::env::remove_var("DEPLOYMENT_PROFILE");
    }

    #[test]
    fn metrics_bind_defaults_and_override() {
        let _g = env_lock().lock().unwrap();
        std::env::remove_var("METRICS_BIND");
        assert_eq!(metrics_bind_addr(9090), "0.0.0.0:9090");
        std::env::set_var("METRICS_BIND", "127.0.0.1");
        assert_eq!(metrics_bind_addr(9090), "127.0.0.1:9090");
        std::env::remove_var("METRICS_BIND");
    }
}
