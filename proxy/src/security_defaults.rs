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
    fn metrics_bind_defaults_and_override() {
        let _g = env_lock().lock().unwrap();
        std::env::remove_var("METRICS_BIND");
        assert_eq!(metrics_bind_addr(9090), "0.0.0.0:9090");
        std::env::set_var("METRICS_BIND", "127.0.0.1");
        assert_eq!(metrics_bind_addr(9090), "127.0.0.1:9090");
        std::env::remove_var("METRICS_BIND");
    }
}
