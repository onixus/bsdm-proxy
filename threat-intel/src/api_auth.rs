//! Admin API authorization and SOAR audit trail.
//!
//! Mirrors the proxy control plane (`proxy/src/security_defaults.rs`,
//! `ControlApiState::is_authorized_bearer`):
//! - mutating `POST /api/v1/soar/*` requires `Authorization: Bearer <TI_API_TOKEN>`
//! - no token configured + fail-closed (production default) → mutations denied
//! - every accepted or rejected mutation is appended to a JSONL audit log
//!
//! Read-only endpoints (`/health`, `/metrics`) stay open so probes and the
//! Prometheus scraper keep working.

use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

/// Loopback by default: the admin API must be published deliberately.
const DEFAULT_BIND: &str = "127.0.0.1";

/// Length-independent comparison, no early exit on the first differing byte.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

/// Auth posture of the collector admin API.
#[derive(Debug, Clone)]
pub struct AdminApiSecurity {
    token: Option<String>,
    fail_closed: bool,
    bind_host: String,
    audit_path: PathBuf,
}

impl AdminApiSecurity {
    pub fn from_env(output_dir: &Path) -> Self {
        let token = std::env::var("TI_API_TOKEN")
            .ok()
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty());
        // Explicit lab override; never set it on a pilot network. It is the only
        // way to open the mutating endpoints: the posture deliberately ignores
        // DEPLOYMENT_PROFILE, which other services flip for unrelated reasons and
        // which would otherwise silently unauthenticate SOAR mutations.
        let allow_insecure = env_flag("TI_API_ALLOW_INSECURE");
        let fail_closed = !allow_insecure;
        let bind_host = std::env::var("TI_ADMIN_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_string());
        let audit_path = std::env::var("TI_SOAR_AUDIT_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| output_dir.join("soar-audit.jsonl"));

        let security = Self {
            token,
            fail_closed,
            bind_host,
            audit_path,
        };
        security.log_posture(allow_insecure);
        security
    }

    fn log_posture(&self, allow_insecure: bool) {
        match (&self.token, self.fail_closed) {
            (Some(_), _) => info!(
                bind = %self.bind_host,
                audit_path = %self.audit_path.display(),
                "threat-intel SOAR API auth enabled (Bearer TI_API_TOKEN)"
            ),
            (None, true) => warn!(
                "TI_API_TOKEN is not set: mutating SOAR endpoints are disabled (fail-closed). \
                 Set TI_API_TOKEN to use /api/v1/soar/block and /api/v1/soar/unblock"
            ),
            (None, false) => warn!(
                allow_insecure,
                "threat-intel SOAR API has no TI_API_TOKEN and is not fail-closed — \
                 mutating endpoints are open. Lab use only."
            ),
        }
    }

    /// `host` part of the admin listener; `127.0.0.1` unless `TI_ADMIN_BIND` overrides it.
    pub fn bind_host(&self) -> &str {
        &self.bind_host
    }

    pub fn audit_path(&self) -> &Path {
        &self.audit_path
    }

    /// Token configured → constant-time match. No token → allowed only in an
    /// explicitly opened lab profile.
    pub fn is_authorized_bearer(&self, bearer: Option<&str>) -> bool {
        match &self.token {
            Some(expected) => {
                bearer.is_some_and(|token| constant_time_eq(token.as_bytes(), expected.as_bytes()))
            }
            None => !self.fail_closed,
        }
    }

    /// Authorization for a raw HTTP request head.
    pub fn is_request_authorized(&self, request: &str) -> bool {
        self.is_authorized_bearer(extract_bearer(request))
    }

    /// Test constructor.
    #[cfg(test)]
    pub fn for_test(token: Option<&str>, fail_closed: bool, audit_path: PathBuf) -> Self {
        Self {
            token: token.map(str::to_string),
            fail_closed,
            bind_host: DEFAULT_BIND.to_string(),
            audit_path,
        }
    }
}

/// Extracts `Authorization: Bearer <token>` from a raw request head.
pub fn extract_bearer(request: &str) -> Option<&str> {
    // Skip the request line; stop at the blank line that ends the head.
    for line in request.lines().skip(1) {
        if line.trim().is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("authorization") {
            continue;
        }
        // Malformed or non-Bearer credentials are treated as absent.
        let (scheme, token) = value.trim().split_once(' ')?;
        if !scheme.eq_ignore_ascii_case("bearer") {
            return None;
        }
        let token = token.trim();
        return (!token.is_empty()).then_some(token);
    }
    None
}

#[derive(Debug, Serialize)]
struct SoarAuditRecord<'a> {
    timestamp_unix: u64,
    actor: &'a str,
    peer: &'a str,
    action: &'a str,
    indicator: &'a str,
    change_reason: &'a str,
    mode: &'a str,
    outcome: &'a str,
    source_path: &'static str,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn sanitize_audit_text(value: &str, max: usize) -> String {
    let cleaned: String = value
        .chars()
        .filter(|c| !c.is_control())
        .take(max)
        .collect();
    if cleaned.trim().is_empty() {
        "unknown".to_string()
    } else {
        cleaned
    }
}

/// Appends one SOAR action to the audit trail (JSONL, `O_APPEND`, mode 0600).
#[allow(clippy::too_many_arguments)]
pub fn append_soar_audit(
    audit_path: &Path,
    actor: &str,
    peer: &str,
    action: &str,
    indicator: &str,
    change_reason: &str,
    mode: &str,
    outcome: &str,
) -> Result<(), String> {
    if let Some(parent) = audit_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create audit dir {}: {e}", parent.display()))?;
        }
    }

    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(audit_path)
        .map_err(|e| format!("open audit log {}: {e}", audit_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
    }

    serde_json::to_writer(
        &mut file,
        &SoarAuditRecord {
            timestamp_unix: unix_now(),
            actor: &sanitize_audit_text(actor, 128),
            peer: &sanitize_audit_text(peer, 64),
            action,
            indicator: &sanitize_audit_text(indicator, 512),
            change_reason: &sanitize_audit_text(change_reason, 512),
            mode,
            outcome,
            source_path: "threat-intel-soar",
        },
    )
    .map_err(|e| format!("serialize audit record: {e}"))?;
    file.write_all(b"\n")
        .map_err(|e| format!("write audit log {}: {e}", audit_path.display()))?;
    let _ = file.sync_data();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_matches_only_identical_secrets() {
        assert!(constant_time_eq(b"ti-token", b"ti-token"));
        assert!(!constant_time_eq(b"ti-token", b"ti-tokeN"));
        assert!(!constant_time_eq(b"short", b"much-longer-token"));
    }

    #[test]
    fn extracts_bearer_case_insensitively() {
        let req =
            "POST /api/v1/soar/block HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer s3cret\r\n\r\n{}";
        assert_eq!(extract_bearer(req), Some("s3cret"));

        let lower = "POST / HTTP/1.1\r\nauthorization: bearer s3cret\r\n\r\n";
        assert_eq!(extract_bearer(lower), Some("s3cret"));

        assert_eq!(extract_bearer("POST / HTTP/1.1\r\n\r\n"), None);
        assert_eq!(
            extract_bearer("POST / HTTP/1.1\r\nAuthorization: Basic abc\r\n\r\n"),
            None
        );
        assert_eq!(
            extract_bearer("POST / HTTP/1.1\r\nAuthorization: Bearer   \r\n\r\n"),
            None
        );
    }

    #[test]
    fn token_mismatch_and_missing_token_are_rejected() {
        let sec = AdminApiSecurity::for_test(Some("right"), true, PathBuf::from("/tmp/a.jsonl"));
        assert!(sec.is_authorized_bearer(Some("right")));
        assert!(!sec.is_authorized_bearer(Some("wrong")));
        assert!(!sec.is_authorized_bearer(None));
    }

    #[test]
    fn no_token_is_fail_closed_in_production_posture() {
        let closed = AdminApiSecurity::for_test(None, true, PathBuf::from("/tmp/a.jsonl"));
        assert!(!closed.is_authorized_bearer(None));
        assert!(!closed.is_authorized_bearer(Some("anything")));

        // Explicit lab opt-out only.
        let open = AdminApiSecurity::for_test(None, false, PathBuf::from("/tmp/a.jsonl"));
        assert!(open.is_authorized_bearer(None));
    }

    #[test]
    fn audit_record_is_appended_as_jsonl() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("soar-audit.jsonl");

        append_soar_audit(
            &path,
            "soc1",
            "127.0.0.1:5000",
            "block",
            "evil.test",
            "C2 beacon",
            "shadow",
            "accepted",
        )
        .unwrap();
        append_soar_audit(
            &path,
            "",
            "127.0.0.1:5001",
            "unblock",
            "evil.test",
            "false positive",
            "shadow",
            "denied",
        )
        .unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["actor"], "soc1");
        assert_eq!(first["action"], "block");
        assert_eq!(first["mode"], "shadow");
        assert_eq!(first["outcome"], "accepted");
        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second["actor"], "unknown");
        assert_eq!(second["outcome"], "denied");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "audit log must stay 0600");
        }
    }
}
