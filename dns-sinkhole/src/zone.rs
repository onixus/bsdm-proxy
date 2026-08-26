//! RPZ-lite / plain domain blocklist loader.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

/// Why a zone could not be loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZoneError {
    /// The file is observe-only threat-intel output, not a zone to enforce.
    ShadowArtifact(String),
    /// Unreadable file or malformed content.
    Invalid(String),
}

impl std::fmt::Display for ZoneError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ShadowArtifact(m) | Self::Invalid(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for ZoneError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZoneAction {
    /// Use global sinkhole / NXDOMAIN policy.
    Policy,
    /// Explicit A from zone file.
    A(Ipv4Addr),
    /// Explicit AAAA from zone file.
    Aaaa(Ipv6Addr),
}

#[derive(Debug, Default, Clone)]
pub struct Zone {
    /// Exact FQDN (lowercase, no trailing dot) → action.
    exact: HashMap<String, ZoneAction>,
    /// Suffix match: hostname ends with `.{suffix}` or equals suffix.
    suffixes: Vec<(String, ZoneAction)>,
}

impl Zone {
    pub fn load_path(path: &Path) -> Result<Self, ZoneError> {
        // The collector writes observe-only artifacts under a `.shadow` suffix.
        // Refuse them by name as well as by marker: a copy that kept the suffix
        // is still an artifact nobody signed off for enforcement (ADR 0008).
        if path
            .as_os_str()
            .to_string_lossy()
            .ends_with(SHADOW_ARTIFACT_SUFFIX)
        {
            return Err(ZoneError::ShadowArtifact(format!(
                "refusing to load {}: a '{SHADOW_ARTIFACT_SUFFIX}' artifact is observe-only \
                 threat-intel output, not a zone. Enforcement requires \
                 TI_ENFORCEMENT_MODE=enforce on the collector",
                path.display()
            )));
        }
        let text = std::fs::read_to_string(path)
            .map_err(|e| ZoneError::Invalid(format!("read zone: {e}")))?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, ZoneError> {
        let mut zone = Self::default();
        for (lineno, raw) in text.lines().enumerate() {
            let cleaned = strip_comment(raw);
            let line = cleaned.trim();
            if line.is_empty() {
                continue;
            }
            if line.starts_with('$') {
                // $TTL etc. — ignore for PoC
                continue;
            }
            if is_shadow_marker(line) {
                return Err(ZoneError::ShadowArtifact(format!(
                    "zone line {}: this zone is marked '{SHADOW_MARKER_NAME} TXT \"shadow\"' — \
                     it is an observe-only threat-intel artifact and must not be enforced. \
                     Set TI_ENFORCEMENT_MODE=enforce on the collector to produce a real zone",
                    lineno + 1
                )));
            }
            parse_line(&mut zone, line)
                .map_err(|e| ZoneError::Invalid(format!("zone line {}: {e}", lineno + 1)))?;
        }
        Ok(zone)
    }

    pub fn lookup(&self, qname: &str) -> Option<&ZoneAction> {
        let name = normalize_name(qname);
        if let Some(a) = self.exact.get(&name) {
            return Some(a);
        }
        for (suf, action) in &self.suffixes {
            if name == *suf || name.ends_with(&format!(".{suf}")) {
                return Some(action);
            }
        }
        None
    }

    pub fn len(&self) -> usize {
        self.exact.len() + self.suffixes.len()
    }
}

/// Owner name that `threat-intel` writes into an observe-only zone.
///
/// Kept in sync with `threat_intel::rpz::SHADOW_MARKER_NAME`; the two crates do
/// not depend on each other, so the constant is duplicated rather than shared.
const SHADOW_MARKER_NAME: &str = "_bsdm-enforcement-mode";

/// Filename suffix of the collector's observe-only artifacts.
const SHADOW_ARTIFACT_SUFFIX: &str = ".shadow";

/// True for the marker record that makes a zone unloadable.
///
/// Matched on the owner name alone: whatever the mode says, a zone that carries
/// the record at all is collector output that no operator promoted.
fn is_shadow_marker(line: &str) -> bool {
    line.split_whitespace().next().is_some_and(|owner| {
        owner
            .trim_end_matches('.')
            .eq_ignore_ascii_case(SHADOW_MARKER_NAME)
    })
}

fn strip_comment(line: &str) -> String {
    let mut out = String::new();
    let mut in_quote = false;
    for ch in line.chars() {
        if ch == '"' {
            in_quote = !in_quote;
        }
        if !in_quote && (ch == ';' || ch == '#') {
            break;
        }
        out.push(ch);
    }
    out
}

fn normalize_name(name: &str) -> String {
    let n = name.trim().trim_end_matches('.').to_ascii_lowercase();
    n
}

fn parse_line(zone: &mut Zone, line: &str) -> Result<(), String> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() {
        return Ok(());
    }

    // Plain list: single token (optional leading '.' for suffix)
    if parts.len() == 1 {
        let tok = parts[0];
        if let Some(suf) = tok.strip_prefix('.') {
            zone.suffixes
                .push((normalize_name(suf), ZoneAction::Policy));
        } else {
            zone.exact.insert(normalize_name(tok), ZoneAction::Policy);
        }
        return Ok(());
    }

    // RPZ-lite: name [TTL] type rdata...
    let name_raw = parts[0];
    let mut idx = 1;
    // skip optional TTL
    if parts
        .get(idx)
        .is_some_and(|p| p.chars().all(|c| c.is_ascii_digit()))
    {
        idx += 1;
    }
    // skip optional class IN
    if parts.get(idx).is_some_and(|p| p.eq_ignore_ascii_case("IN")) {
        idx += 1;
    }
    let rtype = parts
        .get(idx)
        .ok_or_else(|| "missing RR type".to_string())?
        .to_ascii_uppercase();
    idx += 1;
    let rdata = parts.get(idx..).unwrap_or(&[]).join(" ");

    let (is_suffix, name) = if let Some(s) = name_raw.strip_prefix("*.") {
        (true, normalize_name(s))
    } else {
        (false, normalize_name(name_raw))
    };

    let action = match rtype.as_str() {
        "CNAME" => {
            // CNAME .  → policy block
            ZoneAction::Policy
        }
        "A" => {
            let ip: Ipv4Addr = rdata.parse().map_err(|e| format!("A rdata: {e}"))?;
            ZoneAction::A(ip)
        }
        "AAAA" => {
            let ip: Ipv6Addr = rdata.parse().map_err(|e| format!("AAAA rdata: {e}"))?;
            ZoneAction::Aaaa(ip)
        }
        other => return Err(format!("unsupported RR type {other}")),
    };

    if is_suffix {
        zone.suffixes.push((name, action));
    } else {
        zone.exact.insert(name, action);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_shadow_marked_zone_is_refused() {
        // Exactly what threat-intel writes in shadow mode: the human-readable
        // banner is a comment, the TXT record is the enforceable half.
        let err = Zone::parse(
            r#"
$TTL 300
; SHADOW MODE (TI_ENFORCEMENT_MODE=shadow): observe-only artifact.
_bsdm-enforcement-mode IN TXT "shadow"
phish.test. CNAME .
"#,
        )
        .unwrap_err();
        assert!(
            matches!(err, ZoneError::ShadowArtifact(_)),
            "shadow-marked zone must be refused, got {err:?}"
        );
    }

    #[test]
    fn a_shadow_suffixed_path_is_refused_before_it_is_read() {
        // The file does not even exist: the suffix alone must stop the load,
        // otherwise a copy that kept the name would be enforced.
        let err = Zone::load_path(Path::new("/nonexistent/threats.rpz.shadow")).unwrap_err();
        assert!(
            matches!(err, ZoneError::ShadowArtifact(_)),
            "a .shadow path must be refused by name, got {err:?}"
        );
    }

    #[test]
    fn an_enforce_zone_without_the_marker_still_loads() {
        let z = Zone::parse("$TTL 300\nphish.test. CNAME .\n").unwrap();
        assert!(matches!(z.lookup("phish.test"), Some(ZoneAction::Policy)));
    }

    #[test]
    fn parses_plain_and_rpz() {
        let z = Zone::parse(
            r#"
; comment
blocked.test. CNAME .
*.evil.example. CNAME .
fixed.test. A 10.0.0.1
malware.example
.blocked.suffix
"#,
        )
        .unwrap();
        assert!(matches!(z.lookup("blocked.test"), Some(ZoneAction::Policy)));
        assert!(matches!(
            z.lookup("a.evil.example"),
            Some(ZoneAction::Policy)
        ));
        assert!(matches!(
            z.lookup("fixed.test"),
            Some(ZoneAction::A(ip)) if *ip == Ipv4Addr::new(10, 0, 0, 1)
        ));
        assert!(matches!(
            z.lookup("malware.example"),
            Some(ZoneAction::Policy)
        ));
        assert!(matches!(
            z.lookup("x.blocked.suffix"),
            Some(ZoneAction::Policy)
        ));
        assert!(z.lookup("clean.example").is_none());
    }
}
