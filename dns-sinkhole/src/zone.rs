//! RPZ-lite / plain domain blocklist loader.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

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
    pub fn load_path(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("read zone: {e}"))?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, String> {
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
            parse_line(&mut zone, line).map_err(|e| format!("zone line {}: {e}", lineno + 1))?;
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
