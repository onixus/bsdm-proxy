//! Proxy Auto-Configuration (PAC) Script Generator
//! Generates JavaScript FindProxyForURL(url, host) routines from the local RouteTable.
//! Includes strict escaping to protect against PAC JavaScript injection.

use crate::router::{RouteTable, RouteTarget};

/// Generate a compliant Proxy Auto-Configuration (PAC) script from a RouteTable
pub fn generate_pac(
    routes: &RouteTable,
    proxy_authority: &str,
    socks_authority: Option<&str>,
) -> String {
    let clean_proxy_auth = sanitize_authority(proxy_authority);
    let clean_socks_auth = socks_authority.map(sanitize_authority);

    let mut js = String::with_capacity(2048);
    js.push_str("// BSDM Auto-Generated Proxy Auto-Configuration (PAC) File\n");
    js.push_str("// Generated dynamically by BSDM Agent / BSDM Connect\n\n");
    js.push_str("function FindProxyForURL(url, host) {\n");
    js.push_str("    host = host.toLowerCase();\n\n");

    // Standard bypass for plain local hostnames
    js.push_str("    // 1. Localhost and private LAN default bypass\n");
    js.push_str("    if (isPlainHostName(host) || host === 'localhost' || host === '127.0.0.1' || host === '::1') {\n");
    js.push_str("        return 'DIRECT';\n");
    js.push_str("    }\n\n");

    let proxy_ret = format!("PROXY {clean_proxy_auth}; DIRECT");
    let socks_ret = clean_socks_auth
        .as_ref()
        .map(|s| format!("SOCKS5 {s}; SOCKS {s}; DIRECT"))
        .unwrap_or_else(|| proxy_ret.clone());
    let block_ret = "PROXY 127.0.0.1:0";

    js.push_str("    // 2. Custom Domain Routing Rules\n");
    for rule in &routes.rules {
        if !rule.enabled {
            continue;
        }

        let ret_val = match rule.target {
            RouteTarget::Direct => "DIRECT",
            RouteTarget::Proxy => &proxy_ret,
            RouteTarget::Tunnel => &socks_ret,
            RouteTarget::Block => block_ret,
        };

        if let Some(comment) = &rule.comment {
            js.push_str(&format!("    // Rule: {}\n", sanitize_comment(comment)));
        }

        let mut conditions = Vec::new();
        for single_pat in rule.pattern.split(&[';', ','][..]) {
            let pat = single_pat.trim();
            if pat.is_empty() {
                continue;
            }

            if pat.contains('/') {
                // CIDR block (e.g. 10.0.0.0/8)
                if let Some((ip, mask_len_str)) = pat.split_once('/') {
                    if let Ok(mask_len) = mask_len_str.parse::<u8>() {
                        let clean_ip = escape_js_string(ip.trim());
                        let mask_ip = cidr_to_mask(mask_len);
                        conditions.push(format!("isInNet(host, '{clean_ip}', '{mask_ip}')"));
                        continue;
                    }
                }
            }

            if let Some(suffix) = pat.strip_prefix("*.") {
                let clean_suffix = escape_js_string(suffix);
                conditions.push(format!(
                    "dnsDomainIs(host, '.{clean_suffix}') || host === '{clean_suffix}'"
                ));
            } else if let Some(suffix) = pat.strip_prefix('.') {
                let clean_suffix = escape_js_string(suffix);
                conditions.push(format!(
                    "dnsDomainIs(host, '.{clean_suffix}') || host === '{clean_suffix}'"
                ));
            } else if pat.contains('*') {
                let clean_pat = escape_js_string(pat);
                conditions.push(format!("shExpMatch(host, '{clean_pat}')"));
            } else {
                let clean_pat = escape_js_string(pat);
                conditions.push(format!("host === '{clean_pat}'"));
            }
        }

        if !conditions.is_empty() {
            let cond_str = conditions.join(" || ");
            let clean_ret_val = escape_js_string(ret_val);
            js.push_str(&format!("    if ({cond_str}) {{\n"));
            js.push_str(&format!("        return '{clean_ret_val}';\n"));
            js.push_str("    }\n\n");
        }
    }

    let default_ret = match routes.default_target {
        RouteTarget::Direct => "DIRECT",
        RouteTarget::Proxy => &proxy_ret,
        RouteTarget::Tunnel => &socks_ret,
        RouteTarget::Block => block_ret,
    };
    let clean_default_ret = escape_js_string(default_ret);

    js.push_str("    // 3. Default Fallback Routing\n");
    js.push_str(&format!("    return '{clean_default_ret}';\n"));
    js.push_str("}\n");

    js
}

/// Escape JavaScript string literal characters (prevent PAC injection)
pub fn escape_js_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '\"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\0' => out.push_str(""),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

/// Sanitize single-line comment by removing newlines and comment breaks
fn sanitize_comment(s: &str) -> String {
    s.replace(['\n', '\r'], " ")
        .replace("*/", "* /")
        .trim()
        .to_string()
}

/// Sanitize authority string (host:port) to strictly allowed characters
fn sanitize_authority(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_alphanumeric() || *c == '.' || *c == ':' || *c == '-' || *c == '_')
        .collect()
}

fn cidr_to_mask(bits: u8) -> String {
    let mask: u32 = if bits == 0 {
        0
    } else {
        !((1 << (32 - bits.min(32))) - 1)
    };
    format!(
        "{}.{}.{}.{}",
        (mask >> 24) & 0xFF,
        (mask >> 16) & 0xFF,
        (mask >> 8) & 0xFF,
        mask & 0xFF
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::router::RouteRule;

    #[test]
    fn test_generate_pac_structure() {
        let table = RouteTable::default_corporate();
        let pac = generate_pac(&table, "127.0.0.1:3128", Some("127.0.0.1:1080"));

        assert!(pac.contains("function FindProxyForURL(url, host)"));
        assert!(pac.contains("isPlainHostName(host)"));
        assert!(pac.contains("PROXY 127.0.0.1:3128; DIRECT"));
        assert!(pac.contains("SOCKS5 127.0.0.1:1080; SOCKS 127.0.0.1:1080; DIRECT"));
        assert!(pac.contains("dnsDomainIs(host, '.corp')"));
        assert!(pac.contains("isInNet(host, '10.0.0.0', '255.0.0.0')"));
        assert!(pac.contains("return 'DIRECT';"));
    }

    #[test]
    fn test_pac_injection_escaped() {
        let mut table = RouteTable::default_corporate();
        let _ = table.upsert_rule(RouteRule {
            id: "inj-rule".to_string(),
            pattern: "*.malicious.com'; alert(1); var x='".to_string(),
            target: RouteTarget::Proxy,
            enabled: true,
            comment: Some("Test /* comment \n newline */ breakout".to_string()),
        });

        let pac = generate_pac(&table, "127.0.0.1:3128", None);
        assert!(!pac.contains("alert(1); var x="));
        assert!(pac.contains("\\'"));
        assert!(!pac.contains("\n newline */ breakout"));
    }
}
