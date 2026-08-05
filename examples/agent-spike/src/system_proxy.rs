//! OS system-proxy helpers for the local policy agent (lab / pilot install path).
//!
//! Applies HTTP(S) proxy settings so browser/OS traffic can be steered toward
//! the BSDM data-plane (`HTTP_PORT`, default 3128). This is **not** MDM-grade
//! product packaging — installers wrap these hooks with clear privilege notes.

use std::process::Command;

/// Forward-proxy endpoint the OS should use.
#[derive(Debug, Clone)]
pub struct ProxyEndpoint {
    pub host: String,
    pub port: u16,
    /// Host patterns that must bypass the proxy (CIDR/host globs as OS allows).
    pub bypass: Vec<String>,
}

impl ProxyEndpoint {
    pub fn from_env() -> Self {
        let host = std::env::var("SYSTEM_PROXY_HOST")
            .or_else(|_| std::env::var("DATA_PLANE_PROXY_HOST"))
            .unwrap_or_else(|_| "127.0.0.1".into());
        let port = std::env::var("SYSTEM_PROXY_PORT")
            .or_else(|_| std::env::var("DATA_PLANE_PROXY_PORT"))
            .ok()
            .and_then(|s| s.parse().ok())
            .or_else(|| std::env::var("HTTP_PORT").ok().and_then(|s| s.parse().ok()))
            .unwrap_or(3128);
        let bypass = std::env::var("SYSTEM_PROXY_BYPASS")
            .ok()
            .map(|s| {
                s.split(',')
                    .map(str::trim)
                    .filter(|p| !p.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .filter(|v: &Vec<String>| !v.is_empty())
            .unwrap_or_else(default_bypass);
        Self { host, port, bypass }
    }

    pub fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

fn default_bypass() -> Vec<String> {
    vec![
        "localhost".into(),
        "127.0.0.1".into(),
        "::1".into(),
        "*.local".into(),
    ]
}

/// Current host platform tag (`linux` | `macos` | `windows` | other).
pub fn platform_tag() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "other"
    }
}

/// Apply OS system HTTP(S) proxy settings.
pub fn set_system_proxy(ep: &ProxyEndpoint, dry_run: bool) -> Result<String, String> {
    if dry_run {
        return Ok(format!(
            "dry-run: would set system proxy {} on {}",
            ep.authority(),
            platform_tag()
        ));
    }
    #[cfg(target_os = "macos")]
    {
        return set_macos(ep);
    }
    #[cfg(target_os = "linux")]
    {
        return set_linux(ep);
    }
    #[cfg(target_os = "windows")]
    {
        return set_windows(ep);
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = ep;
        Err(format!(
            "system proxy not implemented on platform {}",
            platform_tag()
        ))
    }
}

/// Clear OS system HTTP(S) proxy settings.
pub fn clear_system_proxy(dry_run: bool) -> Result<String, String> {
    if dry_run {
        return Ok(format!(
            "dry-run: would clear system proxy on {}",
            platform_tag()
        ));
    }
    #[cfg(target_os = "macos")]
    {
        return clear_macos();
    }
    #[cfg(target_os = "linux")]
    {
        return clear_linux();
    }
    #[cfg(target_os = "windows")]
    {
        return clear_windows();
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Err(format!(
            "system proxy not implemented on platform {}",
            platform_tag()
        ))
    }
}

fn run(cmd: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| format!("exec {cmd}: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        return Err(format!(
            "{cmd} {:?} failed ({}): {} {}",
            args,
            out.status,
            stdout.trim(),
            stderr.trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

// --- macOS -----------------------------------------------------------------

#[cfg(target_os = "macos")]
fn macos_services() -> Result<Vec<String>, String> {
    let raw = run("networksetup", &["-listallnetworkservices"])?;
    Ok(raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("An asterisk"))
        .filter(|l| !l.starts_with('*')) // disabled services are prefixed with *
        .map(str::to_string)
        .collect())
}

#[cfg(target_os = "macos")]
fn set_macos(ep: &ProxyEndpoint) -> Result<String, String> {
    let services = macos_services()?;
    if services.is_empty() {
        return Err("no network services found (networksetup)".into());
    }
    let bypass = ep.bypass.join(",");
    let mut applied = Vec::new();
    for svc in &services {
        // Prefer common interfaces; still try all enabled services.
        let _ = run(
            "networksetup",
            &["-setwebproxy", svc, &ep.host, &ep.port.to_string()],
        );
        let _ = run(
            "networksetup",
            &["-setsecurewebproxy", svc, &ep.host, &ep.port.to_string()],
        );
        let _ = run("networksetup", &["-setwebproxystate", svc, "on"]);
        let _ = run("networksetup", &["-setsecurewebproxystate", svc, "on"]);
        if !bypass.is_empty() {
            let _ = run("networksetup", &["-setproxybypassdomains", svc, &bypass]);
        }
        applied.push(svc.clone());
    }
    Ok(format!(
        "macOS system proxy set to {} on services: {}",
        ep.authority(),
        applied.join(", ")
    ))
}

#[cfg(target_os = "macos")]
fn clear_macos() -> Result<String, String> {
    let services = macos_services()?;
    for svc in &services {
        let _ = run("networksetup", &["-setwebproxystate", svc, "off"]);
        let _ = run("networksetup", &["-setsecurewebproxystate", svc, "off"]);
    }
    Ok(format!(
        "macOS system proxy disabled on {} service(s)",
        services.len()
    ))
}

// --- Linux -----------------------------------------------------------------

#[cfg(target_os = "linux")]
fn set_linux(ep: &ProxyEndpoint) -> Result<String, String> {
    let mut notes = Vec::new();
    let mode = std::env::var("SYSTEM_PROXY_LINUX_MODE")
        .unwrap_or_else(|_| "user".into())
        .to_ascii_lowercase();

    // GNOME session (user).
    if mode == "user" || mode == "all" || mode == "gsettings" {
        if Command::new("gsettings").arg("--version").output().is_ok() {
            let _ = run(
                "gsettings",
                &["set", "org.gnome.system.proxy", "mode", "'manual'"],
            );
            let _ = run(
                "gsettings",
                &[
                    "set",
                    "org.gnome.system.proxy.http",
                    "host",
                    &format!("'{}'", ep.host),
                ],
            );
            let _ = run(
                "gsettings",
                &[
                    "set",
                    "org.gnome.system.proxy.http",
                    "port",
                    &ep.port.to_string(),
                ],
            );
            let _ = run(
                "gsettings",
                &[
                    "set",
                    "org.gnome.system.proxy.https",
                    "host",
                    &format!("'{}'", ep.host),
                ],
            );
            let _ = run(
                "gsettings",
                &[
                    "set",
                    "org.gnome.system.proxy.https",
                    "port",
                    &ep.port.to_string(),
                ],
            );
            let ignore: String = ep
                .bypass
                .iter()
                .map(|b| format!("'{b}'"))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = run(
                "gsettings",
                &[
                    "set",
                    "org.gnome.system.proxy",
                    "ignore-hosts",
                    &format!("[{ignore}]"),
                ],
            );
            notes.push("gsettings (GNOME)".into());
        } else {
            notes.push("gsettings unavailable".into());
        }
    }

    // Always write a user-level env snippet agents/shells can source.
    let home = std::env::var("HOME").map_err(|_| "HOME unset".to_string())?;
    let dir = std::path::PathBuf::from(&home).join(".config/bsdm-agent");
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    let env_path = dir.join("proxy.env");
    let body = format!(
        "# Generated by bsdm-agent system-proxy\nexport http_proxy=http://{a}\nexport https_proxy=http://{a}\nexport HTTP_PROXY=http://{a}\nexport HTTPS_PROXY=http://{a}\nexport no_proxy={bp}\nexport NO_PROXY={bp}\n",
        a = ep.authority(),
        bp = ep.bypass.join(",")
    );
    std::fs::write(&env_path, body).map_err(|e| format!("write {}: {e}", env_path.display()))?;
    notes.push(format!("wrote {}", env_path.display()));

    // Optional system-wide profile.d (requires root).
    if mode == "system" || mode == "all" {
        let sys = std::path::Path::new("/etc/profile.d/bsdm-agent-proxy.sh");
        let body = format!(
            "# Generated by bsdm-agent system-proxy\nexport http_proxy=http://{a}\nexport https_proxy=http://{a}\nexport HTTP_PROXY=http://{a}\nexport HTTPS_PROXY=http://{a}\nexport no_proxy={bp}\nexport NO_PROXY={bp}\n",
            a = ep.authority(),
            bp = ep.bypass.join(",")
        );
        match std::fs::write(sys, body) {
            Ok(()) => notes.push(format!("wrote {}", sys.display())),
            Err(e) => notes.push(format!(
                "skip system profile ({}): run installer as root for SYSTEM_PROXY_LINUX_MODE=system",
                e
            )),
        }
    }

    Ok(format!(
        "Linux system proxy → {} ({})",
        ep.authority(),
        notes.join("; ")
    ))
}

#[cfg(target_os = "linux")]
fn clear_linux() -> Result<String, String> {
    let mut notes = Vec::new();
    if Command::new("gsettings").arg("--version").output().is_ok() {
        let _ = run(
            "gsettings",
            &["set", "org.gnome.system.proxy", "mode", "'none'"],
        );
        notes.push("gsettings mode=none".into());
    }
    if let Ok(home) = std::env::var("HOME") {
        let env_path = std::path::PathBuf::from(home).join(".config/bsdm-agent/proxy.env");
        if env_path.exists() {
            let _ = std::fs::remove_file(&env_path);
            notes.push(format!("removed {}", env_path.display()));
        }
    }
    let sys = std::path::Path::new("/etc/profile.d/bsdm-agent-proxy.sh");
    if sys.exists() {
        match std::fs::remove_file(sys) {
            Ok(()) => notes.push(format!("removed {}", sys.display())),
            Err(e) => notes.push(format!("could not remove {}: {e}", sys.display())),
        }
    }
    Ok(format!("Linux system proxy cleared ({})", notes.join("; ")))
}

// --- Windows ---------------------------------------------------------------

#[cfg(target_os = "windows")]
fn set_windows(ep: &ProxyEndpoint) -> Result<String, String> {
    let server = ep.authority();
    let bypass = ep.bypass.join(";");
    // WinINET user proxy (browsers / many apps).
    let ps = format!(
        "$p='HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'; \
         Set-ItemProperty -Path $p -Name ProxyEnable -Value 1; \
         Set-ItemProperty -Path $p -Name ProxyServer -Value '{server}'; \
         Set-ItemProperty -Path $p -Name ProxyOverride -Value '{bypass}'"
    );
    run("powershell", &["-NoProfile", "-Command", &ps])?;
    // WinHTTP (system services) — best-effort.
    let _ = run(
        "netsh",
        &[
            "winhttp",
            "set",
            "proxy",
            &server,
            &format!("bypass-list={bypass}"),
        ],
    );
    Ok(format!("Windows system proxy set to {server}"))
}

#[cfg(target_os = "windows")]
fn clear_windows() -> Result<String, String> {
    let ps = "$p='HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'; \
              Set-ItemProperty -Path $p -Name ProxyEnable -Value 0";
    run("powershell", &["-NoProfile", "-Command", ps])?;
    let _ = run("netsh", &["winhttp", "reset", "proxy"]);
    Ok("Windows system proxy cleared".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_authority_and_defaults() {
        let ep = ProxyEndpoint {
            host: "10.0.0.5".into(),
            port: 3128,
            bypass: default_bypass(),
        };
        assert_eq!(ep.authority(), "10.0.0.5:3128");
        assert!(ep.bypass.iter().any(|b| b == "localhost"));
    }

    #[test]
    fn dry_run_does_not_touch_os() {
        let ep = ProxyEndpoint::from_env();
        let msg = set_system_proxy(&ep, true).unwrap();
        assert!(msg.contains("dry-run"));
        let msg = clear_system_proxy(true).unwrap();
        assert!(msg.contains("dry-run"));
    }
}
