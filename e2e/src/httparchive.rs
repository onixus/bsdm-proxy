//! HTTP Archive Top 1k median page profile (shared with scripts/httparchive-top1k-profile.json).

use anyhow::{bail, Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct HttpArchiveProfile {
    pub schema_version: u32,
    pub lens: String,
    pub devices: std::collections::HashMap<String, DeviceProfile>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DeviceProfile {
    pub total_bytes: u64,
    pub total_requests: u32,
    pub resource_types: Vec<ResourceTypeGroup>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ResourceTypeGroup {
    #[serde(rename = "type")]
    pub resource_type: String,
    pub requests: u32,
    pub bytes: u64,
    pub mime: String,
    pub extension: String,
}

#[derive(Debug, Clone)]
pub struct HttpArchiveResource {
    pub resource_id: String,
    pub resource_type: String,
    pub size_bytes: usize,
    pub mime: String,
    pub path: String,
}

pub fn profile_path() -> std::path::PathBuf {
    std::env::var("HTTPARCHIVE_PROFILE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| crate::workspace_path("scripts/httparchive-top1k-profile.json"))
}

pub fn load_profile() -> Result<HttpArchiveProfile> {
    let path = profile_path();
    let raw = std::fs::read_to_string(&path).with_context(|| format!("read {path:?}"))?;
    let profile: HttpArchiveProfile =
        serde_json::from_str(&raw).context("parse httparchive profile json")?;
    validate_profile(&profile)?;
    Ok(profile)
}

fn split_bytes(total: u64, count: u32) -> Vec<u64> {
    if count == 0 {
        return Vec::new();
    }
    let base = total / u64::from(count);
    let rem = (total % u64::from(count)) as u32;
    (0..count)
        .map(|i| base + u64::from(u32::from(i < rem)))
        .collect()
}

pub fn expand_device(
    profile: &HttpArchiveProfile,
    device: &str,
) -> Result<Vec<HttpArchiveResource>> {
    let dev = profile
        .devices
        .get(device)
        .with_context(|| format!("unknown device {device:?}"))?;
    let mut resources = Vec::new();
    let mut seq = 0u32;
    for group in &dev.resource_types {
        let sizes = split_bytes(group.bytes, group.requests);
        for (idx, size) in sizes.into_iter().enumerate() {
            let rid = format!("{}-{:02}", group.resource_type, idx);
            let path = format!("/httparchive/{device}/{seq:03}-{rid}.{}", group.extension);
            resources.push(HttpArchiveResource {
                resource_id: rid,
                resource_type: group.resource_type.clone(),
                size_bytes: size as usize,
                mime: group.mime.clone(),
                path,
            });
            seq += 1;
        }
    }
    Ok(resources)
}

pub fn validate_profile(profile: &HttpArchiveProfile) -> Result<()> {
    if profile.schema_version != 1 {
        bail!(
            "unsupported httparchive profile schema {}",
            profile.schema_version
        );
    }
    if profile.lens != "top1k" {
        bail!("expected top1k lens, got {}", profile.lens);
    }
    for (device, dev) in &profile.devices {
        let resources = expand_device(profile, device)?;
        let bytes: u64 = resources.iter().map(|r| r.size_bytes as u64).sum();
        let count = resources.len() as u32;
        if count != dev.total_requests {
            bail!(
                "{device}: expanded {count} resources, expected {}",
                dev.total_requests
            );
        }
        if bytes != dev.total_bytes {
            bail!(
                "{device}: expanded {bytes} bytes, expected {}",
                dev.total_bytes
            );
        }
    }
    Ok(())
}

pub fn body_for(resource: &HttpArchiveResource) -> Vec<u8> {
    let prefix = format!("ha:{}:{}:", resource.resource_type, resource.size_bytes);
    let mut body = prefix.into_bytes();
    if body.len() < resource.size_bytes {
        body.resize(resource.size_bytes, 0);
    } else {
        body.truncate(resource.size_bytes);
    }
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_matches_httparchive_medians() {
        let profile = load_profile().expect("load profile");
        let desktop = expand_device(&profile, "desktop").expect("desktop");
        assert_eq!(desktop.len(), 71);
        assert_eq!(
            desktop.iter().map(|r| r.size_bytes).sum::<usize>(),
            2_713_088
        );
        let mobile = expand_device(&profile, "mobile").expect("mobile");
        assert_eq!(mobile.len(), 66);
        assert_eq!(
            mobile.iter().map(|r| r.size_bytes).sum::<usize>(),
            2_366_464
        );
    }
}
