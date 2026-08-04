//! Agent OCSP-style status API (lab Phase C).
//!
//! Not a full RFC 6960 binary responder — JSON status queries over
//! fingerprint/serial, backed by enroll registry + agent CRL.
//! Wire-format OCSP DER remains reserved for a later product slice.

use crate::agent_crl::{AgentCrl, CrlEntry};
use crate::device_registry::DeviceRegistry;
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

/// OCSP-like cert status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OcspCertStatus {
    /// Issued and not revoked.
    Good,
    /// Present on the agent CRL.
    Revoked,
    /// Not issued by this control plane / unknown.
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct OcspStatusResponse {
    pub status: OcspCertStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    pub this_update: u64,
    pub next_update: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Honesty: this is a lab JSON status API, not ASN.1 OCSP.
    pub format: &'static str,
}

const NEXT_UPDATE_SECS: u64 = 300;

/// Resolve status from CRL + device registry.
pub fn check_status(
    crl: &AgentCrl,
    devices: &DeviceRegistry,
    fingerprint: Option<&str>,
    serial: Option<&str>,
) -> Result<OcspStatusResponse, String> {
    let fp = fingerprint.map(str::trim).filter(|s| !s.is_empty());
    let ser = serial.map(str::trim).filter(|s| !s.is_empty());
    if fp.is_none() && ser.is_none() {
        return Err("fingerprint or serial query parameter required".into());
    }

    let now = unix_now();
    let next = now + NEXT_UPDATE_SECS;

    // Prefer CRL match (fingerprint first, then serial).
    if let Some(f) = fp {
        if let Some(entry) = crl.entry_by_fingerprint(f) {
            return Ok(revoked_response(Some(f), ser, &entry, now, next));
        }
    }
    if let Some(s) = ser {
        if let Some(entry) = crl.entry_by_serial(s) {
            return Ok(revoked_response(fp, Some(s), &entry, now, next));
        }
    }

    // Good if known issued and not revoked.
    let good = match (fp, ser) {
        (Some(f), _) if devices.cert_fingerprint_valid(f) => true,
        (_, Some(s)) if devices.cert_serial_valid(s) => true,
        _ => false,
    };
    if good {
        return Ok(OcspStatusResponse {
            status: OcspCertStatus::Good,
            fingerprint: fp.map(|s| s.to_ascii_lowercase()),
            serial: ser.map(|s| s.to_ascii_lowercase()),
            device_id: None,
            this_update: now,
            next_update: next,
            revoked_at: None,
            reason: None,
            format: "json-lab-v1",
        });
    }

    // Known but revoked on device registry without CRL entry (legacy) → still revoked.
    let known = match (fp, ser) {
        (Some(f), _) if devices.cert_fingerprint_known(f) => true,
        (_, Some(s)) if devices.cert_serial_known(s) => true,
        _ => false,
    };
    if known {
        // Device marked revoked in registry but maybe no cert was on CRL (no fingerprint).
        return Ok(OcspStatusResponse {
            status: OcspCertStatus::Revoked,
            fingerprint: fp.map(|s| s.to_ascii_lowercase()),
            serial: ser.map(|s| s.to_ascii_lowercase()),
            device_id: None,
            this_update: now,
            next_update: next,
            revoked_at: Some(now),
            reason: Some("device-revoked".into()),
            format: "json-lab-v1",
        });
    }

    Ok(OcspStatusResponse {
        status: OcspCertStatus::Unknown,
        fingerprint: fp.map(|s| s.to_ascii_lowercase()),
        serial: ser.map(|s| s.to_ascii_lowercase()),
        device_id: None,
        this_update: now,
        next_update: next,
        revoked_at: None,
        reason: None,
        format: "json-lab-v1",
    })
}

fn revoked_response(
    fp: Option<&str>,
    ser: Option<&str>,
    entry: &CrlEntry,
    now: u64,
    next: u64,
) -> OcspStatusResponse {
    OcspStatusResponse {
        status: OcspCertStatus::Revoked,
        fingerprint: Some(entry.fingerprint.clone()).or_else(|| fp.map(|s| s.to_ascii_lowercase())),
        serial: entry
            .serial_hex
            .clone()
            .or_else(|| ser.map(|s| s.to_ascii_lowercase())),
        device_id: Some(entry.device_id.clone()),
        this_update: now,
        next_update: next,
        revoked_at: Some(entry.revoked_at),
        reason: Some(entry.reason.clone()),
        format: "json-lab-v1",
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_registry::{DeviceRegistry, EnrollRequest};

    #[test]
    fn status_good_revoked_unknown() {
        let reg = DeviceRegistry::memory_only();
        let crl = AgentCrl::memory_only();
        let enroll = reg
            .enroll(EnrollRequest {
                device_id: Some("d1".into()),
                platform: "linux".into(),
                name: None,
                user_identity: None,
                capabilities: vec![],
                device_type: None,
                cert_subject: Some("CN=d1".into()),
                cert_fingerprint: Some("aabbcc".into()),
                cert_serial: Some("0f0f".into()),
            })
            .unwrap();
        assert_eq!(enroll.device_id, "d1");

        let good = check_status(&crl, &reg, Some("AABBCC"), None).unwrap();
        assert_eq!(good.status, OcspCertStatus::Good);

        crl.revoke("d1", Some("aabbcc"), Some("0f0f"), "cessation");
        let rev = check_status(&crl, &reg, Some("aabbcc"), None).unwrap();
        assert_eq!(rev.status, OcspCertStatus::Revoked);
        assert_eq!(rev.reason.as_deref(), Some("cessation"));

        let unk = check_status(&crl, &reg, Some("deadbeef"), None).unwrap();
        assert_eq!(unk.status, OcspCertStatus::Unknown);

        let by_serial = check_status(&crl, &reg, None, Some("0F0F")).unwrap();
        assert_eq!(by_serial.status, OcspCertStatus::Revoked);
    }
}
