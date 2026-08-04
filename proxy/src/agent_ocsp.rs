//! Agent OCSP: lab JSON status + RFC 6960 DER responder (Phase C).
//!
//! - `GET /api/v1/agent/ocsp/status` — JSON (`json-lab-v1`) by fingerprint/serial.
//! - `POST /api/v1/agent/ocsp` — `application/ocsp-request` →
//!   `application/ocsp-response` DER, CA-signed (RSA or ECDSA P-256).
//! - Optional `GET /api/v1/agent/ocsp?b64=` for base64-encoded requests.
//!
//! Backed by enroll registry + agent CRL. Stapling / multi-responder is out of
//! scope; this is a product control-plane responder for agent client certs.

use crate::agent_crl::{AgentCrl, CrlEntry};
use crate::device_registry::DeviceRegistry;
use crate::tls::CertCache;
use der::asn1::{BitString, Null, ObjectIdentifier, OctetString};
use der::{DateTime, Decode, Encode};
use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, RsaKeyPair};
use serde::Serialize;
use sha2::{Digest, Sha256};
use spki::AlgorithmIdentifierOwned;
use std::time::{SystemTime, UNIX_EPOCH};
use x509_cert::certificate::Certificate;
use x509_cert::ext::pkix::CrlReason;
use x509_ocsp::{
    BasicOcspResponse, CertId, CertStatus, OcspGeneralizedTime, OcspRequest, OcspResponse,
    OcspResponseStatus, ResponderId, ResponseData, RevokedInfo, SingleResponse, Version,
};

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

fn unix_to_ocsp_time(secs: u64) -> Result<OcspGeneralizedTime, String> {
    let dt = DateTime::from_unix_duration(std::time::Duration::from_secs(secs))
        .map_err(|e| format!("ocsp time: {e}"))?;
    Ok(OcspGeneralizedTime::from(dt))
}

fn serial_to_hex(serial: &x509_cert::serial_number::SerialNumber) -> String {
    hex::encode(serial.as_bytes())
}

fn cert_status_from_lab(status: &OcspStatusResponse) -> Result<CertStatus, String> {
    match status.status {
        OcspCertStatus::Good => Ok(CertStatus::good()),
        OcspCertStatus::Unknown => Ok(CertStatus::unknown()),
        OcspCertStatus::Revoked => {
            let when = status.revoked_at.unwrap_or(status.this_update);
            let revocation_time = unix_to_ocsp_time(when)?;
            // Map free-form reasons onto standard CRLReason when obvious.
            let reason = match status.reason.as_deref() {
                Some("keyCompromise") | Some("key_compromise") => Some(CrlReason::KeyCompromise),
                Some("cACompromise") => Some(CrlReason::CaCompromise),
                Some("affiliationChanged") => Some(CrlReason::AffiliationChanged),
                Some("superseded") => Some(CrlReason::Superseded),
                Some("cessationOfOperation") | Some("cessation") => {
                    Some(CrlReason::CessationOfOperation)
                }
                Some("certificateHold") => Some(CrlReason::CertificateHold),
                Some("privilegeWithdrawn") => Some(CrlReason::PrivilegeWithdrawn),
                Some("aACompromise") => Some(CrlReason::AaCompromise),
                _ => Some(CrlReason::CessationOfOperation),
            };
            Ok(CertStatus::revoked(RevokedInfo {
                revocation_time,
                revocation_reason: reason,
            }))
        }
    }
}

/// Build a CA-signed RFC 6960 `OCSPResponse` DER for an agent client cert request.
pub fn respond_der(
    request_der: &[u8],
    cert_cache: &CertCache,
    crl: &AgentCrl,
    devices: &DeviceRegistry,
) -> Result<Vec<u8>, String> {
    if request_der.is_empty() {
        return Err("empty OCSP request".into());
    }
    let req =
        OcspRequest::from_der(request_der).map_err(|e| format!("decode OCSP request: {e}"))?;
    if req.tbs_request.request_list.is_empty() {
        return Err("OCSP request has empty requestList".into());
    }

    let ca_pem = cert_cache.ca_cert_pem();
    let ca = parse_ca_certificate(&ca_pem)?;
    let this_update = unix_to_ocsp_time(unix_now())?;
    let next_update = unix_to_ocsp_time(unix_now() + NEXT_UPDATE_SECS)?;

    let mut responses = Vec::with_capacity(req.tbs_request.request_list.len());
    for single in &req.tbs_request.request_list {
        let serial_hex = serial_to_hex(&single.req_cert.serial_number);
        let lab = check_status(crl, devices, None, Some(&serial_hex))?;
        let cert_status = cert_status_from_lab(&lab)?;
        responses.push(SingleResponse {
            cert_id: single.req_cert.clone(),
            cert_status,
            this_update,
            next_update: Some(next_update),
            single_extensions: None,
        });
    }

    let mut response_extensions = None;
    if let Some(nonce) = req.nonce() {
        use x509_cert::ext::AsExtension;
        use x509_cert::name::Name;
        let ext = nonce
            .to_extension(&Name::default(), &[])
            .map_err(|e| format!("OCSP nonce extension: {e}"))?;
        response_extensions = Some(vec![ext]);
    }

    let produced_at = OcspGeneralizedTime::try_from(SystemTime::now())
        .map_err(|e| format!("OCSP producedAt: {e}"))?;

    let tbs = ResponseData {
        version: Version::V1,
        responder_id: ResponderId::ByName(ca.tbs_certificate.subject.clone()),
        produced_at,
        responses,
        response_extensions,
    };
    let tbs_der = tbs
        .to_der()
        .map_err(|e| format!("encode OCSP tbsResponseData: {e}"))?;

    let (signature_algorithm, signature_bytes) =
        sign_tbs_with_ca_key(&cert_cache.ca_key_pkcs8_der(), &tbs_der)?;
    let signature = BitString::from_bytes(&signature_bytes)
        .map_err(|e| format!("OCSP signature BIT STRING: {e}"))?;

    let basic = BasicOcspResponse {
        tbs_response_data: tbs,
        signature_algorithm,
        signature,
        certs: Some(vec![ca]),
    };
    let resp = OcspResponse::successful(basic).map_err(|e| format!("OCSP wrap: {e}"))?;
    resp.to_der()
        .map_err(|e| format!("encode OCSP response: {e}"))
}

/// Malformed-request / internal-error style unsigned OCSP response.
pub fn error_response_der(status: OcspResponseStatus) -> Vec<u8> {
    OcspResponse {
        response_status: status,
        response_bytes: None,
    }
    .to_der()
    .unwrap_or_default()
}

fn parse_ca_certificate(pem: &str) -> Result<Certificate, String> {
    let mut reader = std::io::Cursor::new(pem.as_bytes());
    let ders = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("CA PEM parse: {e}"))?;
    let der = ders
        .first()
        .ok_or_else(|| "CA PEM contains no certificate".to_string())?;
    Certificate::from_der(der.as_ref()).map_err(|e| format!("CA cert DER: {e}"))
}

/// Sign OCSP `tbsResponseData` with the CA key (ECDSA P-256 or RSA PKCS#1 v1.5 SHA-256).
fn sign_tbs_with_ca_key(
    key_pkcs8_der: &[u8],
    tbs_der: &[u8],
) -> Result<(AlgorithmIdentifierOwned, Vec<u8>), String> {
    let rng = SystemRandom::new();

    // ECDSA P-256 (rcgen in-memory CA default).
    if let Ok(kp) = EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        key_pkcs8_der,
        &rng,
    ) {
        let sig = kp
            .sign(&rng, tbs_der)
            .map_err(|e| format!("OCSP ECDSA sign: {e}"))?;
        let alg = AlgorithmIdentifierOwned {
            // ecdsa-with-SHA256
            oid: ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"),
            parameters: None,
        };
        return Ok((alg, sig.as_ref().to_vec()));
    }

    // RSA (scripts/gen-ca.sh 4096-bit).
    if let Ok(kp) = RsaKeyPair::from_pkcs8(key_pkcs8_der) {
        let mut sig = vec![0u8; kp.public().modulus_len()];
        kp.sign(&signature::RSA_PKCS1_SHA256, &rng, tbs_der, &mut sig)
            .map_err(|e| format!("OCSP RSA sign: {e}"))?;
        let alg = AlgorithmIdentifierOwned {
            // sha256WithRSAEncryption
            oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11"),
            parameters: Some(Null.into()),
        };
        return Ok((alg, sig));
    }

    Err("CA private key is neither ECDSA P-256 nor RSA PKCS#8 — cannot sign OCSP DER".into())
}

/// Build a SHA-256 CertID for tests / clients without pulling x509-ocsp Digest OID traits.
pub fn cert_id_sha256(
    issuer: &Certificate,
    serial_number: x509_cert::serial_number::SerialNumber,
) -> Result<CertId, String> {
    let name_der = issuer
        .tbs_certificate
        .subject
        .to_der()
        .map_err(|e| format!("issuer name DER: {e}"))?;
    let key_bits = issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    Ok(CertId {
        hash_algorithm: AlgorithmIdentifierOwned {
            // id-sha256
            oid: ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1"),
            parameters: Some(Null.into()),
        },
        issuer_name_hash: OctetString::new(Sha256::digest(name_der).to_vec())
            .map_err(|e| format!("issuerNameHash: {e}"))?,
        issuer_key_hash: OctetString::new(Sha256::digest(key_bits).to_vec())
            .map_err(|e| format!("issuerKeyHash: {e}"))?,
        serial_number,
    })
}

/// Decode base64 (standard or URL-safe, optional padding) OCSP request.
pub fn decode_b64_request(b64: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    let s = b64.trim().replace('-', "+").replace('_', "/");
    let padded = match s.len() % 4 {
        2 => format!("{s}=="),
        3 => format!("{s}="),
        _ => s,
    };
    base64::engine::general_purpose::STANDARD
        .decode(padded.as_bytes())
        .map_err(|e| format!("OCSP request base64: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_registry::{DeviceRegistry, EnrollRequest};
    use rcgen::KeyPair;
    use x509_ocsp::TbsRequest;

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

    #[test]
    fn der_ocsp_good_and_revoked() {
        use rcgen::{CertificateParams, DistinguishedName, DnType};

        let ca_key = KeyPair::generate().unwrap();
        let cache = CertCache::from_pem(ca_key.serialize_pem().as_bytes(), b"").unwrap();
        let reg = DeviceRegistry::memory_only();
        let crl = AgentCrl::memory_only();

        let agent_key = KeyPair::generate().unwrap();
        let mut csr_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        csr_params.distinguished_name = DistinguishedName::new();
        csr_params
            .distinguished_name
            .push(DnType::CommonName, "csr-placeholder");
        let csr_pem = csr_params
            .serialize_request(&agent_key)
            .unwrap()
            .pem()
            .unwrap();
        let signed = cache
            .sign_agent_client_csr(&csr_pem, "ocsp-dev", None, "linux", 30)
            .unwrap();

        reg.enroll(EnrollRequest {
            device_id: Some("ocsp-dev".into()),
            platform: "linux".into(),
            name: Some("OCSP".into()),
            user_identity: None,
            capabilities: vec![],
            device_type: Some("desktop".into()),
            cert_subject: Some(signed.subject.clone()),
            cert_fingerprint: Some(signed.fingerprint_sha256.clone()),
            cert_serial: Some(signed.serial_hex.clone()),
        })
        .unwrap();

        let ca = parse_ca_certificate(&cache.ca_cert_pem()).unwrap();
        let serial_bytes = hex::decode(&signed.serial_hex).unwrap();
        let serial = x509_cert::serial_number::SerialNumber::new(&serial_bytes).unwrap();
        let cert_id = cert_id_sha256(&ca, serial).unwrap();
        let req = OcspRequest {
            tbs_request: TbsRequest {
                version: Version::V1,
                requestor_name: None,
                request_list: vec![x509_ocsp::Request {
                    req_cert: cert_id,
                    single_request_extensions: None,
                }],
                request_extensions: None,
            },
            optional_signature: None,
        };
        let req_der = req.to_der().unwrap();

        let good_der = respond_der(&req_der, &cache, &crl, &reg).unwrap();
        let good = OcspResponse::from_der(&good_der).unwrap();
        assert_eq!(good.response_status, OcspResponseStatus::Successful);

        crl.revoke(
            "ocsp-dev",
            Some(&signed.fingerprint_sha256),
            Some(&signed.serial_hex),
            "cessationOfOperation",
        );
        let rev_der = respond_der(&req_der, &cache, &crl, &reg).unwrap();
        let rev = OcspResponse::from_der(&rev_der).unwrap();
        assert_eq!(rev.response_status, OcspResponseStatus::Successful);
        assert!(!rev_der.is_empty());
        assert_ne!(good_der, rev_der);
    }
}
