//! Integration tests for Enterprise SIEM, SOAR, and ML Domain Reputation.

use threat_intel::config::EnforcementMode;
use threat_intel::indicator::IndicatorKind;
use threat_intel::ml_reputation::{evaluate_domain_reputation, normalize_homoglyphs};
use threat_intel::siem::{SiemEvent, SiemEventAction};
use threat_intel::soar::{
    execute_soar_block, execute_soar_investigation, execute_soar_unblock, SoarBlockRequest,
    SoarUnblockRequest,
};
use threat_intel::storage::SqliteStorage;

#[test]
fn test_siem_cef_and_ecs_pipeline() {
    let storage = SqliteStorage::in_memory().unwrap();

    // 1. Create blocked IOC via SOAR
    execute_soar_block(
        &storage,
        SoarBlockRequest {
            indicator: "https://banking-sec-auth.net/login".into(),
            kind: IndicatorKind::Url,
            reason: "Active credential harvesting campaign".into(),
            ttl_secs: Some(86400 * 14),
            operator: Some("soc_lead".into()),
        },
        EnforcementMode::Enforce,
    )
    .unwrap();

    let ind = storage
        .query_indicator(
            "https://banking-sec-auth.net/login",
            Some(IndicatorKind::Url),
        )
        .unwrap()
        .unwrap();

    // 2. Generate SIEM events
    let event = SiemEvent::from_stored(&ind, SiemEventAction::Blocked);

    // Verify CEF format
    let cef = event.to_cef();
    assert!(cef.starts_with("CEF:0|BSDM-Proxy|ThreatIntel|0.9.13|IOC_BLOCKED|"));
    assert!(cef.contains("act=ioc_blocked"));
    assert!(cef.contains("cs1=soar:soc_lead"));
    assert!(cef.contains("request=https://banking-sec-auth.net/login"));
    assert!(cef.contains("shost=banking-sec-auth.net"));

    // Verify ECS JSON format
    let ecs = event.to_ecs_json();
    assert_eq!(ecs["event"]["action"], "ioc_blocked");
    assert_eq!(ecs["threat"]["indicator"]["type"], "url");
    assert_eq!(
        ecs["threat"]["indicator"]["value"],
        "https://banking-sec-auth.net/login"
    );
    assert_eq!(ecs["threat"]["indicator"]["provider"], "soar:soc_lead");

    // Verify Syslog RFC 5424
    let syslog = event.to_syslog_rfc5424("bsdm-edge-gw-01");
    assert!(syslog.contains("<134>1 "));
    assert!(syslog.contains("bsdm-edge-gw-01 bsdm-threat-intel"));
}

#[test]
fn test_soar_full_lifecycle() {
    let storage = SqliteStorage::in_memory().unwrap();
    let domain = "phishing-bank-update.org";

    // Step 1: Query unblocked domain -> not found
    let inv1 = execute_soar_investigation(&storage, domain, Some(IndicatorKind::Domain)).unwrap();
    assert!(!inv1.found);
    assert!(!inv1.is_active);

    // Step 2: SOAR automated block
    let block_res = execute_soar_block(
        &storage,
        SoarBlockRequest {
            indicator: domain.into(),
            kind: IndicatorKind::Domain,
            reason: "Threat intel correlation hit".into(),
            ttl_secs: Some(3600),
            operator: Some("automated_soar_playbook".into()),
        },
        EnforcementMode::Enforce,
    )
    .unwrap();
    assert!(block_res.success);

    // Step 3: Investigate blocked domain -> found & active
    let inv2 = execute_soar_investigation(&storage, domain, Some(IndicatorKind::Domain)).unwrap();
    assert!(inv2.found);
    assert!(inv2.is_active);
    assert_eq!(inv2.indicator.as_ref().unwrap().confidence_score, 100);

    // Step 4: SOAR automated unblock
    let unblock_res = execute_soar_unblock(
        &storage,
        SoarUnblockRequest {
            indicator: domain.into(),
            kind: Some(IndicatorKind::Domain),
            reason: "Playbook completed analysis, marked false positive".into(),
            operator: Some("tier2_analyst".into()),
        },
        EnforcementMode::Enforce,
    )
    .unwrap();
    assert!(unblock_res.success);

    // Step 5: Verify purged from storage
    let inv3 = execute_soar_investigation(&storage, domain, Some(IndicatorKind::Domain)).unwrap();
    assert!(!inv3.found);
}

#[test]
fn test_ml_reputation_models() {
    // 1. Homoglyphs normalization & detection
    // "рaypal.com" where 'р' is Cyrillic \u{0440}
    let cyrillic_paypal = "\u{0440}aypal.com";
    let (norm, has_homo) = normalize_homoglyphs(cyrillic_paypal);
    assert!(has_homo);
    assert_eq!(norm, "paypal.com");

    let score1 = evaluate_domain_reputation(cyrillic_paypal, None);
    assert!(score1.is_suspicious);
    assert_eq!(score1.target_brand, Some("paypal".to_string()));
    assert!(score1
        .heuristics
        .contains(&"homoglyph_detected".to_string()));

    // 2. Typosquatting (distance 1: "microsft.com")
    let score2 = evaluate_domain_reputation("microsft.com", None);
    assert!(score2.is_suspicious);
    assert_eq!(score2.target_brand, Some("microsoft".to_string()));
    assert!(score2.risk_score >= 85);

    // 3. Keyword Stacking ("verify-apple-account-security.org")
    let score3 = evaluate_domain_reputation("verify-apple-account.org", None);
    assert!(score3.is_suspicious);
    assert_eq!(score3.target_brand, Some("apple".to_string()));
    assert!(score3
        .heuristics
        .iter()
        .any(|h| h.contains("brand_keyword_stacking")));

    // 4. Subdomain brand deception ("telegram.org.malware-c2.net")
    let score4 = evaluate_domain_reputation("telegram.auth.malware-c2.net", None);
    assert!(score4.is_suspicious);
    assert_eq!(score4.target_brand, Some("telegram".to_string()));
    assert!(score4
        .heuristics
        .iter()
        .any(|h| h.contains("subdomain_brand_deception")));

    // 5. Normal safe domain
    let score5 = evaluate_domain_reputation("rust-lang.org", None);
    assert!(!score5.is_suspicious);
    assert_eq!(score5.risk_score, 0);
}
