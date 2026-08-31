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
            confidence_score: None,
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
    let expected_prefix = format!(
        "CEF:0|BSDM-Proxy|ThreatIntel|{}|IOC_BLOCKED|",
        env!("CARGO_PKG_VERSION")
    );
    assert!(cef.starts_with(&expected_prefix));
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

    // Step 2: SOAR automated block with default confidence
    let block_res = execute_soar_block(
        &storage,
        SoarBlockRequest {
            indicator: domain.into(),
            kind: IndicatorKind::Domain,
            reason: "Threat intel correlation hit".into(),
            ttl_secs: Some(3600),
            operator: Some("automated_soar_playbook".into()),
            confidence_score: None,
        },
        EnforcementMode::Enforce,
    )
    .unwrap();
    assert!(block_res.success);

    // Step 3: Investigate blocked domain -> found & active with default confidence (90)
    let inv2 = execute_soar_investigation(&storage, domain, Some(IndicatorKind::Domain)).unwrap();
    assert!(inv2.found);
    assert!(inv2.is_active);
    assert_eq!(inv2.indicator.as_ref().unwrap().confidence_score, 90);

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

#[test]
fn test_siem_transport_delivery() {
    use std::io::Read;
    use std::net::TcpListener;
    use threat_intel::siem::{
        FileSiemTransport, SiemDispatcher, SiemFormat, SyslogProtocol, SyslogTransport,
    };

    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("siem_dispatch.log");
    let file_transport = FileSiemTransport::new(&file_path, SiemFormat::Cef, "gw-01").unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let tcp_transport = SyslogTransport::new(
        format!("127.0.0.1:{port}"),
        SyslogProtocol::Tcp,
        SiemFormat::EcsJson,
        "gw-01",
    );

    let dispatcher = SiemDispatcher::new(vec![Box::new(file_transport), Box::new(tcp_transport)]);

    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0u8; 2048];
        let n = stream.read(&mut buf).unwrap();
        String::from_utf8(buf[..n].to_vec()).unwrap()
    });

    let storage = SqliteStorage::in_memory().unwrap();
    execute_soar_block(
        &storage,
        SoarBlockRequest {
            indicator: "http://phish-attack.test/update".into(),
            kind: IndicatorKind::Url,
            reason: "Credential harvesting".into(),
            ttl_secs: Some(3600),
            operator: Some("soc".into()),
            confidence_score: None,
        },
        EnforcementMode::Enforce,
    )
    .unwrap();

    let ind = storage
        .query_indicator("http://phish-attack.test/update", Some(IndicatorKind::Url))
        .unwrap()
        .unwrap();
    let event = SiemEvent::from_stored(&ind, SiemEventAction::Blocked);

    dispatcher.export_event(&event).unwrap();

    let tcp_received = handle.join().unwrap();
    assert!(tcp_received.contains("\"action\":\"ioc_blocked\""));
    assert!(tcp_received.contains("phish-attack.test"));

    let file_content = std::fs::read_to_string(&file_path).unwrap();
    assert!(file_content.starts_with("CEF:0|BSDM-Proxy|ThreatIntel|"));
    assert!(file_content.contains("request=http://phish-attack.test/update"));
}

#[test]
fn test_rpz_monotonic_and_rollback_e2e() {
    use threat_intel::rpz::{
        backup_path, has_rpz_backup, parse_soa_serial, rollback_rpz_zone, write_rpz_file, RpzConfig,
    };

    let dir = tempfile::tempdir().unwrap();
    let rpz_path = dir.path().join("threats.rpz");
    let cfg = RpzConfig::default();

    // Gen 1
    write_rpz_file(&rpz_path, &["bad1.com".to_string()], &cfg).unwrap();
    assert!(rpz_path.exists());
    assert!(!has_rpz_backup(&rpz_path));
    let s1 = parse_soa_serial(&std::fs::read_to_string(&rpz_path).unwrap()).unwrap();

    // Gen 2
    write_rpz_file(&rpz_path, &["bad2.com".to_string()], &cfg).unwrap();
    assert!(has_rpz_backup(&rpz_path));
    let s2 = parse_soa_serial(&std::fs::read_to_string(&rpz_path).unwrap()).unwrap();
    assert!(s2 > s1);

    // Verify Gen 2 active and Gen 1 backup
    let active = std::fs::read_to_string(&rpz_path).unwrap();
    assert!(active.contains("bad2.com CNAME ."));
    assert!(!active.contains("bad1.com CNAME ."));

    let bak = std::fs::read_to_string(backup_path(&rpz_path)).unwrap();
    assert!(bak.contains("bad1.com CNAME ."));

    // Rollback
    let ok = rollback_rpz_zone(&rpz_path).unwrap();
    assert!(ok);

    let restored = std::fs::read_to_string(&rpz_path).unwrap();
    assert!(restored.contains("bad1.com CNAME ."));
    assert!(!restored.contains("bad2.com CNAME ."));
}

#[test]
fn test_ml_anomaly_and_campaign_clustering_e2e() {
    use threat_intel::ml_reputation::{cluster_phishing_campaigns, detect_domain_anomalies};

    // 1. Anomaly test
    let anom = detect_domain_anomalies("login.auth.security.verify.apple.fake-server.net");
    assert!(anom.is_anomalous);
    assert!(anom.subdomain_depth >= 2);

    let dga = detect_domain_anomalies("kjhgfdsazxcvbnm1234.com");
    assert!(dga.is_anomalous);
    assert!(dga.entropy > 3.0);

    // 2. Campaign clustering
    let batch = vec![
        "secure-login-microsoft-auth.com".into(),
        "portal-microsoft-update.net".into(),
        "google-verify-account.com".into(),
        "google-auth-service.org".into(),
        "pzkqmlvjfrtwxya1.biz".into(),
        "pzkqmlvjfrtwxya2.biz".into(),
    ];

    let clusters = cluster_phishing_campaigns(&batch);
    assert!(clusters.len() >= 3);

    let ms = clusters
        .iter()
        .find(|c| c.target_brand.as_deref() == Some("microsoft"))
        .expect("Microsoft campaign must be identified");
    assert_eq!(ms.domains.len(), 2);

    let google = clusters
        .iter()
        .find(|c| c.target_brand.as_deref() == Some("google"))
        .expect("Google campaign must be identified");
    assert_eq!(google.domains.len(), 2);

    let dga_c = clusters
        .iter()
        .find(|c| c.cluster_type == "dga_pattern")
        .expect("DGA campaign must be identified");
    assert_eq!(dga_c.domains.len(), 2);
}
