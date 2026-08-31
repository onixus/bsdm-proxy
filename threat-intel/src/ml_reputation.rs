//! TASK-TI-040: ML Domain Reputation & Typosquatting / Homoglyph Detection Engine.
//!
//! Provides algorithmic reputation scoring and brand impersonation detection:
//! - Visual Homoglyph / Confusable normalization (Cyrillic/Greek/Lookalikes).
//! - Damerau-Levenshtein edit distance against protected enterprise & consumer brands.
//! - Subdomain brand deception and deceptive keyword stacking.

use serde::{Deserialize, Serialize};

/// Default protected high-value brands commonly targeted by phishing campaigns.
pub const DEFAULT_PROTECTED_BRANDS: &[&str] = &[
    "google",
    "microsoft",
    "apple",
    "amazon",
    "paypal",
    "netflix",
    "telegram",
    "sberbank",
    "yandex",
    "gosuslugi",
    "tinkoff",
    "binance",
    "coinbase",
    "facebook",
    "instagram",
    "whatsapp",
    "github",
    "cloudflare",
    "outlook",
    "office365",
];

const SUSPICIOUS_KEYWORDS: &[&str] = &[
    "login", "verify", "account", "security", "update", "signin", "auth", "support", "password",
    "secure", "confirm", "wallet", "banking", "service", "portal",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainReputationScore {
    pub domain: String,
    pub risk_score: u8,
    pub is_suspicious: bool,
    pub target_brand: Option<String>,
    pub heuristics: Vec<String>,
    pub normalized_ascii: String,
}

/// Evaluates domain reputation against homoglyph, typosquatting, and deceptive patterns.
pub fn evaluate_domain_reputation(
    domain: &str,
    custom_brands: Option<&[&str]>,
) -> DomainReputationScore {
    let raw_lower = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let (norm_ascii, has_homoglyphs) = normalize_homoglyphs(&raw_lower);

    let brands = custom_brands.unwrap_or(DEFAULT_PROTECTED_BRANDS);
    let mut heuristics = Vec::new();
    let mut max_risk: u8 = 0;
    let mut detected_brand: Option<String> = None;

    if has_homoglyphs {
        heuristics.push("homoglyph_detected".to_string());
        max_risk = max_risk.max(40);
    }

    // Extract domain name without TLD
    let labels: Vec<&str> = norm_ascii.split('.').collect();
    if labels.is_empty() {
        return DomainReputationScore {
            domain: raw_lower,
            risk_score: 0,
            is_suspicious: false,
            target_brand: None,
            heuristics: vec![],
            normalized_ascii: norm_ascii,
        };
    }

    // Main second-level domain (SLD) candidate
    let sld = if labels.len() >= 2 {
        labels[labels.len() - 2]
    } else {
        labels[0]
    };

    // 1. Check exact brand in SLD with suspicious keyword stacking (e.g. login-microsoft.com)
    for &brand in brands {
        if sld == brand {
            if has_homoglyphs {
                heuristics.push(format!("homoglyph_brand_impersonation:{brand}"));
                max_risk = max_risk.max(95);
                detected_brand = Some(brand.to_string());
            }
            // Legitimate brand apex without homoglyphs (e.g. google.com) is not suspicious
            continue;
        }

        // Exact brand substring inside hyphenated or composite domain
        if sld.contains(brand) {
            let has_keyword = SUSPICIOUS_KEYWORDS.iter().any(|&k| sld.contains(k));
            if has_keyword || sld.contains('-') || sld.contains('_') {
                heuristics.push(format!("brand_keyword_stacking:{brand}"));
                max_risk = max_risk.max(85);
                detected_brand = Some(brand.to_string());
            }
        }

        // Subdomain brand deception (e.g. microsoft.com.attacker.net or apple.verify.org)
        if labels.len() >= 3 && labels[..labels.len() - 2].contains(&brand) {
            heuristics.push(format!("subdomain_brand_deception:{brand}"));
            max_risk = max_risk.max(90);
            detected_brand = Some(brand.to_string());
        }

        // 2. Typosquatting / Damerau-Levenshtein edit distance
        let dist = damerau_levenshtein(sld, brand);
        if dist == 1 && brand.len() >= 4 {
            heuristics.push(format!("typosquatting_distance_1:{brand}"));
            let score = if has_homoglyphs { 95 } else { 85 };
            max_risk = max_risk.max(score);
            detected_brand = Some(brand.to_string());
        } else if dist == 2 && brand.len() >= 7 {
            heuristics.push(format!("typosquatting_distance_2:{brand}"));
            max_risk = max_risk.max(70);
            detected_brand = Some(brand.to_string());
        }
    }

    let is_suspicious = max_risk >= 65;

    DomainReputationScore {
        domain: raw_lower,
        risk_score: max_risk,
        is_suspicious,
        target_brand: detected_brand,
        heuristics,
        normalized_ascii: norm_ascii,
    }
}

/// Normalizes visual homoglyphs (Cyrillic, Greek, lookalike Unicode) to ASCII.
/// Returns `(normalized_string, bool_has_homoglyphs)`.
pub fn normalize_homoglyphs(s: &str) -> (String, bool) {
    let mut has_homoglyphs = false;
    let mut out = String::with_capacity(s.len());

    for ch in s.chars() {
        match ch {
            // Cyrillic lookalikes
            '\u{0430}' | '\u{0410}' => {
                // а, А -> a
                has_homoglyphs = true;
                out.push('a');
            }
            '\u{0435}' | '\u{0415}' | '\u{0451}' | '\u{0401}' => {
                // е, Е, ё, Ё -> e
                has_homoglyphs = true;
                out.push('e');
            }
            '\u{043E}' | '\u{041E}' => {
                // о, О -> o
                has_homoglyphs = true;
                out.push('o');
            }
            '\u{0440}' | '\u{0420}' => {
                // р, Р -> p
                has_homoglyphs = true;
                out.push('p');
            }
            '\u{0441}' | '\u{0421}' => {
                // с, С -> c
                has_homoglyphs = true;
                out.push('c');
            }
            '\u{0443}' | '\u{0423}' => {
                // у, У -> y
                has_homoglyphs = true;
                out.push('y');
            }
            '\u{0445}' | '\u{0425}' => {
                // х, Х -> x
                has_homoglyphs = true;
                out.push('x');
            }
            '\u{0456}' | '\u{0406}' => {
                // і, І -> i
                has_homoglyphs = true;
                out.push('i');
            }
            // Lookalike special symbols
            '0' => out.push('0'),
            '1' => out.push('1'),
            c if c.is_ascii() => out.push(c),
            other => {
                has_homoglyphs = true;
                out.push(other);
            }
        }
    }

    (out, has_homoglyphs)
}

/// Computes Damerau-Levenshtein distance (insertions, deletions, substitutions, transpositions).
pub fn damerau_levenshtein(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let n = a_chars.len();
    let m = b_chars.len();

    if n == 0 {
        return m;
    }
    if m == 0 {
        return n;
    }

    let mut dp = vec![vec![0usize; m + 1]; n + 1];

    for (i, row) in dp.iter_mut().enumerate().take(n + 1) {
        row[0] = i;
    }
    for (j, val) in dp[0].iter_mut().enumerate().take(m + 1) {
        *val = j;
    }

    for i in 1..=n {
        for j in 1..=m {
            let cost = if a_chars[i - 1] == b_chars[j - 1] {
                0
            } else {
                1
            };

            dp[i][j] = (dp[i - 1][j] + 1) // deletion
                .min(dp[i][j - 1] + 1) // insertion
                .min(dp[i - 1][j - 1] + cost); // substitution

            // Transposition check
            if i > 1
                && j > 1
                && a_chars[i - 1] == b_chars[j - 2]
                && a_chars[i - 2] == b_chars[j - 1]
            {
                dp[i][j] = dp[i][j].min(dp[i - 2][j - 2] + 1);
            }
        }
    }

    dp[n][m]
}

/// Computes Shannon entropy of a string (in bits per character).
pub fn calculate_shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq = std::collections::HashMap::new();
    for ch in s.chars() {
        *freq.entry(ch).or_insert(0usize) += 1;
    }
    let len = s.chars().count() as f64;
    let mut entropy = 0.0;
    for &count in freq.values() {
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

/// Structured domain anomaly scoring result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DomainAnomalyScore {
    pub domain: String,
    pub anomaly_score: u8,
    pub is_anomalous: bool,
    pub entropy: f64,
    pub digit_ratio: f64,
    pub subdomain_depth: usize,
    pub reasons: Vec<String>,
}

/// Evaluates domain lexical features: Shannon entropy, digit ratios, deep subdomains, and hyphen stacking.
pub fn detect_domain_anomalies(domain: &str) -> DomainAnomalyScore {
    let clean = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = clean.split('.').collect();
    if labels.is_empty() || clean.is_empty() {
        return DomainAnomalyScore {
            domain: clean,
            anomaly_score: 0,
            is_anomalous: false,
            entropy: 0.0,
            digit_ratio: 0.0,
            subdomain_depth: 0,
            reasons: vec![],
        };
    }

    let sld = if labels.len() >= 2 {
        labels[labels.len() - 2]
    } else {
        labels[0]
    };

    let entropy = calculate_shannon_entropy(sld);
    let digit_count = sld.chars().filter(|c| c.is_ascii_digit()).count();
    let digit_ratio = if sld.is_empty() {
        0.0
    } else {
        digit_count as f64 / sld.len() as f64
    };
    let subdomain_depth = labels.len().saturating_sub(2);

    let mut reasons = Vec::new();
    let mut score: u32 = 0;

    // 1. High Shannon entropy (random DGA-like strings)
    if entropy >= 3.8 {
        score += 55;
        reasons.push(format!("high_shannon_entropy:{:.2}", entropy));
    } else if entropy >= 3.4 {
        score += 30;
        reasons.push(format!("elevated_shannon_entropy:{:.2}", entropy));
    }

    // 2. High digit ratio
    if digit_ratio >= 0.35 {
        score += 50;
        reasons.push(format!("high_digit_ratio:{:.2}", digit_ratio));
    } else if digit_ratio >= 0.20 {
        score += 25;
        reasons.push(format!("elevated_digit_ratio:{:.2}", digit_ratio));
    }

    // 3. Deep subdomain stacking (e.g. login.apple.auth.verify.attacker.com)
    if subdomain_depth >= 2 {
        score += 50;
        reasons.push(format!("deep_subdomain_stacking:depth_{}", subdomain_depth));
    }

    // 4. Excessive hyphenation (e.g. secure-login-account-update-bank.com)
    let hyphen_count = sld.chars().filter(|&c| c == '-').count();
    if hyphen_count >= 3 {
        score += 40;
        reasons.push(format!("excessive_hyphenation:count_{}", hyphen_count));
    }

    // 5. Consecutive digit blocks (>= 5 digits)
    let has_consecutive_digits = {
        let mut max_seq = 0;
        let mut curr = 0;
        for c in sld.chars() {
            if c.is_ascii_digit() {
                curr += 1;
                max_seq = max_seq.max(curr);
            } else {
                curr = 0;
            }
        }
        max_seq >= 5
    };
    if has_consecutive_digits {
        score += 35;
        reasons.push("consecutive_digit_block".to_string());
    }

    let anomaly_score = score.min(100) as u8;
    let is_anomalous = anomaly_score >= 45;

    DomainAnomalyScore {
        domain: clean,
        anomaly_score,
        is_anomalous,
        entropy,
        digit_ratio,
        subdomain_depth,
        reasons,
    }
}

/// Structured phishing campaign cluster grouping related malicious domains.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignCluster {
    pub campaign_name: String,
    pub cluster_type: String,
    pub target_brand: Option<String>,
    pub domains: Vec<String>,
    pub confidence_score: u8,
    pub pattern_signature: String,
}

/// Clusters suspicious domain indicators into named threat campaigns by target brand,
/// structural homoglyphs, keyword stacking, subdomain deception, or algorithmic DGA traits.
pub fn cluster_phishing_campaigns(domains: &[String]) -> Vec<CampaignCluster> {
    use std::collections::HashMap;

    struct ClusterAccumulator {
        campaign_name: String,
        cluster_type: String,
        target_brand: Option<String>,
        domains: Vec<String>,
        pattern_signature: String,
        max_risk: u8,
    }

    let mut clusters: HashMap<String, ClusterAccumulator> = HashMap::new();

    for domain in domains {
        let rep = evaluate_domain_reputation(domain, None);
        let anomaly = detect_domain_anomalies(domain);

        let (key, name, c_type, brand, sig) = if let Some(brand) = &rep.target_brand {
            if rep.heuristics.contains(&"homoglyph_detected".to_string())
                || rep
                    .heuristics
                    .iter()
                    .any(|h| h.starts_with("homoglyph_brand_impersonation"))
            {
                (
                    format!("brand_homoglyph:{brand}"),
                    format!("Homoglyph Wave Targeting {brand}"),
                    "homoglyph_wave".to_string(),
                    Some(brand.clone()),
                    format!("homoglyph_target_{brand}"),
                )
            } else if rep
                .heuristics
                .iter()
                .any(|h| h.starts_with("brand_keyword_stacking"))
            {
                (
                    format!("brand_stacking:{brand}"),
                    format!("Brand Impersonation & Keyword Stacking Targeting {brand}"),
                    "brand_impersonation".to_string(),
                    Some(brand.clone()),
                    format!("keyword_stacking_{brand}"),
                )
            } else if rep
                .heuristics
                .iter()
                .any(|h| h.starts_with("subdomain_brand_deception"))
            {
                (
                    format!("brand_subdomain:{brand}"),
                    format!("Subdomain Deception Campaign Targeting {brand}"),
                    "subdomain_deception".to_string(),
                    Some(brand.clone()),
                    format!("subdomain_spoofing_{brand}"),
                )
            } else {
                (
                    format!("brand_typosquatting:{brand}"),
                    format!("Typosquatting Cluster Targeting {brand}"),
                    "typosquatting_cluster".to_string(),
                    Some(brand.clone()),
                    format!("typosquatting_{brand}"),
                )
            }
        } else if anomaly.is_anomalous {
            if anomaly
                .reasons
                .iter()
                .any(|r| r.starts_with("high_shannon_entropy"))
            {
                (
                    "dga_entropy_cluster".to_string(),
                    "Algorithmic DGA / High-Entropy Cluster".to_string(),
                    "dga_pattern".to_string(),
                    None,
                    "high_entropy_dga".to_string(),
                )
            } else if anomaly
                .reasons
                .iter()
                .any(|r| r.starts_with("deep_subdomain_stacking"))
            {
                (
                    "deep_subdomain_cluster".to_string(),
                    "Deep Subdomain Stacking Cluster".to_string(),
                    "subdomain_stacking".to_string(),
                    None,
                    "subdomain_stacking_pattern".to_string(),
                )
            } else {
                (
                    "anomalous_lexical_cluster".to_string(),
                    "Anomalous Lexical Structure Cluster".to_string(),
                    "lexical_anomaly".to_string(),
                    None,
                    "general_anomaly".to_string(),
                )
            }
        } else {
            // Check for common suspicious keywords (e.g. login, verify, update)
            let lower = domain.to_ascii_lowercase();
            if let Some(&kw) = SUSPICIOUS_KEYWORDS.iter().find(|&&k| lower.contains(k)) {
                (
                    format!("keyword_wave:{kw}"),
                    format!("Generic Credential Harvesting Campaign ({kw})"),
                    "keyword_stacking".to_string(),
                    None,
                    format!("keyword_target_{kw}"),
                )
            } else {
                (
                    "unclassified_threats".to_string(),
                    "Unclassified Threat Indicators".to_string(),
                    "unclassified".to_string(),
                    None,
                    "general_ioc".to_string(),
                )
            }
        };

        let effective_risk = rep.risk_score.max(anomaly.anomaly_score);
        let entry = clusters.entry(key).or_insert_with(|| ClusterAccumulator {
            campaign_name: name,
            cluster_type: c_type,
            target_brand: brand,
            domains: Vec::new(),
            pattern_signature: sig,
            max_risk: 0,
        });

        entry.domains.push(domain.clone());
        entry.max_risk = entry.max_risk.max(effective_risk);
    }

    let mut result: Vec<CampaignCluster> = clusters
        .into_values()
        .map(|acc| {
            let size_bonus = ((acc.domains.len().saturating_sub(1) as u32) * 5).min(20) as u8;
            let confidence_score = (acc.max_risk.saturating_add(size_bonus)).clamp(10, 100);

            CampaignCluster {
                campaign_name: acc.campaign_name,
                cluster_type: acc.cluster_type,
                target_brand: acc.target_brand,
                domains: acc.domains,
                confidence_score,
                pattern_signature: acc.pattern_signature,
            }
        })
        .collect();

    // Sort by domain count descending, then confidence descending
    result.sort_by(|a, b| {
        b.domains
            .len()
            .cmp(&a.domains.len())
            .then_with(|| b.confidence_score.cmp(&a.confidence_score))
    });

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_damerau_levenshtein() {
        assert_eq!(damerau_levenshtein("google", "google"), 0);
        assert_eq!(damerau_levenshtein("gogle", "google"), 1); // deletion
        assert_eq!(damerau_levenshtein("googel", "google"), 1); // transposition
        assert_eq!(damerau_levenshtein("googlr", "google"), 1); // substitution
        assert_eq!(damerau_levenshtein("microsoft", "micros0ft"), 1);
    }

    #[test]
    fn test_homoglyph_normalization() {
        // "gооgle" with Cyrillic 'о'
        let cyrillic_google = "g\u{043E}\u{043E}gle.com";
        let (norm, has_homoglyphs) = normalize_homoglyphs(cyrillic_google);
        assert!(has_homoglyphs);
        assert_eq!(norm, "google.com");
    }

    #[test]
    fn test_evaluate_typosquatting_and_homoglyphs() {
        // 1. Typosquatted Google
        let res = evaluate_domain_reputation("gogle.com", None);
        assert!(res.is_suspicious);
        assert_eq!(res.target_brand, Some("google".to_string()));
        assert!(res
            .heuristics
            .iter()
            .any(|h| h.contains("typosquatting_distance_1")));

        // 2. Homoglyph Microsoft with Cyrillic 'о'
        let res2 = evaluate_domain_reputation("micr\u{043E}soft.com", None);
        assert!(res2.is_suspicious);
        assert_eq!(res2.target_brand, Some("microsoft".to_string()));
        assert!(res2.heuristics.contains(&"homoglyph_detected".to_string()));

        // 3. Keyword stacking: login-microsoft-security.com
        let res3 = evaluate_domain_reputation("login-microsoft-security.com", None);
        assert!(res3.is_suspicious);
        assert_eq!(res3.target_brand, Some("microsoft".to_string()));
        assert!(res3
            .heuristics
            .iter()
            .any(|h| h.contains("brand_keyword_stacking")));

        // 4. Subdomain deception: apple.com.phishing-server.net
        let res4 = evaluate_domain_reputation("apple.security.phishing-server.net", None);
        assert!(res4.is_suspicious);
        assert_eq!(res4.target_brand, Some("apple".to_string()));
        assert!(res4
            .heuristics
            .iter()
            .any(|h| h.contains("subdomain_brand_deception")));

        // 5. Legitimate domain
        let res5 = evaluate_domain_reputation("example.org", None);
        assert!(!res5.is_suspicious);
        assert_eq!(res5.risk_score, 0);
    }

    #[test]
    fn test_shannon_entropy_calculation() {
        let low_ent = calculate_shannon_entropy("aaaaaaa");
        assert_eq!(low_ent, 0.0);

        let standard = calculate_shannon_entropy("google");
        assert!(standard > 1.5 && standard < 2.5);

        let dga = calculate_shannon_entropy("xkrptzqmwlvjfsy");
        assert!(dga >= 3.8);
    }

    #[test]
    fn test_detect_domain_anomalies() {
        // 1. DGA-like random string
        let dga = detect_domain_anomalies("xkrptzqmwlvjfsy.net");
        assert!(dga.is_anomalous);
        assert!(dga
            .reasons
            .iter()
            .any(|r| r.starts_with("high_shannon_entropy")));

        // 2. High digit ratio + consecutive digits
        let digits = detect_domain_anomalies("bank987654321.com");
        assert!(digits.is_anomalous);
        assert!(digits.reasons.iter().any(|r| r.contains("digit")));

        // 3. Deep subdomain stacking
        let deep = detect_domain_anomalies("auth.login.verify.update.evil-host.com");
        assert!(deep.is_anomalous);
        assert!(deep
            .reasons
            .iter()
            .any(|r| r.contains("deep_subdomain_stacking")));

        // 4. Legitimate simple domain
        let safe = detect_domain_anomalies("crates.io");
        assert!(!safe.is_anomalous);
        assert_eq!(safe.anomaly_score, 0);
    }

    #[test]
    fn test_cluster_phishing_campaigns() {
        let domains = vec![
            "login-microsoft-auth.com".to_string(),
            "verify-microsoft-security.net".to_string(),
            "micr\u{043E}soft.com".to_string(),
            "apple.security.update-now.org".to_string(),
            "xkrptzqmwlvjfsy1.info".to_string(),
            "xkrptzqmwlvjfsy2.info".to_string(),
        ];

        let clusters = cluster_phishing_campaigns(&domains);
        assert!(!clusters.is_empty());

        // Check for Microsoft cluster
        let ms_cluster = clusters
            .iter()
            .find(|c| c.target_brand.as_deref() == Some("microsoft"));
        assert!(ms_cluster.is_some());

        // Check for Apple cluster
        let apple_cluster = clusters
            .iter()
            .find(|c| c.target_brand.as_deref() == Some("apple"));
        assert!(apple_cluster.is_some());

        // Check for DGA cluster
        let dga_cluster = clusters.iter().find(|c| c.cluster_type == "dga_pattern");
        assert!(dga_cluster.is_some());
    }
}
