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
}
