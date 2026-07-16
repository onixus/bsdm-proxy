//! Shannon entropy helpers for M4 high-entropy domain heuristics.

use std::collections::HashMap;

/// Shannon entropy in bits/character over Unicode scalar values.
pub fn shannon_entropy(s: &str) -> f64 {
    let len = s.chars().count();
    if len == 0 {
        return 0.0;
    }
    let mut counts: HashMap<char, usize> = HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_default() += 1;
    }
    let n = len as f64;
    counts.values().fold(0.0, |acc, &count| {
        let p = count as f64 / n;
        acc - p * p.log2()
    })
}

/// Leftmost DNS label (before first `.`), lowercased for stable scoring.
pub fn leftmost_label(domain: &str) -> &str {
    domain
        .split('.')
        .next()
        .unwrap_or(domain)
        .trim_end_matches('.')
}

/// Entropy of the leftmost label (typical DGA / C2 hostnames).
pub fn domain_label_entropy(domain: &str) -> f64 {
    let label = leftmost_label(domain).to_ascii_lowercase();
    shannon_entropy(&label)
}

/// Legacy length + digit-run heuristic (pre-Shannon).
pub fn legacy_high_entropy_domain(domain: &str, min_domain_len: usize) -> bool {
    if domain.len() < min_domain_len {
        return false;
    }
    let mut digit_run = 0usize;
    for c in domain.chars() {
        if c.is_ascii_digit() {
            digit_run += 1;
            if digit_run >= 4 {
                return true;
            }
        } else {
            digit_run = 0;
        }
    }
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HighEntropyMode {
    /// Shannon bits on leftmost label only.
    Shannon,
    /// Length + digit-run only (historical).
    Legacy,
    /// Either Shannon or legacy (default).
    Either,
}

impl HighEntropyMode {
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "shannon" | "sha" => Self::Shannon,
            "legacy" | "digits" => Self::Legacy,
            _ => Self::Either,
        }
    }
}

/// Match result for high-entropy domain heuristics.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HighEntropyMatch {
    pub entropy: f64,
    pub shannon_hit: bool,
    pub legacy_hit: bool,
}

impl HighEntropyMatch {
    pub fn kind_label(self) -> &'static str {
        match (self.shannon_hit, self.legacy_hit) {
            (true, true) => "shannon+legacy",
            (true, false) => "shannon",
            (false, true) => "legacy",
            (false, false) => "none",
        }
    }
}

/// Whether a domain should alert under the configured mode.
pub fn matches_high_entropy(
    domain: &str,
    mode: HighEntropyMode,
    shannon_min_bits: f64,
    min_label_len: usize,
    legacy_min_domain_len: usize,
) -> Option<HighEntropyMatch> {
    let label = leftmost_label(domain);
    let entropy = domain_label_entropy(domain);
    // DNS labels are ASCII in practice; char count == byte length for hostnames.
    let label_len = label.chars().count();
    let shannon_hit = label_len >= min_label_len && entropy >= shannon_min_bits;
    let legacy_hit = legacy_high_entropy_domain(domain, legacy_min_domain_len);

    let ok = match mode {
        HighEntropyMode::Shannon => shannon_hit,
        HighEntropyMode::Legacy => legacy_hit,
        HighEntropyMode::Either => shannon_hit || legacy_hit,
    };
    if ok {
        Some(HighEntropyMatch {
            entropy,
            shannon_hit,
            legacy_hit,
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_uniform_low_entropy() {
        assert_eq!(shannon_entropy(""), 0.0);
        assert!(shannon_entropy("aaaa") < 0.1);
    }

    #[test]
    fn randomish_label_high_entropy() {
        let h = shannon_entropy("xk9m2qp7wzb4");
        assert!(h > 3.0, "entropy={h}");
    }

    #[test]
    fn leftmost_label_extracted() {
        assert_eq!(leftmost_label("AbC123.evil.com"), "AbC123");
        assert_eq!(domain_label_entropy("AAAA.example.com"), 0.0);
    }

    #[test]
    fn mode_either_accepts_shannon_or_legacy() {
        let dga = "xk9m2qp7wzb4cd.example";
        let legacy = "totally-normal-looking-host-1234.example.com";
        assert!(matches_high_entropy(dga, HighEntropyMode::Either, 3.3, 10, 25).is_some());
        assert!(matches_high_entropy(legacy, HighEntropyMode::Either, 3.3, 10, 25).is_some());
        assert!(matches_high_entropy("google.com", HighEntropyMode::Either, 3.3, 10, 25).is_none());
    }

    #[test]
    fn mode_shannon_rejects_low_entropy_long_digit_domain() {
        // Long domain with digit run but low-entropy label "aaaa"
        let d = "aaaa1111.example.com";
        assert!(matches_high_entropy(d, HighEntropyMode::Legacy, 3.5, 10, 10).is_some());
        assert!(matches_high_entropy(d, HighEntropyMode::Shannon, 3.5, 10, 10).is_none());
    }
}
