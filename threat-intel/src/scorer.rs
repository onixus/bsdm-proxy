//! TASK-TI-010: Confidence Scoring Engine.
//!
//! Calculates risk and confidence scores ($1 \dots 100$) for IOCs by synthesizing:
//! - Primary feed reputation / source weight ($0 \dots 100$).
//! - Multi-source correlation bonus ($+20$ for 2 sources, $+35$ for $\ge 3$ sources).
//! - Freshness decay based on elapsed time since sighting/reporting.
//! - Domain and context tag bonuses (e.g. verified malicious).

use chrono::{DateTime, Utc};

/// Parameters influencing scoring calculation.
#[derive(Debug, Clone)]
pub struct ScoringInput {
    pub source_weight: u8,
    pub source_count: usize,
    pub reported_or_collected_at: DateTime<Utc>,
    pub tags: Vec<String>,
}

/// Computes an aggregated confidence score from $1$ to $100$.
pub fn calculate_confidence(input: &ScoringInput) -> u8 {
    let mut score = input.source_weight as f32;

    // 1. Multi-source correlation bonus
    if input.source_count >= 3 {
        score += 35.0;
    } else if input.source_count == 2 {
        score += 20.0;
    }

    // 2. Tag bonuses
    for tag in &input.tags {
        let lower = tag.to_ascii_lowercase();
        if lower == "verified" || lower == "confirmed" || lower == "c2" {
            score += 10.0;
        }
    }

    // 3. Freshness decay
    let age = Utc::now().signed_duration_since(input.reported_or_collected_at);
    let hours = age.num_hours();
    if hours > 24 * 30 {
        // > 30 days old
        score *= 0.5;
    } else if hours > 24 * 7 {
        // > 7 days old
        score *= 0.7;
    } else if hours > 24 {
        // > 1 day old
        score *= 0.9;
    }

    // Clamp to 1..=100
    score.round().clamp(1.0, 100.0) as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn single_source_fresh() {
        let input = ScoringInput {
            source_weight: 80,
            source_count: 1,
            reported_or_collected_at: Utc::now(),
            tags: vec![],
        };
        assert_eq!(calculate_confidence(&input), 80);
    }

    #[test]
    fn multi_source_bonus() {
        let input2 = ScoringInput {
            source_weight: 70,
            source_count: 2,
            reported_or_collected_at: Utc::now(),
            tags: vec![],
        };
        assert_eq!(calculate_confidence(&input2), 90); // 70 + 20

        let input3 = ScoringInput {
            source_weight: 70,
            source_count: 3,
            reported_or_collected_at: Utc::now(),
            tags: vec![],
        };
        assert_eq!(calculate_confidence(&input3), 100); // 70 + 35 clamped to 100
    }

    #[test]
    fn tag_bonus() {
        let input = ScoringInput {
            source_weight: 60,
            source_count: 1,
            reported_or_collected_at: Utc::now(),
            tags: vec!["verified".into()],
        };
        assert_eq!(calculate_confidence(&input), 70); // 60 + 10
    }

    #[test]
    fn freshness_decay() {
        let old = Utc::now() - Duration::days(10);
        let input = ScoringInput {
            source_weight: 80,
            source_count: 1,
            reported_or_collected_at: old,
            tags: vec![],
        };
        assert_eq!(calculate_confidence(&input), 56); // 80 * 0.7 = 56
    }
}
