//! Collector output.
//!
//! TASK-TI-001 stops at a file snapshot per source plus a run report; the
//! database layer is TASK-TI-002 and plugs in behind the same trait.

use crate::indicator::RawIndicator;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::io::Write;
use std::path::{Path, PathBuf};

pub trait IndicatorSink: Send + Sync {
    /// Replace the snapshot for `source` with `indicators`.
    fn write_batch(&self, source: &str, indicators: &[RawIndicator]) -> std::io::Result<()>;

    /// Persist the aggregated state of the last run of every source.
    fn write_report(&self, report: &CollectionReport) -> std::io::Result<()>;
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceReport {
    pub source: String,
    pub url: String,
    pub status: &'static str,
    pub indicators: usize,
    pub duration_ms: u128,
    pub attempts: u32,
    pub finished_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct CollectionReport {
    pub generated_at: Option<DateTime<Utc>>,
    pub sources: Vec<SourceReport>,
}

impl CollectionReport {
    /// Record the newest result for a source, replacing the previous one.
    pub fn record(&mut self, entry: SourceReport) {
        self.generated_at = Some(Utc::now());
        match self.sources.iter_mut().find(|s| s.source == entry.source) {
            Some(existing) => *existing = entry,
            None => self.sources.push(entry),
        }
    }
}

/// Writes `<dir>/<source>.jsonl` snapshots and `<dir>/report.json`.
pub struct JsonlFileSink {
    dir: PathBuf,
}

impl JsonlFileSink {
    pub fn new(dir: impl Into<PathBuf>) -> std::io::Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Write via a temp file so readers never observe a half-written snapshot.
    fn write_atomic(&self, file_name: &str, contents: &[u8]) -> std::io::Result<()> {
        let target = self.dir.join(file_name);
        let tmp = self.dir.join(format!("{file_name}.tmp"));
        {
            let mut file = std::fs::File::create(&tmp)?;
            file.write_all(contents)?;
            file.sync_all()?;
        }
        std::fs::rename(&tmp, &target)
    }
}

impl IndicatorSink for JsonlFileSink {
    fn write_batch(&self, source: &str, indicators: &[RawIndicator]) -> std::io::Result<()> {
        let mut buffer = Vec::with_capacity(indicators.len() * 128);
        for indicator in indicators {
            serde_json::to_writer(&mut buffer, indicator)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            buffer.push(b'\n');
        }
        self.write_atomic(&format!("{source}.jsonl"), &buffer)
    }

    fn write_report(&self, report: &CollectionReport) -> std::io::Result<()> {
        let json = serde_json::to_vec_pretty(report)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        self.write_atomic("report.json", &json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::indicator::IndicatorKind;

    fn indicator(value: &str) -> RawIndicator {
        RawIndicator {
            value: value.into(),
            kind: IndicatorKind::Url,
            source: "openphish".into(),
            source_weight: 90,
            collected_at: Utc::now(),
            reported_at: None,
            reference: None,
            tags: Vec::new(),
        }
    }

    #[test]
    fn writes_one_json_object_per_line() {
        let dir = tempfile::tempdir().unwrap();
        let sink = JsonlFileSink::new(dir.path()).unwrap();
        sink.write_batch(
            "openphish",
            &[
                indicator("https://a.example/"),
                indicator("https://b.example/"),
            ],
        )
        .unwrap();

        let body = std::fs::read_to_string(dir.path().join("openphish.jsonl")).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2);
        let parsed: RawIndicator = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(parsed.value, "https://a.example/");
        assert!(!dir.path().join("openphish.jsonl.tmp").exists());
    }

    #[test]
    fn snapshot_replaces_previous_run() {
        let dir = tempfile::tempdir().unwrap();
        let sink = JsonlFileSink::new(dir.path()).unwrap();
        sink.write_batch(
            "openphish",
            &[
                indicator("https://a.example/"),
                indicator("https://b.example/"),
            ],
        )
        .unwrap();
        sink.write_batch("openphish", &[indicator("https://c.example/")])
            .unwrap();
        let body = std::fs::read_to_string(dir.path().join("openphish.jsonl")).unwrap();
        assert_eq!(body.lines().count(), 1);
    }

    #[test]
    fn report_keeps_one_entry_per_source() {
        let dir = tempfile::tempdir().unwrap();
        let sink = JsonlFileSink::new(dir.path()).unwrap();
        let mut report = CollectionReport::default();
        for indicators in [1usize, 5] {
            report.record(SourceReport {
                source: "openphish".into(),
                url: "https://openphish.com/feed.txt".into(),
                status: "ok",
                indicators,
                duration_ms: 3,
                attempts: 1,
                finished_at: Utc::now(),
                error: None,
            });
        }
        sink.write_report(&report).unwrap();

        let body = std::fs::read_to_string(dir.path().join("report.json")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        let sources = value["sources"].as_array().unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0]["indicators"], 5);
    }
}
