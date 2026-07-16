#!/usr/bin/env python3
"""Export population baseline JSON artifact for ml-worker (ML_BASELINE_PATH).

Queries ClickHouse entity_features aggregates and writes BaselineSet JSON
compatible with ml-worker::baseline::BaselineSet.

Usage:
  python3 scripts/ml/export_baseline.py -o /tmp/baseline.json
  ML_BASELINE_PATH=/tmp/baseline.json ML_MODEL=ueba_zscore_v0 ./target/release/ml-worker
"""
from __future__ import annotations

import argparse
import json
import os
import urllib.parse
import urllib.request


def ch_query(url: str, sql: str) -> list[dict]:
    req = urllib.request.Request(
        url.rstrip("/") + "/?" + urllib.parse.urlencode({"query": sql}),
        data=b"",
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        body = resp.read().decode()
    return [json.loads(line) for line in body.splitlines() if line.strip()]


def moments(row: dict, name: str) -> dict:
    return {
        "mean": float(row.get(f"mean_{name}", 0) or 0),
        "std": float(row.get(f"std_{name}", 0) or 0),
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("-o", "--output", default="baseline.json")
    p.add_argument("--lookback-secs", type=int, default=86400)
    p.add_argument("--min-samples", type=int, default=30)
    args = p.parse_args()

    url = os.environ.get("CLICKHOUSE_URL", "http://127.0.0.1:8123")
    db = os.environ.get("CLICKHOUSE_DATABASE", "bsdm")
    table = os.environ.get("ML_FEATURES_TABLE", "entity_features")
    fq = f"{db}.{table}"
    sql = f"""
SELECT
  entity_type,
  count() AS sample_count,
  avg(request_count) AS mean_request_count,
  ifNull(stddevSamp(request_count), 0) AS std_request_count,
  avg(unique_domains) AS mean_unique_domains,
  ifNull(stddevSamp(unique_domains), 0) AS std_unique_domains,
  avg(unique_urls) AS mean_unique_urls,
  ifNull(stddevSamp(unique_urls), 0) AS std_unique_urls,
  avg(deny_count) AS mean_deny_count,
  ifNull(stddevSamp(deny_count), 0) AS std_deny_count,
  avg(threat_hit_count) AS mean_threat_hit_count,
  ifNull(stddevSamp(threat_hit_count), 0) AS std_threat_hit_count,
  avg(avg_response_size) AS mean_avg_response_size,
  ifNull(stddevSamp(avg_response_size), 0) AS std_avg_response_size,
  avg(avg_duration_ms) AS mean_avg_duration_ms,
  ifNull(stddevSamp(avg_duration_ms), 0) AS std_avg_duration_ms,
  avg(gap_cv) AS mean_gap_cv,
  ifNull(stddevSamp(gap_cv), 0) AS std_gap_cv,
  avg(max_domain_len) AS mean_max_domain_len,
  ifNull(stddevSamp(max_domain_len), 0) AS std_max_domain_len,
  avg(if(request_count = 0, 0, deny_count / request_count)) AS mean_deny_ratio,
  ifNull(stddevSamp(if(request_count = 0, 0, deny_count / request_count)), 0) AS std_deny_ratio,
  avg(if(request_count = 0, 0, threat_hit_count / request_count)) AS mean_threat_ratio,
  ifNull(stddevSamp(if(request_count = 0, 0, threat_hit_count / request_count)), 0) AS std_threat_ratio
FROM {fq}
WHERE extracted_at >= now() - INTERVAL {args.lookback_secs} SECOND
GROUP BY entity_type
HAVING sample_count >= {args.min_samples}
FORMAT JSONEachRow
"""
    rows = ch_query(url, sql)
    baselines = {}
    for row in rows:
        et = row["entity_type"]
        baselines[et] = {
            "entity_type": et,
            "sample_count": int(row["sample_count"]),
            "request_count": moments(row, "request_count"),
            "unique_domains": moments(row, "unique_domains"),
            "unique_urls": moments(row, "unique_urls"),
            "deny_count": moments(row, "deny_count"),
            "threat_hit_count": moments(row, "threat_hit_count"),
            "avg_response_size": moments(row, "avg_response_size"),
            "avg_duration_ms": moments(row, "avg_duration_ms"),
            "gap_cv": moments(row, "gap_cv"),
            "max_domain_len": moments(row, "max_domain_len"),
            "deny_ratio": moments(row, "deny_ratio"),
            "threat_ratio": moments(row, "threat_ratio"),
        }
    artifact = {"baselines": baselines, "source": "export_baseline.py"}
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2)
        f.write("\n")
    print(f"wrote {args.output} types={list(baselines)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
