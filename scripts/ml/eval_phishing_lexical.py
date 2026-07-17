#!/usr/bin/env python3
"""Evaluate phishing_lexical_v0 scores against weak labels in ml_scores.

Usage:
  python3 scripts/ml/eval_phishing_lexical.py
  python3 scripts/ml/eval_phishing_lexical.py --url http://127.0.0.1:8123 --days 7
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.parse
import urllib.request


def ch_query(url: str, database: str, sql: str) -> str:
    q = urllib.parse.urlencode({"database": database, "default_format": "JSONEachRow"})
    req = urllib.request.Request(
        f"{url.rstrip('/')}/?{q}",
        data=sql.encode(),
        method="POST",
        headers={"Content-Type": "text/plain"},
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read().decode()


def main() -> int:
    p = argparse.ArgumentParser(description="Evaluate M5.3 phishing lexical scores")
    p.add_argument("--url", default="http://127.0.0.1:8123")
    p.add_argument("--database", default="bsdm")
    p.add_argument("--days", type=int, default=7)
    p.add_argument("--threshold", type=float, default=0.8)
    args = p.parse_args()

    sql = f"""
SELECT
  entity_id,
  score,
  features_json
FROM {args.database}.ml_scores
WHERE scored_at >= now() - INTERVAL {args.days} DAY
  AND model = 'phishing_lexical_v0'
FORMAT JSONEachRow
"""
    raw = ch_query(args.url, args.database, sql).strip()
    if not raw:
        print("No phishing_lexical_v0 scores found.")
        return 0

    rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
    labeled = []
    for row in rows:
        try:
            fj = json.loads(row.get("features_json") or "{}")
        except json.JSONDecodeError:
            fj = {}
        weak = fj.get("weak_labels") or {}
        has_label = any(
            int(weak.get(k, 0) or 0) > 0
            for k in ("phishing_category", "phishtank", "ut1")
        )
        labeled.append((row["entity_id"], float(row["score"]), has_label))

    n = len(labeled)
    high = [r for r in labeled if r[1] >= args.threshold]
    high_labeled = [r for r in high if r[2]]
    weak_total = sum(1 for r in labeled if r[2])

    print(f"phishing_lexical_v0 scores (last {args.days}d): {n}")
    print(f"  weak-label domains: {weak_total}")
    print(f"  score >= {args.threshold}: {len(high)}")
    if high:
        pct = 100.0 * len(high_labeled) / len(high)
        print(f"  high-score with weak label: {len(high_labeled)} ({pct:.1f}%)")

    print("\nTop 10 by score:")
    for domain, score, has_label in sorted(labeled, key=lambda x: -x[1])[:10]:
        tag = " [weak]" if has_label else ""
        print(f"  {score:.3f}  {domain}{tag}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
