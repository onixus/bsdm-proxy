#!/usr/bin/env python3
"""Evaluate cc_beacon_v0 scores vs beacon_periodic weak labels.

Usage:
  python3 scripts/ml/eval_cc_beacon.py
  python3 scripts/ml/eval_cc_beacon.py --url http://127.0.0.1:8123 --days 7
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
    p = argparse.ArgumentParser(description="Evaluate M5.4 cc_beacon_v0 scores")
    p.add_argument("--url", default="http://127.0.0.1:8123")
    p.add_argument("--database", default="bsdm")
    p.add_argument("--days", type=int, default=7)
    p.add_argument("--threshold", type=float, default=0.8)
    args = p.parse_args()

    sql = f"""
SELECT entity_id, score, features_json
FROM {args.database}.ml_scores
WHERE scored_at >= now() - INTERVAL {args.days} DAY
  AND model = 'cc_beacon_v0'
FORMAT JSONEachRow
"""
    raw = ch_query(args.url, args.database, sql).strip()
    if not raw:
        print("No cc_beacon_v0 scores found.")
        return 0

    rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
    parsed = []
    for row in rows:
        try:
            fj = json.loads(row.get("features_json") or "{}")
        except json.JSONDecodeError:
            fj = {}
        periodic = bool(fj.get("beacon_periodic_match"))
        parsed.append((row["entity_id"], float(row["score"]), periodic))

    n = len(parsed)
    high = [r for r in parsed if r[1] >= args.threshold]
    high_periodic = [r for r in high if r[2]]
    periodic_total = sum(1 for r in parsed if r[2])

    print(f"cc_beacon_v0 scores (last {args.days}d): {n}")
    print(f"  beacon_periodic weak label: {periodic_total}")
    print(f"  score >= {args.threshold}: {len(high)}")
    if high:
        pct = 100.0 * len(high_periodic) / len(high)
        print(f"  high-score with periodic match: {len(high_periodic)} ({pct:.1f}%)")

    print("\nTop 10 by score:")
    for eid, score, periodic in sorted(parsed, key=lambda x: -x[1])[:10]:
        tag = " [periodic]" if periodic else ""
        print(f"  {score:.3f}  {eid}{tag}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
