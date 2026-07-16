#!/usr/bin/env python3
"""Compare anomaly_stub_v0 vs ueba_zscore_v0 scores from ClickHouse.

Reads recent rows from bsdm.ml_scores (and optionally recomputes stub offline
from entity_features JSON if present). Prints rank correlation / top divergences.

Usage:
  CLICKHOUSE_URL=http://127.0.0.1:8123 python3 scripts/ml/compare_stub_vs_ueba.py
"""
from __future__ import annotations

import json
import os
import sys
import urllib.parse
import urllib.request
from collections import defaultdict


def ch_query(url: str, sql: str) -> list[dict]:
    req = urllib.request.Request(
        url.rstrip("/") + "/?" + urllib.parse.urlencode({"query": sql}),
        data=b"",
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        body = resp.read().decode()
    rows = []
    for line in body.splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def main() -> int:
    url = os.environ.get("CLICKHOUSE_URL", "http://127.0.0.1:8123")
    hours = int(os.environ.get("COMPARE_HOURS", "24"))
    sql = f"""
SELECT
  entity_type,
  entity_id,
  model,
  score,
  severity,
  scored_at
FROM bsdm.ml_scores
WHERE scored_at >= now() - INTERVAL {hours} HOUR
FORMAT JSONEachRow
"""
    try:
        rows = ch_query(url, sql)
    except Exception as exc:
        print(f"ClickHouse query failed: {exc}", file=sys.stderr)
        print("Ensure CH is up and ml-worker has written scores.", file=sys.stderr)
        return 1

    by_key: dict[tuple[str, str], dict[str, float]] = defaultdict(dict)
    for r in rows:
        model = str(r.get("model", ""))
        # Normalize fallback labels
        if model.startswith("anomaly_stub"):
            bucket = "stub"
        elif model.startswith("ueba_zscore"):
            bucket = "ueba"
        else:
            bucket = model
        key = (str(r.get("entity_type")), str(r.get("entity_id")))
        by_key[key][bucket] = float(r.get("score", 0))

    paired = [
        (k, v["stub"], v["ueba"])
        for k, v in by_key.items()
        if "stub" in v and "ueba" in v
    ]
    print(f"scores_rows={len(rows)} entities_with_both={len(paired)} window_hours={hours}")
    if not paired:
        print(
            "No paired stub+ueba scores. Run ml-worker twice with ML_MODEL=anomaly_stub_v0 "
            "then ML_MODEL=ueba_zscore_v0, or inspect bsdm.ml_scores."
        )
        # Still show top UEBA scores
        ueba_only = sorted(
            (
                (str(r.get("entity_type")), str(r.get("entity_id")), float(r.get("score", 0)))
                for r in rows
                if str(r.get("model", "")).startswith("ueba")
            ),
            key=lambda x: -x[2],
        )[:15]
        print("top_ueba:")
        for et, eid, sc in ueba_only:
            print(f"  {et}\t{eid}\t{sc:.4f}")
        return 0

    # Spearman-ish: compare rankings
    stub_rank = {
        k: i
        for i, (k, _, _) in enumerate(sorted(paired, key=lambda x: -x[1]))
    }
    ueba_rank = {
        k: i
        for i, (k, _, _) in enumerate(sorted(paired, key=lambda x: -x[2]))
    }
    n = len(paired)
    d2 = sum((stub_rank[k] - ueba_rank[k]) ** 2 for k, _, _ in paired)
    rho = 1.0 - (6.0 * d2) / (n * (n * n - 1)) if n > 1 else 1.0
    print(f"spearman_rho_approx={rho:.4f}")

    divergences = sorted(
        ((k, stub, ueba, abs(stub - ueba)) for k, stub, ueba in paired),
        key=lambda x: -x[3],
    )[:15]
    print("top_divergences(|stub-ueba|):")
    for (et, eid), stub, ueba, delta in divergences:
        print(f"  {et}\t{eid}\tstub={stub:.4f}\tueba={ueba:.4f}\tdelta={delta:.4f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
