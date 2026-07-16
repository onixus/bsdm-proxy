#!/usr/bin/env python3
"""HTTP Archive Top 1k: random sites load (cold + warm repeats)."""
from __future__ import annotations

import argparse
import importlib.util
import os
import sys
import time
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from httparchive_profile import (  # noqa: E402
    load_profile,
    random_site_ids,
    site_page_bytes,
    site_urls,
    validate_profile,
)

_spec = importlib.util.spec_from_file_location(
    "httparchive_page_load", ROOT / "scripts" / "httparchive-page-load.py"
)
_page_load = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(_page_load)
fetch = _page_load.fetch


def run_batch(
    urls: list[str],
    proxy: str,
    proxy_auth: str | None,
    concurrency: int,
    timeout: float,
) -> tuple[int, int, int, int, float]:
    hits = misses = total_bytes = 0
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        futures = {
            pool.submit(fetch, proxy, url, proxy_auth, timeout): url for url in urls
        }
        for fut in as_completed(futures):
            url = futures[fut]
            try:
                cache, nbytes, _elapsed = fut.result()
                total_bytes += nbytes
                if cache == "HIT":
                    hits += 1
                else:
                    misses += 1
            except urllib.error.URLError as exc:
                print(f"FAIL {url}: {exc}", file=sys.stderr)
                raise
    elapsed = time.perf_counter() - t0
    return hits, misses, total_bytes, len(urls), elapsed


def print_phase(name: str, hits: int, misses: int, nbytes: int, reqs: int, elapsed: float) -> None:
    rps = reqs / elapsed if elapsed > 0 else 0.0
    mbps = (nbytes * 8) / elapsed / 1_000_000 if elapsed > 0 else 0.0
    print(f"  {name}")
    print(f"    Duration:   {elapsed:.2f}s")
    print(f"    Requests:   {reqs}")
    print(f"    Throughput: {rps:.1f} req/s")
    print(f"    Bytes:      {nbytes} ({nbytes / 1_048_576:.2f} MiB)")
    print(f"    Goodput:    {mbps:.1f} Mbit/s")
    print(f"    Cache HIT:  {hits}")
    print(f"    Cache MISS: {misses}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="HTTP Archive: N random Top1k sites, cold then warm repeats"
    )
    parser.add_argument("--proxy", default=os.environ.get("PROXY", "http://127.0.0.1:12788"))
    parser.add_argument("--upstream", default=os.environ.get("UPSTREAM", "http://127.0.0.1:18080"))
    parser.add_argument("--device", choices=["desktop", "mobile"], default="desktop")
    parser.add_argument("--sites", type=int, default=int(os.environ.get("BENCH_SITES", "70")))
    parser.add_argument("--site-pool", type=int, default=int(os.environ.get("BENCH_SITE_POOL", "1000")))
    parser.add_argument("--seed", type=int, default=int(os.environ.get("BENCH_SITE_SEED", "42")))
    parser.add_argument(
        "--concurrency",
        type=int,
        default=int(os.environ.get("PAGE_CONCURRENCY", "12")),
    )
    parser.add_argument(
        "--warm-repeats",
        type=int,
        default=int(os.environ.get("BENCH_WARM_REPEATS", "20")),
    )
    parser.add_argument("--proxy-user", default=os.environ.get("CURL_PROXY_USER"))
    parser.add_argument("--timeout", type=float, default=120.0)
    args = parser.parse_args()

    profile = load_profile()
    validate_profile(profile)
    site_ids = random_site_ids(args.sites, args.site_pool, args.seed)
    urls = site_urls(args.upstream, profile, site_ids, args.device)
    page_bytes = site_page_bytes(profile, args.device)

    print(
        f"HTTP Archive sites bench: device={args.device} sites={args.sites} "
        f"pool={args.site_pool} seed={args.seed} concurrency={args.concurrency} "
        f"warm_repeats={args.warm_repeats} page_bytes={page_bytes}"
    )
    print(f"Site IDs: {site_ids[:5]}...{site_ids[-3:]}")

    total_hits = total_misses = total_bytes = total_reqs = 0
    total_elapsed = 0.0

    print("")
    print("==> phase 1: cold (first visit to each site)")
    h, m, b, r, e = run_batch(
        urls, args.proxy, args.proxy_user, args.concurrency, args.timeout
    )
    print_phase("cold", h, m, b, r, e)
    total_hits += h
    total_misses += m
    total_bytes += b
    total_reqs += r
    total_elapsed += e

    expected_cold = page_bytes * args.sites
    if b != expected_cold:
        print(
            f"ERROR: cold expected {expected_cold} bytes, got {b}",
            file=sys.stderr,
        )
        return 1

    print("")
    print(f"==> phase 2: warm ({args.warm_repeats} repeats to the same sites)")
    warm_bytes = 0
    warm_hits = warm_misses = warm_reqs = 0
    warm_elapsed = 0.0
    for rep in range(1, args.warm_repeats + 1):
        h, m, b, r, e = run_batch(
            urls, args.proxy, args.proxy_user, args.concurrency, args.timeout
        )
        warm_bytes += b
        warm_hits += h
        warm_misses += m
        warm_reqs += r
        warm_elapsed += e
        total_hits += h
        total_misses += m
        total_bytes += b
        total_reqs += r
        total_elapsed += e
        if rep <= 3 or rep == args.warm_repeats:
            print_phase(f"warm repeat {rep}/{args.warm_repeats}", h, m, b, r, e)
        elif rep == 4:
            print("  ...")

    expected_warm = page_bytes * args.sites * args.warm_repeats
    if warm_bytes != expected_warm:
        print(
            f"ERROR: warm expected {expected_warm} bytes, got {warm_bytes}",
            file=sys.stderr,
        )
        return 1

    print("")
    print("==> warm-only")
    print_phase("warm phases", warm_hits, warm_misses, warm_bytes, warm_reqs, warm_elapsed)
    print("")
    print("==> totals")
    print_phase("all phases", total_hits, total_misses, total_bytes, total_reqs, total_elapsed)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
