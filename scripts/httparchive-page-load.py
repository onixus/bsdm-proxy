#!/usr/bin/env python3
"""Simulate a median Top 1k page load through a forward proxy."""
from __future__ import annotations

import argparse
import os
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from httparchive_profile import device_summary, expand_device, load_profile, validate_profile  # noqa: E402


def cache_label(headers) -> str:
    """Normalize cache status from BSDM (x-cache-status) or Squid (Cache-Status / X-Cache)."""
    xcs = headers.get("x-cache-status")
    if xcs:
        if xcs.endswith("-STREAMING"):
            return xcs.removesuffix("-STREAMING")
        return xcs
    cache_status = headers.get("Cache-Status") or headers.get("cache-status")
    if cache_status:
        lower = cache_status.lower()
        if "hit" in lower:
            return "HIT"
        if "miss" in lower:
            return "MISS"
    x_cache = headers.get("X-Cache") or headers.get("x-cache")
    if x_cache:
        lower = x_cache.lower()
        if "hit" in lower:
            return "HIT"
        if "miss" in lower:
            return "MISS"
    return "-"


def fetch(
    proxy: str,
    url: str,
    proxy_auth: str | None,
    timeout: float,
) -> tuple[str, int, float]:
    handlers: list[urllib.request.BaseHandler] = [
        urllib.request.ProxyHandler({"http": proxy, "https": proxy})
    ]
    if proxy_auth:
        password_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        password_mgr.add_password(None, proxy, *proxy_auth.split(":", 1))
        handlers.append(urllib.request.ProxyBasicAuthHandler(password_mgr))
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, method="GET")
    start = time.perf_counter()
    with opener.open(req, timeout=timeout) as resp:
        data = resp.read()
        elapsed = time.perf_counter() - start
        cache = cache_label(resp.headers)
        return cache, len(data), elapsed


def main() -> int:
    parser = argparse.ArgumentParser(description="HTTP Archive median page load via proxy")
    parser.add_argument("--proxy", default=os.environ.get("PROXY", "http://127.0.0.1:12788"))
    parser.add_argument("--upstream", default=os.environ.get("UPSTREAM", "http://127.0.0.1:18080"))
    parser.add_argument("--device", choices=["desktop", "mobile"], default="desktop")
    parser.add_argument("--concurrency", type=int, default=int(os.environ.get("PAGE_CONCURRENCY", "6")))
    parser.add_argument("--repeat", type=int, default=1, help="Repeat full page load N times")
    parser.add_argument("--proxy-user", default=os.environ.get("CURL_PROXY_USER"))
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()

    profile = load_profile()
    validate_profile(profile)
    resources = expand_device(profile, args.device)
    summary = device_summary(profile, args.device)
    upstream = args.upstream.rstrip("/")
    urls = [f"{upstream}{r.path}" for r in resources]

    print(
        f"HTTP Archive page load: device={args.device} "
        f"resources={summary['requests']} bytes={summary['bytes']}"
    )

    total_bytes = 0
    hits = 0
    misses = 0
    t0 = time.perf_counter()

    for round_idx in range(args.repeat):
        if args.repeat > 1:
            print(f"-- round {round_idx + 1}/{args.repeat} --")
        with ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as pool:
            futures = {
                pool.submit(fetch, args.proxy, url, args.proxy_user, args.timeout): url
                for url in urls
            }
            for fut in as_completed(futures):
                url = futures[fut]
                try:
                    cache, nbytes, _elapsed = fut.result()
                    total_bytes += nbytes
                    if cache == "HIT":
                        hits += 1
                    elif cache in ("MISS", "NEGATIVE_MISS", "BYPASS"):
                        misses += 1
                    elif cache in ("-", ""):
                        misses += 1  # proxy omits header on first upstream fetch
                except urllib.error.URLError as exc:
                    print(f"FAIL {url}: {exc}", file=sys.stderr)
                    return 1

    elapsed = time.perf_counter() - t0
    req_total = len(urls) * args.repeat
    rps = req_total / elapsed if elapsed > 0 else 0.0
    mbps = (total_bytes * 8) / elapsed / 1_000_000 if elapsed > 0 else 0.0
    expected_bytes = summary["bytes"] * args.repeat

    print(f"Duration:     {elapsed:.2f}s")
    print(f"Requests:     {req_total}")
    print(f"Throughput:   {rps:.1f} req/s")
    print(f"Bytes:        {total_bytes} ({total_bytes / 1_048_576:.2f} MiB)")
    if total_bytes != expected_bytes:
        print(
            f"ERROR:       expected {expected_bytes} bytes, got {total_bytes} "
            f"— check upstream mock on {upstream}",
            file=sys.stderr,
        )
        return 1
    print(f"Goodput:      {mbps:.1f} Mbit/s")
    print(f"Cache HIT:    {hits}")
    print(f"Cache MISS:   {misses}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
