#!/usr/bin/env python3
"""Shared HTTP Archive Top 1k profile loader and resource expansion."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PROFILE = ROOT / "scripts" / "httparchive-top1k-profile.json"


@dataclass(frozen=True)
class Resource:
    resource_id: str
    resource_type: str
    size_bytes: int
    mime: str
    extension: str
    path: str


def profile_path() -> Path:
    return Path(os.environ.get("HTTPARCHIVE_PROFILE", DEFAULT_PROFILE))


def load_profile(path: Path | None = None) -> dict[str, Any]:
    with (path or profile_path()).open(encoding="utf-8") as fh:
        return json.load(fh)


def split_bytes(total: int, count: int) -> list[int]:
    if count <= 0:
        return []
    base, rem = divmod(total, count)
    return [base + (1 if i < rem else 0) for i in range(count)]


def expand_device(profile: dict[str, Any], device: str) -> list[Resource]:
    dev = profile["devices"][device]
    resources: list[Resource] = []
    seq = 0
    for group in dev["resource_types"]:
        sizes = split_bytes(int(group["bytes"]), int(group["requests"]))
        for idx, size in enumerate(sizes):
            rid = f"{group['type']}-{idx:02d}"
            resources.append(
                Resource(
                    resource_id=rid,
                    resource_type=group["type"],
                    size_bytes=size,
                    mime=group["mime"],
                    extension=group["extension"],
                    path=f"/httparchive/{device}/{seq:03d}-{rid}.{group['extension']}",
                )
            )
            seq += 1
    return resources


def device_summary(profile: dict[str, Any], device: str) -> dict[str, int]:
    resources = expand_device(profile, device)
    return {
        "requests": len(resources),
        "bytes": sum(r.size_bytes for r in resources),
        "expected_requests": int(profile["devices"][device]["total_requests"]),
        "expected_bytes": int(profile["devices"][device]["total_bytes"]),
    }


def validate_profile(profile: dict[str, Any]) -> None:
    for device, dev in profile["devices"].items():
        summary = device_summary(profile, device)
        if summary["requests"] != summary["expected_requests"]:
            raise ValueError(
                f"{device}: request count {summary['requests']} != {summary['expected_requests']}"
            )
        if summary["bytes"] != summary["expected_bytes"]:
            raise ValueError(
                f"{device}: byte total {summary['bytes']} != {summary['expected_bytes']}"
            )


if __name__ == "__main__":
    prof = load_profile()
    validate_profile(prof)
    for device in prof["devices"]:
        s = device_summary(prof, device)
        print(f"{device}: {s['requests']} requests, {s['bytes']} bytes OK")
