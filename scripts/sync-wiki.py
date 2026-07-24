#!/usr/bin/env python3
"""Generate the GitHub Wiki from canonical repository documentation."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_URL = "https://github.com/onixus/bsdm-proxy"

PAGES: dict[str, str] = {
    "docs/README.md": "Home.md",
    "docs/project-status.md": "Project-Status.md",
    "docs/getting-started/deployment.md": "Installation-Guide.md",
    "docs/getting-started/pilot-deployment.md": "Pilot-100-Users.md",
    "docs/getting-started/lite-mode.md": "Lite-Mode.md",
    "docs/getting-started/troubleshooting.md": "Troubleshooting-and-FAQ.md",
    "docs/architecture/overview.md": "Architecture-Overview.md",
    "docs/architecture/capacity-planning.md": "Capacity-Planning.md",
    "docs/architecture/performance.md": "Performance-Tuning.md",
    "docs/architecture/hierarchical-caching.md": "Hierarchical-Caching.md",
    "docs/architecture/structure.md": "Codebase-Structure.md",
    "docs/features/authentication.md": "Authentication.md",
    "docs/features/acl-policy.md": "ACL-Policy.md",
    "docs/features/categorization.md": "Domain-Categorization.md",
    "docs/features/control-plane.md": "Control-Plane-API.md",
    "docs/features/dns-sinkhole.md": "DNS-Sinkhole.md",
    "docs/features/semantic-cache.md": "AI-Semantic-Cache.md",
    "docs/features/wasm-plugins.md": "WASM-Plugins.md",
    "docs/features/icap-inspection.md": "ICAP-Inspection.md",
    "docs/analytics/clickhouse-retrosearch.md": "ClickHouse-RetroSearch.md",
    "docs/analytics/alerting.md": "Threat-Alerting.md",
    "docs/analytics/ml-security.md": "ML-Security.md",
    "docs/ops-and-dev/configuration.md": "Configuration.md",
    "docs/ops-and-dev/k8s-architecture.md": "Kubernetes-Deployment.md",
    "docs/ops-and-dev/logging.md": "Logging-and-Metrics.md",
    "docs/ops-and-dev/benchmarks.md": "Benchmarks.md",
    "docs/ops-and-dev/development.md": "Development-Guide.md",
    "docs/ops-and-dev/licensing.md": "Licensing.md",
    "docs/maintenance.md": "Documentation-Maintenance.md",
    "docs/roadmap.md": "Roadmap.md",
    "docs/releases/v0.2.3-test.md": "Release-0.2.3-test.md",
    "docs/releases/v0.3.0.md": "Release-0.3.0.md",
    "docs/releases/v0.3.1.md": "Release-0.3.1.md",
    "docs/releases/v0.3.2.md": "Release-0.3.2.md",
    "docs/releases/v0.5.0.md": "Release-0.5.0.md",
    "docs/releases/v0.5.7+033.md": "Release-0.5.7+033.md",
}

LINK_RE = re.compile(r"(!?\[[^\]]*]\()([^)]+)(\))")


def split_target(raw: str) -> tuple[str, str]:
    target = raw.strip().strip("<>")
    if " " in target:
        target = target.split(" ", 1)[0]
    if "#" in target:
        path, anchor = target.split("#", 1)
        return unquote(path), f"#{anchor}"
    return unquote(target), ""


def transform_links(source_rel: str, content: str) -> str:
    source = ROOT / source_rel

    def replace(match: re.Match[str]) -> str:
        prefix, raw, suffix = match.groups()
        path_part, anchor = split_target(raw)
        if (
            not path_part
            or path_part.startswith(("http://", "https://", "mailto:", "data:", "tel:"))
        ):
            return match.group(0)

        resolved = (source.parent / path_part).resolve()
        try:
            repo_rel = resolved.relative_to(ROOT).as_posix()
        except ValueError:
            return match.group(0)

        if repo_rel in PAGES:
            target = PAGES[repo_rel].removesuffix(".md") + anchor
        elif resolved.is_dir():
            target = f"{REPOSITORY_URL}/tree/main/{repo_rel}{anchor}"
        elif resolved.exists():
            target = f"{REPOSITORY_URL}/blob/main/{repo_rel}{anchor}"
        else:
            target = raw
        return f"{prefix}{target}{suffix}"

    return LINK_RE.sub(replace, content)


def sidebar() -> str:
    return """# BSDM-Proxy

* [Home](Home)
* [Project status](Project-Status)
* [Pilot: 100 users](Pilot-100-Users)

## Getting started
* [Installation](Installation-Guide)
* [Lite mode](Lite-Mode)
* [Troubleshooting](Troubleshooting-and-FAQ)
* [Configuration](Configuration)

## Architecture
* [Overview](Architecture-Overview)
* [Capacity planning](Capacity-Planning)
* [Performance](Performance-Tuning)
* [Hierarchy](Hierarchical-Caching)
* [Codebase structure](Codebase-Structure)

## Security and policy
* [Authentication](Authentication)
* [ACL](ACL-Policy)
* [Categorization](Domain-Categorization)
* [Control plane](Control-Plane-API)
* [DNS / DoH / DoT](DNS-Sinkhole)
* [Semantic cache](AI-Semantic-Cache)
* [WASM](WASM-Plugins)
* [ICAP](ICAP-Inspection)

## Analytics
* [ClickHouse](ClickHouse-RetroSearch)
* [Threat alerting](Threat-Alerting)
* [ML security](ML-Security)

## Operations
* [Kubernetes](Kubernetes-Deployment)
* [Logging and metrics](Logging-and-Metrics)
* [Benchmarks](Benchmarks)
* [Development](Development-Guide)
* [Licensing](Licensing)
* [Docs maintenance](Documentation-Maintenance)
* [Roadmap](Roadmap)
"""


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: sync-wiki.py /path/to/wiki", file=sys.stderr)
        return 2

    wiki = Path(sys.argv[1]).resolve()
    if not wiki.exists():
        print(f"wiki directory not found: {wiki}", file=sys.stderr)
        return 2

    for source_rel in PAGES:
        if not (ROOT / source_rel).exists():
            print(f"canonical page missing: {source_rel}", file=sys.stderr)
            return 1

    managed = set(PAGES.values()) | {"_Sidebar.md", "_Footer.md"}
    for existing in wiki.glob("*.md"):
        if existing.name not in managed:
            existing.unlink()

    banner = (
        "<!-- Generated from the main repository. "
        "Edit the canonical docs file, not this Wiki page. -->\n\n"
    )
    for source_rel, target_name in PAGES.items():
        content = (ROOT / source_rel).read_text(encoding="utf-8")
        rendered = transform_links(source_rel, content)
        (wiki / target_name).write_text(banner + rendered, encoding="utf-8")

    (wiki / "_Sidebar.md").write_text(sidebar(), encoding="utf-8")
    (wiki / "_Footer.md").write_text(
        "Canonical source: [repository documentation]"
        f"({REPOSITORY_URL}/tree/main/docs). "
        "Generated pages should not be edited directly.\n",
        encoding="utf-8",
    )
    print(f"Generated {len(PAGES)} Wiki pages in {wiki}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
