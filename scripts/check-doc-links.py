#!/usr/bin/env python3
"""Check local Markdown links in repository documentation."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
LINK_RE = re.compile(r"!?\[[^\]]*]\(([^)]+)\)")
SKIP_PARTS = {".git", "node_modules", "target"}
SKIP_PREFIXES = ("http://", "https://", "mailto:", "data:", "tel:")


def markdown_files() -> list[Path]:
    return sorted(
        path
        for path in ROOT.rglob("*.md")
        if not any(part in SKIP_PARTS for part in path.relative_to(ROOT).parts)
    )


def link_path(raw: str) -> str:
    target = raw.strip().strip("<>")
    if " " in target:
        target = target.split(" ", 1)[0]
    return unquote(target.split("#", 1)[0])


def main() -> int:
    broken: list[tuple[Path, int, str]] = []
    for source in markdown_files():
        for line_number, line in enumerate(
            source.read_text(encoding="utf-8").splitlines(), start=1
        ):
            for match in LINK_RE.finditer(line):
                raw = match.group(1)
                target = link_path(raw)
                if (
                    not target
                    or target.startswith("#")
                    or target.startswith(SKIP_PREFIXES)
                ):
                    continue
                resolved = (source.parent / target).resolve()
                try:
                    resolved.relative_to(ROOT)
                except ValueError:
                    broken.append((source, line_number, raw))
                    continue
                if not resolved.exists():
                    broken.append((source, line_number, raw))

    if not broken:
        print(f"Markdown links OK ({len(markdown_files())} files)")
        return 0

    print("Broken local Markdown links:")
    for source, line_number, target in broken:
        print(f"  {source.relative_to(ROOT)}:{line_number}: {target}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
