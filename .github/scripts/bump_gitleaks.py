#!/usr/bin/env python3
"""Propose a gitleaks version bump, with a safety delay.

Policy:
- The pinned version in leakguard.py stays the single source of truth.
- A release becomes eligible only DELAY_DAYS (default 7) after it was
  published, so a compromised or broken release has time to be caught
  by the community before it is proposed here.
- This script only edits files. The workflow runs the test suite with
  the new binary and opens a pull request; nothing is merged or
  installed automatically.

Usage: python .github/scripts/bump_gitleaks.py [--dry-run]
Exit code 0 always; prints "BUMP <old> -> <new>" or "NO-BUMP ...".
"""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DELAY_DAYS = int(os.environ.get("BUMP_DELAY_DAYS", "7"))
FILES = ["leakguard.py", "scripts/leakguard.py", "README.md", "README.ja.md"]


def parse_ver(s: str) -> tuple[int, ...]:
    return tuple(int(x) for x in s.split("."))


def latest_eligible() -> str | None:
    req = urllib.request.Request(
        "https://api.github.com/repos/gitleaks/gitleaks/releases?per_page=20",
        headers={"Accept": "application/vnd.github+json",
                 **({"Authorization": f"Bearer {os.environ['GH_TOKEN']}"} if os.environ.get("GH_TOKEN") else {})},
    )
    releases = json.load(urllib.request.urlopen(req, timeout=60))
    cutoff = datetime.now(timezone.utc) - timedelta(days=DELAY_DAYS)
    best: str | None = None
    for r in releases:
        if r.get("draft") or r.get("prerelease"):
            continue
        published = datetime.fromisoformat(r["published_at"].replace("Z", "+00:00"))
        if published > cutoff:
            continue
        v = r["tag_name"].lstrip("v")
        if best is None or parse_ver(v) > parse_ver(best):
            best = v
    return best


def main() -> int:
    dry = "--dry-run" in sys.argv
    src = (ROOT / "leakguard.py").read_text(encoding="utf-8")
    current = re.search(r'^GITLEAKS_VERSION = "([\d.]+)"', src, re.M).group(1)
    latest = latest_eligible()
    if latest is None or parse_ver(latest) <= parse_ver(current):
        print(f"NO-BUMP current={current} latest-eligible={latest} delay={DELAY_DAYS}d")
        return 0
    print(f"BUMP {current} -> {latest}")
    if dry:
        return 0
    for rel in FILES:
        p = ROOT / rel
        if p.exists():
            p.write_text(p.read_text(encoding="utf-8").replace(current, latest), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
