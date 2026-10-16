#!/usr/bin/env python3
"""
Query the Terraform Registry for the latest version of each provider in
providers/main.tf, update the pinned versions, and regenerate the lock file.

Exit codes:
  0 = success (files may or may not have changed)
  1 = fatal error
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path
from typing import Any

PROVIDERS_DIR = Path(__file__).resolve().parent / "providers"
MAIN_TF = PROVIDERS_DIR / "main.tf"
REGISTRY_API = "https://registry.terraform.io/v1/providers"

PROVIDER_BLOCK_RE = re.compile(
    r'(?P<pre>\s+(?P<alias>\w+)\s*=\s*\{\s*\n'
    r'\s*source\s*=\s*"(?P<source>[^"]+)"\s*\n'
    r'\s*version\s*=\s*")(?P<version>[^"]+)(")',
    re.MULTILINE,
)


def _semver_tuple(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split(".") if x.isdigit())


def _fetch_latest_version(source: str) -> str | None:
    parts = source.split("/")
    if len(parts) < 2:
        return None
    namespace, name = parts[-2], parts[-1]
    url = f"{REGISTRY_API}/{namespace}/{name}/versions"
    req = urllib.request.Request(url, headers={"User-Agent": "deprecation-watch-bump"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data: dict[str, Any] = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        print(f"  Failed to query {url}: {exc}", file=sys.stderr)
        return None

    versions = data.get("versions") or []
    release_versions = []
    for entry in versions:
        v = entry if isinstance(entry, str) else (entry.get("version") if isinstance(entry, dict) else None)
        if v and re.fullmatch(r"\d+\.\d+\.\d+", v):
            release_versions.append(v)
    if not release_versions:
        return None
    return max(release_versions, key=_semver_tuple)


def bump_main_tf() -> list[dict[str, str]]:
    """Update version pins in main.tf. Returns list of changes."""
    text = MAIN_TF.read_text(encoding="utf-8")
    changes: list[dict[str, str]] = []

    def _replacer(m: re.Match[str]) -> str:
        source = m.group("source")
        current = m.group("version")
        latest = _fetch_latest_version(source)
        if latest and _semver_tuple(latest) > _semver_tuple(current):
            changes.append({"source": source, "from": current, "to": latest})
            return m.group("pre") + latest + m.group(5)
        return m.group(0)

    new_text = PROVIDER_BLOCK_RE.sub(_replacer, text)
    if new_text != text:
        MAIN_TF.write_text(new_text, encoding="utf-8")
    return changes


def regenerate_lockfile() -> bool:
    tf_bin = os.environ.get("TERRAFORM_PATH") or shutil.which("terraform")
    if not tf_bin:
        print("terraform CLI not found", file=sys.stderr)
        return False

    print("Running terraform init -upgrade …")
    init = subprocess.run(
        [tf_bin, "init", "-upgrade", "-no-color", "-input=false"],
        cwd=PROVIDERS_DIR,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    if init.returncode != 0:
        print(f"terraform init -upgrade failed:\n{init.stderr[-4000:]}", file=sys.stderr)
        return False

    print("Running terraform providers lock for linux_amd64 + darwin_amd64 …")
    lock = subprocess.run(
        [tf_bin, "providers", "lock",
         "-platform=linux_amd64", "-platform=darwin_amd64",
         "-no-color"],
        cwd=PROVIDERS_DIR,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    if lock.returncode != 0:
        print(f"terraform providers lock failed:\n{lock.stderr[-4000:]}", file=sys.stderr)
        return False

    return True


def main() -> int:
    if not MAIN_TF.is_file():
        print(f"main.tf not found at {MAIN_TF}", file=sys.stderr)
        return 1

    print(f"Checking latest provider versions from {REGISTRY_API} …")
    changes = bump_main_tf()
    if not changes:
        print("All providers are already at the latest version.")
        return 0

    print(f"\nBumped {len(changes)} provider(s):")
    for c in changes:
        print(f"  {c['source']}: {c['from']} → {c['to']}")

    if not regenerate_lockfile():
        return 1

    print("\nDone. main.tf and .terraform.lock.hcl updated.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
