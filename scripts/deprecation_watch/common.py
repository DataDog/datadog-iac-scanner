"""Shared paths and helpers for deprecation_watch scripts."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


def repo_root() -> Path:
    """Repository root (parent of scripts/)."""
    return Path(__file__).resolve().parent.parent.parent


def queries_dir() -> Path:
    return repo_root() / "assets" / "queries"


def libraries_dir() -> Path:
    return repo_root() / "assets" / "libraries"


def snapshots_dir() -> Path:
    return repo_root() / "deprecation_snapshots"


def out_dir() -> Path:
    d = repo_root() / "scripts" / "deprecation_watch" / "out"
    d.mkdir(parents=True, exist_ok=True)
    return d


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def github_output(name: str, value: str) -> None:
    """Append KEY=VALUE to GITHUB_OUTPUT if set (GitHub Actions)."""
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(f"{name}={value}\n")
