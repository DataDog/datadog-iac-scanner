#!/usr/bin/env python3
"""
Fetch upstream deprecation signals for Terraform, CloudFormation, Kubernetes, Ansible, CI/CD.

Writes JSON files under scripts/deprecation_watch/out/
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any

import yaml

from common import out_dir, read_json, write_json

PROVIDERS_DIR = Path(__file__).resolve().parent / "providers"

CFN_SPEC_URL = (
    "https://d1uauaxba7bl26.cloudfront.net/latest/gzip/CloudFormationResourceSpecification.json"
)

ANSIBLE_RUNTIME_SOURCES = [
    {
        "name": "amazon.aws",
        "url": "https://raw.githubusercontent.com/ansible-collections/amazon.aws/main/meta/runtime.yml",
    },
    {
        "name": "community.aws",
        "url": "https://raw.githubusercontent.com/ansible-collections/community.aws/main/meta/runtime.yml",
    },
    {
        "name": "azure.azcollection",
        "url": "https://raw.githubusercontent.com/ansible-collections/azure.azcollection/main/meta/runtime.yml",
    },
    {
        "name": "google.cloud",
        "url": "https://raw.githubusercontent.com/ansible-collections/google.cloud/main/meta/runtime.yml",
    },
]

K8S_LATEST_RELEASE_API = "https://api.github.com/repos/kubernetes/kubernetes/releases/latest"
PLUTO_VERSIONS_URL = "https://raw.githubusercontent.com/FairwindsOps/pluto/master/versions.yaml"


def _http_get(url: str, timeout: int = 120, retries: int = 2) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "datadog-iac-scanner-deprecation-watch"})
    last_exc: Exception | None = None
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_exc = exc
            if attempt < retries - 1:
                wait = 2 ** (attempt + 1)
                print(f"HTTP GET {url} failed ({exc}), retrying in {wait}s…", file=sys.stderr)
                time.sleep(wait)
    raise last_exc  # type: ignore[misc]


def validate_cloudformation_spec(data: dict[str, Any]) -> None:
    if not isinstance(data, dict):
        raise ValueError("CloudFormation spec must be a JSON object")
    if "ResourceTypes" not in data or not isinstance(data["ResourceTypes"], dict):
        raise ValueError("CloudFormation spec missing ResourceTypes map")


def fetch_cloudformation() -> dict[str, Any]:
    raw = _http_get(CFN_SPEC_URL)
    data = json.loads(gzip.decompress(raw).decode("utf-8"))
    validate_cloudformation_spec(data)
    names = sorted(data["ResourceTypes"].keys())
    return {
        "resource_type_names": names,
        "count": len(names),
        "source": CFN_SPEC_URL,
    }


def fetch_kubernetes_release() -> dict[str, Any]:
    raw = _http_get(K8S_LATEST_RELEASE_API, timeout=60)
    rel = json.loads(raw.decode("utf-8"))
    tag = rel.get("tag_name", "")
    return {"latest_release_tag": tag, "source": K8S_LATEST_RELEASE_API}


def _parse_k8s_version(v: str) -> tuple[int, ...]:
    """'v1.25.0' → (1, 25, 0)."""
    return tuple(int(x) for x in v.lstrip("v").split(".") if x.isdigit())


def fetch_kubernetes_deprecation_table() -> dict[str, Any]:
    """Fetch Pluto versions.yaml and transform into our deprecation_table schema."""
    raw = _http_get(PLUTO_VERSIONS_URL, timeout=60)
    data = yaml.safe_load(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Pluto versions.yaml root must be a mapping")

    entries = data.get("deprecated-versions") or []
    k8s_entries = [e for e in entries if isinstance(e, dict) and e.get("component") == "k8s"]

    # Group by kind to determine removed vs deprecated-apiVersion
    by_kind: dict[str, list[dict[str, Any]]] = {}
    for e in k8s_entries:
        kind = e.get("kind", "")
        if not kind:
            continue
        by_kind.setdefault(kind, []).append(e)

    removed_kinds: list[dict[str, Any]] = []
    deprecated_api_version_kinds: list[dict[str, Any]] = []

    for kind, kind_entries in sorted(by_kind.items()):
        # A kind is "removed" if the entry with the latest removed-in version
        # has an empty replacement-api (the kind has no surviving apiVersion).
        with_removal = [
            e for e in kind_entries
            if e.get("removed-in") and str(e["removed-in"]).strip()
        ]
        if not with_removal:
            continue

        latest = max(with_removal, key=lambda e: _parse_k8s_version(str(e.get("removed-in", "v0.0.0"))))
        latest_replacement = str(latest.get("replacement-api") or "").strip()

        if not latest_replacement:
            removed_in_raw = str(latest.get("removed-in", ""))
            removed_kinds.append({
                "kind": kind,
                "removed_in": removed_in_raw.lstrip("v"),
                "replacement": "",
                "notes": "API removed; no replacement kind (source: Pluto)",
            })
        else:
            for e in kind_entries:
                removed_in = str(e.get("removed-in") or "").strip()
                if not removed_in:
                    continue
                deprecated_api_version_kinds.append({
                    "apiVersion": str(e.get("version", "")),
                    "kind": kind,
                    "replacement_apiVersion": str(e.get("replacement-api") or ""),
                    "notes": f"Removed in {removed_in}",
                })

    return {
        "removed_kinds": removed_kinds,
        "deprecated_api_version_kinds": deprecated_api_version_kinds,
        "source": PLUTO_VERSIONS_URL,
        "entry_count": len(k8s_entries),
    }


def _block_deprecated(block: dict[str, Any]) -> bool:
    if not isinstance(block, dict):
        return False
    if block.get("Deprecated") is True or block.get("deprecated") is True:
        return True
    desc = (block.get("Description") or block.get("description") or "").lower()
    if "deprecated" in desc and "use " in desc:
        return True
    return False


def fetch_terraform_schema() -> dict[str, Any]:
    """Run terraform providers schema -json in providers/. Uses TERRAFORM_PATH or terraform on PATH."""
    tf_bin = os.environ.get("TERRAFORM_PATH") or shutil.which("terraform")
    if not tf_bin:
        return {"error": "terraform CLI not found", "providers": {}}
    init_cmd = [tf_bin, "init", "-no-color", "-input=false"]
    if (PROVIDERS_DIR / ".terraform.lock.hcl").is_file():
        init_cmd.append("-lockfile=readonly")
    init = subprocess.run(
        init_cmd,
        cwd=PROVIDERS_DIR,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    if init.returncode != 0:
        return {
            "error": "terraform init failed",
            "stderr": init.stderr[-8000:],
            "stdout": init.stdout[-4000:],
            "providers": {},
        }
    proc = subprocess.run(
        [tf_bin, "providers", "schema", "-json", "-no-color"],
        cwd=PROVIDERS_DIR,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    if proc.returncode != 0:
        return {
            "error": "terraform providers schema failed",
            "stderr": proc.stderr[-8000:],
            "providers": {},
        }
    schema = json.loads(proc.stdout)
    providers_out: dict[str, Any] = {}
    for addr, pschema in (schema.get("provider_schemas") or {}).items():
        deprecated_types: list[str] = []
        for rname, rschema in (pschema.get("resource_schemas") or {}).items():
            block = (rschema or {}).get("block") or {}
            if _block_deprecated(block):
                deprecated_types.append(rname)
        deprecated_types.sort()
        short = addr.split("/")[-2] + "/" + addr.split("/")[-1] if "/" in addr else addr
        providers_out[addr] = {
            "short": short,
            "deprecated_resource_types": deprecated_types,
        }
    return {"providers": providers_out, "source": "terraform providers schema -json"}


def _parse_ansible_runtime_modules(text: str) -> list[dict[str, Any]]:
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError("runtime.yml root must be a mapping")
    pr = data.get("plugin_routing") or {}
    modules = (pr.get("modules") or {}) if isinstance(pr, dict) else {}
    if not isinstance(modules, dict):
        return []
    out: list[dict[str, Any]] = []
    for mod_name, entry in modules.items():
        if not isinstance(entry, dict):
            continue
        row: dict[str, Any] = {"module": mod_name}
        if "redirect" in entry:
            row["redirect"] = entry["redirect"]
        if "deprecation" in entry and isinstance(entry["deprecation"], dict):
            row["deprecation"] = entry["deprecation"]
        if "tombstone" in entry:
            row["tombstone"] = entry["tombstone"]
        if len(row) > 1:
            out.append(row)
    return out


def fetch_ansible_runtimes() -> dict[str, Any]:
    collections: dict[str, Any] = {}
    for src in ANSIBLE_RUNTIME_SOURCES:
        try:
            body = _http_get(src["url"], timeout=120).decode("utf-8")
            modules = _parse_ansible_runtime_modules(body)
            collections[src["name"]] = {
                "url": src["url"],
                "deprecated_or_redirected_modules": modules,
                "count": len(modules),
            }
        except Exception as exc:  # noqa: BLE001 — surface per-collection errors
            collections[src["name"]] = {"url": src["url"], "error": str(exc)}
    return {"collections": collections}


GITHUB_API = "https://api.github.com"


def _github_headers() -> dict[str, str]:
    """Build headers for GitHub API requests, including auth token if available."""
    headers = {"User-Agent": "datadog-iac-scanner-deprecation-watch", "Accept": "application/vnd.github+json"}
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _github_repo_status(owner_repo: str, headers: dict[str, str]) -> dict[str, Any]:
    """Check a single GitHub repo's status via the API. Returns status dict."""
    url = f"{GITHUB_API}/repos/{owner_repo}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return {
                "status": "archived" if data.get("archived") else "active",
                "archived": bool(data.get("archived")),
                "full_name": data.get("full_name", owner_repo),
                "description": (data.get("description") or "")[:200],
            }
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"status": "not_found", "archived": False, "full_name": owner_repo}
        if exc.code == 301:
            return {"status": "moved", "archived": False, "full_name": owner_repo}
        return {"status": f"error_http_{exc.code}", "archived": False, "full_name": owner_repo}
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {"status": f"error_{type(exc).__name__}", "archived": False, "full_name": owner_repo}


def fetch_cicd_action_status(rule_targets_path: Path) -> dict[str, Any]:
    """Check GitHub repo status for every action owner/repo referenced in CI/CD rules."""
    if not rule_targets_path.is_file():
        return {"error": "rule_targets.json not found", "actions": {}}

    targets = read_json(rule_targets_path)
    cicd_index = targets.get("cicd") if isinstance(targets, dict) else {}
    if not isinstance(cicd_index, dict) or not cicd_index:
        return {"actions": {}, "count": 0}

    # Dedupe to owner/repo (strip sub-paths like gradle/actions/setup-gradle → gradle/actions)
    owner_repos: set[str] = set()
    for action in cicd_index:
        parts = action.split("/")
        if len(parts) >= 2:
            owner_repos.add(f"{parts[0]}/{parts[1]}")

    headers = _github_headers()
    actions: dict[str, Any] = {}
    for repo in sorted(owner_repos):
        actions[repo] = _github_repo_status(repo, headers)
        # Lightweight rate-limit courtesy
        time.sleep(0.25)

    return {
        "actions": actions,
        "count": len(actions),
        "source": "GitHub API (repos endpoint)",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--platforms",
        default="terraform,cloudformation,k8s,ansible,cicd",
        help="Comma-separated list of platforms to fetch",
    )
    args = parser.parse_args()
    platforms = {p.strip() for p in args.platforms.split(",") if p.strip()}
    out = out_dir()

    if "cloudformation" in platforms:
        write_json(out / "cloudformation_fetched.json", fetch_cloudformation())

    if "k8s" in platforms:
        k8s: dict[str, Any] = {"release": fetch_kubernetes_release()}
        try:
            k8s["deprecation_table"] = fetch_kubernetes_deprecation_table()
        except Exception as exc:  # noqa: BLE001
            print(f"Pluto versions.yaml fetch failed ({exc}), K8s deprecations unavailable", file=sys.stderr)
            k8s["deprecation_table"] = {"error": str(exc)}
        write_json(out / "kubernetes_fetched.json", k8s)

    if "terraform" in platforms:
        write_json(out / "terraform_fetched.json", fetch_terraform_schema())

    if "ansible" in platforms:
        write_json(out / "ansible_fetched.json", fetch_ansible_runtimes())

    if "cicd" in platforms:
        rule_targets_path = out / "rule_targets.json"
        write_json(out / "cicd_fetched.json", fetch_cicd_action_status(rule_targets_path))

    print(f"Wrote fetch outputs to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
