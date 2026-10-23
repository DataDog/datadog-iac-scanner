#!/usr/bin/env python3
"""
Create Jira issues for deprecation_watch report.json entries (deduplicated by label).

Environment:
  JIRA_BASE_URL   e.g. https://your-domain.atlassian.net
  JIRA_EMAIL      Atlassian account email
  JIRA_API_TOKEN  API token (or JIRA_TOKEN as alias)
  JIRA_PROJECT_KEY (optional, default K9VULN)
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any

from common import out_dir

API_VERSION = "3"


def _dedup_label(platform: str, target: str) -> str:
    h = hashlib.sha256(f"{platform}:{target}".encode("utf-8")).hexdigest()[:12]
    return f"dw-{h}"


def _adf_doc(lines: list[str]) -> dict[str, Any]:
    content: list[dict[str, Any]] = []
    for line in lines:
        content.append(
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": line}],
            }
        )
    return {"type": "doc", "version": 1, "content": content}


def _build_auth_header() -> str:
    email = os.environ.get("JIRA_EMAIL", "").strip()
    token = (os.environ.get("JIRA_API_TOKEN") or os.environ.get("JIRA_TOKEN") or "").strip()
    if not email or not token:
        raise SystemExit("JIRA_EMAIL and JIRA_API_TOKEN (or JIRA_TOKEN) must be set")
    raw = f"{email}:{token}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


_AUTH_HEADER: str | None = None


def _auth_header() -> str:
    global _AUTH_HEADER  # noqa: PLW0603
    if _AUTH_HEADER is None:
        _AUTH_HEADER = _build_auth_header()
    return _AUTH_HEADER


def _request(
    method: str,
    url: str,
    *,
    data: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, str]:
    hdrs = {
        "Authorization": _auth_header(),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    if headers:
        hdrs.update(headers)
    body = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        return exc.code, err_body


def _jira_base() -> str:
    base = os.environ.get("JIRA_BASE_URL", "").strip().rstrip("/")
    if not base:
        raise SystemExit("JIRA_BASE_URL must be set (e.g. https://your-domain.atlassian.net)")
    return base


def _issue_exists(project: str, label: str) -> bool:
    jql = f'project = {project} AND labels = "{label}" AND resolution IS EMPTY'
    url = f"{_jira_base()}/rest/api/{API_VERSION}/search"
    payload = {"jql": jql, "maxResults": 1, "fields": ["key"]}
    code, body = _request("POST", url, data=payload)
    if code != 200:
        print(f"Jira search failed HTTP {code}: {body[:2000]}", file=sys.stderr)
        return True  # fail-safe: do not create duplicates if search is broken
    data = json.loads(body)
    issues = data.get("issues") or data.get("values") or []
    return len(issues) > 0


def _create_issue(project: str, summary: str, description_lines: list[str], labels: list[str]) -> str | None:
    url = f"{_jira_base()}/rest/api/{API_VERSION}/issue"
    fields: dict[str, Any] = {
        "project": {"key": project},
        "summary": summary[:254],
        "description": _adf_doc(description_lines),
        "issuetype": {"name": os.environ.get("JIRA_ISSUE_TYPE", "Task")},
        "labels": labels[:50],
    }
    payload = {"fields": fields}
    code, body = _request("POST", url, data=payload)
    if code not in (200, 201):
        print(f"Create issue failed HTTP {code}: {body[:4000]}", file=sys.stderr)
        return None
    data = json.loads(body)
    return str(data.get("key", ""))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="Print actions without calling Jira")
    args = parser.parse_args()

    report_path = out_dir() / "report.json"
    if not report_path.is_file():
        print(f"Missing {report_path}", file=sys.stderr)
        return 2
    report = json.loads(report_path.read_text(encoding="utf-8"))
    findings = report.get("findings") or []
    if not findings:
        print("No findings; nothing to do.")
        return 0

    project = (os.environ.get("JIRA_PROJECT_KEY") or "K9VULN").strip() or "K9VULN"
    created = 0
    dry_count = 0
    for row in findings:
        if not isinstance(row, dict):
            continue
        platform = str(row.get("platform", ""))
        target = str(row.get("target", ""))
        if not platform or not target:
            continue
        label = _dedup_label(platform, target)
        if args.dry_run:
            print(f"[dry-run] Would create/check label={label} platform={platform} target={target}")
            dry_count += 1
            continue
        if _issue_exists(project, label):
            print(f"Skip (open issue exists) label={label}")
            continue
        n_rules = len(row.get("affected_rules") or [])
        summary = f"[Deprecation] {platform}: {target} deprecated -- affects {n_rules} rule(s)"
        lines = [
            f"DEPRECATION_WATCH_ID: {label}",
            "",
            f"Platform: {platform}",
            f"Target: {target}",
            f"Severity: {row.get('severity', '')}",
            f"Source: {row.get('deprecation_source', '')}",
        ]
        if row.get("replacement"):
            lines.append(f"Replacement: {row.get('replacement')}")
        if row.get("notes"):
            lines.append(f"Notes: {row.get('notes')}")
        lines.append("")
        lines.append("Affected rules:")
        for ref in row.get("affected_rules") or []:
            if isinstance(ref, dict):
                lines.append(f"- {ref.get('rule_path', '')} ({ref.get('context', '')})")
            else:
                lines.append(f"- {ref}")
        labels = ["deprecation-watch", platform.replace(" ", "-")[:60], label]
        key = _create_issue(project, summary, lines, labels)
        if key:
            print(f"Created {key} for {platform}/{target}")
            created += 1
    if args.dry_run:
        print(f"Dry run complete. {dry_count} issue(s) would be created (subject to dedup).")
    else:
        print(f"Done. Created {created} issue(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
