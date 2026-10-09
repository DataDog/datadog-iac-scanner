#!/usr/bin/env python3
"""
Cross-reference fetched deprecation data with extracted rule targets.

Reads:
  scripts/deprecation_watch/out/rule_targets.json
  scripts/deprecation_watch/out/*_fetched.json
  deprecation_snapshots/cloudformation/resource_type_names.json

Writes:
  scripts/deprecation_watch/out/report.json
  GITHUB_OUTPUT has_new_deprecations=true|false
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from common import github_output, out_dir, read_json, snapshots_dir, write_json


def _load(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    data = read_json(path)
    return data if isinstance(data, dict) else {}


def _tf_provider_prefix(resource_type: str) -> str:
    """Extract provider prefix like 'aws_' from 'aws_s3_bucket_object'."""
    idx = resource_type.find("_")
    return resource_type[: idx + 1] if idx > 0 else ""


def _build_tf_file_type_index(rt_index: dict[str, Any]) -> dict[str, set[str]]:
    """Map rule file path → set of TF resource types with *direct* resource blocks.

    Only ``direct`` context refs count (``input.document[i].resource.<TYPE>``).
    Other contexts like ``module_equivalent`` are a different code path and
    don't mean the rule handles that type as a direct resource declaration.
    """
    idx: dict[str, set[str]] = {}
    for rt_name, refs in rt_index.items():
        if not isinstance(refs, list):
            continue
        for ref in refs:
            if isinstance(ref, dict) and ref.get("rule_path") and ref.get("context") == "direct":
                idx.setdefault(ref["rule_path"], set()).add(rt_name)
    return idx


def _terraform_findings(tf_fetch: dict[str, Any], rules: dict[str, Any]) -> list[dict[str, Any]]:
    rt_index = rules.get("terraform") or {}
    if not isinstance(rt_index, dict):
        return []
    prov = tf_fetch.get("providers") or {}
    if not isinstance(prov, dict):
        return []

    deprecated_set: set[str] = set()
    for pdata in prov.values():
        if isinstance(pdata, dict):
            deprecated_set.update(pdata.get("deprecated_resource_types") or [])

    file_type_index = _build_tf_file_type_index(rt_index)

    by_target: dict[str, dict[str, Any]] = {}
    for addr, pdata in prov.items():
        if not isinstance(pdata, dict):
            continue
        for rtype in pdata.get("deprecated_resource_types") or []:
            if rtype not in rt_index or rtype in by_target:
                continue
            prefix = _tf_provider_prefix(rtype)
            affected: list[dict[str, Any]] = []
            for ref in rt_index[rtype]:
                if not isinstance(ref, dict):
                    continue
                ctx = str(ref.get("context", ""))
                rp = str(ref.get("rule_path", ""))

                # Library helper lists (check_aws_resource_supports_tags, etc.)
                # contain hundreds of types — not the security-checking rules
                # that need updating.
                if ctx.startswith("check_"):
                    continue

                # If the same rule file also references non-deprecated types
                # from the same provider prefix the rule already handles the
                # replacement → suppress this reference.
                if prefix:
                    colocated = file_type_index.get(rp, set())
                    has_replacement = any(
                        t.startswith(prefix) and t != rtype and t not in deprecated_set
                        for t in colocated
                    )
                    if has_replacement:
                        continue

                affected.append(ref)

            if affected:
                by_target[rtype] = {
                    "platform": "terraform",
                    "target": rtype,
                    "deprecation_source": f"terraform provider schema ({pdata.get('short', addr)})",
                    "replacement": None,
                    "severity": "high",
                    "affected_rules": affected,
                }
    return list(by_target.values())


def _cfn_service_prefix(resource_type: str) -> str:
    """Extract service prefix like 'AWS::Lambda::' from 'AWS::Lambda::Function'."""
    parts = resource_type.split("::")
    return f"{parts[0]}::{parts[1]}::" if len(parts) >= 3 else ""


def _cloudformation_findings(cfn_fetch: dict[str, Any], rules: dict[str, Any]) -> list[dict[str, Any]]:
    snap_path = snapshots_dir() / "cloudformation" / "resource_type_names.json"
    snap = _load(snap_path)
    old_names = set(snap.get("resource_type_names") or [])
    new_names = set(cfn_fetch.get("resource_type_names") or [])
    if not new_names:
        return []
    removed = sorted(old_names - new_names)
    rt_index = rules.get("cloudFormation") or {}
    if not isinstance(rt_index, dict):
        return []

    # Build per-file type index for CFN
    cfn_file_index: dict[str, set[str]] = {}
    for rt_name, refs in rt_index.items():
        if not isinstance(refs, list):
            continue
        for ref in refs:
            if isinstance(ref, dict) and ref.get("rule_path"):
                cfn_file_index.setdefault(ref["rule_path"], set()).add(rt_name)

    findings: list[dict[str, Any]] = []
    for rtype in removed:
        if rtype not in rt_index:
            continue
        prefix = _cfn_service_prefix(rtype)
        affected: list[dict[str, Any]] = []
        for ref in rt_index[rtype]:
            if not isinstance(ref, dict):
                continue
            rp = str(ref.get("rule_path", ""))
            if prefix:
                colocated = cfn_file_index.get(rp, set())
                has_replacement = any(
                    t.startswith(prefix) and t != rtype and t not in removed
                    for t in colocated
                )
                if has_replacement:
                    continue
            affected.append(ref)
        if not affected:
            continue
        findings.append(
            {
                "platform": "cloudFormation",
                "target": rtype,
                "deprecation_source": "AWS CloudFormation resource specification (type removed from latest spec)",
                "replacement": None,
                "severity": "critical",
                "affected_rules": affected,
            }
        )
    return findings


# Rule contexts that match by kind only (not API version). Rules with these
# contexts already work with both old and new API versions for the same kind.
_K8S_KIND_ONLY_CONTEXTS = {"document.kind", "listKinds", "kinds_set", "resource.kind"}


def _kubernetes_findings(k8s_fetch: dict[str, Any], rules: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    table = k8s_fetch.get("deprecation_table") or {}
    if not isinstance(table, dict):
        return []
    kinds_index = rules.get("k8s") or {}
    if not isinstance(kinds_index, dict):
        return []
    for entry in table.get("removed_kinds") or []:
        if not isinstance(entry, dict):
            continue
        kind = entry.get("kind")
        if kind and kind in kinds_index:
            findings.append(
                {
                    "platform": "k8s",
                    "target": kind,
                    "deprecation_source": f"Kubernetes API removal (removed in {entry.get('removed_in', '?')})",
                    "replacement": entry.get("replacement"),
                    "severity": "critical",
                    "affected_rules": kinds_index[kind],
                    "notes": entry.get("notes"),
                }
            )
    # Deprecated API versions (not removed kinds). Rules that match by kind
    # (e.g. document.kind == "Deployment") work for BOTH the old and the new
    # API version, so only keep rules that check a specific API version.
    api_by_kind: dict[str, list[dict[str, Any]]] = {}
    for entry in table.get("deprecated_api_version_kinds") or []:
        if not isinstance(entry, dict):
            continue
        kind = entry.get("kind")
        if kind and kind in kinds_index:
            api_by_kind.setdefault(str(kind), []).append(entry)
    for kind, entries in sorted(api_by_kind.items()):
        affected = [
            r
            for r in kinds_index[kind]
            if isinstance(r, dict) and r.get("context", "") not in _K8S_KIND_ONLY_CONTEXTS
        ]
        if not affected:
            continue
        apis = sorted({str(e.get("apiVersion", "")) for e in entries})
        repls = sorted({str(e.get("replacement_apiVersion", "")) for e in entries})
        findings.append(
            {
                "platform": "k8s",
                "target": f"deprecated-api::{kind}",
                "deprecation_source": "Kubernetes deprecated API versions (source: Pluto versions.yaml)",
                "replacement": ", ".join(r for r in repls if r),
                "severity": "medium",
                "affected_rules": affected,
                "notes": f"Deprecated apiVersions for this kind: {', '.join(apis)}",
            }
        )
    return findings


def _ansible_reverse_variant_index(modules_map: dict[str, Any]) -> dict[str, set[str]]:
    """Map every variant / FQCN / short name -> canonical keys from ansible.rego."""
    rev: dict[str, set[str]] = {}
    for canonical, entry in modules_map.items():
        if not isinstance(entry, dict):
            continue
        c = str(canonical)
        names = {c}
        for x in entry.get("variants") or []:
            names.add(str(x))
        for n in names:
            rev.setdefault(n, set()).add(c)
    return rev


def _ansible_canonicals_for_runtime_row(
    row: dict[str, Any],
    rev: dict[str, set[str]],
    canon_keys: set[str],
) -> set[str]:
    """Resolve runtime.yml plugin_routing row to scanner canonical module names."""
    found: set[str] = set()
    mod = row.get("module")
    if isinstance(mod, str) and mod.strip():
        found |= rev.get(mod.strip(), set())
    red = row.get("redirect")
    if isinstance(red, str) and red.strip():
        r = red.strip()
        found |= rev.get(r, set())
        if "." in r:
            tail = r.rsplit(".", 1)[-1]
            if tail in canon_keys:
                found.add(tail)
    return found & canon_keys


def _ansible_row_severity(row: dict[str, Any]) -> str | None:
    """Return severity label or None if this row should be ignored."""
    dep = row.get("deprecation")
    has_dep = isinstance(dep, dict) and bool(dep.get("removal_version") or dep.get("removal_date"))
    has_hard = bool(row.get("tombstone") or has_dep)
    has_redirect = isinstance(row.get("redirect"), str) and bool(row.get("redirect"))
    if has_hard:
        return "high"
    if has_redirect:
        return "medium"
    return None


def _canonical_already_covers_redirect(
    canonical: str,
    redirect: str | None,
    modules_map: dict[str, Any],
) -> bool:
    """True when the canonical's variant set already includes the redirect target.

    If the rule already supports both the deprecated alias AND the replacement,
    there is nothing to fix -- suppress the finding.
    """
    if not redirect:
        return False
    entry = modules_map.get(canonical)
    if not isinstance(entry, dict):
        return False
    variants: set[str] = set(entry.get("variants") or [])
    variants.add(canonical)
    if redirect in variants:
        return True
    # Also check bare tail: "amazon.aws.kms_key" -> "kms_key"
    if "." in redirect:
        tail = redirect.rsplit(".", 1)[-1]
        if tail in variants:
            return True
    return False


def _ansible_findings(ans_fetch: dict[str, Any], rules: dict[str, Any]) -> list[dict[str, Any]]:
    by_key: dict[str, dict[str, Any]] = {}
    canon_index = rules.get("ansible") or {}
    modules_map = rules.get("ansible_modules") or {}
    if not isinstance(canon_index, dict) or not isinstance(modules_map, dict):
        return []

    canon_keys = {str(k) for k in canon_index}
    rev = _ansible_reverse_variant_index(modules_map)
    collections = (ans_fetch.get("collections") or {}) if isinstance(ans_fetch, dict) else {}

    for coll_name, coll in collections.items():
        if not isinstance(coll, dict) or "error" in coll:
            continue
        for row in coll.get("deprecated_or_redirected_modules") or []:
            if not isinstance(row, dict):
                continue
            sev = _ansible_row_severity(row)
            if not sev:
                continue
            canonicals = _ansible_canonicals_for_runtime_row(row, rev, canon_keys)
            if not canonicals:
                continue
            mod = row.get("module")
            for canonical in sorted(canonicals):
                # If the rule's variants already cover both the deprecated alias
                # AND the redirect target, no action needed — skip.
                if _canonical_already_covers_redirect(canonical, row.get("redirect"), modules_map):
                    continue
                # One row per canonical across collections (Jira dedup + report clarity).
                key = f"ansible:{canonical}"
                refs = canon_index.get(canonical) or []
                routing = {k: v for k, v in row.items() if k != "module"}
                src = (
                    f"Ansible collection runtime.yml ({coll_name}) — "
                    f"routing for module `{mod}`"
                )
                if key not in by_key:
                    by_key[key] = {
                        "platform": "ansible",
                        "target": str(canonical),
                        "deprecation_source": src,
                        "replacement": row.get("redirect"),
                        "severity": sev,
                        "affected_rules": refs,
                        "routing": routing,
                        "runtime_modules_seen": [mod] if mod else [],
                        "collections_seen": [coll_name],
                    }
                else:
                    prev = by_key[key]
                    if sev == "high" and prev.get("severity") == "medium":
                        prev["severity"] = "high"
                    if mod and mod not in (prev.get("runtime_modules_seen") or []):
                        prev.setdefault("runtime_modules_seen", []).append(mod)
                    if coll_name not in (prev.get("collections_seen") or []):
                        prev.setdefault("collections_seen", []).append(coll_name)
                    prev["deprecation_source"] = f"{prev.get('deprecation_source', '')}; {src}"
                    prev["routing"] = routing
    return list(by_key.values())


def _cicd_findings(cicd_fetch: dict[str, Any], rules: dict[str, Any]) -> list[dict[str, Any]]:
    cicd_index = rules.get("cicd") or {}
    if not isinstance(cicd_index, dict):
        return []
    actions = cicd_fetch.get("actions") or {}
    if not isinstance(actions, dict):
        return []

    findings: list[dict[str, Any]] = []
    for action_ref, refs in cicd_index.items():
        if not isinstance(refs, list):
            continue
        # Resolve action_ref to owner/repo (strip sub-paths)
        parts = action_ref.split("/")
        owner_repo = f"{parts[0]}/{parts[1]}" if len(parts) >= 2 else action_ref
        status = actions.get(owner_repo)
        if not isinstance(status, dict):
            continue
        state = status.get("status", "")
        if state == "active" or state.startswith("error_"):
            continue

        severity = "critical" if state == "not_found" else "high"
        if state == "archived":
            source = f"GitHub repo {owner_repo} is archived"
            notes = status.get("description") or "Repository has been archived by its owner"
        elif state == "not_found":
            source = f"GitHub repo {owner_repo} returns 404 (deleted or transferred)"
            notes = "Repository may have been deleted, made private, or transferred"
        elif state == "moved":
            source = f"GitHub repo {owner_repo} has been moved (301 redirect)"
            notes = "Repository was transferred to a different owner or renamed"
        else:
            source = f"GitHub repo {owner_repo} returned unexpected status: {state}"
            notes = None

        findings.append({
            "platform": "cicd",
            "target": action_ref,
            "deprecation_source": source,
            "replacement": None,
            "severity": severity,
            "affected_rules": refs,
            "notes": notes,
        })
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--print-findings",
        action="store_true",
        help="Print a concise text summary of findings to stdout after writing report.json",
    )
    args = parser.parse_args()
    base = out_dir()
    rules_path = base / "rule_targets.json"
    if not rules_path.is_file():
        print("Missing rule_targets.json — run extract_rule_targets.py first", file=sys.stderr)
        return 2
    rules = _load(rules_path)

    findings: list[dict[str, Any]] = []
    tf_fetch = _load(base / "terraform_fetched.json")
    if tf_fetch.get("error"):
        print("terraform fetch error:", tf_fetch.get("error"), file=sys.stderr)
    findings.extend(_terraform_findings(tf_fetch, rules))

    cfn_fetch = _load(base / "cloudformation_fetched.json")
    findings.extend(_cloudformation_findings(cfn_fetch, rules))

    k8s_fetch = _load(base / "kubernetes_fetched.json")
    findings.extend(_kubernetes_findings(k8s_fetch, rules))

    ans_fetch = _load(base / "ansible_fetched.json")
    findings.extend(_ansible_findings(ans_fetch, rules))

    cicd_fetch = _load(base / "cicd_fetched.json")
    findings.extend(_cicd_findings(cicd_fetch, rules))

    report = {"findings": findings, "count": len(findings)}
    write_json(base / "report.json", report)
    val = "true" if findings else "false"
    github_output("has_new_deprecations", val)
    print(f"Wrote {base / 'report.json'} findings={len(findings)}")
    if args.print_findings and findings:
        print("\n--- findings (platform | severity | target | replacement/source snippet) ---")
        for f in sorted(findings, key=lambda x: (str(x.get("platform")), str(x.get("severity")), str(x.get("target")))):
            plat = f.get("platform", "")
            sev = f.get("severity", "")
            tgt = f.get("target", "")
            rep = f.get("replacement") or ""
            src = (f.get("deprecation_source") or "")[:100]
            print(f"{plat}\t{sev}\t{tgt}\t{rep}\t{src}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
