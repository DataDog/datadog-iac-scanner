#!/usr/bin/env python3
"""
Extract IaC targets referenced by Rego rules (Terraform, CloudFormation, k8s, Ansible, CI/CD).

Writes scripts/deprecation_watch/out/rule_targets.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, DefaultDict, Iterable

from common import libraries_dir, out_dir, queries_dir, write_json

# Terraform: input.document[i].resource.TYPE[name] or input.document[i].resource[var][
TF_DIRECT = re.compile(
    r'input\.document\[[^\]]+\]\.resource\.([a-z0-9_]+)\[',
    re.IGNORECASE,
)
TF_STRING_LITERAL = re.compile(r'"((?:aws|azurerm|google|alicloud|tencentcloud|databricks|kubernetes|github)_[a-z0-9_]+)"')
TF_MODULE_EQ_KEY = re.compile(
    r'get_module_equivalent_key\s*\(\s*"[^"]+"\s*,\s*[^,]+\s*,\s*"([a-z0-9_]+)"',
    re.IGNORECASE,
)

# CloudFormation
CFN_TYPE_EQ = re.compile(r'resource\.Type\s*==\s*"(AWS::[^"]+)"')
CFN_TYPE_STRING = re.compile(r'"(AWS::[^"]+)"')

# Kubernetes
K8S_KIND_EQ_DOC = re.compile(r'document\.kind\s*==\s*"([A-Za-z][A-Za-z0-9]*)"\s*')
K8S_KIND_EQ_RES = re.compile(r'resource\.kind\s*==\s*"([A-Za-z][A-Za-z0-9]*)"\s*')
K8S_KINDS_SET = re.compile(r'kinds\s*:=\s*\{([^}]+)\}', re.DOTALL)
K8S_LIST_KINDS = re.compile(r'listKinds\s*:=\s*\[([^\]]+)\]', re.DOTALL)
# Ansible
ANSIBLE_CANONICAL = re.compile(r'^\s*canonical\s*:=\s*"([a-z0-9_]+)"', re.MULTILINE)

# CI/CD (GitHub Actions): owner/repo action references
# Map keys:  "owner/repo": ... or "owner/repo/path": ...
CICD_ACTION_MAP_KEY = re.compile(r'"([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*)"\s*:')
# Set members: "owner/repo",  or  "owner/repo/path",
CICD_ACTION_SET_MEMBER = re.compile(r'"([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*)"[,\s}]')
# startswith(uses, "owner/repo")
CICD_ACTION_STARTSWITH = re.compile(r'startswith\(\s*\w+\s*,\s*"([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*)"\s*\)')

# Terraform library: "aws_xxx": "",
TF_LIB_PAIR = re.compile(r'"((?:aws|azurerm|google|alicloud|tencentcloud|databricks|kubernetes|github)_[a-z0-9_]+)"\s*:\s*""')


def _walk_query_regos(base: Path) -> Iterable[Path]:
    if not base.is_dir():
        return
    yield from base.rglob("query.rego")


def _relative_to_repo(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def extract_terraform_library_tag_lists(terraform_lib: Path) -> dict[str, list[str]]:
    """Parse check_*_supports_tags/labels maps from terraform.rego."""
    text = terraform_lib.read_text(encoding="utf-8")
    sections: dict[str, list[str]] = {}

    def extract_block(start_marker: str) -> list[str]:
        idx = text.find(start_marker)
        if idx == -1:
            return []
        brace_start = text.find("resource = {", idx)
        if brace_start == -1:
            return []
        # Scan to the matching closing brace
        depth = 0
        for i in range(brace_start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    return sorted(set(TF_LIB_PAIR.findall(text[brace_start : i + 1])))
        return sorted(set(TF_LIB_PAIR.findall(text[brace_start:])))

    sections["check_aws_resource_supports_tags"] = extract_block("check_aws_resource_supports_tags(p)")
    sections["check_gcp_resource_supports_labels"] = extract_block("check_gcp_resource_supports_labels(p)")
    sections["check_azure_resource_supports_tags"] = extract_block("check_azure_resource_supports_tags(p)")
    return sections


def extract_ansible_modules_map(ansible_lib: Path) -> dict[str, dict[str, Any]]:
    """Parse ansible_modules := { ... } from ansible.rego (best-effort regex)."""
    text = ansible_lib.read_text(encoding="utf-8")
    start = text.find("ansible_modules := {")
    if start == -1:
        return {}
    depth = 0
    i = start + len("ansible_modules := ")
    # find opening {
    while i < len(text) and text[i] != "{":
        i += 1
    if i >= len(text):
        return {}
    start_brace = i
    depth = 1
    i += 1
    while i < len(text) and depth:
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
        i += 1
    block = text[start_brace:i]
    modules: dict[str, dict[str, Any]] = {}
    # Each entry: "key": {"variants": {...}, "name_key": "..."},
    entry_re = re.compile(
        r'"([a-z0-9_]+)"\s*:\s*\{\s*"variants"\s*:\s*\{([^}]*)\}',
        re.DOTALL,
    )
    for m in entry_re.finditer(block):
        key, variants_body = m.group(1), m.group(2)
        variants = re.findall(r'"([^"]+)"', variants_body)
        modules[key] = {"variants": sorted(set(variants))}
    return modules


def extract_from_file(
    path: Path,
    platform: str,
    repo: Path,
    acc: DefaultDict[str, DefaultDict[str, list[dict[str, Any]]]],
) -> None:
    rel = _relative_to_repo(path, repo)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return
    meta = {"rule_path": rel, "rule_id": None}
    mp = path.parent / "metadata.json"
    if mp.is_file():
        try:
            meta["rule_id"] = json.loads(mp.read_text(encoding="utf-8")).get("id")
        except (json.JSONDecodeError, OSError):
            pass

    if platform == "terraform":
        for rt in TF_DIRECT.findall(text):
            acc["terraform"][rt].append({**meta, "context": "direct"})
        for rt in TF_MODULE_EQ_KEY.findall(text):
            acc["terraform"][rt].append({**meta, "context": "module_equivalent"})
        # dynamic: collect string literals that look like resource types when file uses resource[var]
        if "].resource[" in text:
            for rt in TF_STRING_LITERAL.findall(text):
                if len(rt) > 4:
                    acc["terraform"][rt].append({**meta, "context": "literal"})

    elif platform == "cloudFormation":
        for rt in CFN_TYPE_EQ.findall(text):
            acc["cloudFormation"][rt].append({**meta, "context": "type_eq"})
        if "resourceTypes" in text:
            for rt in CFN_TYPE_STRING.findall(text):
                if rt.startswith("AWS::"):
                    acc["cloudFormation"][rt].append({**meta, "context": "set_or_array"})

    elif platform == "k8s":
        for k in K8S_KIND_EQ_DOC.findall(text):
            acc["k8s"][k].append({**meta, "context": "document.kind"})
        for k in K8S_KIND_EQ_RES.findall(text):
            acc["k8s"][k].append({**meta, "context": "resource.kind"})
        for block in K8S_KINDS_SET.findall(text):
            for km in re.finditer(r'"([A-Za-z][A-Za-z0-9]*)"', block):
                acc["k8s"][km.group(1)].append({**meta, "context": "kinds_set"})
        for block in K8S_LIST_KINDS.findall(text):
            for km in re.finditer(r'"([A-Za-z][A-Za-z0-9]*)"', block):
                acc["k8s"][km.group(1)].append({**meta, "context": "listKinds"})

    elif platform == "ansible":
        for can in ANSIBLE_CANONICAL.findall(text):
            acc["ansible"][can].append({**meta, "context": "canonical"})

    elif platform == "cicd":
        # Strip comment lines before extracting to avoid false positives
        code_lines = [ln for ln in text.splitlines() if not ln.lstrip().startswith("#")]
        code_text = "\n".join(code_lines)
        seen: set[str] = set()
        for pat, ctx in [
            (CICD_ACTION_MAP_KEY, "map_key"),
            (CICD_ACTION_SET_MEMBER, "set_member"),
            (CICD_ACTION_STARTSWITH, "startswith"),
        ]:
            for action in pat.findall(code_text):
                if action not in seen and not action.startswith("docker://"):
                    seen.add(action)
                    acc["cicd"][action].append({**meta, "context": ctx})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    repo = Path(__file__).resolve().parent.parent.parent
    acc: DefaultDict[str, DefaultDict[str, list[dict[str, Any]]]] = defaultdict(
        lambda: defaultdict(list)
    )

    # Terraform rules
    tf_base = queries_dir() / "terraform"
    for p in _walk_query_regos(tf_base):
        extract_from_file(p, "terraform", repo, acc)

    # CloudFormation
    cfn_base = queries_dir() / "cloudFormation"
    for p in _walk_query_regos(cfn_base):
        extract_from_file(p, "cloudFormation", repo, acc)

    # Kubernetes
    k8s_base = queries_dir() / "k8s"
    for p in _walk_query_regos(k8s_base):
        extract_from_file(p, "k8s", repo, acc)

    # Ansible
    ans_base = queries_dir() / "ansible"
    for p in _walk_query_regos(ans_base):
        extract_from_file(p, "ansible", repo, acc)

    # CI/CD (GitHub Actions)
    cicd_base = queries_dir() / "cicd"
    for p in _walk_query_regos(cicd_base):
        extract_from_file(p, "cicd", repo, acc)
    # Also scan the CI/CD library for action references
    cicd_lib = libraries_dir() / "cicd.rego"
    if cicd_lib.is_file():
        extract_from_file(cicd_lib, "cicd", repo, acc)

    # Library: terraform tag lists
    tf_lib = libraries_dir() / "terraform.rego"
    lib_lists = extract_terraform_library_tag_lists(tf_lib)
    lib_meta = {"rule_path": str(tf_lib.relative_to(repo)), "rule_id": None}
    for list_name, types in lib_lists.items():
        for rt in types:
            acc["terraform"][rt].append({**lib_meta, "context": list_name})

    # Ansible module map for variant resolution in cross_reference / reporting
    ansible_lib = libraries_dir() / "ansible.rego"
    ansible_modules = extract_ansible_modules_map(ansible_lib)

    out = {
        "terraform": {k: v for k, v in sorted(acc["terraform"].items())},
        "cloudFormation": {k: v for k, v in sorted(acc["cloudFormation"].items())},
        "k8s": {k: v for k, v in sorted(acc["k8s"].items())},
        "ansible": {k: v for k, v in sorted(acc["ansible"].items())},
        "ansible_modules": ansible_modules,
        "cicd": {k: v for k, v in sorted(acc["cicd"].items())},
    }

    dest = out_dir() / "rule_targets.json"
    write_json(dest, out)
    print(f"Wrote {dest} ({sum(len(v) for v in acc['terraform'].values())} terraform refs, ...)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
