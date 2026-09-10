# deprecation\_watch

Detects upstream IaC deprecations (Terraform, CloudFormation, Kubernetes, Ansible) and abandoned GitHub Actions (CI/CD) that affect Rego rules in this scanner, and opens deduplicated Jira tickets for any that need attention.

## How it works

1. **extract\_rule\_targets.py** — scans every `query.rego` to build a map of resource types / kinds / modules / action references each rule targets.
2. **fetch\_deprecations.py** — pulls live deprecation signals from upstream sources (Terraform provider schema, AWS CFN spec, Pluto `versions.yaml`, Ansible collection `runtime.yml`, GitHub API for action repo status).
3. **cross\_reference.py** — compares fetched deprecations against rule targets. Rules that already cover both the deprecated and replacement type are suppressed.
4. **create\_jira\_tickets.py** — creates one Jira ticket per finding, deduplicated by a stable label hash so re-runs never create duplicates for the same issue.

## Workflows

| Workflow | Schedule | What it does |
|---|---|---|
| `deprecation-watch` | Weekly (Mon 9 AM UTC) | Runs the full pipeline, creates Jira tickets, and opens a PR to rotate the CFN snapshot |
| `deprecation-watch-bump-providers` | Monthly (1st, 9 AM UTC) | Bumps Terraform provider version pins and opens a PR with the updated lockfile |

Both can also be triggered manually via `workflow_dispatch`.

## Local run

```bash
cd scripts/deprecation_watch
pip3 install -r requirements.txt
python3 extract_rule_targets.py
python3 fetch_deprecations.py --platforms cloudformation,k8s,ansible
# Terraform requires the CLI on PATH (or set TERRAFORM_PATH)
TERRAFORM_PATH=/path/to/terraform python3 fetch_deprecations.py --platforms terraform
python3 cross_reference.py
python3 cross_reference.py --print-findings   # tab-separated summary to stdout
python3 create_jira_tickets.py --dry-run
```

## Jira environment variables

| Variable | Required | Default |
|---|---|---|
| `JIRA_BASE_URL` | yes | — |
| `JIRA_EMAIL` | yes | — |
| `JIRA_API_TOKEN` (or `JIRA_TOKEN`) | yes | — |
| `JIRA_PROJECT_KEY` | no | `K9VULN` |
| `JIRA_ISSUE_TYPE` | no | `Task` |

## Suppression logic

A finding is suppressed (not flagged) when the rule already handles both the deprecated resource and its replacement:

- **Terraform / CloudFormation** — if the same `query.rego` file has a direct `input.document[i].resource.<TYPE>` block for a non-deprecated type with the same provider/service prefix, the deprecated reference is suppressed.
- **Kubernetes** — rules that match by `kind` alone (not `apiVersion`) automatically work with both old and new API versions, so deprecated-apiVersion findings are suppressed. Fully removed kinds are always flagged.
- **Ansible** — if the `ansible.rego` module map already lists both the deprecated alias and the redirect target as variants, the finding is suppressed.
- **CI/CD** — no suppression. Any non-active action repo (archived, deleted, moved) that is referenced by a rule produces a finding.

## Terraform lockfile

To regenerate `providers/.terraform.lock.hcl` locally:

```bash
cd scripts/deprecation_watch/providers
terraform init -upgrade
terraform providers lock -platform=linux_amd64 -platform=darwin_amd64
```
