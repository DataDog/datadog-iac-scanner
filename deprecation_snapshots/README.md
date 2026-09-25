# deprecation\_snapshots

Baseline data used by `scripts/deprecation_watch/cross_reference.py` to detect removed or renamed upstream resource types.

- **cloudformation/resource\_type\_names.json** — all `AWS::*` type names from the CloudFormation Resource Specification. Auto-rotated weekly by the `deprecation-watch` workflow (opens a PR). Removals detected by diffing the live spec against this file.
- **Kubernetes** — fetched live from [FairwindsOps/Pluto `versions.yaml`](https://github.com/FairwindsOps/pluto) each run; no local snapshot.
- **Terraform** — uses live `terraform providers schema` output. Provider versions in `scripts/deprecation_watch/providers/main.tf` are auto-bumped monthly.
