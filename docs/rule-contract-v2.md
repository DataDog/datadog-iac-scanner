# IaC Rule Contract v2

IaC Rule Contract v2 defines a normalized, resource-centric 4-state input model, a `data.datadog.iac` helper facade, and a findings-only output format for Rego rules. It coexists with legacy `DatadogPolicy` rules without requiring `metadata.json` changes. Contract v2 is currently supported only for Terraform; rules for other platforms continue to use the legacy contract.

## Entry Rule & Selection

The scanner selects the contract from the Rego entry rule in `package datadog`:

- **Legacy**: `DatadogPolicy contains result if { ... }`
- **Contract v2**: `results contains result if { ... }`

A rule file must define one or the other (never both), and `results` must be a partial set rule whose findings are constructed with `data.datadog.output.format(resource, details)`.

## Input Model

Each evaluation unit represents one deployment boundary (for example, a Terraform root module or plan file):

```json
{
  "contract_version": "v2",
  "platform": "terraform",
  "scope_complete": true,
  "resources": {
    "aws_s3_bucket": [
      {
        "id": "root|r:0",
        "kind": "resource",
        "type": "aws_s3_bucket",
        "name": "logs",
        "address": "aws_s3_bucket.logs",
        "file": "/path/to/main.tf",
        "scope_complete": true,
        "attributes": {
          "bucket": "app-logs",
          "versioning": [{ "enabled": false }],
          "cidr_blocks": [{ "$unknown": true }, "0.0.0.0/0"]
        },
        "state": {
          "unknown": { "cidr_blocks.0": true },
          "null": { "acl": true },
          "written": { "bucket": true, "acl": true, "versioning": true }
        },
        "derived": {
          "json": { "policy": { "Version": "2012-10-17", "Statement": [] } },
          "json_unknown": { "policy": { "Statement.0.Principal.AWS": true } },
          "json_refs": {
            "policy": {
              "Statement.0.Principal.AWS": [
                { "kind": "data", "type": "aws_caller_identity", "name": "current", "attr": "account_id" }
              ]
            }
          }
        },
        "relations": {
          "targets": { "kms_key_id": { "ids": ["root|r:2"], "complete": true } },
          "related": { "aws_s3_bucket_versioning": { "bucket": { "ids": ["root|r:1"], "complete": true } } },
          "referrers": { "bucket": { "ids": ["root|r:1"], "complete": true } }
        },
        "platform": {
          "terraform": {
            "source_kind": "hcl",
            "provider_id": "root|p:0",
            "module_address": "",
            "instance_key": ""
          }
        }
      }
    ]
  },
  "by_id": { "root|r:0": {} }
}
```

Optional fields:
- `input.arguments` is attached only when rule arguments are configured.
- `platform.terraform.computed` is populated for Terraform Plan JSON (`source_kind == "plan"`) and read via `data.datadog.terraform.computed(res, path)`.
- `platform.terraform.source_null` records canonical paths that are literal nulls in Plan configuration. `data.datadog.terraform.source_is_null(res, path)` reads these without changing runtime attributes or null state; HCL falls back to `iac.is_null_value`. Ambiguous nested array paths are omitted unless Plan values identify their configured block element.

## Authoring Model & Unknown-Value Semantics

Attributes carry explicit 4-state provenance (`known`, `unknown`, `null`, `absent`):

- **Known** values appear in `attributes` (nested blocks are normalized to arrays at every depth across HCL, `.tf.json`, and Plan JSON).
- **Unknown** scalar and object attributes are omitted from `attributes` and recorded in `state.unknown`. Inside lists, unknown elements are preserved as `{"$unknown": true}` slots so concrete sibling indices stay aligned with `state.unknown`, source ranges, and remediation extraction. Collections with unknown size (such as unresolved `dynamic` blocks or maps with unknown keys) are recorded in `state.incomplete_collections`. In `.tf.json`, `dynamic` blocks are not expanded: their generated block collections are recorded as incomplete (and unknown when no static block of that type is written), so absence and collection checks over them stay undefined.
- **Null** attributes are omitted from `attributes` and recorded in `state.null`. Explicit JSON nulls inside derived JSON documents are retained as JSON `null`, including in wholly known subtrees of a partially known document.
- **Absent** attributes appear in neither `attributes`, `state.unknown`, nor `state.null`.

Terraform Plan rules can opt into provider-computed values through
`data.datadog.terraform.computed_view(resource)`. This stateful view retains
unknown and null provenance and uses the original resource paths. The
`computed(resource, path)` helper uses the same Plan provenance, so a literal
object shaped like an internal unknown marker remains known unless
`after_unknown` marks that path unknown. The view contains
the computed subset; use the ordinary resource for configured fields. Use
`value_view(resource_or_block, path)` to select a view for a particular field:
known unset Plan fields fall back to their computed view; configured unknowns
remain unknown. Read the same relative path from that view and keep the finding
bound to the original resource. Nested views retain their full source paths.

Plan JSON keeps provider-computed fields separate from written configuration at
every nesting level. A literal written in configuration remains known (or null)
when the provider marks its eventual default as `after_unknown`. Known planned
values remain authoritative. Plan configuration omits `dynamic` blocks, so a
planned nested element that no configuration block of its type matches keeps
its unknown leaves unknown rather than treating them as provider-computed. Of
its known leaves, only the fields that some configuration block of that type
writes stay in the ordinary attributes; the others (provider defaults) appear
only in `computed_view`. A nested block type written only through `dynamic` blocks has no configuration
entry at all, so Plan input cannot distinguish it from a provider-computed
block: its elements appear only in `computed_view` (and through `value_view`),
not in the ordinary resource attributes. Rules that must see such blocks
should read them through `value_view`, or rely on HCL or `.tf.json` input
(Plan input is experimental, behind `--x-terraform-plan`). Source string templates remain available through
`iac.template_parts`, including when the provider stores a digest instead. Configuration-only provisioners use the
same nested block views, with nonconstant expressions unknown. Deferred scalar
data reads preserve their configured inputs and reference identity when absent
from Plan value sections; their computed outputs remain unknown. Counted/keyed
data declarations and unobserved expanded module instances are never invented.

**Scope of guarantee:** OPA evaluates standard 2-valued Rego; Contract v2 does **not** claim automatic 3-valued soundness for arbitrary raw Rego expressions (such as raw `not r.attributes.x`, `object.get` defaults, or negated custom helpers reading raw attributes). Instead, rules achieve fail-closed unknown behavior without manual unknown guards by authoring through the `data.datadog.iac` facade and verifying unknown safety in CI with `pkg/ruletest` unknown-mutation helpers (`MutateAttributesToUnknown` and `MutateAttributePairsToUnknown`).

## Standard Libraries

- **`data.datadog.output`**
  - `format(resource, details)` builds a finding bound to `resource`. Supported `details` keys: `path` (attribute path), `after` (desired value for replacement fixes; the scanner extracts `"before"` from the source AST), `remediation`, `remediationType`, and `overrideKey`. Scanner-owned identity and classification fields are reserved and stripped from `details`; they cannot override the rule or resource identity.
- **`data.datadog.iac`**
  - **Absence & state**: `get`, `read`, `is_known`, `all_known`, `is_complete`, `is_unknown`, `is_null_value`, `is_written`, `is_absent`, `is_unset`, `is_empty`.
  - **Exemptions & comparisons**: `is_true`, `is_false`, `equals`, `not_equals`, `not_in`.
  - **Nested blocks & collections**: `blocks` (returns stateful block views preserving parent 4-state provenance at any depth), `path_of`, `known_items`, `indexed_items` (object elements retain state provenance and paths), `complete_items` (defined only when all elements are known and the collection is closed), `length` (defined when collection size is known, including closed arrays with unknown element values), `object_keys` (the exact closed key set, including keys with unknown or null values).
  - **Embedded JSON & string templates**: `json_doc`, `json_refs`, `json_has_unknown`, `template_parts`.
  - **Intra-unit relations**: `targets`, `targets_complete`, `targets_via`, `targets_via_complete`, `related`, `related_complete`, `no_related`, `referrers`, `referrers_complete`, `no_referrers`, `no_resources`.
- **`data.datadog.terraform`**
  - `provider_config(res)`, `same_provider_config(a, b)`, `computed(res, path)`, `computed_view(res)`, `value_view(res, path)`, `source_is_null(res, path)`, `filter_expr(res)`, `filter_pattern_known(res)`, `source_kind(res)`.
  - `same_provider_config` compares Terraform provider configuration IDs, including nested views. Two resources without an explicit provider ID match the ambient default provider.

## Safe Negative and Collection Checks

The facade predicates express proofs; they are not total Boolean values to
negate. For example, `not iac.is_true(r, ["enabled"])` succeeds when `enabled`
is unknown. Use `iac.not_equals(r, ["enabled"], true)` when absent/null values
also select an insecure provider default, or `iac.is_false` when only an
explicit false value is insecure. `is_unset`, `is_absent`, `not_equals`, and
`not_in` are undefined when the queried path is beneath an incomplete
collection, so an open collection cannot prove absence or an exemption.
`iac.read` reports `unknown` rather than `absent` for paths beneath an
incomplete collection.

Use `iac.blocks` for nested blocks and `iac.known_items` / `iac.indexed_items`
for array elements. Object elements are stateful views: access their fields
through `iac`, and use `iac.path_of` to recover the original resource path.
Treat these views as opaque: internal `_dd_` fields carry provenance, while
`iac.get` and `iac.object_keys` preserve the original source keys and values.
Unknown and null slots are identified by recorded state; a literal object
that resembles an internal placeholder remains known data.
JSON document views use paths relative to that document and carry its own
unknown flags. Prefix the source attribute path when binding a JSON finding
(for example, `array.concat(["policy"], iac.path_of(statement, []))`).
For a universal check, sort, or negative membership test, first require
`iac.complete_items`; filtering out unknown elements cannot prove the whole
collection safe or unsafe. For key-only policies, use `iac.object_keys`: unknown
values do not hide known keys. The function is undefined for a whole-object
unknown or an open key set, so it cannot establish missing keys in those cases.

Relation lists contain established matches, while completeness is a separate
proof. Use `no_related`, `no_referrers`, or the corresponding completeness
helper before inferring absence or applying universal checks. Nested paths
without numeric indices aggregate the matches and incompleteness of all
matching block instances. `targets_via(r, path, "name")` distinguishes a
reference reading a target's name from one reading its ARN. Literal names
match within one provider configuration, with globally unique S3 bucket names
as the exception; explicit Terraform references remain authoritative. A known
source literal can still match an unknown target name: both the source target
list and that candidate's reverse list remain incomplete, without inventing
an edge or tainting unrelated attributes and provider configurations.

## Testing Local Rules

Both published tests and local assets use `pkg/ruletest/harness`. Contract v2
uses the same independent fixture roots through either source; legacy published
fixtures retain their aggregate-root compatibility mode. A local assets directory contains `queries/` and `libraries/`:

```bash
datadog-iac-scanner test-rules --rules-dir /path/to/assets -t Terraform --unknown-mutations
```

A local `-q` source is classified as default only when its cleaned absolute path equals the scanner's `assets/queries` directory. Equivalent relative and absolute spellings compare identically; other local rule roots remain custom.

Each top-level positive/negative fixture is a separate deployment root.
Subdirectories group multi-file roots. `--unknown-mutations` replaces written
HCL attributes with unknown expressions and rejects findings introduced by
that information loss. Add `--unknown-pairs` to check simultaneous attribute
pairs. Independent findings may remain, including when only a remediation
input becomes unknown. Plan JSON and `.tf.json` uncertainty also need explicit
fixtures; HCL mutations do not replace those adapter checks.

## Decoupled Optional Remediation

For standard replacement fixes, pass `"path"` and `"after"` to `dd_output.format(resource, details)`; the scanner derives `"before"` from the source AST and omits the fix when the source expression is dynamic.

`iac.template_parts(resource, path)` returns ordered `{known, value?}` chunks.
For a string leaf inside embedded JSON, pass its complete source path on the
original resource (for example `["policy", "Statement", 0, "Principal", "AWS"]`).
An optional `ref` records an exact traversal or alias as `{kind, type, name,
attr}`. Opaque transformations carry no such identity proof; a reference
appearing inside a function is not the value returned by that function.
Check `known` before using a chunk; unknown chunks retain their indices. This
allows a known prefix or suffix to prove a condition without inventing the
unknown part of a string.

`after` is replacement source text. Include HCL quotes for string values (for
example, `"after": "\"private\""` or `"after": json.marshal("private")`);
booleans and numbers use source strings such as `"true"` and `"14"`. The scanner
extracts `before` from the original expression, including its quotes.

When a rule computes custom remediation text from attributes that may be unknown, define an explicit optional `remediate(resource, finding)` function in `package datadog` rather than reading those attributes inside `results`:

```rego
remediate(bucket, _) := {
	"remediation": json.marshal({
		"before": json.marshal(iac.get(bucket, ["acl"])),
		"after": json.marshal("private"),
	}),
	"remediationType": "replacement",
}
```

Custom replacement payloads must encode a JSON object with `before` and `after` source strings. Prefer the standard `after` field when the scanner can derive the original source.

`remediate` runs after `results` has already proven the finding. If `remediate` is undefined (for example when `iac.get` encounters an unknown attribute), only the remediation is omitted—the proven finding is preserved.

## Root Isolation

Absent resource types are omitted from `input.resources`. For an `every` quantifier over an optional type, use `object.get(input.resources, type, [])` so a known empty inventory remains an empty collection. Absence conclusions still require the appropriate root or relation completeness proof; an empty fallback does not establish completeness.

Every Terraform root module (or plan file) is an independent evaluation boundary. Root discovery uses the same module-call and external-module selection in pure-v2 and mixed legacy/v2 scans, so adding a legacy Terraform rule does not change the v2 root set. Every projected resource always includes its computed `relations`, including in resource-scoped chunks; relation reads do not depend on which rules are loaded and do not by themselves force root scope. Only pure single-resource rules (targeting one concrete resource type via a single top-level positive iteration in `results`, with no providers, `no_resources`, self-joins, or collection aggregates over `input.resources`) are batched across roots. Rules that read root-level data such as `input.by_id` or `input.scope_complete`, or perform cross-resource joins, evaluate one root at a time.

## Limits and failure behaviour

Contract v2 evaluates Terraform HCL, `.tf.json`, and Plan JSON only. A Terraform root is marked incomplete when configuration files are skipped or fail to read or parse, or when module evaluation leaves part of the root unresolved. Incomplete scope cannot establish absence: the facade checks described above remain undefined where their proof depends on an incomplete collection. Positive checks over known values can still produce findings. Contract v2 does not emit findings by guessing at values or resources it could not evaluate.

The scanner logs root/plan evaluation failures and exposes additive counters in scan metadata under `contract_v2`: `roots_failed`, `plans_failed`, and `roots_scope_incomplete`. The last counter reports roots whose scope could not be fully evaluated. A failed root or plan is skipped; consult the warnings and metadata rather than treating a missing finding as proof of safety. Contract v2 findings keep links to matching resource occurrences when an inventory is requested.

Failed rule compilations are listed in `rule_stats.failed_to_compile`, and runtime or finding-decode failures are listed separately in `rule_stats.failed_to_evaluate`. Failures from custom rules are warning-only. Only a compile failure from the default rule source is recorded in `default_rule_compile_failed`, and the scanner exits with engine error code `126` for that case. When `--metadata-path` is supplied, scan metadata is written before that exit; otherwise the failure is reported in logs. Runtime/decode failures and custom-rule compile failures do not change the scan exit code.

The existing legacy Terraform plan parser's line reporting is unchanged. Contract v2 Plan JSON locations are derived from the original plan file bytes.

## Rule validation

Contract v2 validation reserves the top-level names `iac`, `output`, and `terraform` for its libraries. Do not define rules with those names in `package datadog`. The `contract/schema-path` Regal check validates Terraform resource/data types and literal attribute paths when a generated provider-schema index is supplied. Facade path arguments may be a string or an array of literal string/number steps. Dynamic paths and paths whose resource type cannot be inferred are not checked; without schema data the check is a no-op. With schema data, Regal emits a non-failing JSON notice per module reporting checked and unchecked facade calls and the unchecked percentage; dynamic paths and uninferred resource types contribute to the unchecked count. If a provider-version difference requires an exception, suppress it with a reason, for example `# regal ignore:schema-path # reason: provider-version compatibility`.

The facade accepts Terraform booleans and the strings `"true"`, `"false"`, `"1"`, and `"0"` for boolean checks, matching Terraform's string-to-bool conversion; strings such as `"yes"` and `"on"` are not interpreted as booleans. `output.format` consumes `path` as the finding location and strips scanner-owned fields from the returned details: `_dd_id`, `documentId`, `resourceType`, `resourceName`, `searchKey`, `id`, `queryName`, `severity`, `platform`, `category`, `descriptionID`, and `cloudProvider`. A supplied finding `path` must be a string or an array of string/number path steps. Invalid path values are reported as `contract/invalid-path` and are not emitted as resource findings.

`test-rules` now applies its order-determinism check to legacy rules as well as Contract v2 rules, and uses a three-minute rule-test timeout. This can expose order-sensitive rules that were not detected by the previous test behavior.

## Example Rule

```rego
package datadog

import rego.v1

import data.datadog.iac
import data.datadog.output as dd_output

results contains result if {
	some cluster in input.resources.aws_rds_cluster
	iac.not_in(cluster, ["engine_mode"], {"serverless", "global"})
	iac.is_false(cluster, ["storage_encrypted"])
	result := dd_output.format(cluster, {
		"path": ["storage_encrypted"],
		"after": "true",
	})
}
```

## Offline Bundles

`fetch-bundle` keeps default and custom rules in one merged `rules.json` for compatibility with older scanners, and marks each rule's origin. When a bundle predates those markers, its rules are treated as custom because their origin is unknown; compile failures are listed and warned but do not trigger exit code `126`. Fetching a new bundle restores default-rule compile gating.
