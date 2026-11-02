# Terraform rule input contract: design

Date: 2026-11-01
Repositories and branches (both named `chakib.hamie/terraform_rule_input_contract`):

- Scanner: `datadog-iac-scanner`, branched from the head of PR #465 (`268882d29`, Terraform-semantic finding identity).
- Rules: `datadog-iac-scanner-default-rules`, branched from `main` (`e1b5d04cf`).

## Intent

Terraform rules rebuild Terraform semantics themselves because the scanner does not hand them what it already computed. They parse `${...}` text, split reference strings on dots, guess module scope from the directory, walk the plan configuration tree and keep separate branches for source and plan input. About 4,800 lines across 205 Terraform rule files exist for this, and the name-only joins cause missed findings.

Two examples were reproduced:

- `s3_bucket_without_versioning` misses an unversioned `aws_s3_bucket.b` when another root also declares `aws_s3_bucket.b` with versioning.
- `security_group_is_not_configured` misses subnets when one module is called twice with different `count` values on its association.

The scanner already evaluates modules, variables, locals, `count` and `for_each`. It then discards the results that matter for relationships, and it gives rules three differently shaped inputs: the per-file converter, evaluated module documents and plan JSON.

This work makes the scanner the single owner of Terraform semantics. Rules shrink to the security question. The scanner shrinks too, by removing duplicated evaluators and dead paths.

Both branches are the definitive next versions of the scanner and the rules, to be split into reviewable PRs afterwards. Each rule test must pass when the rules branch runs against the scanner branch. Rules tested against the released scanner may fail; that is accepted.

## Goals

1. **One evaluator.** Evaluated values are authoritative for every block of every successfully evaluated root module: resources, data, ephemeral, variables, outputs, locals, module calls and provider blocks. The per-file converter keeps only the JSON shape, line information (`_dd_lines`) and plain `${...}` text when a root cannot be evaluated.
2. **Terraform-true instances.** A resource whose `count`/`for_each` is known to produce zero instances in every evaluated call disappears from the scan. Unknown counts keep today's single placeholder instance.
3. **Per-resource metadata `_dd_meta`.** Every resource, data and ephemeral object carries `_dd_meta`, with the same shape for source and plan scans (see Contract).
4. **Root-aware findings.** A rule result may name the root module it applies to. The engine then attributes the finding to that root only, instead of copying it to every root that shares the document.
5. **Uniform plan input.** In plan scans, unknown values are present-but-unknown, `null` values and unconfigured empty nested blocks are absent, and `_dd_meta` replaces `_dd_tfplan_meta`.
6. **Cleanups made possible by 1–5.** Each is removed in the branch:
   - the module equivalence table (`ParseAllModuleVariables`, `generateEquivalentMap` and the enrichment cache in `pkg/parser/terraform/modules/modules.go`; `MergeModulesData` in `pkg/engine/source/source.go`; the `data.common_lib.modules` injection);
   - the string-only `resolveExpr` resolver in `modules.go`, if `list-modules` can take module sources from the evaluator;
   - the dead `ScanParams.TerraformVarsPath` plumbing;
   - `joinPlainRootSiblings` and the plain-root special case;
   - the plan call-site plumbing (`call_site_expressions`, `referencedArgumentChain` and related functions);
   - `_dd_tfplan_meta`, `json.PlanAddresses` and the plan-address branch of `terraform_scope.go`;
   - the evaluator's three pass-through wrappers;
   - instance-name string re-parsing (`parseResourceInstanceKey`, `ResourceBaseName` callers), replaced by a structured instance key;
   - the five separate "which names does this expression read" analyses, replaced by one shared helper;
   - the converter-side variable, local and data-source evaluation that duplicates `tfeval`.
7. **Rules migrated.** Every Terraform rule and library helper that reconstructs addresses, scopes, references, unknowns or plan shape is rewritten on `_dd_meta`. Helpers with no remaining caller are deleted. Helpers carrying provider knowledge stay, for example: an S3 bucket's id is its name, the Azure resource ID format, IAM policy parsing, CloudWatch filter patterns.

## Non-goals

- Changing resource keys in documents. HCL keeps base names, plans keep `module.x.name` / `name[0]` keys. Line detection and fingerprints depend on them. Identity comes from `_dd_meta.address`.
- Changing finding identity or fingerprints produced by PR #465 for findings that still exist.
- A relationship DSL or a relations library in Rego. Joins stay a few lines of plain Rego on `_dd_meta`.
- Provider or region metadata in `_dd_meta`. This is a possible follow-up that would delete the CloudWatch region helpers.
- Remote module download behaviour, and the `--x-terraform-plan` flag gating plan parsing.
- Non-Terraform platforms.

## Anti-goals

These would make the work a failure even if it technically works:

- Any silent wrong result: a cache entry shared by inputs that differ, or a finding attributed to a root where it does not hold.
- Losing the PR #468 memory characteristics: cross-root deduplication of identical module documents must keep working.
- A migrated rule that floods false positives on an older scanner without `_dd_meta`. Migrated rules must produce nothing when `_dd_meta` is missing.
- New `# regal ignore:` suppressions, or rules flagged by `./tool.sh perf`.
- Replacing rule-side workaround code with an equivalent library of workarounds.

## Contract

`_dd_meta` is a key inside each resource, data and ephemeral object (`doc.resource.<type>.<name>._dd_meta`):

```json
"_dd_meta": {
  "address": "module.a.azurerm_subnet_network_security_group_association.s[0]",
  "root_modules": ["envs/prod"],
  "unknown": { "subnet_id": true },
  "references": { "subnet_id": ["module.a.azurerm_subnet.s"] }
}
```

- **`address`:** the absolute instance address within its root module, written as Terraform writes it. Data sources start with `data.`, ephemeral resources with `ephemeral.`. It must be byte-identical to the `resource_id` PR #465 puts on findings.
- **`root_modules`:** every root module the document stands for. Source scans use the repository-relative root directory and plan scans the repository-relative plan file path, the same strings as `root_module` in PR #465. It is a list because identical module documents are shared across roots. Rules join on the pair `[root, address]`.
- **`unknown`:** values Terraform would only know at apply time, in the same shape as Terraform's `after_unknown`. Only `true` leaves are present: nested blocks become lists of objects, and a whole unknown value is `true`. Omitted when nothing is unknown.
- **`references`:** for each attribute path that reads another resource, data or ephemeral instance, the absolute instance addresses it reads. The shape mirrors the values; leaves are lists of addresses.
  - References are followed through locals, variables and module calls, module outputs, `each`, `count.index`, literal indexes and conditionals. Only resource, data and ephemeral addresses appear.
  - When the instance cannot be determined (for example a dynamic index), every instance of the target is listed.
  - The key is absent when the source cannot be traced, for example a root variable with no value, or a module that was not fetched.
  - References are recorded whether or not the value is known.
- **Rule results:** a result may carry `"rootModule": "<root>"`. When present, the finding is attributed only to that root. When absent, today's behaviour holds (every caller of a shared document).
- **Unknown values in documents:**
  - Source scans keep today's `${<use-site text>}` rendering, falling back to `${__dd_unknown__}`.
  - Plan scans fill every unknown leaf with `${__dd_unknown__}`.
  - Rules decide unknownness from `_dd_meta.unknown`, never from the text.
- **Plan absence:**
  - `null` values are dropped, because Terraform treats null as unset.
  - An empty nested-block list is dropped when the configuration has no expression for it.
- **Bookkeeping:**
  - `_dd_meta` is a block-level key that is never a label, so it need not be in the label-level bookkeeping sets; a block literally named `_dd_meta` is content.
  - `root_modules` is excluded from the content hash used for cross-root deduplication.
  - `_dd_meta` is visible to rules; it is never stripped.

### Example: the NSG rule after migration

```rego
associated_subnets contains [root, address] if {
	some doc in input.document
	some association in doc.resource.azurerm_subnet_network_security_group_association
	some root in association._dd_meta.root_modules
	some address in association._dd_meta.references.subnet_id
}

DatadogPolicy contains result if {
	some doc in input.document
	some name, subnet in doc.resource.azurerm_subnet
	some root in subnet._dd_meta.root_modules
	not [root, subnet._dd_meta.address] in associated_subnets
	...
	result := {..., "rootModule": root}
}
```

## Constraints

- **Scanner repository is public.** No customer names, internal links or private content in code, fixtures, commits or PR text.
- **Scanner checks:**
  - `go test $(go list ./... | grep -v /e2e) -count=1`
  - `go test ./test/e2e -count=1`
  - `golangci-lint run -c .golangci.yml --timeout 20m` (v2.9.0) before each commit touching Go.
  - Any new dependency is recorded in `LICENSE-3rdparty.csv`.
- **Scanner worktree path** must end in a directory named `datadog-iac-scanner`, for the tests that locate the repository root.
- **Rules checks:**
  - `opa fmt --fail .` and `regal lint --fail-level error .`
  - `./tool.sh verify` and `./tool.sh test`
  - `./tool.sh perf --changed-since origin/main`, which must not flag a changed rule.
  - Joins follow the performance guidance in the rules repo `CLAUDE.md`, for example precomputed partial sets.
- **Rules are served to every scanner version, with no version gating.** A migrated rule must not report when `_dd_meta` is missing.
- **The rules repository pins the scanner in `go.mod`.** During development the rules worktree uses an untracked `go.work` including the scanner worktree. The final rules branch requires the pushed scanner branch commit.
- **Commit messages** are one sentence and never use the name KICS. Branch names are prefix plus underscores, with no ticket keys.
- **Scanner performance:**
  - The large-monorepo memory profile from PR #468 (20k versus 197k documents) must not regress.
  - The evaluation cache, the local memo and `equalValues` must never see marked cty values.

## Approaches

### References

Three approaches were considered:

- **Marks in the main evaluation.** Tag resource values with cty marks and let evaluation propagate them, the way Terraform propagates `sensitive`. Rejected: `ctyjson.Marshal` fails on marked values, and the cache key then writes `marshal-error(<type>)` (`tfeval/cache.go:222-233`). Two different inputs would share one cache entry, silently. Cached attributes are also shared across module addresses, so stored addresses would go stale. Every evaluator call site that converts values would also have to tolerate marks.
- **Static tracing.** Walk expression traversals through scopes, building on `module_arguments.go`'s `valueAnalyzer`. Kept as the fallback: it cannot pick the instance selected through `for` expressions, `merge` or `zipmap` without evaluating them, and it reports `module.*` reads as ambiguous.
- **Shadow evaluation at document time (chosen).** After the main evaluation, for each resource instance being turned into a document:
  1. Build a provenance context from the module scope's evaluation context, in which every resource, data and ephemeral instance object is marked with its own absolute address.
  2. Re-evaluate the resource's attribute expressions in that context, reaching locals through the scope and module inputs through the call chain's call-site bodies.
  3. Collect the marks per path with `UnmarkDeepWithPaths`.

  Marks never enter the main evaluation or any cache. This follows the existing pattern: the renderer already re-evaluates unresolved expressions against the scope at document time.
  - **Phantom attributes.** Computed attributes that no configuration sets, such as `.id`, become marked unknown attributes on the injected instance objects. The set comes from scanning every traversal in the evaluated module tree.
  - **Spike gate.** The first references task is a measured spike on a large multi-root repository fixture. If the pass costs more than 25% of module-evaluation time or memory, the static-tracing fallback is used.

### Plan references

Resolved in the plan parser from `configuration` and the module tree:
- Prefix the module instance.
- Follow `var.x` to the call-site argument and `module.m.out` to the child output.
- Prefer `x[0]` over `x`.

Locals cannot be followed from plan JSON, because Terraform does not include locals in the plan configuration. References through a local are absent in plan scans.

### Zero instances

Dropped, matching Terraform. The evaluator must report "zero in every evaluated call" separately from "unresolved", which today both return `nil` from `expandBlock` (`tfeval/evaluator.go:1019`). Directories that were not fully evaluated keep today's as-written behaviour.

### Rollout to old scanners

Migrated rules are silent without `_dd_meta`. Old scanners may miss findings, and never get false positives. There is no dual-branch fallback and no version gating.

### Plan unknowns

Present-but-unknown, matching Terraform's model: the attribute exists, its value is unknown, and it is reported in `unknown`.

## Decided

- **Root routing.** A finding is attributed only to the root named by `rootModule`. The engine's identity prediction and supersede logic (`findings.go`) must apply the same filter.
- **Plan line detection.** A searchKey pointing at an attribute absent from the plan file resolves to the nearest ancestor that exists, or to the resource header. It must not search forward into `after_unknown` or `configuration` text.
- **Rule resource-type filter.** `rule_resource_types.go` stays a performance filter. A type no rule names is not evaluated, and its references still appear as addresses.
- **One-evaluator fallback.** When a root cannot be evaluated, the converter renders values as `${...}` text with no variable, local or data substitution.
- **Shared Terraform graph helpers.** `DataKey`, `DataCycles`, `BodyTraversals` and `LocalTraversalName` move from `pkg/parser/terraform` to a new leaf package, so that `tfeval` no longer imports the converter's package.
- **Line information stays the converter's job.** Evaluated values are patched into the converter's documents, which keep their ids and `_dd_lines`. Expanded instances keep today's layer documents.
- **Development linking.** The rules worktree links to the scanner worktree with an untracked `go.work`.

- **Untraceable references are uncertain, not absent.** When a join attribute is configured but has no `references` entry, the rule treats every finding that join would produce in that root as uncertain and does not report it. In the NSG example, an association whose `subnet_id` is untraced suppresses "unassociated subnet" findings in its root. Over-reporting is the failure mode to avoid. Each migrated join rule has a negative fixture for this case.
- **Metadata in fallback roots.** When a root cannot be evaluated, or a file belongs to a directory evaluated only as its own root, resources still carry `address` (`<type>.<name>`, with the module prefix when known) and `root_modules` (the evaluated root directories that reach the file, else the file's own directory). `references` and `unknown` are absent there, so joins fall under the uncertainty rule above. Directories no root calls are evaluated as their own root, as today.
- **Static-tracing fallback contract.** If the spike selects static tracing, a reference whose instance cannot be selected lists every instance of the target, and a reference through a module output lists the output's possible sources. Over-approximation can only hide findings in "is X referenced" rules, never invent them.
- **Unknown in source scans.** A value is unknown when evaluation leaves it unknown: root variables with no default and no value, attributes of resources only known after apply, and anything derived from them. This matches what `terraform plan` would report, given values for every variable that has one.

## Left to the builder

- Internal type and function names, file layout inside the packages named above, and test fixture design.
- How the shared "reads" helper is shaped, as long as all five current analyses use it.
- The structured instance key's Go type.
- The order of rule migrations, as long as each rule family moves together with the deletion of the helpers it used.
- How the phantom attribute set is computed and cached per module tree.

## Owner decisions

- `data.common_lib.modules` and `_dd_tfplan_meta` are deleted outright, with no compatibility shim.
- The `// kics_terraform_vars: <path>` comment directive is ported to the evaluator: the named file's values apply to the root that contains the commented file, before auto-loaded `.tfvars` files.
