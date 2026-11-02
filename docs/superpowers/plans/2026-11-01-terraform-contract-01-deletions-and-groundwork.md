# Terraform contract, plan 1: deletions and groundwork — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the dead module table, the dead variable-file plumbing and the evaluator's pass-through wrappers. Then give the evaluator the shared pieces the later plans build on: one leaf package for reference analysis, and a structured instance key.

**Architecture:**
- These are behaviour-preserving refactors of the scanner. The only output change is that rules no longer receive `data.common_lib.modules`.
- A new leaf package, `pkg/parser/terraform/tfrefs`, owns the question "which Terraform objects does this expression read", so that `tfeval` stops importing the per-file converter package.
- Instances carry their base name and key as fields instead of re-parsing `name[...]` strings.

**Tech Stack:** Go, `hashicorp/hcl/v2` (`hclsyntax`), `zclconf/go-cty`, OPA.

**Spec:** `docs/superpowers/specs/2026-11-01-terraform-rule-input-contract-design.md`

## Plan series

Each plan is written when the previous one has landed, because its interfaces depend on the previous result (plan 4 depends on the spike):

1. This plan: deletions and groundwork.
2. Evaluated values for every resource of an evaluated root, and dropping zero-instance resources.
3. `_dd_meta.address` and `root_modules`, rule-result `rootModule` routing, and the fallback-root metadata.
4. References: the measured spike, then source references, then the plan resolver.
5. Plan input: unknown placeholders, `_dd_meta.unknown`, dropping nulls and empty blocks, and the line-detection fallback.
6. Rules repository: migrations and library deletions. This plan runs in the rules worktree against the scanner worktree through `go.work`.
7. One evaluator for all blocks, the ported `kics_terraform_vars` directive, and shrinking the converter.
8. Removing `_dd_tfplan_meta` and the plan-address path.

## Global Constraints

- The scanner repository is public: no customer names, internal links or private content in code, fixtures or commits.
- Commit messages are one sentence and never contain the name KICS.
- Run `golangci-lint run -c .golangci.yml --timeout 20m` (v2.9.0) before each commit that touches Go.
- Unit suite: `go test $(go list ./... | grep -v /e2e) -count=1`, with every package `ok`. In-process end-to-end: `go test ./test/e2e -count=1`, `ok`.
- Run every command from the worktree root `.../.worktrees/terraform_rule_input_contract/datadog-iac-scanner`. The last path element must stay `datadog-iac-scanner`.
- Do not change the strings of finding identities, resource addresses or document keys.
- Never add marked cty values to the evaluation cache, the local memo or `equalValues`.

## Review Focus

1. A `for_each` key containing `$`, `%`, `"`, `\`, non-ASCII characters, or the empty string must give the same instance name byte for byte as today. Task 6 pins this.
2. Splats (`aws_x.y[*].id`), indexes with a dynamic key (`aws_x.y[var.k]`), `self`, `each`, `count`, `path`, `terraform` and `data.` roots must be classified exactly as before by each ported analysis. Task 5 pins this.
3. Rules with custom `InputData` must still compile against their own data, and the compiled-query cache must still key on the base data hash. Task 1 pins this.
4. A data-source cycle through locals must still be detected after the helpers move. Task 4 keeps the existing `DataCycles` tests in the new package.
5. Directive-driven variable files (`// kics_terraform_vars:`) must keep working in the converter after the scan-level path is removed. Task 2 pins this.

---

### Task 1: Remove the module equivalence table

**Files:**
- Modify: `pkg/parser/terraform/modules/modules.go`. Delete `resolveModuleToLocalPath`, `moduleEnrichCache` and its methods, `enrichModule`, `ParseAllModuleVariables`, `runModuleEnrichWorker`, `collectModuleResults`, `generateEquivalentMap`, `processEquivalentMapFile`, `getVariableAttributes`, `isVariableReference` and `parseVariableReference`. Also delete the `ParsedModule` fields and the `ModuleAttributesInfo` type, if nothing else uses them after the deletion.
- Modify: `pkg/engine/source/source.go:97`. Delete `MergeModulesData`.
- Modify: `pkg/engine/inspector.go`.
  - Delete the `moduleParse` goroutine (lines 587–623) and the "Found %d modules" log.
  - Drop the `modules []tfmodules.ParsedModule` parameter from `buildMergedInputData`, `precomputeBaseInputData`, `LoadQuery`, `executeQueries`, `evalQuery` and every caller.
- Modify: `pkg/engine/module_resolve.go:325-345`. Delete `buildModuleMetadataResolver` and `moduleMetadataResolver`, if they have no other caller.
- Delete the tests of the deleted functions. Keep the tests for `ParseTerraformModules`, `ParseTerraformModulesFromFiles` and `resolveExpr`: `list-modules` and `modulegraph` still use them.
- Test: `pkg/engine/inspector_input_data_test.go` (create).

**Interfaces:**
- Produces:
  - `func (q *QueryLoader) buildMergedInputData(query *model.QueryMetadata) (string, error)`
  - `func (q *QueryLoader) precomputeBaseInputData() map[string]string`
  - `LoadQuery(ctx, query, baseStores, baseDataHashes, cacheEnabled)`

- [ ] **Step 1: Write the failing test.** `TestBaseInputDataHasNoModuleTable` builds a `QueryLoader` with a Terraform platform library and a common library, whose input data is `{"common_lib": {"x": 1}}`. It calls `precomputeBaseInputData()` and asserts:
  - the JSON for `"terraform"` has `common_lib.x == 1`;
  - it has no `common_lib.modules` key.

  `TestCustomInputDataStillMerged` asserts that `buildMergedInputData(&model.QueryMetadata{Platform: "terraform", InputData: `{"k": 2}`})` contains both `k == 2` and `common_lib.x == 1`.
- [ ] **Step 2: Run them.** Run `go test ./pkg/engine -run 'TestBaseInputDataHasNoModuleTable|TestCustomInputDataStillMerged' -count=1`. Expected: build failure, because the signatures still take `modules`.
- [ ] **Step 3: Delete the code listed under Files.** Thread the new signatures through.
- [ ] **Step 4: Check that nothing reads the table.** `rg -n "ParseAllModuleVariables|MergeModulesData|AttributesData|common_lib.*modules" --type go` prints nothing outside `docs/`.
- [ ] **Step 5: Run the unit suite and the in-process end-to-end tests.** All `ok`.
- [ ] **Step 6: Lint, then commit** with "Remove the unused Terraform module equivalence table from rule input data."

### Task 2: Remove the scan-level Terraform variable-file path

**Files:**
- Modify: `pkg/scan/client.go:71,197`. Delete the `TerraformVarsPath` field and its initialiser.
- Modify: `pkg/scan/scan.go:375` and `pkg/parser/terraform/terraform.go`. `NewDefaultWithParams` loses its variable-path parameter, and the parser struct loses the field.
- Modify: `pkg/parser/terraform/variables.go:475`. The function taking `terraformVarsPath string` loses that parameter. The path comes only from the directive.
- Test: `pkg/parser/terraform/variables_test.go`.

**Interfaces:**
- Produces: `func NewDefaultWithParams(fsys vfs.FS, sciInfo model.SCIInfo) (*Parser, error)`. Keep today's parameter types for the parameters that remain.

- [ ] **Step 1: Add `TestVarsDirectiveStillApplies`.**
  - The fixture `main.tf` starts with `// kics_terraform_vars: vars/custom.tfvars` and declares `variable "name" {}` and `resource "aws_s3_bucket" "b" { bucket = var.name }`.
  - `vars/custom.tfvars` sets `name = "from-directive"`.
  - Assert that the parsed document's `resource.aws_s3_bucket.b.bucket == "from-directive"`.
- [ ] **Step 2: Run it** with `go test ./pkg/parser/terraform -run TestVarsDirectiveStillApplies -count=1`. Expected: PASS today. This is the characterisation test that guards the deletion.
- [ ] **Step 3: Delete the field and parameter, and update every caller and test constructor.**
- [ ] **Step 4: Run the unit suite.** All `ok`.
- [ ] **Step 5: Lint, then commit** with "Remove the unused scan-level Terraform variable-file path."

### Task 3: Inline the evaluator's pass-through wrappers

**Files:**
- Modify: `pkg/parser/terraform/tfeval/evaluator.go`. Inline `applyModuleOutputs` (defined at line 551, called at 504), `evaluateRootResources` (644, called at 506) and `installSiblingModuleOutputs` (824, called at 773) into their single callers, then delete them.

**Interfaces:** none. This is a pure refactor.

- [ ] **Step 1: Confirm each function has exactly one call site:** `rg -n "applyModuleOutputs\(|evaluateRootResources\(|installSiblingModuleOutputs\(" pkg` shows one definition and one call each.
- [ ] **Step 2: Inline them, keeping statement order.**
- [ ] **Step 3: Run** `go test ./pkg/parser/terraform/... ./pkg/engine/... -count=1`. All `ok`.
- [ ] **Step 4: Lint, then commit** with "Inline the Terraform evaluator's single-use wrapper functions."

### Task 4: Move the shared Terraform graph helpers into `tfrefs`

**Files:**
- Create: `pkg/parser/terraform/tfrefs/graph.go`. Move `DataKey`, `DataCycles` and `BodyTraversals` from `pkg/parser/terraform/data_source.go:150-230`, and `LocalTraversalName` from `variables.go:409`, with their doc comments.
- Create: `pkg/parser/terraform/tfrefs/graph_test.go`. Move the existing tests of those functions.
- Modify: `pkg/parser/terraform/tfeval/{evaluator.go,module_calls.go,data.go}` and the converter callers to use `tfrefs.`.

**Interfaces:**
- Produces, in package `tfrefs`, with the same signatures as today:
  - `DataKey(typ, name string) string`
  - `DataCycles(reads, locals map[string][]hcl.Traversal) map[string]bool`
  - `BodyTraversals(body hcl.Body) []hcl.Traversal`
  - `LocalTraversalName(traversal hcl.Traversal) (string, bool)`

- [ ] **Step 1: Add `TestTfevalDoesNotImportConverter`** to `pkg/parser/terraform/tfeval/imports_test.go`. It loads the package with `golang.org/x/tools/go/packages` if that is already a dependency; otherwise it runs `go list -deps` through `os/exec`. It asserts that `github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform` is not among the dependencies.
- [ ] **Step 2: Run it.** Expected: FAIL, listing the converter package.
- [ ] **Step 3: Move the functions and tests.** `tfrefs` imports only `hcl/v2`, `hclsyntax` and the standard library.
- [ ] **Step 4: Run** `go test ./pkg/parser/terraform/... -count=1`. All `ok`, including the moved `DataCycles` tests.
- [ ] **Step 5: Lint, then commit** with "Move the shared Terraform reference helpers into a leaf package."

### Task 5: One reference classifier for every "what does this read" analysis

**Files:**
- Create: `pkg/parser/terraform/tfrefs/ref.go` and `ref_test.go`.
- Modify, porting each analysis to `tfrefs.Of` or `tfrefs.Parse`:
  - `readsOf` in `pkg/parser/terraform/variables.go:376`;
  - `localGraph.noteReads` in `tfeval/local_graph.go:107`;
  - `callSiblingReads` in `tfeval/module_calls.go:192`;
  - `bodyReadsResource` and `readsResource` in `tfeval/evaluator.go:963,981`;
  - the callers of `BodyTraversals`.

  Each keeps its own result type and filtering. Only the classification of a traversal moves.

**Interfaces:**
- Produces:

```go
type Kind uint8

const (
	KindOther Kind = iota // a traversal Terraform would reject, or an unrecognised root
	KindVar
	KindLocal
	KindResource // <type>.<name>
	KindData     // data.<type>.<name>
	KindEphemeral
	KindModule // module.<name>
	KindEach
	KindCount
	KindSelf
	KindPath
	KindTerraform
)

// Ref is one object an expression reads, classified as Terraform's addrs.ParseRef does.
type Ref struct {
	Kind Kind
	Type string // resource, data and ephemeral types; empty otherwise
	Name string // variable, local, module, resource or data name
	// Key is the literal instance key that follows the name, nil when absent or dynamic.
	Key        *cty.Value
	DynamicKey bool // an index follows the name and is not a literal
	Traversal  hcl.Traversal
}

func Parse(t hcl.Traversal) Ref
func Of(expr hcl.Expression) []Ref // one Ref per expr.Variables() entry, in order
func OfBody(body hcl.Body) []Ref   // every attribute and nested block, dynamic blocks included
```

- [ ] **Step 1: Write the table test `TestParse`.** Parse each input with `hclsyntax.ParseTraversalAbs`, or `ParseExpression` for splats, and expect:

  | Input | Kind | Type | Name | Key | DynamicKey |
  |---|---|---|---|---|---|
  | `var.a` | Var | | a | | |
  | `local.a` | Local | | a | | |
  | `aws_s3_bucket.b.id` | Resource | aws_s3_bucket | b | nil | false |
  | `aws_s3_bucket.b[0].id` | Resource | | | `cty.NumberIntVal(0)` | |
  | `aws_s3_bucket.b["k"].id` | | | | `cty.StringVal("k")` | |
  | `aws_s3_bucket.b[var.k].id` (from an expression) | | | | | true |
  | `data.aws_iam_policy_document.p.json` | Data | aws_iam_policy_document | p | | |
  | `ephemeral.random_password.p.result` | Ephemeral | random_password | p | | |
  | `module.m.out` | Module | | m | | |
  | `each.value` | Each | | | | |
  | `count.index` | Count | | | | |
  | `self.x` | Self | | | | |
  | `path.module` | Path | | | | |
  | `terraform.workspace` | Terraform | | | | |
  | `aws_s3_bucket` (one part) | Other | | | | |

  `TestOfSplat` checks that `aws_x.y[*].id` gives one `KindResource` ref with `Type == "aws_x"` and `Name == "y"`.
- [ ] **Step 2: Run** `go test ./pkg/parser/terraform/tfrefs -count=1`. Expected: FAIL, undefined `Parse`.
- [ ] **Step 3: Implement `Parse`, `Of` and `OfBody`.** `OfBody` walks `hclsyntax.Body` attributes and blocks recursively. For a non-`hclsyntax` body it falls back to `BodyTraversals`.
- [ ] **Step 4: Run the tfrefs tests.** PASS.
- [ ] **Step 5: Port the five analyses one at a time**, running `go test ./pkg/parser/terraform/... ./pkg/engine/... -count=1` after each. All `ok` with no test changed. A test that needs changing reveals a classification difference: stop and record it in the ledger.
- [ ] **Step 6: Lint, then commit** with "Classify Terraform references in one shared helper."

### Task 6: Structured instance keys

**Files:**
- Create: `pkg/parser/terraform/tfeval/instance_key.go` and `instance_key_test.go`.
- Modify: `tfeval/evaluator.go`.
  - `ResolvedResource` gains `BaseName string` and `Key InstanceKey`. These are set wherever instances are created, and `Name` stays `BaseName + Key.String()`.
  - The caller at line 1147 reads the fields.
- Modify: `pkg/engine/module_resolve.go:996,1008,1126,1144`. Use `r.BaseName`, and `r.Key.Kind == NoKey` where line 996 compares the name with its base.
- Modify: `tfeval/parse.go`. Delete `parseResourceInstanceKey` and `ResourceBaseName`. Keep `decodeHCLString` only if it is still used.

**Interfaces:**
- Produces:

```go
type KeyKind uint8

const (
	NoKey KeyKind = iota
	IntKey
	StringKey
)

type InstanceKey struct {
	Kind KeyKind
	Int  int
	Str  string
}

// String renders the key as Terraform writes it in an address: "", "[3]" or ["k"] with HCL string escaping.
func (k InstanceKey) String() string
```

- [ ] **Step 1: Write `TestInstanceKeyString`** with the cases below. The quoted cases must equal what today's code writes for the same `for_each` key, captured once from the current `Name` construction before the change and pasted into the test.

  | Key | `String()` |
  |---|---|
  | `{NoKey}` | `""` |
  | `{IntKey, Int: 3}` | `"[3]"` |
  | `{StringKey, Str: "dev"}` | `["dev"]` |
  | `{StringKey, Str: ""}` | `[""]` |
  | `{StringKey, Str: "a$b"}` | as today |
  | `{StringKey, Str: "a${b}"}` | as today |
  | `{StringKey, Str: "a%{b}"}` | as today |
  | `{StringKey, Str: "q\"x"}` | as today |
  | `{StringKey, Str: "é"}` | as today |

  `TestResolvedResourceNameMatchesKey` evaluates a fixture with `count = 2` and `for_each = {"a$b" = 1, "" = 2}`. It asserts `r.Name == r.BaseName + r.Key.String()` for every instance, and that the set of `Name`s equals the set produced before the change, pasted as literals.
- [ ] **Step 2: Run** `go test ./pkg/parser/terraform/tfeval -run 'TestInstanceKeyString|TestResolvedResourceNameMatchesKey' -count=1`. Expected: FAIL, undefined.
- [ ] **Step 3: Implement `InstanceKey.String()`** with the same escaping call today's name construction uses. Set the fields at instance creation, then port the callers.
- [ ] **Step 4: Run the unit suite and the in-process end-to-end tests.** All `ok`, with no change to fingerprints in end-to-end snapshots.
- [ ] **Step 5: Lint, then commit** with "Carry Terraform instance keys as structured fields."
