# Terraform contract, plan 5: plan input and `_dd_meta.unknown` — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rules decide unknownness from `_dd_meta.unknown` in source and plan scans alike, plan documents look like source documents (configured unknown values present as `${__dd_unknown__}`, unconfigured computed attributes, nulls and unconfigured empty blocks absent), and a plan finding on an attribute the file does not contain lands on its nearest existing ancestor.

**Architecture:**
- Source scans: `tfeval.Unknowns` walks a resolved resource's cty attributes (guided by the document it rendered, when there is one) into the `unknown` shape; the engine stores it beside `references` in instantiated documents and in written root blocks.
- Plan scans: a value pass in `pkg/parser/json` rewrites each planned resource's `values` from its `after_unknown` and its configuration `expressions` before it enters the document, and records the pruned `after_unknown` as `unknown` in the plan meta, which `stampPlanMeta` copies into `_dd_meta`.
- Line detection: `detectTerraformPlanLine` walks the searchKey path up to the resource header instead of handing a missing attribute to text matching.

**Tech Stack:** Go, go-cty, gjson, `hashicorp/terraform-json` (`hcl_plan`).

**Spec:** `docs/superpowers/specs/2026-11-01-terraform-rule-input-contract-design.md` (Goals 3 and 5; Contract `unknown`, unknown values in documents, plan absence; Approaches: Plan unknowns; Decided: plan line detection, metadata in fallback roots, unknown in source scans).

## Plan series (revised)

1-4. Done: groundwork, zero-instance blocks, `_dd_meta` address/roots and root routing, references.
5. This plan.
6. Rules repository migrations (rules that read `_dd_tfplan_meta.after_unknown`, test `== null` on plan values, or parse `${...}` for unknownness move to `_dd_meta.unknown`).
7. One evaluator for all blocks, `joinPlainRootSiblings` deleted.
8. Removing `_dd_tfplan_meta` (with its `after_unknown`) and the plan-address path.

Rulings carried in: `_dd_meta` overwrites any user-written value; `rewriteBlockMeta` keeps every meta key it does not rewrite (plan 4 fix wave), so `unknown` survives root routing without further change; fallback roots carry no `unknown` (spec); tasks share files where they can; per-task reviewer only for routing, identity, hashing, resolver correctness or public contract; targeted runs per task, the full suite once per plan.

## Global Constraints

- The scanner repository is public: no customer names, internal links or private content in code, fixtures or commits.
- Commit messages are one sentence and never name the upstream scanner this one was forked from.
- No verbose comments; tests go in an existing test file when one fits.
- Lint: `$(go env GOPATH)/bin/golangci-lint run -c .golangci.yml --timeout 20m ./pkg/... ./cmd/...` before each commit touching Go. Unit suite `go test $(go list ./... | grep -v /e2e) -count=1`; in-process end-to-end `go test ./test/e2e -count=1`. Run from the worktree root (its directory must stay named `datadog-iac-scanner`); never use sleep or polling loops.
- The placeholder is `partial.UnknownPlaceholder` (`"${__dd_unknown__}"`, `pkg/parser/terraform/partial/partial.go`); never spell the string anew.
- `unknown` shape: Terraform's `after_unknown` with only `true` leaves kept in objects; a wholly unknown value is `true`; nested blocks are lists of objects; a list keeps its length and positions, a known element being `{}` when it is an object and `false` otherwise; an object or list with nothing unknown is omitted; the key is absent when nothing is unknown.
- Source scans keep today's `${<use-site text>}` rendering; only plan scans write the placeholder into values.
- Plan absence: a `null` object entry is dropped (list elements are not, to keep positions); an empty list is dropped when the configuration `expressions` at the same path has no key for it. `false`, `0`, `""`, `{}` are values and stay.
- `_dd_lines` keys inside plan values are bookkeeping: never dropped, never treated as content.
- `unknown` takes part in the cross-root deduplication key; `root_modules` still does not.
- Never change finding identities, fingerprints or document keys of existing blocks. `_dd_tfplan_meta` keeps its `after_unknown` unchanged until plan 8.

## Review Focus

1. A source attribute that is partly unknown but rendered as text by the renderer (`tags = merge(var.t, { a = "b" })`, `var.t` unset) is a string in the document, so `unknown.tags` must be `true`, not a nested object a rule would index into. Task 1 pins this.
2. A plan list with an unknown middle element (`values.ips = ["a", null, "c"]`, `after_unknown.ips = [false, true, false]`) becomes `["a", "${__dd_unknown__}", "c"]` with `unknown.ips = [false, true, false]`; dropping the null first would shift positions. Task 2 pins this.
3. A plan nested block written as an explicit empty list (`ingress = []` in configuration) or produced by a `dynamic` block (expression key present) stays `[]`; only an unconfigured one goes. Task 2 pins this.
4. A searchKey on a plan attribute dropped because it was `null` still resolves to that attribute's own line, since the file contains it (`_dd_lines` kept). Task 3 pins this.
5. Two roots call one module and render identical content, but one passes the literal text `"$${var.x}"` (known) and the other leaves `x` unset (rendered `${var.x}`, unknown). They must not share a document, or one root gets the other's `unknown`. Task 1 pins this.

---

### Task 1: `_dd_meta.unknown` in source scans

**Files:**
- Modify: `pkg/parser/terraform/tfeval/document.go`: add `Unknowns`.
- Modify: `pkg/engine/terraform_meta.go`: `resourceMeta(addr string, roots []string, extras blockMetaExtras)`, with `unknownKey = "unknown"` beside `referencesKey`; update the callers in `stampWrittenMeta` (zero extras), `stampPlanMeta`, and `groupDocument` (`module_resolve.go`).
- Modify: `pkg/engine/module_resolve.go`: `instantiatedResource` gains `unknown map[string]interface{}` and `unknownHash uint64`, filled in `addGroupEntry` from `tfeval.Unknowns(r, attrs)` and hashed in `groupContentKey` after `referencesHash`; `writtenReferences` becomes `writtenMeta map[string]blockMetaExtras`, `add` also records `tfeval.Unknowns(p.r, nil)`, and `stampWrittenReferences` is renamed `stampWrittenExtras`, writing both keys when set.
- Test: `pkg/parser/terraform/tfeval/document_test.go`, `pkg/engine/module_resolve_test.go`, `pkg/engine/module_resolve_dedup_test.go` (existing).

**Interfaces:**
- Produces:

```go
// Unknowns returns r's _dd_meta.unknown, nil when every value is known. doc,
// when non-nil, is AttributesToDocument(r): a value it holds as a scalar is
// wholly unknown.
func Unknowns(r *ResolvedResource, doc map[string]interface{}) map[string]interface{}

type blockMetaExtras struct{ references, unknown map[string]interface{} }
func resourceMeta(addr string, roots []string, extras blockMetaExtras) map[string]interface{}
```

Walk: skip a wholly known value; `!v.IsKnown()` or a non-container counterpart in `doc` gives `true`; objects and maps recurse by key; lists, tuples and sets recurse by element under the Global Constraints shape. Unknown `count`/`for_each` values are not reported (they are not attributes of the instance).

- [ ] **Step 1: Write the failing tests:**
  - In `document_test.go`, with `writeModule` and `New().EvaluateModule` as `TestAttributesToDocumentKeepsReferenceText` does: `TestUnknownsRootVariableAndComputedAttribute`: `name = var.unset` and `subnet_id = aws_subnet.s.id` give `{"name": true, "subnet_id": true}`; a resource with only literals gives nil. `TestUnknownsNestedBlockAndList`: two `ingress` blocks, the second with `cidr_blocks = [var.unset, "10.0.0.0/8"]`, give `{"ingress": [{}, {"cidr_blocks": [true, false]}]}`. `TestUnknownsRenderedTextIsWhole`: Review Focus 1, `Unknowns(r, AttributesToDocument(r))["tags"] == true`. `TestUnknownsKnownVariableNotReported`: `var.x` with a default gives nil.
  - In `module_resolve_test.go`: `TestInstantiatedDocCarriesUnknown` (via `resolveModuleFixture`): a module resource reading `var.unset` has `metaOf(...)["unknown"] == {"name": true}`, and a sibling with literals has no `unknown` key. Extend `TestWrittenRootBlockCarriesReferences` to assert `unknown == {"subnet_id": true}` on the association and no `unknown` on `aws_subnet.s`. Extend `TestRootRewriteKeepsReferences` to assert `unknown` is unchanged too.
  - In `module_resolve_dedup_test.go`: `TestUnknownSplitsDedup`: Review Focus 5, two roots calling one module, one with `x = "$${var.x}"` (known, renders the same text) and one leaving `x` unset: two documents, only the second with `unknown`.
- [ ] **Step 2: Run** `go test ./pkg/parser/terraform/tfeval ./pkg/engine -run 'TestUnknowns|TestInstantiatedDocCarriesUnknown|TestWrittenRootBlockCarriesReferences|TestRootRewriteKeepsReferences|TestUnknownSplitsDedup' -count=1`. Expected: FAIL (undefined `Unknowns`, missing `unknown` keys).
- [ ] **Step 3: Implement** as above.
- [ ] **Step 4: Run** `go test ./pkg/parser/terraform/... ./pkg/engine/... -count=1` and `TestResolveModuleDocuments_DocumentsDoNotGrowWithCallSites`. All `ok`.
- [ ] **Step 5: Lint, then commit** with "Record the attribute paths evaluation leaves unknown in the metadata of Terraform source blocks."

### Task 2: Plan values look like source values

**Files:**
- Create: `pkg/parser/json/tfplan_values.go` (`tfplan.go` is already ~700 lines).
- Modify: `pkg/parser/json/tfplan.go`: `tfplanResourceMeta` gains `Unknown any \`json:"unknown,omitempty"\``; `readModule` and `readPriorStateData` pass `resource.AttributeValues` through `planValues` before storing them, using `correlation.afterUnknownByAddress[resource.Address]` and `correlation.configByAddress[canonicalConfigAddress(resource.Address)]`; `resourceMetaFor` and `recordPlanAddress` set `Unknown`; add `PlanUnknowns(doc model.Document) map[[2]string]interface{}` beside `PlanReferences`.
- Modify: `pkg/engine/terraform_meta.go`: `stampPlanMeta(doc, addresses, extras map[[2]string]blockMetaExtras, root)`; `pkg/engine/terraform_scope.go` builds `extras` from `json.PlanReferences` and `json.PlanUnknowns`.
- Test: `pkg/parser/json/tfplan_test.go`, `pkg/engine/terraform_scope_test.go` (existing).

**Interfaces:**
- Consumes: `blockMetaExtras`, `resourceMeta` (Task 1).
- Produces:

```go
// planValues rewrites one resource's planned values in place and returns its
// _dd_meta.unknown, nil when nothing is unknown.
func planValues(values map[string]any, afterUnknown any, expressions *gjson.Result) map[string]any
func PlanUnknowns(doc model.Document) map[[2]string]interface{}
```

Order inside `planValues`, per object level: (1) every `true` leaf of `afterUnknown` whose key is configured at that level (present in `expressions`, or inside a configured attribute's value) sets the value at that path to `partial.UnknownPlaceholder`, creating missing object keys and replacing `null` list elements; (2) `null` entries are deleted; (3) an empty list whose key is absent from `expressions` at that level is deleted (a nested block element's expressions are the element at the same index of the expressions list; no expressions object means absent); (4) recurse. `_dd_lines` is skipped at every level. The returned unknown is `afterUnknown` pruned to the Global Constraints shape.

- [ ] **Step 1: Write the failing tests** in `tfplan_test.go`, with small inline plan JSON in the style of `TestPlanReferencesDirectAndIndexed`:
  - `TestPlanValuesUnknownPlaceholder`: `after_unknown = {"id": true, "arn": true, "name": false}`, `values = {"name": "a"}`, `id` and `arn` configured by reference, gives `values == {"name": "a", "id": "${__dd_unknown__}", "arn": "${__dd_unknown__}"}` and `_dd_tfplan_meta...unknown == {"id": true, "arn": true}`; `after_unknown = {"name": false}` gives no `unknown`.
  - `TestPlanValuesUnknownListPositions`: Review Focus 2.
  - `TestPlanValuesUnknownNestedBlock`: `after_unknown.ingress = [{}, {"id": true}]` gives `unknown.ingress == [{}, {"id": true}]` and, `id` being unconfigured, no placeholder at `ingress[1].id`; `after_unknown.ingress = true` gives `values.ingress == "${__dd_unknown__}"`.
  - `TestPlanValuesDropNulls`: `{"description": null, "enabled": false, "count": 0, "name": "", "tags": {}}` keeps the last four only; a null nested inside a block element is dropped too.
  - `TestPlanValuesDropUnconfiguredEmptyBlocks`: Review Focus 3, `ebs_block_device: []` with no `expressions.ebs_block_device` is dropped; `ingress: []` with `expressions.ingress` present is kept; the same at one nesting level down.
  - `TestPlanValuesKeepLineBookkeeping`: the `_dd_lines` map of a values object survives, including the entry of a dropped null attribute.
  - `TestPlanValuesPriorStateData`: a prior-state data source with a null attribute loses it.
  - Update the expected documents of `TestJson_parseTFPlan` cases whose fixtures hold nulls or unconfigured empty lists, and nothing else.
  - In `terraform_scope_test.go`, extend `TestStampTerraformScopesAddsPlanMeta` to assert `_dd_meta.unknown` equals the parser's value.
- [ ] **Step 2: Run** `go test ./pkg/parser/json ./pkg/engine -run 'TestPlanValues|TestJson_parseTFPlan|TestStampTerraformScopesAddsPlanMeta' -count=1`. Expected: FAIL.
- [ ] **Step 3: Implement** as above.
- [ ] **Step 4: Run** `go test ./pkg/parser/... ./pkg/engine/... ./pkg/detector/... -count=1`. All `ok`; `_dd_tfplan_meta` snapshot changes are limited to the new `unknown` field.
- [ ] **Step 5: Lint, then commit** with "Fill unknown plan values with the placeholder, record them as unknown and drop null values and unconfigured empty blocks."

### Task 3: Plan line detection falls back to the nearest ancestor

**Files:**
- Modify: `pkg/detector/default_detect.go`: `detectTerraformPlanLine`.
- Test: `pkg/detector/default_detect_test.go` (existing).

**Interfaces:**
- Produces: `detectTerraformPlanLine` tries `GetLineBySearchLine` on the full path, then on each shorter prefix down to the resource header (`tfPlanMinAttributePathLen` components); it returns nil (text matching) only when even the header has no line or the line is `<= 1` (the minified case, unchanged).

- [ ] **Step 1: Write the failing tests** in `default_detect_test.go`, in the style of `Test_detectLineTerraformPlanResourceLevel`, each plan also carrying a `resource_changes` entry whose `after_unknown` and a `configuration` whose `expressions` contain the searched attribute name:
  - `Test_detectLineTerraformPlanUnknownAttributeUsesHeader`: `aws_instance[web].arn` (unknown, absent from `values`) returns the `values` line of `aws_instance.web`, not the `after_unknown` or `expressions` line.
  - `Test_detectLineTerraformPlanMissingNestedUsesAncestor`: `aws_security_group[sg].ingress.0.description` with `ingress[0]` present but no `description` returns the `ingress` element's line.
  - `Test_detectLineTerraformPlanDroppedNullKeepsOwnLine`: Review Focus 4, `aws_instance[web].description` where `description` is `null` in the file returns its own line.
  - `Test_detectLineTerraformPlanMinified` stays green unchanged.
- [ ] **Step 2: Run** `go test ./pkg/detector -run 'Test_detectLineTerraformPlan' -count=1`. Expected: FAIL on the first two.
- [ ] **Step 3: Implement** as above.
- [ ] **Step 4: Run** `go test ./pkg/detector/... -count=1`. All `ok`.
- [ ] **Step 5: Lint, then commit** with "Resolve a plan finding on an attribute the plan file lacks to its nearest existing ancestor."

### Task 4: Unknowns end to end

**Files:**
- Test: `test/e2e/e2e_test.go` (existing); a source fixture and a plan fixture under `test/e2e/fixtures/`, and a custom rule under `test/e2e/testdata/rules/`, beside `Test_E2ETerraformSharedModuleRootRouting`'s; plan scanning enabled as `Test_E2ETerraformPlanFlag` does.

- [ ] **Step 1: Write the test** `Test_E2ETerraformUnknownMeta`: the custom rule reports every `aws_instance` whose `_dd_meta.unknown.ami` is `true` and every one whose `description` key exists, and is silent without `_dd_meta`. Source fixture: `aws_instance.a` (`ami = var.unset`) and `aws_instance.b` (`ami = "ami-1"`). Plan fixture: the same two, `a`'s `ami` unknown in `after_unknown`, both with `"description": null`. Assert exactly the `ami` finding on `aws_instance.a` in each scan, no `description` finding, and the plan finding's line equals `a`'s `values` line.
- [ ] **Step 2: Run** `go test ./test/e2e -run Test_E2ETerraformUnknownMeta -count=1`. Expected: PASS after Tasks 1-3 (it fails on the base commit).
- [ ] **Step 3: Run** the unit suite and `go test ./test/e2e -count=1`. All `ok`.
- [ ] **Step 4: Lint, then commit** with "Pin that rules see unknown values and absent nulls the same way in source and plan scans."

**Review gates:** Tasks 1 and 2 get a per-task reviewer (public contract and dedup hashing). Tasks 3 and 4 get a controller skim; the whole-plan review covers them.
