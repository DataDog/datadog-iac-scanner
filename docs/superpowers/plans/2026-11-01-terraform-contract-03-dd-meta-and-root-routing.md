# Terraform contract, plan 3: `_dd_meta` and root routing — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every Terraform resource, data and ephemeral object a rule sees carries `_dd_meta = {address, root_modules}`, and a rule result may name the one root module it applies to.

**Architecture:**
- The engine writes `_dd_meta` into the Rego input in three places: instantiated module documents (full instance address, every root sharing the document), blocks that stay in their written file (bare address, the file's own root), and plan resources (the plan's address, the plan file as root).
- A rule result field `rootModule` is parsed into a new non-serialised field on the vulnerability, and the four functions that copy or predict findings across roots apply one shared filter.
- `references` and `unknown` are added by plans 4 and 5; this plan fixes the key, its shape and where it is written.

**Tech Stack:** Go, OPA/Rego.

**Spec:** `docs/superpowers/specs/2026-11-01-terraform-rule-input-contract-design.md` (Goals 3 and 4, Contract).

## Plan series (revised)

1. Done: deletions and groundwork. 2. Done: zero-instance blocks disappear.
3. This plan.
4. References: the measured spike, source references, plan resolver.
5. Plan input: unknown placeholders, `_dd_meta.unknown`, dropping nulls and empty blocks, line-detection fallback.
6. Rules repository migrations and library deletions. It must also fix rule fixtures that use `count = 0` as a positive case, because `test-rules` runs fixtures through module resolution.
7. One evaluator for all blocks (this is where evaluated values reach plain root documents in place), the ported variable-file directive, `joinPlainRootSiblings` deleted, the converter shrunk, and one owner for count-zero handling.
8. Removing `_dd_tfplan_meta` and the plan-address path.

Rulings carried in: the written-file stamp is one formula for plain roots and fallback roots (see Task 1), so evaluated-value patching is not needed here. A module call with `count = 0` is unchanged. Hand-built `ResolvedResource` fixtures must set `BaseName` and `Key`.

## Global Constraints

- The scanner repository is public: no customer names, internal links or private content in code, fixtures or commits.
- Commit messages are one sentence and never contain the name KICS.
- No verbose comments; put tests in an existing test file when one fits.
- Lint: `$(go env GOPATH)/bin/golangci-lint run -c .golangci.yml --timeout 20m ./pkg/... ./cmd/...` before each commit touching Go. Unit suite `go test $(go list ./... | grep -v /e2e) -count=1`; in-process end-to-end `go test ./test/e2e -count=1`. Run from the worktree root; never use sleep or polling loops.
- `_dd_meta.address` must be byte-identical to the `resource_id` the finding identity produces for the same instance (`address.Instance` in `pkg/parser/terraform/address`).
- `_dd_meta.root_modules` uses the same repository-relative strings as `root_module` on findings.
- `_dd_meta` is excluded from the content hash used to deduplicate documents across roots, and is listed in `bookkeepingKeys`.
- Never change finding identities, fingerprints or document keys of existing blocks.
- Document keys stay base-named; `_dd_meta` is a key inside the resource object, never a sibling.
- Never add marked cty values to the evaluation cache, the local memo or `equalValues`.

## Review Focus

1. A module document shared by two roots must list both roots in every resource's `root_modules`, in a stable order. Task 2 pins this.
2. A resource object that holds only `_dd_meta` after removal of its attributes must count as empty, so removal still deletes it. Task 1 pins this.
3. Two instances of one block (`count = 2`) get `address` ending `[0]` and `[1]` in separate layer documents. Task 2 pins this.
4. A rule result with `rootModule` set to a root that does not hold the document yields no finding, and the predicted identities in `supersedes` agree with what routing keeps. Task 4 pins this.
5. A `data` block and an `ephemeral` block with the same type and name as a managed resource get `data.` and `ephemeral.` addresses. Tasks 1 and 2 pin this.

---

### Task 1: `_dd_meta` on blocks that stay in their written file

**Files:**
- Create: `pkg/engine/terraform_meta.go` (a small file: the key constant and the two helpers below).
- Modify: `pkg/engine/terraform_scope.go`. Add `_dd_meta` to `bookkeepingKeys`; call the stamp from `stampTerraformScopes` for every non-plan, non-synthetic Terraform config file, after its scope is built.
- Test: `pkg/engine/terraform_scope_test.go` (existing).

**Interfaces:**
- Produces:

```go
const ddMetaKey = "_dd_meta"

// resourceMeta is the _dd_meta object: address string, root_modules []interface{} of strings.
func resourceMeta(address string, roots []string) map[string]interface{}

// stampWrittenMeta adds _dd_meta to every name-keyed block of the resource,
// data and ephemeral sections of doc that has none: address from
// address.Instance("", block, ""), root_modules [scope.RootModule]. List-shaped
// type entries are left alone.
func stampWrittenMeta(doc map[string]interface{}, scope *model.TerraformScope)
```

- [ ] **Step 1: Write the failing tests** in `terraform_scope_test.go`, using that file's helpers to build a parsed document and call `stampTerraformScopes`:
  - `TestStampTerraformScopesAddsMeta`: a file in `envs/prod` with `resource.aws_s3_bucket.b`, `data.aws_iam_policy_document.p` and `ephemeral.random_password.pw`. Assert each object's `_dd_meta` equals `{"address": "aws_s3_bucket.b", "root_modules": ["envs/prod"]}`, `{"address": "data.aws_iam_policy_document.p", ...}` and `{"address": "ephemeral.random_password.pw", ...}`.
  - `TestStampTerraformScopesKeepsListShapedTypes`: a type entry that is a list is unchanged.
  - `TestMetaOnlyBlockCountsAsEmpty`: `onlyMetadataKeys` is true for `{"_dd_meta": {...}, "_dd_lines": {...}}`.
- [ ] **Step 2: Run** `go test ./pkg/engine -run 'TestStampTerraformScopesAddsMeta|TestStampTerraformScopesKeepsListShapedTypes|TestMetaOnlyBlockCountsAsEmpty' -count=1`. Expected: FAIL.
- [ ] **Step 3: Implement** the constant, `resourceMeta`, `stampWrittenMeta`, the `bookkeepingKeys` entry and the call in `stampTerraformScopes`. Check that nothing else in the engine hashes or compares the parsed document in a way that the new key changes (search for users of `f.Document` before payload building) and record the result in the report.
- [ ] **Step 4: Run** `go test ./pkg/engine/... ./pkg/runner/... ./pkg/server/... -count=1`. All `ok`.
- [ ] **Step 5: Lint, then commit** with "Stamp Terraform blocks that stay in their written file with a metadata object."

### Task 2: `_dd_meta` on instantiated module documents

**Files:**
- Modify: `pkg/engine/module_resolve.go`.
  - `groupDocument`: write the object as a shallow copy of `e.attrs` plus `_dd_meta` (address from `address.Instance(g.moduleAddress, block, instanceSuffix)`, using the same `g.instances` suffix `TerraformScope.Instances` uses, so it equals the finding's `resource_id`; roots `[g.rootModule]`). The attribute hash stays computed before, so `_dd_meta` is excluded from deduplication.
  - After `evaluateRootModules` returns in `resolveModuleDocuments`: for each shared document, set every resource's `root_modules` to its own root plus the roots in `extras[docID]`, sorted and without duplicates.
- Test: `pkg/engine/module_resolve_test.go` (existing).

**Interfaces:**
- Consumes: `resourceMeta` (Task 1).
- Produces: `func setDocumentRoots(doc model.Document, roots []string)`, which rewrites `root_modules` in every `_dd_meta` of the document's resource, data and ephemeral sections.

- [ ] **Step 1: Write the failing tests** in `module_resolve_test.go`:
  - `TestInstantiatedDocCarriesMeta`: a root calling a module with `aws_s3_bucket.b` and `data.aws_iam_policy_document.p`. Assert the instantiated document's objects have `_dd_meta.address` equal to `module.m.aws_s3_bucket.b` and `module.m.data.aws_iam_policy_document.p`, and that each equals the `ResourceID` the engine's identity function (`terraformIdentityFor` or the helper the neighbouring tests use) gives the same block.
  - `TestInstantiatedDocMetaInstanceAddresses`: `count = 2` gives two layer documents whose addresses end `[0]` and `[1]`, and a `for_each = {"a$b" = 1}` instance address equals the `Name` produced by the evaluator for that key.
  - `TestSharedDocListsEveryRoot`: two roots `envs/a` and `envs/b` calling one module with identical inputs share one document; its `_dd_meta.root_modules` is `["envs/a", "envs/b"]` for every resource. With different inputs there are two documents with one root each.
  - `TestMetaDoesNotSplitDedup`: the two-root case above still produces exactly one document (meta is not hashed).
- [ ] **Step 2: Run** `go test ./pkg/engine -run 'TestInstantiatedDoc|TestSharedDocListsEveryRoot|TestMetaDoesNotSplitDedup' -count=1`. Expected: FAIL.
- [ ] **Step 3: Implement** the meta in `groupDocument` and `setDocumentRoots` after the roots are merged. Copy the attribute map shallowly so the map held by `docGroup.entries` is never mutated.
- [ ] **Step 4: Run** `go test ./pkg/engine/... ./pkg/server/... -count=1` and `go test ./test/e2e -count=1`. All `ok`, with no change to fingerprints in end-to-end snapshots.
- [ ] **Step 5: Lint, then commit** with "Give instantiated Terraform documents a metadata object with the instance address and every root."

### Task 3: `_dd_meta` on plan resources

**Files:**
- Modify: `pkg/engine/terraform_scope.go`. In the plan branch of `stampTerraformScopes`, add `_dd_meta` to each resource, data and ephemeral object of the plan document from `PlanAddresses` (address as the plan states it, `root_modules` `[scope.RootModule]`). Keep `_dd_tfplan_meta` untouched.
- Test: `pkg/engine/terraform_scope_test.go` (existing).

**Interfaces:**
- Consumes: `resourceMeta`, `json.PlanAddresses(doc)`.

- [ ] **Step 1: Write the failing test** `TestStampTerraformScopesAddsPlanMeta` using the existing plan fixture helpers in that test file: a plan with `module.m.aws_s3_bucket.b[1]` and a root `aws_s3_bucket.r`. Assert `_dd_meta.address` equals the plan address exactly and `root_modules` is the repository-relative plan file path.
- [ ] **Step 2: Run it.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `go test ./pkg/engine/... ./pkg/runner/... ./pkg/parser/... -count=1`. All `ok`.
- [ ] **Step 5: Lint, then commit** with "Stamp Terraform plan resources with the same metadata object as source resources."

### Task 4: Rule results can name one root module

**Files:**
- Modify: `pkg/model/model.go`. Add `OnlyRootModule string` with `json:"-"` to the vulnerability type next to `RootModule`.
- Modify: `pkg/engine/vulnerability_builder.go`. Parse the result field `rootModule` into it.
- Modify: `pkg/engine/inspector.go` (`expandModuleFindings`), `pkg/engine/module_file_findings.go` (`attributeModuleFileFindings`), `pkg/engine/findings.go` (`appendRouteIdentities`, and whatever `supersedes` and `skipSupersededResult` need to see the field before line detection).
- Test: `pkg/engine/findings_test.go` (existing), including the existing identity-prediction parity test's style.

**Interfaces:**
- Produces: `Vulnerability.OnlyRootModule string`. One shared predicate, `func rootAllowed(only, root string) bool` (true when `only` is empty or equals `root`), used by all four functions.
- Rules: the primary finding is kept when `rootAllowed(v.OnlyRootModule, v.RootModule)`; each extra caller when `rootAllowed(only, ex.rootModule)`; each module-file call when `rootAllowed(only, call.rootModule)`; the as-written finding on a module file (`keepWritten`) when `rootAllowed(only, <the file's own root>)`.

- [ ] **Step 1: Write the failing tests** in `findings_test.go`, reusing its routing fixtures (a shared document with extras, and a module file with calls):
  - `TestRouteHonoursOnlyRootModule`: a finding for a shared document with extras `envs/b` and `envs/c` and primary `envs/a`: with `OnlyRootModule = "envs/b"` exactly one routed finding with `RootModule == "envs/b"`; with `""` three; with `"envs/zzz"` none.
  - `TestModuleFileFindingsHonourOnlyRootModule`: the same for `attributeModuleFileFindings`, including the as-written copy.
  - `TestSupersedesAgreesWithRouteWithOnlyRootModule`: for each of the three cases above, `findingIdentities` and the routed output name the same identities (the property the existing `TestFindingSet_SupersedesMeansRouteKeepsNothingNew` pins).
  - `TestBuilderParsesRootModule`: a Rego result object with `rootModule` yields `OnlyRootModule`; one without leaves it empty.
- [ ] **Step 2: Run** `go test ./pkg/engine -run 'TestRouteHonoursOnlyRootModule|TestModuleFileFindingsHonourOnlyRootModule|TestSupersedesAgreesWithRoute|TestBuilderParsesRootModule' -count=1`. Expected: FAIL.
- [ ] **Step 3: Implement** the field, the parse, `rootAllowed` and its four uses.
- [ ] **Step 4: Run** `go test ./pkg/engine/... -count=1` and `go test ./test/e2e -count=1`. All `ok`.
- [ ] **Step 5: Lint, then commit** with "Let a rule result restrict its finding to one Terraform root module."

### Task 5: The headline case end to end

**Files:**
- Test: `test/e2e/e2e_test.go` (existing) with a small fixture directory and a small custom rule, following how neighbouring tests supply rules.

- [ ] **Step 1: Write the failing test** `Test_E2ETerraformSharedModuleRootRouting`. Two roots (`envs/a`, `envs/b`) call one local module that declares an `aws_s3_bucket.b` whose `versioning` is set by an input: `true` in `envs/a`, absent in `envs/b`. A custom rule (Rego in the test's rules directory, with metadata) flags an `aws_s3_bucket` without enabled versioning, joining on `[root, _dd_meta.address]` and returning `rootModule: root`. Assert exactly one finding, whose root module is `envs/b`, and none for `envs/a`.
- [ ] **Step 2: Run it.** Expected: FAIL before Tasks 1-4's behaviour is wired through the fixture, PASS after. If it already passes, keep it and note it in the report.
- [ ] **Step 3: Run the unit suite and the in-process end-to-end tests.** All `ok`.
- [ ] **Step 4: Lint, then commit** with "Pin that a rule can attribute a shared-module finding to the one root that violates it."
