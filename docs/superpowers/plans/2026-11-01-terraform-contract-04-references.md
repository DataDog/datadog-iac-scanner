# Terraform contract, plan 4: `_dd_meta.references` — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every resource, data and ephemeral object a rule sees in a source or plan scan carries `_dd_meta.references`: for each attribute path that reads another resource, data or ephemeral instance, the absolute instance addresses it reads.

**Architecture:**
- Task 1 is a measured spike of the chosen design: a shadow provenance pass in `tfeval` that re-evaluates a resolved resource's body in a copy of its scope's context where every instance object is marked with its own absolute address, then reads the marks per path with `cty.Value.UnmarkDeepWithPaths`. Marks never reach the main evaluation, the evaluation cache, the local memo or `equalValues`.
- Tasks 4-8 build the shadow pass for real and are executed only when the spike's ruling is `shadow`. When the ruling is `static`, Tasks F1-F3 replace them, built on `valueAnalyzer` in `pkg/engine/module_arguments.go`.
- Tasks 2 and 3 do not depend on the ruling: routing unresolved module directories to their callers' roots (deferred from plan 3), and plan references resolved from the plan JSON `configuration`.

**Tech Stack:** Go, HCL v2 (`hclsyntax`), go-cty marks, gjson for plan JSON.

**Spec:** `docs/superpowers/specs/2026-11-01-terraform-rule-input-contract-design.md` (Contract `references`; Approaches: References, Plan references; Decided: untraceable references are uncertain, metadata in fallback roots, static-tracing fallback contract).

## Plan series (revised)

1-3. Done: groundwork, zero-instance blocks, `_dd_meta` address/roots and root routing.
4. This plan.
5. Plan input: unknown placeholders, `_dd_meta.unknown`, dropping nulls and empty blocks, line-detection fallback.
6. Rules repository migrations (the NSG rule is the first join on `references`).
7. One evaluator for all blocks, `joinPlainRootSiblings` deleted.
8. Removing `_dd_tfplan_meta` and the plan-address path. Plan 8 moves Task 3's references off `_dd_tfplan_meta` with the address.

Rulings carried in: `_dd_meta` overwrites any user-written value; `bookkeepingKeys` stays label-level; hand-built `ResolvedResource` fixtures set `BaseName` and `Key`; the unresolved-directory roots item from plan 3 is Task 2 here, because a join rule keyed by a caller root otherwise never sees those blocks and the uncertainty rule cannot apply to them.

## Global Constraints

- The scanner repository is public: no customer names, internal links or private content in code, fixtures or commits.
- Commit messages are one sentence and never contain the name KICS.
- No verbose comments; tests go in an existing test file when one fits.
- Lint: `$(go env GOPATH)/bin/golangci-lint run -c .golangci.yml --timeout 20m ./pkg/... ./cmd/...` before each commit touching Go. Unit suite `go test $(go list ./... | grep -v /e2e) -count=1`; in-process end-to-end `go test ./test/e2e -count=1`. Run from the worktree root (its directory must stay named `datadog-iac-scanner`); never use sleep or polling loops.
- Every address in `references` is byte-identical to the `_dd_meta.address` of its target: build it with `address.Instance(module, block, suffix)` and `address.InstanceSuffix` from `pkg/parser/terraform/address`; parse traversals with `tfrefs.Parse` / `tfrefs.Of`.
- Only resource, data (`data.`) and ephemeral (`ephemeral.`) addresses appear; never `var.`, `local.`, `module.<name>` alone, `each`, `count` or `path`.
- References are recorded whether or not the value is known.
- When the instance cannot be determined (dynamic index), every instance of the target is listed, sorted.
- The `references` key is absent when nothing on the resource can be traced (root variable with no value, module not fetched, fallback roots); an attribute with no traced read has no entry.
- Shape mirrors the document's values: a top-level attribute is a key, a nested block is a list of objects in document order; a leaf is a sorted, duplicate-free list of address strings. A marked path whose ancestor is also marked merges into the ancestor's leaf.
- Never add marked cty values to the evaluation cache (`cache.go`), the local memo (`local_memo.go`), `equalValues` or `injectResourceRefs`.
- `references` takes part in the cross-root deduplication key; `root_modules` still does not.
- Never change finding identities, fingerprints or document keys of existing blocks.

## Review Focus

1. Two roots call one module with identical rendered content but pass references to different root resources (`aws_subnet.a.id` versus `aws_subnet.b.id`, both unknown). They must not share a document, or one root gets the other's references silently. Task 6 pins this.
2. Rewriting `root_modules` after deduplication (`setDocumentRoots`, `routeModuleFileRoots`, Task 2's routing) must keep `references`; today `rewriteBlockMeta` rebuilds the object from address and roots only. Task 6 pins this.
3. `aws_subnet.s[var.i].id` with `var.i` unknown and `count = 3` lists `[0]`, `[1]` and `[2]`, while `aws_subnet.s[1].id` lists only `[1]`. Task 4 pins this.
4. A reference to a computed attribute no configuration sets (`aws_subnet.s.id`) is still recorded (phantom attributes). Task 4 pins this.
5. A plan resource in `module.net[1]` reading `var.subnet_id`, which the caller sets from `aws_subnet.s[1].id`, lists `aws_subnet.s[1]` (root prefix), not `module.net[1].aws_subnet.s[1]`. Task 3 pins this.

---

### Task 1: Spike — measure the shadow provenance pass

**Files:**
- Create: `pkg/parser/terraform/tfeval/provenance.go` (prototype; Task 4 turns it into the real pass).
- Test: `pkg/parser/terraform/tfeval/evaluator_test.go` (existing), next to `BenchmarkResolveLocalsChain`, reusing `writeModule`.
- Create: `.superpowers/sdd/2026-11-01-terraform-contract-04-references/spike.md` (the result file; `.superpowers/` is git-excluded, so it stays local and the ruling is also copied into the commit's ledger entry).

**Interfaces:**
- Produces (prototype; names kept by Task 4):

```go
type refMark struct {
	addr string
	all  bool // marks a whole block's collection, not one instance
}

// References returns r's _dd_meta.references, or nil when nothing is traced.
func References(r *ResolvedResource) map[string]interface{}
```

The prototype must exercise every cost the real pass has: copying the scope's resource, data and ephemeral variables with each instance object marked `refMark{addr}` and each block collection marked `refMark{addr: base, all: true}`; phantom attributes as marked unknowns; re-evaluating locals the body reads (with `evalLocal`, never `localValue`); re-evaluating the call chain's call-site arguments (`CallSite.Body` in `CallSite.Caller`'s context) for `var.*`; `evalBodyWith` with `(&bodyState{}).withoutMemo()`; `UnmarkDeepWithPaths`. It need not get every address right.

- [ ] **Step 1: Write the fixture generator** `writeProvenanceRepo(tb testing.TB, roots, subnets int) []string` returning root dirs: a `modules/network` module with `aws_subnet.s` (`count = var.n`), `aws_network_security_group.g`, `azurerm_subnet_network_security_group_association.a` (`count = var.n`, `subnet_id = local.ids[count.index]`, `local.ids = aws_subnet.s[*].id`, `nsg = var.nsg_id`), nested one level into `modules/network/rules` that reads a module input; each of `roots` roots declares one `aws_network_security_group.root`, calls `module "net"` twice (`n = subnets` and `n = 1`) passing `nsg_id = aws_network_security_group.root.id`.
- [ ] **Step 2: Write** `BenchmarkProvenancePass` with sub-benchmarks `eval` (every root through `New().EvaluateModule`) and `eval+references` (the same, then `References` on every returned resource), for `roots` in `{10, 50, 200}` and `subnets = 8`, with `b.ReportAllocs()`. Add `TestProvenanceSpikeReport`, skipped unless `DD_PROVENANCE_SPIKE` is set, that runs both via `testing.Benchmark` at `roots = 200`, samples peak `runtime.MemStats.HeapInuse` for each, and prints the ratios.
- [ ] **Step 3: Implement the prototype** in `provenance.go` until `TestProvenanceSpikeReport` runs and the `eval+references` arm returns a non-nil map for the association resources.
- [ ] **Step 4: Run** `DD_PROVENANCE_SPIKE=1 go test ./pkg/parser/terraform/tfeval -run TestProvenanceSpikeReport -bench BenchmarkProvenancePass -benchtime 5x -count 1`. Expected: numbers printed for all three sizes.
- [ ] **Step 5: Write `spike.md`** with exactly these sections:
  - `Fixture`: roots, resources and documents at each size.
  - `Results`: a table `size | eval ns/op | +refs ns/op | time ratio | eval B/op | +refs B/op | alloc ratio | eval peak heap | +refs peak heap | heap ratio`.
  - `Ruling: shadow` when every ratio at `roots = 200` is at most 1.25, else `Ruling: static`, with one sentence naming the ratio that decided it.
  - `Notes`: what the prototype did not cover that could change the cost.
- [ ] **Step 6: Lint, then commit** with "Measure the cost of a shadow provenance pass over a large multi-root module tree." If the ruling is `static`, delete `provenance.go` and the benchmark's `eval+references` arm in the same commit, keep the generator for Task F1.

**Ruling gate:** Tasks 4-8 run only on `Ruling: shadow`. On `Ruling: static`, run F1-F3, then Tasks 6 and 8 with `References` replaced by F1's function. The controller records the ruling in the progress ledger before dispatching Task 4 or F1.

### Task 2: Unresolved module directories carry their callers' roots

**Files:**
- Modify: `pkg/engine/module_resolve.go`. Add `unresolvedRoots map[string][]string` (dir to sorted roots) to `moduleResolutionResult`, filled in `resolveModuleDocuments` after `scrubInstantiatedForUnresolvedDirs` from `rootsReaching(roots, staticCalls, map[string][]*model.FileMetadata{dir: filesByDir[dir]})` for each dir of `unresolvedModuleDirs`; in `instantiateLocalModules`, call the new routing for files of those dirs.
- Test: `pkg/engine/module_resolve_test.go` (existing).

**Interfaces:**
- Consumes: `rewriteBlockMeta` (as fixed by Task 6 to keep other keys; until then it rebuilds from address and roots, which is enough here).
- Produces: `func routeUnresolvedDirRoots(files model.FileMetadatas, unresolvedRoots map[string][]string, repoPath string)`: for each file whose `moduleFileDir` has roots, set every block's `root_modules` to them, keeping its bare address. A directory with no reaching root keeps its own root.

- [ ] **Step 1: Write the failing tests** in `module_resolve_test.go`, building on `TestResolveModuleDocuments_PartialRootFailureKeepsModuleBody`'s fixture:
  - `TestUnresolvedDirListsCallerRoots`: `envs/a` and `envs/b` call `modules/m`, whose evaluation fails in both (depth or cycle stop as in that test). After `instantiateLocalModules`, `metaOf(..., "aws_s3_bucket", "b")["root_modules"]` is `["envs/a", "envs/b"]` and `address` is `aws_s3_bucket.b`.
  - `TestUnresolvedDirReachedThroughOpaqueCall`: a root whose module source is `"${var.src}"` is listed (opaque calls reach everything, as in `rootsReaching`).
  - `TestUncalledDirKeepsOwnRoot`: a directory no root calls keeps `[own dir]`.
- [ ] **Step 2: Run** `go test ./pkg/engine -run 'TestUnresolvedDir|TestUncalledDirKeepsOwnRoot' -count=1`. Expected: FAIL.
- [ ] **Step 3: Implement** the field, its computation and `routeUnresolvedDirRoots`, called after `routeModuleFileRoots`. The roots are repository-relative, using the same conversion `resourceRootModule` uses.
- [ ] **Step 4: Run** `go test ./pkg/engine/... -count=1` and `go test ./test/e2e -count=1`. All `ok`.
- [ ] **Step 5: Lint, then commit** with "List the calling roots in the metadata of module directories that could not be evaluated."

### Task 3: Plan references from the plan configuration

**Files:**
- Modify: `pkg/parser/json/tfplan.go`. Add `References any \`json:"references,omitempty"\`` to `tfplanResourceMeta`; keep, per config address, the raw `expressions` and the config module path in `resourceChangeCorrelation` (new `configByAddress map[string]planConfigResource`), plus every config module's `module_calls` expressions and `outputs` expressions by config module path, and the set of planned instance addresses from `resource_changes` grouped by `canonicalConfigAddress`. `resourceMetaFor` fills `References` from the resource's own instance address. Add `PlanReferences(doc model.Document) map[[2]string]interface{}` beside `PlanAddresses`.
- Modify: `pkg/engine/terraform_meta.go`: `stampPlanMeta` takes the references map and writes `references` when present; `pkg/engine/terraform_scope.go` passes `json.PlanReferences(doc)`.
- Test: `pkg/parser/json/tfplan_test.go`, `pkg/engine/terraform_scope_test.go` (existing).

**Interfaces:**
- Produces:

```go
// planReferences resolves one expressions tree of the resource at instance
// address addr into the references shape, nil when nothing is traced.
func planReferences(expressions gjson.Result, addr string, c *resourceChangeCorrelation) map[string]interface{}
func PlanReferences(doc model.Document) map[[2]string]interface{}
func stampPlanMeta(doc map[string]interface{}, addresses map[[2]string]string, references map[[2]string]interface{}, root string)
```

Resolution of one `references` list: drop every entry for which a more specific entry with the same prefix exists (`aws_subnet.s[0]` beats `aws_subnet.s`, and `.id` suffixes are cut to the instance); resource, `data.` and `ephemeral.` entries get the resource's module instance prefix (the address up to its last `module.x[...]` step); an entry without an index on an expanded block lists every planned instance under that prefix; `var.x` resolves the parent module call's `expressions[x]` with the parent prefix; `module.m.out` / `module.m[k].out` resolves the child's `outputs[out].expression` under each matching planned instance of `module.m`; `local.*`, `each.*`, `count.*`, `path.*` and `terraform.*` contribute nothing. Recursion on `var` and outputs is bounded by the module depth.

- [ ] **Step 1: Write the failing tests** in `tfplan_test.go`, with small inline plan JSON in the style of `TestJson_parseTFPlan_dd_tfplan_meta_module_call_var_reference_attached`:
  - `TestPlanReferencesDirectAndIndexed`: `subnet_id` with references `["aws_subnet.s[0].id","aws_subnet.s[0]","aws_subnet.s"]` gives `{"subnet_id": ["aws_subnet.s[0]"]}`; with only `["aws_subnet.s.id","aws_subnet.s"]` and planned `aws_subnet.s[0]`, `aws_subnet.s[1]`, gives both.
  - `TestPlanReferencesThroughVariableAndOutput`: the Review Focus 5 case lists `["aws_subnet.s[1]"]`; a root resource reading `module.net.subnet_id`, whose output expression references `aws_subnet.s`, lists `module.net[0].aws_subnet.s` and `module.net[1].aws_subnet.s`.
  - `TestPlanReferencesNestedBlocksAndLocals`: a nested block `ingress` with two entries mirrors as a list of two objects; a reference through `local.x` is absent, and a resource with only local reads has no `References`.
  - `TestPlanReferencesDataAndEphemeral`: `data.aws_iam_policy_document.p` is kept with its `data.` prefix.
  - In `terraform_scope_test.go`, extend `TestStampTerraformScopesAddsPlanMeta` to assert `_dd_meta.references` equals the parser's value.
- [ ] **Step 2: Run** `go test ./pkg/parser/json ./pkg/engine -run 'TestPlanReferences|TestStampTerraformScopesAddsPlanMeta' -count=1`. Expected: FAIL.
- [ ] **Step 3: Implement** as above. `call_site_expressions` and `referencedArgumentChain` are left untouched (plan 8 deletes them).
- [ ] **Step 4: Run** `go test ./pkg/parser/... ./pkg/engine/... -count=1` and `go test ./test/e2e -count=1`. All `ok`; the `_dd_tfplan_meta` snapshot tests change only by the new `references` field.
- [ ] **Step 5: Lint, then commit** with "Resolve plan resource references from the plan configuration into the metadata object."

### Task 4: Shadow pass — direct reads within one module (ruling `shadow`)

**Files:**
- Modify: `pkg/parser/terraform/tfeval/provenance.go` (from Task 1).
- Modify: `pkg/parser/terraform/tfeval/evaluator.go`: `expandBlock`'s `makeOne` keeps `Iteration` for every expanded instance (the root-module exception goes), since `count.index` and `each` must be re-bound.
- Test: `pkg/parser/terraform/tfeval/document_test.go` (existing).

**Interfaces:**
- Produces: `References(r *ResolvedResource) map[string]interface{}` (signature from Task 1); `type provenanceContext struct{...}` built by `func newProvenanceContext(scope *ModuleScope, moduleAddress string) *provenanceContext`, which callers may reuse for every resource of one `(scope, moduleAddress)`; `func (p *provenanceContext) references(r *ResolvedResource) map[string]interface{}`.
- The phantom attribute set for a scope is every `tfrefs.Ref` attribute name read from `scope.Bodies` (via `tfrefs.OfBody`) on a resource, data or ephemeral target; each missing one is added to the marked instance objects as `cty.DynamicVal` marked with the instance address.
- Path collection: an instance mark gives its address; a collection mark gives every instance address of that block unless an instance mark of the same block is on the same path.

- [ ] **Step 1: Write the failing tests** in `document_test.go`, evaluating a single-root `writeModule` fixture with `New().EvaluateModule` and calling `References` on the named resource:
  - `TestReferencesDirectRead`: `subnet_id = aws_subnet.s.id` gives `{"subnet_id": ["aws_subnet.s"]}` (phantom `id`).
  - `TestReferencesCountIndexAndLiteralIndex`: with `count = 3` on both, `aws_subnet.s[count.index].id` on instance `[2]` gives `["aws_subnet.s[2]"]`; `aws_subnet.s[1].id` gives `["aws_subnet.s[1]"]`.
  - `TestReferencesDynamicIndexListsEveryInstance`: `aws_subnet.s[var.i].id` with `var.i` unset gives the three addresses, sorted.
  - `TestReferencesEachAndConditional`: `for_each` keyed `"a"`/`"b"` with `aws_subnet.s[each.key].id` gives `aws_subnet.s["a"]` on instance `["a"]`; `var.on ? aws_subnet.s["a"].id : aws_subnet.s["b"].id` with `var.on = true` gives `["aws_subnet.s[\"a\"]"]`, and with `var.on` unset both.
  - `TestReferencesNestedBlockAndDataEphemeral`: a nested `ingress` block reading `data.aws_ip_ranges.r.cidr_blocks` gives `{"ingress": [{"cidr_blocks": ["data.aws_ip_ranges.r"]}]}`; `ephemeral.random_password.p.result` gives `ephemeral.random_password.p`.
  - `TestReferencesAbsentWithoutReads`: a literal-only resource returns nil; `var.x` with no value returns nil.
  - `TestReferencesLeaveCachesUnmarked`: after `References`, `scope.evalCtx` variables, every `e.cache` entry and every `e.localMemo` value report `!v.ContainsMarked()`.
- [ ] **Step 2: Run** `go test ./pkg/parser/terraform/tfeval -run 'TestReferences' -count=1`. Expected: FAIL.
- [ ] **Step 3: Implement** `newProvenanceContext` and `references` for same-module reads; addresses via `address.Instance(moduleAddress, block, address.InstanceSuffix(key))`.
- [ ] **Step 4: Run** `go test ./pkg/parser/terraform/... -count=1`. All `ok`.
- [ ] **Step 5: Lint, then commit** with "Trace the instances a resolved Terraform resource reads in its own module through a marked shadow evaluation."

### Task 5: Shadow pass — locals, variables and module outputs (ruling `shadow`)

**Files:**
- Modify: `pkg/parser/terraform/tfeval/provenance.go`; `pkg/parser/terraform/tfeval/evaluator.go`: `ModuleScope` gains `outputs map[string]hclsyntax.Expression` (from `parsed.outputs`) and `children map[string]*ModuleScope` keyed by the call's relative instance address (`net`, `net[0]`, `net["a"]`), filled in `evaluateLocalModuleBlocks`; `evaluate` returns its scope, and `evalCacheEntry` stores it so a cache hit hands back the same child scopes.
- Test: `pkg/parser/terraform/tfeval/document_test.go` (existing).

**Interfaces:**
- Consumes: Task 4's `provenanceContext`.
- Produces: in the provenance context, `local` is re-evaluated in dependency order (`scope.localGraph`) with `evalLocal`; `var` is the call site's arguments re-evaluated in the caller's provenance context (`CallSite.Caller`, module address one step shorter), memoised per context; `module` is each child's outputs re-evaluated in the child's provenance context. Root variables stay unmarked.

- [ ] **Step 1: Write the failing tests** in `document_test.go`:
  - `TestReferencesThroughLocals`: `local.ids = aws_subnet.s[*].id`, `subnet_id = local.ids[count.index]` on instance `[1]` gives `["aws_subnet.s[1]"]`.
  - `TestReferencesThroughVariable`: a root `aws_network_security_group.g` passed as `nsg_id = aws_network_security_group.g.id` to `module "net"`; the module's association has `nsg = var.nsg_id` and gives `["aws_network_security_group.g"]` (no module prefix).
  - `TestReferencesThroughModuleOutput`: a root resource reading `module.net[0].subnet_id`, whose output is `aws_subnet.s.id`, gives `["module.net[0].aws_subnet.s"]`; reading `module.net` with an unknown index lists both module instances' subnets.
  - `TestReferencesAcrossCacheHits`: two identical calls `module "a"` and `module "b"` (cache hit on the second) give `module.a.aws_subnet.s` and `module.b.aws_subnet.s` respectively.
- [ ] **Step 2: Run** `go test ./pkg/parser/terraform/tfeval -run 'TestReferencesThrough|TestReferencesAcrossCacheHits' -count=1`. Expected: FAIL.
- [ ] **Step 3: Implement** the scope fields and the three provenance variables.
- [ ] **Step 4: Run** `go test ./pkg/parser/terraform/... -count=1`. All `ok`.
- [ ] **Step 5: Lint, then commit** with "Follow references through locals, module inputs and module outputs in the shadow evaluation."

### Task 6: References in instantiated and written documents

**Files:**
- Modify: `pkg/engine/terraform_meta.go`: `resourceMeta(addr string, roots []string, references map[string]interface{})` adds `references` when non-nil.
- Modify: `pkg/engine/module_resolve.go`: `instantiatedResource` gains `references`; `addGroupEntry` fills it from `References(r)` (one `provenanceContext` per `(r.Scope, r.ModuleAddress)` for the call to `instantiatedDocs`); `groupContentKey` hashes it (through `hashAttributes` of the map); `groupDocument` passes it; `rewriteBlockMeta` keeps every key of the existing meta except those it rewrites. Plain root resources (`r.ModuleAddress == ""`, `NoKey`, not instantiated) record their references in a new `writtenReferences map[string]map[string]interface{}` keyed by `resolvedBlockKey(fileID, kind, name)` on `moduleResolutionResult`, written into the file's `_dd_meta` in `instantiateLocalModules`.
- Test: `pkg/engine/module_resolve_test.go`, `pkg/engine/module_resolve_dedup_test.go` (existing).

**Interfaces:**
- Consumes: `References` / `newProvenanceContext` (Tasks 4-5) or F1's function.

- [ ] **Step 1: Write the failing tests:**
  - `TestInstantiatedDocCarriesReferences` (`module_resolve_test.go`, via `resolveModuleFixture`): the association in `module.net` has `_dd_meta.references.subnet_id` equal to `["module.net.aws_subnet.s[0]"]` on instance `[0]`, and each address equals the target's own `_dd_meta.address`.
  - `TestWrittenRootBlockCarriesReferences`: a plain root `aws_route_table_association.a` reading `aws_subnet.s.id` gets `references` in its written file's `_dd_meta`.
  - `TestReferencesSplitDedup` (`module_resolve_dedup_test.go`): Review Focus 1 — two roots, same rendered content, different referenced root resources: two documents, each with its own reference; identical references still give one document.
  - `TestRootRewriteKeepsReferences`: after `routeSharedDocumentRoots` and `routeModuleFileRoots`, `references` is unchanged.
- [ ] **Step 2: Run** `go test ./pkg/engine -run 'TestInstantiatedDocCarriesReferences|TestWrittenRootBlockCarriesReferences|TestReferencesSplitDedup|TestRootRewriteKeepsReferences' -count=1`. Expected: FAIL.
- [ ] **Step 3: Implement** as above.
- [ ] **Step 4: Run** `go test ./pkg/engine/... ./pkg/server/... -count=1` and `go test ./test/e2e -count=1`, plus `TestResolveModuleDocuments_DocumentsDoNotGrowWithCallSites`. All `ok`, no fingerprint change in end-to-end snapshots.
- [ ] **Step 5: Lint, then commit** with "Write traced references into the metadata of instantiated and written Terraform blocks."

### Task 7: Resource-type filter and memory guard (ruling `shadow`)

**Files:**
- Modify: `pkg/engine/module_resolve.go` (the provenance contexts are dropped when `instantiatedDocs` returns).
- Test: `pkg/engine/module_resolve_test.go`, `pkg/parser/terraform/tfeval/evaluator_test.go` (existing).

- [ ] **Step 1: Write the failing tests:**
  - `TestReferencesNameUntargetedTypes`: with rule targets naming only the association type, its `subnet_id` still lists the `aws_subnet` address (spec: a type no rule names is not evaluated, its references still appear).
  - Extend `BenchmarkProvenancePass` with a `resolveModuleDocuments` arm on `writeFanOut(t, 77, false)`-style input, and `TestProvenanceRetainsNothing`: after `resolveModuleDocuments`, `runtime.GC` and `HeapInuse` are within 5% of the same run with references disabled through an unexported test hook.
- [ ] **Step 2: Run** `go test ./pkg/engine ./pkg/parser/terraform/tfeval -run 'TestReferencesNameUntargetedTypes|TestProvenanceRetainsNothing' -count=1`. Expected: FAIL on the first if the target filter drops the type from the provenance context.
- [ ] **Step 3: Implement**: the provenance context marks every declared block type of the scope, not only targeted ones; contexts live in a map local to `instantiatedDocs`.
- [ ] **Step 4: Run** the unit suite. All `ok`.
- [ ] **Step 5: Lint, then commit** with "Keep references to untargeted resource types and release the provenance contexts after documents are built."

### Task 8: The NSG headline case end to end

**Files:**
- Test: `test/e2e/e2e_test.go` (existing), a fixture directory and a custom rule beside `Test_E2ETerraformSharedModuleRootRouting`'s.

- [ ] **Step 1: Write the failing test** `Test_E2ETerraformReferencesJoinAcrossModuleCalls`: one root calls `module "a"` with `n = 2` and `module "b"` with `n = 1`; the module declares `aws_subnet.s` (`count = 3`) and `azurerm_subnet_network_security_group_association.s` (`count = var.n`, `subnet_id = aws_subnet.s[count.index].id`). The custom rule is the spec's NSG example (join `[root, address]` on `references.subnet_id`, `rootModule: root`, silent without `_dd_meta`, and treating an association with `subnet_id` but no `references.subnet_id` as uncertain). Assert findings exactly for `module.a.aws_subnet.s[2]`, `module.b.aws_subnet.s[1]` and `module.b.aws_subnet.s[2]`. A second root whose association reads `subnet_id = var.unset` yields no finding in that root.
- [ ] **Step 2: Run it.** Expected: PASS after Tasks 4-7 (or F1-F3); FAIL before.
- [ ] **Step 3: Run** the unit suite and `go test ./test/e2e -count=1`. All `ok`.
- [ ] **Step 4: Lint, then commit** with "Pin that a rule can join module subnets to their associations through traced references."

### Fallback tasks (ruling `static` only)

Each has the same five steps and the same tests as the shadow task it replaces, with expectations relaxed where the spec's fallback contract allows over-approximation.

- **F1 (replaces 4):** `func staticReferences(r *tfeval.ResolvedResource, a *valueAnalyzer) map[string]interface{}` in a new `pkg/engine/module_references.go`, walking `r.Body` with `valueAnalyzer.collectBody` and resolving each `blockReference` through `tfrefs.Parse`; a literal index or `count.index`/`each.key` bound in `r.Iteration` selects the instance, anything else lists every instance from `valueAnalyzer.expandsInstances`. Commit: "Trace the instances a Terraform resource reads by walking its expressions statically."
- **F2 (replaces 5):** follow `valueAnalyzer.local` and `traceCallArgument` up `r.CallChain`; a `module.m.out` read lists every resource address the output's expression can reach in every instance of `module.m` (the fallback contract). Commit: "Follow static references through locals, module inputs and module outputs."
- **F3 (replaces 7):** the resource-type test of Task 7 only; no memory guard, since nothing is evaluated. Commit: "Keep static references to untargeted resource types."

Task 6 and Task 8 then run unchanged against `staticReferences`; Task 8's dynamic-index cases may list more instances, which the assertion allows only for `module.*` reads.
