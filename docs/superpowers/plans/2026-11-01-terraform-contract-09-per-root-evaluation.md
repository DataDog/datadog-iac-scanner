# Terraform contract, plan 9: per-root evaluation of cross-document rules — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Terraform rule that joins documents sees one root module at a time, so a finding on a document shared by several roots goes only to the roots where the join fails. Rules never name a root: not in their results, not in their joins, and `_dd_meta` carries no `root_modules`.

**Architecture:**
- The engine knows which roots each document stands for (primary caller, extra callers, module-file calls, plain root files, plan files, fallback roots) and keeps that off the rule input.
- At compile time each Terraform rule is classified. A rule that provably reads one document per finding is document-local, and anything else is cross-document.
- Document-local rules evaluate once over the deduplicated documents, as today, and their findings go to every caller of the document.
- Cross-document rules evaluate once per root, over an input holding only that root's documents, and their findings go only to that root. A scan with one root evaluates every rule once.
- The per-root inputs are built once per scan from the same document terms as the Terraform input, so no document is copied.

**Tech Stack:** Go, OPA (`ast`, `rego`), go-cty.

**Spec:** `docs/superpowers/specs/2026-11-01-terraform-rule-input-contract-design.md` (Contract; Decided: per-root evaluation).

## Owner decisions

- Rule results are platform-agnostic. A result never carries `rootModule` or any other Terraform routing; the field was removed before this plan.
- The engine attributes findings to roots by evaluating cross-document rules per root, and rules join on `_dd_meta.address` alone.
- `_dd_meta.root_modules` is removed: rules see one root's documents, so they do not need it.
- Performance comes from evaluating only cross-document rules per root, sharing document terms, and profiling. There are no caps: no ratio gates, no limits on roots or documents, and no fallback that skips per-root evaluation above some size.

## Plan series

1-5, 7. Done. Plan 3's result-field routing was removed (`Stop reading a root module from rule results...`). 6. Rules migration (rules repository), rewritten on this contract: joins on `address`, no root anywhere in a rule. 8. Removing `_dd_tfplan_meta` and the plan-address path. 9. This plan.

## Global Constraints

- The scanner repository is public: no customer names, internal links or private content in code, fixtures or commits.
- Commit messages are one sentence and never name the upstream scanner this one was forked from.
- No verbose comments; tests go in an existing test file when one fits.
- Lint: `$(go env GOPATH)/bin/golangci-lint run -c .golangci.yml --timeout 20m ./pkg/... ./cmd/...` before each commit touching Go. Unit suite `go test $(go list ./... | grep -v /e2e) -count=1`; e2e `go test ./test/e2e -count=1`. Run from the worktree root (directory stays `datadog-iac-scanner`); never sleep or poll.
- The rule result shape is unchanged for every platform. Nothing in this plan reads a new key from a result.
- Finding identities (`resource_id`, `root_module`) and fingerprints of document-local findings are unchanged. Cross-document findings keep their identities, and only the roots they are reported in change.
- Non-Terraform platforms and their inputs are untouched.
- Document count must not grow with call sites (`TestResolveModuleDocuments_DocumentsDoNotGrowWithCallSites` stays green unchanged).
- No caps (see Owner decisions).

## Review Focus

1. Roots `envs/a` and `envs/b` call one module whose `azurerm_subnet.s` document is shared. Only `envs/a` has an association referencing it. A rule joining on `address` alone yields exactly one finding, with root module `envs/b`. Task 4 pins it end to end.
2. A document-local rule on the same shared subnet yields one finding per root, with today's fingerprints. Task 4 pins it.
3. A rule that calls a library helper scanning `input.document` is cross-document even though its own body has one loop. A rule that reads `input.document[0]`, passes `input` or `input.document` to a function, or uses `walk(input)` is cross-document. Task 2 pins each.
4. Supersede prediction (`findingSet.supersedes`, `findingIdentities`) agrees with routing for a per-root run (`TestFindingSet_SupersedesMeansRouteKeepsNothingNew` extended). Task 4 pins it.
5. A plan file and a fallback root each form their own root. Task 1 pins it.

---

### Task 1: The roots each document stands for

**Files:**
- Modify: `pkg/engine/module_resolve.go` (the resolution result gains `docRoots map[string][]string`: document id to sorted repository-relative roots).
- Test: `pkg/engine/module_resolve_test.go`, `pkg/engine/module_resolve_dedup_test.go`.

**Interfaces:**
- Produces: `docRoots` for every Terraform document in the payload, from the engine's own structures: the group's `rootModule`, `extras[docID]`, `moduleFiles[docID].calls`, plain root files (their root), plan files (the plan file path), fallback roots (as `_dd_meta.root_modules` computes them today).

- [ ] **Step 1: Write the failing test** `TestDocRootsMatchMetadataRoots`: on the multi-root dedup fixture, a fallback-root fixture and a plan fixture, `docRoots[id]` equals the document's `_dd_meta.root_modules` for every resource-bearing document. This pins the replacement before Task 5 removes the metadata.
- [ ] **Step 2: Run** `go test ./pkg/engine -run TestDocRootsMatchMetadataRoots -count=1`. Expected: FAIL (undefined).
- [ ] **Step 3: Implement**, run `go test ./pkg/engine/... -count=1`, lint, commit with "Record the root modules each Terraform document stands for in the engine."

**Review gate:** per-task reviewer (routing).

### Task 2: Classify rules as document-local or cross-document

**Files:**
- Create: `pkg/engine/rule_document_scope.go`.
- Test: `pkg/engine/rule_document_scope_test.go`.
- Modify: where rule-targeted resource types are computed (`pkg/engine/rule_resource_types.go`), to compute the scope from the same compiled modules.

**Interfaces:**
- Produces: `crossDocument(query) bool` per loaded Terraform query, from the compiled rule and its libraries.
- A rule is document-local only when every body of its entry rule reaches exactly one iteration over `input.document` and nothing else reachable from it reads `input.document` or `input` as a whole. Reachable means through rule references, partial rules, functions and library calls, as `cmd/perf_static.go` in the rules repository follows them. Anything the analysis cannot prove is cross-document.

- [ ] **Step 1: Write the failing tests:** a table of Rego modules covering a single loop (local); two loops (cross); a loop plus a membership test on a partial set built over `input.document` (cross); a loop plus a call to a library function that iterates `input.document` (cross); `input.document[0]` (cross); `walk(input)` (cross); `input.document` passed to a function (cross); several entry bodies each with one loop (local).
- [ ] **Step 2: Run** `go test ./pkg/engine -run TestRuleDocumentScope -count=1`. Expected: FAIL.
- [ ] **Step 3: Implement.** Then run the classifier over the rules repository's Terraform rules (`/Users/chakib.hamie/dd/datadog-iac-scanner-default-rules/.worktrees/terraform_rule_input_contract/assets`) with a throwaway driver and record the cross-document count and list in the report. Do not commit the driver.
- [ ] **Step 4:** Lint, commit with "Classify Terraform rules by whether they read more than one document."

**Review gate:** per-task reviewer (a local misclassification attributes a join finding to every root).

### Task 3: Per-root inputs

**Files:**
- Modify: `pkg/engine/inspector.go` (`platformPayloads` gains `terraformByRoot map[string]ast.Value`, built next to `byPlatform`).
- Test: `pkg/engine/inspector_test.go`.

**Interfaces:**
- Produces: for each root, `{"document": [...]}` holding the terms of exactly the Terraform documents whose `docRoots` include it, in payload order, the same `*ast.Term` values as the Terraform bucket. Built once per scan, only when a cross-document Terraform rule is loaded and the scan has more than one root.

- [ ] **Step 1: Write the failing tests:** term pointer identity with the Terraform bucket; a shared document appears in each of its roots; one root builds no partitions; no cross-document rule builds no partitions.
- [ ] **Step 2: Run**, implement, run `go test ./pkg/engine/... -count=1`, lint, commit with "Build one Terraform input per root module from the shared document terms."

**Review gate:** controller skim; whole-plan review.

### Task 4: Evaluate cross-document rules per root

**Files:**
- Modify: `pkg/engine/inspector.go` (`evalQuery` and the worker loop: a cross-document Terraform rule becomes one work unit per root), `pkg/engine/findings.go` (`findingSet` routing and `findingIdentities`/`appendRouteIdentities` take the run's root: the primary copy only when its root is the run root, extra callers and module-file calls only for the run root).
- Test: `pkg/engine/findings_test.go`, `pkg/engine/inspector_test.go`, `test/e2e` (new `Test_E2ETerraformSharedModuleCrossDocumentRule` with a custom rule directory, as `Test_E2ETerraformPlanFlag` sets up rules).

- [ ] **Step 1: Write the failing tests:** Review Focus 1 and 2 end to end; Review Focus 4 as a unit test; a single-root scan reports the same findings and fingerprints before and after.
- [ ] **Step 2: Run** them. Expected: FAIL on Review Focus 1 (two findings, one per root).
- [ ] **Step 3: Implement.** Per-root units of one rule share the prepared query and run on the existing worker pool. Their findings merge into the rule's result in root order, so output order is deterministic.
- [ ] **Step 4: Run** the unit suite and e2e, lint, commit with "Evaluate Terraform rules that join documents once per root module and report their findings in that root."

**Review gate:** per-task reviewer (routing, identity).

### Task 5: Remove `root_modules` from `_dd_meta`

**Files:**
- Modify: `pkg/engine/terraform_meta.go`, `pkg/engine/module_resolve.go`, `pkg/parser/json/` plan metadata stamping, and every test asserting `root_modules`. The spec already describes the contract without it.

- [ ] **Step 1:** Change the metadata tests to expect no `root_modules`; keep `TestDocRootsMatchMetadataRoots` as `TestDocRoots` with the expected roots written out.
- [ ] **Step 2: Implement**, run the unit suite and e2e, lint, commit with "Stop writing root modules into Terraform resource metadata, since rules see one root at a time."

**Review gate:** per-task reviewer (public contract).

### Task 6: Measure and optimise

**Files:**
- Modify: `pkg/engine/module_resolve_bench_test.go` or the inspector benchmarks (add `BenchmarkInspectMultiRootCrossDocument`: 10, 50 and 200 roots calling shared modules, one document-local and one cross-document rule).

- [ ] **Step 1:** Run the benchmark (medians of 5, `-benchtime 5x`) and the large-monorepo memory profile from PR #468 at the commit before Task 3, then at HEAD. Record time, B/op and peak heap in the progress file.
- [ ] **Step 2:** Profile HEAD (`-cpuprofile`, `-memprofile`). Optimise what the profile shows, for example partition building, per-unit setup, decode or worker scheduling. Commit each optimisation separately with its before and after numbers in the report.
- [ ] **Step 3:** Report the final numbers to the owner. There is no pass/fail ratio (Owner decisions).

**Review gate:** whole-plan review.
