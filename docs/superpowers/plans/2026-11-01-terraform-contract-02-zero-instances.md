# Terraform contract, plan 2: zero-instance blocks disappear — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A resource, data or ephemeral block whose `count`/`for_each` is known to produce zero instances in every evaluated call no longer reaches the rules, as in Terraform.

**Architecture:**
- The evaluator already sees these blocks: `expandBlock` returns nothing for them. Today that is indistinguishable from "never evaluated", so the engine leaves the block in its written file. The evaluator now records them, following the existing `ModuleInstance` bookkeeping (record, cache, replay, take).
- The engine treats a block that is zero-instance in every evaluation, and has no instance in any, as replaced: the existing `removeInstantiatedResources` path deletes it from the written file and its line-info document.

**Tech Stack:** Go, `hashicorp/hcl/v2`, `zclconf/go-cty`.

**Spec:** `docs/superpowers/specs/2026-11-01-terraform-rule-input-contract-design.md` (Goal 2).

## Plan series (revised)

Plan 1 landed (deletions and groundwork). Remaining, each written when the previous one lands:

2. This plan: zero-instance blocks disappear.
3. `_dd_meta` (address, root modules) written into every resource of an evaluated root. Includes patching evaluated values into the plain root documents in place, which is how Goal 1 is reached for non-expanded blocks, and the `rootModule` routing of rule results.
4. References: the measured spike, source references, then the plan resolver.
5. Plan input: unknown placeholders, `_dd_meta.unknown`, dropping nulls and empty blocks, line-detection fallback.
6. Rules repository migrations and library deletions.
7. One evaluator for all blocks, the ported variable-file directive, and the converter shrink. `joinPlainRootSiblings` is deleted here, once rules no longer need same-document siblings.
8. Removing `_dd_tfplan_meta` and the plan-address path.

Carried from plan 1's review: any hand-built `ResolvedResource` in a test must set `BaseName` and `Key`, or `instantiatedDocs` treats it as unexpanded.

## Global Constraints

- The scanner repository is public: no customer names, internal links or private content in code, fixtures or commits.
- Commit messages are one sentence and never contain the name KICS.
- No verbose comments; put tests in an existing test file when one fits.
- Lint: `$(go env GOPATH)/bin/golangci-lint run -c .golangci.yml --timeout 20m ./pkg/... ./cmd/...` before each commit touching Go. Unit suite `go test $(go list ./... | grep -v /e2e) -count=1`, in-process end-to-end `go test ./test/e2e -count=1`.
- Run commands from the worktree root; never use sleep or polling loops.
- Unknown `count`/`for_each` keeps today's single placeholder instance. Only a known zero drops a block.
- Never change finding identities, addresses or document keys of blocks that still exist.
- Never add marked cty values to the evaluation cache, the local memo or `equalValues`.

## Review Focus

1. A module file called twice, with zero instances in one call and instances in the other, must keep its blocks and findings. Task 2 pins this.
2. `count = var.enabled ? 1 : 0` with `enabled` defaulting false drops the block; with `enabled` having no value it keeps one placeholder instance. Task 1 pins both.
3. A module cache hit (same directory and inputs reached through another call path) must still report the zero-instance blocks. Task 1 pins this.
4. A root that failed to evaluate, or a directory in `unresolvedModuleDirs`, must keep its blocks as written. Task 2 pins this.
5. A `for_each` over an empty map or empty set, a data block and an ephemeral block each drop independently of a managed resource with the same type and name. Task 2 pins this.

---

### Task 1: The evaluator records zero-instance blocks

**Files:**
- Modify: `pkg/parser/terraform/tfeval/evaluator.go`.
  - Add the `EmptyBlock` type and `TakeEmptyBlocks`.
  - Add an `emptyBlocks` field to `Evaluator` and `evalCacheEntry` (`cache.go`).
  - Mirror every place `e.instances` is saved, truncated on a failed evaluation, replayed on a cache hit, reset in `EvaluateModule` and handed over by `TakeModuleInstances` (search `e.instances` and `instancesBefore`).
  - Record in `expandBlock`'s zero-items case.
- Modify: `pkg/parser/terraform/tfeval/data.go`. A data block that expands to zero instances records the same way (the call is at `d.e.expandBlock(b, evalCtx, d.addr, d.chain, true)`). Record once per final evaluation of the module, not once per refresh.
- Test: `pkg/parser/terraform/tfeval/evaluator_test.go` (existing).

**Interfaces:**
- Produces:

```go
// EmptyBlock is a resource, data or ephemeral block whose count or for_each
// expanded to zero instances.
type EmptyBlock struct {
	Type, Name, DefinedIn string // DefinedIn as in ResolvedResource.DefinedIn
	Data, Ephemeral       bool
}

// TakeEmptyBlocks returns the blocks the last EvaluateModule found empty, and clears them.
func (e *Evaluator) TakeEmptyBlocks() []EmptyBlock
```

- [ ] **Step 1: Write the failing tests** in `evaluator_test.go`, using the file's existing helpers for evaluating a directory fixture:
  - `TestEmptyBlocks_KnownZero`: one module with `aws_s3_bucket.a` (`count = 0`), `aws_s3_bucket.b` (`for_each = {}`), `aws_s3_bucket.c` (`count = var.on ? 1 : 0` with `variable "on" { default = false }`), and `data.aws_iam_policy_document.d` (`count = 0`). Assert `TakeEmptyBlocks()` holds exactly those four, with `Data` true for `d`, and that the resolved resources contain none of them.
  - `TestEmptyBlocks_UnknownKeepsPlaceholder`: `count = var.n` with `variable "n" {}`. Assert the block is not in `TakeEmptyBlocks()` and resolves to one instance.
  - `TestEmptyBlocks_ReplayedOnCacheHit`: the same module directory reached from two module calls with identical inputs. Assert `TakeEmptyBlocks()` after one `EvaluateModule` of the parent lists the empty block (once per distinct `DefinedIn`, `Type`, `Name` is enough; duplicates are allowed).
  - `TestEmptyBlocks_ClearedByTake`: a second `TakeEmptyBlocks()` returns nil.
- [ ] **Step 2: Run** `go test ./pkg/parser/terraform/tfeval -run 'TestEmptyBlocks' -count=1`. Expected: FAIL, undefined `TakeEmptyBlocks`.
- [ ] **Step 3: Implement** the type, field, recording, cache save and replay, truncation on failure and `TakeEmptyBlocks`, mirroring `ModuleInstance` bookkeeping. Record unconditionally; it needs no tracking switch.
- [ ] **Step 4: Run** `go test ./pkg/parser/terraform/... -count=1`. All `ok`.
- [ ] **Step 5: Lint, then commit** with "Record the blocks whose count or for_each expands to zero instances."

### Task 2: The engine drops zero-instance blocks from the written files

**Files:**
- Modify: `pkg/engine/module_resolve.go`.
  - `evaluateRootModules` and the `rootMerge` / `rootResult` types carry the empty blocks next to the module instances (`evaluator.TakeModuleInstances()` call sites at `merge` and `evaluateRoot`).
  - `resolveModuleDocuments` computes the dropped set and adds it to the `instantiated` index before `res.suppressed` is built.
  - Extract the block-kind string used by `blockKind` into `func blockKindOf(typ string, data, ephemeral bool) string`, and use it for both.
- Test: `pkg/engine/module_resolve_test.go` (existing).

**Interfaces:**
- Consumes: `tfeval.EmptyBlock`, `Evaluator.TakeEmptyBlocks()` (Task 1).
- Produces: `func blockKindOf(typ string, data, ephemeral bool) string` with the same result as today's `blockKind` for a resolved resource.

**Rule for the dropped set:** an `EmptyBlock` is dropped when no `ResolvedResource` anywhere in the same resolution has the same `DefinedIn` (absolute), kind and `BaseName`. The block is then recorded with `instantiated.add(fileID, kind, name)`, which makes the existing removal loop delete it from `Document` and `LineInfoDocument`. The existing guard stays: a file whose directory is in `unresolvedModuleDirs` keeps everything.

- [ ] **Step 1: Write the failing tests** in `module_resolve_test.go`, using that file's existing helpers for building a repository and calling `resolveModuleDocuments`:
  - `TestZeroInstanceBlockIsRemovedFromItsFile`: a root `main.tf` with `aws_s3_bucket.gone` (`count = 0`) and `aws_s3_bucket.kept`, with a rule target matching `aws_s3_bucket`. Assert the written file's document has `kept` and not `gone`, and that its line-info document matches.
  - `TestZeroInstanceBlockRemovedWhenTypeIsNotTargeted`: same, with no rule target. `gone` is still removed.
  - `TestZeroInThisCallInstancesInAnother`: a module directory called twice, `count = var.n` with `n = 0` in one call and `n = 2` in the other. Assert the block still produces two instance documents and stays in `suppressed`.
  - `TestDataAndEphemeralEmptyBlocksDropIndependently`: `aws_x.same` (`count = 1`), `data.aws_x.same` (`count = 0`), `ephemeral.aws_x.same` (`count = 0`). Assert only the managed resource remains.
  - `TestUnresolvedDirKeepsEmptyBlocks`: a directory in `unresolvedModuleDirs` keeps a `count = 0` block as written.
- [ ] **Step 2: Run** `go test ./pkg/engine -run 'TestZeroInstance|TestZeroInThisCall|TestDataAndEphemeralEmpty|TestUnresolvedDirKeeps' -count=1`. Expected: FAIL.
- [ ] **Step 3: Implement** `blockKindOf`, the carrying of empty blocks, and the dropped-set rule above.
- [ ] **Step 4: Run** `go test ./pkg/engine/... ./pkg/server/... -count=1`. All `ok`.
- [ ] **Step 5: Lint, then commit** with "Drop blocks that expand to zero instances from the scanned files."

### Task 3: End to end

**Files:**
- Test: `test/e2e` (existing Terraform end-to-end test file and fixtures; add a fixture directory only if no existing one fits).

- [ ] **Step 1: Write the failing test.** A Terraform fixture with `resource "aws_s3_bucket" "off" { count = 0 ... }` that violates a rule shipped for the scanner tests and a second, enabled violating bucket. Scan it in-process like the neighbouring tests do. Assert the finding exists for the enabled bucket and that no finding names `off`.
- [ ] **Step 2: Run** `go test ./test/e2e -run <name> -count=1`. Expected: FAIL before Task 2's behaviour is wired through the fixture, PASS after. If it already passes because Tasks 1 and 2 are in, record that in the report and keep the test as the regression pin.
- [ ] **Step 3: Run the unit suite and the in-process end-to-end tests.** All `ok`.
- [ ] **Step 4: Lint, then commit** with "Pin that blocks with a known zero count produce no findings."
