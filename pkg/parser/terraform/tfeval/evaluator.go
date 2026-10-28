/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package tfeval evaluates local Terraform modules: bind inputs, resolve locals,
// recurse into nested modules, emit resource and data instances with concrete cty
// values where possible. Anything still unresolvable (e.g. computed attributes or
// data source results localdata does not compute) stays cty.UnknownVal.
package tfeval

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/internal/pathutil"
	"github.com/DataDog/datadog-iac-scanner/pkg/ctyutil"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/dynamicblock"
	tffunctions "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/functions"
	tfinstances "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/instances"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/resolver"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/partial"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
	"github.com/zclconf/go-cty/cty/gocty"
)

const (
	// defaultMaxDepth caps nested module recursion (cycles, deep graphs).
	defaultMaxDepth = 15
	// localsMaxPasses caps fixed-point resolution of locals that reference each other.
	localsMaxPasses = 10
	// resourceRefPasses caps passes that install same-module resource attrs for refs.
	resourceRefPasses = 3
	// maxCountExpansion caps instances per count/for_each block (resources and modules).
	maxCountExpansion = tfinstances.MaxPerBlock
	// maxExpansionShape is the largest truncated count/for_each collection we will
	// materialize with unknown tails so length() and missing keys stay honest.
	// Beyond this, the whole ref becomes unknown instead of allocating a huge shape.
	maxExpansionShape = 512
	// defaultMaxInstantiated is the last-resort cap on resources one scan may
	// instantiate, counted over the whole scan rather than per root: the documents
	// an instantiated resource turns into are retained until the scan ends. A cap
	// that resets per root bounds no total at all, because a repository can hold
	// any number of roots and a pod runs several scans concurrently (four by
	// default), each with its own evaluator.
	defaultMaxInstantiated = 150000
)

// ErrModuleNotEvaluated reports that a module was skipped rather than evaluated,
// so callers must leave it to be scanned as written instead of treating it as a
// module that resolved to nothing.
var ErrModuleNotEvaluated = errors.New("tfeval: module not evaluated")

// ResolvedResource is a resource block after evaluation with attributes
// resolved to concrete cty values where possible, unknown otherwise.
type ResolvedResource struct {
	Type       string
	Name       string
	Attributes map[string]cty.Value
	// Body is the resource's HCL body, used to recover the reference text of
	// attributes evaluation could not resolve. It is not consulted during
	// evaluation, so recovered references never feed back into resolved values.
	Body *hclsyntax.Body
	// Scope is the module declaring the resource as it was evaluated.
	Scope *ModuleScope
	// Iteration holds the each or count value of an expanded instance, nil
	// for a block without count or for_each.
	Iteration map[string]cty.Value

	// Source location and module address for finding attribution.
	DefinedIn     string
	DefLine       int
	DefEndLine    int
	DefColumn     int
	DefEndColumn  int
	ModuleAddress string // "" for root module resources
	CallChain     []CallSite
	// ExpansionTruncated is set when count/for_each produced more instances than
	// maxCountExpansion; the source block must stay in the scan for the rest.
	ExpansionTruncated bool
	// ExpansionTotal is the full count/for_each size when ExpansionTruncated.
	ExpansionTotal int
	// ExpansionKeys is every for_each key when truncated and within
	// maxExpansionShape, so ref injection can pad omitted keys as unknown.
	ExpansionKeys []string
	// DynamicCounts is how many blocks each dynamic block of Body generated for
	// this instance, so generated blocks can be mapped back to their sources.
	DynamicCounts DynamicCounts

	// Data marks an instance of a data block rather than a resource.
	Data bool
}

// CallSite records one hop in a module call chain.
type CallSite struct {
	ModuleName      string
	Source          string
	Version         string
	CalledFrom      string
	CalledLine      int
	CalledEndLine   int
	CalledColumn    int
	CalledEndColumn int
	// Body is the module block's body, used to trace a resource attribute back
	// to the call argument that sets it. Read-only after evaluation.
	Body *hclsyntax.Body
	// Caller is the module declaring the call as it was evaluated.
	Caller *ModuleScope
}

// ModuleScope is a module's local value expressions with the var and local
// values its blocks were evaluated with, so a value can be traced back to the
// module inputs it reads after evaluation. Read-only after evaluation.
type ModuleScope struct {
	Locals map[string]hclsyntax.Expression
	// Bodies are the module's parsed files, from which the resource and data
	// blocks a value references can be read.
	Bodies []*hclsyntax.Body
	Var    cty.Value
	Local  cty.Value

	// evalCtx is the context the module's blocks were evaluated in, final once
	// evaluation completes, and sources the module's files by filename. They
	// let a value evaluation could not resolve be rendered as its parts.
	evalCtx *hcl.EvalContext
	sources map[string][]byte

	// localDeps classifies, per local, which of the roots that change during
	// evaluation (the module's resources, its module outputs, its data) the
	// local reads, directly or through other locals; localCache holds the
	// values the last resolution returned. A re-resolution re-evaluates only
	// the locals reading a root that changed, and reuses the rest verbatim.
	localDeps  map[string]localDeps
	localCache map[string]cty.Value
}

// localDeps records which changing roots a local's value follows. The
// classification is transitive: a local reading another local that reads
// resources is marked as reading resources too.
type localDeps struct {
	resources bool
	modules   bool
	data      bool
}

// dataLocals returns the locals reading data.*, directly or through other
// locals, per the classification resolveLocalsIncremental computed. It must
// run after that first resolution, which is what computes the classification.
func (s *ModuleScope) dataLocals() map[string]bool {
	out := make(map[string]bool, len(s.localDeps))
	for name, deps := range s.localDeps {
		if deps.data {
			out[name] = true
		}
	}
	return out
}

// ModuleInstance is one evaluated call of a module directory, whether or not
// the module declares resources.
type ModuleInstance struct {
	Dir           string
	ModuleAddress string
	CallChain     []CallSite
}

// Evaluator evaluates local Terraform modules.
type Evaluator struct {
	funcs    map[string]function.Function
	maxDepth int
	// cyclicDataWarned holds the directories already warned about for a data
	// reference cycle.
	cyclicDataWarned sync.Map
	// fsys serves the evaluator's directory reads (module and tfvars files).
	// Defaults to the real disk; content-push scans inject an in-memory FS.
	fsys vfs.FS
	// cache memoizes completed module evaluations keyed by (dir, packageRoot,
	// input digest). A single Evaluator is used for an entire scan, so entries
	// with the same key represent the same module reached with the same resolved
	// inputs, whatever path led there.
	cache   map[evalCacheKey]*evalCacheEntry
	keyMemo keyMemo
	// localMemo shares local values across the module evaluations reading the
	// same values; localReads is what each local expression reads. Both follow
	// the evaluation cache's lifetime.
	localMemo  map[localMemoKey]cty.Value
	localReads map[hclsyntax.Expression]localReads
	// When set, non-local module sources resolve here and recurse with caller inputs.
	remoteResolver RemoteResolver

	// Aggregate cap on resources this evaluator will instantiate, enforced inside
	// the recursion rather than between root modules: a single root can expand
	// without bound, so a check that only runs at root boundaries never fires.
	maxInstantiated int
	instantiated    int
	// Speculative sibling evaluation is bounded separately from final instances.
	prepassInstantiated int
	prepassDepth        int
	budgetExceeded      bool
	// budgetRefusals counts the budget checks that refused work: a failed
	// chargeInstantiationBudget, an exhausted budget at evaluationStop, or a
	// resource expansion over its remaining limit. Charges are rolled back only
	// when no refusal happened since the snapshot: restoring after a refusal
	// hands the full budget to the next instance or sibling, which redoes the
	// refused work and fails the same way, once per remaining instance.
	budgetRefusals int
	skipped        uint64
	// budgetDemand is the most instantiated resources any budget check since
	// the last ResetBudgetDemand needed room for: evaluation started from an
	// earlier count makes the same decisions while that count plus the demand
	// stays within the budget.
	budgetDemand int

	// count/for_each expansion truncation observability (scan-wide on this evaluator).
	expansionTruncations    int
	expansionMaxRequested   int
	expansionTruncationWarn bool

	// dataBlockEvals counts the data block expansions that actually ran, so
	// tests can check what the eval cache and budget skips save.
	dataBlockEvals int

	// notEvaluatedDirs holds every module directory this evaluator declined to
	// evaluate for depth, cycle or budget. It accumulates for the whole scan
	// because suppression is decided per directory over all call sites at once:
	// one skipped instance means the directory is only partially resolved, so
	// its body must stay in the scan even though other instances did resolve.
	notEvaluatedDirs map[string]bool

	// instances holds the module calls the running EvaluateModule evaluated.
	// They are only collected when trackInstances is set.
	instances      []ModuleInstance
	trackInstances bool

	// parseMu guards dirCache, which evaluators forked from one another share.
	parseMu  *sync.Mutex
	dirCache map[string]dirParse
	// funcFS serves the Terraform filesystem functions of every module this
	// evaluator reaches, so paths confined once stay resolved for the scan.
	funcFS *tffunctions.ScanFS

	// mergeAllow, when set, limits OpenTofu twin-shadowing to inventory paths.
	mergeAllow map[string]struct{}
}

type dirParse struct {
	bodies  []*hclsyntax.Body
	sources map[string][]byte
	err     error
}

func New() *Evaluator {
	return NewWithFS(vfs.DiskFS{})
}

// FS returns the filesystem the evaluator reads module and tfvars files through.
func (e *Evaluator) FS() vfs.FS {
	return e.fsys
}

// NewWithFS builds an Evaluator that reads module and tfvars files through
// fsys. A nil fsys falls back to the real disk.
func NewWithFS(fsys vfs.FS) *Evaluator {
	if fsys == nil {
		fsys = vfs.Default()
	}
	return &Evaluator{
		funcs:            tffunctions.TerraformFuncs,
		maxDepth:         defaultMaxDepth,
		maxInstantiated:  defaultMaxInstantiated,
		cache:            make(map[evalCacheKey]*evalCacheEntry),
		parseMu:          &sync.Mutex{},
		dirCache:         make(map[string]dirParse),
		funcFS:           tffunctions.NewScanFS(vfs.DiskFS{}),
		notEvaluatedDirs: make(map[string]bool),
		fsys:             fsys,
	}
}

// skipEvaluation records dir as not evaluated and returns ErrModuleNotEvaluated.
func (e *Evaluator) skipEvaluation(dir string) error {
	e.skipped++
	e.notEvaluatedDirs[filepath.Clean(dir)] = true
	return ErrModuleNotEvaluated
}

// NotEvaluatedDirs returns the module directories that were skipped rather than
// evaluated. Callers must keep the content of these directories in the scan: a
// directory can have both resolved and skipped call sites, and the skipped ones
// have no synthetic document standing in for them.
func (e *Evaluator) NotEvaluatedDirs() []string {
	dirs := make([]string, 0, len(e.notEvaluatedDirs))
	for dir := range e.notEvaluatedDirs {
		dirs = append(dirs, dir)
	}
	return dirs
}

// SetMaxInstantiated overrides the instantiation budget. A value of zero or less
// disables it.
func (e *Evaluator) SetMaxInstantiated(n int) { e.maxInstantiated = n }

// MaxInstantiated reports the per-scan instantiation budget.
func MaxInstantiated() int { return defaultMaxInstantiated }

// MaxCountExpansion reports the per-block count/for_each instance cap.
func MaxCountExpansion() int { return maxCountExpansion }

// MaxDynamicExpansion is the cap on the blocks one dynamic block generates.
func MaxDynamicExpansion() int { return dynamicblock.MaxExpansion }

func truncationMessage(kind string) string {
	if kind == "dynamic" {
		return "tfeval: dynamic block expansion cap exceeded; block scanned as written"
	}
	return "tfeval: count/for_each expansion truncated; remaining instances scanned as written"
}

// InstantiatedCount reports how many module resources have been charged against
// the scan-wide retained-document budget.
func (e *Evaluator) InstantiatedCount() int { return e.instantiated }

// RestoreInstantiatedCount rolls back charges from a root whose evaluation failed
// after descendants were counted but before any documents were emitted.
func (e *Evaluator) RestoreInstantiatedCount(n int) {
	e.instantiated = n
	e.budgetExceeded = e.maxInstantiated > 0 && e.instantiated >= e.maxInstantiated
}

// restoreInstantiationCount rolls back the active budget counter (scan-wide or
// speculative prepass) after a nested evaluation is discarded. budgetExceeded is
// left alone: a failed charge already recorded that the scan hit the limit.
func (e *Evaluator) restoreInstantiationCount(n int) {
	*e.currentInstantiationCount() = n
}

func (e *Evaluator) parseDir(ctx context.Context, dir, packageRoot string) ([]*hclsyntax.Body, map[string][]byte, error) {
	key := filepath.Clean(dir) + "\x00" + filepath.Clean(packageRoot)

	e.parseMu.Lock()
	if dp, ok := e.dirCache[key]; ok {
		e.parseMu.Unlock()
		return dp.bodies, dp.sources, dp.err
	}
	e.parseMu.Unlock()

	bodies, sources, err := parseDir(ctx, dir, packageRoot, e.mergeAllow, e.fsys)

	e.parseMu.Lock()
	e.dirCache[key] = dirParse{bodies: bodies, sources: sources, err: err}
	e.parseMu.Unlock()
	return bodies, sources, err
}

// Fork returns an evaluator that can evaluate other roots concurrently with e.
// It shares e's settings and its parse and path caches; its evaluation cache,
// budget counters and skipped directories are its own.
func (e *Evaluator) Fork() *Evaluator {
	return &Evaluator{
		funcs:            e.funcs,
		maxDepth:         e.maxDepth,
		fsys:             e.fsys,
		cache:            make(map[evalCacheKey]*evalCacheEntry),
		remoteResolver:   e.remoteResolver,
		maxInstantiated:  e.maxInstantiated,
		notEvaluatedDirs: make(map[string]bool),
		parseMu:          e.parseMu,
		dirCache:         e.dirCache,
		funcFS:           e.funcFS,
		mergeAllow:       e.mergeAllow,
		trackInstances:   e.trackInstances,
	}
}

// SetTrackModuleInstances makes evaluations record the module calls they
// evaluate, for TakeModuleInstances. Forks inherit the setting.
func (e *Evaluator) SetTrackModuleInstances(track bool) { e.trackInstances = track }

// InstantiationBudget reports the evaluator's instantiation budget; zero or less
// means none.
func (e *Evaluator) InstantiationBudget() int { return e.maxInstantiated }

// ResetBudgetDemand starts a new BudgetDemand measurement.
func (e *Evaluator) ResetBudgetDemand() { e.budgetDemand = 0 }

// BudgetDemand reports the most instantiated resources, counted from the
// evaluator's count at ResetBudgetDemand, any budget check has needed room for.
func (e *Evaluator) BudgetDemand() int { return e.budgetDemand }

func (e *Evaluator) noteBudgetDemand(demand int) {
	if e.prepassDepth == 0 && demand > e.budgetDemand {
		e.budgetDemand = demand
	}
}

// ExpansionTruncations reports how many count/for_each/dynamic expansions hit a cap.
func (e *Evaluator) ExpansionTruncations() int { return e.expansionTruncations }

// ExpansionMaxRequested reports the largest requested instance count seen when truncating.
func (e *Evaluator) ExpansionMaxRequested() int { return e.expansionMaxRequested }

// DataBlockEvaluations reports how many data block expansions ran, counting
// only evaluations the eval cache could not avoid.
func (e *Evaluator) DataBlockEvaluations() int { return e.dataBlockEvals }

// AddExpansionStats folds truncation counters from a forked evaluator into e.
func (e *Evaluator) AddExpansionStats(hits, maxRequested int) {
	e.expansionTruncations += hits
	if maxRequested > e.expansionMaxRequested {
		e.expansionMaxRequested = maxRequested
	}
}

// TakeExpansionStats returns and clears truncation counters recorded since the last take.
func (e *Evaluator) TakeExpansionStats() (hits, maxRequested int) {
	hits = e.expansionTruncations
	maxRequested = e.expansionMaxRequested
	e.expansionTruncations = 0
	e.expansionMaxRequested = 0
	e.expansionTruncationWarn = false
	return hits, maxRequested
}

func (e *Evaluator) noteCountExpansionTruncated(ctx context.Context, kind, address string, requested, expanded, limit int) {
	if e.prepassDepth > 0 {
		return
	}
	e.expansionTruncations++
	if requested > e.expansionMaxRequested {
		e.expansionMaxRequested = requested
	}
	if e.expansionTruncationWarn {
		return
	}
	e.expansionTruncationWarn = true
	contextLogger := logger.FromContext(ctx)
	contextLogger.Warn().
		Str("expansion_kind", kind).
		Str("address", address).
		Int("requested_instances", requested).
		Int("expanded_instances", expanded).
		Int("count_expansion_cap", limit).
		Msg(truncationMessage(kind))
}

// TakeNotEvaluatedDirs returns the directories skipped since the last call and
// forgets them.
func (e *Evaluator) TakeNotEvaluatedDirs() []string {
	dirs := e.NotEvaluatedDirs()
	e.notEvaluatedDirs = make(map[string]bool)
	return dirs
}

// TakeModuleInstances returns the module calls the last EvaluateModule
// evaluated, nothing when it failed, and forgets them.
func (e *Evaluator) TakeModuleInstances() []ModuleInstance {
	instances := e.instances
	e.instances = nil
	return instances
}

// recordModuleInstance notes an evaluated call when instances are tracked. The
// chain is shared with the call's resources and must not be modified.
func (e *Evaluator) recordModuleInstance(dir, addr string, chain []CallSite) {
	if e.trackInstances {
		e.instances = append(e.instances, ModuleInstance{Dir: dir, ModuleAddress: addr, CallChain: chain})
	}
}

// AddNotEvaluatedDirs records directories another evaluator skipped.
func (e *Evaluator) AddNotEvaluatedDirs(dirs []string) {
	for _, dir := range dirs {
		e.notEvaluatedDirs[dir] = true
	}
}

// ForgetRootParse drops the parsed files of dir once it has been evaluated as a
// root module. The parse cache pays off for modules many roots call; a root is
// evaluated once, so keeping its files only holds memory until the scan ends.
// Anything that reaches dir again parses it again.
func (e *Evaluator) ForgetRootParse(dir string) {
	abs, err := e.fsys.Abs(dir)
	if err != nil {
		abs = filepath.Clean(dir)
	}
	key := filepath.Clean(abs) + "\x00" + filepath.Clean("")
	e.parseMu.Lock()
	delete(e.dirCache, key)
	e.parseMu.Unlock()
}

func (e *Evaluator) SetRemoteResolver(r RemoteResolver) {
	e.remoteResolver = r
}

// SetMergeAllow restricts OpenTofu twin-shadowing to inventory paths.
func (e *Evaluator) SetMergeAllow(allow map[string]struct{}) {
	e.mergeAllow = allow
}

func (e *Evaluator) ReleaseCaches() {
	e.ReleaseEvalCache()
	e.parseMu.Lock()
	e.dirCache = make(map[string]dirParse)
	e.parseMu.Unlock()
	e.funcFS = tffunctions.NewScanFS(vfs.DiskFS{})
}

// ReleaseEvalCache drops memoized module evaluations while keeping parsed HCL
// bodies. The key includes rootDir, so a later root does not reuse them, and
// each entry holds its subtree. The parse cache is keyed by directory alone
// and is kept.
func (e *Evaluator) ReleaseEvalCache() {
	e.cache = make(map[evalCacheKey]*evalCacheEntry)
	e.keyMemo = keyMemo{}
	e.ReleaseLocalMemo()
	e.localReads = nil
}

// ReleaseLocalMemo drops local values shared across module instances.
func (e *Evaluator) ReleaseLocalMemo() {
	e.localMemo = nil
}

// LocalMemoSize, KeyMemoSize and EvalCacheSize report what a root left retained.
func (e *Evaluator) LocalMemoSize() int { return len(e.localMemo) }

// KeyMemoSize reports collections retained so their digests stay valid.
func (e *Evaluator) KeyMemoSize() int { return len(e.keyMemo.entries) }

// EvalCacheSize reports memoized module evaluations.
func (e *Evaluator) EvalCacheSize() int { return len(e.cache) }

// EvaluateModule evaluates the module rooted at dir with the given inputs and
// returns all resources materialized by this module and its nested modules.
// visitedChildDirs contains every child directory that was successfully evaluated
// as a module (i.e. dirs that should be suppressed from standalone scanning).
func (e *Evaluator) EvaluateModule(
	ctx context.Context,
	dir string,
	inputs map[string]cty.Value,
) (resources []ResolvedResource, outputs map[string]cty.Value, visitedChildDirs map[string]bool, err error) {
	ctx = pathutil.WithResolvedPathCache(ctx)
	// fsys.Abs, not filepath.Abs: a content-push FS keeps the pushed path shape,
	// and resolving against the process CWD would break key matching against
	// the pushed file set. DiskFS.Abs is filepath.Abs, so the CLI is unchanged.
	abs, absErr := e.fsys.Abs(dir)
	if absErr != nil {
		contextLogger := logger.FromContext(ctx)
		contextLogger.Warn().Err(absErr).Msgf("tfeval: resolving module dir %s failed, falling back to Clean", dir)
		abs = filepath.Clean(dir)
	}
	visiting := map[string]bool{}
	allVisited := map[string]bool{}
	instantiatedBefore := e.instantiated
	e.instances = nil
	resources, outputs, err = e.evaluate(ctx, abs, abs, "", inputs, "", nil, 0, visiting, allVisited)
	if err != nil {
		e.RestoreInstantiatedCount(instantiatedBefore)
		e.instances = nil
	}
	return resources, outputs, allVisited, err
}

// evaluate is the recursive worker; visiting tracks dirs on the current stack for cycle
// detection; allVisited accumulates every child dir successfully evaluated as a module.
func (e *Evaluator) evaluate(
	ctx context.Context,
	dir, rootDir string,
	packageRoot string,
	inputs map[string]cty.Value,
	addr string,
	chain []CallSite,
	depth int,
	visiting map[string]bool,
	allVisited map[string]bool,
) ([]ResolvedResource, map[string]cty.Value, error) {
	if err := e.evaluationStop(ctx, dir, depth, visiting); err != nil {
		return nil, nil, err
	}

	cacheKey := evalCacheKey{
		dir:         dir,
		rootDir:     rootDir,
		packageRoot: packageRoot,
		inputs:      e.keyMemo.inputsKey(inputs),
	}
	if resources, outputs, hit, err := e.reuseCachedEvaluation(
		ctx, cacheKey, dir, addr, chain, depth, allVisited,
	); hit {
		return resources, outputs, err
	}

	visiting[dir] = true
	defer delete(visiting, dir)
	skippedBefore := e.skipped
	instancesBefore := len(e.instances)

	// Snapshot allVisited so we can determine which dirs this subtree adds.
	prevAllVisited := make(map[string]bool, len(allVisited))
	for k := range allVisited {
		prevAllVisited[k] = true
	}

	bodies, sources, err := e.parseDir(ctx, dir, packageRoot)
	if err != nil {
		return nil, nil, err
	}

	varDecls, localExprs, moduleBlocks, resourceBlocks, outputExprs := collectBlocks(bodies)

	varVals := e.resolveVariables(varDecls, inputs)

	evalCtx := &hcl.EvalContext{
		Variables: map[string]cty.Value{
			"var": objectOrEmpty(varVals),
		},
		Functions: tffunctions.EvalFuncsWithRoot(dir, rootDir, e.funcFS),
	}
	for name, value := range tffunctions.ContextVariables(dir, rootDir) {
		evalCtx.Variables[name] = value
	}

	resourceTypes := declaredResourceTypes(resourceBlocks)
	scope := &ModuleScope{Locals: localExprs, Bodies: bodies, Var: evalCtx.Variables["var"], evalCtx: evalCtx, sources: sources}
	evalCtx.Variables["local"] = objectOrEmpty(
		e.resolveLocalsIncremental(scope, localExprs, resourceTypes, evalCtx, false, false))
	data := newModuleData(e, bodies, sources, scope, resourceTypes, addr, chain, hasUnconditionalResourceBlock(resourceBlocks))
	e.noteCyclicData(ctx, dir, data)
	data.refresh(ctx, evalCtx)

	if !e.preinjectResourceRefs(ctx, resourceBlocks, moduleBlocks, localExprs, scope, resourceTypes, evalCtx, data, addr, chain) {
		return nil, nil, e.skipEvaluation(dir)
	}

	reads := callSiblingReads(moduleBlocks)
	e.applySiblingModulePrepass(
		ctx, moduleBlocks, reads, evalCtx, scope, data, dir, rootDir, packageRoot, addr, chain, depth, visiting,
	)

	childResources, moduleOutputs := e.evaluateLocalModuleBlocks(
		ctx, moduleBlocks, reads, evalCtx, scope, data, localExprs, dir, rootDir, packageRoot, addr, chain, depth, visiting,
		allVisited,
	)

	e.applyModuleOutputs(ctx, evalCtx, scope, localExprs, data, moduleOutputs)

	rootResources, err := e.evaluateRootResources(
		ctx, dir, resourceBlocks, localExprs, scope, resourceTypes, evalCtx, data, addr, chain,
	)
	if err != nil {
		return nil, nil, err
	}

	// Re-inject the final-pass resource values so that outputs and locals that
	// reference the Nth hop of an N-hop chain can resolve. For chains shorter
	// than resourceRefPasses hops all resources were already injected inside the
	// loop, so injectResourceRefs returns false and the locals refresh is skipped.
	if injectResourceRefs(evalCtx, rootResources) {
		evalCtx.Variables["local"] = objectOrEmpty(
			e.resolveLocalsIncremental(scope, localExprs, resourceTypes, evalCtx, true, false))
	}
	if data.readsOwnResources() {
		data.refresh(ctx, evalCtx)
	}
	scope.Local = evalCtx.Variables["local"]
	for i := range rootResources {
		rootResources[i].Scope = scope
	}
	dataInstances := data.resolved(scope)
	// Charge resources and data together so a module that fits only one of the
	// two does not leave a partial charge when its evaluation is discarded.
	if !e.chargeModuleCall(ctx, addr, len(rootResources)+len(dataInstances)) {
		return nil, nil, e.skipEvaluation(dir)
	}
	resources := make([]ResolvedResource, 0, len(rootResources)+len(dataInstances)+len(childResources))
	resources = append(resources, rootResources...)
	resources = append(resources, dataInstances...)
	resources = append(resources, childResources...)

	outputs := make(map[string]cty.Value, len(outputExprs))
	for name, expr := range outputExprs {
		outputs[name] = e.evalExpr(expr, evalCtx)
	}

	// Collect dirs added to allVisited during this evaluation for the cache entry.
	var visitedDirs []string
	for d := range allVisited {
		if !prevAllVisited[d] {
			visitedDirs = append(visitedDirs, d)
		}
	}
	e.cacheCompletedEvaluation(
		cacheKey, skippedBefore, resources, e.instances[instancesBefore:], outputs, visitedDirs, addr, len(chain), depth,
	)

	return resources, outputs, nil
}

// applyModuleOutputs installs the module.* outputs of the module calls and
// refreshes what reads them.
func (e *Evaluator) applyModuleOutputs(
	ctx context.Context,
	evalCtx *hcl.EvalContext,
	scope *ModuleScope,
	localExprs map[string]hclsyntax.Expression,
	data *moduleData,
	moduleOutputs map[string]cty.Value,
) {
	e.installModuleOutputs(ctx, evalCtx, scope, localExprs, data, moduleOutputs)
}

// installModuleOutputs publishes module.* and refreshes what reads it: first
// the locals reading module outputs, then the data blocks. That locals-before-
// data ordering is load-bearing. Republishing the module.* value the data was
// already refreshed against skips the refresh: nothing data reads changed.
func (e *Evaluator) installModuleOutputs(
	ctx context.Context,
	evalCtx *hcl.EvalContext,
	scope *ModuleScope,
	localExprs map[string]hclsyntax.Expression,
	data *moduleData,
	moduleOutputs map[string]cty.Value,
) {
	if len(moduleOutputs) == 0 {
		return
	}
	value := cty.ObjectVal(moduleOutputs)
	evalCtx.Variables["module"] = value
	evalCtx.Variables["local"] = objectOrEmpty(
		e.resolveLocalsIncremental(scope, localExprs, nil, evalCtx, false, true))
	if !data.readsModules() || data.refreshedWithModule(value) {
		return
	}
	data.refresh(ctx, evalCtx)
}

func (e *Evaluator) evaluationStop(
	ctx context.Context,
	dir string,
	depth int,
	visiting map[string]bool,
) error {
	contextLogger := logger.FromContext(ctx)
	if depth > e.maxDepth {
		contextLogger.Warn().Msgf("tfeval: max module depth %d exceeded at %s", e.maxDepth, dir)
		return e.skipEvaluation(dir)
	}
	if visiting[dir] {
		contextLogger.Warn().Msgf("tfeval: module cycle detected at %s, stopping recursion", dir)
		return e.skipEvaluation(dir)
	}
	if e.instantiationBudgetExhausted() {
		e.reportInstantiationBudgetExceeded(ctx, *e.currentInstantiationCount())
		return e.skipEvaluation(dir)
	}
	return nil
}

func (e *Evaluator) reuseCachedEvaluation(
	ctx context.Context,
	key evalCacheKey,
	dir, addr string,
	chain []CallSite,
	depth int,
	allVisited map[string]bool,
) (
	resources []ResolvedResource,
	outputs map[string]cty.Value,
	hit bool,
	err error,
) {
	entry, ok := e.cache[key]
	if !ok {
		return nil, nil, false, nil
	}
	if entry.evalDepth > depth {
		return nil, nil, false, nil
	}
	if e.prepassDepth == 0 || entry.baseAddr != addr || entry.baseChainLen != len(chain) {
		if charge := moduleResourceCount(entry.resources); charge > 0 {
			if !e.chargeInstantiationBudget(ctx, charge) {
				return nil, nil, true, e.skipEvaluation(dir)
			}
		}
	}
	for _, visited := range entry.visitedDirs {
		allVisited[visited] = true
	}
	e.instances = append(e.instances, entry.rebaseInstances(addr, chain)...)
	return entry.rebase(addr, chain), entry.outputs, true, nil
}

func (e *Evaluator) preinjectResourceRefs(
	ctx context.Context,
	resourceBlocks, moduleBlocks []*hclsyntax.Block,
	localExprs map[string]hclsyntax.Expression,
	scope *ModuleScope,
	resourceTypes map[string]struct{},
	evalCtx *hcl.EvalContext,
	data *moduleData,
	addr string,
	chain []CallSite,
) bool {
	if len(resourceBlocks) == 0 || len(moduleBlocks) == 0 {
		return true
	}
	resources, complete := e.evalResourceBlocks(
		ctx, resourceBlocks, evalCtx, addr, chain, e.remainingInstantiationBudget(),
	)
	if !complete {
		return false
	}
	injected := injectResourceRefs(evalCtx, resources)
	evalCtx.Variables["local"] = objectOrEmpty(
		e.resolveLocalsIncremental(scope, localExprs, resourceTypes, evalCtx, injected, false))
	if data.readsOwnResources() {
		data.refresh(ctx, evalCtx)
	}
	return true
}

func (e *Evaluator) evaluateRootResources(
	ctx context.Context,
	dir string,
	resourceBlocks []*hclsyntax.Block,
	localExprs map[string]hclsyntax.Expression,
	scope *ModuleScope,
	resourceTypes map[string]struct{},
	evalCtx *hcl.EvalContext,
	data *moduleData,
	addr string,
	chain []CallSite,
) ([]ResolvedResource, error) {
	resources, complete := e.rootResourcesWithRefPasses(
		ctx, resourceBlocks, localExprs, scope, resourceTypes, evalCtx, data, addr, chain,
	)
	if !complete {
		return nil, e.skipEvaluation(dir)
	}
	return resources, nil
}

func (e *Evaluator) cacheCompletedEvaluation(
	key evalCacheKey,
	skippedBefore uint64,
	resources []ResolvedResource,
	instances []ModuleInstance,
	outputs map[string]cty.Value,
	visitedDirs []string,
	addr string,
	chainLen int,
	depth int,
) {
	if e.skipped != skippedBefore {
		return
	}
	for i := range resources {
		if resources[i].ExpansionTruncated {
			return
		}
	}
	e.cache[key] = &evalCacheEntry{
		resources:    resources,
		instances:    slices.Clone(instances),
		outputs:      outputs,
		visitedDirs:  visitedDirs,
		baseAddr:     addr,
		baseChainLen: chainLen,
		evalDepth:    depth,
	}
}

// moduleResourceCount is what a cached evaluation charges the instantiation
// budget: the resource and data instances of module calls, which are retained
// alike.
func moduleResourceCount(resources []ResolvedResource) int {
	n := 0
	for i := range resources {
		if resources[i].ModuleAddress != "" {
			n++
		}
	}
	return n
}

// chargeModuleCall charges n instances of a module call to the instantiation
// budget. The root module's own instances are not charged.
func (e *Evaluator) chargeModuleCall(ctx context.Context, addr string, n int) bool {
	return addr == "" || e.chargeInstantiationBudget(ctx, n)
}

func (e *Evaluator) chargeInstantiationBudget(ctx context.Context, n int) bool {
	if n == 0 || e.maxInstantiated <= 0 {
		return true
	}
	instantiated := e.currentInstantiationCount()
	e.noteBudgetDemand(*instantiated + n)
	if n <= e.maxInstantiated-*instantiated {
		*instantiated += n
		if *instantiated == e.maxInstantiated {
			e.reportInstantiationBudgetExceeded(ctx, *instantiated)
		}
		return true
	}
	e.reportInstantiationBudgetExceeded(ctx, *instantiated)
	e.noteBudgetRefusal()
	return false
}

// noteBudgetRefusal records that a budget check refused work, so a rollback
// spanning it would retry work the budget already declined.
func (e *Evaluator) noteBudgetRefusal() { e.budgetRefusals++ }

func (e *Evaluator) reportInstantiationBudgetExceeded(ctx context.Context, instantiated int) {
	if e.prepassDepth > 0 {
		return
	}
	if e.budgetExceeded {
		return
	}
	e.budgetExceeded = true
	contextLogger := logger.FromContext(ctx)
	contextLogger.Warn().
		Int("resources_instantiated", instantiated).
		Int("resource_budget", e.maxInstantiated).
		Msg("tfeval: module instantiation budget exhausted; " +
			"stopping recursion, remaining modules are scanned as written")
}

func (e *Evaluator) remainingInstantiationBudget() int {
	if e.maxInstantiated <= 0 {
		return -1
	}
	return e.maxInstantiated - *e.currentInstantiationCount()
}

func (e *Evaluator) currentInstantiationCount() *int {
	if e.prepassDepth > 0 {
		return &e.prepassInstantiated
	}
	return &e.instantiated
}

func (e *Evaluator) instantiationBudgetExhausted() bool {
	if e.maxInstantiated <= 0 {
		return false
	}
	count := *e.currentInstantiationCount()
	e.noteBudgetDemand(count + 1)
	if count >= e.maxInstantiated {
		e.noteBudgetRefusal()
		return true
	}
	return false
}

// BudgetExceeded reports whether evaluation stopped early for budget, so callers
// can leave the modules it did not reach to be scanned as written.
func (e *Evaluator) BudgetExceeded() bool { return e.budgetExceeded }

// ResetSpeculativeBudget clears the counter for speculative sibling evaluation at
// a root boundary. That work is discarded once the root it belongs to is done.
//
// The count of resources actually instantiated is deliberately not reset. Those
// become documents that live until the scan ends, so their bound has to span the
// scan; resetting it per root is what left the total unbounded when several scans
// ran concurrently on one pod.
func (e *Evaluator) ResetSpeculativeBudget() {
	e.prepassInstantiated = 0
}

func (e *Evaluator) applySiblingModulePrepass(
	ctx context.Context,
	moduleBlocks []*hclsyntax.Block,
	reads []siblingReads,
	evalCtx *hcl.EvalContext,
	scope *ModuleScope,
	data *moduleData,
	dir, rootDir, packageRoot, addr string,
	chain []CallSite,
	depth int,
	visiting map[string]bool,
) {
	if len(moduleBlocks) <= 1 {
		return
	}
	prelimOutputs := e.preliminaryModuleOutputs(
		ctx, moduleBlocks, reads, evalCtx, scope, dir, rootDir, packageRoot, addr, chain, depth, visiting,
	)
	e.installModuleOutputs(ctx, evalCtx, scope, scope.Locals, data, prelimOutputs)
}

func (e *Evaluator) evaluateLocalModuleBlocks(
	ctx context.Context,
	moduleBlocks []*hclsyntax.Block,
	reads []siblingReads,
	evalCtx *hcl.EvalContext,
	scope *ModuleScope,
	data *moduleData,
	localExprs map[string]hclsyntax.Expression,
	dir, rootDir, packageRoot, addr string,
	chain []CallSite,
	depth int,
	visiting map[string]bool,
	allVisited map[string]bool,
) (childResources []ResolvedResource, moduleOutputs map[string]cty.Value) {
	contextLogger := logger.FromContext(ctx)

	// Seed with the pre-pass values already in evalCtx so that forward dependencies
	// (module B referencing module C where C appears later in file order) survive the
	// first iteration's evalCtx.Variables["module"] update.
	moduleOutputs = publishedModuleOutputs(evalCtx)

	// Data reading module outputs is refreshed on every publication, so it
	// keeps being published after every call.
	var siblings *siblingOutputs
	if !data.readsModules() {
		siblings = &siblingOutputs{
			e: e, ctx: ctx, evalCtx: evalCtx, scope: scope, localExprs: localExprs, data: data, outputs: moduleOutputs,
		}
	}
	for blockIndex, mb := range moduleBlocks {
		callCtx := evalCtx
		if siblings != nil {
			callCtx = siblings.contextFor(&reads[blockIndex])
		}
		call, ok := e.resolveModuleCall(ctx, mb, callCtx, dir, packageRoot)
		if !ok {
			continue
		}
		plan := moduleInstances(mb, callCtx)
		if plan.truncated() {
			kind := "module_count"
			if plan.mode == expansionForEach {
				kind = "module_for_each"
			}
			e.noteCountExpansionTruncated(ctx, kind, "module."+call.label, plan.requested, len(plan.instances), maxCountExpansion)
			// The instances left out have no synthetic document standing in
			// for them, so the module must also be scanned as written.
			_ = e.skipEvaluation(call.dir)
		}
		site := call.site(scope)
		outs := make([]cty.Value, len(plan.instances))
		for i, instance := range plan.instances {
			modInputs := e.evalBody(mb.Body, instance.ctx, reservedModuleAttrs)
			childAddr := instance.address(addr, call.label)
			childChain := append(cloneChain(chain), site)
			instancesBefore := len(e.instances)
			instantiatedBefore := *e.currentInstantiationCount()
			refusalsBefore := e.budgetRefusals

			childRes, childOuts, cErr := e.evaluate(
				ctx, call.dir, rootDir, call.packageRoot, modInputs, childAddr,
				childChain, depth+1, visiting, allVisited,
			)
			if cErr != nil {
				if isReportableModuleEvalError(cErr) {
					contextLogger.Warn().Msgf("tfeval: failed to evaluate module %q at %s: %v", call.label, call.dir, cErr)
				}
				// Deliberately not added to allVisited: the module was not resolved, so
				// it must keep being scanned where it is written.
				e.discardFailedChild(instancesBefore, instantiatedBefore, refusalsBefore)
				continue
			}
			e.recordModuleInstance(call.dir, childAddr, childChain)
			allVisited[call.dir] = true
			childResources = append(childResources, childRes...)
			outs[i] = objectOrEmpty(childOuts)
		}
		if value, ok := moduleOutputsValue(plan, outs); ok {
			if siblings != nil {
				siblings.set(call.label, value)
				continue
			}
			moduleOutputs[call.label] = value
			e.installSiblingModuleOutputs(ctx, evalCtx, scope, localExprs, data, moduleOutputs)
		}
	}
	return childResources, moduleOutputs
}

// noteCyclicData warns, once per directory, about the data blocks reading their
// own result, which data.* exposes as unknown.
func (e *Evaluator) noteCyclicData(ctx context.Context, dir string, data *moduleData) {
	if data == nil || len(data.cyclic) == 0 {
		return
	}
	if _, seen := e.cyclicDataWarned.LoadOrStore(dir, true); seen {
		return
	}
	names := make([]string, 0, len(data.cyclic))
	for b := range data.cyclic {
		names = append(names, terraform.DataKey(b.Labels[0], b.Labels[1]))
	}
	slices.Sort(names)
	contextLogger := logger.FromContext(ctx)
	contextLogger.Warn().Strs("data_blocks", names).
		Msgf("tfeval: data reference cycle at %s; the blocks are read as unknown", dir)
}

// publishedModuleOutputs returns the module outputs evalCtx already publishes
// as module.*, by call name.
func publishedModuleOutputs(evalCtx *hcl.EvalContext) map[string]cty.Value {
	out := map[string]cty.Value{}
	existing, ok := evalCtx.Variables["module"]
	if !ok || !existing.IsKnown() || existing.IsNull() || !existing.Type().IsObjectType() {
		return out
	}
	for it := existing.ElementIterator(); it.Next(); {
		k, v := it.Element()
		if name, ok := ctyutil.ConcreteString(k); ok {
			out[name] = v
		}
	}
	return out
}

// discardFailedChild drops the instances and charges a failed child left
// behind, mirroring EvaluateModule, so siblings can still use the budget — but
// not when the failure was the budget itself: the refusal stands, so the
// remaining instances stop early instead of redoing the same work with a
// budget that would refuse it again.
func (e *Evaluator) discardFailedChild(instancesBefore, instantiatedBefore, refusalsBefore int) {
	e.instances = e.instances[:instancesBefore]
	if e.budgetRefusals == refusalsBefore {
		e.restoreInstantiationCount(instantiatedBefore)
	}
}

// installSiblingModuleOutputs publishes module.* for later siblings and
// refreshes locals and data that read those outputs.
func (e *Evaluator) installSiblingModuleOutputs(
	ctx context.Context,
	evalCtx *hcl.EvalContext,
	scope *ModuleScope,
	localExprs map[string]hclsyntax.Expression,
	data *moduleData,
	moduleOutputs map[string]cty.Value,
) {
	e.installModuleOutputs(ctx, evalCtx, scope, localExprs, data, moduleOutputs)
}

// isReportableModuleEvalError excludes a missing local source, which the module
// parser already reports.
func isReportableModuleEvalError(err error) bool {
	return !errors.Is(err, ErrModuleNotEvaluated) && !errors.Is(err, fs.ErrNotExist)
}

func (e *Evaluator) resolveModuleDir(
	ctx context.Context, callerDir, packageRoot, source, version, callerFile, moduleName string,
) (dir, childPackageRoot string, ok bool) {
	if tfmodules.LooksLikeLocalModuleSource(source) {
		if packageRoot == "" {
			dir, _, err := tfmodules.LocalModuleDirWithContext(ctx, e.fsys, callerDir, source)
			return dir, "", err == nil
		}
		localDir := resolveLocalDir(callerDir, source)
		confined, resolveErr := resolver.ResolvePathWithinRoot(ctx, packageRoot, localDir)
		return confined, packageRoot, resolveErr == nil
	}
	if e.remoteResolver != nil {
		return e.remoteResolver(source, version, callerFile, moduleName)
	}
	return "", "", false
}

func (e *Evaluator) rootResourcesWithRefPasses(
	ctx context.Context,
	resourceBlocks []*hclsyntax.Block,
	localExprs map[string]hclsyntax.Expression,
	scope *ModuleScope,
	resourceTypes map[string]struct{},
	evalCtx *hcl.EvalContext,
	data *moduleData,
	addr string,
	chain []CallSite,
) ([]ResolvedResource, bool) {
	var rootResources []ResolvedResource
	types := declaredResourceTypes(resourceBlocks)
	localsReadOwn := localsReadResources(localExprs, types)
	dataReadsOwn := data.readsOwnResources()
	// Resources may consume refreshed data through locals (data → local →
	// resource) without a direct data.* traversal in the body.
	readsDataPath := resourcesReadResources(resourceBlocks, dataRoot)
	if data != nil {
		readsDataPath = readsDataPath || resourcesReadNamedLocals(resourceBlocks, data.dataLocals)
	}
	readsOwn := localsReadOwn || resourcesReadResources(resourceBlocks, types) ||
		(dataReadsOwn && readsDataPath)
	for pass := 0; pass < resourceRefPasses; pass++ {
		var complete bool
		rootResources, complete = e.evalResourceBlocks(
			ctx, resourceBlocks, evalCtx, addr, chain, e.remainingInstantiationBudget(),
		)
		if !complete {
			return nil, false
		}
		// Always inject so resolved attrs reach evalCtx on every pass including the last.
		changed := injectResourceRefs(evalCtx, rootResources)
		if !changed || !readsOwn {
			// Nothing the resource blocks or locals read has changed, so
			// evaluating them again would reproduce these instances.
			return rootResources, true
		}
		// Refresh locals after every successful injection so that locals referencing
		// newly-resolved resource attrs are up-to-date before outputs are computed.
		if localsReadOwn {
			evalCtx.Variables["local"] = objectOrEmpty(
				e.resolveLocalsIncremental(scope, localExprs, resourceTypes, evalCtx, true, false))
		}
		if dataReadsOwn {
			data.refresh(ctx, evalCtx)
		}
		if pass+1 >= resourceRefPasses {
			break
		}
	}
	// One final evaluation picks up attrs that were only injected on the last pass
	// (e.g. the Nth resource in an A→B→C→D chain whose evalCtx was updated after the
	// last evalResourceBlocks call).
	return e.evalResourceBlocks(
		ctx, resourceBlocks, evalCtx, addr, chain, e.remainingInstantiationBudget(),
	)
}

// declaredResourceTypes returns the resource types a module declares, the
// variables injecting its resources can change.
func declaredResourceTypes(resourceBlocks []*hclsyntax.Block) map[string]struct{} {
	types := make(map[string]struct{}, len(resourceBlocks))
	for _, rb := range resourceBlocks {
		if len(rb.Labels) >= 2 {
			types[rb.Labels[0]] = struct{}{}
		}
	}
	return types
}

func localsReadResources(localExprs map[string]hclsyntax.Expression, types map[string]struct{}) bool {
	for _, expr := range localExprs {
		if readsResource(expr, types) {
			return true
		}
	}
	return false
}

func resourcesReadResources(resourceBlocks []*hclsyntax.Block, types map[string]struct{}) bool {
	for _, rb := range resourceBlocks {
		if bodyReadsResource(rb.Body, types) {
			return true
		}
	}
	return false
}

// resourcesReadNamedLocals reports whether any resource body reads one of the
// named locals (for example locals that alias data.*).
func resourcesReadNamedLocals(resourceBlocks []*hclsyntax.Block, names map[string]bool) bool {
	if len(names) == 0 {
		return false
	}
	for _, rb := range resourceBlocks {
		if bodyReadsNamedLocals(rb.Body, names) {
			return true
		}
	}
	return false
}

func bodyReadsNamedLocals(body *hclsyntax.Body, names map[string]bool) bool {
	for _, attr := range body.Attributes {
		if readsNamedLocals(attr.Expr, names) {
			return true
		}
	}
	for _, block := range body.Blocks {
		if bodyReadsNamedLocals(block.Body, names) {
			return true
		}
	}
	return false
}

func readsNamedLocals(expr hclsyntax.Expression, names map[string]bool) bool {
	for _, traversal := range expr.Variables() {
		name, ok := terraform.LocalTraversalName(traversal)
		if ok && names[name] {
			return true
		}
	}
	return false
}

func bodyReadsResource(body *hclsyntax.Body, types map[string]struct{}) bool {
	for _, attr := range body.Attributes {
		if readsResource(attr.Expr, types) {
			return true
		}
	}
	for _, block := range body.Blocks {
		if bodyReadsResource(block.Body, types) {
			return true
		}
	}
	return false
}

func readsResource(expr hclsyntax.Expression, types map[string]struct{}) bool {
	if len(types) == 0 {
		return false
	}
	for _, traversal := range expr.Variables() {
		if _, ok := types[traversal.RootName()]; ok {
			return true
		}
	}
	return false
}

// hasUnconditionalResourceBlock reports whether a resource block instantiates
// one instance regardless of context, letting an exhausted budget discard the
// module at its resource limit.
func hasUnconditionalResourceBlock(blocks []*hclsyntax.Block) bool {
	for _, rb := range blocks {
		if len(rb.Labels) >= 2 && rb.Body.Attributes["count"] == nil && rb.Body.Attributes["for_each"] == nil {
			return true
		}
	}
	return false
}

// dataExpansionWithinBudget reports whether a module call's data blocks may
// expand. A fully exhausted budget discards the call at its resource limit or
// final charge either way, so the expansion would only pay for thrown-away
// instances. Partial overruns and the exempt cases (root module, prepass, no
// unconditional resource block, disabled budget) take the unchanged path; a
// disabled budget reports -1 from remainingInstantiationBudget, which must not
// read as exhausted.
func (e *Evaluator) dataExpansionWithinBudget(addr string, hasUnconditionalResource bool) bool {
	if addr == "" || !hasUnconditionalResource || e.prepassDepth > 0 || e.maxInstantiated <= 0 {
		return true
	}
	return e.remainingInstantiationBudget() > 0
}

// evalResourceBlocks evaluates resource blocks (count/for_each expanded when known).
func (e *Evaluator) evalResourceBlocks(
	ctx context.Context,
	resourceBlocks []*hclsyntax.Block,
	evalCtx *hcl.EvalContext,
	addr string,
	chain []CallSite,
	limit int,
) ([]ResolvedResource, bool) {
	resources := make([]ResolvedResource, 0, len(resourceBlocks))
	for _, rb := range resourceBlocks {
		expanded := e.expandBlock(ctx, rb, evalCtx, addr, chain, false)
		if limit >= 0 {
			e.noteBudgetDemand(e.maxInstantiated - limit + len(resources) + len(expanded))
			if len(resources)+len(expanded) > limit {
				e.noteBudgetRefusal()
				return resources, false
			}
		}
		resources = append(resources, expanded...)
	}
	return resources, true
}

// expandBlock emits zero, one, or N instances of a resource or data block;
// known count/for_each get count.index / each.* in a child context; unknown
// expansion uses one placeholder instance.
func (e *Evaluator) expandBlock(
	ctx context.Context,
	rb *hclsyntax.Block,
	evalCtx *hcl.EvalContext,
	addr string,
	chain []CallSite,
	data bool,
) []ResolvedResource {
	if len(rb.Labels) < 2 {
		return nil
	}
	typeName, resName := rb.Labels[0], rb.Labels[1]
	address := joinAddr(addr, typeName+"."+resName)

	// Attributes that ignore each/count evaluate identically in every instance.
	memo := newInvariantMemo()

	// A dynamic block kept as written is one finding of the block, however many
	// instances or parent blocks repeat it, so it is reported once per call.
	overflows := make(map[string]dynamicOverflow)
	defer func() {
		labels := make([]string, 0, len(overflows))
		for label := range overflows {
			labels = append(labels, label)
		}
		slices.Sort(labels)
		for _, label := range labels {
			o := overflows[label]
			e.noteCountExpansionTruncated(ctx, "dynamic", address+".dynamic."+label, o.requested, 0, o.limit)
		}
	}()

	makeOne := func(name string, child *hcl.EvalContext) ResolvedResource {
		// Only attribution of module resources and data evaluation read the
		// iteration, so the resource instances of the root module do not keep it.
		var iteration map[string]cty.Value
		if child != evalCtx && (addr != "" || data) {
			iteration = child.Variables
		}
		state := &bodyState{memo: memo, dynamic: &dynamicRecorder{}}
		attrs := e.evalBodyWith(rb.Body, child, nil, state)
		for _, o := range state.dynamic.overflow {
			if prev, seen := overflows[o.label]; !seen || o.requested > prev.requested {
				overflows[o.label] = o
			}
		}
		return ResolvedResource{
			Type:          typeName,
			Name:          name,
			Attributes:    attrs,
			DynamicCounts: state.dynamic.counts,
			Body:          rb.Body,
			Iteration:     iteration,
			DefinedIn:     rb.TypeRange.Filename,
			DefLine:       rb.TypeRange.Start.Line,
			DefEndLine:    rb.Range().End.Line,
			DefColumn:     rb.TypeRange.Start.Column,
			DefEndColumn:  rb.Range().End.Column,
			ModuleAddress: addr,
			CallChain:     cloneChain(chain),
			Data:          data,
		}
	}

	if out, ok := e.expandCountInstances(ctx, rb, resName, address, evalCtx, makeOne); ok {
		return out
	}
	if out, ok := e.expandForEachInstances(ctx, rb, resName, address, evalCtx, makeOne); ok {
		return out
	}
	return []ResolvedResource{makeOne(resName, evalCtx)}
}

func (e *Evaluator) expandCountInstances(
	ctx context.Context,
	rb *hclsyntax.Block,
	resName, address string,
	evalCtx *hcl.EvalContext,
	makeOne func(string, *hcl.EvalContext) ResolvedResource,
) ([]ResolvedResource, bool) {
	countAttr := rb.Body.Attributes["count"]
	if countAttr == nil {
		return nil, false
	}
	cv, diags := countAttr.Expr.Value(evalCtx)
	if !diags.HasErrors() && cv.IsKnown() && !cv.IsNull() && cv.Type() == cty.Number {
		var n int
		if err := gocty.FromCtyValue(cv, &n); err != nil {
			return nil, false
		}
		if n <= 0 {
			return nil, true
		}
		nExpand := min(n, maxCountExpansion)
		truncated := n > maxCountExpansion
		if truncated {
			e.noteCountExpansionTruncated(ctx, "count", address, n, nExpand, maxCountExpansion)
		}
		out := make([]ResolvedResource, 0, nExpand)
		for i := 0; i < nExpand; i++ {
			child := evalCtx.NewChild()
			child.Variables = map[string]cty.Value{
				"count": cty.ObjectVal(map[string]cty.Value{
					"index": cty.NumberIntVal(int64(i)),
				}),
			}
			res := makeOne(fmt.Sprintf("%s[%d]", resName, i), child)
			if truncated {
				res.ExpansionTruncated = true
				res.ExpansionTotal = n
			}
			out = append(out, res)
		}
		return out, true
	}
	child := evalCtx.NewChild()
	child.Variables = map[string]cty.Value{
		"count": cty.ObjectVal(map[string]cty.Value{
			"index": cty.UnknownVal(cty.Number),
		}),
	}
	return []ResolvedResource{makeOne(resName, child)}, true
}

func (e *Evaluator) expandForEachInstances(
	ctx context.Context,
	rb *hclsyntax.Block,
	resName, address string,
	evalCtx *hcl.EvalContext,
	makeOne func(string, *hcl.EvalContext) ResolvedResource,
) ([]ResolvedResource, bool) {
	feAttr := rb.Body.Attributes["for_each"]
	if feAttr == nil {
		return nil, false
	}
	fv, diags := feAttr.Expr.Value(evalCtx)
	if diags.HasErrors() || !isForEachCollection(fv) {
		return []ResolvedResource{unknownForEachResource(resName, evalCtx, makeOne)}, true
	}
	if fv.LengthInt() == 0 {
		return nil, true
	}
	return e.expandKnownForEachResources(ctx, fv, resName, address, evalCtx, makeOne), true
}

func unknownForEachResource(
	resName string,
	evalCtx *hcl.EvalContext,
	makeOne func(string, *hcl.EvalContext) ResolvedResource,
) ResolvedResource {
	child := evalCtx.NewChild()
	child.Variables = map[string]cty.Value{
		"each": cty.ObjectVal(map[string]cty.Value{
			"key":   cty.UnknownVal(cty.String),
			"value": cty.UnknownVal(cty.DynamicPseudoType),
		}),
	}
	return makeOne(resName, child)
}

func (e *Evaluator) expandKnownForEachResources(
	ctx context.Context,
	fv cty.Value,
	resName, address string,
	evalCtx *hcl.EvalContext,
	makeOne func(string, *hcl.EvalContext) ResolvedResource,
) []ResolvedResource {
	total := fv.LengthInt()
	truncated := total > maxCountExpansion
	if truncated {
		e.noteCountExpansionTruncated(ctx, "for_each", address, total, maxCountExpansion, maxCountExpansion)
	}
	// Only walk the full collection when we need every key to pad a truncated shape.
	needKeys := truncated && total <= maxExpansionShape
	expandTo := min(total, maxCountExpansion)
	out := make([]ResolvedResource, 0, expandTo)
	var allKeys []string
	if needKeys {
		allKeys = make([]string, 0, total)
	}
	for it := fv.ElementIterator(); it.Next(); {
		k, kv := it.Element()
		keyStr := "__"
		if s, ok := ctyutil.ConcreteString(k); ok {
			keyStr = s
		}
		if needKeys {
			allKeys = append(allKeys, keyStr)
		}
		if len(out) < expandTo {
			out = append(out, makeForEachResource(resName, keyStr, k, kv, evalCtx, makeOne, truncated, total))
			continue
		}
		if !needKeys {
			break
		}
	}
	if needKeys {
		for i := range out {
			out[i].ExpansionKeys = allKeys
		}
	}
	return out
}

func makeForEachResource(
	resName, keyStr string,
	key, value cty.Value,
	evalCtx *hcl.EvalContext,
	makeOne func(string, *hcl.EvalContext) ResolvedResource,
	truncated bool,
	total int,
) ResolvedResource {
	child := evalCtx.NewChild()
	child.Variables = map[string]cty.Value{
		"each": cty.ObjectVal(map[string]cty.Value{
			"key":   key,
			"value": value,
		}),
	}
	res := makeOne(fmt.Sprintf("%s[%q]", resName, keyStr), child)
	if fe, ok := res.Attributes[metaArgForEach]; ok {
		res.Attributes[metaArgForEach] = instanceForEach(fe, keyStr, value)
	}
	if truncated {
		res.ExpansionTruncated = true
		res.ExpansionTotal = total
	}
	return res
}

// instanceForEach narrows a resource's evaluated for_each to the element of one
// instance, as the instance sees it in Terraform: each instance kept the whole
// collection, so instance documents grew with the square of the instance count.
// Rules that read for_each only test that it is non-empty or walk the values
// each.value can take, which for one instance is its own value.
func instanceForEach(fe cty.Value, key string, value cty.Value) cty.Value {
	if !fe.IsKnown() || fe.IsNull() || fe.IsMarked() {
		return fe
	}
	ty := fe.Type()
	switch {
	case ty.IsMapType():
		return cty.MapVal(map[string]cty.Value{key: value})
	case ty.IsObjectType():
		return cty.ObjectVal(map[string]cty.Value{key: value})
	case ty.IsSetType():
		return cty.SetVal([]cty.Value{value})
	}
	return fe
}

// injectResourceRefs sets evalCtx.Variables[type][name] from resources; returns true if changed.
// Count-expanded resources are exposed as ordered tuples so that x[0].attr resolves correctly;
// for_each-expanded resources as keyed objects so that x["k"].attr resolves correctly.
// Truncated expansions keep the full requested shape with unknown values for omitted instances.
func injectResourceRefs(evalCtx *hcl.EvalContext, resources []ResolvedResource) bool {
	type instBucket struct {
		keys     []string
		attrs    []map[string]cty.Value
		isCount  bool
		expanded bool // true when any instance has brackets (count or for_each)
		total    int
		allKeys  []string
	}
	byType := make(map[string]map[string]*instBucket)
	for i := range resources {
		r := &resources[i]
		base, key, isCount, expanded := parseResourceInstanceKey(r.Name)
		if byType[r.Type] == nil {
			byType[r.Type] = make(map[string]*instBucket)
		}
		b := byType[r.Type][base]
		if b == nil {
			b = &instBucket{isCount: isCount, expanded: expanded}
			byType[r.Type][base] = b
		} else if expanded {
			b.expanded = true
		}
		b.keys = append(b.keys, key)
		b.attrs = append(b.attrs, referenceAttributes(r.Attributes))
		if r.ExpansionTruncated && r.ExpansionTotal > b.total {
			b.total = r.ExpansionTotal
			b.allKeys = r.ExpansionKeys
		}
	}
	if len(byType) == 0 {
		return false
	}
	progress := false
	for typeName, nameMap := range byType {
		typeAttrs := make(map[string]cty.Value, len(nameMap))
		for baseName, b := range nameMap {
			typeAttrs[baseName] = buildInstanceCtyVal(b.keys, b.attrs, b.isCount, b.expanded, b.total, b.allKeys)
		}
		newVal := cty.ObjectVal(typeAttrs)
		if existing, ok := evalCtx.Variables[typeName]; !ok || !equalValues(existing, newVal) {
			evalCtx.Variables[typeName] = newVal
			progress = true
		}
	}
	return progress
}

// Resource meta-arguments that expand a block into instances.
const (
	metaArgCount   = "count"
	metaArgForEach = "for_each"
)

// referenceAttributes drops the count and for_each meta-arguments, which
// Terraform does not expose on a resource instance. Every instance of a block
// carries the whole for_each collection, so keeping it made the reference value
// grow with the square of the instance count and comparing it, on every
// reference pass, sort each copy.
func referenceAttributes(attrs map[string]cty.Value) map[string]cty.Value {
	_, hasCount := attrs[metaArgCount]
	_, hasForEach := attrs[metaArgForEach]
	if !hasCount && !hasForEach {
		return attrs
	}
	out := make(map[string]cty.Value, len(attrs))
	for name, v := range attrs {
		if name != metaArgCount && name != metaArgForEach {
			out[name] = v
		}
	}
	return out
}

// buildInstanceCtyVal converts grouped resource instances into the cty value used for ref injection.
// Non-expanded resources become plain objects. Count resources become ordered tuples (x[0]).
// For_each resources become keyed objects (x["key"]), including the empty-string key case.
// When total > len(keys), omitted instances are unknown so length()/missing keys stay honest.
func buildInstanceCtyVal(keys []string, attrsSlice []map[string]cty.Value, isCount, expanded bool, total int, allKeys []string) cty.Value {
	if !expanded {
		// Plain (non-indexed) resource: expose as a simple attribute object.
		return objectOrEmpty(attrsSlice[0])
	}
	if total > maxExpansionShape {
		return cty.DynamicVal
	}
	if isCount {
		type indexed struct {
			i     int
			attrs map[string]cty.Value
		}
		items := make([]indexed, len(keys))
		for i, k := range keys {
			n, _ := strconv.Atoi(k)
			items[i] = indexed{n, attrsSlice[i]}
		}
		sort.Slice(items, func(i, j int) bool { return items[i].i < items[j].i })
		n := len(items)
		if total > n {
			n = total
		}
		elems := make([]cty.Value, n)
		for i := range elems {
			elems[i] = cty.DynamicVal
		}
		for _, item := range items {
			if item.i >= 0 && item.i < len(elems) {
				elems[item.i] = objectOrEmpty(item.attrs)
			}
		}
		return cty.TupleVal(elems)
	}
	// for_each: expose as object keyed by string keys so x["key"].attr resolves.
	// Empty-string keys ("") are valid Terraform for_each keys and are kept.
	kvs := make(map[string]cty.Value, max(len(keys), len(allKeys)))
	for _, k := range allKeys {
		kvs[k] = cty.DynamicVal
	}
	for i, k := range keys {
		kvs[k] = objectOrEmpty(attrsSlice[i])
	}
	if len(kvs) == 0 {
		return cty.EmptyObjectVal
	}
	return cty.ObjectVal(kvs)
}

// resolveVariables binds inputs to variables, falling back to the default then
// unknown, and conforms the value to the variable's type. A null input to a
// non-nullable variable takes the default, as in Terraform.
func (e *Evaluator) resolveVariables(
	varDecls map[string]variableDecl,
	inputs map[string]cty.Value,
) map[string]cty.Value {
	out := make(map[string]cty.Value, len(varDecls))
	for name, decl := range varDecls {
		v, ok := inputs[name]
		if ok && decl.nonNullable && v.IsNull() {
			ok = false
		}
		if !ok {
			if decl.def == nil {
				out[name] = cty.UnknownVal(cty.DynamicPseudoType)
				continue
			}
			def, diags := decl.def.Value(&hcl.EvalContext{Functions: e.funcs})
			if diags.HasErrors() {
				out[name] = cty.UnknownVal(cty.DynamicPseudoType)
				continue
			}
			v = def
		}
		out[name] = decl.conform(v)
	}
	return out
}

// resolveLocalsIncremental resolves the module's locals, reusing what an
// earlier resolution of the same module evaluation produced for the locals
// that read nothing that changed since. A local is re-evaluated when it reads
// the module's resources and they were re-injected, when it reads module
// outputs and they changed, or when it reads data, which the data refresh
// re-resolves out of band; everything else is a pure function of the module
// inputs and the locals reused before it, so its value cannot have changed.
// The re-evaluated locals still converge through the same pass machinery as a
// full resolution. resourceTypes is only read on the first call, where the
// per-local classification is computed; later calls may pass nil.
func (e *Evaluator) resolveLocalsIncremental(
	scope *ModuleScope,
	localExprs map[string]hclsyntax.Expression,
	resourceTypes map[string]struct{},
	base *hcl.EvalContext,
	resourcesChanged, modulesChanged bool,
) map[string]cty.Value {
	if scope.localDeps == nil {
		resourceReaders := localsReadingRoot(localExprs, resourceTypes)
		moduleReaders := localsReadingRoot(localExprs, moduleRoot)
		dataReaders := localsReadingRoot(localExprs, dataRoot)
		deps := make(map[string]localDeps, len(localExprs))
		for name := range localExprs {
			deps[name] = localDeps{
				resources: resourceReaders[name],
				modules:   moduleReaders[name],
				data:      dataReaders[name],
			}
		}
		scope.localDeps = deps
		scope.localCache = make(map[string]cty.Value, len(localExprs))
	}
	fixed := make(map[string]cty.Value, len(scope.localCache))
	for name, v := range scope.localCache {
		deps := scope.localDeps[name]
		// Data-reading locals are never reused: the data refresh re-resolves
		// them out of band, so the cache may hold a value older than data.*.
		if deps.data || (resourcesChanged && deps.resources) || (modulesChanged && deps.modules) {
			continue
		}
		fixed[name] = v
	}
	resolved := e.resolveLocalsWith(localExprs, base, fixed)
	for name, v := range resolved {
		scope.localCache[name] = v
	}
	return resolved
}

// resolveLocalsWith resolves localExprs keeping the locals in fixed at their
// value, for a refresh only some locals depend on.
func (e *Evaluator) resolveLocalsWith(
	localExprs map[string]hclsyntax.Expression,
	base *hcl.EvalContext,
	fixed map[string]cty.Value,
) map[string]cty.Value {
	resolved := make(map[string]cty.Value, len(localExprs))
	for name, v := range fixed {
		resolved[name] = v
	}

	for pass := 0; pass < localsMaxPasses; pass++ {
		progressed := false
		ctx := base.NewChild()
		ctx.Variables = map[string]cty.Value{"local": objectOrEmpty(resolved)}

		for name, expr := range localExprs {
			if _, ok := fixed[name]; ok {
				continue
			}
			prev, seen := resolved[name]
			if seen && prev.IsWhollyKnown() {
				continue
			}
			v := e.localValue(expr, ctx)
			if !v.IsKnown() || (seen && equalValues(prev, v)) {
				continue
			}
			resolved[name] = v
			progressed = true
		}
		if !progressed {
			break
		}
	}

	for name := range localExprs {
		if _, ok := resolved[name]; !ok {
			resolved[name] = cty.UnknownVal(cty.DynamicPseudoType)
		}
	}
	return resolved
}

// evalBody evaluates an HCL body into the shape produced by the Terraform parser.
// It keeps dynamic blocks as written: a module call cannot hold them, and there
// is no per-resource budget here to bound their expansion.
func (e *Evaluator) evalBody(
	body *hclsyntax.Body,
	ctx *hcl.EvalContext,
	skip map[string]bool,
) map[string]cty.Value {
	return e.evalBodyWith(body, ctx, skip, nil)
}

// bodyState carries what evaluating a resource body shares across its nested
// blocks: the memo of expressions that ignore the iteration, and how many
// blocks each dynamic block generated.
type bodyState struct {
	memo    *invariantMemo
	dynamic *dynamicRecorder
	// iterators are the iterator names of the dynamic blocks enclosing the body
	// being evaluated; expressions reading one of them vary between blocks.
	iterators []string
}

type dynamicRecorder struct {
	counts    DynamicCounts
	generated int
	overflow  []dynamicOverflow
}

// withoutMemo shares the dynamic counts but not the memo, for the as-written
// body of a dynamic block that is not expanded: it reads an iterator that
// nothing binds there, which is no reason to reuse its value elsewhere.
func (st *bodyState) withoutMemo() *bodyState {
	if st == nil {
		return nil
	}
	return &bodyState{dynamic: st.dynamic}
}

// inDynamic is the state for the content of a dynamic block binding iterator.
func (st *bodyState) inDynamic(iterator string) *bodyState {
	if st == nil {
		return nil
	}
	names := make([]string, len(st.iterators), len(st.iterators)+1)
	copy(names, st.iterators)
	return &bodyState{memo: st.memo, dynamic: st.dynamic, iterators: append(names, iterator)}
}

func (e *Evaluator) evalBodyWith(
	body *hclsyntax.Body,
	ctx *hcl.EvalContext,
	skip map[string]bool,
	st *bodyState,
) map[string]cty.Value {
	out := make(map[string]cty.Value, len(body.Attributes)+len(body.Blocks))

	for name, attr := range body.Attributes {
		if skip[name] {
			continue
		}
		out[name] = e.evalExprMemo(attr.Expr, ctx, st)
	}

	blocks := nestedBlocks{out: out}
	for _, b := range body.Blocks {
		if st != nil && dynamicblock.Is(b) {
			e.addDynamicBlocks(&blocks, b, ctx, st)
			continue
		}
		path := append([]string{b.Type}, b.Labels...)
		blocks.add(path, objectOrEmpty(e.evalBodyWith(b.Body, ctx, nil, st)))
	}
	blocks.flushAll()
	return out
}

// nestedBlocks adds the nested blocks of one body to out as addNestedBlock
// does, but collects the blocks of a repeated unlabeled type and builds their
// tuple once: rebuilding it per block made a body with n such blocks (written
// or generated by dynamic blocks) cost n^2.
type nestedBlocks struct {
	out map[string]cty.Value
	// pending holds, per key, the elements of the tuple out[key] will be set
	// to; out[key] is stale while the key is pending.
	pending map[string][]cty.Value
}

func (n *nestedBlocks) add(path []string, value cty.Value) {
	key := path[0]
	if len(path) > 1 {
		n.flush(key)
		addNestedBlock(n.out, path, value)
		return
	}
	if list, ok := n.pending[key]; ok {
		n.pending[key] = append(list, value)
		return
	}
	current, ok := n.out[key]
	if !ok {
		n.out[key] = value
		return
	}
	if n.pending == nil {
		n.pending = make(map[string][]cty.Value)
	}
	if current.Type().IsTupleType() {
		n.pending[key] = append(current.AsValueSlice(), value)
	} else {
		n.pending[key] = []cty.Value{current, value}
	}
}

func (n *nestedBlocks) flush(key string) {
	if list, ok := n.pending[key]; ok {
		n.out[key] = cty.TupleVal(list)
		delete(n.pending, key)
	}
}

func (n *nestedBlocks) flushAll() {
	for key := range n.pending {
		n.flush(key)
	}
}

// invariantMemo reuses the value of expressions that do not read each, count or
// a dynamic block's iterator across the instances of one resource block and the
// blocks its dynamic blocks generate, which share a parent context.
type invariantMemo struct {
	values map[hclsyntax.Expression]cty.Value
	varies map[hclsyntax.Expression]bool
}

func newInvariantMemo() *invariantMemo {
	return &invariantMemo{
		values: make(map[hclsyntax.Expression]cty.Value),
		varies: make(map[hclsyntax.Expression]bool),
	}
}

// readsIteration reports whether expr reads each, count, or the iterator of an
// enclosing dynamic block. An expression sits in one place of the body, so its
// enclosing iterators, and with them the answer, never change.
func (m *invariantMemo) readsIteration(expr hclsyntax.Expression, iterators []string) bool {
	if v, ok := m.varies[expr]; ok {
		return v
	}
	reads := false
	for _, t := range expr.Variables() {
		root := t.RootName()
		if root == "each" || root == "count" || slices.Contains(iterators, root) {
			reads = true
			break
		}
	}
	m.varies[expr] = reads
	return reads
}

func (e *Evaluator) evalExprMemo(expr hclsyntax.Expression, ctx *hcl.EvalContext, st *bodyState) cty.Value {
	if st == nil || st.memo == nil || st.memo.readsIteration(expr, st.iterators) {
		return e.evalExpr(expr, ctx)
	}
	if v, ok := st.memo.values[expr]; ok {
		return v
	}
	v := e.evalExpr(expr, ctx)
	st.memo.values[expr] = v
	return v
}

func addNestedBlock(out map[string]cty.Value, path []string, value cty.Value) {
	key := path[0]
	if len(path) == 1 {
		if current, ok := out[key]; ok {
			if current.Type().IsTupleType() {
				out[key] = cty.TupleVal(append(current.AsValueSlice(), value))
			} else {
				out[key] = cty.TupleVal([]cty.Value{current, value})
			}
		} else {
			out[key] = value
		}
		return
	}

	nested := map[string]cty.Value{}
	if current, ok := out[key]; ok && current.Type().IsObjectType() {
		nested = current.AsValueMap()
	}
	addNestedBlock(nested, path[1:], value)
	out[key] = objectOrEmpty(nested)
}

// evalExpr evaluates an expression, returning unknown for what it cannot
// resolve.
func (e *Evaluator) evalExpr(expr hclsyntax.Expression, ctx *hcl.EvalContext) cty.Value {
	if v, ok := evalLength(expr, ctx); ok {
		return v
	}
	v, diags := expr.Value(ctx)
	if diags.HasErrors() {
		return partial.WithUnknownRefs(expr, ctx)
	}
	return v
}

// evalLength evaluates a one-argument length call once. Object length comes from
// the type, because calling the function walks the object to look for marks.
func evalLength(expr hclsyntax.Expression, ctx *hcl.EvalContext) (cty.Value, bool) {
	call, ok := expr.(*hclsyntax.FunctionCallExpr)
	if !ok || call.Name != "length" || call.ExpandFinal || len(call.Args) != 1 {
		return cty.NilVal, false
	}
	v, diags := call.Args[0].Value(ctx)
	if diags.HasErrors() {
		return partial.WithUnknownRefs(expr, ctx), true
	}
	if v.Type().IsObjectType() && !v.IsNull() {
		if !v.IsKnown() {
			return cty.UnknownVal(cty.Number), true
		}
		return cty.NumberIntVal(int64(len(v.Type().AttributeTypes()))), true
	}
	got, err := tffunctions.LengthFunc.Call([]cty.Value{v})
	if err != nil {
		return partial.WithUnknownRefs(expr, ctx), true
	}
	return got, true
}

// preliminaryModuleOutputs evaluates local modules once to fill module.* for sibling refs.
// Passes the real chain so the cache key matches the main-loop evaluate calls, turning the
// second evaluation into a cache hit. Copies visiting; uses a fresh allVisited.
func (e *Evaluator) preliminaryModuleOutputs(
	ctx context.Context,
	moduleBlocks []*hclsyntax.Block,
	reads []siblingReads,
	evalCtx *hcl.EvalContext,
	scope *ModuleScope,
	dir, rootDir, packageRoot, addr string,
	chain []CallSite,
	depth int,
	visiting map[string]bool,
) map[string]cty.Value {
	e.prepassDepth++
	// The calls evaluated here are speculative; cache entries keep their own.
	instancesBefore := len(e.instances)
	defer func() {
		e.prepassDepth--
		e.instances = e.instances[:instancesBefore]
	}()

	out := map[string]cty.Value{}
	tmpVisiting := make(map[string]bool, len(visiting))
	for k, v := range visiting {
		tmpVisiting[k] = v
	}
	// Each call sees the outputs of the calls before it in this pre-pass, so
	// that its inputs resolve to the same values that the main evaluation loop
	// will compute — this keeps cache keys consistent. The pre-pass publishes
	// module.* only, so a call reading a few named outputs is given just those,
	// and module.* is rebuilt only for a call reading it as a whole or reading
	// as many outputs as it holds. The caller publishes the complete object
	// once the loop is done.
	stale := false
	for blockIndex, mb := range moduleBlocks {
		callCtx := evalCtx
		switch r := &reads[blockIndex]; {
		case len(out) == 0:
		case r.wholeModule || len(r.modules) >= len(out):
			if stale {
				evalCtx.Variables["module"] = cty.ObjectVal(out)
				stale = false
			}
		case len(r.modules) > 0:
			callCtx = evalCtx.NewChild()
			callCtx.Variables = map[string]cty.Value{blockTypeModule: namedObject(out, r.modules)}
		}
		call, ok := e.resolveModuleCall(ctx, mb, callCtx, dir, packageRoot)
		if !ok {
			continue
		}
		plan := moduleInstances(mb, callCtx) // prepass: no truncation accounting
		site := call.site(scope)
		outs := make([]cty.Value, len(plan.instances))
		for i, instance := range plan.instances {
			modInputs := e.evalBody(mb.Body, instance.ctx, reservedModuleAttrs)
			childChain := append(cloneChain(chain), site)
			_, childOuts, err := e.evaluate(
				ctx, call.dir, rootDir, call.packageRoot, modInputs, instance.address(addr, call.label), childChain,
				depth+1, tmpVisiting, map[string]bool{},
			)
			if err == nil {
				outs[i] = objectOrEmpty(childOuts)
			}
		}
		if value, ok := moduleOutputsValue(plan, outs); ok {
			out[call.label] = value
			stale = true
		}
	}
	return out
}
