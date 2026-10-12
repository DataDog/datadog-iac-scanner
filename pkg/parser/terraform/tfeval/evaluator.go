/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package tfeval evaluates local Terraform modules: bind inputs, resolve locals,
// recurse into nested modules, emit resources with concrete cty values where possible.
// Anything still unresolvable (e.g. data sources) stays cty.UnknownVal, not sentinels.
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
	tffunctions "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/functions"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/resolver"
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
	maxCountExpansion = 50
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
	// fsys serves the evaluator's directory reads (module and tfvars files).
	// Defaults to the real disk; content-push scans inject an in-memory FS.
	fsys vfs.FS
	// cache memoizes completed module evaluations keyed by (dir, packageRoot,
	// canonical-inputs). A single Evaluator is used for an entire scan, so entries
	// with the same key represent the same module reached with the same resolved
	// inputs, whatever path led there.
	cache map[evalCacheKey]*evalCacheEntry
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
	skipped             uint64
	// budgetDemand is the most instantiated resources any budget check since
	// the last ResetBudgetDemand needed room for: evaluation started from an
	// earlier count makes the same decisions while that count plus the demand
	// stays within the budget.
	budgetDemand int

	// count/for_each expansion truncation observability (scan-wide on this evaluator).
	expansionTruncations    int
	expansionMaxRequested   int
	expansionTruncationWarn bool

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
	bodies []*hclsyntax.Body
	err    error
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

// InstantiatedCount reports how many module resources have been charged against
// the scan-wide retained-document budget.
func (e *Evaluator) InstantiatedCount() int { return e.instantiated }

// RestoreInstantiatedCount rolls back charges from a root whose evaluation failed
// after descendants were counted but before any documents were emitted.
func (e *Evaluator) RestoreInstantiatedCount(n int) {
	e.instantiated = n
	e.budgetExceeded = e.maxInstantiated > 0 && e.instantiated >= e.maxInstantiated
}

func (e *Evaluator) parseDir(ctx context.Context, dir, packageRoot string) ([]*hclsyntax.Body, error) {
	key := filepath.Clean(dir) + "\x00" + filepath.Clean(packageRoot)

	e.parseMu.Lock()
	if dp, ok := e.dirCache[key]; ok {
		e.parseMu.Unlock()
		return dp.bodies, dp.err
	}
	e.parseMu.Unlock()

	bodies, err := parseDir(ctx, dir, packageRoot, e.mergeAllow, e.fsys)

	e.parseMu.Lock()
	e.dirCache[key] = dirParse{bodies: bodies, err: err}
	e.parseMu.Unlock()
	return bodies, err
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

// ExpansionTruncations reports how many count/for_each expansions hit the per-block cap.
func (e *Evaluator) ExpansionTruncations() int { return e.expansionTruncations }

// ExpansionMaxRequested reports the largest requested instance count seen when truncating.
func (e *Evaluator) ExpansionMaxRequested() int { return e.expansionMaxRequested }

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

func (e *Evaluator) noteCountExpansionTruncated(ctx context.Context, kind, address string, requested, expanded int) {
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
		Int("count_expansion_cap", maxCountExpansion).
		Msg("tfeval: count/for_each expansion truncated; remaining instances scanned as written")
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
// bodies. Every entry holds the resolved resources of its whole subtree, so
// retaining entries for a whole repository scales peak memory with the number of
// roots. Entries are reusable across roots now that the key is the inputs alone,
// but in practice each root passes its own values to the shared modules it calls,
// so the hit rate across roots is low and not worth that peak. The parse cache is
// keyed by directory alone, genuinely is shared by every root, and is kept.
func (e *Evaluator) ReleaseEvalCache() {
	e.cache = make(map[evalCacheKey]*evalCacheEntry)
}

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
		inputs:      canonicalInputsKey(inputs),
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

	bodies, err := e.parseDir(ctx, dir, packageRoot)
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

	evalCtx.Variables["local"] = objectOrEmpty(e.resolveLocals(localExprs, evalCtx))
	scope := &ModuleScope{Locals: localExprs, Bodies: bodies, Var: evalCtx.Variables["var"]}

	if !e.preinjectResourceRefs(ctx, resourceBlocks, moduleBlocks, localExprs, evalCtx, addr, chain) {
		return nil, nil, e.skipEvaluation(dir)
	}

	e.applySiblingModulePrepass(
		ctx, moduleBlocks, evalCtx, scope, dir, rootDir, packageRoot, addr, chain, depth, visiting,
	)

	childResources, moduleOutputs := e.evaluateLocalModuleBlocks(
		ctx, moduleBlocks, evalCtx, scope, dir, rootDir, packageRoot, addr, chain, depth, visiting, allVisited,
	)

	if len(moduleOutputs) > 0 {
		evalCtx.Variables["module"] = cty.ObjectVal(moduleOutputs)
		evalCtx.Variables["local"] = objectOrEmpty(e.resolveLocals(localExprs, evalCtx))
	}

	rootResources, err := e.evaluateRootResources(
		ctx, dir, resourceBlocks, localExprs, evalCtx, addr, chain,
	)
	if err != nil {
		return nil, nil, err
	}

	// Re-inject the final-pass resource values so that outputs and locals that
	// reference the Nth hop of an N-hop chain can resolve. For chains shorter
	// than resourceRefPasses hops all resources were already injected inside the
	// loop, so injectResourceRefs returns false and the locals refresh is skipped.
	if injectResourceRefs(evalCtx, rootResources) {
		evalCtx.Variables["local"] = objectOrEmpty(e.resolveLocals(localExprs, evalCtx))
	}
	scope.Local = evalCtx.Variables["local"]
	for i := range rootResources {
		rootResources[i].Scope = scope
	}

	resources := make([]ResolvedResource, 0, len(rootResources)+len(childResources))
	resources = append(resources, rootResources...)
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
	evalCtx *hcl.EvalContext,
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
	injectResourceRefs(evalCtx, resources)
	evalCtx.Variables["local"] = objectOrEmpty(e.resolveLocals(localExprs, evalCtx))
	return true
}

func (e *Evaluator) evaluateRootResources(
	ctx context.Context,
	dir string,
	resourceBlocks []*hclsyntax.Block,
	localExprs map[string]hclsyntax.Expression,
	evalCtx *hcl.EvalContext,
	addr string,
	chain []CallSite,
) ([]ResolvedResource, error) {
	resources, complete := e.rootResourcesWithRefPasses(
		ctx, resourceBlocks, localExprs, evalCtx, addr, chain,
	)
	if !complete {
		return nil, e.skipEvaluation(dir)
	}
	if addr != "" && !e.chargeInstantiationBudget(ctx, len(resources)) {
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

func moduleResourceCount(resources []ResolvedResource) int {
	n := 0
	for i := range resources {
		if resources[i].ModuleAddress != "" {
			n++
		}
	}
	return n
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
	return false
}

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
	return count >= e.maxInstantiated
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
	evalCtx *hcl.EvalContext,
	scope *ModuleScope,
	dir, rootDir, packageRoot, addr string,
	chain []CallSite,
	depth int,
	visiting map[string]bool,
) {
	if len(moduleBlocks) <= 1 {
		return
	}
	prelimOutputs := e.preliminaryModuleOutputs(
		ctx, moduleBlocks, evalCtx, scope, dir, rootDir, packageRoot, addr, chain, depth, visiting,
	)
	if len(prelimOutputs) == 0 {
		return
	}
	evalCtx.Variables["module"] = cty.ObjectVal(prelimOutputs)
	localVals := e.resolveLocals(scope.Locals, evalCtx)
	evalCtx.Variables["local"] = objectOrEmpty(localVals)
}

func (e *Evaluator) evaluateLocalModuleBlocks(
	ctx context.Context,
	moduleBlocks []*hclsyntax.Block,
	evalCtx *hcl.EvalContext,
	scope *ModuleScope,
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
	moduleOutputs = map[string]cty.Value{}
	if existing, ok := evalCtx.Variables["module"]; ok &&
		existing.IsKnown() &&
		!existing.IsNull() &&
		existing.Type().IsObjectType() {
		for it := existing.ElementIterator(); it.Next(); {
			k, v := it.Element()
			name, ok := ctyutil.ConcreteString(k)
			if !ok {
				continue
			}
			moduleOutputs[name] = v
		}
	}

	for _, mb := range moduleBlocks {
		call, ok := e.resolveModuleCall(ctx, mb, evalCtx, dir, packageRoot)
		if !ok {
			continue
		}
		plan := moduleInstances(mb, evalCtx)
		if plan.truncated() {
			kind := "module_count"
			if plan.mode == expansionForEach {
				kind = "module_for_each"
			}
			e.noteCountExpansionTruncated(ctx, kind, "module."+call.label, plan.requested, len(plan.instances))
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
				e.instances = e.instances[:instancesBefore]
				continue
			}
			e.recordModuleInstance(call.dir, childAddr, childChain)
			allVisited[call.dir] = true
			childResources = append(childResources, childRes...)
			outs[i] = objectOrEmpty(childOuts)
		}
		if value, ok := moduleOutputsValue(plan, outs); ok {
			moduleOutputs[call.label] = value
			// Update evalCtx so the next sibling's modInputs can reference this
			// module's now-resolved outputs (e.g. module.B.x = module.A.output).
			evalCtx.Variables["module"] = cty.ObjectVal(moduleOutputs)
		}
	}
	return childResources, moduleOutputs
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
			dir, _ := tfmodules.LocalModuleDir(e.fsys, callerDir, source)
			return dir, "", true
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
	evalCtx *hcl.EvalContext,
	addr string,
	chain []CallSite,
) ([]ResolvedResource, bool) {
	var rootResources []ResolvedResource
	types := declaredResourceTypes(resourceBlocks)
	localsReadOwn := localsReadResources(localExprs, types)
	readsOwn := localsReadOwn || resourcesReadResources(resourceBlocks, types)
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
			evalCtx.Variables["local"] = objectOrEmpty(e.resolveLocals(localExprs, evalCtx))
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
		expanded := e.expandResourceBlock(ctx, rb, evalCtx, addr, chain)
		if limit >= 0 {
			e.noteBudgetDemand(e.maxInstantiated - limit + len(resources) + len(expanded))
			if len(resources)+len(expanded) > limit {
				return resources, false
			}
		}
		resources = append(resources, expanded...)
	}
	return resources, true
}

// expandResourceBlock emits zero, one, or N instances per block; known count/for_each
// get count.index / each.* in a child context; unknown expansion uses one placeholder instance.
func (e *Evaluator) expandResourceBlock(
	ctx context.Context,
	rb *hclsyntax.Block,
	evalCtx *hcl.EvalContext,
	addr string,
	chain []CallSite,
) []ResolvedResource {
	if len(rb.Labels) < 2 {
		return nil
	}
	typeName, resName := rb.Labels[0], rb.Labels[1]
	address := joinAddr(addr, typeName+"."+resName)

	// Attributes that ignore each/count evaluate identically in every instance.
	memo := newInvariantMemo()

	makeOne := func(name string, child *hcl.EvalContext) ResolvedResource {
		// Only attribution of module resources reads the iteration, so the
		// instances of the root module do not keep it.
		var iteration map[string]cty.Value
		if child != evalCtx && addr != "" {
			iteration = child.Variables
		}
		return ResolvedResource{
			Type:          typeName,
			Name:          name,
			Attributes:    e.evalBodyMemo(rb.Body, child, memo),
			Body:          rb.Body,
			Iteration:     iteration,
			DefinedIn:     rb.TypeRange.Filename,
			DefLine:       rb.TypeRange.Start.Line,
			DefEndLine:    rb.Range().End.Line,
			DefColumn:     rb.TypeRange.Start.Column,
			DefEndColumn:  rb.Range().End.Column,
			ModuleAddress: addr,
			CallChain:     cloneChain(chain),
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
			e.noteCountExpansionTruncated(ctx, "count", address, n, nExpand)
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
		e.noteCountExpansionTruncated(ctx, "for_each", address, total, maxCountExpansion)
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
	if truncated {
		res.ExpansionTruncated = true
		res.ExpansionTotal = total
	}
	return res
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
		b.attrs = append(b.attrs, r.Attributes)
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
		if existing, ok := evalCtx.Variables[typeName]; !ok || !existing.RawEquals(newVal) {
			evalCtx.Variables[typeName] = newVal
			progress = true
		}
	}
	return progress
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

// resolveLocals evaluates locals to a fixed point, retrying cross-references until no progress.
// A local only partly known keeps its known parts and is re-evaluated on later
// passes, since the locals it reads may still resolve further.
func (e *Evaluator) resolveLocals(
	localExprs map[string]hclsyntax.Expression,
	base *hcl.EvalContext,
) map[string]cty.Value {
	resolved := make(map[string]cty.Value, len(localExprs))

	for pass := 0; pass < localsMaxPasses; pass++ {
		progressed := false
		ctx := base.NewChild()
		ctx.Variables = map[string]cty.Value{"local": objectOrEmpty(resolved)}

		for name, expr := range localExprs {
			prev, seen := resolved[name]
			if seen && prev.IsWhollyKnown() {
				continue
			}
			v, diags := expr.Value(ctx)
			if diags.HasErrors() || !v.IsKnown() || (seen && prev.RawEquals(v)) {
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
func (e *Evaluator) evalBody(
	body *hclsyntax.Body,
	ctx *hcl.EvalContext,
	skip map[string]bool,
) map[string]cty.Value {
	return e.evalBodyWith(body, ctx, skip, nil)
}

func (e *Evaluator) evalBodyMemo(body *hclsyntax.Body, ctx *hcl.EvalContext, memo *invariantMemo) map[string]cty.Value {
	return e.evalBodyWith(body, ctx, nil, memo)
}

func (e *Evaluator) evalBodyWith(
	body *hclsyntax.Body,
	ctx *hcl.EvalContext,
	skip map[string]bool,
	memo *invariantMemo,
) map[string]cty.Value {
	out := make(map[string]cty.Value, len(body.Attributes)+len(body.Blocks))

	for name, attr := range body.Attributes {
		if skip[name] {
			continue
		}
		out[name] = e.evalExprMemo(attr.Expr, ctx, memo)
	}

	for _, b := range body.Blocks {
		path := append([]string{b.Type}, b.Labels...)
		addNestedBlock(out, path, objectOrEmpty(e.evalBodyWith(b.Body, ctx, nil, memo)))
	}
	return out
}

// invariantMemo reuses the value of expressions that do not read each or
// count across the instances of one resource block, which share a parent
// context.
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

func (m *invariantMemo) readsIteration(expr hclsyntax.Expression) bool {
	if v, ok := m.varies[expr]; ok {
		return v
	}
	reads := false
	for _, t := range expr.Variables() {
		if root := t.RootName(); root == "each" || root == "count" {
			reads = true
			break
		}
	}
	m.varies[expr] = reads
	return reads
}

func (e *Evaluator) evalExprMemo(expr hclsyntax.Expression, ctx *hcl.EvalContext, memo *invariantMemo) cty.Value {
	if memo == nil || memo.readsIteration(expr) {
		return e.evalExpr(expr, ctx)
	}
	if v, ok := memo.values[expr]; ok {
		return v
	}
	v := e.evalExpr(expr, ctx)
	memo.values[expr] = v
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

// evalExpr evaluates an expression, returning unknown on any resolution failure.
func (e *Evaluator) evalExpr(expr hclsyntax.Expression, ctx *hcl.EvalContext) cty.Value {
	v, diags := expr.Value(ctx)
	if diags.HasErrors() {
		return cty.UnknownVal(cty.DynamicPseudoType)
	}
	return v
}

// preliminaryModuleOutputs evaluates local modules once to fill module.* for sibling refs.
// Passes the real chain so the cache key matches the main-loop evaluate calls, turning the
// second evaluation into a cache hit. Copies visiting; uses a fresh allVisited.
func (e *Evaluator) preliminaryModuleOutputs(
	ctx context.Context,
	moduleBlocks []*hclsyntax.Block,
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
	for _, mb := range moduleBlocks {
		call, ok := e.resolveModuleCall(ctx, mb, evalCtx, dir, packageRoot)
		if !ok {
			continue
		}
		plan := moduleInstances(mb, evalCtx) // prepass: no truncation accounting
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
			// Make each module's outputs visible to subsequent siblings within this
			// same pre-pass loop, so their inputs resolve to the same values that the
			// main evaluation loop will compute — this keeps cache keys consistent.
			evalCtx.Variables["module"] = cty.ObjectVal(out)
		}
	}
	return out
}
