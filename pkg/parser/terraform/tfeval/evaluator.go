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
	"path/filepath"
	"sort"
	"strconv"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	tffunctions "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/functions"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/resolver"

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
	// maxCountExpansion caps instances per count/for_each block.
	maxCountExpansion = 10
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
}

// Evaluator evaluates local Terraform modules.
type Evaluator struct {
	funcs    map[string]function.Function
	maxDepth int
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

	// notEvaluatedDirs holds every module directory this evaluator declined to
	// evaluate for depth, cycle or budget. It accumulates for the whole scan
	// because suppression is decided per directory over all call sites at once:
	// one skipped instance means the directory is only partially resolved, so
	// its body must stay in the scan even though other instances did resolve.
	notEvaluatedDirs map[string]bool

	parseMu  sync.Mutex
	dirCache map[string]dirParse
}

type dirParse struct {
	bodies []*hclsyntax.Body
	err    error
}

func New() *Evaluator {
	return &Evaluator{
		funcs:            tffunctions.TerraformFuncs,
		maxDepth:         defaultMaxDepth,
		maxInstantiated:  defaultMaxInstantiated,
		cache:            make(map[evalCacheKey]*evalCacheEntry),
		dirCache:         make(map[string]dirParse),
		notEvaluatedDirs: make(map[string]bool),
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

// InstantiatedCount reports how many module resources have been charged against
// the scan-wide retained-document budget.
func (e *Evaluator) InstantiatedCount() int { return e.instantiated }

// RestoreInstantiatedCount rolls back charges from a root whose evaluation failed
// after descendants were counted but before any documents were emitted.
func (e *Evaluator) RestoreInstantiatedCount(n int) {
	e.instantiated = n
	e.budgetExceeded = e.maxInstantiated > 0 && e.instantiated >= e.maxInstantiated
}

func (e *Evaluator) parseDir(dir, packageRoot string) ([]*hclsyntax.Body, error) {
	key := filepath.Clean(dir) + "\x00" + filepath.Clean(packageRoot)

	e.parseMu.Lock()
	if dp, ok := e.dirCache[key]; ok {
		e.parseMu.Unlock()
		return dp.bodies, dp.err
	}
	e.parseMu.Unlock()

	bodies, err := parseDir(dir, packageRoot)

	e.parseMu.Lock()
	e.dirCache[key] = dirParse{bodies: bodies, err: err}
	e.parseMu.Unlock()
	return bodies, err
}

func (e *Evaluator) SetRemoteResolver(r RemoteResolver) {
	e.remoteResolver = r
}

func (e *Evaluator) ReleaseCaches() {
	e.ReleaseEvalCache()
	e.parseMu.Lock()
	e.dirCache = make(map[string]dirParse)
	e.parseMu.Unlock()
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
	ctx = resolver.WithResolvedPathCache(ctx)
	abs, absErr := filepath.Abs(dir)
	if absErr != nil {
		contextLogger := logger.FromContext(ctx)
		contextLogger.Warn().Err(absErr).Msgf("tfeval: filepath.Abs failed for %s, falling back to Clean", dir)
		abs = filepath.Clean(dir)
	}
	visiting := map[string]bool{}
	allVisited := map[string]bool{}
	instantiatedBefore := e.instantiated
	resources, outputs, err = e.evaluate(ctx, abs, "", inputs, "", nil, 0, visiting, allVisited)
	if err != nil {
		e.RestoreInstantiatedCount(instantiatedBefore)
	}
	return resources, outputs, allVisited, err
}

// evaluate is the recursive worker; visiting tracks dirs on the current stack for cycle
// detection; allVisited accumulates every child dir successfully evaluated as a module.
func (e *Evaluator) evaluate(
	ctx context.Context,
	dir string,
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

	// Snapshot allVisited so we can determine which dirs this subtree adds.
	prevAllVisited := make(map[string]bool, len(allVisited))
	for k := range allVisited {
		prevAllVisited[k] = true
	}

	bodies, err := e.parseDir(dir, packageRoot)
	if err != nil {
		return nil, nil, err
	}

	varExprs, localExprs, moduleBlocks, resourceBlocks, outputExprs := collectBlocks(bodies)

	varVals := e.resolveVariables(varExprs, inputs)

	evalCtx := &hcl.EvalContext{
		Variables: map[string]cty.Value{
			"var": objectOrEmpty(varVals),
		},
		Functions: e.funcs,
	}

	evalCtx.Variables["local"] = objectOrEmpty(e.resolveLocals(localExprs, evalCtx))

	if !e.preinjectResourceRefs(resourceBlocks, moduleBlocks, localExprs, evalCtx, addr, chain) {
		return nil, nil, e.skipEvaluation(dir)
	}

	e.applySiblingModulePrepass(ctx, moduleBlocks, evalCtx, localExprs, dir, packageRoot, addr, chain, depth, visiting)

	childResources, moduleOutputs := e.evaluateLocalModuleBlocks(
		ctx, moduleBlocks, evalCtx, dir, packageRoot, addr, chain, depth, visiting, allVisited,
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
		cacheKey, skippedBefore, resources, outputs, visitedDirs, addr, len(chain), depth,
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
	return entry.rebase(addr, chain), entry.outputs, true, nil
}

func (e *Evaluator) preinjectResourceRefs(
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
		resourceBlocks, evalCtx, addr, chain, e.remainingInstantiationBudget(),
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
		resourceBlocks, localExprs, evalCtx, addr, chain,
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
	return e.maxInstantiated > 0 &&
		*e.currentInstantiationCount() >= e.maxInstantiated
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
	localExprs map[string]hclsyntax.Expression,
	dir, packageRoot, addr string,
	chain []CallSite,
	depth int,
	visiting map[string]bool,
) {
	if len(moduleBlocks) <= 1 {
		return
	}
	prelimOutputs := e.preliminaryModuleOutputs(
		ctx, moduleBlocks, evalCtx, dir, packageRoot, addr, chain, depth, visiting,
	)
	if len(prelimOutputs) == 0 {
		return
	}
	evalCtx.Variables["module"] = cty.ObjectVal(prelimOutputs)
	localVals := e.resolveLocals(localExprs, evalCtx)
	evalCtx.Variables["local"] = objectOrEmpty(localVals)
}

func (e *Evaluator) evaluateLocalModuleBlocks(
	ctx context.Context,
	moduleBlocks []*hclsyntax.Block,
	evalCtx *hcl.EvalContext,
	dir, packageRoot, addr string,
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
	if existing, ok := evalCtx.Variables["module"]; ok && existing.Type().IsObjectType() {
		for it := existing.ElementIterator(); it.Next(); {
			k, v := it.Element()
			moduleOutputs[k.AsString()] = v
		}
	}

	for _, mb := range moduleBlocks {
		label := blockLabel(mb)
		if label == "" {
			continue
		}
		source := knownString(mb.Body.Attributes["source"], evalCtx)
		if source == "" {
			continue
		}

		version := knownString(mb.Body.Attributes["version"], evalCtx)
		childDir, childPackageRoot, ok := e.resolveModuleDir(
			ctx, dir, packageRoot, source, version, mb.TypeRange.Filename, label,
		)
		if !ok {
			continue
		}

		if isLiteralZero(mb.Body.Attributes["count"], evalCtx) {
			continue
		}
		if isEmptyCollection(mb.Body.Attributes["for_each"], evalCtx) {
			continue
		}

		modInputs := e.evalBody(mb.Body, evalCtx, reservedModuleAttrs)

		site := CallSite{
			ModuleName:      label,
			Source:          source,
			Version:         version,
			CalledFrom:      mb.TypeRange.Filename,
			CalledLine:      mb.TypeRange.Start.Line,
			CalledEndLine:   mb.Range().End.Line,
			CalledColumn:    mb.TypeRange.Start.Column,
			CalledEndColumn: mb.Range().End.Column,
		}
		childAddr := joinAddr(addr, "module."+label)

		childRes, childOuts, cErr := e.evaluate(
			ctx, childDir, childPackageRoot, modInputs, childAddr,
			append(cloneChain(chain), site), depth+1, visiting, allVisited,
		)
		if cErr != nil {
			if !errors.Is(cErr, ErrModuleNotEvaluated) {
				contextLogger.Warn().Msgf("tfeval: failed to evaluate module %q at %s: %v", label, childDir, cErr)
			}
			// Deliberately not added to allVisited: the module was not resolved, so
			// it must keep being scanned where it is written.
			continue
		}
		allVisited[childDir] = true
		childResources = append(childResources, childRes...)
		moduleOutputs[label] = objectOrEmpty(childOuts)
		// Update evalCtx so the next sibling's modInputs can reference this
		// module's now-resolved outputs (e.g. module.B.x = module.A.output).
		evalCtx.Variables["module"] = cty.ObjectVal(moduleOutputs)
	}
	return childResources, moduleOutputs
}

func (e *Evaluator) resolveModuleDir(
	ctx context.Context, callerDir, packageRoot, source, version, callerFile, moduleName string,
) (dir, childPackageRoot string, ok bool) {
	cleanSource := StripGetterPrefix(source)
	if tfmodules.LooksLikeLocalModuleSource(cleanSource) {
		localDir := resolveLocalDir(callerDir, source)
		if packageRoot == "" {
			return localDir, "", true
		}
		confined, resolveErr := resolver.ResolvePathWithinRoot(ctx, packageRoot, localDir)
		return confined, packageRoot, resolveErr == nil
	}
	if e.remoteResolver != nil {
		return e.remoteResolver(source, version, callerFile, moduleName)
	}
	return "", "", false
}

func (e *Evaluator) rootResourcesWithRefPasses(
	resourceBlocks []*hclsyntax.Block,
	localExprs map[string]hclsyntax.Expression,
	evalCtx *hcl.EvalContext,
	addr string,
	chain []CallSite,
) ([]ResolvedResource, bool) {
	var rootResources []ResolvedResource
	for pass := 0; pass < resourceRefPasses; pass++ {
		var complete bool
		rootResources, complete = e.evalResourceBlocks(
			resourceBlocks, evalCtx, addr, chain, e.remainingInstantiationBudget(),
		)
		if !complete {
			return nil, false
		}
		// Always inject so resolved attrs reach evalCtx on every pass including the last.
		changed := injectResourceRefs(evalCtx, rootResources)
		if !changed {
			break
		}
		// Refresh locals after every successful injection so that locals referencing
		// newly-resolved resource attrs are up-to-date before outputs are computed.
		localVals := e.resolveLocals(localExprs, evalCtx)
		evalCtx.Variables["local"] = objectOrEmpty(localVals)
		if pass+1 >= resourceRefPasses {
			break
		}
	}
	// One final evaluation picks up attrs that were only injected on the last pass
	// (e.g. the Nth resource in an A→B→C→D chain whose evalCtx was updated after the
	// last evalResourceBlocks call).
	return e.evalResourceBlocks(
		resourceBlocks, evalCtx, addr, chain, e.remainingInstantiationBudget(),
	)
}

// evalResourceBlocks evaluates resource blocks (count/for_each expanded when known).
func (e *Evaluator) evalResourceBlocks(
	resourceBlocks []*hclsyntax.Block,
	evalCtx *hcl.EvalContext,
	addr string,
	chain []CallSite,
	limit int,
) ([]ResolvedResource, bool) {
	resources := make([]ResolvedResource, 0, len(resourceBlocks))
	for _, rb := range resourceBlocks {
		expanded := e.expandResourceBlock(rb, evalCtx, addr, chain)
		if limit >= 0 && len(resources)+len(expanded) > limit {
			return resources, false
		}
		resources = append(resources, expanded...)
	}
	return resources, true
}

// expandResourceBlock emits zero, one, or N instances per block; known count/for_each
// get count.index / each.* in a child context; unknown expansion uses one placeholder instance.
func (e *Evaluator) expandResourceBlock(
	rb *hclsyntax.Block,
	evalCtx *hcl.EvalContext,
	addr string,
	chain []CallSite,
) []ResolvedResource {
	if len(rb.Labels) < 2 {
		return nil
	}
	typeName, resName := rb.Labels[0], rb.Labels[1]

	makeOne := func(name string, ctx *hcl.EvalContext) ResolvedResource {
		return ResolvedResource{
			Type:          typeName,
			Name:          name,
			Attributes:    e.evalBody(rb.Body, ctx, nil),
			Body:          rb.Body,
			DefinedIn:     rb.TypeRange.Filename,
			DefLine:       rb.TypeRange.Start.Line,
			DefEndLine:    rb.Range().End.Line,
			DefColumn:     rb.TypeRange.Start.Column,
			DefEndColumn:  rb.Range().End.Column,
			ModuleAddress: addr,
			CallChain:     cloneChain(chain),
		}
	}

	if out, ok := e.expandCountInstances(rb, resName, evalCtx, makeOne); ok {
		return out
	}
	if out, ok := e.expandForEachInstances(rb, resName, evalCtx, makeOne); ok {
		return out
	}
	return []ResolvedResource{makeOne(resName, evalCtx)}
}

func (e *Evaluator) expandCountInstances(
	rb *hclsyntax.Block,
	resName string,
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
		nExpand := n
		truncated := n > maxCountExpansion
		if nExpand > maxCountExpansion {
			nExpand = maxCountExpansion
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
			res.ExpansionTruncated = truncated
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
	rb *hclsyntax.Block,
	resName string,
	evalCtx *hcl.EvalContext,
	makeOne func(string, *hcl.EvalContext) ResolvedResource,
) ([]ResolvedResource, bool) {
	feAttr := rb.Body.Attributes["for_each"]
	if feAttr == nil {
		return nil, false
	}
	fv, diags := feAttr.Expr.Value(evalCtx)
	if !diags.HasErrors() && fv.IsKnown() && !fv.IsNull() {
		t := fv.Type()
		if t.IsObjectType() || t.IsMapType() || t.IsSetType() {
			if fv.LengthInt() == 0 {
				return nil, true
			}
			out := make([]ResolvedResource, 0)
			total := fv.LengthInt()
			truncated := total > maxCountExpansion
			i := 0
			for it := fv.ElementIterator(); it.Next() && i < maxCountExpansion; i++ {
				k, kv := it.Element()
				keyStr := "__"
				if k.Type() == cty.String && k.IsKnown() {
					keyStr = k.AsString()
				}
				child := evalCtx.NewChild()
				child.Variables = map[string]cty.Value{
					"each": cty.ObjectVal(map[string]cty.Value{
						"key":   k,
						"value": kv,
					}),
				}
				res := makeOne(fmt.Sprintf("%s[%q]", resName, keyStr), child)
				res.ExpansionTruncated = truncated
				out = append(out, res)
			}
			return out, true
		}
	}
	child := evalCtx.NewChild()
	child.Variables = map[string]cty.Value{
		"each": cty.ObjectVal(map[string]cty.Value{
			"key":   cty.UnknownVal(cty.String),
			"value": cty.UnknownVal(cty.DynamicPseudoType),
		}),
	}
	return []ResolvedResource{makeOne(resName, child)}, true
}

// injectResourceRefs sets evalCtx.Variables[type][name] from resources; returns true if changed.
// Count-expanded resources are exposed as ordered tuples so that x[0].attr resolves correctly;
// for_each-expanded resources as keyed objects so that x["k"].attr resolves correctly.
func injectResourceRefs(evalCtx *hcl.EvalContext, resources []ResolvedResource) bool {
	type instBucket struct {
		keys     []string
		attrs    []map[string]cty.Value
		isCount  bool
		expanded bool // true when any instance has brackets (count or for_each)
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
	}
	if len(byType) == 0 {
		return false
	}
	progress := false
	for typeName, nameMap := range byType {
		typeAttrs := make(map[string]cty.Value, len(nameMap))
		for baseName, b := range nameMap {
			typeAttrs[baseName] = buildInstanceCtyVal(b.keys, b.attrs, b.isCount, b.expanded)
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
func buildInstanceCtyVal(keys []string, attrsSlice []map[string]cty.Value, isCount, expanded bool) cty.Value {
	if !expanded {
		// Plain (non-indexed) resource: expose as a simple attribute object.
		return objectOrEmpty(attrsSlice[0])
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
		elems := make([]cty.Value, len(items))
		for i, item := range items {
			elems[i] = objectOrEmpty(item.attrs)
		}
		return cty.TupleVal(elems)
	}
	// for_each: expose as object keyed by string keys so x["key"].attr resolves.
	// Empty-string keys ("") are valid Terraform for_each keys and are kept.
	kvs := make(map[string]cty.Value, len(keys))
	for i, k := range keys {
		kvs[k] = objectOrEmpty(attrsSlice[i])
	}
	if len(kvs) == 0 {
		return cty.EmptyObjectVal
	}
	return cty.ObjectVal(kvs)
}

// resolveVariables binds inputs to variables, falling back to the default then unknown.
func (e *Evaluator) resolveVariables(
	varExprs map[string]hclsyntax.Expression,
	inputs map[string]cty.Value,
) map[string]cty.Value {
	out := make(map[string]cty.Value, len(varExprs))
	for name, defaultExpr := range varExprs {
		if v, ok := inputs[name]; ok {
			out[name] = v
			continue
		}
		if defaultExpr != nil {
			if v, diags := defaultExpr.Value(&hcl.EvalContext{Functions: e.funcs}); !diags.HasErrors() {
				out[name] = v
				continue
			}
		}
		out[name] = cty.UnknownVal(cty.DynamicPseudoType)
	}
	return out
}

// resolveLocals evaluates locals to a fixed point, retrying cross-references until no progress.
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
			if _, done := resolved[name]; done {
				continue
			}
			v, diags := expr.Value(ctx)
			if diags.HasErrors() || !v.IsWhollyKnown() {
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
	out := make(map[string]cty.Value, len(body.Attributes)+len(body.Blocks))

	for name, attr := range body.Attributes {
		if skip[name] {
			continue
		}
		out[name] = e.evalExpr(attr.Expr, ctx)
	}

	for _, b := range body.Blocks {
		path := append([]string{b.Type}, b.Labels...)
		addNestedBlock(out, path, objectOrEmpty(e.evalBody(b.Body, ctx, nil)))
	}
	return out
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
	dir, packageRoot, addr string,
	chain []CallSite,
	depth int,
	visiting map[string]bool,
) map[string]cty.Value {
	e.prepassDepth++
	defer func() { e.prepassDepth-- }()

	out := map[string]cty.Value{}
	tmpVisiting := make(map[string]bool, len(visiting))
	for k, v := range visiting {
		tmpVisiting[k] = v
	}
	for _, mb := range moduleBlocks {
		label := blockLabel(mb)
		if label == "" {
			continue
		}
		source := knownString(mb.Body.Attributes["source"], evalCtx)
		if source == "" {
			continue
		}
		version := knownString(mb.Body.Attributes["version"], evalCtx)
		childDir, childPackageRoot, ok := e.resolveModuleDir(
			ctx, dir, packageRoot, source, version, mb.TypeRange.Filename, label,
		)
		if !ok {
			continue
		}
		if isLiteralZero(mb.Body.Attributes["count"], evalCtx) {
			continue
		}
		if isEmptyCollection(mb.Body.Attributes["for_each"], evalCtx) {
			continue
		}
		modInputs := e.evalBody(mb.Body, evalCtx, reservedModuleAttrs)
		site := CallSite{
			ModuleName:      label,
			Source:          source,
			Version:         version,
			CalledFrom:      mb.TypeRange.Filename,
			CalledLine:      mb.TypeRange.Start.Line,
			CalledEndLine:   mb.Range().End.Line,
			CalledColumn:    mb.TypeRange.Start.Column,
			CalledEndColumn: mb.Range().End.Column,
		}
		childAddr := joinAddr(addr, "module."+label)
		childChain := append(cloneChain(chain), site)
		_, childOuts, _ := e.evaluate(
			ctx, childDir, childPackageRoot, modInputs, childAddr, childChain,
			depth+1, tmpVisiting, map[string]bool{},
		)
		if len(childOuts) > 0 {
			out[label] = objectOrEmpty(childOuts)
			// Make each module's outputs visible to subsequent siblings within this
			// same pre-pass loop, so their inputs resolve to the same values that the
			// main evaluation loop will compute — this keeps cache keys consistent.
			evalCtx.Variables["module"] = cty.ObjectVal(out)
		}
	}
	return out
}
