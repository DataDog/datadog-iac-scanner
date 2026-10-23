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
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/resolver"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/partial"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

const (
	// localsMaxPasses caps fixed-point resolution of locals that reference each other.
	localsMaxPasses = 10
	// resourceRefPasses caps passes that install same-module resource attrs for refs.
	resourceRefPasses = 3
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
	Iteration *Iteration

	// Source location and module address for finding attribution.
	DefinedIn     string
	DefLine       int
	DefEndLine    int
	DefColumn     int
	DefEndColumn  int
	ModuleAddress string // "" for root module resources
	// CallChain is shared by every resource of a module instance and must not
	// be modified.
	CallChain []CallSite
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

// Iteration is the count index or for_each element an expanded instance was
// evaluated with. It is kept in this form rather than as the context
// variables, which take several times the memory and are rebuilt on demand
// for the few that need them.
type Iteration struct {
	// Name is "count" or "each".
	Name string
	// Key is count.index or each.key, and Value each.value.
	Key, Value cty.Value
}

// Variables returns the count or each variable the instance was evaluated with.
func (it *Iteration) Variables() map[string]cty.Value {
	if it == nil {
		return nil
	}
	if it.Name == iterCount {
		return map[string]cty.Value{iterCount: cty.ObjectVal(map[string]cty.Value{"index": it.Key})}
	}
	return map[string]cty.Value{iterEach: cty.ObjectVal(map[string]cty.Value{"key": it.Key, "value": it.Value})}
}

// IterationOf is the iteration of the count or each variable in vars, nil
// when vars binds neither.
func IterationOf(vars map[string]cty.Value) *Iteration {
	if count, ok := vars[iterCount]; ok && count.Type().IsObjectType() && count.Type().HasAttribute("index") {
		return &Iteration{Name: iterCount, Key: count.GetAttr("index")}
	}
	if each, ok := vars[iterEach]; ok && each.Type().IsObjectType() && each.Type().HasAttribute("key") && each.Type().HasAttribute("value") {
		return &Iteration{Name: iterEach, Key: each.GetAttr("key"), Value: each.GetAttr("value")}
	}
	return nil
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
	funcs map[string]function.Function
	// fsys serves the evaluator's directory reads (module and tfvars files).
	// Defaults to the real disk; content-push scans inject an in-memory FS.
	fsys vfs.FS
	// cache memoizes completed module evaluations keyed by (dir, packageRoot,
	// input digest). A single Evaluator is used for an entire scan, so entries
	// with the same key represent the same module reached with the same resolved
	// inputs, whatever path led there.
	cache   map[evalCacheKey]*evalCacheEntry
	keyMemo keyMemo
	// When set, non-local module sources resolve here and recurse with caller inputs.
	remoteResolver RemoteResolver

	// inParallel is set on an evaluator evaluating instances of a module call
	// concurrently with others, whose nested calls are evaluated in order.
	inParallel bool

	// cacheOrder is the keys of cache entries in the order they were made,
	// so a rollback can find the entries made since a point.
	cacheOrder []evalCacheKey

	// steps counts evaluation steps since the last cancellation check, and
	// canceled is the scan's cancellation once a check saw it.
	steps    uint32
	canceled error
	// report counts what this evaluator evaluated.
	report Report

	prepassDepth int
	skipped      uint64

	// dataBlockEvals counts the data block expansions that actually ran, so
	// tests can check what the eval cache saves.
	dataBlockEvals int

	// notEvaluatedDirs holds every module directory this evaluator declined to
	// evaluate for a cycle or an invalid configuration. It accumulates for the whole scan
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

// Report returns what the evaluator evaluated since it was created or its
// report was last taken.
func (e *Evaluator) Report() *Report { return &e.report }

// TakeReport returns the report and starts a new one.
func (e *Evaluator) TakeReport() Report {
	r := e.report
	e.report = Report{}
	return r
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
// It shares e's settings and its parse and path caches; its evaluation
// cache, report and skipped directories are its own.
func (e *Evaluator) Fork() *Evaluator {
	return &Evaluator{
		funcs:            e.funcs,
		fsys:             e.fsys,
		cache:            make(map[evalCacheKey]*evalCacheEntry),
		remoteResolver:   e.remoteResolver,
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

// DataBlockEvaluations reports how many data block expansions ran, counting
// only evaluations the eval cache could not avoid.
func (e *Evaluator) DataBlockEvaluations() int { return e.dataBlockEvals }

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
	e.cacheOrder = nil
	e.keyMemo = keyMemo{}
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
	allVisited := newVisitSet()
	e.instances = nil
	if e.canceled = ctx.Err(); e.canceled != nil {
		return nil, nil, allVisited.dirs, ErrEvaluationStopped
	}
	outputs, err = e.evaluate(ctx, abs, abs, "", inputs, "", nil, visiting, allVisited, &resources)
	if err == nil {
		err = e.stopped()
	}
	if err != nil {
		resources, outputs = nil, nil
		e.instances = nil
	}
	return resources, outputs, allVisited.dirs, err
}

// visitSet is the module directories an evaluation resolved, in the order
// they were first resolved, so the ones a nested evaluation adds are the
// order's tail.
type visitSet struct {
	dirs  map[string]bool
	order []string
}

func newVisitSet() *visitSet { return &visitSet{dirs: map[string]bool{}} }

func (v *visitSet) add(dir string) {
	if !v.dirs[dir] {
		v.dirs[dir] = true
		v.order = append(v.order, dir)
	}
}

// evaluate is the recursive worker; visiting tracks dirs on the current stack for cycle
// detection; allVisited accumulates every child dir successfully evaluated as a module.
//
// The module's instances, and those of every module it calls, are appended to
// out, the result of the whole root: each instance is stored once, rather
// than copied into the result of every module above it. Nothing is appended
// when evaluation fails, which the caller rolls back with discardFrom.
func (e *Evaluator) evaluate(
	ctx context.Context,
	dir, rootDir string,
	packageRoot string,
	inputs map[string]cty.Value,
	addr string,
	chain []CallSite,
	visiting map[string]bool,
	allVisited *visitSet,
	out *[]ResolvedResource,
) (map[string]cty.Value, error) {
	if err := e.evaluationStop(ctx, dir, addr, visiting); err != nil {
		return nil, err
	}

	cacheKey := evalCacheKey{
		dir:         dir,
		rootDir:     rootDir,
		packageRoot: packageRoot,
		inputs:      e.keyMemo.inputsKey(inputs),
	}
	if outputs, hit, err := e.reuseCachedEvaluation(cacheKey, addr, chain, allVisited, out); hit {
		return outputs, err
	}
	if e.prepassDepth == 0 {
		e.report.ModuleEvaluations++
	}

	visiting[dir] = true
	defer delete(visiting, dir)
	mark := e.markEvaluation(allVisited, out)

	bodies, sources, err := e.parseDir(ctx, dir, packageRoot)
	if err != nil {
		return nil, err
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
	data := newModuleData(e, bodies, sources, scope, resourceTypes, addr, chain)
	data.refresh(ctx, evalCtx)

	// Resource values are published to the module's context only when an
	// expression of the module reads one; otherwise they would be built, and
	// kept with the module's context, for nothing.
	readsRefs := len(resourceTypes) > 0 && bodiesReadResources(bodies, resourceTypes)
	if readsRefs && !e.preinjectResourceRefs(ctx, resourceBlocks, moduleBlocks, localExprs, scope, resourceTypes, evalCtx, data, addr, chain) {
		return nil, e.skipEvaluation(dir)
	}

	e.applySiblingModulePrepass(
		ctx, moduleBlocks, evalCtx, scope, data, dir, rootDir, packageRoot, addr, chain, visiting,
	)
	if err := e.stopped(); err != nil {
		return nil, err
	}

	moduleOutputs := e.evaluateLocalModuleBlocks(
		ctx, moduleBlocks, evalCtx, scope, data, localExprs, dir, rootDir, packageRoot, addr, chain, visiting, allVisited, out,
	)
	if err := e.stopped(); err != nil {
		return nil, err
	}

	e.applyModuleOutputs(ctx, evalCtx, scope, localExprs, data, moduleOutputs)

	rootResources, err := e.evaluateRootResources(
		ctx, resourceBlocks, localExprs, scope, resourceTypes, evalCtx, data, addr, chain, readsRefs,
	)
	if err != nil {
		return nil, err
	}

	e.publishFinalResources(ctx, rootResources, resourceBlocks, localExprs, scope, resourceTypes, evalCtx, data, readsRefs)
	return e.completeEvaluation(cacheKey, mark, rootResources, data.resolved(scope), outputExprs, evalCtx,
		allVisited, out, addr, len(chain))
}

// publishFinalResources makes the final resource values visible to outputs,
// locals and data, and attaches the module's scope to its resources.
func (e *Evaluator) publishFinalResources(
	ctx context.Context,
	rootResources []ResolvedResource,
	resourceBlocks []*hclsyntax.Block,
	localExprs map[string]hclsyntax.Expression,
	scope *ModuleScope,
	resourceTypes map[string]struct{},
	evalCtx *hcl.EvalContext,
	data *moduleData,
	readsRefs bool,
) {
	// Re-inject the final-pass resource values so that outputs and locals that
	// reference the Nth hop of an N-hop chain can resolve. For chains shorter
	// than resourceRefPasses hops all resources were already injected inside the
	// loop, so injectResourceRefs returns false and the locals refresh is skipped.
	if readsRefs && injectResourceRefs(evalCtx, rootResources, emptyExpansions(resourceBlocks, evalCtx)) {
		evalCtx.Variables[localRootName] = objectOrEmpty(
			e.resolveLocalsIncremental(scope, localExprs, resourceTypes, evalCtx, true, false))
	}
	if data.readsOwnResources() {
		data.refresh(ctx, evalCtx)
	}
	scope.Local = evalCtx.Variables[localRootName]
	for i := range rootResources {
		rootResources[i].Scope = scope
	}
}

// evaluationMark is where a module evaluation began in the records the
// evaluator keeps while evaluating a root.
type evaluationMark struct {
	skipped            uint64
	instances, visited int
	start              int
}

func (e *Evaluator) markEvaluation(allVisited *visitSet, out *[]ResolvedResource) evaluationMark {
	return evaluationMark{
		skipped: e.skipped, instances: len(e.instances),
		visited: len(allVisited.order), start: len(*out),
	}
}

// completeEvaluation appends the module's own instances to out after those of
// the modules it calls, evaluates its outputs and caches the evaluation.
func (e *Evaluator) completeEvaluation(
	key evalCacheKey,
	mark evaluationMark,
	rootResources, dataInstances []ResolvedResource,
	outputExprs map[string]hclsyntax.Expression,
	evalCtx *hcl.EvalContext,
	allVisited *visitSet,
	out *[]ResolvedResource,
	addr string,
	chainLen int,
) (map[string]cty.Value, error) {
	if err := e.stopped(); err != nil {
		return nil, err
	}
	*out = append(*out, rootResources...)
	*out = append(*out, dataInstances...)

	outputs := make(map[string]cty.Value, len(outputExprs))
	for name, expr := range outputExprs {
		outputs[name] = e.evalExpr(expr, evalCtx)
	}

	// The dirs added to allVisited during this evaluation, for the cache entry.
	visitedDirs := slices.Clone(allVisited.order[mark.visited:])
	e.cacheCompletedEvaluation(
		key, mark.skipped, out, mark.start, e.instances[mark.instances:], outputs, visitedDirs,
		addr, chainLen,
	)
	return outputs, nil
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
	dir, addr string,
	visiting map[string]bool,
) error {
	if visiting[dir] {
		// Terraform rejects a module that calls itself, so there is no
		// instance to evaluate; the call is left as written.
		contextLogger := logger.FromContext(ctx)
		contextLogger.Warn().Msgf("tfeval: module cycle detected at %s, stopping recursion", dir)
		return e.skipEvaluation(dir)
	}
	if !e.step(ctx) {
		return ErrEvaluationStopped
	}
	return nil
}

func (e *Evaluator) reuseCachedEvaluation(
	key evalCacheKey,
	addr string,
	chain []CallSite,
	allVisited *visitSet,
	out *[]ResolvedResource,
) (
	outputs map[string]cty.Value,
	hit bool,
	err error,
) {
	entry, ok := e.cache[key]
	if !ok {
		return nil, false, nil
	}
	if e.prepassDepth == 0 {
		e.report.CacheHits++
	}
	for _, visited := range entry.visitedDirs {
		allVisited.add(visited)
	}
	e.instances = append(e.instances, entry.rebaseInstances(addr, chain)...)
	entry.appendRebased(out, addr, chain)
	return entry.outputs, true, nil
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
	if len(resourceBlocks) == 0 || len(moduleBlocks) == 0 || !moduleCallsReadResources(moduleBlocks, scope, resourceTypes) {
		return true
	}
	resources, complete := e.evalResourceBlocks(ctx, resourceBlocks, evalCtx, addr, chain)
	if !complete {
		return false
	}
	injected := injectResourceRefs(evalCtx, resources, emptyExpansions(resourceBlocks, evalCtx))
	evalCtx.Variables["local"] = objectOrEmpty(
		e.resolveLocalsIncremental(scope, localExprs, resourceTypes, evalCtx, injected, false))
	if data.readsOwnResources() {
		data.refresh(ctx, evalCtx)
	}
	return true
}

func (e *Evaluator) evaluateRootResources(
	ctx context.Context,
	resourceBlocks []*hclsyntax.Block,
	localExprs map[string]hclsyntax.Expression,
	scope *ModuleScope,
	resourceTypes map[string]struct{},
	evalCtx *hcl.EvalContext,
	data *moduleData,
	addr string,
	chain []CallSite,
	readsRefs bool,
) ([]ResolvedResource, error) {
	if !readsRefs {
		resources, complete := e.evalResourceBlocks(ctx, resourceBlocks, evalCtx, addr, chain)
		if !complete {
			return nil, ErrEvaluationStopped
		}
		return resources, nil
	}
	resources, complete := e.rootResourcesWithRefPasses(
		ctx, resourceBlocks, localExprs, scope, resourceTypes, evalCtx, data, addr, chain,
	)
	if !complete {
		return nil, ErrEvaluationStopped
	}
	return resources, nil
}

func (e *Evaluator) cacheCompletedEvaluation(
	key evalCacheKey,
	skippedBefore uint64,
	result *[]ResolvedResource,
	start int,
	instances []ModuleInstance,
	outputs map[string]cty.Value,
	visitedDirs []string,
	addr string,
	chainLen int,
) {
	if e.skipped != skippedBefore {
		return
	}
	e.cacheOrder = append(e.cacheOrder, key)
	e.cache[key] = &evalCacheEntry{
		result:       result,
		start:        start,
		end:          len(*result),
		instances:    slices.Clone(instances),
		outputs:      outputs,
		visitedDirs:  visitedDirs,
		baseAddr:     addr,
		baseChainLen: chainLen,
	}
	e.report.CacheEntries++
}

func (e *Evaluator) applySiblingModulePrepass(
	ctx context.Context,
	moduleBlocks []*hclsyntax.Block,
	evalCtx *hcl.EvalContext,
	scope *ModuleScope,
	data *moduleData,
	dir, rootDir, packageRoot, addr string,
	chain []CallSite,
	visiting map[string]bool,
) {
	if len(moduleBlocks) <= 1 || !readsLaterSibling(moduleBlocks, scope) {
		return
	}
	prelimOutputs := e.preliminaryModuleOutputs(
		ctx, moduleBlocks, evalCtx, scope, dir, rootDir, packageRoot, addr, chain, visiting,
	)
	e.installModuleOutputs(ctx, evalCtx, scope, scope.Locals, data, prelimOutputs)
}

// readsLaterSibling reports whether a module call reads the outputs of a call
// declared at or after it, directly or through a local reading module.*. Only
// then does it need the speculative sibling pass: the calls are evaluated in
// order, and each publishes its outputs before the next is evaluated, so a
// call reading only earlier siblings already sees their final outputs.
func readsLaterSibling(moduleBlocks []*hclsyntax.Block, scope *ModuleScope) bool {
	position := make(map[string]int, len(moduleBlocks))
	for i, mb := range moduleBlocks {
		position[blockLabel(mb)] = i
	}
	for i, mb := range moduleBlocks {
		later := false
		visitBodyTraversals(mb.Body, func(traversal hcl.Traversal) bool {
			switch traversal.RootName() {
			case blockTypeModule:
				if len(traversal) < 2 {
					later = true
					break
				}
				step, ok := traversal[1].(hcl.TraverseAttr)
				if !ok {
					later = true
					break
				}
				if at, declared := position[step.Name]; declared && at >= i {
					later = true
				}
			case localRootName:
				name, ok := terraform.LocalTraversalName(traversal)
				if !ok || (scope != nil && scope.localDeps[name].modules && i < len(moduleBlocks)-1) {
					later = true
				}
			}
			return !later
		})
		if later {
			return true
		}
	}
	return false
}

// visitBodyTraversals calls visit for every traversal in body, nested blocks
// included, until visit returns false.
func visitBodyTraversals(body *hclsyntax.Body, visit func(hcl.Traversal) bool) bool {
	for _, attr := range body.Attributes {
		for _, traversal := range attr.Expr.Variables() {
			if !visit(traversal) {
				return false
			}
		}
	}
	for _, block := range body.Blocks {
		if !visitBodyTraversals(block.Body, visit) {
			return false
		}
	}
	return true
}

func (e *Evaluator) evaluateLocalModuleBlocks(
	ctx context.Context,
	moduleBlocks []*hclsyntax.Block,
	evalCtx *hcl.EvalContext,
	scope *ModuleScope,
	data *moduleData,
	localExprs map[string]hclsyntax.Expression,
	dir, rootDir, packageRoot, addr string,
	chain []CallSite,
	visiting map[string]bool,
	allVisited *visitSet,
	out *[]ResolvedResource,
) (moduleOutputs map[string]cty.Value) {
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
		// Every instance of the call shares the chain leading to it.
		childChain := append(cloneChain(chain), call.site(scope))
		var keys, outs []cty.Value
		if n := e.concurrentInstances(&plan); n > 0 {
			keys, outs = e.evaluateCallConcurrently(ctx, mb, &call, &plan, n, rootDir, addr, childChain, visiting, allVisited, out)
			if e.stopped() != nil {
				return moduleOutputs
			}
		} else {
			for instance := range plan.all {
				if e.stopped() != nil {
					return moduleOutputs
				}
				modInputs := e.evalBody(mb.Body, instance.ctx, reservedModuleAttrs)
				childAddr := instance.address(addr, call.label)
				instancesBefore := len(e.instances)
				mark := e.resultMark(out)

				childOuts, cErr := e.evaluate(
					ctx, call.dir, rootDir, call.packageRoot, modInputs, childAddr,
					childChain, visiting, allVisited, out,
				)
				keys = append(keys, instance.key)
				if cErr != nil {
					if isReportableModuleEvalError(cErr) {
						contextLogger.Warn().Msgf("tfeval: failed to evaluate module %q at %s: %v", call.label, call.dir, cErr)
					}
					// Deliberately not added to allVisited: the module was not resolved, so
					// it must keep being scanned where it is written.
					e.instances = e.instances[:instancesBefore]
					e.discardFrom(mark)
					outs = append(outs, cty.NilVal)
					continue
				}
				e.recordModuleInstance(call.dir, childAddr, childChain)
				allVisited.add(call.dir)
				outs = append(outs, objectOrEmpty(childOuts))
			}
		}
		if value, ok := moduleOutputsValue(&plan, keys, outs); ok {
			moduleOutputs[call.label] = value
			e.installSiblingModuleOutputs(ctx, evalCtx, scope, localExprs, data, moduleOutputs)
		}
	}
	return moduleOutputs
}

// evaluateCallConcurrently evaluates the n instances of a module call on
// several workers, and appends their instances to out in instance order.
func (e *Evaluator) evaluateCallConcurrently(
	ctx context.Context,
	mb *hclsyntax.Block,
	call *moduleCall,
	plan *moduleExpansionPlan,
	n int,
	rootDir, addr string,
	childChain []CallSite,
	visiting map[string]bool,
	allVisited *visitSet,
	out *[]ResolvedResource,
) (keys, outs []cty.Value) {
	contextLogger := logger.FromContext(ctx)
	instances, results := e.evaluateInstancesConcurrently(ctx, mb, call, plan, n, rootDir, addr, childChain, visiting, allVisited)
	// The result grows once for every instance rather than once per instance.
	total := 0
	for i := range results {
		total += len(results[i].resources)
	}
	*out = slices.Grow(*out, total)
	for i := range results {
		r := &results[i]
		keys = append(keys, instances[i].key)
		if r.err != nil {
			if isReportableModuleEvalError(r.err) {
				contextLogger.Warn().Msgf("tfeval: failed to evaluate module %q at %s: %v", call.label, call.dir, r.err)
			}
			outs = append(outs, cty.NilVal)
			continue
		}
		*out = append(*out, r.resources...)
		e.instances = append(e.instances, r.instances...)
		e.recordModuleInstance(call.dir, instances[i].address(addr, call.label), childChain)
		allVisited.add(call.dir)
		outs = append(outs, objectOrEmpty(r.outputs))
	}
	return keys, outs
}

// resultMark is a point in a result to roll back to.
type resultMark struct {
	result *[]ResolvedResource
	length int
	cached int
}

func (e *Evaluator) resultMark(result *[]ResolvedResource) resultMark {
	return resultMark{result: result, length: len(*result), cached: len(e.cacheOrder)}
}

// discardFrom drops what a failed evaluation appended to the result since m,
// and forgets the cache entries made since then that point into the part
// dropped. Entries of results other than m's stay valid.
func (e *Evaluator) discardFrom(m resultMark) {
	*m.result = (*m.result)[:m.length]
	kept := e.cacheOrder[:m.cached]
	for _, key := range e.cacheOrder[m.cached:] {
		entry, ok := e.cache[key]
		if ok && entry.result == m.result && entry.end > m.length {
			delete(e.cache, key)
			continue
		}
		kept = append(kept, key)
	}
	e.cacheOrder = kept
}

// localRootName is the root of local value references.
const localRootName = "local"

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
		rootResources, complete = e.evalResourceBlocks(ctx, resourceBlocks, evalCtx, addr, chain)
		if !complete {
			return nil, false
		}
		// Always inject so resolved attrs reach evalCtx on every pass including the last.
		changed := injectResourceRefs(evalCtx, rootResources, emptyExpansions(resourceBlocks, evalCtx))
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
	return e.evalResourceBlocks(ctx, resourceBlocks, evalCtx, addr, chain)
}

// bodiesReadResources reports whether any expression of a module's files
// reads one of the resource types it declares.
func bodiesReadResources(bodies []*hclsyntax.Body, types map[string]struct{}) bool {
	for _, body := range bodies {
		if bodyReadsResource(body, types) {
			return true
		}
	}
	return false
}

// moduleCallsReadResources reports whether a module call reads the module's
// resources, directly or through a local, so the resources must be known
// before the calls are evaluated.
func moduleCallsReadResources(moduleBlocks []*hclsyntax.Block, scope *ModuleScope, types map[string]struct{}) bool {
	for _, mb := range moduleBlocks {
		if bodyReadsResource(mb.Body, types) {
			return true
		}
		reads := false
		visitBodyTraversals(mb.Body, func(traversal hcl.Traversal) bool {
			if name, ok := terraform.LocalTraversalName(traversal); ok {
				reads = scope.localDeps[name].resources
			} else if traversal.RootName() == localRootName {
				reads = true
			}
			return !reads
		})
		if reads {
			return true
		}
	}
	return false
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

// evalResourceBlocks evaluates resource blocks, count/for_each expanded when
// known. It reports false when the scan was canceled, in which
// case the instances are not a complete result.
func (e *Evaluator) evalResourceBlocks(
	ctx context.Context,
	resourceBlocks []*hclsyntax.Block,
	evalCtx *hcl.EvalContext,
	addr string,
	chain []CallSite,
) ([]ResolvedResource, bool) {
	var resources []ResolvedResource
	for _, rb := range resourceBlocks {
		var ok bool
		resources, ok = e.expandBlock(ctx, rb, evalCtx, addr, chain, false, resources)
		if !ok {
			return nil, false
		}
	}
	return resources, true
}

// expandBlock appends to out the zero, one or N instances of a resource or
// data block: known count/for_each get count.index / each.* in a child
// context, an unknown one a single instance with an unknown iteration. It
// reports false when the scan was canceled.
func (e *Evaluator) expandBlock(
	ctx context.Context,
	rb *hclsyntax.Block,
	evalCtx *hcl.EvalContext,
	addr string,
	chain []CallSite,
	data bool,
	out []ResolvedResource,
) ([]ResolvedResource, bool) {
	if len(rb.Labels) < 2 {
		return out, true
	}
	x := &blockExpansion{
		e: e, ctx: ctx, rb: rb, evalCtx: evalCtx, addr: addr, chain: chain, data: data, out: out,
		// Attributes that ignore each/count evaluate identically in every instance.
		memo: newInvariantMemo(),
	}
	name := rb.Labels[1]
	var ok bool
	switch {
	case rb.Body.Attributes[iterCount] != nil:
		ok = x.count(name, rb.Body.Attributes[iterCount])
	case rb.Body.Attributes[forEachArg] != nil:
		ok = x.forEach(name, rb.Body.Attributes[forEachArg])
	default:
		ok = x.add(name, evalCtx, cty.NilVal, cty.NilVal)
	}
	return x.out, ok
}

const (
	iterCount  = "count"
	iterEach   = "each"
	forEachArg = "for_each"
)

// blockExpansion builds the instances of one resource or data block.
type blockExpansion struct {
	e       *Evaluator
	ctx     context.Context
	rb      *hclsyntax.Block
	evalCtx *hcl.EvalContext
	addr    string
	chain   []CallSite
	data    bool
	out     []ResolvedResource
	memo    *invariantMemo
	// skip and forEachOf replace the for_each argument of each instance by
	// the instance's own element.
	skip      map[string]bool
	forEachOf func(key, value cty.Value) cty.Value
}

func (x *blockExpansion) count(name string, attr *hclsyntax.Attribute) bool {
	n, state := countValue(attr.Expr, x.evalCtx)
	if state != expansionKnown {
		return x.add(name, unknownIterationContext(x.evalCtx, iterCount), cty.NilVal, cty.NilVal)
	}
	for i := range n {
		index := cty.NumberIntVal(int64(i))
		if !x.add(name+"["+strconv.Itoa(i)+"]", iterationContext(x.evalCtx, iterCount, map[string]cty.Value{"index": index}), index, cty.NilVal) {
			return false
		}
	}
	return true
}

func (x *blockExpansion) forEach(name string, attr *hclsyntax.Attribute) bool {
	fv, state := forEachValue(attr.Expr, x.evalCtx)
	if state != expansionKnown {
		return x.add(name, unknownIterationContext(x.evalCtx, iterEach), cty.NilVal, cty.NilVal)
	}
	// Each instance holds the element it was created for rather than the
	// whole collection, which would make every instance as large as the
	// expansion, and the expansion quadratic in its size.
	x.skip = map[string]bool{forEachArg: true}
	x.forEachOf = instanceForEach(fv.Type())
	for it := fv.ElementIterator(); it.Next(); {
		k, v := it.Element()
		key, _ := ctyutil.ConcreteString(k)
		child := iterationContext(x.evalCtx, iterEach, map[string]cty.Value{"key": k, "value": v})
		if !x.add(name+"["+strconv.Quote(key)+"]", child, k, v) {
			return false
		}
	}
	return true
}

// add evaluates one instance under child and reports whether evaluation may go on.
func (x *blockExpansion) add(name string, child *hcl.EvalContext, key, value cty.Value) bool {
	e := x.e
	if !e.step(x.ctx) {
		return false
	}
	if e.prepassDepth == 0 {
		e.report.InstanceEvaluations++
	}
	// Only attribution of module resources and data evaluation read the
	// iteration, so the resource instances of the root module do not keep it.
	var iteration *Iteration
	if child != x.evalCtx && (x.addr != "" || x.data) {
		iteration = IterationOf(child.Variables)
	}
	state := &bodyState{memo: x.memo, dynamic: &dynamicRecorder{}}
	attrs := e.evalBodyWith(x.ctx, x.rb.Body, child, x.skip, state)
	if x.forEachOf != nil {
		attrs[forEachArg] = x.forEachOf(key, value)
	}
	rb := x.rb
	x.out = append(x.out, ResolvedResource{
		Type:          rb.Labels[0],
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
		ModuleAddress: x.addr,
		CallChain:     x.chain,
		Data:          x.data,
	})
	return e.stopped() == nil
}

// instanceForEach returns the for_each attribute of one instance of a block
// expanding a collection of type t: a collection of the same kind holding the
// instance's own element, so it reads as known and non-empty, and yields the
// instance's key and value when iterated.
func instanceForEach(t cty.Type) func(key, value cty.Value) cty.Value {
	if t.IsSetType() {
		return func(key, _ cty.Value) cty.Value { return cty.SetVal([]cty.Value{key}) }
	}
	return func(key, value cty.Value) cty.Value {
		return cty.ObjectVal(map[string]cty.Value{key.AsString(): value})
	}
}

// injectResourceRefs sets evalCtx.Variables[type][name] from resources; returns true if changed.
// Count-expanded resources are exposed as ordered tuples so that x[0].attr resolves correctly;
// for_each-expanded resources as keyed objects so that x["k"].attr resolves correctly.
//
// empty holds the blocks whose known count or for_each yields no instance, as
// emptyExpansions returns them; they are published as the empty tuple or
// object Terraform gives them, so length() and iteration over them are known.
func injectResourceRefs(evalCtx *hcl.EvalContext, resources []ResolvedResource, empty map[string]map[string]cty.Value) bool {
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
	for typeName, names := range empty {
		if byType[typeName] == nil {
			byType[typeName] = make(map[string]*instBucket)
		}
		for name := range names {
			if _, ok := byType[typeName][name]; !ok {
				byType[typeName][name] = nil
			}
		}
	}
	if len(byType) == 0 {
		return false
	}
	progress := false
	for typeName, nameMap := range byType {
		typeAttrs := make(map[string]cty.Value, len(nameMap))
		for baseName, b := range nameMap {
			if b == nil {
				typeAttrs[baseName] = empty[typeName][baseName]
				continue
			}
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

// emptyExpansions returns, by type and name, the blocks whose known count or
// for_each yields no instance, with the value Terraform gives them.
func emptyExpansions(blocks []*hclsyntax.Block, evalCtx *hcl.EvalContext) map[string]map[string]cty.Value {
	var out map[string]map[string]cty.Value
	for _, b := range blocks {
		if len(b.Labels) < 2 {
			continue
		}
		var value cty.Value
		if attr := b.Body.Attributes["count"]; attr != nil {
			if n, state := countValue(attr.Expr, evalCtx); state == expansionKnown && n == 0 {
				value = cty.EmptyTupleVal
			}
		} else if attr := b.Body.Attributes["for_each"]; attr != nil {
			if v, state := forEachValue(attr.Expr, evalCtx); state == expansionKnown && v.LengthInt() == 0 {
				value = cty.EmptyObjectVal
			}
		}
		if value == cty.NilVal {
			continue
		}
		if out == nil {
			out = make(map[string]map[string]cty.Value)
		}
		if out[b.Labels[0]] == nil {
			out[b.Labels[0]] = make(map[string]cty.Value)
		}
		out[b.Labels[0]][b.Labels[1]] = value
	}
	return out
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
	kvs := make(map[string]cty.Value, len(keys))
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
			v, diags := expr.Value(ctx)
			if diags.HasErrors() {
				v = partial.WithUnknownRefs(expr, ctx)
			}
			if !v.IsKnown() || (seen && prev.RawEquals(v)) {
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
// It keeps dynamic blocks as written: a module call cannot hold them.
func (e *Evaluator) evalBody(
	body *hclsyntax.Body,
	ctx *hcl.EvalContext,
	skip map[string]bool,
) map[string]cty.Value {
	return e.evalBodyWith(context.Background(), body, ctx, skip, nil)
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
	counts DynamicCounts
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
	gctx context.Context,
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

	var blocks blockSet
	for _, b := range body.Blocks {
		if st != nil && dynamicblock.Is(b) {
			e.addDynamicBlocks(gctx, &blocks, b, ctx, st)
			continue
		}
		path := append([]string{b.Type}, b.Labels...)
		blocks.add(path, objectOrEmpty(e.evalBodyWith(gctx, b.Body, ctx, nil, st)))
	}
	blocks.into(out)
	return out
}

// blockSet collects the nested blocks of a body, in order, so the blocks
// sharing a type become one tuple built once rather than grown one block at a
// time, which is quadratic in the number of blocks a dynamic block generates.
type blockSet struct {
	paths  [][]string
	values []cty.Value
}

func (bs *blockSet) add(path []string, value cty.Value) {
	bs.paths = append(bs.paths, path)
	bs.values = append(bs.values, value)
}

// into adds the blocks to out exactly as adding them one at a time with
// addNestedBlock would.
func (bs *blockSet) into(out map[string]cty.Value) {
	for _, g := range bs.groups() {
		_, preset := out[g.key]
		switch {
		case preset || (g.labeled && g.unlabeled):
			for _, i := range g.indexes {
				addNestedBlock(out, bs.paths[i], bs.values[i])
			}
		case g.labeled:
			var inner blockSet
			for _, i := range g.indexes {
				inner.add(bs.paths[i][1:], bs.values[i])
			}
			nested := make(map[string]cty.Value)
			inner.into(nested)
			out[g.key] = objectOrEmpty(nested)
		case len(g.indexes) == 1:
			out[g.key] = bs.values[g.indexes[0]]
		default:
			elems := make([]cty.Value, len(g.indexes))
			for j, i := range g.indexes {
				elems[j] = bs.values[i]
			}
			out[g.key] = cty.TupleVal(elems)
		}
	}
}

// blockGroup is the blocks of a blockSet sharing a type, in order.
type blockGroup struct {
	key       string
	indexes   []int
	unlabeled bool
	labeled   bool
}

func (bs *blockSet) groups() []*blockGroup {
	byKey := make(map[string]*blockGroup)
	var order []*blockGroup
	for i, path := range bs.paths {
		g, ok := byKey[path[0]]
		if !ok {
			g = &blockGroup{key: path[0]}
			byKey[path[0]] = g
			order = append(order, g)
		}
		g.indexes = append(g.indexes, i)
		if len(path) == 1 {
			g.unlabeled = true
		} else {
			g.labeled = true
		}
	}
	return order
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
	evalCtx *hcl.EvalContext,
	scope *ModuleScope,
	dir, rootDir, packageRoot, addr string,
	chain []CallSite,
	visiting map[string]bool,
) map[string]cty.Value {
	e.prepassDepth++
	// The calls evaluated here are speculative; cache entries keep their own
	// instances and notes.
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
	// The instances evaluated here are not part of the result. They are kept
	// apart for as long as the cache entries made here may be reused.
	scratch := new([]ResolvedResource)
	for _, mb := range moduleBlocks {
		call, ok := e.resolveModuleCall(ctx, mb, evalCtx, dir, packageRoot)
		if !ok {
			continue
		}
		plan := moduleInstances(mb, evalCtx)
		childChain := append(cloneChain(chain), call.site(scope))
		var keys, outs []cty.Value
		for instance := range plan.all {
			if e.stopped() != nil {
				return out
			}
			modInputs := e.evalBody(mb.Body, instance.ctx, reservedModuleAttrs)
			mark := e.resultMark(scratch)
			childOuts, err := e.evaluate(
				ctx, call.dir, rootDir, call.packageRoot, modInputs, instance.address(addr, call.label), childChain,
				tmpVisiting, newVisitSet(), scratch,
			)
			if err != nil {
				e.discardFrom(mark)
			}
			keys = append(keys, instance.key)
			if err == nil {
				outs = append(outs, objectOrEmpty(childOuts))
			} else {
				outs = append(outs, cty.NilVal)
			}
		}
		if value, ok := moduleOutputsValue(&plan, keys, outs); ok {
			out[call.label] = value
			// Make each module's outputs visible to subsequent siblings within this
			// same pre-pass loop, so their inputs resolve to the same values that the
			// main evaluation loop will compute — this keeps cache keys consistent.
			evalCtx.Variables["module"] = cty.ObjectVal(out)
		}
	}
	return out
}
