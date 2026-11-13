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
	Iteration map[string]cty.Value

	// Source location and module address for finding attribution.
	DefinedIn     string
	DefLine       int
	DefEndLine    int
	DefColumn     int
	DefEndColumn  int
	ModuleAddress string // "" for root module resources
	CallChain     []CallSite
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

	// localGraph is the graph of the module directory's locals, which gives
	// the order they resolve in and which of the roots that change during
	// evaluation (the module's resources, its module outputs, its data) each
	// reads; localCache holds the values the last resolution returned. A
	// re-resolution re-evaluates only the locals reading a root that changed,
	// and reuses the rest verbatim.
	localGraph *localGraph
	localCache map[string]cty.Value
	static     *dirStatic
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
	// cycleWarned holds the directories already warned about for a reference
	// cycle among their locals or data blocks.
	cycleWarned sync.Map
	// fsys serves the evaluator's directory reads (module and tfvars files).
	// Defaults to the real disk; content-push scans inject an in-memory FS.
	fsys vfs.FS
	// cache memoizes completed module evaluations keyed by (dir, packageRoot,
	// input digest). A single Evaluator is used for an entire scan, so entries
	// with the same key represent the same module reached with the same resolved
	// inputs, whatever path led there.
	cache   map[evalCacheKey]*evalCacheEntry
	keyMemo keyMemo
	// contexts shares the read-only functions and path values of a directory
	// within a root. Scopes retain these after evaluation for attribution and
	// rendering; rebuilding the functions for each instance pins all their
	// filesystem closures once per call, even when every value is unique.
	contexts map[moduleContextKey]moduleContext
	// localMemo shares locals and invariant resource attributes across module
	// evaluations reading the same values; localReads records their dependencies.
	// Both follow the evaluation cache's lifetime.
	localMemo  map[localMemoKey]cty.Value
	localReads map[hclsyntax.Expression]localReads
	// When set, non-local module sources resolve here and recurse with caller inputs.
	remoteResolver RemoteResolver

	skipped uint64

	// dataBlockEvals counts the data block expansions that actually ran, so
	// tests can check what the eval cache saves.
	dataBlockEvals int

	// notEvaluatedDirs holds every module directory this evaluator declined to
	// evaluate for depth or cycle. It accumulates for the whole scan
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

// dirParse is a parsed module directory: its files, the blocks evaluation
// reads, and the graph of its locals and data blocks.
type dirParse struct {
	bodies        []*hclsyntax.Body
	sources       map[string][]byte
	varDecls      map[string]variableDecl
	localExprs    map[string]hclsyntax.Expression
	modules       []*hclsyntax.Block
	resources     []*hclsyntax.Block
	outputs       map[string]hclsyntax.Expression
	resourceTypes map[string]struct{}
	locals        *localGraph
	static        *dirStatic
	err           error
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

// parseDir returns the parsed module directory, parsed once and shared by
// every fork with its locals graph.
func (e *Evaluator) parseDir(ctx context.Context, dir, packageRoot string) dirParse {
	key := filepath.Clean(dir) + "\x00" + filepath.Clean(packageRoot)

	e.parseMu.Lock()
	if dp, ok := e.dirCache[key]; ok {
		e.parseMu.Unlock()
		return dp
	}
	e.parseMu.Unlock()

	bodies, sources, err := parseDir(ctx, dir, packageRoot, e.mergeAllow, e.fsys)
	dp := dirParse{bodies: bodies, sources: sources, err: err}
	if err == nil {
		dp.varDecls, dp.localExprs, dp.modules, dp.resources, dp.outputs = collectBlocks(bodies)
		dp.resourceTypes = declaredResourceTypes(dp.resources)
		dp.locals = newLocalGraph(dp.localExprs, dp.resourceTypes, collectDataBlocks(bodies))
		dp.static = newDirStatic(&dp)
	}

	e.parseMu.Lock()
	e.dirCache[key] = dp
	e.parseMu.Unlock()
	return dp
}

// Fork returns an evaluator that can evaluate other roots concurrently with e.
// It shares e's settings and its parse and path caches; its evaluation cache
// and skipped directories are its own.
func (e *Evaluator) Fork() *Evaluator {
	return &Evaluator{
		funcs:            e.funcs,
		maxDepth:         e.maxDepth,
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
// bodies. The key includes rootDir, so a later root does not reuse them, and
// each entry holds its subtree. The parse cache is keyed by directory alone
// and is kept.
func (e *Evaluator) ReleaseEvalCache() {
	e.cache = make(map[evalCacheKey]*evalCacheEntry)
	e.keyMemo = keyMemo{}
	e.contexts = nil
	e.ReleaseLocalMemo()
	e.localReads = nil
}

// ReleaseLocalMemo drops expression values shared across module instances.
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
	e.instances = nil
	resources, outputs, err = e.evaluate(ctx, abs, abs, "", inputs, "", nil, 0, visiting, allVisited)
	if err == nil {
		// A canceled or timed-out scan may have stopped mid-expansion. Do not
		// return that partial tree as a completed evaluation.
		err = ctx.Err()
	}
	if err != nil {
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
	if resources, outputs, hit := e.reuseCachedEvaluation(cacheKey, addr, chain, depth, allVisited); hit {
		return resources, outputs, nil
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

	parsed := e.parseDir(ctx, dir, packageRoot)
	if parsed.err != nil {
		return nil, nil, parsed.err
	}
	bodies, sources, moduleBlocks, resourceBlocks := parsed.bodies, parsed.sources, parsed.modules, parsed.resources

	varVals := e.resolveVariables(parsed.varDecls, inputs)
	shared := e.moduleContext(dir, rootDir)

	evalCtx := &hcl.EvalContext{
		Variables: map[string]cty.Value{
			"var": objectOrEmpty(varVals),
		},
		Functions: shared.functions,
	}
	for name, value := range shared.variables {
		evalCtx.Variables[name] = value
	}

	scope := &ModuleScope{
		Locals: parsed.localExprs, Bodies: bodies, Var: evalCtx.Variables["var"], evalCtx: evalCtx, sources: sources,
		localGraph: parsed.locals, static: parsed.static,
	}
	e.noteCycles(ctx, dir, parsed.locals)
	evalCtx.Variables["local"] = e.resolveLocalsIncremental(scope, evalCtx, false, false)
	data := newModuleData(e, sources, parsed.locals, parsed.static, addr, chain)
	data.refresh(ctx, evalCtx)

	e.preinjectResourceRefs(ctx, resourceBlocks, moduleBlocks, scope, evalCtx, data, addr, chain)

	reads := parsed.static.siblings
	e.applySiblingModulePrepass(
		ctx, moduleBlocks, reads, evalCtx, scope, data, dir, rootDir, packageRoot, addr, chain, depth, visiting,
	)

	childResources, moduleOutputs := e.evaluateLocalModuleBlocks(
		ctx, moduleBlocks, reads, evalCtx, scope, data, dir, rootDir, packageRoot, addr, chain, depth, visiting, allVisited,
	)

	e.applyModuleOutputs(ctx, evalCtx, scope, data, moduleOutputs)

	rootResources := e.evaluateRootResources(
		ctx, resourceBlocks, scope, evalCtx, data, addr, chain,
	)

	// Re-inject the final-pass resource values so that outputs and locals that
	// reference the Nth hop of an N-hop chain can resolve. For chains shorter
	// than resourceRefPasses hops all resources were already injected inside the
	// loop, so injectResourceRefs returns false and the locals refresh is skipped.
	if injectResourceRefs(evalCtx, rootResources) {
		evalCtx.Variables["local"] = e.resolveLocalsIncremental(scope, evalCtx, true, false)
	}
	if data.readsOwnResources() {
		data.refresh(ctx, evalCtx)
	}
	scope.Local = evalCtx.Variables["local"]
	for i := range rootResources {
		rootResources[i].Scope = scope
	}
	dataInstances := data.resolved(scope)
	resources := make([]ResolvedResource, 0, len(rootResources)+len(dataInstances)+len(childResources))
	resources = append(resources, rootResources...)
	resources = append(resources, dataInstances...)
	resources = append(resources, childResources...)

	outputs := make(map[string]cty.Value, len(parsed.outputs))
	for name, expr := range parsed.outputs {
		outputs[name] = e.evalExpr(expr, evalCtx)
	}

	// A canceled or timed-out scan may have stopped mid-expansion. Do not
	// memoize that partial tree: a later EvaluateModule on the same Evaluator
	// would reuse it as a complete result.
	if err := ctx.Err(); err != nil {
		e.instances = e.instances[:instancesBefore]
		return nil, nil, err
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
	data *moduleData,
	moduleOutputs map[string]cty.Value,
) {
	e.installModuleOutputs(ctx, evalCtx, scope, data, moduleOutputs)
}

// installModuleOutputs publishes module.* and refreshes what reads it: first
// the locals reading module outputs, then the data blocks. That locals-before-
// data ordering is load-bearing. Republishing the module.* value the data was
// already refreshed against skips the refresh: nothing data reads changed.
func (e *Evaluator) installModuleOutputs(
	ctx context.Context,
	evalCtx *hcl.EvalContext,
	scope *ModuleScope,
	data *moduleData,
	moduleOutputs map[string]cty.Value,
) {
	if len(moduleOutputs) == 0 {
		return
	}
	value := cty.ObjectVal(moduleOutputs)
	evalCtx.Variables["module"] = value
	evalCtx.Variables["local"] = e.resolveLocalsIncremental(scope, evalCtx, false, true)
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
	if err := ctx.Err(); err != nil {
		return err
	}
	contextLogger := logger.FromContext(ctx)
	if depth > e.maxDepth {
		contextLogger.Warn().Msgf("tfeval: max module depth %d exceeded at %s", e.maxDepth, dir)
		return e.skipEvaluation(dir)
	}
	if visiting[dir] {
		contextLogger.Warn().Msgf("tfeval: module cycle detected at %s, stopping recursion", dir)
		return e.skipEvaluation(dir)
	}
	return nil
}

func (e *Evaluator) reuseCachedEvaluation(
	key evalCacheKey,
	addr string,
	chain []CallSite,
	depth int,
	allVisited map[string]bool,
) (resources []ResolvedResource, outputs map[string]cty.Value, hit bool) {
	entry, ok := e.cache[key]
	if !ok {
		return nil, nil, false
	}
	if entry.evalDepth > depth {
		return nil, nil, false
	}
	for _, visited := range entry.visitedDirs {
		allVisited[visited] = true
	}
	e.instances = append(e.instances, entry.rebaseInstances(addr, chain)...)
	return entry.rebase(addr, chain), entry.outputs, true
}

func (e *Evaluator) preinjectResourceRefs(
	ctx context.Context,
	resourceBlocks, moduleBlocks []*hclsyntax.Block,
	scope *ModuleScope,
	evalCtx *hcl.EvalContext,
	data *moduleData,
	addr string,
	chain []CallSite,
) {
	if len(resourceBlocks) == 0 || len(moduleBlocks) == 0 {
		return
	}
	resources := e.evalResourceBlocks(ctx, resourceBlocks, evalCtx, addr, chain)
	injected := injectResourceRefs(evalCtx, resources)
	evalCtx.Variables["local"] = e.resolveLocalsIncremental(scope, evalCtx, injected, false)
	if data.readsOwnResources() {
		data.refresh(ctx, evalCtx)
	}
}

func (e *Evaluator) evaluateRootResources(
	ctx context.Context,
	resourceBlocks []*hclsyntax.Block,
	scope *ModuleScope,
	evalCtx *hcl.EvalContext,
	data *moduleData,
	addr string,
	chain []CallSite,
) []ResolvedResource {
	return e.rootResourcesWithRefPasses(ctx, resourceBlocks, scope, evalCtx, data, addr, chain)
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
	e.installModuleOutputs(ctx, evalCtx, scope, data, prelimOutputs)
}

func (e *Evaluator) evaluateLocalModuleBlocks(
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
			e: e, ctx: ctx, evalCtx: evalCtx, scope: scope, data: data, outputs: moduleOutputs,
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
		plan := moduleInstances(ctx, mb, callCtx)
		site := call.site(scope)
		// Do not pre-size to plan.Len(): an uncapped count panics before cancel.
		outs := make([]cty.Value, 0)
		for i := range plan.Len() {
			if ctx.Err() != nil {
				break
			}
			instance := plan.At(i)
			modInputs := e.evalBody(ctx, mb.Body, instance.ctx, reservedModuleAttrs)
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
				// What stopped this instance — the depth, a cycle or a directory
				// that does not resolve — is the same for every instance of the
				// call. The loop stops instead of redoing the same failing work
				// once per instance; the un-evaluated instances stay unknown in
				// the call's outputs.
				outs = append(outs, cty.NilVal)
				break
			}
			e.recordModuleInstance(call.dir, childAddr, childChain)
			allVisited[call.dir] = true
			childResources = append(childResources, childRes...)
			outs = append(outs, objectOrEmpty(childOuts))
		}
		if value, ok := moduleOutputsValue(plan, outs); ok {
			if siblings != nil {
				siblings.set(call.label, value)
				continue
			}
			moduleOutputs[call.label] = value
			e.installSiblingModuleOutputs(ctx, evalCtx, scope, data, moduleOutputs)
		}
	}
	return childResources, moduleOutputs
}

// noteCycles warns, once per directory, about the cycles among the locals and
// the data blocks reading their own result, which evaluation reads as unknown.
func (e *Evaluator) noteCycles(ctx context.Context, dir string, locals *localGraph) {
	if len(locals.cycles) == 0 && len(locals.cyclicData) == 0 {
		return
	}
	if _, seen := e.cycleWarned.LoadOrStore(dir, true); seen {
		return
	}
	contextLogger := logger.FromContext(ctx)
	for _, cycle := range locals.cycles {
		contextLogger.Warn().Strs("locals", cycle).
			Msgf("tfeval: cycle among locals at %s; the locals are read as unknown", dir)
	}
	if len(locals.cyclicData) == 0 {
		return
	}
	names := make([]string, 0, len(locals.cyclicData))
	for b := range locals.cyclicData {
		names = append(names, terraform.DataKey(b.Labels[0], b.Labels[1]))
	}
	slices.Sort(names)
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

// installSiblingModuleOutputs publishes module.* for later siblings and
// refreshes locals and data that read those outputs.
func (e *Evaluator) installSiblingModuleOutputs(
	ctx context.Context,
	evalCtx *hcl.EvalContext,
	scope *ModuleScope,
	data *moduleData,
	moduleOutputs map[string]cty.Value,
) {
	e.installModuleOutputs(ctx, evalCtx, scope, data, moduleOutputs)
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
	scope *ModuleScope,
	evalCtx *hcl.EvalContext,
	data *moduleData,
	addr string,
	chain []CallSite,
) []ResolvedResource {
	var rootResources []ResolvedResource
	localsReadOwn := scope.localGraph.readsResources
	dataReadsOwn := data.readsOwnResources()
	// Resources may consume refreshed data through locals (data → local →
	// resource) without a direct data.* traversal in the body.
	readsOwn := scope.static.resourcesReadOwn || (dataReadsOwn && scope.static.resourcesReadData)
	for pass := 0; pass < resourceRefPasses; pass++ {
		rootResources = e.evalResourceBlocks(ctx, resourceBlocks, evalCtx, addr, chain)
		// Always inject so resolved attrs reach evalCtx on every pass including the last.
		changed := injectResourceRefs(evalCtx, rootResources)
		if !changed || !readsOwn {
			// Nothing the resource blocks or locals read has changed, so
			// evaluating them again would reproduce these instances.
			return rootResources
		}
		// Refresh locals after every successful injection so that locals referencing
		// newly-resolved resource attrs are up-to-date before outputs are computed.
		if localsReadOwn {
			evalCtx.Variables["local"] = e.resolveLocalsIncremental(scope, evalCtx, true, false)
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

// evalResourceBlocks evaluates resource blocks (count/for_each expanded when known).
func (e *Evaluator) evalResourceBlocks(
	ctx context.Context,
	resourceBlocks []*hclsyntax.Block,
	evalCtx *hcl.EvalContext,
	addr string,
	chain []CallSite,
) []ResolvedResource {
	resources := make([]ResolvedResource, 0, len(resourceBlocks))
	for _, rb := range resourceBlocks {
		resources = append(resources, e.expandBlock(ctx, rb, evalCtx, addr, chain, false)...)
	}
	return resources
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

	// Attributes that ignore each/count evaluate identically in every instance.
	memo := newInvariantMemo()

	makeOne := func(name string, child *hcl.EvalContext) ResolvedResource {
		// Only attribution of module resources and data evaluation read the
		// iteration, so the resource instances of the root module do not keep it.
		var iteration map[string]cty.Value
		if child != evalCtx && (addr != "" || data) {
			iteration = child.Variables
		}
		state := &bodyState{memo: memo, dynamic: &dynamicRecorder{}}
		attrs := e.evalBodyWith(ctx, rb.Body, child, nil, state)
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

	if out, ok := e.expandCountInstances(ctx, rb, resName, evalCtx, makeOne); ok {
		return out
	}
	if out, ok := e.expandForEachInstances(ctx, rb, resName, evalCtx, makeOne); ok {
		return out
	}
	return []ResolvedResource{makeOne(resName, evalCtx)}
}

func (e *Evaluator) expandCountInstances(
	ctx context.Context,
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
		// Grown with append, never sized from n: an uncapped count from an
		// untrusted repository must not allocate before the scan can stop.
		out := make([]ResolvedResource, 0)
		for i := 0; i < n; i++ {
			if ctx.Err() != nil {
				break
			}
			child := evalCtx.NewChild()
			child.Variables = map[string]cty.Value{
				"count": cty.ObjectVal(map[string]cty.Value{
					"index": cty.NumberIntVal(int64(i)),
				}),
			}
			out = append(out, makeOne(fmt.Sprintf("%s[%d]", resName, i), child))
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
	resName string,
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
	return e.expandKnownForEachResources(ctx, fv, resName, evalCtx, makeOne), true
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
	resName string,
	evalCtx *hcl.EvalContext,
	makeOne func(string, *hcl.EvalContext) ResolvedResource,
) []ResolvedResource {
	// Grown with append, never sized from the collection: an uncapped for_each
	// from an untrusted repository must not allocate before the scan can stop.
	out := make([]ResolvedResource, 0)
	for it := fv.ElementIterator(); it.Next(); {
		if ctx.Err() != nil {
			break
		}
		k, kv := it.Element()
		keyStr := "__"
		if s, ok := ctyutil.ConcreteString(k); ok {
			keyStr = s
		}
		out = append(out, makeForEachResource(resName, keyStr, k, kv, evalCtx, makeOne))
	}
	return out
}

func makeForEachResource(
	resName, keyStr string,
	key, value cty.Value,
	evalCtx *hcl.EvalContext,
	makeOne func(string, *hcl.EvalContext) ResolvedResource,
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
		b.attrs = append(b.attrs, referenceAttributes(r.Attributes))
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

// resolveLocalsIncremental resolves the module's locals into local.*, reusing
// what an earlier resolution of the same module evaluation produced for the
// locals that read nothing that changed since. A local is re-evaluated when
// it reads the module's resources and they were re-injected, when it reads
// module outputs and they changed, or when it reads data, which the data
// refresh re-resolves out of band; everything else is a pure function of the
// module inputs and the locals reused before it, so its value cannot have
// changed. The classification is transitive, so a local reading one that is
// re-evaluated is re-evaluated after it, once, in dependency order.
func (e *Evaluator) resolveLocalsIncremental(
	scope *ModuleScope,
	base *hcl.EvalContext,
	resourcesChanged, modulesChanged bool,
) cty.Value {
	g := scope.localGraph
	members := g.order
	if scope.localCache == nil {
		scope.localCache = make(map[string]cty.Value, len(g.names))
	} else {
		members = make([]int, 0, len(g.order))
		for _, v := range g.order {
			deps := g.deps[v]
			// Data-reading locals are never reused: the data refresh re-resolves
			// them out of band, so the cache may hold a value older than data.*.
			if deps.data || (resourcesChanged && deps.resources) || (modulesChanged && deps.modules) {
				members = append(members, v)
			}
		}
	}
	e.resolveLocals(g, base, scope.localCache, members)
	return objectOrEmpty(scope.localCache)
}

// evalBody evaluates an HCL body into the shape produced by the Terraform parser.
// It keeps dynamic blocks as written when their for_each does not resolve.
func (e *Evaluator) evalBody(
	ctx context.Context,
	body *hclsyntax.Body,
	evalCtx *hcl.EvalContext,
	skip map[string]bool,
) map[string]cty.Value {
	return e.evalBodyWith(ctx, body, evalCtx, skip, nil)
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
	ctx context.Context,
	body *hclsyntax.Body,
	evalCtx *hcl.EvalContext,
	skip map[string]bool,
	st *bodyState,
) map[string]cty.Value {
	out := make(map[string]cty.Value, len(body.Attributes)+len(body.Blocks))

	for name, attr := range body.Attributes {
		if skip[name] {
			continue
		}
		out[name] = e.evalExprMemo(attr.Expr, evalCtx, st)
	}

	blocks := nestedBlocks{out: out}
	for _, b := range body.Blocks {
		if ctx.Err() != nil {
			break
		}
		if st != nil && dynamicblock.Is(b) {
			e.addDynamicBlocks(ctx, &blocks, b, evalCtx, st)
			continue
		}
		path := append([]string{b.Type}, b.Labels...)
		blocks.add(path, objectOrEmpty(e.evalBodyWith(ctx, b.Body, evalCtx, nil, st)))
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
	// Preserve the object-length fast path before memo keys walk the inputs.
	v, ok := evalLength(expr, ctx)
	if !ok {
		v = e.memoizedValue(expr, ctx, e.evalExpr)
	}
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
	// The calls evaluated here are speculative; cache entries keep their own.
	instancesBefore := len(e.instances)
	defer func() {
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
		if ctx.Err() != nil {
			return out
		}
		call, ok := e.resolveModuleCall(ctx, mb, callCtx, dir, packageRoot)
		if !ok {
			continue
		}
		plan := moduleInstances(ctx, mb, callCtx)
		site := call.site(scope)
		outs := make([]cty.Value, 0, plan.Len())
		for i := range plan.Len() {
			if ctx.Err() != nil {
				break
			}
			instance := plan.At(i)
			modInputs := e.evalBody(ctx, mb.Body, instance.ctx, reservedModuleAttrs)
			childChain := append(cloneChain(chain), site)
			_, childOuts, err := e.evaluate(
				ctx, call.dir, rootDir, call.packageRoot, modInputs, instance.address(addr, call.label), childChain,
				depth+1, tmpVisiting, map[string]bool{},
			)
			if err == nil {
				outs = append(outs, objectOrEmpty(childOuts))
				continue
			}
			// The failure is the same for every instance of the call; the rest
			// of the outputs stay unknown.
			outs = append(outs, cty.NilVal)
			break
		}
		if value, ok := moduleOutputsValue(plan, outs); ok {
			out[call.label] = value
			stale = true
		}
	}
	return out
}
