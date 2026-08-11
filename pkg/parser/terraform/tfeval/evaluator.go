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
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	tffunctions "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/functions"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"

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
)

// ResolvedResource is a resource block after evaluation with attributes
// resolved to concrete cty values where possible, unknown otherwise.
type ResolvedResource struct {
	Type       string
	Name       string
	Attributes map[string]cty.Value

	// Source location and module address for finding attribution.
	DefinedIn     string
	DefLine       int
	ModuleAddress string // "" for root module resources
	CallChain     []CallSite
}

// CallSite records one hop in a module call chain.
type CallSite struct {
	ModuleName string
	Source     string
	CalledFrom string
	CalledLine int
}

// Evaluator evaluates local Terraform modules.
type Evaluator struct {
	funcs    map[string]function.Function
	maxDepth int
	// cache memoizes completed module evaluations keyed by (dir, addr, canonical-inputs).
	// A single Evaluator is used for an entire scan, so the cache is shared across root
	// module calls — entries with the same key represent the same module called with the
	// same resolved inputs from the same structural position in the module tree.
	cache map[evalCacheKey]*evalCacheEntry
	// When set, non-local module sources resolve here and recurse with caller inputs.
	remoteResolver RemoteResolver

	parseMu  sync.Mutex
	dirCache map[string]dirParse
}

type dirParse struct {
	bodies []*hclsyntax.Body
	err    error
}

func New() *Evaluator {
	return &Evaluator{
		funcs:    tffunctions.TerraformFuncs,
		maxDepth: defaultMaxDepth,
		cache:    make(map[evalCacheKey]*evalCacheEntry),
		dirCache: make(map[string]dirParse),
	}
}

func (e *Evaluator) parseDir(dir string) ([]*hclsyntax.Body, error) {
	key := filepath.Clean(dir)

	e.parseMu.Lock()
	if dp, ok := e.dirCache[key]; ok {
		e.parseMu.Unlock()
		return dp.bodies, dp.err
	}
	e.parseMu.Unlock()

	bodies, err := parseDir(dir)

	e.parseMu.Lock()
	e.dirCache[key] = dirParse{bodies: bodies, err: err}
	e.parseMu.Unlock()
	return bodies, err
}

func (e *Evaluator) SetRemoteResolver(r RemoteResolver) {
	e.remoteResolver = r
}

func (e *Evaluator) ReleaseCaches() {
	e.parseMu.Lock()
	e.cache = nil
	e.dirCache = nil
	e.parseMu.Unlock()
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
	abs, absErr := filepath.Abs(dir)
	if absErr != nil {
		contextLogger := logger.FromContext(ctx)
		contextLogger.Warn().Err(absErr).Msgf("tfeval: filepath.Abs failed for %s, falling back to Clean", dir)
		abs = filepath.Clean(dir)
	}
	visiting := map[string]bool{}
	allVisited := map[string]bool{}
	resources, outputs, err = e.evaluate(ctx, abs, inputs, "", nil, 0, visiting, allVisited)
	return resources, outputs, allVisited, err
}

// evaluate is the recursive worker; visiting tracks dirs on the current stack for cycle
// detection; allVisited accumulates every child dir successfully evaluated as a module.
func (e *Evaluator) evaluate(
	ctx context.Context,
	dir string,
	inputs map[string]cty.Value,
	addr string,
	chain []CallSite,
	depth int,
	visiting map[string]bool,
	allVisited map[string]bool,
) ([]ResolvedResource, map[string]cty.Value, error) {
	contextLogger := logger.FromContext(ctx)

	if depth > e.maxDepth {
		contextLogger.Warn().Msgf("tfeval: max module depth %d exceeded at %s", e.maxDepth, dir)
		return nil, map[string]cty.Value{}, nil
	}
	if visiting[dir] {
		contextLogger.Warn().Msgf("tfeval: module cycle detected at %s, stopping recursion", dir)
		return nil, map[string]cty.Value{}, nil
	}

	// Pre-pass and main loop share (dir, addr, inputs, chain); distinct callers differ in chain only.
	cacheKey := evalCacheKey{dir: dir, addr: addr, inputs: canonicalInputsKey(inputs), chain: chainKey(chain)}
	if entry, ok := e.cache[cacheKey]; ok {
		for _, d := range entry.visitedDirs {
			allVisited[d] = true
		}
		return entry.resources, entry.outputs, nil
	}

	visiting[dir] = true
	defer delete(visiting, dir)

	// Snapshot allVisited so we can determine which dirs this subtree adds.
	prevAllVisited := make(map[string]bool, len(allVisited))
	for k := range allVisited {
		prevAllVisited[k] = true
	}

	bodies, err := e.parseDir(dir)
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

	localVals := e.resolveLocals(localExprs, evalCtx)
	evalCtx.Variables["local"] = objectOrEmpty(localVals)

	// Pre-inject sibling resource attrs so module inputs that reference them
	// (e.g. module "x" { val = aws_resource.y.attr }) resolve on first evaluation.
	if len(resourceBlocks) > 0 && len(moduleBlocks) > 0 {
		earlyRes := e.evalResourceBlocks(resourceBlocks, evalCtx, addr, chain)
		injectResourceRefs(evalCtx, earlyRes)
		localVals = e.resolveLocals(localExprs, evalCtx)
		evalCtx.Variables["local"] = objectOrEmpty(localVals)
	}

	e.applySiblingModulePrepass(ctx, moduleBlocks, evalCtx, localExprs, dir, addr, chain, depth, visiting)

	childResources, moduleOutputs := e.evaluateLocalModuleBlocks(
		ctx, moduleBlocks, evalCtx, dir, addr, chain, depth, visiting, allVisited,
	)

	if len(moduleOutputs) > 0 {
		evalCtx.Variables["module"] = cty.ObjectVal(moduleOutputs)
		localVals = e.resolveLocals(localExprs, evalCtx)
		evalCtx.Variables["local"] = objectOrEmpty(localVals)
	}

	rootResources := e.rootResourcesWithRefPasses(resourceBlocks, localExprs, evalCtx, addr, chain)

	// Re-inject the final-pass resource values so that outputs and locals that
	// reference the Nth hop of an N-hop chain can resolve. For chains shorter
	// than resourceRefPasses hops all resources were already injected inside the
	// loop, so injectResourceRefs returns false and the locals refresh is skipped.
	if injectResourceRefs(evalCtx, rootResources) {
		localVals = e.resolveLocals(localExprs, evalCtx)
		evalCtx.Variables["local"] = objectOrEmpty(localVals)
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
	e.cache[cacheKey] = &evalCacheEntry{
		resources:   resources,
		outputs:     outputs,
		visitedDirs: visitedDirs,
	}

	return resources, outputs, nil
}

func (e *Evaluator) applySiblingModulePrepass(
	ctx context.Context,
	moduleBlocks []*hclsyntax.Block,
	evalCtx *hcl.EvalContext,
	localExprs map[string]hclsyntax.Expression,
	dir, addr string,
	chain []CallSite,
	depth int,
	visiting map[string]bool,
) {
	if len(moduleBlocks) <= 1 {
		return
	}
	prelimOutputs := e.preliminaryModuleOutputs(ctx, moduleBlocks, evalCtx, dir, addr, chain, depth, visiting)
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
	dir, addr string,
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
		childDir, ok := e.resolveModuleDir(dir, source, version, mb.TypeRange.Filename, label)
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
			ModuleName: label,
			Source:     source,
			CalledFrom: mb.TypeRange.Filename,
			CalledLine: mb.TypeRange.Start.Line,
		}
		childAddr := joinAddr(addr, "module."+label)

		childRes, childOuts, cErr := e.evaluate(
			ctx, childDir, modInputs, childAddr, append(cloneChain(chain), site), depth+1, visiting, allVisited,
		)
		if cErr != nil {
			contextLogger.Warn().Msgf("tfeval: failed to evaluate module %q at %s: %v", label, childDir, cErr)
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

func (e *Evaluator) resolveModuleDir(callerDir, source, version, callerFile, moduleName string) (dir string, ok bool) {
	cleanSource := StripGetterPrefix(source)
	if tfmodules.LooksLikeLocalModuleSource(cleanSource) {
		return resolveLocalDir(callerDir, source), true
	}
	if e.remoteResolver != nil {
		d, resolved := e.remoteResolver(source, version, callerFile, moduleName)
		return d, resolved
	}
	return "", false
}

func (e *Evaluator) rootResourcesWithRefPasses(
	resourceBlocks []*hclsyntax.Block,
	localExprs map[string]hclsyntax.Expression,
	evalCtx *hcl.EvalContext,
	addr string,
	chain []CallSite,
) []ResolvedResource {
	var rootResources []ResolvedResource
	for pass := 0; pass < resourceRefPasses; pass++ {
		rootResources = e.evalResourceBlocks(resourceBlocks, evalCtx, addr, chain)
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
	return e.evalResourceBlocks(resourceBlocks, evalCtx, addr, chain)
}

// evalResourceBlocks evaluates resource blocks (count/for_each expanded when known).
func (e *Evaluator) evalResourceBlocks(
	resourceBlocks []*hclsyntax.Block,
	evalCtx *hcl.EvalContext,
	addr string,
	chain []CallSite,
) []ResolvedResource {
	resources := make([]ResolvedResource, 0, len(resourceBlocks))
	for _, rb := range resourceBlocks {
		resources = append(resources, e.expandResourceBlock(rb, evalCtx, addr, chain)...)
	}
	return resources
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
			DefinedIn:     rb.TypeRange.Filename,
			DefLine:       rb.TypeRange.Start.Line,
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
				out = append(out, makeOne(fmt.Sprintf("%s[%q]", resName, keyStr), child))
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
	for _, r := range resources {
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

// evalBody evaluates an HCL body into an attribute map. Attributes in skip are
// omitted. Nested blocks of the same type are always encoded as tuples (including
// a single block) so the shape matches the canonical Terraform parser output rules expect.
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

	grouped := map[string][]cty.Value{}
	order := make([]string, 0, len(body.Blocks))
	for _, b := range body.Blocks {
		if _, seen := grouped[b.Type]; !seen {
			order = append(order, b.Type)
		}
		grouped[b.Type] = append(grouped[b.Type], objectOrEmpty(e.evalBody(b.Body, ctx, nil)))
	}
	for _, t := range order {
		list := grouped[t]
		out[t] = cty.TupleVal(list)
	}
	return out
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
	dir, addr string,
	chain []CallSite,
	depth int,
	visiting map[string]bool,
) map[string]cty.Value {
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
		childDir, ok := e.resolveModuleDir(dir, source, version, mb.TypeRange.Filename, label)
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
			ModuleName: label,
			Source:     source,
			CalledFrom: mb.TypeRange.Filename,
			CalledLine: mb.TypeRange.Start.Line,
		}
		childAddr := joinAddr(addr, "module."+label)
		childChain := append(cloneChain(chain), site)
		_, childOuts, _ := e.evaluate(ctx, childDir, modInputs, childAddr, childChain, depth+1, tmpVisiting, map[string]bool{})
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
