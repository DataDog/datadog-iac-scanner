/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"context"
	"slices"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/ctyutil"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/localdata"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/partial"
	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	hcljson "github.com/hashicorp/hcl/v2/json"
	"github.com/zclconf/go-cty/cty"
)

const blockTypeData = "data"

var dataRoot = map[string]struct{}{blockTypeData: {}}

func collectDataBlocks(bodies []*hclsyntax.Body) []*hclsyntax.Block {
	var blocks []*hclsyntax.Block
	for _, body := range bodies {
		for _, block := range body.Blocks {
			if block.Type == blockTypeData && len(block.Labels) >= 2 {
				blocks = append(blocks, block)
			}
		}
	}
	return blocks
}

// moduleData evaluates a module's data blocks. Their instances become
// documents like resources do, and data.* exposes their arguments plus the
// attributes localdata computes for data sources whose result follows from
// their configuration alone.
type moduleData struct {
	e          *Evaluator
	blocks     []*hclsyntax.Block
	sources    map[string][]byte
	localExprs map[string]hclsyntax.Expression
	addr       string
	chain      []CallSite

	// dataLocals are the locals reading data.*, directly or through other locals.
	dataLocals  map[string]bool
	readsData   bool
	readsLocals bool
	// readsResources is set when the blocks read the module's resources,
	// directly or through locals, so resource passes must refresh them.
	readsResources bool
	// readsModuleOutputs is set when the blocks read module.*, directly or
	// through locals.
	readsModuleOutputs bool

	// evalCache memoizes each data block's last evaluation against the context
	// inputs it read, so a refresh pass with unchanged inputs reuses it.
	evalCache map[*hclsyntax.Block]blockEvalCache

	// moduleAtRefresh is the module.* value the data blocks were last refreshed
	// against; republishing it need not refresh the data again.
	moduleAtRefresh cty.Value

	// jsonBodies holds the native JSON body of each locally computed data
	// block declared in a JSON configuration file. Converted to native syntax
	// without a schema, its nested blocks read as attributes.
	jsonBodies map[*hclsyntax.Block]hcl.Body

	instances []ResolvedResource
}

func newModuleData(
	e *Evaluator,
	bodies []*hclsyntax.Body,
	sources map[string][]byte,
	scope *ModuleScope,
	resourceTypes map[string]struct{},
	addr string,
	chain []CallSite,
) *moduleData {
	blocks := collectDataBlocks(bodies)
	if len(blocks) == 0 {
		return nil
	}
	d := &moduleData{
		e: e, blocks: blocks, sources: sources, localExprs: scope.Locals, addr: addr, chain: chain,
		dataLocals: scope.dataLocals(),
	}
	for _, b := range blocks {
		d.readsData = d.readsData || bodyReadsResource(b.Body, dataRoot)
		d.readsResources = d.readsResources || bodyReadsResource(b.Body, resourceTypes)
		d.readsLocals = d.readsLocals || bodyReadsResource(b.Body, localRoot)
	}
	if d.readsLocals && localsReadResources(scope.Locals, resourceTypes) {
		d.readsResources = true
	}
	for _, b := range blocks {
		d.readsModuleOutputs = d.readsModuleOutputs || bodyReadsResource(b.Body, moduleRoot)
	}
	if d.readsLocals && localsReadResources(scope.Locals, moduleRoot) {
		d.readsModuleOutputs = true
	}
	d.jsonBodies = jsonLocalDataBodies(blocks, sources)
	return d
}

func jsonLocalDataBodies(blocks []*hclsyntax.Block, sources map[string][]byte) map[*hclsyntax.Block]hcl.Body {
	var out map[*hclsyntax.Block]hcl.Body
	parsed := map[string][]*hcl.Block{}
	for _, b := range blocks {
		filename := b.TypeRange.Filename
		if _, ok := localdata.Lookup(b.Labels[0]); !ok || !tfpath.IsJSONConfig(filename) {
			continue
		}
		native, ok := parsed[filename]
		if !ok {
			native = jsonDataBlocks(sources[filename], filename)
			parsed[filename] = native
		}
		for _, nb := range native {
			if slices.Equal(nb.Labels, b.Labels) {
				if out == nil {
					out = map[*hclsyntax.Block]hcl.Body{}
				}
				out[b] = nb.Body
				break
			}
		}
	}
	return out
}

func jsonDataBlocks(src []byte, filename string) []*hcl.Block {
	file, diags := hcljson.Parse(src, filename)
	if diags.HasErrors() {
		return nil
	}
	content, _, _ := file.Body.PartialContent(jsonConfigSchema)
	if content == nil {
		return nil
	}
	var out []*hcl.Block
	for _, block := range content.Blocks {
		if block.Type == blockTypeData {
			out = append(out, block)
		}
	}
	return out
}

var (
	localRoot  = map[string]struct{}{"local": {}}
	moduleRoot = map[string]struct{}{blockTypeModule: {}}
)

func (d *moduleData) readsModules() bool {
	return d != nil && d.readsModuleOutputs
}

// refreshedWithModule reports whether the data blocks were already refreshed
// against the given module.* value.
func (d *moduleData) refreshedWithModule(value cty.Value) bool {
	return d != nil && !d.moduleAtRefresh.IsNull() && d.moduleAtRefresh.RawEquals(value)
}

// localsReadingRoot returns the locals reading roots, directly or through
// other locals.
func localsReadingRoot(localExprs map[string]hclsyntax.Expression, roots map[string]struct{}) map[string]bool {
	reading := map[string]bool{}
	for changed := true; changed; {
		changed = false
		for name, expr := range localExprs {
			if reading[name] {
				continue
			}
			for _, traversal := range expr.Variables() {
				if readsRootOrLocal(traversal, roots, reading) {
					reading[name] = true
					changed = true
					break
				}
			}
		}
	}
	return reading
}

func readsRootOrLocal(traversal hcl.Traversal, roots map[string]struct{}, locals map[string]bool) bool {
	root := traversal.RootName()
	if _, ok := roots[root]; ok {
		return true
	}
	name, ok := terraform.LocalTraversalName(traversal)
	return ok && locals[name]
}

func (d *moduleData) readsOwnResources() bool {
	return d != nil && d.readsResources
}

// refresh re-evaluates the data blocks and installs data.*, refreshing the
// locals that read it when it changed, until data.* settles. The pass bound
// matches a source_policy_documents chain as long as the blocks and the locals
// aliasing them, as getDataSourcePolicy does at the root.
func (d *moduleData) refresh(ctx context.Context, evalCtx *hcl.EvalContext) {
	if d == nil {
		return
	}
	defer func() { d.moduleAtRefresh = evalCtx.Variables[blockTypeModule] }()
	chained := d.readsData || (d.readsLocals && len(d.dataLocals) > 0)
	bound := len(d.blocks) + len(d.dataLocals)
	if bound < 1 {
		bound = 1
	}
	for pass := 0; pass <= bound; pass++ {
		value := d.evaluate(ctx, evalCtx)
		if existing, ok := evalCtx.Variables[blockTypeData]; ok && existing.RawEquals(value) {
			break
		}
		evalCtx.Variables[blockTypeData] = value
		if len(d.dataLocals) > 0 {
			d.refreshDataLocals(evalCtx)
		}
		if !chained {
			break
		}
	}
}

// refreshDataLocals re-resolves the locals reading data.*, keeping the others:
// they may read files or other costly function results.
func (d *moduleData) refreshDataLocals(evalCtx *hcl.EvalContext) {
	fixed := map[string]cty.Value{}
	if current, ok := evalCtx.Variables["local"]; ok && ctyutil.Materialized(current) && current.Type().IsObjectType() {
		for name, v := range current.AsValueMap() {
			if !d.dataLocals[name] {
				fixed[name] = v
			}
		}
	}
	evalCtx.Variables["local"] = objectOrEmpty(d.e.resolveLocalsWith(d.localExprs, evalCtx, fixed))
}

func (d *moduleData) evaluate(ctx context.Context, evalCtx *hcl.EvalContext) cty.Value {
	instances := make([]ResolvedResource, 0, len(d.blocks))
	exposed := make([]ResolvedResource, 0, len(d.blocks))
	for _, b := range d.blocks {
		inputs := blockEvalInputs(b, evalCtx)
		cached, ok := d.evalCache[b]
		if !ok || !sameCtyValues(cached.inputs, inputs) {
			cached = d.evalBlock(ctx, b, evalCtx, inputs)
		}
		instances = append(instances, cached.instances...)
		exposed = append(exposed, cached.exposed...)
	}
	d.instances = instances
	byType := &hcl.EvalContext{Variables: map[string]cty.Value{}}
	injectResourceRefs(byType, exposed, emptyExpansions(d.blocks, evalCtx))
	return objectOrEmpty(byType.Variables)
}

// blockEvalCache is a data block's last evaluation: the context variables it
// read and the instances that evaluation produced.
type blockEvalCache struct {
	inputs    map[string]cty.Value
	instances []ResolvedResource
	// exposed are the instances as data.* exposes them, with the attributes
	// localdata computes added and, at the root module, the iteration dropped.
	exposed []ResolvedResource
}

// evalBlock evaluates one data block and memoizes the result against the
// context inputs it read: unchanged inputs reproduce the same result.
func (d *moduleData) evalBlock(
	ctx context.Context, b *hclsyntax.Block, evalCtx *hcl.EvalContext, inputs map[string]cty.Value,
) blockEvalCache {
	cached := blockEvalCache{inputs: inputs}
	d.e.dataBlockEvals++
	// An expansion stopped by cancellation is partial; the evaluation fails as
	// a whole once it checks, so nothing partial is kept.
	expanded, _ := d.e.expandBlock(ctx, b, evalCtx, d.addr, d.chain, true, nil)
	for i := range expanded {
		inst := &expanded[i]
		view := *inst
		if source, ok := localdata.Lookup(inst.Type); ok {
			view.Attributes = d.withComputedAttributes(inst, b, evalCtx, source)
		}
		if d.addr == "" {
			inst.Iteration = nil
		}
		cached.instances = append(cached.instances, *inst)
		cached.exposed = append(cached.exposed, view)
	}
	if d.evalCache == nil {
		d.evalCache = make(map[*hclsyntax.Block]blockEvalCache)
	}
	d.evalCache[b] = cached
	return cached
}

// blockEvalInputs snapshots the context variables the block's traversals name.
// References to data, local, var and module are tracked per name, so a block
// is only invalidated when what it reads changes; ambiguous references fall
// back to the whole root object.
func blockEvalInputs(b *hclsyntax.Block, evalCtx *hcl.EvalContext) map[string]cty.Value {
	roots := map[string]struct{}{}
	refs := rootRefs{}
	bodyTraversalRoots(b.Body, roots, &refs)
	inputs := make(map[string]cty.Value, len(roots)+len(refs.named))
	for root := range roots {
		if _, sliced := sliceableRoots[root]; sliced && !refs.whole[root] {
			continue // tracked below, per reference
		}
		if v, ok := evalCtx.Variables[root]; ok {
			inputs[root] = v
		}
	}
	for key, ref := range refs.named {
		root, ok := evalCtx.Variables[ref.root]
		if !ok || !slicableObject(root) {
			// The root object is not published yet; its appearance must
			// invalidate the block.
			inputs[key] = cty.NullVal(cty.DynamicPseudoType)
			continue
		}
		inputs[key] = rootSliceValue(root, ref.path)
	}
	return inputs
}

// sliceableRoots maps roots whose references are tracked per name to the
// deepest path worth snapshotting: data.<type>.<name>, local.<name>, var.<name>,
// and module.<label>.<output>.
var sliceableRoots = map[string]int{
	blockTypeData:   2,
	"local":         1,
	"var":           1,
	blockTypeModule: 2,
}

// slicableObject reports whether value can be read per named attribute: a
// known, non-null object.
func slicableObject(value cty.Value) bool {
	return value.IsKnown() && !value.IsNull() && value.Type().IsObjectType()
}

// rootSliceValue reads the current <root>.<path…> value, or a null when any
// level is missing: the missing level's appearance must invalidate the block.
func rootSliceValue(root cty.Value, path []string) cty.Value {
	value := root
	for _, step := range path {
		if !slicableObject(value) || !value.Type().HasAttribute(step) {
			return cty.NullVal(cty.DynamicPseudoType)
		}
		value = value.GetAttr(step)
	}
	return value
}

// rootRef is one pinned reference: the root object it reads and the attribute
// path under it.
type rootRef struct {
	root string
	path []string
}

// rootRefs classifies a block's traversals into the sliceable roots: named
// maps each root-qualified key to the reference it reads; whole marks a root
// referenced ambiguously (bare root, splat, dynamic key, non-name index) and
// tracked whole.
type rootRefs struct {
	named map[string]rootRef
	whole map[string]bool
}

func (r *rootRefs) note(traversal hcl.Traversal) {
	root := traversal.RootName()
	depth, ok := sliceableRoots[root]
	if !ok {
		return
	}
	if len(traversal) < 2 {
		r.markWhole(root)
		return
	}
	path := make([]string, 0, min(len(traversal)-1, depth))
	for i := 1; i < len(traversal) && len(path) < depth; i++ {
		step, ok := refStepName(traversal[i])
		if !ok {
			r.markWhole(root)
			return
		}
		path = append(path, step)
	}
	if r.named == nil {
		r.named = map[string]rootRef{}
	}
	r.named[root+"."+strings.Join(path, ".")] = rootRef{root: root, path: path}
}

func (r *rootRefs) markWhole(root string) {
	if r.whole == nil {
		r.whole = map[string]bool{}
	}
	r.whole[root] = true
}

// refStepName reads one reference step: an attribute or a constant string
// index naming an attribute. Dots are excluded so the input keys stay
// unambiguous.
func refStepName(step hcl.Traverser) (string, bool) {
	switch s := step.(type) {
	case hcl.TraverseAttr:
		return s.Name, true
	case hcl.TraverseIndex:
		if key, ok := ctyutil.ConcreteString(s.Key); ok && key != "" && !strings.ContainsAny(key, ".\x00") {
			return key, true
		}
	}
	return "", false
}

func bodyTraversalRoots(body *hclsyntax.Body, roots map[string]struct{}, refs *rootRefs) {
	for _, attr := range body.Attributes {
		for _, traversal := range attr.Expr.Variables() {
			roots[traversal.RootName()] = struct{}{}
			refs.note(traversal)
		}
	}
	for _, block := range body.Blocks {
		bodyTraversalRoots(block.Body, roots, refs)
	}
}

// sameCtyValues reports whether two snapshots hold equal values under equal
// key sets.
func sameCtyValues(a, b map[string]cty.Value) bool {
	if len(a) != len(b) {
		return false
	}
	for name, v := range a {
		w, ok := b[name]
		if !ok || !v.RawEquals(w) {
			return false
		}
	}
	return true
}

// withComputedAttributes adds the attributes a data source computes from its
// configuration to inst's, rendering what does not resolve as text.
func (d *moduleData) withComputedAttributes(
	inst *ResolvedResource, b *hclsyntax.Block, evalCtx *hcl.EvalContext, source localdata.Source,
) map[string]cty.Value {
	ctx := evalCtx
	if inst.Iteration != nil {
		ctx = evalCtx.NewChild()
		ctx.Variables = inst.Iteration.Variables()
	}
	rd := &partial.Renderer{Ctx: ctx, Source: partial.FileSources(d.sources)}
	var computed map[string]string
	if body, ok := d.jsonBodies[b]; ok {
		src := d.sources[b.TypeRange.Filename]
		computed = source(body, func(expr hcl.Expression) (cty.Value, bool) {
			return renderJSON(rd, expr, src)
		})
	} else {
		computed = source(b.Body, rd.Render)
	}
	attrs := make(map[string]cty.Value, len(inst.Attributes)+len(computed))
	for k, v := range inst.Attributes {
		attrs[k] = v
	}
	for k, v := range computed {
		attrs[k] = cty.StringVal(v)
	}
	return attrs
}

// renderJSON renders a JSON configuration expression, in the scope of the
// variables it was bound to when read inside a dynamic block.
func renderJSON(rd *partial.Renderer, expr hcl.Expression, src []byte) (cty.Value, bool) {
	if inner, vars, ok := partial.Unbind(expr); ok {
		scoped := &partial.Renderer{Ctx: partial.Scope(rd.Ctx, vars), Source: rd.Source}
		return renderJSON(scoped, inner, src)
	}
	return rd.Render(jsonExprToHCL(expr, src))
}

// resolved returns the data instances of the module's final evaluation.
func (d *moduleData) resolved(scope *ModuleScope) []ResolvedResource {
	if d == nil {
		return nil
	}
	for i := range d.instances {
		d.instances[i].Scope = scope
	}
	return d.instances
}
