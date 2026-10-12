/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"context"
	"slices"

	"github.com/DataDog/datadog-iac-scanner/pkg/ctyutil"
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

	// dataLocals are the locals reading data.*, directly or through other
	// locals: the only ones a change of data.* can change.
	dataLocals  map[string]bool
	readsData   bool
	readsLocals bool
	// readsResources is set when the blocks read the module's resources,
	// directly or through locals, so resource passes must refresh them.
	readsResources bool
	// readsModuleOutputs is set when the blocks read module.*, directly or
	// through locals.
	readsModuleOutputs bool

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
	localExprs map[string]hclsyntax.Expression,
	resourceTypes map[string]struct{},
	addr string,
	chain []CallSite,
) *moduleData {
	blocks := collectDataBlocks(bodies)
	if len(blocks) == 0 {
		return nil
	}
	d := &moduleData{
		e: e, blocks: blocks, sources: sources, localExprs: localExprs, addr: addr, chain: chain,
		dataLocals: localsReadingRoot(localExprs, dataRoot),
	}
	for _, b := range blocks {
		d.readsData = d.readsData || bodyReadsResource(b.Body, dataRoot)
		d.readsResources = d.readsResources || bodyReadsResource(b.Body, resourceTypes)
		d.readsLocals = d.readsLocals || bodyReadsResource(b.Body, localRoot)
	}
	if d.readsLocals && localsReadResources(localExprs, resourceTypes) {
		d.readsResources = true
	}
	for _, b := range blocks {
		d.readsModuleOutputs = d.readsModuleOutputs || bodyReadsResource(b.Body, moduleRoot)
	}
	if d.readsLocals && localsReadResources(localExprs, moduleRoot) {
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
	if root != "local" || len(traversal) < 2 {
		return false
	}
	attr, ok := traversal[1].(hcl.TraverseAttr)
	return ok && locals[attr.Name]
}

func (d *moduleData) readsOwnResources() bool {
	return d != nil && d.readsResources
}

// refresh re-evaluates the data blocks and installs data.*, refreshing the
// locals that read it when it changed. Blocks reading data, directly or
// through those locals, are re-evaluated until data.* settles.
func (d *moduleData) refresh(ctx context.Context, evalCtx *hcl.EvalContext) {
	if d == nil {
		return
	}
	chained := d.readsData || (d.readsLocals && len(d.dataLocals) > 0)
	for pass := 0; pass < resourceRefPasses; pass++ {
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
		expanded := d.e.expandBlock(ctx, b, evalCtx, d.addr, d.chain, true)
		for i := range expanded {
			inst := &expanded[i]
			view := *inst
			if source, ok := localdata.Lookup(inst.Type); ok {
				view.Attributes = d.withComputedAttributes(inst, b, evalCtx, source)
			}
			if d.addr == "" {
				inst.Iteration = nil
			}
			exposed = append(exposed, view)
		}
		instances = append(instances, expanded...)
	}
	d.instances = instances
	byType := &hcl.EvalContext{Variables: map[string]cty.Value{}}
	injectResourceRefs(byType, exposed)
	return cty.ObjectVal(byType.Variables)
}

// withComputedAttributes adds the attributes a data source computes from its
// configuration to inst's, rendering what does not resolve as text.
func (d *moduleData) withComputedAttributes(
	inst *ResolvedResource, b *hclsyntax.Block, evalCtx *hcl.EvalContext, source localdata.Source,
) map[string]cty.Value {
	ctx := evalCtx
	if inst.Iteration != nil {
		ctx = evalCtx.NewChild()
		ctx.Variables = inst.Iteration
	}
	rd := &partial.Renderer{Ctx: ctx, Source: partial.FileSources(d.sources)}
	var computed map[string]string
	if body, ok := d.jsonBodies[b]; ok {
		src := d.sources[b.TypeRange.Filename]
		computed = source(body, func(expr hcl.Expression) (cty.Value, bool) {
			return rd.Render(jsonExprToHCL(expr, src))
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
