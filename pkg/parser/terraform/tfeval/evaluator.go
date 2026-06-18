/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package tfeval evaluates local Terraform modules by binding caller inputs to
// module variables, resolving locals, recursing into nested modules, and
// returning a flat list of resources with concrete attribute values.
// Unresolvable references (data sources, cross-resource refs, etc.) are left
// as cty.UnknownVal rather than sentinel strings.
package tfeval

import (
	"context"
	"path/filepath"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	tffunctions "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/functions"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

const (
	// defaultMaxDepth bounds nested-module recursion to protect against
	// pathological or cyclic local module graphs.
	defaultMaxDepth = 15
	// localsMaxPasses bounds the fixed-point iteration used to resolve locals
	// that reference one another.
	localsMaxPasses = 10
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
}

func New() *Evaluator {
	return &Evaluator{
		funcs:    tffunctions.TerraformFuncs,
		maxDepth: defaultMaxDepth,
	}
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
	visiting[dir] = true
	defer delete(visiting, dir)

	bodies, err := parseDir(dir)
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

	// Pre-pass: collect sibling module outputs so they are available in evalCtx
	// when computing inputs in the main loop. Terraform allows module inputs to
	// reference outputs of sibling modules regardless of block order; without
	// this pass those references always resolve to unknown.
	if len(moduleBlocks) > 1 {
		prelimOutputs := e.preliminaryModuleOutputs(ctx, moduleBlocks, evalCtx, dir, addr, depth, visiting)
		if len(prelimOutputs) > 0 {
			evalCtx.Variables["module"] = cty.ObjectVal(prelimOutputs)
			localVals = e.resolveLocals(localExprs, evalCtx)
			evalCtx.Variables["local"] = objectOrEmpty(localVals)
		}
	}

	var childResources []ResolvedResource
	moduleOutputs := map[string]cty.Value{}

	for _, mb := range moduleBlocks {
		label := blockLabel(mb)
		if label == "" {
			continue
		}
		source := knownString(mb.Body.Attributes["source"], evalCtx)
		if source == "" || !tfmodules.LooksLikeLocalModuleSource(StripGetterPrefix(source)) {
			continue // remote/registry sources are out of scope
		}

		childDir := resolveLocalDir(dir, source)

		// Skip module instances that are explicitly disabled.
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
	}

	if len(moduleOutputs) > 0 {
		// Re-evaluate locals now that module.* outputs are available.
		evalCtx.Variables["module"] = cty.ObjectVal(moduleOutputs)
		localVals = e.resolveLocals(localExprs, evalCtx)
		evalCtx.Variables["local"] = objectOrEmpty(localVals)
	}

	resources := make([]ResolvedResource, 0, len(resourceBlocks)+len(childResources))
	resources = append(resources, e.evalResourceBlocks(resourceBlocks, evalCtx, addr, chain)...)
	resources = append(resources, childResources...)

	outputs := make(map[string]cty.Value, len(outputExprs))
	for name, expr := range outputExprs {
		outputs[name] = e.evalExpr(expr, evalCtx)
	}

	return resources, outputs, nil
}

// evalResourceBlocks evaluates all resource blocks in the current module scope.
func (e *Evaluator) evalResourceBlocks(
	resourceBlocks []*hclsyntax.Block,
	evalCtx *hcl.EvalContext,
	addr string,
	chain []CallSite,
) []ResolvedResource {
	resources := make([]ResolvedResource, 0, len(resourceBlocks))
	for _, rb := range resourceBlocks {
		if len(rb.Labels) < 2 {
			continue
		}
		// Skip resources with count = 0 or for_each = {}; Terraform creates no instances.
		if isLiteralZero(rb.Body.Attributes["count"], evalCtx) {
			continue
		}
		if isEmptyCollection(rb.Body.Attributes["for_each"], evalCtx) {
			continue
		}
		resources = append(resources, ResolvedResource{
			Type:          rb.Labels[0],
			Name:          rb.Labels[1],
			Attributes:    e.evalBody(rb.Body, evalCtx, nil),
			DefinedIn:     rb.TypeRange.Filename,
			DefLine:       rb.TypeRange.Start.Line,
			ModuleAddress: addr,
			CallChain:     cloneChain(chain),
		})
	}
	return resources
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

// preliminaryModuleOutputs runs a lightweight first pass over local module
// blocks to collect their outputs. The results are installed into evalCtx
// before the real evaluation loop so sibling module references (e.g.
// module.a.out used as an input to module.b) resolve to known values.
//
// Uses a throw-away allVisited map so the main pass records accurate visited
// dirs. The visiting set is copied to preserve cycle detection.
func (e *Evaluator) preliminaryModuleOutputs(
	ctx context.Context,
	moduleBlocks []*hclsyntax.Block,
	evalCtx *hcl.EvalContext,
	dir, addr string,
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
		if source == "" || !tfmodules.LooksLikeLocalModuleSource(StripGetterPrefix(source)) {
			continue
		}
		if isLiteralZero(mb.Body.Attributes["count"], evalCtx) {
			continue
		}
		if isEmptyCollection(mb.Body.Attributes["for_each"], evalCtx) {
			continue
		}
		childDir := resolveLocalDir(dir, source)
		modInputs := e.evalBody(mb.Body, evalCtx, reservedModuleAttrs)
		childAddr := joinAddr(addr, "module."+label)
		_, childOuts, _ := e.evaluate(ctx, childDir, modInputs, childAddr, nil, depth+1, tmpVisiting, map[string]bool{})
		if len(childOuts) > 0 {
			out[label] = objectOrEmpty(childOuts)
		}
	}
	return out
}
