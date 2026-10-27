/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"context"

	"github.com/DataDog/datadog-iac-scanner/pkg/ctyutil"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform"
	tfinstances "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/instances"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// moduleCall is a module block whose source resolved to a directory.
type moduleCall struct {
	block                  *hclsyntax.Block
	label, source, version string
	dir, packageRoot       string
}

func (e *Evaluator) resolveModuleCall(
	ctx context.Context, mb *hclsyntax.Block, evalCtx *hcl.EvalContext, callerDir, packageRoot string,
) (moduleCall, bool) {
	label := blockLabel(mb)
	if label == "" {
		return moduleCall{}, false
	}
	source := ctyutil.StringFromAttribute(mb.Body.Attributes["source"], evalCtx)
	if source == "" {
		return moduleCall{}, false
	}
	version := ctyutil.StringFromAttribute(mb.Body.Attributes["version"], evalCtx)
	dir, childPackageRoot, ok := e.resolveModuleDir(
		ctx, callerDir, packageRoot, source, version, mb.TypeRange.Filename, label,
	)
	if !ok {
		return moduleCall{}, false
	}
	return moduleCall{
		block: mb, label: label, source: source, version: version, dir: dir, packageRoot: childPackageRoot,
	}, true
}

func (c *moduleCall) site(scope *ModuleScope) CallSite {
	return CallSite{
		ModuleName:      c.label,
		Source:          c.source,
		Version:         c.version,
		CalledFrom:      c.block.TypeRange.Filename,
		CalledLine:      c.block.TypeRange.Start.Line,
		CalledEndLine:   c.block.Range().End.Line,
		CalledColumn:    c.block.TypeRange.Start.Column,
		CalledEndColumn: c.block.Range().End.Column,
		Body:            c.block.Body,
		Caller:          scope,
	}
}

// moduleExpansion is how a module call's count or for_each expanded.
type moduleExpansion int

const (
	expansionNone moduleExpansion = iota
	expansionCount
	expansionForEach
	// expansionUnknown is a count or for_each that could not be resolved; the
	// call is evaluated once with an unknown count.index or each.
	expansionUnknown
)

// moduleInstance is one instance of a module call: the key Terraform addresses
// it by and the context its arguments are evaluated in.
type moduleInstance struct {
	key cty.Value
	ctx *hcl.EvalContext
}

func (i moduleInstance) address(parent, label string) string {
	seg := "module." + label
	if i.key != cty.NilVal {
		if formatted, ok := ctyutil.FormatIndexKey(i.key); ok {
			seg += formatted
		}
	}
	return joinAddr(parent, seg)
}

// moduleExpansionPlan is the result of expanding a module call's count/for_each.
type moduleExpansionPlan struct {
	instances []moduleInstance
	mode      moduleExpansion
	// requested is the full instance count when known (before the per-block cap).
	requested int
	// forEachKeys is every for_each key when mode is for_each and the collection
	// is within maxExpansionShape (including keys beyond the expansion cap).
	forEachKeys []cty.Value
}

func (p moduleExpansionPlan) truncated() bool {
	return p.requested > maxCountExpansion && (p.mode == expansionCount || p.mode == expansionForEach)
}

// moduleInstances expands a module call's count or for_each under ctx.
func moduleInstances(mb *hclsyntax.Block, ctx *hcl.EvalContext) moduleExpansionPlan {
	count, forEach := tfinstances.Attributes(mb.Body)
	plan := tfinstances.Resolve(count, forEach, ctx, maxExpansionShape)
	return modulePlan(&plan, ctx)
}

// modulePlan adds caller contexts and the module-specific unresolved fallback.
// Expansion decisions and iteration bindings come from the shared resolver;
// output padding and instantiation budgets remain owned by the evaluator.
func modulePlan(plan *tfinstances.Plan, ctx *hcl.EvalContext) moduleExpansionPlan {
	if plan.Kind == "" {
		return moduleExpansionPlan{
			instances: []moduleInstance{{ctx: ctx}},
			mode:      expansionNone,
			requested: 1,
		}
	}
	if plan.Unresolved {
		return moduleExpansionPlan{
			instances: []moduleInstance{{ctx: instanceContext(ctx, plan, tfinstances.Item{})}},
			mode:      expansionUnknown,
		}
	}
	mode := expansionForEach
	if plan.Kind == tfinstances.KindCount {
		mode = expansionCount
	}
	expanded := make([]moduleInstance, len(plan.Items))
	for i, item := range plan.Items {
		expanded[i] = moduleInstance{key: item.Key, ctx: instanceContext(ctx, plan, item)}
	}
	return moduleExpansionPlan{
		instances:   expanded,
		mode:        mode,
		requested:   plan.Requested,
		forEachKeys: plan.ForEachKeys,
	}
}

func instanceContext(ctx *hcl.EvalContext, plan *tfinstances.Plan, item tfinstances.Item) *hcl.EvalContext {
	name, value := plan.Variable(item)
	child := ctx.NewChild()
	child.Variables = map[string]cty.Value{name: value}
	return child
}

func isForEachCollection(v cty.Value) bool { return tfinstances.ForEachCollection(v) }

// moduleOutputsValue is what module.<label> evaluates to in the caller: the
// outputs object of a single call, a tuple of them for count and an object of
// them keyed like for_each. outs holds cty.NilVal for instances that failed.
// When the expansion was truncated, the returned collection keeps the full
// requested shape with unknown values for instances that were not evaluated,
// unless the shape would exceed maxExpansionShape (then the whole value is unknown).
func moduleOutputsValue(plan moduleExpansionPlan, outs []cty.Value) (cty.Value, bool) {
	switch plan.mode {
	case expansionUnknown:
		return cty.DynamicVal, true
	case expansionCount:
		return truncatedCountOutputs(plan.requested, outs), true
	case expansionForEach:
		return truncatedForEachOutputs(plan, outs), true
	}
	if len(outs) == 1 && outs[0] != cty.NilVal {
		return outs[0], true
	}
	return cty.NilVal, false
}

func truncatedCountOutputs(requested int, outs []cty.Value) cty.Value {
	if requested == 0 {
		return cty.EmptyTupleVal
	}
	if requested > maxExpansionShape {
		return cty.DynamicVal
	}
	elems := make([]cty.Value, requested)
	for i := range elems {
		if i < len(outs) {
			elems[i] = orUnknown(outs[i])
		} else {
			elems[i] = cty.DynamicVal
		}
	}
	return cty.TupleVal(elems)
}

func truncatedForEachOutputs(plan moduleExpansionPlan, outs []cty.Value) cty.Value {
	if plan.requested == 0 {
		return cty.EmptyObjectVal
	}
	if plan.requested > maxExpansionShape {
		return cty.DynamicVal
	}
	byKey := make(map[string]cty.Value, plan.requested)
	switch {
	case len(plan.forEachKeys) == plan.requested:
		// Truncated (or fully keyed) shape: start with unknown for every key.
		for _, key := range plan.forEachKeys {
			s, _ := ctyutil.ConcreteString(key)
			byKey[s] = cty.DynamicVal
		}
	case plan.truncated():
		// Truncated but keys were not kept — do not publish a short object.
		return cty.DynamicVal
	}
	for i, out := range outs {
		if i >= len(plan.instances) {
			break
		}
		key, _ := ctyutil.ConcreteString(plan.instances[i].key)
		byKey[key] = orUnknown(out)
	}
	return objectOrEmpty(byKey)
}

func orUnknown(v cty.Value) cty.Value {
	if v == cty.NilVal {
		return cty.DynamicVal
	}
	return v
}

// siblingReads is what a module call reads that the calls evaluated before
// it can change: module outputs by call name, and locals by name.
type siblingReads struct {
	modules []string
	locals  []string
	// wholeModule is a read of module.* other than by a static call name.
	wholeModule bool
	// opaque is a read whose value cannot be narrowed to named outputs and
	// locals: module.* or local.* as a whole, or data.*.
	opaque bool
}

func callSiblingReads(moduleBlocks []*hclsyntax.Block) []siblingReads {
	out := make([]siblingReads, len(moduleBlocks))
	for i, mb := range moduleBlocks {
		out[i].addBody(mb.Body)
	}
	return out
}

func (r *siblingReads) addBody(body *hclsyntax.Body) {
	for _, attr := range body.Attributes {
		for _, traversal := range attr.Expr.Variables() {
			r.add(traversal)
		}
	}
	for _, block := range body.Blocks {
		r.addBody(block.Body)
	}
}

func (r *siblingReads) add(traversal hcl.Traversal) {
	switch traversal.RootName() {
	case blockTypeModule:
		if name, ok := staticAttributeName(traversal); ok {
			r.modules = append(r.modules, name)
			return
		}
		r.wholeModule, r.opaque = true, true
	case "local":
		if name, ok := terraform.LocalTraversalName(traversal); ok {
			r.locals = append(r.locals, name)
			return
		}
		r.opaque = true
	case blockTypeData:
		r.opaque = true
	}
}

// staticAttributeName is the attribute a traversal's first step names, as
// LocalTraversalName reads it for local.
func staticAttributeName(traversal hcl.Traversal) (string, bool) {
	if len(traversal) < 2 {
		return "", false
	}
	switch step := traversal[1].(type) {
	case hcl.TraverseAttr:
		return step.Name, true
	case hcl.TraverseIndex:
		if step.Key.IsKnown() && !step.Key.IsNull() && step.Key.Type() == cty.String {
			return step.Key.AsString(), true
		}
	}
	return "", false
}

// namedObject is the object of the values the names select, leaving out the
// names values has none for, as the whole object would have them missing.
func namedObject(values map[string]cty.Value, names []string) cty.Value {
	attrs := make(map[string]cty.Value, len(names))
	for _, name := range names {
		if v, ok := values[name]; ok {
			attrs[name] = v
		}
	}
	return cty.ObjectVal(attrs)
}

// siblingOutputs gives each module call of a module the module.* and local.*
// values it would see if the outputs of every call evaluated before it were
// published, without publishing them after every call. Publishing rebuilds
// the whole module.* object and re-resolves every local reading it, so doing
// it after each of S calls reading an earlier call made the calls cost S^2.
// A call reading only named outputs and locals gets a context holding just
// those, computed the way publishing would compute them; any other read
// publishes first. The caller publishes the complete outputs once all calls
// are evaluated. It is only used when the data blocks do not read module
// outputs, so publishing never refreshes data and data.* stays as it is.
type siblingOutputs struct {
	e          *Evaluator
	ctx        context.Context
	evalCtx    *hcl.EvalContext
	scope      *ModuleScope
	localExprs map[string]hclsyntax.Expression
	data       *moduleData
	outputs    map[string]cty.Value
	// stale is set when outputs changed since evalCtx last published them.
	stale bool
}

func (s *siblingOutputs) set(label string, value cty.Value) {
	s.outputs[label] = value
	s.stale = true
}

func (s *siblingOutputs) publish() *hcl.EvalContext {
	if s.stale {
		s.e.installModuleOutputs(s.ctx, s.evalCtx, s.scope, s.localExprs, s.data, s.outputs)
		s.stale = false
	}
	return s.evalCtx
}

// contextFor returns the context to evaluate a call reading r in.
func (s *siblingOutputs) contextFor(r *siblingReads) *hcl.EvalContext {
	if !s.stale {
		return s.evalCtx
	}
	if r.opaque || s.scope == nil || s.scope.localDeps == nil {
		return s.publish()
	}
	following, ok := s.followingLocals(r.locals)
	if !ok {
		return s.publish()
	}
	if len(r.modules) == 0 && len(following) == 0 {
		// Nothing the call reads changes when the outputs are published.
		return s.evalCtx
	}
	modules := make(map[string]cty.Value, len(r.modules))
	s.addOutputs(modules, r.modules)
	exprs, fixed, ok := s.localsFollowing(following, modules)
	if !ok {
		return s.publish()
	}
	child := s.evalCtx.NewChild()
	child.Variables = map[string]cty.Value{blockTypeModule: cty.ObjectVal(modules)}
	if len(r.locals) == 0 {
		return child
	}
	child.Variables["local"] = s.localsObject(r.locals, exprs, fixed, child)
	return child
}

// followingLocals returns the named locals following module outputs. It fails
// for a local it does not know or one reading data, which publishing would
// re-resolve against data.*.
func (s *siblingOutputs) followingLocals(names []string) ([]string, bool) {
	var following []string
	for _, name := range names {
		deps, ok := s.scope.localDeps[name]
		if !ok || deps.data {
			return nil, false
		}
		if deps.modules {
			following = append(following, name)
		}
	}
	return following, true
}

// localsObject is the object of the named locals as publishing would leave
// them: it re-resolves the locals following module outputs, exprs here, and
// keeps the others at their last value, as fixed does.
func (s *siblingOutputs) localsObject(
	names []string, exprs map[string]hclsyntax.Expression, fixed map[string]cty.Value, ctx *hcl.EvalContext,
) cty.Value {
	values := s.scope.localCache
	if len(exprs) > 0 {
		values = s.e.resolveLocalsWith(exprs, ctx, fixed)
		for _, name := range names {
			if _, ok := values[name]; !ok {
				values[name] = s.scope.localCache[name]
			}
		}
	}
	return namedObject(values, names)
}

// addOutputs adds the outputs of the named calls to modules, leaving out the
// calls with none, as the whole module.* object would have them missing.
func (s *siblingOutputs) addOutputs(modules map[string]cty.Value, names []string) {
	for _, name := range names {
		if v, ok := s.outputs[name]; ok {
			modules[name] = v
		}
	}
}

// localsFollowing returns the locals following module outputs that the named
// ones read, themselves included, and the values of the other locals they
// read. It adds the module outputs they read to modules, and fails when one
// reads something it cannot narrow.
func (s *siblingOutputs) localsFollowing(
	names []string, modules map[string]cty.Value,
) (exprs map[string]hclsyntax.Expression, fixed map[string]cty.Value, ok bool) {
	exprs = make(map[string]hclsyntax.Expression, len(names))
	fixed = map[string]cty.Value{}
	queue := append([]string(nil), names...)
	for len(queue) > 0 {
		name := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if _, seen := exprs[name]; seen {
			continue
		}
		expr, known := s.localExprs[name]
		if !known {
			return nil, nil, false
		}
		exprs[name] = expr
		for _, traversal := range expr.Variables() {
			var r siblingReads
			r.add(traversal)
			if r.opaque {
				return nil, nil, false
			}
			s.addOutputs(modules, r.modules)
			for _, l := range r.locals {
				deps, known := s.scope.localDeps[l]
				switch {
				case !known || deps.data:
					return nil, nil, false
				case deps.modules:
					queue = append(queue, l)
				default:
					fixed[l] = s.scope.localCache[l]
				}
			}
		}
	}
	return exprs, fixed, true
}
