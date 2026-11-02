/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package engine

import (
	"slices"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/address"
	tfinstances "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/instances"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfrefs"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// referenceTrace collects the instance addresses of the resource, data and
// ephemeral blocks an attribute reads, following locals, module inputs and
// module outputs.
type referenceTrace struct {
	frame *referenceFrame
	// suffix is the instance key of the reading instance, as in an address,
	// and forEach the for_each giving it its each value.
	suffix  string
	forEach hclsyntax.Expression
	// indexKey is the index applied to the traversal being read, as in
	// aws_subnet.s[count.index].
	indexKey hclsyntax.Expression
	// attribute is the attribute read after that index, as in
	// module.m[var.i].out.
	attribute string
	found     []string
	// untraced is set when part of what is read could not be followed.
	untraced bool
}

// referenceFrame is a module instance: its scope, its address and, below the
// root, the call block and instance key it was called with. partial marks a
// frame, or a frame called from one, whose callers are unknown.
type referenceFrame struct {
	scope         *tfeval.ModuleScope
	moduleAddress string
	call          *hclsyntax.Body
	callSuffix    string
	parent        *referenceFrame
	partial       bool
}

type referenceCacheKey struct {
	expr          hclsyntax.Expression
	scope         *tfeval.ModuleScope
	moduleAddress string
	suffix        string
	partial       bool
}

type traced struct {
	found    []string
	untraced bool
}

type referenceScope struct {
	scope         *tfeval.ModuleScope
	moduleAddress string
}

var referenceKinds = map[tfrefs.Kind]string{
	tfrefs.KindResource:  address.KindResource,
	tfrefs.KindData:      address.KindData,
	tfrefs.KindEphemeral: address.KindEphemeral,
}

// staticReferences returns r's references: its attributes and nested blocks
// mirrored, each leaf the sorted addresses of the instances it reads, or nil
// when nothing is read. An index that cannot be resolved reads every instance.
func staticReferences(r *tfeval.ResolvedResource, a *valueAnalyzer) map[string]interface{} {
	if r.Body == nil || r.Scope == nil {
		return nil
	}
	a.refs = &referenceTrace{frame: resourceFrame(r), suffix: r.Key.String(), forEach: forEachOf(r.Body)}
	defer func() { a.refs = nil }()
	return a.bodyReferences(r.Body)
}

// refIntern shares the leaves of the references metadata. The same addresses
// are read by every instance of a block and by every block of a repeated
// module, so without sharing each reader keeps its own copy of the same
// strings for the whole resolution. It is only used from the merge goroutine.
type refIntern struct {
	leaves map[string][]interface{}
	boxed  map[string]interface{}
	key    []byte
}

func newRefIntern() *refIntern {
	return &refIntern{leaves: map[string][]interface{}{}, boxed: map[string]interface{}{}}
}

// leaf returns the shared boxed form of addrs, which must be sorted and
// deduplicated.
func (i *refIntern) leaf(addrs []string) []interface{} {
	if i == nil {
		i = newRefIntern()
	}
	i.key = i.key[:0]
	for _, addr := range addrs {
		i.key = append(i.key, addr...)
		i.key = append(i.key, 0)
	}
	if leaf, ok := i.leaves[string(i.key)]; ok {
		return leaf
	}
	leaf := make([]interface{}, len(addrs))
	for n, addr := range addrs {
		box, ok := i.boxed[addr]
		if !ok {
			box = addr
			i.boxed[addr] = box
		}
		leaf[n] = box
	}
	i.leaves[string(i.key)] = leaf
	return leaf
}

// resourceReferences is r's staticReferences, read with one analyzer per
// module instance.
func (c *moduleAttributionCache) resourceReferences(r *tfeval.ResolvedResource) map[string]interface{} {
	key := referenceScope{scope: r.Scope, moduleAddress: r.ModuleAddress}
	a, ok := c.referenceAnalyzers[key]
	if !ok {
		a = c.analyzer(r.Scope, nil)
		c.referenceAnalyzers[key] = a
	}
	a.iteration, a.evalCtx = r.Iteration, nil
	return staticReferences(r, a)
}

func (a *valueAnalyzer) bodyReferences(body *hclsyntax.Body) map[string]interface{} {
	out := map[string]interface{}{}
	for name, attr := range body.Attributes {
		a.refs.found, a.refs.untraced = a.refs.found[:0], false
		a.reads(attr.Expr)
		if len(a.refs.found) > 0 && !a.refs.untraced {
			slices.Sort(a.refs.found)
			out[name] = a.cache.refs.leaf(slices.Compact(a.refs.found))
		}
	}
	var order []string
	nested := map[string][]interface{}{}
	traced := map[string]bool{}
	for _, block := range body.Blocks {
		name := block.Type
		var refs map[string]interface{}
		if block.Type == dynamicBlockType && len(block.Labels) > 0 {
			name = block.Labels[0]
			refs = a.dynamicReferences(block)
		} else {
			refs = a.bodyReferences(block.Body)
		}
		if _, seen := nested[name]; !seen {
			order = append(order, name)
		}
		if refs == nil {
			refs = map[string]interface{}{}
		} else {
			traced[name] = true
		}
		nested[name] = append(nested[name], refs)
	}
	for _, name := range order {
		if traced[name] {
			out[name] = nested[name]
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (a *valueAnalyzer) dynamicReferences(block *hclsyntax.Block) map[string]interface{} {
	name := block.Labels[0]
	if attr, ok := block.Body.Attributes[dynamicIterator]; ok {
		if traversal, diags := hcl.AbsTraversalForExpr(attr.Expr); !diags.HasErrors() {
			name = traversal.RootName()
		}
	}
	var out map[string]interface{}
	depth := len(a.iterators)
	a.iterators = append(a.iterators, iteratorReads{name: name})
	for _, content := range block.Body.Blocks {
		if content.Type == dynamicContentType {
			out = a.bodyReferences(content.Body)
		}
	}
	a.iterators = a.iterators[:depth]
	return out
}

func (t *referenceTrace) traversal(a *valueAnalyzer, root string, traversal hcl.Traversal) {
	switch root {
	case moduleVariableRoot:
		t.variable(a, traversal)
	case moduleLocalRoot:
		t.local(a, traversal)
	case moduleCallRoot:
		t.moduleOutput(a, traversal)
	case resourceEachRoot:
		if len(traversal) > 1 && stepString(traversal[1]) == eachValueStep {
			t.eachValue(a)
		}
	default:
		if !nonReferenceRoots[root] {
			t.record(a, traversal)
		}
	}
}

// record adds the instances traversal reads: the one a literal index, or the
// index applied to it, selects, or every instance of the block.
func (t *referenceTrace) record(a *valueAnalyzer, traversal hcl.Traversal) {
	indexKey := t.takeIndex()
	ref := tfrefs.Parse(traversal)
	kind, ok := referenceKinds[ref.Kind]
	if !ok || ref.Type == "" || ref.Name == "" {
		return
	}
	block := address.Block{Kind: kind, Type: ref.Type, Name: ref.Name}
	suffix := ""
	switch {
	case ref.Key != nil:
		suffix = address.InstanceSuffix(*ref.Key)
	case indexKey != nil && len(traversal) == nameEnd(kind):
		suffix = t.selectedSuffix(a, indexKey)
	}
	t.addInstances(a, t.frame.moduleAddress, block, suffix)
}

func nameEnd(kind string) int {
	if kind == address.KindResource {
		return 2
	}
	return 3
}

// addInstances adds the instance of block suffix selects in the module a
// analyzes, or every instance when suffix is empty or selects none.
func (t *referenceTrace) addInstances(a *valueAnalyzer, moduleAddress string, block address.Block, suffix string) {
	body := a.blockBody(address.Addr(block))
	if body == nil {
		return
	}
	count, forEach := tfinstances.Attributes(body)
	if count == nil && forEach == nil {
		t.add(moduleAddress, block, "")
		return
	}
	suffixes := a.cache.instancesOf(a, block, count, forEach).suffixes
	if suffixes == nil {
		t.add(moduleAddress, block, "")
		return
	}
	if suffix != "" {
		key := numericKey(suffix)
		if i := slices.IndexFunc(suffixes, func(s string) bool { return numericKey(s) == key }); i >= 0 {
			t.add(moduleAddress, block, suffixes[i])
			return
		}
	}
	for _, s := range suffixes {
		t.add(moduleAddress, block, s)
	}
}

type blockInstancesKey struct {
	scope *tfeval.ModuleScope
	block address.Block
}

// blockInstances are the instance keys of an expanding block, nil when its
// expansion is unresolved.
type blockInstances struct {
	suffixes []string
}

func (c *moduleAttributionCache) instancesOf(a *valueAnalyzer, block address.Block, count, forEach hcl.Expression) blockInstances {
	key := blockInstancesKey{scope: a.scope, block: block}
	if instances, ok := c.blockInstances[key]; ok {
		return instances
	}
	var instances blockInstances
	if plan := tfinstances.Resolve(count, forEach, c.analyzer(a.scope, nil).context()); !plan.Unresolved {
		instances.suffixes = make([]string, len(plan.Items))
		for i, item := range plan.Items {
			instances.suffixes[i] = address.InstanceSuffix(item.Key)
		}
	}
	c.blockInstances[key] = instances
	return instances
}

// numericKey reads ["1"] as [1]: Terraform converts between a number and a
// string of digits when indexing.
func numericKey(suffix string) string {
	digits := strings.TrimSuffix(strings.TrimPrefix(suffix, `["`), `"]`)
	if len(digits) == len(suffix)-4 && digits != "" && strings.Trim(digits, "0123456789") == "" {
		return "[" + digits + "]"
	}
	return suffix
}

// selectedSuffix is the instance an index selects: the reading instance's own
// key for count.index or each.key, or the index's evaluated value.
func (t *referenceTrace) selectedSuffix(a *valueAnalyzer, key hclsyntax.Expression) string {
	if scope, ok := key.(*hclsyntax.ScopeTraversalExpr); ok && t.suffix != "" && len(scope.Traversal) == 2 {
		switch root, step := scope.Traversal.RootName(), stepString(scope.Traversal[1]); {
		case root == "count" && step == "index", root == resourceEachRoot && step == eachKeyStep:
			return t.suffix
		}
	}
	if v, ok := a.value(key); ok && !v.IsNull() {
		return address.InstanceSuffix(v)
	}
	return ""
}

func (t *referenceTrace) add(moduleAddress string, block address.Block, suffix string) {
	t.found = append(t.found, address.Instance(moduleAddress, block, suffix))
}

// indexesReference reports whether an index applied to collection selects
// instances of the one block it reads.
func indexesReference(collection hclsyntax.Expression) bool {
	collection = withoutParentheses(collection)
	if splat, ok := collection.(*hclsyntax.SplatExpr); ok {
		collection = splat.Source
	}
	_, ok := collection.(*hclsyntax.ScopeTraversalExpr)
	return ok
}

func withoutParentheses(expr hclsyntax.Expression) hclsyntax.Expression {
	for {
		parens, ok := expr.(*hclsyntax.ParenthesesExpr)
		if !ok {
			return expr
		}
		expr = parens.Expression
	}
}

// indexedAttribute keeps the attribute e reads after an index on a
// reference, as in module.m[var.i].out.
func (t *referenceTrace) indexedAttribute(e *hclsyntax.RelativeTraversalExpr) {
	step, ok := firstStep(e.Traversal).(hcl.TraverseAttr)
	if !ok {
		return
	}
	if index, indexed := e.Source.(*hclsyntax.IndexExpr); indexed && indexesReference(index.Collection) {
		t.attribute = step.Name
	}
}

func (t *referenceTrace) takeIndex() hclsyntax.Expression {
	indexKey := t.indexKey
	t.indexKey, t.attribute = nil, ""
	return indexKey
}

// local adds what the local name reads.
func (t *referenceTrace) local(a *valueAnalyzer, traversal hcl.Traversal) {
	indexKey := t.takeIndex()
	expr, ok := t.frame.scope.Locals[stepName(traversal)]
	if !ok {
		t.untraced = true
		return
	}
	if !t.selectThrough(a, expr, traversal, indexKey, t.frame) {
		t.follow(a.cache.frameReferences(t.frame, expr, "", nil))
	}
}

func (t *referenceTrace) follow(r traced) {
	t.found = append(t.found, r.found...)
	t.untraced = t.untraced || r.untraced
}

// variable adds what the call argument setting the input reads in the
// calling module instance.
func (t *referenceTrace) variable(a *valueAnalyzer, traversal hcl.Traversal) {
	indexKey := t.takeIndex()
	f := t.frame
	name := stepName(traversal)
	if f.parent == nil || f.call == nil {
		t.untraced = t.untraced || f.partial || !knownInput(f.scope, name)
		return
	}
	arg, ok := f.call.Attributes[name]
	if !ok || t.selectThrough(a, arg.Expr, traversal, indexKey, f.parent) {
		return
	}
	t.follow(a.cache.frameReferences(f.parent, arg.Expr, f.callSuffix, forEachOf(f.call)))
}

// knownInput reports whether the module's input name evaluated to a known
// value, which a root input reads no block through.
func knownInput(scope *tfeval.ModuleScope, name string) bool {
	if name == "" || scope == nil || scope.Var == cty.NilVal || !scope.Var.Type().IsObjectType() ||
		!scope.Var.Type().HasAttribute(name) {
		return false
	}
	return scope.Var.GetAttr(name).IsWhollyKnown()
}

// selectThrough adds the one instance selected by an index applied to a
// local or input that holds every instance of a block, as local.ids[1] with
// ids = aws_subnet.s[*].id. It reports whether it did.
func (t *referenceTrace) selectThrough(
	a *valueAnalyzer, expr hclsyntax.Expression, traversal hcl.Traversal, indexKey hclsyntax.Expression, owner *referenceFrame,
) bool {
	suffix := ""
	switch {
	case len(traversal) == 2 && indexKey != nil:
		suffix = t.selectedSuffix(a, indexKey)
	case len(traversal) > 2:
		if step, ok := traversal[2].(hcl.TraverseIndex); ok {
			suffix = address.InstanceSuffix(step.Key)
		}
	}
	if suffix == "" {
		return false
	}
	block, ok := wholeBlock(expr)
	if !ok {
		return false
	}
	t.addInstances(a.cache.analyzer(owner.scope, nil), owner.moduleAddress, block, suffix)
	return true
}

// wholeBlock is the block expr holds every instance of, as aws_subnet.s or
// aws_subnet.s[*].id.
func wholeBlock(expr hclsyntax.Expression) (address.Block, bool) {
	expr = withoutParentheses(expr)
	if splat, ok := expr.(*hclsyntax.SplatExpr); ok {
		expr = splat.Source
	}
	scope, ok := expr.(*hclsyntax.ScopeTraversalExpr)
	if !ok {
		return address.Block{}, false
	}
	ref := tfrefs.Parse(scope.Traversal)
	kind, ok := referenceKinds[ref.Kind]
	if !ok || ref.Type == "" || ref.Name == "" || ref.Key != nil || len(scope.Traversal) != nameEnd(kind) {
		return address.Block{}, false
	}
	return address.Block{Kind: kind, Type: ref.Type, Name: ref.Name}, true
}

// eachValue adds what each.value reads: the reader's own instance of a block
// its for_each iterates, or what the for_each reads.
func (t *referenceTrace) eachValue(a *valueAnalyzer) {
	t.takeIndex()
	if t.forEach == nil {
		return
	}
	if block, ok := wholeBlock(t.forEach); ok && t.suffix != "" {
		t.addInstances(a.cache.analyzer(t.frame.scope, nil), t.frame.moduleAddress, block, t.suffix)
		return
	}
	t.follow(a.cache.frameReferences(t.frame, t.forEach, "", nil))
}

func forEachOf(body *hclsyntax.Body) hclsyntax.Expression {
	if body == nil {
		return nil
	}
	if attr, ok := body.Attributes[forEachAttribute]; ok {
		return attr.Expr
	}
	return nil
}

// moduleOutput adds every resource an output of the called module can reach,
// in the instance a literal index or the applied index selects, or in every
// instance of the call.
func (t *referenceTrace) moduleOutput(a *valueAnalyzer, traversal hcl.Traversal) {
	attribute := t.attribute
	indexKey := t.takeIndex()
	label := stepName(traversal)
	children := t.frame.scope.Children[label]
	if len(children) == 0 {
		t.untraced = true
		return
	}
	rest := traversal[2:]
	suffix := ""
	if step, ok := firstStep(rest).(hcl.TraverseIndex); ok {
		suffix = address.InstanceSuffix(step.Key)
		rest = rest[1:]
	} else if len(rest) == 0 && indexKey != nil {
		suffix = t.selectedSuffix(a, indexKey)
	}
	output := ""
	if step, ok := firstStep(rest).(hcl.TraverseAttr); ok {
		output = step.Name
	} else if len(rest) == 0 && indexKey != nil {
		output = attribute
	}
	selected := children
	if suffix != "" {
		if i := slices.IndexFunc(children, func(c tfeval.ChildScope) bool { return c.Suffix == suffix }); i >= 0 {
			selected = children[i : i+1]
		}
	}
	for _, child := range selected {
		if child.Scope == nil {
			t.untraced = true
			continue
		}
		f := &referenceFrame{
			scope:         child.Scope,
			moduleAddress: joinModuleAddress(t.frame.moduleAddress, "module."+label+child.Suffix),
			call:          child.Call,
			callSuffix:    child.Suffix,
			parent:        t.frame,
			partial:       t.frame.partial,
		}
		for name, expr := range child.Scope.Outputs {
			if output == "" || name == output {
				t.follow(a.cache.frameReferences(f, expr, "", nil))
			}
		}
	}
}

// frameReferences is what expr reads in the module instance f, read by an
// instance with key suffix and for_each forEach, which expr determines. A
// read that loops back to itself reads nothing further.
func (c *moduleAttributionCache) frameReferences(
	f *referenceFrame, expr hclsyntax.Expression, suffix string, forEach hclsyntax.Expression,
) traced {
	key := referenceCacheKey{expr: expr, scope: f.scope, moduleAddress: f.moduleAddress, suffix: suffix, partial: f.partial}
	if r, ok := c.references[key]; ok {
		return r
	}
	c.references[key] = traced{}
	a := c.analyzer(f.scope, nil)
	a.refs = &referenceTrace{frame: f, suffix: suffix, forEach: forEach}
	a.reads(expr)
	slices.Sort(a.refs.found)
	r := traced{found: slices.Clip(slices.Compact(a.refs.found)), untraced: a.refs.untraced}
	c.references[key] = r
	return r
}

func joinModuleAddress(parent, segment string) string {
	if parent == "" {
		return segment
	}
	return parent + "." + segment
}

// resourceFrame is the module instance declaring r, linked to its callers
// up to the root.
func resourceFrame(r *tfeval.ResolvedResource) *referenceFrame {
	segments := moduleSegments(r.ModuleAddress)
	if len(segments) != len(r.CallChain) {
		return &referenceFrame{scope: r.Scope, moduleAddress: r.ModuleAddress, partial: r.ModuleAddress != ""}
	}
	var frame *referenceFrame
	for i := 0; i <= len(r.CallChain); i++ {
		next := &referenceFrame{scope: r.Scope, parent: frame}
		if i < len(r.CallChain) {
			next.scope = r.CallChain[i].Caller
		}
		if i > 0 {
			next.moduleAddress = r.ModuleAddress[:segments[i-1].end]
			next.call = r.CallChain[i-1].Body
			next.callSuffix = segments[i-1].suffix
		}
		frame = next
	}
	return frame
}

// moduleSegment is one module.<label><key> step of a module address: where it
// ends in the address and its instance key.
type moduleSegment struct {
	end    int
	suffix string
}

func moduleSegments(addr string) []moduleSegment {
	const prefix = "module."
	var out []moduleSegment
	for i := 0; i < len(addr); {
		if i > 0 {
			if addr[i] != '.' {
				return nil
			}
			i++
		}
		if !strings.HasPrefix(addr[i:], prefix) {
			return nil
		}
		i += len(prefix)
		for i < len(addr) && addr[i] != '.' && addr[i] != '[' {
			i++
		}
		start := i
		if i < len(addr) && addr[i] == '[' {
			i = keyEnd(addr, i)
		}
		out = append(out, moduleSegment{end: i, suffix: addr[start:i]})
	}
	return out
}

// keyEnd is the index just past the bracketed key opening at addr[i].
func keyEnd(addr string, i int) int {
	inString := false
	for ; i < len(addr); i++ {
		switch c := addr[i]; {
		case inString && c == '\\':
			i++
		case c == '"':
			inString = !inString
		case !inString && c == ']':
			return i + 1
		}
	}
	return i
}
