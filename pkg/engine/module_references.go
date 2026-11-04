/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package engine

import (
	"math/big"
	"slices"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/address"
	tfinstances "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/instances"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/metaargs"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfrefs"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
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
	// ambiguous is set when found over-approximates what is read: a choice
	// or an index that could not be resolved listed every alternative.
	ambiguous bool
	// dynamic is how many blocks each dynamic block of the resource
	// generated, so its references line up with its blocks.
	dynamic tfeval.DynamicCounts
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
	found     []string
	untraced  bool
	ambiguous bool
}

type referenceScope struct {
	scope         *tfeval.ModuleScope
	moduleAddress string
	iteration     string
}

var referenceKinds = map[tfrefs.Kind]string{
	tfrefs.KindResource:  address.KindResource,
	tfrefs.KindData:      address.KindData,
	tfrefs.KindEphemeral: address.KindEphemeral,
}

// staticReferences returns r's references: its attributes and nested blocks
// mirrored, each leaf the sorted addresses of the instances it reads, empty
// when it reads none, and absent when what it reads could not be traced. An
// index that cannot be resolved reads every instance. ambiguous mirrors the
// references with a true leaf where the addresses over-approximate the read.
func staticReferences(r *tfeval.ResolvedResource, a *valueAnalyzer) (refs, ambiguous map[string]interface{}) {
	if r.Body == nil || r.Scope == nil {
		return nil, nil
	}
	a.refs = &referenceTrace{
		frame: resourceFrame(r), suffix: r.Key.String(), forEach: forEachOf(r.Body), dynamic: r.DynamicCounts,
	}
	defer func() { a.refs = nil }()
	refs, ambiguous = a.bodyReferences(r.Body)
	for name := range refs {
		if metaargs.Is(name) {
			delete(refs, name)
			delete(ambiguous, name)
		}
	}
	return refs, nilIfEmpty(ambiguous)
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
// module instance and root iteration bindings (count/each), matching
// resourceAttributes so expanded roots keep each.value and count.index.
func (c *moduleAttributionCache) resourceReferences(r *tfeval.ResolvedResource) (refs, ambiguous map[string]interface{}) {
	key := referenceScope{scope: r.Scope, moduleAddress: r.ModuleAddress, iteration: iterationKey(r.Iteration)}
	a, ok := c.referenceAnalyzers[key]
	if !ok {
		a = c.analyzer(r.Scope, r.Iteration)
		c.referenceAnalyzers[key] = a
	}
	a.iteration, a.evalCtx = r.Iteration, nil
	return staticReferences(r, a)
}

func (a *valueAnalyzer) bodyReferences(body *hclsyntax.Body) (refs, ambiguous map[string]interface{}) {
	refs, ambiguous = a.attributeReferences(body)
	nestedRefs := map[string][]interface{}{}
	nestedAmbiguous := map[string][]interface{}{}
	traced, ambiguousBlocks, misaligned := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, block := range body.Blocks {
		if metaargs.Hidden(block.Type) {
			continue
		}
		name, instances, varies, blockRefs, blockAmbiguous := a.nestedBlockReferences(block)
		if varies {
			misaligned[name] = true
		}
		if instances == 0 {
			continue
		}
		if blockRefs == nil {
			blockRefs = map[string]interface{}{}
		} else {
			traced[name] = true
		}
		if blockAmbiguous == nil {
			blockAmbiguous = map[string]interface{}{}
		} else {
			ambiguousBlocks[name] = true
		}
		for range instances {
			nestedRefs[name] = append(nestedRefs[name], blockRefs)
			nestedAmbiguous[name] = append(nestedAmbiguous[name], blockAmbiguous)
		}
	}
	for name := range nestedRefs {
		if misaligned[name] {
			continue
		}
		if traced[name] {
			refs[name] = nestedRefs[name]
		}
		if ambiguousBlocks[name] {
			ambiguous[name] = nestedAmbiguous[name]
		}
	}
	// An empty references object is kept: the body was read and nothing in it
	// traced, which is different from a body that was never analyzed.
	return refs, nilIfEmpty(ambiguous)
}

// attributeReferences is the references of body's attributes, and which of
// them over-approximate what is read.
func (a *valueAnalyzer) attributeReferences(body *hclsyntax.Body) (refs, ambiguous map[string]interface{}) {
	refs, ambiguous = map[string]interface{}{}, map[string]interface{}{}
	for name, attr := range body.Attributes {
		a.refs.found, a.refs.untraced, a.refs.ambiguous = a.refs.found[:0], false, false
		a.reads(attr.Expr)
		if a.refs.untraced {
			continue
		}
		slices.Sort(a.refs.found)
		a.refs.found = slices.Compact(a.refs.found)
		refs[name] = a.cache.refs.leaf(a.refs.found)
		if a.refs.ambiguous && len(a.refs.found) > 0 {
			ambiguous[name] = true
		}
	}
	return refs, ambiguous
}

// nestedBlockReferences is the references of a nested block, the name it is
// held under and how many blocks it stands for: one, or as many as a dynamic
// block generated, none when it was kept as written. varies is set when a
// dynamic block generated a different number of blocks per instance of its
// parent, so its entries cannot line up with the blocks.
func (a *valueAnalyzer) nestedBlockReferences(
	block *hclsyntax.Block,
) (name string, instances int, varies bool, refs, ambiguous map[string]interface{}) {
	if block.Type != dynamicBlockType || len(block.Labels) == 0 {
		refs, ambiguous = a.bodyReferences(block.Body)
		return block.Type, 1, false, refs, ambiguous
	}
	n, known := a.refs.dynamic.Generated(block)
	if !known {
		n = 0
	}
	refs, ambiguous = a.dynamicReferences(block)
	return block.Labels[0], n, a.refs.dynamic.Varies(block), refs, ambiguous
}

func nilIfEmpty(m map[string]interface{}) map[string]interface{} {
	if len(m) == 0 {
		return nil
	}
	return m
}

func (a *valueAnalyzer) dynamicReferences(block *hclsyntax.Block) (refs, ambiguous map[string]interface{}) {
	name := block.Labels[0]
	if attr, ok := block.Body.Attributes[dynamicIterator]; ok {
		if traversal, diags := hcl.AbsTraversalForExpr(attr.Expr); !diags.HasErrors() {
			name = traversal.RootName()
		}
	}
	depth := len(a.iterators)
	a.iterators = append(a.iterators, iteratorReads{name: name, collection: forEachOf(block.Body)})
	for _, content := range block.Body.Blocks {
		if content.Type == dynamicContentType {
			refs, ambiguous = a.bodyReferences(content.Body)
		}
	}
	a.iterators = a.iterators[:depth]
	return refs, ambiguous
}

// markIfSeveral marks the trace ambiguous when what was found from start on
// names more than one instance: the read selects one of them.
func (t *referenceTrace) markIfSeveral(start int) {
	if start > len(t.found) {
		return
	}
	first := ""
	for _, addr := range t.found[start:] {
		if first == "" {
			first = addr
		} else if addr != first {
			t.ambiguous = true
			return
		}
	}
}

// foundSince returns the sorted, duplicate-free addresses found from start on.
func (t *referenceTrace) foundSince(start int) []string {
	if start > len(t.found) {
		return nil
	}
	out := slices.Clone(t.found[start:])
	slices.Sort(out)
	return slices.Compact(out)
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
		if t.readDynamicIterator(a, root, traversal) {
			return
		}
		if !nonReferenceRoots[root] {
			t.record(a, traversal)
		}
	}
}

// readDynamicIterator follows a dynamic block iterator's for_each when
// traversal is <iterator>.value. The collection may hold several addresses,
// so the read is ambiguous when they differ.
func (t *referenceTrace) readDynamicIterator(a *valueAnalyzer, root string, traversal hcl.Traversal) bool {
	if a == nil || len(traversal) < 2 || stepString(traversal[1]) != eachValueStep {
		return false
	}
	for i := len(a.iterators) - 1; i >= 0; i-- {
		it := a.iterators[i]
		if it.name != root || it.collection == nil {
			continue
		}
		start := len(t.found)
		t.follow(a.cache.frameReferences(t.frame, it.collection, "", nil))
		t.markIfSeveral(start)
		return true
	}
	return false
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
	suffix, indexed := "", false
	switch {
	case ref.Key != nil:
		suffix, indexed = address.InstanceSuffix(*ref.Key), true
	case indexKey != nil && len(traversal) == nameEnd(kind):
		suffix, indexed = t.selectedSuffix(a, indexKey), true
	}
	t.addInstances(a, t.frame.moduleAddress, block, suffix, indexed)
}

func nameEnd(kind string) int {
	if kind == address.KindResource {
		return 2
	}
	return 3
}

// addInstances adds the instance of block suffix selects in the module a
// analyzes, or every instance when suffix is empty or selects none. indexed
// says the read selects one instance, so listing several is ambiguous.
func (t *referenceTrace) addInstances(a *valueAnalyzer, moduleAddress string, block address.Block, suffix string, indexed bool) {
	body := a.blockBody(address.Addr(block))
	if body == nil {
		// A block the module does not declare (or this scan did not load)
		// cannot be traced; recording nothing would read as "references none".
		t.untraced = true
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
	if indexed && len(suffixes) > 1 {
		t.ambiguous = true
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
	if v, ok := t.selectedKey(a, key); ok {
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
	held := heldValue{expr: expr, owner: t.frame}
	if !t.selectThrough(a, held, traversal, indexKey) {
		t.followSelected(held.read(a.cache, expr), traversal, indexKey)
	}
}

func (t *referenceTrace) follow(r traced) {
	t.found = append(t.found, r.found...)
	t.untraced = t.untraced || r.untraced
	t.ambiguous = t.ambiguous || r.ambiguous
}

// followSelected follows the whole of a local or input from which the
// traversal, or the index applied to it, selects a part: listing more than
// one instance then over-approximates the read.
func (t *referenceTrace) followSelected(r traced, traversal hcl.Traversal, indexKey hclsyntax.Expression) {
	start := len(t.found)
	t.follow(r)
	if len(traversal) > 2 || indexKey != nil {
		t.markIfSeveral(start)
	}
}

// variable adds what the call argument setting the input reads in the
// calling module instance. A root input reads no block of the root, known
// or not; it is untraced only when the callers are unknown.
func (t *referenceTrace) variable(a *valueAnalyzer, traversal hcl.Traversal) {
	indexKey := t.takeIndex()
	f := t.frame
	name := stepName(traversal)
	if f.parent == nil || f.call == nil {
		t.untraced = t.untraced || f.partial
		return
	}
	arg, ok := f.call.Attributes[name]
	if !ok {
		return
	}
	held := heldValue{expr: arg.Expr, owner: f.parent, suffix: f.callSuffix, forEach: forEachOf(f.call)}
	if !t.selectThrough(a, held, traversal, indexKey) {
		t.followSelected(held.read(a.cache, arg.Expr), traversal, indexKey)
	}
}

// heldValue is the expression a local or an input holds, with the module
// instance it is read in and, for an input, the call's instance key and
// for_each.
type heldValue struct {
	expr    hclsyntax.Expression
	owner   *referenceFrame
	suffix  string
	forEach hclsyntax.Expression
}

func (h heldValue) read(c *moduleAttributionCache, expr hclsyntax.Expression) traced {
	return c.frameReferences(h.owner, expr, h.suffix, h.forEach)
}

// selectThrough adds what one selected part of a local or input reads: the
// one instance an index selects from a value holding every instance of a
// block, as local.ids[1] with ids = aws_subnet.s[*].id, or the one item a key
// selects from an object or tuple constructor, as local.by_name["a"]. It
// reports whether it did.
func (t *referenceTrace) selectThrough(
	a *valueAnalyzer, held heldValue, traversal hcl.Traversal, indexKey hclsyntax.Expression,
) bool {
	var key cty.Value
	switch {
	case len(traversal) == 2 && indexKey != nil:
		if v, ok := t.selectedKey(a, indexKey); ok {
			key = v
		}
	case len(traversal) > 2:
		switch step := traversal[2].(type) {
		case hcl.TraverseIndex:
			key = step.Key
		case hcl.TraverseAttr:
			key = cty.StringVal(step.Name)
		}
	}
	if key == cty.NilVal {
		return false
	}
	ownerAnalyzer := a.cache.analyzer(held.owner.scope, nil)
	if item, ok := constructorItem(ownerAnalyzer, held.expr, key); ok {
		// local.nested.x.selected keeps following the remaining steps.
		// Stopping at the first key would read every address in that item.
		if len(traversal) > 3 {
			nested := held
			nested.expr = item
			rest := make(hcl.Traversal, 2, len(traversal)-1)
			rest[0], rest[1] = traversal[0], traversal[1]
			rest = append(rest, traversal[3:]...)
			if t.selectThrough(a, nested, rest, nil) {
				return true
			}
		}
		t.follow(held.read(a.cache, item))
		return true
	}
	block, ok := wholeBlock(held.expr)
	if !ok {
		return false
	}
	if len(traversal) > 2 {
		if _, isIndex := traversal[2].(hcl.TraverseIndex); !isIndex {
			return false
		}
	}
	t.addInstances(ownerAnalyzer, held.owner.moduleAddress, block, address.InstanceSuffix(key), true)
	return true
}

// selectedKey is the key an index selects: the reading instance's own key for
// count.index or each.key, or the index's evaluated value.
func (t *referenceTrace) selectedKey(a *valueAnalyzer, key hclsyntax.Expression) (cty.Value, bool) {
	if scope, ok := key.(*hclsyntax.ScopeTraversalExpr); ok && t.suffix != "" && len(scope.Traversal) == 2 {
		switch root, step := scope.Traversal.RootName(), stepString(scope.Traversal[1]); {
		case root == "count" && step == "index", root == resourceEachRoot && step == eachKeyStep:
			return instanceKeyValue(t.suffix)
		}
	}
	if v, ok := a.value(key); ok && !v.IsNull() {
		return v, true
	}
	return cty.NilVal, false
}

// instanceKeyValue reads an instance suffix, [0] or ["k"], back as its key.
func instanceKeyValue(suffix string) (cty.Value, bool) {
	trav, diags := hclsyntax.ParseTraversalAbs([]byte("x"+suffix), "", hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() || len(trav) != 2 {
		return cty.NilVal, false
	}
	step, ok := trav[1].(hcl.TraverseIndex)
	if !ok {
		return cty.NilVal, false
	}
	return step.Key, true
}

// constructorItem is the item key selects from an object or tuple
// constructor whose keys are all static.
func constructorItem(a *valueAnalyzer, expr hclsyntax.Expression, key cty.Value) (hclsyntax.Expression, bool) {
	if !key.IsKnown() || key.IsNull() {
		return nil, false
	}
	switch e := withoutParentheses(expr).(type) {
	case *hclsyntax.ObjectConsExpr:
		k, err := convert.Convert(key, cty.String)
		if err != nil {
			return nil, false
		}
		var item hclsyntax.Expression
		for _, it := range e.Items {
			name, ok := a.staticKey(it.KeyExpr)
			if !ok {
				return nil, false
			}
			if name == k.AsString() {
				item = it.ValueExpr
			}
		}
		return item, item != nil
	case *hclsyntax.TupleConsExpr:
		n, err := convert.Convert(key, cty.Number)
		if err != nil {
			return nil, false
		}
		i, accuracy := n.AsBigFloat().Int64()
		if accuracy != big.Exact || i < 0 || int(i) >= len(e.Exprs) {
			return nil, false
		}
		return e.Exprs[i], true
	}
	return nil, false
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
		t.addInstances(a.cache.analyzer(t.frame.scope, nil), t.frame.moduleAddress, block, t.suffix, true)
		return
	}
	// each.value is one element of the collection, which may read several.
	start := len(t.found)
	t.follow(a.cache.frameReferences(t.frame, t.forEach, "", nil))
	t.markIfSeveral(start)
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
		// A call that is written but could not be evaluated may still contain
		// resources. A module this configuration never declares cannot.
		if moduleCallDeclared(t.frame.scope, label) {
			t.untraced = true
		}
		return
	}
	suffix, indexed, output := t.moduleOutputRead(a, traversal[2:], indexKey, attribute)
	selected := children
	if suffix != "" {
		if i := slices.IndexFunc(children, func(c tfeval.ChildScope) bool { return c.Suffix == suffix }); i >= 0 {
			selected = children[i : i+1]
		}
	}
	if indexed && len(selected) > 1 {
		t.ambiguous = true
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

// moduleOutputRead splits what follows module.<label> in a read: the instance
// a literal or applied index selects, whether the read selects one, and the
// output read ("" for all of them).
func (t *referenceTrace) moduleOutputRead(
	a *valueAnalyzer, rest hcl.Traversal, indexKey hclsyntax.Expression, attribute string,
) (suffix string, indexed bool, output string) {
	if step, ok := firstStep(rest).(hcl.TraverseIndex); ok {
		suffix, indexed = address.InstanceSuffix(step.Key), true
		rest = rest[1:]
	} else if len(rest) == 0 && indexKey != nil {
		suffix, indexed = t.selectedSuffix(a, indexKey), true
	}
	if step, ok := firstStep(rest).(hcl.TraverseAttr); ok {
		output = step.Name
	} else if len(rest) == 0 && indexKey != nil {
		output = attribute
	}
	return suffix, indexed, output
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
	r := traced{found: slices.Clip(slices.Compact(a.refs.found)), untraced: a.refs.untraced, ambiguous: a.refs.ambiguous}
	c.references[key] = r
	return r
}

// moduleCallDeclared reports whether scope writes a module block with label.
func moduleCallDeclared(scope *tfeval.ModuleScope, label string) bool {
	if scope == nil {
		return false
	}
	for _, body := range scope.Bodies {
		if body == nil {
			continue
		}
		for _, block := range body.Blocks {
			if block.Type == "module" && len(block.Labels) > 0 && block.Labels[0] == label {
				return true
			}
		}
	}
	return false
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
