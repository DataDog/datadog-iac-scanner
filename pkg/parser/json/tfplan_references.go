/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package json

import (
	"slices"
	"sort"
	"strings"

	tfaddress "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/address"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/tidwall/gjson"
)

const maxReferenceHops = 32

type planRefKind int

const (
	planRefResource planRefKind = iota
	planRefVar
	planRefModule
	// planRefSelector is count.index or each.key: it chooses, reads no block.
	planRefSelector
	planRefEachValue
	// planRefNothing is path, terraform or self: no block is read.
	planRefNothing
	// planRefUntraced is a local, which a plan has no expression for, or a
	// reference that does not parse.
	planRefUntraced
)

// planRef is one entry of a plan "references" list reduced to the instance it
// names: base is the block address (or variable name), index its literal
// instance suffix, output the module output read.
type planRef struct {
	kind   planRefKind
	block  tfaddress.Block
	base   string
	index  string
	output string
}

func parsePlanRef(s string) planRef {
	parsed, diags := hclsyntax.ParseTraversalAbs([]byte(s), "", hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return planRef{kind: planRefUntraced}
	}
	trav := planTraversal(parsed)
	untraced := planRef{kind: planRefUntraced}
	switch root := parsed.RootName(); root {
	case "var":
		name, ok := trav.attr(1)
		if !ok {
			return untraced
		}
		return planRef{kind: planRefVar, base: name}
	case tfaddress.KindModule:
		return trav.moduleRef()
	case "count":
		return planRef{kind: planRefSelector}
	case "each":
		if step, _ := trav.attr(1); step == "value" {
			return planRef{kind: planRefEachValue}
		}
		return planRef{kind: planRefSelector}
	case "path", "terraform", "self":
		return planRef{kind: planRefNothing}
	case "local":
		return untraced
	case tfaddress.KindData, tfaddress.KindEphemeral:
		typ, ok1 := trav.attr(1)
		name, ok2 := trav.attr(2)
		if !ok1 || !ok2 {
			return untraced
		}
		block := tfaddress.Block{Kind: root, Type: typ, Name: name}
		return planRef{kind: planRefResource, block: block, base: tfaddress.Addr(block), index: trav.index(3)}
	default:
		name, ok := trav.attr(1)
		if !ok {
			return untraced
		}
		block := tfaddress.Block{Kind: tfaddress.KindResource, Type: root, Name: name}
		return planRef{kind: planRefResource, block: block, base: tfaddress.Addr(block), index: trav.index(2)}
	}
}

// planTraversal reads the steps of one plan reference.
type planTraversal hcl.Traversal

func (t planTraversal) attr(i int) (string, bool) {
	if i >= len(t) {
		return "", false
	}
	a, ok := t[i].(hcl.TraverseAttr)
	return a.Name, ok
}

func (t planTraversal) index(i int) string {
	if i >= len(t) {
		return ""
	}
	if idx, ok := t[i].(hcl.TraverseIndex); ok {
		return tfaddress.InstanceSuffix(idx.Key)
	}
	return ""
}

// moduleRef parses module.<name>[<index>].<output>.
func (t planTraversal) moduleRef() planRef {
	name, ok := t.attr(1)
	if !ok {
		return planRef{kind: planRefUntraced}
	}
	pos := 2
	idx := t.index(pos)
	if idx != "" {
		pos++
	}
	out, ok := t.attr(pos)
	if !ok && pos < len(t) {
		return planRef{kind: planRefUntraced}
	}
	return planRef{kind: planRefModule, base: "module." + name, index: idx, output: out}
}

// mostSpecificRefs reduces a references list to the reads it names. Terraform
// lists each read from its longest form to its shortest and then, right after
// a keyed instance or a module output, the resource or call containing it;
// that entry is not a read of its own. An unkeyed entry anywhere else is one:
// a read through an index that is not a literal is listed unkeyed.
func mostSpecificRefs(refs []string) []planRef {
	out := make([]planRef, 0, len(refs))
	seen := make(map[planRef]bool)
	var prev planRef
	for i, s := range refs {
		r := parsePlanRef(s)
		containing := i > 0 && containsRead(&r, &prev)
		prev = r
		if containing || seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	return out
}

// containsRead reports whether r is the entry Terraform appends after read:
// the resource of a keyed instance, the call of an output, or the call of a
// keyed call instance.
func containsRead(r, read *planRef) bool {
	if r.kind != read.kind || r.base != read.base || r.output != "" {
		return false
	}
	switch r.kind {
	case planRefResource:
		return r.index == "" && read.index != ""
	case planRefModule:
		if read.output != "" {
			return r.index == read.index
		}
		return r.index == "" && read.index != ""
	}
	return false
}

func joinModule(moduleInstance, s string) string {
	if moduleInstance == "" {
		return s
	}
	return moduleInstance + "." + s
}

// modulePrefixes lists the module instance addresses leading addr, outermost
// first.
func modulePrefixes(addr string) []string {
	trav, diags := hclsyntax.ParseTraversalAbs([]byte(addr), "", hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return nil
	}
	var out []string
	cur := ""
	for i := 0; i+1 < len(trav); {
		name, ok := trav[i+1].(hcl.TraverseAttr)
		if !ok || stepName(trav[i]) != "module" {
			break
		}
		cur = joinModule(cur, "module."+name.Name)
		i += 2
		if i < len(trav) {
			if idx, ok := trav[i].(hcl.TraverseIndex); ok {
				cur += tfaddress.InstanceSuffix(idx.Key)
				i++
			}
		}
		out = append(out, cur)
	}
	return out
}

func stepName(step hcl.Traverser) string {
	switch t := step.(type) {
	case hcl.TraverseRoot:
		return t.Name
	case hcl.TraverseAttr:
		return t.Name
	}
	return ""
}

// collectStateAddresses adds the resource addresses of a state module tree,
// skipping destroyed ones and, with dataOnly, managed resources (prior state
// still lists what the plan replaces or removes).
func collectStateAddresses(module *gjson.Result, dataOnly bool, deleted, into map[string]bool) {
	module.Get("resources").ForEach(func(_, resource gjson.Result) bool {
		addr := resource.Get("address").String()
		if addr == "" || deleted[addr] || dataOnly && resource.Get("mode").String() != "data" {
			return true
		}
		into[addr] = true
		return true
	})
	module.Get("child_modules").ForEach(func(_, child gjson.Result) bool {
		collectStateAddresses(&child, dataOnly, deleted, into)
		return true
	})
}

// indexInstances groups the planned resource and module instance addresses by
// canonical config address, sorted.
func (c *resourceChangeCorrelation) indexInstances(planned map[string]bool) {
	c.instances = make(map[string][]string)
	c.moduleInstances = make(map[string][]string)
	modules := make(map[string]bool)
	for addr := range planned {
		canonical := canonicalConfigAddress(addr)
		c.instances[canonical] = append(c.instances[canonical], addr)
		for _, m := range modulePrefixes(addr) {
			modules[m] = true
		}
	}
	for m := range modules {
		canonical := canonicalConfigAddress(m)
		c.moduleInstances[canonical] = append(c.moduleInstances[canonical], m)
	}
	for _, list := range c.instances {
		sort.Strings(list)
	}
	for _, list := range c.moduleInstances {
		sort.Strings(list)
	}
}

// instancesUnder returns the candidates equal to prefix or an instance of it.
func instancesUnder(candidates []string, prefix string) []string {
	var out []string
	for _, cand := range candidates {
		if cand == prefix || strings.HasPrefix(cand, prefix+"[") {
			out = append(out, cand)
		}
	}
	return out
}

// planReader is the instance reading an expression: its own count or
// for_each key, and the for_each expression giving it each.value.
type planReader struct {
	key     string
	forEach gjson.Result
}

// planTrace is what a references list reads: the instance addresses, whether
// part of it could not be followed, and whether the addresses over-approximate
// the read.
type planTrace struct {
	addrs     []string
	untraced  bool
	ambiguous bool
}

func (t *planTrace) merge(other planTrace) {
	t.addrs = append(t.addrs, other.addrs...)
	t.untraced = t.untraced || other.untraced
	t.ambiguous = t.ambiguous || other.ambiguous
}

// instanceKeyOf is the instance key ending addr, "" when it has none.
func instanceKeyOf(addr string) string {
	trav, diags := hclsyntax.ParseTraversalAbs([]byte(addr), "", hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() || len(trav) == 0 {
		return ""
	}
	if idx, ok := trav[len(trav)-1].(hcl.TraverseIndex); ok {
		return tfaddress.InstanceSuffix(idx.Key)
	}
	return ""
}

// planReferences resolves one expressions tree of the resource at instance
// address addr into the references shape, and the matching ambiguous shape.
// An expressions object whose attributes are all untraced yields an empty
// references object: a missing key stays untraced, so a concrete planned
// value is not indexed as something the configuration wrote.
func planReferences(expressions *gjson.Result, addr string, c *resourceChangeCorrelation) (refs, ambiguous map[string]interface{}) {
	prefixes := modulePrefixes(addr)
	moduleInstance := ""
	if len(prefixes) > 0 {
		moduleInstance = prefixes[len(prefixes)-1]
	}
	reader := planReader{key: instanceKeyOf(addr), forEach: c.forEachByAddress[canonicalConfigAddress(addr)]}
	return c.planReferencesIn(expressions, moduleInstance, &reader)
}

// planReferencesIn is planReferences for expressions Terraform evaluates in
// module moduleInstance, "" for the root module, by reader.
func (c *resourceChangeCorrelation) planReferencesIn(
	expressions *gjson.Result, moduleInstance string, reader *planReader,
) (refs, ambiguous map[string]interface{}) {
	shaped, shapedAmbiguous := c.shapeBody(expressions, moduleInstance, reader, 0)
	refs, _ = shaped.(map[string]interface{})
	ambiguous, _ = shapedAmbiguous.(map[string]interface{})
	if len(refs) == 0 {
		return map[string]interface{}{}, nil
	}
	if len(ambiguous) == 0 {
		ambiguous = nil
	}
	return refs, ambiguous
}

func refStrings(v *gjson.Result) ([]string, bool) {
	refs := v.Get("references")
	if !v.IsObject() || !refs.IsArray() {
		return nil, false
	}
	var out []string
	for _, r := range refs.Array() {
		if r.Type != gjson.String {
			return nil, false
		}
		out = append(out, r.String())
	}
	return out, true
}

// shapeBody mirrors a configuration body: an expression becomes the sorted
// list of addresses it reads, empty when it reads none and absent when it
// cannot be traced, a nested block a list of objects, one per block. The
// second result mirrors it with true where the addresses over-approximate
// the read.
func (c *resourceChangeCorrelation) shapeBody(
	v *gjson.Result, moduleInstance string, reader *planReader, depth int,
) (refs, ambiguous interface{}) {
	if !v.IsObject() {
		return nil, nil
	}
	obj, ambiguousObj := map[string]interface{}{}, map[string]interface{}{}
	v.ForEach(func(key, item gjson.Result) bool {
		if key.String() == linesKey {
			return true
		}
		var shaped, shapedAmbiguous interface{}
		switch {
		case item.IsArray():
			shaped, shapedAmbiguous = c.shapeList(item.Array(), moduleInstance, reader, depth)
		case isExpression(&item):
			shaped, shapedAmbiguous = c.shapeExpression(&item, moduleInstance, reader, depth)
		default:
			shaped, shapedAmbiguous = c.shapeList([]gjson.Result{item}, moduleInstance, reader, depth)
		}
		if shaped != nil {
			obj[key.String()] = shaped
		}
		if shapedAmbiguous != nil {
			ambiguousObj[key.String()] = shapedAmbiguous
		}
		return true
	})
	if len(obj) == 0 {
		return nil, nil
	}
	if len(ambiguousObj) == 0 {
		return obj, nil
	}
	return obj, ambiguousObj
}

// shapeExpression is shapeBody of one attribute expression.
func (c *resourceChangeCorrelation) shapeExpression(
	v *gjson.Result, moduleInstance string, reader *planReader, depth int,
) (refs, ambiguous interface{}) {
	var trace planTrace
	if v.Get("references").Exists() {
		list, ok := refStrings(v)
		if !ok {
			return nil, nil
		}
		trace = c.resolveReferences(list, moduleInstance, reader, depth)
	}
	if trace.untraced {
		return nil, nil
	}
	out := make([]interface{}, len(trace.addrs))
	for i, a := range trace.addrs {
		out[i] = a
	}
	if trace.ambiguous && len(out) > 0 {
		return out, true
	}
	return out, nil
}

// shapeList is shapeBody of a list of nested blocks: one entry per block, {}
// for a block that reads nothing traced.
func (c *resourceChangeCorrelation) shapeList(
	items []gjson.Result, moduleInstance string, reader *planReader, depth int,
) (refs, ambiguous interface{}) {
	list := make([]interface{}, len(items))
	ambiguousList := make([]interface{}, len(items))
	found, foundAmbiguous := false, false
	for i := range items {
		shaped, shapedAmbiguous := c.shapeBody(&items[i], moduleInstance, reader, depth)
		list[i], ambiguousList[i] = map[string]interface{}{}, map[string]interface{}{}
		if shaped != nil {
			list[i], found = shaped, true
		}
		if shapedAmbiguous != nil {
			ambiguousList[i], foundAmbiguous = shapedAmbiguous, true
		}
	}
	if !found {
		return nil, nil
	}
	if !foundAmbiguous {
		return list, nil
	}
	return list, ambiguousList
}

func flattenRefs(v *gjson.Result) []string {
	if refs, ok := refStrings(v); ok {
		return refs
	}
	var out []string
	if v.IsArray() || v.IsObject() {
		v.ForEach(func(_, item gjson.Result) bool {
			out = append(out, flattenRefs(&item)...)
			return true
		})
	}
	return out
}

// resolveReferences returns the sorted, duplicate-free instance addresses a
// references list names in the module instance moduleInstance, read by reader.
func (c *resourceChangeCorrelation) resolveReferences(
	refs []string, moduleInstance string, reader *planReader, depth int,
) planTrace {
	if depth > maxReferenceHops {
		return planTrace{untraced: true}
	}
	parsed := mostSpecificRefs(refs)
	memoKey := resolveMemoKey(refs, parsed, moduleInstance, reader)
	if out, ok := c.resolved[memoKey]; ok {
		return out
	}
	configPath := canonicalConfigAddress(moduleInstance)
	var trace planTrace
	selects := false
	for i := range parsed {
		r := &parsed[i]
		switch r.kind {
		case planRefResource:
			trace.merge(c.resolveResource(r, moduleInstance, configPath))
		case planRefVar:
			read := c.resolveVariable(r.base, moduleInstance, configPath, depth)
			if !read.untraced && len(read.addrs) == 0 {
				selects = true
			}
			trace.merge(read)
		case planRefModule:
			trace.merge(c.resolveModuleOutput(r, moduleInstance, configPath, depth))
		case planRefEachValue:
			trace.merge(c.resolveEachValue(moduleInstance, configPath, reader, depth))
		case planRefSelector:
			selects = true
		case planRefUntraced:
			trace.untraced = true
		}
	}
	sort.Strings(trace.addrs)
	trace.addrs = slices.Compact(trace.addrs)
	// A plan lists the references of every alternative and of every index
	// without saying which applies: a read that also chooses, by an index or
	// a condition, may read any of the instances it lists, or none when the
	// other alternative is a literal.
	if selects && len(trace.addrs) > 0 {
		trace.ambiguous = true
	}
	c.resolved[memoKey] = trace
	return trace
}

// resolveMemoKey keys resolveReferences' memo by module instance and
// references, plus the reader's instance when the list reads each.value.
func resolveMemoKey(refs []string, parsed []planRef, moduleInstance string, reader *planReader) string {
	key := moduleInstance + "\x00" + strings.Join(refs, "\x00")
	if slices.ContainsFunc(parsed, func(r planRef) bool { return r.kind == planRefEachValue }) {
		key += "\x00" + reader.key + "\x00" + reader.forEach.Raw
	}
	return key
}

// resolveResource resolves a read of a resource, data source or ephemeral
// resource to its planned instances.
func (c *resourceChangeCorrelation) resolveResource(r *planRef, moduleInstance, configPath string) planTrace {
	if r.block.Kind == tfaddress.KindEphemeral {
		// Terraform plans no ephemeral instance.
		return planTrace{untraced: true}
	}
	instances := c.resourceInstances(r, moduleInstance, configPath)
	if len(instances) == 0 && !c.declared[joinModule(configPath, r.base)] {
		// Neither planned nor declared: the read cannot be traced. An empty
		// list would claim it reads nothing.
		return planTrace{untraced: true}
	}
	return planTrace{addrs: instances}
}

// resolveModuleOutput resolves a read of a module call's output, or of the
// whole call, in every instance of the call the read selects.
func (c *resourceChangeCorrelation) resolveModuleOutput(r *planRef, moduleInstance, configPath string, depth int) planTrace {
	childPath := joinModule(configPath, r.base)
	outputs := c.moduleOutputs[childPath]
	expr := outputs.Get(gjsonKey(r.output) + ".expression")
	if r.output == "" {
		// The whole module object reads every output.
		expr = outputs
	}
	if !expr.Exists() {
		return planTrace{untraced: true}
	}
	children, ok := c.childInstances(r, moduleInstance, childPath)
	if !ok {
		return planTrace{untraced: true}
	}
	var trace planTrace
	childRefs := flattenRefs(&expr)
	for _, child := range children {
		trace.merge(c.resolveReferences(childRefs, child, &planReader{}, depth+1))
	}
	return trace
}

// resolveVariable resolves var.name against the module call's argument, in
// the parent module instance. A root variable, or an input left to its
// default, reads no block.
func (c *resourceChangeCorrelation) resolveVariable(name, moduleInstance, configPath string, depth int) planTrace {
	if configPath == "" {
		return planTrace{}
	}
	call, ok := c.moduleCalls[configPath]
	if !ok {
		return planTrace{untraced: true}
	}
	arg := call.Get(gjsonKey(name))
	if !arg.Exists() {
		return planTrace{}
	}
	parent := ""
	if prefixes := modulePrefixes(moduleInstance); len(prefixes) > 1 {
		parent = prefixes[len(prefixes)-2]
	}
	reader := planReader{key: instanceKeyOf(moduleInstance), forEach: c.moduleForEach[configPath]}
	return c.resolveReferences(flattenRefs(&arg), parent, &reader, depth+1)
}

// resolveEachValue resolves each.value: the reader's own instance of a block
// its for_each iterates, or what the for_each reads, one element of which the
// reader sees.
func (c *resourceChangeCorrelation) resolveEachValue(moduleInstance, configPath string, reader *planReader, depth int) planTrace {
	if !reader.forEach.Exists() {
		return planTrace{untraced: true}
	}
	refs := flattenRefs(&reader.forEach)
	if parsed := mostSpecificRefs(refs); len(parsed) == 1 && reader.key != "" &&
		parsed[0].kind == planRefResource && parsed[0].index == "" {
		own := parsed[0]
		own.index = reader.key
		if instances := c.resourceInstances(&own, moduleInstance, configPath); len(instances) == 1 {
			return planTrace{addrs: instances}
		}
	}
	trace := c.resolveReferences(refs, moduleInstance, &planReader{}, depth+1)
	if len(trace.addrs) > 1 {
		trace.ambiguous = true
	}
	return trace
}

// gjsonKey escapes a map key for a gjson path.
func gjsonKey(key string) string {
	var b strings.Builder
	for _, r := range key {
		if strings.ContainsRune(`.*?|#@\!=<>%`, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

func (c *resourceChangeCorrelation) resourceInstances(r *planRef, moduleInstance, configPath string) []string {
	candidates := c.instances[joinModule(configPath, r.base)]
	if r.index != "" {
		// An explicit index that plans no instance traces to nothing; do not
		// fall back to other instances of the same config address.
		return instancesUnder(candidates, tfaddress.Instance(moduleInstance, r.block, r.index))
	}
	prefix := joinModule(moduleInstance, r.base)
	if found := instancesUnder(candidates, prefix); len(found) > 0 {
		return found
	}
	// moduleInstance may be a config path (no [key]); match every planned
	// instance whose config address equals prefix.
	return instancesMatchingConfig(candidates, prefix)
}

// instancesMatchingConfig returns candidates whose config address (instance
// keys stripped) equals prefix's.
func instancesMatchingConfig(candidates []string, prefix string) []string {
	want := canonicalConfigAddress(prefix)
	var out []string
	for _, cand := range candidates {
		if canonicalConfigAddress(cand) == want {
			out = append(out, cand)
		}
	}
	return out
}

// childInstances lists the instances of a module call a read selects. A plan
// names a call instance only through the resources it plans, so a call
// without count or for_each still has its one instance when it plans none;
// ok is false when the instances of a repeated call cannot be told.
func (c *resourceChangeCorrelation) childInstances(r *planRef, moduleInstance, childPath string) (instances []string, ok bool) {
	prefix := joinModule(moduleInstance, r.base) + r.index
	if planned := instancesUnder(c.moduleInstances[childPath], prefix); len(planned) > 0 {
		return planned, true
	}
	if planned := instancesMatchingConfig(c.moduleInstances[childPath], prefix); len(planned) > 0 {
		return planned, true
	}
	if !c.repeatedModules[childPath] && r.index == "" {
		return []string{joinModule(moduleInstance, r.base)}, true
	}
	return nil, false
}
