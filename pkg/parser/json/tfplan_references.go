/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package json

import (
	"fmt"
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

func (r *planRef) group() string {
	return fmt.Sprintf("%d|%s|%s", r.kind, r.base, r.output)
}

func parsePlanRef(s string) (planRef, bool) {
	trav, diags := hclsyntax.ParseTraversalAbs([]byte(s), "", hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return planRef{}, false
	}
	attr := func(i int) (string, bool) {
		if i >= len(trav) {
			return "", false
		}
		a, ok := trav[i].(hcl.TraverseAttr)
		return a.Name, ok
	}
	index := func(i int) string {
		if i >= len(trav) {
			return ""
		}
		if idx, ok := trav[i].(hcl.TraverseIndex); ok {
			return tfaddress.InstanceSuffix(idx.Key)
		}
		return ""
	}
	switch root := trav.RootName(); root {
	case "var":
		name, ok := attr(1)
		return planRef{kind: planRefVar, base: name}, ok
	case tfaddress.KindModule:
		name, ok := attr(1)
		if !ok {
			return planRef{}, false
		}
		pos := 2
		idx := index(pos)
		if idx != "" {
			pos++
		}
		out, ok := attr(pos)
		if !ok {
			return planRef{}, false
		}
		return planRef{kind: planRefModule, base: "module." + name, index: idx, output: out}, true
	case "local", "each", "count", "path", "terraform", "self":
		return planRef{}, false
	case tfaddress.KindData, tfaddress.KindEphemeral:
		typ, ok1 := attr(1)
		name, ok2 := attr(2)
		if !ok1 || !ok2 {
			return planRef{}, false
		}
		block := tfaddress.Block{Kind: root, Type: typ, Name: name}
		return planRef{kind: planRefResource, block: block, base: tfaddress.Addr(block), index: index(3)}, true
	default:
		name, ok := attr(1)
		if !ok {
			return planRef{}, false
		}
		block := tfaddress.Block{Kind: tfaddress.KindResource, Type: root, Name: name}
		return planRef{kind: planRefResource, block: block, base: tfaddress.Addr(block), index: index(2)}, true
	}
}

// mostSpecificRefs drops an entry when another with the same target names an
// instance.
func mostSpecificRefs(refs []string) []planRef {
	var parsed []planRef
	indexed := make(map[string]bool)
	for _, s := range refs {
		r, ok := parsePlanRef(s)
		if !ok {
			continue
		}
		parsed = append(parsed, r)
		if r.index != "" {
			indexed[r.group()] = true
		}
	}
	seen := make(map[planRef]bool)
	out := parsed[:0]
	for _, r := range parsed {
		if r.index == "" && indexed[r.group()] || seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	return out
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

// planReferences resolves one expressions tree of the resource at instance
// address addr into the references shape, nil when nothing is traced.
func planReferences(expressions *gjson.Result, addr string, c *resourceChangeCorrelation) map[string]interface{} {
	prefixes := modulePrefixes(addr)
	moduleInstance := ""
	if len(prefixes) > 0 {
		moduleInstance = prefixes[len(prefixes)-1]
	}
	shaped, _ := c.shapeReferences(expressions, moduleInstance, 0).(map[string]interface{})
	if len(shaped) == 0 {
		return nil
	}
	return shaped
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

// shapeReferences mirrors an expressions tree: an expression with references
// becomes a sorted list of addresses, a nested block a list of objects.
func (c *resourceChangeCorrelation) shapeReferences(v *gjson.Result, moduleInstance string, depth int) interface{} {
	if refs, ok := refStrings(v); ok {
		addrs := c.resolveReferences(refs, moduleInstance, depth)
		if len(addrs) == 0 {
			return nil
		}
		list := make([]interface{}, len(addrs))
		for i, a := range addrs {
			list[i] = a
		}
		return list
	}
	switch {
	case v.IsArray():
		items := v.Array()
		list := make([]interface{}, len(items))
		found := false
		for i := range items {
			shaped := c.shapeReferences(&items[i], moduleInstance, depth)
			if shaped == nil {
				shaped = map[string]interface{}{}
			} else {
				found = true
			}
			list[i] = shaped
		}
		if !found {
			return nil
		}
		return list
	case v.IsObject():
		obj := make(map[string]interface{})
		v.ForEach(func(key, item gjson.Result) bool {
			if shaped := c.shapeReferences(&item, moduleInstance, depth); shaped != nil {
				obj[key.String()] = shaped
			}
			return true
		})
		if len(obj) == 0 {
			return nil
		}
		return obj
	}
	return nil
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
// references list names in the module instance moduleInstance.
func (c *resourceChangeCorrelation) resolveReferences(refs []string, moduleInstance string, depth int) []string {
	if depth > maxReferenceHops {
		return nil
	}
	memoKey := moduleInstance + "\x00" + strings.Join(refs, "\x00")
	if out, ok := c.resolved[memoKey]; ok {
		return out
	}
	configPath := canonicalConfigAddress(moduleInstance)
	set := make(map[string]bool)
	for _, r := range mostSpecificRefs(refs) {
		switch r.kind {
		case planRefResource:
			for _, a := range c.resourceInstances(&r, moduleInstance, configPath) {
				set[a] = true
			}
		case planRefVar:
			for _, a := range c.resolveVariable(r.base, moduleInstance, configPath, depth) {
				set[a] = true
			}
		case planRefModule:
			childPath := joinModule(configPath, r.base)
			expr := c.moduleOutputs[childPath].Get(r.output + ".expression")
			if !expr.Exists() {
				continue
			}
			childRefs := flattenRefs(&expr)
			for _, child := range c.childInstances(&r, moduleInstance, childPath) {
				for _, a := range c.resolveReferences(childRefs, child, depth+1) {
					set[a] = true
				}
			}
		}
	}
	out := make([]string, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	sort.Strings(out)
	c.resolved[memoKey] = out
	return out
}

// resolveVariable resolves var.name against the module call's argument, in
// the parent module instance.
func (c *resourceChangeCorrelation) resolveVariable(name, moduleInstance, configPath string, depth int) []string {
	arg := c.moduleCalls[configPath].Get(name)
	if configPath == "" || !arg.Exists() {
		return nil
	}
	parent := ""
	if prefixes := modulePrefixes(moduleInstance); len(prefixes) > 1 {
		parent = prefixes[len(prefixes)-2]
	}
	return c.resolveReferences(flattenRefs(&arg), parent, depth+1)
}

func (c *resourceChangeCorrelation) resourceInstances(r *planRef, moduleInstance, configPath string) []string {
	candidates := c.instances[joinModule(configPath, r.base)]
	if r.index != "" {
		return instancesUnder(candidates, tfaddress.Instance(moduleInstance, r.block, r.index))
	}
	return instancesUnder(candidates, joinModule(moduleInstance, r.base))
}

func (c *resourceChangeCorrelation) childInstances(r *planRef, moduleInstance, childPath string) []string {
	return instancesUnder(c.moduleInstances[childPath], joinModule(moduleInstance, r.base)+r.index)
}
