/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package model

import (
	"slices"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/address"
	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/refs"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// trace records the references of every resource, output and module call
// instance from the plan's configuration expressions. A plan lists the
// objects an expression reads, not how it reads them, so an expression that
// combines a block reference with a variable, a local or each.value (a
// conditional, a lookup) gives may-only references.
func (b *planBuilder) trace() {
	for _, m := range b.root.Modules {
		cfg := b.config[m]
		for _, blk := range m.Blocks {
			var body map[string]any
			switch blk.Kind {
			case address.KindResource, address.KindData:
				res := b.configResource(m, address.Addr(address.Block{Kind: blk.Kind, Type: blk.Type, Name: blk.Name}))
				body, _ = res["expressions"].(map[string]any)
			case address.KindOutput:
				out, _ := object(cfg, "outputs", blk.Name)
				if expr, ok := out["expression"].(map[string]any); ok {
					body = map[string]any{"value": expr}
				}
			case address.KindModule:
				call, _ := object(cfg, "module_calls", blk.Name)
				body, _ = call["expressions"].(map[string]any)
			default:
				continue
			}
			for _, inst := range blk.Instances {
				b.traceInstance(m, inst, body)
			}
		}
	}
}

func (b *planBuilder) traceInstance(m *Module, inst *Instance, body map[string]any) {
	type seenKey struct {
		path string
		to   *Instance
		attr string
		read string
	}
	seen := map[seenKey]int{}
	walkConfig(body, nil, func(expr map[string]any, path []string) {
		targets, untraced := b.resolve(m, inst, stringList(expr["references"]), true, 0)
		key := strings.Join(path, ".")
		for _, tg := range targets {
			certain := tg.certain && !uncertainBlock(inst.Block) && !uncertainBlock(tg.inst.Block)
			k := seenKey{key, tg.inst, tg.attr, tg.read}
			if i, ok := seen[k]; ok {
				inst.Refs[i].Certain = inst.Refs[i].Certain || certain
				continue
			}
			seen[k] = len(inst.Refs)
			inst.Refs = append(inst.Refs, Ref{Path: slices.Clone(path), To: tg.inst, Attr: tg.attr, Read: tg.read, Certain: certain})
		}
		if untraced {
			if inst.Untraced == nil {
				inst.Untraced = map[string]bool{}
			}
			inst.Untraced[key] = true
		}
	})
}

// walkConfig calls fn for every expression of a configuration body with its
// attribute path, names only.
func walkConfig(body map[string]any, prefix []string, fn func(map[string]any, []string)) {
	for _, k := range sortedMapKeys(body) {
		path := append(slices.Clone(prefix), k)
		switch v := body[k].(type) {
		case []any:
			for _, nb := range v {
				if m, ok := nb.(map[string]any); ok {
					walkConfig(m, path, fn)
				}
			}
		case map[string]any:
			if isExpression(v) {
				fn(v, path)
			} else {
				walkConfig(v, path, fn)
			}
		}
	}
}

// resolve returns the instances the references of one expression in module
// instance m read, following module arguments and outputs, and whether it
// reads a value it could not trace to a block. inst is the block instance that
// holds the expression, used to resolve each.value against its for_each.
func (b *planBuilder) resolve(m *Module, inst *Instance, refStrs []string, certain bool, depth int) (out []target, untraced bool) {
	if depth > maxTraceDepth || m == nil {
		return nil, true
	}
	parsed, certain, untraced := planRefs(refStrs, certain)
	byIndex := countIndexed(inst, parsed)
	for i := range parsed {
		got, u := b.follow(m, inst, &parsed[i], certain, depth)
		if byIndex && parsed[i].Key == nil && (parsed[i].Kind == refs.KindResource || parsed[i].Kind == refs.KindData) {
			got = sameIndex(got, inst.Key, certain)
		}
		out = append(out, got...)
		untraced = untraced || u
	}
	return out, untraced
}

// planRefs parses the references of one expression. An expression that
// combines a block reference with another input gives may-only references,
// and a reference that does not parse is untraced.
func planRefs(refStrs []string, certain bool) (parsed []refs.Ref, outCertain, untraced bool) {
	sources, inputs := 0, 0
	for _, s := range mostSpecific(expandCountIndexRefs(refStrs)) {
		t, diags := hclsyntax.ParseTraversalAbs([]byte(s), "", hcl.InitialPos)
		if diags.HasErrors() {
			untraced = true
			continue
		}
		r := refs.Parse(t)
		switch r.Kind {
		case refs.KindResource, refs.KindData, refs.KindEphemeral, refs.KindModule:
			sources++
		case refs.KindVar, refs.KindLocal, refs.KindSelf:
			inputs++
		case refs.KindEach:
			if readsEachValue(r.After()) {
				inputs++
			}
		}
		parsed = append(parsed, r)
	}
	if inputs > 0 && sources+inputs > 1 {
		certain = false
	}
	return parsed, certain, untraced
}

// expandCountIndexRefs rewrites block[count.index](.attr)* plan reference
// strings into the bare address (plus attributes) and a separate count.index.
// A plan lists resource.name[count.index].id as one string; ParseTraversalAbs
// rejects that dynamic index, and mostSpecific would then drop the bare
// resource.name that countIndexed needs.
func expandCountIndexRefs(list []string) []string {
	const marker = "[count.index]"
	out := make([]string, 0, len(list)+1)
	needCount := false
	for _, s := range list {
		i := strings.Index(s, marker)
		if i < 0 {
			out = append(out, s)
			continue
		}
		before, after := s[:i], s[i+len(marker):]
		if (after != "" && after[0] != '.') || strings.ContainsAny(before, "[]") || !countIndexBlockAddress(before) {
			out = append(out, s)
			continue
		}
		out = append(out, before+after)
		needCount = true
	}
	if needCount && !slices.Contains(out, "count.index") {
		out = append(out, "count.index")
	}
	return out
}

// countIndexBlockAddress reports a resource, data, ephemeral or module address
// a plan may index with count.index: type.name, data.type.name,
// ephemeral.type.name or module.name.
func countIndexBlockAddress(s string) bool {
	parts := strings.Split(s, ".")
	switch len(parts) {
	case 2:
		if parts[0] == "" || parts[1] == "" {
			return false
		}
		switch parts[0] {
		case "var", "local", "each", "count", "self", "path", "terraform", address.KindData, address.KindEphemeral:
			return false
		}
		return true
	case 3:
		return (parts[0] == address.KindData || parts[0] == address.KindEphemeral) && parts[1] != "" && parts[2] != ""
	}
	return false
}

// countIndexed reports an expression of a counted instance that reads one
// block without key and count.index: a plan drops the dynamic index of
// block[count.index], so the expression reads the same-index instance.
func countIndexed(inst *Instance, parsed []refs.Ref) bool {
	if inst == nil || !strings.HasPrefix(inst.Key, "[") || strings.HasPrefix(inst.Key, `["`) {
		return false
	}
	index, blocks := false, 0
	for _, r := range parsed {
		switch r.Kind {
		case refs.KindCount:
			index = index || slices.Equal(r.After(), []string{"index"})
		case refs.KindResource, refs.KindData:
			if r.Key == nil {
				blocks++
			}
		default:
			return false
		}
	}
	return index && blocks == 1
}

// sameIndex keeps the target at index key, all the may-only targets when the
// block has no such instance.
func sameIndex(targets []target, key string, certain bool) []target {
	for _, tg := range targets {
		if tg.inst.Key == key {
			tg.certain = certain
			return []target{tg}
		}
	}
	return targets
}

func (b *planBuilder) follow(m *Module, inst *Instance, r *refs.Ref, certain bool, depth int) ([]target, bool) {
	switch r.Kind {
	case refs.KindResource, refs.KindData, refs.KindEphemeral:
		return b.blockRef(m, r, certain)
	case refs.KindVar:
		return b.varRef(m, r, certain, depth)
	case refs.KindModule:
		return b.moduleRef(m, r, certain, depth)
	case refs.KindLocal, refs.KindSelf, refs.KindOther:
		return nil, true
	case refs.KindEach:
		return b.eachRef(m, inst, r, certain, depth)
	}
	return nil, false
}

// eachRef resolves each.value against the instance's for_each expression in
// the plan configuration: a resource map selects the same-key instance.
func (b *planBuilder) eachRef(m *Module, inst *Instance, r *refs.Ref, certain bool, depth int) ([]target, bool) {
	after := r.After()
	if !readsEachValue(after) {
		return nil, false
	}
	if inst == nil || inst.Block == nil {
		return nil, true
	}
	res := b.configResource(m, address.Addr(address.Block{Kind: inst.Block.Kind, Type: inst.Block.Type, Name: inst.Block.Name}))
	fe, ok := res["for_each_expression"].(map[string]any)
	if !ok {
		return nil, true
	}
	got, u := b.resolve(m, nil, stringList(fe["references"]), certain, depth+1)
	if len(got) == 0 {
		return nil, u
	}
	attr := ""
	if len(after) > 1 {
		attr = after[1]
	}
	var out []target
	for _, tg := range got {
		if inst.Key != "" && tg.inst.Key != inst.Key {
			continue
		}
		c := certain && inst.Key != "" && tg.inst.Key == inst.Key
		if attr != "" {
			tg.attr = attr
		} else {
			tg.attr = ""
		}
		tg.certain = c
		out = append(out, tg)
	}
	if len(out) == 0 {
		return nil, true
	}
	return out, false
}

// mostSpecific drops the references another one of the list extends: a plan
// lists aws_s3_bucket.b.id with aws_s3_bucket.b.
func mostSpecific(list []string) []string {
	out := make([]string, 0, len(list))
	for _, s := range list {
		extended := slices.ContainsFunc(list, func(o string) bool {
			return len(o) > len(s) && strings.HasPrefix(o, s) && (o[len(s)] == '.' || o[len(s)] == '[')
		})
		if !extended && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// blockRef resolves a reference to a resource, data or ephemeral block. A
// reference without key to an expanded block may stand for a dynamic index,
// which the plan drops: its targets are may-only. An address the complete
// root does not declare targets nothing.
func (b *planBuilder) blockRef(m *Module, r *refs.Ref, certain bool) ([]target, bool) {
	kind := map[refs.Kind]string{
		refs.KindResource: address.KindResource, refs.KindData: address.KindData, refs.KindEphemeral: address.KindEphemeral,
	}[r.Kind]
	blocks := b.blocks[m][address.Addr(address.Block{Kind: kind, Type: r.Type, Name: r.Name})]
	if r.Name == "" {
		return nil, true
	}
	if len(blocks) == 0 {
		return nil, b.root.Incomplete
	}
	attr := ""
	if after := r.After(); len(after) > 0 {
		attr = after[0]
	}
	read := r.ReadPath()
	var out []target
	for _, blk := range blocks {
		for _, inst := range blk.Instances {
			c := certain
			switch {
			case r.Key != nil:
				if inst.Key != address.InstanceSuffix(*r.Key) {
					continue
				}
			case inst.Key != "":
				c = false
			}
			out = append(out, target{inst: inst, attr: attr, read: read, certain: c})
		}
	}
	return out, len(out) == 0
}

// varRef follows a module variable to the argument of the call that set it.
// A root variable has the value the plan was made with.
func (b *planBuilder) varRef(m *Module, r *refs.Ref, certain bool, depth int) ([]target, bool) {
	if m.Address == "" {
		return nil, false
	}
	call := b.configCall(m)
	if call == nil {
		return nil, true
	}
	arg, ok := object(call, "expressions", r.Name)
	if !ok {
		return nil, false
	}
	return b.resolve(m.parent, nil, stringList(arg["references"]), certain, depth+1)
}

// moduleRef follows a module output to the expression of every instance of
// the call it reads.
func (b *planBuilder) moduleRef(m *Module, r *refs.Ref, certain bool, depth int) ([]target, bool) {
	after := r.After()
	if r.Name == "" || len(after) == 0 {
		return nil, true
	}
	prefix := joinAddr(m.Address, address.KindModule+"."+r.Name)
	var out []target
	untraced, found := false, false
	for _, child := range m.calls[r.Name] {
		c := certain
		rest := strings.TrimPrefix(child.Address, prefix)
		if r.Key != nil {
			if rest != address.InstanceSuffix(*r.Key) {
				continue
			}
		} else if rest != "" {
			c = false
		}
		found = true
		expr, ok := object(b.config[child], "outputs", after[0], "expression")
		if !ok {
			untraced = true
			continue
		}
		got, u := b.resolve(child, nil, stringList(expr["references"]), c, depth+1)
		out = append(out, got...)
		untraced = untraced || u
	}
	if !found {
		return out, b.root.Incomplete
	}
	return out, untraced
}
