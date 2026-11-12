/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package project

import (
	"encoding/json"
	slashpath "path"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/jsonfilter"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/address"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/dynamicblock"
	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/value"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// JoinRoot joins a scan base and a model-relative file. The model stores
// relative paths with forward slashes. A base that uses forward slashes, as
// the in-memory filesystem does, stays that way: filepath.Join would rewrite
// it to the OS separator and the file would no longer match. A file outside
// the base (a module package) is cleaned of its "..".
func JoinRoot(base, rel string) string {
	rel = filepath.ToSlash(rel)
	if strings.Contains(base, `\`) {
		return filepath.Join(base, filepath.FromSlash(rel))
	}
	if base == "" || base == "." {
		return rel
	}
	return slashpath.Clean(strings.TrimRight(base, "/") + "/" + strings.TrimLeft(rel, "/"))
}

// LegacyOptions configure Legacy.
type LegacyOptions struct {
	// Base is the scan base the block files are relative to.
	Base string
	// Placeholder stands for unknown values nested in an attribute.
	Placeholder string
	// FileID returns the id of the scanned file at an absolute path; blocks
	// of files it does not know are left out.
	FileID func(path string) (string, bool)
	// Taken records root-module files already emitted by an earlier call, so
	// roots evaluated one at a time do not report the same written file twice.
	Taken map[string]struct{}
	// InstanceID returns the id of the document of a module instance from
	// the id of its file; nil appends the root and module address.
	InstanceID func(fileID string, m *model.Module) string
}

// LegacyDoc is one document of Legacy.
type LegacyDoc struct {
	Doc  map[string]any
	Path string
	// Module is the module instance the document holds the blocks of, nil
	// for the root module of a root.
	Module *model.Module
	// Instances names, by the key a block instance has in Doc, the block
	// label and instance key it was written with.
	Instances map[LegacyKey]LegacyInstance
}

// LegacyKey is the block kind, type and document key of an expanded block.
type LegacyKey struct{ Kind, Type, Name string }

// LegacyInstance is the label and count or for_each key of an expanded block.
type LegacyInstance struct{ Label, Suffix string }

// Legacy rebuilds the documents of the rules written before the contract input: one
// document per scanned file, {"id", "file", "resource": {type: {name: {...}}},
// "data", "module", "variable", "output", "provider", "locals"}. A block
// with count or for_each has one entry per instance, keyed by the label and
// the instance key ("b[0]"); a nested block written once is an object, a
// nested block written several times a list. The blocks of a module instance
// are a document of their own, per instance, so each call is evaluated and
// attributed separately. A wholly unknown attribute is its expression as
// "${...}", an unknown part of a value the placeholder.
func Legacy(roots []*model.Root, opts LegacyOptions) []map[string]any {
	docs := LegacyDocs(roots, opts)
	out := make([]map[string]any, len(docs))
	for i := range docs {
		out[i] = docs[i].Doc
	}
	return out
}

// LegacyDocs is Legacy with what each document was built from.
func LegacyDocs(roots []*model.Root, opts LegacyOptions) []*LegacyDoc {
	conv := value.Converter{Placeholder: opts.Placeholder}
	owners := map[string]*model.Module{}
	docs := map[string]*LegacyDoc{}
	var order []string
	for _, r := range roots {
		for _, m := range r.Modules {
			for _, b := range m.Blocks {
				path := JoinRoot(opts.Base, b.File)
				key, asInstance, skip := legacyDocPlacement(opts, owners, path, r, m, b)
				if skip {
					continue
				}
				d, ok := docs[key]
				if !ok {
					id, known := opts.FileID(path)
					if !known {
						continue
					}
					d = &LegacyDoc{Path: path}
					if asInstance {
						d.Module = m
						id = instanceID(opts, id, r, m)
					} else {
						owners[path] = m
						if opts.Taken != nil {
							opts.Taken[path] = struct{}{}
						}
					}
					d.Doc = map[string]any{"id": id, "file": path}
					docs[key] = d
					order = append(order, key)
				}
				d.add(b, conv)
			}
		}
	}
	out := make([]*LegacyDoc, 0, len(order))
	for _, key := range order {
		out = append(out, docs[key])
	}
	return out
}

// legacyDocPlacement chooses the document key for a block. Resource, data and
// ephemeral blocks of a module instance stay on a per-instance document.
// Everything else of a module directory is reported once on the written file,
// as before the contract input, so roots do not multiply the same static finding.
func legacyDocPlacement(
	opts LegacyOptions, owners map[string]*model.Module, path string, r *model.Root, m *model.Module, b *model.Block,
) (key string, asInstance, skip bool) {
	instanceKind := b.Kind == address.KindResource || b.Kind == address.KindData || b.Kind == address.KindEphemeral
	if m.Address != "" && instanceKind {
		return path + "\x00" + r.ID + "\x00" + m.Address, true, false
	}
	if _, seen := opts.Taken[path]; seen && owners[path] == nil {
		return "", false, true
	}
	if owner, ok := owners[path]; ok && owner != m && m.Address == "" {
		return "", false, true
	}
	return path, false, false
}

func instanceID(opts LegacyOptions, fileID string, r *model.Root, m *model.Module) string {
	if opts.InstanceID != nil {
		return opts.InstanceID(fileID, m)
	}
	return fileID + "\x00" + r.ID + "|" + m.Address
}

func (d *LegacyDoc) add(b *model.Block, conv value.Converter) {
	switch b.Kind {
	case address.KindResource, address.KindData, address.KindEphemeral:
		byName := child(child(d.Doc, b.Kind), b.Type)
		for _, inst := range b.Instances {
			name := b.Name + inst.Key
			byName[name] = legacyAttrs(b, inst, conv)
			if inst.Key != "" {
				if d.Instances == nil {
					d.Instances = map[LegacyKey]LegacyInstance{}
				}
				d.Instances[LegacyKey{Kind: b.Kind, Type: b.Type, Name: name}] = LegacyInstance{Label: b.Name, Suffix: inst.Key}
			}
		}
	case address.KindModule:
		// A call to a local module is evaluated through the module's own
		// documents; reporting the call too would flag one problem twice.
		if resolvedLocalCall(b) {
			return
		}
		addLegacyBlock(d.Doc, b, legacyAttrs(b, firstInstance(b), conv))
	default:
		var inst *model.Instance
		if len(b.Instances) > 0 {
			inst = b.Instances[0]
		}
		addLegacyBlock(d.Doc, b, legacyAttrs(b, inst, conv))
	}
}

func firstInstance(b *model.Block) *model.Instance {
	if len(b.Instances) == 0 {
		return nil
	}
	return b.Instances[0]
}

// resolvedLocalCall reports whether b calls a module by a local path and the
// model evaluated the call.
func resolvedLocalCall(b *model.Block) bool {
	if len(b.Module.Called(b.Name)) == 0 {
		return false
	}
	inst := firstInstance(b)
	if inst == nil {
		return false
	}
	src, ok := inst.Attrs["source"]
	if !ok || !src.IsKnown() || src.IsNull() || src.Type() != cty.String {
		return false
	}
	path := src.AsString()
	return strings.HasPrefix(path, "./") || strings.HasPrefix(path, "../")
}

func addLegacyBlock(doc map[string]any, b *model.Block, attrs map[string]any) {
	switch b.Kind {
	case address.KindModule, address.KindVariable, address.KindOutput:
		child(doc, b.Kind)[b.Name] = attrs
	case address.KindProvider:
		providers := child(doc, address.KindProvider)
		switch prev := providers[b.Type].(type) {
		case nil:
			providers[b.Type] = attrs
		case []any:
			providers[b.Type] = append(prev, attrs)
		default:
			providers[b.Type] = []any{prev, attrs}
		}
	case model.KindLocals:
		locals := child(doc, model.KindLocals)
		for k, v := range attrs {
			locals[k] = v
		}
	}
}

func child(m map[string]any, key string) map[string]any {
	c, ok := m[key].(map[string]any)
	if !ok {
		c = map[string]any{}
		m[key] = c
	}
	return c
}

// legacyAttrs is instance inst of b in the legacy shape; a plan's computed
// values fill the attributes the configuration does not write.
func legacyAttrs(b *model.Block, inst *model.Instance, conv value.Converter) map[string]any {
	out := map[string]any{}
	if inst == nil {
		return out
	}
	var body *hclsyntax.Body
	if b.Syntax != nil {
		body = b.Syntax.Body
	}
	for name, v := range inst.Computed {
		if value.Present(v) {
			out[name] = conv.Go(v)
		}
	}
	for name, v := range inst.Attrs {
		if !value.Present(v) {
			continue
		}
		if text, ok := partialText(inst, name, conv); ok {
			out[name] = text
			continue
		}
		if text, ok := unknownText(b, body, name, v); ok {
			out[name] = text
			continue
		}
		out[name] = conv.Go(v)
	}
	collapseBlocks(out, body)
	prepareLegacyFilterPatterns(out)
	return out
}

// prepareLegacyFilterPatterns rewrites pattern attributes the way the runner
// sanitizes KindTerraform documents, so counted instances keep _dd_filter_expr.
func prepareLegacyFilterPatterns(doc map[string]any) {
	for key, v := range doc {
		switch node := v.(type) {
		case map[string]any:
			prepareLegacyFilterPatterns(node)
		case []any:
			for _, item := range node {
				if child, ok := item.(map[string]any); ok {
					prepareLegacyFilterPatterns(child)
				}
			}
		case string:
			if key == "pattern" {
				doc[key] = jsonfilter.Resolve(node)
			}
		}
	}
}

// partialText renders a string with an unknown part the way the legacy
// converter did: a template with the placeholder for each unknown part, and
// a JSON-encoded value with the placeholder for each unknown leaf.
func partialText(inst *model.Instance, name string, conv value.Converter) (string, bool) {
	if v, ok := inst.JSON[name]; ok {
		b, err := json.Marshal(conv.Go(v))
		if err != nil {
			return "", false
		}
		return string(b), true
	}
	parts, ok := inst.Templates[name]
	if !ok {
		return "", false
	}
	var sb strings.Builder
	for _, p := range parts {
		if p.IsKnown() && !p.IsNull() && p.Type() == cty.String {
			sb.WriteString(p.AsString())
			continue
		}
		sb.WriteString(conv.Placeholder)
	}
	return sb.String(), true
}

// unknownText is the source of a wholly unknown attribute written in body,
// as the legacy converter rendered an expression it could not resolve.
func unknownText(b *model.Block, body *hclsyntax.Body, name string, v cty.Value) (string, bool) {
	v, _ = v.UnmarkDeep()
	if v.IsKnown() || body == nil || b.Module == nil || b.Module.Scope == nil {
		return "", false
	}
	attr, ok := body.Attributes[name]
	if !ok {
		return "", false
	}
	rng := attr.Expr.Range()
	src := b.Module.Scope.Sources()[rng.Filename]
	if rng.Start.Byte < 0 || rng.End.Byte > len(src) || rng.Start.Byte >= rng.End.Byte {
		return "", false
	}
	return "${" + string(src[rng.Start.Byte:rng.End.Byte]) + "}", true
}

// collapseBlocks turns the nested blocks of obj written once in body into an
// object, at every depth.
func collapseBlocks(obj map[string]any, body *hclsyntax.Body) {
	if body == nil {
		return
	}
	for name, bodies := range nestedBodies(body) {
		list, ok := obj[name].([]any)
		if !ok {
			continue
		}
		for i, e := range list {
			if m, ok := e.(map[string]any); ok {
				collapseBlocks(m, bodies[min(i, len(bodies)-1)])
			}
		}
		if len(list) == 1 {
			if m, ok := list[0].(map[string]any); ok {
				obj[name] = m
			}
		}
	}
}

// nestedBodies returns, by block type, the bodies of the nested blocks of
// body; a dynamic block contributes its content to the type it generates.
func nestedBodies(body *hclsyntax.Body) map[string][]*hclsyntax.Body {
	out := map[string][]*hclsyntax.Body{}
	for _, nb := range body.Blocks {
		if dynamicblock.Is(nb) {
			if content := dynamicblock.Content(nb); content != nil {
				typ := dynamicblock.GeneratedType(nb)
				out[typ] = append(out[typ], content)
			}
			continue
		}
		out[nb.Type] = append(out[nb.Type], nb.Body)
	}
	return out
}
