/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package blockmeta builds the parts of a block's _dd_meta that come from its
// written body, the same way for a block kept as written and an evaluated one.
package blockmeta

import (
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/dynamicblock"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/metaargs"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// Generated reports how many blocks the dynamic block b generated, none when
// it was kept as written; varies is set when b generated a different number
// of blocks under each instance of its parent.
type Generated func(b *hclsyntax.Block) (n int, varies bool)

// Configured is the _dd_meta.configured of body, whose document is doc: true
// at each attribute body sets to a non-null value and, per nested block type,
// a list with one shape per block in doc, static and generated alike; a
// dynamic block kept as written generated none. A type whose blocks cannot be
// lined up with doc, because a dynamic block's count varies or generated is
// nil, is true. Meta-arguments and labeled nested blocks, such as
// provisioners, are not listed. Nil when nothing is.
func Configured(body *hclsyntax.Body, doc map[string]interface{}, generated Generated) map[string]interface{} {
	if body == nil {
		return nil
	}
	out := map[string]interface{}{}
	for name := range body.Attributes {
		if v, ok := doc[name]; ok && v != nil && !metaargs.Is(name) {
			out[name] = true
		}
	}
	var order []string
	byType := map[string][]*hclsyntax.Block{}
	for _, b := range body.Blocks {
		typ := b.Type
		switch {
		case dynamicblock.Is(b):
			if _, labeled := b.Body.Attributes["labels"]; labeled {
				continue
			}
			typ = dynamicblock.GeneratedType(b)
		case len(b.Labels) > 0 || metaargs.Is(b.Type):
			continue
		}
		if _, seen := byType[typ]; !seen {
			order = append(order, typ)
		}
		byType[typ] = append(byType[typ], b)
	}
	for _, typ := range order {
		if shape := nestedShape(byType[typ], doc[typ], generated); shape != nil {
			out[typ] = shape
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// nestedShape is the configured shape of the blocks of one type, in body
// order, whose document value is v.
func nestedShape(blocks []*hclsyntax.Block, v interface{}, generated Generated) interface{} {
	elems := blockObjects(v)
	shapes := make([]interface{}, 0, len(elems))
	for _, b := range blocks {
		body, n := b.Body, 1
		if dynamicblock.Is(b) {
			count, varies := 0, true
			if generated != nil {
				count, varies = generated(b)
			}
			if varies {
				return shapesFromDocs(elems)
			}
			body, n = dynamicblock.Content(b), count
		}
		for range n {
			if len(shapes) == len(elems) {
				return shapesFromDocs(elems)
			}
			shape := Configured(body, elems[len(shapes)], generated)
			if shape == nil {
				shape = map[string]interface{}{}
			}
			shapes = append(shapes, shape)
		}
	}
	if len(shapes) != len(elems) {
		return shapesFromDocs(elems)
	}
	if len(shapes) == 0 {
		return nil
	}
	return shapes
}

// shapesFromDocs is the configured shape of nested blocks when they cannot be
// lined up with the HCL that produced them: one shape per document element.
func shapesFromDocs(elems []map[string]interface{}) interface{} {
	if len(elems) == 0 {
		return nil
	}
	shapes := make([]interface{}, len(elems))
	for i, e := range elems {
		shape := map[string]interface{}{}
		for name, v := range e {
			if v == nil || name == "_dd_lines" || metaargs.Is(name) {
				continue
			}
			if nested := blockObjects(v); nested != nil {
				if s := shapesFromDocs(nested); s != nil {
					shape[name] = s
				}
				continue
			}
			shape[name] = true
		}
		shapes[i] = shape
	}
	return shapes
}

// blockObjects is the objects of a nested block's list value, nil if any
// element is not one.
func blockObjects(v interface{}) []map[string]interface{} {
	list, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]map[string]interface{}, 0, len(list))
	for _, item := range list {
		switch m := item.(type) {
		case map[string]interface{}:
			out = append(out, m)
		case model.Document:
			out = append(out, m)
		default:
			return nil
		}
	}
	return out
}

// Provider is the provider configuration a resource, data or ephemeral block
// of type typ uses in the module declaring it: the one its provider
// meta-argument expr names, or, when expr is nil, the default configuration
// of the provider its type belongs to. It is empty when expr is not a
// provider configuration reference.
func Provider(expr hcl.Expression, typ string) string {
	if expr == nil {
		return DefaultProvider(typ)
	}
	addr, _ := ProviderAddress(expr)
	return addr
}

// BodyProvider is Provider for a block's HCL body.
func BodyProvider(body *hclsyntax.Body, typ string) string {
	if attr, ok := body.Attributes["provider"]; ok {
		return Provider(attr.Expr, typ)
	}
	return DefaultProvider(typ)
}

// referenceRoots are the names Terraform reserves for references to values,
// which never name a provider.
var referenceRoots = map[string]bool{
	"var": true, "local": true, "module": true, "data": true, "ephemeral": true, "resource": true,
	"each": true, "count": true, "self": true, "path": true, "terraform": true,
}

// ProviderAddress reads a provider configuration reference, aws or aws.west.
func ProviderAddress(expr hcl.Expression) (string, bool) {
	traversal, diags := hcl.AbsTraversalForExpr(expr)
	if diags.HasErrors() || len(traversal) == 0 || len(traversal) > 2 || referenceRoots[traversal.RootName()] {
		return "", false
	}
	name := traversal.RootName()
	if len(traversal) == 2 {
		alias, ok := traversal[1].(hcl.TraverseAttr)
		if !ok {
			return "", false
		}
		name += "." + alias.Name
	}
	return name, true
}

// DefaultProvider is the default configuration of the provider a resource
// type belongs to, the type's prefix up to its first underscore.
func DefaultProvider(typ string) string {
	name, _, _ := strings.Cut(typ, "_")
	return name
}

// ProvidersMap reads a module call's providers argument, mapping each
// configuration the called module sees to the caller's configuration it is.
// Nil when the call has none.
func ProvidersMap(call *hclsyntax.Body) map[string]string {
	if call == nil {
		return nil
	}
	attr, ok := call.Attributes["providers"]
	if !ok {
		return nil
	}
	pairs, diags := hcl.ExprMap(attr.Expr)
	if diags.HasErrors() {
		return nil
	}
	out := make(map[string]string, len(pairs))
	for _, pair := range pairs {
		key, keyOK := ProviderAddress(pair.Key)
		value, valueOK := ProviderAddress(pair.Value)
		if keyOK && valueOK {
			out[key] = value
		}
	}
	return out
}

// Inherit is the caller's configuration for addr, a configuration the called
// module sees, given the call's providers map: the mapped one, or the same
// default configuration, which a module inherits unless the map names it.
// ok is false for an alias the map does not pass.
func Inherit(addr string, providers map[string]string) (string, bool) {
	if mapped, ok := providers[addr]; ok {
		return mapped, true
	}
	if strings.Contains(addr, ".") {
		return addr, false
	}
	return addr, true
}

// Declares reports whether bodies, the files of one module, write the
// provider block of configuration addr, aws or aws.west.
func Declares(bodies []*hclsyntax.Body, addr string) bool {
	name, alias, _ := strings.Cut(addr, ".")
	for _, body := range bodies {
		if body == nil {
			continue
		}
		for _, b := range body.Blocks {
			if b.Type != "provider" || len(b.Labels) != 1 || b.Labels[0] != name {
				continue
			}
			if got, ok := providerAlias(b.Body); ok && got == alias {
				return true
			}
		}
	}
	return false
}

// providerAlias is the literal alias of a provider block, "" for the default
// configuration; ok is false when the alias is not a literal string.
func providerAlias(body *hclsyntax.Body) (string, bool) {
	attr, ok := body.Attributes["alias"]
	if !ok {
		return "", true
	}
	v, diags := attr.Expr.Value(nil)
	if diags.HasErrors() || v.IsNull() || !v.IsKnown() || v.Type() != cty.String {
		return "", false
	}
	return v.AsString(), true
}

// ModuleProvider is the address of configuration addr declared by the module
// at config path modulePath, module.a.module.b, as Terraform keys it in a
// plan: "module.a.module.b:aws.west".
func ModuleProvider(modulePath, addr string) string {
	return modulePath + ":" + addr
}

// Meta is the _dd_meta of a top-level block from its parts, nil when every
// part is empty.
func Meta(provider string, configured, unknown map[string]interface{}) map[string]interface{} {
	meta := map[string]interface{}{}
	if provider != "" {
		meta["provider"] = provider
	}
	if len(configured) > 0 {
		meta["configured"] = configured
	}
	if len(unknown) > 0 {
		meta["unknown"] = unknown
	}
	if len(meta) == 0 {
		return nil
	}
	return meta
}
