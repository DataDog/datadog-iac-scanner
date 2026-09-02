/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"encoding/json"
	"strings"

	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// UnknownAttributePlaceholder is stored for cty unknown values when converting
// to the document shape rules consume, so keys stay present and MissingAttribute
// checks do not treat unresolved expressions as absent (which would false-positive).
const UnknownAttributePlaceholder = "__DD_TFEVAL_UNKNOWN__"

// AttributesToDocument converts a resolved resource's attributes into the
// map[string]interface{} shape the rule pipeline consumes. Every attribute is
// always included: a value evaluation could not resolve falls back to its
// reference text, or to UnknownAttributePlaceholder when it has none, so
// presence-based rules do not fire false positives on unresolved expressions.
func AttributesToDocument(r *ResolvedResource) map[string]interface{} {
	return attributesToDocument(r.Attributes, r.Body)
}

// attrSource locates the HCL that produced a value so unresolved values can fall
// back to their reference text. Exactly one field is set, or none when the value
// cannot be traced back to a specific expression or block.
type attrSource struct {
	expr       hclsyntax.Expression // attribute value expression
	body       *hclsyntax.Body      // body of a single nested block
	blocks     []*hclsyntax.Block   // nested blocks sharing one type
	labelDepth int
}

func attributesToDocument(attrs map[string]cty.Value, body *hclsyntax.Body) map[string]interface{} {
	out := make(map[string]interface{}, len(attrs))
	for key, val := range attrs {
		out[key] = ctyValueToDocument(val, sourceFor(body, key))
	}
	return out
}

// sourceFor finds the attribute expression or nested blocks that produced key.
func sourceFor(body *hclsyntax.Body, key string) attrSource {
	if body == nil {
		return attrSource{}
	}
	if attr, ok := body.Attributes[key]; ok && attr != nil {
		return attrSource{expr: attr.Expr}
	}
	var blocks []*hclsyntax.Block
	for _, b := range body.Blocks {
		if b.Type == key {
			blocks = append(blocks, b)
		}
	}
	return attrSource{blocks: blocks}
}

// ctyValueToDocument converts a cty.Value to a JSON-serializable value, using
// src to recover what an unresolved value looked like in the configuration.
func ctyValueToDocument(v cty.Value, src attrSource) interface{} {
	if !v.IsKnown() {
		return unresolvedToDocument(src.expr)
	}
	if v.IsNull() {
		return nil
	}

	t := v.Type()
	switch t {
	case cty.String:
		return v.AsString()
	case cty.Bool:
		return v.True()
	case cty.Number:
		// json.Number avoids float64 precision loss for large integers.
		return json.Number(v.AsBigFloat().Text('f', -1))
	}

	switch {
	case t.IsTupleType(), t.IsListType(), t.IsSetType():
		return ctySeqToDocument(v, src)
	case t.IsObjectType(), t.IsMapType():
		return ctyMapToDocument(v, src)
	}
	return UnknownAttributePlaceholder
}

// ctySeqToDocument converts a tuple/list/set to a slice.
func ctySeqToDocument(v cty.Value, src attrSource) []interface{} {
	n := v.LengthInt()
	elemSrcs := seqElementSources(src, n)
	list := make([]interface{}, 0, n)
	i := 0
	for it := v.ElementIterator(); it.Next(); i++ {
		_, ev := it.Element()
		var es attrSource
		if i < len(elemSrcs) {
			es = elemSrcs[i]
		}
		list = append(list, ctyValueToDocument(ev, es))
	}
	return list
}

// seqElementSources pairs sequence elements with the HCL they came from, which
// only holds when the lengths line up (evaluation preserves element order).
func seqElementSources(src attrSource, n int) []attrSource {
	if len(src.blocks) == n {
		out := make([]attrSource, n)
		for i, b := range src.blocks {
			if src.labelDepth >= len(b.Labels) {
				out[i] = attrSource{body: b.Body}
			} else {
				out[i] = attrSource{blocks: []*hclsyntax.Block{b}, labelDepth: src.labelDepth}
			}
		}
		return out
	}
	if tuple, ok := src.expr.(*hclsyntax.TupleConsExpr); ok && len(tuple.Exprs) == n {
		out := make([]attrSource, n)
		for i, e := range tuple.Exprs {
			out[i] = attrSource{expr: e}
		}
		return out
	}
	return nil
}

// ctyMapToDocument converts an object/map to a Go map; non-string or unknown
// keys are skipped (keys are always strings in well-formed Terraform).
func ctyMapToDocument(v cty.Value, src attrSource) map[string]interface{} {
	body := src.body
	if body == nil && len(src.blocks) == 1 && src.labelDepth >= len(src.blocks[0].Labels) {
		body = src.blocks[0].Body
	}
	items := objectConsSources(src.expr)

	obj := make(map[string]interface{}, v.LengthInt())
	for it := v.ElementIterator(); it.Next(); {
		key, ev := it.Element()
		if key.Type() != cty.String || !key.IsKnown() {
			continue
		}
		name := key.AsString()
		var es attrSource
		switch {
		case body != nil:
			es = sourceFor(body, name)
		case items[name] != nil:
			es = attrSource{expr: items[name]}
		case len(src.blocks) > 0:
			es = labeledBlockSource(src, name)
		}
		obj[name] = ctyValueToDocument(ev, es)
	}
	return obj
}

func labeledBlockSource(src attrSource, label string) attrSource {
	blocks := make([]*hclsyntax.Block, 0, len(src.blocks))
	for _, block := range src.blocks {
		if src.labelDepth < len(block.Labels) && block.Labels[src.labelDepth] == label {
			blocks = append(blocks, block)
		}
	}
	return attrSource{blocks: blocks, labelDepth: src.labelDepth + 1}
}

// objectConsSources maps the statically known keys of an object constructor to
// their value expressions.
func objectConsSources(expr hclsyntax.Expression) map[string]hclsyntax.Expression {
	cons, ok := expr.(*hclsyntax.ObjectConsExpr)
	if !ok {
		return nil
	}
	out := make(map[string]hclsyntax.Expression, len(cons.Items))
	for _, item := range cons.Items {
		k, diags := item.KeyExpr.Value(nil)
		if diags.HasErrors() || !k.IsKnown() || k.IsNull() || k.Type() != cty.String {
			continue
		}
		out[k.AsString()] = item.ValueExpr
	}
	return out
}

// unresolvedToDocument recovers whatever a value that failed to evaluate can
// still offer rules: reference text for references, literals for parts that need
// no context, and the same treatment element-wise for collection constructors.
// A collection is reported as unknown as a whole when any part of it is, so it
// has to be rebuilt from the expression rather than from the value.
func unresolvedToDocument(expr hclsyntax.Expression) interface{} {
	if expr == nil {
		return UnknownAttributePlaceholder
	}
	if ref, ok := referenceText(expr); ok {
		return ref
	}
	if val, diags := expr.Value(nil); !diags.HasErrors() && val.IsWhollyKnown() {
		return ctyValueToDocument(val, attrSource{})
	}
	switch e := expr.(type) {
	case *hclsyntax.TupleConsExpr:
		list := make([]interface{}, 0, len(e.Exprs))
		for _, elem := range e.Exprs {
			list = append(list, unresolvedToDocument(elem))
		}
		return list
	case *hclsyntax.ObjectConsExpr:
		items := objectConsSources(e)
		obj := make(map[string]interface{}, len(items))
		for name, valExpr := range items {
			obj[name] = unresolvedToDocument(valExpr)
		}
		return obj
	}
	return UnknownAttributePlaceholder
}

// referenceText renders a reference expression back to the interpolated form the
// plain HCL parser emits for unresolved values, e.g. "${aws_s3_bucket.b.id}".
// Rules link resources by parsing these strings, so keeping them is what lets an
// instantiated resource still be matched against the resource it points at.
func referenceText(expr hclsyntax.Expression) (string, bool) {
	if expr == nil {
		return "", false
	}
	traversal, diags := hcl.AbsTraversalForExpr(expr)
	if diags.HasErrors() {
		return "", false
	}
	rendered, ok := renderTraversal(traversal)
	if !ok {
		return "", false
	}
	return "${" + rendered + "}", true
}

func renderTraversal(traversal hcl.Traversal) (string, bool) {
	if len(traversal) == 0 {
		return "", false
	}
	var sb strings.Builder
	for _, step := range traversal {
		switch s := step.(type) {
		case hcl.TraverseRoot:
			sb.WriteString(s.Name)
		case hcl.TraverseAttr:
			sb.WriteByte('.')
			sb.WriteString(s.Name)
		case hcl.TraverseIndex:
			switch s.Key.Type() {
			case cty.String:
				sb.WriteString(`["` + s.Key.AsString() + `"]`)
			case cty.Number:
				sb.WriteString("[" + s.Key.AsBigFloat().Text('f', -1) + "]")
			default:
				return "", false
			}
		default:
			return "", false
		}
	}
	return sb.String(), true
}

// RemoteResolver maps a non-local module call to its selected directory and acquired package root.
type RemoteResolver func(
	source, version, callerFile, moduleName string,
) (dir, packageRoot string, ok bool)

func CalledModuleDirs(dir string, resolver RemoteResolver) []string {
	bodies, err := parseDir(dir, "")
	if err != nil {
		return nil
	}
	return calledModuleDirs(dir, bodies, resolver)
}

func (e *Evaluator) CalledModuleDirs(dir string) []string {
	bodies, err := e.parseDir(dir, "")
	if err != nil {
		return nil
	}
	return calledModuleDirs(dir, bodies, e.remoteResolver)
}

func calledModuleDirs(dir string, bodies []*hclsyntax.Body, resolver RemoteResolver) []string {
	moduleBlocks := collectModuleBlocks(bodies)

	emptyCtx := &hcl.EvalContext{}
	var dirs []string
	for _, mb := range moduleBlocks {
		source := knownString(mb.Body.Attributes["source"], emptyCtx)
		if source == "" {
			continue
		}
		cleanSource := StripGetterPrefix(source)
		if tfmodules.LooksLikeLocalModuleSource(cleanSource) {
			dirs = append(dirs, resolveLocalDir(dir, source))
			continue
		}
		if resolver != nil {
			version := knownString(mb.Body.Attributes["version"], emptyCtx)
			if d, _, ok := resolver(source, version, mb.TypeRange.Filename, blockLabel(mb)); ok {
				dirs = append(dirs, d)
			}
		}
	}
	return dirs
}

// CalledLocalDirs returns the resolved directories of every local module called
// from dir. Remote/registry sources are ignored.
func CalledLocalDirs(dir string) []string {
	return CalledModuleDirs(dir, nil)
}
