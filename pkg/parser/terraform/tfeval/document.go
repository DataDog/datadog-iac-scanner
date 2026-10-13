/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/ctyutil"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/dynamicblock"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
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
	return attributesToDocument(r.Attributes, r.Body, r.DynamicCounts)
}

// attrSource locates the HCL that produced a value so unresolved values can fall
// back to their reference text. Exactly one field is set, or none when the value
// cannot be traced back to a specific expression or block.
type attrSource struct {
	expr       hclsyntax.Expression // attribute value expression
	body       *hclsyntax.Body      // body of a single nested block
	blocks     []*hclsyntax.Block   // nested blocks sharing one type
	labelDepth int
	// counts is how many elements each of blocks generated, when known: one for
	// a static block, the evaluated count for a dynamic block's content.
	counts []int
	// dynamic is how many blocks each dynamic block of the resource generated.
	dynamic DynamicCounts
}

// generatedBlockType marks the content of a dynamic block among the blocks of
// an attrSource; no HCL block type contains a space.
const generatedBlockType = "dynamic content"

// blocksFor returns the blocks that produced n elements, one entry per element.
// With the generated counts of the dynamic blocks known, each block is repeated
// as often as it generated, and the sources go unmapped when the counts do not
// add up to n. Without them it falls back to inferring the split from n: every
// source block when the counts line up, the static blocks alone when the
// dynamic ones generated none, or a single dynamic block's content once per
// element it generated, in place. Several dynamic blocks of one type leave that
// inference ambiguous.
func (s *attrSource) blocksFor(n int) []*hclsyntax.Block {
	if blocks, ok := s.blocksFromCounts(n); ok {
		return blocks
	}
	if len(s.blocks) == n {
		return s.blocks
	}
	dynamic := 0
	for _, b := range s.blocks {
		if b.Type == generatedBlockType {
			dynamic++
		}
	}
	static := len(s.blocks) - dynamic
	switch {
	case static == n:
		out := make([]*hclsyntax.Block, 0, static)
		for _, b := range s.blocks {
			if b.Type != generatedBlockType {
				out = append(out, b)
			}
		}
		return out
	case dynamic == 1 && n > static:
		out := make([]*hclsyntax.Block, 0, n)
		for _, b := range s.blocks {
			if b.Type != generatedBlockType {
				out = append(out, b)
				continue
			}
			for range n - static {
				out = append(out, b)
			}
		}
		return out
	}
	return s.blocks
}

// blocksFromCounts expands the source blocks by how many elements each
// generated; ok is false when a count is not known.
func (s *attrSource) blocksFromCounts(n int) (blocks []*hclsyntax.Block, ok bool) {
	if len(s.counts) != len(s.blocks) || s.counts == nil {
		return nil, false
	}
	total := 0
	for _, c := range s.counts {
		if c < 0 {
			return nil, false
		}
		total += c
	}
	if total != n {
		return nil, true
	}
	out := make([]*hclsyntax.Block, 0, n)
	for i, b := range s.blocks {
		for range s.counts[i] {
			out = append(out, b)
		}
	}
	return out, true
}

func attributesToDocument(attrs map[string]cty.Value, body *hclsyntax.Body, dynamic DynamicCounts) map[string]interface{} {
	out := make(map[string]interface{}, len(attrs))
	for key, val := range attrs {
		src := sourceFor(body, key, dynamic)
		out[key] = ctyValueToDocument(val, &src)
	}
	return out
}

// sourceFor finds the attribute expression or nested blocks that produced key.
func sourceFor(body *hclsyntax.Body, key string, dynamic DynamicCounts) attrSource {
	if body == nil {
		return attrSource{}
	}
	if attr, ok := body.Attributes[key]; ok && attr != nil {
		return attrSource{expr: attr.Expr}
	}
	var blocks []*hclsyntax.Block
	var counts []int
	for _, b := range body.Blocks {
		switch {
		case b.Type == key:
			if count, ok := asWrittenCount(dynamic, b); ok {
				blocks = append(blocks, b)
				counts = append(counts, count)
			}
		case dynamicblock.Is(b) && dynamicblock.GeneratedType(b) == key:
			// Every dynamic block of this type stands in as one marker; counts
			// say how many blocks it generated, none when kept as written.
			if marker, ok := generatedMarker(b); ok {
				blocks = append(blocks, marker)
				counts = append(counts, generatedCount(dynamic, b))
			}
		}
	}
	if dynamic == nil {
		counts = nil
	}
	return attrSource{blocks: blocks, counts: counts, dynamic: dynamic}
}

// anyLabel stands for a label of a generated block that is only known once
// evaluated, in the labels of its marker.
const anyLabel = "\x00any"

// generatedMarker stands for the blocks a dynamic block generates among the
// blocks of an attrSource. It carries one anyLabel per label the generated
// blocks take, so a labeled dynamic block maps through the same path as a
// labeled static one; ok is false when it cannot, because the labels or the
// content are not statically known.
func generatedMarker(b *hclsyntax.Block) (marker *hclsyntax.Block, ok bool) {
	content := dynamicblock.Content(b)
	if content == nil {
		return nil, false
	}
	var labels []string
	if attr, has := b.Body.Attributes["labels"]; has {
		tuple, isTuple := attr.Expr.(*hclsyntax.TupleConsExpr)
		if !isTuple {
			return nil, false
		}
		labels = make([]string, len(tuple.Exprs))
		for i := range labels {
			labels[i] = anyLabel
		}
	}
	return &hclsyntax.Block{Type: generatedBlockType, Labels: labels, Body: content}, true
}

// generatedCount is how many blocks the dynamic block b generated; a block the
// evaluation never reached generated none.
func generatedCount(dynamic DynamicCounts, b *hclsyntax.Block) int {
	n, ok := dynamic[b]
	if !ok || n == keptAsWritten {
		return 0
	}
	return n
}

// asWrittenCount is how many elements the source b contributes as written under
// its own key: a static block always, a dynamic block only when kept as written.
// An expanded dynamic block contributes nothing under the key, since its blocks
// are generated under their own type.
func asWrittenCount(dynamic DynamicCounts, b *hclsyntax.Block) (int, bool) {
	if !dynamicblock.Is(b) || dynamic == nil {
		return 1, true
	}
	n, seen := dynamic[b]
	switch {
	case !seen:
		return 0, false
	case n == keptAsWritten:
		return 1, true
	case n == unknownDynamicCount:
		return unknownDynamicCount, true
	default:
		return 0, false
	}
}

// ctyValueToDocument converts a cty.Value to a JSON-serializable value, using
// src to recover what an unresolved value looked like in the configuration.
func ctyValueToDocument(v cty.Value, src *attrSource) interface{} {
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
func ctySeqToDocument(v cty.Value, src *attrSource) []interface{} {
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
		list = append(list, ctyValueToDocument(ev, &es))
	}
	return list
}

// seqElementSources pairs sequence elements with the HCL they came from, which
// only holds when the lengths line up (evaluation preserves element order).
func seqElementSources(src *attrSource, n int) []attrSource {
	if blocks := src.blocksFor(n); len(blocks) == n {
		out := make([]attrSource, n)
		for i, b := range blocks {
			if src.labelDepth >= len(b.Labels) {
				out[i] = attrSource{body: b.Body, dynamic: src.dynamic}
			} else {
				out[i] = attrSource{blocks: []*hclsyntax.Block{b}, labelDepth: src.labelDepth, counts: singleCount(src), dynamic: src.dynamic}
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
func ctyMapToDocument(v cty.Value, src *attrSource) map[string]interface{} {
	body := src.body
	if blocks := src.blocksFor(1); body == nil && len(blocks) == 1 && src.labelDepth >= len(blocks[0].Labels) {
		body = blocks[0].Body
	}
	items := objectConsSources(src.expr)

	obj := make(map[string]interface{}, v.LengthInt())
	for it := v.ElementIterator(); it.Next(); {
		key, ev := it.Element()
		name, ok := ctyutil.ConcreteString(key)
		if !ok {
			continue
		}
		var es attrSource
		switch {
		case body != nil:
			es = sourceFor(body, name, src.dynamic)
		case items[name] != nil:
			es = attrSource{expr: items[name]}
		case len(src.blocks) > 0:
			es = labeledBlockSource(src, name)
		}
		obj[name] = ctyValueToDocument(ev, &es)
	}
	return obj
}

func labeledBlockSource(src *attrSource, label string) attrSource {
	blocks := make([]*hclsyntax.Block, 0, len(src.blocks))
	var counts []int
	for i, block := range src.blocks {
		if src.labelDepth >= len(block.Labels) {
			continue
		}
		if got := block.Labels[src.labelDepth]; got == label || got == anyLabel {
			blocks = append(blocks, block)
			if len(src.counts) == len(src.blocks) {
				count := src.counts[i]
				if block.Type == generatedBlockType {
					// Only some of the blocks it generated carry this label.
					count = unknownDynamicCount
				}
				counts = append(counts, count)
			}
		}
	}
	return attrSource{blocks: blocks, labelDepth: src.labelDepth + 1, counts: counts, dynamic: src.dynamic}
}

// singleCount is the counts of a source reduced to one block of its own.
func singleCount(src *attrSource) []int {
	if src.counts == nil {
		return nil
	}
	return []int{1}
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
		if diags.HasErrors() {
			continue
		}
		key, ok := ctyutil.ConcreteString(k)
		if !ok {
			continue
		}
		out[key] = item.ValueExpr
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
		return ctyValueToDocument(val, &attrSource{})
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
			formatted, ok := ctyutil.FormatIndexKey(s.Key)
			if !ok {
				return "", false
			}
			sb.WriteString(formatted)
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

func CalledModuleDirs(dir string, resolver RemoteResolver, fsys vfs.FS) []string {
	bodies, err := parseDir(context.Background(), dir, "", nil, fsys)
	if err != nil {
		return nil
	}
	return calledModuleDirs(dir, bodies, resolver, fsys)
}

func (e *Evaluator) CalledModuleDirs(dir string) []string {
	bodies, err := e.parseDir(context.Background(), dir, "")
	if err != nil {
		return nil
	}
	return calledModuleDirs(dir, bodies, e.remoteResolver, e.fsys)
}

func calledModuleDirs(dir string, bodies []*hclsyntax.Body, resolver RemoteResolver, fsys vfs.FS) []string {
	moduleBlocks := collectModuleBlocks(bodies)

	emptyCtx := &hcl.EvalContext{}
	var dirs []string
	for _, mb := range moduleBlocks {
		source := ctyutil.StringFromAttribute(mb.Body.Attributes["source"], emptyCtx)
		if source == "" {
			continue
		}
		if local, ok := tfmodules.LocalModuleDir(fsys, dir, source); ok {
			dirs = append(dirs, local)
			continue
		}
		if resolver != nil {
			version := ctyutil.StringFromAttribute(mb.Body.Attributes["version"], emptyCtx)
			if d, _, ok := resolver(source, version, mb.TypeRange.Filename, blockLabel(mb)); ok {
				dirs = append(dirs, d)
			}
		}
	}
	return dirs
}

// CalledLocalDirs returns the resolved directories of every local module called
// from dir. Remote/registry sources are ignored.
func CalledLocalDirs(dir string, fsys vfs.FS) []string {
	return CalledModuleDirs(dir, nil, fsys)
}
