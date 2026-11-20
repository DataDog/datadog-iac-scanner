/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package partial renders Terraform expressions evaluation cannot fully
// resolve into values rules can read. The parts that resolve keep their value
// and every part that does not becomes its own "${expr}" text, so a policy
// interpolating a computed ARN stays a parseable document instead of collapsing
// to unknown as a whole. Both the plain Terraform parser and module evaluation
// render through it, so an unresolved value reads the same either way.
package partial

import (
	"sort"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/ctyutil"
	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	ctyconvert "github.com/zclconf/go-cty/cty/convert"
)

// UnknownPlaceholder stands for an unresolved value that has no source text to
// render. It has the "${...}" shape rules recognize as an unresolved reference.
const UnknownPlaceholder = "${__dd_unknown__}"

const templateFileFunc = "templatefile"

// Source returns the configuration text of a range, or false when it has none.
type Source func(hcl.Range) (string, bool)

// FileSources reads ranges from the native syntax files in files, keyed by
// filename.
func FileSources(files map[string][]byte) Source {
	return func(rng hcl.Range) (string, bool) {
		src, ok := files[rng.Filename]
		if !ok || tfpath.IsJSONConfig(rng.Filename) {
			return "", false
		}
		return sourceRange(src, rng)
	}
}

// BytesSource reads ranges from the single file src.
func BytesSource(src []byte) Source {
	return func(rng hcl.Range) (string, bool) {
		return sourceRange(src, rng)
	}
}

func sourceRange(src []byte, rng hcl.Range) (string, bool) {
	if rng.Start.Byte < 0 || rng.Start.Byte >= rng.End.Byte || rng.End.Byte > len(src) {
		return "", false
	}
	return strings.TrimSpace(string(src[rng.Start.Byte:rng.End.Byte])), true
}

// Renderer renders expressions against Ctx, taking the text of unresolved
// parts from Source. Without Source, references still render from their
// traversal; without Ctx, only what needs no context resolves.
type Renderer struct {
	Ctx    *hcl.EvalContext
	Source Source
	// Reference optionally supplies a partial value for a bare reference during
	// rendering. It must not install that value in Ctx: content-dependent
	// expressions must continue to evaluate against authoritative values.
	// Create lexical child renderers with WithBindings to preserve shadowing.
	Reference func(hcl.Traversal, *hcl.EvalContext) (cty.Value, bool)
}

var emptyCtx = &hcl.EvalContext{}

func (r *Renderer) ctx() *hcl.EvalContext {
	if r.Ctx == nil {
		return emptyCtx
	}
	return r.Ctx
}

// Render returns expr's value with every unresolved part rendered as text, or
// false when expr cannot be rendered.
func (r *Renderer) Render(expr hcl.Expression) (cty.Value, bool) {
	if b, ok := expr.(bound); ok {
		return r.WithBindings(b.vars).Render(b.Expression)
	}
	if v, diags := expr.Value(r.ctx()); !diags.HasErrors() && v.IsWhollyKnown() {
		v, _ = v.UnmarkDeep()
		return v, true
	}
	syn, ok := expr.(hclsyntax.Expression)
	if !ok {
		return cty.NilVal, false
	}
	return r.RenderUnresolved(syn)
}

// RenderUnresolved is Render for an expr already known not to resolve.
func (r *Renderer) RenderUnresolved(expr hclsyntax.Expression) (cty.Value, bool) {
	if v, ok := r.referenceExpression(expr); ok {
		return v, true
	}
	if f, ok := expr.(*hclsyntax.ForExpr); ok && !r.forPlacesOnly(f) {
		// A for body that decides on its elements cannot render per element,
		// and rendering the expression whole would discard the evaluated
		// known elements; refuse so the caller falls back to its value.
		return cty.NilVal, false
	}
	if v, diags := r.substitute(expr).Value(r.ctx()); !diags.HasErrors() && v.IsWhollyKnown() {
		v, _ = v.UnmarkDeep()
		return v, true
	}
	return r.renderParts(expr)
}

// Text renders expr as its own "${expr}" text, from Source or else from its
// traversal. Rules link resources by parsing reference texts such as
// "${aws_s3_bucket.b.id}".
func (r *Renderer) Text(expr hclsyntax.Expression) (string, bool) {
	if wrap, ok := expr.(*hclsyntax.TemplateWrapExpr); ok {
		return r.Text(wrap.Wrapped)
	}
	if r.Source != nil {
		if s, ok := r.Source(expr.Range()); ok {
			if strings.HasPrefix(s, "%{") {
				return s, true
			}
			return interpolation(s), true
		}
	}
	traversal, diags := hcl.AbsTraversalForExpr(expr)
	if diags.HasErrors() {
		return "", false
	}
	text, ok := formatTraversal(traversal)
	if !ok {
		return "", false
	}
	return interpolation(text), true
}

// interpolation wraps text as a template interpolation.
func interpolation(text string) string {
	return "${" + text + "}"
}

// formatTraversal renders traversal the way it is written in configuration.
func formatTraversal(traversal hcl.Traversal) (string, bool) {
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

// reference renders a bare reference: a value with no resolved part is its own
// text, and a partly resolved one keeps its resolved parts.
func (r *Renderer) reference(traversal hcl.Traversal) (cty.Value, bool) {
	if r.Reference != nil {
		if v, ok := r.Reference(traversal, r.ctx()); ok {
			return v, true
		}
	}
	text, ok := r.traversalText(traversal)
	if !ok {
		return cty.NilVal, false
	}
	v, diags := traversal.TraverseAbs(r.ctx())
	if diags.HasErrors() || !v.IsKnown() {
		return cty.StringVal(interpolation(text)), true
	}
	v, _ = v.UnmarkDeep()
	return substituteUnknowns(v, text), true
}

// referenceExpression also accepts an indexed reference when its selector is
// known in the current instance. A function-valued base remains an expression,
// not a reference whose result can be replaced by presentation text.
func (r *Renderer) referenceExpression(expr hclsyntax.Expression) (cty.Value, bool) {
	if t, diags := hcl.AbsTraversalForExpr(expr); !diags.HasErrors() {
		return r.reference(t)
	}
	if r.Reference != nil {
		if t, ok := ReferenceTraversal(expr, r.ctx()); ok {
			return r.Reference(t, r.ctx())
		}
	}
	return cty.NilVal, false
}

// ReferenceTraversal resolves known index selectors of a pure reference without
// evaluating its base. A coalesce with only known null/empty predecessors can
// select its final reference; transformations never become references.
func ReferenceTraversal(expr hcl.Expression, ctx *hcl.EvalContext) (hcl.Traversal, bool) {
	var parts []hcl.Traversal
	for {
		switch node := expr.(type) {
		case *hclsyntax.RelativeTraversalExpr:
			parts = append(parts, node.Traversal)
			expr = node.Source
		case *hclsyntax.IndexExpr:
			key, diags := node.Key.Value(ctx)
			if diags.HasErrors() {
				return nil, false
			}
			key, _ = key.Unmark()
			if !key.IsKnown() || key.IsNull() {
				return nil, false
			}
			parts = append(parts, hcl.Traversal{hcl.TraverseIndex{Key: key, SrcRange: node.Key.Range()}})
			expr = node.Collection
		case *hclsyntax.FunctionCallExpr:
			selected, ok := selectedCoalesce(node, ctx)
			if !ok {
				return nil, false
			}
			expr = selected
		case *hclsyntax.ParenthesesExpr:
			expr = node.Expression
		default:
			t, diags := hcl.AbsTraversalForExpr(expr)
			if diags.HasErrors() {
				return nil, false
			}
			t = append(hcl.Traversal{}, t...)
			for i := len(parts) - 1; i >= 0; i-- {
				t = append(t, parts[i]...)
			}
			return t, true
		}
	}
}

// selectedCoalesce uses only authoritative values to prove which expression
// supplies the result. Rendered JSON is never an argument to the function.
func selectedCoalesce(node *hclsyntax.FunctionCallExpr, ctx *hcl.EvalContext) (hcl.Expression, bool) {
	if node.Name != "coalesce" || node.ExpandFinal || len(node.Args) < 2 {
		return nil, false
	}
	if _, diags := node.Value(ctx); diags.HasErrors() {
		return nil, false
	}
	for _, arg := range node.Args[:len(node.Args)-1] {
		v, diags := arg.Value(ctx)
		if diags.HasErrors() || !v.IsKnown() {
			return nil, false
		}
		v, _ = v.Unmark()
		if !v.IsNull() && !v.RawEquals(cty.StringVal("")) {
			return nil, false
		}
	}
	return node.Args[len(node.Args)-1], true
}

// traversalText is a traversal as written, which keeps spellings such as
// list.0 that formatTraversal normalizes away.
func (r *Renderer) traversalText(traversal hcl.Traversal) (string, bool) {
	if r.Source != nil {
		if s, ok := r.Source(traversal.SourceRange()); ok {
			return s, true
		}
	}
	return formatTraversal(traversal)
}

// substitute returns expr with every unresolved part that is not placed whole
// into the value replaced by a literal of its rendering. Evaluating the result
// lets functions such as jsonencode or merge build their value around the text
// of what they could not resolve, while anything deciding on content (a
// condition, comparison or content-dependent function) is rendered whole
// rather than run on text the configuration does not have.
func (r *Renderer) substitute(expr hclsyntax.Expression) hclsyntax.Expression {
	if r.resolves(expr) {
		return expr
	}
	if f, ok := expr.(*hclsyntax.ForExpr); ok {
		return r.forLiteral(f)
	}
	children, ok := r.placedChildren(expr)
	if !ok {
		return r.leaf(expr)
	}
	substituted := make([]hclsyntax.Expression, len(children))
	for i, child := range children {
		substituted[i] = r.substitute(child)
	}
	return withChildren(expr, substituted)
}

func (r *Renderer) leaf(expr hclsyntax.Expression) hclsyntax.Expression {
	v, ok := r.renderWhole(expr)
	if !ok {
		v = cty.StringVal(UnknownPlaceholder)
	}
	return literal(v, expr.Range())
}

// renderWhole renders expr without looking into it: a reference keeps what
// resolves of its value, anything else is its own text.
func (r *Renderer) renderWhole(expr hclsyntax.Expression) (cty.Value, bool) {
	if v, ok := r.referenceExpression(expr); ok {
		return v, true
	}
	return r.textValue(expr)
}

func literal(v cty.Value, rng hcl.Range) hclsyntax.Expression {
	return &hclsyntax.LiteralValueExpr{Val: v, SrcRange: rng}
}

// placedChildren returns the subexpressions expr only places into its value,
// or false when expr decides something on them.
func (r *Renderer) placedChildren(expr hclsyntax.Expression) ([]hclsyntax.Expression, bool) {
	switch e := expr.(type) {
	case *hclsyntax.FunctionCallExpr:
		switch e.Name {
		case "format":
			return e.Args, len(e.Args) > 0 && r.placingFormat(e.Args[0])
		case templateFileFunc, "templatestring":
			return e.Args, len(e.Args) == 2 && r.placingTemplate(e.Name, e.Args[0])
		}
		return e.Args, placingFunctions[e.Name]
	case *hclsyntax.ConditionalExpr:
		return []hclsyntax.Expression{e.TrueResult, e.FalseResult}, r.resolves(e.Condition)
	case *hclsyntax.TemplateExpr:
		return e.Parts, true
	case *hclsyntax.TemplateWrapExpr:
		return []hclsyntax.Expression{e.Wrapped}, true
	case *hclsyntax.ParenthesesExpr:
		return []hclsyntax.Expression{e.Expression}, true
	case *hclsyntax.TupleConsExpr:
		return e.Exprs, true
	case *hclsyntax.ObjectConsExpr:
		values := make([]hclsyntax.Expression, len(e.Items))
		for i, item := range e.Items {
			if !r.resolves(item.KeyExpr) {
				return nil, false
			}
			values[i] = item.ValueExpr
		}
		return values, true
	}
	return nil, false
}

// withChildren returns a copy of expr, one placedChildren accepts, holding
// children instead.
func withChildren(expr hclsyntax.Expression, children []hclsyntax.Expression) hclsyntax.Expression {
	switch e := expr.(type) {
	case *hclsyntax.FunctionCallExpr:
		c := *e
		c.Args = children
		return &c
	case *hclsyntax.ConditionalExpr:
		c := *e
		c.TrueResult, c.FalseResult = children[0], children[1]
		return &c
	case *hclsyntax.TemplateExpr:
		c := *e
		c.Parts = children
		return &c
	case *hclsyntax.TemplateWrapExpr:
		c := *e
		c.Wrapped = children[0]
		return &c
	case *hclsyntax.ParenthesesExpr:
		c := *e
		c.Expression = children[0]
		return &c
	case *hclsyntax.TupleConsExpr:
		c := *e
		c.Exprs = children
		return &c
	case *hclsyntax.ObjectConsExpr:
		c := *e
		c.Items = make([]hclsyntax.ObjectConsItem, len(e.Items))
		for i, item := range e.Items {
			c.Items[i] = hclsyntax.ObjectConsItem{KeyExpr: item.KeyExpr, ValueExpr: children[i]}
		}
		return &c
	}
	return expr
}

// placesOnly reports whether expr only ever places the references it reads.
func (r *Renderer) placesOnly(expr hclsyntax.Expression) bool {
	switch e := expr.(type) {
	case *hclsyntax.RelativeTraversalExpr, *hclsyntax.IndexExpr:
		if r.Reference != nil && referenceShape(expr) {
			return true
		}
	case *hclsyntax.ForExpr:
		if r.Reference != nil && r.forPlacesOnly(e) {
			return true
		}
	case *hclsyntax.LiteralValueExpr, *hclsyntax.ScopeTraversalExpr, *hclsyntax.AnonSymbolExpr:
		return true
	}
	children, ok := r.placedChildren(expr)
	if !ok {
		return false
	}
	for _, child := range children {
		if !r.placesOnly(child) {
			return false
		}
	}
	return true
}

// referenceShape recognizes a reference before an enclosing loop has bound its
// index variables. Actual selectors still evaluate only in the child context.
func referenceShape(expr hcl.Expression) bool {
	for {
		switch e := expr.(type) {
		case *hclsyntax.RelativeTraversalExpr:
			expr = e.Source
		case *hclsyntax.IndexExpr:
			expr = e.Collection
		case *hclsyntax.ParenthesesExpr:
			expr = e.Expression
		default:
			_, diags := hcl.AbsTraversalForExpr(expr)
			return !diags.HasErrors()
		}
	}
}

// forLiteral evaluates a for expression over a resolved collection with every
// unresolved reference its body reads standing as text. Its body runs per
// element, so it is not substituted through: it must only place what it reads.
func (r *Renderer) forLiteral(e *hclsyntax.ForExpr) hclsyntax.Expression {
	if r.forPlacesOnly(e) {
		if r.Reference != nil {
			if v, ok := r.renderFor(e); ok {
				return literal(v, e.Range())
			}
			return r.leaf(e)
		}
		if v, ok := r.evalReferencesAsText(e); ok {
			return literal(v, e.Range())
		}
	}
	return r.leaf(e)
}

// renderFor renders only values. Collection membership, filters, and object
// keys must resolve in the authoritative per-element context before any
// presentation reference can contribute text.
func (r *Renderer) renderFor(e *hclsyntax.ForExpr) (cty.Value, bool) {
	collection, known := r.forCollection(e)
	if !known {
		return cty.NilVal, false
	}
	base, _ := ReferenceTraversal(e.CollExpr, r.ctx())
	if collection.Type().IsSetType() {
		base = nil
	}
	values := []cty.Value{}
	groups := map[string][]cty.Value{}
	for it := collection.ElementIterator(); it.Next(); {
		key, value := it.Element()
		child := r.forRenderer(e, key, value, base)
		include, known := child.forIncludes(e)
		if !known {
			return cty.NilVal, false
		}
		if !include {
			continue
		}
		name, known := child.forKey(e)
		if !known || (!e.Group && e.KeyExpr != nil && len(groups[name]) != 0) {
			return cty.NilVal, false
		}
		rendered, ok := child.Render(e.ValExpr)
		if !ok || !rendered.IsWhollyKnown() {
			return cty.NilVal, false
		}
		if e.KeyExpr == nil {
			values = append(values, rendered)
		} else {
			groups[name] = append(groups[name], rendered)
		}
	}
	if e.KeyExpr == nil {
		return cty.TupleVal(values), true
	}
	return forObject(groups, e.Group), true
}

func forObject(groups map[string][]cty.Value, grouped bool) cty.Value {
	object := make(map[string]cty.Value, len(groups))
	for key, values := range groups {
		if grouped {
			object[key] = cty.TupleVal(values)
		} else {
			object[key] = values[0]
		}
	}
	return cty.ObjectVal(object)
}

func (r *Renderer) forCollection(e *hclsyntax.ForExpr) (cty.Value, bool) {
	collection, diags := e.CollExpr.Value(r.ctx())
	if diags.HasErrors() || !collection.IsKnown() || collection.IsNull() || !collection.CanIterateElements() {
		return cty.NilVal, false
	}
	collection, _ = collection.Unmark()
	if !collection.Length().IsKnown() {
		return cty.NilVal, false
	}
	return collection, true
}

// forRenderer preserves provenance when a loop value aliases an element of a
// referenced collection. It remaps references, never the authoritative value.
func (r *Renderer) forRenderer(e *hclsyntax.ForExpr, key, value cty.Value, base hcl.Traversal) *Renderer {
	vars := make(map[string]cty.Value, 2)
	if e.KeyVar != "" {
		vars[e.KeyVar] = key
	}
	vars[e.ValVar] = value
	var aliases map[string]hcl.Traversal
	if len(base) != 0 {
		alias := append(append(hcl.Traversal{}, base...), hcl.TraverseIndex{Key: key})
		aliases = map[string]hcl.Traversal{e.ValVar: alias}
	}
	return r.withBindings(vars, aliases)
}

func (r *Renderer) forIncludes(e *hclsyntax.ForExpr) (include, known bool) {
	if e.CondExpr == nil {
		return true, true
	}
	value, diags := e.CondExpr.Value(r.ctx())
	if diags.HasErrors() {
		return false, false
	}
	value, err := ctyconvert.Convert(value, cty.Bool)
	if err != nil || !value.IsKnown() || value.IsNull() {
		return false, false
	}
	value, _ = value.Unmark()
	return value.True(), true
}

func (r *Renderer) forKey(e *hclsyntax.ForExpr) (string, bool) {
	if e.KeyExpr == nil {
		return "", true
	}
	value, diags := e.KeyExpr.Value(r.ctx())
	if diags.HasErrors() {
		return "", false
	}
	value, err := ctyconvert.Convert(value, cty.String)
	if err != nil || !value.IsKnown() || value.IsNull() {
		return "", false
	}
	value, _ = value.Unmark()
	return value.AsString(), true
}

func (r *Renderer) forPlacesOnly(e *hclsyntax.ForExpr) bool {
	if r.Reference != nil {
		return r.placesOnly(e.ValExpr)
	}
	if e.KeyExpr != nil && !r.placesOnly(e.KeyExpr) {
		return false
	}
	if !r.placesOnly(e.ValExpr) {
		return false
	}
	if e.CondExpr == nil {
		return r.placesOnly(e.CollExpr)
	}
	if !r.resolves(e.CollExpr) {
		return false
	}
	for _, traversal := range e.CondExpr.Variables() {
		if root := traversal.RootName(); root == e.KeyVar || root == e.ValVar {
			continue
		}
		v, diags := traversal.TraverseAbs(r.ctx())
		if diags.HasErrors() || !v.IsWhollyKnown() {
			return false
		}
	}
	return true
}

func (r *Renderer) evalReferencesAsText(expr hclsyntax.Expression) (cty.Value, bool) {
	o := newOverlay(r.ctx())
	for _, traversal := range longestFirst(expr.Variables()) {
		v, diags := traversal.TraverseAbs(r.ctx())
		if !diags.HasErrors() && v.IsWhollyKnown() {
			continue
		}
		text, ok := r.traversalText(traversal)
		if !ok {
			return cty.NilVal, false
		}
		leaf := cty.StringVal(interpolation(text))
		if !diags.HasErrors() {
			v, _ = v.UnmarkDeep()
			leaf = substituteUnknowns(v, text)
		}
		o.set(traversal, leaf)
	}
	if o.empty() {
		return cty.NilVal, false
	}
	v, diags := expr.Value(o.context())
	if diags.HasErrors() || !v.IsWhollyKnown() {
		return cty.NilVal, false
	}
	v, _ = v.UnmarkDeep()
	return v, true
}

func (r *Renderer) resolves(expr hclsyntax.Expression) bool {
	v, diags := expr.Value(r.ctx())
	return !diags.HasErrors() && v.IsWhollyKnown()
}

// placingFunctions only place their arguments into their result, so an
// argument standing as text cannot change anything else about it. Functions
// that branch on content (coalesce, lookup, compact, try, templatestring, ...),
// compare or reshape it (distinct, toset, flatten, formatlist, ...), convert
// neighboring values to a common type (tolist, tomap) or rewrite it (lower,
// replace, base64encode, ...) are left out. format places only through plain
// verbs; see placingFormat.
var placingFunctions = map[string]bool{
	"concat":     true,
	"element":    true,
	"join":       true,
	"jsondecode": true,
	"jsonencode": true,
	"keys":       true,
	"merge":      true,
	"tostring":   true,
	"values":     true,
	"yamldecode": true,
	"yamlencode": true,
	"zipmap":     true,
}

// placingFormat reports whether a format string resolves and only uses verbs
// that write their argument as is: a width, precision or flag would pad or cut
// the text standing for an unresolved argument.
func (r *Renderer) placingFormat(spec hclsyntax.Expression) bool {
	v, diags := spec.Value(r.ctx())
	s, ok := ctyutil.ConcreteString(v)
	if diags.HasErrors() || !ok {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			continue
		}
		i++
		if i == len(s) || !strings.ContainsRune("sv%", rune(s[i])) {
			return false
		}
	}
	return true
}

// placingTemplate reports whether the template a templatefile or
// templatestring call renders only interpolates bare variables, with no
// directive or expression that could decide on or rewrite their text.
func (r *Renderer) placingTemplate(name string, arg hclsyntax.Expression) bool {
	v, diags := arg.Value(r.ctx())
	s, ok := ctyutil.ConcreteString(v)
	if diags.HasErrors() || !ok {
		return false
	}
	if name == templateFileFunc {
		file, ok := r.ctx().Functions["file"]
		if !ok {
			return false
		}
		content, err := file.Call([]cty.Value{cty.StringVal(s)})
		if s, ok = ctyutil.ConcreteString(content); err != nil || !ok {
			return false
		}
	}
	tmpl, diags := hclsyntax.ParseTemplate([]byte(s), name, hcl.InitialPos)
	if diags.HasErrors() {
		return false
	}
	placing := true
	_ = hclsyntax.VisitAll(tmpl, func(node hclsyntax.Node) hcl.Diagnostics {
		switch n := node.(type) {
		case *hclsyntax.TemplateExpr, *hclsyntax.TemplateWrapExpr, *hclsyntax.LiteralValueExpr:
		case *hclsyntax.ScopeTraversalExpr:
			placing = placing && len(n.Traversal) == 1
		default:
			placing = false
		}
		return nil
	})
	return placing
}

// renderParts rebuilds the constructors evaluation could not substitute
// through from their rendered parts, and renders anything else as its text.
func (r *Renderer) renderParts(expr hclsyntax.Expression) (cty.Value, bool) {
	switch e := expr.(type) {
	case *hclsyntax.TemplateWrapExpr:
		return r.Render(e.Wrapped)
	case *hclsyntax.TemplateExpr:
		var b strings.Builder
		for _, part := range e.Parts {
			b.WriteString(r.StringPart(part))
		}
		return cty.StringVal(b.String()), true
	case *hclsyntax.TupleConsExpr:
		if len(e.Exprs) == 0 {
			return cty.EmptyTupleVal, true
		}
		elems := make([]cty.Value, len(e.Exprs))
		for i, elem := range e.Exprs {
			elems[i] = r.renderOrPlaceholder(elem)
		}
		return cty.TupleVal(elems), true
	case *hclsyntax.ObjectConsExpr:
		attrs := make(map[string]cty.Value, len(e.Items))
		for _, item := range e.Items {
			key, diags := item.KeyExpr.Value(r.ctx())
			name, ok := ctyutil.ConcreteString(key)
			if diags.HasErrors() || !ok {
				return r.textValue(expr)
			}
			attrs[name] = r.renderOrPlaceholder(item.ValueExpr)
		}
		if len(attrs) == 0 {
			return cty.EmptyObjectVal, true
		}
		return cty.ObjectVal(attrs), true
	}
	return r.textValue(expr)
}

func (r *Renderer) textValue(expr hclsyntax.Expression) (cty.Value, bool) {
	s, ok := r.Text(expr)
	if !ok {
		return cty.NilVal, false
	}
	return cty.StringVal(s), true
}

func (r *Renderer) renderOrPlaceholder(expr hclsyntax.Expression) cty.Value {
	if v, ok := r.Render(expr); ok {
		return v
	}
	return cty.StringVal(UnknownPlaceholder)
}

// StringPart is the text a template part contributes: its value when it
// renders to a string, its own interpolation otherwise.
func (r *Renderer) StringPart(part hclsyntax.Expression) string {
	if v, ok := r.Render(part); ok {
		if s, err := ctyconvert.Convert(v, cty.String); err == nil {
			if str, ok := ctyutil.ConcreteString(s); ok {
				return str
			}
		}
	}
	if s, ok := r.Text(part); ok {
		return s
	}
	return UnknownPlaceholder
}

// Evaluate evaluates an expression and retries failed reference traversals as
// unknowns, preserving known siblings. Remaining expression errors are returned
// separately; callers must not infer a successful evaluation from an unknown
// fallback value. Reference recovery remains permissive and does not validate
// declarations or provider schemas.
func Evaluate(expr hcl.Expression, ctx *hcl.EvalContext) (cty.Value, hcl.Diagnostics) {
	value, diagnostics := expr.Value(ctx)
	if !diagnostics.HasErrors() {
		return value, diagnostics
	}
	o := newOverlay(ctx)
	for _, traversal := range longestFirst(expr.Variables()) {
		if _, diags := traversal.TraverseAbs(ctx); diags.HasErrors() {
			o.set(traversal, cty.DynamicVal)
		}
	}
	if o.empty() {
		return cty.DynamicVal, diagnostics
	}
	value, diagnostics = expr.Value(o.context())
	if diagnostics.HasErrors() {
		return cty.DynamicVal, diagnostics
	}
	return value, diagnostics
}

// longestFirst orders traversals so one reading a prefix of another is set
// last in an overlay, covering the longer one rather than being replaced by it.
func longestFirst(traversals []hcl.Traversal) []hcl.Traversal {
	sort.SliceStable(traversals, func(i, j int) bool {
		return len(traversals[i]) > len(traversals[j])
	})
	return traversals
}

// overlay shadows the values some traversals read in a context.
//
// A root whose first step is an attribute name keeps its attributes in a map
// until context() builds the object: setting each of n traversals under one
// root by rebuilding the root object made an expression reading n attributes
// of module or local cost n^2.
type overlay struct {
	ctx  *hcl.EvalContext
	vars map[string]cty.Value
	// objects holds, by root, the attributes of a root set through an
	// attribute step, built into vars by context().
	objects map[string]map[string]cty.Value
}

func newOverlay(ctx *hcl.EvalContext) *overlay {
	return &overlay{ctx: ctx}
}

func (o *overlay) empty() bool {
	return len(o.vars) == 0 && len(o.objects) == 0
}

func (o *overlay) set(traversal hcl.Traversal, leaf cty.Value) {
	if o.vars == nil {
		o.vars = map[string]cty.Value{}
	}
	root := traversal.RootName()
	if attrs, ok := o.objects[root]; ok {
		if len(traversal) == 1 {
			delete(o.objects, root)
			o.vars[root] = leaf
			return
		}
		// Any other step leaves an object as it is, as setPath does.
		if key, ok := attributeStep(traversal[1]); ok {
			child, childHas := attrs[key]
			attrs[key] = setPath(child, childHas, traversal[2:], leaf)
		}
		return
	}
	base, has := o.vars[root]
	if !has {
		base, has = lookupVariable(o.ctx, root)
	}
	if len(traversal) > 1 {
		if key, ok := attributeStep(traversal[1]); ok {
			attrs := objectAttributes(base, has)
			child, childHas := attrs[key]
			attrs[key] = setPath(child, childHas, traversal[2:], leaf)
			if o.objects == nil {
				o.objects = map[string]map[string]cty.Value{}
			}
			o.objects[root] = attrs
			delete(o.vars, root)
			return
		}
	}
	o.vars[root] = setPath(base, has, traversal[1:], leaf)
}

func (o *overlay) context() *hcl.EvalContext {
	for root, attrs := range o.objects {
		o.vars[root] = cty.ObjectVal(attrs)
	}
	o.objects = nil
	child := o.ctx.NewChild()
	child.Variables = o.vars
	return child
}

// attributeStep returns the attribute a step names when setPath sets it as
// an object attribute.
func attributeStep(step hcl.Traverser) (string, bool) {
	switch s := step.(type) {
	case hcl.TraverseAttr:
		return s.Name, true
	case hcl.TraverseIndex:
		if ctyutil.Materialized(s.Key) && s.Key.Type() == cty.String {
			return s.Key.AsString(), true
		}
	}
	return "", false
}

// objectAttributes returns a copy of the attributes setPath starts an object
// from: base's own when it is a known object or map, none otherwise.
func objectAttributes(base cty.Value, has bool) map[string]cty.Value {
	attrs := map[string]cty.Value{}
	if !has {
		return attrs
	}
	base, _ = base.Unmark()
	if ctyutil.Materialized(base) && (base.Type().IsObjectType() || base.Type().IsMapType()) {
		for k, v := range base.AsValueMap() {
			attrs[k] = v
		}
	}
	return attrs
}

// lookupVariable finds name the way evaluation does, innermost context first.
func lookupVariable(ctx *hcl.EvalContext, name string) (cty.Value, bool) {
	for c := ctx; c != nil; c = c.Parent() {
		if v, ok := c.Variables[name]; ok {
			return v, true
		}
	}
	return cty.NilVal, false
}

// substituteUnknowns replaces every unknown part of v with the interpolation of
// its path, keeping what is known.
func substituteUnknowns(v cty.Value, path string) cty.Value {
	if !v.IsKnown() {
		return cty.StringVal(interpolation(path))
	}
	if v.IsNull() || v.IsWhollyKnown() {
		return v
	}
	ty := v.Type()
	switch {
	case ty.IsListType() || ty.IsTupleType() || ty.IsSetType():
		elems := v.AsValueSlice()
		out := make([]cty.Value, len(elems))
		for i, elem := range elems {
			out[i] = substituteUnknowns(elem, path+"["+strconv.Itoa(i)+"]")
		}
		return cty.TupleVal(out)
	case ty.IsMapType() || ty.IsObjectType():
		elems := v.AsValueMap()
		out := make(map[string]cty.Value, len(elems))
		for key, elem := range elems {
			out[key] = substituteUnknowns(elem, path+attrStep(key))
		}
		return cty.ObjectVal(out)
	}
	return cty.StringVal(interpolation(path))
}

func attrStep(key string) string {
	if hclsyntax.ValidIdentifier(key) {
		return "." + key
	}
	return "[" + strconv.Quote(key) + "]"
}

// setPath returns base with the value at steps replaced by leaf, creating the
// objects on the way where base has none. A step base cannot take, such as an
// index past the end of a list, leaves base as it is.
func setPath(base cty.Value, has bool, steps hcl.Traversal, leaf cty.Value) cty.Value {
	if len(steps) == 0 {
		return leaf
	}
	if has {
		base, _ = base.Unmark()
	}
	materialized := has && ctyutil.Materialized(base)
	var key string
	switch s := steps[0].(type) {
	case hcl.TraverseAttr:
		key = s.Name
	case hcl.TraverseIndex:
		if !ctyutil.Materialized(s.Key) {
			return base
		}
		if s.Key.Type() == cty.Number {
			idx, ok := ctyutil.LiteralInt(s.Key)
			if !ok || idx < 0 {
				return base
			}
			return setIndex(base, materialized, idx, steps[1:], leaf)
		}
		if s.Key.Type() != cty.String {
			return base
		}
		key = s.Key.AsString()
	default:
		return base
	}
	attrs := map[string]cty.Value{}
	if materialized && (base.Type().IsObjectType() || base.Type().IsMapType()) {
		for k, v := range base.AsValueMap() {
			attrs[k] = v
		}
	}
	child, childHas := attrs[key]
	attrs[key] = setPath(child, childHas, steps[1:], leaf)
	return cty.ObjectVal(attrs)
}

func setIndex(base cty.Value, materialized bool, idx int, rest hcl.Traversal, leaf cty.Value) cty.Value {
	ty := cty.NilType
	if materialized {
		ty = base.Type()
	}
	if materialized && (ty.IsListType() || ty.IsTupleType()) {
		elems := base.AsValueSlice()
		if idx >= len(elems) {
			return base
		}
		elems[idx] = setPath(elems[idx], true, rest, leaf)
		return cty.TupleVal(elems)
	}
	if materialized {
		return base
	}
	elems := make([]cty.Value, idx+1)
	for i := range elems {
		elems[i] = cty.DynamicVal
	}
	elems[idx] = setPath(cty.NilVal, false, rest, leaf)
	return cty.TupleVal(elems)
}
