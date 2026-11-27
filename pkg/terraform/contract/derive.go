/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package contract

import (
	"bytes"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/jsonfilter"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/address"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/dynamicblock"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/DataDog/datadog-iac-scanner/pkg/policy"
	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/refs"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

const (
	maxLocalAliasDepth = 16
	iamPolicyDocType   = "aws_iam_policy_document"
	defaultIAMVersion  = "2012-10-17"
	defaultIAMEffect   = "Allow"
	iamBlockStatement  = "statement"
	iamBlockPrincipals = "principals"
	iamBlockNotPrinc   = "not_principals"
	iamBlockCondition  = "condition"
)

// DeriveOptions controls which demand-driven derivations are populated.
type DeriveOptions struct {
	ParseJSON      bool
	JSONTypes      map[string]bool // when non-nil, only derive JSON on matching resource bucket keys
	ParseFilterAST bool
}

// deriveResource populates demand-driven DerivedData (parsed JSON documents +
// typed json_refs, CloudWatch metric filter ASTs, and template parts) on res.
// nolint:gocyclo
func deriveResource(
	res *policy.Resource,
	body *hclsyntax.Body,
	scope *tfeval.ModuleScope,
	iteration map[string]cty.Value,
	opts DeriveOptions,
	sources ...*tfeval.ResolvedResource,
) {
	if res == nil {
		return
	}
	d := &policy.DerivedData{}

	// 1. CloudWatch metric filter AST (demand-driven on filter resources).
	if opts.ParseFilterAST && res.Type == typeCloudWatchMetricFilter {
		if pat, ok := res.Attributes["pattern"].(string); ok && pat != "" {
			if astMap, parsed := jsonfilter.Parse(pat); parsed {
				d.FilterExpr = map[string]any{"pattern": astMap}
			}
		}
	}

	wantJSON := opts.ParseJSON && (len(opts.JSONTypes) == 0 || opts.JSONTypes[res.BucketKey()])
	if wantJSON {
		// 2a. Concrete JSON string attributes (top-level and nested blocks).
		deriveConcreteJSONStrings(d, res.Attributes, "")

		// 2b. Partially known jsonencode(...), JSON heredocs, local.* aliases,
		// and data.aws_iam_policy_document.*.json references (top-level & nested).
		if body != nil {
			var evalCtx *hcl.EvalContext
			getCtx := func(expression hclsyntax.Expression) *hcl.EvalContext {
				if evalCtx == nil {
					if scope != nil {
						evalCtx = scope.EvalContext()
					}
					if evalCtx == nil {
						evalCtx = &hcl.EvalContext{}
					}
					if len(iteration) > 0 {
						child := evalCtx.NewChild()
						child.Variables = iteration
						evalCtx = child
					}
				}
				if len(sources) > 0 && sources[0] != nil {
					return sources[0].EvalContextForFile(expression.Range().Filename, evalCtx)
				}
				return evalCtx
			}
			var dynCounts tfeval.DynamicCounts
			if len(sources) > 0 && sources[0] != nil {
				dynCounts = sources[0].DynamicCounts
			}
			deriveBodyUnknownJSON(d, body, "", resourceMetaArgs, res, scope, getCtx, dynCounts)
		}
	}

	if len(d.JSON) > 0 || len(d.JSONUnknown) > 0 || len(d.JSONRefs) > 0 ||
		len(d.FilterExpr) > 0 || len(d.TemplateParts) > 0 {
		res.Derived = d
	}
}

func deriveConcreteJSONStrings(d *policy.DerivedData, m map[string]any, prefix string) {
	for name, val := range m {
		pk := policy.JoinPathKey(prefix, policy.Key(name))
		switch typed := val.(type) {
		case string:
			if doc, parsed := tryUnmarshalJSONString(typed); parsed {
				if d.JSON == nil {
					d.JSON = make(map[string]any)
				}
				d.JSON[pk] = doc
			}
		case []any:
			for i, elem := range typed {
				if sub, ok := elem.(map[string]any); ok && !policy.IsUnknownSlot(sub) {
					deriveConcreteJSONStrings(d, sub, policy.JoinPathKey(pk, policy.Index(int64(i))))
				}
			}
		}
	}
}

func deriveBodyUnknownJSON(
	d *policy.DerivedData,
	body *hclsyntax.Body,
	prefix string,
	skipMeta map[string]bool,
	res *policy.Resource,
	scope *tfeval.ModuleScope,
	getCtx func(hclsyntax.Expression) *hcl.EvalContext,
	dynCounts tfeval.DynamicCounts,
) {
	if body == nil {
		return
	}
	for name, attr := range body.Attributes {
		if skipMeta[name] {
			continue
		}
		pk := policy.JoinPathKey(prefix, policy.Key(name))
		if d.JSON != nil {
			if _, already := d.JSON[pk]; already {
				continue
			}
		}
		if !res.State.Unknown[pk] {
			continue
		}
		deriveUnknownExpr(d, pk, attr.Expr, scope, getCtx(attr.Expr), 0)
	}
	idxByType := map[string]int{}
	unknownTypes := map[string]bool{}
	for _, blk := range body.Blocks {
		if blk.Type == blockTypeDynamic {
			if !dynamicblock.Is(blk) {
				continue
			}
			generatedType := dynamicblock.GeneratedType(blk)
			count := dynCounts[blk]
			if count == tfeval.DynamicKeptAsWritten {
				continue
			}
			if count < 0 {
				unknownTypes[generatedType] = true
				continue
			}
			idxByType[generatedType] += count
			continue
		}
		if skipMeta[blk.Type] || unknownTypes[blk.Type] {
			continue
		}
		pos := idxByType[blk.Type]
		idxByType[blk.Type] = pos + 1
		elemPrefix := policy.JoinPathKey(policy.JoinPathKey(prefix, policy.Key(blk.Type)), policy.Index(int64(pos)))
		deriveBodyUnknownJSON(d, blk.Body, elemPrefix, nil, res, scope, getCtx, dynCounts)
	}
}

func tryUnmarshalJSONString(s string) (any, bool) {
	trimmed := strings.TrimSpace(s)
	if len(trimmed) < 2 || (trimmed[0] != '{' && trimmed[0] != '[') {
		return nil, false
	}
	dec := json.NewDecoder(strings.NewReader(trimmed))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, false
	}
	return doc, true
}

func deriveUnknownExpr(
	d *policy.DerivedData,
	attrName string,
	expr hclsyntax.Expression,
	scope *tfeval.ModuleScope,
	ctx *hcl.EvalContext,
	depth int,
) {
	if expr == nil || depth > maxLocalAliasDepth {
		return
	}
	switch e := expr.(type) {
	case *hclsyntax.ParenthesesExpr:
		deriveUnknownExpr(d, attrName, e.Expression, scope, ctx, depth+1)
	case *hclsyntax.TemplateWrapExpr:
		deriveUnknownExpr(d, attrName, e.Wrapped, scope, ctx, depth+1)
	case *hclsyntax.ScopeTraversalExpr:
		deriveTraversalExpr(d, attrName, e, scope, ctx, depth)
	case *hclsyntax.FunctionCallExpr:
		if e.Name == functionJSONEncode && len(e.Args) == 1 {
			unk := map[string]bool{}
			jrefs := map[string][]policy.TypedRef{}
			doc, ok := evalJSONEncodeExpr(e.Args[0], scope, ctx, "", unk, jrefs, &jsonTemplateCollector{d, attrName})
			recordDerivedJSON(d, attrName, doc, ok, unk, jrefs)
		}
	case *hclsyntax.TemplateExpr:
		deriveJSONTemplate(d, attrName, e, scope, ctx)
	}
}

func deriveTraversalExpr(
	d *policy.DerivedData,
	attrName string,
	e *hclsyntax.ScopeTraversalExpr,
	scope *tfeval.ModuleScope,
	ctx *hcl.EvalContext,
	depth int,
) {
	if scope == nil {
		return
	}
	r := refs.Parse(e.Traversal)
	switch {
	case r.Kind == refs.KindLocal && r.Name != "":
		if localExpr, ok := scope.Locals[r.Name]; ok {
			deriveUnknownExpr(d, attrName, localExpr, scope, ctx, depth+1)
		}
	case r.Kind == refs.KindData && r.Type == iamPolicyDocType && r.Name != "" &&
		(r.FirstAttr() == "json" || r.FirstAttr() == "minified_json"):
		if blk := findDataBlock(scope, iamPolicyDocType, r.Name); blk != nil {
			unk := map[string]bool{}
			jrefs := map[string][]policy.TypedRef{}
			// Evaluate the data block in its module scope without leaking the
			// referring resource's each/count iteration context.
			dataCtx := ctx.NewChild()
			dataCtx.Variables = map[string]cty.Value{"each": cty.DynamicVal, "count": cty.DynamicVal}
			doc := buildPartialIAMPolicyDoc(blk.Body, scope, dataCtx, unk, jrefs, &jsonTemplateCollector{d, attrName})
			recordDerivedJSON(d, attrName, doc, doc != nil, unk, jrefs)
		}
	}
}

func recordDerivedJSON(
	d *policy.DerivedData,
	attrName string,
	doc any,
	hasDoc bool,
	unk map[string]bool,
	jrefs map[string][]policy.TypedRef,
) {
	if hasDoc {
		if d.JSON == nil {
			d.JSON = make(map[string]any)
		}
		d.JSON[attrName] = doc
	}
	if len(unk) > 0 {
		if d.JSONUnknown == nil {
			d.JSONUnknown = make(map[string]map[string]bool)
		}
		d.JSONUnknown[attrName] = unk
	}
	if len(jrefs) > 0 {
		if d.JSONRefs == nil {
			d.JSONRefs = make(map[string]map[string][]policy.TypedRef)
		}
		d.JSONRefs[attrName] = jrefs
	}
}

func findDataBlock(scope *tfeval.ModuleScope, typ, name string) *hclsyntax.Block {
	if scope == nil {
		return nil
	}
	for _, body := range scope.Bodies {
		for _, blk := range body.Blocks {
			if blk.Type == address.KindData && len(blk.Labels) >= 2 && blk.Labels[0] == typ && blk.Labels[1] == name {
				return blk
			}
		}
	}
	return nil
}

// buildPartialIAMPolicyDoc synthesizes a JSON IAM policy object from a
// `data "aws_iam_policy_document"` block whose identifiers/conditions contain
// unknown expressions, preserving concrete statements and recording typed refs.
// nolint:gocyclo
func buildPartialIAMPolicyDoc(
	body *hclsyntax.Body,
	scope *tfeval.ModuleScope,
	ctx *hcl.EvalContext,
	unk map[string]bool,
	jrefs map[string][]policy.TypedRef,
	collector *jsonTemplateCollector,
) map[string]any {
	if body == nil {
		return nil
	}
	version := defaultIAMVersion
	if attr, ok := body.Attributes["version"]; ok {
		if v, diags := attr.Expr.Value(ctx); !diags.HasErrors() {
			if s, ok := ctyStringValue(v); ok {
				version = s
			}
		}
	}
	for _, mergeKey := range []string{"source_policy_documents", "override_policy_documents", "source_json", "override_json"} {
		if attr, ok := body.Attributes[mergeKey]; ok {
			unk["Statement"] = true
			if tr := extractTypedRefs(attr.Expr, scope, 0); len(tr) > 0 {
				jrefs["Statement"] = append(jrefs["Statement"], tr...)
			}
		}
	}
	var statements []any
	stmtIdx := 0
	for _, blk := range body.Blocks {
		if blk.Type == blockTypeDynamic {
			if dynamicblock.Is(blk) && dynamicblock.GeneratedType(blk) == iamBlockStatement {
				unk["Statement"] = true
			}
			continue
		}
		if blk.Type != iamBlockStatement {
			continue
		}
		stmtPrefix := policy.JoinPathKey(policy.PathKey(policy.Path{policy.Key("Statement")}), policy.Index(int64(stmtIdx)))
		stmtIdx++
		stmt := map[string]any{"Effect": defaultIAMEffect}
		evalAttrInto := func(hclKey, jsonKey string, deleteIfUnknown bool) {
			attr, ok := blk.Body.Attributes[hclKey]
			if !ok {
				return
			}
			leaf := policy.JoinPathKey(stmtPrefix, policy.Key(jsonKey))
			if val, ok := evalJSONEncodeExpr(attr.Expr, scope, ctx, leaf, unk, jrefs, collector); ok {
				stmt[jsonKey] = val
			} else if deleteIfUnknown {
				delete(stmt, jsonKey)
			}
		}
		evalAttrInto("sid", "Sid", false)
		evalAttrInto("effect", "Effect", true)
		evalAttrInto("actions", "Action", false)
		evalAttrInto("not_actions", "NotAction", false)
		evalAttrInto("resources", "Resource", false)
		evalAttrInto("not_resources", "NotResource", false)

		principals := map[string]any{}
		notPrincipals := map[string]any{}
		conditions := map[string]map[string]any{}
		for _, sub := range blk.Body.Blocks {
			switch sub.Type {
			case blockTypeDynamic:
				if !dynamicblock.Is(sub) {
					continue
				}
				switch dynamicblock.GeneratedType(sub) {
				case iamBlockPrincipals:
					unk[policy.JoinPathKey(stmtPrefix, policy.Key("Principal"))] = true
				case iamBlockNotPrinc:
					unk[policy.JoinPathKey(stmtPrefix, policy.Key("NotPrincipal"))] = true
				case iamBlockCondition:
					unk[policy.JoinPathKey(stmtPrefix, policy.Key("Condition"))] = true
				}
			case iamBlockPrincipals:
				evalIAMPrincipalBlock(sub.Body, scope, ctx, policy.JoinPathKey(stmtPrefix, policy.Key("Principal")), principals, unk, jrefs, collector)
			case iamBlockNotPrinc:
				evalIAMPrincipalBlock(
					sub.Body, scope, ctx, policy.JoinPathKey(stmtPrefix, policy.Key("NotPrincipal")),
					notPrincipals, unk, jrefs, collector,
				)
			case iamBlockCondition:
				evalIAMConditionBlock(sub.Body, scope, ctx, policy.JoinPathKey(stmtPrefix, policy.Key("Condition")), conditions, unk, jrefs, collector)
			}
		}
		if len(principals) > 0 {
			stmt["Principal"] = principals
		}
		if len(notPrincipals) > 0 {
			stmt["NotPrincipal"] = notPrincipals
		}
		if len(conditions) > 0 {
			condOut := make(map[string]any, len(conditions))
			for test, vars := range conditions {
				condOut[test] = vars
			}
			stmt["Condition"] = condOut
		}
		statements = append(statements, stmt)
	}
	if len(statements) == 0 {
		return nil
	}
	return map[string]any{
		"Version":   version,
		"Statement": statements,
	}
}

func evalIAMPrincipalBlock(
	body *hclsyntax.Body,
	scope *tfeval.ModuleScope,
	ctx *hcl.EvalContext,
	parentLeaf string,
	dst map[string]any,
	unk map[string]bool,
	jrefs map[string][]policy.TypedRef,
	collector *jsonTemplateCollector,
) {
	if body == nil {
		return
	}
	pType := ""
	if ta, ok := body.Attributes["type"]; ok {
		if v, diags := ta.Expr.Value(ctx); !diags.HasErrors() {
			pType, _ = ctyStringValue(v)
		}
	}
	if pType == "" {
		unk[parentLeaf] = true
		return
	}
	ia, ok := body.Attributes["identifiers"]
	if !ok {
		return
	}
	leaf := policy.JoinPathKey(parentLeaf, policy.Key(pType))
	subUnk := map[string]bool{}
	subRefs := map[string][]policy.TypedRef{}
	val, ok := evalJSONEncodeExpr(ia.Expr, scope, ctx, leaf, subUnk, subRefs, collector)
	for k, v := range subUnk {
		unk[k] = v
	}
	for k, list := range subRefs {
		jrefs[k] = append(jrefs[k], list...)
	}
	if !ok {
		return
	}
	existing, hasExisting := dst[pType]
	if !hasExisting {
		dst[pType] = val
		return
	}
	// Merge multiple principals blocks of the same type instead of overwriting.
	dst[pType] = mergePrincipalValues(existing, val)
}

func mergePrincipalValues(a, b any) []any {
	toSlice := func(v any) []any {
		if s, ok := v.([]any); ok {
			return s
		}
		return []any{v}
	}
	as := toSlice(a)
	bs := toSlice(b)
	merged := make([]any, 0, len(as)+len(bs))
	merged = append(merged, as...)
	merged = append(merged, bs...)
	return merged
}

func evalIAMConditionBlock(
	body *hclsyntax.Body,
	scope *tfeval.ModuleScope,
	ctx *hcl.EvalContext,
	condLeaf string,
	dst map[string]map[string]any,
	unk map[string]bool,
	jrefs map[string][]policy.TypedRef,
	collector *jsonTemplateCollector,
) {
	if body == nil {
		return
	}
	testStr, varStr := "", ""
	if ta, ok := body.Attributes["test"]; ok {
		if v, diags := ta.Expr.Value(ctx); !diags.HasErrors() {
			testStr, _ = ctyStringValue(v)
		}
	}
	if va, ok := body.Attributes["variable"]; ok {
		if v, diags := va.Expr.Value(ctx); !diags.HasErrors() {
			varStr, _ = ctyStringValue(v)
		}
	}
	if testStr == "" || varStr == "" {
		unk[condLeaf] = true
		return
	}
	valAttr, ok := body.Attributes["values"]
	if !ok {
		return
	}
	leaf := policy.JoinPathKey(policy.JoinPathKey(condLeaf, policy.Key(testStr)), policy.Key(varStr))
	val, ok := evalJSONEncodeExpr(valAttr.Expr, scope, ctx, leaf, unk, jrefs, collector)
	if dst[testStr] == nil {
		dst[testStr] = make(map[string]any)
	}
	if !ok {
		unk[leaf] = true
		return
	}
	dst[testStr][varStr] = val
}

// evalJSONEncodeExpr evaluates a jsonencode(...) HCL argument directly into
// concrete Go JSON values, preserving exact array indices via policy.UnknownSlot()
// while recording unknown paths and typed reference provenance deterministically.
// nolint:gocyclo
func evalJSONEncodeExpr(
	expr hclsyntax.Expression,
	scope *tfeval.ModuleScope,
	ctx *hcl.EvalContext,
	leafPath string,
	unk map[string]bool,
	jrefs map[string][]policy.TypedRef,
	collector *jsonTemplateCollector,
) (any, bool) {
	if expr == nil {
		return nil, false
	}
	val, valDiags := expr.Value(ctx)
	if !valDiags.HasErrors() && val.IsWhollyKnown() {
		if conv, ok := convertPartialCtyJSON(val, leafPath, unk); ok {
			return conv, true
		}
		if val.IsNull() {
			return nil, true
		}
	}

	if collector != nil && val != cty.NilVal && (val.Type() == cty.String || val.Type() == cty.DynamicPseudoType) {
		collector.record(leafPath, sourceStringParts(expr, scope, ctx, 0))
	}

	switch e := expr.(type) {
	case *hclsyntax.ParenthesesExpr:
		return evalJSONEncodeExpr(e.Expression, scope, ctx, leafPath, unk, jrefs, collector)
	case *hclsyntax.ObjectConsExpr:
		out := make(map[string]any, len(e.Items))
		for _, item := range e.Items {
			kv, diags := item.KeyExpr.Value(ctx)
			if diags.HasErrors() || !kv.IsKnown() || kv.IsNull() || kv.Type() != cty.String {
				unk[leafPath] = true
				continue
			}
			k := kv.AsString()
			childPath := policy.JoinPathKey(leafPath, policy.Key(k))
			if cv, ok := evalJSONEncodeExpr(item.ValueExpr, scope, ctx, childPath, unk, jrefs, collector); ok {
				out[k] = cv
			}
		}
		return out, true
	case *hclsyntax.TupleConsExpr:
		out := make([]any, 0, len(e.Exprs))
		for i, elem := range e.Exprs {
			childPath := policy.JoinPathKey(leafPath, policy.Index(int64(i)))
			if cv, ok := evalJSONEncodeExpr(elem, scope, ctx, childPath, unk, jrefs, collector); ok {
				out = append(out, cv)
			} else {
				// Preserve exact Statement/element indices!
				out = append(out, policy.UnknownSlot())
			}
		}
		return out, true
	default:
		// Handle partially-known evaluated objects/tuples (e.g. jsonencode(local.obj)
		// or jsonencode(merge(...))) by walking the evaluated cty structure so known
		// fields remain accessible and unknown leaves are recorded accurately.
		if !valDiags.HasErrors() && val != cty.NilVal && val.IsKnown() && !val.IsNull() {
			ty := val.Type()
			if ty.IsObjectType() || ty.IsMapType() || ty.IsTupleType() || ty.IsListType() || ty.IsSetType() {
				if conv, ok := convertPartialCtyJSON(val, leafPath, unk); ok {
					if tr := extractTypedRefs(expr, scope, 0); len(tr) > 0 {
						jrefs[leafPath] = append(jrefs[leafPath], tr...)
					}
					return conv, true
				}
			}
		}
		unk[leafPath] = true
		if tr := extractTypedRefs(expr, scope, 0); len(tr) > 0 {
			jrefs[leafPath] = append(jrefs[leafPath], tr...)
		}
		return nil, false
	}
}

// nolint:gocyclo
func convertPartialCtyJSON(v cty.Value, leafPath string, unk map[string]bool) (any, bool) {
	if v == cty.NilVal {
		return nil, false
	}
	v, _ = v.UnmarkDeep()
	if !v.IsKnown() {
		unk[leafPath] = true
		return nil, false
	}
	if v.IsNull() {
		return nil, true
	}
	ty := v.Type()
	switch {
	case ty == cty.String:
		return v.AsString(), true
	case ty == cty.Bool:
		return v.True(), true
	case ty == cty.Number:
		return exactNumber(v.AsBigFloat()), true
	case ty.IsListType() || ty.IsTupleType() || ty.IsSetType():
		out := make([]any, 0, v.LengthInt())
		pos := 0
		for it := v.ElementIterator(); it.Next(); {
			_, elem := it.Element()
			childPath := policy.JoinPathKey(leafPath, policy.Index(int64(pos)))
			pos++
			if cv, ok := convertPartialCtyJSON(elem, childPath, unk); ok {
				out = append(out, cv)
			} else {
				out = append(out, policy.UnknownSlot())
			}
		}
		return out, true
	case ty.IsMapType() || ty.IsObjectType():
		out := make(map[string]any, v.LengthInt())
		for it := v.ElementIterator(); it.Next(); {
			k, elem := it.Element()
			k, _ = k.UnmarkDeep()
			if !k.IsKnown() || k.IsNull() || k.Type() != cty.String {
				unk[leafPath] = true
				continue
			}
			ks := k.AsString()
			childPath := policy.JoinPathKey(leafPath, policy.Key(ks))
			if cv, ok := convertPartialCtyJSON(elem, childPath, unk); ok {
				out[ks] = cv
			}
		}
		return out, true
	default:
		unk[leafPath] = true
		return nil, false
	}
}

// deriveJSONTemplate handles JSON heredocs / template strings containing
// unknown interpolations. Each unknown part gets an indexed internal marker
// before JSON unmarshaling, then markers are stripped and mapped back to their
// exact typed refs without depending on Go map iteration order.
// nolint:gocyclo
func deriveJSONTemplate(
	d *policy.DerivedData,
	attrName string,
	e *hclsyntax.TemplateExpr,
	scope *tfeval.ModuleScope,
	ctx *hcl.EvalContext,
) {
	token, ok := newJSONSentinelToken()
	if !ok {
		return
	}
	markerPrefix := "\x00__dd_tpl_" + token + "_idx_"
	markerSuffix := "__\x00"
	parts := make([]policy.TemplatePart, 0, len(e.Parts))
	var buf strings.Builder
	var partRefs [][]policy.TypedRef
	var unknownParts []policy.TemplatePart
	hasKnown, hasUnknown := false, false

	for _, part := range e.Parts {
		val, diags := part.Value(ctx)
		if !diags.HasErrors() && val.IsKnown() && !val.IsNull() {
			if s, ok := ctyStringValue(val); ok {
				hasKnown = true
				parts = append(parts, policy.TemplatePart{Known: true, Value: s})
				buf.WriteString(s)
				continue
			}
		}
		hasUnknown = true
		idx := len(partRefs)
		partRefs = append(partRefs, extractTypedRefs(part, scope, 0))
		chunk := policy.TemplatePart{Known: false, Ref: directSourceReference(part, scope, 0)}
		parts = append(parts, chunk)
		unknownParts = append(unknownParts, chunk)
		fmt.Fprintf(&buf, `\u0000__dd_tpl_%s_idx_%d__\u0000`, token, idx)
	}

	if hasKnown {
		if d.TemplateParts == nil {
			d.TemplateParts = make(map[string][]policy.TemplatePart)
		}
		d.TemplateParts[attrName] = parts
	}
	if !hasKnown || !hasUnknown {
		return
	}

	rawDoc, ok := tryUnmarshalJSONString(buf.String())
	if !ok {
		return
	}
	unk := map[string]bool{}
	jrefs := map[string][]policy.TypedRef{}
	cleaned, kept := stripJSONSentinels(
		rawDoc, "", partRefs, unk, jrefs, &jsonTemplateCollector{d, attrName},
		unknownParts, markerPrefix, markerSuffix,
	)
	recordDerivedJSON(d, attrName, cleaned, kept, unk, jrefs)
}

func stripJSONSentinels(
	v any,
	leafPath string,
	partRefs [][]policy.TypedRef,
	unk map[string]bool,
	jrefs map[string][]policy.TypedRef,
	collector *jsonTemplateCollector,
	unknownParts []policy.TemplatePart,
	markerPrefix string,
	markerSuffix string,
) (any, bool) {
	switch x := v.(type) {
	case string:
		indices := findSentinelIndices(x, markerPrefix, markerSuffix)
		if len(indices) == 0 {
			return x, true
		}
		collector.record(leafPath, sentinelStringParts(x, unknownParts, markerPrefix, markerSuffix))
		unk[leafPath] = true
		var collected []policy.TypedRef
		for _, idx := range indices {
			if idx >= 0 && idx < len(partRefs) {
				collected = append(collected, partRefs[idx]...)
			}
		}
		if len(collected) > 0 {
			jrefs[leafPath] = collected
		}
		return nil, false
	case []any:
		out := make([]any, 0, len(x))
		for i, elem := range x {
			childPath := policy.JoinPathKey(leafPath, policy.Index(int64(i)))
			if cleaned, ok := stripJSONSentinels(elem, childPath, partRefs, unk, jrefs, collector, unknownParts, markerPrefix, markerSuffix); ok {
				out = append(out, cleaned)
			} else {
				out = append(out, policy.UnknownSlot())
			}
		}
		return out, true
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			if len(findSentinelIndices(k, markerPrefix, markerSuffix)) > 0 {
				unk[leafPath] = true
				continue
			}
			childPath := policy.JoinPathKey(leafPath, policy.Key(k))
			if cleaned, ok := stripJSONSentinels(val, childPath, partRefs, unk, jrefs, collector, unknownParts, markerPrefix, markerSuffix); ok {
				out[k] = cleaned
			}
		}
		return out, true
	default:
		return v, true
	}
}

func newJSONSentinelToken() (string, bool) {
	var entropy [16]byte
	if _, err := cryptorand.Read(entropy[:]); err != nil {
		return "", false
	}
	return hex.EncodeToString(entropy[:]), true
}

func findSentinelIndices(s, markerPrefix, markerSuffix string) []int {
	if markerPrefix == "" || !strings.Contains(s, markerPrefix) {
		return nil
	}
	var out []int
	rem := s
	for {
		start := strings.Index(rem, markerPrefix)
		if start < 0 {
			break
		}
		rem = rem[start+len(markerPrefix):]
		end := strings.Index(rem, markerSuffix)
		if end < 0 {
			break
		}
		if idx, err := strconv.Atoi(rem[:end]); err == nil {
			out = append(out, idx)
		}
		rem = rem[end+len(markerSuffix):]
	}
	return out
}

// jsonTemplateCollector exposes string leaf chunks under the original resource
// attribute path, so rules can prove source structure without placeholder text.
type jsonTemplateCollector struct {
	derived   *policy.DerivedData
	attribute string
}

func (c *jsonTemplateCollector) record(leaf string, parts []policy.TemplatePart) {
	if c == nil || len(parts) == 0 {
		return
	}
	if c.derived.TemplateParts == nil {
		c.derived.TemplateParts = map[string][]policy.TemplatePart{}
	}
	path := c.attribute
	if leaf != "" {
		path += "." + leaf
	}
	c.derived.TemplateParts[path] = parts
}

func directSourceReference(expr hclsyntax.Expression, scope *tfeval.ModuleScope, depth int) *policy.TypedRef {
	if depth > maxLocalAliasDepth {
		return nil
	}
	switch expression := expr.(type) {
	case *hclsyntax.ParenthesesExpr:
		return directSourceReference(expression.Expression, scope, depth+1)
	case *hclsyntax.TemplateWrapExpr:
		return directSourceReference(expression.Wrapped, scope, depth+1)
	case *hclsyntax.ScopeTraversalExpr:
		ref := refs.Parse(expression.Traversal)
		if ref.Kind == refs.KindLocal && len(expression.Traversal) == 2 && scope != nil {
			return directSourceReference(scope.Locals[ref.Name], scope, depth+1)
		}
		if ref.Kind != refs.KindOther && ref.Kind != refs.KindLocal && !ref.DynamicKey {
			return &policy.TypedRef{Kind: ref.Kind.String(), Type: ref.Type, Name: ref.Name, Attr: ref.ReadPath()}
		}
	}
	return nil
}

func sourceStringParts(expr hclsyntax.Expression, scope *tfeval.ModuleScope, ctx *hcl.EvalContext, depth int) []policy.TemplatePart {
	if expr == nil || depth > maxLocalAliasDepth {
		return nil
	}
	if value, diagnostics := expr.Value(ctx); !diagnostics.HasErrors() && value.IsKnown() && !value.IsNull() {
		if text, ok := ctyStringValue(value); ok {
			return []policy.TemplatePart{{Known: true, Value: text, Ref: directSourceReference(expr, scope, depth)}}
		}
	}
	switch expression := expr.(type) {
	case *hclsyntax.ParenthesesExpr:
		return sourceStringParts(expression.Expression, scope, ctx, depth+1)
	case *hclsyntax.TemplateWrapExpr:
		return sourceStringParts(expression.Wrapped, scope, ctx, depth+1)
	case *hclsyntax.TemplateExpr:
		var parts []policy.TemplatePart
		for _, child := range expression.Parts {
			parts = append(parts, sourceStringParts(child, scope, ctx, depth+1)...)
		}
		return parts
	case *hclsyntax.ScopeTraversalExpr:
		ref := refs.Parse(expression.Traversal)
		if ref.Kind == refs.KindLocal && len(expression.Traversal) == 2 && scope != nil {
			return sourceStringParts(scope.Locals[ref.Name], scope, ctx, depth+1)
		}
	}
	return []policy.TemplatePart{{Known: false, Ref: directSourceReference(expr, scope, depth)}}
}

func sentinelStringParts(value string, unknown []policy.TemplatePart, markerPrefix, markerSuffix string) []policy.TemplatePart {
	var parts []policy.TemplatePart
	for {
		start := strings.Index(value, markerPrefix)
		if start < 0 {
			if value != "" {
				parts = append(parts, policy.TemplatePart{Known: true, Value: value})
			}
			return parts
		}
		if start > 0 {
			parts = append(parts, policy.TemplatePart{Known: true, Value: value[:start]})
		}
		remaining := value[start+len(markerPrefix):]
		end := strings.Index(remaining, markerSuffix)
		if end < 0 {
			return nil
		}
		index, err := strconv.Atoi(remaining[:end])
		if err != nil || index < 0 || index >= len(unknown) {
			return nil
		}
		parts = append(parts, unknown[index])
		value = remaining[end+len(markerSuffix):]
	}
}

// extractTypedRefs extracts structured TypedRef provenance from expr, following
// local.* aliases up to maxLocalAliasDepth.
func extractTypedRefs(expr hcl.Expression, scope *tfeval.ModuleScope, depth int) []policy.TypedRef {
	if expr == nil || depth > maxLocalAliasDepth {
		return nil
	}
	var out []policy.TypedRef
	for _, r := range refs.Of(expr) {
		if r.Kind == refs.KindLocal && scope != nil && scope.Locals != nil {
			if localExpr, ok := scope.Locals[r.Name]; ok {
				if expanded := extractTypedRefs(localExpr, scope, depth+1); len(expanded) > 0 {
					out = append(out, expanded...)
					continue
				}
			}
		}
		if r.Kind == refs.KindOther {
			continue
		}
		out = append(out, policy.TypedRef{
			Kind: r.Kind.String(),
			Type: r.Type,
			Name: r.Name,
			Attr: r.ReadPath(),
		})
	}
	return out
}

func ctyStringValue(v cty.Value) (string, bool) {
	v, _ = v.UnmarkDeep()
	if !v.IsKnown() || v.IsNull() {
		return "", false
	}
	switch v.Type() {
	case cty.String:
		return v.AsString(), true
	case cty.Bool:
		if v.True() {
			return "true", true
		}
		return "false", true
	case cty.Number:
		return v.AsBigFloat().Text('f', -1), true
	default:
		return "", false
	}
}

func decodeJSONWithNumbers(src []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(src))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	return doc, nil
}
