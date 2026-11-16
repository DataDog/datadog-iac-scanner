/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package terragrunt

import (
	"context"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// varLocal is the root of local references.
const varLocal = "local"

// evaluateLocals evaluates the locals blocks in dependency order. A local in
// a cycle, or reading a missing local, is unknown.
func evaluateLocals(ctx context.Context, body *hclsyntax.Body, evalCtx *hcl.EvalContext) map[string]cty.Value {
	exprs := map[string]hclsyntax.Expression{}
	for _, block := range blocksOfType(body, "locals") {
		for name, attr := range block.Body.Attributes {
			exprs[name] = attr.Expr
		}
	}
	values := make(map[string]cty.Value, len(exprs))
	state := make(map[string]int, len(exprs)) // 1: evaluating, 2: done
	var visit func(name string) cty.Value
	visit = func(name string) cty.Value {
		switch state[name] {
		case 1:
			contextLogger := logger.FromContext(ctx)
			contextLogger.Debug().Msgf("terragrunt: cycle through local.%s; it is read as unknown", name)
			return cty.DynamicVal
		case 2:
			return values[name]
		}
		expr, ok := exprs[name]
		if !ok {
			return cty.DynamicVal
		}
		state[name] = 1
		deps := map[string]cty.Value{}
		for _, dep := range localReferences(expr) {
			deps[dep] = visit(dep)
		}
		for done, value := range values {
			deps[done] = value
		}
		child := evalCtx.NewChild()
		child.Variables = map[string]cty.Value{varLocal: cty.ObjectVal(deps)}
		value := evalExpr(ctx, expr, child)
		state[name] = 2
		values[name] = value
		return value
	}
	for _, name := range sortedKeys(exprs) {
		visit(name)
	}
	return values
}

// localReferences lists the locals expr reads.
func localReferences(expr hclsyntax.Expression) []string {
	var names []string
	seen := map[string]bool{}
	for _, traversal := range expr.Variables() {
		if traversal.RootName() != varLocal || len(traversal) < 2 {
			continue
		}
		attr, ok := traversal[1].(hcl.TraverseAttr)
		if !ok || seen[attr.Name] {
			continue
		}
		seen[attr.Name] = true
		names = append(names, attr.Name)
	}
	return names
}
