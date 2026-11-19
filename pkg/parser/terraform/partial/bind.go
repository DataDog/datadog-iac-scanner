/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package partial

import (
	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
)

// bound is an expression that reads vars in addition to the context it is
// evaluated in, such as the iterator of the dynamic block that generated it.
type bound struct {
	hcl.Expression
	vars map[string]cty.Value
}

// Bind returns expr evaluating with vars added to the context it is given. A
// Renderer renders it against that scope, so its unresolved parts stay
// separate from the parts vars resolve.
func Bind(expr hcl.Expression, vars map[string]cty.Value) hcl.Expression {
	return bound{Expression: expr, vars: vars}
}

// WithBindings returns a renderer in a lexical child scope. Bound names mask
// reference recovery from the parent even when their values are unknown.
// The caller must not mutate vars after passing it to the renderer.
func (r *Renderer) WithBindings(vars map[string]cty.Value) *Renderer {
	return r.withBindings(vars, nil)
}

// withBindings can also preserve explicitly proven aliases for bound values.
// Alias traversals belong to the parent scope, before the new names are bound.
func (r *Renderer) withBindings(vars map[string]cty.Value, aliases map[string]hcl.Traversal) *Renderer {
	if len(vars) == 0 {
		return r
	}
	child := &Renderer{Ctx: scope(r.ctx(), vars), Source: r.Source}
	if r.Reference != nil {
		child.Reference = func(t hcl.Traversal, _ *hcl.EvalContext) (cty.Value, bool) {
			if len(t) == 0 {
				return cty.NilVal, false
			}
			if _, bound := vars[t.RootName()]; !bound {
				return r.Reference(t, r.ctx())
			}
			alias := aliases[t.RootName()]
			if len(alias) == 0 {
				return cty.NilVal, false
			}
			composed := append(append(hcl.Traversal{}, alias...), t[1:]...)
			return r.Reference(composed, r.ctx())
		}
	}
	return child
}

// Unbind returns the expression and variables Bind was given, for evaluators
// that read expressions themselves rather than through a Renderer.
func Unbind(expr hcl.Expression) (inner hcl.Expression, vars map[string]cty.Value, ok bool) {
	b, ok := expr.(bound)
	if !ok {
		return nil, nil, false
	}
	return b.Expression, b.vars, true
}

// Scope returns a child of ctx in which vars are defined. For presentation,
// use [Renderer.WithBindings] so reference recovery observes the same scope.
func Scope(ctx *hcl.EvalContext, vars map[string]cty.Value) *hcl.EvalContext {
	return scope(ctx, vars)
}

func (b bound) Value(ctx *hcl.EvalContext) (cty.Value, hcl.Diagnostics) {
	return b.Expression.Value(scope(ctx, b.vars))
}

func scope(ctx *hcl.EvalContext, vars map[string]cty.Value) *hcl.EvalContext {
	if ctx == nil {
		ctx = &hcl.EvalContext{}
	}
	child := ctx.NewChild()
	child.Variables = vars
	return child
}
