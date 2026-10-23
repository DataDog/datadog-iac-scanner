/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfeval

import (
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/instances"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// WithScanFallbacks adds one as-written scan view per truncated module block,
// evaluated with that call's inputs and an unknown count/each binding. These
// views replace defining-file copies, which otherwise repeat already evaluated
// instances and may use different variable defaults. They are not instances:
// call this only after evaluation, never for reference injection or budgeting.
func WithScanFallbacks(resources []ResolvedResource) []ResolvedResource {
	type blockKey struct {
		body   *hclsyntax.Body
		scope  *ModuleScope
		module string
	}
	seen := make(map[blockKey]bool)
	var out []ResolvedResource
	for i := range resources {
		r := &resources[i]
		if !r.ExpansionTruncated || r.ModuleAddress == "" || r.Body == nil || r.Scope == nil || r.Scope.evalCtx == nil {
			continue
		}
		if out == nil {
			out = append([]ResolvedResource(nil), resources...)
		}
		// The scan view below covers the omitted tail, so all defining-file
		// layers can now be suppressed without losing the as-written fallback.
		out[i].ExpansionTruncated = false
		key := blockKey{body: r.Body, scope: r.Scope, module: r.ModuleAddress}
		if seen[key] {
			continue
		}
		seen[key] = true
		plan := instances.Plan{Kind: instances.KindForEach, Unresolved: true}
		if _, counted := r.Iteration[instances.KindCount]; counted {
			plan.Kind = instances.KindCount
		}
		name, value := plan.Variable(instances.Item{})
		fallback := *r
		fallback.Name = ResourceBaseName(r.Name)
		fallback.Iteration = map[string]cty.Value{name: value}
		ctx := r.Scope.evalCtx.NewChild()
		ctx.Variables = fallback.Iteration
		state := &bodyState{dynamic: &dynamicRecorder{}}
		var evaluator Evaluator
		fallback.Attributes = evaluator.evalBodyWith(r.Body, ctx, nil, state)
		fallback.DynamicCounts = state.dynamic.counts
		fallback.ExpansionTruncated = false
		out = append(out, fallback)
	}
	if out == nil {
		return resources
	}
	return out
}
