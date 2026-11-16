/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package terragrunt

import (
	"context"
	"path/filepath"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// dependency is a dependency block: the unit whose outputs it reads.
type dependency struct {
	// configPath is the dependency's terragrunt.hcl.
	configPath  string
	mock        cty.Value
	skipOutputs bool
}

// WithDependencyOutputs returns an evaluator reading dependency outputs from
// outputs, keyed by the dependency's terragrunt.hcl. The evaluator never
// reads state: these are the outputs the scan evaluated for those units.
func (e *Evaluator) WithDependencyOutputs(outputs map[string]cty.Value) *Evaluator {
	out := *e
	out.outputs = outputs
	return &out
}

// evaluateDependencies evaluates the dependency blocks of a file. Paths are
// resolved from the unit directory, as Terragrunt runs there.
func (e *Evaluator) evaluateDependencies(
	ctx context.Context, body *hclsyntax.Body, evalCtx *hcl.EvalContext, s *scope,
) map[string]dependency {
	contextLogger := logger.FromContext(ctx)
	deps := map[string]dependency{}
	for _, block := range blocksOfType(body, "dependency") {
		if len(block.Labels) == 0 {
			continue
		}
		name := block.Labels[0]
		if enabled := attributeValue(block.Body, "enabled", evalCtx); isKnownFalse(enabled) {
			continue
		}
		dep := dependency{mock: attributeValue(block.Body, "mock_outputs", evalCtx)}
		dep.skipOutputs = isKnownTrue(attributeValue(block.Body, "skip_outputs", evalCtx))
		if target, ok := knownString(attributeValue(block.Body, "config_path", evalCtx)); ok {
			if path, err := e.dependencyConfig(filepath.Dir(s.terragruntPath), target); err == nil {
				dep.configPath = path
			} else {
				contextLogger.Debug().Msgf("terragrunt: dependency %q: %v", name, err)
			}
		}
		deps[name] = dep
	}
	return deps
}

// dependencyConfig resolves config_path, a unit directory or its config file.
func (e *Evaluator) dependencyConfig(dir, target string) (string, error) {
	path, err := e.confine(dir, target)
	if err != nil {
		return "", err
	}
	// A stack unit's dependency is generated too, so it may not exist.
	if info, statErr := e.fsys.Stat(path); (statErr == nil && info.IsDir()) || filepath.Ext(path) != ".hcl" {
		return e.confine(path, ConfigFileName)
	}
	return path, nil
}

// dependencyObject is the dependency variable. Each output is the one the scan
// evaluated for the dependency when known, else the mock, else unknown.
func (e *Evaluator) dependencyObject(deps map[string]dependency) cty.Value {
	out := make(map[string]cty.Value, len(deps))
	for name, dep := range deps {
		var evaluated cty.Value
		if !dep.skipOutputs && dep.configPath != "" {
			evaluated = e.outputs[dep.configPath]
		}
		out[name] = cty.ObjectVal(map[string]cty.Value{"outputs": combineOutputs(evaluated, dep.mock)})
	}
	return cty.ObjectVal(out)
}

// combineOutputs takes each known evaluated output, and the mock for the rest.
func combineOutputs(evaluated, mock cty.Value) cty.Value {
	evaluatedMap := valueMap(evaluated)
	mockMap := valueMap(mock)
	if evaluatedMap == nil && mockMap == nil {
		return cty.DynamicVal
	}
	out := make(map[string]cty.Value, len(evaluatedMap)+len(mockMap))
	for name, value := range mockMap {
		out[name] = value
	}
	for name, value := range evaluatedMap {
		if _, mocked := mockMap[name]; mocked && !value.IsWhollyKnown() {
			continue
		}
		out[name] = value
	}
	return cty.ObjectVal(out)
}

// valueMap is a known object or map's elements, nil otherwise.
func valueMap(v cty.Value) map[string]cty.Value {
	if !mergeable(v) || !isMapLike(v.Type()) {
		return nil
	}
	m := v.AsValueMap()
	if m == nil {
		m = map[string]cty.Value{}
	}
	return m
}

func isKnownTrue(v cty.Value) bool {
	return v != cty.NilVal && v.Type() == cty.Bool && v.IsKnown() && !v.IsNull() && v.True()
}

func isKnownFalse(v cty.Value) bool {
	return v != cty.NilVal && v.Type() == cty.Bool && v.IsKnown() && !v.IsNull() && v.False()
}
