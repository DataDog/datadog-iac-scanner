/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"path/filepath"
	"sort"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/terragrunt"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/zclconf/go-cty/cty"
)

// terragruntUnit is a Terragrunt unit evaluated as a call to its module.
type terragruntUnit struct {
	unit   *terragrunt.Unit
	call   *tfeval.SyntheticCall
	inputs map[string]cty.Value
	// moduleDir is the directory the call resolves to.
	moduleDir string
}

// discoverTerragruntUnits evaluates the scanned terragrunt.hcl files into the
// module calls they make, sorted by file, and marks the modules they call as
// called. A file other units only include, with no terraform.source, is
// shared configuration rather than a unit.
func discoverTerragruntUnits(
	ctx context.Context,
	files model.FileMetadatas,
	repoPath string,
	fsys vfs.FS,
	resolver tfeval.RemoteResolver,
	called map[string]bool,
) []terragruntUnit {
	evaluated, included := evaluateTerragruntFiles(ctx, terragruntUnitPaths(files, repoPath), repoPath, fsys)
	contextLogger := logger.FromContext(ctx)
	units := make([]terragruntUnit, 0, len(evaluated))
	for _, unit := range evaluated {
		if included[unit.ConfigFile] && unit.Source == "" {
			continue
		}
		call, inputs, ok := unit.Call()
		if !ok {
			contextLogger.Info().Msgf("terragrunt: unit %s is skipped or has no known source", unit.ConfigFile)
			continue
		}
		moduleDir, ok := resolveModuleTargetDir(
			ctx, fsys, unit.Dir, repoPath, call.Source, call.Version, call.CallerFile, call.Label, resolver)
		if !ok || moduleDir == "" {
			contextLogger.Info().Msgf("terragrunt: source %q of unit %s did not resolve", call.Source, unit.ConfigFile)
			continue
		}
		moduleDir = filepath.Clean(moduleDir)
		called[moduleDir] = true
		units = append(units, terragruntUnit{unit: unit, call: call, inputs: inputs, moduleDir: moduleDir})
	}
	return dependencyOrder(units)
}

// dependencyOrder puts each unit after the units it reads outputs of, keeping
// file order otherwise. Units in a cycle stay in file order.
func dependencyOrder(units []terragruntUnit) []terragruntUnit {
	index := make(map[string]int, len(units))
	for i := range units {
		index[units[i].unit.ConfigFile] = i
	}
	state := make([]int, len(units)) // 1: visiting, 2: placed
	ordered := make([]terragruntUnit, 0, len(units))
	var visit func(i int)
	visit = func(i int) {
		if state[i] != 0 {
			return
		}
		state[i] = 1
		for _, dep := range units[i].unit.Dependencies {
			if j, ok := index[dep]; ok && state[j] == 0 {
				visit(j)
			}
		}
		state[i] = 2
		ordered = append(ordered, units[i])
	}
	for i := range units {
		visit(i)
	}
	return ordered
}

// terragruntUnitPaths returns the absolute paths of the scanned units, sorted.
func terragruntUnitPaths(files model.FileMetadatas, repoPath string) []string {
	var paths []string
	seen := map[string]bool{}
	for _, f := range files {
		if f == nil || filepath.Base(f.FilePath) != tfpath.TerragruntConfig {
			continue
		}
		path := absPath(f.FilePath, repoPath)
		if !seen[path] {
			seen[path] = true
			paths = append(paths, path)
		}
	}
	sort.Strings(paths)
	return paths
}

// evaluateTerragruntFiles evaluates each unit file, and returns the files the
// units include.
func evaluateTerragruntFiles(
	ctx context.Context, paths []string, repoPath string, fsys vfs.FS,
) (units []*terragrunt.Unit, included map[string]bool) {
	if len(paths) == 0 {
		return nil, nil
	}
	contextLogger := logger.FromContext(ctx)
	evaluator := terragrunt.New(fsys, repoPath)
	included = map[string]bool{}
	for _, path := range paths {
		if ctx.Err() != nil {
			return nil, nil
		}
		unit, err := evaluator.EvaluateUnit(ctx, path)
		if err != nil {
			contextLogger.Warn().Err(err).Msgf("terragrunt: failed to evaluate unit %s", path)
			continue
		}
		units = append(units, unit)
		for _, inc := range unit.Includes {
			included[inc] = true
		}
	}
	return units, included
}

// evaluateTerragruntUnits evaluates each unit's call after the roots and
// merges it like a root. A unit that fails leaves its module, and what that
// module calls, scanned where they are written. A unit reading dependency
// outputs is evaluated again once the units it depends on are.
func (m *rootMerge) evaluateTerragruntUnits(units []terragruntUnit) {
	outputs := make(map[string]cty.Value, len(units))
	for i := range units {
		if m.ctx.Err() != nil {
			return
		}
		unit := &units[i]
		m.withDependencyOutputs(unit, outputs)
		inputs := m.unitInputs(unit)
		resources, unitOutputs, visited, err := m.evaluator.EvaluateCall(m.ctx, unit.call, inputs)
		m.evaluator.ReleaseEvalCache()
		instances := m.evaluator.TakeModuleInstances()
		if err != nil {
			if isContextError(err) {
				return
			}
			contextLogger := logger.FromContext(m.ctx)
			contextLogger.Warn().Err(err).Msgf("tfeval: failed to evaluate Terragrunt unit %s", unit.call.CallerFile)
			m.unresolvedModuleDirs[unit.moduleDir] = true
			for _, called := range discoverCalledModuleClosure(
				m.ctx, m.evaluator, m.filesByDir, m.repoPath, m.resolver, unit.moduleDir,
			) {
				m.unresolvedModuleDirs[called] = true
			}
			continue
		}
		outputs[unit.unit.ConfigFile] = cty.ObjectVal(unitOutputs)
		m.mergeResolved(resources, instances, visited)
	}
}

// withDependencyOutputs evaluates the unit again with the outputs evaluated
// for its dependencies, keeping the call when its source did not change.
func (m *rootMerge) withDependencyOutputs(unit *terragruntUnit, outputs map[string]cty.Value) {
	if len(unit.unit.Dependencies) == 0 {
		return
	}
	known := map[string]cty.Value{}
	for _, dep := range unit.unit.Dependencies {
		if value, ok := outputs[dep]; ok {
			known[dep] = value
		}
	}
	if len(known) == 0 {
		return
	}
	evaluator := terragrunt.New(m.evaluator.FS(), m.repoPath).WithDependencyOutputs(known)
	again, err := evaluator.EvaluateUnit(m.ctx, unit.unit.ConfigFile)
	if err != nil {
		return
	}
	call, inputs, ok := again.Call()
	if !ok || call.Source != unit.call.Source || call.Version != unit.call.Version {
		return
	}
	unit.unit, unit.call, unit.inputs = again, call, inputs
}

// unitInputs applies Terraform's precedence to the unit's values: inputs
// (TF_VAR_), then the module's tfvars files, then -var-file and -var. An
// input something else overrides is no longer an argument of the call.
func (m *rootMerge) unitInputs(unit *terragruntUnit) map[string]cty.Value {
	inputs := make(map[string]cty.Value, len(unit.inputs))
	for name, value := range unit.inputs {
		inputs[name] = value
	}
	overridden := func(name string, value cty.Value) {
		inputs[name] = value
		if unit.call.Body != nil {
			delete(unit.call.Body.Attributes, name)
		}
	}
	for name, value := range m.evaluator.LoadRootVarsWithContext(m.ctx, unit.moduleDir) {
		overridden(name, value)
	}
	for _, override := range unit.unit.VarOverrides {
		overridden(override.Name, override.Value)
	}
	return inputs
}
