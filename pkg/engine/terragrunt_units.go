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
	// workingFiles maps the unit's own files, as Terragrunt copies them into
	// the module's working copy, to where they are.
	workingFiles map[string]string
	// unitIsModule is set when the unit's own Terraform files are part of
	// its module, rather than a root of their own.
	unitIsModule bool
	// stack is set for a unit a stack generates.
	stack *terragrunt.StackUnit
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
	stackUnits := expandTerragruntStacks(ctx, terragruntPaths(files, repoPath, tfpath.TerragruntStack), repoPath, fsys)
	templates := map[string]bool{}
	for _, su := range stackUnits {
		templates[su.SourceConfig] = true
	}
	evaluated, included := evaluateTerragruntFiles(
		ctx, terragruntPaths(files, repoPath, tfpath.TerragruntConfig), repoPath, fsys)
	contextLogger := logger.FromContext(ctx)
	units := make([]terragruntUnit, 0, len(evaluated)+len(stackUnits))
	for _, unit := range evaluated {
		// A stack's unit configuration is evaluated where the stack generates it.
		if templates[unit.ConfigFile] || (included[unit.ConfigFile] && unit.Source == "") {
			continue
		}
		tgCall, inputs, ok := unit.Call()
		if !ok {
			contextLogger.Info().Msgf("terragrunt: unit %s is skipped or has no known source", unit.ConfigFile)
			continue
		}
		call := syntheticCall(tgCall)
		moduleDir, ok := resolveModuleTargetDir(
			ctx, fsys, unit.Dir, repoPath, call.Source, call.Version, call.CallerFile, call.Label, resolver)
		if !ok || moduleDir == "" {
			contextLogger.Info().Msgf("terragrunt: source %q of unit %s did not resolve", call.Source, unit.ConfigFile)
			continue
		}
		moduleDir = filepath.Clean(moduleDir)
		called[moduleDir] = true
		tu := terragruntUnit{unit: unit, call: call, inputs: inputs, moduleDir: moduleDir}
		if moduleDir != unit.Dir {
			tu.workingFiles, tu.unitIsModule = workingCopyFiles(fsys, unit.Dir, moduleDir)
			if tu.unitIsModule {
				called[unit.Dir] = true
			}
		}
		units = append(units, tu)
	}
	for _, su := range stackUnits {
		if tu, ok := stackTerragruntUnit(ctx, su, repoPath, fsys, resolver, called); ok {
			units = append(units, tu)
		}
	}
	return dependencyOrder(units)
}

// expandTerragruntStacks expands the scanned stack files into their units.
func expandTerragruntStacks(ctx context.Context, paths []string, repoPath string, fsys vfs.FS) []*terragrunt.StackUnit {
	if len(paths) == 0 {
		return nil
	}
	contextLogger := logger.FromContext(ctx)
	evaluator := terragrunt.New(fsys, repoPath)
	var out []*terragrunt.StackUnit
	for _, path := range paths {
		units, err := evaluator.ExpandStack(ctx, path)
		if err != nil {
			contextLogger.Warn().Err(err).Msgf("terragrunt: failed to expand stack %s", path)
			continue
		}
		out = append(out, units...)
	}
	return out
}

// stackTerragruntUnit is the call of a unit a stack generates. Its generated
// files map back to the unit's configuration in the repository; when they are
// the module, that directory is called rather than a root.
func stackTerragruntUnit(
	ctx context.Context,
	su *terragrunt.StackUnit,
	repoPath string,
	fsys vfs.FS,
	resolver tfeval.RemoteResolver,
	called map[string]bool,
) (terragruntUnit, bool) {
	tgCall, inputs, ok := su.Call()
	if !ok {
		return terragruntUnit{}, false
	}
	call := syntheticCall(tgCall)
	moduleDir := call.SourceDir
	if filepath.Clean(call.Source) != "." {
		resolved, ok := resolveModuleTargetDir(
			ctx, fsys, call.SourceDir, repoPath, call.Source, call.Version, call.CallerFile, call.Label, resolver)
		if !ok || resolved == "" {
			contextLogger := logger.FromContext(ctx)
			contextLogger.Info().Msgf("terragrunt: source %q of stack unit %s did not resolve", call.Source, su.Unit.ConfigFile)
			return terragruntUnit{}, false
		}
		moduleDir = filepath.Clean(resolved)
	} else {
		called[filepath.Dir(su.SourceConfig)] = true
	}
	called[moduleDir] = true
	return terragruntUnit{
		unit: su.Unit, call: call, inputs: inputs, moduleDir: moduleDir, workingFiles: su.Files, stack: su,
	}, true
}

// workingCopyFiles lists the unit directory's Terraform and auto-loaded
// tfvars files by the path Terragrunt copies them to in the module. hasConfig
// reports whether any is Terraform configuration.
func workingCopyFiles(fsys vfs.FS, unitDir, moduleDir string) (files map[string]string, hasConfig bool) {
	entries, err := fsys.ReadDir(unitDir)
	if err != nil {
		return nil, false
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Type().IsRegular() {
			names = append(names, entry.Name())
		}
	}
	selected := tfpath.AutoloadedVarFiles(names)
	for _, name := range names {
		if tfpath.IsConfig(name) {
			selected = append(selected, name)
			hasConfig = true
		}
	}
	if len(selected) == 0 {
		return nil, false
	}
	files = make(map[string]string, len(selected))
	for _, name := range selected {
		files[filepath.Join(moduleDir, name)] = filepath.Join(unitDir, name)
	}
	return files, hasConfig
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

// terragruntPaths returns the absolute paths of the scanned files named name,
// sorted.
func terragruntPaths(files model.FileMetadatas, repoPath, name string) []string {
	var paths []string
	seen := map[string]bool{}
	for _, f := range files {
		if f == nil || filepath.Base(f.FilePath) != name {
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
		evaluator := m.unitEvaluator(unit)
		inputs := m.unitInputs(evaluator, unit)
		resources, unitOutputs, visited, err := evaluator.EvaluateCall(m.ctx, unit.call, inputs)
		evaluator.ReleaseEvalCache()
		instances := evaluator.TakeModuleInstances()
		if evaluator != m.evaluator {
			m.evaluator.AddNotEvaluatedDirs(evaluator.TakeNotEvaluatedDirs())
		}
		if err != nil {
			if isContextError(err) {
				return
			}
			contextLogger := logger.FromContext(m.ctx)
			contextLogger.Warn().Err(err).Msgf("tfeval: failed to evaluate Terragrunt unit %s", unit.call.CallerFile)
			m.unresolvedModuleDirs[unit.moduleDir] = true
			if unit.unitIsModule {
				m.unresolvedModuleDirs[unit.unit.Dir] = true
			}
			for _, called := range discoverCalledModuleClosure(
				m.ctx, m.evaluator, m.filesByDir, m.repoPath, m.resolver, unit.moduleDir,
			) {
				m.unresolvedModuleDirs[called] = true
			}
			continue
		}
		outputs[unit.unit.ConfigFile] = cty.ObjectVal(unitOutputs)
		remapWorkingCopy(resources, instances, unit.workingFiles)
		if unit.unitIsModule {
			visited[unit.unit.Dir] = true
		}
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
	if unit.stack != nil {
		again, err := unit.stack.WithDependencyOutputs(m.ctx, known)
		if err != nil {
			return
		}
		tgCall, inputs, ok := again.Call()
		if !ok || tgCall.Source != unit.call.Source || tgCall.Version != unit.call.Version {
			return
		}
		unit.stack, unit.unit, unit.call, unit.inputs = again, again.Unit, syntheticCall(tgCall), inputs
		return
	}
	evaluator := terragrunt.New(m.evaluator.FS(), m.repoPath).WithDependencyOutputs(known)
	again, err := evaluator.EvaluateUnit(m.ctx, unit.unit.ConfigFile)
	if err != nil {
		return
	}
	tgCall, inputs, ok := again.Call()
	if !ok || tgCall.Source != unit.call.Source || tgCall.Version != unit.call.Version {
		return
	}
	unit.unit, unit.call, unit.inputs = again, syntheticCall(tgCall), inputs
}

// unitInputs applies Terraform's precedence to the unit's values: inputs
// (TF_VAR_), then the module's tfvars files, then -var-file and -var. An
// input something else overrides is no longer an argument of the call.
func (m *rootMerge) unitInputs(evaluator *tfeval.Evaluator, unit *terragruntUnit) map[string]cty.Value {
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
	for name, value := range evaluator.LoadRootVarsWithContext(m.ctx, unit.moduleDir) {
		overridden(name, value)
	}
	for i := range unit.unit.VarOverrides {
		overridden(unit.unit.VarOverrides[i].Name, unit.unit.VarOverrides[i].Value)
	}
	return inputs
}

func syntheticCall(call *terragrunt.Call) *tfeval.SyntheticCall {
	return &tfeval.SyntheticCall{
		Label:      call.Label,
		Source:     call.Source,
		Version:    call.Version,
		CallerFile: call.CallerFile,
		SourceDir:  call.SourceDir,
		Range:      call.Range,
		Body:       call.Body,
	}
}

// unitEvaluator reads the module as Terragrunt's working copy: the module
// with the unit's own files added, which replace module files of the same
// name.
func (m *rootMerge) unitEvaluator(unit *terragruntUnit) *tfeval.Evaluator {
	if len(unit.workingFiles) == 0 {
		return m.evaluator
	}
	fsys := m.evaluator.FS()
	files := make(map[string][]byte, len(unit.workingFiles))
	for copied, original := range unit.workingFiles {
		if content, err := fsys.ReadFile(original); err == nil {
			files[copied] = content
		}
	}
	return m.evaluator.WithFS(vfs.NewOverlay(fsys, files))
}

// remapWorkingCopy points what the unit's copied files declare back to the
// files themselves.
func remapWorkingCopy(resources []tfeval.ResolvedResource, instances []tfeval.ModuleInstance, files map[string]string) {
	if len(files) == 0 {
		return
	}
	remapChain := func(chain []tfeval.CallSite) {
		for i := range chain {
			if original, ok := files[chain[i].CalledFrom]; ok {
				chain[i].CalledFrom = original
			}
		}
	}
	for i := range resources {
		if original, ok := files[resources[i].DefinedIn]; ok {
			resources[i].DefinedIn = original
		}
		remapChain(resources[i].CallChain)
	}
	for i := range instances {
		remapChain(instances[i].CallChain)
	}
}
