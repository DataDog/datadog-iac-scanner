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
		units = append(units, terragruntUnit{call: call, inputs: inputs, moduleDir: moduleDir})
	}
	return units
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
// module calls, scanned where they are written.
func (m *rootMerge) evaluateTerragruntUnits(units []terragruntUnit) {
	for i := range units {
		if m.ctx.Err() != nil {
			return
		}
		unit := &units[i]
		resources, _, visited, err := m.evaluator.EvaluateCall(m.ctx, unit.call, unit.inputs)
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
		m.mergeResolved(resources, instances, visited)
	}
}
