/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package scan

import (
	"context"
	"path/filepath"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/terragrunt"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
)

// terragruntModuleCalls evaluates the units among paths into the remote module
// calls they make, so module discovery fetches their modules. Each call's
// FileName is the unit file, so the engine finds the module from the unit.
func terragruntModuleCalls(ctx context.Context, paths []string, repoPath string, fsys vfs.FS) []tfmodules.ParsedModule {
	if len(paths) == 0 {
		return nil
	}
	contextLogger := logger.FromContext(ctx)
	evaluator := terragrunt.New(fsys, repoPath)
	var calls []tfmodules.ParsedModule
	for _, path := range paths {
		if ctx.Err() != nil {
			return nil
		}
		if abs, err := filepath.Abs(path); err == nil {
			path = abs
		}
		unit, err := evaluator.EvaluateUnit(ctx, path)
		if err != nil {
			contextLogger.Debug().Err(err).Msgf("terragrunt: failed to evaluate unit %s for module discovery", path)
			continue
		}
		call, _, ok := unit.Call()
		if !ok || tfmodules.LooksLikeLocalModuleSource(call.Source) {
			continue
		}
		sourceType, scope := tfmodules.DetectModuleSourceType(call.Source)
		calls = append(calls, tfmodules.ParsedModule{
			Name:          call.Label,
			Source:        call.Source,
			Version:       call.Version,
			SourceType:    sourceType,
			RegistryScope: scope,
			FileName:      unit.ConfigFile,
			DefLine:       call.Range.Start.Line,
			DefEndLine:    call.Range.End.Line,
		})
	}
	return calls
}
