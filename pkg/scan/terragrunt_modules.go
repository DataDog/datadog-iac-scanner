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
	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
)

// terragruntModuleCalls evaluates the units and stacks among paths into the
// remote module calls they make, so module discovery fetches their modules.
// Each call's FileName is the file declaring it, so the engine finds the
// module from there.
func terragruntModuleCalls(ctx context.Context, paths []string, repoPath string, fsys vfs.FS) []tfmodules.ParsedModule {
	if len(paths) == 0 {
		return nil
	}
	contextLogger := logger.FromContext(ctx)
	evaluator := terragrunt.New(fsys, repoPath)
	var stacks, units []string
	for _, path := range paths {
		if abs, err := filepath.Abs(path); err == nil {
			path = abs
		}
		if filepath.Base(path) == tfpath.TerragruntStack {
			stacks = append(stacks, path)
		} else {
			units = append(units, path)
		}
	}
	calls, templates := stackModuleCalls(ctx, evaluator, stacks)
	for _, path := range units {
		if templates[path] || ctx.Err() != nil {
			continue
		}
		unit, err := evaluator.EvaluateUnit(ctx, path)
		if err != nil {
			contextLogger.Debug().Err(err).Msgf("terragrunt: failed to evaluate unit %s for module discovery", path)
			continue
		}
		if call, _, ok := unit.Call(); ok {
			calls = appendRemoteCall(calls, call)
		}
	}
	return calls
}

// stackModuleCalls returns the remote module calls of the stacks' units, and
// the unit configurations those units are generated from.
func stackModuleCalls(
	ctx context.Context, evaluator *terragrunt.Evaluator, stacks []string,
) (calls []tfmodules.ParsedModule, templates map[string]bool) {
	contextLogger := logger.FromContext(ctx)
	templates = map[string]bool{}
	for _, path := range stacks {
		if ctx.Err() != nil {
			return calls, templates
		}
		stackUnits, err := evaluator.ExpandStack(ctx, path)
		if err != nil {
			contextLogger.Debug().Err(err).Msgf("terragrunt: failed to expand stack %s for module discovery", path)
			continue
		}
		for _, su := range stackUnits {
			templates[su.SourceConfig] = true
			if call, _, ok := su.Call(); ok {
				calls = appendRemoteCall(calls, call)
			}
		}
	}
	return calls, templates
}

// appendRemoteCall appends call when its source is remote.
func appendRemoteCall(calls []tfmodules.ParsedModule, call *terragrunt.Call) []tfmodules.ParsedModule {
	if call.Source == "" || tfmodules.LooksLikeLocalModuleSource(call.Source) {
		return calls
	}
	sourceType, scope := tfmodules.DetectModuleSourceType(call.Source)
	return append(calls, tfmodules.ParsedModule{
		Name:          call.Label,
		Source:        call.Source,
		Version:       call.Version,
		SourceType:    sourceType,
		RegistryScope: scope,
		FileName:      call.CallerFile,
		DefLine:       call.Range.Start.Line,
		DefEndLine:    call.Range.End.Line,
	})
}
