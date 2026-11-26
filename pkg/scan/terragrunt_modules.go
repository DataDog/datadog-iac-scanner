/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package scan

import (
	"context"
	"path/filepath"

	"github.com/rs/zerolog"

	"github.com/DataDog/datadog-iac-scanner/pkg/engine"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/terragrunt"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
)

// terragruntRepoRoot is the repository root the Terraform parser translates
// units with (SCIInfo.RepositoryDir), so the pre-scan sees the same
// translations. RepoPath is the same directory in the CLI and the fallback.
func (c *Client) terragruntRepoRoot() string {
	if c.ScanParams.SCIInfo.RepositoryDir != "" {
		return c.ScanParams.SCIInfo.RepositoryDir
	}
	return c.ScanParams.RepoPath
}

// terragruntModuleCalls translates the units among paths and returns the
// module calls they make, so module discovery fetches the remote ones.
// Each call is named like the translation's module block and its FileName is
// in the unit's directory, so the engine finds the module from the unit.
func terragruntModuleCalls(ctx context.Context, fsys vfs.FS, repoRoot string, paths []string) []tfmodules.ParsedModule {
	contextLogger := logger.FromContext(ctx)
	// The parser logs why a unit is skipped; the pre-scan stays quiet.
	quiet := zerolog.Nop().WithContext(ctx)
	var calls []tfmodules.ParsedModule
	for _, path := range paths {
		if ctx.Err() != nil {
			return calls
		}
		src, err := tfmodules.ReadConfigFile(ctx, fsys, path, "")
		if err != nil {
			contextLogger.Debug().Err(err).Msgf("terragrunt: cannot read unit %s for module discovery", path)
			continue
		}
		translation, err := terragrunt.Translate(quiet, fsys, repoRoot, path, src, nil)
		if err != nil || translation == nil {
			continue
		}
		calls = append(calls, translationCall(translation, path))
	}
	return calls
}

// translationCall builds the call of the translation's module block. The
// module graph drops local and empty sources.
func translationCall(translation *model.TerragruntTranslation, unitPath string) tfmodules.ParsedModule {
	source := translation.Source
	sourceType, scope := tfmodules.DetectModuleSourceType(source)
	call := tfmodules.ParsedModule{
		Name:          terragrunt.ModuleName,
		Source:        source,
		Version:       translation.Version,
		SourceType:    sourceType,
		RegistryScope: scope,
		FileName:      filepath.Join(filepath.Dir(unitPath), terragrunt.VirtualFileName),
	}
	if len(translation.Lines) > 0 {
		call.DefLine, call.DefEndLine = translation.Lines[0].Real.LineStart, translation.Lines[0].Real.LineEnd
	}
	return call
}

// fetchedTerragruntModules is the directory the pre-scan fetched for the
// remote module of the unit in callerRoot, or "".
func (c *Client) fetchedTerragruntModules(callerRoot, source, version string) string {
	dir, _ := engine.LookupRemoteDir(c.terragruntModuleDirs, callerRoot, source, version, terragrunt.ModuleName)
	return dir.Path
}
