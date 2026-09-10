/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package scan

import (
	"context"
	"strings"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/engine"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/provider"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/modulegraph"
	tfresolver "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/resolver"
)

const (
	moduleSourceTypeGit     = "git"
	moduleSourceTypeUnknown = "unknown"

	DefaultModuleResolutionTimeout = 5 * time.Minute
)

func (c *Client) resolveTerraformModulesForScan(
	ctx context.Context,
	paramsPlatforms []string,
	extractedPaths *provider.ExtractedPath,
	baselinePaths []string,
) (
	moduleCleanup func(),
	remoteModulePaths []string,
	remoteSourceDirs map[string]engine.RemoteModuleDirectory,
	remoteModuleProvenance map[string]engine.RemoteModuleProvenance,
	resolvedModules []modulegraph.ResolvedModule,
	err error,
) {
	if !platformsIncludeTerraform(paramsPlatforms) || !c.shouldPreScanTerraformModules(extractedPaths.Path) {
		return nil, nil, nil, nil, nil, nil
	}

	contextLogger := logger.FromContext(ctx)
	filteredFilesSource, err := c.getFileSystemSourceProvider(ctx, extractedPaths.Path)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	moduleDiscoveryPaths, err := filteredFilesSource.TerraformFiles(ctx)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	resolveCtx, cancel := c.moduleResolutionContext(ctx)
	defer cancel()

	chain, err := c.buildModuleResolverChain(resolveCtx, moduleDiscoveryPaths)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	if c.ScanParams.TerraformModules == TerraformModulesOn {
		contextLogger.Info().Msg("Resolving remote Terraform modules...")
	}

	result := c.resolveTerraformModuleGraph(resolveCtx, extractedPaths.Path, moduleDiscoveryPaths, baselinePaths, chain)
	if result.TimedOut {
		contextLogger.Warn().Dur("timeout", c.ScanParams.ModuleResolutionTimeout).
			Msg("Terraform module resolution timed out; scanning modules resolved before the deadline")
	}
	for _, event := range result.BudgetEvents {
		contextLogger.Warn().
			Str("module_source", event.Source).
			Str("gate", event.Gate).
			Str("limit_name", event.Limit).
			Int64("limit", event.Maximum).
			Int64("measured", event.Measured).
			Int("shedding_rank", event.SheddingRank).
			Msg("Terraform module excluded by resource budget")
	}
	for i := range result.Failures {
		failure := &result.Failures[i]
		contextLogger.Warn().
			Str("module_source", failure.Source).
			Str("module_name", failure.Name).
			Str("caller_root", failure.CallerRoot).
			Str("reason", failure.Reason).
			Msg("Terraform module resolution failed")
	}
	if len(result.ScanPaths) > 0 {
		contextLogger.Info().Msgf("Adding %d remote module file(s) to scan", len(result.ScanPaths))
	}
	for localPath, canonicalSource := range result.SourceMappings {
		extractedPaths.ExtractionMap[localPath] = model.ExtractedPathObject{
			Path:      canonicalSource,
			LocalPath: false,
		}
	}
	remoteSourceDirs = make(map[string]engine.RemoteModuleDirectory, len(result.Modules)*3)
	remoteModuleProvenance = make(map[string]engine.RemoteModuleProvenance, len(result.Modules)*3)
	for i := range result.Modules {
		module := &result.Modules[i]
		directory := engine.RemoteModuleDirectory{
			Path:        module.LocalPath,
			PackageRoot: module.PackageRoot,
		}
		sourceType := resolvedModuleSourceType(module)
		provenance := engine.RemoteModuleProvenance{
			Source:          module.Source,
			ResolvedVersion: module.ResolvedVersion,
			ResolvedRef:     module.ResolvedRef,
			CanonicalSource: module.CanonicalSource,
			SourceType:      sourceType,
			ModuleRoot:      module.LocalPath,
		}
		for _, key := range []string{
			engine.RemoteModuleKey(module.CallerRoot, module.Source, module.Version),
			engine.RemoteModuleCallKey(module.CallerRoot, module.Source, module.Version, module.Name),
			engine.RemoteModuleCallKey(module.CallerRoot, module.Source, "", module.Name),
		} {
			remoteSourceDirs[key] = directory
			remoteModuleProvenance[key] = provenance
		}
	}
	return result.Cleanup, result.ScanPaths, remoteSourceDirs, remoteModuleProvenance, result.Modules, nil
}

func (c *Client) resolveTerraformModuleGraph(
	ctx context.Context,
	rootPaths, discoveryPaths, baselinePaths []string,
	moduleResolver tfresolver.Resolver,
) modulegraph.Result {
	packageBytes := c.ScanParams.MaxModulePackageBytes
	if packageBytes == 0 {
		packageBytes = DefaultRemoteModuleMaxPackageBytes
	}
	fileBytes := c.ScanParams.MaxModuleFileBytes
	if fileBytes == 0 {
		fileBytes = DefaultRemoteModuleMaxFileBytes
	}
	packageFiles := c.ScanParams.MaxModulePackageFiles
	if packageFiles == 0 {
		packageFiles = DefaultRemoteModuleMaxPackageFiles
	}
	return modulegraph.Resolve(ctx, &modulegraph.Request{
		RootPaths:      rootPaths,
		DiscoveryPaths: discoveryPaths,
		Resolver:       moduleResolver,
		MaxDepth:       c.ScanParams.ModuleMaxDepth,
		ResourceLimits: tfresolver.ResourceLimits{
			MaxPackageBytes: packageBytes,
			MaxFileBytes:    fileBytes,
			MaxPackageFiles: packageFiles,
			MaxTotalBytes:   c.ScanParams.MaxModuleBytesTotal,
		},
		BaselinePaths:   baselinePaths,
		TotalParseBytes: c.ScanParams.MaxModuleParseBytes,
		FS:              c.fsys,
	})
}

// resolvedModuleSourceType keeps the type detected from the declared source. A resolved Git ref only
// classifies otherwise unknown sources, since registry downloads may be Git-backed and must stay
// registry modules so their semver, not the commit SHA, is reported.
func resolvedModuleSourceType(module *modulegraph.ResolvedModule) string {
	sourceType, _ := tfmodules.DetectModuleSourceType(module.Source)
	if sourceType == moduleSourceTypeUnknown && module.ResolvedRef != "" {
		return moduleSourceTypeGit
	}
	return sourceType
}

func (c *Client) moduleResolutionContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if timeout := c.ScanParams.ModuleResolutionTimeout; timeout > 0 {
		return context.WithTimeout(ctx, timeout)
	}
	return ctx, func() {}
}

func (c *Client) shouldPreScanTerraformModules(_ []string) bool {
	return c.ScanParams.TerraformModules == TerraformModulesOn
}

func (c *Client) buildModuleResolverChain(
	ctx context.Context, moduleDiscoveryPaths []string,
) (*tfresolver.ChainResolver, error) {
	var manifest *tfresolver.Manifest
	if c.ScanParams.RemoteModulesManifestPath != "" {
		var err error
		manifest, err = tfresolver.LoadManifest(ctx, c.ScanParams.RemoteModulesManifestPath)
		if err != nil {
			return nil, err
		}
	}

	cacheBytes := c.ScanParams.MaxModuleCacheBytes
	if cacheBytes == 0 {
		cacheBytes = DefaultRemoteModuleMaxCacheBytes
	}
	return tfresolver.NewDefaultChain(ctx, &tfresolver.DefaultChainConfig{
		DiscoveryPaths: moduleDiscoveryPaths,
		Manifest:       manifest,
		FetchRemote: c.ScanParams.TerraformModules == TerraformModulesOn &&
			!c.ScanParams.NetworkIsolation,
		FetchTimeout:  c.ScanParams.ModuleFetchTimeout,
		HostAllowlist: c.ScanParams.RemoteModulesHostAllowlist,
		CacheRoot:     c.ScanParams.RemoteModulesCacheDir,
		MaxCacheBytes: cacheBytes,
	})
}

func platformsIncludeTerraform(platforms []string) bool {
	for _, p := range platforms {
		if strings.EqualFold(p, "terraform") {
			return true
		}
	}
	return false
}
