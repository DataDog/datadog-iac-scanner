/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package scan

import (
	"context"
	"os"
	"path/filepath"
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
	err error,
) {
	if !platformsIncludeTerraform(paramsPlatforms) || !c.shouldPreScanTerraformModules(extractedPaths.Path) {
		return nil, nil, nil, nil, nil
	}

	contextLogger := logger.FromContext(ctx)
	filteredFilesSource, err := c.getFileSystemSourceProvider(ctx, extractedPaths.Path)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	moduleDiscoveryPaths, err := filteredFilesSource.TerraformFiles(ctx)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	resolveCtx, cancel := c.moduleResolutionContext(ctx)
	defer cancel()

	chain, err := c.buildModuleResolverChain(resolveCtx, moduleDiscoveryPaths)
	if err != nil {
		return nil, nil, nil, nil, err
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
	for _, failure := range result.Failures {
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
	return result.Cleanup, result.ScanPaths, remoteSourceDirs, remoteModuleProvenance, nil
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
		MaxModules:     c.ScanParams.ModuleMaxModules,
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
	contextLogger := logger.FromContext(ctx)

	resolvers := []tfresolver.Resolver{
		tfresolver.LocalResolver{},
		&tfresolver.DotTerraformResolver{RootDirs: dotTerraformRootDirs(moduleDiscoveryPaths)},
	}

	if c.ScanParams.RemoteModulesManifestPath != "" {
		manifest, err := tfresolver.LoadManifest(ctx, c.ScanParams.RemoteModulesManifestPath)
		if err != nil {
			return nil, err
		}
		resolvers = append(resolvers, tfresolver.NewPrefetchedResolver(manifest))
	}

	if c.ScanParams.TerraformModules != TerraformModulesOn || c.ScanParams.NetworkIsolation {
		return tfresolver.NewChainResolver(resolvers...), nil
	}

	ggCfg := tfresolver.NewGoGetterConfig()
	if t := c.ScanParams.ModuleFetchTimeout; t > 0 {
		ggCfg.FetchTimeout = t
	}
	ggCfg.HostAllowlist = c.ScanParams.RemoteModulesHostAllowlist

	cacheBytes := c.ScanParams.MaxModuleCacheBytes
	if cacheBytes == 0 {
		cacheBytes = DefaultRemoteModuleMaxCacheBytes
	}

	var (
		cacheRoot string
		budget    *tfresolver.ModuleCacheBudget
	)
	cacheRoot = strings.TrimSpace(c.ScanParams.RemoteModulesCacheDir)
	if cacheRoot == "" {
		var rootErr error
		cacheRoot, rootErr = tfresolver.DefaultModuleCacheRoot()
		if rootErr != nil {
			contextLogger.Warn().Err(rootErr).Msg("Remote module cache root unavailable; cache limits will not be enforced")
		}
	}
	if cacheRoot != "" {
		var budgetErr error
		budget, budgetErr = tfresolver.NewModuleCacheBudget(cacheRoot, cacheBytes)
		if budgetErr != nil {
			contextLogger.Warn().Err(budgetErr).Msg("Remote module cache budget unavailable; cache limits will not be enforced")
		}
	}

	gitCacheDir := tfresolver.ModuleCacheSubdir(cacheRoot, tfresolver.CacheSubdirGitBare)
	localCacheDir := tfresolver.ModuleCacheSubdir(cacheRoot, tfresolver.CacheSubdirGitLocal)
	git := tfresolver.NewBareGitResolver(gitCacheDir, c.ScanParams.RemoteModulesHostAllowlist...)
	git.Budget = budget
	ggCfg.Git = git
	localGit := tfresolver.NewLocalGitRefResolver(dotTerraformRootDirs(moduleDiscoveryPaths), localCacheDir)
	localGit.Budget = budget
	resolvers = append(resolvers, localGit, git)

	moduleCacheDir := tfresolver.ModuleCacheSubdir(cacheRoot, tfresolver.CacheSubdirModules)
	cache, err := tfresolver.NewModuleCacheWithDir(moduleCacheDir, budget)
	if err != nil {
		contextLogger.Warn().Err(err).Msg("Module disk cache unavailable; fetched modules will not be cached")
	} else {
		ggCfg.Cache = cache
	}

	resolvers = append(resolvers, tfresolver.NewGoGetterResolver(ggCfg))
	return tfresolver.NewChainResolver(resolvers...), nil
}

func dotTerraformRootDirs(paths []string) []string {
	seen := make(map[string]bool, len(paths))
	roots := make([]string, 0, len(paths))
	for _, p := range paths {
		root := terraformRootDir(p)
		if root == "" || seen[root] {
			continue
		}
		seen[root] = true
		roots = append(roots, root)
	}
	return roots
}

func terraformRootDir(path string) string {
	info, err := os.Stat(path)
	if err == nil && !info.IsDir() {
		path = filepath.Dir(path)
	}
	clean := filepath.Clean(path)
	for {
		if hasTerraformModulesManifest(clean) {
			return clean
		}
		parent := filepath.Dir(clean)
		if parent == clean {
			return filepath.Clean(path)
		}
		clean = parent
	}
}

func hasTerraformModulesManifest(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, ".terraform", "modules", "modules.json"))
	return err == nil
}

func platformsIncludeTerraform(platforms []string) bool {
	for _, p := range platforms {
		if strings.EqualFold(p, "terraform") {
			return true
		}
	}
	return false
}
