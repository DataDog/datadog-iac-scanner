/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package scan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/engine"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/provider"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/modulegraph"
	tfresolver "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/resolver"
)

func (c *Client) resolveTerraformModulesForScan(
	ctx context.Context,
	paramsPlatforms []string,
	extractedPaths *provider.ExtractedPath,
) (moduleCleanup func(), remoteModulePaths []string, remoteSourceDirs map[string]string, err error) {
	if !platformsIncludeTerraform(paramsPlatforms) || !c.shouldPreScanTerraformModules(extractedPaths.Path) {
		return nil, nil, nil, nil
	}

	contextLogger := logger.FromContext(ctx)
	if c.ScanParams.EnableRemoteModules {
		contextLogger.Info().Msg("Resolving remote Terraform modules...")
	} else {
		contextLogger.Debug().Msg("Resolving Terraform modules from local, manifest, or .terraform/modules sources only")
	}

	result, err := c.resolveTerraformModuleGraph(ctx, extractedPaths.Path)
	if err != nil {
		return nil, nil, nil, err
	}
	if result.Error != nil {
		result.Cleanup()
		return nil, nil, nil, fmt.Errorf("resolving modules from manifest: %w", result.Error)
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
	remoteSourceDirs = make(map[string]string, len(result.Modules)*3)
	for i := range result.Modules {
		module := &result.Modules[i]
		requestedVersion := module.RequestedVersion
		if requestedVersion == "" {
			requestedVersion = module.Version
		}
		remoteSourceDirs[engine.RemoteModuleKey(
			module.CallerRoot, module.Source, requestedVersion,
		)] = module.LocalPath
		remoteSourceDirs[engine.RemoteModuleCallKey(
			module.CallerRoot, module.Source, requestedVersion, module.Name,
		)] = module.LocalPath
		remoteSourceDirs[engine.RemoteModuleCallKey(
			module.CallerRoot, module.Source, "", module.Name,
		)] = module.LocalPath
		if module.ResolvedVersion != "" && module.ResolvedVersion != requestedVersion {
			remoteSourceDirs[engine.RemoteModuleKey(
				module.CallerRoot, module.Source, module.ResolvedVersion,
			)] = module.LocalPath
		}
	}
	return result.Cleanup, result.ScanPaths, remoteSourceDirs, nil
}

func (c *Client) resolveTerraformModuleGraph(
	ctx context.Context, rootPaths []string,
) (modulegraph.Result, error) {
	hostedMode := c.ScanParams.RemoteModulesManifestPath != ""
	var manifest *tfresolver.Manifest
	if hostedMode {
		loaded, err := tfresolver.LoadManifest(c.ScanParams.RemoteModulesManifestPath)
		if err != nil {
			return modulegraph.Result{}, fmt.Errorf(
				"loading modules manifest %q: %w",
				c.ScanParams.RemoteModulesManifestPath, err,
			)
		}
		manifest = loaded
	}
	if manifest.HasCompleteDiscovery() {
		if c.ScanParams.ModuleMaxDepth <= 0 {
			return modulegraph.Result{SourceMappings: make(map[string]string), Cleanup: func() {}}, nil
		}
		return modulegraph.FromManifestDiscovery(
			manifest.Discovery,
			c.ScanParams.RepoPath,
			c.ScanParams.ModuleMaxDepth,
		), nil
	}

	filteredFilesSource, err := c.getFileSystemSourceProvider(ctx, rootPaths)
	if err != nil {
		return modulegraph.Result{}, err
	}
	moduleDiscoveryPaths, err := filteredFilesSource.TerraformFiles(ctx)
	if err != nil {
		return modulegraph.Result{}, err
	}
	var chain *tfresolver.ChainResolver
	if hostedMode {
		chain, err = c.buildModuleResolverChainWithManifest(ctx, moduleDiscoveryPaths, manifest)
	} else {
		chain, err = c.buildModuleResolverChain(ctx, moduleDiscoveryPaths)
	}
	if err != nil {
		return modulegraph.Result{}, err
	}
	return modulegraph.Resolve(ctx, &modulegraph.Request{
		RootPaths:            rootPaths,
		DiscoveryPaths:       moduleDiscoveryPaths,
		Resolver:             chain,
		MaxDepth:             c.ScanParams.ModuleMaxDepth,
		FS:                   c.fsys,
		CallScopedResolution: hostedMode,
	}), nil
}

func (c *Client) shouldPreScanTerraformModules(scanPaths []string) bool {
	if c.ScanParams.EnableRemoteModules || c.ScanParams.RemoteModulesManifestPath != "" {
		return true
	}
	return HasTerraformModuleCache(scanPaths)
}

func HasTerraformModuleCache(scanPaths []string) bool {
	for _, root := range dotTerraformRootDirs(scanPaths) {
		if hasTerraformModulesManifest(root) {
			return true
		}
	}
	return false
}

func (c *Client) buildModuleResolverChain(
	ctx context.Context, moduleDiscoveryPaths []string,
) (*tfresolver.ChainResolver, error) {
	var manifest *tfresolver.Manifest
	if c.ScanParams.RemoteModulesManifestPath != "" {
		loaded, err := tfresolver.LoadManifest(c.ScanParams.RemoteModulesManifestPath)
		if err != nil {
			return nil, fmt.Errorf("loading modules manifest %q: %w", c.ScanParams.RemoteModulesManifestPath, err)
		}
		manifest = loaded
	}
	return c.buildModuleResolverChainWithManifest(ctx, moduleDiscoveryPaths, manifest)
}

func (c *Client) buildModuleResolverChainWithManifest(
	ctx context.Context,
	moduleDiscoveryPaths []string,
	manifest *tfresolver.Manifest,
) (*tfresolver.ChainResolver, error) {
	contextLogger := logger.FromContext(ctx)

	resolvers := []tfresolver.Resolver{
		tfresolver.LocalResolver{},
	}

	if c.ScanParams.RemoteModulesManifestPath != "" {
		resolvers = append(resolvers, tfresolver.NewPrefetchedResolver(manifest))
	} else {
		resolvers = append(resolvers, &tfresolver.DotTerraformResolver{
			RootDirs: dotTerraformRootDirs(moduleDiscoveryPaths),
		})
	}

	hostedMode := c.ScanParams.RemoteModulesManifestPath != ""
	if c.ScanParams.EnableRemoteModules && !hostedMode {
		resolvers = append(resolvers,
			tfresolver.NewLocalGitRefResolver(dotTerraformRootDirs(moduleDiscoveryPaths), ""),
			tfresolver.NewBareGitResolver("", c.ScanParams.RemoteModulesHostAllowlist...),
		)
	}

	ggCfg := tfresolver.NewGoGetterConfig()
	ggCfg.Disabled = !c.ScanParams.EnableRemoteModules || hostedMode
	if t := c.ScanParams.ModuleFetchTimeout; t > 0 {
		ggCfg.FetchTimeout = t
		ggCfg.RegistryCache = tfresolver.NewRegistryCache(ggCfg.FetchTimeout)
	}
	ggCfg.MaxTotalBytes = c.ScanParams.MaxModuleBytesTotal
	ggCfg.HostAllowlist = c.ScanParams.RemoteModulesHostAllowlist

	if !ggCfg.Disabled {
		cache, err := tfresolver.NewModuleCache()
		if err != nil {
			contextLogger.Warn().Err(err).Msg("Module disk cache unavailable; fetched modules will not be cached")
		} else {
			ggCfg.Cache = cache
		}
	}

	if !hostedMode {
		resolvers = append(resolvers, tfresolver.NewGoGetterResolver(ggCfg))
	}
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
