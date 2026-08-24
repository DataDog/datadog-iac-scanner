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
) (
	moduleCleanup func(),
	remoteModulePaths []string,
	remoteSourceDirs map[string]engine.RemoteModuleDirectory,
	err error,
) {
	if !platformsIncludeTerraform(paramsPlatforms) || !c.shouldPreScanTerraformModules(extractedPaths.Path) {
		return nil, nil, nil, nil
	}

	contextLogger := logger.FromContext(ctx)
	filteredFilesSource, err := c.getFileSystemSourceProvider(ctx, extractedPaths.Path)
	if err != nil {
		return nil, nil, nil, err
	}
	moduleDiscoveryPaths, err := filteredFilesSource.TerraformFiles(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	chain := c.buildModuleResolverChain(ctx, moduleDiscoveryPaths)

	if c.ScanParams.EnableRemoteModules {
		contextLogger.Info().Msg("Resolving remote Terraform modules...")
	} else {
		contextLogger.Debug().Msg("Resolving Terraform modules from local, manifest, or .terraform/modules sources only")
	}

	result := modulegraph.Resolve(ctx, &modulegraph.Request{
		RootPaths:      extractedPaths.Path,
		DiscoveryPaths: moduleDiscoveryPaths,
		Resolver:       chain,
		MaxDepth:       c.ScanParams.ModuleMaxDepth,
		FS:             c.fsys,
	})
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
	for _, module := range result.Modules {
		directory := engine.RemoteModuleDirectory{
			Path:        module.LocalPath,
			PackageRoot: module.PackageRoot,
		}
		remoteSourceDirs[engine.RemoteModuleKey(
			module.CallerRoot, module.Source, module.Version,
		)] = directory
		remoteSourceDirs[engine.RemoteModuleCallKey(
			module.CallerRoot, module.Source, module.Version, module.Name,
		)] = directory
		remoteSourceDirs[engine.RemoteModuleCallKey(
			module.CallerRoot, module.Source, "", module.Name,
		)] = directory
	}
	return result.Cleanup, result.ScanPaths, remoteSourceDirs, nil
}

func (c *Client) shouldPreScanTerraformModules(scanPaths []string) bool {
	if !c.ScanParams.EnableRemoteModules {
		return false
	}
	if c.ScanParams.RemoteModulesManifestPath != "" {
		return true
	}
	for _, root := range dotTerraformRootDirs(scanPaths) {
		if hasTerraformModulesManifest(root) {
			return true
		}
	}
	return true
}

func (c *Client) buildModuleResolverChain(ctx context.Context, moduleDiscoveryPaths []string) *tfresolver.ChainResolver {
	contextLogger := logger.FromContext(ctx)

	resolvers := []tfresolver.Resolver{
		tfresolver.LocalResolver{},
		&tfresolver.DotTerraformResolver{RootDirs: dotTerraformRootDirs(moduleDiscoveryPaths)},
	}

	if c.ScanParams.RemoteModulesManifestPath != "" {
		manifest, err := tfresolver.LoadManifest(c.ScanParams.RemoteModulesManifestPath)
		if err != nil {
			contextLogger.Warn().Err(err).
				Msgf("Failed to load modules manifest %q; remote modules from manifest will be unresolved",
					c.ScanParams.RemoteModulesManifestPath)
		} else {
			resolvers = append(resolvers, tfresolver.NewPrefetchedResolver(manifest))
		}
	}

	if c.ScanParams.EnableRemoteModules {
		resolvers = append(resolvers,
			tfresolver.NewLocalGitRefResolver(dotTerraformRootDirs(moduleDiscoveryPaths), ""),
			tfresolver.NewBareGitResolver("", c.ScanParams.RemoteModulesHostAllowlist...),
		)
	}

	ggCfg := tfresolver.NewGoGetterConfig()
	ggCfg.Disabled = !c.ScanParams.EnableRemoteModules
	if t := c.ScanParams.ModuleFetchTimeout; t > 0 {
		ggCfg.FetchTimeout = t
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

	resolvers = append(resolvers, tfresolver.NewGoGetterResolver(ggCfg))
	return tfresolver.NewChainResolver(resolvers...)
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
