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
	"sort"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/engine"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	tfresolver "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/resolver"
)

type moduleResolverAdapter struct {
	resolver tfresolver.Resolver
}

func (r moduleResolverAdapter) Resolve(ctx context.Context, mod *tfmodules.ParsedModule) (string, error) {
	res, err := r.resolver.Resolve(ctx, mod)
	if err != nil {
		return "", err
	}
	return res.LocalPath, nil
}

func (c *Client) prepareRemoteModules(ctx context.Context, paths []string, inspector *engine.Inspector) error {
	if !c.ScanParams.EnableRemoteModules {
		return nil
	}
	files, roots, err := c.collectTerraformModuleFiles(paths)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return nil
	}

	parsedModules, err := tfmodules.ParseTerraformModules(ctx, c.fsys, files, c.ScanParams.ParallelScanFlag)
	if err != nil {
		return err
	}
	if len(parsedModules) == 0 {
		return nil
	}

	resolver, err := c.buildTerraformModuleResolver(roots)
	if err != nil {
		return err
	}
	enriched, err := tfmodules.ParseAllModuleVariables(ctx, c.fsys, parsedModules, c.ScanParams.RepoPath,
		moduleResolverAdapter{resolver: resolver})
	if err != nil {
		return err
	}

	dirs := make(map[string]string)
	for i := range enriched {
		mod := &enriched[i]
		if mod.IsLocal || mod.AbsSource == "" {
			continue
		}
		root := moduleRoot(mod.FileName, c.ScanParams.RepoPath)
		dirs[engine.RemoteModuleKey(root, mod.Source, mod.Version)] = mod.AbsSource
		dirs[engine.RemoteModuleCallKey(root, mod.Source, mod.Version, mod.Name)] = mod.AbsSource
	}
	if len(dirs) == 0 {
		return nil
	}
	inspector.SetRemoteModuleDirectories(dirs)
	remotePaths := mapValues(dirs)
	inspector.SetExternalModulePaths(remotePaths)
	c.remoteModulePaths = remotePaths
	contextLogger := logger.FromContext(ctx)
	contextLogger.Info().Msgf("Resolved %d Terraform remote module directories", len(dirs))
	return nil
}

func (c *Client) buildTerraformModuleResolver(roots []string) (tfresolver.Resolver, error) {
	resolvers := []tfresolver.Resolver{
		&tfresolver.DotTerraformResolver{RootDirs: roots},
		tfresolver.NewLocalGitRefResolver(roots, ""),
		tfresolver.NewBareGitResolver(""),
	}
	if c.ScanParams.RemoteModulesManifestPath != "" {
		manifest, err := tfresolver.LoadManifest(c.ScanParams.RemoteModulesManifestPath)
		if err != nil {
			return nil, err
		}
		resolvers = append([]tfresolver.Resolver{tfresolver.NewPrefetchedResolver(manifest)}, resolvers...)
	}
	cfg := tfresolver.NewGoGetterConfig()
	cfg.HostAllowlist = c.ScanParams.RemoteModulesHostAllowlist
	cache, err := tfresolver.NewModuleCache()
	if err != nil {
		return nil, err
	}
	cfg.Cache = cache
	resolvers = append(resolvers, tfresolver.NewGoGetterResolver(cfg))
	return tfresolver.NewChainResolver(resolvers...), nil
}

func (c *Client) collectTerraformModuleFiles(paths []string) (model.FileMetadatas, []string, error) {
	filesByPath := make(map[string]*model.FileMetadata)
	roots := make(map[string]struct{})
	addPath := func(path string) error {
		if !strings.EqualFold(filepath.Ext(path), ".tf") {
			return nil
		}
		data, ok := c.contentCache[path]
		if !ok {
			var err error
			data, err = os.ReadFile(filepath.Clean(path))
			if err != nil {
				return err
			}
		}
		filesByPath[path] = &model.FileMetadata{FilePath: path, OriginalData: string(data)}
		roots[moduleRoot(path, c.ScanParams.RepoPath)] = struct{}{}
		return nil
	}

	if len(c.walkInventory) > 0 {
		for _, path := range c.walkInventory {
			if err := addPath(path); err != nil {
				return nil, nil, err
			}
		}
	} else {
		for _, scanPath := range paths {
			info, err := os.Stat(scanPath)
			if err != nil {
				return nil, nil, err
			}
			if !info.IsDir() {
				if err := addPath(scanPath); err != nil {
					return nil, nil, err
				}
				continue
			}
			err = filepath.WalkDir(scanPath, func(path string, d os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if d.IsDir() && strings.HasPrefix(d.Name(), ".terra") {
					return filepath.SkipDir
				}
				if d.IsDir() {
					return nil
				}
				return addPath(path)
			})
			if err != nil {
				return nil, nil, err
			}
		}
	}

	pathsSorted := make([]string, 0, len(filesByPath))
	for path := range filesByPath {
		pathsSorted = append(pathsSorted, path)
	}
	sort.Strings(pathsSorted)
	files := make(model.FileMetadatas, 0, len(pathsSorted))
	for _, path := range pathsSorted {
		files = append(files, filesByPath[path])
	}

	rootsSorted := make([]string, 0, len(roots))
	for root := range roots {
		rootsSorted = append(rootsSorted, root)
	}
	sort.Strings(rootsSorted)
	return files, rootsSorted, nil
}

func moduleRoot(fileName, repoPath string) string {
	if fileName == "" {
		return filepath.Clean(repoPath)
	}
	if filepath.IsAbs(fileName) {
		return filepath.Clean(filepath.Dir(fileName))
	}
	return filepath.Clean(filepath.Dir(filepath.Join(repoPath, fileName)))
}

func mapValues(values map[string]string) []string {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		seen[value] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
