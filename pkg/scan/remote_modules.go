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
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/engine"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	tfresolver "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/resolver"
)

type moduleResolverAdapter struct {
	resolver tfresolver.Resolver
	mu       sync.Mutex
	cleanups []func()
	once     sync.Once
}

func (r *moduleResolverAdapter) Resolve(ctx context.Context, mod *tfmodules.ParsedModule) (string, error) {
	res, err := r.resolver.Resolve(ctx, mod)
	if err != nil {
		return "", err
	}
	if res.Cleanup != nil {
		r.mu.Lock()
		r.cleanups = append(r.cleanups, res.Cleanup)
		r.mu.Unlock()
	}
	return res.LocalPath, nil
}

func (r *moduleResolverAdapter) cleanup() {
	r.once.Do(func() {
		r.mu.Lock()
		cleanups := append([]func(){}, r.cleanups...)
		r.cleanups = nil
		r.mu.Unlock()
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	})
}

func (c *Client) prepareRemoteModules(
	ctx context.Context, paths []string, inspector *engine.Inspector,
) (cleanup func(), err error) {
	noCleanup := func() {}
	if !c.ScanParams.EnableRemoteModules {
		return noCleanup, nil
	}
	files, roots, err := c.collectTerraformModuleFiles(paths)
	if err != nil {
		return noCleanup, err
	}
	if len(files) == 0 {
		return noCleanup, nil
	}

	parsedModules, err := tfmodules.ParseTerraformModules(ctx, c.fsys, files, c.ScanParams.ParallelScanFlag)
	if err != nil {
		return noCleanup, err
	}
	if len(parsedModules) == 0 {
		return noCleanup, nil
	}

	resolver, err := c.buildTerraformModuleResolver(roots)
	if err != nil {
		return noCleanup, err
	}
	adapter := &moduleResolverAdapter{resolver: resolver}
	enriched, err := tfmodules.ParseAllModuleVariables(ctx, c.fsys, parsedModules, c.ScanParams.RepoPath,
		adapter)
	if err != nil {
		adapter.cleanup()
		return noCleanup, err
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
		return adapter.cleanup, nil
	}
	inspector.SetRemoteModuleDirectories(dirs)
	remotePaths := mapValues(dirs)
	inspector.SetExternalModulePaths(remotePaths)
	c.remoteModulePaths = remotePaths
	if err := c.addRemoteModuleFilesToInventory(remotePaths); err != nil {
		adapter.cleanup()
		return noCleanup, err
	}
	contextLogger := logger.FromContext(ctx)
	contextLogger.Info().Msgf("Resolved %d Terraform remote module directories", len(dirs))
	return adapter.cleanup, nil
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
	files := newTerraformModuleFiles(c.contentCache, c.ScanParams.RepoPath)
	if len(c.walkInventory) > 0 {
		for _, path := range c.walkInventory {
			if err := files.add(path); err != nil {
				return nil, nil, err
			}
		}
		return files.sorted()
	}
	for _, scanPath := range paths {
		if err := files.addScanPath(scanPath); err != nil {
			return nil, nil, err
		}
	}
	return files.sorted()
}

type terraformModuleFiles struct {
	contentCache map[string][]byte
	repoPath     string
	filesByPath  map[string]*model.FileMetadata
	roots        map[string]struct{}
}

func newTerraformModuleFiles(contentCache map[string][]byte, repoPath string) *terraformModuleFiles {
	return &terraformModuleFiles{
		contentCache: contentCache,
		repoPath:     repoPath,
		filesByPath:  make(map[string]*model.FileMetadata),
		roots:        make(map[string]struct{}),
	}
}

func (f *terraformModuleFiles) add(path string) error {
	if !strings.EqualFold(filepath.Ext(path), ".tf") {
		return nil
	}
	data, ok := f.contentCache[path]
	if !ok {
		var err error
		data, err = os.ReadFile(filepath.Clean(path))
		if err != nil {
			return err
		}
	}
	f.filesByPath[path] = &model.FileMetadata{FilePath: path, OriginalData: string(data)}
	f.roots[moduleRoot(path, f.repoPath)] = struct{}{}
	return nil
}

func (f *terraformModuleFiles) addScanPath(scanPath string) error {
	info, err := os.Stat(scanPath)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return f.add(scanPath)
	}
	return filepath.WalkDir(scanPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && strings.HasPrefix(d.Name(), ".terra") {
			return filepath.SkipDir
		}
		if d.IsDir() {
			return nil
		}
		return f.add(path)
	})
}

func (f *terraformModuleFiles) sorted() (model.FileMetadatas, []string, error) {
	pathsSorted := make([]string, 0, len(f.filesByPath))
	for path := range f.filesByPath {
		pathsSorted = append(pathsSorted, path)
	}
	sort.Strings(pathsSorted)
	files := make(model.FileMetadatas, 0, len(pathsSorted))
	for _, path := range pathsSorted {
		files = append(files, f.filesByPath[path])
	}

	rootsSorted := make([]string, 0, len(f.roots))
	for root := range f.roots {
		rootsSorted = append(rootsSorted, root)
	}
	sort.Strings(rootsSorted)
	return files, rootsSorted, nil
}

func (c *Client) addRemoteModuleFilesToInventory(moduleDirs []string) error {
	if len(c.walkInventory) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(c.walkInventory))
	for _, path := range c.walkInventory {
		seen[path] = struct{}{}
	}
	for _, dir := range moduleDirs {
		moduleFiles := make([]string, 0)
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if !strings.EqualFold(filepath.Ext(path), ".tf") {
				return nil
			}
			norm := strings.ReplaceAll(path, "\\", "/")
			moduleFiles = append(moduleFiles, norm)
			return nil
		})
		if err != nil {
			return err
		}
		for _, path := range moduleFiles {
			if _, ok := seen[path]; ok {
				continue
			}
			seen[path] = struct{}{}
			c.walkInventory = append(c.walkInventory, path)
			if c.contentCache != nil {
				if _, ok := c.contentCache[path]; !ok {
					data, readErr := os.ReadFile(filepath.Clean(path))
					if readErr != nil {
						return readErr
					}
					c.contentCache[path] = data
				}
			}
		}
	}
	sort.Strings(c.walkInventory)
	return nil
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
