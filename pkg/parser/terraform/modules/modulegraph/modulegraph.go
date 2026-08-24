/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package modulegraph

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/resolver"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"
)

const (
	seedGroupConcurrencyFactor = 4
	sourceTypeRegistry         = "registry"
)

type Request struct {
	RootPaths      []string
	DiscoveryPaths []string
	Resolver       resolver.Resolver
	MaxDepth       int
	FS             vfs.FS
}

type ResolvedModule struct {
	CallerRoot      string
	Source          string
	Version         string
	Name            string
	LocalPath       string
	PackageRoot     string
	CanonicalSource string
}

type Result struct {
	ScanPaths      []string
	Modules        []ResolvedModule
	SourceMappings map[string]string
	Cleanup        func()
}

type resolvedEntry struct {
	res resolver.Resolution
	err error
}

type remoteModuleGroup struct {
	representative *tfmodules.ParsedModule
	callers        []*tfmodules.ParsedModule
}

type walkerSnapshot struct {
	paths          []string
	modules        []ResolvedModule
	sourceMappings map[string]string
	cleanups       []func()
}

type visitedSet struct {
	mu    sync.Mutex
	paths map[string]bool
}

type resolutionCache struct {
	mu      sync.RWMutex
	entries map[string]resolvedEntry
}

type resultCollector struct {
	mu             sync.RWMutex
	paths          []string
	modules        []ResolvedModule
	sourceMappings map[string]string
	cleanups       []func()
}

type moduleParseCache struct {
	mu      sync.RWMutex
	entries map[string]map[string]tfmodules.ParsedModule
}

type walker struct {
	visited     visitedSet
	resolutions resolutionCache
	results     resultCollector
	parseCache  moduleParseCache
	sf          singleflight.Group
	resolver    resolver.Resolver
	maxDepth    int
	fsys        vfs.FS
}

func Resolve(ctx context.Context, request *Request) Result {
	result := Result{
		SourceMappings: make(map[string]string),
		Cleanup:        func() {},
	}
	if request == nil || request.MaxDepth <= 0 || request.Resolver == nil {
		return result
	}
	ctx = resolver.WithResolvedPathCache(ctx)

	w := &walker{
		visited: visitedSet{
			paths: make(map[string]bool),
		},
		resolutions: resolutionCache{
			entries: make(map[string]resolvedEntry),
		},
		results: resultCollector{
			sourceMappings: make(map[string]string),
		},
		parseCache: moduleParseCache{
			entries: make(map[string]map[string]tfmodules.ParsedModule),
		},
		resolver: request.Resolver,
		maxDepth: request.MaxDepth,
		fsys:     request.FS,
	}
	seedGroups, repositoryGroups := w.seedGroups(ctx, request.RootPaths, request.DiscoveryPaths)

	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(max(1, runtime.GOMAXPROCS(0)*seedGroupConcurrencyFactor))
	for seedDir, allowedFiles := range seedGroups {
		g.Go(func() error {
			w.traverse(gCtx, seedDir, allowedFiles, repositoryGroups, 0, "")
			return nil
		})
	}
	_ = g.Wait()

	snapshot := w.results.snapshot()
	result.ScanPaths = snapshot.paths
	result.Modules = snapshot.modules
	result.SourceMappings = snapshot.sourceMappings

	sort.Strings(result.ScanPaths)
	sort.Slice(result.Modules, func(i, j int) bool {
		left, right := result.Modules[i], result.Modules[j]
		return strings.Join([]string{left.CallerRoot, left.Source, left.Version, left.Name}, "\x00") <
			strings.Join([]string{right.CallerRoot, right.Source, right.Version, right.Name}, "\x00")
	})
	var once sync.Once
	result.Cleanup = func() {
		once.Do(func() {
			for _, cleanup := range snapshot.cleanups {
				cleanup()
			}
		})
	}
	return result
}

func (w *walker) parseModulesInDir(
	ctx context.Context, dir string, allowedFiles map[string]bool, packageRoot string,
) map[string]tfmodules.ParsedModule {
	key := filepath.Clean(dir) + "\x00" + filepath.Clean(packageRoot) + "\x00" + allowedFilesCacheKey(allowedFiles)

	if mods, ok := w.parseCache.get(key); ok {
		return mods
	}

	var mods map[string]tfmodules.ParsedModule
	files, err := tfmodules.LoadTFFilesFromDir(dir, packageRoot)
	if err == nil && len(files) > 0 {
		withParseSlot(ctx, func() {
			parsed, parseErr := tfmodules.ParseTerraformModulesFromFiles(ctx, w.fsys, files, allowedFiles)
			if parseErr == nil {
				mods = parsed
			}
		})
	}

	w.parseCache.set(key, mods)
	return mods
}

func allowedFilesCacheKey(allowed map[string]bool) string {
	if allowed == nil {
		return "all"
	}
	paths := make([]string, 0, len(allowed))
	for path := range allowed {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return strings.Join(paths, "\x00")
}

func visitKey(localPath, packageRoot string) string {
	return filepath.Clean(localPath) + "\x00" + filepath.Clean(packageRoot)
}

func (s *visitedSet) tryAdd(localPath, packageRoot string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := visitKey(localPath, packageRoot)
	if s.paths[key] {
		return false
	}
	s.paths[key] = true
	return true
}

func (c *resultCollector) addPaths(paths ...string) {
	if len(paths) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.paths = append(c.paths, paths...)
}

func (c *resultCollector) addResolvedModule(mod *tfmodules.ParsedModule, resolution resolver.Resolution) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.modules = append(c.modules, ResolvedModule{
		CallerRoot:      moduleCallRoot(mod),
		Source:          mod.Source,
		Version:         mod.Version,
		Name:            mod.Name,
		LocalPath:       resolution.LocalPath,
		PackageRoot:     resolution.PackageRoot,
		CanonicalSource: canonicalModuleURL(mod.Source, mod.Version),
	})
}

func (c *resultCollector) addSourceMapping(localPath, source string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sourceMappings[localPath] = source
}

func (c *resultCollector) addCleanup(cleanup func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cleanups = append(c.cleanups, cleanup)
}

func (c *resultCollector) snapshot() walkerSnapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	sourceMappings := make(map[string]string, len(c.sourceMappings))
	for localPath, source := range c.sourceMappings {
		sourceMappings[localPath] = source
	}
	return walkerSnapshot{
		paths:          append([]string(nil), c.paths...),
		modules:        append([]ResolvedModule(nil), c.modules...),
		sourceMappings: sourceMappings,
		cleanups:       append([]func(){}, c.cleanups...),
	}
}

func (c *resolutionCache) get(resolveID string) (resolvedEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[resolveID]
	return entry, ok
}

func (c *resolutionCache) set(resolveID string, entry resolvedEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[resolveID] = entry
}

func (c *moduleParseCache) get(key string) (map[string]tfmodules.ParsedModule, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	mods, ok := c.entries[key]
	return mods, ok
}

func (c *moduleParseCache) set(key string, mods map[string]tfmodules.ParsedModule) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = mods
}

func (w *walker) resolveRemote(
	ctx context.Context, mod *tfmodules.ParsedModule,
) (resolver.Resolution, bool, error) {
	resolveID := remoteResolveIdentity(mod)

	if entry, ok := w.resolutions.get(resolveID); ok {
		return entry.res, true, entry.err
	}

	value, err, shared := w.sf.Do(resolveID, func() (interface{}, error) {
		if entry, ok := w.resolutions.get(resolveID); ok {
			return entry.res, entry.err
		}

		resolution, resolveErr := w.resolver.Resolve(ctx, mod)
		if resolveErr == nil && resolution.PackageRoot == "" && resolution.LocalPath != "" {
			resolution.PackageRoot = resolution.LocalPath
		}
		w.resolutions.set(resolveID, resolvedEntry{res: resolution, err: resolveErr})
		return resolution, resolveErr
	})
	if err != nil {
		return resolver.Resolution{}, shared, err
	}
	return value.(resolver.Resolution), shared, nil
}

var parseSem = make(chan struct{}, max(1, runtime.GOMAXPROCS(0)))

func withParseSlot(ctx context.Context, fn func()) {
	select {
	case parseSem <- struct{}{}:
		defer func() { <-parseSem }()
		fn()
	case <-ctx.Done():
	}
}

func (w *walker) seedGroups(
	ctx context.Context, paths, discoveryPaths []string,
) (seedGroups, repositoryGroups map[string]map[string]bool) {
	allowedByDir := make(map[string]map[string]bool)
	for _, path := range discoveryPaths {
		if !isTerraformFile(path) {
			continue
		}
		path = filepath.Clean(path)
		dir := filepath.Dir(path)
		if allowedByDir[dir] == nil {
			allowedByDir[dir] = make(map[string]bool)
		}
		allowedByDir[dir][path] = true
	}

	groups := make(map[string]map[string]bool)
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if !info.IsDir() {
			if !isTerraformFile(path) {
				continue
			}
			dir := filepath.Dir(path)
			if groups[dir] == nil {
				groups[dir] = make(map[string]bool)
			}
			groups[dir][path] = true
			continue
		}
		if len(discoveryPaths) == 0 {
			groups[path] = nil
			continue
		}
		for dir, allowedFiles := range allowedByDir {
			if pathContainsDir(path, dir) {
				groups[dir] = allowedFiles
			}
		}
	}
	seeds := make(map[string]map[string]bool, len(groups))
	for dir, allowedFiles := range groups {
		seeds[dir] = allowedFiles
	}
	for child := range w.localModuleChildDirs(ctx, groups) {
		delete(seeds, child)
	}
	return seeds, groups
}

func pathContainsDir(root, dir string) bool {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(dir))
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

func (w *walker) localModuleChildDirs(
	ctx context.Context, groups map[string]map[string]bool,
) map[string]bool {
	children := make(map[string]bool)
	for dir, allowedFiles := range groups {
		mods := w.parseModulesInDir(ctx, dir, allowedFiles, "")
		for key := range mods {
			mod := mods[key]
			if mod.IsLocal && groups[filepath.Clean(mod.AbsSource)] != nil {
				children[filepath.Clean(mod.AbsSource)] = true
			}
		}
	}
	return children
}

func (w *walker) traverse(
	ctx context.Context,
	seed string,
	allowedFiles map[string]bool,
	repoAllowedDirs map[string]map[string]bool,
	depth int,
	packageRoot string,
) {
	if depth >= w.maxDepth {
		return
	}
	mods := w.parseModulesInDir(ctx, seed, allowedFiles, packageRoot)
	if mods == nil {
		return
	}

	for key := range mods {
		mod := mods[key]
		if !mod.IsLocal || mod.AbsSource == "" {
			continue
		}
		localDir := mod.AbsSource
		childAllowedFiles := map[string]bool(nil)
		if packageRoot == "" {
			var ok bool
			childAllowedFiles, ok = repoAllowedDirs[filepath.Clean(localDir)]
			if !ok {
				continue
			}
		} else {
			var err error
			localDir, err = resolver.ResolvePathWithinRoot(ctx, packageRoot, localDir)
			if err != nil {
				contextLogger := logger.FromContext(ctx)
				contextLogger.Debug().
					Err(err).
					Msgf("skipping local module %q from %q", mod.Source, mod.FileName)
				continue
			}
		}
		if !w.visited.tryAdd(localDir, packageRoot) {
			continue
		}
		if packageRoot != "" {
			w.results.addPaths(flatTerraformFilePaths(ctx, localDir, packageRoot)...)
		}
		w.traverse(ctx, localDir, childAllowedFiles, repoAllowedDirs, depth+1, packageRoot)
	}

	w.traverseRemoteModules(ctx, mods, repoAllowedDirs, depth)
}

func (w *walker) traverseRemoteModules(
	ctx context.Context,
	mods map[string]tfmodules.ParsedModule,
	repoAllowedDirs map[string]map[string]bool,
	depth int,
) {
	groups := make(map[string]*remoteModuleGroup)
	for key := range mods {
		mod := mods[key]
		if mod.IsLocal {
			continue
		}
		id := remoteResolveIdentity(&mod)

		cached, hit := w.resolutions.get(id)
		if hit {
			if cached.err == nil && cached.res.LocalPath != "" {
				w.results.addResolvedModule(&mod, cached.res)
			}
			continue
		}

		if group, ok := groups[id]; ok {
			group.callers = append(group.callers, &mod)
		} else {
			groups[id] = &remoteModuleGroup{
				representative: &mod,
				callers:        []*tfmodules.ParsedModule{&mod},
			}
		}
	}
	if len(groups) == 0 {
		return
	}

	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(max(1, resolver.FetchConcurrency))
	for _, group := range groups {
		g.Go(func() error {
			w.traverseRemoteModuleGroup(gCtx, group, repoAllowedDirs, depth)
			return nil
		})
	}
	_ = g.Wait()
}

func (w *walker) traverseRemoteModuleGroup(
	ctx context.Context,
	group *remoteModuleGroup,
	repoAllowedDirs map[string]map[string]bool,
	depth int,
) {
	contextLogger := logger.FromContext(ctx)
	representative := group.representative
	contextLogger.Debug().Msgf("Fetching remote Terraform module %q", representative.Source)
	resolution, shared, err := w.resolveRemote(ctx, representative)
	if err != nil {
		if !shared {
			contextLogger.Debug().Err(err).
				Msgf("Failed to resolve remote Terraform module %q", representative.Source)
		}
		return
	}
	if resolution.LocalPath == "" {
		if !shared {
			contextLogger.Debug().
				Msgf("Resolved remote Terraform module %q without a local path", representative.Source)
		}
		return
	}
	if !shared {
		contextLogger.Debug().Msgf("Fetched remote Terraform module %q", representative.Source)
	}

	for _, mod := range group.callers {
		w.results.addResolvedModule(mod, resolution)
	}
	if !w.visited.tryAdd(resolution.LocalPath, resolution.PackageRoot) {
		return
	}
	if resolution.Cleanup != nil {
		w.results.addCleanup(resolution.Cleanup)
	}
	w.results.addPaths(flatTerraformFilePaths(ctx, resolution.LocalPath, resolution.PackageRoot)...)
	w.results.addSourceMapping(
		resolution.LocalPath,
		canonicalModuleURL(representative.Source, representative.Version),
	)
	w.traverse(ctx, resolution.LocalPath, nil, repoAllowedDirs, depth+1, resolution.PackageRoot)
}

func moduleCallRoot(mod *tfmodules.ParsedModule) string {
	if mod.FileName == "" {
		return "."
	}
	return filepath.Clean(filepath.Dir(mod.FileName))
}

func remoteResolveIdentity(mod *tfmodules.ParsedModule) string {
	sourceType, _ := tfmodules.DetectModuleSourceType(mod.Source)
	if sourceType == sourceTypeRegistry && mod.Version == "" {
		return callKey(moduleCallRoot(mod), mod.Source, mod.Version, mod.Name)
	}
	if key, ok := resolver.GitModuleResolveKey(mod.Source, mod.Version); ok {
		return key
	}
	return canonicalGitModuleSource(mod.Source) + "\x00" + strings.TrimSpace(mod.Version)
}

func callKey(root, source, version, name string) string {
	return filepath.Clean(root) + "\x00" + strings.TrimSpace(source) + "\x00" +
		strings.TrimSpace(version) + "\x00" + strings.TrimSpace(name)
}

func flatTerraformFilePaths(ctx context.Context, dir, packageRoot string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var paths []string
	for _, entry := range entries {
		if path, ok := resolver.ScannableTerraformPath(ctx, entry, dir, packageRoot); ok {
			paths = append(paths, path)
		}
	}
	return paths
}

func isTerraformFile(path string) bool {
	return strings.HasSuffix(strings.ToLower(path), ".tf")
}

func canonicalGitModuleSource(moduleSource string) string {
	source := strings.TrimSpace(moduleSource)
	source = strings.ReplaceAll(source, "///", "//")
	switch {
	case strings.Contains(source, ".git//"):
		return strings.Replace(source, ".git//", "//", 1)
	case strings.Contains(source, ".git?"):
		return strings.Replace(source, ".git?", "?", 1)
	case strings.HasSuffix(source, ".git"):
		return strings.TrimSuffix(source, ".git")
	}
	return source
}

func canonicalModuleURL(moduleSource, version string) string {
	source := canonicalGitModuleSource(moduleSource)
	sourceType, scope := tfmodules.DetectModuleSourceType(source)
	if sourceType == sourceTypeRegistry && scope == "public" &&
		!strings.HasPrefix(source, "registry.terraform.io/") {
		source = "registry.terraform.io/" + source
	}
	if index := strings.Index(source, "@"); index != -1 {
		if schemeEnd := strings.Index(source, "://"); schemeEnd != -1 && schemeEnd < index {
			source = source[:schemeEnd+3] + source[index+1:]
		}
	}
	if version != "" {
		source += "@" + version
	}
	return source
}
