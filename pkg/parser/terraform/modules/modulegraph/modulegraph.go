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

type walker struct {
	mu             sync.Mutex
	visited        map[string]bool
	resolved       map[string]resolvedEntry
	paths          []string
	modules        []ResolvedModule
	sourceMappings map[string]string
	cleanups       []func()

	sf       singleflight.Group
	resolver resolver.Resolver
	maxDepth int
	fsys     vfs.FS

	parseMu    sync.Mutex
	parseCache map[string]map[string]tfmodules.ParsedModule
}

func Resolve(ctx context.Context, request *Request) Result {
	result := Result{
		SourceMappings: make(map[string]string),
		Cleanup:        func() {},
	}
	if request == nil || request.MaxDepth <= 0 || request.Resolver == nil {
		return result
	}

	w := &walker{
		visited:        make(map[string]bool),
		resolved:       make(map[string]resolvedEntry),
		sourceMappings: make(map[string]string),
		resolver:       request.Resolver,
		maxDepth:       request.MaxDepth,
		fsys:           request.FS,
		parseCache:     make(map[string]map[string]tfmodules.ParsedModule),
	}
	seedGroups, repositoryGroups := w.seedGroups(ctx, request.RootPaths, request.DiscoveryPaths)

	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(max(1, runtime.GOMAXPROCS(0)*seedGroupConcurrencyFactor))
	for seedDir, allowedFiles := range seedGroups {
		g.Go(func() error {
			w.traverse(gCtx, seedDir, allowedFiles, repositoryGroups, 0, false)
			return nil
		})
	}
	_ = g.Wait()

	w.mu.Lock()
	result.ScanPaths = append(result.ScanPaths, w.paths...)
	result.Modules = append(result.Modules, w.modules...)
	for localPath, source := range w.sourceMappings {
		result.SourceMappings[localPath] = source
	}
	cleanups := append([]func(){}, w.cleanups...)
	w.mu.Unlock()

	sort.Strings(result.ScanPaths)
	sort.Slice(result.Modules, func(i, j int) bool {
		left, right := result.Modules[i], result.Modules[j]
		return strings.Join([]string{left.CallerRoot, left.Source, left.Version, left.Name}, "\x00") <
			strings.Join([]string{right.CallerRoot, right.Source, right.Version, right.Name}, "\x00")
	})
	var once sync.Once
	result.Cleanup = func() {
		once.Do(func() {
			for _, cleanup := range cleanups {
				cleanup()
			}
		})
	}
	return result
}

func (w *walker) parseModulesInDir(
	ctx context.Context, dir string, allowedFiles map[string]bool,
) map[string]tfmodules.ParsedModule {
	key := filepath.Clean(dir) + "\x00" + allowedFilesCacheKey(allowedFiles)

	w.parseMu.Lock()
	if mods, ok := w.parseCache[key]; ok {
		w.parseMu.Unlock()
		return mods
	}
	w.parseMu.Unlock()

	var mods map[string]tfmodules.ParsedModule
	files, err := tfmodules.LoadTFFilesFromDir(dir)
	if err == nil && len(files) > 0 {
		withParseSlot(ctx, func() {
			parsed, parseErr := tfmodules.ParseTerraformModulesFromFiles(ctx, w.fsys, files, allowedFiles)
			if parseErr == nil {
				mods = parsed
			}
		})
	}

	w.parseMu.Lock()
	w.parseCache[key] = mods
	w.parseMu.Unlock()
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

func (w *walker) tryVisit(localPath string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.visited[localPath] {
		return false
	}
	w.visited[localPath] = true
	return true
}

func (w *walker) addPaths(paths ...string) {
	if len(paths) == 0 {
		return
	}
	w.mu.Lock()
	w.paths = append(w.paths, paths...)
	w.mu.Unlock()
}

func (w *walker) addResolvedModule(mod *tfmodules.ParsedModule, localPath string) {
	w.mu.Lock()
	w.modules = append(w.modules, ResolvedModule{
		CallerRoot:      moduleCallRoot(mod),
		Source:          mod.Source,
		Version:         mod.Version,
		Name:            mod.Name,
		LocalPath:       localPath,
		CanonicalSource: canonicalModuleURL(mod.Source, mod.Version),
	})
	w.mu.Unlock()
}

func (w *walker) addSourceMapping(localPath, source string) {
	w.mu.Lock()
	w.sourceMappings[localPath] = source
	w.mu.Unlock()
}

func (w *walker) addCleanup(cleanup func()) {
	w.mu.Lock()
	w.cleanups = append(w.cleanups, cleanup)
	w.mu.Unlock()
}

func (w *walker) resolveRemote(
	ctx context.Context, mod *tfmodules.ParsedModule,
) (resolver.Resolution, bool, error) {
	resolveID := remoteResolveIdentity(mod)

	w.mu.Lock()
	if entry, ok := w.resolved[resolveID]; ok {
		w.mu.Unlock()
		return entry.res, true, entry.err
	}
	w.mu.Unlock()

	value, err, shared := w.sf.Do(resolveID, func() (interface{}, error) {
		w.mu.Lock()
		if entry, ok := w.resolved[resolveID]; ok {
			w.mu.Unlock()
			return entry.res, entry.err
		}
		w.mu.Unlock()

		resolution, resolveErr := w.resolver.Resolve(ctx, mod)
		w.mu.Lock()
		w.resolved[resolveID] = resolvedEntry{res: resolution, err: resolveErr}
		w.mu.Unlock()
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
		mods := w.parseModulesInDir(ctx, dir, allowedFiles)
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
	inRemoteTree bool,
) {
	if depth >= w.maxDepth {
		return
	}
	mods := w.parseModulesInDir(ctx, seed, allowedFiles)
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
		if !inRemoteTree {
			var ok bool
			childAllowedFiles, ok = repoAllowedDirs[filepath.Clean(localDir)]
			if !ok {
				continue
			}
		}
		if !w.tryVisit(localDir) {
			continue
		}
		if inRemoteTree {
			w.addPaths(flatTerraformFilePaths(localDir)...)
		}
		w.traverse(ctx, localDir, childAllowedFiles, repoAllowedDirs, depth+1, inRemoteTree)
	}

	w.traverseRemoteModules(ctx, mods, repoAllowedDirs, depth)
}

type remoteModuleGroup struct {
	representative *tfmodules.ParsedModule
	callers        []*tfmodules.ParsedModule
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

		w.mu.Lock()
		cached, hit := w.resolved[id]
		w.mu.Unlock()
		if hit {
			if cached.err == nil && cached.res.LocalPath != "" {
				w.addResolvedModule(&mod, cached.res.LocalPath)
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
			contextLogger.Warn().Err(err).
				Msgf("Failed to resolve remote Terraform module %q", representative.Source)
		}
		return
	}
	if resolution.LocalPath == "" {
		if !shared {
			contextLogger.Warn().
				Msgf("Resolved remote Terraform module %q without a local path", representative.Source)
		}
		return
	}
	if !shared {
		contextLogger.Info().Msgf("Fetched remote Terraform module %q", representative.Source)
	}

	for _, mod := range group.callers {
		w.addResolvedModule(mod, resolution.LocalPath)
	}
	if !w.tryVisit(resolution.LocalPath) {
		return
	}
	if resolution.Cleanup != nil {
		w.addCleanup(resolution.Cleanup)
	}
	w.addPaths(flatTerraformFilePaths(resolution.LocalPath)...)
	w.addSourceMapping(
		resolution.LocalPath,
		canonicalModuleURL(representative.Source, representative.Version),
	)
	w.traverse(ctx, resolution.LocalPath, nil, repoAllowedDirs, depth+1, true)
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

func flatTerraformFilePaths(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var paths []string
	for _, entry := range entries {
		if !entry.IsDir() && isTerraformFile(entry.Name()) {
			paths = append(paths, filepath.Join(dir, entry.Name()))
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
