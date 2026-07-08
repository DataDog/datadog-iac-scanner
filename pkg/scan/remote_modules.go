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
	"runtime"
	"sort"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"

	"github.com/DataDog/datadog-iac-scanner/pkg/engine"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/provider"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	tfresolver "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/resolver"
)

const seedGroupConcurrencyFactor = 4

// resolveTerraformModulesForScan runs the bounded module graph-walker and wires its
// results into extractedPaths so the scanner sees resolved remote module files.
func (c *Client) resolveTerraformModulesForScan(
	ctx context.Context,
	paramsPlatforms []string,
	extractedPaths *provider.ExtractedPath,
) (moduleCleanups []func(), remoteModulePaths []string, remoteSourceDirs map[string]string, err error) {
	if !platformsIncludeTerraform(paramsPlatforms) || !c.shouldPreScanTerraformModules(extractedPaths.Path) {
		return nil, nil, nil, nil
	}

	contextLogger := logger.FromContext(ctx)
	filteredFilesSource, err := c.getFileSystemSourceProvider(ctx, extractedPaths.Path, nil)
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

	maxDepth := c.ScanParams.ModuleMaxDepth
	if maxDepth == 0 {
		maxDepth = 8 // default when unset
	}
	moduleScanPaths, moduleExtractions, sourceDirs, cleanups := c.resolveRemoteModuleScanPaths(
		ctx, extractedPaths.Path, moduleDiscoveryPaths, chain, maxDepth)
	if len(moduleScanPaths) > 0 {
		contextLogger.Info().Msgf("Adding %d remote module file(s) to scan", len(moduleScanPaths))
		remoteModulePaths = moduleScanPaths
		for k, v := range moduleExtractions {
			extractedPaths.ExtractionMap[k] = v
		}
	}
	return cleanups, remoteModulePaths, sourceDirs, nil
}

func (c *Client) shouldPreScanTerraformModules(scanPaths []string) bool {
	// EnableRemoteModules is the primary gate; without it nothing is resolved.
	if !c.ScanParams.EnableRemoteModules {
		return false
	}
	// When enabled, also run the walker if a manifest or .terraform/modules data is present
	// (covers offline / pre-fetched scenarios without requiring network access).
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

// buildModuleResolverChain returns: local → .terraform/modules → manifest → LocalGitRef → BareGit → GoGetter
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
			tfresolver.NewLocalGitRefResolver(c.ScanParams.Path, ""),
			tfresolver.NewBareGitResolver(""),
		)
	}

	ggCfg := tfresolver.NewGoGetterConfig()
	ggCfg.Disabled = !c.ScanParams.EnableRemoteModules
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

	resolvers = append(resolvers, tfresolver.NewGoGetterResolver(ggCfg))
	return tfresolver.NewChainResolver(resolvers...)
}

// ── graph-walker ──────────────────────────────────────────────────────────────

type resolvedEntry struct {
	res tfresolver.Resolution
	err error
}

type moduleGraphWalker struct {
	mu          sync.Mutex
	visited     map[string]bool
	resolved    map[string]resolvedEntry
	paths       []string
	extractions map[string]model.ExtractedPathObject
	sourceDirs  map[string]string
	cleanups    []func()

	sf       singleflight.Group
	chain    tfresolver.Resolver
	maxDepth int
	fsys     interface{ Abs(string) (string, error) } // vfs.FS subset needed for path resolution

	parseMu    sync.Mutex
	parseCache map[string]map[string]tfmodules.ParsedModule
}

func (c *Client) newModuleGraphWalker(chain tfresolver.Resolver, maxDepth int) *moduleGraphWalker {
	return &moduleGraphWalker{
		visited:     make(map[string]bool),
		resolved:    make(map[string]resolvedEntry),
		extractions: make(map[string]model.ExtractedPathObject),
		sourceDirs:  make(map[string]string),
		chain:       chain,
		maxDepth:    maxDepth,
		fsys:        c.fsys,
		parseCache:  make(map[string]map[string]tfmodules.ParsedModule),
	}
}

func (w *moduleGraphWalker) parseModulesInDir(
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
		withModuleParseSlot(ctx, func() {
			if fsys, ok := w.fsys.(interface {
				Abs(string) (string, error)
			}); ok {
				_ = fsys // vfs.FS is threaded through ParseTerraformModulesFromFiles
			}
			if parsed, parseErr := tfmodules.ParseTerraformModulesFromFiles(ctx, nil, files, allowedFiles); parseErr == nil {
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
	for p := range allowed {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return strings.Join(paths, "\x00")
}

func (w *moduleGraphWalker) tryVisit(localPath string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.visited[localPath] {
		return false
	}
	w.visited[localPath] = true
	return true
}

func (w *moduleGraphWalker) addPaths(paths ...string) {
	if len(paths) == 0 {
		return
	}
	w.mu.Lock()
	w.paths = append(w.paths, paths...)
	w.mu.Unlock()
}

func (w *moduleGraphWalker) addExtraction(key string, val model.ExtractedPathObject) {
	w.mu.Lock()
	w.extractions[key] = val
	w.mu.Unlock()
}

func (w *moduleGraphWalker) addSourceDirs(entries map[string]string) {
	if len(entries) == 0 {
		return
	}
	w.mu.Lock()
	for k, v := range entries {
		w.sourceDirs[k] = v
	}
	w.mu.Unlock()
}

func (w *moduleGraphWalker) addCleanup(fn func()) {
	w.mu.Lock()
	w.cleanups = append(w.cleanups, fn)
	w.mu.Unlock()
}

// resolveRemote resolves a module and returns the result plus a shared flag.
// shared=true means this goroutine was a singleflight follower (another goroutine
// already did the work); callers should suppress duplicate log lines when shared=true.
func (w *moduleGraphWalker) resolveRemote(ctx context.Context, mod *tfmodules.ParsedModule) (tfresolver.Resolution, bool, error) {
	resolveID := remoteResolveIdentity(mod)

	w.mu.Lock()
	if entry, ok := w.resolved[resolveID]; ok {
		w.mu.Unlock()
		return entry.res, true, entry.err
	}
	w.mu.Unlock()

	v, err, shared := w.sf.Do(resolveID, func() (interface{}, error) {
		w.mu.Lock()
		if entry, ok := w.resolved[resolveID]; ok {
			w.mu.Unlock()
			return entry.res, entry.err
		}
		w.mu.Unlock()

		res, resolveErr := w.chain.Resolve(ctx, mod)
		w.mu.Lock()
		w.resolved[resolveID] = resolvedEntry{res: res, err: resolveErr}
		w.mu.Unlock()
		return res, resolveErr
	})
	if err != nil {
		return tfresolver.Resolution{}, shared, err
	}
	return v.(tfresolver.Resolution), shared, nil
}

var moduleParseSem = make(chan struct{}, max(1, runtime.GOMAXPROCS(0)))

func withModuleParseSlot(ctx context.Context, fn func()) {
	select {
	case moduleParseSem <- struct{}{}:
		defer func() { <-moduleParseSem }()
		fn()
	case <-ctx.Done():
	}
}

func (c *Client) resolveRemoteModuleScanPaths(
	ctx context.Context,
	rootPaths []string,
	moduleDiscoveryPaths []string,
	chain tfresolver.Resolver,
	maxDepth int,
) (
	moduleScanPaths []string,
	moduleExtractions map[string]model.ExtractedPathObject,
	remoteSourceDirs map[string]string,
	cleanups []func(),
) {
	if maxDepth < 0 {
		return nil, nil, nil, nil
	}
	walker := c.newModuleGraphWalker(chain, maxDepth)
	seedGroups := walker.tfSeedGroups(ctx, rootPaths, moduleDiscoveryPaths)

	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(runtime.GOMAXPROCS(0) * seedGroupConcurrencyFactor)
	for seedDir, allowedFiles := range seedGroups {
		g.Go(func() error {
			walker.traverse(gCtx, seedDir, allowedFiles, seedGroups, 0, false)
			return nil
		})
	}
	_ = g.Wait()

	return walker.paths, walker.extractions, walker.sourceDirs, walker.cleanups
}

func (w *moduleGraphWalker) tfSeedGroups(ctx context.Context, paths, moduleDiscoveryPaths []string) map[string]map[string]bool {
	allowedByDir := make(map[string]map[string]bool)
	for _, path := range moduleDiscoveryPaths {
		if !strings.HasSuffix(strings.ToLower(path), ".tf") {
			continue
		}
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
			if !strings.HasSuffix(strings.ToLower(path), ".tf") {
				continue
			}
			dir := filepath.Dir(path)
			if groups[dir] == nil {
				groups[dir] = make(map[string]bool)
			}
			groups[dir][path] = true
			continue
		}
		if len(moduleDiscoveryPaths) == 0 {
			groups[path] = nil
			continue
		}
		for dir, allowedFiles := range allowedByDir {
			if pathContainsDir(path, dir) {
				groups[dir] = allowedFiles
			}
		}
	}
	for child := range w.localModuleChildDirs(ctx, groups) {
		delete(groups, child)
	}
	return groups
}

func pathContainsDir(root, dir string) bool {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(dir))
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

func (w *moduleGraphWalker) localModuleChildDirs(ctx context.Context, groups map[string]map[string]bool) map[string]bool {
	children := make(map[string]bool)
	for dir, allowedFiles := range groups {
		mods := w.parseModulesInDir(ctx, dir, allowedFiles)
		for src := range mods {
			if mods[src].IsLocal && groups[filepath.Clean(mods[src].AbsSource)] != nil {
				children[filepath.Clean(mods[src].AbsSource)] = true
			}
		}
	}
	return children
}

func (w *moduleGraphWalker) traverse(
	ctx context.Context,
	seed string,
	allowedFiles map[string]bool,
	repoAllowedDirs map[string]map[string]bool,
	depth int,
	inRemoteTree bool,
) {
	if w.maxDepth <= 0 || depth >= w.maxDepth {
		return
	}
	mods := w.parseModulesInDir(ctx, seed, allowedFiles)
	if mods == nil {
		return
	}

	for src := range mods {
		if !mods[src].IsLocal {
			continue
		}
		localDir := mods[src].AbsSource
		if localDir == "" {
			continue
		}
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
			w.addPaths(flatTFFilePaths(localDir)...)
		}
		w.traverse(ctx, localDir, childAllowedFiles, repoAllowedDirs, depth+1, inRemoteTree)
	}

	w.traverseRemoteMods(ctx, mods, repoAllowedDirs, depth)
}

type remoteModGroup struct {
	representative *tfmodules.ParsedModule
	callers        []*tfmodules.ParsedModule
}

func (w *moduleGraphWalker) traverseRemoteMods(
	ctx context.Context,
	mods map[string]tfmodules.ParsedModule,
	repoAllowedDirs map[string]map[string]bool,
	depth int,
) {
	groups := make(map[string]*remoteModGroup)
	for src := range mods {
		if mods[src].IsLocal {
			continue
		}
		m := mods[src]
		id := remoteResolveIdentity(&m)

		w.mu.Lock()
		cached, hit := w.resolved[id]
		w.mu.Unlock()
		if hit {
			if cached.err == nil && cached.res.LocalPath != "" {
				root := moduleCallRoot(&m)
				w.addSourceDirs(map[string]string{
					engine.RemoteModuleKey(root, m.Source, m.Version):             cached.res.LocalPath,
					engine.RemoteModuleCallKey(root, m.Source, m.Version, m.Name): cached.res.LocalPath,
					engine.RemoteModuleCallKey(root, m.Source, "", m.Name):        cached.res.LocalPath,
				})
			}
			continue
		}

		if g, ok := groups[id]; ok {
			g.callers = append(g.callers, &m)
		} else {
			groups[id] = &remoteModGroup{representative: &m, callers: []*tfmodules.ParsedModule{&m}}
		}
	}
	if len(groups) == 0 {
		return
	}

	contextLogger := logger.FromContext(ctx)
	eg, gCtx := errgroup.WithContext(ctx)
	eg.SetLimit(tfresolver.FetchConcurrency)
	for _, grp := range groups {
		eg.Go(func() error {
			rep := grp.representative
			contextLogger.Debug().Msgf("Fetching remote Terraform module %q", rep.Source)
			res, shared, resolveErr := w.resolveRemote(gCtx, rep)
			if resolveErr != nil {
				// Only log from the singleflight leader; followers share the same error
				// but there is nothing additional to report.
				if !shared {
					contextLogger.Warn().Err(resolveErr).Msgf("Failed to resolve remote Terraform module %q", rep.Source)
				}
				return nil
			}
			if res.LocalPath == "" {
				if !shared {
					contextLogger.Warn().Msgf("Resolved remote Terraform module %q without a local path", rep.Source)
				}
				return nil
			}
			if !shared {
				contextLogger.Info().Msgf("Fetched remote Terraform module %q", rep.Source)
			}

			sourceDirs := make(map[string]string, len(grp.callers)*3)
			for _, mod := range grp.callers {
				root := moduleCallRoot(mod)
				sourceDirs[engine.RemoteModuleKey(root, mod.Source, mod.Version)] = res.LocalPath
				sourceDirs[engine.RemoteModuleCallKey(root, mod.Source, mod.Version, mod.Name)] = res.LocalPath
				sourceDirs[engine.RemoteModuleCallKey(root, mod.Source, "", mod.Name)] = res.LocalPath
			}
			w.addSourceDirs(sourceDirs)

			if !w.tryVisit(res.LocalPath) {
				return nil
			}
			if res.Cleanup != nil {
				w.addCleanup(res.Cleanup)
			}
			w.addPaths(flatTFFilePaths(res.LocalPath)...)
			w.addExtraction(res.LocalPath, model.ExtractedPathObject{
				Path:      canonicalModuleURL(rep.Source, rep.Version),
				LocalPath: false,
			})
			w.traverse(gCtx, res.LocalPath, nil, repoAllowedDirs, depth+1, true)
			return nil
		})
	}
	_ = eg.Wait()
}

func moduleCallRoot(mod *tfmodules.ParsedModule) string {
	if mod.FileName == "" {
		return "."
	}
	return filepath.Clean(filepath.Dir(mod.FileName))
}

func remoteResolveIdentity(mod *tfmodules.ParsedModule) string {
	sourceType, _ := tfmodules.DetectModuleSourceType(mod.Source)
	if sourceType == "registry" && mod.Version == "" {
		return engine.RemoteModuleCallKey(moduleCallRoot(mod), mod.Source, mod.Version, mod.Name)
	}
	if key, ok := tfresolver.GitModuleResolveKey(mod.Source, mod.Version); ok {
		return key
	}
	return canonicalGitModuleSource(mod.Source) + "\x00" + strings.TrimSpace(mod.Version)
}

func flatTFFilePaths(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var paths []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(strings.ToLower(name), ".tf") {
			paths = append(paths, filepath.Join(dir, name))
		}
	}
	return paths
}

func canonicalGitModuleSource(moduleSource string) string {
	s := strings.TrimSpace(moduleSource)
	// Normalize triple-slash subdirectory separators (typos in source URLs) before
	// other folding so that "repo///path" and "repo//path" share the same identity.
	s = strings.ReplaceAll(s, "///", "//")
	switch {
	case strings.Contains(s, ".git//"):
		return strings.Replace(s, ".git//", "//", 1)
	case strings.Contains(s, ".git?"):
		return strings.Replace(s, ".git?", "?", 1)
	case strings.HasSuffix(s, ".git"):
		return strings.TrimSuffix(s, ".git")
	}
	return s
}

func canonicalModuleURL(moduleSource, version string) string {
	out := canonicalGitModuleSource(moduleSource)
	st, scope := tfmodules.DetectModuleSourceType(out)
	if st == "registry" && scope == "public" {
		if !strings.HasPrefix(out, "registry.terraform.io/") {
			out = "registry.terraform.io/" + out
		}
	}
	if idx := strings.Index(out, "@"); idx != -1 {
		if schemeEnd := strings.Index(out, "://"); schemeEnd != -1 && schemeEnd < idx {
			out = out[:schemeEnd+3] + out[idx+1:]
		}
	}
	if version != "" {
		out = out + "@" + version
	}
	return out
}

// ── .terraform discovery helpers ─────────────────────────────────────────────

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

// ── legacy helpers kept for the prebuilt-walk (server) path ──────────────────

// addRemoteModuleFilesToInventory appends newly-resolved remote module files to the
// prebuilt walk inventory and content cache (server / prebuilt-walk mode only).
func (c *Client) addRemoteModuleFilesToInventory(moduleDirs []string) error {
	if len(c.walkInventory) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(c.walkInventory))
	for _, path := range c.walkInventory {
		seen[path] = struct{}{}
	}
	for _, dir := range moduleDirs {
		var moduleFiles []string
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
