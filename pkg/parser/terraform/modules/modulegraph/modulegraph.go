/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package modulegraph

import (
	"context"
	"errors"
	"math"
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
	RootPaths       []string
	DiscoveryPaths  []string
	Resolver        resolver.Resolver
	MaxDepth        int
	ResourceLimits  resolver.ResourceLimits
	BaselinePaths   []string
	TotalParseBytes int64
	FS              vfs.FS
}

type ResolvedModule struct {
	CallerRoot        string
	CallerFile        string
	CallerLine        int
	CallerEndLine     int
	Source            string
	Version           string
	ResolvedVersion   string
	ResolvedRef       string
	Name              string
	LocalPath         string
	PackageRoot       string
	ParentPackageRoot string
	Depth             int
	CanonicalSource   string
}

type Result struct {
	ScanPaths            []string
	Modules              []ResolvedModule
	Failures             []ResolutionFailure
	SourceMappings       map[string]string
	BudgetEvents         []BudgetEvent
	BaselineParseBytes   int64
	ModuleAdmissionBytes int64
	TimedOut             bool
	Cleanup              func()
}

type BudgetEvent struct {
	Source       string
	Gate         string
	Limit        string
	Maximum      int64
	Measured     int64
	SheddingRank int
}

type ResolutionFailure struct {
	CallerRoot    string
	CallerFile    string
	CallerLine    int
	CallerEndLine int
	Source        string
	Version       string
	Name          string
	Reason        string
}

type resolvedEntry struct {
	res resolver.Resolution
	err error
}

type remoteModuleGroup struct {
	representative    *tfmodules.ParsedModule
	callers           []*tfmodules.ParsedModule
	parentPackageRoot string
}

type walkerSnapshot struct {
	paths          []string
	modules        []ResolvedModule
	sourceMappings map[string]string
	cleanups       []func()
	budgetEvents   []BudgetEvent
	failures       []ResolutionFailure
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
	budgetEvents   []BudgetEvent
	failures       []ResolutionFailure
}

type moduleParseCache struct {
	mu      sync.RWMutex
	entries map[string]map[string]tfmodules.ParsedModule
}

type pendingTraversal struct {
	seed            string
	repoAllowedDirs map[string]map[string]bool
	depth           int
	packageRoot     string
}

type pendingTraversalCollector struct {
	mu      sync.Mutex
	entries map[string]pendingTraversal
}

type walker struct {
	visited          visitedSet
	resolutions      resolutionCache
	results          resultCollector
	parseCache       moduleParseCache
	pending          pendingTraversalCollector
	parseSem         chan struct{}
	sf               singleflight.Group
	measureSF        singleflight.Group
	resolver         resolver.Resolver
	budget           *resolver.ResourceBudget
	measurePackages  bool
	deferExpansion   bool
	admissionBytes   int64
	acquisitionBytes int64
	acquisitionBase  int64
	maxDepth         int
	fsys             vfs.FS
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
	budget := resolver.NewResourceBudget(request.ResourceLimits)
	ctx = resolver.WithResourceBudget(ctx, budget)
	moduleMaximum, baselineBytes, enforceAdmission := moduleAdmissionLimit(request)

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
		pending: pendingTraversalCollector{
			entries: make(map[string]pendingTraversal),
		},
		parseSem:         make(chan struct{}, max(1, runtime.GOMAXPROCS(0))),
		resolver:         request.Resolver,
		budget:           budget,
		measurePackages:  request.ResourceLimits.Enabled() || request.TotalParseBytes > 0,
		deferExpansion:   enforceAdmission,
		admissionBytes:   moduleMaximum,
		acquisitionBytes: acquisitionAllowance(moduleMaximum),
		maxDepth:         request.MaxDepth,
		fsys:             request.FS,
	}
	if enforceAdmission {
		w.acquisitionBase = budget.TotalUsage().Bytes
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
	if enforceAdmission {
		w.expandAdmittedPackages(ctx, moduleMaximum)
	}

	snapshot := w.results.snapshot()
	shedToTotalLimit(&snapshot, budget, moduleMaximum, enforceAdmission)
	result.ScanPaths = snapshot.paths
	result.Modules = snapshot.modules
	result.Failures = snapshot.failures
	result.SourceMappings = snapshot.sourceMappings
	result.BudgetEvents = snapshot.budgetEvents
	result.BaselineParseBytes = baselineBytes
	result.ModuleAdmissionBytes = moduleMaximum
	result.TimedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)

	sort.Strings(result.ScanPaths)
	sort.Slice(result.Modules, func(i, j int) bool {
		left, right := result.Modules[i], result.Modules[j]
		return strings.Join([]string{left.CallerRoot, left.Source, left.Version, left.Name}, "\x00") <
			strings.Join([]string{right.CallerRoot, right.Source, right.Version, right.Name}, "\x00")
	})
	sort.Slice(result.Failures, func(i, j int) bool {
		left, right := result.Failures[i], result.Failures[j]
		if left.CallerFile != right.CallerFile {
			return left.CallerFile < right.CallerFile
		}
		if left.CallerLine != right.CallerLine {
			return left.CallerLine < right.CallerLine
		}
		if left.Source != right.Source {
			return left.Source < right.Source
		}
		return left.Name < right.Name
	})
	sort.Slice(result.BudgetEvents, func(i, j int) bool {
		left, right := result.BudgetEvents[i], result.BudgetEvents[j]
		if left.SheddingRank != right.SheddingRank {
			return left.SheddingRank < right.SheddingRank
		}
		return strings.Join([]string{left.Source, left.Gate, left.Limit}, "\x00") <
			strings.Join([]string{right.Source, right.Gate, right.Limit}, "\x00")
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

func (w *walker) expandAdmittedPackages(ctx context.Context, maximum int64) {
	var deferred []pendingTraversal
	for {
		pending := make([]pendingTraversal, 0, len(deferred))
		pending = append(pending, deferred...)
		pending = append(pending, w.pending.drain()...)
		if len(pending) == 0 {
			return
		}

		snapshot := w.results.snapshot()
		shedToTotalLimit(&snapshot, w.budget, maximum, true)
		accepted := make(map[string]bool, len(snapshot.modules))
		for i := range snapshot.modules {
			accepted[filepath.Clean(snapshot.modules[i].PackageRoot)] = true
		}
		admitted, rejected := partitionPendingTraversals(pending, accepted)
		if len(admitted) == 0 {
			return
		}
		deferred = rejected

		g, gCtx := errgroup.WithContext(ctx)
		g.SetLimit(max(1, resolver.FetchConcurrency))
		for _, traversal := range admitted {
			g.Go(func() error {
				w.traverse(
					gCtx,
					traversal.seed,
					nil,
					traversal.repoAllowedDirs,
					traversal.depth,
					traversal.packageRoot,
				)
				return nil
			})
		}
		_ = g.Wait()
	}
}

func partitionPendingTraversals(
	pending []pendingTraversal, accepted map[string]bool,
) (admitted, rejected []pendingTraversal) {
	admitted = make([]pendingTraversal, 0, len(pending))
	rejected = make([]pendingTraversal, 0, len(pending))
	for _, traversal := range pending {
		if accepted[filepath.Clean(traversal.packageRoot)] {
			admitted = append(admitted, traversal)
		} else {
			rejected = append(rejected, traversal)
		}
	}
	sort.Slice(admitted, func(i, j int) bool {
		left, right := admitted[i], admitted[j]
		if left.depth != right.depth {
			return left.depth < right.depth
		}
		if left.packageRoot != right.packageRoot {
			return left.packageRoot < right.packageRoot
		}
		return left.seed < right.seed
	})
	return admitted, rejected
}

func (w *walker) parseModulesInDir(
	ctx context.Context, dir string, allowedFiles map[string]bool, packageRoot string,
) map[string]tfmodules.ParsedModule {
	key := filepath.Clean(dir) + "\x00" + filepath.Clean(packageRoot) + "\x00" + allowedFilesCacheKey(allowedFiles)

	if mods, ok := w.parseCache.get(key); ok {
		return mods
	}
	if err := ctx.Err(); err != nil {
		return nil
	}

	files, err := tfmodules.LoadTFFilesFromDir(dir, packageRoot)
	if err != nil {
		return nil
	}
	if len(files) == 0 {
		empty := map[string]tfmodules.ParsedModule{}
		w.parseCache.set(key, empty)
		return empty
	}

	var parsed map[string]tfmodules.ParsedModule
	parseErr := w.withParseSlot(ctx, func() error {
		var slotErr error
		parsed, slotErr = tfmodules.ParseTerraformModulesFromFiles(ctx, w.fsys, files, allowedFiles)
		return slotErr
	})
	if parseErr != nil || ctx.Err() != nil {
		return nil
	}
	if parsed == nil {
		parsed = map[string]tfmodules.ParsedModule{}
	}
	w.parseCache.set(key, parsed)
	return parsed
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

func (c *resultCollector) addResolvedModule(
	mod *tfmodules.ParsedModule, resolution resolver.Resolution, parentPackageRoot string, depth int,
) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.modules = append(c.modules, ResolvedModule{
		CallerRoot:        moduleCallRoot(mod),
		CallerFile:        mod.FileName,
		CallerLine:        mod.DefLine,
		CallerEndLine:     mod.DefEndLine,
		Source:            mod.Source,
		Version:           mod.Version,
		ResolvedVersion:   resolution.ResolvedVersion,
		ResolvedRef:       resolution.ResolvedRef,
		Name:              mod.Name,
		LocalPath:         resolution.LocalPath,
		PackageRoot:       resolution.PackageRoot,
		ParentPackageRoot: parentPackageRoot,
		Depth:             depth,
		CanonicalSource:   canonicalModuleURL(mod.Source, resolution.ResolvedVersion),
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

func (c *resultCollector) addBudgetEvent(source string, budgetErr *resolver.BudgetExceededError) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.budgetEvents = append(c.budgetEvents, BudgetEvent{
		Source:   source,
		Gate:     budgetErr.Gate,
		Limit:    budgetErr.Limit,
		Maximum:  budgetErr.Maximum,
		Measured: budgetErr.Measured,
	})
}

func (c *resultCollector) addResolutionFailure(mod *tfmodules.ParsedModule, err error) {
	if mod == nil || err == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failures = append(c.failures, ResolutionFailure{
		CallerRoot:    moduleCallRoot(mod),
		CallerFile:    mod.FileName,
		CallerLine:    mod.DefLine,
		CallerEndLine: mod.DefEndLine,
		Source:        mod.Source,
		Version:       mod.Version,
		Name:          mod.Name,
		Reason:        err.Error(),
	})
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
		budgetEvents:   append([]BudgetEvent(nil), c.budgetEvents...),
		failures:       append([]ResolutionFailure(nil), c.failures...),
	}
}

func (c *resolutionCache) get(resolveID string) (resolvedEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[resolveID]
	return entry, ok
}

func (c *resolutionCache) set(resolveID string, entry *resolvedEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[resolveID] = *entry
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

func (c *pendingTraversalCollector) add(traversal pendingTraversal) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[visitKey(traversal.seed, traversal.packageRoot)] = traversal
}

func (c *pendingTraversalCollector) drain() []pendingTraversal {
	c.mu.Lock()
	defer c.mu.Unlock()
	entries := make([]pendingTraversal, 0, len(c.entries))
	for _, traversal := range c.entries {
		entries = append(entries, traversal)
	}
	clear(c.entries)
	return entries
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
		if resolveErr != nil {
			var budgetErr *resolver.BudgetExceededError
			if errors.As(resolveErr, &budgetErr) {
				w.results.addBudgetEvent(mod.Source, budgetErr)
			}
		}
		if resolveErr == nil {
			resolveErr = w.accountPackage(ctx, mod.Source, resolution)
		}
		if ctx.Err() == nil {
			w.resolutions.set(resolveID, &resolvedEntry{res: resolution, err: resolveErr})
		}
		return resolution, resolveErr
	})
	if err != nil {
		return resolver.Resolution{}, shared, err
	}
	return value.(resolver.Resolution), shared, nil
}

func (w *walker) accountPackage(
	ctx context.Context, source string, resolution resolver.Resolution,
) error {
	if resolution.PackageRoot == "" || !w.measurePackages {
		return nil
	}
	if err := w.measurePackage(ctx, resolution.PackageRoot); err != nil {
		if resolution.Cleanup != nil {
			resolution.Cleanup()
		}
		var budgetErr *resolver.BudgetExceededError
		if errors.As(err, &budgetErr) {
			w.results.addBudgetEvent(source, budgetErr)
		}
		return &tfmodules.UnresolvedError{Reason: "module package rejected: " + err.Error()}
	}
	return nil
}

// measurePackage charges a package root to the budget, collapsing the walks of
// modules that share a root. The flight is forgotten as soon as it starts, so
// only callers whose content was already on disk when the walk began reuse its
// result; later callers, whose extraction may still have been running, measure
// the root again.
func (w *walker) measurePackage(ctx context.Context, root string) error {
	key := filepath.Clean(root)
	_, err, _ := w.measureSF.Do(key, func() (interface{}, error) {
		w.measureSF.Forget(key)
		limits := w.budget.Limits()
		if scoped := resolver.ResourceBudgetFromContext(ctx); scoped != nil {
			limits = scoped.Limits()
		}
		usage, measureErr := resolver.MeasurePackage(ctx, root, limits)
		if measureErr != nil {
			return nil, measureErr
		}
		return nil, w.budget.AdmitPackage(root, usage)
	})
	return err
}

func (w *walker) withParseSlot(ctx context.Context, fn func() error) error {
	select {
	case w.parseSem <- struct{}{}:
		defer func() { <-w.parseSem }()
		return fn()
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (w *walker) seedGroups(
	ctx context.Context, paths, discoveryPaths []string,
) (seedGroups, repositoryGroups map[string]map[string]bool) {
	allowedByDir := make(map[string]map[string]bool)
	for _, path := range discoveryPaths {
		if !tfmodules.IsTerraformConfigPath(path) {
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
			if !tfmodules.IsTerraformConfigPath(path) {
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

	w.traverseRemoteModules(ctx, mods, repoAllowedDirs, depth, packageRoot)
}

func (w *walker) traverseRemoteModules(
	ctx context.Context,
	mods map[string]tfmodules.ParsedModule,
	repoAllowedDirs map[string]map[string]bool,
	depth int,
	parentPackageRoot string,
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
				w.results.addResolvedModule(&mod, cached.res, parentPackageRoot, depth+1)
			} else if cached.err != nil && ctx.Err() == nil {
				w.results.addResolutionFailure(&mod, cached.err)
			}
			continue
		}

		if group, ok := groups[id]; ok {
			group.callers = append(group.callers, &mod)
		} else {
			groups[id] = &remoteModuleGroup{
				representative:    &mod,
				callers:           []*tfmodules.ParsedModule{&mod},
				parentPackageRoot: parentPackageRoot,
			}
		}
	}
	if len(groups) == 0 {
		return
	}
	w.acquireRemoteModuleGroups(ctx, groups, repoAllowedDirs, depth)
}

// acquisitionOvershootFactor bounds how far one frontier may fetch past the
// aggregate admission limit. Package sizes are only known once the package is on
// disk, so a frontier has to be oversampled for shedding to have anything to
// choose between; capping the overshoot keeps a module that declares thousands
// of remote children from materializing all of them before admission runs.
const acquisitionOvershootFactor = 2

func acquisitionAllowance(maximum int64) int64 {
	if maximum > math.MaxInt64/acquisitionOvershootFactor {
		return math.MaxInt64
	}
	return maximum * acquisitionOvershootFactor
}

// acquireRemoteModuleGroups fetches a frontier in deterministically ordered
// batches, stopping once the frontier has fetched past its allowance. Without
// this the whole frontier is fetched before admission gets to reject anything,
// so the bytes on disk are bounded only by how many modules a caller declares.
func (w *walker) acquireRemoteModuleGroups(
	ctx context.Context,
	groups map[string]*remoteModuleGroup,
	repoAllowedDirs map[string]map[string]bool,
	depth int,
) {
	ids := orderedGroupIDs(groups)
	if w.deferExpansion && w.acquisitionBytes <= 0 {
		w.recordUnacquiredGroups(groups, ids)
		return
	}
	size := max(1, resolver.FetchConcurrency)
	for start := 0; start < len(ids); {
		type acquisition struct {
			group *remoteModuleGroup
			lease *resolver.AcquisitionLease
		}
		batch := make([]acquisition, 0, size)
		end := min(start+size, len(ids))
		for _, id := range ids[start:end] {
			lease, ok := w.acquireAcquisition(ctx, len(batch) == 0)
			if !ok {
				break
			}
			batch = append(batch, acquisition{group: groups[id], lease: lease})
		}
		if len(batch) == 0 {
			if ctx.Err() == nil {
				w.recordUnacquiredGroups(groups, ids[start:])
			}
			return
		}

		g, gCtx := errgroup.WithContext(ctx)
		g.SetLimit(size)
		for _, item := range batch {
			g.Go(func() error {
				defer item.lease.Release()
				w.traverseRemoteModuleGroup(
					gCtx, item.group, repoAllowedDirs, depth, item.lease,
				)
				return nil
			})
		}
		_ = g.Wait()
		start += len(batch)
	}
}

// orderedGroupIDs gives the frontier a stable order so that when acquisition
// stops early, which modules were fetched does not depend on map iteration.
func orderedGroupIDs(groups map[string]*remoteModuleGroup) []string {
	ids := make([]string, 0, len(groups))
	for id := range groups {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		left := groups[ids[i]].representative
		right := groups[ids[j]].representative
		if left.Source != right.Source {
			return left.Source < right.Source
		}
		return ids[i] < ids[j]
	})
	return ids
}

func (w *walker) acquireAcquisition(
	ctx context.Context, wait bool,
) (*resolver.AcquisitionLease, bool) {
	if !w.deferExpansion {
		return nil, true
	}
	requested := w.budget.Limits().MaxPackageBytes
	maximum := w.acquisitionBase + w.acquisitionBytes
	if maximum < w.acquisitionBase {
		maximum = math.MaxInt64
	}
	if wait {
		return w.budget.AcquireAcquisition(ctx, maximum, requested)
	}
	return w.budget.TryAcquireAcquisition(maximum, requested)
}

func (w *walker) recordUnacquiredGroups(groups map[string]*remoteModuleGroup, ids []string) {
	measured := w.budget.TotalUsage().Bytes
	for _, id := range ids {
		w.results.addBudgetEvent(groups[id].representative.Source, &resolver.BudgetExceededError{
			Gate:     "acquisition",
			Limit:    "module_bytes_total",
			Maximum:  w.admissionBytes,
			Measured: measured,
		})
	}
}

func (w *walker) traverseRemoteModuleGroup(
	ctx context.Context,
	group *remoteModuleGroup,
	repoAllowedDirs map[string]map[string]bool,
	depth int,
	lease *resolver.AcquisitionLease,
) {
	if lease != nil {
		limits := w.budget.Limits()
		if limits.MaxPackageBytes <= 0 || lease.Bytes() < limits.MaxPackageBytes {
			limits.MaxPackageBytes = lease.Bytes()
		}
		ctx = resolver.WithResourceBudget(ctx, resolver.NewResourceBudget(limits))
	}
	contextLogger := logger.FromContext(ctx)
	representative := group.representative
	contextLogger.Debug().Msgf("Fetching remote Terraform module %q", representative.Source)
	resolution, shared, err := w.resolveRemote(ctx, representative)
	if err != nil {
		if ctx.Err() == nil {
			for _, mod := range group.callers {
				w.results.addResolutionFailure(mod, err)
			}
		}
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
		w.results.addResolvedModule(mod, resolution, group.parentPackageRoot, depth+1)
	}
	if resolution.Cleanup != nil {
		w.results.addCleanup(resolution.Cleanup)
	}
	if !w.visited.tryAdd(resolution.LocalPath, resolution.PackageRoot) {
		return
	}
	w.results.addPaths(flatTerraformFilePaths(ctx, resolution.LocalPath, resolution.PackageRoot)...)
	w.results.addSourceMapping(
		resolution.LocalPath,
		canonicalModuleURL(representative.Source, resolution.ResolvedVersion),
	)
	if !w.deferExpansion {
		w.traverse(ctx, resolution.LocalPath, nil, repoAllowedDirs, depth+1, resolution.PackageRoot)
		return
	}
	w.pending.add(pendingTraversal{
		seed:            resolution.LocalPath,
		repoAllowedDirs: repoAllowedDirs,
		depth:           depth + 1,
		packageRoot:     resolution.PackageRoot,
	})
}

func moduleCallRoot(mod *tfmodules.ParsedModule) string {
	if mod.FileName == "" {
		return "."
	}
	return filepath.Clean(filepath.Dir(mod.FileName))
}

// terraformWorkspaceRoot finds the nearest ancestor directory containing
// .terraform/modules/modules.json, matching DotTerraformResolver lookup scope.
func terraformWorkspaceRoot(fileName string) string {
	if fileName == "" {
		return "."
	}
	clean := filepath.Clean(filepath.Dir(fileName))
	fallback := clean
	for {
		if _, err := os.Stat(filepath.Join(clean, ".terraform", "modules", "modules.json")); err == nil {
			return clean
		}
		parent := filepath.Dir(clean)
		if parent == clean {
			return fallback
		}
		clean = parent
	}
}

func remoteResolveIdentity(mod *tfmodules.ParsedModule) string {
	sourceType, _ := tfmodules.DetectModuleSourceType(mod.Source)
	if sourceType == sourceTypeRegistry {
		return terraformWorkspaceRoot(mod.FileName) + "\x00" + strings.TrimSpace(mod.Source) + "\x00" +
			strings.TrimSpace(mod.Version)
	}
	if key, ok := resolver.GitModuleResolveKey(mod.Source, mod.Version); ok {
		return key
	}
	return canonicalGitModuleSource(mod.Source) + "\x00" + strings.TrimSpace(mod.Version)
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

func canonicalModuleURL(moduleSource, resolvedVersion string) string {
	source := strings.TrimSpace(moduleSource)
	if addr, err := tfmodules.ParseRegistryModuleSource(source); err == nil {
		canonical := addr.String()
		if version := concreteRegistryVersion(resolvedVersion); version != "" {
			canonical += "@" + version
		}
		return canonical
	}
	source = canonicalGitModuleSource(source)
	if index := strings.Index(source, "@"); index != -1 {
		if schemeEnd := strings.Index(source, "://"); schemeEnd != -1 && schemeEnd < index {
			source = source[:schemeEnd+3] + source[index+1:]
		}
	}
	return source
}

func concreteRegistryVersion(version string) string {
	version = strings.TrimSpace(version)
	if version == "" || strings.ContainsAny(version, " \t") {
		return ""
	}
	for _, c := range version {
		if c != '.' && c != '-' && c != '+' && (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return ""
		}
	}
	return version
}
