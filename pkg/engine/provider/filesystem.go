/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package provider

import (
	"context"
	"fmt"
	ioFs "io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/pkg/errors"
	"github.com/yargevad/filepathx"
)

// FileSystemSourceProvider provides a path to be scanned
// and a list of files which will not be scanned
type FileSystemSourceProvider struct {
	paths     []string
	excludes  map[string][]os.FileInfo
	onlyPaths []string
	mu        sync.RWMutex

	prebuiltPaths []string
	chartRoots    []string
	contentCache  map[string][]byte
	unfiltered    map[string]struct{}
}

var (
	queryRegexExcludeTerraCache = regexp.MustCompile(fmt.Sprintf(`^(.*?%s)?\.terra.*`, regexp.QuoteMeta(string(os.PathSeparator))))
	// ErrNotSupportedFile - error representing when a file format is not supported by the scanner
	ErrNotSupportedFile = errors.New("invalid file format")
)

// NewFileSystemSourceProvider initializes a FileSystemSourceProvider with path and files that will be ignored
func NewFileSystemSourceProvider(ctx context.Context, paths, excludes, onlyPaths []string) (*FileSystemSourceProvider, error) {
	contextLogger := logger.FromContext(ctx)
	contextLogger.Debug().Msgf("provider.NewFileSystemSourceProvider()")
	ex := make(map[string][]os.FileInfo, len(excludes))
	osPaths := make([]string, len(paths))
	for idx, path := range paths {
		osPaths[idx] = filepath.FromSlash(path)
	}
	fs := &FileSystemSourceProvider{
		paths:    osPaths,
		excludes: ex,
	}

	for _, exclude := range excludes {
		excludePaths, err := GetExcludePaths(exclude)
		if err != nil {
			return nil, err
		}
		if err := fs.addExcluded(ctx, excludePaths); err != nil {
			return nil, err
		}
	}

	// onlyPaths uses nil/non-nil to signal whether a restriction is in effect:
	//   - nil: no restriction configured → all files pass
	//   - non-nil (even empty): restriction in effect → only matching files pass
	//
	// We initialize onlyPaths as non-nil before appending so that even if all
	// provided glob patterns expand to nothing, the non-nil sentinel is preserved.
	if len(onlyPaths) > 0 {
		fs.onlyPaths = make([]string, 0)
		for _, only := range onlyPaths {
			expanded, err := GetExcludePaths(only)
			if err != nil {
				return nil, err
			}
			fs.onlyPaths = append(fs.onlyPaths, expanded...)
		}
	}

	return fs, nil
}

// AddExcluded add new excluded files to the File System Source Provider
// Hold a mutex before calling this function
func (s *FileSystemSourceProvider) addExcluded(ctx context.Context, excludePaths []string) error {
	contextLogger := logger.FromContext(ctx)
	for _, excludePath := range excludePaths {
		excludePath = filepath.Clean(excludePath)
		info, err := os.Stat(excludePath)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			if sysErr, ok := err.(*ioFs.PathError); ok {
				contextLogger.Warn().Msgf("Failed getting file info for file '%s', Skipping due to: %s, Error number: %d",
					excludePath, sysErr, sysErr.Err.(syscall.Errno))
				continue
			}
			return errors.Wrap(err, "failed to open excluded file")
		}
		if _, ok := s.excludes[info.Name()]; !ok {
			s.excludes[info.Name()] = make([]os.FileInfo, 0)
		}
		s.excludes[info.Name()] = append(s.excludes[info.Name()], info)
	}
	return nil
}

// GetExcludePaths gets all the files that should be excluded
func GetExcludePaths(pathExpressions string) ([]string, error) {
	if strings.ContainsAny(pathExpressions, "*?[") {
		info, err := filepathx.Glob(pathExpressions)
		if err != nil {
			return []string{pathExpressions}, nil
		}
		return info, nil
	}
	return []string{pathExpressions}, nil
}

// GetBasePaths returns base path of FileSystemSourceProvider
func (s *FileSystemSourceProvider) GetBasePaths() []string {
	return s.paths
}

// IgnoreDamagedFile reports whether a damaged or inaccessible file should be skipped.
func IgnoreDamagedFile(ctx context.Context, path string) bool {
	return ignoreDamagedFiles(ctx, path)
}

// IsTerraformCacheDir reports whether path is a Terraform/Terragrunt cache directory
// that should be skipped during repository walks.
func IsTerraformCacheDir(path string) bool {
	return queryRegexExcludeTerraCache.MatchString(path)
}

// ExcludePaths registers paths to skip during later walks (e.g. rendered Helm templates).
func (s *FileSystemSourceProvider) ExcludePaths(ctx context.Context, paths []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addExcluded(ctx, paths)
}

func (s *FileSystemSourceProvider) AddUnfilteredPaths(paths []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range paths {
		normalized := filepath.ToSlash(p)
		s.paths = append(s.paths, filepath.FromSlash(normalized))
		if s.unfiltered == nil {
			s.unfiltered = make(map[string]struct{})
		}
		s.unfiltered[normalized] = struct{}{}
		if len(s.prebuiltPaths) > 0 {
			s.prebuiltPaths = append(s.prebuiltPaths, normalized)
		}
	}
}

// TerraformFiles returns Terraform/OpenTofu config paths used for module discovery
// before scanning: native .tf/.tofu files plus .tf.json/.tofu.json files.
func (s *FileSystemSourceProvider) TerraformFiles(ctx context.Context) ([]string, error) {
	configExtensions := model.Extensions{
		tfpath.ExtTF: {}, tfpath.ExtTofu: {}, tfpath.ExtTFJSON: {}, tfpath.ExtTofuJSON: {},
	}
	seen := make(map[string]struct{})
	var files []string
	add := func(path string) {
		norm := filepath.ToSlash(path)
		if _, ok := seen[norm]; ok {
			return
		}
		seen[norm] = struct{}{}
		files = append(files, norm)
	}

	for _, scanPath := range s.paths {
		fileInfo, err := os.Stat(scanPath)
		if err != nil {
			return nil, errors.Wrap(err, "failed to open path")
		}
		if !fileInfo.IsDir() {
			if shouldSkip, _, _ := s.checkConditions(ctx, fileInfo, configExtensions, scanPath, nil); !shouldSkip {
				add(scanPath)
			}
			continue
		}

		collected, err := s.collectFiles(ctx, scanPath, unavailableResolverSink, configExtensions)
		if err != nil {
			return nil, errors.Wrap(err, "failed to collect files")
		}
		for _, path := range collected {
			add(path)
		}
	}
	sort.Strings(files)
	return files, nil
}

func unavailableResolverSink(context.Context, string) ([]string, error) {
	return nil, errors.New("resolver unavailable")
}

// ignoreDamagedFiles checks whether we should ignore a damaged file from a scan or not.
func ignoreDamagedFiles(ctx context.Context, path string) bool {
	contextLogger := logger.FromContext(ctx)
	shouldIgnoreFile := false
	fileInfo, err := os.Lstat(path)
	if err != nil {
		contextLogger.Warn().Msgf("Failed getting the file info for file '%s'", path)
		return false
	}
	contextLogger.Info().Msgf("No mode type bits are set( is a regular file ) for file '%s' : %t ", path, fileInfo.Mode().IsRegular())

	if fileInfo.Mode()&os.ModeSymlink == os.ModeSymlink {
		contextLogger.Warn().Msgf("File '%s' is a symbolic link - but seems not to be accessible", path)
		shouldIgnoreFile = true
	}

	return shouldIgnoreFile
}

// GetSources tries to open file or directory and execute sink function on it
func (s *FileSystemSourceProvider) GetSources(ctx context.Context,
	extensions model.Extensions, sink Sink, resolverSink ResolverSink) error {
	files, err := s.collectScanFiles(ctx, extensions, resolverSink)
	if err != nil {
		return err
	}
	for _, filePath := range files {
		if err := s.processFile(ctx, filePath, sink); err != nil {
			return err
		}
	}
	return nil
}

// GetParallelSources is an alternative to GetSources, parallelising the task
func (s *FileSystemSourceProvider) GetParallelSources(ctx context.Context,
	extensions model.Extensions, sink Sink, resolverSink ResolverSink) error {
	filesToProcess, err := s.collectScanFiles(ctx, extensions, resolverSink)
	if err != nil {
		return err
	}
	contextLogger := logger.FromContext(ctx)
	contextLogger.Info().Msgf("Collected %d files to process", len(filesToProcess))

	// Phase 2: Process files in parallel
	return s.processFilesParallel(ctx, filesToProcess, sink)
}

func (s *FileSystemSourceProvider) collectScanFiles(ctx context.Context,
	extensions model.Extensions, resolverSink ResolverSink) ([]string, error) {
	// Phase 1: Collect all file paths to process
	var filesToProcess []string
	for _, scanPath := range s.paths {
		fileInfo, err := os.Stat(scanPath)
		if err != nil {
			return nil, errors.Wrap(err, "failed to open path")
		}
		if !fileInfo.IsDir() {
			// Single file - validate and add to queue
			openFileErr := validateScanFile(ctx, scanPath, extensions)
			if openFileErr != nil {
				if errors.Is(openFileErr, ErrNotSupportedFile) || ignoreDamagedFiles(ctx, scanPath) {
					continue
				}
				return nil, openFileErr
			}
			filesToProcess = append(filesToProcess, scanPath)
			continue
		}

		// Directory - collect all files first
		files, err := s.collectFiles(ctx, scanPath, resolverSink, extensions)
		if err != nil {
			return nil, errors.Wrap(err, "failed to collect files")
		}
		filesToProcess = append(filesToProcess, files...)
	}
	return filesToProcess, nil
}

// InventoryFile is a discovered file and its matched extension token.
type InventoryFile struct {
	Path string
	Ext  string
}

// SetPrebuiltWalk reuses analyzer walk inventory to skip a second tree walk.
func (s *FileSystemSourceProvider) SetPrebuiltWalk(paths, chartRoots []string, contentCache map[string][]byte) {
	s.prebuiltPaths = paths
	s.chartRoots = chartRoots
	s.contentCache = contentCache
}

// ContentCache returns bytes read during analyzer classification, keyed by path.
func (s *FileSystemSourceProvider) ContentCache() map[string][]byte {
	return s.contentCache
}

// ReleaseContentCache drops the cached file bytes: only needed during the sink
// phase (parsed files keep their content in OriginalData), and the map is shared
// with the scan Client, so clearing here releases both references.
func (s *FileSystemSourceProvider) ReleaseContentCache() {
	if s.contentCache != nil {
		for k := range s.contentCache {
			delete(s.contentCache, k)
		}
	}
}

// BuildInventoryFromPrebuilt renders Helm charts and filters pre-collected paths.
func (s *FileSystemSourceProvider) BuildInventoryFromPrebuilt(ctx context.Context,
	extensions model.Extensions,
	chartFn func(ctx context.Context, chartPath string) (skip bool)) ([]InventoryFile, error) {
	renderedRoots := renderChartsShallowFirst(ctx, s.chartRoots, chartFn)

	files := make([]InventoryFile, 0, len(s.prebuiltPaths))
	for _, path := range s.prebuiltPaths {
		norm := toSlash(path)
		if IsHelmChartFile(norm, renderedRoots) {
			continue
		}
		if _, ok := s.unfiltered[norm]; !ok {
			excluded, err := s.isPathExcluded(norm)
			if err != nil || excluded {
				continue
			}
		}
		ext := utils.ExtensionFromPath(norm)
		if ext == "" {
			if resolved, err := utils.GetExtension(ctx, norm); err == nil {
				ext = resolved
			}
		}
		if ext == "" || !extensions.Include(ext) {
			continue
		}
		files = append(files, InventoryFile{Path: norm, Ext: ext})
	}
	return files, nil
}

// helmRootFiles are the files Helm itself reads at a chart root; values*.yaml
// alternates are matched separately.
var helmRootFiles = map[string]struct{}{
	"Chart.yaml":         {},
	"Chart.lock":         {},
	"requirements.yaml":  {},
	"requirements.lock":  {},
	"values.schema.json": {},
}

// helmChartDirs are the chart-root subdirectories Helm renders or loads as
// dependencies.
var helmChartDirs = map[string]struct{}{
	"templates": {},
	"crds":      {},
	"charts":    {},
}

// IsHelmChartFile reports whether path is part of the Helm structure of one of
// chartRoots: a file Helm reads at the root (Chart.yaml, values*.yaml, ...) or
// anything under its templates/, crds/ or charts/. Other files that merely sit
// under a chart root (Terraform, plain manifests, CI workflows) are not, so a
// rendered chart does not hide them from their own parsers. A nested chart root
// is covered only when it sits under a parent's charts/, the one place Helm
// loads subcharts from. A "." root is a chart at the workspace (or scan) root.
func IsHelmChartFile(path string, chartRoots []string) bool {
	return isHelmChartFileOf(toSlash(path), chartRoots, "")
}

// isHelmChartFileOf is IsHelmChartFile over a slash path, ignoring the root skip.
func isHelmChartFileOf(path string, chartRoots []string, skip string) bool {
	for _, root := range chartRoots {
		root = toSlash(root)
		if root == skip {
			continue
		}
		if rel, ok := chartRelative(path, root); ok && isHelmChartRelative(rel) {
			return true
		}
	}
	return false
}

// toSlash normalizes both separators, whatever the host OS: pushed and analyzer
// paths may carry either.
func toSlash(p string) string {
	return strings.ReplaceAll(p, "\\", "/")
}

// chartRelative returns path relative to the slash chart root root, where "."
// is the workspace (or scan) root, and whether path lies under it.
func chartRelative(path, root string) (string, bool) {
	if root == "." {
		return path, true
	}
	if !strings.HasPrefix(path, root+"/") {
		return "", false
	}
	return path[len(root)+1:], true
}

func isHelmChartRelative(rel string) bool {
	if first, rest, nested := strings.Cut(rel, "/"); nested {
		_, ok := helmChartDirs[first]
		return ok && rest != ""
	}
	if _, ok := helmRootFiles[rel]; ok {
		return true
	}
	ext := filepath.Ext(rel)
	return strings.HasPrefix(rel, "values") && (ext == ".yaml" || ext == ".yml")
}

// isHelmChartDir reports whether dir is one of chartRoots' templates/, crds/ or
// charts/ directories, or lies under one.
func isHelmChartDir(dir string, chartRoots []string) bool {
	dir = toSlash(dir)
	for _, root := range chartRoots {
		rel, ok := chartRelative(dir, toSlash(root))
		if !ok {
			continue
		}
		first, _, _ := strings.Cut(rel, "/")
		if _, ok := helmChartDirs[first]; ok {
			return true
		}
	}
	return false
}

// HelmChartFiles keeps the paths of files that are part of the Helm structure
// of chartRoot (see IsHelmChartFile).
func HelmChartFiles(paths []string, chartRoot string) []string {
	roots := []string{chartRoot}
	kept := make([]string, 0, len(paths))
	for _, p := range paths {
		if IsHelmChartFile(p, roots) {
			kept = append(kept, p)
		}
	}
	return kept
}

// IsNestedRenderedChart reports whether root is a subchart of an already
// rendered chart, which rendered it as part of its own tree.
func IsNestedRenderedChart(root string, renderedRoots []string) bool {
	root = toSlash(root)
	if root == "." {
		return false
	}
	return isHelmChartFileOf(root+"/Chart.yaml", renderedRoots, root)
}

// renderChartsShallowFirst calls chartFn for each chart root, parents before
// their subcharts, skipping a subchart once its parent rendered it. It returns
// the roots chartFn reported as rendered, the set whose Helm files are then
// withheld from the parsers (see IsHelmChartFile).
func renderChartsShallowFirst(ctx context.Context, roots []string,
	chartFn func(ctx context.Context, chartPath string) (rendered bool)) []string {
	renderedRoots := make([]string, 0, len(roots))
	for _, root := range chartRootsShallowFirst(roots) {
		normRoot := toSlash(root)
		if IsNestedRenderedChart(normRoot, renderedRoots) {
			continue
		}
		if chartFn(ctx, normRoot) {
			renderedRoots = append(renderedRoots, normRoot)
		}
	}
	return renderedRoots
}

func chartRootsShallowFirst(roots []string) []string {
	if len(roots) == 0 {
		return nil
	}
	sorted := append([]string(nil), roots...)
	sort.Slice(sorted, func(i, j int) bool {
		return len(sorted[i]) < len(sorted[j])
	})
	return sorted
}

func (s *FileSystemSourceProvider) isPathExcluded(path string) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return true, nil
		}
		return false, errors.Wrap(err, "failed to stat inventory path")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if f, ok := s.excludes[info.Name()]; ok && containsFile(f, info) {
		return true, nil
	}
	if s.onlyPaths != nil {
		underOnlyPath := false
		for _, op := range s.onlyPaths {
			if pathWithinBase(op, path) {
				underOnlyPath = true
				break
			}
		}
		if !underOnlyPath {
			return true, nil
		}
	}
	return false, nil
}

// WalkInventory collects matching files, calling chartFn at each Helm chart root.
func (s *FileSystemSourceProvider) WalkInventory(ctx context.Context,
	extensions model.Extensions,
	chartFn func(ctx context.Context, chartPath string) (skip bool)) ([]InventoryFile, error) {
	if len(s.prebuiltPaths) > 0 {
		return s.BuildInventoryFromPrebuilt(ctx, extensions, chartFn)
	}
	var files []InventoryFile

	for _, scanPath := range s.paths {
		fileInfo, err := os.Stat(scanPath)
		if err != nil {
			return nil, errors.Wrap(err, "failed to open path")
		}

		if !fileInfo.IsDir() {
			if openFileErr := validateScanFile(ctx, scanPath, extensions); openFileErr != nil {
				if errors.Is(openFileErr, ErrNotSupportedFile) || ignoreDamagedFiles(ctx, scanPath) {
					continue
				}
				return nil, openFileErr
			}
			ext, _ := utils.GetExtension(ctx, scanPath)
			files = append(files, InventoryFile{Path: toSlash(scanPath), Ext: ext})
			continue
		}

		walkErr := s.walkDirectory(ctx, scanPath, extensions,
			func(ctx context.Context, path string, resolved *[]string) error {
				if chartFn(ctx, toSlash(path)) {
					*resolved = append(*resolved, path)
				}
				return nil
			},
			func(_ context.Context, path, ext string) error {
				files = append(files, InventoryFile{Path: toSlash(path), Ext: ext})
				return nil
			})
		if walkErr != nil {
			return nil, errors.Wrap(walkErr, "failed to walk directory")
		}
	}

	return files, nil
}

func (s *FileSystemSourceProvider) walkDirectory(ctx context.Context, scanPath string, extensions model.Extensions,
	onChart func(ctx context.Context, path string, resolvedChartPaths *[]string) error,
	onFile func(ctx context.Context, path, ext string) error) error {
	var resolvedChartPaths []string
	return filepath.Walk(scanPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		shouldSkip, ext, skipFolder := s.checkConditions(ctx, info, extensions, path, resolvedChartPaths)
		if shouldSkip {
			return skipFolder
		}

		if info.IsDir() {
			return onChart(ctx, path, &resolvedChartPaths)
		}

		return onFile(ctx, path, ext)
	})
}

func (s *FileSystemSourceProvider) collectFiles(ctx context.Context, scanPath string,
	resolverSink ResolverSink, extensions model.Extensions) (files []string, err error) {
	err = s.walkDirectory(ctx, scanPath, extensions,
		func(ctx context.Context, path string, resolved *[]string) error {
			return s.resolveChartDir(ctx, path, resolverSink, resolved)
		},
		func(_ context.Context, path, _ string) error {
			files = append(files, toSlash(path))
			return nil
		})
	return files, err
}

// processFilesParallel processes collected files using a worker pool
func (s *FileSystemSourceProvider) processFilesParallel(ctx context.Context, files []string, sink Sink) error {
	if ctx == nil {
		ctx = context.Background()
	}

	// File reading is I/O-bound, so this pool does NOT draw from the shared CPU
	// budget (it would only waste CPU slots while blocked on disk). It keeps its
	// own wider [min,max] bound so disk parallelism is not throttled by core
	// count. The first error cancels the rest.
	return utils.ForEach(ctx, files,
		utils.PoolOptions{MinWorkers: utils.IOMinWorkers, MaxWorkers: utils.IOMaxWorkers},
		func(ctx context.Context, filePath string, _ int) error {
			return s.processFile(ctx, filePath, sink)
		})
}

// processFile opens and processes a single file
func (s *FileSystemSourceProvider) processFile(ctx context.Context, filePath string, sink Sink) error {
	c, err := os.Open(filepath.Clean(filePath)) // nolint:gosec
	if err != nil {
		if ignoreDamagedFiles(ctx, filepath.Clean(filePath)) {
			return nil
		}
		return errors.Wrap(err, "failed to open file")
	}
	defer c.Close() //nolint:all

	return sink(ctx, filePath, c)
}

func openScanFile(ctx context.Context, scanPath string, extensions model.Extensions) (*os.File, error) {
	ext, _ := utils.GetExtension(ctx, scanPath)

	if !extensions.Include(ext) {
		return nil, ErrNotSupportedFile
	}

	c, errOpenFile := os.Open(filepath.Clean(scanPath))
	if errOpenFile != nil {
		return nil, errors.Wrap(errOpenFile, "failed to open path")
	}
	return c, nil
}

func validateScanFile(ctx context.Context, scanPath string, extensions model.Extensions) error {
	file, err := openScanFile(ctx, scanPath, extensions)
	if err != nil {
		return err
	}
	return file.Close()
}

// nolint:gocyclo
func (s *FileSystemSourceProvider) checkConditions(ctx context.Context, info os.FileInfo, extensions model.Extensions,
	path string, resolvedChartPaths []string) (skip bool, ext string, err error) {
	contextLogger := logger.FromContext(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()

	if info.IsDir() {
		// exclude terraform cache folders
		if queryRegexExcludeTerraCache.MatchString(path) {
			contextLogger.Info().Msgf("Directory ignored: %s", path)

			err := s.addExcluded(ctx, []string{info.Name()})
			if err != nil {
				return true, "", err
			}
			return true, "", filepath.SkipDir
		}
		if f, ok := s.excludes[info.Name()]; ok && containsFile(f, info) {
			contextLogger.Info().Msgf("Directory ignored: %s", path)
			return true, "", filepath.SkipDir
		}
		// Everything under a rendered chart's templates/, crds/ or charts/ is a
		// Helm file, so the subtree is pruned rather than walked file by file.
		if isHelmChartDir(path, resolvedChartPaths) {
			return true, "", filepath.SkipDir
		}
		_, err := os.Stat(filepath.Join(path, "Chart.yaml"))
		if err != nil || IsNestedRenderedChart(path, resolvedChartPaths) {
			return true, "", nil
		}
		return false, "", nil
	}

	if f, ok := s.excludes[info.Name()]; ok && containsFile(f, info) {
		return true, "", nil
	}
	if IsHelmChartFile(path, resolvedChartPaths) {
		return true, "", nil
	}
	if s.onlyPaths != nil {
		underOnlyPath := false
		for _, op := range s.onlyPaths {
			if pathWithinBase(op, path) {
				underOnlyPath = true
				break
			}
		}
		if !underOnlyPath {
			return true, "", nil
		}
	}
	ext, _ = utils.GetExtension(ctx, path)
	if !extensions.Include(ext) {
		return true, "", nil
	}
	return false, ext, nil
}

func pathWithinBase(base, path string) bool {
	rel, err := filepath.Rel(filepath.Clean(base), filepath.Clean(path))
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

// resolveChartDir renders a Helm chart directory through the resolver. On success
// the chart's Helm files are skipped for the rest of the walk so they are not
// scanned again as raw, unrendered templates (which would yield bogus names like
// name: {{ .Release.Revision }}); other files under the chart root still are.
// On failure it returns nil to fall back to scanning the raw files.
func (s *FileSystemSourceProvider) resolveChartDir(ctx context.Context, path string,
	resolverSink ResolverSink, resolvedChartPaths *[]string) error {
	contextLogger := logger.FromContext(ctx)
	normPath := toSlash(path)
	excluded, errRes := resolverSink(ctx, normPath)
	if errRes != nil {
		// The render failure is already logged by the resolver sink; this is
		// just the fallback announcement, so keep it at Debug.
		contextLogger.Debug().Msgf("Scanning raw files of Helm chart '%s' as a fallback after render failure", path)
		return nil
	}
	if errAdd := s.ExcludePaths(ctx, HelmChartFiles(excluded, normPath)); errAdd != nil {
		contextLogger.Err(errAdd).Msgf("Filesystem files provider couldn't exclude rendered Chart files, Chart=%s", filepath.Base(path))
	}
	*resolvedChartPaths = append(*resolvedChartPaths, path)
	return nil
}

func containsFile(fileList []os.FileInfo, target os.FileInfo) bool {
	for _, file := range fileList {
		if os.SameFile(file, target) {
			return true
		}
	}
	return false
}
