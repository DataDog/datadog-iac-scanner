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
		excludePaths, err := GetExcludePaths(ctx, exclude)
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
			expanded, err := GetExcludePaths(ctx, only)
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
func GetExcludePaths(ctx context.Context, pathExpressions string) ([]string, error) {
	contextLogger := logger.FromContext(ctx)
	if strings.ContainsAny(pathExpressions, "*?[") {
		info, err := filepathx.Glob(pathExpressions)
		if err != nil {
			contextLogger.Error().Msgf("failed to get exclude path %s: %s", pathExpressions, err)
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
		s.paths = append(s.paths, filepath.FromSlash(p))
	}
}

func (s *FileSystemSourceProvider) TerraformFiles(ctx context.Context) ([]string, error) {
	files := make([]string, 0)
	extensions := model.Extensions{".tf": {}}
	for _, scanPath := range s.paths {
		fileInfo, err := os.Stat(scanPath)
		if err != nil {
			return nil, errors.Wrap(err, "failed to open path")
		}
		if !fileInfo.IsDir() {
			if shouldSkip, _ := s.checkConditions(ctx, fileInfo, extensions, scanPath, nil); shouldSkip {
				continue
			}
			files = append(files, strings.ReplaceAll(scanPath, "\\", "/"))
			continue
		}
		collected, err := s.collectFiles(ctx, scanPath, noopResolverSink, extensions)
		if err != nil {
			return nil, errors.Wrap(err, "failed to collect files")
		}
		files = append(files, collected...)
	}
	return files, nil
}

func noopResolverSink(context.Context, string) ([]string, error) {
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
	for _, scanPath := range s.paths {
		fileInfo, err := os.Stat(scanPath)
		if err != nil {
			return errors.Wrap(err, "failed to open path")
		}

		if !fileInfo.IsDir() {
			c, openFileErr := openScanFile(ctx, scanPath, extensions)
			if openFileErr != nil {
				if errors.Is(openFileErr, ErrNotSupportedFile) || ignoreDamagedFiles(ctx, scanPath) {
					continue
				}
				return openFileErr
			}
			if sinkErr := sink(ctx, scanPath, c); sinkErr != nil {
				return sinkErr
			}
			continue
		}

		err = s.walkDir(ctx, scanPath, sink, resolverSink, extensions)
		if err != nil {
			return errors.Wrap(err, "failed to walk directory")
		}
		continue
	}
	return nil
}

// GetParallelSources is an alternative to GetSources, parallelising the task
func (s *FileSystemSourceProvider) GetParallelSources(ctx context.Context,
	extensions model.Extensions, sink Sink, resolverSink ResolverSink) error {
	contextLogger := logger.FromContext(ctx)

	// Phase 1: Collect all file paths to process
	var filesToProcess []string

	for _, scanPath := range s.paths {
		fileInfo, err := os.Stat(scanPath)
		if err != nil {
			return errors.Wrap(err, "failed to open path")
		}

		if !fileInfo.IsDir() {
			// Single file - validate and add to queue
			_, openFileErr := openScanFile(ctx, scanPath, extensions)
			if openFileErr != nil {
				if errors.Is(openFileErr, ErrNotSupportedFile) || ignoreDamagedFiles(ctx, scanPath) {
					continue
				}
				return openFileErr
			}
			filesToProcess = append(filesToProcess, scanPath)
			continue
		}

		// Directory - collect all files first
		files, err := s.collectFiles(ctx, scanPath, resolverSink, extensions)
		if err != nil {
			return errors.Wrap(err, "failed to collect files")
		}
		filesToProcess = append(filesToProcess, files...)
	}

	contextLogger.Info().Msgf("Collected %d files to process", len(filesToProcess))

	// Phase 2: Process files in parallel
	return s.processFilesParallel(ctx, filesToProcess, sink)
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

// BuildInventoryFromPrebuilt renders Helm charts and filters pre-collected paths.
func (s *FileSystemSourceProvider) BuildInventoryFromPrebuilt(ctx context.Context,
	extensions model.Extensions,
	chartFn func(ctx context.Context, chartPath string) (skip bool)) ([]InventoryFile, error) {
	// Shallow-first; skip nested roots after parent chart renders.
	renderedRoots := make([]string, 0, len(s.chartRoots))
	chartRoots := chartRootsShallowFirst(s.chartRoots)
	for _, root := range chartRoots {
		normRoot := strings.ReplaceAll(root, "\\", "/")
		if isUnderChartRoot(normRoot, renderedRoots) {
			continue
		}
		if chartFn(ctx, normRoot) {
			renderedRoots = append(renderedRoots, normRoot)
		}
	}

	files := make([]InventoryFile, 0, len(s.prebuiltPaths))
	for _, path := range s.prebuiltPaths {
		norm := strings.ReplaceAll(path, "\\", "/")
		if isUnderChartRoot(norm, renderedRoots) {
			continue
		}
		excluded, err := s.isPathExcluded(norm)
		if err != nil || excluded {
			continue
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

func isUnderChartRoot(path string, chartRoots []string) bool {
	for _, root := range chartRoots {
		if path == root ||
			strings.HasPrefix(path, root+string(os.PathSeparator)) ||
			strings.HasPrefix(path, root+"/") {
			return true
		}
	}
	return false
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
			if path == op || strings.HasPrefix(path, op+string(os.PathSeparator)) ||
				strings.HasPrefix(path, op+"/") {
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
			if _, openFileErr := openScanFile(ctx, scanPath, extensions); openFileErr != nil {
				if errors.Is(openFileErr, ErrNotSupportedFile) || ignoreDamagedFiles(ctx, scanPath) {
					continue
				}
				return nil, openFileErr
			}
			ext, _ := utils.GetExtension(ctx, scanPath)
			files = append(files, InventoryFile{Path: strings.ReplaceAll(scanPath, "\\", "/"), Ext: ext})
			continue
		}

		walkErr := s.walkDirectory(ctx, scanPath, extensions,
			func(ctx context.Context, path string, resolved *[]string) error {
				if chartFn(ctx, strings.ReplaceAll(path, "\\", "/")) {
					*resolved = append(*resolved, path)
					return filepath.SkipDir
				}
				return nil
			},
			func(ctx context.Context, path string) error {
				ext, _ := utils.GetExtension(ctx, path)
				files = append(files, InventoryFile{Path: strings.ReplaceAll(path, "\\", "/"), Ext: ext})
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
	onFile func(ctx context.Context, path string) error) error {
	var resolvedChartPaths []string
	return filepath.Walk(scanPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if shouldSkip, skipFolder := s.checkConditions(ctx, info, extensions, path, resolvedChartPaths); shouldSkip {
			return skipFolder
		}

		if info.IsDir() {
			return onChart(ctx, path, &resolvedChartPaths)
		}

		return onFile(ctx, path)
	})
}

func (s *FileSystemSourceProvider) collectFiles(ctx context.Context, scanPath string,
	resolverSink ResolverSink, extensions model.Extensions) (files []string, err error) {
	err = s.walkDirectory(ctx, scanPath, extensions,
		func(ctx context.Context, path string, resolved *[]string) error {
			return s.resolveChartDir(ctx, path, resolverSink, resolved)
		},
		func(ctx context.Context, path string) error {
			files = append(files, strings.ReplaceAll(path, "\\", "/"))
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
	c, err := os.Open(filepath.Clean(filePath))
	if err != nil {
		if ignoreDamagedFiles(ctx, filepath.Clean(filePath)) {
			return nil
		}
		return errors.Wrap(err, "failed to open file")
	}
	defer c.Close() //nolint:all

	return sink(ctx, filePath, c)
}

func (s *FileSystemSourceProvider) walkDir(ctx context.Context, scanPath string,
	sink Sink, resolverSink ResolverSink, extensions model.Extensions) error {
	return s.walkDirectory(ctx, scanPath, extensions,
		func(ctx context.Context, path string, resolved *[]string) error {
			return s.resolveChartDir(ctx, path, resolverSink, resolved)
		},
		func(ctx context.Context, path string) error {
			c, err := os.Open(filepath.Clean(path)) // nolint:gosec
			if err != nil {
				if ignoreDamagedFiles(ctx, filepath.Clean(path)) {
					return nil
				}
				return errors.Wrap(err, "failed to open file")
			}
			defer func(c *os.File) {
				_ = c.Close()
			}(c)

			return sink(ctx, strings.ReplaceAll(path, "\\", "/"), c)
		})
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

// nolint:gocyclo
func (s *FileSystemSourceProvider) checkConditions(ctx context.Context, info os.FileInfo, extensions model.Extensions,
	path string, resolvedChartPaths []string) (bool, error) {
	contextLogger := logger.FromContext(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()

	if info.IsDir() {
		// exclude terraform cache folders
		if queryRegexExcludeTerraCache.MatchString(path) {
			contextLogger.Info().Msgf("Directory ignored: %s", path)

			err := s.addExcluded(ctx, []string{info.Name()})
			if err != nil {
				return true, err
			}
			return true, filepath.SkipDir
		}
		if f, ok := s.excludes[info.Name()]; ok && containsFile(f, info) {
			contextLogger.Info().Msgf("Directory ignored: %s", path)
			return true, filepath.SkipDir
		}
		_, err := os.Stat(filepath.Join(path, "Chart.yaml"))
		if err != nil || isUnderResolvedChart(path, resolvedChartPaths) {
			return true, nil
		}
		return false, nil
	}

	if f, ok := s.excludes[info.Name()]; ok && containsFile(f, info) {
		return true, nil
	}
	if s.onlyPaths != nil {
		underOnlyPath := false
		for _, op := range s.onlyPaths {
			if path == op || strings.HasPrefix(path, op+string(os.PathSeparator)) {
				underOnlyPath = true
				break
			}
		}
		if !underOnlyPath {
			return true, nil
		}
	}
	ext, _ := utils.GetExtension(ctx, path)
	if !extensions.Include(ext) {
		return true, nil
	}
	return false, nil
}

// resolveChartDir renders a Helm chart directory through the resolver. On success
// it returns filepath.SkipDir so the chart subtree is not walked again as raw,
// unrendered templates (which would yield bogus names like name: {{ .Release.Revision }}).
// On failure it returns nil to fall back to scanning the raw files.
func (s *FileSystemSourceProvider) resolveChartDir(ctx context.Context, path string,
	resolverSink ResolverSink, resolvedChartPaths *[]string) error {
	contextLogger := logger.FromContext(ctx)
	excluded, errRes := resolverSink(ctx, strings.ReplaceAll(path, "\\", "/"))
	if errRes != nil {
		// The render failure is already logged by the resolver sink; this is
		// just the fallback announcement, so keep it at Debug.
		contextLogger.Debug().Msgf("Scanning raw files of Helm chart '%s' as a fallback after render failure", path)
		return nil
	}
	if errAdd := s.ExcludePaths(ctx, excluded); errAdd != nil {
		contextLogger.Err(errAdd).Msgf("Filesystem files provider couldn't exclude rendered Chart files, Chart=%s", filepath.Base(path))
	}
	*resolvedChartPaths = append(*resolvedChartPaths, path)
	return filepath.SkipDir
}

func isUnderResolvedChart(path string, resolvedChartPaths []string) bool {
	for _, chartRoot := range resolvedChartPaths {
		if strings.HasPrefix(path, chartRoot+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

func containsFile(fileList []os.FileInfo, target os.FileInfo) bool {
	for _, file := range fileList {
		if os.SameFile(file, target) {
			return true
		}
	}
	return false
}
