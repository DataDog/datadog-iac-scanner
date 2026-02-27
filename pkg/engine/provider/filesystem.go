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
	paths    []string
	excludes map[string][]os.FileInfo
	mu       sync.RWMutex
}

const (
	minNumWorkers = 4
	maxNumWorkers = 64
)

var (
	queryRegexExcludeTerraCache = regexp.MustCompile(fmt.Sprintf(`^(.*?%s)?\.terra.*`, regexp.QuoteMeta(string(os.PathSeparator))))
	// ErrNotSupportedFile - error representing when a file format is not supported by KICS
	ErrNotSupportedFile = errors.New("invalid file format")
)

// NewFileSystemSourceProvider initializes a FileSystemSourceProvider with path and files that will be ignored
func NewFileSystemSourceProvider(ctx context.Context, paths, excludes []string) (*FileSystemSourceProvider, error) {
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
		if err := fs.AddExcluded(ctx, excludePaths); err != nil {
			return nil, err
		}
	}

	return fs, nil
}

// AddExcluded add new excluded files to the File System Source Provider
func (s *FileSystemSourceProvider) AddExcluded(ctx context.Context, excludePaths []string) error {
	contextLogger := logger.FromContext(ctx)
	for _, excludePath := range excludePaths {
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
		s.mu.Lock()
		if _, ok := s.excludes[info.Name()]; !ok {
			s.excludes[info.Name()] = make([]os.FileInfo, 0)
		}
		s.excludes[info.Name()] = append(s.excludes[info.Name()], info)
		s.mu.Unlock()
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

		err = s.walkDir(ctx, scanPath, false, sink, resolverSink, extensions)
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
		files, err := s.collectFiles(ctx, scanPath, false, resolverSink, extensions)
		if err != nil {
			return errors.Wrap(err, "failed to collect files")
		}
		filesToProcess = append(filesToProcess, files...)
	}

	contextLogger.Info().Msgf("Collected %d files to process", len(filesToProcess))

	// Phase 2: Process files in parallel
	return s.processFilesParallel(ctx, filesToProcess, sink)
}

// collectFiles walks the directory tree and collects file paths without processing them, except Helm files
func (s *FileSystemSourceProvider) collectFiles(ctx context.Context, scanPath string, resolved bool,
	resolverSink ResolverSink, extensions model.Extensions) (files []string, err error) {
	contextLogger := logger.FromContext(ctx)

	err = filepath.Walk(scanPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if shouldSkip, skipFolder := s.checkConditions(ctx, info, extensions, path, resolved); shouldSkip {
			return skipFolder
		}

		// ------------------ Helm resolver --------------------------------
		if info.IsDir() {
			excluded, errRes := resolverSink(ctx, strings.ReplaceAll(path, "\\", "/"))
			if errRes != nil {
				return nil
			}
			if errAdd := s.AddExcluded(ctx, excluded); errAdd != nil {
				contextLogger.Err(errAdd).Msgf("Filesystem files provider couldn't exclude rendered Chart files, Chart=%s", info.Name())
			}
			resolved = true
			return nil
		}
		// -----------------------------------------------------------------

		// Just collect the file path, don't open or process it yet
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
	contextLogger := logger.FromContext(ctx)

	numWorkers := s.calculateWorkerCount()
	contextLogger.Info().Msgf("Processing files with %d workers", numWorkers)

	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Create channels for work distribution
	filesChan := make(chan string, numWorkers*2)
	errChan := make(chan error, numWorkers)
	var wg sync.WaitGroup

	// Start worker goroutines
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go s.processFileWorker(workerCtx, &wg, filesChan, errChan, sink)
	}

	// Feed files to workers
	go s.feedFilesToWorkers(workerCtx, files, filesChan)

	go func() {
		wg.Wait()
		close(errChan)
	}()

	var firstErr error
	for err := range errChan {
		if err != nil && firstErr == nil {
			firstErr = err
			cancel()
		}
	}

	return firstErr
}

// calculateWorkerCount determines the optimal number of workers for parallel processing
func (s *FileSystemSourceProvider) calculateWorkerCount() int {
	numWorkers := utils.AdjustNumWorkers(0) // 0 means auto-detect
	if numWorkers < 1 {
		numWorkers = minNumWorkers
	}
	if numWorkers > maxNumWorkers {
		numWorkers = maxNumWorkers
	}
	return numWorkers
}

// processFileWorker is a worker goroutine that processes files from the channel
func (s *FileSystemSourceProvider) processFileWorker(ctx context.Context, wg *sync.WaitGroup,
	filesChan <-chan string, errChan chan<- error, sink Sink) {
	defer wg.Done()
	for filePath := range filesChan {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if err := s.processFile(ctx, filePath, sink); err != nil {
			select {
			case errChan <- err:
			case <-ctx.Done():
				return
			}
			// Stop processing more files after encountering an error
			return
		}
	}
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

// feedFilesToWorkers sends files to the worker pool through the channel
func (s *FileSystemSourceProvider) feedFilesToWorkers(ctx context.Context, files []string, filesChan chan<- string) {
	defer close(filesChan)
	for _, file := range files {
		select {
		case <-ctx.Done():
			return
		case filesChan <- file:
		}
	}
}

func (s *FileSystemSourceProvider) walkDir(ctx context.Context, scanPath string, resolved bool,
	sink Sink, resolverSink ResolverSink, extensions model.Extensions) error {
	contextLogger := logger.FromContext(ctx)
	return filepath.Walk(scanPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if shouldSkip, skipFolder := s.checkConditions(ctx, info, extensions, path, resolved); shouldSkip {
			return skipFolder
		}

		// ------------------ Helm resolver --------------------------------
		if info.IsDir() {
			excluded, errRes := resolverSink(ctx, strings.ReplaceAll(path, "\\", "/"))
			if errRes != nil {
				return nil
			}
			if errAdd := s.AddExcluded(ctx, excluded); errAdd != nil {
				contextLogger.Err(errAdd).Msgf("Filesystem files provider couldn't exclude rendered Chart files, Chart=%s", info.Name())
			}
			resolved = true
			return nil
		}
		// -----------------------------------------------------------------

		c, err := os.Open(filepath.Clean(path))
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

func (s *FileSystemSourceProvider) checkConditions(ctx context.Context, info os.FileInfo, extensions model.Extensions,
	path string, resolved bool) (bool, error) {
	contextLogger := logger.FromContext(ctx)
	s.mu.RLock()
	defer s.mu.RUnlock()

	if info.IsDir() {
		// exclude terraform cache folders
		if queryRegexExcludeTerraCache.MatchString(path) {
			contextLogger.Info().Msgf("Directory ignored: %s", path)

			err := s.AddExcluded(ctx, []string{info.Name()})
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
		if err != nil || resolved {
			return true, nil
		}
		return false, nil
	}

	if f, ok := s.excludes[info.Name()]; ok && containsFile(f, info) {
		return true, nil
	}
	ext, _ := utils.GetExtension(ctx, path)
	if !extensions.Include(ext) {
		return true, nil
	}
	return false, nil
}

func containsFile(fileList []os.FileInfo, target os.FileInfo) bool {
	for _, file := range fileList {
		if os.SameFile(file, target) {
			return true
		}
	}
	return false
}
