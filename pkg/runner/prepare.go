/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package runner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/analyzer"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/provider"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/pkg/errors"
)

// contentCacheMu guards concurrent deletes from the shared contentCache map
// during parallel dispatchFile calls.
var contentCacheMu sync.Mutex

// SharedWalkProvider returns the disk provider when every service shares one.
func SharedWalkProvider(services []*Service) (*provider.FileSystemSourceProvider, bool) {
	if len(services) == 0 {
		return nil, false
	}
	fsp, ok := services[0].SourceProvider.(*provider.FileSystemSourceProvider)
	if !ok {
		return nil, false
	}
	for _, s := range services[1:] {
		if other, ok := s.SourceProvider.(*provider.FileSystemSourceProvider); !ok || other != fsp {
			return nil, false
		}
	}
	return fsp, true
}

// SharedMemoryProvider returns the memory provider when every service shares one.
func SharedMemoryProvider(services []*Service) (*provider.MemorySourceProvider, bool) {
	if len(services) == 0 {
		return nil, false
	}
	mp, ok := services[0].SourceProvider.(*provider.MemorySourceProvider)
	if !ok {
		return nil, false
	}
	for _, s := range services[1:] {
		if other, ok := s.SourceProvider.(*provider.MemorySourceProvider); !ok || other != mp {
			return nil, false
		}
	}
	return mp, true
}

// preparedSource is what the shared prepare needs from a source provider. The
// disk walk (the CLI) and the IDE's pushed files differ only here: how files
// are listed (with each chart rendered through chartFn), how their bytes are
// read, how a file is routed to parsers, and what a chart's outcome records.
type preparedSource interface {
	WalkInventory(ctx context.Context, extensions model.Extensions,
		chartFn func(ctx context.Context, chartPath string) (rendered bool)) ([]provider.InventoryFile, error)
	// chartFailed runs when a chart fails to render; its raw files are scanned instead.
	chartFailed(chartPath string)
	// readContent returns nil content and a nil contentErr to skip the file.
	// contentErr is handed to the sinks; err aborts the scan.
	readContent(ctx context.Context, filePath string, maxFileSize int) (c *Content, contentErr, err error)
	// platform is the file's platform for parser routing, "" when undetermined.
	platform(ctx context.Context, services []*Service, filePath string, c *Content) string
}

// PrepareSharedWalk walks once, renders each chart once, and dispatches files to parsers.
func PrepareSharedWalk(ctx context.Context,
	fsp *provider.FileSystemSourceProvider,
	services []*Service,
	scanID string,
	openAPIResolveReferences bool,
	maxResolverDepth int) error {
	return prepareSources(ctx, diskSource{fsp}, services, scanID, openAPIResolveReferences, maxResolverDepth,
		utils.PoolOptions{MinWorkers: utils.IOMinWorkers, MaxWorkers: utils.IOMaxWorkers})
}

// PrepareMemorySources is PrepareSharedWalk over the files the IDE pushed, and
// the path every server scan takes. A chart that fails to render escalates its
// directory via the missing set. parallel controls only the file-dispatch
// concurrency (the --x-parallelparsing flag); charts render in both modes.
func PrepareMemorySources(ctx context.Context,
	mp *provider.MemorySourceProvider,
	services []*Service,
	scanID string,
	openAPIResolveReferences bool,
	maxResolverDepth int,
	parallel bool) error {
	pool := utils.PoolOptions{CPUBound: true}
	if !parallel {
		// The flag is off: sequential dispatch, as the legacy per-service path was.
		pool = utils.PoolOptions{Workers: 1}
	}
	return prepareSources(ctx, memorySource{mp}, services, scanID, openAPIResolveReferences, maxResolverDepth, pool)
}

// prepareSources lists src's files, rendering each Helm chart once (parents
// before their subcharts under charts/, which the parent renders), and hands
// every listed file to the parsers for its platform. Only a rendered chart's
// Helm files are withheld from the parsers, never other files under its root.
func prepareSources(ctx context.Context,
	src preparedSource,
	services []*Service,
	scanID string,
	openAPIResolveReferences bool,
	maxResolverDepth int,
	pool utils.PoolOptions) error {
	contextLogger := logger.FromContext(ctx)

	files, err := src.WalkInventory(ctx, unionExtensions(services),
		func(ctx context.Context, chartPath string) bool {
			return resolveAndStoreChart(ctx, src, services, chartPath, scanID, openAPIResolveReferences, maxResolverDepth)
		})
	if err != nil {
		return errors.Wrap(err, "failed to walk sources")
	}

	contextLogger.Info().Msgf("Collected %d files to process across %d parsers", len(files), len(services))

	routing := buildExtensionRouting(services)
	return utils.ForEach(ctx, files, pool,
		func(ctx context.Context, f provider.InventoryFile, _ int) error {
			return dispatchFile(ctx, src, routing[f.Ext], f.Path, scanID, openAPIResolveReferences, maxResolverDepth)
		})
}

func resolveAndStoreChart(
	ctx context.Context,
	src preparedSource,
	services []*Service,
	chartPath, scanID string,
	openAPIResolveReferences bool,
	maxResolverDepth int,
) bool {
	resFiles, kind, err := services[0].resolveOnly(ctx, chartPath)
	if kind == model.KindCOMMON {
		return true
	}
	if err != nil {
		for _, s := range services {
			s.logResolverResolveError(ctx, kind, chartPath, err)
		}
		src.chartFailed(chartPath)
		return false
	}
	routed := services
	if kind == model.KindHELM {
		if platform, ok := analyzer.PlatformForKind(kind); ok {
			routed = servicesForPlatformAndParserKind(services, platform, model.KindYAML)
		}
	}
	for _, s := range routed {
		s.storeResolvedFiles(ctx, resFiles, kind, scanID, openAPIResolveReferences, maxResolverDepth)
	}
	return true
}

// dispatchFile feeds one listed file's content to the services whose parser
// supports its extension, narrowed to the parsers for its platform.
func dispatchFile(ctx context.Context,
	src preparedSource,
	services []*Service,
	filePath, scanID string,
	openAPIResolveReferences bool,
	maxResolverDepth int) error {
	if len(services) == 0 {
		return nil
	}
	c, contentErr, err := src.readContent(ctx, filePath, services[0].MaxFileSize)
	if err != nil {
		return err
	}
	if c == nil && contentErr == nil {
		return nil
	}
	if len(services) > 1 {
		services = servicesForPlatform(services, src.platform(ctx, services, filePath, c))
	}

	for i, s := range services {
		content := c
		if i > 0 {
			content = cloneContent(c)
		}
		if err := s.sinkContent(ctx, filePath, scanID, content, contentErr, openAPIResolveReferences, maxResolverDepth); err != nil {
			return err
		}
	}
	return nil
}

// diskSource is the CLI's source: the walked (or analyzer-prebuilt) inventory,
// read from disk or the analyzer's content cache, routed by the analyzer's
// per-file platform.
type diskSource struct {
	*provider.FileSystemSourceProvider
}

func (diskSource) chartFailed(string) {}

func (d diskSource) readContent(ctx context.Context, filePath string, maxFileSize int) (*Content, error, error) {
	if contentCache := d.ContentCache(); contentCache != nil {
		norm := filepath.ToSlash(filePath)
		contentCacheMu.Lock()
		cached, ok := contentCache[norm]
		contentCacheMu.Unlock()
		if ok {
			c, getErr := contentFromBytes(cached, maxFileSize, filePath)
			// contentFromBytes copies the bytes: delete the cache entry so the raw-byte
			// cache drains during the walk (concurrent, so guard the write).
			contentCacheMu.Lock()
			delete(contentCache, norm)
			contentCacheMu.Unlock()
			if getErr != nil {
				// The cached content was rejected (e.g. over the size limit);
				// re-reading the file from disk would only fail the same way,
				// so surface the error directly.
				return nil, nil, errors.Wrapf(getErr, "failed to get file content: %s", filePath)
			}
			return c, nil, nil
		}
	}
	f, err := os.Open(filepath.Clean(filePath))
	if err != nil {
		if provider.IgnoreDamagedFile(ctx, filepath.Clean(filePath)) {
			return nil, nil, nil
		}
		return nil, nil, errors.Wrap(err, "failed to open file")
	}
	buf := scanReadBufferPool.Get().(*[]byte)
	c, getErr := getContent(f, *buf, maxFileSize, filePath)
	scanReadBufferPool.Put(buf)
	_ = f.Close()
	return c, getErr, nil
}

func (diskSource) platform(_ context.Context, services []*Service, filePath string, _ *Content) string {
	return sharedFilePlatform(services, filePath)
}

// memorySource is the server's source: the pushed files, read from the
// request's in-memory FS. The analyzer never walks pushed content, so each
// file is classified here, from its bytes, the way the analyzer classifies a
// file on disk.
type memorySource struct {
	*provider.MemorySourceProvider
}

func (m memorySource) chartFailed(chartPath string) {
	m.RecordMissing(chartPath)
}

func (m memorySource) readContent(ctx context.Context, filePath string, maxFileSize int) (*Content, error, error) {
	content, err := m.ReadFile(filePath)
	if err != nil {
		// Pushed files always read; a miss means the file was withdrawn after
		// the provider snapshot — skip rather than fail the scan.
		contextLogger := logger.FromContext(ctx)
		contextLogger.Warn().Msgf("memory dispatch: could not read pushed file %s: %v", filePath, err)
		return nil, nil, nil
	}
	c, getErr := contentFromBytes(content, maxFileSize, filePath)
	if getErr != nil {
		return nil, nil, errors.Wrapf(getErr, "failed to get file content: %s", filePath)
	}
	return c, nil, nil
}

func (memorySource) platform(ctx context.Context, services []*Service, filePath string, c *Content) string {
	if c == nil || c.Content == nil {
		return ""
	}
	return analyzer.ClassifyFile(ctx, services[0].Parser.FS(), filePath, *c.Content, services[0].Platforms)
}

func sharedFilePlatform(services []*Service, filePath string) string {
	path := filepath.ToSlash(filePath)
	platform := ""
	for _, service := range services {
		candidate, ok := service.FilePlatform[path]
		if !ok {
			continue
		}
		if platform != "" && !strings.EqualFold(platform, candidate) {
			return ""
		}
		platform = candidate
	}
	return platform
}

func servicesForPlatform(services []*Service, platform string) []*Service {
	if platform == "" {
		return services
	}
	routed := make([]*Service, 0, len(services))
	for _, service := range services {
		if containsPlatformFold(service.Parser.Platform, platform) {
			routed = append(routed, service)
		}
	}
	if len(routed) == 0 {
		return services
	}
	return routed
}

func cloneContent(c *Content) *Content {
	if c == nil {
		return nil
	}
	var b []byte
	if c.Content != nil {
		b = append(b, *c.Content...)
	}
	return &Content{
		Content:        &b,
		CountLines:     c.CountLines,
		IsMinified:     c.IsMinified,
		CountResources: c.CountResources,
	}
}

func servicesForPlatformAndParserKind(
	services []*Service,
	platform string,
	kind model.FileKind,
) []*Service {
	routed := make([]*Service, 0, len(services))
	for _, service := range services {
		if service.Parser.Parsers.GetKind() == kind &&
			containsPlatformFold(service.Parser.Platform, platform) {
			routed = append(routed, service)
		}
	}
	if len(routed) == 0 {
		return services
	}
	return routed
}

func containsPlatformFold(platforms []string, wanted string) bool {
	for _, platform := range platforms {
		if strings.EqualFold(platform, wanted) {
			return true
		}
	}
	return false
}

func unionExtensions(services []*Service) model.Extensions {
	union := model.Extensions{}
	for _, s := range services {
		for ext := range s.Parser.SupportedExtensions() {
			union[ext] = struct{}{}
		}
	}
	return union
}

func buildExtensionRouting(services []*Service) map[string][]*Service {
	routing := make(map[string][]*Service)
	for _, s := range services {
		for ext := range s.Parser.SupportedExtensions() {
			routing[ext] = append(routing[ext], s)
		}
	}
	return routing
}
