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

// PrepareSharedWalk walks once, renders each chart once, and dispatches files to parsers.
func PrepareSharedWalk(ctx context.Context,
	fsp *provider.FileSystemSourceProvider,
	services []*Service,
	scanID string,
	openAPIResolveReferences bool,
	maxResolverDepth int) error {
	contextLogger := logger.FromContext(ctx)

	union := unionExtensions(services)

	files, err := fsp.WalkInventory(ctx, union,
		func(ctx context.Context, chartPath string) bool {
			return dispatchChart(ctx, fsp, services, chartPath, scanID, openAPIResolveReferences, maxResolverDepth)
		})
	if err != nil {
		return errors.Wrap(err, "failed to walk sources")
	}

	contextLogger.Info().Msgf("Collected %d files to process across %d parsers", len(files), len(services))

	routing := buildExtensionRouting(services)

	return utils.ForEach(ctx, files,
		utils.PoolOptions{MinWorkers: utils.IOMinWorkers, MaxWorkers: utils.IOMaxWorkers},
		func(ctx context.Context, f provider.InventoryFile, _ int) error {
			return dispatchFile(ctx, routing[f.Ext], f.Path, scanID, openAPIResolveReferences, maxResolverDepth, fsp.ContentCache())
		})
}

// PrepareMemorySources renders each pushed Helm chart once and dispatches the
// remaining pushed files to the parsers — the content-push analog of
// PrepareSharedWalk, and the path every server scan takes. Nested chart roots
// under an already rendered chart are skipped (the parent rendered them); a
// chart that fails to render escalates its directory via the missing set and
// falls back to raw scanning, as the disk walk does. parallel controls only the
// file-dispatch concurrency (the --x-parallelparsing flag); charts render in
// both modes.
func PrepareMemorySources(ctx context.Context,
	mp *provider.MemorySourceProvider,
	services []*Service,
	scanID string,
	openAPIResolveReferences bool,
	maxResolverDepth int,
	parallel bool) error {
	contextLogger := logger.FromContext(ctx)

	union := unionExtensions(services)
	files := mp.EligibleFiles(union)

	renderedRoots := make([]string, 0)
	for _, root := range mp.ChartRoots(union) {
		if provider.IsUnderChartRoot(root, renderedRoots) {
			continue
		}
		if dispatchMemoryChart(ctx, mp, services, root, scanID, openAPIResolveReferences, maxResolverDepth) {
			renderedRoots = append(renderedRoots, root)
		}
	}

	contextLogger.Info().Msgf("Collected %d pushed files to process across %d parsers", len(files), len(services))

	routing := buildExtensionRouting(services)
	pool := utils.PoolOptions{CPUBound: true}
	if !parallel {
		// The flag is off: sequential dispatch, as the legacy per-service path was.
		pool = utils.PoolOptions{Workers: 1}
	}
	return utils.ForEach(ctx, files,
		pool,
		func(ctx context.Context, filePath string, _ int) error {
			if provider.IsUnderChartRoot(filePath, renderedRoots) {
				return nil
			}
			return dispatchMemoryFile(ctx, mp, routing[memRoutingKey(filePath)], filePath, scanID, openAPIResolveReferences, maxResolverDepth)
		})
}

// memRoutingKey returns the extension key the routing map is built with — the
// same form the memory provider uses to filter eligible files.
func memRoutingKey(path string) string {
	if ext := utils.ExtensionFromPath(path); ext != "" {
		return ext
	}
	return filepath.Base(path)
}

func dispatchMemoryChart(ctx context.Context,
	mp *provider.MemorySourceProvider,
	services []*Service,
	chartPath, scanID string,
	openAPIResolveReferences bool,
	maxResolverDepth int) bool {
	return resolveAndStoreChart(ctx, services, chartPath, scanID, openAPIResolveReferences, maxResolverDepth,
		func() { mp.RecordMissing(chartPath) }, nil)
}

func dispatchChart(ctx context.Context,
	fsp *provider.FileSystemSourceProvider,
	services []*Service,
	chartPath, scanID string,
	openAPIResolveReferences bool,
	maxResolverDepth int) bool {
	return resolveAndStoreChart(ctx, services, chartPath, scanID, openAPIResolveReferences, maxResolverDepth,
		nil,
		func(resFiles model.ResolvedFiles) {
			if err := fsp.ExcludePaths(ctx, resFiles.Excluded); err != nil {
				contextLogger := logger.FromContext(ctx)
				contextLogger.Err(err).Msgf("could not exclude rendered chart files: %s", chartPath)
			}
		})
}

func resolveAndStoreChart(
	ctx context.Context,
	services []*Service,
	chartPath, scanID string,
	openAPIResolveReferences bool,
	maxResolverDepth int,
	onErr func(),
	afterResolve func(model.ResolvedFiles),
) bool {
	resFiles, kind, err := services[0].resolveOnly(ctx, chartPath)
	if kind == model.KindCOMMON {
		return true
	}
	if err != nil {
		for _, s := range services {
			s.logResolverResolveError(ctx, kind, chartPath, err)
		}
		if onErr != nil {
			onErr()
		}
		return false
	}
	if afterResolve != nil {
		afterResolve(resFiles)
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

// dispatchMemoryFile feeds one pushed file's content to every service whose
// parser supports its extension — dispatchFile's in-memory counterpart.
func dispatchMemoryFile(ctx context.Context,
	mp *provider.MemorySourceProvider,
	services []*Service,
	filePath, scanID string,
	openAPIResolveReferences bool,
	maxResolverDepth int) error {
	if len(services) == 0 {
		return nil
	}
	content, err := mp.ReadFile(filePath)
	if err != nil {
		// Pushed files always read; a miss means the file was withdrawn after
		// the provider snapshot — skip rather than fail the scan.
		contextLogger := logger.FromContext(ctx)
		contextLogger.Warn().Msgf("memory dispatch: could not read pushed file %s: %v", filePath, err)
		return nil
	}
	c, getErr := contentFromBytes(content, services[0].MaxFileSize, filePath)
	if getErr != nil {
		return errors.Wrapf(getErr, "failed to get file content: %s", filePath)
	}
	for i, s := range services {
		content := c
		if i > 0 {
			content = cloneContent(c)
		}
		if err := s.sinkContent(ctx, filePath, scanID, content, getErr, openAPIResolveReferences, maxResolverDepth); err != nil {
			return err
		}
	}
	return nil
}

func dispatchFile(ctx context.Context,
	services []*Service,
	filePath, scanID string,
	openAPIResolveReferences bool,
	maxResolverDepth int,
	contentCache map[string][]byte) error {
	if len(services) == 0 {
		return nil
	}
	services = servicesForPlatform(services, sharedFilePlatform(services, filePath))

	var c *Content
	var getErr error
	if contentCache != nil {
		norm := filepath.ToSlash(filePath)
		contentCacheMu.Lock()
		cached, ok := contentCache[norm]
		contentCacheMu.Unlock()
		if ok {
			c, getErr = contentFromBytes(cached, services[0].MaxFileSize, filePath)
			// contentFromBytes copies the bytes: delete the cache entry so the raw-byte
			// cache drains during the walk (concurrent, so guard the write).
			contentCacheMu.Lock()
			delete(contentCache, norm)
			contentCacheMu.Unlock()
			if getErr != nil {
				// The cached content was rejected (e.g. over the size limit);
				// re-reading the file from disk would only fail the same way,
				// so surface the error directly.
				return errors.Wrapf(getErr, "failed to get file content: %s", filePath)
			}
		}
	}
	if c == nil {
		f, err := os.Open(filepath.Clean(filePath))
		if err != nil {
			if provider.IgnoreDamagedFile(ctx, filepath.Clean(filePath)) {
				return nil
			}
			return errors.Wrap(err, "failed to open file")
		}
		buf := scanReadBufferPool.Get().(*[]byte)
		c, getErr = getContent(f, *buf, services[0].MaxFileSize, filePath)
		scanReadBufferPool.Put(buf)
		_ = f.Close()
	}

	for i, s := range services {
		content := c
		if i > 0 {
			content = cloneContent(c)
		}
		if err := s.sinkContent(ctx, filePath, scanID, content, getErr, openAPIResolveReferences, maxResolverDepth); err != nil {
			return err
		}
	}
	return nil
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
