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

	"github.com/DataDog/datadog-iac-scanner/pkg/engine/provider"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	pulumi "github.com/DataDog/datadog-iac-scanner/pkg/parser/pulumi"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/pulumi/projectindex"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/pkg/errors"
)

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

	// Build the Pulumi cross-file symbol index once and attach it to the shared
	// context so all language parsers can resolve relative imports without an
	// extra repo walk.
	paths := make([]string, 0, len(files))
	for _, f := range files {
		paths = append(paths, f.Path)
	}
	idx := projectindex.Build(paths, fsp.ContentCache())
	if len(idx.ByFile) > 0 {
		ctx = pulumi.WithProjectIndex(ctx, idx)
	}

	routing := buildExtensionRouting(services)

	return utils.ForEach(ctx, files,
		utils.PoolOptions{MinWorkers: utils.IOMinWorkers, MaxWorkers: utils.IOMaxWorkers},
		func(ctx context.Context, f provider.InventoryFile, _ int) error {
			return dispatchFile(ctx, routing[f.Ext], f.Path, scanID, openAPIResolveReferences, maxResolverDepth, fsp.ContentCache())
		})
}

func dispatchChart(ctx context.Context,
	fsp *provider.FileSystemSourceProvider,
	services []*Service,
	chartPath, scanID string,
	openAPIResolveReferences bool,
	maxResolverDepth int) bool {
	contextLogger := logger.FromContext(ctx)
	resFiles, kind, err := services[0].resolveOnly(ctx, chartPath)
	if kind == model.KindCOMMON {
		return true
	}
	if err != nil {
		for _, s := range services {
			s.logResolverResolveError(ctx, kind, chartPath, err)
		}
		return false
	}
	if err := fsp.ExcludePaths(ctx, resFiles.Excluded); err != nil {
		contextLogger.Err(err).Msgf("could not exclude rendered chart files: %s", chartPath)
	}
	for _, s := range services {
		s.storeResolvedFiles(ctx, resFiles, kind, scanID, openAPIResolveReferences, maxResolverDepth)
	}
	return true
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

	var c *Content
	var getErr error
	if contentCache != nil {
		norm := filepath.ToSlash(filePath)
		if cached, ok := contentCache[norm]; ok {
			c, getErr = contentFromBytes(cached, services[0].MaxFileSize, filePath)
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
