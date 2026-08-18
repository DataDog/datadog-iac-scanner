/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package provider

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"sort"

	"github.com/DataDog/datadog-iac-scanner/internal/pathutil"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
)

// MemorySourceProvider serves a fixed set of files (pushed over HTTP) to the
// scan pipeline, reading their content through a vfs.FS. It replaces the
// disk-walking FileSystemSourceProvider in the server's content-push path, so
// there is no filesystem walk, no symlink/SameFile handling, and no Helm chart
// discovery.
//
// The resolverSink (used by FileSystemSourceProvider to render Helm charts) is
// intentionally never invoked: Helm rendering needs a real on-disk chart path
// and is unsupported in content-push mode. Pushed Helm templates fall through to
// raw-YAML scanning.
type MemorySourceProvider struct {
	fsys        vfs.FS
	paths       []string
	ignorePaths []string
	onlyPaths   []string
}

// NewMemorySourceProvider builds a provider over the given paths, reading each
// file's content from fsys (the same in-memory FS used for cross-file
// resolution, so content is stored once). ignorePaths/onlyPaths are the config's
// global path filters; they apply the same ignore-paths/only-paths semantics the
// disk source provider applies, so server-mode scans honor them too.
func NewMemorySourceProvider(fsys vfs.FS, paths, ignorePaths, onlyPaths []string) *MemorySourceProvider {
	sorted := append([]string(nil), paths...)
	sort.Strings(sorted)
	return &MemorySourceProvider{fsys: fsys, paths: sorted, ignorePaths: ignorePaths, onlyPaths: onlyPaths}
}

// GetBasePaths returns a synthetic root. Pushed paths are reported back exactly
// as they were pushed, whether relative or absolute, so there is no real base to
// name. The server's entry point (scan.Client.Scan) never consults this: it
// returns the raw vulnerabilities, skipping the summary step that relativizes
// file names against a base path.
func (m *MemorySourceProvider) GetBasePaths() []string { return []string{"."} }

// GetSources feeds each pushed file whose extension a parser supports into the
// sink, reading its content through the vfs.FS.
func (m *MemorySourceProvider) GetSources(ctx context.Context,
	extensions model.Extensions, sink Sink, _ ResolverSink) error {
	contextLogger := logger.FromContext(ctx)
	for _, p := range m.paths {
		if !extensions.Include(memExtension(p)) {
			continue
		}
		if pathutil.Excluded(p, m.ignorePaths, m.onlyPaths) {
			continue
		}
		content, err := m.fsys.ReadFile(p)
		if err != nil {
			contextLogger.Warn().Msgf("memory source provider: could not read pushed file %s: %v", p, err)
			continue
		}
		if err := sink(ctx, p, io.NopCloser(bytes.NewReader(content))); err != nil {
			return err
		}
	}
	return nil
}

// GetParallelSources fans the per-file sink (which parses the content into a
// document tree — the CPU-heavy step) across a bounded worker pool. There is no
// I/O to parallelize for in-memory content, but parsing is CPU-bound and a
// non-trivial share of a warm server scan, so this can speed up large pushes.
// It draws from the shared process-wide CPU budget (CPUBound) like the engine's
// other CPU-heavy pools, so concurrent scans don't oversubscribe the cores. The
// same sink is called concurrently by the disk provider, so it is safe for
// concurrent use.
func (m *MemorySourceProvider) GetParallelSources(ctx context.Context,
	extensions model.Extensions, sink Sink, _ ResolverSink) error {
	contextLogger := logger.FromContext(ctx)

	// Select the eligible files first (cheap; no parsing yet).
	eligible := make([]string, 0, len(m.paths))
	for _, p := range m.paths {
		if !extensions.Include(memExtension(p)) {
			continue
		}
		if pathutil.Excluded(p, m.ignorePaths, m.onlyPaths) {
			continue
		}
		eligible = append(eligible, p)
	}

	// Parse the eligible files in parallel. A file that cannot be read is logged
	// and skipped (not an error); the first sink error cancels the rest.
	return utils.ForEach(ctx, eligible,
		utils.PoolOptions{CPUBound: true},
		func(ctx context.Context, p string, _ int) error {
			content, err := m.fsys.ReadFile(p)
			if err != nil {
				contextLogger.Warn().Msgf("memory source provider: could not read pushed file %s: %v", p, err)
				return nil
			}
			return sink(ctx, p, io.NopCloser(bytes.NewReader(content)))
		})
}

// memExtension determines a pushed file's extension token from its path alone
// (no disk access), mirroring the dotted form parsers declare in
// SupportedExtensions (".tf", ".yaml", …). Extensionless files fall back to
// their base name so filename-keyed types like "Dockerfile" still match. Unlike
// utils.GetExtension it never stats the file, since pushed content has no
// on-disk presence.
func memExtension(p string) string {
	if ext := filepath.Ext(p); ext != "" {
		return ext
	}
	return filepath.Base(p)
}

var _ SourceProvider = (*MemorySourceProvider)(nil)
