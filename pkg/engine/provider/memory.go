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

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
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
	fsys  vfs.FS
	paths []string
}

// NewMemorySourceProvider builds a provider over the given paths, reading each
// file's content from fsys (the same in-memory FS used for cross-file
// resolution, so content is stored once).
func NewMemorySourceProvider(fsys vfs.FS, paths []string) *MemorySourceProvider {
	sorted := append([]string(nil), paths...)
	sort.Strings(sorted)
	return &MemorySourceProvider{fsys: fsys, paths: sorted}
}

// GetBasePaths returns the synthetic root the pushed (workspace-relative) paths
// are reported against.
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

// GetParallelSources has no I/O to parallelize over in-memory content, so it
// delegates to GetSources.
func (m *MemorySourceProvider) GetParallelSources(ctx context.Context,
	extensions model.Extensions, sink Sink, resolverSink ResolverSink) error {
	return m.GetSources(ctx, extensions, sink, resolverSink)
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
