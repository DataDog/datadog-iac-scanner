/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package functions

import (
	"path/filepath"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
)

// ScanFS serves the filesystem functions of one scan. The files a scan reads do
// not change under it, so each path's symlinks are resolved once instead of on
// every call that confines a path to its module.
type ScanFS struct {
	vfs.FS

	mu       sync.Mutex
	resolved map[string]resolvedPath
}

type resolvedPath struct {
	path string
	err  error
}

func NewScanFS(fsys vfs.FS) *ScanFS {
	return &ScanFS{FS: fsys, resolved: make(map[string]resolvedPath)}
}

// EvalSymlinks is filepath.EvalSymlinks, remembered for the life of the scan.
func (s *ScanFS) EvalSymlinks(path string) (string, error) {
	s.mu.Lock()
	cached, ok := s.resolved[path]
	s.mu.Unlock()
	if ok {
		return cached.path, cached.err
	}
	resolved, err := filepath.EvalSymlinks(path)
	s.mu.Lock()
	s.resolved[path] = resolvedPath{path: resolved, err: err}
	s.mu.Unlock()
	return resolved, err
}

func evalSymlinks(fsys vfs.FS, path string) (string, error) {
	if s, ok := fsys.(*ScanFS); ok {
		return s.EvalSymlinks(path)
	}
	return filepath.EvalSymlinks(path)
}

func isMemFS(fsys vfs.FS) bool {
	if s, ok := fsys.(*ScanFS); ok {
		fsys = s.FS
	}
	_, ok := fsys.(*vfs.MemFS)
	return ok
}
