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
	"github.com/zclconf/go-cty/cty/function"
)

// ScanFS serves the filesystem functions of one scan. The files a scan reads do
// not change under it, so each path's symlinks are resolved once instead of on
// every call that confines a path to its module, and what the file, decode and
// template functions make of a file or input is shared by every call asking
// for it again. Whoever creates a ScanFS decides how long those results live.
type ScanFS struct {
	vfs.FS

	mu       sync.Mutex
	resolved map[string]resolvedPath

	memo *scanMemo
}

type resolvedPath struct {
	path string
	err  error
}

func NewScanFS(fsys vfs.FS) *ScanFS {
	if parent, ok := fsys.(*ScanFS); ok {
		// Same scan: share the parent's memo and its process budget.
		return &ScanFS{FS: parent.FS, resolved: make(map[string]resolvedPath), memo: parent.memo}
	}
	return &ScanFS{FS: fsys, resolved: make(map[string]resolvedPath), memo: newScanMemo()}
}

// ReleaseMemo drops kept results and their budget charge. The next function
// call creates a fresh memo; ReleaseCaches must not reserve a full budget.
func (s *ScanFS) ReleaseMemo() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.memo != nil {
		s.memo.release()
		s.memo = nil
	}
}

// ensureMemo returns the scan memo, creating one after ReleaseMemo.
func (s *ScanFS) ensureMemo() *scanMemo {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.memo == nil {
		s.memo = newScanMemo()
	}
	return s.memo
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

// realPath names the file at path, so links to one file share its results.
func (s *ScanFS) realPath(path string) string {
	if !vfs.IsDisk(s.FS) {
		return path
	}
	if resolved, err := s.EvalSymlinks(path); err == nil {
		return resolved
	}
	return path
}

// scanMemo holds the results a ScanFS shares, within scanBudget. Decodes, file
// results and template renders have a budget each, so none can take another's
// room, and share the process allowance for larger results.
type scanMemo struct {
	decodes *resultMemo[decodeKey, valueResult]
	files   *resultMemo[fileKey, fileResult]
	renders *resultMemo[renderKey, valueResult]
	keys    *decodeKeys
	// decodeFuncs are jsondecode and yamldecode sharing decodes.
	decodeFuncs map[string]function.Function
}

func newScanMemo() *scanMemo {
	total := scanBudget()
	budget := total / kindShare
	large := processRetained()
	m := &scanMemo{
		decodes: newResultMemo(budget, large, estimateDecode),
		files:   newResultMemo(budget, large, estimateFile),
		renders: newResultMemo(budget, large, estimateRender),
		keys:    &decodeKeys{pinned: map[stringID]struct{}{}, keys: map[idKey]decodeKey{}},
	}
	m.decodeFuncs = decodeFuncs(m)
	m.files.kept = func(r fileResult) {
		if s, ok := r.outputString(); ok {
			m.keys.pin(s)
		}
	}
	m.renders.kept = func(r valueResult) {
		if s, ok := r.outputString(); ok {
			m.keys.pin(s)
		}
	}
	return m
}

func (m *scanMemo) release() {
	m.decodes.releaseAll()
	m.files.releaseAll()
	m.renders.releaseAll()
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
