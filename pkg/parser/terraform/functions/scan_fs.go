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
// every call that confines a path to its module, and what the file and decode
// functions make of a file or input is shared by every call asking for it
// again. Whoever creates a ScanFS decides how long those results live.
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
	return &ScanFS{FS: fsys, resolved: make(map[string]resolvedPath), memo: newScanMemo()}
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

// resultKinds is the number of memos a ScanFS has: files and decodes.
const resultKinds = 2

// scanMemo holds the results a ScanFS shares, within scanBudget. Decodes and
// file results have a budget each, so neither can take the other's room, and
// share one allowance for larger results.
type scanMemo struct {
	decodes *resultMemo[decodeKey, valueResult]
	files   *resultMemo[fileKey, fileResult]
	keys    *decodeKeys
	// decodeFuncs are jsondecode and yamldecode sharing decodes.
	decodeFuncs map[string]function.Function
}

func newScanMemo() *scanMemo {
	total := scanBudget()
	budget := total / kindShare
	large := &allowance{size: total - resultKinds*budget}
	m := &scanMemo{
		decodes: newResultMemo(budget, large, estimateDecode),
		files:   newResultMemo(budget, large, estimateFile),
		keys:    &decodeKeys{pinned: map[stringID]struct{}{}, keys: map[idKey]decodeKey{}},
	}
	m.decodeFuncs = decodeFuncs(m)
	m.files.kept = func(r fileResult) {
		if s, ok := r.outputString(); ok {
			m.keys.pin(s)
		}
	}
	return m
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
