/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package model

import (
	"context"
	"io/fs"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
)

// scannedFS hides, in every directory holding a scanned file, the
// configuration files the scan left out (ignored, excluded or too large).
// Directories without a scanned file, such as module directories outside the
// scanned paths, are served as they are.
type scannedFS struct {
	vfs.FS
	files map[string]bool
	dirs  map[string]bool
}

var _ vfs.Wrapper = (*scannedFS)(nil)

// newScannedFS serves the files of the set files and the plans.
func newScannedFS(fsys vfs.FS, files map[string]bool, plans []string) *scannedFS {
	s := &scannedFS{FS: fsys, files: make(map[string]bool, len(files)+len(plans)), dirs: map[string]bool{}}
	add := func(f string) {
		s.files[pathKey(f)] = true
		s.dirs[pathKey(filepath.Dir(f))] = true
	}
	for f, ok := range files {
		if ok {
			add(f)
		}
	}
	for _, f := range plans {
		add(f)
	}
	return s
}

// pathKey compares paths whatever separator the filesystem's Abs returns.
func pathKey(path string) string {
	return filepath.ToSlash(filepath.Clean(path))
}

func (s *scannedFS) Unwrap() vfs.FS { return s.FS }

// hidden reports whether name is a configuration file, or a plain JSON file
// that could be one, of a scanned directory that the scan does not hold.
func (s *scannedFS) hidden(name string) bool {
	if !tfpath.IsConfig(name) && !tfpath.IsPlainJSON(name) {
		return false
	}
	return s.dirs[pathKey(filepath.Dir(name))] && !s.files[pathKey(name)]
}

func (s *scannedFS) ReadFile(name string) ([]byte, error) {
	if s.hidden(name) {
		return nil, &fs.PathError{Op: "read", Path: name, Err: fs.ErrNotExist}
	}
	return s.FS.ReadFile(name)
}

func (s *scannedFS) Stat(name string) (fs.FileInfo, error) {
	info, err := s.FS.Stat(name)
	if err == nil && !info.IsDir() && s.hidden(name) {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrNotExist}
	}
	return info, err
}

func (s *scannedFS) ReadDir(name string) ([]fs.DirEntry, error) {
	entries, err := s.FS.ReadDir(name)
	if err != nil || !s.dirs[pathKey(name)] {
		return entries, err
	}
	return slices.DeleteFunc(entries, func(e fs.DirEntry) bool {
		return !e.IsDir() && s.hidden(filepath.Join(name, e.Name()))
	}), nil
}

func (s *scannedFS) Glob(pattern string) ([]string, error) {
	matches, err := s.FS.Glob(pattern)
	if err != nil {
		return matches, err
	}
	return slices.DeleteFunc(matches, s.hidden), nil
}

// scanFiles fills dirs with the directories of files and the module
// directories they call, directly or through other modules, and marks the
// ones called as local modules. Directories under a hidden directory of base
// are left out, as walk does.
func scanFiles(
	ctx context.Context, fsys vfs.FS, resolver tfeval.RemoteResolver, base string, files map[string]bool,
	dirs map[string]*dirInfo, called map[string]bool,
) error {
	remote := map[string]bool{}
	resolver = recordingResolver(resolver, remote)
	queue, err := scannedDirs(fsys, base, files, dirs)
	if err != nil {
		return err
	}
	seen := make(map[string]bool, len(queue))
	for _, dir := range queue {
		seen[dir] = true
	}
	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		dir := queue[0]
		queue = queue[1:]
		clear(remote)
		for _, child := range tfeval.CalledModuleDirs(dir, resolver, fsys) {
			child = filepath.Clean(child)
			if child == dir {
				continue
			}
			if !remote[child] {
				called[child] = true
			}
			if seen[child] {
				continue
			}
			seen[child] = true
			queue = append(queue, child)
			if info, _, err := readDirInfo(fsys, child); err == nil && info != nil {
				dirs[child] = info
			}
		}
	}
	return nil
}

// scannedDirs reads the directories of files that are not under a hidden
// directory of base into dirs, and returns them sorted.
func scannedDirs(fsys vfs.FS, base string, files map[string]bool, dirs map[string]*dirInfo) ([]string, error) {
	set := map[string]bool{}
	for f, ok := range files {
		if dir := filepath.Clean(filepath.Dir(f)); ok && !underHiddenDir(base, dir) {
			set[dir] = true
		}
	}
	out := slices.Sorted(maps.Keys(set))
	for _, dir := range out {
		info, _, err := readDirInfo(fsys, dir)
		if err != nil {
			return nil, err
		}
		if info != nil {
			dirs[dir] = info
		}
	}
	return out, nil
}

// recordingResolver is resolver, also recording in remote the directories it
// resolves.
func recordingResolver(resolver tfeval.RemoteResolver, remote map[string]bool) tfeval.RemoteResolver {
	if resolver == nil {
		return nil
	}
	return func(source, version, callerFile, moduleName string) (string, string, bool) {
		dir, packageRoot, ok := resolver(source, version, callerFile, moduleName)
		if ok {
			remote[filepath.Clean(dir)] = true
		}
		return dir, packageRoot, ok
	}
}

func underHiddenDir(base, dir string) bool {
	rel, err := filepath.Rel(base, dir)
	if err != nil || rel == "." {
		return false
	}
	for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
		if part != ".." && strings.HasPrefix(part, ".") {
			return true
		}
	}
	return false
}
