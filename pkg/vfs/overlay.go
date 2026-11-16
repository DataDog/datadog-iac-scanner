/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package vfs

import (
	"io/fs"
	"path/filepath"
	"sort"
	"time"
)

// Overlay serves Files over Base: a file in Files replaces or adds to Base's
// file of the same path. Files are regular files; their directories must
// exist in Base. Overlay never writes.
type Overlay struct {
	Base  FS
	Files map[string][]byte
}

// NewOverlay returns an Overlay of files, by cleaned absolute path, over base.
func NewOverlay(base FS, files map[string][]byte) *Overlay {
	if base == nil {
		base = Default()
	}
	cleaned := make(map[string][]byte, len(files))
	for path, content := range files {
		cleaned[filepath.Clean(path)] = content
	}
	return &Overlay{Base: base, Files: cleaned}
}

// ReadFile reads an overlay file, or Base's.
func (o *Overlay) ReadFile(name string) ([]byte, error) {
	if content, ok := o.Files[filepath.Clean(name)]; ok {
		return content, nil
	}
	return o.Base.ReadFile(name)
}

// Stat stats an overlay file, or Base's.
func (o *Overlay) Stat(name string) (fs.FileInfo, error) {
	if content, ok := o.Files[filepath.Clean(name)]; ok {
		return overlayInfo{name: filepath.Base(name), size: int64(len(content))}, nil
	}
	return o.Base.Stat(name)
}

// ReadDir lists Base's entries with the overlay files of the directory added,
// replacing Base's entries of the same name.
func (o *Overlay) ReadDir(name string) ([]fs.DirEntry, error) {
	entries, err := o.Base.ReadDir(name)
	if err != nil {
		return nil, err
	}
	dir := filepath.Clean(name)
	added := map[string]fs.DirEntry{}
	for path, content := range o.Files {
		if filepath.Dir(path) == dir {
			base := filepath.Base(path)
			added[base] = fs.FileInfoToDirEntry(overlayInfo{name: base, size: int64(len(content))})
		}
	}
	if len(added) == 0 {
		return entries, nil
	}
	out := make([]fs.DirEntry, 0, len(entries)+len(added))
	for _, entry := range entries {
		if _, replaced := added[entry.Name()]; !replaced {
			out = append(out, entry)
		}
	}
	for _, entry := range added {
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out, nil
}

// Glob matches Base's files and the overlay files.
func (o *Overlay) Glob(pattern string) ([]string, error) {
	matches, err := o.Base.Glob(pattern)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(matches))
	for _, match := range matches {
		seen[filepath.Clean(match)] = true
	}
	for path := range o.Files {
		if ok, _ := filepath.Match(pattern, path); ok && !seen[path] {
			matches = append(matches, path)
		}
	}
	sort.Strings(matches)
	return matches, nil
}

// Abs resolves name as Base does.
func (o *Overlay) Abs(name string) (string, error) { return o.Base.Abs(name) }

// overlayFileMode is the mode of overlay files: regular and read-only.
const overlayFileMode fs.FileMode = 0o444

type overlayInfo struct {
	name string
	size int64
}

func (i overlayInfo) Name() string       { return i.name }
func (i overlayInfo) Size() int64        { return i.size }
func (i overlayInfo) Mode() fs.FileMode  { return overlayFileMode }
func (i overlayInfo) ModTime() time.Time { return time.Time{} }
func (i overlayInfo) IsDir() bool        { return false }
func (i overlayInfo) Sys() any           { return nil }
