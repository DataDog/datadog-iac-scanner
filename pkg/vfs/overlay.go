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
	"strings"
)

// Overlay serves in-memory files on top of a base FS. Overlay files are regular
// and read-only, and replace a base entry of the same path. Directories that
// hold only overlay files exist in the overlay.
//
// An Overlay is immutable after construction, so it is safe for concurrent use
// when its base is.
type Overlay struct {
	base  FS
	files map[string][]byte
}

// NewOverlay returns an Overlay of files over base (the real disk when nil).
// Keys are resolved with base.Abs and cleaned; contents are copied.
func NewOverlay(base FS, files map[string][]byte) *Overlay {
	if base == nil {
		base = Default()
	}
	o := &Overlay{base: base, files: make(map[string][]byte, len(files))}
	for p, c := range files {
		o.files[o.key(p)] = append([]byte(nil), c...)
	}
	return o
}

// Unwrap returns the base FS, so type checks can see through the overlay.
func (o *Overlay) Unwrap() FS { return o.base }

// key returns the cleaned absolute form of name.
func (o *Overlay) key(name string) string {
	if abs, err := o.base.Abs(name); err == nil {
		name = abs
	}
	return filepath.Clean(name)
}

// ReadFile reads an overlay file, else the base file.
func (o *Overlay) ReadFile(name string) ([]byte, error) {
	if c, ok := o.files[o.key(name)]; ok {
		return append([]byte(nil), c...), nil
	}
	return o.base.ReadFile(name)
}

// Stat stats an overlay file, else the base path, else an overlay-only directory.
func (o *Overlay) Stat(name string) (fs.FileInfo, error) {
	key := o.key(name)
	if c, ok := o.files[key]; ok {
		return memFileInfo{name: filepath.Base(key), size: int64(len(c))}, nil
	}
	info, err := o.base.Stat(name)
	if err != nil && len(o.children(key)) > 0 {
		return memFileInfo{name: filepath.Base(key), dir: true}, nil
	}
	return info, err
}

// ReadDir merges the base entries with the overlay entries of the directory.
func (o *Overlay) ReadDir(name string) ([]fs.DirEntry, error) {
	extra := o.children(o.key(name))
	entries, err := o.base.ReadDir(name)
	if err != nil && len(extra) == 0 {
		return nil, err
	}
	byName := make(map[string]fs.DirEntry, len(entries)+len(extra))
	for _, e := range entries {
		byName[e.Name()] = e
	}
	for n, e := range extra {
		if _, ok := byName[n]; ok && e.IsDir() {
			continue
		}
		byName[n] = e
	}
	out := make([]fs.DirEntry, 0, len(byName))
	for _, e := range byName {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out, nil
}

// Glob returns the sorted, deduplicated union of the base matches and the
// overlay files matching pattern. Overlay matches are absolute paths.
func (o *Overlay) Glob(pattern string) ([]string, error) {
	out, err := o.base.Glob(pattern)
	if err != nil {
		return nil, err
	}
	pat := o.key(pattern)
	seen := make(map[string]struct{}, len(out))
	for _, p := range out {
		seen[p] = struct{}{}
	}
	for key := range o.files {
		ok, err := filepath.Match(pat, key)
		if err != nil {
			return nil, err
		}
		if _, dup := seen[key]; ok && !dup {
			out = append(out, key)
			seen[key] = struct{}{}
		}
	}
	sort.Strings(out)
	return out, nil
}

// Abs resolves name against the base.
func (o *Overlay) Abs(name string) (string, error) { return o.base.Abs(name) }

// children returns the overlay entries directly under dir, by name.
func (o *Overlay) children(dir string) map[string]fs.DirEntry {
	out := make(map[string]fs.DirEntry)
	prefix := dir
	if !strings.HasSuffix(prefix, string(filepath.Separator)) {
		prefix += string(filepath.Separator)
	}
	for key, c := range o.files {
		rel, ok := strings.CutPrefix(key, prefix)
		if !ok || rel == "" {
			continue
		}
		seg, _, nested := strings.Cut(rel, string(filepath.Separator))
		if !nested {
			out[rel] = memDirEntry{name: rel, size: int64(len(c))}
		} else if _, ok := out[seg]; !ok {
			out[seg] = memDirEntry{name: seg, dir: true}
		}
	}
	return out
}

var _ FS = (*Overlay)(nil)
