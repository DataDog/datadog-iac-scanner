/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package vfs

import (
	"io/fs"
	"path"
	"sort"
)

// Overlay serves in-memory files on top of a base FS. Overlay files are regular
// and read-only, and replace a base entry of the same path. Directories that
// hold only overlay files exist in the overlay.
//
// An Overlay is immutable after construction, so it is safe for concurrent use
// when its base is.
type Overlay struct {
	base FS
	// files is keyed by the slash form of each path, so lookups do not depend
	// on separators; display is the path in the base's own form.
	files map[string]overlayFile
}

type overlayFile struct {
	display string
	content []byte
}

// NewOverlay returns an Overlay of files over base (the real disk when nil).
// Keys are resolved with base.Abs; contents are copied.
func NewOverlay(base FS, files map[string][]byte) *Overlay {
	if base == nil {
		base = Default()
	}
	o := &Overlay{base: base, files: make(map[string]overlayFile, len(files))}
	for p, c := range files {
		display := o.abs(p)
		o.files[normalize(display)] = overlayFile{display: display, content: append([]byte(nil), c...)}
	}
	return o
}

// Unwrap returns the base FS, so type checks can see through the overlay.
func (o *Overlay) Unwrap() FS { return o.base }

// abs returns name as the base resolves it (MemFS keeps forward slashes).
func (o *Overlay) abs(name string) string { return AbsOrClean(o.base, name) }

func (o *Overlay) key(name string) string { return normalize(o.abs(name)) }

// ReadFile reads an overlay file, else the base file.
func (o *Overlay) ReadFile(name string) ([]byte, error) {
	if f, ok := o.files[o.key(name)]; ok {
		return append([]byte(nil), f.content...), nil
	}
	return o.base.ReadFile(name)
}

// Stat stats an overlay file, else the base path, else an overlay-only directory.
func (o *Overlay) Stat(name string) (fs.FileInfo, error) {
	key := o.key(name)
	if f, ok := o.files[key]; ok {
		return memFileInfo{name: path.Base(key), size: int64(len(f.content))}, nil
	}
	info, err := o.base.Stat(name)
	if err != nil && len(o.children(key)) > 0 {
		return memFileInfo{name: path.Base(key), dir: true}, nil
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
// overlay files matching pattern, overlay matches in the base's path form.
func (o *Overlay) Glob(pattern string) ([]string, error) {
	out, err := o.base.Glob(pattern)
	if err != nil {
		return nil, err
	}
	pat := o.key(pattern)
	seen := make(map[string]struct{}, len(out))
	for _, p := range out {
		seen[normalize(p)] = struct{}{}
	}
	for key, f := range o.files {
		ok, err := path.Match(pat, key)
		if err != nil {
			return nil, err
		}
		if _, dup := seen[key]; ok && !dup {
			out = append(out, f.display)
			seen[key] = struct{}{}
		}
	}
	sort.Strings(out)
	return out, nil
}

// Abs resolves name against the base.
func (o *Overlay) Abs(name string) (string, error) { return o.base.Abs(name) }

// children returns the overlay entries directly under dir (a slash key), by name.
func (o *Overlay) children(dir string) map[string]fs.DirEntry {
	out := make(map[string]fs.DirEntry)
	for key, f := range o.files {
		name, isDir, ok := childOf(key, dir)
		if !ok {
			continue
		}
		if !isDir {
			out[name] = memDirEntry{name: name, size: int64(len(f.content))}
		} else if _, seen := out[name]; !seen {
			out[name] = memDirEntry{name: name, dir: true}
		}
	}
	return out
}

var _ FS = (*Overlay)(nil)
