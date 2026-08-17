/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package vfs

import (
	"io/fs"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	memDirMode  fs.FileMode = fs.ModeDir | 0o555
	memFileMode fs.FileMode = 0o444
)

// MemFS is an in-memory FS built from content pushed over HTTP. Keys are
// normalized (cleaned, forward-slash) paths. It is request-scoped: a fresh
// instance is built per analyze request, so the missing-file set it accumulates
// belongs to exactly one scan and never leaks across requests.
//
// Concurrency: Terraform module enrichment runs reader goroutines, so all access
// is guarded by a mutex.
type MemFS struct {
	mu      sync.Mutex
	files   map[string][]byte
	missing map[string]struct{}
}

// NewMemFS builds a MemFS from a path -> content map. Keys are normalized so
// they match the paths the Terraform readers compute via filepath.Join/Dir.
func NewMemFS(files map[string][]byte) *MemFS {
	m := &MemFS{
		files:   make(map[string][]byte, len(files)),
		missing: make(map[string]struct{}),
	}
	for p, c := range files {
		m.files[normalize(p)] = c
	}
	return m
}

// normalize makes a path comparable: OS-cleaned then forward-slashed, mirroring
// how FileSystemSourceProvider normalizes the paths it emits.
func normalize(p string) string {
	return filepath.ToSlash(filepath.Clean(p))
}

func notExist(op, name string) error {
	return &fs.PathError{Op: op, Path: name, Err: syscall.ENOENT}
}

// ReadFile returns a copy of the named file's content, or fs.ErrNotExist if it
// was not pushed (recording the miss for the escalation list).
func (m *MemFS) ReadFile(name string) ([]byte, error) {
	key := normalize(name)
	m.mu.Lock()
	defer m.mu.Unlock()
	if content, ok := m.files[key]; ok {
		out := make([]byte, len(content))
		copy(out, content)
		return out, nil
	}
	m.missing[key] = struct{}{}
	return nil, notExist("open", name)
}

// Stat reports whether the named file was pushed. A miss is NOT recorded: Stat
// is only used for speculative existence probes (terraform.tfvars, an optional
// vars file), so recording it would produce false escalations for files that
// legitimately do not exist.
func (m *MemFS) Stat(name string) (fs.FileInfo, error) {
	key := normalize(name)
	m.mu.Lock()
	defer m.mu.Unlock()
	if content, ok := m.files[key]; ok {
		return memFileInfo{name: path.Base(key), size: int64(len(content))}, nil
	}
	return nil, notExist("stat", name)
}

// ReadDir returns the immediate children of a directory synthesized from the
// pushed file keys. A miss (no file lives under the directory) is recorded: an
// absent directory is the primary escalation signal (a Terraform module whose
// source directory was not pushed).
func (m *MemFS) ReadDir(name string) ([]fs.DirEntry, error) {
	dir := normalize(name)
	m.mu.Lock()
	defer m.mu.Unlock()

	type childInfo struct {
		isDir bool
		size  int64
	}
	children := make(map[string]childInfo)
	for p, content := range m.files {
		var rel string
		if dir == "." {
			rel = p
		} else if r, ok := underDir(p, dir); ok {
			rel = r
		} else {
			continue
		}
		if rel == "" {
			continue
		}
		if seg, _, found := strings.Cut(rel, "/"); found {
			// A descendant: its first path segment is an immediate subdirectory.
			// An absolute key under dir "." has an empty first segment ("" for
			// "/ws/main.tf"), which names no directory — skip it rather than
			// synthesizing an entry called "".
			if seg == "" {
				continue
			}
			if _, ok := children[seg]; !ok {
				children[seg] = childInfo{isDir: true}
			}
			continue
		}
		children[rel] = childInfo{size: int64(len(content))}
	}

	if len(children) == 0 {
		m.missing[dir] = struct{}{}
		return nil, notExist("readdir", name)
	}
	names := make([]string, 0, len(children))
	for n := range children {
		names = append(names, n)
	}
	sort.Strings(names)
	entries := make([]fs.DirEntry, 0, len(names))
	for _, n := range names {
		ci := children[n]
		entries = append(entries, memDirEntry{name: n, dir: ci.isDir, size: ci.size})
	}
	return entries, nil
}

// Glob returns pushed paths matching pattern (filepath.Glob semantics over the
// single directory level the Terraform readers use, e.g. "<dir>/*.tf"). A
// non-match is never recorded — an empty glob is legal, exactly as on disk.
func (m *MemFS) Glob(pattern string) ([]string, error) {
	pat := filepath.ToSlash(pattern)
	if _, err := path.Match(pat, ""); err != nil {
		return nil, err
	}
	dir, base := path.Split(pat)
	cleanDir := path.Clean(dir)

	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for p := range m.files {
		pdir, pbase := path.Split(p)
		if path.Clean(pdir) != cleanDir {
			continue
		}
		if ok, _ := path.Match(base, pbase); ok {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out, nil
}

// Abs normalizes rather than resolving against the process working directory,
// so a path keeps the shape it was pushed with. Relative paths stay relative to
// the request's own workspace, which is what makes Terraform module and
// missing-file paths correct even when a single server process serves many IDE
// workspaces; absolute paths (a file outside every workspace folder) stay
// absolute, which is self-disambiguating.
func (m *MemFS) Abs(name string) (string, error) {
	return normalize(name), nil
}

// Paths returns the sorted set of pushed file paths (used to seed the scan's
// file set in server mode).
func (m *MemFS) Paths() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.files))
	for p := range m.files {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// MissingFiles returns the sorted set of paths the scan referenced but that were
// not pushed — the escalation list returned to the IDE.
func (m *MemFS) MissingFiles() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.missing))
	for p := range m.missing {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// underDir returns the path of p relative to dir if p is a strict descendant of
// dir (a non-empty remainder after the "dir/" prefix). dir may already end in
// "/" (e.g. the root "/" or a Windows drive root "C:/"); avoid doubling the
// separator in that case, since "dir/" + "/" matches no key.
func underDir(p, dir string) (string, bool) {
	prefix := dir + "/"
	if strings.HasSuffix(dir, "/") {
		prefix = dir
	}
	if after, ok := strings.CutPrefix(p, prefix); ok && after != "" {
		return after, true
	}
	return "", false
}

// memFileInfo is a minimal fs.FileInfo for in-memory entries.
type memFileInfo struct {
	name string
	size int64
	dir  bool
}

func (fi memFileInfo) Name() string { return fi.name }
func (fi memFileInfo) Size() int64  { return fi.size }
func (fi memFileInfo) Mode() fs.FileMode {
	if fi.dir {
		return memDirMode
	}
	return memFileMode
}
func (fi memFileInfo) ModTime() time.Time { return time.Time{} }
func (fi memFileInfo) IsDir() bool        { return fi.dir }
func (fi memFileInfo) Sys() any           { return nil }

// memDirEntry is a minimal fs.DirEntry for in-memory directory listings.
type memDirEntry struct {
	name string
	size int64
	dir  bool
}

func (de memDirEntry) Name() string { return de.name }
func (de memDirEntry) IsDir() bool  { return de.dir }
func (de memDirEntry) Type() fs.FileMode {
	if de.dir {
		return fs.ModeDir
	}
	return 0
}
func (de memDirEntry) Info() (fs.FileInfo, error) {
	return memFileInfo(de), nil
}

var _ FS = (*MemFS)(nil)
