/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package vfs

import (
	"io/fs"
	"maps"
	"path"
	"path/filepath"
	"sort"
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
	mu                  sync.Mutex
	files               map[string][]byte
	directories         map[string][]fs.DirEntry
	missing             map[string]struct{}
	completeDirectories map[string]bool
	completeShared      bool
}

// DirectorySnapshot identifies directory trees supplied in full by the caller.
// Merely having some pushed descendants never establishes completeness.
type DirectorySnapshot interface {
	DirectoryComplete(name string) bool
}

// MarkDirectoryComplete declares that all files below name have been supplied.
func (m *MemFS) MarkDirectoryComplete(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.completeDirectories[normalize(name)] {
		return
	}
	if m.completeShared {
		m.completeDirectories = maps.Clone(m.completeDirectories)
		m.completeShared = false
	}
	if m.completeDirectories == nil {
		m.completeDirectories = make(map[string]bool)
	}
	m.completeDirectories[normalize(name)] = true
}

func (m *MemFS) DirectoryComplete(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.directoryComplete(normalize(name))
}

func (m *MemFS) directoryComplete(name string) bool {
	for {
		if m.completeDirectories[name] {
			return true
		}
		parent := normalize(filepath.Dir(name))
		if parent == name {
			return false
		}
		name = parent
	}
}

// Fork shares immutable pushed files while collecting requests independently.
// A compiler can publish its requests only after its invocation is retained.
func (m *MemFS) Fork() *MemFS {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.completeShared = true
	return &MemFS{
		files: m.files, directories: m.directories, missing: make(map[string]struct{}),
		completeDirectories: m.completeDirectories, completeShared: true,
	}
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
	m.directories = indexDirectories(m.files)
	return m
}

// Build once per snapshot, in work proportional to path components. Forks
// share this immutable index; wildcard walks visit only returned children.
func indexDirectories(files map[string][]byte) map[string][]fs.DirEntry {
	children := make(map[string]map[string]memDirEntry)
	for name, content := range files {
		entry := memDirEntry{name: filepath.Base(name), size: int64(len(content))}
		for {
			directory := normalize(filepath.Dir(name))
			if directory == name {
				break
			}
			if children[directory] == nil {
				children[directory] = make(map[string]memDirEntry)
			}
			if previous, exists := children[directory][entry.name]; !exists || previous.dir {
				children[directory][entry.name] = entry
			}
			name = directory
			entry = memDirEntry{name: filepath.Base(name), dir: true}
		}
	}
	index := make(map[string][]fs.DirEntry, len(children))
	for directory, entries := range children {
		listing := make([]fs.DirEntry, 0, len(entries))
		for _, entry := range entries {
			listing = append(listing, entry)
		}
		sort.Slice(listing, func(i, j int) bool { return listing[i].Name() < listing[j].Name() })
		index[directory] = listing
	}
	return index
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
	if !m.directoryComplete(normalize(filepath.Dir(key))) {
		m.missing[key] = struct{}{}
	}
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

// DirInfo returns the info of a directory synthesized from the pushed file
// keys: one exists when a pushed file lives under name. A miss is not recorded.
func (m *MemFS) DirInfo(name string) (fs.FileInfo, bool) {
	dir := normalize(name)
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.directories[dir]; exists {
		return memFileInfo{name: path.Base(dir), dir: true}, true
	}
	return nil, false
}

// ReadDir returns the immediate children of a directory synthesized from the
// pushed file keys. A miss (no file lives under the directory) is recorded: an
// absent directory is the primary escalation signal (a Terraform module whose
// source directory was not pushed).
func (m *MemFS) ReadDir(name string) ([]fs.DirEntry, error) {
	dir := normalize(name)
	m.mu.Lock()
	defer m.mu.Unlock()

	entries, exists := m.directories[dir]
	if !exists {
		if !m.directoryComplete(dir) {
			m.missing[dir] = struct{}{}
		}
		return nil, notExist("readdir", name)
	}
	return append([]fs.DirEntry(nil), entries...), nil
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

// MissingRecorder is an FS that collects escalation requests for paths the scan
// needed but was not given. MemFS is one; the real disk is not.
type MissingRecorder interface {
	RecordMissing(name string)
}

// RecordMissing adds path to the missing set. Read misses record themselves;
// this is for escalation signals that cannot be expressed as a plain read miss
// (a Helm chart that failed to render from pushed content).
func (m *MemFS) RecordMissing(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.missing[normalize(name)] = struct{}{}
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
