/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/functions"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
)

// copyFS shows a module directory as Terragrunt's working copy does: the files
// the unit copies (its directory's, filtered) replace those of the module.
type copyFS struct {
	vfs.FS
	scan      *functions.ScanFS
	moduleDir string
	unit      *unitFiles
}

func newCopyFS(scan *functions.ScanFS, moduleDir string, unit *unitFiles) *copyFS {
	return &copyFS{FS: scan, scan: scan, moduleDir: filepath.Clean(moduleDir), unit: unit}
}

// Unwrap returns the base filesystem, so type checks see through the copy.
func (c *copyFS) Unwrap() vfs.FS { return c.scan }

// EvalSymlinks resolves symlinks as the base does.
func (c *copyFS) EvalSymlinks(path string) (string, error) { return c.scan.EvalSymlinks(path) }

// rel returns name relative to the module directory ("." for itself), if inside.
func (c *copyFS) rel(name string) (string, bool) {
	r, err := filepath.Rel(c.moduleDir, filepath.Clean(name))
	if err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		return "", false
	}
	return r, true
}

// unitPath is the copy of name in the unit directory, when there is one.
func (c *copyFS) unitPath(name string) (string, bool) {
	r, ok := c.rel(name)
	if !ok || r == "." || !c.unit.filter.Copies(filepath.ToSlash(r)) {
		return "", false
	}
	p, err := functions.ConfinePath(c.unit.dir, c.scan, r)
	if err != nil {
		return "", false
	}
	if _, err := c.scan.Stat(p); err != nil {
		return "", false
	}
	return p, true
}

func (c *copyFS) ReadFile(name string) ([]byte, error) {
	if p, ok := c.unitPath(name); ok {
		return c.scan.ReadFile(p)
	}
	return c.scan.ReadFile(name)
}

func (c *copyFS) Stat(name string) (fs.FileInfo, error) {
	if p, ok := c.unitPath(name); ok {
		return c.scan.Stat(p)
	}
	return c.scan.Stat(name)
}

// ReadDir lists the module's entries and the unit's copied ones.
func (c *copyFS) ReadDir(name string) ([]fs.DirEntry, error) {
	entries, err := c.scan.ReadDir(name)
	r, inside := c.rel(name)
	if !inside {
		return entries, err
	}
	dir, cerr := functions.ConfinePath(c.unit.dir, c.scan, r)
	if cerr != nil {
		return entries, err
	}
	unitEntries, uerr := c.scan.ReadDir(dir)
	if uerr != nil {
		return entries, err
	}
	byName := make(map[string]fs.DirEntry, len(entries))
	for _, e := range entries {
		byName[e.Name()] = e
	}
	for _, e := range unitEntries {
		entryRel := filepath.ToSlash(filepath.Join(r, e.Name()))
		if e.IsDir() && c.unit.filter.Traverses(entryRel) || !e.IsDir() && c.unit.filter.Copies(entryRel) {
			byName[e.Name()] = e
		}
	}
	merged := make([]fs.DirEntry, 0, len(byName))
	for _, e := range byName {
		merged = append(merged, e)
	}
	sort.Slice(merged, func(i, j int) bool { return merged[i].Name() < merged[j].Name() })
	return merged, nil
}
