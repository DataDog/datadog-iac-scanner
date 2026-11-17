/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
)

// terraformSourceFS serves scanned configuration and variable files with
// nonempty source snapshots held by FileMetadata. Empty snapshots are
// indistinguishable from metadata that has no source content, so those paths
// pass through to the wrapped filesystem along with other unscanned paths.
type terraformSourceFS struct {
	vfs.FS
	unwrap  vfs.FS
	content map[string]string
	dirs    map[string]*terraformSourceDir
}

// Directory snapshots are limited to disk directories with captured sources.
// Other directories may be materialized by a resolver during evaluation.
type terraformSourceDir struct {
	mu      sync.Mutex
	entries []fs.DirEntry
	loaded  bool
}

var _ vfs.Wrapper = (*terraformSourceFS)(nil)

func (s *terraformSourceFS) Unwrap() vfs.FS { return s.unwrap }

func (s *terraformSourceFS) key(name string) string {
	if abs, err := s.Abs(name); err == nil {
		name = abs
	}
	return filepath.Clean(name)
}

func (s *terraformSourceFS) ReadFile(name string) ([]byte, error) {
	if content, ok := s.content[s.key(name)]; ok {
		return []byte(content), nil
	}
	return s.FS.ReadFile(name)
}

func (s *terraformSourceFS) Stat(name string) (fs.FileInfo, error) {
	if content, ok := s.content[s.key(name)]; ok {
		return planFileInfo{name: filepath.Base(name), size: int64(len(content))}, nil
	}
	return s.FS.Stat(name)
}

// ReadDir reuses successful listings of captured source directories. Return a
// fresh slice because callers filter directory entries in place.
func (s *terraformSourceFS) ReadDir(name string) ([]fs.DirEntry, error) {
	dir := s.dirs[s.key(name)]
	if dir == nil {
		return s.FS.ReadDir(name)
	}
	dir.mu.Lock()
	defer dir.mu.Unlock()
	if !dir.loaded {
		entries, err := s.FS.ReadDir(name)
		if err != nil {
			return entries, err
		}
		dir.entries, dir.loaded = entries, true
	}
	return slices.Clone(dir.entries), nil
}

// withScannedTerraform serves scanned Terraform config and tfvars files with
// nonempty OriginalData, while retaining the existing disk-first overlay for plans.
func (c *Inspector) withScannedTerraform(files model.FileMetadatas, plans []string) vfs.FS {
	content := make(map[string]string)
	for _, f := range files {
		if f == nil || f.ModuleCallChain != "" || f.OriginalData == "" || !scannedTerraformSource(f) {
			continue
		}
		path, err := c.fsys.Abs(f.FilePath)
		if err != nil {
			continue
		}
		content[filepath.Clean(path)] = f.OriginalData
	}
	dirs := make(map[string]*terraformSourceDir)
	if vfs.IsDisk(c.fsys) {
		for path := range content {
			dirs[filepath.Dir(path)] = &terraformSourceDir{}
		}
	}
	return &terraformSourceFS{
		FS:      c.withScannedPlans(files, plans),
		unwrap:  c.fsys,
		content: content,
		dirs:    dirs,
	}
}

func scannedTerraformSource(f *model.FileMetadata) bool {
	if f.Kind != model.KindTerraform {
		return false
	}
	if isTerraformConfigFile(f) {
		return true
	}
	path := strings.ToLower(f.FilePath)
	return strings.HasSuffix(path, tfpath.ExtTFVars) || tfpath.IsTFVarsJSON(path)
}
