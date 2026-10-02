/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfmodules

import (
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
)

// StripGetterPrefix removes go-getter scheme prefixes so the source can be
// treated as a path. Compound prefixes like "git::file://./path" are fully
// stripped in two passes.
func StripGetterPrefix(source string) string {
	source = strings.TrimSpace(source)
	for _, scheme := range []string{"git::", "hg::", "http::", "https::"} {
		if after, ok := strings.CutPrefix(source, scheme); ok {
			source = after
			break
		}
	}
	return strings.TrimPrefix(source, "file://")
}

// environmentsDir is the directory whose per-environment subdirectories build
// systems merge into the parent module before running Terraform.
const environmentsDir = "environments"

// ResolveLocalModuleDir resolves a local module source (without go-getter
// prefixes) against callerDir the way Terraform does. When that directory does
// not exist, it tries the layouts build systems produce by assembling a module
// from several directories, and returns the first that exists:
//   - callerDir is <module>/environments/<name>, whose files are merged into
//     <module>, so a relative source is relative to <module>;
//   - an absolute source points into a build container where the repository is
//     mounted elsewhere (e.g. /cnab/app/terraform/<repo path>), so its longest
//     suffix of at least two segments that exists under an ancestor of
//     callerDir is used.
//
// The Terraform resolution is returned when no fallback exists, so errors
// still name the path Terraform would use.
func ResolveLocalModuleDir(fsys vfs.FS, callerDir, source string) string {
	resolved := filepath.Clean(source)
	if !filepath.IsAbs(source) {
		resolved = filepath.Join(callerDir, source)
	}
	if fsys == nil || isDir(fsys, resolved) {
		return resolved
	}
	if !filepath.IsAbs(source) {
		if parent := filepath.Dir(callerDir); filepath.Base(parent) == environmentsDir {
			if merged := filepath.Join(filepath.Dir(parent), source); isDir(fsys, merged) {
				return merged
			}
		}
		return resolved
	}
	if mounted, ok := repoPathOfAbsSource(fsys, callerDir, resolved); ok {
		return mounted
	}
	return resolved
}

func repoPathOfAbsSource(fsys vfs.FS, callerDir, source string) (string, bool) {
	parts := strings.Split(strings.Trim(filepath.ToSlash(source), "/"), "/")
	for i := 0; i <= len(parts)-2; i++ {
		suffix := filepath.FromSlash(strings.Join(parts[i:], "/"))
		for dir := callerDir; ; {
			if candidate := filepath.Join(dir, suffix); isDir(fsys, candidate) {
				return candidate, true
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	return "", false
}

func isDir(fsys vfs.FS, path string) bool {
	info, err := fsys.Stat(path)
	return err == nil && info.IsDir()
}
