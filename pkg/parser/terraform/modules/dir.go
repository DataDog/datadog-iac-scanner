/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfmodules

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/DataDog/datadog-iac-scanner/internal/pathutil"
	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
)

// ConfigEntries returns non-directory entries matching pred.
// pred is typically tfpath.IsHCLConfig or tfpath.IsConfig.
func ConfigEntries(entries []fs.DirEntry, pred func(string) bool) []fs.DirEntry {
	names := make([]string, 0, len(entries))
	byName := make(map[string]fs.DirEntry, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		names = append(names, name)
		byName[name] = entry
	}
	selected := tfpath.Matching(names, pred)
	out := make([]fs.DirEntry, 0, len(selected))
	for _, name := range selected {
		out = append(out, byName[name])
	}
	return out
}

func mergeAllowed(allow map[string]struct{}, dir, name string) bool {
	if allow == nil {
		return true
	}
	joined := filepath.Join(dir, name)
	if _, ok := allow[filepath.ToSlash(joined)]; ok {
		return true
	}
	_, ok := allow[filepath.ToSlash(filepath.Clean(joined))]
	return ok
}

// SelectHCLConfigNames returns HCL config basenames from entries, optionally
// limited to allow and then OpenTofu-shadowed within that set. keep, when set,
// is never dropped from a scan-set merge.
func SelectHCLConfigNames(entries []fs.DirEntry, dir string, allow map[string]struct{}, keep string) []string {
	return selectConfigNames(entries, dir, allow, keep, tfpath.IsHCLConfig)
}

// SelectConfigNames is SelectHCLConfigNames plus JSON config files.
func SelectConfigNames(entries []fs.DirEntry, dir string, allow map[string]struct{}, keep string) []string {
	return selectConfigNames(entries, dir, allow, keep, tfpath.IsConfig)
}

func selectConfigNames(
	entries []fs.DirEntry, dir string, allow map[string]struct{}, keep string, pred func(string) bool,
) []string {
	all := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			all = append(all, entry.Name())
		}
	}
	var preferTofu func(string) bool
	if allow != nil {
		hasAllowed := false
		for _, name := range all {
			if mergeAllowed(allow, dir, name) {
				hasAllowed = true
				break
			}
		}
		if hasAllowed {
			preferTofu = func(name string) bool {
				return mergeAllowed(allow, dir, name)
			}
		}
	}
	if keep != "" {
		return tfpath.SelectKeepingWithTofuPrecedence(
			all, pred, filepath.Base(keep), preferTofu,
		)
	}
	return tfpath.SelectWithTofuPrecedence(all, pred, preferTofu)
}

// ConfinedFilePath reports whether a directory entry is a regular file the
// Terraform parser can scan. Regular files are accepted. Symlinks are accepted
// only when their target is a regular file confined within packageRoot (or dir
// when packageRoot is empty).
func ConfinedFilePath(ctx context.Context, entry fs.DirEntry, dir, packageRoot string) (string, bool) {
	if entry.IsDir() {
		return "", false
	}
	candidate := filepath.Join(dir, entry.Name())
	entryType := entry.Type()
	if entryType.IsRegular() {
		return candidate, true
	}
	if entryType&fs.ModeSymlink == 0 && entryType != 0 {
		return "", false
	}
	resolved, err := pathutil.EvalSymlinksCached(ctx, candidate)
	if err != nil {
		return "", false
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() {
		return "", false
	}
	confineRoot := packageRoot
	if confineRoot == "" {
		confineRoot = dir
	}
	resolvedRoot, err := pathutil.EvalSymlinksCached(ctx, confineRoot)
	if err != nil {
		return "", false
	}
	resolvedTarget, err := pathutil.EvalSymlinksCached(ctx, resolved)
	if err != nil {
		return "", false
	}
	rel, err := filepath.Rel(resolvedRoot, resolvedTarget)
	if err != nil || pathutil.PathEscapesDir(rel) {
		return "", false
	}
	return candidate, true
}
