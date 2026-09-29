/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"context"
	"fmt"
	"path"
	"path/filepath"
	"sort"
	"strings"

	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
)

// ModuleConfigReader returns the Terraform configuration files, native or JSON,
// directly inside each package-relative directory of dirs, keyed by directory
// and file name. Missing directories are left out.
type ModuleConfigReader func(ctx context.Context, dirs []string) (map[string]map[string][]byte, error)

// LocalModuleClosure returns subdir followed by every package-relative
// directory reachable from it through literal local module sources: the
// directories a package must hold, each with its subtree, for the module at
// subdir to load. It is the closure BareGitResolver materializes for a git
// module. Paths use forward slashes and "." is the package root.
func LocalModuleClosure(ctx context.Context, subdir string, read ModuleConfigReader) ([]string, error) {
	start := path.Clean(filepath.ToSlash(strings.TrimSpace(subdir)))
	if !filepath.IsLocal(filepath.FromSlash(start)) {
		return nil, fmt.Errorf("module subdirectory %q is not a local path", subdir)
	}
	visited := map[string]bool{start: true}
	closure := []string{start}
	frontier := []string{start}
	for len(frontier) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		configs, err := read(ctx, frontier)
		if err != nil {
			return nil, err
		}
		var next []string
		for _, dir := range frontier {
			files := configs[dir]
			names := make([]string, 0, len(files))
			for name := range files {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range tfpath.Select(names, tfpath.IsConfig) {
				for _, source := range configModuleSources(files[name], path.Join(dir, name)) {
					child, ok := packageRelativeModuleDir(dir, source)
					if !ok || visited[child] {
						continue
					}
					visited[child] = true
					closure = append(closure, child)
					next = append(next, child)
				}
			}
		}
		frontier = next
	}
	return closure, nil
}

// packageRelativeModuleDir mirrors localArchiveSubdir on package-relative
// slash paths: a local source that leaves the package, or names its root,
// cannot be materialized from one subtree.
func packageRelativeModuleDir(dir, source string) (string, bool) {
	if !tfmodules.LooksLikeLocalModuleSource(source) ||
		path.IsAbs(filepath.ToSlash(source)) || filepath.IsAbs(source) || strings.HasPrefix(source, "file://") {
		return "", false
	}
	child := path.Clean(path.Join(dir, filepath.ToSlash(source)))
	if child == "." || child == ".." || strings.HasPrefix(child, "../") {
		return "", false
	}
	return child, true
}
