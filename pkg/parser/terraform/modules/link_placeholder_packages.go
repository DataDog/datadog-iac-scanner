/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfmodules

import (
	"context"
	"path/filepath"

	"github.com/DataDog/datadog-iac-scanner/internal/pathutil"
)

type linkPlaceholderPackagesKey struct{}

// WithLinkPlaceholderPackages registers verified downloaded package boundaries
// for readers that do not carry an explicit package root. The stored roots are
// copied so concurrent readers do not depend on the caller's slice.
func WithLinkPlaceholderPackages(ctx context.Context, roots []string) context.Context {
	packages := make([]string, 0, len(roots))
	seen := make(map[string]bool, len(roots))
	for _, root := range roots {
		if root == "" {
			continue
		}
		root, err := filepath.Abs(root)
		if err != nil || seen[root] {
			continue
		}
		seen[root] = true
		packages = append(packages, root)
	}
	return context.WithValue(ctx, linkPlaceholderPackagesKey{}, packages)
}

// linkPlaceholderPackageRoot selects the narrowest registered boundary. It
// never infers a package from an arbitrary ancestor outside the repository.
func linkPlaceholderPackageRoot(ctx context.Context, path string) string {
	packages, _ := ctx.Value(linkPlaceholderPackagesKey{}).([]string)
	if len(packages) == 0 {
		return ""
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return ""
	}
	var selected string
	for _, root := range packages {
		if len(root) <= len(selected) {
			continue
		}
		if packageContainsPath(root, path) {
			selected = root
		}
	}
	resolvedPath := canonicalPackagePath(ctx, path)
	if resolvedPath == "" {
		return selected
	}
	var resolvedSelected string
	if selected != "" {
		resolvedSelected, err = pathutil.EvalSymlinksCached(ctx, selected)
		if err != nil {
			return selected
		}
	}
	for _, root := range packages {
		resolvedRoot, resolveErr := pathutil.EvalSymlinksCached(ctx, root)
		if resolveErr != nil || !packageContainsPath(resolvedRoot, resolvedPath) {
			continue
		}
		// Keep an existing lexical boundary when a native alias leaves it.
		// A canonical match can only select a narrower boundary inside it.
		if resolvedSelected == "" || (resolvedRoot != resolvedSelected && packageContainsPath(resolvedSelected, resolvedRoot)) {
			selected, resolvedSelected = root, resolvedRoot
		}
	}
	return selected
}

func packageContainsPath(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && !pathutil.PathEscapesDir(rel)
}

// A logical module path can contain a placeholder directory that the OS cannot
// traverse yet. Resolve its closest existing ancestor to identify its package.
func canonicalPackagePath(ctx context.Context, path string) string {
	for ancestor := path; ; ancestor = filepath.Dir(ancestor) {
		if resolved, err := pathutil.EvalSymlinksCached(ctx, ancestor); err == nil {
			rel, err := filepath.Rel(ancestor, path)
			if err != nil {
				return ""
			}
			return filepath.Join(resolved, rel)
		}
		if filepath.Dir(ancestor) == ancestor {
			return ""
		}
	}
}
