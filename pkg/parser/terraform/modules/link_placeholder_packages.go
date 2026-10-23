/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfmodules

import (
	"context"
	"path/filepath"
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
	path, err := filepath.Abs(path)
	if err != nil {
		return ""
	}
	packages, _ := ctx.Value(linkPlaceholderPackagesKey{}).([]string)
	var selected string
	for _, root := range packages {
		if len(root) <= len(selected) {
			continue
		}
		if _, err := pathWithinRoot(root, path); err == nil {
			selected = root
		}
	}
	return selected
}
