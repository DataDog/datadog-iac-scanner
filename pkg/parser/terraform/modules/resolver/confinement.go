/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type resolvedPathCacheKey struct{}

// WithResolvedPathCache attaches a scan-scoped EvalSymlinks cache to ctx.
// Nested calls reuse the existing cache so graph walking and evaluation share hits.
func WithResolvedPathCache(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if resolvedPathCacheFrom(ctx) != nil {
		return ctx
	}
	return context.WithValue(ctx, resolvedPathCacheKey{}, &sync.Map{})
}

func resolvedPathCacheFrom(ctx context.Context) *sync.Map {
	if ctx == nil {
		return nil
	}
	cache, _ := ctx.Value(resolvedPathCacheKey{}).(*sync.Map)
	return cache
}

func evalSymlinksCached(ctx context.Context, path string) (string, error) {
	clean := filepath.Clean(path)
	if cache := resolvedPathCacheFrom(ctx); cache != nil {
		if v, ok := cache.Load(clean); ok {
			return v.(string), nil
		}
	}
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return "", err
	}
	if cache := resolvedPathCacheFrom(ctx); cache != nil {
		cache.Store(clean, resolved)
	}
	return resolved, nil
}

func ConfineResolution(ctx context.Context, res Resolution) (Resolution, error) {
	if res.LocalPath == "" {
		return Resolution{}, fmt.Errorf("resolved module has no local path")
	}
	if res.PackageRoot == "" {
		res.PackageRoot = res.LocalPath
	}
	root, err := resolveDirectory(ctx, res.PackageRoot)
	if err != nil {
		return Resolution{}, fmt.Errorf("resolving package root %q: %w", res.PackageRoot, err)
	}
	localPath, err := ResolvePathWithinRoot(ctx, root, res.LocalPath)
	if err != nil {
		return Resolution{}, fmt.Errorf("resolving module path %q: %w", res.LocalPath, err)
	}
	res.PackageRoot = filepath.Clean(res.PackageRoot)
	res.LocalPath = filepath.Clean(localPath)
	return res, nil
}

func ResolvePathWithinRoot(ctx context.Context, root, target string) (string, error) {
	resolvedRoot, err := evalSymlinksCached(ctx, root)
	if err != nil {
		return "", err
	}
	resolvedTarget, err := evalSymlinksCached(ctx, target)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(resolvedRoot, resolvedTarget)
	if err != nil || pathEscapesDir(rel) {
		return "", fmt.Errorf("resolved path %q escapes package root %q", resolvedTarget, resolvedRoot)
	}
	info, err := os.Stat(resolvedTarget)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("resolved path %q is not a directory", resolvedTarget)
	}
	return filepath.Clean(target), nil
}

func resolveDirectory(ctx context.Context, path string) (string, error) {
	resolved, err := evalSymlinksCached(ctx, path)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%q is not a directory", resolved)
	}
	return resolved, nil
}

func pathEscapesDir(rel string) bool {
	return rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

// ScannableTerraformPath reports whether a directory entry is a .tf file that can be read.
// Regular files are accepted. Symlinks are accepted only when their target is a regular
// file confined within packageRoot (or dir when packageRoot is empty).
func ScannableTerraformPath(ctx context.Context, entry fs.DirEntry, dir, packageRoot string) (path string, ok bool) {
	if entry.IsDir() {
		return "", false
	}
	name := entry.Name()
	if !strings.HasSuffix(strings.ToLower(name), ".tf") {
		return "", false
	}
	candidate := filepath.Join(dir, name)
	entryType := entry.Type()
	if entryType.IsRegular() {
		return candidate, true
	}
	if entryType&fs.ModeSymlink == 0 && entryType != 0 {
		return "", false
	}
	resolved, err := evalSymlinksCached(ctx, candidate)
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
	if _, err := ResolvePathWithinRoot(ctx, confineRoot, resolved); err != nil {
		return "", false
	}
	return candidate, true
}
