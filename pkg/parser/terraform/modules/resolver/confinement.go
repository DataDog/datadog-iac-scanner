/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/DataDog/datadog-iac-scanner/internal/pathutil"
)

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
	resolvedRoot, err := pathutil.EvalSymlinksCached(ctx, root)
	if err != nil {
		return "", err
	}
	resolvedTarget, err := pathutil.EvalSymlinksCached(ctx, target)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(resolvedRoot, resolvedTarget)
	if err != nil || pathutil.PathEscapesDir(rel) {
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
	resolved, err := pathutil.EvalSymlinksCached(ctx, path)
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
