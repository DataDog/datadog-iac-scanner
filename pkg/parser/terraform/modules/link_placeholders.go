/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfmodules

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/internal/pathutil"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
)

const (
	maxLinkPlaceholderBytes = 4096
	maxLinkPlaceholderHops  = 40
)

// ErrSkippedLinkPlaceholder identifies an unsafe or unavailable checkout symlink.
// Callers skip these at debug level, rather than reporting an invalid config.
var ErrSkippedLinkPlaceholder = errors.New("skipped Terraform symlink placeholder")

type linkPlaceholderRootKey struct{}

// WithLinkPlaceholderRoot supplies the scan's repository boundary when its
// checkout has no .git entry. Downloaded modules can override it with their
// package boundary. An empty root leaves an existing boundary unchanged.
func WithLinkPlaceholderRoot(ctx context.Context, root string) context.Context {
	if root == "" {
		return ctx
	}
	return context.WithValue(ctx, linkPlaceholderRootKey{}, root)
}

// placeholderTarget deliberately recognizes a narrow subset of Git symlink
// blobs: one unquoted path, with at most a final line ending. Config links need
// a path separator or a Terraform suffix; a bare identifier, number, JSON string,
// HCL assignment, comment or block is never a config link.
// Directory links can name a single directory because a file cannot otherwise
// serve as a module directory. No Git metadata is required or modified.
func placeholderTarget(data []byte, directory bool) (string, bool) {
	if !placeholderCandidate(data) {
		return "", false
	}
	target := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	if target == "" || strings.HasPrefix(target, "//") {
		return "", false
	}
	// Strip a native Windows volume only for validation; path resolution still
	// checks the full path against the root, including its volume.
	portable := filepath.ToSlash(strings.TrimPrefix(target, filepath.VolumeName(target)))
	for _, char := range portable {
		if !placeholderPathChar(char) {
			return "", false
		}
	}
	if !directory && !strings.ContainsRune(portable, '/') &&
		!tfpath.IsConfig(target) && !strings.HasSuffix(target, ".tfvars") && !tfpath.IsTFVarsJSON(target) {
		return "", false
	}
	return filepath.FromSlash(target), true
}

// Reject ordinary configuration before allocating its string representation.
// The final platform-aware validation above still decides whether it is a link.
func placeholderCandidate(data []byte) bool {
	if len(data) == 0 || len(data) > maxLinkPlaceholderBytes {
		return false
	}
	if data[len(data)-1] == '\n' {
		data = data[:len(data)-1]
	}
	if len(data) > 0 && data[len(data)-1] == '\r' {
		data = data[:len(data)-1]
	}
	// Native Windows volumes can contain characters that are invalid in the
	// remaining path. Leave those to the platform-aware validation above.
	nativeVolume := len(data) > 0 && (data[0] == '\\' || (len(data) > 1 && data[1] == ':'))
	if !nativeVolume {
		for _, char := range data {
			if !placeholderPathChar(rune(char)) && char != '\\' {
				return false
			}
		}
	}
	return true
}

func placeholderPathChar(char rune) bool {
	return (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') ||
		strings.ContainsRune("/._-", char)
}

func placeholderRoot(ctx context.Context, fsys vfs.FS, dir, packageRoot string) string {
	if packageRoot != "" {
		return packageRoot
	}
	if root := linkPlaceholderPackageRoot(ctx, dir); root != "" {
		return root
	}
	if root, _ := ctx.Value(linkPlaceholderRootKey{}).(string); root != "" {
		return root
	}
	if root, ok := vfs.RepositoryRoot(fsys, dir); ok {
		return root
	}
	// Without a repository boundary, only resolve inside the containing module.
	return dir
}

func pathWithinRoot(root, path string) (string, error) {
	rel, err := filepath.Rel(root, path)
	if err != nil || pathutil.PathEscapesDir(rel) {
		return "", fmt.Errorf("path %q escapes root %q", path, root)
	}
	return rel, nil
}

// resolvePlaceholderPath walks components so a placeholder can stand for a
// directory anywhere in a module path. Real symlinks are evaluated by the same
// scan-scoped cache used for native symlink confinement. Every hop is confined
// before reading it; the hop cap also bounds cycles mixing both link types.
func resolvePlaceholderPath(
	ctx context.Context, root, path string, directory bool, materialize func(context.Context, string) error,
) (resolved string, linked bool, err error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", false, err
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", false, err
	}
	rel, err := pathWithinRoot(absRoot, absPath)
	resolvedRoot, resolveErr := pathutil.EvalSymlinksCached(ctx, absRoot)
	if resolveErr != nil {
		return "", false, resolveErr
	}
	if err != nil {
		absRoot, rel, err = aliasedPlaceholderRoot(ctx, resolvedRoot, absPath)
		if err != nil {
			return "", false, err
		}
	}
	current := filepath.Join(resolvedRoot, rel)
	for range maxLinkPlaceholderHops {
		if err := ctx.Err(); err != nil {
			return "", linked, err
		}
		var followed bool
		current, followed, err = walkPlaceholderPath(ctx, resolvedRoot, current, directory, materialize)
		linked = linked || followed
		if err != nil {
			return "", linked, err
		}
		if !followed {
			rel, err = pathWithinRoot(resolvedRoot, current)
			if err != nil {
				return "", linked, err
			}
			// Keep the inventory's checkout spelling (e.g. /var on macOS)
			// after checking confinement against the canonical root.
			return filepath.Join(absRoot, rel), linked, nil
		}
	}
	return "", linked, fmt.Errorf("too many symlink placeholders in %q", path)
}

// aliasedPlaceholderRoot accepts a different spelling of the checkout root
// only after an existing ancestor resolves to the same directory. Resolving
// ancestors also works when path contains a placeholder directory that the OS
// cannot traverse. The usual, lexically confined path avoids this extra walk.
func aliasedPlaceholderRoot(ctx context.Context, resolvedRoot, path string) (aliasRoot, rel string, err error) {
	for dir := path; ; dir = filepath.Dir(dir) {
		resolvedDir, err := pathutil.EvalSymlinksCached(ctx, dir)
		if err == nil {
			if rel, relErr := filepath.Rel(resolvedRoot, resolvedDir); relErr == nil && rel == "." {
				rel, relErr = pathWithinRoot(dir, path)
				return dir, rel, relErr
			}
		}
		if filepath.Dir(dir) == dir {
			return "", "", fmt.Errorf("path %q escapes root %q", path, resolvedRoot)
		}
	}
}

// walkPlaceholderPath returns either the first placeholder's target (with the
// remaining components appended), or the fully resolved path when none remain.
func walkPlaceholderPath(
	ctx context.Context, root, path string, directory bool, materialize func(context.Context, string) error,
) (resolved string, followed bool, err error) {
	rel, err := pathWithinRoot(root, path)
	if err != nil {
		// An absolute target can use the checkout's native alias too. Verify
		// that alias before walking its components under the canonical root.
		_, rel, err = aliasedPlaceholderRoot(ctx, root, path)
		if err != nil {
			return "", false, err
		}
	}
	parts := strings.Split(rel, string(os.PathSeparator))
	current := root
	for i, part := range parts {
		candidate := filepath.Join(current, part)
		current, err = resolvePlaceholderComponent(ctx, candidate, materialize)
		if err != nil {
			return "", false, err
		}
		if _, err = pathWithinRoot(root, current); err != nil {
			return "", false, err
		}
		info, statErr := os.Stat(current)
		if statErr != nil {
			return "", false, statErr
		}
		wantDir := directory || i < len(parts)-1
		if info.IsDir() && wantDir {
			continue
		}
		data, readErr := readLinkPlaceholder(current, info)
		if readErr != nil {
			return "", false, readErr
		}
		if target, ok := placeholderTarget(data, wantDir); ok {
			next := target
			if !filepath.IsAbs(target) {
				next = filepath.Join(filepath.Dir(current), target)
			}
			return filepath.Join(append([]string{next}, parts[i+1:]...)...), true, nil
		}
		if wantDir || !info.Mode().IsRegular() {
			return "", false, fmt.Errorf("unexpected file type at %q", current)
		}
	}
	return current, false, nil
}

func resolvePlaceholderComponent(ctx context.Context, path string, materialize func(context.Context, string) error) (string, error) {
	resolved, err := pathutil.EvalSymlinksCached(ctx, path)
	if !errors.Is(err, os.ErrNotExist) || materialize == nil {
		return resolved, err
	}
	// The preceding component has already been resolved and confined. Sparse
	// packages may acquire this missing component before walking continues.
	if err := materialize(ctx, path); err != nil {
		return "", err
	}
	return pathutil.EvalSymlinksCached(ctx, path)
}

func readLinkPlaceholder(path string, info os.FileInfo) ([]byte, error) {
	if !info.Mode().IsRegular() || info.Size() > maxLinkPlaceholderBytes {
		return nil, nil
	}
	file, err := os.Open(filepath.Clean(path)) //nolint:gosec
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	return io.ReadAll(io.LimitReader(file, maxLinkPlaceholderBytes+1))
}

func skippedPlaceholder(ctx context.Context, path string, err error) error {
	log := logger.FromContext(ctx)
	log.Debug().Err(err).Msgf("Skipping Terraform symlink placeholder %q", path)
	return fmt.Errorf("%w: %s: %w", ErrSkippedLinkPlaceholder, path, err)
}

// ResolveConfigContent follows a config placeholder without changing its logical
// filename: relative Terraform references still belong to the linking module.
// In-memory scans never read the host filesystem to resolve pushed content.
func ResolveConfigContent(ctx context.Context, fsys vfs.FS, path, packageRoot string, data []byte) ([]byte, error) {
	return resolveConfigContent(ctx, fsys, path, packageRoot, data, nil)
}

func resolveConfigContent(
	ctx context.Context, fsys vfs.FS, path, packageRoot string, data []byte, materialize func(context.Context, string) error,
) ([]byte, error) {
	if !vfs.IsDisk(fsys) {
		return data, nil
	}
	if _, ok := placeholderTarget(data, false); !ok {
		return data, nil
	}
	root := placeholderRoot(ctx, fsys, filepath.Dir(path), packageRoot)
	resolved, _, err := resolvePlaceholderPath(ctx, root, path, false, materialize)
	if err != nil {
		return nil, skippedPlaceholder(ctx, path, err)
	}
	if ConfigFileTooLarge(resolved, MaxConfigFileBytesFromContext(ctx)) {
		return nil, skippedPlaceholder(ctx, path, errors.New("target exceeds configuration size limit"))
	}
	data, err = fsys.ReadFile(resolved)
	if err != nil {
		return nil, skippedPlaceholder(ctx, path, err)
	}
	return data, nil
}

// ReadConfigFile reads a Terraform config, following confined checkout links.
func ReadConfigFile(ctx context.Context, fsys vfs.FS, path, packageRoot string) ([]byte, error) {
	return ReadConfigFileWithMaterializer(ctx, fsys, path, packageRoot, nil)
}

// ReadConfigFileWithMaterializer allows sparse packages to acquire missing link
// targets. materialize is called only for confined missing path components of a
// detected placeholder, under the same hop and file-size limits as disk reads.
func ReadConfigFileWithMaterializer(
	ctx context.Context, fsys vfs.FS, path, packageRoot string, materialize func(context.Context, string) error,
) ([]byte, error) {
	data, err := fsys.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	return resolveConfigContent(ctx, fsys, path, packageRoot, data, materialize)
}

// ResolveModuleDir follows placeholder directories using the caller's repository
// (or the supplied downloaded package) as its boundary. Ordinary missing module
// sources retain their existing validation errors.
func ResolveModuleDir(ctx context.Context, fsys vfs.FS, callerDir, path, packageRoot string) (string, error) {
	return ResolveModuleDirWithMaterializer(ctx, fsys, callerDir, path, packageRoot, nil)
}

// ResolveModuleDirWithMaterializer is ResolveModuleDir for a sparse package that
// can acquire confined missing path components while resolving a directory.
func ResolveModuleDirWithMaterializer(
	ctx context.Context, fsys vfs.FS, callerDir, path, packageRoot string, materialize func(context.Context, string) error,
) (string, error) {
	if !vfs.IsDisk(fsys) || isDir(fsys, path) {
		return path, nil
	}
	root := placeholderRoot(ctx, fsys, callerDir, packageRoot)
	resolved, linked, err := resolvePlaceholderPath(ctx, root, path, true, materialize)
	if err != nil {
		if linked {
			return "", skippedPlaceholder(ctx, path, err)
		}
		if materialize != nil {
			return "", err
		}
		return path, nil
	}
	return resolved, nil
}
