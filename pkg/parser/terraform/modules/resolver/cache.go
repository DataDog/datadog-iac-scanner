/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/sync/singleflight"
)

const cacheDirPerms = 0o700
const cacheSelectionFile = ".module-subdir"

// moduleCache is a content-addressed on-disk module store ($XDG_CACHE_HOME/.../modules).
type moduleCache struct {
	dir string
	sf  singleflight.Group
}

// NewModuleCache creates ~/.cache/.../modules (or XDG_CACHE_HOME) and returns it.
func NewModuleCache() (*moduleCache, error) {
	base := os.Getenv("XDG_CACHE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("determining home dir for module cache: %w", err)
		}
		base = filepath.Join(home, ".cache")
	}
	dir := filepath.Join(filepath.Clean(base), "datadog-iac-scanner", "modules")
	if err := os.MkdirAll(dir, cacheDirPerms); err != nil {
		return nil, fmt.Errorf("creating module cache: %w", err)
	}
	return &moduleCache{dir: dir}, nil
}

// moduleCacheKey is sha256(packageSource + NUL + version) hex.
func moduleCacheKey(source, version string) string {
	h := sha256.New()
	_, _ = h.Write([]byte("package-v1"))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(moduleCachePackageSource(source)))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(version))
	return hex.EncodeToString(h.Sum(nil))
}

func moduleCachePackageSource(source string) string {
	packageSource, _ := splitGetterSubdir(source)
	return packageSource
}

// lookup returns a cached package root when the entry is complete.
func (c *moduleCache) lookup(source, version string) (packageRoot string, ok bool) {
	dir := filepath.Join(c.dir, moduleCacheKey(source, version))
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return "", false
	}
	if _, err := os.ReadFile(filepath.Join(dir, cacheSelectionFile)); err != nil { //nolint:gosec
		return "", false
	}
	return dir, true
}

// store copies srcDir into the cache key path via temp dir + rename (concurrent-safe).
// A singleflight ensures that only one goroutine performs the copy+rename per key;
// concurrent callers with the same key wait and share the result, which avoids the
// Windows file-locking errors that arise when multiple goroutines race to rename
// different temp dirs onto the same destination directory.
func (c *moduleCache) store(source, version, srcDir, subdir string) (string, error) {
	key := moduleCacheKey(source, version)
	dst := filepath.Join(c.dir, key)
	if cached, ok := c.lookup(source, version); ok {
		return cached, nil
	}
	v, err, _ := c.sf.Do(key, func() (interface{}, error) {
		// Re-check after acquiring the singleflight slot.
		if cached, ok := c.lookup(source, version); ok {
			return cached, nil
		}
		if _, err := os.Stat(dst); err == nil {
			_ = os.RemoveAll(dst)
		}
		tmp, err := os.MkdirTemp(c.dir, ".tmp-")
		if err != nil {
			return "", fmt.Errorf("creating cache temp dir: %w", err)
		}
		if err := copyRegularFiles(tmp, srcDir); err != nil {
			_ = os.RemoveAll(tmp)
			return "", fmt.Errorf("copying to cache: %w", err)
		}
		if err := os.WriteFile(filepath.Join(tmp, cacheSelectionFile), []byte(subdir), cacheFilePerms); err != nil {
			_ = os.RemoveAll(tmp)
			return "", fmt.Errorf("writing cache selection: %w", err)
		}
		if err := os.Rename(tmp, dst); err != nil {
			_ = os.RemoveAll(tmp)
			if cached, ok := c.lookup(source, version); ok {
				return cached, nil
			}
			return "", fmt.Errorf("publishing cache entry: %w", err)
		}
		return dst, nil
	})
	if err != nil {
		return "", err
	}
	return v.(string), nil
}

func copyRegularFiles(dest, source string) error {
	return fs.WalkDir(os.DirFS(source), ".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == "." {
			return nil
		}
		destPath := filepath.Join(dest, filepath.FromSlash(path))
		if entry.IsDir() {
			return os.MkdirAll(destPath, cacheDirPerms)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		sourceFile, err := os.Open(filepath.Join(source, filepath.FromSlash(path))) //nolint:gosec
		if err != nil {
			return err
		}
		destFile, err := os.OpenFile(destPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode().Perm()) //nolint:gosec
		if err != nil {
			_ = sourceFile.Close()
			return err
		}
		_, copyErr := io.Copy(destFile, sourceFile)
		sourceCloseErr := sourceFile.Close()
		destCloseErr := destFile.Close()
		if copyErr != nil {
			return copyErr
		}
		if sourceCloseErr != nil {
			return sourceCloseErr
		}
		return destCloseErr
	})
}
