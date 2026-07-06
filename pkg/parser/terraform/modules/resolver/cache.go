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
	"os"
	"path/filepath"

	"golang.org/x/sync/singleflight"
)

const cacheDirPerms = 0o700

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

// moduleCacheKey is sha256(source + NUL + version) hex.
func moduleCacheKey(source, version string) string {
	h := sha256.New()
	_, _ = h.Write([]byte(source))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(version))
	return hex.EncodeToString(h.Sum(nil))
}

// lookup returns a cache hit directory for (source, version), if any.
func (c *moduleCache) lookup(source, version string) (localDir string, ok bool) {
	dir := filepath.Join(c.dir, moduleCacheKey(source, version))
	if info, err := os.Stat(dir); err == nil && info.IsDir() {
		return dir, true
	}
	return "", false
}

// store copies srcDir into the cache key path via temp dir + rename (concurrent-safe).
// A singleflight ensures that only one goroutine performs the copy+rename per key;
// concurrent callers with the same key wait and share the result, which avoids the
// Windows file-locking errors that arise when multiple goroutines race to rename
// different temp dirs onto the same destination directory.
func (c *moduleCache) store(source, version, srcDir string) (string, error) {
	key := moduleCacheKey(source, version)
	dst := filepath.Join(c.dir, key)
	if info, err := os.Stat(dst); err == nil && info.IsDir() {
		return dst, nil
	}
	v, err, _ := c.sf.Do(key, func() (interface{}, error) {
		// Re-check after acquiring the singleflight slot.
		if info, err := os.Stat(dst); err == nil && info.IsDir() {
			return dst, nil
		}
		tmp, err := os.MkdirTemp(c.dir, ".tmp-")
		if err != nil {
			return "", fmt.Errorf("creating cache temp dir: %w", err)
		}
		if err := os.CopyFS(tmp, os.DirFS(srcDir)); err != nil {
			_ = os.RemoveAll(tmp)
			return "", fmt.Errorf("copying to cache: %w", err)
		}
		if err := os.Rename(tmp, dst); err != nil {
			_ = os.RemoveAll(tmp)
			if info, statErr := os.Stat(dst); statErr == nil && info.IsDir() {
				return dst, nil
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
