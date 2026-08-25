/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sync/singleflight"

	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
)

const (
	cacheDirPerms        = 0o700
	cacheSelectionFile   = ".module-subdir"
	cacheSizeFile        = ".module-bytes"
	DefaultMaxCacheBytes = 2 * 1024 * 1024 * 1024

	CacheSubdirModules  = "modules"
	CacheSubdirGitBare  = "git-bare"
	CacheSubdirGitLocal = "git-local"
)

var errCacheEntryTooLarge = errors.New("cache entry exceeds cache size limit")

// moduleCache is a content-addressed on-disk module store.
type moduleCache struct {
	dir    string
	budget *ModuleCacheBudget
	sf     singleflight.Group
}

func NewModuleCache() (*moduleCache, error) {
	root, err := DefaultModuleCacheRoot()
	if err != nil {
		return nil, err
	}
	budget, err := NewModuleCacheBudget(root, DefaultMaxCacheBytes)
	if err != nil {
		return nil, err
	}
	return NewModuleCacheWithDir("", budget)
}

func NewModuleCacheWithDir(dir string, budget *ModuleCacheBudget) (*moduleCache, error) {
	if dir == "" {
		if budget != nil && budget.Root() != "" {
			dir = filepath.Join(budget.Root(), CacheSubdirModules)
		} else {
			root, err := DefaultModuleCacheRoot()
			if err != nil {
				return nil, err
			}
			dir = filepath.Join(root, CacheSubdirModules)
			if budget == nil {
				var budgetErr error
				budget, budgetErr = NewModuleCacheBudget(root, DefaultMaxCacheBytes)
				if budgetErr != nil {
					return nil, budgetErr
				}
			}
		}
	}
	dir = filepath.Clean(dir)
	if err := os.MkdirAll(dir, cacheDirPerms); err != nil {
		return nil, fmt.Errorf("creating module cache: %w", err)
	}
	return &moduleCache{dir: dir, budget: budget}, nil
}

func DefaultModuleCacheRoot() (string, error) {
	base := os.Getenv("XDG_CACHE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("determining home dir for module cache: %w", err)
		}
		base = filepath.Join(home, ".cache")
	}
	return filepath.Join(filepath.Clean(base), "datadog-iac-scanner"), nil
}

func ModuleCacheSubdir(root, name string) string {
	if strings.TrimSpace(root) == "" {
		return ""
	}
	return filepath.Join(filepath.Clean(root), name)
}

func moduleCacheKey(source, version string) string {
	h := sha256.New()
	_, _ = h.Write([]byte("package-v2"))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(canonicalizeModuleCacheSource(source)))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(strings.TrimSpace(version)))
	return hex.EncodeToString(h.Sum(nil))
}

func canonicalizeModuleCacheSource(source string) string {
	packageSource, _ := splitGetterSubdir(source)
	st, _ := tfmodules.DetectModuleSourceType(packageSource)
	switch st {
	case sourceTypeRegistry:
		host, namespace, name, provider, err := parseRegistrySource(packageSource)
		if err == nil {
			return strings.ToLower(host) + "/" + namespace + "/" + name + "/" + provider
		}
	case sourceTypeGit:
		if key, ok := GitModuleResolveKey(packageSource, ""); ok {
			return key
		}
	}
	return packageSource
}

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

func (c *moduleCache) lookupLease(source, version string) (packageRoot string, release func(), ok bool) {
	path := filepath.Join(c.dir, moduleCacheKey(source, version))
	release = c.lease(path)
	packageRoot, ok = c.lookup(source, version)
	if !ok {
		release()
		return "", func() {}, false
	}
	return packageRoot, release, true
}

func (c *moduleCache) lease(path string) func() {
	if c == nil || c.budget == nil || path == "" {
		return func() {}
	}
	return c.budget.Lease(path)
}

func (c *moduleCache) admitStored(path string) error {
	if c == nil || c.budget == nil {
		return nil
	}
	if err := c.budget.EnsureEntryFits(path); err != nil {
		return err
	}
	c.budget.Admit(path)
	return nil
}

func (c *moduleCache) store(source, version, srcDir, subdir string) (stored string, release func(), err error) {
	key := moduleCacheKey(source, version)
	dst := filepath.Join(c.dir, key)
	release = c.lease(dst)
	if cached, ok := c.lookup(source, version); ok {
		return cached, release, nil
	}
	var published bool
	v, err, _ := c.sf.Do(key, func() (interface{}, error) {
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
		copied, err := copyRegularFiles(tmp, srcDir)
		if err != nil {
			_ = os.RemoveAll(tmp)
			return "", fmt.Errorf("copying to cache: %w", err)
		}
		if err := os.WriteFile(filepath.Join(tmp, cacheSelectionFile), []byte(subdir), cacheFilePerms); err != nil {
			_ = os.RemoveAll(tmp)
			return "", fmt.Errorf("writing cache selection: %w", err)
		}
		size := copied + int64(len(subdir))
		if c.budget != nil && size > c.budget.MaxBytes() {
			_ = os.RemoveAll(tmp)
			return "", errCacheEntryTooLarge
		}
		if err := os.WriteFile(filepath.Join(tmp, cacheSizeFile), []byte(strconv.FormatInt(size, 10)), cacheFilePerms); err != nil {
			_ = os.RemoveAll(tmp)
			return "", fmt.Errorf("writing cache size: %w", err)
		}
		if err := os.Rename(tmp, dst); err != nil {
			_ = os.RemoveAll(tmp)
			if cached, ok := c.lookup(source, version); ok {
				return cached, nil
			}
			return "", fmt.Errorf("publishing cache entry: %w", err)
		}
		published = true
		return dst, nil
	})
	if err != nil {
		release()
		return "", func() {}, err
	}
	stored = v.(string)
	if published {
		if fitErr := c.admitStored(stored); fitErr != nil {
			release()
			return "", func() {}, fitErr
		}
	}
	return stored, release, nil
}

type cacheEntry struct {
	path    string
	size    int64
	modTime time.Time
}

func listCacheEntries(dir string) (entries []cacheEntry, total int64) {
	items, err := os.ReadDir(dir)
	if err != nil {
		return nil, 0
	}
	entries = make([]cacheEntry, 0, len(items))
	for _, item := range items {
		path := filepath.Join(dir, item.Name())
		info, infoErr := item.Info()
		if infoErr != nil {
			continue
		}
		if !item.IsDir() || strings.HasPrefix(item.Name(), ".") {
			if !item.IsDir() {
				total += info.Size()
			}
			continue
		}
		size, ok := readCacheSize(path)
		if !ok {
			size = directorySize(path)
		}
		total += size
		entries = append(entries, cacheEntry{path: path, size: size, modTime: info.ModTime()})
	}
	return entries, total
}

func readCacheSize(dir string) (int64, bool) {
	data, err := os.ReadFile(filepath.Join(dir, cacheSizeFile)) //nolint:gosec
	if err != nil {
		return 0, false
	}
	size, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	return size, err == nil && size >= 0
}

func directorySize(path string) int64 {
	var total int64
	_ = fs.WalkDir(os.DirFS(path), ".", func(_ string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}
		info, infoErr := entry.Info()
		if infoErr != nil || !info.Mode().IsRegular() {
			return nil
		}
		total += info.Size()
		return nil
	})
	return total
}

func copyRegularFiles(dest, source string) (int64, error) {
	var written int64
	err := fs.WalkDir(os.DirFS(source), ".", func(path string, entry fs.DirEntry, walkErr error) error {
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
		n, copyErr := io.Copy(destFile, sourceFile)
		sourceCloseErr := sourceFile.Close()
		destCloseErr := destFile.Close()
		if copyErr != nil {
			return copyErr
		}
		if sourceCloseErr != nil {
			return sourceCloseErr
		}
		if destCloseErr != nil {
			return destCloseErr
		}
		written += n
		return nil
	})
	return written, err
}
