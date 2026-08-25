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
	"sort"
	"strconv"
	"strings"
	"sync"
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

var errCacheEntryTooLarge = errors.New("module package exceeds cache size limit")

// moduleCache is a content-addressed on-disk module store.
type moduleCache struct {
	dir      string
	maxBytes int64
	sf       singleflight.Group
	evictMu  sync.Mutex
	total    int64
	sized    bool
	inUse    map[string]bool
}

func NewModuleCache() (*moduleCache, error) {
	return NewModuleCacheWithDir("", DefaultMaxCacheBytes)
}

func NewModuleCacheWithDir(dir string, maxBytes int64) (*moduleCache, error) {
	if dir == "" {
		root, err := defaultModuleCacheRoot()
		if err != nil {
			return nil, err
		}
		dir = filepath.Join(root, CacheSubdirModules)
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxCacheBytes
	}
	dir = filepath.Clean(dir)
	if err := os.MkdirAll(dir, cacheDirPerms); err != nil {
		return nil, fmt.Errorf("creating module cache: %w", err)
	}
	return &moduleCache{dir: dir, maxBytes: maxBytes}, nil
}

func defaultModuleCacheRoot() (string, error) {
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
	c.retain(dir)
	return dir, true
}

func (c *moduleCache) store(source, version, srcDir, subdir string) (string, error) {
	key := moduleCacheKey(source, version)
	dst := filepath.Join(c.dir, key)
	if cached, ok := c.lookup(source, version); ok {
		return cached, nil
	}
	var published bool
	var added int64
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
		if c.maxBytes > 0 && size > c.maxBytes {
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
		added = size
		return dst, nil
	})
	if err != nil {
		return "", err
	}
	stored := v.(string)
	c.retain(stored)
	if published {
		c.accountAndEvict(stored, added)
	}
	return stored, nil
}

func (c *moduleCache) retain(path string) {
	if c == nil || path == "" {
		return
	}
	c.evictMu.Lock()
	defer c.evictMu.Unlock()
	if c.inUse == nil {
		c.inUse = make(map[string]bool)
	}
	c.inUse[filepath.Clean(path)] = true
}

func (c *moduleCache) accountAndEvict(keep string, added int64) {
	if c == nil || c.maxBytes <= 0 {
		return
	}
	c.evictMu.Lock()
	defer c.evictMu.Unlock()

	if !c.sized {
		_, c.total = listCacheEntries(c.dir)
		c.sized = true
	} else {
		c.total += added
	}
	if c.total <= c.maxBytes {
		return
	}

	entries, total := listCacheEntries(c.dir)
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].modTime.Equal(entries[j].modTime) {
			return entries[i].path < entries[j].path
		}
		return entries[i].modTime.Before(entries[j].modTime)
	})
	keep = filepath.Clean(keep)
	for _, entry := range entries {
		if total <= c.maxBytes {
			break
		}
		path := filepath.Clean(entry.path)
		if path == keep || c.inUse[path] {
			continue
		}
		if err := os.RemoveAll(entry.path); err != nil {
			continue
		}
		total -= entry.size
	}
	c.total = max(total, 0)
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

func evictUnretainedDirs(dir string, maxBytes int64, retained map[string]bool) {
	if maxBytes <= 0 || dir == "" {
		return
	}
	entries, total := listCacheEntries(dir)
	if total <= maxBytes {
		return
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].modTime.Equal(entries[j].modTime) {
			return entries[i].path < entries[j].path
		}
		return entries[i].modTime.Before(entries[j].modTime)
	})
	for _, entry := range entries {
		if total <= maxBytes {
			return
		}
		path := filepath.Clean(entry.path)
		if retained[path] {
			continue
		}
		if err := os.RemoveAll(entry.path); err != nil {
			continue
		}
		total -= entry.size
	}
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
