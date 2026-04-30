package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sigs.k8s.io/kustomize/kyaml/filesys"
)

// BoundedFS wraps a kustomize FileSystem and rejects paths outside repoRoot.
type BoundedFS struct {
	inner   filesys.FileSystem
	repoAbs string
}

// NewBoundedFS returns a disk-backed filesystem bounded to repoRoot (must exist).
func NewBoundedFS(repoRoot string) (*BoundedFS, error) {
	abs, err := canonicalPath(repoRoot)
	if err != nil {
		return nil, err
	}
	if st, err := os.Stat(abs); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("sandbox: repo root %q is not a directory", abs)
	}
	return &BoundedFS{
		inner:   filesys.MakeFsOnDisk(),
		repoAbs: filepath.Clean(abs),
	}, nil
}

func (b *BoundedFS) under(abs string) bool {
	cp, err := canonicalPath(abs)
	if err != nil {
		cp = filepath.Clean(abs)
	}
	return cp == b.repoAbs || strings.HasPrefix(cp, b.repoAbs+string(filepath.Separator))
}

func (b *BoundedFS) checkCleaned(d filesys.ConfirmedDir, f string, resolveLeaf bool) error {
	full, err := canonicalPath(filepath.Join(string(d), f))
	if err != nil {
		full = filepath.Clean(filepath.Join(string(d), f))
	}
	if err := b.checkParents(full); err != nil {
		return err
	}
	if !resolveLeaf {
		if parent := filepath.Dir(full); parent != full {
			if ev, err := filepath.EvalSymlinks(parent); err == nil {
				full = filepath.Join(filepath.Clean(ev), filepath.Base(full))
			}
		}
		// Writes follow leaf symlinks at the OS layer, which would let a
		// pre-existing or dangling symlink escape the sandbox. Reject any
		// symlink leaf so the outside target is never created or overwritten.
		if li, lerr := os.Lstat(full); lerr == nil && li.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink leaf rejected for write: %s", full)
		}
	}
	if !b.under(full) {
		return fmt.Errorf("path outside scan root: %s", full)
	}
	return nil
}

func (b *BoundedFS) checkParents(path string) error {
	cur := filepath.Clean(path)
	if cur == b.repoAbs {
		return nil
	}
	for {
		parent := filepath.Dir(cur)
		if parent == cur {
			return nil
		}
		ev, err := canonicalPath(parent)
		if err == nil {
			if ev == b.repoAbs {
				return nil
			}
			if !strings.HasPrefix(ev, b.repoAbs+string(filepath.Separator)) {
				return fmt.Errorf("path outside scan root: %s", path)
			}
		}
		cur = parent
	}
}

func canonicalPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if ev, err := filepath.EvalSymlinks(abs); err == nil {
		return filepath.Clean(ev), nil
	}
	return filepath.Clean(abs), nil
}

func (b *BoundedFS) cleanedPath(path string, resolveLeaf bool) (filesys.ConfirmedDir, string, error) {
	d, f, err := b.inner.CleanedAbs(path)
	if err != nil {
		return "", "", err
	}
	if err := b.checkCleaned(d, f, resolveLeaf); err != nil {
		return "", "", err
	}
	return d, f, nil
}

// Create implements filesys.FileSystem.
func (b *BoundedFS) Create(path string) (filesys.File, error) {
	if _, _, err := b.cleanedPath(path, false); err != nil {
		return nil, err
	}
	return b.inner.Create(path)
}

// Mkdir implements filesys.FileSystem.
func (b *BoundedFS) Mkdir(path string) error {
	if _, _, err := b.cleanedPath(path, false); err != nil {
		return err
	}
	return b.inner.Mkdir(path)
}

// MkdirAll implements filesys.FileSystem.
func (b *BoundedFS) MkdirAll(path string) error {
	if _, _, err := b.cleanedPath(path, false); err != nil {
		return err
	}
	return b.inner.MkdirAll(path)
}

// RemoveAll implements filesys.FileSystem.
func (b *BoundedFS) RemoveAll(path string) error {
	if _, _, err := b.cleanedPath(path, true); err != nil {
		return err
	}
	return b.inner.RemoveAll(path)
}

// Open implements filesys.FileSystem.
func (b *BoundedFS) Open(path string) (filesys.File, error) {
	if _, _, err := b.cleanedPath(path, true); err != nil {
		return nil, err
	}
	return b.inner.Open(path)
}

// IsDir implements filesys.FileSystem.
func (b *BoundedFS) IsDir(path string) bool {
	if _, _, err := b.cleanedPath(path, true); err != nil {
		return false
	}
	return b.inner.IsDir(path)
}

// ReadDir implements filesys.FileSystem.
func (b *BoundedFS) ReadDir(path string) ([]string, error) {
	if _, _, err := b.cleanedPath(path, true); err != nil {
		return nil, err
	}
	return b.inner.ReadDir(path)
}

// CleanedAbs implements filesys.FileSystem.
func (b *BoundedFS) CleanedAbs(path string) (filesys.ConfirmedDir, string, error) {
	return b.cleanedPath(path, true)
}

// Exists implements filesys.FileSystem.
func (b *BoundedFS) Exists(path string) bool {
	if _, _, err := b.cleanedPath(path, true); err != nil {
		return false
	}
	return b.inner.Exists(path)
}

// Glob implements filesys.FileSystem.
func (b *BoundedFS) Glob(pattern string) ([]string, error) {
	matches, err := b.inner.Glob(pattern)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, m := range matches {
		if _, _, err := b.cleanedPath(m, true); err != nil {
			continue
		}
		out = append(out, m)
	}
	return out, nil
}

// ReadFile implements filesys.FileSystem.
func (b *BoundedFS) ReadFile(path string) ([]byte, error) {
	if _, _, err := b.cleanedPath(path, true); err != nil {
		return nil, err
	}
	return b.inner.ReadFile(path)
}

// WriteFile implements filesys.FileSystem.
func (b *BoundedFS) WriteFile(path string, data []byte) error {
	if _, _, err := b.cleanedPath(path, false); err != nil {
		return err
	}
	return b.inner.WriteFile(path, data)
}

// Walk implements filesys.FileSystem.
func (b *BoundedFS) Walk(path string, walkFn filepath.WalkFunc) error {
	if _, _, err := b.cleanedPath(path, true); err != nil {
		return err
	}
	return b.inner.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return walkFn(p, info, err)
		}
		cd, cf, errC := b.inner.CleanedAbs(p)
		if errC != nil {
			return walkFn(p, info, errC)
		}
		if errB := b.checkCleaned(cd, cf, true); errB != nil {
			return filepath.SkipDir
		}
		return walkFn(p, info, nil)
	})
}
