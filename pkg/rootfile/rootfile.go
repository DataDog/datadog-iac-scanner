// Package rootfile provides filesystem reads scoped with os.OpenRoot for safer path handling.
package rootfile

import (
	"fmt"
	"os"
	"path/filepath"
)

func openParentRoot(absPath string) (*os.Root, string, error) {
	absPath = filepath.Clean(absPath)
	dir := filepath.Dir(absPath)
	rel, err := filepath.Rel(dir, absPath)
	if err != nil {
		return nil, "", err
	}
	if !filepath.IsLocal(rel) {
		return nil, "", fmt.Errorf("path %q is not local under %q", absPath, dir)
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, "", err
	}
	return r, filepath.ToSlash(rel), nil
}

// ReadFile reads absPath by opening filepath.Dir(absPath) with os.OpenRoot and reading the relative path.
func ReadFile(absPath string) ([]byte, error) {
	r, rel, err := openParentRoot(absPath)
	if err != nil {
		return nil, err
	}
	data, rerr := r.ReadFile(rel)
	cerr := r.Close()
	if rerr != nil {
		return nil, rerr
	}
	if cerr != nil {
		return nil, cerr
	}
	return data, nil
}

// Lstat returns file info for absPath using os.OpenRoot on the parent directory.
func Lstat(absPath string) (os.FileInfo, error) {
	r, rel, err := openParentRoot(absPath)
	if err != nil {
		return nil, err
	}
	fi, rerr := r.Lstat(rel)
	cerr := r.Close()
	if rerr != nil {
		return nil, rerr
	}
	if cerr != nil {
		return nil, cerr
	}
	return fi, nil
}
