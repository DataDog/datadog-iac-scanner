package kustomize

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// copyTreeNoSymlinks copies srcRoot into dstRoot, skipping symlinks (no escape via links).
func copyTreeNoSymlinks(dstRoot, srcRoot string) error {
	srcRoot = filepath.Clean(srcRoot)
	dstRoot = filepath.Clean(dstRoot)
	return filepath.WalkDir(srcRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(srcRoot, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dstRoot, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		srcFile, err := os.Open(path)
		if err != nil {
			return err
		}
		defer srcFile.Close()
		dstFile, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		if _, err := io.Copy(dstFile, srcFile); err != nil {
			_ = dstFile.Close()
			return err
		}
		return dstFile.Close()
	})
}

// CopyRepoRelativeFilesNoSymlinks copies relFiles from srcRoot to dstRoot by relative path; skips symlinks and out-of-root paths.
func CopyRepoRelativeFilesNoSymlinks(dstRoot, srcRoot string, relFiles []string) error {
	srcRoot = filepath.Clean(srcRoot)
	dstRoot = filepath.Clean(dstRoot)
	for _, rel := range relFiles {
		rel = filepath.Clean(rel)
		if rel == "." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." {
			continue
		}
		src := filepath.Join(srcRoot, rel)
		if !isUnderRoot(src, srcRoot) {
			continue
		}
		fi, err := os.Lstat(src)
		if err != nil || fi.Mode()&os.ModeSymlink != 0 || fi.IsDir() {
			continue
		}
		dst := filepath.Join(dstRoot, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return err
		}
		srcFile, err := os.Open(src)
		if err != nil {
			return err
		}
		dstFile, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			_ = srcFile.Close()
			return err
		}
		if _, err := io.Copy(dstFile, srcFile); err != nil {
			_ = dstFile.Close()
			_ = srcFile.Close()
			return err
		}
		if err := dstFile.Close(); err != nil {
			_ = srcFile.Close()
			return err
		}
		if err := srcFile.Close(); err != nil {
			return err
		}
	}
	return nil
}
