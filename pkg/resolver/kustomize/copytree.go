package kustomize

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const (
	dirPermCopyTree  = 0o700
	filePermCopyTree = 0o600
	parentDirPrefix  = ".." + string(filepath.Separator)
	relDotDot        = ".."
)

func mkdirParentInRoot(dstR *os.Root, rel string) error {
	parent := filepath.Dir(rel)
	if parent == "." || parent == "" {
		return nil
	}
	parentSlash := filepath.ToSlash(filepath.Clean(parent))
	if parentSlash == "." {
		return nil
	}
	return dstR.MkdirAll(parentSlash, dirPermCopyTree)
}

func copyOneRelFile(dstR, srcR *os.Root, srcRoot, rel string) error {
	rel = filepath.Clean(rel)
	if rel == "." || !filepath.IsLocal(rel) || strings.HasPrefix(rel, parentDirPrefix) || rel == relDotDot {
		return nil
	}
	joined := filepath.Join(srcRoot, rel)
	if !isUnderRoot(joined, srcRoot) {
		return nil
	}
	relSlash := filepath.ToSlash(rel)
	fi, err := srcR.Lstat(relSlash)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 || fi.IsDir() {
		return nil
	}
	data, err := srcR.ReadFile(relSlash)
	if err != nil {
		return err
	}
	if err := mkdirParentInRoot(dstR, rel); err != nil {
		return err
	}
	df, err := dstR.OpenFile(relSlash, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, filePermCopyTree)
	if err != nil {
		return err
	}
	_, werr := df.Write(data)
	cerr := df.Close()
	return errors.Join(werr, cerr)
}

// CopyRepoRelativeFilesNoSymlinks copies relFiles from srcRoot to dstRoot by relative path; skips symlinks and out-of-root paths.
func CopyRepoRelativeFilesNoSymlinks(dstRoot, srcRoot string, relFiles []string) (err error) {
	srcRoot = filepath.Clean(srcRoot)
	dstRoot = filepath.Clean(dstRoot)
	if mkerr := os.MkdirAll(dstRoot, dirPermCopyTree); mkerr != nil {
		return mkerr
	}
	srcR, err := os.OpenRoot(srcRoot)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := srcR.Close(); cerr != nil {
			err = errors.Join(err, cerr)
		}
	}()
	dstR, err := os.OpenRoot(dstRoot)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := dstR.Close(); cerr != nil {
			err = errors.Join(err, cerr)
		}
	}()

	for _, rel := range relFiles {
		if cerr := copyOneRelFile(dstR, srcR, srcRoot, rel); cerr != nil {
			return cerr
		}
	}
	return err
}
