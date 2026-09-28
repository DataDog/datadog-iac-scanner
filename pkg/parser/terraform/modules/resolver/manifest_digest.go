/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// PackageVisitor observes a package while its digest is computed, so a caller
// that also needs the bytes reads each file once. Paths are relative to the
// package root, which is visited as ".".
type PackageVisitor struct {
	Dir func(relative string) error
	// File may read content, which yields the file's bytes as they are hashed;
	// whatever it leaves unread is hashed afterwards.
	File func(relative, path string, info fs.FileInfo, content io.Reader) error
}

// ComputePackageDigest hashes regular files by relative path, size, and content.
func ComputePackageDigest(ctx context.Context, root string) (string, error) {
	return WalkPackageDigest(ctx, root, PackageVisitor{})
}

// WalkPackageDigest computes ComputePackageDigest while calling visitor for
// every directory and regular file of root.
func WalkPackageDigest(ctx context.Context, root string, visitor PackageVisitor) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("resolving package root: %w", err)
	}
	hasher := sha256.New()
	err = filepath.WalkDir(resolvedRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("symlink %q is not allowed in a manifest package", path)
		}
		relativePath, err := filepath.Rel(resolvedRoot, path)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if visitor.Dir != nil {
				return visitor.Dir(relativePath)
			}
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("non-regular file %q is not allowed in a manifest package", path)
		}
		if err := writeDigestField(hasher, []byte(filepath.ToSlash(relativePath))); err != nil {
			return err
		}
		if err := binary.Write(hasher, binary.BigEndian, uint64(info.Size())); err != nil {
			return err
		}
		return hashPackageFile(hasher, relativePath, path, info, visitor.File)
	})
	if err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(hasher.Sum(nil)), nil
}

func hashPackageFile(
	hasher io.Writer,
	relativePath, path string,
	info fs.FileInfo,
	visit func(relative, path string, info fs.FileInfo, content io.Reader) error,
) error {
	file, err := os.Open(path) //nolint:gosec
	if err != nil {
		return err
	}
	if visit != nil {
		if err := visit(relativePath, path, info, io.TeeReader(file, hasher)); err != nil {
			_ = file.Close()
			return err
		}
	}
	_, copyErr := io.Copy(hasher, file)
	closeErr := file.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func writeDigestField(writer io.Writer, value []byte) error {
	if err := binary.Write(writer, binary.BigEndian, uint64(len(value))); err != nil {
		return err
	}
	_, err := writer.Write(value)
	return err
}
