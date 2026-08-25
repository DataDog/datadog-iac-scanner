/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"archive/zip"
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"

	getter "github.com/hashicorp/go-getter"
)

const (
	maxArchiveExpansionRatio = 20
	maxEntryExpansionRatio   = 100
	// minStreamRatioBytes is the amount of output that must be produced before a
	// streaming ratio check is trusted. Decompressors buffer input ahead of the
	// bytes they emit, so a short prefix of a well-formed archive can look far
	// more compressed than the archive as a whole.
	minStreamRatioBytes = 1 << 20
)

type zipBudgetDecompressor struct {
	inner  getter.Decompressor
	limits ResourceLimits
}

func limitedDecompressors(limits ResourceLimits, maxPackageBytes int64) map[string]getter.Decompressor {
	decompressors := getter.LimitedDecompressors(limits.MaxPackageFiles, maxPackageBytes)
	maxFileBytes := limits.MaxFileBytes
	singleFileLimit := "file_bytes"
	if maxPackageBytes > 0 && (maxFileBytes <= 0 || maxPackageBytes < maxFileBytes) {
		maxFileBytes = maxPackageBytes
		singleFileLimit = limitPackageBytes
	}
	singleFormats := map[string]archiveReaderFunc{
		"bz2": bzip2ArchiveReader,
		"gz":  gzipArchiveReader,
		"xz":  xzArchiveReader,
		"zst": zstdArchiveReader,
	}
	for name, open := range singleFormats {
		decompressors[name] = &singleFileBudgetDecompressor{
			maxFileBytes: maxFileBytes,
			limitName:    singleFileLimit,
			open:         open,
		}
	}
	tarFormats := map[string]archiveReaderFunc{
		"tar":     rawArchiveReader,
		"tar.bz2": bzip2ArchiveReader,
		"tar.gz":  gzipArchiveReader,
		"tar.xz":  xzArchiveReader,
		"tar.zst": zstdArchiveReader,
		"tbz2":    bzip2ArchiveReader,
		"tgz":     gzipArchiveReader,
		"txz":     xzArchiveReader,
		"tzst":    zstdArchiveReader,
	}
	for name, open := range tarFormats {
		decompressors[name] = &tarBudgetDecompressor{limits: limits, open: open}
	}
	if zipDecompressor := decompressors["zip"]; zipDecompressor != nil {
		decompressors["zip"] = &zipBudgetDecompressor{
			inner:  zipDecompressor,
			limits: limits,
		}
	}
	return decompressors
}

func (d *zipBudgetDecompressor) Decompress(
	dst, src string, dir bool, umask os.FileMode,
) error {
	compressed, err := os.Stat(src)
	if err != nil {
		return err
	}
	if err := d.checkEntries(src); err != nil {
		return err
	}
	if err := d.inner.Decompress(dst, src, dir, umask); err != nil {
		return err
	}
	usage, err := MeasurePackage(context.Background(), dst, d.limits)
	if err != nil {
		_ = os.RemoveAll(dst)
		return err
	}
	if exceedsExpansionRatio(usage.Bytes, compressed.Size(), maxArchiveExpansionRatio) {
		_ = os.RemoveAll(dst)
		return expansionRatioError("archive_expansion_ratio", usage.Bytes, compressed.Size(), maxArchiveExpansionRatio)
	}
	return nil
}

func (d *zipBudgetDecompressor) checkEntries(path string) error {
	archive, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer func() { _ = archive.Close() }()

	tree := newPackageTreeCounter(NewResourceBudget(d.limits).NewPackageCounter())
	for _, file := range archive.File {
		name := filepath.Clean(file.Name)
		if file.FileInfo().IsDir() {
			if name == "." {
				if err := tree.counter.AddEntry(0); err != nil {
					return err
				}
				continue
			}
			if !filepath.IsLocal(name) {
				return fmt.Errorf("zip entry %q is not a local path", file.Name)
			}
			if err := tree.addDir(name); err != nil {
				return err
			}
			continue
		}
		if !filepath.IsLocal(name) {
			return fmt.Errorf("zip entry %q is not a local path", file.Name)
		}
		if err := tree.addDir(filepath.Dir(name)); err != nil {
			return err
		}
		if file.UncompressedSize64 > math.MaxInt64 {
			return fmt.Errorf("zip entry %q is too large", file.Name)
		}
		size := int64(file.UncompressedSize64)
		if err := tree.counter.AddEntry(size); err != nil {
			return err
		}
		if exceedsExpansionRatio(size, int64(file.CompressedSize64), maxEntryExpansionRatio) {
			return fmt.Errorf(
				"zip entry %q: %w",
				file.Name,
				expansionRatioError(
					"entry_expansion_ratio", size, int64(file.CompressedSize64), maxEntryExpansionRatio,
				),
			)
		}
	}
	return nil
}

func expansionRatioError(limit string, expanded, compressed, maximum int64) error {
	measured := expanded
	if compressed > 0 {
		measured = (expanded + compressed - 1) / compressed
	}
	return &BudgetExceededError{
		Gate:     "stream",
		Limit:    limit,
		Maximum:  maximum,
		Measured: measured,
	}
}

// exceedsStreamExpansionRatio applies the ratio check mid-stream, once enough
// output has been produced for the measurement to be meaningful. The final,
// unconditional check still runs when the stream ends.
func exceedsStreamExpansionRatio(expanded, compressed, ratio int64) bool {
	if expanded < minStreamRatioBytes {
		return false
	}
	return exceedsExpansionRatio(expanded, compressed, ratio)
}

func exceedsExpansionRatio(expanded, compressed, ratio int64) bool {
	if expanded <= 0 {
		return false
	}
	if compressed <= 0 {
		return true
	}
	if compressed > math.MaxInt64/ratio {
		return false
	}
	return expanded > compressed*ratio
}
