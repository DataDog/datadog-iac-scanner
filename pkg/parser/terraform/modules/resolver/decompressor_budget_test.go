/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCopySingleFileAcceptsMaxInt64Limit(t *testing.T) {
	t.Parallel()

	var dst bytes.Buffer
	src := bytes.NewBufferString("content")
	compressed := &countingReader{reader: src}

	written, err := copySingleFileWithBudget(
		&dst, compressed, compressed, math.MaxInt64, "file_bytes",
	)

	require.NoError(t, err)
	require.Equal(t, int64(len("content")), written)
	require.Equal(t, "content", dst.String())
}

func TestBudgetedZipRejectsEntryBeforeExtraction(t *testing.T) {
	t.Parallel()

	src := filepath.Join(t.TempDir(), "module.zip")
	file, err := os.Create(src)
	require.NoError(t, err)
	writer := zip.NewWriter(file)
	entry, err := writer.Create("main.tf")
	require.NoError(t, err)
	_, err = entry.Write(bytes.Repeat([]byte("0"), 64*1024))
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	require.NoError(t, file.Close())

	decompressor := limitedDecompressors(ResourceLimits{
		MaxPackageBytes: 128 * 1024,
		MaxFileBytes:    128 * 1024,
		MaxPackageFiles: 10,
	}, 128*1024)["zip"]
	dst := filepath.Join(t.TempDir(), "module")

	err = decompressor.Decompress(dst, src, true, 0)

	require.ErrorContains(t, err, "entry")
	require.ErrorContains(t, err, "entry_expansion_ratio")
	_, statErr := os.Stat(dst)
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestBudgetedZipCountsImplicitDirectories(t *testing.T) {
	t.Parallel()

	src := filepath.Join(t.TempDir(), "module.zip")
	file, err := os.Create(src)
	require.NoError(t, err)
	writer := zip.NewWriter(file)
	entry, err := writer.Create("one/two/three/main.tf")
	require.NoError(t, err)
	_, err = entry.Write([]byte("content"))
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	require.NoError(t, file.Close())

	decompressor := limitedDecompressors(ResourceLimits{
		MaxPackageBytes: 128,
		MaxFileBytes:    128,
		MaxPackageFiles: 3,
	}, 128)["zip"]
	dst := filepath.Join(t.TempDir(), "module")

	err = decompressor.Decompress(dst, src, true, 0)

	require.ErrorContains(t, err, "package_file_count")
	_, statErr := os.Stat(dst)
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestBudgetedTarRejectsFileBeforeWritingPastLimit(t *testing.T) {
	t.Parallel()

	src := filepath.Join(t.TempDir(), "module.tgz")
	file, err := os.Create(src)
	require.NoError(t, err)
	compressed := gzip.NewWriter(file)
	archive := tar.NewWriter(compressed)
	require.NoError(t, archive.WriteHeader(&tar.Header{
		Name:     "./",
		Mode:     0o755,
		Typeflag: tar.TypeDir,
	}))
	require.NoError(t, archive.WriteHeader(&tar.Header{
		Name: "main.tf",
		Mode: 0o600,
		Size: 7,
	}))
	_, err = archive.Write([]byte("content"))
	require.NoError(t, err)
	require.NoError(t, archive.Close())
	require.NoError(t, compressed.Close())
	require.NoError(t, file.Close())

	decompressor := limitedDecompressors(ResourceLimits{
		MaxPackageBytes: 128,
		MaxFileBytes:    3,
		MaxPackageFiles: 10,
	}, 128)["tgz"]
	dst := filepath.Join(t.TempDir(), "module")

	err = decompressor.Decompress(dst, src, true, 0)

	var budgetErr *BudgetExceededError
	require.ErrorAs(t, err, &budgetErr)
	require.Equal(t, "file_bytes", budgetErr.Limit)
	_, statErr := os.Stat(filepath.Join(dst, "main.tf"))
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestBudgetedSingleFileReportsPackageLimit(t *testing.T) {
	t.Parallel()

	src := filepath.Join(t.TempDir(), "module.gz")
	file, err := os.Create(src)
	require.NoError(t, err)
	compressed := gzip.NewWriter(file)
	_, err = compressed.Write([]byte("content"))
	require.NoError(t, err)
	require.NoError(t, compressed.Close())
	require.NoError(t, file.Close())
	dst := filepath.Join(t.TempDir(), "module.tf")
	decompressor := limitedDecompressors(ResourceLimits{
		MaxPackageBytes: 3,
		MaxFileBytes:    10,
	}, 3)["gz"]

	err = decompressor.Decompress(dst, src, false, 0)

	var budgetErr *BudgetExceededError
	require.ErrorAs(t, err, &budgetErr)
	require.Equal(t, "package_bytes", budgetErr.Limit)
	require.Equal(t, int64(3), budgetErr.Maximum)
	_, statErr := os.Stat(dst)
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestBudgetedTarCountsImplicitParentDirectories(t *testing.T) {
	t.Parallel()

	src := filepath.Join(t.TempDir(), "module.tgz")
	file, err := os.Create(src)
	require.NoError(t, err)
	compressed := gzip.NewWriter(file)
	archive := tar.NewWriter(compressed)
	// Only the leaf entries are present; the three directories holding them are
	// created implicitly and must still be charged to the file count.
	for _, name := range []string{"a/b/c/one.tf", "a/b/c/two.tf"} {
		require.NoError(t, archive.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: 1}))
		_, err = archive.Write([]byte("x"))
		require.NoError(t, err)
	}
	require.NoError(t, archive.Close())
	require.NoError(t, compressed.Close())
	require.NoError(t, file.Close())

	decompressor := limitedDecompressors(ResourceLimits{
		MaxPackageBytes: 128,
		MaxFileBytes:    128,
		MaxPackageFiles: 4,
	}, 128)["tgz"]

	err = decompressor.Decompress(filepath.Join(t.TempDir(), "module"), src, true, 0)

	var budgetErr *BudgetExceededError
	require.ErrorAs(t, err, &budgetErr)
	require.Equal(t, "package_file_count", budgetErr.Limit)
	require.Equal(t, int64(4), budgetErr.Maximum)
}

func TestBudgetedTarAcceptsArchiveWithHighlyCompressedPrefix(t *testing.T) {
	t.Parallel()

	src := filepath.Join(t.TempDir(), "module.tgz")
	file, err := os.Create(src)
	require.NoError(t, err)
	compressed := gzip.NewWriter(file)
	archive := tar.NewWriter(compressed)
	// Zero-filled leading entries compress far better than the ratio limit, but
	// the archive as a whole stays well inside it.
	require.NoError(t, archive.WriteHeader(&tar.Header{Name: "zeros.bin", Mode: 0o600, Size: 4096}))
	_, err = archive.Write(make([]byte, 4096))
	require.NoError(t, err)
	body := make([]byte, 256*1024)
	_, err = rand.Read(body)
	require.NoError(t, err)
	require.NoError(t, archive.WriteHeader(&tar.Header{
		Name: "main.tf", Mode: 0o600, Size: int64(len(body)),
	}))
	_, err = archive.Write(body)
	require.NoError(t, err)
	require.NoError(t, archive.Close())
	require.NoError(t, compressed.Close())
	require.NoError(t, file.Close())

	decompressor := limitedDecompressors(ResourceLimits{
		MaxPackageBytes: 1024 * 1024,
		MaxFileBytes:    1024 * 1024,
		MaxPackageFiles: 10,
	}, 1024*1024)["tgz"]
	dst := filepath.Join(t.TempDir(), "module")

	require.NoError(t, decompressor.Decompress(dst, src, true, 0))
	extracted, err := os.ReadFile(filepath.Join(dst, "main.tf"))
	require.NoError(t, err)
	require.Equal(t, body, extracted)
}

func TestBudgetedTarRejectsRatioAtEndOfSmallArchive(t *testing.T) {
	t.Parallel()

	src := filepath.Join(t.TempDir(), "module.tgz")
	file, err := os.Create(src)
	require.NoError(t, err)
	compressed := gzip.NewWriter(file)
	archive := tar.NewWriter(compressed)
	// The archive expands well past the ratio limit, but stays small enough
	// that the mid-stream check never runs, so only the check at the end of the
	// stream can catch it.
	for i := range 64 {
		require.NoError(t, archive.WriteHeader(&tar.Header{
			Name: fmt.Sprintf("file%02d.tf", i), Mode: 0o600, Size: 1024,
		}))
		_, err = archive.Write(make([]byte, 1024))
		require.NoError(t, err)
	}
	require.NoError(t, archive.Close())
	require.NoError(t, compressed.Close())
	require.NoError(t, file.Close())

	decompressor := limitedDecompressors(ResourceLimits{
		MaxPackageBytes: 1024 * 1024,
		MaxFileBytes:    1024 * 1024,
		MaxPackageFiles: 128,
	}, 1024*1024)["tgz"]

	err = decompressor.Decompress(filepath.Join(t.TempDir(), "module"), src, true, 0)

	require.ErrorContains(t, err, "archive_expansion_ratio")
}
