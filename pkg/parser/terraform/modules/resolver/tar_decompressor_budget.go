/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"archive/tar"
	"bufio"
	"compress/bzip2"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

type archiveReaderFunc func(io.Reader) (io.Reader, func(), error)

type tarBudgetDecompressor struct {
	limits ResourceLimits
	open   archiveReaderFunc
}

type singleFileBudgetDecompressor struct {
	maxFileBytes int64
	limitName    string
	open         archiveReaderFunc
}

const (
	decompressionCopyBufferSize = 32 * 1024
	decompressedFilePerm        = 0o622
)

func (d *singleFileBudgetDecompressor) Decompress(
	dst, src string, _ bool, umask os.FileMode,
) error {
	source, err := os.Open(src) //nolint:gosec
	if err != nil {
		return err
	}
	defer func() { _ = source.Close() }()
	compressed := &countingReader{reader: source}
	reader, closeReader, err := d.open(compressed)
	if err != nil {
		return err
	}
	defer closeReader()

	if err := os.MkdirAll(filepath.Dir(dst), dirPerm&^umask); err != nil {
		return err
	}
	file, err := os.OpenFile( //nolint:gosec
		dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, decompressedFilePerm&^umask,
	)
	if err != nil {
		return err
	}
	written, copyErr := copySingleFileWithBudget(
		file, reader, compressed, d.maxFileBytes, d.limitName,
	)
	closeErr := file.Close()
	if copyErr != nil {
		_ = os.Remove(dst)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(dst)
		return closeErr
	}
	if exceedsExpansionRatio(written, compressed.read, maxArchiveExpansionRatio) {
		_ = os.Remove(dst)
		return expansionRatioError(
			"archive_expansion_ratio", written, compressed.read, maxArchiveExpansionRatio,
		)
	}
	return nil
}

func copySingleFileWithBudget(
	dst io.Writer, src io.Reader, compressed *countingReader, maximum int64, limitName string,
) (int64, error) {
	buffer := make([]byte, decompressionCopyBufferSize)
	var written int64
	for {
		readBuffer := buffer
		if maximum > 0 {
			remaining := maximum - written
			if remaining < int64(len(readBuffer)) {
				readBuffer = readBuffer[:remaining+1]
			}
		}
		n, err := src.Read(readBuffer)
		if maximum > 0 && written+int64(n) > maximum {
			return written, &BudgetExceededError{
				Gate:     "stream",
				Limit:    limitName,
				Maximum:  maximum,
				Measured: written + int64(n),
			}
		}
		if n > 0 {
			count, writeErr := dst.Write(readBuffer[:n])
			written += int64(count)
			if writeErr != nil {
				return written, writeErr
			}
			if count != n {
				return written, io.ErrShortWrite
			}
			if exceedsStreamExpansionRatio(written, compressed.read, maxArchiveExpansionRatio) {
				return written, expansionRatioError(
					"archive_expansion_ratio", written, compressed.read, maxArchiveExpansionRatio,
				)
			}
		}
		if err == io.EOF {
			return written, nil
		}
		if err != nil {
			return written, err
		}
	}
}

func (d *tarBudgetDecompressor) Decompress(dst, src string, dir bool, umask os.FileMode) error {
	if !dir {
		return fmt.Errorf("tar module archive requires a directory destination")
	}
	source, err := os.Open(src) //nolint:gosec
	if err != nil {
		return err
	}
	defer func() { _ = source.Close() }()

	compressed := &countingReader{reader: source}
	reader, closeReader, err := d.open(compressed)
	if err != nil {
		return err
	}
	defer closeReader()

	if err := os.MkdirAll(dst, dirPerm&^umask); err != nil {
		return err
	}
	state := newPackageTreeCounter(NewResourceBudget(d.limits).NewPackageCounter())
	archive := tar.NewReader(reader)
	for {
		header, nextErr := archive.Next()
		if nextErr == io.EOF {
			return tarFinalRatioError(state.counter, compressed)
		}
		if nextErr != nil {
			return nextErr
		}
		if err := extractTarBudgetEntry(archive, header, dst, umask, state, compressed); err != nil {
			return err
		}
	}
}

func tarFinalRatioError(counter *PackageCounter, compressed *countingReader) error {
	if !exceedsExpansionRatio(counter.Usage().Bytes, compressed.read, maxArchiveExpansionRatio) {
		return nil
	}
	return expansionRatioError(
		"archive_expansion_ratio", counter.Usage().Bytes, compressed.read, maxArchiveExpansionRatio,
	)
}

func extractTarBudgetEntry(
	archive *tar.Reader,
	header *tar.Header,
	dst string,
	umask os.FileMode,
	state *packageTreeCounter,
	compressed *countingReader,
) error {
	name := filepath.Clean(header.Name)
	if name == "." && header.Typeflag == tar.TypeDir {
		return state.counter.AddEntry(0)
	}
	if name == "." || !filepath.IsLocal(name) {
		return fmt.Errorf("tar entry %q is not a local path", header.Name)
	}
	path := filepath.Join(dst, name)
	switch header.Typeflag {
	case tar.TypeDir:
		if err := state.addDir(name); err != nil {
			return err
		}
		return os.MkdirAll(path, header.FileInfo().Mode().Perm()&^umask)
	case tar.TypeReg, 0:
		if err := state.addDir(filepath.Dir(name)); err != nil {
			return err
		}
		if err := state.counter.AddEntry(header.Size); err != nil {
			return err
		}
		if err := writeTarBudgetFile(archive, path, header, umask); err != nil {
			return err
		}
		if exceedsStreamExpansionRatio(
			state.counter.Usage().Bytes, compressed.read, maxArchiveExpansionRatio,
		) {
			return expansionRatioError(
				"archive_expansion_ratio",
				state.counter.Usage().Bytes,
				compressed.read,
				maxArchiveExpansionRatio,
			)
		}
		return nil
	case tar.TypeXHeader, tar.TypeXGlobalHeader:
		return nil
	default:
		return fmt.Errorf("tar entry %q has unsupported type %d", header.Name, header.Typeflag)
	}
}

func writeTarBudgetFile(
	archive *tar.Reader, path string, header *tar.Header, umask os.FileMode,
) error {
	if err := os.MkdirAll(filepath.Dir(path), dirPerm&^umask); err != nil {
		return err
	}
	file, err := os.OpenFile( //nolint:gosec
		path,
		os.O_CREATE|os.O_EXCL|os.O_WRONLY,
		header.FileInfo().Mode().Perm()&^umask,
	)
	if err != nil {
		return err
	}
	_, copyErr := io.CopyN(file, archive, header.Size)
	closeErr := file.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

type countingReader struct {
	reader io.Reader
	read   int64
}

func (r *countingReader) Read(buffer []byte) (int, error) {
	n, err := r.reader.Read(buffer)
	r.read += int64(n)
	return n, err
}

func rawArchiveReader(reader io.Reader) (io.Reader, func(), error) {
	return reader, func() {}, nil
}

func gzipArchiveReader(reader io.Reader) (io.Reader, func(), error) {
	archive, err := gzip.NewReader(reader)
	if err != nil {
		return nil, func() {}, err
	}
	return archive, func() { _ = archive.Close() }, nil
}

func bzip2ArchiveReader(reader io.Reader) (io.Reader, func(), error) {
	return bzip2.NewReader(reader), func() {}, nil
}

func xzArchiveReader(reader io.Reader) (io.Reader, func(), error) {
	archive, err := xz.NewReader(bufio.NewReader(reader))
	return archive, func() {}, err
}

func zstdArchiveReader(reader io.Reader) (io.Reader, func(), error) {
	archive, err := zstd.NewReader(reader)
	if err != nil {
		return nil, func() {}, err
	}
	return archive, archive.Close, nil
}
