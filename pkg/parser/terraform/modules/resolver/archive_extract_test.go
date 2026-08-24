/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

type tarEntry struct {
	name     string
	typeflag byte
	body     string
	linkname string
}

func extractTestArchive(r *bytes.Reader, dest string) error {
	extracted := int64(0)
	return extractRegularFilesWithBudget(r, dest, &extracted)
}

func tarBytes(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, entry := range entries {
		require.NoError(t, writer.WriteHeader(&tar.Header{
			Name:     entry.name,
			Typeflag: entry.typeflag,
			Mode:     0o644,
			Size:     int64(len(entry.body)),
			Linkname: entry.linkname,
		}))
		if entry.body != "" {
			_, err := writer.Write([]byte(entry.body))
			require.NoError(t, err)
		}
	}
	require.NoError(t, writer.Close())
	return buffer.Bytes()
}

func TestExtractRegularFiles(t *testing.T) {
	dest := t.TempDir()
	archive := tarBytes(t,
		tarEntry{name: "modules/", typeflag: tar.TypeDir},
		tarEntry{name: "modules/vpc/main.tf", typeflag: tar.TypeReg, body: `resource "x" "y" {}`},
	)

	require.NoError(t, extractTestArchive(bytes.NewReader(archive), dest))
	data, err := os.ReadFile(filepath.Join(dest, "modules", "vpc", "main.tf"))
	require.NoError(t, err)
	require.Equal(t, `resource "x" "y" {}`, string(data))
}

func TestExtractRegularFilesSkipsNonRegularEntries(t *testing.T) {
	dest := t.TempDir()
	archive := tarBytes(t,
		tarEntry{name: "main.tf", typeflag: tar.TypeReg, body: `resource "x" "y" {}`},
		tarEntry{name: "linked.tf", typeflag: tar.TypeSymlink, linkname: "/etc/passwd"},
		tarEntry{name: "hard.tf", typeflag: tar.TypeLink, linkname: "main.tf"},
		tarEntry{name: "dev.tf", typeflag: tar.TypeChar},
	)

	require.NoError(t, extractTestArchive(bytes.NewReader(archive), dest))
	_, err := os.Lstat(filepath.Join(dest, "linked.tf"))
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.Lstat(filepath.Join(dest, "hard.tf"))
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.ReadFile(filepath.Join(dest, "main.tf"))
	require.NoError(t, err)
}

func TestExtractRegularFilesRejectsEscapingPaths(t *testing.T) {
	parent := t.TempDir()
	dest := filepath.Join(parent, "extract")
	require.NoError(t, os.Mkdir(dest, 0o755))

	for _, name := range []string{"../outside.tf", "modules/../../outside.tf", "/absolute.tf"} {
		t.Run(name, func(t *testing.T) {
			archive := tarBytes(t, tarEntry{name: name, typeflag: tar.TypeReg, body: "content"})
			require.ErrorContains(t, extractTestArchive(bytes.NewReader(archive), dest), "is not a local path")
			_, err := os.Stat(filepath.Join(parent, "outside.tf"))
			require.ErrorIs(t, err, os.ErrNotExist)
		})
	}
}
