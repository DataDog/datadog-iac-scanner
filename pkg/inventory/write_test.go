/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package inventory

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWriteFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inventory.json")
	require.NoError(t, os.WriteFile(path, []byte("stale"), 0o600))

	inv := NewCollector(dir).Build(testMetadata())
	require.NoError(t, WriteFile(path, inv))

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var got Inventory
	require.NoError(t, json.Unmarshal(data, &got))
	require.Equal(t, inv.ScanID, got.ScanID)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1, "the temporary file must not be left behind")

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(filePerms), info.Mode().Perm())
	}
}

func TestWriteFileFailureLeavesNoFile(t *testing.T) {
	dir := t.TempDir()
	// The target is a directory, so the final rename fails.
	path := filepath.Join(dir, "inventory.json")
	require.NoError(t, os.MkdirAll(filepath.Join(path, "child"), 0o755))

	require.Error(t, WriteFile(path, NewCollector(dir).Build(testMetadata())))

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1, "only the directory that blocked the write remains")

	require.Error(t, WriteFile(filepath.Join(dir, "missing", "inventory.json"), &Inventory{}))
}

func TestRemoveStale(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inventory.json")

	require.NoError(t, RemoveStale(path), "a missing file is not an error")

	require.NoError(t, WriteFile(path, NewCollector(dir).Build(testMetadata())))
	require.NoError(t, RemoveStale(path))
	_, err := os.Stat(path)
	require.True(t, os.IsNotExist(err), "an earlier inventory is removed")

	// Anything else stays, such as a report or a scanned file.
	require.NoError(t, os.WriteFile(path, []byte(`{"version":"2.1.0","runs":[]}`), 0o600))
	require.ErrorIs(t, RemoveStale(path), ErrNotInventory)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, `{"version":"2.1.0","runs":[]}`, string(data))

	other := filepath.Join(dir, "dir")
	require.NoError(t, os.MkdirAll(filepath.Join(other, "child"), 0o755))
	require.ErrorIs(t, RemoveStale(other), ErrNotInventory)
}

func TestEncodeIsTheJSONOfTheInventory(t *testing.T) {
	c := NewCollector(t.TempDir())
	c.RecordFile("a.tf", "terraform", FileScanned, "")
	c.RecordFile("b<c>.yaml", "", FileFailed, ReasonParseError)
	c.AddUnresolvedSource(UnresolvedSource{Platform: "terraform", Source: "git::https://example.invalid/m.git?ref=a&depth=1", Reason: "network"})
	c.AddResource(&Resource{ResourcePath: "aws_s3_bucket.a", Platform: "terraform", ResourceType: "aws_s3_bucket",
		ResourceName: "a", File: "a.tf", LineStart: 1, LineEnd: 3, Completeness: CompletenessComplete, ModulePath: `[{"name":"x"}]`})
	c.AddResource(&Resource{ResourcePath: "v1/Service//web", Platform: "kubernetes", ResourceType: "Service",
		ResourceName: "web", File: "k.yaml", LineStart: 1, Completeness: CompletenessComplete, DocumentID: "doc"})
	c.AddFinding(&Finding{Fingerprint: "f", DocumentID: "doc"})
	full := c.Build(testMetadata())
	require.Len(t, full.FindingLinks, 1)
	for _, inv := range []*Inventory{full, NewCollector(t.TempDir()).Build(testMetadata())} {
		var want bytes.Buffer
		enc := json.NewEncoder(&want)
		enc.SetEscapeHTML(false)
		require.NoError(t, enc.Encode(inv))

		var got bytes.Buffer
		require.NoError(t, encode(&got, inv))
		require.Equal(t, want.String(), got.String())
	}
}
