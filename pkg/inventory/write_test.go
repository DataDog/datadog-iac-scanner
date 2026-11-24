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

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

func TestWriteFileCreatesItsDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out", "inventory.json")
	require.NoError(t, WriteFile(path, NewCollector(t.TempDir()).Build(testMetadata())))
	require.FileExists(t, path)

	// A directory cannot be made where a file is, such as a report.
	report := filepath.Join(t.TempDir(), "result.sarif")
	require.NoError(t, os.WriteFile(report, []byte("{}"), 0o600))
	require.Error(t, WriteFile(filepath.Join(report, "inventory.json"), NewCollector(t.TempDir()).Build(testMetadata())))
	data, err := os.ReadFile(report)
	require.NoError(t, err)
	require.Equal(t, "{}", string(data), "the report stays as it was")
}

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

	// Nor is a file that only starts like one: the whole header is checked.
	for _, content := range []string{
		`{"schema_version":2,"settings":{"keep":"this is not scanner inventory"}}`,
		`{"schema_version":"1","settings":{"keep":"no scan id"}}`,
		`{"schema_version":"1","scan_id":"s","scanner_version":"v","scanned_at":3}`,
	} {
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
		require.ErrorIs(t, RemoveStale(path), ErrNotInventory, content)
		data, err = os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, content, string(data))
	}

	other := filepath.Join(dir, "dir")
	require.NoError(t, os.MkdirAll(filepath.Join(other, "child"), 0o755))
	require.ErrorIs(t, RemoveStale(other), ErrNotInventory)

	if runtime.GOOS == "windows" {
		return
	}
	// Through a symlink then "..", the file checked is the file removed: the
	// system resolves the link before "..", the cleaned path does not.
	base, elsewhere := t.TempDir(), t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(elsewhere, "sub"), 0o755))
	require.NoError(t, os.Symlink(filepath.Join(elsewhere, "sub"), filepath.Join(base, "link")))
	genuine := filepath.Join(base, "inventory.json")
	require.NoError(t, WriteFile(genuine, NewCollector(base).Build(testMetadata())))
	settings := filepath.Join(elsewhere, "inventory.json")
	require.NoError(t, os.WriteFile(settings, []byte(`{"keep":"these settings"}`), 0o600))
	aliased := base + string(filepath.Separator) + "link" + string(filepath.Separator) + ".." + string(filepath.Separator) + "inventory.json"

	require.ErrorIs(t, RemoveStale(aliased), ErrNotInventory)
	data, err = os.ReadFile(settings)
	require.NoError(t, err)
	require.Equal(t, `{"keep":"these settings"}`, string(data), "the file the path reaches is not an inventory")
	require.FileExists(t, genuine, "nor is the one its cleaned spelling names removed")
}

func TestResolvePath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	sep := string(filepath.Separator)
	require.NoError(t, os.MkdirAll(filepath.Join(root, "out", "sub"), 0o755))
	require.NoError(t, os.Symlink(filepath.Join(root, "out", "sub"), filepath.Join(root, "link")))
	require.NoError(t, os.Symlink("inventory.json", filepath.Join(root, "out", "dangling")))

	for path, want := range map[string]string{
		root + sep + "link" + sep + ".." + sep + "inventory.json": filepath.Join(root, "out", "inventory.json"),
		root + sep + "link" + sep + "new" + sep + "file.json":     filepath.Join(root, "out", "sub", "new", "file.json"),
		root + sep + "missing" + sep + ".." + sep + "x.json":      filepath.Join(root, "x.json"),
	} {
		got, err := ResolvePath(path, false)
		require.NoError(t, err)
		require.Equal(t, want, got, path)
	}
	dangling := filepath.Join(root, "out", "dangling")
	got, err := ResolvePath(dangling, false)
	require.NoError(t, err)
	require.Equal(t, dangling, got, "a rename or a removal acts on the link itself")
	got, err = ResolvePath(dangling, true)
	require.NoError(t, err)
	require.Equal(t, filepath.Join(root, "out", "inventory.json"), got, "a write follows it, though it points nowhere yet")

	require.NoError(t, os.Symlink("loop", filepath.Join(root, "loop")))
	_, err = ResolvePath(filepath.Join(root, "loop", "x"), true)
	require.Error(t, err)
}

func TestResolvePathWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows path forms")
	}
	t.Chdir(t.TempDir())
	wd, err := os.Getwd()
	require.NoError(t, err)
	volume := filepath.VolumeName(wd)
	file := filepath.Join(wd, "file.json")
	// A UNC share root exercises volume parsing without accessing a network share.
	const uncRoot = `\\server\share\`
	for _, tt := range []struct{ name, path, want string }{
		{"rooted", file[len(volume):], file},
		{"rooted with a forward slash", filepath.ToSlash(file[len(volume):]), file},
		{"drive-relative", volume + "file.json", file},
		{"absolute", file, file},
		{"UNC", uncRoot, uncRoot},
		{"relative", "file.json", file},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolvePath(tt.path, true)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestEncodeIsTheJSONOfTheInventory(t *testing.T) {
	c := NewCollector(t.TempDir())
	c.RecordFile("a.tf", "terraform", FileScanned, "")
	c.RecordFile("b<c>.yaml", "", FileFailed, ReasonParseError)
	c.AddUnresolvedSource(UnresolvedSource{Platform: "terraform", Source: "git::https://example.invalid/m.git?ref=a&depth=1", Reason: "network"})
	c.AddResource(&Resource{ResourcePath: "aws_s3_bucket.a", Platform: "terraform", ResourceType: "aws_s3_bucket",
		ResourceName: "a", File: "a.tf", LineStart: 1, LineEnd: 3, Completeness: CompletenessComplete, ModulePath: `[{"name":"x"}]`})
	o := &model.ResourceOccurrence{ResourcePath: "v1/Service//web", Platform: "kubernetes", ResourceType: "Service",
		ResourceName: "web", File: "k.yaml", Source: model.ResourceLocation{Start: model.ResourceLine{Line: 1}}}
	row := ProjectResource(o)
	c.AddResource(&row)
	c.AddFinding(&Finding{Fingerprint: "f", Occurrences: []*model.ResourceOccurrence{o}})
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
