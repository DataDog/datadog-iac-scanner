package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/stretchr/testify/require"
)

func TestModuleEntriesFromPathsListsDeclarationsWithoutFetching(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(`
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.0.0"
}
`), 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(root, ".terraform", "modules", "ignored"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, ".terraform", "modules", "ignored", "main.tf"), []byte(`
module "ignored" {
  source = "example/ignored/aws"
}
`), 0o644))

	entries, err := moduleEntriesFromPaths(t.Context(), []string{root}, false)
	require.NoError(t, err)
	require.Equal(t, []tfmodules.ListModuleEntry{{
		Name:          "vpc",
		Source:        "terraform-aws-modules/vpc/aws",
		Version:       "5.0.0",
		SourceType:    "registry",
		RegistryScope: "public",
		FileName:      "main.tf",
		DefLine:       2,
		DefEndLine:    5,
	}}, entries)
}

func TestWriteModuleEntriesEmitsJSONArray(t *testing.T) {
	var output bytes.Buffer
	require.NoError(t, writeModuleEntries(&output, []tfmodules.ListModuleEntry{{
		Name:       "vpc",
		Source:     "./modules/vpc",
		SourceType: "local",
		FileName:   "main.tf",
		DefLine:    1,
		DefEndLine: 3,
	}}))

	var entries []tfmodules.ListModuleEntry
	require.NoError(t, json.Unmarshal(output.Bytes(), &entries))
	require.Len(t, entries, 1)
	require.Equal(t, "vpc", entries[0].Name)
}

func TestModuleEntriesFromPathsFollowsSymlinkedRoot(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "repo")
	require.NoError(t, os.MkdirAll(root, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(`
module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
}
`), 0o644))

	link := filepath.Join(base, "repo-link")
	require.NoError(t, os.Symlink(root, link))

	entries, err := moduleEntriesFromPaths(t.Context(), []string{link}, false)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Equal(t, "vpc", entries[0].Name)
	require.Equal(t, "main.tf", entries[0].FileName)
}
