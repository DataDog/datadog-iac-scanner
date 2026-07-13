package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/stretchr/testify/require"
)

func TestCollectTerraformFilesForModuleListing(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "modules", "child")
	cache := filepath.Join(root, ".terraform", "modules", "cached")
	require.NoError(t, os.MkdirAll(child, 0o755))
	require.NoError(t, os.MkdirAll(cache, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(`
module "remote" {
  source = "registry.example.com/acme/network/aws"
}
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(child, "main.tf"), []byte(`
module "local" {
  source = "../other"
}
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(cache, "main.tf"), []byte(`
module "ignored" {
  source = "registry.example.com/acme/ignored/aws"
}
`), 0o644))

	files, err := collectTerraformFiles([]string{root})
	require.NoError(t, err)
	require.Len(t, files, 2)

	modules, err := tfmodules.ParseTerraformModulesFromFiles(
		context.Background(),
		nil,
		files,
		allowedModuleFiles([]string{root}, files),
	)
	require.NoError(t, err)
	entries := tfmodules.ListModuleEntries(modules, true)
	require.Len(t, entries, 2)
	require.Equal(t, "local", entries[0].Name)
	require.Equal(t, "remote", entries[1].Name)
}
