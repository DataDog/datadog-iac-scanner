package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
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

	files, err := collectTerraformFiles([]string{root}, false)
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

func TestDirectModuleDiscoveryFollowsOnlyReachableLocalModules(t *testing.T) {
	root := t.TempDir()
	reachable := filepath.Join(root, "modules", "reachable")
	unreachable := filepath.Join(root, "examples", "unreachable")
	testModule := filepath.Join(root, "test", "fixture")
	for _, dir := range []string{reachable, unreachable, testModule} {
		require.NoError(t, os.MkdirAll(dir, 0o755))
	}
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(`
module "reachable" {
  source = "./modules/reachable"
}
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(reachable, "main.tf"), []byte(`
module "remote_child" {
  source = "registry.example.com/acme/child/aws"
}
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(unreachable, "main.tf"), []byte(`
module "example_remote" {
  source = "registry.example.com/acme/example/aws"
}
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(testModule, "main.tf"), []byte(`
module "test_remote" {
  source = "registry.example.com/acme/test/aws"
}
`), 0o644))

	files, allowed, err := collectModuleDiscoveryFiles(t.Context(), []string{root}, true)
	require.NoError(t, err)
	require.Len(t, files, 2)

	modules, err := tfmodules.ParseTerraformModulesFromFiles(t.Context(), nil, files, allowed)
	require.NoError(t, err)
	entries := tfmodules.ListModuleEntries(modules, true)
	require.Equal(t, []string{"reachable", "remote_child"}, []string{entries[0].Name, entries[1].Name})
}

func TestDirectModuleDiscoveryHandlesLocalCycles(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "child")
	require.NoError(t, os.MkdirAll(child, 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(root, "main.tf"),
		[]byte(`module "child" { source = "./child" }`),
		0o644,
	))
	require.NoError(t, os.WriteFile(
		filepath.Join(child, "main.tf"),
		[]byte(`module "root" { source = ".." }`),
		0o644,
	))

	files, _, err := collectModuleDiscoveryFiles(t.Context(), []string{root}, true)
	require.NoError(t, err)
	require.Len(t, files, 2)
}

func TestDirectModuleDiscoveryParsesEachFrontierOnce(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "child")
	grandchild := filepath.Join(child, "grandchild")
	require.NoError(t, os.MkdirAll(grandchild, 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(root, "main.tf"),
		[]byte(`module "child" { source = "./child" }`),
		0o644,
	))
	require.NoError(t, os.WriteFile(
		filepath.Join(child, "main.tf"),
		[]byte(`module "grandchild" { source = "./grandchild" }`),
		0o644,
	))
	require.NoError(t, os.WriteFile(filepath.Join(grandchild, "main.tf"), []byte("# leaf"), 0o644))
	files, err := collectTerraformFiles([]string{root}, true)
	require.NoError(t, err)
	allowed := allowedModuleFiles([]string{root}, files)
	var frontierSizes []int

	discovered, _, err := collectReachableModuleDiscoveryFilesWithParser(
		[]string{root},
		files,
		allowed,
		func(frontier model.FileMetadatas, frontierAllowed map[string]bool) (map[string]tfmodules.ParsedModule, error) {
			frontierSizes = append(frontierSizes, len(frontier))
			return tfmodules.ParseTerraformModulesFromFiles(t.Context(), nil, frontier, frontierAllowed)
		},
	)

	require.NoError(t, err)
	require.Len(t, discovered, 3)
	require.Equal(t, []int{1, 1, 1}, frontierSizes)
}

func TestDirectModuleDiscoveryRejectsSymlinkedModulesOutsideRoot(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	require.NoError(t, os.WriteFile(
		filepath.Join(outside, "main.tf"),
		[]byte(`module "escaped" { source = "registry.example.com/acme/escaped/aws" }`),
		0o644,
	))
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "escaped")))
	require.NoError(t, os.WriteFile(
		filepath.Join(root, "main.tf"),
		[]byte(`module "outside" { source = "./escaped" }`),
		0o644,
	))

	files, allowed, err := collectModuleDiscoveryFiles(t.Context(), []string{root}, true)

	require.NoError(t, err)
	require.Len(t, files, 1)
	modules, err := tfmodules.ParseTerraformModulesFromFiles(t.Context(), nil, files, allowed)
	require.NoError(t, err)
	entries := tfmodules.ListModuleEntries(modules, true)
	require.Len(t, entries, 1)
	require.Equal(t, "outside", entries[0].Name)
}
