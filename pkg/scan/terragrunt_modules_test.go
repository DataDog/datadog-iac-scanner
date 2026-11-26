package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/resolver"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeUnits(t *testing.T, files map[string]string) (root string, paths []string) {
	t.Helper()
	root = writeRepo(t, files)
	for name := range files {
		if filepath.Base(name) == "terragrunt.hcl" {
			paths = append(paths, filepath.Join(root, filepath.FromSlash(name)))
		}
	}
	return root, paths
}

// Units with a module block become calls (the module graph drops local ones),
// named and located like the block, with Terragrunt registry URLs rewritten.
func TestTerragruntModuleCalls(t *testing.T) {
	root, paths := writeUnits(t, map[string]string{
		"a/terragrunt.hcl": "terraform {\n  source = \"tfr:///terraform-aws-modules/vpc/aws?version=5.0.0\"\n}\n",
		"b/terragrunt.hcl": "terraform {\n  source = \"git::https://example.invalid/m.git//x?ref=v1\"\n}\n",
		"c/terragrunt.hcl": "terraform {\n  source = \"../modules/m\"\n}\n",
		"d/terragrunt.hcl": "inputs = { a = 1 }\n",
		"e/terragrunt.hcl": "terraform {\n  source = get_env(\"X\")\n}\n",
		"f/terragrunt.hcl": "terraform {\n  source = \"tfr://registry.example.invalid/ns/name/aws//sub?version=1.2.3\"\n}\n",
	})

	calls := terragruntModuleCalls(t.Context(), vfs.DiskFS{}, root, paths)

	bySource := map[string]int{}
	for i, c := range calls {
		bySource[c.Source] = i
		assert.Equal(t, "terragrunt", c.Name)
		assert.False(t, c.IsLocal)
	}
	require.Len(t, calls, 4, "%v", bySource)

	reg := calls[bySource["terraform-aws-modules/vpc/aws"]]
	assert.Equal(t, "5.0.0", reg.Version)
	assert.Equal(t, "registry", reg.SourceType)
	assert.Equal(t, filepath.Join(root, "a"), filepath.Dir(reg.FileName))
	assert.Equal(t, 2, reg.DefLine)

	host := calls[bySource["registry.example.invalid/ns/name/aws//sub"]]
	assert.Equal(t, "1.2.3", host.Version)

	git := calls[bySource["git::https://example.invalid/m.git//x?ref=v1"]]
	assert.Empty(t, git.Version)
	assert.Equal(t, "git", git.SourceType)
}

// A repository with only Terragrunt units and no .tf file: with the flag, the
// pre-scan fetches the unit's module and the scan reports its resources;
// without it the unit is not seen.
func TestScanTerragruntOnlyRepositoryFetchesRemoteModule(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		root := t.TempDir()
		moduleDir := filepath.Join(filepath.Dir(root), "downloaded-vpc")
		require.NoError(t, os.MkdirAll(moduleDir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(moduleDir, "main.tf"), []byte(`
variable "cidr" {}
resource "aws_vpc" "this" {
  cidr_block = var.cidr
}
`), 0o644))
		if !enabled { // keep one scannable file, so the scan has input
			require.NoError(t, os.WriteFile(filepath.Join(root, "other.tf"), []byte("resource \"null_resource\" \"x\" {}\n"), 0o644))
		}
		unitDir := filepath.Join(root, "live")
		require.NoError(t, os.MkdirAll(unitDir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(unitDir, "terragrunt.hcl"), []byte(`terraform {
  source = "tfr:///terraform-aws-modules/vpc/aws?version=5.0.0"
}

inputs = {
  cidr = "10.0.0.0/16"
}
`), 0o644))
		manifestPath := filepath.Join(root, "modules.json")
		data, err := json.Marshal(resolver.Manifest{Modules: map[string]resolver.ManifestEntry{
			"terraform-aws-modules/vpc/aws@5.0.0": {LocalPath: moduleDir, Version: "5.0.0"},
		}})
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(manifestPath, data, 0o644))

		params := remoteModuleScanParams(root)
		params.TerraformModules = TerraformModulesOn
		params.RemoteModulesManifestPath = manifestPath
		params.ShouldScanTerragrunt = enabled

		results, client := executeRemoteModuleScanClient(t, params)
		if !enabled {
			assert.Empty(t, results.Results)
			continue
		}
		require.NotEmpty(t, results.Results)
		// The parser finds the unit's fetched module in the pre-scan's directories.
		assert.Equal(t, moduleDir,
			client.fetchedTerragruntModules(unitDir, "terraform-aws-modules/vpc/aws", "5.0.0"))
		assert.Equal(t, filepath.ToSlash(filepath.Join(moduleDir, "main.tf")), filepath.ToSlash(results.Results[0].FileName))
		// The engine found the fetched module from the unit: the finding comes from its instantiation.
		require.NotNil(t, results.Results[0].ModuleAttribution)
		assert.Equal(t, "live/terragrunt.hcl", results.Results[0].ModuleAttribution.CallSite.Filename)
		assert.Contains(t, results.Results[0].ModuleAttribution.Source, "terraform-aws-modules/vpc/aws")
		assert.Equal(t, "5.0.0", results.Results[0].ModuleAttribution.Version)
	}
}
