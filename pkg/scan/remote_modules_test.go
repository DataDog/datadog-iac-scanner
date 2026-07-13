package scan

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	engineprovider "github.com/DataDog/datadog-iac-scanner/pkg/engine/provider"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/resolver"
	consolePrinter "github.com/DataDog/datadog-iac-scanner/pkg/printer"
	"github.com/stretchr/testify/require"
)

func TestRemoteModulesDisabledByDefault(t *testing.T) {
	root := t.TempDir()
	_, manifestPath := writeRemoteModuleFixture(t, root)

	params := remoteModuleScanParams(root)
	params.RemoteModulesManifestPath = manifestPath
	params.EnableRemoteModules = false

	results := executeRemoteModuleScan(t, params)
	require.Empty(t, results.Results)
}

func TestRemoteModulesManifestEnablesModuleInstantiation(t *testing.T) {
	root := t.TempDir()
	moduleDir, manifestPath := writeRemoteModuleFixture(t, root)

	params := remoteModuleScanParams(root)
	params.EnableRemoteModules = true
	params.RemoteModulesManifestPath = manifestPath

	results := executeRemoteModuleScan(t, params)
	require.NotEmpty(t, results.Results)
	require.Equal(t, filepath.ToSlash(filepath.Join(moduleDir, "main.tf")), filepath.ToSlash(results.Results[0].FileName))
}

func TestRemoteModuleFilesBypassPrebuiltInventoryFilters(t *testing.T) {
	root := t.TempDir()
	moduleDir, _ := writeRemoteModuleFixture(t, root)
	rootFile := filepath.Join(root, "main.tf")
	moduleFile := filepath.Join(moduleDir, "main.tf")

	files, err := engineprovider.NewFileSystemSourceProvider(
		context.Background(), []string{root}, nil, []string{root},
	)
	require.NoError(t, err)
	files.SetPrebuiltWalk([]string{rootFile}, nil, nil)
	files.AddUnfilteredPaths([]string{moduleFile})

	inventory, err := files.BuildInventoryFromPrebuilt(
		context.Background(),
		model.Extensions{".tf": {}},
		func(context.Context, string) bool { return false },
	)
	require.NoError(t, err)
	paths := make([]string, 0, len(inventory))
	for _, file := range inventory {
		paths = append(paths, file.Path)
	}
	require.ElementsMatch(t, []string{filepath.ToSlash(rootFile), filepath.ToSlash(moduleFile)}, paths)
}

func writeRemoteModuleFixture(t *testing.T, root string) (string, string) {
	t.Helper()
	moduleDir := filepath.Join(filepath.Dir(root), "downloaded-vpc")
	require.NoError(t, os.MkdirAll(moduleDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(moduleDir, "main.tf"), []byte(`
variable "cidr" {}
resource "aws_vpc" "this" {
  cidr_block = var.cidr
}
`), 0o644))

	rootFile := filepath.Join(root, "main.tf")
	require.NoError(t, os.WriteFile(rootFile, []byte(`
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.0.0"
  cidr    = "10.0.0.0/16"
}
`), 0o644))

	manifestPath := filepath.Join(root, "modules.json")
	manifest := resolver.Manifest{
		Modules: map[string]resolver.ManifestEntry{
			"terraform-aws-modules/vpc/aws@5.0.0": {LocalPath: moduleDir, Version: "5.0.0"},
		},
	}
	data, err := json.Marshal(manifest)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(manifestPath, data, 0o644))
	return moduleDir, manifestPath
}

func remoteModuleScanParams(root string) *Parameters {
	return &Parameters{
		Path:                    []string{root},
		PreviewLines:            3,
		CloudProvider:           []string{"aws"},
		Platform:                []string{"Terraform"},
		RepoPath:                root,
		QueriesPath:             []string{root},
		ChangedDefaultQueryPath: true,
		ScanID:                  "remote-module-test",
		MaxFileSizeFlag:         100,
		MaxResolverDepth:        15,
		FlagEvaluator: featureflags.NewLocalEvaluatorWithOverrides(map[string]bool{
			featureflags.IacEnableLocalModuleEval: true,
		}),
	}
}

func executeRemoteModuleScan(t *testing.T, params *Parameters) *Results {
	t.Helper()
	ctx := context.Background()
	client, err := NewClient(ctx, params, &consolePrinter.Printer{})
	require.NoError(t, err)
	client.querySourceFactory = func(_ context.Context, _ []string) (source.QueriesSource, error) {
		return &stubQuerySource{queries: []model.QueryMetadata{{
			Query: "remote-module-vpc-rule",
			Content: `package datadog

DatadogPolicy contains result if {
	input.document[i].resource.aws_vpc[name]
	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_vpc",
		"resourceName": name,
		"searchKey": sprintf("aws_vpc[%s]", [name]),
	}
}`,
			InputData: "{}",
			Platform:  "terraform",
			Metadata: map[string]interface{}{
				"id":        "remote-module-vpc-rule",
				"legacyId":  "remote-module-vpc-rule",
				"queryName": "Remote Module VPC Rule",
				"severity":  "HIGH",
				"platform":  "Terraform",
				"category":  "Configuration",
			},
			Aggregation: 1,
		}}}, nil
	}
	results, err := client.executeScan(ctx)
	require.NoError(t, err)
	require.NotNil(t, results)
	return results
}
