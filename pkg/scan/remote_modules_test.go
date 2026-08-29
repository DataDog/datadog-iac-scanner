package scan

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	engineprovider "github.com/DataDog/datadog-iac-scanner/pkg/engine/provider"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/modulegraph"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/resolver"
	consolePrinter "github.com/DataDog/datadog-iac-scanner/pkg/printer"
	"github.com/stretchr/testify/require"
)

func TestResolvedModuleSourceTypeUsesResolvedGitRef(t *testing.T) {
	module := &modulegraph.ResolvedModule{
		Source:      "https://github.com/acme/network.git//modules/vpc",
		ResolvedRef: "45ea6a143c2d",
	}

	require.Equal(t, "git", resolvedModuleSourceType(module))
}

func TestResolvedModuleSourceTypeKeepsRegistryForGitBackedDownload(t *testing.T) {
	module := &modulegraph.ResolvedModule{
		Source:          "terraform-aws-modules/vpc/aws",
		ResolvedRef:     "45ea6a143c2d",
		ResolvedVersion: "5.0.0",
	}

	require.Equal(t, "registry", resolvedModuleSourceType(module))
}

func TestRemoteModulesDisabledByDefault(t *testing.T) {
	root := t.TempDir()
	_, manifestPath := writeRemoteModuleFixture(t, root)

	params := remoteModuleScanParams(root)
	params.RemoteModulesManifestPath = manifestPath
	params.TerraformModules = TerraformModulesOff

	results := executeRemoteModuleScan(t, params)
	require.Empty(t, results.Results)
}

func TestOnModeBuildsNetworkResolvers(t *testing.T) {
	client := &Client{ScanParams: &Parameters{TerraformModules: TerraformModulesOn}}

	chain, err := client.buildModuleResolverChain(t.Context(), []string{t.TempDir()})
	require.NoError(t, err)

	resolvers := reflect.ValueOf(chain).Elem().FieldByName("resolvers")
	require.GreaterOrEqual(t, resolvers.Len(), 4)
	foundNetwork := false
	for i := 0; i < resolvers.Len(); i++ {
		resolverType := resolvers.Index(i).Elem().Type().String()
		if strings.Contains(resolverType, "GoGetter") ||
			strings.Contains(resolverType, "BareGit") ||
			strings.Contains(resolverType, "LocalGitRef") {
			foundNetwork = true
		}
	}
	require.True(t, foundNetwork)
}

func TestOnModeRejectsMalformedManifest(t *testing.T) {
	manifestPath := filepath.Join(t.TempDir(), "modules.json")
	require.NoError(t, os.WriteFile(manifestPath, []byte(`{"schema_version":1}`), 0o644))
	client := &Client{ScanParams: &Parameters{
		TerraformModules:      TerraformModulesOn,
		RemoteModulesManifestPath: manifestPath,
	}}

	_, err := client.buildModuleResolverChain(t.Context(), []string{t.TempDir()})
	require.ErrorContains(t, err, "root must be a non-empty relative path")
}

func TestRemoteModulesManifestEnablesModuleInstantiation(t *testing.T) {
	root := t.TempDir()
	moduleDir, manifestPath := writeRemoteModuleFixture(t, root)

	params := remoteModuleScanParams(root)
	params.TerraformModules = TerraformModulesOn
	params.RemoteModulesManifestPath = manifestPath

	results := executeRemoteModuleScan(t, params)
	require.NotEmpty(t, results.Results)
	require.Equal(t, filepath.ToSlash(filepath.Join(moduleDir, "main.tf")), filepath.ToSlash(results.Results[0].FileName))
}

func TestManifestV1PreservesLegacyFindingOutput(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "repo")
	moduleDir := filepath.Join(base, "modules", "vpc")
	require.NoError(t, os.MkdirAll(root, 0o755))
	require.NoError(t, os.MkdirAll(moduleDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(`
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.0.0"
  cidr    = "10.0.0.0/16"
}
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(moduleDir, "main.tf"), []byte(`
variable "cidr" {}
resource "aws_vpc" "this" {
  cidr_block = var.cidr
}
`), 0o644))

	legacyPath := filepath.Join(base, "legacy.json")
	writeJSONFile(t, legacyPath, resolver.Manifest{
		Dir: base,
		Modules: map[string]resolver.ManifestEntry{
			"terraform-aws-modules/vpc/aws@5.0.0": {
				LocalPath: moduleDir,
				Version:   "5.0.0",
			},
		},
	})
	digest, err := resolver.ComputePackageDigest(t.Context(), moduleDir)
	require.NoError(t, err)
	v1Path := filepath.Join(base, "v1.json")
	writeJSONFile(t, v1Path, map[string]any{
		"schema_version": resolver.ManifestSchemaVersion,
		"root":           "modules",
		"modules": []map[string]any{{
			"source":            "terraform-aws-modules/vpc/aws",
			"requested_version": "5.0.0",
			"resolved_version":  "5.0.0",
			"source_type":       "registry",
			"local_path":        "vpc",
			"content_digest":    digest,
			"status":            "resolved",
			"declarations": []map[string]any{{
				"filename":    "main.tf",
				"line_start":  2,
				"line_end":    6,
				"module_name": "vpc",
			}},
		}},
	})

	legacyParams := remoteModuleScanParams(root)
	legacyParams.TerraformModules = TerraformModulesOn
	legacyParams.RemoteModulesManifestPath = legacyPath
	v1Params := remoteModuleScanParams(root)
	v1Params.TerraformModules = TerraformModulesOn
	v1Params.RemoteModulesManifestPath = v1Path

	legacy := executeRemoteModuleScan(t, legacyParams)
	v1 := executeRemoteModuleScan(t, v1Params)
	legacySummary := model.CreateSummary(
		t.Context(),
		model.Counters{},
		legacy.Results,
		legacyParams.ScanID,
		legacy.ExtractedPaths.ExtractionMap,
		root,
		model.SCIInfo{},
	)
	v1Summary := model.CreateSummary(
		t.Context(),
		model.Counters{},
		v1.Results,
		v1Params.ScanID,
		v1.ExtractedPaths.ExtractionMap,
		root,
		model.SCIInfo{},
	)
	require.Len(t, legacySummary.Queries, 1)
	require.Len(t, v1Summary.Queries, 1)
	require.Equal(t, legacySummary.Queries[0].Files[0].Fingerprint, v1Summary.Queries[0].Files[0].Fingerprint)
	require.Equal(t, legacySummary.Queries[0].Files[0].ModuleAttribution, v1Summary.Queries[0].Files[0].ModuleAttribution)
}

func TestRemoteModuleMaxDepthZeroDisablesTraversal(t *testing.T) {
	root := t.TempDir()
	_, manifestPath := writeRemoteModuleFixture(t, root)

	params := remoteModuleScanParams(root)
	params.TerraformModules = TerraformModulesOn
	params.RemoteModulesManifestPath = manifestPath
	params.ModuleMaxDepth = 0

	results := executeRemoteModuleScan(t, params)
	require.Empty(t, results.Results)
}

func TestDotTerraformRootDirsUsesFileParent(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "main.tf")
	require.NoError(t, os.WriteFile(file, nil, 0o644))

	require.Equal(t, []string{root}, dotTerraformRootDirs([]string{file}))
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

func writeJSONFile(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o644))
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
		ModuleMaxDepth:          DefaultRemoteModuleMaxDepth,
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
