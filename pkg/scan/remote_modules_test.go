package scan

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	engineprovider "github.com/DataDog/datadog-iac-scanner/pkg/engine/provider"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/resolver"
	consolePrinter "github.com/DataDog/datadog-iac-scanner/pkg/printer"
	"github.com/stretchr/testify/require"
)

func TestRemoteModulesDisabledByDefault(t *testing.T) {
	root := t.TempDir()
	writeRemoteModuleFixture(t, root)

	params := remoteModuleScanParams(root)
	params.EnableRemoteModules = false

	results := executeRemoteModuleScan(t, params)
	require.Empty(t, results.Results)
}

func TestRemoteModulesManifestEnablesOfflineModuleInstantiation(t *testing.T) {
	root := t.TempDir()
	moduleDir, manifestPath := writeRemoteModuleFixture(t, root)

	params := remoteModuleScanParams(root)
	params.EnableRemoteModules = false
	params.RemoteModulesManifestPath = manifestPath

	results := executeRemoteModuleScan(t, params)
	require.NotEmpty(t, results.Results)
	require.Equal(t, filepath.ToSlash(filepath.Join(moduleDir, "main.tf")), filepath.ToSlash(results.Results[0].FileName))
}

func TestRemoteModulesManifestSkipsMissingEntryWithoutNetworkFallback(t *testing.T) {
	root := t.TempDir()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	t.Cleanup(server.Close)

	rootFile := filepath.Join(root, "main.tf")
	require.NoError(t, os.WriteFile(rootFile, []byte(`
resource "aws_vpc" "repository" {
  cidr_block = "10.0.0.0/16"
}
module "missing" {
  source = "`+server.URL+`/module.zip"
}
`), 0o644))
	manifestPath := filepath.Join(root, "modules.json")
	data, err := json.Marshal(resolver.Manifest{Modules: map[string]resolver.ManifestEntry{}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(manifestPath, data, 0o644))

	params := remoteModuleScanParams(root)
	params.EnableRemoteModules = true
	params.RemoteModulesManifestPath = manifestPath
	results := executeRemoteModuleScan(t, params)

	require.Len(t, results.Results, 1)
	require.Equal(t, filepath.ToSlash(rootFile), filepath.ToSlash(results.Results[0].FileName))
	require.Zero(t, requests.Load())
}

func TestRemoteModulesManifestSkipsUnresolvedEntryAndIncludesResolvedSibling(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "repository")
	require.NoError(t, os.MkdirAll(root, 0o755))
	moduleDir := filepath.Join(base, "resolved-vpc")
	require.NoError(t, os.MkdirAll(moduleDir, 0o755))
	moduleFile := filepath.Join(moduleDir, "main.tf")
	require.NoError(t, os.WriteFile(moduleFile, []byte(`
resource "aws_vpc" "resolved" {
  cidr_block = "10.0.0.0/16"
}
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(`
module "resolved" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "1.0.0"
}
module "unresolved" {
  source  = "terraform-aws-modules/subnets/aws"
  version = "1.0.0"
}
`), 0o644))

	manifestPath := filepath.Join(base, "modules.json")
	data, err := json.Marshal(resolver.Manifest{
		Dir: base,
		Modules: map[string]resolver.ManifestEntry{
			"terraform-aws-modules/vpc/aws@1.0.0": {
				LocalPath: moduleDir,
				Version:   "1.0.0",
				Outcome:   "resolved",
			},
			"terraform-aws-modules/subnets/aws@1.0.0": {
				Outcome: "unresolved",
			},
		},
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(manifestPath, data, 0o644))

	params := remoteModuleScanParams(root)
	params.RemoteModulesManifestPath = manifestPath
	results := executeRemoteModuleScan(t, params)

	require.Len(t, results.Results, 1)
	require.Equal(t, filepath.ToSlash(moduleFile), filepath.ToSlash(results.Results[0].FileName))
}

func TestRemoteModuleMaxDepthZeroDisablesTraversal(t *testing.T) {
	root := t.TempDir()
	_, manifestPath := writeRemoteModuleFixture(t, root)

	params := remoteModuleScanParams(root)
	params.EnableRemoteModules = true
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

func TestShouldPreScanTerraformModules(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		root := t.TempDir()
		client := &Client{ScanParams: &Parameters{}}
		require.False(t, client.shouldPreScanTerraformModules([]string{root}))
	})

	t.Run("network resolution", func(t *testing.T) {
		root := t.TempDir()
		client := &Client{ScanParams: &Parameters{EnableRemoteModules: true}}
		require.True(t, client.shouldPreScanTerraformModules([]string{root}))
	})

	t.Run("prefetched manifest", func(t *testing.T) {
		root := t.TempDir()
		client := &Client{ScanParams: &Parameters{RemoteModulesManifestPath: filepath.Join(root, "modules.json")}}
		require.True(t, client.shouldPreScanTerraformModules([]string{root}))
	})

	t.Run("terraform cache", func(t *testing.T) {
		root := t.TempDir()
		manifestDir := filepath.Join(root, ".terraform", "modules")
		require.NoError(t, os.MkdirAll(manifestDir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(manifestDir, "modules.json"), []byte(`{}`), 0o644))
		client := &Client{ScanParams: &Parameters{}}
		require.True(t, client.shouldPreScanTerraformModules([]string{root}))
	})
}

func TestBuildModuleResolverChainFailsOnInvalidManifest(t *testing.T) {
	client := &Client{ScanParams: &Parameters{
		RemoteModulesManifestPath: filepath.Join(t.TempDir(), "missing.json"),
	}}

	_, err := client.buildModuleResolverChain(context.Background(), []string{t.TempDir()})

	require.Error(t, err)
	require.Contains(t, err.Error(), "loading modules manifest")
}

func TestBuildModuleResolverChainPrefersExplicitManifestOverTerraformCache(t *testing.T) {
	root := t.TempDir()
	resolvedRoot, err := filepath.EvalSymlinks(root)
	require.NoError(t, err)
	staleDir := filepath.Join(resolvedRoot, "stale")
	preferredDir := filepath.Join(resolvedRoot, "preferred")
	for _, dir := range []string{staleDir, preferredDir} {
		require.NoError(t, os.MkdirAll(dir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`resource "x" "y" {}`), 0o644))
	}

	tfModulesDir := filepath.Join(resolvedRoot, ".terraform", "modules")
	require.NoError(t, os.MkdirAll(tfModulesDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(tfModulesDir, "modules.json"), []byte(`{
  "Modules": [{"Key":"m","Source":"terraform-aws-modules/vpc/aws","Version":"1.0.0","Dir":"stale"}]
}`), 0o644))

	manifestPath := filepath.Join(resolvedRoot, "modules.json")
	manifestData, err := json.Marshal(resolver.Manifest{
		Dir: resolvedRoot,
		Modules: map[string]resolver.ManifestEntry{
			"terraform-aws-modules/vpc/aws@1.0.0": {LocalPath: preferredDir, Version: "1.0.0"},
		},
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(manifestPath, manifestData, 0o644))

	client := &Client{ScanParams: &Parameters{RemoteModulesManifestPath: manifestPath}}
	chain, err := client.buildModuleResolverChain(context.Background(), []string{resolvedRoot})
	require.NoError(t, err)

	got, err := chain.Resolve(context.Background(), &tfmodules.ParsedModule{
		Source:  "terraform-aws-modules/vpc/aws",
		Version: "1.0.0",
	})
	require.NoError(t, err)
	require.Equal(t, preferredDir, got.LocalPath)
}

func TestBuildModuleResolverChainDoesNotFallBackToTerraformCache(t *testing.T) {
	root := t.TempDir()
	staleDir := filepath.Join(root, ".terraform", "modules", "stale")
	require.NoError(t, os.MkdirAll(staleDir, 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(root, ".terraform", "modules", "modules.json"),
		[]byte(`{"Modules":[{"Key":"m","Source":"terraform-aws-modules/vpc/aws","Version":"1.0.0","Dir":"stale"}]}`),
		0o644,
	))
	manifestPath := filepath.Join(root, "hosted-modules.json")
	data, err := json.Marshal(resolver.Manifest{Modules: map[string]resolver.ManifestEntry{}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(manifestPath, data, 0o644))

	client := &Client{ScanParams: &Parameters{RemoteModulesManifestPath: manifestPath}}
	chain, err := client.buildModuleResolverChain(t.Context(), []string{root})
	require.NoError(t, err)

	_, err = chain.Resolve(t.Context(), &tfmodules.ParsedModule{
		Name: "m", Source: "terraform-aws-modules/vpc/aws", Version: "1.0.0",
		FileName: filepath.Join(root, "main.tf"),
	})
	require.ErrorContains(t, err, "not found in manifest")
}

func TestBuildModuleResolverChainIsNetworklessWithManifest(t *testing.T) {
	root := t.TempDir()
	manifestPath := filepath.Join(root, "modules.json")
	data, err := json.Marshal(resolver.Manifest{
		SchemaVersion: 2,
		Modules:       map[string]resolver.ManifestEntry{},
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(manifestPath, data, 0o644))

	client := &Client{ScanParams: &Parameters{
		EnableRemoteModules:       true,
		RemoteModulesManifestPath: manifestPath,
	}}
	chain, err := client.buildModuleResolverChain(context.Background(), []string{root})
	require.NoError(t, err)

	_, err = chain.Resolve(context.Background(), &tfmodules.ParsedModule{
		Source:   "git::https://127.0.0.1:1/acme/network.git?ref=v1",
		Version:  "1.0.0",
		FileName: filepath.Join(root, "main.tf"),
	})

	require.ErrorContains(t, err, "not found in manifest")
	require.NotContains(t, err.Error(), "fetch failed")
	require.NotContains(t, err.Error(), "BareGitResolver")
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
  version = "~> 5.0"
  cidr    = "10.0.0.0/16"
}
`), 0o644))

	manifestPath := filepath.Join(root, "modules.json")
	manifest := resolver.Manifest{
		Modules: map[string]resolver.ManifestEntry{
			"terraform-aws-modules/vpc/aws@~> 5.0": {LocalPath: moduleDir, Version: "5.1.2"},
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
