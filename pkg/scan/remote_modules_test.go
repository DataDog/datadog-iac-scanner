package scan

import (
	"bytes"
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
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestLogModuleResolutionFailuresWarnsOncePerReason(t *testing.T) {
	const allowlist = `module host "registry.example.com" is not in --module-host-allowlist`
	const denied = "Permission denied (publickey)."
	var failures []modulegraph.ResolutionFailure
	for i := 0; i < 7; i++ {
		failures = append(failures, modulegraph.ResolutionFailure{
			Source:     "registry.example.com/acme/module-" + string(rune('a'+i)) + "/aws",
			Version:    "v5.5.1",
			Name:       "network",
			CallerFile: "root/main.tf",
			CallerLine: i + 1,
			Failure:    resolver.FailureDetails{Class: "host_not_allowlisted", Stage: "policy"},
			Reason:     allowlist,
		})
	}
	for i := 0; i < 3; i++ {
		failures = append(failures, modulegraph.ResolutionFailure{
			Source: "git@github.com:acme/private//vpc?ref=v1", CallerFile: "root/main.tf", Reason: denied,
		})
	}

	var buf bytes.Buffer
	log := zerolog.New(&buf).Level(zerolog.InfoLevel)
	logModuleResolutionFailures(&log, failures)

	var warnings []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var entry map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &entry))
		warnings = append(warnings, entry)
	}
	require.Len(t, warnings, 2)
	require.Equal(t, allowlist, warnings[0]["reason"])
	require.Equal(t, "info", warnings[0]["level"])
	require.EqualValues(t, 7, warnings[0]["module_calls"])
	require.EqualValues(t, 7, warnings[0]["module_source_count"])
	require.Len(t, warnings[0]["module_sources"], maxLoggedFailureSources)
	require.Equal(t, "host_not_allowlisted", warnings[0]["failure_class"])
	require.Equal(t, "policy", warnings[0]["failure_stage"])
	require.Len(t, warnings[0]["module_samples"], maxLoggedFailureSources)
	sample := warnings[0]["module_samples"].([]any)[0].(map[string]any)
	require.Equal(t, "v5.5.1", sample["version"])
	require.Equal(t, "network", sample["name"])
	require.Equal(t, "root/main.tf:1", sample["caller_location"])
	require.Equal(t, denied, warnings[1]["reason"])
	require.Equal(t, "warn", warnings[1]["level"])
	require.EqualValues(t, 3, warnings[1]["module_calls"])
	require.EqualValues(t, 1, warnings[1]["module_source_count"])

	var warnOnly bytes.Buffer
	warnLog := zerolog.New(&warnOnly).Level(zerolog.WarnLevel)
	logModuleResolutionFailures(&warnLog, failures)
	require.NotContains(t, warnOnly.String(), allowlist)
	require.Contains(t, warnOnly.String(), denied)
}

func TestLogModuleResolutionFailureSamplesRetainDeclaredVersions(t *testing.T) {
	const downloadURL = "https://registry.terraform.io/v1/modules/acme/network/aws/5.5.1/download"
	details := resolver.FailureDetails{
		Class: resolver.FailureRegistryVersionNotFound, Stage: "registry_download", RequestURL: downloadURL, HTTPStatus: 404,
	}
	failures := []modulegraph.ResolutionFailure{
		{
			Source: "acme/network/aws", Version: "v5.5.1", Name: "vpc", CallerFile: "network/main.tf", CallerLine: 7,
			Reason: "download failed", Failure: details,
			Attempts: []resolver.FailureAttempt{{FailureDetails: details, Reason: "download failed"}},
		},
		{
			Source: "acme/network/aws", Version: "~> 5.0", Name: "fixture", CallerFile: "testdata/main.tf", CallerLine: 3,
			Reason: "download failed", Failure: details,
		},
	}
	var buf bytes.Buffer
	log := zerolog.New(&buf).Level(zerolog.WarnLevel)
	logModuleResolutionFailures(&log, failures)
	var warning map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &warning))
	require.Equal(t, downloadURL, warning["http_url"])
	require.EqualValues(t, 404, warning["http_status_code"])
	require.Len(t, warning["failure_attempts"], 1)
	samples := warning["module_samples"].([]any)
	require.Len(t, samples, 2)
	require.Equal(t, "v5.5.1", samples[0].(map[string]any)["version"])
	require.Equal(t, "network/main.tf:7", samples[0].(map[string]any)["caller_location"])
	require.Equal(t, "~> 5.0", samples[1].(map[string]any)["version"])
	require.Equal(t, "testdata/main.tf:3", samples[1].(map[string]any)["caller_location"])

	// Concurrent graph traversal must not change the selected sample order.
	failures[0], failures[1] = failures[1], failures[0]
	failures[0].Attempts = failures[1].Attempts
	var reversed bytes.Buffer
	log = zerolog.New(&reversed).Level(zerolog.WarnLevel)
	logModuleResolutionFailures(&log, failures)
	require.Equal(t, buf.String(), reversed.String())
}

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

func TestOnModeSkipsNetworkResolversWhenNetworkIsolated(t *testing.T) {
	client := &Client{ScanParams: &Parameters{
		TerraformModules: TerraformModulesOn,
		NetworkIsolation: true,
	}}

	chain, err := client.buildModuleResolverChain(t.Context(), []string{t.TempDir()})
	require.NoError(t, err)

	resolvers := reflect.ValueOf(chain).Elem().FieldByName("resolvers")
	require.Equal(t, 2, resolvers.Len())
	for i := 0; i < resolvers.Len(); i++ {
		resolverType := resolvers.Index(i).Elem().Type().String()
		require.NotContains(t, resolverType, "GoGetter")
		require.NotContains(t, resolverType, "BareGit")
		require.NotContains(t, resolverType, "LocalGitRef")
	}
}

func TestOnModeRejectsMalformedManifest(t *testing.T) {
	manifestPath := filepath.Join(t.TempDir(), "modules.json")
	require.NoError(t, os.WriteFile(manifestPath, []byte(`{"schema_version":1}`), 0o644))
	client := &Client{ScanParams: &Parameters{
		TerraformModules:          TerraformModulesOn,
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

func TestScanRemoteModuleConfigPlaceholder(t *testing.T) {
	root := t.TempDir()
	moduleDir, manifestPath := writeRemoteModuleFixture(t, root)
	config := filepath.Join(moduleDir, "main.tf")
	require.NoError(t, os.Rename(config, filepath.Join(moduleDir, "main.hcl")))
	require.NoError(t, os.WriteFile(config, []byte("./main.hcl"), 0o644))
	params := remoteModuleScanParams(root)
	params.TerraformModules = TerraformModulesOn
	params.RemoteModulesManifestPath = manifestPath

	results := executeRemoteModuleScan(t, params)
	require.NotEmpty(t, results.Results)
	for _, file := range results.Files {
		if filepath.ToSlash(file.FilePath) == filepath.ToSlash(config) {
			return
		}
	}
	t.Fatal("downloaded placeholder config was skipped")
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

	require.Equal(t, []string{root}, resolver.TerraformRootDirs([]string{file}))
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
		utils.PoolOptions{},
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
		FlagEvaluator:           featureflags.NewLocalEvaluator(),
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
