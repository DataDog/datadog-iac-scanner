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
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/modulegraph"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/moduleprepare"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/resolver"
	consolePrinter "github.com/DataDog/datadog-iac-scanner/pkg/printer"
	cyclonedx "github.com/DataDog/datadog-iac-scanner/pkg/report/model"
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
			CallerFile: "root/main.tf",
			Reason:     allowlist,
		})
	}
	for i := 0; i < 3; i++ {
		failures = append(failures, modulegraph.ResolutionFailure{
			Source: "git@github.com:acme/private//vpc?ref=v1", CallerFile: "root/main.tf", Reason: denied,
			Code: resolver.FailureGitAuthRequired, Detail: "git clone --bare ssh://git@github.com/acme/private",
		})
	}

	var buf bytes.Buffer
	log := zerolog.New(&buf).Level(zerolog.WarnLevel)
	logModuleResolutionFailures(&log, failures)

	var warnings []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var entry map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &entry))
		warnings = append(warnings, entry)
	}
	require.Len(t, warnings, 2)
	require.Equal(t, allowlist, warnings[0]["reason"])
	require.EqualValues(t, 7, warnings[0]["module_calls"])
	require.EqualValues(t, 7, warnings[0]["module_source_count"])
	require.Len(t, warnings[0]["module_sources"], maxLoggedFailureSources)
	require.Equal(t, denied, warnings[1]["reason"])
	require.Equal(t, resolver.FailureGitAuthRequired, warnings[1]["code"])
	require.Equal(t, "git clone --bare ssh://git@github.com/acme/private", warnings[1]["detail"])
	require.EqualValues(t, 3, warnings[1]["module_calls"])
	require.EqualValues(t, 1, warnings[1]["module_source_count"])
}

func logLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var lines []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var entry map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &entry))
		lines = append(lines, entry)
	}
	return lines
}

// failingPrepareResolver fails every module with a code it names itself and
// a detail that carries URL credentials, as a download failure can.
type failingPrepareResolver struct {
	code string
}

func (r failingPrepareResolver) Resolve(context.Context, *tfmodules.ParsedModule) (resolver.Resolution, error) {
	// The detail says nothing a text rule could classify, so only the code
	// named here can reach the offline scan.
	return resolver.Resolution{}, &tfmodules.UnresolvedError{
		Reason: "fetch failed",
		Code:   r.code,
		Detail: "error downloading 'https://user:SECRETXYZ987@modules.example/acme/vpc': resolver returned no body",
	}
}

// TestModuleFailureSurvivesPreparationAndOfflineScan checks the handoff from
// preparation to the offline scan: a failure classified during Prepare reaches
// the manifest, and the offline scan reports the same code and detail in its
// failure log line, with credentials redacted. The code may come from the
// scanner or from a resolver outside it.
func TestModuleFailureSurvivesPreparationAndOfflineScan(t *testing.T) {
	tests := []struct {
		name     string
		resolver failingPrepareResolver
		wantCode string
	}{
		{"scanner code", failingPrepareResolver{code: resolver.FailureNetwork}, resolver.FailureNetwork},
		{"code set by an injected resolver", failingPrepareResolver{code: "request_limit_exceeded"}, "request_limit_exceeded"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(`
module "vpc" {
  source = "https://modules.example/acme/vpc.zip"
}
`), 0o644))
			artifactDir := filepath.Join(t.TempDir(), "prepared")

			prepared, err := moduleprepare.Prepare(t.Context(), &moduleprepare.Config{
				RepositoryRoot: root,
				ArtifactDir:    artifactDir,
				DiscoveryPaths: []string{"main.tf"},
				Resolver:       tt.resolver,
			})
			require.NoError(t, err)
			require.Len(t, prepared.Failures, 1)
			wantDetail := prepared.Failures[0].Detail
			require.Equal(t, tt.wantCode, prepared.Failures[0].Code)
			require.Contains(t, wantDetail, "no body")
			require.NotContains(t, wantDetail, "SECRETXYZ987")

			manifestData, err := os.ReadFile(prepared.ManifestPath)
			require.NoError(t, err)
			require.NotContains(t, string(manifestData), "SECRETXYZ987")
			manifest, err := resolver.LoadManifest(t.Context(), prepared.ManifestPath)
			require.NoError(t, err)

			// The offline scan resolves the same declaration from the manifest.
			offline := modulegraph.Resolve(t.Context(), &modulegraph.Request{
				RootPaths:      []string{root},
				DiscoveryPaths: []string{filepath.Join(root, "main.tf")},
				Resolver:       resolver.NewPrefetchedResolver(manifest),
				MaxDepth:       2,
			})
			require.Len(t, offline.Failures, 1)
			require.Equal(t, tt.wantCode, offline.Failures[0].Code)
			require.Equal(t, wantDetail, offline.Failures[0].Detail)

			var buf bytes.Buffer
			log := zerolog.New(&buf).Level(zerolog.WarnLevel)
			logModuleResolutionFailures(&log, offline.Failures)
			lines := logLines(t, &buf)
			require.Len(t, lines, 1)
			require.Equal(t, "Terraform module resolution failed", lines[0]["message"])
			require.Equal(t, tt.wantCode, lines[0]["code"])
			require.Equal(t, wantDetail, lines[0]["detail"])
			require.Equal(t, "fetch failed", lines[0]["reason"])
			require.NotContains(t, buf.String(), "SECRETXYZ987")
		})
	}
}

// TestLogModuleResolutionFailures covers the failure log lines of a scan: one
// debug line per call and one warning per distinct code and reason. Log relays
// read their keys, so the key sets are part of the contract.

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
	// The finding reports the resolved module path, exactly as before; its
	// ordering path names the module's canonical source, so the order cannot
	// follow a per-scan location.
	require.Equal(t, filepath.ToSlash(filepath.Join(moduleDir, "main.tf")), filepath.ToSlash(results.Results[0].FileName))
	require.Equal(t, "registry.terraform.io/terraform-aws-modules/vpc/aws@5.0.0/main.tf",
		filepath.ToSlash(results.Results[0].OrderPath))
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
	results, _ := executeRemoteModuleScanClient(t, params)
	return results
}

func executeRemoteModuleScanClient(t *testing.T, params *Parameters) (*Results, *Client) {
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
	return results, client
}

// The CycloneDX report hashes each reported file from disk. Findings from a
// fetched module keep the detected (readable) path as their reported name —
// only the ordering path names the canonical source — so the module's
// component stays in the report with a real hash.
func TestRemoteModuleCycloneDXReportKeepsTheComponentHash(t *testing.T) {
	root := t.TempDir()
	_, manifestPath := writeRemoteModuleFixture(t, root)

	params := remoteModuleScanParams(root)
	params.TerraformModules = TerraformModulesOn
	params.RemoteModulesManifestPath = manifestPath

	results := executeRemoteModuleScan(t, params)
	require.NotEmpty(t, results.Results)

	summary := model.CreateSummary(t.Context(), model.Counters{}, results.Results, params.ScanID,
		results.ExtractedPaths.ExtractionMap, root, model.SCIInfo{})
	report := cyclonedx.BuildCycloneDxReport(t.Context(), &summary, summary.FilePaths)
	require.NotEmpty(t, report.Components.Components)
	for _, component := range report.Components.Components {
		require.Len(t, component.Hashes, 1)
		require.Regexp(t, "^[0-9a-f]{64}$", component.Hashes[0].Content,
			"the component's sha256 must be a real hash of the file on disk")
	}
}
