package scan

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/config"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	tfresolver "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/resolver"
	consolePrinter "github.com/DataDog/datadog-iac-scanner/pkg/printer"
	"github.com/stretchr/testify/require"
)

// stubQuerySource serves a fixed query slice and a trivial Rego library.
type stubQuerySource struct {
	queries []model.QueryMetadata
}

func (s *stubQuerySource) GetQueries(_ context.Context, _ *source.QueryInspectorParameters) ([]model.QueryMetadata, error) {
	return s.queries, nil
}

func (s *stubQuerySource) GetQueryLibrary(_ context.Context, platform string) (source.RegoLibraries, error) {
	return source.RegoLibraries{
		LibraryCode:      "package generic." + platform + "\n",
		LibraryInputData: "{}",
	}, nil
}

type stubModuleResolver struct {
	dirs  map[string]string
	calls map[string]int
}

func (r stubModuleResolver) Resolve(_ context.Context, mod *tfmodules.ParsedModule) (tfresolver.Resolution, error) {
	if r.calls != nil {
		r.calls[mod.Source]++
	}
	if dir, ok := r.dirs[mod.Source+":"+mod.Name]; ok {
		return tfresolver.Resolution{LocalPath: dir}, nil
	}
	dir, ok := r.dirs[mod.Source]
	if !ok {
		return tfresolver.Resolution{}, &tfmodules.UnresolvedError{Reason: "not found"}
	}
	return tfresolver.Resolution{LocalPath: dir}, nil
}

// Test_ExecuteScan runs the scan pipeline against a synthetic in-memory rule
// so the assertions are decoupled from the rule corpus.
func Test_ExecuteScan(t *testing.T) {
	const ruleID = "test-execute-scan-rule"
	rego := `package datadog

DatadogPolicy contains result if {
	input.document[i].resource.aws_s3_bucket[name]
	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_s3_bucket",
		"resourceName": name,
		"searchKey": sprintf("aws_s3_bucket[%s]", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "aws_s3_bucket should be encrypted",
		"keyActualValue": "aws_s3_bucket is not encrypted",
	}
}
`
	query := model.QueryMetadata{
		Query:     ruleID,
		Content:   rego,
		InputData: "{}",
		Platform:  "terraform",
		Metadata: map[string]interface{}{
			"id":        ruleID,
			"legacyId":  ruleID,
			"queryName": "Synthetic Execute-Scan Rule",
			"severity":  "HIGH",
			"platform":  "Terraform",
			"category":  "Encryption",
		},
	}

	scanParams := Parameters{
		Path:                    []string{filepath.Join("test", "sample.tf")},
		QueriesPath:             []string{"."},
		LibrariesPath:           "assets/libraries",
		PreviewLines:            3,
		CloudProvider:           []string{"aws"},
		Platform:                []string{"Terraform"},
		ChangedDefaultQueryPath: false,
		MaxFileSizeFlag:         100,
		ScanID:                  "console",
		MaxResolverDepth:        15,
		FlagEvaluator:           featureflags.NewLocalEvaluator(),
	}

	ctx := context.Background()
	c, err := NewClient(ctx, &scanParams, &consolePrinter.Printer{})
	require.NoError(t, err)
	c.querySourceFactory = func(_ context.Context, _ []string) (source.QueriesSource, error) {
		return &stubQuerySource{queries: []model.QueryMetadata{query}}, nil
	}

	r, err := c.executeScan(ctx)
	require.NoError(t, err)
	require.NotNil(t, r)
	require.NotEmpty(t, r.Results, "expected at least one synthetic violation")

	for i, result := range r.Results {
		require.Equalf(t, model.Severity("HIGH"), model.Severity(result.Severity), "result[%d] severity", i)
		require.Equalf(t, ruleID, result.QueryID, "result[%d] query id", i)
	}
}

func Test_CreateQueryFilter(t *testing.T) {
	tests := []struct {
		name           string
		scanParams     Parameters
		expectedOutput source.QueryInspectorParameters
	}{
		{
			name: "test empty filter",
			scanParams: Parameters{
				Config:          config.IacConfig{},
				InputData:       "",
				BillOfMaterials: false,
			},
			expectedOutput: source.QueryInspectorParameters{
				ExcludeQueries: source.QueryFilter{},
				IncludeQueries: source.QueryFilter{},
				InputDataPath:  "",
				BomQueries:     false,
			},
		},
		{
			name: "test query filter with some fields and BoM",
			scanParams: Parameters{
				Config: config.IacConfig{
					IgnoreRules:      []string{"c065b98e-1515-4991-9dca-b602bd6a2fbb"},
					IgnoreSeverities: []string{"info"},
					OnlyCategories:   []string{"Accessibility"},
				},
				InputData:       "",
				BillOfMaterials: true,
			},
			expectedOutput: source.QueryInspectorParameters{
				ExcludeQueries: source.QueryFilter{
					ByIDs:        []string{"c065b98e-1515-4991-9dca-b602bd6a2fbb"},
					BySeverities: []string{"info"},
				},
				IncludeQueries: source.QueryFilter{
					ByCategories: []string{"Accessibility"},
				},
				InputDataPath: "",
				BomQueries:    true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{}
			c.ScanParams = &tt.scanParams

			v := c.createQueryFilter()

			require.Equal(t, tt.expectedOutput, *v)
		})
	}
}

func TestDotTerraformRootDirsNormalizesFileInputs(t *testing.T) {
	root := t.TempDir()
	err := os.MkdirAll(filepath.Join(root, ".terraform", "modules"), 0o755)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(root, ".terraform", "modules", "modules.json"), []byte(`{"Modules":[]}`), 0o644)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(root, "main.tf"), []byte(`module "x" { source = "example/x/aws" }`), 0o644)
	require.NoError(t, err)
	nested := filepath.Join(root, "envs", "prod")
	err = os.MkdirAll(filepath.Join(nested, ".terraform", "modules"), 0o755)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(nested, ".terraform", "modules", "modules.json"), []byte(`{"Modules":[]}`), 0o644)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(nested, "main.tf"), []byte(`module "x" { source = "example/x/aws" }`), 0o644)
	require.NoError(t, err)

	require.ElementsMatch(t, []string{root, nested}, dotTerraformRootDirs([]string{
		filepath.Join(root, "main.tf"),
		filepath.Join(nested, "main.tf"),
	}))
}

func TestResolveRemoteModuleScanPathsRespectsFileSeeds(t *testing.T) {
	root := t.TempDir()
	allowedModule := filepath.Join(root, "allowed-module")
	excludedModule := filepath.Join(root, "excluded-module")
	require.NoError(t, os.MkdirAll(allowedModule, 0o755))
	require.NoError(t, os.MkdirAll(excludedModule, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(allowedModule, "main.tf"), []byte(`resource "x" "allowed" {}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(excludedModule, "main.tf"), []byte(`resource "x" "excluded" {}`), 0o644))
	allowedFile := filepath.Join(root, "main.tf")
	excludedFile := filepath.Join(root, "experimental.tf")
	require.NoError(t, os.WriteFile(filepath.Join(root, "locals.tf"), []byte(`locals { allowed_source = "allowed" }`), 0o644))
	require.NoError(t, os.WriteFile(allowedFile, []byte(`module "allowed" { source = local.allowed_source }`), 0o644))
	require.NoError(t, os.WriteFile(excludedFile, []byte(`module "excluded" { source = "excluded" }`), 0o644))

	paths, _, _, _ := resolveRemoteModuleScanPaths(context.Background(), []string{root}, []string{allowedFile}, stubModuleResolver{
		dirs: map[string]string{
			"allowed":  allowedModule,
			"excluded": excludedModule,
		},
	}, 1)

	require.Contains(t, paths, filepath.Join(allowedModule, "main.tf"))
	require.NotContains(t, paths, filepath.Join(excludedModule, "main.tf"))
}

func TestResolveRemoteModuleScanPathsDoesNotSeedUncalledNestedModules(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "modules", "uncalled")
	stack := filepath.Join(root, "stack")
	remoteModule := filepath.Join(root, "remote-module")
	require.NoError(t, os.MkdirAll(nested, 0o755))
	require.NoError(t, os.MkdirAll(stack, 0o755))
	require.NoError(t, os.MkdirAll(remoteModule, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.tf"), []byte(`resource "x" "root" {}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(nested, "main.tf"), []byte(`module "remote" { source = "remote" }`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(stack, "main.tf"), []byte(`module "remote" { source = "remote" }`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(remoteModule, "main.tf"), []byte(`resource "x" "remote" {}`), 0o644))

	paths, _, _, _ := resolveRemoteModuleScanPaths(context.Background(), []string{root}, []string{
		filepath.Join(root, "main.tf"),
		filepath.Join(nested, "main.tf"),
		filepath.Join(stack, "main.tf"),
	}, stubModuleResolver{
		dirs: map[string]string{"remote": remoteModule},
	}, 2)

	require.ElementsMatch(t, []string{filepath.Join(remoteModule, "main.tf")}, paths)
}

func TestResolveRemoteModuleScanPathsKeepsFilteredLocalModulesOutOfGraph(t *testing.T) {
	root := t.TempDir()
	wrapper := filepath.Join(root, "modules", "wrapper")
	remoteModule := filepath.Join(root, "remote-module")
	require.NoError(t, os.MkdirAll(wrapper, 0o755))
	require.NoError(t, os.MkdirAll(remoteModule, 0o755))
	rootFile := filepath.Join(root, "main.tf")
	require.NoError(t, os.WriteFile(rootFile, []byte(`module "wrapper" { source = "./modules/wrapper" }`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(wrapper, "main.tf"), []byte(`module "remote" { source = "remote" }`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(remoteModule, "main.tf"), []byte(`resource "x" "remote" {}`), 0o644))

	paths, _, _, _ := resolveRemoteModuleScanPaths(context.Background(), []string{root}, []string{rootFile}, stubModuleResolver{
		dirs: map[string]string{"remote": remoteModule},
	}, 2)

	require.Empty(t, paths)
}

func TestResolveRemoteModuleScanPathsKeepsUnversionedDuplicateSourcesByName(t *testing.T) {
	root := t.TempDir()
	remoteA := filepath.Join(root, "remote-a")
	remoteB := filepath.Join(root, "remote-b")
	require.NoError(t, os.MkdirAll(remoteA, 0o755))
	require.NoError(t, os.MkdirAll(remoteB, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(remoteA, "main.tf"), []byte(`resource "x" "a" {}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(remoteB, "main.tf"), []byte(`resource "x" "b" {}`), 0o644))
	rootFile := filepath.Join(root, "main.tf")
	require.NoError(t, os.WriteFile(rootFile, []byte(`
module "a" { source = "same/source/aws" }
module "b" { source = "same/source/aws" }
`), 0o644))

	_, _, sourceDirs, _ := resolveRemoteModuleScanPaths(context.Background(), []string{rootFile}, []string{rootFile}, stubModuleResolver{
		dirs: map[string]string{
			"same/source/aws:a": remoteA,
			"same/source/aws:b": remoteB,
		},
	}, 1)

	require.Equal(t, remoteA, sourceDirs[engine.RemoteModuleCallKey(root, "same/source/aws", "", "a")])
	require.Equal(t, remoteB, sourceDirs[engine.RemoteModuleCallKey(root, "same/source/aws", "", "b")])
}

func TestResolveRemoteModuleScanPathsDeduplicatesByRemoteIdentity(t *testing.T) {
	root := t.TempDir()
	remoteModule := filepath.Join(root, "remote-module")
	require.NoError(t, os.MkdirAll(remoteModule, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(remoteModule, "main.tf"), []byte(`resource "x" "remote" {}`), 0o644))
	rootFile := filepath.Join(root, "main.tf")
	require.NoError(t, os.WriteFile(rootFile, []byte(`
module "a" { source = "git::https://example.com/mod.git?ref=main" }
module "b" { source = "git::https://example.com/mod.git?ref=main" }
`), 0o644))
	calls := map[string]int{}

	paths, _, _, _ := resolveRemoteModuleScanPaths(context.Background(), []string{rootFile}, []string{rootFile}, stubModuleResolver{
		dirs:  map[string]string{"git::https://example.com/mod.git?ref=main": remoteModule},
		calls: calls,
	}, 1)

	require.Equal(t, 1, calls["git::https://example.com/mod.git?ref=main"])
	require.ElementsMatch(t, []string{filepath.Join(remoteModule, "main.tf")}, paths)
}

func TestResolveRemoteModuleScanPathsDepthZeroDisablesRemoteModules(t *testing.T) {
	root := t.TempDir()
	remoteModule := filepath.Join(root, "remote-module")
	require.NoError(t, os.MkdirAll(remoteModule, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(remoteModule, "main.tf"), []byte(`resource "x" "remote" {}`), 0o644))
	rootFile := filepath.Join(root, "main.tf")
	require.NoError(t, os.WriteFile(rootFile, []byte(`module "remote" { source = "remote" }`), 0o644))

	paths, _, _, _ := resolveRemoteModuleScanPaths(context.Background(), []string{rootFile}, []string{rootFile}, stubModuleResolver{
		dirs: map[string]string{"remote": remoteModule},
	}, 0)

	require.Empty(t, paths)
}

func TestResolveRemoteModuleScanPathsCountsLocalHopsTowardDepth(t *testing.T) {
	root := t.TempDir()
	localModule := filepath.Join(root, "modules", "wrapper")
	remoteModule := filepath.Join(root, "remote-module")
	require.NoError(t, os.MkdirAll(localModule, 0o755))
	require.NoError(t, os.MkdirAll(remoteModule, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(remoteModule, "main.tf"), []byte(`resource "x" "remote" {}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(localModule, "main.tf"), []byte(`module "remote" { source = "remote" }`), 0o644))
	rootFile := filepath.Join(root, "main.tf")
	require.NoError(t, os.WriteFile(rootFile, []byte(`module "wrapper" { source = "./modules/wrapper" }`), 0o644))

	paths, _, _, _ := resolveRemoteModuleScanPaths(context.Background(), []string{rootFile}, []string{rootFile}, stubModuleResolver{
		dirs: map[string]string{"remote": remoteModule},
	}, 1)

	require.Empty(t, paths)
}

func TestBuildModuleResolverChainAllowsZeroByteCaps(t *testing.T) {
	client := &Client{ScanParams: &Parameters{
		MaxModuleBytesTotal: 0,
	}}

	chain := client.buildModuleResolverChain(context.Background(), nil)

	require.NotNil(t, chain)
}

// TestCanonicalGitModuleSourceFoldsGitSuffix guards the determinism fix: the
// ".git" and no-".git" spellings of the same git module resolve to the same
// content, so they must canonicalize identically. Otherwise the spelling
// recorded for a finding depends on a resolution race and varies run-to-run.
func TestCanonicalGitModuleSourceFoldsGitSuffix(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"subdir", "git::https://github.com/org/repo.git//sub?ref=v1", "git::https://github.com/org/repo//sub?ref=v1"},
		{"no-suffix subdir", "git::https://github.com/org/repo//sub?ref=v1", "git::https://github.com/org/repo//sub?ref=v1"},
		{"ref only", "git::https://github.com/org/repo.git?ref=v1", "git::https://github.com/org/repo?ref=v1"},
		{"trailing", "git::https://github.com/org/repo.git", "git::https://github.com/org/repo"},
		{"registry untouched", "registry.terraform.io/org/name/aws", "registry.terraform.io/org/name/aws"},
		{"local untouched", "./modules/local", "./modules/local"},
		{"whitespace trimmed", "  git::https://github.com/org/repo.git//sub  ", "git::https://github.com/org/repo//sub"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, canonicalGitModuleSource(tt.in))
		})
	}
}

func TestCanonicalModuleURLStableAcrossGitSpelling(t *testing.T) {
	withGit := canonicalModuleURL("git::https://github.com/org/repo.git//sub", "v1.2.3")
	withoutGit := canonicalModuleURL("git::https://github.com/org/repo//sub", "v1.2.3")
	require.Equal(t, withoutGit, withGit)
}

func TestRemoteResolveIdentityStableAcrossGitSpelling(t *testing.T) {
	withGit := remoteResolveIdentity(&tfmodules.ParsedModule{Source: "git::https://github.com/org/repo.git//sub?ref=v1", Version: ""})
	withoutGit := remoteResolveIdentity(&tfmodules.ParsedModule{Source: "git::https://github.com/org/repo//sub?ref=v1", Version: ""})
	require.Equal(t, withoutGit, withGit)
}
