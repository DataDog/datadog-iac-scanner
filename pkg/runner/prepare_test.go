/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package runner

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/internal/storage"
	"github.com/DataDog/datadog-iac-scanner/internal/tracker"
	"github.com/DataDog/datadog-iac-scanner/pkg/analyzer"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/provider"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser"
	"github.com/DataDog/datadog-iac-scanner/pkg/resolver"
	"github.com/DataDog/datadog-iac-scanner/pkg/resolver/helm"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/stretchr/testify/require"

	ansibleConfigParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/ansible/ini/config"
	ansibleHostsParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/ansible/ini/hosts"
	bicepParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/bicep"
	buildahParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/buildah"
	dockerParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/docker"
	protoParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/grpc"
	jsonParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/json"
	terraformParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform"
	cicdParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml/cicd"
	yamlParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml/default"
)

func buildParityServices(t *testing.T, ctx context.Context, paths []string) ([]*Service, *storage.MemoryStorage) {
	t.Helper()

	fsp, err := provider.NewFileSystemSourceProvider(ctx, paths, nil, nil)
	require.NoError(t, err)

	trk, err := tracker.NewTracker(1)
	require.NoError(t, err)

	combinedParser, err := parser.NewBuilder(ctx).
		WithFS(vfs.DiskFS{}).
		Add(&yamlParser.Parser{}).
		Add(terraformParser.NewDefault()).
		Add(&bicepParser.Parser{}).
		Add(&cicdParser.Parser{}).
		Add(&dockerParser.Parser{}).
		Add(&protoParser.Parser{}).
		Add(&buildahParser.Parser{}).
		Add(&ansibleConfigParser.Parser{}).
		Add(&ansibleHostsParser.Parser{}).
		Add(&jsonParser.Parser{}).
		Build([]string{""}, []string{""})
	require.NoError(t, err)

	combinedResolver, err := resolver.NewBuilder().Add(ctx, &helm.Resolver{}).Build(ctx)
	require.NoError(t, err)

	store := storage.NewMemoryStorage()
	services := make([]*Service, 0, len(combinedParser))
	for _, p := range combinedParser {
		services = append(services, &Service{
			SourceProvider: fsp,
			Storage:        store,
			Parser:         p,
			Tracker:        trk,
			Resolver:       combinedResolver,
			MaxFileSize:    100,
			Platforms:      []string{""},
		})
	}
	return services, store
}

// documentFingerprint keys prepared documents by platform, kind, path, helm id, and size.
func documentFingerprint(t *testing.T, store *storage.MemoryStorage) map[string]int {
	t.Helper()
	files, err := store.GetFiles(context.Background(), "parity")
	require.NoError(t, err)
	fp := make(map[string]int, len(files))
	for _, f := range files {
		key := fmt.Sprintf("%s|%s|%s|%s|%d", f.Platform, f.Kind, f.FilePath, f.HelmID, len(f.OriginalData))
		fp[key]++
	}
	return fp
}

func requireSharedDocumentParity(
	t *testing.T,
	perService, shared map[string]int,
	routeClassifiedYAML bool,
) {
	t.Helper()
	require.Equal(t, keysSorted(perService), keysSorted(shared),
		"shared walk and per-service walk must prepare the same documents")
	for key, expectedCount := range perService {
		isHelm := strings.Contains(key, "|HELM|")
		isClassifiedYAML := strings.Contains(key, "|YAML|") && !strings.HasPrefix(key, "|")
		if isHelm || routeClassifiedYAML && isClassifiedYAML {
			require.Equal(t, 1, shared[key], "shared walk must route each classified document once")
			continue
		}
		require.Equal(t, expectedCount, shared[key], "non-Helm document count changed for %s", key)
	}
}

func TestPrepareSharedWalk_MatchesPerService(t *testing.T) {
	ctx := context.Background()

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "deploy.yaml"),
		"apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  template:\n    spec:\n      containers:\n        - name: c\n          image: nginx:latest\n")
	writeFile(t, filepath.Join(dir, "workflow.yaml"),
		"name: ci\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
	writeFile(t, filepath.Join(dir, "main.tf"),
		"resource \"aws_s3_bucket\" \"b\" {\n  bucket = \"my-bucket\"\n}\n")
	writeFile(t, filepath.Join(dir, "config.json"),
		"{\n  \"key\": \"value\"\n}\n")
	writeFile(t, filepath.Join(dir, "Dockerfile"),
		"FROM alpine:3.19\nRUN echo hi\n")

	paths := []string{dir}
	for _, rel := range []string{
		"../../test/fixtures/test_helm",
		"../../test/fixtures/test_helm_library",
		"../../test/fixtures/test_helm_subchart",
		"../../test/fixtures/helm_template_parser_error",
	} {
		abs, absErr := filepath.Abs(filepath.FromSlash(rel))
		require.NoError(t, absErr)
		paths = append(paths, abs)
	}

	parallelFlags := featureflags.NewLocalEvaluatorWithOverrides(map[string]bool{
		featureflags.IaCEnableKicsParallelFileParsing: true,
	})

	sharedServices, sharedStore := buildParityServices(t, ctx, paths)
	fsp, ok := SharedWalkProvider(sharedServices)
	require.True(t, ok, "shared walk provider should apply")
	require.NoError(t, PrepareSharedWalk(ctx, fsp, sharedServices, "parity", false, 5))

	perServiceServices, perServiceStore := buildParityServices(t, ctx, paths)
	var wg sync.WaitGroup
	errCh := make(chan error, len(perServiceServices))
	for _, s := range perServiceServices {
		wg.Add(1)
		go s.PrepareSources(ctx, "parity", false, 5, &wg, errCh, parallelFlags)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		require.NoError(t, err)
	}

	shared := documentFingerprint(t, sharedStore)
	perService := documentFingerprint(t, perServiceStore)

	requireSharedDocumentParity(t, perService, shared, false)
}

// TestPrepareSharedWalk_PrebuiltWalk_MatchesPerService drives the CLI hot path:
// the analyzer walks once, the provider reuses that inventory (SetPrebuiltWalk)
// and content cache, and services classify via the analyzer's path→platform map.
// The prepared documents must still match the legacy per-service walk.
func TestPrepareSharedWalk_PrebuiltWalk_MatchesPerService(t *testing.T) {
	ctx := context.Background()

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "deploy.yaml"),
		"apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  template:\n    spec:\n      containers:\n        - name: c\n          image: nginx:latest\n")
	writeFile(t, filepath.Join(dir, "main.tf"),
		"resource \"aws_s3_bucket\" \"b\" {\n  bucket = \"my-bucket\"\n}\n")
	writeFile(t, filepath.Join(dir, "variables.tf"),
		"variable \"env\" {\n  type = string\n}\n")
	writeFile(t, filepath.Join(dir, "terraform.tfvars"),
		"env = \"prod\"\n")
	writeFile(t, filepath.Join(dir, "extra.auto.tfvars"),
		"env = \"staging\"\n")
	writeFile(t, filepath.Join(dir, "Dockerfile"),
		"FROM alpine:3.19\nRUN echo hi\n")

	paths := []string{dir}
	for _, rel := range []string{
		"../../test/fixtures/test_helm",
		"../../test/fixtures/test_helm_subchart",
	} {
		abs, absErr := filepath.Abs(filepath.FromSlash(rel))
		require.NoError(t, absErr)
		paths = append(paths, abs)
	}

	analyzed, err := analyzer.Analyze(ctx, &analyzer.Analyzer{
		RepoPath:    dir,
		Paths:       paths,
		Types:       []string{""},
		MaxFileSize: 100,
	})
	require.NoError(t, err)

	tfvarsPath := filepath.ToSlash(filepath.Join(dir, "terraform.tfvars"))
	require.Contains(t, analyzed.Inventory, tfvarsPath,
		"tfvars files must be part of the analyzer inventory (regression guard)")

	sharedServices, sharedStore := buildParityServices(t, ctx, paths)
	fsp, ok := SharedWalkProvider(sharedServices)
	require.True(t, ok, "shared walk provider should apply")
	fsp.SetPrebuiltWalk(analyzed.Inventory, analyzed.ChartRoots, analyzed.ContentCache)
	for _, s := range sharedServices {
		s.FilePlatform = analyzed.FilePlatform
	}
	require.NoError(t, PrepareSharedWalk(ctx, fsp, sharedServices, "parity", false, 5))

	perServiceServices, perServiceStore := buildParityServices(t, ctx, paths)
	var wg sync.WaitGroup
	errCh := make(chan error, len(perServiceServices))
	for _, s := range perServiceServices {
		wg.Add(1)
		go s.PrepareSources(ctx, "parity", false, 5, &wg, errCh, featureflags.NewLocalEvaluatorWithOverrides(nil))
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		require.NoError(t, err)
	}

	shared := documentFingerprint(t, sharedStore)
	perService := documentFingerprint(t, perServiceStore)

	requireSharedDocumentParity(t, perService, shared, true)

	tfvarsPrepared := false
	for key := range shared {
		if strings.Contains(key, "terraform.tfvars") {
			tfvarsPrepared = true
			break
		}
	}
	require.True(t, tfvarsPrepared, "tfvars document should be prepared by the shared walk")
}

func TestPrepareSharedWalk_RoutesHelmToKubernetesParser(t *testing.T) {
	ctx := context.Background()
	chartPath, err := filepath.Abs("../../test/fixtures/test_helm_with_crds")
	require.NoError(t, err)
	services, _ := buildParityServices(t, ctx, []string{chartPath})
	fsp, ok := SharedWalkProvider(services)
	require.True(t, ok)
	require.NoError(t, PrepareSharedWalk(ctx, fsp, services, "helm-routing", false, 5))

	for _, service := range services {
		helmDocs := 0
		crdDocs := 0
		for _, file := range service.files {
			if file.Kind != model.KindHELM {
				continue
			}
			helmDocs++
			if file.Document["kind"] == "CustomResourceDefinition" {
				crdDocs++
			}
		}
		switch service.Parser.Parsers.(type) {
		case *cicdParser.Parser:
			require.Zero(t, helmDocs)
		case *yamlParser.Parser:
			require.Equal(t, 7, helmDocs)
			require.Equal(t, 6, crdDocs)
		}
	}
}

func TestPrepareSharedWalk_RoutesKnownYAMLPlatforms(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	deployPath := filepath.Join(dir, "deploy.yaml")
	workflowPath := filepath.Join(dir, "workflow.yaml")
	writeFile(t, deployPath, "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n")
	writeFile(t, workflowPath, "name: ci\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n")

	services, _ := buildParityServices(t, ctx, []string{dir})
	filePlatforms := map[string]string{
		filepath.ToSlash(deployPath):   "kubernetes",
		filepath.ToSlash(workflowPath): "cicd",
	}
	for _, service := range services {
		service.FilePlatform = filePlatforms
	}
	fsp, ok := SharedWalkProvider(services)
	require.True(t, ok)
	require.NoError(t, PrepareSharedWalk(ctx, fsp, services, "routing", false, 5))

	for _, service := range services {
		paths := make([]string, 0, len(service.files))
		for _, file := range service.files {
			paths = append(paths, filepath.ToSlash(file.FilePath))
		}
		switch service.Parser.Parsers.(type) {
		case *cicdParser.Parser:
			require.Equal(t, []string{filepath.ToSlash(workflowPath)}, paths)
		case *yamlParser.Parser:
			require.Equal(t, []string{filepath.ToSlash(deployPath)}, paths)
		}
	}
}

func TestServicesForPlatformAndParserKindFallsBackWhenUnmatched(t *testing.T) {
	ctx := context.Background()
	services, _ := buildParityServices(t, ctx, []string{t.TempDir()})

	routed := servicesForPlatformAndParserKind(services, "kubernetes", model.KindYAML)
	require.Len(t, routed, 1)
	_, ok := routed[0].Parser.Parsers.(*yamlParser.Parser)
	require.True(t, ok)

	cicdServices := make([]*Service, 0, 1)
	for _, service := range services {
		if _, ok := service.Parser.Parsers.(*cicdParser.Parser); ok {
			cicdServices = append(cicdServices, service)
		}
	}
	require.Equal(t, cicdServices,
		servicesForPlatformAndParserKind(cicdServices, "kubernetes", model.KindYAML))

	yamlServices := buildExtensionRouting(services)[".yaml"]
	require.Equal(t, yamlServices, servicesForPlatform(yamlServices, ""))
	require.Equal(t, yamlServices, servicesForPlatform(yamlServices, "unknown"))
}

func TestPrepareSharedWalk_DanglingChartYamlSymlinkStillScansTerraform(t *testing.T) {
	ctx := context.Background()

	dir := t.TempDir()
	chartDir := filepath.Join(dir, "mixed")
	require.NoError(t, os.MkdirAll(chartDir, 0o755))
	require.NoError(t, os.Symlink("/nonexistent/Chart.yaml", filepath.Join(chartDir, "Chart.yaml")))
	mainTF := filepath.Join(chartDir, "main.tf")
	writeFile(t, mainTF, `resource "aws_s3_bucket" "b" { bucket = "my-bucket" }`)

	analyzed, err := analyzer.Analyze(ctx, &analyzer.Analyzer{
		RepoPath:    dir,
		Paths:       []string{dir},
		Types:       []string{"terraform"},
		MaxFileSize: 100,
	})
	require.NoError(t, err)
	require.Contains(t, analyzed.Inventory, filepath.ToSlash(mainTF))

	services, store := buildParityServices(t, ctx, []string{dir})
	fsp, ok := SharedWalkProvider(services)
	require.True(t, ok)
	fsp.SetPrebuiltWalk(analyzed.Inventory, analyzed.ChartRoots, analyzed.ContentCache)
	for _, s := range services {
		s.FilePlatform = analyzed.FilePlatform
	}
	require.NoError(t, PrepareSharedWalk(ctx, fsp, services, "dangling-chart", false, 5))

	prepared := documentFingerprint(t, store)
	require.NotEmpty(t, prepared)
	found := false
	for key := range prepared {
		if strings.Contains(key, "main.tf") {
			found = true
			break
		}
	}
	require.True(t, found, "terraform file under dangling Chart.yaml symlink must be prepared")
}

// TestContentLineCountParity guards that chunked reads (getContent) and cached
// bytes (contentFromBytes) report identical line counts, including large files
// with no trailing newline that span multiple read chunks.
func TestContentLineCountParity(t *testing.T) {
	cases := map[string][]byte{
		"empty":             {},
		"no trailing nl":    []byte("a\nb\nc"),
		"trailing nl":       []byte("a\nb\nc\n"),
		"multi-mb no nl":    bytes.Repeat([]byte("x"), 3*mbConst+123),
		"multi-mb with nls": bytes.Repeat([]byte("line\n"), mbConst),
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			buf := make([]byte, mbConst)
			chunked, err := getContent(bytes.NewReader(content), buf, 100, name)
			require.NoError(t, err)
			cached, err := contentFromBytes(content, 100, name)
			require.NoError(t, err)
			require.Equal(t, cached.CountLines, chunked.CountLines,
				"cached and chunked line counts must match")
		})
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}

func keysSorted(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
