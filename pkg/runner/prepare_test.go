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
	"github.com/rs/zerolog"
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
	return buildServices(t, ctx, vfs.DiskFS{}, fsp)
}

func buildServices(t *testing.T, ctx context.Context, fsys vfs.FS, src provider.SourceProvider) ([]*Service, *storage.MemoryStorage) {
	t.Helper()

	trk, err := tracker.NewTracker(1)
	require.NoError(t, err)

	combinedParser, err := parser.NewBuilder(ctx).
		WithFS(fsys).
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

	combinedResolver, err := resolver.NewBuilder().Add(ctx, helm.NewResolver(fsys)).Build(ctx)
	require.NoError(t, err)

	store := storage.NewMemoryStorage()
	services := make([]*Service, 0, len(combinedParser))
	for _, p := range combinedParser {
		services = append(services, &Service{
			SourceProvider: src,
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

func TestPrepareMemorySources_RoutesPushedYAMLByContent(t *testing.T) {
	ctx := context.Background()
	deployPath := "k8s/deploy.yaml"
	workflowPath := ".github/workflows/ci.yaml"
	memfs := vfs.NewMemFS(map[string][]byte{
		deployPath:   []byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n"),
		workflowPath: []byte("name: ci\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n"),
	})
	mp := provider.NewMemorySourceProvider(memfs, memfs.Paths(), nil, nil)
	services, _ := buildServices(t, ctx, memfs, mp)
	shared, ok := SharedMemoryProvider(services)
	require.True(t, ok)
	require.NoError(t, PrepareMemorySources(ctx, shared, services, "routing", false, 5, false))

	for _, service := range services {
		paths := make([]string, 0, len(service.files))
		for _, file := range service.files {
			paths = append(paths, filepath.ToSlash(file.FilePath))
		}
		switch service.Parser.Parsers.(type) {
		case *cicdParser.Parser:
			require.Equal(t, []string{workflowPath}, paths)
		case *yamlParser.Parser:
			require.Equal(t, []string{deployPath}, paths)
		}
	}
}

// A pushed file whose content rules out every platform is skipped, as the
// analyzer skips it on disk, rather than handed to every parser that accepts
// its extension.
func TestPrepareMemorySources_SkipsFilesExcludedByContent(t *testing.T) {
	ctx := context.Background()
	memfs := vfs.NewMemFS(map[string][]byte{
		"setup.cfg":           []byte("[metadata]\nname = x\n"),
		"pytest.ini":          []byte("[pytest]\naddopts = -p auto\n"),
		"catalog/entity.yaml": []byte("apiVersion: v3\nkind: service\nmetadata:\n  name: web\n"),
		"ansible.cfg":         []byte("[defaults]\nno_log = False\n"),
	})
	mp := provider.NewMemorySourceProvider(memfs, memfs.Paths(), nil, nil)
	services, _ := buildServices(t, ctx, memfs, mp)
	shared, ok := SharedMemoryProvider(services)
	require.True(t, ok)
	require.NoError(t, PrepareMemorySources(ctx, shared, services, "excluded", false, 5, false))

	var paths []string
	for _, service := range services {
		for _, file := range service.files {
			paths = append(paths, filepath.ToSlash(file.FilePath))
		}
	}
	require.Equal(t, []string{"ansible.cfg"}, paths)
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

func TestPrepareSharedWalk_RenderedChartStillScansTerraform(t *testing.T) {
	ctx := context.Background()

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "Chart.yaml"), "apiVersion: v2\nname: root\nversion: 0.1.0\n")
	writeFile(t, filepath.Join(dir, "templates", "deployment.yaml"),
		"apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: {{ .Release.Name }}\n")
	mainTF := filepath.Join(dir, "infra", "main.tf")
	writeFile(t, mainTF, `resource "aws_s3_bucket" "b" { bucket = "my-bucket" }`)

	analyzed, err := analyzer.Analyze(ctx, &analyzer.Analyzer{
		RepoPath:    dir,
		Paths:       []string{dir},
		Types:       []string{""},
		MaxFileSize: 100,
	})
	require.NoError(t, err)

	services, store := buildParityServices(t, ctx, []string{dir})
	fsp, ok := SharedWalkProvider(services)
	require.True(t, ok)
	fsp.SetPrebuiltWalk(analyzed.Inventory, analyzed.ChartRoots, analyzed.ContentCache)
	for _, s := range services {
		s.FilePlatform = analyzed.FilePlatform
	}
	require.NoError(t, PrepareSharedWalk(ctx, fsp, services, "rendered-chart", false, 5))

	found := false
	for key := range documentFingerprint(t, store) {
		if strings.Contains(key, "main.tf") {
			found = true
			break
		}
	}
	require.True(t, found, "terraform beside a rendered root chart must still be prepared")
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

// A chart that fails to render for an unexpected reason is reported at error,
// and its raw templates, which are never valid YAML, still do not each add a
// parse error of their own.
func TestPrepareSharedWalk_UnexpectedRenderErrorStillSilencesRawTemplates(t *testing.T) {
	var logBuf bytes.Buffer
	ctx := zerolog.New(&logBuf).Level(zerolog.WarnLevel).WithContext(context.Background())
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "Chart.yaml"), "apiVersion: v2\nname: web\nversion: 0.1.0\nkubeVersion: \"<1.0.0\"\n")
	writeFile(t, filepath.Join(dir, "templates", "cm.yaml"), "kind: [unclosed\n")

	services, _ := buildParityServices(t, ctx, []string{dir})
	fsp, ok := SharedWalkProvider(services)
	require.True(t, ok)
	require.NoError(t, PrepareSharedWalk(ctx, fsp, services, "unexpected-render", false, 5))

	logged := logBuf.String()
	require.Contains(t, logged, "failed to render file content")
	require.Contains(t, logged, `"level":"error"`)
	require.NotContains(t, logged, "failed to parse file content")
	require.NotContains(t, logged, "Helm charts could not be rendered", "an unexpected failure is not summarized")
}

// libAppCharts is chart app depending, through file://, on its sibling lib,
// whose helper app's template includes.
var libAppCharts = map[string]string{
	"lib/Chart.yaml":            "apiVersion: v2\nname: lib\nversion: 1.0.0\n",
	"lib/templates/_labels.tpl": "{{- define \"lib.labels\" -}}\napp: {{ .Chart.Name }}\n{{- end -}}\n",
	"lib/templates/cm.yaml":     "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: lib\n",
	"app/Chart.yaml": "apiVersion: v2\nname: app\nversion: 1.0.0\n" +
		"dependencies:\n- name: lib\n  version: 1.0.0\n  repository: file://../lib\n",
	"app/templates/cm.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n" +
		"  name: app\n  labels:\n    {{- include \"lib.labels\" . | nindent 4 }}\n",
}

// storedFiles counts the files the YAML parser services stored, by slash path
// relative to dir.
func storedFiles(t *testing.T, services []*Service, dir string) map[string]int {
	t.Helper()
	stored := map[string]int{}
	for _, service := range services {
		if service.Parser.Parsers.GetKind() != model.KindYAML {
			continue
		}
		for _, file := range service.files {
			rel, err := filepath.Rel(dir, file.FilePath)
			require.NoError(t, err)
			stored[filepath.ToSlash(rel)]++
		}
	}
	return stored
}

// A chart renders with its dependency wherever the dependency lies, but the
// dependency's files are reported only when the scan's path filters keep them,
// and once even when the dependency is also scanned as a chart of its own.
func TestPrepareSharedWalk_DependencyChartFiles(t *testing.T) {
	tests := []struct {
		name       string
		ignore     []string
		only       []string
		perService []string // charts the per-service walk renders
		want       map[string]int
	}{
		{name: "both in scope", perService: []string{"app", "lib"},
			want: map[string]int{"app/templates/cm.yaml": 1, "lib/templates/cm.yaml": 1}},
		{name: "dependency outside only-paths", only: []string{"app"}, perService: []string{"app"},
			want: map[string]int{"app/templates/cm.yaml": 1}},
		{name: "dependency in an ignored directory", ignore: []string{"lib"}, perService: []string{"app"},
			want: map[string]int{"app/templates/cm.yaml": 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()
			for rel, body := range libAppCharts {
				writeFile(t, filepath.Join(dir, filepath.FromSlash(rel)), body)
			}
			inDir := func(rels []string) []string {
				var paths []string
				for _, rel := range rels {
					paths = append(paths, filepath.Join(dir, rel))
				}
				return paths
			}
			fsp, err := provider.NewFileSystemSourceProvider(ctx, []string{dir}, inDir(tt.ignore), inDir(tt.only))
			require.NoError(t, err)
			services, _ := buildServices(t, ctx, vfs.DiskFS{}, fsp)
			shared, ok := SharedWalkProvider(services)
			require.True(t, ok)
			require.NoError(t, PrepareSharedWalk(ctx, shared, services, "scan", false, 5))
			require.Equal(t, tt.want, storedFiles(t, services, dir))

			// The per-service path, used when parallel parsing is off, where
			// every service renders the charts itself.
			for _, service := range services {
				if service.Parser.Parsers.GetKind() != model.KindYAML {
					continue
				}
				service.files, service.storedHelm = nil, nil
				for _, chart := range tt.perService {
					_, err := service.resolverSink(ctx, filepath.Join(dir, chart), "scan", false, 5)
					require.NoError(t, err)
				}
				require.Equal(t, tt.want, storedFiles(t, []*Service{service}, dir))
			}
		})
	}
}

// The server renders a pushed chart with the pushed dependencies it declares,
// and drops the rendered files that the request's ignore-paths remove.
func TestPrepareMemorySources_DependencyInIgnorePathsIsNotReported(t *testing.T) {
	ctx := context.Background()
	pushed := make(map[string][]byte, len(libAppCharts))
	for rel, body := range libAppCharts {
		pushed[rel] = []byte(body)
	}
	memfs := vfs.NewMemFS(pushed)
	mp := provider.NewMemorySourceProvider(memfs, memfs.Paths(), []string{"lib/**"}, nil)
	services, _ := buildServices(t, ctx, memfs, mp)
	shared, ok := SharedMemoryProvider(services)
	require.True(t, ok)
	require.NoError(t, PrepareMemorySources(ctx, shared, services, "ignore-paths", false, 5, false))
	require.Equal(t, map[string]int{"app/templates/cm.yaml": 1}, storedFiles(t, services, "."))
}
