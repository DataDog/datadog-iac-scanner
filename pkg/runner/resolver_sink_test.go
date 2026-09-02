/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package runner

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/internal/storage"
	"github.com/DataDog/datadog-iac-scanner/internal/tracker"
	"github.com/DataDog/datadog-iac-scanner/pkg/detector"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser"
	"github.com/DataDog/datadog-iac-scanner/pkg/resolver/helm"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/stretchr/testify/require"

	jsonParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/json"
	yamlParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml/default"
)

func newYAMLResolverSinkService(
	t *testing.T, ctx context.Context,
) (*Service, *storage.MemoryStorage) {
	t.Helper()
	parsers, err := parser.NewBuilder(ctx).
		WithFS(vfs.DiskFS{}).
		Add(&yamlParser.Parser{}).
		Build([]string{"kubernetes"}, nil)
	require.NoError(t, err)
	require.Len(t, parsers, 1)

	trk, err := tracker.NewTracker(1)
	require.NoError(t, err)
	store := storage.NewMemoryStorage()
	service := &Service{
		Storage:   store,
		Parser:    parsers[0],
		Tracker:   trk,
		Platforms: []string{"kubernetes"},
	}
	return service, store
}

func TestPrepareResolvedScanDocumentPreparesHelmInPlace(t *testing.T) {
	nested := map[string]interface{}{
		"_dd_lines": map[string]interface{}{"name": 2},
		"name":      "widget",
	}
	document := map[string]interface{}{
		"_dd_lines": map[string]interface{}{"metadata": 1},
		"metadata":  nested,
		"versions": []interface{}{
			map[string]interface{}{
				"_dd_lines": map[string]interface{}{"name": 5},
				"name":      "v1",
			},
		},
	}

	prepared, err := prepareResolvedScanDocument(document, model.KindHELM)
	require.NoError(t, err)
	require.NotContains(t, prepared, "_dd_lines")
	require.NotContains(t, nested, "_dd_lines")
	require.NotContains(t, prepared["versions"].([]interface{})[0], "_dd_lines")
	prepared["prepared-only"] = true
	require.True(t, document["prepared-only"].(bool))
}

func TestStoreResolvedFilesParsesHelmJSONWithYAMLParser(t *testing.T) {
	ctx := context.Background()
	chartPath, err := filepath.Abs("../../test/fixtures/test_helm_with_crds")
	require.NoError(t, err)
	resolved, err := (&helm.Resolver{}).Resolve(ctx, chartPath)
	require.NoError(t, err)

	service, store := newYAMLResolverSinkService(t, ctx)

	service.storeResolvedFiles(ctx, resolved, model.KindHELM, "helm-crds", false, 15)

	files, err := store.GetFiles(ctx, "helm-crds")
	require.NoError(t, err)
	require.Len(t, files, 7)

	expectedPaths := map[string]int{
		"crds/gadget.json":               1,
		"crds/multi.yaml":                2,
		"crds/nested/device.yaml":        1,
		"crds/nested/crds/repeated.yaml": 1,
		"crds/widget.yaml":               1,
		"templates/service.yaml":         1,
	}
	for _, file := range files {
		normalized := filepath.ToSlash(file.FilePath)
		for suffix, remaining := range expectedPaths {
			if remaining > 0 && strings.HasSuffix(normalized, suffix) {
				expectedPaths[suffix]--
				if suffix == "crds/gadget.json" {
					require.Equal(t, "CustomResourceDefinition", file.Document["kind"])
					metadata, ok := file.Document["metadata"].(map[string]interface{})
					require.True(t, ok)
					require.Equal(t, "gadgets.example.com", metadata["name"])
				}
				break
			}
		}
	}
	for suffix, remaining := range expectedPaths {
		require.Zero(t, remaining, "missing stored Helm document for %s", suffix)
	}
}

func TestStoreResolvedFilesLazilyReconstructsHelmCRDLineInfo(t *testing.T) {
	ctx := context.Background()
	chartPath, err := filepath.Abs("../../test/fixtures/test_helm_with_crds")
	require.NoError(t, err)
	resolved, err := (&helm.Resolver{}).Resolve(ctx, chartPath)
	require.NoError(t, err)

	service, store := newYAMLResolverSinkService(t, ctx)
	expectedByName := make(map[string]map[string]interface{})
	for _, rfile := range resolved.File {
		if !rfile.IsCRD {
			continue
		}
		parsed, parseErr := service.parseResolvedFile(
			ctx, rfile.FileName, rfile.OriginalData, model.KindHELM, false, false, 15)
		require.NoError(t, parseErr)
		require.Greater(t, len(parsed.Docs), rfile.SourceDocumentIndex)
		expectedDocument := parsed.Docs[rfile.SourceDocumentIndex]
		metadata, ok := expectedDocument["metadata"].(map[string]interface{})
		require.True(t, ok)
		name, ok := metadata["name"].(string)
		require.True(t, ok)
		expectedByName[name] = expectedDocument
	}
	require.Len(t, expectedByName, 6)

	service.storeResolvedFiles(ctx, resolved, model.KindHELM, "lazy-crd-line-info", false, 15)
	files, err := store.GetFiles(ctx, "lazy-crd-line-info")
	require.NoError(t, err)

	actualCRDs := 0
	for _, file := range files {
		if file.Document["kind"] != "CustomResourceDefinition" {
			continue
		}
		actualCRDs++
		metadata, ok := file.Document["metadata"].(map[string]interface{})
		require.True(t, ok)
		name, ok := metadata["name"].(string)
		require.True(t, ok)

		require.Nil(t, file.LineInfoDocument)
		lineBeforeLoad := detector.NewDetectLine(1).DetectLine(ctx, file, "metadata.name")
		require.Greater(t, lineBeforeLoad.Line, 0)
		originalData := file.OriginalData
		require.NoError(t, file.EnsureLineInfoDocument(ctx))
		require.Equal(t, originalData, file.OriginalData)

		eagerJSON, marshalErr := json.Marshal(expectedByName[name])
		require.NoError(t, marshalErr)
		lazyJSON, marshalErr := json.Marshal(file.LineInfoDocument)
		require.NoError(t, marshalErr)
		require.JSONEq(t, string(eagerJSON), string(lazyJSON))

		lineAfterLoad := detector.NewDetectLine(1).DetectLine(ctx, file, "metadata.name")
		require.Equal(t, lineBeforeLoad, lineAfterLoad, name)
	}
	require.Equal(t, len(expectedByName), actualCRDs)
}

func TestStoreResolvedFilesKeepsRenderedLineInfoForHelmTemplates(t *testing.T) {
	ctx := context.Background()
	service, store := newYAMLResolverSinkService(t, ctx)
	service.storeResolvedFiles(ctx, model.ResolvedFiles{
		File: []model.ResolvedHelm{{
			FileName:     "chart/templates/service.yaml",
			Content:      []byte("apiVersion: v1\nkind: Service\nmetadata:\n  name: api\n"),
			OriginalData: []byte("apiVersion: v1\nkind: Service\nmetadata:\n  name: {{ .Values.name }}\n"),
		}},
	}, model.KindHELM, "rendered-template-line-info", false, 15)

	files, err := store.GetFiles(ctx, "rendered-template-line-info")
	require.NoError(t, err)
	require.Len(t, files, 1)
	require.NoError(t, files[0].EnsureLineInfoDocument(ctx))
	metadata, ok := files[0].LineInfoDocument["metadata"].(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, "api", metadata["name"])
}

func TestStoreResolvedFilesKeepsCRDSuppressionLines(t *testing.T) {
	ctx := context.Background()
	service, store := newYAMLResolverSinkService(t, ctx)
	original := []byte("# dd-iac-scan ignore-block\n# KICS_HELM_ID_1:\napiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\n")
	content := []byte("\n# Source: chart/crds/widget.yaml\n" + string(original))
	service.storeResolvedFiles(ctx, model.ResolvedFiles{
		File: []model.ResolvedHelm{{
			FileName:     "chart/crds/widget.yaml",
			Content:      content,
			OriginalData: original,
			IsCRD:        true,
		}},
	}, model.KindHELM, "crd-suppression", false, 15)

	files, err := store.GetFiles(ctx, "crd-suppression")
	require.NoError(t, err)
	require.Len(t, files, 1)
	require.Equal(t, []int{1, 2, 3}, files[0].LinesIgnore)
}

func TestStoreResolvedFilesContinuesAfterUnsupportedFile(t *testing.T) {
	ctx := context.Background()
	service, store := newYAMLResolverSinkService(t, ctx)
	resolved := model.ResolvedFiles{
		File: []model.ResolvedHelm{
			{FileName: "chart/notes.txt", Content: []byte("unsupported")},
			{
				FileName:     "chart/templates/service.yaml",
				Content:      []byte("apiVersion: v1\nkind: Service\nmetadata:\n  name: api\n"),
				OriginalData: []byte("apiVersion: v1\nkind: Service\nmetadata:\n  name: api\n"),
			},
		},
	}

	service.storeResolvedFiles(ctx, resolved, model.KindHELM, "unsupported-sibling", false, 15)

	files, err := store.GetFiles(ctx, "unsupported-sibling")
	require.NoError(t, err)
	require.Len(t, files, 1)
	require.Equal(t, "chart/templates/service.yaml", files[0].FilePath)
}

func TestStoreResolvedFilesContinuesAfterMalformedFile(t *testing.T) {
	ctx := context.Background()
	service, store := newYAMLResolverSinkService(t, ctx)
	resolved := model.ResolvedFiles{
		File: []model.ResolvedHelm{
			{FileName: "chart/crds/broken.yaml", Content: []byte("spec: [")},
			{
				FileName:     "chart/templates/service.yaml",
				Content:      []byte("apiVersion: v1\nkind: Service\nmetadata:\n  name: api\n"),
				OriginalData: []byte("apiVersion: v1\nkind: Service\nmetadata:\n  name: api\n"),
			},
		},
	}

	service.storeResolvedFiles(ctx, resolved, model.KindHELM, "malformed-sibling", false, 15)

	files, err := store.GetFiles(ctx, "malformed-sibling")
	require.NoError(t, err)
	require.Len(t, files, 1)
	require.Equal(t, "chart/templates/service.yaml", files[0].FilePath)
}

func TestStoreResolvedFilesSkipsHelmJSONOnJSONParser(t *testing.T) {
	ctx := context.Background()
	parsers, err := parser.NewBuilder(ctx).
		Add(&jsonParser.Parser{}).
		Build([]string{"kubernetes"}, nil)
	require.NoError(t, err)
	require.Len(t, parsers, 1)

	trk, err := tracker.NewTracker(1)
	require.NoError(t, err)
	store := storage.NewMemoryStorage()
	service := &Service{
		Storage: store,
		Parser:  parsers[0],
		Tracker: trk,
	}
	resolved := model.ResolvedFiles{
		File: []model.ResolvedHelm{{
			FileName: "chart/crds/gadget.json",
			Content:  []byte(`{"apiVersion":"v1","kind":"ConfigMap"}`),
		}},
	}

	service.storeResolvedFiles(ctx, resolved, model.KindHELM, "json-parser", false, 15)

	files, err := store.GetFiles(ctx, "json-parser")
	require.NoError(t, err)
	require.Empty(t, files)
}

func TestIsExpectedHelmRenderError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"nil pointer evaluating", errors.New("template: chart/templates/deploy.yaml:5:14: executing \"deploy\" at <.Values.global.name>: nil pointer evaluating interface {}.name"), true},
		{"map has no entry for key", errors.New("map has no entry for key \"datacenter\""), true},
		{"can't evaluate field", errors.New("can't evaluate field Images in type interface {}"), true},
		{"required helper", errors.New("template: chart/templates/deploy.yaml:3:10: executing \"deploy\" at <required \"datacenter\" .Values.datacenter>: error calling required: HELM_ERR_STARTdatacenterHELM_ERR_END"), true},
		// fail is excluded from expected signatures — it is also used for real validation
		// logic (e.g. unsupported kube version) that can trigger with values present.
		{"fail helper stays at error", errors.New("template: chart/templates/deploy.yaml:2:5: executing \"deploy\" at <fail \"env required\">: error calling fail: HELM_ERR_STARTenv requiredHELM_ERR_END"), false},
		{"unrelated render failure", errors.New("chart requires kubeVersion: >=1.20.0 which is incompatible with Kubernetes v1.14.0"), false},
		{"load error", errors.New("failed to load chart from '/repo/chart': no Chart.yaml found"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, isExpectedHelmRenderError(tt.err))
		})
	}
}

func TestIsUnderFailedHelmChart(t *testing.T) {
	svc := &Service{}
	svc.recordFailedHelmChart("/repo/charts/watchdog")
	svc.recordFailedHelmChart("/repo/charts/ingester/")

	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{"direct child template", "/repo/charts/watchdog/templates/deploy.yaml", true},
		{"nested path", "/repo/charts/watchdog/templates/subdir/cm.yaml", true},
		{"trailing-slash chart normalised", "/repo/charts/ingester/templates/svc.yaml", true},
		{"sibling chart not matched", "/repo/charts/other/templates/deploy.yaml", false},
		{"chart root itself not matched", "/repo/charts/watchdog", false},
		{"unrelated file", "/repo/main.tf", false},
		// Non-template chart files must not be suppressed: genuine YAML errors there
		// are real bugs, not expected Go-template fallout.
		{"values.yaml not suppressed", "/repo/charts/watchdog/values.yaml", false},
		{"crds not suppressed", "/repo/charts/watchdog/crds/my-crd.yaml", false},
		{"Chart.yaml not suppressed", "/repo/charts/watchdog/Chart.yaml", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, svc.isUnderFailedHelmChart(tt.filePath))
		})
	}
}

func TestIsUnderFailedHelmChart_NilMap(t *testing.T) {
	// Before any chart has failed, the map is nil; iterating it must be a no-op.
	svc := &Service{}
	require.False(t, svc.isUnderFailedHelmChart("/repo/charts/anything/templates/deploy.yaml"))
}

func TestIsUnderFailedHelmChart_RelativeRoot(t *testing.T) {
	// filepath.Walk(".") reports children as "templates/deploy.yaml" (no leading "./"),
	// so prefix matching must work even when the chart dir is relative.
	svc := &Service{}
	svc.recordFailedHelmChart(".")

	require.True(t, svc.isUnderFailedHelmChart("templates/deploy.yaml"))
	require.True(t, svc.isUnderFailedHelmChart("templates/subdir/cm.yaml"))
	// Non-template files in the same chart must not be suppressed.
	require.False(t, svc.isUnderFailedHelmChart("values.yaml"))
	require.False(t, svc.isUnderFailedHelmChart("crds/my-crd.yaml"))
	// An absolute path outside cwd must not match.
	require.False(t, svc.isUnderFailedHelmChart("/other/repo/templates/deploy.yaml"))
}

func TestIsCommentOnlyContent(t *testing.T) {
	tests := []struct {
		name    string
		content []byte
		want    bool
	}{
		{"empty", []byte(""), true},
		{"blank lines only", []byte("\n\n"), true},
		{"all comments", []byte("# foo\n# bar"), true},
		// isCommentOnlyContent is called on post-split segments, so --- never
		// appears in practice, but the function correctly rejects it as a non-comment.
		{"yaml separator is not a comment", []byte("---\n# comment"), false},
		{"real yaml line", []byte("foo: 1"), false},
		{"comment then yaml", []byte("# ok\nfoo: 1"), false},
		{"whitespace then yaml", []byte("  foo: bar"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, isCommentOnlyContent(tt.content))
		})
	}
}

func TestFilterHelmGeneratedLines(t *testing.T) {
	// Rendered Helm split content that resembles real scanner output.
	// Line 1: empty
	// Line 2: # Source: … (Helm-generated)
	// Line 3: # KICS_HELM_ID_2: (scanner-injected)
	// Line 4: apiVersion: apps/v1
	// Line 5: kind: Deployment
	// Line 6: # some user comment
	// Line 7: metadata:
	renderedContent := []byte("\n# Source: dsm-demo/templates/deployment.yaml\n# KICS_HELM_ID_2:\napiVersion: apps/v1\nkind: Deployment\n# some user comment\nmetadata:\n")

	tests := []struct {
		name        string
		content     []byte
		ignoreLines []int
		want        []int
	}{
		{
			name:        "removes Source and KICS_HELM_ID lines",
			content:     renderedContent,
			ignoreLines: []int{2, 3, 6},
			want:        []int{6},
		},
		{
			name:        "keeps user comment lines untouched",
			content:     renderedContent,
			ignoreLines: []int{6, 7},
			want:        []int{6, 7},
		},
		{
			name:        "no generated lines present — input unchanged",
			content:     renderedContent,
			ignoreLines: []int{4, 5, 7},
			want:        []int{4, 5, 7},
		},
		{
			name:        "empty ignore list stays empty",
			content:     renderedContent,
			ignoreLines: []int{},
			want:        []int{},
		},
		{
			name:        "out-of-range line numbers are kept as-is",
			content:     renderedContent,
			ignoreLines: []int{99, 100},
			want:        []int{99, 100},
		},
		{
			name:        "only generated lines — all removed",
			content:     renderedContent,
			ignoreLines: []int{2, 3},
			want:        []int{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterHelmGeneratedLines(tt.content, tt.ignoreLines)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestFilterHelmGeneratedLines_DDIacScanCommentKept(t *testing.T) {
	// Content where the dd-iac-scan directive appears alongside generated headers.
	// Line 1: empty
	// Line 2: # Source: chart/templates/deploy.yaml
	// Line 3: # KICS_HELM_ID_0:
	// Line 4: # dd-iac-scan ignore-block
	// Line 5: apiVersion: apps/v1
	content := []byte("\n# Source: chart/templates/deploy.yaml\n# KICS_HELM_ID_0:\n# dd-iac-scan ignore-block\napiVersion: apps/v1\n")

	// Suppose processBlock added lines 4 and 5 (not 2 and 3, since it anchors to
	// apiVersion.Line and apiVersion.Line-1). But even if 2 and 3 were included,
	// they should be removed while 4 stays.
	ignoreLines := []int{2, 3, 4, 5}
	got := filterHelmGeneratedLines(content, ignoreLines)

	// Lines 2 and 3 are generated; lines 4 and 5 are real content.
	require.Equal(t, []int{4, 5}, got)
}
