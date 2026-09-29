package runner

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/detector"
	helmDetector "github.com/DataDog/datadog-iac-scanner/pkg/detector/helm"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml/cicd"
	yamlParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml/default"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml/dockercompose"
	"github.com/DataDog/datadog-iac-scanner/pkg/resolver/helm"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

type parseCountingTracker struct {
	noopTracker
	found, parsed []string
	parsedLines   int
}

func (t *parseCountingTracker) TrackFileFound(path string)         { t.found = append(t.found, path) }
func (t *parseCountingTracker) TrackFileParse(path string)         { t.parsed = append(t.parsed, path) }
func (t *parseCountingTracker) TrackFileParseCountLines(lines int) { t.parsedLines += lines }

func requireYAMLDiagnostics(t *testing.T, logs string, count int, partial bool) {
	t.Helper()
	warnings, failures := 0, count
	if partial {
		warnings, failures = count, 0
	}
	require.Equal(t, warnings, strings.Count(logs, `"level":"warn"`), logs)
	require.Equal(t, failures, strings.Count(logs, `"level":"error"`), logs)
}

func TestSinkYAMLEmptyPartialAndFailedTracking(t *testing.T) {
	const good = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: example\n"
	for _, tt := range []struct {
		name, content     string
		docs, diagnostics int
		complete          bool
	}{
		{"empty", "", 0, 0, true},
		{"comments", "# comment\r\n", 0, 0, true},
		{"null", "---\nnull\n---\n", 0, 0, true},
		{"malformed first", "kind: [\n", 0, 2, false},
		{"malformed tail", good + "---\nkind: [\n", 2, 2, false},
		{"unsupported middle", good + "---\nscalar\n---\n" + good, 4, 2, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			ctx := zerolog.New(&logs).WithContext(context.Background())
			p := buildTestParser(t, ctx, func(b *parser.Builder) *parser.Builder { return b.Add(&yamlParser.Parser{}) })
			trk := &parseCountingTracker{}
			svc := &Service{Parser: p, Tracker: trk, Storage: nopLineInfoStorage{}, Platforms: []string{"kubernetes"},
				FilePlatform: map[string]string{"a.yaml": "kubernetes", "b.yaml": "kubernetes"}}
			// Byte-identical files must each report partial coverage, never hit a success cache.
			for _, name := range []string{"a.yaml", "b.yaml"} {
				content := []byte(tt.content)
				require.NoError(t, svc.sinkContent(ctx, name, "scan", &Content{Content: &content, CountLines: strings.Count(tt.content, "\n") + 1}, nil, false, 15))
			}
			require.Len(t, trk.found, 2)
			if tt.complete {
				require.Len(t, trk.parsed, 2)
			} else {
				require.Empty(t, trk.parsed)
				require.Zero(t, trk.parsedLines)
			}
			require.Len(t, svc.files, tt.docs)
			_, cached := svc.lookupSharedParse([]byte(tt.content))
			require.Nil(t, cached)
			requireYAMLDiagnostics(t, logs.String(), tt.diagnostics, tt.docs > 0)
			for _, file := range svc.files {
				require.Equal(t, "ConfigMap", file.Document["kind"])
				require.NoError(t, file.EnsureLineInfoDocument(ctx))
				require.NotEmpty(t, file.LineInfoDocument["_dd_lines"])
				line := detector.NewDetectLine(1).DetectLine(ctx, file, "metadata.name")
				require.Contains(t, []int{4, 11}, line.Line)
			}
			requireYAMLDiagnostics(t, logs.String(), tt.diagnostics, tt.docs > 0) // lazy reparsing must not repeat diagnostics
		})
	}
}

func TestSinkEmptyStringYAMLDocuments(t *testing.T) {
	const good = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: example\n"
	for _, empty := range []string{"\"\"\n", "''\n", "!!str \"\"\n", "!!str\n"} {
		for _, mixed := range []bool{false, true} {
			for _, mode := range []string{"raw", "resolved", "crd"} {
				t.Run(empty+"/"+mode+"/"+strconv.FormatBool(mixed), func(t *testing.T) {
					var logs bytes.Buffer
					ctx := zerolog.New(&logs).WithContext(context.Background())
					svc, _ := newYAMLResolverSinkService(t, ctx)
					trk := &parseCountingTracker{}
					svc.Tracker = trk
					const filename = "chart/templates/example.yaml"
					svc.FilePlatform = map[string]string{filename: "kubernetes"}
					content := []byte(empty)
					wantDocs := 0
					if mixed {
						content = []byte(empty + "---\n" + good + "---\n" + empty)
						wantDocs = 1
					}
					if mode == "raw" {
						require.NoError(t, svc.sinkContent(ctx, filename, "scan", &Content{Content: &content}, nil, false, 15))
					} else {
						svc.storeResolvedFiles(ctx, model.ResolvedFiles{File: []model.ResolvedHelm{{
							FileName: filename, Content: content, OriginalData: content, IsCRD: mode == "crd",
						}}}, model.KindHELM, "scan", false, 15)
					}
					require.Len(t, svc.files, wantDocs)
					require.Equal(t, []string{filename}, trk.parsed)
					for _, file := range svc.files {
						require.Equal(t, "ConfigMap", file.Document["kind"])
						require.NoError(t, file.EnsureLineInfoDocument(ctx))
						require.NotEmpty(t, file.LineInfoDocument["_dd_lines"])
					}
					requireYAMLDiagnostics(t, logs.String(), 0, false)
				})
			}
		}
	}
}

func TestInvalidRootScalarHasOneSafeDiagnostic(t *testing.T) {
	const good = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: example\n"
	for _, scalar := range []struct{ name, content string }{
		{"null", "!!null postgres://user:fake-secret@example.test/db"},
		{"integer", "!!int postgres://user:fake-secret@example.test/db"},
		{"boolean", "!!bool postgres://user:fake-secret@example.test/db"},
		{"binary", "!!binary postgres://user:fake-secret@example.test/db"},
		{"empty integer", `!!int ""`},
	} {
		for _, partial := range []bool{false, true} {
			name := scalar.name + "/failed"
			if partial {
				name = scalar.name + "/partial"
			}
			t.Run(name, func(t *testing.T) {
				var logs bytes.Buffer
				ctx := zerolog.New(&logs).WithContext(context.Background())
				p := buildTestParser(t, ctx, func(b *parser.Builder) *parser.Builder { return b.Add(&yamlParser.Parser{}) })
				trk := &parseCountingTracker{}
				svc := &Service{Parser: p, Tracker: trk, Storage: nopLineInfoStorage{},
					FilePlatform: map[string]string{"test.yaml": "kubernetes"}}
				content := []byte(scalar.content + "\n")
				if partial {
					content = append([]byte(good+"---\n"), content...)
				}
				require.NoError(t, svc.sinkContent(ctx, "test.yaml", "scan", &Content{Content: &content}, nil, false, 15))
				if partial {
					require.Len(t, svc.files, 1)
					require.NoError(t, svc.files[0].EnsureLineInfoDocument(ctx))
				} else {
					require.Empty(t, svc.files)
				}
				require.Empty(t, trk.parsed)
				_, cached := svc.lookupSharedParse(content)
				require.Nil(t, cached)
				require.NotContains(t, logs.String(), "fake-secret")
				requireYAMLDiagnostics(t, logs.String(), 1, partial)
			})
		}
	}
}

func TestYAMLUnknownAnchorHasOneSafeDiagnostic(t *testing.T) {
	const good = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: example\n---\n"
	for _, stream := range []struct {
		name, prefix, documentIndex string
		documents                   int
	}{
		{"failed", "", "1", 0},
		{"partial", good, "2", 1},
	} {
		for _, mode := range []string{"raw", "resolved", "crd"} {
			t.Run(stream.name+"/"+mode, func(t *testing.T) {
				var logs bytes.Buffer
				ctx := zerolog.New(&logs).WithContext(context.Background())
				svc, _ := newYAMLResolverSinkService(t, ctx)
				trk := &parseCountingTracker{}
				svc.Tracker = trk
				const filename = "chart/templates/example.yaml"
				svc.FilePlatform = map[string]string{filename: "kubernetes"}
				content := []byte(stream.prefix + "password: *FakeSecret123\n")
				if mode == "raw" {
					require.NoError(t, svc.sinkContent(ctx, filename, "scan", &Content{Content: &content}, nil, false, 15))
				} else {
					svc.storeResolvedFiles(ctx, model.ResolvedFiles{File: []model.ResolvedHelm{{
						FileName: filename, Content: content, OriginalData: content, IsCRD: mode == "crd",
					}}}, model.KindHELM, "scan", false, 15)
				}
				require.Len(t, svc.files, stream.documents)
				for _, file := range svc.files {
					require.Equal(t, "ConfigMap", file.Document["kind"])
					require.NoError(t, file.EnsureLineInfoDocument(ctx))
					require.NotEmpty(t, file.LineInfoDocument["_dd_lines"])
				}
				require.Len(t, trk.found, 1)
				require.Empty(t, trk.parsed)
				require.Zero(t, trk.parsedLines)
				_, cached := svc.lookupSharedParse(content)
				require.Nil(t, cached)
				require.NotContains(t, logs.String(), "FakeSecret123")
				require.Contains(t, logs.String(), "YAML document "+stream.documentIndex)
				require.Contains(t, logs.String(), "unknown anchor")
				requireYAMLDiagnostics(t, logs.String(), 1, stream.documents > 0) // lazy reparsing must not repeat diagnostics
			})
		}
	}
}

func TestStoreResolvedHelmPartialOriginalSuppression(t *testing.T) {
	ctx := context.Background()
	const original = `apiVersion: v1
kind: ConfigMap
metadata:
  # dd-iac-scan ignore-line
  name: first
---
{{ if true }}
apiVersion: v1
kind: ConfigMap
metadata:
  name: second
{{ end }}
`
	fsys := vfs.NewMemFS(map[string][]byte{
		"chart/Chart.yaml":            []byte("apiVersion: v2\nname: example\nversion: 0.1.0\n"),
		"chart/templates/config.yaml": []byte(original),
	})
	resolved, err := helm.NewResolver(fsys).Resolve(ctx, "chart")
	require.NoError(t, err)
	require.Len(t, resolved.File, 2)
	svc, store := newYAMLResolverSinkService(t, ctx)
	ignoreLines, err := svc.getOriginalIgnoreLines(ctx, resolved.File[0].FileName,
		resolved.File[0].OriginalData, model.KindHELM, false, false, 15)
	require.True(t, model.IsPartialYAMLParseError(err))
	require.Equal(t, []int{4, 5}, ignoreLines)

	svc.storeResolvedFiles(ctx, resolved, model.KindHELM, "partial-original", false, 15)
	files, err := store.GetFiles(ctx, "partial-original")
	require.NoError(t, err)
	require.Len(t, files, 2)
	for _, file := range files {
		// Both rendered documents use the same cached original-source metadata.
		require.Equal(t, []int{4, 5}, file.LinesIgnore)
		line := (helmDetector.DetectKindLine{}).DetectLine(ctx, file, "metadata.name", 1)
		name := file.Document["metadata"].(map[string]interface{})["name"]
		if name == "first" {
			require.Equal(t, 5, line.Line)
			require.Contains(t, file.LinesIgnore, line.Line)
		} else {
			require.Equal(t, "second", name)
			require.Equal(t, 11, line.Line)
			require.NotContains(t, file.LinesIgnore, line.Line)
		}
	}

	queries := []model.QueryMetadata{{
		Query: "partial-original-suppression", Platform: "kubernetes", InputData: "{}", Aggregation: 1,
		Metadata: map[string]interface{}{"id": "partial-original-suppression"},
		Content: `package datadog
DatadogPolicy contains result if {
  doc := input.document[_]
  result := {"documentId": doc.id, "searchKey": "metadata.name", "issueType": "IncorrectValue",
    "resourceType": doc.kind, "resourceName": doc.metadata.name}
}`,
	}}
	inspector, err := engine.NewInspector(ctx, &stubQueriesSource{queries: queries},
		engine.DefaultVulnerabilityBuilder, svc.Tracker.(engine.Tracker), &source.QueryInspectorParameters{},
		nil, "chart", false, false, 1, featureflags.NewLocalEvaluator(), fsys, false, false)
	require.NoError(t, err)
	vulnerabilities, err := inspector.Inspect(ctx, "partial-original", files, []string{"kubernetes"})
	require.NoError(t, err)
	require.Empty(t, inspector.GetFailedQueries())
	require.Len(t, vulnerabilities, 2)
	for _, vulnerability := range vulnerabilities {
		if vulnerability.ResourceName == "first" {
			require.True(t, vulnerability.IsSuppressed)
			require.Equal(t, model.SuppressionJustificationIgnoreComment, vulnerability.SuppressionJustification)
		} else {
			require.Equal(t, "second", vulnerability.ResourceName)
			require.False(t, vulnerability.IsSuppressed)
		}
	}
}

func TestResolvedOriginalIgnoreLinesRejectUnrelatedErrors(t *testing.T) {
	ctx := context.Background()
	parseErr := errors.New("unrelated parser failure")
	p := buildTestParser(t, ctx, func(b *parser.Builder) *parser.Builder {
		return b.Add(&errorWithDocumentParser{err: parseErr})
	})
	svc := &Service{Parser: p}
	original := []byte("kind: ConfigMap\n")
	ignoreLines, err := svc.getOriginalIgnoreLines(ctx, "chart/templates/test.yaml", original,
		model.KindHELM, false, false, 15)
	require.ErrorIs(t, err, parseErr)
	require.Empty(t, ignoreLines)

	cache := map[string]*resolvedSourceData{}
	for range 2 {
		documents := parser.ParsedDocument{IgnoreLines: []int{1, 2}}
		svc.setResolvedLineMetadata(ctx, &documents, &model.ResolvedHelm{
			FileName: "chart/templates/test.yaml", OriginalData: original,
			Content: []byte("# Source: chart/templates/test.yaml\nkind: ConfigMap\n"),
		}, cache, model.KindHELM, false, false, 15)
		require.Equal(t, []int{2}, documents.IgnoreLines)
	}
}

func TestYAMLPartialConsumers(t *testing.T) {
	ctx := context.Background()
	for _, tt := range []struct {
		name, path, good string
		add              func(*parser.Builder) *parser.Builder
	}{
		{"default", "manifest.yaml", "kind: ConfigMap\n", func(b *parser.Builder) *parser.Builder { return b.Add(&yamlParser.Parser{}) }},
		{"compose transform", "compose.yaml", "services:\n  web:\n    image: ${IMAGE:-nginx}\n", func(b *parser.Builder) *parser.Builder {
			return b.Add(dockercompose.NewDefaultWithFS(vfs.NewMemFS(nil)))
		}},
		{"compose simple", "custom.yaml", "services:\n  web:\n    image: nginx\n", func(b *parser.Builder) *parser.Builder {
			return b.Add(dockercompose.NewDefaultWithFS(vfs.NewMemFS(nil)))
		}},
		{"cicd", "workflow.yaml", "jobs:\n  build:\n    steps:\n      - run: echo hello\n        if: ${{ github.event_name == 'push' }}\n", func(b *parser.Builder) *parser.Builder { return b.Add(&cicd.Parser{}) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := buildTestParser(t, ctx, tt.add)
			docs, err := p.Parse(ctx, tt.path, []byte(tt.good+"---\nkind: [\n"), false, false, 15)
			require.True(t, model.IsPartialYAMLParseError(err))
			require.True(t, docs.Partial)
			require.Len(t, docs.Docs, 1)
			switch tt.name {
			case "compose transform", "compose simple":
				services := docs.Docs[0]["services"].(map[string]interface{})
				web := services["web"].(map[string]interface{})
				require.Equal(t, "nginx", web["image"])
			case "cicd":
				jobs := docs.Docs[0]["jobs"].(map[string]interface{})
				build := jobs["build"].(map[string]interface{})
				step := build["steps"].([]interface{})[0].(map[string]interface{})
				run := step["_parsed_run"].(*cicd.ParsedRun)
				require.True(t, run.ParseOK)
				require.Len(t, run.Commands, 1)
				require.Equal(t, "echo", run.Commands[0].Command)
				require.Equal(t, []cicd.ParsedArg{{Type: "literal", Value: "hello"}}, run.Commands[0].Args)
				expressions := step["_parsed_expressions_if"].([]cicd.ParsedExpression)
				require.Len(t, expressions, 1)
				require.True(t, expressions[0].ParseOK)
				require.Equal(t, "github.event_name == 'push'", expressions[0].Raw)
			}
			require.False(t, shareableParse(&docs))
			file := &model.FileMetadata{OriginalData: docs.Content}
			loader := newLineInfoLoader(p, tt.path, 0, false, false, 15)
			lineDoc, err := loader(ctx, file)
			require.NoError(t, err)
			require.NotEmpty(t, lineDoc["_dd_lines"])
			empty, err := p.Parse(ctx, tt.path, []byte("# empty\n"), false, false, 15)
			require.NoError(t, err)
			require.Empty(t, empty.Docs)
		})
	}
}

func TestSinkFailedHelmPartialYAMLStaysDebug(t *testing.T) {
	var logs bytes.Buffer
	ctx := zerolog.New(&logs).WithContext(context.Background())
	svc, _ := newYAMLResolverSinkService(t, ctx)
	trk := &parseCountingTracker{}
	svc.Tracker = trk
	const filename = "chart/templates/example.yaml"
	svc.FilePlatform = map[string]string{filename: "kubernetes"}
	svc.recordFailedHelmChart("chart")
	content := []byte("kind: ConfigMap\n---\npassword: *FakeSecret123\n")
	logs.Reset()
	require.NoError(t, svc.sinkContent(ctx, filename, "scan", &Content{Content: &content}, nil, false, 15))
	require.Len(t, svc.files, 1)
	require.NoError(t, svc.files[0].EnsureLineInfoDocument(ctx))
	require.Empty(t, trk.parsed)
	require.Zero(t, trk.parsedLines)
	_, cached := svc.lookupSharedParse(content)
	require.Nil(t, cached)
	require.NotContains(t, logs.String(), "FakeSecret123")
	require.Contains(t, logs.String(), "skipping unparseable raw Helm template")
	require.Equal(t, 1, strings.Count(logs.String(), `"level":"debug"`), logs.String())
	requireYAMLDiagnostics(t, logs.String(), 0, false)
}

func TestStoreResolvedPartialYAML(t *testing.T) {
	for _, crd := range []bool{false, true} {
		var logs bytes.Buffer
		ctx := zerolog.New(&logs).WithContext(context.Background())
		svc, _ := newYAMLResolverSinkService(t, ctx)
		trk := &parseCountingTracker{}
		svc.Tracker = trk
		content := []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: example\n---\nkind: [\n")
		svc.storeResolvedFiles(ctx, model.ResolvedFiles{File: []model.ResolvedHelm{{FileName: "chart/templates/example.yaml", Content: content, OriginalData: content, IsCRD: crd}}}, model.KindHELM, "scan", false, 15)
		require.Len(t, trk.found, 1)
		require.Empty(t, trk.parsed)
		require.Zero(t, trk.parsedLines)
		require.Len(t, svc.files, 1)
		require.NoError(t, svc.files[0].EnsureLineInfoDocument(ctx))
		require.NotEmpty(t, svc.files[0].LineInfoDocument["_dd_lines"])
		requireYAMLDiagnostics(t, logs.String(), 1, true)
	}
}

type errorWithDocumentParser struct {
	yamlParser.Parser
	err error
}

func (p *errorWithDocumentParser) Parse(_ context.Context, content []byte, _ string, _ bool, _ int) ([]byte, []model.Document, []int, map[string]model.ResolvedFile, error) {
	return content, []model.Document{{"kind": "ConfigMap"}}, []int{4, 5}, nil, p.err
}

func TestSinkOnlyTypedPartialErrorsRetainDocuments(t *testing.T) {
	for _, partial := range []bool{false, true} {
		parseErr := errors.New("invalid postgres://user:secret@example.test/db")
		if partial {
			parseErr = &model.PartialYAMLParseError{Err: parseErr}
		}
		var logs bytes.Buffer
		ctx := zerolog.New(&logs).WithContext(context.Background())
		p := buildTestParser(t, ctx, func(b *parser.Builder) *parser.Builder { return b.Add(&errorWithDocumentParser{err: parseErr}) })
		trk := &parseCountingTracker{}
		svc := &Service{Parser: p, Tracker: trk, Storage: nopLineInfoStorage{},
			FilePlatform: map[string]string{"test.yaml": "kubernetes"}}
		content := []byte("kind: ConfigMap\n")
		require.NoError(t, svc.sinkContent(ctx, "test.yaml", "scan", &Content{Content: &content}, nil, false, 15))
		if partial {
			require.Len(t, svc.files, 1)
		} else {
			require.Empty(t, svc.files)
		}
		require.Empty(t, trk.parsed)
		require.NotContains(t, logs.String(), "user:secret")
		require.Contains(t, logs.String(), "postgres://example.test/db")
		requireYAMLDiagnostics(t, logs.String(), 1, partial)
	}
}
