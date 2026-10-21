package runner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	dockerDetector "github.com/DataDog/datadog-iac-scanner/pkg/detector/docker"
	"github.com/DataDog/datadog-iac-scanner/pkg/dockerfile"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser"
	dockerParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/docker"
	jsonParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/json"
	terraformParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/stretchr/testify/require"
)

func buildTestParser(t *testing.T, ctx context.Context, add func(*parser.Builder) *parser.Builder) *parser.Parser {
	t.Helper()
	ps, err := add(parser.NewBuilder(ctx)).Build([]string{""}, []string{""})
	require.NoError(t, err)
	require.Len(t, ps, 1)
	return ps[0]
}

func TestEnsureLineInfoDocument_matchesEagerParse(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "main.tf")
	content := []byte(`resource "aws_s3_bucket" "logs" {
  bucket = "my-logs"
}
`)
	require.NoError(t, os.WriteFile(path, content, 0o600))

	p := buildTestParser(t, ctx, func(b *parser.Builder) *parser.Builder {
		return b.Add(terraformParser.NewDefault())
	})
	parsed, err := p.Parse(ctx, path, content, false, false, 15)
	require.NoError(t, err)
	require.Len(t, parsed.Docs, 1)

	file := &model.FileMetadata{
		OriginalData:      parsed.Content,
		Kind:              parsed.Kind,
		FilePath:          path,
		LinesOriginalData: utils.SplitLines(parsed.Content),
	}
	loader := newLineInfoLoader(p, path, 0, false, false, 15, nil)
	lazyDoc, err := loader(ctx, file)
	require.NoError(t, err)

	eagerJ, err := json.Marshal(parsed.Docs[0])
	require.NoError(t, err)
	lazyJ, err := json.Marshal(lazyDoc)
	require.NoError(t, err)
	require.JSONEq(t, string(eagerJ), string(lazyJ))

	file.SetLineInfoLoader(loader)
	require.NoError(t, file.EnsureLineInfoDocument(ctx))
	require.True(t, reflect.DeepEqual(lazyDoc, file.LineInfoDocument))
}

func TestEnsureLineInfoDocument_minifiedTFPlanUsesOriginalData(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "plan.json")
	minified := []byte(`{"format_version":"1.0","planned_values":{"root_module":{"resources":[{"address":"alicloud_db_instance.example","type":"alicloud_db_instance","name":"example","values":{"address":"0.0.0.0/0"}}]}}}`)
	require.NoError(t, os.WriteFile(path, minified, 0o600))

	jp := &jsonParser.Parser{}
	_, eagerFromMinified, _, _, err := jp.Parse(ctx, minified, path, false, 1)
	require.NoError(t, err)

	p := buildTestParser(t, ctx, func(b *parser.Builder) *parser.Builder {
		return b.Add(jp)
	})
	parsed, err := p.Parse(ctx, path, minified, false, false, 1)
	require.NoError(t, err)
	require.NotEqual(t, string(minified), parsed.Content)

	file := &model.FileMetadata{
		OriginalData:      parsed.Content,
		Kind:              model.KindTerraformPlan,
		FilePath:          path,
		LinesOriginalData: utils.SplitLines(parsed.Content),
	}
	loader := newLineInfoLoader(p, path, 0, false, false, 1, nil)
	lazyDoc, err := loader(ctx, file)
	require.NoError(t, err)
	require.False(t, reflect.DeepEqual(eagerFromMinified[0], lazyDoc),
		"lazy reparse aligns _dd_lines with indented OriginalData, not the initial minified parse")

	reparsed, err := p.Parse(ctx, path, []byte(parsed.Content), false, false, 1)
	require.NoError(t, err)
	lazyJ, err := json.Marshal(lazyDoc)
	require.NoError(t, err)
	reparsedJ, err := json.Marshal(reparsed.Docs[0])
	require.NoError(t, err)
	require.JSONEq(t, string(reparsedJ), string(lazyJ))

	file.SetLineInfoLoader(loader)
	require.NoError(t, file.EnsureLineInfoDocument(ctx))
	require.True(t, reflect.DeepEqual(lazyDoc, file.LineInfoDocument))
}

func TestDockerLineInfoReusesSourceParse(t *testing.T) {
	p := buildTestParser(t, t.Context(), func(b *parser.Builder) *parser.Builder { return b.Add(&dockerParser.Parser{}) })
	source := "FROM alpine\nCOPY <<EOF /x\nFROM busybox\nEOF\nrun echo hi\n"
	file := &model.FileMetadata{OriginalData: source, Kind: model.KindDOCKER, FilePath: "Dockerfile"}
	file.SetLazyLines()
	file.SetLineInfoLoader(newLineInfoLoader(p, file.FilePath, 0, false, false, 15, nil))
	require.NoError(t, file.EnsureLineInfoDocument(t.Context()))
	require.Contains(t, file.LineInfoDocument, "command", "the full document remains available")
	lines := file.DetectionLines(dockerfile.SourceViewKey, func([]string) []string {
		t.Fatal("line-info parsing must already have recorded the source view")
		return nil
	})
	require.Equal(t, "run echo hi", lines[4])
	require.Empty(t, lines[2], "heredoc payloads cannot become instructions")
}

// A non-Docker parser can participate without the runner knowing its format.
type recordingLineInfoParser struct {
	jsonParser.Parser
	record func(context.Context, *model.FileMetadata)
}

func (p *recordingLineInfoParser) LineInfoContext(ctx context.Context, file *model.FileMetadata) context.Context {
	p.record(ctx, file)
	return ctx
}

func TestLineInfoLoaderInvokesParserHook(t *testing.T) {
	file := &model.FileMetadata{OriginalData: `{"hello":"world"}`, Kind: model.KindJSON, FilePath: "input.json"}
	var recorded *model.FileMetadata
	hook := &recordingLineInfoParser{record: func(ctx context.Context, f *model.FileMetadata) {
		require.True(t, parser.IsLineInfoOnly(ctx))
		recorded = f
	}}
	p := buildTestParser(t, t.Context(), func(b *parser.Builder) *parser.Builder { return b.Add(hook) })
	file.SetLineInfoLoader(newLineInfoLoader(p, file.FilePath, 0, false, false, 15, nil))
	require.NoError(t, file.EnsureLineInfoDocument(t.Context()))
	require.Same(t, file, recorded)
	require.NotEmpty(t, file.LineInfoDocument)
}

// Cached compact locations and the uncached parse must produce the same full
// source document and logical lines, including raw declaration values.
func TestDockerLocationPathsAgree(t *testing.T) {
	for _, source := range []string{
		"FROM alpine\n\u00a0rUn echo hi ",
		"\u2003FROM alpine\n\u0085rUn echo hi ",
		"FROM alpine\nrUn\u00a0echo hi ",

		"FROM alpine\nRUN echo hi\r ",
		"FROM alpine\nRUN echo hi\r \\ \n there ",
		"FROM alpine\nRUN echo hi\r \\ \n\n",

		"FROM alpine\nRUN echo hi ",
		"FROM alpine \t\nRUN echo hi\t \n",
		"FROM alpine\nRUN echo hi \\",
		"FROM alpine\nRUN echo hi \\  \n\n",
		"# escape=`\nFROM alpine\nRUN echo hi `",
		"FROM alpine\n  RUN echo hi \t",
		"FROM alpine\nRUN echo hi \\   \n there \t\n",
		"FROM alpine\nRUN echo first \nFROM busybox\nRUN echo last \t",

		"FROM alpine\nRUN echo caf\xe9 $V\n",
		"FROM alpine\nRUN echo \x00 $V\n",
		"FROM alpine\nARG V=1\nENV A=$V\nRUN echo $A\n",
		"# escape=`\nFROM alpine\nRUN echo `\n hi\nFROM busybox\nRUN [\"echo\", \"hi\"]\n",
		"FROM alpine\nCOPY <<EOF /x\nFROM busybox\nEOF\nONBUILD RUN echo hi\n",
	} {
		t.Run(source, func(t *testing.T) {
			p := buildTestParser(t, t.Context(), func(b *parser.Builder) *parser.Builder { return b.Add(&dockerParser.Parser{}) })
			ctx, content := p.PrepareContext(t.Context(), "Dockerfile", []byte(source))
			_, err := p.Parse(ctx, "Dockerfile", content, false, false, 15)
			require.NoError(t, err)
			bind := p.SourceContext(ctx)
			require.NotNil(t, bind)
			// Getting the context is repeatable and must not end dispatch ownership.
			require.NotNil(t, p.SourceContext(ctx))
			p.FinishContext(ctx)
			var docs []map[string]interface{}
			var lines [][]string
			var findings []model.VulnerabilityLines
			for _, prepare := range []func(context.Context) context.Context{nil, bind} {
				file := &model.FileMetadata{OriginalData: string(content), Kind: model.KindDOCKER, FilePath: "Dockerfile"}
				file.SetLazyLines()
				loader := newLineInfoLoader(p, "Dockerfile", 0, false, false, 15, prepare)
				doc, err := loader(t.Context(), file)
				require.NoError(t, err)
				docs = append(docs, doc)
				view := file.DetectionLines(dockerfile.SourceViewKey, dockerfile.InstructionLines)
				lines = append(lines, view)
				findings = append(findings, (dockerDetector.DetectKindLine{}).DetectLine(t.Context(), file, "{{RUN echo}}", 0))
				physical := file.Lines()
				oracle := dockerfile.InstructionLines(physical)
				if len(oracle) > 0 && &oracle[0] == &physical[0] {
					require.Same(t, &physical[0], &view[0], "unchanged physical lines must be shared")
				}
			}
			require.Equal(t, docs[0], docs[1])
			require.Equal(t, lines[0], lines[1])
			require.Equal(t, findings[0], findings[1], "finding identity includes original text and end column")
		})
	}
}
