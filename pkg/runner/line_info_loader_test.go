package runner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser"
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
	file.SetLineInfoSource(newLineInfoSource(p, path, false, false, 15), 0)
	require.NoError(t, file.EnsureLineInfoDocument(ctx))

	eagerJ, err := json.Marshal(parsed.Docs[0])
	require.NoError(t, err)
	lazyJ, err := json.Marshal(file.LineInfoDocument)
	require.NoError(t, err)
	require.JSONEq(t, string(eagerJ), string(lazyJ))
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
	file.SetLineInfoSource(newLineInfoSource(p, path, false, false, 1), 0)
	require.NoError(t, file.EnsureLineInfoDocument(ctx))
	require.False(t, reflect.DeepEqual(eagerFromMinified[0], file.LineInfoDocument),
		"lazy reparse aligns _dd_lines with indented OriginalData, not the initial minified parse")

	reparsed, err := p.Parse(ctx, path, []byte(parsed.Content), false, false, 1)
	require.NoError(t, err)
	lazyJ, err := json.Marshal(file.LineInfoDocument)
	require.NoError(t, err)
	reparsedJ, err := json.Marshal(reparsed.Docs[0])
	require.NoError(t, err)
	require.JSONEq(t, string(reparsedJ), string(lazyJ))
}

// Scanned and Helm rendered files both reparse through
// newReparseLineInfoSource, so parsers skip what only a scan needs.
func TestNewReparseLineInfoSource_reparsesOnlyForLineInfo(t *testing.T) {
	var lineInfoOnly bool
	src := newReparseLineInfoSource("main.tf", func(ctx context.Context, _ *model.FileMetadata) (parser.ParsedDocument, error) {
		lineInfoOnly = parser.IsLineInfoOnly(ctx)
		return parser.ParsedDocument{Docs: []model.Document{{}}}, nil
	})
	file := &model.FileMetadata{}
	file.SetLineInfoSource(src, 0)
	require.NoError(t, file.EnsureLineInfoDocument(context.Background()))
	require.True(t, lineInfoOnly)
}
