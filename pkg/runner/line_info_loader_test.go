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
	loader := newLineInfoLoader(p, path, 0, false, false, 15)
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
	loader := newLineInfoLoader(p, path, 0, false, false, 1)
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
