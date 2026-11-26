/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package runner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser"
	terraformParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/stretchr/testify/require"
)

func TestShareableParseRejectsTerragruntUnits(t *testing.T) {
	require.False(t, shareableParse(&parser.ParsedDocument{
		Content:               "terraform {}\n",
		Kind:                  model.KindTerraform,
		Docs:                  []model.Document{{"module": map[string]interface{}{}}},
		TerragruntTranslation: &model.TerragruntTranslation{FileName: "terragrunt.generated.tf"},
	}))
}

// Two units with identical content translate differently: each keeps its own
// translation and line information.
func TestSinkTerragruntIdenticalUnitsAreIsolated(t *testing.T) {
	ctx := context.Background()
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	unit := []byte("terraform {\n  source = \"../m\"\n}\ninputs = {\n  acl = \"public-read\"\n}\n")
	files := map[string]string{
		"a/terragrunt.hcl":   string(unit),
		"a/terraform.tfvars": `acl = "private"`,
		"b/terragrunt.hcl":   string(unit),
	}
	for name, content := range files {
		full := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(content), 0o600))
	}

	tf := terraformParser.NewDefaultWithParams(vfs.DiskFS{}, "", model.SCIInfo{RepositoryDir: root})
	tf.EnableTerragrunt()
	parsers, err := parser.NewBuilder(ctx).WithFS(vfs.DiskFS{}).Add(tf).Build([]string{"terraform"}, []string{""})
	require.NoError(t, err)
	svc := &Service{
		Parser:      parsers[0],
		Tracker:     noopTracker{},
		Storage:     nopLineInfoStorage{},
		MaxFileSize: 1 << 20,
		Platforms:   []string{"terraform"},
	}
	for _, name := range []string{"a/terragrunt.hcl", "b/terragrunt.hcl"} {
		content := append([]byte(nil), unit...)
		require.NoError(t, svc.sinkContent(ctx, filepath.Join(root, name), "scan1",
			&Content{Content: &content, CountLines: 6}, nil, false, 1))
	}
	svc.filesMu.Lock()
	got := append([]*model.FileMetadata(nil), svc.files...)
	svc.filesMu.Unlock()
	require.Len(t, got, 2)

	for _, f := range got {
		require.Equal(t, string(unit), f.OriginalData, "the original data stays the unit file")
		require.NotNil(t, f.TerragruntTranslation)
		want := `"public-read"`
		if f.FilePath == filepath.Join(root, "a/terragrunt.hcl") {
			want = `"private"`
		}
		require.Contains(t, f.TerragruntTranslation.Text, want)

		// The lazy line-info reparse reproduces the document, with real lines.
		require.NoError(t, f.EnsureLineInfoDocument(ctx))
		module := f.LineInfoDocument["module"].(model.Document)["terragrunt"].(model.Document)
		require.Equal(t, want[1:len(want)-1], module["acl"])
		lines := module["_dd_lines"].(map[string]model.LineObject)
		require.Equal(t, 2, lines["_dd_source"].Line)
		if f.FilePath == filepath.Join(root, "b/terragrunt.hcl") {
			require.Equal(t, 5, lines["_dd_acl"].Line)
		}
	}
}
