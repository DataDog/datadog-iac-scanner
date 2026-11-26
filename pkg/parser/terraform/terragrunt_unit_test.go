/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package terraform

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	iacparser "github.com/DataDog/datadog-iac-scanner/pkg/parser"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const unitContent = `terraform {
  source = "../modules/bucket"
}

inputs = {
  # dd-iac-scan ignore-line
  acl    = "public-read"
  region = local.region
}
`

func writeUnit(t *testing.T, content string) (root, unit string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	unit = filepath.Join(root, "live", "terragrunt.hcl")
	require.NoError(t, os.MkdirAll(filepath.Dir(unit), 0o755))
	require.NoError(t, os.WriteFile(unit, []byte(content), 0o600))
	return root, unit
}

func unitParser(root string, enabled bool) *Parser {
	p := NewDefaultWithParams(vfs.DiskFS{}, "", model.SCIInfo{RepositoryDir: root})
	if enabled {
		p.EnableTerragrunt()
	}
	return p
}

func moduleBlock(t *testing.T, doc model.Document) model.Document {
	t.Helper()
	modules, ok := doc["module"].(model.Document)
	require.True(t, ok, "%v", doc)
	block, ok := modules["terragrunt"].(model.Document)
	require.True(t, ok, "%v", modules)
	return block
}

func TestParseUnitDocumentAndLines(t *testing.T) {
	root, unit := writeUnit(t, unitContent)
	p := unitParser(root, true)

	resolved, docs, ignore, _, err := p.Parse(context.Background(), []byte(unitContent), unit, true, 15)
	require.NoError(t, err)
	assert.Equal(t, unitContent, string(resolved), "the original content stays the unit file")
	require.Len(t, docs, 1)

	block := moduleBlock(t, docs[0])
	assert.Equal(t, "../modules/bucket", block["source"])
	assert.Equal(t, "public-read", block["acl"])
	assert.Equal(t, "${__dd_unknown__}", block["region"])

	lines, ok := block["_dd_lines"].(map[string]model.LineObject)
	require.True(t, ok)
	assert.Equal(t, 2, lines["_dd_source"].Line, "source maps to the terraform.source line")
	assert.Equal(t, 7, lines["_dd_acl"].Line)
	assert.Equal(t, 8, lines["_dd_region"].Line)
	assert.Equal(t, 2, lines["_dd__default"].Line, "the block maps to the source line")
	top, ok := docs[0]["_dd_lines"].(map[string]model.LineObject)
	require.True(t, ok)
	assert.Equal(t, 2, top["_dd_module"].Line)

	assert.Contains(t, ignore, 7, "the ignore comment of the real file applies")
}

func TestParseUnitLazyLineInfoHasSameDocuments(t *testing.T) {
	root, unit := writeUnit(t, unitContent)
	p := unitParser(root, true)

	_, lazy, _, _, err := p.Parse(iacparser.WithLazyLineInfo(context.Background()), []byte(unitContent), unit, true, 15)
	require.NoError(t, err)
	_, full, _, _, err := p.Parse(iacparser.WithLineInfoOnly(context.Background()), []byte(unitContent), unit, true, 15)
	require.NoError(t, err)

	assert.Equal(t, withoutLines(lazy[0]), withoutLines(full[0]))
	_, hasLines := moduleBlock(t, lazy[0])["_dd_lines"]
	assert.False(t, hasLines, "a lazy parse carries no line information")
	_, hasLines = moduleBlock(t, full[0])["_dd_lines"]
	assert.True(t, hasLines)
}

func TestParseUnitOutputCarriesTranslation(t *testing.T) {
	root, unit := writeUnit(t, unitContent)
	built, err := iacparser.NewBuilder(context.Background()).WithFS(vfs.DiskFS{}).
		Add(unitParser(root, true)).Build([]string{"terraform"}, nil)
	require.NoError(t, err)
	require.Len(t, built, 1)

	out, err := built[0].Parse(context.Background(), unit, []byte(unitContent), true, false, 15)
	require.NoError(t, err)
	assert.Equal(t, model.KindTerraform, out.Kind)
	assert.Equal(t, unitContent, out.Content)
	require.NotNil(t, out.TerragruntTranslation)
	assert.Contains(t, out.TerragruntTranslation.Text, `module "terragrunt"`)
	assert.NotEmpty(t, out.TerragruntTranslation.Lines)

	// Plain Terraform files carry none.
	tf := filepath.Join(root, "live", "main.tf")
	require.NoError(t, os.WriteFile(tf, []byte(`resource "a" "b" {}`), 0o600))
	out, err = built[0].Parse(context.Background(), tf, []byte(`resource "a" "b" {}`), true, false, 15)
	require.NoError(t, err)
	assert.Nil(t, out.TerragruntTranslation)
}

func TestParseUnitSyntaxErrorIsParseError(t *testing.T) {
	bad := "terraform {\n"
	root, unit := writeUnit(t, bad)
	_, _, _, _, err := unitParser(root, true).Parse(context.Background(), []byte(bad), unit, true, 15)
	assert.Error(t, err)
}

func TestParseUnitWithoutTranslationIsEmptyDocument(t *testing.T) {
	content := "inputs = { a = 1 }\n"
	root, unit := writeUnit(t, content)
	out, handled, err := unitParser(root, true).ParseUnit(context.Background(), []byte(content), unit)
	require.NoError(t, err)
	assert.True(t, handled)
	assert.Nil(t, out.TerragruntTranslation)
	assert.Equal(t, []model.Document{{}}, out.Documents)
}

func TestTerragruntDisabledByDefault(t *testing.T) {
	root, unit := writeUnit(t, unitContent)
	p := unitParser(root, false)
	assert.Equal(t, []string{".tf", ".tofu", ".tf.json", ".tofu.json", ".tfvars"}, p.SupportedExtensions())

	_, handled, err := p.ParseUnit(context.Background(), []byte(unitContent), unit)
	require.NoError(t, err)
	assert.False(t, handled)

	built, err := iacparser.NewBuilder(context.Background()).WithFS(vfs.DiskFS{}).
		Add(p).Build([]string{"terraform"}, nil)
	require.NoError(t, err)
	_, err = built[0].Parse(context.Background(), unit, []byte(unitContent), true, false, 15)
	assert.ErrorIs(t, err, iacparser.ErrNotSupportedFile)

	p.EnableTerragrunt()
	assert.Equal(t, []string{".tf", ".tofu", ".tf.json", ".tofu.json", ".tfvars", "terragrunt.hcl"}, p.SupportedExtensions())
}

func TestTerragruntOnlyMatchesExactName(t *testing.T) {
	root, _ := writeUnit(t, unitContent)
	p := unitParser(root, true)
	for _, name := range []string{"root.hcl", "Terragrunt.hcl", "terragrunt.hcl.bak", "env.hcl"} {
		_, handled, err := p.ParseUnit(context.Background(), []byte(unitContent), filepath.Join(root, "live", name))
		require.NoError(t, err)
		assert.False(t, handled, name)
	}
}

func withoutLines(node interface{}) interface{} {
	switch n := node.(type) {
	case model.Document:
		return withoutLines(map[string]interface{}(n))
	case map[string]interface{}:
		out := make(map[string]interface{}, len(n))
		for k, v := range n {
			if k != "_dd_lines" {
				out[k] = withoutLines(v)
			}
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(n))
		for i, v := range n {
			out[i] = withoutLines(v)
		}
		return out
	}
	return node
}
