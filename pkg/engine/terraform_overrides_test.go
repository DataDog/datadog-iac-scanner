/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2026 Datadog, Inc.
 */
package engine

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/stretchr/testify/require"
)

func TestTerraformOverrideDocumentIDsAndOrder(t *testing.T) {
	const module = `module "child" {
  source = "../child"
  prefix = %q
}`
	const base = `variable "prefix" {}
resource "aws_s3_bucket" "example" {
  count  = 1
  bucket = "${var.prefix}-${count.index}"
  acl    = "private"
}`
	const override = `resource "aws_s3_bucket" "example" {
  count = 2
  acl   = "public-read"
}`
	scan := func(root string) []string {
		t.Helper()
		paths := []string{
			writeFile(t, filepath.Join(root, "beta"), "main.tf", fmt.Sprintf(module, "beta")),
			writeFile(t, filepath.Join(root, "child"), "override.tf", override),
			writeFile(t, filepath.Join(root, "alpha"), "main.tf", fmt.Sprintf(module, "alpha")),
			writeFile(t, filepath.Join(root, "child"), "main.tf", base),
		}
		var files model.FileMetadatas
		byPath := make(map[string]string)
		for _, path := range paths {
			parsed := parseTerraform(t, path)
			require.Len(t, parsed, 1)
			f := parsed[0]
			key := model.DocumentKey{Path: model.DocumentPath(path, root, nil), Kind: f.Kind, Platform: "terraform"}
			f.DocumentKey, f.ID, f.Platform = key, key.ID(), "terraform"
			byPath[model.LexicalDocumentPath(path, root)] = f.ID
			files = append(files, f)
		}
		files.SortByDocumentKey()
		ctx := t.Context()
		ins := newTestInspector(t, inspectorOpts{repoPath: root})
		moduleDocs, synthetic, _, _ := ins.instantiateLocalModules(ctx, files, nil, nil, false)
		require.Len(t, synthetic, 4)
		require.Len(t, moduleDocs, len(synthetic))

		combined := files.Combine(ctx, false)
		payloads, err := ins.buildPlatformPayloads(ctx, append(files, synthetic...).ToMap(),
			combined.Documents, moduleDocs, []model.QueryMetadata{{Platform: "terraform"}}, false)
		require.NoError(t, err)
		payload := payloads.byPlatform["terraform"].(ast.Object).Get(ast.StringTerm("document")).Value.(*ast.Array)
		require.Equal(t, len(combined.Documents)+len(synthetic), payload.Len())
		resource := model.TerraformBlock{Kind: "resource", Type: "aws_s3_bucket", Name: "example"}
		ids := make([]string, len(synthetic))
		for i, instance := range synthetic {
			rootName := []string{"alpha", "beta"}[i/2]
			want := fmt.Sprintf("%s\x00%s/main.tf|module.child\x00%d", byPath["child/main.tf"], rootName, i%2)
			require.Equal(t, want, instance.ID)
			ids[i] = instance.ID
			doc := payload.Elem(len(combined.Documents) + i).Value.(ast.Object)
			require.Equal(t, ast.StringTerm(want), doc.Get(ast.StringTerm("id")))
			resources := docAsMap(moduleDocs[i]["resource"])
			bucket := docAsMap(docAsMap(resources["aws_s3_bucket"])["example"])
			require.Equal(t, fmt.Sprintf("%s-%d", rootName, i%2), bucket["bucket"])
			require.Equal(t, "public-read", bucket["acl"])
			source := instance.TerraformOverrides[resource]
			require.NotNil(t, source)
			require.Equal(t, byPath["child/override.tf"], source.Fields["acl"])
		}
		return ids
	}
	first := t.TempDir()
	want := scan(first)
	require.Equal(t, want, scan(first))
	require.Equal(t, want, scan(t.TempDir()))
}
