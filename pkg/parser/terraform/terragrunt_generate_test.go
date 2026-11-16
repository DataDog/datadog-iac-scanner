/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package terraform

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

const terragruntGenerates = `locals {
  region = "eu-west-1"
}

generate "provider" {
  path      = "provider.tf"
  if_exists = "overwrite"
  contents  = <<EOF
provider "aws" {
  region = "${local.region}"
}
EOF
}

generate "vars" {
  path     = "terraform.tfvars"
  contents = "x = 1"
}

generate "off" {
  path     = "off.tf"
  disable  = true
  contents = "resource \"aws_s3_bucket\" \"off\" {}"
}

remote_state {
  backend = "s3"
  config = {
    bucket  = "state"
    encrypt = false
  }
}
`

// What generate and remote_state write is Terraform, converted at the lines
// it has in the Terragrunt file.
func TestParse_TerragruntGeneratedTerraform(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "root.hcl")
	require.NoError(t, os.WriteFile(path, []byte(terragruntGenerates), 0o644))
	p := NewDefaultWithParams(nil, "", model.SCIInfo{RepositoryDir: dir})

	_, documents, _, _, err := p.Parse(context.Background(), []byte(terragruntGenerates), path, true, 15)
	require.NoError(t, err)
	require.Len(t, documents, 2, "provider.tf and the backend; tfvars and disabled files are not Terraform documents")

	provider := documents[0]["provider"].(model.Document)["aws"].(model.Document)
	require.Equal(t, "eu-west-1", provider["region"])
	require.Equal(t, 9, docLine(t, provider), "provider block at its line in the Terragrunt file")

	backend := documents[1]["terraform"].(model.Document)["backend"].(model.Document)["s3"].(model.Document)
	require.Equal(t, "state", backend["bucket"])
	encrypt, err := json.Marshal(backend["encrypt"])
	require.NoError(t, err)
	require.JSONEq(t, "false", string(encrypt))
}

// Blocks an included file declares belong to that file, not to each unit.
func TestParse_TerragruntIncludedGenerateStaysInItsFile(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "root.hcl"), []byte(terragruntGenerates), 0o644))
	unitDir := filepath.Join(dir, "app")
	require.NoError(t, os.MkdirAll(unitDir, 0o755))
	unit := []byte("include \"root\" {\n  path = find_in_parent_folders(\"root.hcl\")\n}\n")
	path := filepath.Join(unitDir, "terragrunt.hcl")
	require.NoError(t, os.WriteFile(path, unit, 0o644))

	_, documents, _, _, err := NewDefaultWithParams(nil, "", model.SCIInfo{RepositoryDir: dir}).
		Parse(context.Background(), unit, path, true, 15)
	require.NoError(t, err)
	require.Equal(t, []model.Document{{}}, documents)
}

// docLine is the line the converter recorded for a block.
func docLine(t *testing.T, doc model.Document) int {
	t.Helper()
	lines, ok := doc["_dd_lines"].(map[string]model.LineObject)
	require.True(t, ok, "no line info in %v", doc)
	return lines["_dd__default"].Line
}
