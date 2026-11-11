/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/engine/schedule"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/unknowngate"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	tfmodel "github.com/DataDog/datadog-iac-scanner/pkg/terraform/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/project"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/stretchr/testify/require"
)

// A gate that cannot be built is an engine error: no verdict, so no result is
// suppressed.
func TestGateErrorKeepsTheResults(t *testing.T) {
	block := ast.NewTerm(ast.NewObject())
	in := &terraformInput{
		projection: &project.Projection{Blocks: map[string]*project.Located{
			"b1": {Placeholder: true, Term: block},
		}},
		placeholder: "ph",
		rules: &terraformRules{byQuery: map[string]*terraformRule{
			"q": {
				harvest: schedule.Rule{Class: schedule.Anchored},
				newGate: func() (*unknowngate.Gate, error) { return nil, errors.New("does not compile") },
			},
		}},
	}
	items := []interface{}{map[string]interface{}{"_dd_id": "b1"}}
	results := rego.ResultSet{{Bindings: rego.Vars{"result": items}}}
	qCtx := &QueryContext{Query: &PreparedQuery{Metadata: model.QueryMetadata{Query: "q"}}}

	in.gateResults(context.Background(), qCtx, ast.NewObject(), results)

	require.Len(t, results[0].Bindings["result"], 1)
	require.Zero(t, in.rules.rule("q").suppressed.Load())
}

const relationalFixture = `
resource "aws_s3_bucket" "b" {
  bucket = "b"
}
resource "aws_s3_bucket_versioning" "v" {
  bucket = aws_s3_bucket.b.id
}
resource "aws_s3_bucket" "other" {
  bucket = "other"
}
resource "aws_instance" "unrelated" {}
`

func projectFixture(t *testing.T, files map[string]string) *terraformInput {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	}
	scan, err := tfmodel.Load(context.Background(), dir, tfmodel.Options{})
	require.NoError(t, err)
	proj := project.Project(scan.Roots, project.Options{Placeholder: "ph"})
	return &terraformInput{projection: proj, placeholder: "ph"}
}

// The minimal input of a relational rule holds the blocks of the types it
// reads, what they relate to, and nothing else.
func TestRelationalInputHoldsTheReadTypesAndTheirRelations(t *testing.T) {
	in := projectFixture(t, map[string]string{"main.tf": relationalFixture})
	var root string
	for _, loc := range in.projection.Blocks {
		root = loc.Root
	}
	types := []schedule.TypeKey{{Kind: schedule.KindResource, Type: "aws_s3_bucket"}}

	narrow := in.relationalInput(root, types, in.projection.Input)

	raw, err := ast.JSON(narrow)
	require.NoError(t, err)
	dd := raw.(map[string]any)["_dd"].(map[string]any)
	buckets := dd["blocks"].(map[string]any)["resource"].(map[string]any)
	require.Len(t, buckets["aws_s3_bucket"], 2)
	require.NotContains(t, buckets, "aws_instance")
	require.NotContains(t, buckets, "aws_s3_bucket_versioning")

	byID := dd["by_id"].(map[string]any)
	var companion string
	for id, v := range byID {
		if v.(map[string]any)["_dd_meta"].(map[string]any)["type"] == "aws_s3_bucket_versioning" {
			companion = id
		}
	}
	require.NotEmpty(t, companion, "the companion is reachable through the relation")
	for id, loc := range in.projection.Blocks {
		if loc.Type == "aws_instance" {
			require.NotContains(t, byID, id)
		}
	}
	require.NotEmpty(t, dd["related"])
	require.Equal(t, "ph", dd["placeholder"])
}

// A nested block list is read by key, so the minimal inputs of the anchored
// and relational rules keep the entry of each block they hold.
func TestMinimalInputsKeepNestedBlocks(t *testing.T) {
	in := projectFixture(t, map[string]string{"main.tf": `
resource "aws_security_group" "sg" {
  ingress {
    from_port = 1
  }
}
resource "aws_s3_bucket" "b" {
  bucket = "b"
}
`})
	var sgID string
	var sg *project.Located
	for id, loc := range in.projection.Blocks {
		if loc.Type == "aws_security_group" {
			sgID, sg = id, loc
		}
	}
	require.NotEmpty(t, sgID)

	nestedOf := func(v ast.Value) map[string]any {
		raw, err := ast.JSON(v)
		require.NoError(t, err)
		dd := raw.(map[string]any)["_dd"].(map[string]any)
		return dd["nested"].(map[string]any)
	}

	anchored := nestedOf(anchoredInput(sg, in.projection.Input))
	require.Contains(t, anchored, sgID)
	require.Contains(t, anchored[sgID], "ingress")

	types := []schedule.TypeKey{{Kind: schedule.KindResource, Type: "aws_security_group"}}
	var root string
	for _, loc := range in.projection.Blocks {
		root = loc.Root
	}
	relational := nestedOf(in.relationalInput(root, types, in.projection.Input))
	require.Contains(t, relational, sgID)
	require.Contains(t, relational[sgID], "ingress")
}

// A placeholder inside a nested block is substituted at stage 2, so the
// substitution scope of a block holds its _dd.nested entry.
func TestSubstitutionScopeHoldsNestedBlocks(t *testing.T) {
	in := projectFixture(t, map[string]string{"main.tf": `
variable "port" {}
resource "aws_security_group" "sg" {
  ingress {
    from_port = var.port
  }
}
`})
	var sg *project.Located
	for _, loc := range in.projection.Blocks {
		if loc.Type == "aws_security_group" {
			sg = loc
		}
	}
	require.NotNil(t, sg)
	require.True(t, sg.Placeholder)
	entry := field(ddIndex(in.projection.Input, "nested"), blockID(sg))
	require.NotNil(t, entry)
	for name, scope := range map[string][]ast.Value{
		"anchored":   blockScope(nil, sg, in.projection.Input),
		"relational": in.linkedScope(sg, in.projection.Input),
	} {
		require.Contains(t, scope, entry, name)
	}
}
