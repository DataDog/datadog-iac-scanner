/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/inventory"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

func blockBody(t *testing.T, src string) *hclsyntax.Body {
	t.Helper()
	file, diags := hclsyntax.ParseConfig([]byte(src), "main.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors(), diags.Error())
	return file.Body.(*hclsyntax.Body).Blocks[0].Body
}

func TestInventoryAddress(t *testing.T) {
	counted := blockBody(t, "resource \"x\" \"y\" {\n  count = var.n\n}\n")
	tests := []struct {
		name           string
		resource       tfeval.ResolvedResource
		wantModuleCall string
		wantPath       string
		wantComplete   bool
	}{
		{
			name:         "root resource",
			resource:     tfeval.ResolvedResource{Type: "aws_s3_bucket", Name: "logs"},
			wantPath:     "aws_s3_bucket.logs",
			wantComplete: true,
		},
		{
			name:         "data source",
			resource:     tfeval.ResolvedResource{Type: "aws_ami", Name: "ubuntu", Data: true},
			wantPath:     "data.aws_ami.ubuntu",
			wantComplete: true,
		},
		{
			name:         "count instance",
			resource:     tfeval.ResolvedResource{Type: "aws_instance", Name: "web[1]", InstanceKey: cty.NumberIntVal(1)},
			wantPath:     "aws_instance.web[1]",
			wantComplete: true,
		},
		{
			name:         "for_each key that needs escaping",
			resource:     tfeval.ResolvedResource{Type: "aws_s3_bucket", Name: `b["a"b"]`, InstanceKey: cty.StringVal(`a"b`)},
			wantPath:     `aws_s3_bucket.b["a\"b"]`,
			wantComplete: true,
		},
		{
			name:     "unknown for_each key",
			resource: tfeval.ResolvedResource{Type: "aws_s3_bucket", Name: "extra", InstanceKey: cty.DynamicVal},
			wantPath: "aws_s3_bucket.extra",
		},
		{
			name:     "count that was not expanded",
			resource: tfeval.ResolvedResource{Type: "x", Name: "y", Body: counted},
			wantPath: "x.y",
		},
		{
			name: "nested module instances",
			resource: tfeval.ResolvedResource{
				Type: "aws_s3_bucket", Name: "this", ModuleAddress: `module.a["prod"].module.b[0]`,
				CallChain: []tfeval.CallSite{
					{ModuleName: "a", InstanceKey: cty.StringVal("prod")},
					{ModuleName: "b", InstanceKey: cty.NumberIntVal(0)},
				},
			},
			wantModuleCall: `module.a["prod"].module.b[0]`,
			wantPath:       `module.a["prod"].module.b[0].aws_s3_bucket.this`,
			wantComplete:   true,
		},
		{
			name: "module with an unknown for_each key",
			resource: tfeval.ResolvedResource{
				Type: "aws_s3_bucket", Name: "this", ModuleAddress: "module.dyn",
				CallChain: []tfeval.CallSite{{ModuleName: "dyn", InstanceKey: cty.DynamicVal}},
			},
			wantModuleCall: "module.dyn",
			wantPath:       "module.dyn.aws_s3_bucket.this",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			moduleCall, path, complete := tt.resource.PartialAddress()
			require.Equal(t, tt.wantModuleCall, moduleCall)
			require.Equal(t, tt.wantPath, path)
			require.Equal(t, tt.wantComplete, complete)

			// A complete address is the one findings will use.
			canonical, ok := tt.resource.TerraformAddress()
			require.Equal(t, complete, ok)
			if ok {
				require.Equal(t, canonical, path)
			}
		})
	}
}

func TestTerraformProvider(t *testing.T) {
	require.Equal(t, "aws", terraformProvider(&tfeval.ResolvedResource{Type: "aws_s3_bucket"}))
	require.Equal(t, "random", terraformProvider(&tfeval.ResolvedResource{Type: "random_id"}))
	aliased := blockBody(t, "resource \"aws_s3_bucket\" \"b\" {\n  provider = aws.west\n}\n")
	require.Equal(t, "aws", terraformProvider(&tfeval.ResolvedResource{Type: "aws_s3_bucket", Body: aliased}))
	beta := blockBody(t, "resource \"google_storage_bucket\" \"b\" {\n  provider = google-beta\n}\n")
	require.Equal(t, "google-beta", terraformProvider(&tfeval.ResolvedResource{Type: "google_storage_bucket", Body: beta}))
}

// collectingSink keeps what the inventory is given.
type collectingSink struct {
	rows    []inventory.Resource
	failure string
}

func (s *collectingSink) AddResource(r *inventory.Resource) { s.rows = append(s.rows, *r) }
func (s *collectingSink) Fail(reason string)                { s.failure = reason }

func TestInventoryEvaluatesRootsNoRuleTargets(t *testing.T) {
	repo := t.TempDir()
	mainTF := filepath.Join(repo, "main.tf")
	require.NoError(t, os.WriteFile(mainTF, []byte("resource \"random_id\" \"x\" {\n  byte_length = 4\n}\n"), 0o600))
	files := model.FileMetadatas{parsedFileMeta(t, "main", mainTF)}
	// No rule targets random_id: the scan evaluates nothing.
	targets := &ruleTargets{types: map[string]bool{"aws_s3_bucket": true}}

	without := resolveModuleDocumentsForTest(context.Background(), files, repo, nil, targets, nil, nil, vfs.DiskFS{}, nil)
	require.False(t, without.ok, "the scan evaluates no root")

	sink := &collectingSink{}
	inv := &terraformInventory{sink: sink, repoPath: repo}
	with := resolveModuleDocuments(context.Background(), files, repo, nil, targets, nil, nil, vfs.DiskFS{}, nil, inv, nil, false)
	require.Equal(t, without, with, "the inventory changes nothing the findings use")
	require.Len(t, sink.rows, 1)
	require.Equal(t, "random_id.x", sink.rows[0].ResourcePath)
	require.Empty(t, sink.failure)
}

// panickingSink fails on every row, as a bug in the inventory would.
type panickingSink struct{ failure string }

func (s *panickingSink) AddResource(*inventory.Resource) { panic("bug") }
func (s *panickingSink) Fail(reason string)              { s.failure = reason }

func TestInventoryPanicDoesNotReachModuleEvaluation(t *testing.T) {
	sink := &panickingSink{}
	inv := &terraformInventory{sink: sink, repoPath: t.TempDir()}
	require.NotPanics(t, func() {
		inv.addRoot(inv.repoPath, []tfeval.ResolvedResource{{Type: "aws_s3_bucket", Name: "b"}}, false, nil)
	}, "a panic in the inventory must not abort the evaluation findings depend on")
	require.Equal(t, inventory.FailureTerraformPanic, sink.failure)
}
