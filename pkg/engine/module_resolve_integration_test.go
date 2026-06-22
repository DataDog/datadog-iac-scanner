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

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	terraformParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform"
	scanUtils "github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// aclRule fires when an aws_s3_bucket has acl == "public-read". It only matches
// after a module is instantiated with that concrete value.
const aclRule = `package datadog

DatadogPolicy contains result if {
	some name, i
	bucket := input.document[i].resource.aws_s3_bucket[name]
	bucket.acl == "public-read"

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_s3_bucket",
		"resourceName": name,
		"searchKey": sprintf("aws_s3_bucket[%s].acl", [name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "acl should not be public-read",
		"keyActualValue": "acl is public-read",
	}
}
`

func parseTerraform(t *testing.T, path string) model.FileMetadatas {
	t.Helper()
	content, err := os.ReadFile(filepath.Clean(path))
	require.NoError(t, err)

	_, docs, ignore, resolved, err := terraformParser.NewDefault().Parse(context.Background(), content, path, true, 15)
	require.NoError(t, err)

	var out model.FileMetadatas
	for _, doc := range docs {
		out = append(out, &model.FileMetadata{
			ID:                uuid.NewString(),
			ScanID:            "test",
			Document:          doc,
			LineInfoDocument:  doc,
			OriginalData:      string(content),
			Kind:              model.KindTerraform,
			FilePath:          path,
			LinesIgnore:       ignore,
			ResolvedFiles:     resolved,
			LinesOriginalData: scanUtils.SplitLines(string(content)),
		})
	}
	return out
}

// TestInspect_InstantiatesModuleAndFindsResolvedValue verifies end-to-end that a
// module called with acl = "public-read" is instantiated so the value-specific
// rule fires and the finding is reported at the module's resource definition file.
func TestInspect_InstantiatesModuleAndFindsResolvedValue(t *testing.T) {
	root := t.TempDir()

	rootDir := filepath.Join(root, "stack")
	modDir := filepath.Join(root, "modules", "bucket")
	require.NoError(t, os.MkdirAll(rootDir, 0o755))
	require.NoError(t, os.MkdirAll(modDir, 0o755))

	rootPath := filepath.Join(rootDir, "main.tf")
	modPath := filepath.Join(modDir, "main.tf")

	require.NoError(t, os.WriteFile(rootPath, []byte(`
module "bucket" {
  source = "../modules/bucket"
  acl    = "public-read"
}
`), 0o644))
	require.NoError(t, os.WriteFile(modPath, []byte(`
variable "acl" {
  type = string
}

resource "aws_s3_bucket" "this" {
  acl = var.acl
}
`), 0o644))

	var files model.FileMetadatas
	files = append(files, parseTerraform(t, rootPath)...)
	files = append(files, parseTerraform(t, modPath)...)

	queries := []model.QueryMetadata{{
		Query:       "acl_rule",
		Content:     aclRule,
		InputData:   "{}",
		Platform:    "terraform",
		Metadata:    map[string]interface{}{"id": "acl-rule"},
		Aggregation: 1,
	}}

	ins := newTestInspector(t, inspectorOpts{
		queries:  queries,
		repoPath: root,
		vb:       DefaultVulnerabilityBuilder,
	})

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries(), "no query should fail")

	require.Len(t, vulns, 1, "expected exactly one finding from the instantiated module")
	v := vulns[0]
	require.Equal(t, "aws_s3_bucket", v.ResourceType)
	require.Equal(t, "main.tf", filepath.Base(v.FileName))
	require.Equal(t, modPath, v.FileName, "finding should be reported at the module resource definition")
	require.Greater(t, v.Line, 0, "line should be detected in the module file")
}

// Two roots call the same module with the same inputs: expect two findings and two distinct ModuleCallChain values.
func TestInspect_TwoCallersGetDistinctCallChains(t *testing.T) {
	root := t.TempDir()

	modDir := filepath.Join(root, "modules", "bucket")
	require.NoError(t, os.MkdirAll(filepath.Join(root, "stack-a"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "stack-b"), 0o755))
	require.NoError(t, os.MkdirAll(modDir, 0o755))

	aPath := filepath.Join(root, "stack-a", "main.tf")
	bPath := filepath.Join(root, "stack-b", "main.tf")
	modPath := filepath.Join(modDir, "main.tf")

	require.NoError(t, os.WriteFile(aPath, []byte(`
module "bucket" {
  source = "../modules/bucket"
  acl    = "public-read"
}
`), 0o644))
	require.NoError(t, os.WriteFile(bPath, []byte(`
module "bucket" {
  source = "../modules/bucket"
  acl    = "public-read"
}
`), 0o644))
	require.NoError(t, os.WriteFile(modPath, []byte(`
variable "acl" {
  type = string
}

resource "aws_s3_bucket" "this" {
  acl = var.acl
}
`), 0o644))

	var files model.FileMetadatas
	files = append(files, parseTerraform(t, aPath)...)
	files = append(files, parseTerraform(t, bPath)...)
	files = append(files, parseTerraform(t, modPath)...)

	queries := []model.QueryMetadata{{
		Query:       "acl_rule",
		Content:     aclRule,
		InputData:   "{}",
		Platform:    "terraform",
		Metadata:    map[string]interface{}{"id": "acl-rule"},
		Aggregation: 1,
	}}

	ins := newTestInspector(t, inspectorOpts{
		queries:  queries,
		repoPath: root,
		vb:       DefaultVulnerabilityBuilder,
	})

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())

	// Both callers pass the same (bad) value, yet we expect one finding per caller,
	// each attributed to the module body but with a distinct call chain.
	require.Len(t, vulns, 2, "expected one finding per module caller")
	chains := map[string]bool{}
	for _, v := range vulns {
		require.Equal(t, modPath, v.FileName, "findings should be reported at the module resource definition")
		require.NotEmpty(t, v.ModuleCallChain, "instantiated finding must carry a module call chain")
		chains[v.ModuleCallChain] = true
	}
	require.Len(t, chains, 2, "the two callers must produce distinct module call chains")
}

// variableTypeRule fires on a variable declaration that has no type, mirroring
// real rules that match non-resource blocks (variable/output/data/locals).
const variableTypeRule = `package datadog

DatadogPolicy contains result if {
	some name, i
	var_block := input.document[i].variable[name]
	not var_block.type

	result := {
		"documentId": input.document[i].id,
		"resourceType": "variable",
		"resourceName": name,
		"searchKey": sprintf("variable[%s]", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "variable should declare a type",
		"keyActualValue": "variable has no type",
	}
}
`

// TestInspect_PreservesNonResourceBlocksInModuleBody verifies that suppressing a
// called module body keeps its non-resource blocks scannable: a rule matching a
// typeless variable in the module file still fires, while the module's resource
// is only reported once (via the instantiated synthetic doc, not the body file).
func TestInspect_PreservesNonResourceBlocksInModuleBody(t *testing.T) {
	root := t.TempDir()

	rootDir := filepath.Join(root, "stack")
	modDir := filepath.Join(root, "modules", "bucket")
	require.NoError(t, os.MkdirAll(rootDir, 0o755))
	require.NoError(t, os.MkdirAll(modDir, 0o755))

	rootPath := filepath.Join(rootDir, "main.tf")
	modPath := filepath.Join(modDir, "main.tf")

	require.NoError(t, os.WriteFile(rootPath, []byte(`
module "bucket" {
  source = "../modules/bucket"
  acl    = "public-read"
}
`), 0o644))
	require.NoError(t, os.WriteFile(modPath, []byte(`
variable "acl" {
}

resource "aws_s3_bucket" "this" {
  acl = var.acl
}
`), 0o644))

	var files model.FileMetadatas
	files = append(files, parseTerraform(t, rootPath)...)
	files = append(files, parseTerraform(t, modPath)...)

	queries := []model.QueryMetadata{{
		Query:       "variable_type_rule",
		Content:     variableTypeRule,
		InputData:   "{}",
		Platform:    "terraform",
		Metadata:    map[string]interface{}{"id": "variable-type-rule"},
		Aggregation: 1,
	}}

	ins := newTestInspector(t, inspectorOpts{
		queries:  queries,
		repoPath: root,
		vb:       DefaultVulnerabilityBuilder,
	})

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())

	require.Len(t, vulns, 1, "typeless variable in the suppressed module body should still be reported")
	require.Equal(t, "variable", vulns[0].ResourceType)
	require.Equal(t, modPath, vulns[0].FileName, "variable finding should be reported in the module body file")
}

// legacyAclRule mimics the two-branch pattern used in the real rules repo:
// one branch scans the resource directly, and one uses the module call-site
// (the legacy get_module_equivalent_key pattern, simplified here to just
// match module[name].acl). With the flag on we must get exactly one finding,
// not two, because the module call-site block is stripped from the payload.
const legacyAclRule = `package datadog

# resource branch: fires on a directly-declared or instantiated aws_s3_bucket
DatadogPolicy contains result if {
	some name, i
	bucket := input.document[i].resource.aws_s3_bucket[name]
	bucket.acl == "public-read"

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_s3_bucket",
		"resourceName": name,
		"searchKey": sprintf("aws_s3_bucket[%s].acl", [name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "acl should not be public-read",
		"keyActualValue": "acl is public-read",
	}
}

# legacy module branch: fires on the module call-site block when acl is passed directly
DatadogPolicy contains result if {
	some name, i
	mod := input.document[i].module[name]
	mod.acl == "public-read"

	result := {
		"documentId": input.document[i].id,
		"resourceType": "module",
		"resourceName": name,
		"searchKey": sprintf("module[%s].acl", [name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "acl should not be public-read",
		"keyActualValue": "acl is public-read",
	}
}
`

// TestInspect_NoDoubleFindings_WithLegacyModuleBranch verifies that a rule with
// both a resource branch and a legacy module branch produces exactly one finding.
// The module call-site block is stripped from the payload so the legacy branch skips.
func TestInspect_NoDoubleFindings_WithLegacyModuleBranch(t *testing.T) {
	root := t.TempDir()

	rootDir := filepath.Join(root, "stack")
	modDir := filepath.Join(root, "modules", "bucket")
	require.NoError(t, os.MkdirAll(rootDir, 0o755))
	require.NoError(t, os.MkdirAll(modDir, 0o755))

	rootPath := filepath.Join(rootDir, "main.tf")
	modPath := filepath.Join(modDir, "main.tf")

	require.NoError(t, os.WriteFile(rootPath, []byte(`
module "bucket" {
  source = "../modules/bucket"
  acl    = "public-read"
}
`), 0o644))
	require.NoError(t, os.WriteFile(modPath, []byte(`
variable "acl" {
  type = string
}

resource "aws_s3_bucket" "this" {
  acl = var.acl
}
`), 0o644))

	var files model.FileMetadatas
	files = append(files, parseTerraform(t, rootPath)...)
	files = append(files, parseTerraform(t, modPath)...)

	queries := []model.QueryMetadata{{
		Query:       "legacy_acl_rule",
		Content:     legacyAclRule,
		InputData:   "{}",
		Platform:    "terraform",
		Metadata:    map[string]interface{}{"id": "legacy-acl-rule"},
		Aggregation: 1,
	}}

	ins := newTestInspector(t, inspectorOpts{
		queries:  queries,
		repoPath: root,
		vb:       DefaultVulnerabilityBuilder,
	})

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())

	// Exactly one finding: the resource branch fires on the instantiated doc.
	// The legacy module branch does NOT fire because the module key is stripped.
	require.Len(t, vulns, 1, "legacy module branch must not fire alongside instantiated resource (no double-findings)")
	require.Equal(t, "aws_s3_bucket", vulns[0].ResourceType, "finding must come from the resource branch, not the module branch")
}
