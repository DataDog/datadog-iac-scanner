/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	terraformParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform"
	scanUtils "github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// moduleEvalEnabled returns a FlagEvaluator with local module evaluation turned on.
func moduleEvalEnabled() featureflags.FlagEvaluator {
	return featureflags.NewLocalEvaluatorWithOverrides(map[string]bool{
		featureflags.IacEnableLocalModuleEval: true,
	})
}

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
		queries:       queries,
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: moduleEvalEnabled(),
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
		queries:       queries,
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: moduleEvalEnabled(),
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

// aggregateCountRule fires when two or more aws_s3_bucket resources exist in the scan.
const aggregateCountRule = `package datadog

DatadogPolicy contains result if {
	buckets := [name | input.document[_].resource.aws_s3_bucket[name]]
	count(buckets) >= 2

	result := {
		"documentId": input.document[0].id,
		"resourceType": "aws_s3_bucket",
		"resourceName": "multiple",
		"searchKey": "aws_s3_bucket",
	}
}
`

// Distinct module instances in one root (bucket_a vs bucket_b) are not merged;
// an aggregate rule still sees both buckets. Does not exercise cross-root dedup.
func TestInspect_WithinConfigDistinctModuleInstancesNotMerged(t *testing.T) {
	root := t.TempDir()

	rootDir := filepath.Join(root, "stack")
	modDir := filepath.Join(root, "modules", "bucket")
	require.NoError(t, os.MkdirAll(rootDir, 0o755))
	require.NoError(t, os.MkdirAll(modDir, 0o755))

	rootPath := filepath.Join(rootDir, "main.tf")
	modPath := filepath.Join(modDir, "main.tf")

	// bucket_a and bucket_b share inputs but differ in module address (part of the dedup key).
	require.NoError(t, os.WriteFile(rootPath, []byte(`
module "bucket_a" {
  source = "../modules/bucket"
  acl    = "public-read"
}

module "bucket_b" {
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
		Query:       "aggregate_count_rule",
		Content:     aggregateCountRule,
		InputData:   "{}",
		Platform:    "terraform",
		Metadata:    map[string]interface{}{"id": "aggregate-count-rule"},
		Aggregation: 1,
	}}

	ins := newTestInspector(t, inspectorOpts{
		queries:       queries,
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: moduleEvalEnabled(),
	})

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())

	require.Len(t, vulns, 1, "aggregate rule must see both bucket instances and fire")
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
		queries:       queries,
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: moduleEvalEnabled(),
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
		queries:       queries,
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: moduleEvalEnabled(),
	})

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())

	// Exactly one finding: the resource branch fires on the instantiated doc.
	// The legacy module branch does NOT fire because the module key is stripped.
	require.Len(t, vulns, 1, "legacy module branch must not fire alongside instantiated resource (no double-findings)")
	require.Equal(t, "aws_s3_bucket", vulns[0].ResourceType, "finding must come from the resource branch, not the module branch")
}

// sgNotUsedRule fires when an aws_security_group is not referenced anywhere in the document.
const sgNotUsedRule = `package datadog

DatadogPolicy contains result if {
	some i, doc in input.document
	some sgName, _ in doc.resource.aws_security_group

	not sg_is_used(sgName, doc)

	result := {
		"documentId":   input.document[i].id,
		"resourceType": "aws_security_group",
		"resourceName": sgName,
		"searchKey":    sprintf("aws_security_group[%s]", [sgName]),
	}
}

sg_is_used(sgName, doc) if {
	[_, value] := walk(doc)
	value.security_group_id == sprintf("aws_security_group.%s.id", [sgName])
}

sg_is_used(sgName, doc) if {
	[_, value] := walk(doc)
	some v in value.vpc_security_group_ids
	v == sprintf("aws_security_group.%s.id", [sgName])
}
`

// Cross-file SG reference in a module must suppress sg_not_used.
func TestInspect_CrossFileModuleRefsResolvedBySiblings(t *testing.T) {
	root := t.TempDir()

	rootDir := filepath.Join(root, "stack")
	modDir := filepath.Join(root, "modules", "app")
	require.NoError(t, os.MkdirAll(rootDir, 0o755))
	require.NoError(t, os.MkdirAll(modDir, 0o755))

	rootPath := filepath.Join(rootDir, "main.tf")
	sgPath := filepath.Join(modDir, "sg.tf")
	instancePath := filepath.Join(modDir, "instance.tf")

	require.NoError(t, os.WriteFile(rootPath, []byte(`
module "app" {
  source = "../modules/app"
}
`), 0o644))

	require.NoError(t, os.WriteFile(sgPath, []byte(`
resource "aws_security_group" "web" {
  name = "web-sg"
}
`), 0o644))

	require.NoError(t, os.WriteFile(instancePath, []byte(`
resource "aws_instance" "app" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
  vpc_security_group_ids = ["aws_security_group.web.id"]
}
`), 0o644))

	var files model.FileMetadatas
	files = append(files, parseTerraform(t, rootPath)...)
	files = append(files, parseTerraform(t, sgPath)...)
	files = append(files, parseTerraform(t, instancePath)...)

	queries := []model.QueryMetadata{{
		Query:       "sg_not_used_rule",
		Content:     sgNotUsedRule,
		InputData:   "{}",
		Platform:    "terraform",
		Metadata:    map[string]interface{}{"id": "sg-not-used"},
		Aggregation: 1,
	}}

	ins := newTestInspector(t, inspectorOpts{
		queries:       queries,
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: moduleEvalEnabled(),
	})

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())

	require.Empty(t, vulns, "sg_not_used must not fire when the SG is referenced in a sibling module file")
}

func TestInspect_CrossFileUnusedSGStillFires(t *testing.T) {
	root := t.TempDir()

	rootDir := filepath.Join(root, "stack")
	modDir := filepath.Join(root, "modules", "app")
	require.NoError(t, os.MkdirAll(rootDir, 0o755))
	require.NoError(t, os.MkdirAll(modDir, 0o755))

	rootPath := filepath.Join(rootDir, "main.tf")
	sgPath := filepath.Join(modDir, "sg.tf")
	instancePath := filepath.Join(modDir, "instance.tf")

	require.NoError(t, os.WriteFile(rootPath, []byte(`
module "app" {
  source = "../modules/app"
}
`), 0o644))

	require.NoError(t, os.WriteFile(sgPath, []byte(`
resource "aws_security_group" "web" {
  name = "web-sg"
}
`), 0o644))

	require.NoError(t, os.WriteFile(instancePath, []byte(`
resource "aws_instance" "app" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
}
`), 0o644))

	var files model.FileMetadatas
	files = append(files, parseTerraform(t, rootPath)...)
	files = append(files, parseTerraform(t, sgPath)...)
	files = append(files, parseTerraform(t, instancePath)...)

	queries := []model.QueryMetadata{{
		Query:       "sg_not_used_rule",
		Content:     sgNotUsedRule,
		InputData:   "{}",
		Platform:    "terraform",
		Metadata:    map[string]interface{}{"id": "sg-not-used"},
		Aggregation: 1,
	}}

	ins := newTestInspector(t, inspectorOpts{
		queries:       queries,
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: moduleEvalEnabled(),
	})

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())

	require.Len(t, vulns, 1, "genuinely unused SG must still be reported")
	require.Equal(t, "aws_security_group", vulns[0].ResourceType)
}

func TestInspect_CrossRootDivergentSiblingNotDeduped(t *testing.T) {
	root := t.TempDir()

	modDir := filepath.Join(root, "modules", "net")
	require.NoError(t, os.MkdirAll(filepath.Join(root, "stack-a"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "stack-b"), 0o755))
	require.NoError(t, os.MkdirAll(modDir, 0o755))

	aPath := filepath.Join(root, "stack-a", "main.tf")
	bPath := filepath.Join(root, "stack-b", "main.tf")
	sgPath := filepath.Join(modDir, "sg.tf")
	instancePath := filepath.Join(modDir, "instance.tf")

	require.NoError(t, os.WriteFile(aPath, []byte(`
module "net" { source = "../modules/net" }
`), 0o644))
	require.NoError(t, os.WriteFile(bPath, []byte(`
module "net" { source = "../modules/net" }
`), 0o644))

	require.NoError(t, os.WriteFile(sgPath, []byte(`
resource "aws_security_group" "firewall" {
  name = "firewall-sg"
}
`), 0o644))

	require.NoError(t, os.WriteFile(instancePath, []byte(`
resource "aws_instance" "server" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
  vpc_security_group_ids = ["aws_security_group.firewall.id"]
}
`), 0o644))

	var files model.FileMetadatas
	files = append(files, parseTerraform(t, aPath)...)
	files = append(files, parseTerraform(t, bPath)...)
	files = append(files, parseTerraform(t, sgPath)...)
	files = append(files, parseTerraform(t, instancePath)...)

	queries := []model.QueryMetadata{{
		Query:       "sg_not_used_rule",
		Content:     sgNotUsedRule,
		InputData:   "{}",
		Platform:    "terraform",
		Metadata:    map[string]interface{}{"id": "sg-not-used"},
		Aggregation: 1,
	}}

	ins := newTestInspector(t, inspectorOpts{
		queries:       queries,
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: moduleEvalEnabled(),
	})

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())

	require.Empty(t, vulns, "sg_not_used must not fire when the SG is referenced in a sibling module file")
}

func TestInspect_CountExpansionBothInstancesScanned(t *testing.T) {
	root := t.TempDir()

	rootDir := filepath.Join(root, "stack")
	modDir := filepath.Join(root, "modules", "buckets")
	require.NoError(t, os.MkdirAll(rootDir, 0o755))
	require.NoError(t, os.MkdirAll(modDir, 0o755))

	rootPath := filepath.Join(rootDir, "main.tf")
	modPath := filepath.Join(modDir, "main.tf")

	require.NoError(t, os.WriteFile(rootPath, []byte(`
module "buckets" {
  source = "../modules/buckets"
  acl    = "public-read"
}
`), 0o644))
	require.NoError(t, os.WriteFile(modPath, []byte(`
variable "acl" {
  type = string
}

resource "aws_s3_bucket" "replica" {
  count  = 2
  bucket = "bucket-${count.index}"
  acl    = var.acl
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
		queries:       queries,
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: moduleEvalEnabled(),
	})

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())

	require.Len(t, vulns, 2, "both count-expanded instances must produce a finding")
}

// TestInspect_SharedBaseStoresConcurrentReads runs multiple queries on one platform
// with several workers so shared baseStores are read concurrently (-race).
func TestInspect_SharedBaseStoresConcurrentReads(t *testing.T) {
	root := t.TempDir()
	rootPath := filepath.Join(root, "main.tf")
	require.NoError(t, os.WriteFile(rootPath, []byte(`
resource "aws_s3_bucket" "this" {
  acl = "public-read"
}
`), 0o644))

	files := parseTerraform(t, rootPath)

	const numQueries = 8
	queries := make([]model.QueryMetadata, 0, numQueries)
	for i := 0; i < numQueries; i++ {
		queries = append(queries, model.QueryMetadata{
			Query:       fmt.Sprintf("acl_rule_%d", i),
			Content:     aclRule,
			InputData:   "{}",
			Platform:    "terraform",
			Metadata:    map[string]interface{}{"id": fmt.Sprintf("acl-rule-%d", i)},
			Aggregation: 1,
		})
	}

	ins := newTestInspector(t, inspectorOpts{
		queries:    queries,
		repoPath:   root,
		numWorkers: 4,
		vb:         DefaultVulnerabilityBuilder,
	})

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	require.Len(t, vulns, numQueries)
}

// TestInspect_LocalModuleEvalWithFlagEnabled confirms that local module evaluation
// runs when the feature flag is on and synthetic docs are injected for resolved modules.
func TestInspect_LocalModuleEvalAlwaysRuns(t *testing.T) {
	root := t.TempDir()
	rootPath := filepath.Join(root, "main.tf")
	modDir := filepath.Join(root, "modules", "s3")
	require.NoError(t, os.MkdirAll(modDir, 0o755))
	modPath := filepath.Join(modDir, "main.tf")

	require.NoError(t, os.WriteFile(rootPath, []byte(`
module "s3" {
  source = "./modules/s3"
  acl    = "public-read"
}
`), 0o644))
	require.NoError(t, os.WriteFile(modPath, []byte(`
variable "acl" {}
resource "aws_s3_bucket" "this" { acl = var.acl }
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
		flagEvaluator: featureflags.NewLocalEvaluatorWithOverrides(map[string]bool{
			featureflags.IacEnableLocalModuleEval: true,
		}),
	})

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	require.NotEmpty(t, vulns, "module eval with flag enabled: rule should fire on resolved module resource")
}
