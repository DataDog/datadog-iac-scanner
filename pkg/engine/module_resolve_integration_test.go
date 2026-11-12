/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	terraformParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform"
	scanUtils "github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
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
	}
}
`

const dynamicBlockRule = `package datadog

DatadogPolicy contains result if {
	some name, i
	instance := input.document[i].resource.google_sql_database_instance[name]
	instance.settings.dynamic.ip_configuration.content.private_network == "projects/test/global/networks/private"

	result := {
		"documentId": input.document[i].id,
		"resourceType": "google_sql_database_instance",
		"resourceName": name,
		"searchKey": sprintf("google_sql_database_instance[%s].settings.dynamic.ip_configuration", [name]),
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
		flagEvaluator: featureflags.NewLocalEvaluator(),
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
	require.NotNil(t, v.ModuleAttribution)
	require.Equal(t, "stack/main.tf", v.ModuleAttribution.CallSite.Filename)
	require.Equal(t, "direct", v.ModuleAttribution.DependencyType)
	require.Len(t, v.ModuleAttribution.ModulePath, 1)
	require.Equal(t, "bucket", v.ModuleAttribution.ModulePath[0].Name)
	require.Equal(t, "modules/bucket", v.ModuleAttribution.ModulePath[0].Source)
	require.Equal(t, "modules/bucket/main.tf", v.ModuleAttribution.ModuleCodeLocation.Filename)
	require.Equal(t, 4, v.ModuleAttribution.CallSite.LineStart, "narrowed to the acl argument")
	require.Equal(t, 4, v.ModuleAttribution.CallSite.LineEnd)
}

func TestInspect_ModuleEvaluationPreservesDynamicBlockLabels(t *testing.T) {
	root := t.TempDir()
	rootDir := filepath.Join(root, "stack")
	modDir := filepath.Join(root, "modules", "sql")
	require.NoError(t, os.MkdirAll(rootDir, 0o755))
	require.NoError(t, os.MkdirAll(modDir, 0o755))

	rootPath := filepath.Join(rootDir, "main.tf")
	modPath := filepath.Join(modDir, "main.tf")
	require.NoError(t, os.WriteFile(rootPath, []byte(`
module "sql" {
  source          = "../modules/sql"
  private_network = "projects/test/global/networks/private"
}
`), 0o644))
	require.NoError(t, os.WriteFile(modPath, []byte(`
variable "private_network" {
  type = string
}

variable "ip_configurations" {}

resource "google_sql_database_instance" "this" {
  settings {
    dynamic "ip_configuration" {
      for_each = var.ip_configurations
      content {
        private_network = var.private_network
      }
    }
  }
}
`), 0o644))

	var files model.FileMetadatas
	files = append(files, parseTerraform(t, rootPath)...)
	files = append(files, parseTerraform(t, modPath)...)

	ins := newTestInspector(t, inspectorOpts{
		queries: []model.QueryMetadata{{
			Query:       "dynamic_block_rule",
			Content:     dynamicBlockRule,
			InputData:   "{}",
			Platform:    "terraform",
			Metadata:    map[string]interface{}{"id": "dynamic-block-rule"},
			Aggregation: 1,
		}},
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Len(t, vulns, 1)
	require.Equal(t, modPath, vulns[0].FileName)
	require.NotNil(t, vulns[0].ModuleAttribution)
}

func TestModuleInstantiationSummary_LoggedAtInfoLevel(t *testing.T) {
	root := t.TempDir()
	rootDir := filepath.Join(root, "stack")
	modDir := filepath.Join(root, "modules", "bucket")
	require.NoError(t, os.MkdirAll(rootDir, 0o755))
	require.NoError(t, os.MkdirAll(modDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(rootDir, "main.tf"), []byte(`
module "bucket" {
  source = "../modules/bucket"
  acl    = "public-read"
}
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(modDir, "main.tf"), []byte(`
variable "acl" { type = string }
resource "aws_s3_bucket" "this" { acl = var.acl }
`), 0o644))

	var files model.FileMetadatas
	files = append(files, parseTerraform(t, filepath.Join(rootDir, "main.tf"))...)
	files = append(files, parseTerraform(t, filepath.Join(modDir, "main.tf"))...)

	queries := []model.QueryMetadata{{
		Query: aclRule, InputData: "{}", Platform: "terraform",
		Metadata: map[string]interface{}{"id": "acl-rule"}, Aggregation: 1,
	}}

	ins := newTestInspector(t, inspectorOpts{
		queries: queries, repoPath: root, vb: DefaultVulnerabilityBuilder,
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})

	var logs bytes.Buffer
	ctx := zerolog.New(&logs).Level(zerolog.InfoLevel).WithContext(context.Background())
	ins.instantiateLocalModules(ctx, files, ruleTargetedResourceTypes(queries, ins.terraformRuleLibraries()...))

	out := logs.String()
	if !strings.Contains(out, "tfeval: module instantiation summary") {
		t.Fatalf("expected info-level summary, got %q", out)
	}
	if !strings.Contains(out, `"level":"info"`) {
		t.Fatalf("expected the summary to log at info level, got %q", out)
	}
	if !strings.Contains(out, `"module_resources_instantiated":`) {
		t.Fatalf("expected structured instantiation count, got %q", out)
	}
	if !strings.Contains(out, `"module_root_count":`) {
		t.Fatalf("expected root count in summary, got %q", out)
	}
	if strings.Contains(out, `"level":"warn"`) {
		t.Fatalf("expected no warn for a module instantiation, got %q", out)
	}
}

// Two roots call the same module with the same inputs: expect two findings and
// two distinct ModuleCallChain values.
func TestInspect_TwoCallersGetDistinctCallChains(t *testing.T) {
	testTwoCallersGetDistinctCallChains(t)
}

func testTwoCallersGetDistinctCallChains(t *testing.T) {
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
		Query:     "acl_rule",
		Content:   aclRule,
		InputData: "{}",
		Platform:  "terraform",
		// "Terraform" is what puts the call chain in the finding identity, as the
		// Terraform rules do. Without it the two callers are one finding.
		Metadata:    map[string]interface{}{"id": "acl-rule", "platform": "Terraform"},
		Aggregation: 1,
	}}

	ins := newTestInspector(t, inspectorOpts{
		queries:       queries,
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: featureflags.NewLocalEvaluator(),
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
		flagEvaluator: featureflags.NewLocalEvaluator(),
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
		flagEvaluator: featureflags.NewLocalEvaluator(),
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
		flagEvaluator: featureflags.NewLocalEvaluator(),
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

// A rule that decides by looking at one whole document sees a module's files
// separately, exactly as it sees the files of any other directory. Giving
// instantiated documents a cross-file view their inline equivalents do not have
// would both change findings depending on where code lives and tie every
// document to the call it came from, which is what makes deduplication
// collapse on repositories with many roots.
func TestInspect_CrossFileModuleRefsMatchInlineBehaviour(t *testing.T) {
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
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())

	inline := inlineEquivalentFindings(t, root, sgNotUsedRule)
	require.Len(t, vulns, inline,
		"a module's cross-file references must be seen exactly as the same code inlined would be")
	require.Len(t, vulns, 1, "one document per file, so the sibling reference is not visible")
}

// inlineEquivalentFindings scans the same two files as a plain directory, with
// no module call, and reports how many findings the rule produces.
func inlineEquivalentFindings(t *testing.T, root, rule string) int {
	t.Helper()
	dir := filepath.Join(root, "inline")
	require.NoError(t, os.MkdirAll(dir, 0o755))

	sgPath := filepath.Join(dir, "sg.tf")
	instancePath := filepath.Join(dir, "instance.tf")
	require.NoError(t, os.WriteFile(sgPath, []byte(`
resource "aws_security_group" "web" {
  name = "web-sg"
}
`), 0o644))
	require.NoError(t, os.WriteFile(instancePath, []byte(`
resource "aws_instance" "app" {
  ami                    = "ami-12345678"
  vpc_security_group_ids = ["aws_security_group.web.id"]
}
`), 0o644))

	var files model.FileMetadatas
	files = append(files, parseTerraform(t, sgPath)...)
	files = append(files, parseTerraform(t, instancePath)...)

	ins := newTestInspector(t, inspectorOpts{
		queries: []model.QueryMetadata{{
			Query:       "sg_not_used_rule",
			Content:     rule,
			InputData:   "{}",
			Platform:    "terraform",
			Metadata:    map[string]interface{}{"id": "sg-not-used"},
			Aggregation: 1,
		}},
		repoPath:      dir,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	return len(vulns)
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
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())

	require.Len(t, vulns, 1, "genuinely unused SG must still be reported")
	require.Equal(t, "aws_security_group", vulns[0].ResourceType)
}

// Two roots calling the same module with the same inputs resolve to identical
// content, so they share one evaluated document — but each call site still gets
// its own finding, since a fix has to be applied per deployment.
func TestInspect_IdenticalCallsShareADocumentAndReportEveryCallSite(t *testing.T) {
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
		Query:     "sg_not_used_rule",
		Content:   sgNotUsedRule,
		InputData: "{}",
		Platform:  "terraform",
		// "Terraform" puts the call chain in the finding identity, as the
		// Terraform rules do. Without it the two callers are one finding.
		Metadata:    map[string]interface{}{"id": "sg-not-used", "platform": "Terraform"},
		Aggregation: 1,
	}}

	ins := newTestInspector(t, inspectorOpts{
		queries:       queries,
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())

	require.Len(t, vulns, 2, "one finding per call site")
	chains := []string{vulns[0].ModuleCallChain, vulns[1].ModuleCallChain}
	require.ElementsMatch(t,
		[]string{"stack-a/main.tf|module.net", "stack-b/main.tf|module.net"},
		chains,
		"each call site must keep its own attribution after deduplication")
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
	// Only the second instance is public: a finding proves that instance was
	// evaluated and scanned. Both instances raise the same finding identity,
	// which the scan reports once, so counting findings would prove nothing.
	require.NoError(t, os.WriteFile(modPath, []byte(`
variable "acl" {
  type = string
}

resource "aws_s3_bucket" "replica" {
  count  = 2
  bucket = "bucket-${count.index}"
  acl    = count.index == 1 ? var.acl : "private"
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
		Metadata:    map[string]interface{}{"id": "acl-rule", "platform": "Terraform"},
		Aggregation: 1,
	}}

	ins := newTestInspector(t, inspectorOpts{
		queries:       queries,
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())

	require.Len(t, vulns, 1, "the second count-expanded instance must be scanned")
	require.Equal(t, "replica", vulns[0].ResourceName)
	require.Equal(t, "stack/main.tf|module.buckets", vulns[0].ModuleCallChain)

	files = append(parseTerraform(t, rootPath), parseTerraform(t, modPath)...)
	vulns, err = ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Len(t, vulns, 1)
	require.Equal(t, "module.buckets.aws_s3_bucket.replica[1]", vulns[0].ResourceID,
		"the instance address picks out count.index 1, not the module call as a whole")
	require.Equal(t, "stack", vulns[0].RootModule)
}

// TestInspect_CountedRootStaysInItsDocument verifies that a root block with
// count stays in the document it is written in, beside its siblings. The
// instances share a fingerprint, and the kept finding carries the first
// instance's address.
func TestInspect_CountedRootStaysInItsDocument(t *testing.T) {
	root := t.TempDir()
	stackDir := filepath.Join(root, "stack")
	require.NoError(t, os.MkdirAll(stackDir, 0o755))
	rootPath := filepath.Join(stackDir, "main.tf")
	require.NoError(t, os.WriteFile(rootPath, []byte(`
resource "aws_s3_bucket" "this" {
  count = 2
  acl   = "public-read"
}

resource "aws_s3_bucket_public_access_block" "guard" {
  bucket = "logs"
}
`), 0o644))

	files := parseTerraform(t, rootPath)
	queries := []model.QueryMetadata{
		{
			Query: "acl_rule", Content: aclRule, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "acl-rule", "platform": "Terraform"}, Aggregation: 1,
		},
		{
			Query: "missing_block", Content: `package datadog

DatadogPolicy contains result if {
	some name, i
	input.document[i].resource.aws_s3_bucket[name]
	object.get(input.document[i].resource, "aws_s3_bucket_public_access_block", {}) == {}

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_s3_bucket",
		"resourceName": name,
		"searchKey": sprintf("aws_s3_bucket[%s].acl", [name]),
	}
}
`, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "missing-block", "platform": "Terraform"}, Aggregation: 1,
		},
		{
			Query: "guard_rule", Content: `package datadog

DatadogPolicy contains result if {
	some name, i
	input.document[i].resource.aws_s3_bucket_public_access_block[name]

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_s3_bucket_public_access_block",
		"resourceName": name,
		"searchKey": sprintf("aws_s3_bucket_public_access_block[%s]", [name]),
	}
}
`, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "guard-rule", "platform": "Terraform"}, Aggregation: 1,
		},
	}
	ins := newTestInspector(t, inspectorOpts{
		queries: queries, repoPath: root, vb: DefaultVulnerabilityBuilder, flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	ins.SetCompactFindingsAtDecode(true)

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())

	byQuery := map[string][]string{}
	var detail []string
	for i := range vulns {
		byQuery[vulns[i].QueryID] = append(byQuery[vulns[i].QueryID], vulns[i].ResourceID)
		detail = append(detail, fmt.Sprintf("%s id=%q root=%q file=%s line=%d", vulns[i].QueryID, vulns[i].ResourceID, vulns[i].RootModule, vulns[i].FileID, vulns[i].Line))
	}
	require.Empty(t, byQuery["missing-block"], "the sibling is in the same document")
	require.Equal(t, []string{"aws_s3_bucket.this[0]"}, byQuery["acl-rule"], strings.Join(detail, "\n"))
	require.Equal(t, []string{"aws_s3_bucket_public_access_block.guard"}, byQuery["guard-rule"])
}

// TestInspect_RootForEachSecurityGroupWithPlainRuleIsUsed verifies that a
// reference to the written block, aws_security_group.web.id, marks that
// for_each group used. The document keeps the block label, so the plain
// reference matches.
func TestInspect_RootForEachSecurityGroupWithPlainRuleIsUsed(t *testing.T) {
	root := t.TempDir()
	stackDir := filepath.Join(root, "stack")
	require.NoError(t, os.MkdirAll(stackDir, 0o755))
	rootPath := filepath.Join(stackDir, "main.tf")
	require.NoError(t, os.WriteFile(rootPath, []byte(`
resource "aws_security_group" "web" {
  for_each = toset(["a", "b"])
  name     = each.key
}

resource "aws_security_group_rule" "in" {
  security_group_id = "aws_security_group.web.id"
  type              = "ingress"
}
`), 0o644))

	files := parseTerraform(t, rootPath)
	queries := []model.QueryMetadata{{
		Query: "sg_not_used_rule", Content: sgNotUsedRule, InputData: "{}", Platform: "terraform",
		Metadata: map[string]interface{}{"id": "sg-not-used", "platform": "Terraform"}, Aggregation: 1,
	}}
	ins := newTestInspector(t, inspectorOpts{
		queries: queries, repoPath: root, vb: DefaultVulnerabilityBuilder, flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	ins.SetCompactFindingsAtDecode(true)

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	require.Empty(t, vulns)
}

// TestInspect_RootResourceAddress verifies that a root resource with no
// count/for_each gets its unindexed Terraform address.
func TestInspect_RootResourceAddress(t *testing.T) {
	root := t.TempDir()
	stackDir := filepath.Join(root, "stack")
	require.NoError(t, os.MkdirAll(stackDir, 0o755))
	rootPath := filepath.Join(stackDir, "main.tf")
	require.NoError(t, os.WriteFile(rootPath, []byte(`
resource "aws_s3_bucket" "this" {
  acl = "public-read"
}
`), 0o644))

	files := parseTerraform(t, rootPath)
	queries := []model.QueryMetadata{{
		Query: "acl_rule", Content: aclRule, InputData: "{}", Platform: "terraform",
		Metadata: map[string]interface{}{"id": "acl-rule", "platform": "Terraform"}, Aggregation: 1,
	}}
	ins := newTestInspector(t, inspectorOpts{
		queries: queries, repoPath: root, vb: DefaultVulnerabilityBuilder, flagEvaluator: featureflags.NewLocalEvaluator(),
	})

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())

	require.Len(t, vulns, 1)
	require.Equal(t, "aws_s3_bucket.this", vulns[0].ResourceID)
	require.Equal(t, "stack", vulns[0].RootModule)
}

// TestInspect_RootResourceCountAddress verifies a counted root resource is
// reported under the written label with the first instance's address.
func TestInspect_RootResourceCountAddress(t *testing.T) {
	root := t.TempDir()
	stackDir := filepath.Join(root, "stack")
	require.NoError(t, os.MkdirAll(stackDir, 0o755))
	rootPath := filepath.Join(stackDir, "main.tf")
	require.NoError(t, os.WriteFile(rootPath, []byte(`
resource "aws_s3_bucket" "this" {
  count  = 2
  bucket = "bucket-${count.index}"
  acl    = "public-read"
}
`), 0o644))

	files := parseTerraform(t, rootPath)
	queries := []model.QueryMetadata{{
		Query: "acl_rule", Content: aclRule, InputData: "{}", Platform: "terraform",
		Metadata: map[string]interface{}{"id": "acl-rule", "platform": "Terraform"}, Aggregation: 1,
	}}
	ins := newTestInspector(t, inspectorOpts{
		queries: queries, repoPath: root, vb: DefaultVulnerabilityBuilder, flagEvaluator: featureflags.NewLocalEvaluator(),
	})

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	require.Len(t, vulns, 1)
	require.Equal(t, "stack", vulns[0].RootModule)
	require.Equal(t, "this", vulns[0].ResourceName)
	require.Equal(t, "aws_s3_bucket.this[0]", vulns[0].ResourceID)
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
func TestInspect_LocalModuleEvalWithFlagEnabled(t *testing.T) {
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
		queries:       queries,
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	require.NotEmpty(t, vulns, "rule should fire on resolved module resource")
}

const ephemeralRule = `package datadog

DatadogPolicy contains result if {
	some name, i
	secret := input.document[i].ephemeral.aws_secretsmanager_secret[name]
	secret.name

	result := {
		"documentId": input.document[i].id,
		"resourceType": "ephemeral.aws_secretsmanager_secret",
		"resourceName": name,
		"searchKey": sprintf("ephemeral.aws_secretsmanager_secret[%s].name", [name]),
	}
}
`

// A root-declared ephemeral block resolves against the file's declared blocks.
// Instances share the written label in the document, so one finding is raised;
// its address is the first instance key.
func TestInspect_RootEphemeralBlockIsAddressed(t *testing.T) {
	root := t.TempDir()
	rootPath := filepath.Join(root, "main.tf")
	require.NoError(t, os.WriteFile(rootPath, []byte(`
ephemeral "aws_secretsmanager_secret" "login" {
  for_each = toset(["a", "b"])
  name     = each.key
}
`), 0o644))

	files := parseTerraform(t, rootPath)
	ins := newTestInspector(t, inspectorOpts{
		queries: []model.QueryMetadata{{
			Query: "ephemeral_rule", Content: ephemeralRule, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "eph-rule", "platform": "Terraform"}, Aggregation: 1,
		}},
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	require.Len(t, vulns, 1)
	require.Equal(t, ".", vulns[0].RootModule, "the file sits at the repository root")
	require.Equal(t, "login", vulns[0].ResourceName)
	require.Equal(t, `ephemeral.aws_secretsmanager_secret.login["a"]`, vulns[0].ResourceID)
}

// A managed resource and an ephemeral block sharing type and name are two
// different blocks: the evaluator carries the kind from HCL, so their
// expansions and references never merge.
func TestInspect_ManagedAndEphemeralSameNameStayApart(t *testing.T) {
	root := t.TempDir()
	callerPath := filepath.Join(root, "main.tf")
	modDir := filepath.Join(root, "modules", "pw")
	require.NoError(t, os.MkdirAll(modDir, 0o755))
	require.NoError(t, os.WriteFile(callerPath, []byte(`
module "pw" { source = "./modules/pw" }
`), 0o644))
	modPath := filepath.Join(modDir, "main.tf")
	require.NoError(t, os.WriteFile(modPath, []byte(`
resource "random_password" "x" {
  for_each = toset(["m"])
  result   = "managed"
}

ephemeral "random_password" "x" {
  for_each = toset(["e1", "e2"])
  result   = each.key
}
`), 0o644))

	ephRule := `package datadog

DatadogPolicy contains result if {
	some name, i
	secret := input.document[i].ephemeral.random_password[name]
	secret.result

	result := {
		"documentId": input.document[i].id,
		"resourceType": "ephemeral.random_password",
		"resourceName": name,
		"searchKey": sprintf("ephemeral.random_password[%s].result", [name]),
	}
}
`
	files := append(parseTerraform(t, callerPath), parseTerraform(t, modPath)...)
	ins := newTestInspector(t, inspectorOpts{
		queries: []model.QueryMetadata{{
			Query: "eph_rule", Content: ephRule, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "eph-rule", "platform": "Terraform"}, Aggregation: 1,
		}},
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	require.Len(t, vulns, 2, "only the ephemeral rule's instances are reported, both addressed")
	ids := []string{vulns[0].ResourceID, vulns[1].ResourceID}
	require.ElementsMatch(t, []string{
		`module.pw.ephemeral.random_password.x["e1"]`,
		`module.pw.ephemeral.random_password.x["e2"]`,
	}, ids, "the managed random_password.x must never answer for the ephemeral one")
}

// A JSON-configured module's ephemeral instances are addressed under the
// call's module path like HCL ones: the JSON config schema must know the
// ephemeral block type, or the caller's instances are lost.
func TestInspect_JSONModuleEphemeralInstancesAddressed(t *testing.T) {
	root := t.TempDir()
	stackDir := filepath.Join(root, "stack")
	modDir := filepath.Join(root, "modules", "secrets")
	require.NoError(t, os.MkdirAll(stackDir, 0o755))
	require.NoError(t, os.MkdirAll(modDir, 0o755))
	rootPath := filepath.Join(stackDir, "main.tf")
	require.NoError(t, os.WriteFile(rootPath, []byte(`
module "secrets" {
  source = "../modules/secrets"
}
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(modDir, "main.tf.json"), []byte(`{
  "ephemeral": {
    "aws_secretsmanager_secret": {
      "login": {
        "for_each": {"a": {}, "b": {}},
        "name": "secret-${each.key}"
      }
    }
  }
}
`), 0o644))

	var files model.FileMetadatas
	files = append(files, parseTerraform(t, rootPath)...)
	files = append(files, parseTerraform(t, filepath.Join(modDir, "main.tf.json"))...)

	ins := newTestInspector(t, inspectorOpts{
		queries: []model.QueryMetadata{{
			Query: "eph_rule", Content: ephemeralRule, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "eph-rule", "platform": "Terraform"}, Aggregation: 1,
		}},
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	require.Len(t, vulns, 2, "both JSON ephemeral instances are reported")
	ids := []string{vulns[0].ResourceID, vulns[1].ResourceID}
	require.ElementsMatch(t, []string{
		`module.secrets.ephemeral.aws_secretsmanager_secret.login["a"]`,
		`module.secrets.ephemeral.aws_secretsmanager_secret.login["b"]`,
	}, ids)
}

// keyedItemsModule is called with a for_each map whose keys differ per caller
// and whose values are unknown: the module sees a map with known keys and
// unknown values, so every instance expands with its own key while the bucket
// and acl attributes stay identical.
const keyedItemsModule = `
variable "items" {
  type = map(number)
}

resource "aws_s3_bucket" "b" {
  for_each = var.items
  bucket   = "static"
  acl      = "public-read"
}
`

// keyedRoot writes a caller root whose for_each key is name-derived.
func keyedRoot(t *testing.T, root, name, key string) model.FileMetadatas {
	t.Helper()
	dir := filepath.Join(root, name)
	require.NoError(t, os.MkdirAll(dir, 0o755))
	path := filepath.Join(dir, "main.tf")
	require.NoError(t, os.WriteFile(path, []byte(`
resource "aws_instance" "src" {
  ami = "ami-1"
}

module "m" {
  source = "../modules/m"
  items  = { `+key+` = aws_instance.src.arn }
}
`), 0o644))
	return parseTerraform(t, path)
}

func keyedModuleFiles(t *testing.T, root string) model.FileMetadatas {
	modDir := filepath.Join(root, "modules", "m")
	require.NoError(t, os.MkdirAll(modDir, 0o755))
	modPath := filepath.Join(modDir, "main.tf")
	require.NoError(t, os.WriteFile(modPath, []byte(keyedItemsModule), 0o644))
	return parseTerraform(t, modPath)
}

func keyedAclRule() []model.QueryMetadata {
	return []model.QueryMetadata{{
		Query: "acl_rule", Content: `package datadog

DatadogPolicy contains result if {
	some name, i
	bucket := input.document[i].resource.aws_s3_bucket[name]
	bucket.acl == "public-read"

	result := {
		"documentId": input.document[i].id,
		"platform": "Terraform",
		"resourceType": "aws_s3_bucket",
		"resourceName": name,
		"searchKey": sprintf("aws_s3_bucket[%s].acl", [name]),
	}
}
`, InputData: "{}", Platform: "terraform",
		Metadata: map[string]interface{}{"id": "acl-rule", "platform": "Terraform"}, Aggregation: 1,
	}}
}

// Two roots iterating different for_each keys over unknown-valued maps each
// report their own keyed instance, with decode-time compaction on and off.
// The rendered attributes of the two instances differ only in the for_each
// reference text, so this also pins that a keyed instance is never reported
// with the primary caller's key.
func TestInspect_KeyedInstancesAcrossRootsStayDistinct(t *testing.T) {
	for _, compact := range []bool{false, true} {
		t.Run(map[bool]string{false: "compaction off", true: "compaction on"}[compact], func(t *testing.T) {
			root := t.TempDir()
			var files model.FileMetadatas
			files = append(files, keyedModuleFiles(t, root)...)
			files = append(files, keyedRoot(t, root, "stack-a", "x")...)
			files = append(files, keyedRoot(t, root, "stack-b", "y")...)

			ins := newTestInspector(t, inspectorOpts{
				queries:       keyedAclRule(),
				repoPath:      root,
				vb:            DefaultVulnerabilityBuilder,
				flagEvaluator: featureflags.NewLocalEvaluator(),
			})
			ins.SetCompactFindingsAtDecode(compact)

			vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
			require.NoError(t, err)
			require.Empty(t, ins.GetFailedQueries())
			require.Len(t, vulns, 2, "one finding per root's own keyed instance")

			ids := map[string]bool{}
			roots := map[string]string{}
			for i := range vulns {
				ids[vulns[i].ResourceID] = true
				roots[vulns[i].ResourceID] = vulns[i].RootModule
			}
			idList := make([]string, 0, len(ids))
			for id := range ids {
				idList = append(idList, id)
			}
			require.ElementsMatch(t, []string{
				`module.m.aws_s3_bucket.b["x"]`,
				`module.m.aws_s3_bucket.b["y"]`,
			}, idList, "each root reports its own for_each key")
			require.Equal(t, "stack-a", roots[`module.m.aws_s3_bucket.b["x"]`],
				"stack-a's finding carries stack-a's key, not the primary caller's")
			require.Equal(t, "stack-b", roots[`module.m.aws_s3_bucket.b["y"]`])
		})
	}
}

// Two roots iterating the SAME key with identical rendered attributes
// deduplicate onto one keyed document: the second caller is recorded in the
// primary document's extras, not emitted as a second document.
func TestInspect_IdenticalKeyedInstancesAcrossRootsStillDedup(t *testing.T) {
	root := t.TempDir()
	var files model.FileMetadatas
	files = append(files, keyedModuleFiles(t, root)...)
	files = append(files, keyedRoot(t, root, "stack-a", "x")...)
	files = append(files, keyedRoot(t, root, "stack-b", "x")...)

	targets := ruleTargetedResourceTypes(keyedAclRule())
	res := resolveModuleDocuments(context.Background(), files, root, relDirForTest(root), nil, targets, nil, nil, nil, nil)
	require.Len(t, res.docs, 1, "identical instances share one keyed document")
	require.Len(t, res.syntheticFiles, 1)
	require.Len(t, res.extras, 1, "the second caller is recorded in extras")

	var primaryID string
	for id := range res.extras {
		primaryID = id
	}
	extras := res.extras[primaryID]
	require.Len(t, extras, 1)
	require.Equal(t, "stack-b", extras[0].rootModule,
		"the extra caller keeps its own root, only the document is shared")

	// End to end: both callers report the shared instance, each under its own root.
	ins := newTestInspector(t, inspectorOpts{
		queries:       keyedAclRule(),
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	ins.SetCompactFindingsAtDecode(true)
	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	require.Len(t, vulns, 2, "one finding per caller, both on the shared instance")
	roots := map[string]bool{}
	for i := range vulns {
		require.Equal(t, `module.m.aws_s3_bucket.b["x"]`, vulns[i].ResourceID)
		roots[vulns[i].RootModule] = true
	}
	require.Equal(t, map[string]bool{"stack-a": true, "stack-b": true}, roots)
}

// The instances of a counted module call stay distinct findings through their
// call chains. Each one also carries the instance address.
func TestInspect_ModuleCountInstancesKeepDistinctFingerprints(t *testing.T) {
	root := t.TempDir()
	rootPath := writeFile(t, filepath.Join(root, "stack"), "main.tf", `
module "bucket" {
  count  = 3
  source = "../modules/bucket"
}
`)
	modPath := writeFile(t, filepath.Join(root, "modules", "bucket"), "main.tf", `
resource "aws_s3_bucket" "this" {
  acl = "public-read"
}
`)
	files := append(parseTerraform(t, rootPath), parseTerraform(t, modPath)...)
	ins := newTestInspector(t, inspectorOpts{
		queries: []model.QueryMetadata{{
			Query: "acl_rule", Content: aclRule, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "acl-rule", "platform": "Terraform"}, Aggregation: 1,
		}},
		repoPath: root, vb: DefaultVulnerabilityBuilder, flagEvaluator: featureflags.NewLocalEvaluator(),
	})

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	require.Len(t, vulns, 3)

	fingerprints := map[string]bool{}
	chains := map[string]bool{}
	for i := range vulns {
		fingerprints[model.FindingIdentity(&vulns[i])] = true
		chains[vulns[i].ModuleCallChain] = true
		require.Equal(t, "stack", vulns[i].RootModule)
		require.Contains(t, vulns[i].ResourceID, "module.bucket[")
	}
	require.Len(t, fingerprints, 3)
	require.Equal(t, map[string]bool{
		"stack/main.tf|module.bucket[0]": true,
		"stack/main.tf|module.bucket[1]": true,
		"stack/main.tf|module.bucket[2]": true,
	}, chains)
}
