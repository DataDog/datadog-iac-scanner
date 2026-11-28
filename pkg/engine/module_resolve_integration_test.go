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
	ins.instantiateLocalModules(ctx, files, ruleTargetedResourceTypes(queries, ins.terraformRuleLibraries()...), nil)

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
		t.Fatalf("expected no warn for an untruncated instantiation, got %q", out)
	}
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

	require.Len(t, vulns, 1, "the second count-expanded instance must be scanned")
	require.Equal(t, "replica", vulns[0].ResourceName)
	require.Equal(t, "stack/main.tf|module.buckets", vulns[0].ModuleCallChain)
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

// Exercise the existing rule interface against evaluated root instances. Each
// positive expansion has a private first instance so a finding proves later
// instances were projected, rather than just the declaration scanned once.
func TestInspect_RootResourceInstances(t *testing.T) {
	for _, tc := range []struct {
		name, config, tfvars string
		files                map[string]string
		want                 int
	}{
		{name: "literal", config: `resource "aws_s3_bucket" "b" { acl = "public-read" }`, want: 1},
		{name: "locals and defaults", config: `
variable "acl" { default = "PUBLIC-READ" }
locals { acl = lower(var.acl) }
resource "aws_s3_bucket" "b" { acl = local.acl }
`, want: 1},
		{name: "cross-file inputs", config: `resource "aws_s3_bucket" "b" { acl = local.acl }`,
			files: map[string]string{"inputs.tf": `
variable "acl" { default = "PUBLIC-READ" }
locals { acl = lower(var.acl) }
`}, want: 1},
		{name: "resource reference", config: `
resource "aws_s3_bucket" "source" {
  bucket = "2"
  acl = "private"
}
resource "aws_s3_bucket" "b" {
  count = tonumber(aws_s3_bucket.source.bucket)
  acl = count.index == 1 ? "public-read" : "private"
}
`, want: 1},
		{name: "module output", config: `
module "settings" { source = "./settings" }
resource "aws_s3_bucket" "b" { acl = module.settings.acl }
`, files: map[string]string{"settings/main.tf": `output "acl" { value = "public-read" }`}, want: 1},
		{name: "automatic variable file", config: `
variable "acl" { default = "private" }
resource "aws_s3_bucket" "b" { acl = var.acl }
`, tfvars: `acl = "public-read"`, want: 1},
		{name: "count", config: `resource "aws_s3_bucket" "b" {
  count = 2
  acl = count.index == 1 ? "public-read" : "private"
}`, want: 1},
		{name: "count both instances", config: `resource "aws_s3_bucket" "b" {
  count = 2
  acl = "public-read"
}`, want: 2},
		{name: "for_each", config: `resource "aws_s3_bucket" "b" {
  for_each = { a = "private", z = "public-read" }
  acl = each.key == "z" ? each.value : "private"
}`, want: 1},
		{name: "for_each both instances", config: `resource "aws_s3_bucket" "b" {
  for_each = { a = "public-read", z = "public-read" }
  acl = each.value
}`, want: 2},
		{name: "zero count", config: `resource "aws_s3_bucket" "b" {
  count = 0
  acl = "public-read"
}`},
		{name: "empty for_each", config: `resource "aws_s3_bucket" "b" {
  for_each = {}
  acl = "public-read"
}`},
		{name: "unknown count invariant", config: `
variable "n" {}
resource "aws_s3_bucket" "b" {
  count = var.n
  acl = "public-read"
}`, want: 1},
		{name: "unknown count dependent", config: `
variable "n" {}
resource "aws_s3_bucket" "b" {
  count = var.n
  acl = count.index == 1 ? "public-read" : "private"
}`},
		{name: "unknown for_each dependent", config: `
variable "buckets" {}
resource "aws_s3_bucket" "b" {
  for_each = var.buckets
  acl = each.value
}`},
		{name: "terraform json", config: `{
  "variable": {"acl": {"default": "public-read"}},
  "resource": {"aws_s3_bucket": {"b": {
    "count": 2,
    "acl": "${count.index == 1 ? var.acl : \"private\"}"
  }}}
}`, want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			filename := "main.tf"
			if tc.name == "terraform json" {
				filename += ".json"
			}
			path := writeFile(t, root, filename, tc.config)
			if tc.tfvars != "" {
				writeFile(t, root, "terraform.tfvars", tc.tfvars)
			}
			files := parseTerraform(t, path)
			for name, content := range tc.files {
				support := writeFile(t, filepath.Dir(filepath.Join(root, name)), filepath.Base(name), content)
				files = append(files, parseTerraform(t, support)...)
			}
			ins := newTestInspector(t, inspectorOpts{repoPath: root, vb: DefaultVulnerabilityBuilder,
				queries: []model.QueryMetadata{{Query: "acl", Content: aclRule, Platform: "terraform", Aggregation: 1}},
			})
			vulns, err := ins.Inspect(t.Context(), "test", files, []string{"terraform"})
			require.NoError(t, err)
			require.Empty(t, ins.GetFailedQueries())
			require.Len(t, vulns, tc.want)
			for _, v := range vulns {
				require.Equal(t, "b", v.ResourceName)
				require.Empty(t, v.ModuleCallChain, "root findings must retain their identity")
				attribute := "acl ="
				if tc.name == "terraform json" {
					attribute = `"acl":`
				}
				line := 1 + strings.Count(tc.config[:strings.LastIndex(tc.config, attribute)], "\n")
				require.Equal(t, line, v.Line, "the finding must point at the written attribute")
			}
			if tc.want == 2 {
				require.Equal(t, model.FindingIdentity(&vulns[0]), model.FindingIdentity(&vulns[1]),
					"instances of one written declaration keep distinct raw results while reporting the same declaration identity")
			}
		})
	}
}

func TestInspect_RootDataInstances(t *testing.T) {
	const rule = `package datadog
DatadogPolicy contains result if {
  some name, i
  input.document[i].data.local_file[name].filename == "public"
  result := {
    "documentId": input.document[i].id,
    "resourceType": "data.local_file",
    "resourceName": name,
    "searchKey": sprintf("data.local_file[%s].filename", [name]),
  }
}`
	for _, tc := range []struct {
		name, expansion, filename string
		want                      int
	}{
		{"count", "count = 2", `count.index == 1 ? "public" : "private"`, 1},
		{"for_each", `for_each = { a = "private", z = "public" }`, "each.value", 1},
		{"zero", "count = 0", `"public"`, 0},
		{"empty", "for_each = {}", `"public"`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			path := writeFile(t, root, "main.tf", fmt.Sprintf("data \"local_file\" \"f\" {\n%s\nfilename = %s\n}", tc.expansion, tc.filename))
			ins := newTestInspector(t, inspectorOpts{repoPath: root, vb: DefaultVulnerabilityBuilder,
				queries: []model.QueryMetadata{{Query: "data", Content: rule, Platform: "terraform", Aggregation: 1}},
			})
			vulns, err := ins.Inspect(t.Context(), "test", parseTerraform(t, path), []string{"terraform"})
			require.NoError(t, err)
			require.Empty(t, ins.GetFailedQueries())
			require.Len(t, vulns, tc.want)
		})
	}
}

func TestInspect_RootExpandedDataOverrideSource(t *testing.T) {
	for _, tc := range []struct {
		name, expansion, overrideValue, address, resourceType, searchPrefix string
	}{
		{"count unqualified", "count = 2", `count.index == 1 ? "public" : "private"`, "data.local_file.f[1]", "local_file", "local_file"},
		{"for_each unqualified", `for_each = { a = "private", z = "public" }`, `each.key == "z" ? "public" : "private"`, `data.local_file.f["z"]`, "local_file", "local_file"},
		{"count qualified", "count = 2", `count.index == 1 ? "public" : "private"`, "data.local_file.f[1]", "data.local_file", "data.local_file"},
		{"for_each qualified", `for_each = { a = "private", z = "public" }`, `each.key == "z" ? "public" : "private"`, `data.local_file.f["z"]`, "data.local_file", "data.local_file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			main := writeFile(t, root, "main.tf", fmt.Sprintf(`data "local_file" "f" {
  %s
  filename = "private"
}
`, tc.expansion))
			override := writeFile(t, root, "override.tf", fmt.Sprintf(`data "local_file" "f" {
  filename = %s
}
`, tc.overrideValue))
			rule := fmt.Sprintf(`package datadog
DatadogPolicy contains result if {
  some i, name
  input.document[i].data.local_file[name].filename == "public"
  result := {
    "documentId": input.document[i].id,
    "resourceType": %q,
    "resourceName": name,
    "searchKey": sprintf("%s[%%s].filename", [name]),
  }
}`, tc.resourceType, tc.searchPrefix)
			ins := newTestInspector(t, inspectorOpts{repoPath: root, vb: DefaultVulnerabilityBuilder,
				queries: []model.QueryMetadata{{Query: "data-override", Content: rule, Platform: "terraform", Aggregation: 1}},
			})
			ins.SetInventory(&collectingSink{})
			files := append(parseTerraform(t, main), parseTerraform(t, override)...)
			vulns, err := ins.Inspect(t.Context(), "test", files, []string{"terraform"})
			require.NoError(t, err)
			require.Empty(t, ins.GetFailedQueries())
			require.Len(t, vulns, 1)
			require.Equal(t, "f", vulns[0].ResourceName)
			require.Equal(t, "override.tf", filepath.Base(vulns[0].FileName))
			require.Equal(t, 2, vulns[0].Line)
			require.Len(t, vulns[0].ResourceOccurrences, 1)
			require.Equal(t, tc.address, vulns[0].ResourceOccurrences[0].Terraform.Address)
		})
	}
}

func TestInspect_RootGoogleIAMPolicyDataDuplicateGuard(t *testing.T) {
	const rule = `package datadog
options := {"user:", "allUsers", "allAuthenticatedUsers"}
DatadogPolicy contains result if {
  some i, name
  policy := input.document[i].data.google_iam_policy[name]
  some optio in options
  check_member(policy.binding, optio)
  valid_role(policy.binding)
  result := {"documentId": input.document[i].id, "resourceType": "google_iam_policy", "resourceName": name, "searchKey": sprintf("google_iam_policy[%s].binding.role", [name])}
}
DatadogPolicy contains result if {
  some i in input.document
  some resourceType, resourcesOfType in i.resource
  some name, resource in resourcesOfType
  is_string(resource.policy_data)
  startswith(resource.policy_data, "{")
  policy := json.unmarshal(resource.policy_data)
  some binding in policy.bindings
  some optio in options
  check_member(binding, optio)
  valid_role(binding)
  not reported_at_data_block(i, binding, optio)
  result := {"documentId": i.id, "resourceType": resourceType, "resourceName": name, "searchKey": sprintf("%s[%s].policy_data", [resourceType, name])}
}
reported_at_data_block(doc, binding, optio) if {
  not doc._dd_tfplan_meta
  some policy in doc.data.google_iam_policy
  is_object(policy.binding)
  policy.binding.role == binding.role
  check_member(policy.binding, optio)
}
check_member(resource, prefix) if {
  some member in resource.members
  startswith(member, prefix)
}
valid_role(resource) if {
  is_string(resource.role)
  resource.role != ""
}
`
	root := t.TempDir()
	path := writeFile(t, root, "main.tf", `data "google_iam_policy" "positive" {
  binding {
    role = "roles/apigee.runtimeAgent"
    members = ["user:jane@example.com"]
  }
}
resource "google_project_iam_policy" "positive" {
  project = "your-project-id"
  policy_data = data.google_iam_policy.positive.policy_data
}
`)
	ins := newTestInspector(t, inspectorOpts{repoPath: root, vb: DefaultVulnerabilityBuilder,
		queries: []model.QueryMetadata{{Query: "iam", Content: rule, Platform: "terraform", Aggregation: 1}},
	})
	vulns, err := ins.Inspect(t.Context(), "test", parseTerraform(t, path), []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	require.Len(t, vulns, 1, "the applied policy must be suppressed when the sibling data policy has the same binding")
	require.Equal(t, "google_iam_policy", vulns[0].ResourceType)
}

func TestInspect_AmbiguousRootStillProjectsCalledModule(t *testing.T) {
	root := t.TempDir()
	main := writeFile(t, root, "main.tf", `resource "aws_s3_bucket" "duplicate" { acl = "private" }
module "child" { source = "./child" }
`)
	duplicate := writeFile(t, root, "duplicate.tf", `resource "aws_s3_bucket" "duplicate" { acl = "private" }`)
	child := writeFile(t, filepath.Join(root, "child"), "main.tf", `resource "aws_s3_bucket" "from_child" { acl = "public-read" }`)
	files := append(parseTerraform(t, main), parseTerraform(t, duplicate)...)
	files = append(files, parseTerraform(t, child)...)
	ins := newTestInspector(t, inspectorOpts{repoPath: root, vb: DefaultVulnerabilityBuilder,
		queries: []model.QueryMetadata{{Query: "acl", Content: aclRule, Platform: "terraform", Aggregation: 1}},
	})
	vulns, err := ins.Inspect(t.Context(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	require.Len(t, vulns, 1, "ambiguous root declarations must keep their legacy input while valid child instances remain projected")
	require.Equal(t, "from_child", vulns[0].ResourceName)
	require.Contains(t, vulns[0].ModuleCallChain, "module.child")
}

func TestInspect_RootCountFindingLinksOnlyAffectedInstance(t *testing.T) {
	const structuredAlias = `package datadog
DatadogPolicy contains result if {
  some i, name
  input.document[i].resource.aws_s3_bucket[name].acl == "public-read"
  result := {"_dd_id": input.document[i].id, "path": ["resource", "aws_s3_bucket", name, "acl"], "resourceType": "aws_s3_bucket", "resourceName": "reported alias"}
}`
	const structuredWithoutDisplayFields = `package datadog
DatadogPolicy contains result if {
  some i, name
  input.document[i].resource.aws_s3_bucket[name].acl == "public-read"
  result := {"_dd_id": input.document[i].id, "path": ["resource", "aws_s3_bucket", name, "acl"]}
}`
	for _, tc := range []struct {
		name, rule, config, override, wantName, wantFile string
		wantLine                                         int
	}{
		{name: "legacy bracket", rule: aclRule, wantName: "b"},
		{name: "legacy dotted", rule: strings.ReplaceAll(aclRule, "aws_s3_bucket[%s].acl", "aws_s3_bucket.%s.acl"), wantName: "b"},
		{name: "legacy alias", rule: `package datadog
DatadogPolicy contains result if {
  some i, name
  input.document[i].resource.aws_s3_bucket[name].acl == "public-read"
  result := {"documentId": input.document[i].id, "resourceType": "aws_s3_bucket", "resourceName": "reported alias", "searchKey": sprintf("aws_s3_bucket.%s.acl", [name])}
}`, wantName: "reported alias"},
		{name: "structured alias", rule: structuredAlias, wantName: "reported alias"},
		{name: "structured without display fields", rule: structuredWithoutDisplayFields},
		{
			name: "override contribution",
			rule: aclRule,
			config: `resource "aws_s3_bucket" "b" {
  count = 2
  acl = "private"
}`,
			override: `resource "aws_s3_bucket" "b" {
  acl = count.index == 1 ? "public-read" : "private"
}`,
			wantName: "b", wantFile: "override.tf", wantLine: 2,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			config := tc.config
			if config == "" {
				config = `resource "aws_s3_bucket" "b" {
  count = 2
  acl = count.index == 1 ? "public-read" : "private"
}
`
			}
			path := writeFile(t, root, "main.tf", config)
			overridePath := ""
			if tc.override != "" {
				overridePath = writeFile(t, root, "override.tf", tc.override)
			}
			ins := newTestInspector(t, inspectorOpts{repoPath: root, vb: DefaultVulnerabilityBuilder,
				queries: []model.QueryMetadata{{Query: "acl", Content: tc.rule, Platform: "terraform", Aggregation: 1}},
			})
			ins.SetInventory(&collectingSink{})
			files := parseTerraform(t, path)
			if overridePath != "" {
				files = append(files, parseTerraform(t, overridePath)...)
			}
			vulns, err := ins.Inspect(t.Context(), "test", files, []string{"terraform"})
			require.NoError(t, err)
			require.Empty(t, ins.GetFailedQueries())
			require.Len(t, vulns, 1)
			require.Equal(t, tc.wantName, vulns[0].ResourceName)
			if tc.wantFile != "" {
				require.Equal(t, tc.wantFile, filepath.Base(vulns[0].FileName))
				require.Equal(t, tc.wantLine, vulns[0].Line)
			}
			require.Len(t, vulns[0].ResourceOccurrences, 1)
			require.Equal(t, "aws_s3_bucket.b[1]", vulns[0].ResourceOccurrences[0].Terraform.Address)
		})
	}
}

func TestInspect_RootInstancesRetainSameFileContextOnce(t *testing.T) {
	root := t.TempDir()
	path := writeFile(t, root, "main.tf", `resource "aws_s3_bucket" "sibling" {
  bucket = "sibling"
  acl = "private"
}
resource "aws_s3_bucket" "b" {
  count = 2
  bucket = "counted"
  acl = count.index == 1 ? "public-read" : "private"
}
`)
	for _, tc := range []struct {
		name, rule string
		want       int
	}{
		{
			name: "later instance joins its singleton sibling",
			rule: `package datadog
DatadogPolicy contains result if {
  some i, name
  input.document[i].resource.aws_s3_bucket[name].acl == "public-read"
  input.document[i].resource.aws_s3_bucket.sibling.bucket == "sibling"
  result := {"documentId": input.document[i].id, "resourceType": "aws_s3_bucket", "resourceName": name, "searchKey": sprintf("aws_s3_bucket[%s].acl", [name])}
}`,
			want: 1,
		},
		{
			name: "aggregate sees singleton once",
			rule: `package datadog
DatadogPolicy contains result if {
  documents := [doc.id | some doc in input.document; doc.resource.aws_s3_bucket.sibling.bucket == "sibling"]
  count(documents) == 1
  some doc in input.document
  doc.resource.aws_s3_bucket.sibling.bucket == "sibling"
  result := {"documentId": doc.id, "resourceType": "aws_s3_bucket", "resourceName": "sibling", "searchKey": "aws_s3_bucket.sibling.bucket"}
}`,
			want: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := parseTerraform(t, path)
			writtenID := files[0].ID
			ins := newTestInspector(t, inspectorOpts{repoPath: root, vb: DefaultVulnerabilityBuilder,
				queries: []model.QueryMetadata{{Query: "root-context", Content: tc.rule, Platform: "terraform", Aggregation: 1}},
			})
			vulns, err := ins.Inspect(t.Context(), "test", files, []string{"terraform"})
			require.NoError(t, err)
			require.Empty(t, ins.GetFailedQueries())
			require.Len(t, vulns, tc.want)
			if tc.name == "later instance joins its singleton sibling" {
				require.Equal(t, "b", vulns[0].ResourceName)
				require.Equal(t, 8, vulns[0].Line)
				require.Equal(t, writtenID, vulns[0].FileID, "root findings retain the original document identity")
				require.Empty(t, vulns[0].ModuleCallChain)
			}
		})
	}
}
