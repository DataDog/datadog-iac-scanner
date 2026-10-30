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

func TestModuleInstantiationSummary_LoggedAtWarnLevel(t *testing.T) {
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
	ctx := zerolog.New(&logs).Level(zerolog.WarnLevel).WithContext(context.Background())
	ins.instantiateLocalModules(ctx, files, ruleTargetedResourceTypes(queries, ins.terraformRuleLibraries()...))

	out := logs.String()
	if !strings.Contains(out, "tfeval: module instantiation summary") {
		t.Fatalf("expected warn-level summary for agents to grep, got %q", out)
	}
	if !strings.Contains(out, `"module_resources_instantiated":`) {
		t.Fatalf("expected structured instantiation count, got %q", out)
	}
	if !strings.Contains(out, `"module_root_count":`) {
		t.Fatalf("expected root count in summary, got %q", out)
	}
}

// Two roots call the same module with the same inputs: expect two findings and
// two distinct root modules in their identities (K9CODESEC-7158).
func TestInspect_TwoCallersGetDistinctRootModules(t *testing.T) {
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
		// "Terraform" is what puts the root module in the finding identity, as
		// the Terraform rules do. Without it the two callers are one finding.
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
	// each attributed to the module body but under its own root module.
	require.Len(t, vulns, 2, "expected one finding per module caller")
	roots := map[string]bool{}
	for _, v := range vulns {
		require.Equal(t, modPath, v.FileName, "findings should be reported at the module resource definition")
		require.NotEmpty(t, v.ResourceID, "instantiated finding must carry its Terraform address")
		roots[v.RootModule] = true
	}
	require.Len(t, roots, 2, "the two callers must produce distinct root modules")
	require.True(t, roots["stack-a"])
	require.True(t, roots["stack-b"])
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
// match module[name].acl). The call-site block stays in the scan so
// module-block rules keep their coverage: the two branches report two
// distinct blocks, and their identities — the call block's
// <module path>.module.<name> versus the resource instance's address — keep
// them apart instead of collapsing into one.
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

	// Two findings, one per block: the call block on the caller file and the
	// instantiated resource in the module body. The call-site block keeps its
	// rule coverage (K9CODESEC-7158), and the two identities never collapse.
	require.Len(t, vulns, 2, "both blocks are reported: the call site and the instantiated resource")
	byType := map[string]model.Vulnerability{}
	for i := range vulns {
		byType[vulns[i].ResourceType] = vulns[i]
	}
	require.Equal(t, "module.bucket", byType["module"].ResourceID,
		"the call block is addressed by its module path")
	require.Equal(t, "module.bucket.aws_s3_bucket.this", byType["aws_s3_bucket"].ResourceID,
		"the resource is addressed by its instance address under the call")
	require.Equal(t, rootPath, byType["module"].FileName)
	require.Equal(t, modPath, byType["aws_s3_bucket"].FileName)
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
		// "Terraform" puts the root module in the finding identity, as the
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
	roots := []string{vulns[0].RootModule, vulns[1].RootModule}
	require.ElementsMatch(t, []string{"stack-a", "stack-b"}, roots,
		"each call site must keep its own root after deduplication")
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
	require.Equal(t, "module.buckets.aws_s3_bucket.replica[1]", vulns[0].ResourceID,
		"the finding's instance address must pick out count.index 1, not the module call as a whole")
	require.Equal(t, "stack", vulns[0].RootModule)
}

// TestInspect_ExpandedRootKeepsSiblingInOwningInstance verifies where a root
// count/for_each split leaves the file's other resources: the owning instance
// document (the first layer) keeps them next to the layer-0 instances, the
// way a called module's unexpanded blocks stay in its layer-0 document, and
// later layers carry only their own instance. Copying the siblings into every
// layer made the scan's documents grow with siblings × layers, so every rule
// re-evaluated each sibling once per instance and peak memory followed the
// product rather than the configuration.
func TestInspect_ExpandedRootKeepsSiblingInOwningInstance(t *testing.T) {
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
			Metadata: map[string]interface{}{"id": "acl-rule"}, Aggregation: 1,
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
			Metadata: map[string]interface{}{"id": "missing-block"}, Aggregation: 1,
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
			Metadata: map[string]interface{}{"id": "guard-rule"}, Aggregation: 1,
		},
	}
	ins := newTestInspector(t, inspectorOpts{
		queries: queries, repoPath: root, vb: DefaultVulnerabilityBuilder, flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	ins.SetCompactFindingsAtDecode(false)

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())

	byQuery := map[string][]string{}
	var detail []string
	for i := range vulns {
		byQuery[vulns[i].QueryID] = append(byQuery[vulns[i].QueryID], vulns[i].ResourceID)
		detail = append(detail, fmt.Sprintf("%s id=%q root=%q file=%s line=%d", vulns[i].QueryID, vulns[i].ResourceID, vulns[i].RootModule, vulns[i].FileID, vulns[i].Line))
	}
	require.Equal(t, []string{"aws_s3_bucket.this[1]"}, byQuery["missing-block"],
		"the owning instance keeps the sibling, so a same-document rule sees it next to this[0] only")
	require.ElementsMatch(t, []string{"aws_s3_bucket.this[0]", "aws_s3_bucket.this[1]"}, byQuery["acl-rule"], strings.Join(detail, "\n"))
	require.Equal(t, []string{"aws_s3_bucket_public_access_block.guard"}, byQuery["guard-rule"],
		"the sibling is reported once, by the owning document")
}

// TestInspect_RootResourceAddress verifies that a root resource with no
// count/for_each gets its unindexed Terraform address attached without going
// through the per-instance instantiation pipeline (K9CODESEC-7158).
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
		Metadata: map[string]interface{}{"id": "acl-rule"}, Aggregation: 1,
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

// TestInspect_RootResourceCountAddress verifies that a root resource with a
// real count expansion gets one distinct, indexed Terraform address per
// instance (K9CODESEC-7158): the instances are no longer collapsed to one
// finding, unlike before this resolved their addresses.
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
		Metadata: map[string]interface{}{"id": "acl-rule"}, Aggregation: 1,
	}}
	ins := newTestInspector(t, inspectorOpts{
		queries: queries, repoPath: root, vb: DefaultVulnerabilityBuilder, flagEvaluator: featureflags.NewLocalEvaluator(),
	})

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())

	require.Len(t, vulns, 2, "each count instance is its own finding once its address resolves")
	gotIDs := []string{vulns[0].ResourceID, vulns[1].ResourceID}
	require.ElementsMatch(t, []string{"aws_s3_bucket.this[0]", "aws_s3_bucket.this[1]"}, gotIDs)
	require.Equal(t, "stack", vulns[0].RootModule)
	require.Equal(t, "stack", vulns[1].RootModule)
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
