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
	"sort"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

// bucketModuleDefaultPublic defaults to a public ACL, so a scan of the module
// on its own reports it.
const bucketModuleDefaultPublic = `variable "acl" {
  default = "public-read"
}

resource "aws_s3_bucket" "this" {
  acl = var.acl
}
`

// writeTerragruntRepo writes files under a new repository root and parses the
// Terraform and Terragrunt files among them.
func writeTerragruntRepo(t *testing.T, tree map[string]string) (string, model.FileMetadatas) {
	t.Helper()
	root := t.TempDir()
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	names := make([]string, 0, len(tree))
	for name, content := range tree {
		path := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
		names = append(names, name)
	}
	sort.Strings(names)
	var files model.FileMetadatas
	for _, name := range names {
		switch filepath.Ext(name) {
		case ".tf":
		case ".hcl":
			if filepath.Base(name) != "terragrunt.hcl" {
				continue
			}
		default:
			continue
		}
		files = append(files, parseTerraform(t, filepath.Join(root, name))...)
	}
	return root, files
}

func inspectACL(t *testing.T, root string, files model.FileMetadatas) []model.Vulnerability {
	t.Helper()
	ins := newTestInspector(t, inspectorOpts{
		queries: []model.QueryMetadata{{
			Query:       "acl_rule",
			Content:     aclRule,
			InputData:   "{}",
			Platform:    "terraform",
			Metadata:    map[string]interface{}{"id": "acl-rule"},
			Aggregation: 1,
		}},
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	sort.Slice(vulns, func(i, j int) bool {
		return callSiteFile(vulns[i]) < callSiteFile(vulns[j])
	})
	return vulns
}

func callSiteFile(v model.Vulnerability) string {
	if v.ModuleAttribution == nil {
		return ""
	}
	return v.ModuleAttribution.CallSite.Filename
}

// Each unit is a call to its module with its own inputs: one finding per unit
// whose values are insecure, attributed to that unit, and none for the module
// scanned with its defaults.
func TestInspect_TerragruntUnitsCallTheirModule(t *testing.T) {
	root, files := writeTerragruntRepo(t, map[string]string{
		"modules/bucket/main.tf": bucketModuleDefaultPublic,
		"live/prod/terragrunt.hcl": `terraform {
  source = "../../modules/bucket"
}

inputs = {
  acl = "public-read"
}
`,
		"live/dev/terragrunt.hcl": `terraform {
  source = "../../modules/bucket"
}

inputs = {
  acl = "private"
}
`,
		"live/staging/terragrunt.hcl": `terraform {
  source = "../../modules//bucket"
}
`,
	})
	vulns := inspectACL(t, root, files)

	require.Len(t, vulns, 2)
	modFile := filepath.Join(root, "modules/bucket/main.tf")
	for _, v := range vulns {
		require.Equal(t, modFile, v.FileName, "the finding stays on the module resource")
		require.NotNil(t, v.ModuleAttribution)
		require.Len(t, v.ModuleAttribution.ModulePath, 1)
		require.Equal(t, "terragrunt", v.ModuleAttribution.ModulePath[0].Name)
		require.Equal(t, "modules/bucket/main.tf", v.ModuleAttribution.ModuleCodeLocation.Filename)
	}

	prod, staging := vulns[0].ModuleAttribution, vulns[1].ModuleAttribution
	require.Equal(t, "live/prod/terragrunt.hcl", prod.CallSite.Filename)
	require.Equal(t, 6, prod.CallSite.LineStart, "narrowed to the acl input")
	require.Equal(t, "live/staging/terragrunt.hcl", staging.CallSite.Filename)
	require.Equal(t, 2, staging.CallSite.LineStart, "the module default is anchored at terraform.source")
	require.NotEqual(t, vulns[0].ModuleCallChain, vulns[1].ModuleCallChain, "each unit has its own identity")
}

// A unit whose source does not resolve leaves the module scanned as written.
func TestInspect_TerragruntUnresolvedSourceKeepsModuleStandalone(t *testing.T) {
	root, files := writeTerragruntRepo(t, map[string]string{
		"modules/bucket/main.tf": bucketModuleDefaultPublic,
		"live/prod/terragrunt.hcl": `terraform {
  source = "../../modules/missing"
}
inputs = { acl = "private" }
`,
	})
	vulns := inspectACL(t, root, files)

	require.Len(t, vulns, 1)
	require.Equal(t, filepath.Join(root, "modules/bucket/main.tf"), vulns[0].FileName)
	require.Nil(t, vulns[0].ModuleAttribution)
}

// An ignore comment in terragrunt.hcl suppresses the finding attributed there.
func TestInspect_TerragruntIgnoreComment(t *testing.T) {
	root, files := writeTerragruntRepo(t, map[string]string{
		"modules/bucket/main.tf": bucketModuleDefaultPublic,
		"live/prod/terragrunt.hcl": `terraform {
  source = "../../modules/bucket"
}

inputs = {
  // dd-iac-scan ignore-line
  acl = "public-read"
}
`,
	})
	vulns := inspectACL(t, root, files)
	require.Len(t, vulns, 1)
	require.True(t, vulns[0].IsSuppressed)
	require.Equal(t, model.SuppressionKindInSource, vulns[0].SuppressionKind)
	require.Equal(t, "live/prod/terragrunt.hcl", callSiteFile(vulns[0]))
}

// Without terraform.source the unit directory is the module, called with the
// unit's inputs. A root terragrunt.hcl that units only include is shared
// configuration, not a unit.
func TestInspect_TerragruntUnitDirectoryIsTheModule(t *testing.T) {
	root, files := writeTerragruntRepo(t, map[string]string{
		"terragrunt.hcl": `inputs = {
  acl = "public-read"
}
`,
		"app/main.tf": `variable "acl" {
  default = "private"
}

resource "aws_s3_bucket" "this" {
  acl = var.acl
}
`,
		"app/terragrunt.hcl": `include {
  path = find_in_parent_folders()
}
`,
	})
	vulns := inspectACL(t, root, files)

	require.Len(t, vulns, 1)
	v := vulns[0]
	require.Equal(t, filepath.Join(root, "app/main.tf"), v.FileName)
	require.NotNil(t, v.ModuleAttribution)
	require.Equal(t, "app/terragrunt.hcl", v.ModuleAttribution.CallSite.Filename)
}

// Units that pass identical inputs to one module share an evaluation, and
// each still gets its own finding.
func TestInspect_TerragruntIdenticalUnitsEachReport(t *testing.T) {
	unit := `terraform {
  source = "../../modules/bucket"
}
inputs = { acl = "public-read" }
`
	root, files := writeTerragruntRepo(t, map[string]string{
		"modules/bucket/main.tf": bucketModuleDefaultPublic,
		"live/a/terragrunt.hcl":  unit,
		"live/b/terragrunt.hcl":  unit,
		"live/c/terragrunt.hcl":  unit,
	})
	vulns := inspectACL(t, root, files)

	require.Len(t, vulns, 3)
	got := []string{callSiteFile(vulns[0]), callSiteFile(vulns[1]), callSiteFile(vulns[2])}
	require.Equal(t, []string{"live/a/terragrunt.hcl", "live/b/terragrunt.hcl", "live/c/terragrunt.hcl"}, got)
}

// A unit's tfr:// source resolves to the module the pre-scan fetched for the
// unit, which is then instantiated with the unit's inputs.
func TestInspect_TerragruntRemoteSource(t *testing.T) {
	fx := newRemoteBucketFixture(t)
	require.NoError(t, os.MkdirAll(fx.callerRoot, 0o755))
	unitPath := filepath.Join(fx.callerRoot, "terragrunt.hcl")
	require.NoError(t, os.WriteFile(unitPath, []byte(`terraform {
  source = "tfr://`+remoteBucketSource+`?version=`+remoteBucketVersion+`"
}

inputs = {
  acl = "public-read"
}
`), 0o644))

	vulns := inspectRemoteBucket(t, fx, []string{unitPath}, aclRule)

	require.Len(t, vulns, 1)
	v := vulns[0]
	require.Equal(t, fx.modPath, v.FileName)
	require.NotNil(t, v.ModuleAttribution)
	require.Equal(t, "stack/terragrunt.hcl", v.ModuleAttribution.CallSite.Filename)
	require.Equal(t, 6, v.ModuleAttribution.CallSite.LineStart)
	require.Equal(t, remoteBucketSource, v.ModuleAttribution.Source)
	require.Equal(t, remoteBucketVersion, v.ModuleAttribution.Version)
}

// A dependency output the scan evaluated reaches the unit reading it, over
// the mock, whichever unit comes first in file order.
func TestInspect_TerragruntDependencyOutputs(t *testing.T) {
	root, files := writeTerragruntRepo(t, map[string]string{
		"modules/bucket/main.tf": bucketModuleDefaultPublic,
		"modules/settings/main.tf": `output "acl" {
  value = "public-read"
}
`,
		"live/settings/terragrunt.hcl": `terraform {
  source = "../../modules/settings"
}
`,
		"live/app/terragrunt.hcl": `terraform {
  source = "../../modules/bucket"
}

dependency "settings" {
  config_path  = "../settings"
  mock_outputs = { acl = "private" }
}

inputs = {
  acl = dependency.settings.outputs.acl
}
`,
	})
	vulns := inspectACL(t, root, files)

	require.Len(t, vulns, 1)
	require.Equal(t, "live/app/terragrunt.hcl", callSiteFile(vulns[0]))
	require.Equal(t, 11, vulns[0].ModuleAttribution.CallSite.LineStart)
}

// -var-file values override inputs, and the module's own tfvars files do too:
// the overridden input is no longer where the value comes from.
func TestInspect_TerragruntVarFilesOverrideInputs(t *testing.T) {
	root, files := writeTerragruntRepo(t, map[string]string{
		"modules/bucket/main.tf": bucketModuleDefaultPublic,
		"modules/tfvars/main.tf": bucketModuleDefaultPublic,
		"modules/tfvars/terraform.tfvars": `acl = "public-read"
`,
		"live/varfile/public.tfvars": `acl = "public-read"
`,
		"live/varfile/terragrunt.hcl": `terraform {
  source = "../../modules/bucket"

  extra_arguments "vars" {
    commands           = ["plan", "apply"]
    required_var_files = ["public.tfvars"]
  }
}

inputs = {
  acl = "private"
}
`,
		"live/tfvars/terragrunt.hcl": `terraform {
  source = "../../modules/tfvars"
}

inputs = {
  acl = "private"
}
`,
	})
	vulns := inspectACL(t, root, files)

	require.Len(t, vulns, 2)
	require.Equal(t, "live/tfvars/terragrunt.hcl", callSiteFile(vulns[0]))
	require.Equal(t, "live/varfile/terragrunt.hcl", callSiteFile(vulns[1]))
	for _, v := range vulns {
		require.Equal(t, 2, v.ModuleAttribution.CallSite.LineStart, "anchored at terraform.source, not the overridden input")
	}
}
