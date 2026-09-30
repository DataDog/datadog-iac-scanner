/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/config"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

const plainCaller = `
module "bucket" {
  source = "../modules/bucket"
  acl    = "public-read"
}
`

// inspectTwoCallers scans two roots passing the same value to one module, so
// the second caller's finding is a clone of the first's deduplicated document.
func inspectTwoCallers(
	t *testing.T, callerA, callerB string, ruleConfigs map[string]config.IacRuleConfig,
	adjustA ...func(*model.FileMetadata),
) (vulns []model.Vulnerability, aPath, bPath string) {
	t.Helper()
	root := t.TempDir()
	aPath = writeCallerFixture(t, root, "stack-a/main.tf", callerA)
	bPath = writeCallerFixture(t, root, "stack-b/main.tf", callerB)
	modPath := writeCallerFixture(t, root, "modules/bucket/main.tf", `
variable "acl" {
  type = string
}

resource "aws_s3_bucket" "this" {
  acl = var.acl
}
`)

	var files model.FileMetadatas
	for _, path := range []string{aPath, bPath, modPath} {
		files = append(files, parseTerraform(t, path)...)
	}
	for i := range files {
		if files[i].FilePath != aPath {
			continue
		}
		for _, adjust := range adjustA {
			adjust(files[i])
		}
	}
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
	ins.ruleConfigs = ruleConfigs

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	return vulns, aPath, bPath
}

func suppressedByCaller(vulns []model.Vulnerability) map[string]bool {
	out := make(map[string]bool, len(vulns))
	for _, v := range vulns {
		out[v.ModuleAttribution.CallSite.Filename] = v.IsSuppressed
	}
	return out
}

func TestInspect_CallSiteIgnoreCommentSuppressesOnlyThatCaller(t *testing.T) {
	vulns, _, _ := inspectTwoCallers(t, `
module "bucket" {
  source = "../modules/bucket"
  # dd-iac-scan ignore-line
  acl    = "public-read"
}
`, plainCaller, nil)

	require.Len(t, vulns, 2)
	require.Equal(t, map[string]bool{"stack-a/main.tf": true, "stack-b/main.tf": false}, suppressedByCaller(vulns))
	for _, v := range vulns {
		if v.IsSuppressed {
			require.Equal(t, model.SuppressionJustificationIgnoreComment, v.SuppressionJustification)
		}
	}
}

func TestInspect_IgnoreCommentOnModuleBlockStillSuppresses(t *testing.T) {
	vulns, _, _ := inspectTwoCallers(t, plainCaller, `
# dd-iac-scan ignore-line
module "bucket" {
  source = "../modules/bucket"
  acl    = "public-read"
}
`, nil)

	require.Len(t, vulns, 2)
	require.Equal(t, map[string]bool{"stack-a/main.tf": false, "stack-b/main.tf": true}, suppressedByCaller(vulns))
}

func TestInspect_DisableCommandInCallerSuppressesOnlyThatCaller(t *testing.T) {
	vulns, _, _ := inspectTwoCallers(t, plainCaller, plainCaller, nil, func(file *model.FileMetadata) {
		file.Commands = model.CommentsCommands{"disable": "acl-rule"}
	})

	require.Len(t, vulns, 2)
	require.Equal(t, map[string]bool{"stack-a/main.tf": true, "stack-b/main.tf": false}, suppressedByCaller(vulns))
	for _, v := range vulns {
		if v.IsSuppressed {
			require.Equal(t, model.SuppressionJustificationDisableInFile, v.SuppressionJustification)
		}
	}
}

func TestInspect_RulePathFilterAppliesToCallSite(t *testing.T) {
	vulns, _, _ := inspectTwoCallers(t, plainCaller, plainCaller, map[string]config.IacRuleConfig{
		"acl-rule": {IgnorePaths: []string{"**/stack-a/**"}},
	})

	require.Len(t, vulns, 1)
	require.Equal(t, "stack-b/main.tf", vulns[0].ModuleAttribution.CallSite.Filename)
}

// TestInspect_ExternalCallerBypassesRulePathFilter mirrors the file-side
// external-module-path bypass (TestInspectorExternalModulePathBypassesRulePathFilter)
// for the caller side: a scanned remote package's root module calls a local
// submodule, and the caller-side only-paths filter must not drop the
// submodule finding even though the caller file is outside the configured
// paths.
func TestInspect_ExternalCallerBypassesRulePathFilter(t *testing.T) {
	repoRoot := t.TempDir()
	packageRoot := t.TempDir()
	callerPath := writeCallerFixture(t, packageRoot, "main.tf", `
module "bucket" {
  source = "./modules/bucket"
  acl    = "public-read"
}
`)
	modPath := writeCallerFixture(t, packageRoot, "modules/bucket/main.tf", `
variable "acl" {
  type = string
}

resource "aws_s3_bucket" "this" {
  acl = var.acl
}
`)

	var files model.FileMetadatas
	for _, path := range []string{callerPath, modPath} {
		files = append(files, parseTerraform(t, path)...)
	}

	ins := newTestInspector(t, inspectorOpts{
		queries: []model.QueryMetadata{{
			Query:       "acl_rule",
			Content:     aclRule,
			InputData:   "{}",
			Platform:    "terraform",
			Metadata:    map[string]interface{}{"id": "acl-rule"},
			Aggregation: 1,
		}},
		repoPath:      repoRoot,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	ins.SetExternalModulePaths([]string{packageRoot})
	ins.ruleConfigs = map[string]config.IacRuleConfig{
		"acl-rule": {OnlyPaths: []string{filepath.Join(repoRoot, "src")}},
	}

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	require.Len(t, vulns, 1)
	require.False(t, vulns[0].IsSuppressed)
}
