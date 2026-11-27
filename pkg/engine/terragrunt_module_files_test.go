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

	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

const (
	// The module's own bucket is private whatever the default is.
	privateBucketModule = "variable \"acl\" {\n  default = \"public-read\"\n}\n\nresource \"aws_s3_bucket\" \"this\" {\n  acl = \"private\"\n}\n"
	// extra.tf: the acl argument is on line 3.
	extraTF = "# the unit's own bucket\nresource \"aws_s3_bucket\" \"extra\" {\n  acl = var.acl\n}\n"
	unitDir = "live/prod/"
)

func (r *terragruntRepo) scanUnit(unitFiles ...string) []model.Vulnerability {
	r.t.Helper()
	files := append(r.files(), r.unitFiles(true, unitFiles...)...)
	files = append(files, r.parseUnit(filepath.Join(r.root, "live", "prod", "terragrunt.hcl")))
	return r.inspect(files)
}

func vulnsIn(vulns []model.Vulnerability, file string) []model.Vulnerability {
	var out []model.Vulnerability
	for _, v := range vulns {
		if v.FileName == file {
			out = append(out, v)
		}
	}
	return out
}

func TestTerragruntUnitFileSeesModuleDefault(t *testing.T) {
	r := newTerragruntRepo(t, privateBucketModule)
	extra := r.write(unitDir+"extra.tf", extraTF)
	r.write(unitDir+"terragrunt.hcl", defaultUnit)

	vulns := r.scanUnit(unitDir + "extra.tf")
	require.Len(t, vulns, 1, "one finding, no duplicate of the directly scanned file")
	require.Equal(t, extra, vulns[0].FileName)
	require.Equal(t, 3, vulns[0].Line)
	require.NotNil(t, vulns[0].ModuleAttribution)
	require.Equal(t, "live/prod/terragrunt.hcl", vulns[0].ModuleAttribution.CallSite.Filename)
	require.Equal(t, "live/prod/extra.tf", vulns[0].ModuleAttribution.ModuleCodeLocation.Filename)
	require.Equal(t, 3, vulns[0].ModuleAttribution.ModuleCodeLocation.LineStart)
}

func TestTerragruntUnitFileSeesModuleTfvars(t *testing.T) {
	r := newTerragruntRepo(t, "variable \"acl\" {\n  default = \"private\"\n}\n")
	r.write("modules/bucket/terraform.tfvars", "acl = \"public-read\"\n")
	extra := r.write(unitDir+"extra.tf", extraTF)
	r.write(unitDir+"terragrunt.hcl", defaultUnit)

	vulns := r.scanUnit(unitDir + "extra.tf")
	require.Len(t, vulns, 1)
	require.Equal(t, extra, vulns[0].FileName)
}

func TestTerragruntUnitFileSeesInputs(t *testing.T) {
	r := newTerragruntRepo(t, privateBucketModule)
	extra := r.write(unitDir+"extra.tf", extraTF)
	r.write(unitDir+"terragrunt.hcl", publicUnit)

	vulns := r.scanUnit(unitDir + "extra.tf")
	require.Len(t, vulns, 1)
	require.Equal(t, extra, vulns[0].FileName)
}

func TestTerragruntUnitFileResolvesUnknownInputToNothing(t *testing.T) {
	r := newTerragruntRepo(t, privateBucketModule)
	r.write(unitDir+"extra.tf", extraTF)
	r.write(unitDir+"terragrunt.hcl", "terraform {\n  source = \"../../modules/bucket\"\n}\ninputs = {\n  acl = get_env(\"DD_TEST_UNSET_ACL\")\n}\n")
	require.Empty(t, r.scanUnit(unitDir+"extra.tf"), "an unknown input never falls back to the default")
}

func TestTerragruntUnitFileIgnoreComment(t *testing.T) {
	r := newTerragruntRepo(t, privateBucketModule)
	r.write(unitDir+"extra.tf", "resource \"aws_s3_bucket\" \"extra\" {\n  # dd-iac-scan ignore-line\n  acl = var.acl\n}\n")
	r.write(unitDir+"terragrunt.hcl", defaultUnit)

	vulns := r.scanUnit(unitDir + "extra.tf")
	require.Len(t, vulns, 1)
	require.True(t, vulns[0].IsSuppressed)
	require.Equal(t, model.SuppressionJustificationIgnoreComment, vulns[0].SuppressionJustification)
}

func TestTerragruntUnitOverrideFilePatchesModuleBlock(t *testing.T) {
	r := newTerragruntRepo(t, "resource \"aws_s3_bucket\" \"this\" {\n  acl = \"private\"\n}\n")
	override := r.write(unitDir+"main_override.tf", "resource \"aws_s3_bucket\" \"this\" {\n  acl = \"public-read\"\n}\n")
	r.write(unitDir+"terragrunt.hcl", defaultUnit)

	vulns := r.scanUnit(unitDir + "main_override.tf")
	require.Len(t, vulns, 1, "the merged bucket is reported once")
	require.Equal(t, override, vulns[0].FileName, "on the override file that sets the value")
	require.Equal(t, 2, vulns[0].Line)
	require.Equal(t, "live/prod/main_override.tf", vulns[0].ModuleAttribution.ModuleCodeLocation.Filename)
	require.Equal(t, 2, vulns[0].ModuleAttribution.ModuleCodeLocation.LineStart)
}

func TestTerragruntUnitFileShadowsModuleFile(t *testing.T) {
	r := newTerragruntRepo(t, publicModule)
	r.write(unitDir+"main.tf", "resource \"aws_s3_bucket\" \"this\" {\n  acl = \"private\"\n}\n")
	r.write(unitDir+"terragrunt.hcl", defaultUnit)

	files := append(r.files(), r.unitFiles(true, unitDir+"main.tf")...)
	files = append(files, r.parseUnit(filepath.Join(r.root, "live", "prod", "terragrunt.hcl")))
	for _, v := range r.inspect(files) {
		// Only the module as written remains: the unit's call never instantiates its file.
		require.Equal(t, filepath.Join(r.root, "modules", "bucket", "main.tf"), v.FileName)
		require.Nil(t, v.ModuleAttribution, "no finding comes from the unit's call")
	}
}

func TestTerragruntUnitFilesFlagOffUnchanged(t *testing.T) {
	r := newTerragruntRepo(t, privateBucketModule)
	extra := r.write(unitDir+"extra.tf", "resource \"aws_s3_bucket\" \"extra\" {\n  acl = \"public-read\"\n}\n")
	vulns := r.inspect(r.unitFiles(false, unitDir+"extra.tf"))
	require.Len(t, vulns, 1)
	require.Equal(t, extra, vulns[0].FileName)
}

func TestTerragruntUnitWithoutTerraformFilesUnchanged(t *testing.T) {
	r := newTerragruntRepo(t, publicModule)
	r.write(unitDir+"terragrunt.hcl", publicUnit)
	vulns := r.scanUnit()
	require.Len(t, vulns, 1)
	require.Equal(t, filepath.Join(r.root, "modules", "bucket", "main.tf"), vulns[0].FileName)
}

func TestTerragruntUnitFileExcludedFromCopyIsScannedOnItsOwn(t *testing.T) {
	r := newTerragruntRepo(t, privateBucketModule)
	extra := r.write(unitDir+"extra.tf", extraTF)
	r.write(unitDir+"terragrunt.hcl",
		"terraform {\n  source = \"../../modules/bucket\"\n  exclude_from_copy = [\"extra.tf\"]\n}\ninputs = { acl = \"public-read\" }\n")
	vulns := r.scanUnit(unitDir + "extra.tf")
	// Not copied: no part of the module, so no call chain; its own scan takes the inputs.
	require.Len(t, vulns, 1)
	require.Equal(t, extra, vulns[0].FileName)
	require.Nil(t, vulns[0].ModuleAttribution)
}

// The module cannot be resolved (here a remote source with nothing fetched):
// the unit's files are scanned on their own, with the unit's inputs.
func TestTerragruntUnresolvedModuleFallsBackToInputs(t *testing.T) {
	r := newTerragruntRepo(t, privateBucketModule)
	extra := r.write(unitDir+"extra.tf", extraTF)
	r.write(unitDir+"terragrunt.hcl", "terraform {\n  source = \"tfr:///acme/bucket/aws?version=1.0.0\"\n}\ninputs = { acl = \"public-read\" }\n")

	vulns := r.scanUnit(unitDir + "extra.tf")
	require.Len(t, vulns, 1, "the inputs, not the file's own defaults, decide")
	require.Equal(t, extra, vulns[0].FileName)
	require.Equal(t, 3, vulns[0].Line)
}

func TestTerragruntFetchedModuleUnitFile(t *testing.T) {
	fx := newRemoteBucketFixture(t)
	r := &terragruntRepo{root: fx.root, t: t}
	extra := r.write("stack/extra.tf", extraTF)
	unit := r.write("stack/terragrunt.hcl", "terraform {\n  source = \"tfr://"+remoteBucketSource+"?version="+remoteBucketVersion+
		"\"\n}\n\ninputs = {\n  acl = \"public-read\"\n}\n")
	files := append(parseTerraform(t, fx.modPath), r.unitFiles(true, "stack/extra.tf")...)
	files = append(files, r.parseUnit(unit))

	ins := newTestInspector(t, inspectorOpts{
		queries: []model.QueryMetadata{{
			Query: "acl_rule", Content: aclRule, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "acl-rule"}, Aggregation: 1,
		}},
		repoPath: fx.root, vb: DefaultVulnerabilityBuilder, flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	registerTerragruntRemote(ins, fx)
	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)

	require.Len(t, vulnsIn(vulns, extra), 1)
	require.Equal(t, 3, vulnsIn(vulns, extra)[0].Line)
	require.Equal(t, "stack/extra.tf", vulnsIn(vulns, extra)[0].ModuleAttribution.ModuleCodeLocation.Filename)
	require.Len(t, vulnsIn(vulns, fx.modPath), 1, "the module's own bucket")
	require.Len(t, vulns, 2)
}

func TestTerragruntUnitFilesDoNotAffectAnotherUnitOfTheModule(t *testing.T) {
	r := newTerragruntRepo(t, "resource \"aws_s3_bucket\" \"this\" {\n  acl = \"private\"\n}\n")
	override := r.write("live/a/main_override.tf", "resource \"aws_s3_bucket\" \"this\" {\n  acl = \"public-read\"\n}\n")
	r.write("live/a/terragrunt.hcl", defaultUnit)
	r.write("live/b/terragrunt.hcl", defaultUnit)

	files := append(r.files("live/a/terragrunt.hcl", "live/b/terragrunt.hcl"), r.unitFiles(true, "live/a/main_override.tf")...)
	vulns := r.inspect(files)
	require.Len(t, vulns, 1)
	require.Equal(t, override, vulns[0].FileName)
	require.Contains(t, vulns[0].ModuleCallChain, "live/a/terragrunt.hcl")
}

func TestTerragruntOverrideOfOneUnitDoesNotMoveAnotherUnitsFinding(t *testing.T) {
	r := newTerragruntRepo(t, "variable \"acl\" {\n  default = \"private\"\n}\n\nresource \"aws_s3_bucket\" \"this\" {\n  acl = var.acl\n}\n")
	override := r.write("live/a/main_override.tf", "resource \"aws_s3_bucket\" \"this\" {\n  acl = \"public-read\"\n}\n")
	r.write("live/a/terragrunt.hcl", defaultUnit)
	r.write("live/b/terragrunt.hcl", "terraform {\n  source = \"../../modules/bucket\"\n}\ninputs = { acl = \"public-read\" }\n")

	files := append(r.files("live/a/terragrunt.hcl", "live/b/terragrunt.hcl"), r.unitFiles(true, "live/a/main_override.tf")...)
	vulns := r.inspect(files)
	require.Len(t, vulns, 2)
	module := filepath.Join(r.root, "modules", "bucket", "main.tf")
	for _, v := range vulns {
		if v.ModuleAttribution != nil && v.ModuleAttribution.CallSite.Filename == "live/b/terragrunt.hcl" {
			require.Equal(t, module, v.FileName)
			require.Equal(t, "modules/bucket/main.tf", v.ModuleAttribution.ModuleCodeLocation.Filename)
			require.Equal(t, 6, v.Line)
		} else {
			require.Equal(t, override, v.FileName)
			require.Equal(t, "live/a/main_override.tf", v.ModuleAttribution.ModuleCodeLocation.Filename)
		}
	}
}

func TestTerragruntUnitsOverridingTheSameWayReportOnTheirOwnFile(t *testing.T) {
	r := newTerragruntRepo(t, "resource \"aws_s3_bucket\" \"this\" {\n  acl = \"private\"\n}\n")
	const override = "resource \"aws_s3_bucket\" \"this\" {\n  acl = \"public-read\"\n}\n"
	a := r.write("live/a/main_override.tf", override)
	b := r.write("live/b/main_override.tf", override)
	r.write("live/a/terragrunt.hcl", defaultUnit)
	r.write("live/b/terragrunt.hcl", defaultUnit)

	files := append(r.files("live/a/terragrunt.hcl", "live/b/terragrunt.hcl"),
		r.unitFiles(true, "live/a/main_override.tf", "live/b/main_override.tf")...)
	var got, located []string
	for _, v := range r.inspect(files) {
		got = append(got, v.FileName)
		located = append(located, v.ModuleAttribution.ModuleCodeLocation.Filename)
	}
	require.ElementsMatch(t, []string{a, b}, got)
	require.ElementsMatch(t, []string{"live/a/main_override.tf", "live/b/main_override.tf"}, located)
}

func TestIndexKeepsUnitModuleFilesOutOfTheirDirectory(t *testing.T) {
	r := newTerragruntRepo(t, privateBucketModule)
	extra := r.write(unitDir+"extra.tf", extraTF)
	other := r.write(unitDir+"other.tf", extraTF)
	unit := r.write(unitDir+"terragrunt.hcl", "terraform {\n  source = \"../../modules/bucket\"\n  exclude_from_copy = [\"other.tf\"]\n}\n")
	files := append(r.unitFiles(true, unitDir+"extra.tf", unitDir+"other.tf"), r.parseUnit(unit))

	byPath, byDir, dirs := indexTerraformFiles(context.Background(), files, r.root, unitModuleFiles(files, r.root))
	require.Contains(t, byPath, extra, "still attributed by path")
	var names []string
	for _, f := range byDir[filepath.Dir(unit)] {
		names = append(names, filepath.Base(f.FilePath))
	}
	require.ElementsMatch(t, []string{"terragrunt.hcl", filepath.Base(other)}, names)
	require.True(t, dirs[filepath.Dir(unit)])
}

const (
	sgRule = `package datadog

DatadogPolicy contains result if {
	some name, i
	sg := input.document[i].resource.aws_security_group[name]
	sg.ingress.cidr_blocks[_] == "0.0.0.0/0"

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_security_group",
		"resourceName": name,
		"searchKey": sprintf("aws_security_group[%s].ingress", [name]),
	}
}
`
	sgModule = "resource \"aws_security_group\" \"this\" {\n  name = \"sg\"\n\n  ingress {\n    cidr_blocks = [\"10.0.0.0/8\"]\n  }\n}\n"
	sgBlock  = "  ingress {\n    cidr_blocks = [\"0.0.0.0/0\"]\n  }\n}\n"
)

func (r *terragruntRepo) inspectSG(files model.FileMetadatas) []model.Vulnerability {
	r.t.Helper()
	ins := newTestInspector(r.t, inspectorOpts{
		queries: []model.QueryMetadata{{
			Query: "sg_rule", Content: sgRule, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "sg-rule"}, Aggregation: 1,
		}},
		repoPath: r.root, vb: DefaultVulnerabilityBuilder, flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(r.t, err)
	require.Empty(r.t, ins.GetFailedQueries())
	return vulns
}

func TestTerragruntUnitNestedBlockOverrideCodeLocation(t *testing.T) {
	r := newTerragruntRepo(t, sgModule)
	override := r.write(unitDir+"main_override.tf", "resource \"aws_security_group\" \"this\" {\n"+sgBlock)
	unit := r.write(unitDir+"terragrunt.hcl", defaultUnit)
	files := append(r.files(), r.unitFiles(true, unitDir+"main_override.tf")...)
	vulns := r.inspectSG(append(files, r.parseUnit(unit)))
	require.Len(t, vulns, 1)
	require.Equal(t, override, vulns[0].FileName)
	require.Equal(t, "live/prod/main_override.tf", vulns[0].ModuleAttribution.ModuleCodeLocation.Filename)
}

func TestTerragruntUnitsWithTheSameNestedOverrideKeepTheirOwnFile(t *testing.T) {
	r := newTerragruntRepo(t, sgModule)
	a := r.write("live/a/main_override.tf", "resource \"aws_security_group\" \"this\" {\n  # dd-iac-scan ignore-line\n"+sgBlock)
	b := r.write("live/b/main_override.tf", "resource \"aws_security_group\" \"this\" {\n"+sgBlock)
	r.write("live/a/terragrunt.hcl", defaultUnit)
	r.write("live/b/terragrunt.hcl", defaultUnit)
	files := append(r.files("live/a/terragrunt.hcl", "live/b/terragrunt.hcl"),
		r.unitFiles(true, "live/a/main_override.tf", "live/b/main_override.tf")...)

	byFile := map[string]model.Vulnerability{}
	for _, v := range r.inspectSG(files) {
		byFile[v.FileName] = v
	}
	require.Len(t, byFile, 2)
	require.True(t, byFile[a].IsSuppressed, "the comment of a's override file")
	require.False(t, byFile[b].IsSuppressed, "b's own override file has no comment")
	require.Equal(t, "live/b/main_override.tf", byFile[b].ModuleAttribution.ModuleCodeLocation.Filename)
}

func TestTerragruntUnitFileReadsUnitAsset(t *testing.T) {
	r := newTerragruntRepo(t, privateBucketModule)
	extra := r.write(unitDir+"extra.tf", "resource \"aws_s3_bucket\" \"extra\" {\n  acl = file(\"acl.txt\")\n}\n")
	r.write(unitDir+"acl.txt", "public-read")
	r.write(unitDir+"terragrunt.hcl", defaultUnit)

	vulns := r.scanUnit(unitDir + "extra.tf")
	require.Len(t, vulns, 1, "the asset beside the unit is copied next to the module")
	require.Equal(t, extra, vulns[0].FileName)
	require.Equal(t, "live/prod/extra.tf", vulns[0].ModuleAttribution.ModuleCodeLocation.Filename)
}

func TestTerragruntAssetOnlyUnitOverridesModuleAsset(t *testing.T) {
	r := newTerragruntRepo(t, "resource \"aws_s3_bucket\" \"this\" {\n  acl = file(\"${path.module}/acl.txt\")\n}\n")
	r.write("modules/bucket/acl.txt", "private")
	r.write(unitDir+"acl.txt", "public-read")
	r.write(unitDir+"terragrunt.hcl", defaultUnit)

	vulns := r.scanUnit()
	require.Len(t, vulns, 1, "the unit's asset replaces the module's next to it")
	require.Equal(t, filepath.Join(r.root, "modules", "bucket", "main.tf"), vulns[0].FileName)
	require.Equal(t, "live/prod/terragrunt.hcl", vulns[0].ModuleAttribution.CallSite.Filename)

	r.write(unitDir+"acl.txt", "private")
	require.Empty(t, r.scanUnit())
}

func TestTerragruntUnitWithNothingCopiedKeepsThePlainView(t *testing.T) {
	r := newTerragruntRepo(t, "resource \"aws_s3_bucket\" \"this\" {\n  acl = file(\"${path.module}/acl.txt\")\n}\n")
	r.write("modules/bucket/acl.txt", "public-read")
	unit := r.write(unitDir+"terragrunt.hcl", defaultUnit)
	files := r.files()
	files = append(files, r.parseUnit(unit))
	require.Empty(t, unitModuleFiles(files, r.root), "only terragrunt.hcl: nothing to overlay")
	require.Len(t, r.inspect(files), 1)
}
