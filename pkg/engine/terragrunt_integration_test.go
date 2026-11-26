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
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	terraformParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/terragrunt"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	scanUtils "github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

const (
	bucketModule = "variable \"acl\" {\n  default = \"%s\"\n}\n\nresource \"aws_s3_bucket\" \"this\" {\n  acl = var.acl\n}\n"
	publicModule = "variable \"acl\" {\n  default = \"public-read\"\n}\n\nresource \"aws_s3_bucket\" \"this\" {\n  acl = var.acl\n}\n"
	// Lines: source is line 2, the acl input line 6.
	publicUnit  = "terraform {\n  source = \"../../modules/bucket\"\n}\n\ninputs = {\n  acl = \"public-read\"\n}\n"
	defaultUnit = "terraform {\n  source = \"../../modules/bucket\"\n}\n"
)

type terragruntRepo struct {
	root string
	t    *testing.T
}

func newTerragruntRepo(t *testing.T, module string) *terragruntRepo {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	r := &terragruntRepo{root: root, t: t}
	r.write("modules/bucket/main.tf", module)
	return r
}

func (r *terragruntRepo) write(rel, content string) string {
	r.t.Helper()
	p := filepath.Join(r.root, filepath.FromSlash(rel))
	return writeFile(r.t, filepath.Dir(p), filepath.Base(p), content)
}

// parseUnit parses a terragrunt.hcl with Terragrunt enabled.
func (r *terragruntRepo) parseUnit(path string) *model.FileMetadata {
	return r.parseUnitWith(path, nil)
}

// parseUnitWith also gives the parser the fetched module directories.
func (r *terragruntRepo) parseUnitWith(path string, fetched terragrunt.ModuleDirs) *model.FileMetadata {
	r.t.Helper()
	content, err := os.ReadFile(filepath.Clean(path))
	require.NoError(r.t, err)
	p := terraformParser.NewDefaultWithParams(vfs.DiskFS{}, "", model.SCIInfo{RepositoryDir: r.root})
	p.EnableTerragrunt()
	p.SetFetchedModules(fetched)
	out, handled, err := p.ParseUnit(context.Background(), content, path)
	require.NoError(r.t, err)
	require.True(r.t, handled)
	require.Len(r.t, out.Documents, 1)
	return &model.FileMetadata{
		ID:                    uuid.NewString(),
		ScanID:                "test",
		Document:              out.Documents[0],
		LineInfoDocument:      out.Documents[0],
		OriginalData:          string(content),
		Kind:                  model.KindTerraform,
		FilePath:              path,
		LinesIgnore:           out.IgnoreLines,
		LinesOriginalData:     scanUtils.SplitLines(string(content)),
		TerragruntTranslation: out.TerragruntTranslation,
		TerragruntInputs:      out.TerragruntInputs,
	}
}

// parseTF parses a .tf file of a unit's directory, with Terragrunt enabled or not.
func (r *terragruntRepo) parseTF(path string, terragrunt bool) model.FileMetadatas {
	r.t.Helper()
	content, err := os.ReadFile(filepath.Clean(path))
	require.NoError(r.t, err)
	p := terraformParser.NewDefaultWithParams(vfs.DiskFS{}, "", model.SCIInfo{RepositoryDir: r.root})
	if terragrunt {
		p.EnableTerragrunt()
	}
	_, docs, ignore, resolved, err := p.Parse(context.Background(), content, path, true, 15)
	require.NoError(r.t, err)
	var out model.FileMetadatas
	for _, doc := range docs {
		out = append(out, &model.FileMetadata{
			ID: uuid.NewString(), ScanID: "test", Document: doc, LineInfoDocument: doc,
			OriginalData: string(content), Kind: model.KindTerraform, FilePath: path,
			LinesIgnore: ignore, ResolvedFiles: resolved, LinesOriginalData: scanUtils.SplitLines(string(content)),
		})
	}
	return out
}

// unitFiles parses the unit and the .tf files of its directory.
func (r *terragruntRepo) unitFiles(terragrunt bool, tfs ...string) model.FileMetadatas {
	r.t.Helper()
	var files model.FileMetadatas
	for _, rel := range tfs {
		files = append(files, r.parseTF(filepath.Join(r.root, filepath.FromSlash(rel)), terragrunt)...)
	}
	return files
}

const (
	defaultACLTF  = "variable \"acl\" {\n  default = \"%s\"\n}\n\nresource \"aws_s3_bucket\" \"this\" {\n  acl = var.acl\n}\n"
	noSourceUnit  = "inputs = {\n  acl = \"public-read\"\n}\n"
	envInputUnit  = "inputs = {\n  acl = get_env(\"DD_TEST_UNSET_ACL\")\n}\n"
	unitModuleTF  = "variable \"acl\" {\n  default = \"private\"\n}\n\nmodule \"bucket\" {\n  source = \"../../modules/bucket\"\n  acl    = var.acl\n}\n"
	unitMainTFRel = "live/prod/main.tf"
)

func TestTerragruntUnitWithoutSourceFeedsItsTerraformFiles(t *testing.T) {
	r := newTerragruntRepo(t, bucketModule2("private"))
	main := r.write(unitMainTFRel, fmt.Sprintf(defaultACLTF, "private"))
	unit := r.write("live/prod/terragrunt.hcl", noSourceUnit)

	files := append(r.unitFiles(true, unitMainTFRel), r.parseUnit(unit))
	vulns := r.inspect(files)
	require.Len(t, vulns, 1)
	require.Equal(t, main, vulns[0].FileName, "the finding is on the unit's own .tf file")
}

func TestTerragruntUnitWithoutSourceUnknownInputKeepsDefaultOut(t *testing.T) {
	r := newTerragruntRepo(t, bucketModule2("private"))
	r.write(unitMainTFRel, fmt.Sprintf(defaultACLTF, "public-read"))
	unit := r.write("live/prod/terragrunt.hcl", envInputUnit)

	files := append(r.unitFiles(true, unitMainTFRel), r.parseUnit(unit))
	require.Empty(t, r.inspect(files), "an unknown input must not fall back to the insecure default")
}

func TestTerragruntUnitWithoutSourcePassesInputsToCalledModule(t *testing.T) {
	r := newTerragruntRepo(t, publicModule)
	r.write(unitMainTFRel, unitModuleTF)
	unit := r.write("live/prod/terragrunt.hcl", noSourceUnit)

	files := append(r.files(), r.unitFiles(true, unitMainTFRel)...)
	files = append(files, r.parseUnit(unit))
	vulns := r.inspect(files)
	require.Len(t, vulns, 1)
	require.Equal(t, filepath.Join(r.root, "modules", "bucket", "main.tf"), vulns[0].FileName)
	require.Equal(t, "live/prod/main.tf", vulns[0].ModuleAttribution.CallSite.Filename)
}

func TestTerragruntUnitWithoutSourceTfvarsOverrideInputs(t *testing.T) {
	r := newTerragruntRepo(t, bucketModule2("private"))
	r.write(unitMainTFRel, fmt.Sprintf(defaultACLTF, "private"))
	r.write("live/prod/terraform.tfvars", "acl = \"private\"\n")
	unit := r.write("live/prod/terragrunt.hcl", noSourceUnit)

	files := append(r.unitFiles(true, unitMainTFRel), r.parseUnit(unit))
	require.Empty(t, r.inspect(files))
}

func TestTerragruntUnitWithoutSourceFlagOffUnchanged(t *testing.T) {
	r := newTerragruntRepo(t, bucketModule2("private"))
	r.write(unitMainTFRel, fmt.Sprintf(defaultACLTF, "private"))
	r.write("live/prod/terragrunt.hcl", noSourceUnit)

	require.Empty(t, r.inspect(r.unitFiles(false, unitMainTFRel)), "the default applies without the flag")
}

const (
	// The module declares acl but its bucket does not use it.
	fixedACLModule = "variable \"acl\" {\n  default = \"private\"\n}\n\nresource \"aws_s3_bucket\" \"this\" {\n  acl = \"private\"\n}\n"
	extraTFRel     = "live/prod/extra.tf"
	extraUsesVar   = "resource \"aws_s3_bucket\" \"extra\" {\n  acl = var.acl\n}\n"
	extraDeclares  = "variable \"acl\" {\n  default = \"private\"\n}\n\n" + extraUsesVar
)

func TestTerragruntUnitWithSourceFeedsItsDirectoryTerraformFiles(t *testing.T) {
	for name, extraTF := range map[string]string{"declared in the source module only": extraUsesVar, "declared in extra.tf": extraDeclares} {
		t.Run(name, func(t *testing.T) {
			r := newTerragruntRepo(t, fixedACLModule)
			extra := r.write(extraTFRel, extraTF)
			unit := r.write("live/prod/terragrunt.hcl", publicUnit)

			files := append(r.files(), r.unitFiles(true, extraTFRel)...)
			files = append(files, r.parseUnit(unit))
			vulns := r.inspect(files)
			require.Len(t, vulns, 1)
			require.Equal(t, extra, vulns[0].FileName)
		})
	}
}

func TestTerragruntUnitWithSourceInputsStillReachModuleCall(t *testing.T) {
	r := newTerragruntRepo(t, publicModule)
	extra := r.write(extraTFRel, extraUsesVar)
	unit := r.write("live/prod/terragrunt.hcl", publicUnit)

	files := append(r.files(), r.unitFiles(true, extraTFRel)...)
	files = append(files, r.parseUnit(unit))
	var got []string
	for _, v := range r.inspect(files) {
		got = append(got, v.FileName)
	}
	require.ElementsMatch(t, []string{extra, filepath.Join(r.root, "modules", "bucket", "main.tf")}, got)
}

func TestTerragruntUnitWithSourceUnknownInputsFeedNothing(t *testing.T) {
	r := newTerragruntRepo(t, fixedACLModule)
	r.write(extraTFRel, extraDeclares)
	unit := r.write("live/prod/terragrunt.hcl", "terraform {\n  source = \"../../modules/bucket\"\n}\ninputs = { (get_env(\"DD_TEST_UNSET_K\")) = 1 }\n")

	files := append(r.files(), r.unitFiles(true, extraTFRel)...)
	require.Empty(t, r.inspect(append(files, r.parseUnit(unit))))
}

func TestTerragruntSkippedUnitFeedsNothing(t *testing.T) {
	r := newTerragruntRepo(t, fixedACLModule)
	r.write(extraTFRel, extraDeclares)
	unit := r.write("live/prod/terragrunt.hcl", "skip = true\n"+publicUnit)

	files := append(r.files(), r.unitFiles(true, extraTFRel)...)
	require.Empty(t, r.inspect(append(files, r.parseUnit(unit))))
}

func bucketModule2(acl string) string { return fmt.Sprintf(bucketModule, acl) }

func (r *terragruntRepo) files(units ...string) model.FileMetadatas {
	r.t.Helper()
	files := parseTerraform(r.t, filepath.Join(r.root, "modules", "bucket", "main.tf"))
	for _, u := range units {
		files = append(files, r.parseUnit(filepath.Join(r.root, filepath.FromSlash(u))))
	}
	return files
}

func (r *terragruntRepo) inspect(files model.FileMetadatas) []model.Vulnerability {
	r.t.Helper()
	return r.inspectWithVars(files, nil)
}

func (r *terragruntRepo) inspectWithVars(files model.FileMetadatas, vars map[string]cty.Value) []model.Vulnerability {
	r.t.Helper()
	ins := newTestInspector(r.t, inspectorOpts{
		queries: []model.QueryMetadata{{
			Query: "acl_rule", Content: aclRule, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "acl-rule"}, Aggregation: 1,
		}},
		repoPath:      r.root,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	if vars != nil {
		ins.SetTerraformRootVars(vars)
	}
	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(r.t, err)
	require.Empty(r.t, ins.GetFailedQueries())
	return vulns
}

func TestTerragruntExplicitVarsBeatUnitInputsForCalledModule(t *testing.T) {
	r := newTerragruntRepo(t, publicModule)
	r.write(unitMainTFRel, unitModuleTF)
	unit := r.write("live/prod/terragrunt.hcl", noSourceUnit)
	parse := func() model.FileMetadatas {
		files := append(r.files(), r.unitFiles(true, unitMainTFRel)...)
		return append(files, r.parseUnit(unit))
	}

	explicit := map[string]cty.Value{"acl": cty.StringVal("private")}
	require.Empty(t, r.inspectWithVars(parse(), explicit), "explicit variables beat unit inputs")
	require.Len(t, r.inspect(parse()), 1, "control: the unit input applies without explicit variables")
}

func TestTerragruntInputPointsAtInputsLine(t *testing.T) {
	r := newTerragruntRepo(t, publicModule)
	r.write("live/prod/terragrunt.hcl", publicUnit)

	vulns := r.inspect(r.files("live/prod/terragrunt.hcl"))
	require.Len(t, vulns, 1)
	v := vulns[0]
	require.Equal(t, filepath.Join(r.root, "modules", "bucket", "main.tf"), v.FileName)
	attr := v.ModuleAttribution
	require.NotNil(t, attr)
	require.Equal(t, "live/prod/terragrunt.hcl", attr.CallSite.Filename)
	require.Equal(t, 6, attr.CallSite.LineStart, "the input that sets the value")
	require.Equal(t, 6, attr.CallSite.LineEnd)
	require.Equal(t, model.ArgumentControlCaller, attr.ArgumentControl)
	require.Len(t, attr.ModulePath, 1)
	require.Equal(t, "live/prod/terragrunt.hcl", attr.ModulePath[0].CodeLocation.Filename)
	require.Equal(t, 2, attr.ModulePath[0].CodeLocation.LineStart, "the terraform.source attribute")
}

func TestTerragruntRemovesStandaloneModuleResult(t *testing.T) {
	r := newTerragruntRepo(t, publicModule)
	require.Len(t, r.inspect(r.files()), 1, "scanned alone, the module default is insecure")

	r.write("live/prod/terragrunt.hcl", "terraform {\n  source = \"../../modules/bucket\"\n}\n\ninputs = {\n  acl = \"private\"\n}\n")
	require.Empty(t, r.inspect(r.files("live/prod/terragrunt.hcl")),
		"the unit overrides the default: no standalone finding is left")
}

func TestTerragruntModuleDefaultAnchorsAtSource(t *testing.T) {
	r := newTerragruntRepo(t, publicModule)
	r.write("live/prod/terragrunt.hcl", defaultUnit)

	vulns := r.inspect(r.files("live/prod/terragrunt.hcl"))
	require.Len(t, vulns, 1)
	attr := vulns[0].ModuleAttribution
	require.NotNil(t, attr)
	require.Equal(t, "live/prod/terragrunt.hcl", attr.CallSite.Filename)
	require.Equal(t, 2, attr.CallSite.LineStart, "the terraform.source attribute")
}

func TestTerragruntTfvarsInputPointsIntoTfvars(t *testing.T) {
	r := newTerragruntRepo(t, "variable \"acl\" {\n  default = \"private\"\n}\n\nresource \"aws_s3_bucket\" \"this\" {\n  acl = var.acl\n}\n")
	r.write("live/prod/terragrunt.hcl", defaultUnit)
	r.write("live/prod/terraform.tfvars", "# unit values\nacl = \"public-read\"\n")

	vulns := r.inspect(r.files("live/prod/terragrunt.hcl"))
	require.Len(t, vulns, 1)
	attr := vulns[0].ModuleAttribution
	require.NotNil(t, attr)
	require.Equal(t, "live/prod/terraform.tfvars", attr.CallSite.Filename)
	require.Equal(t, 2, attr.CallSite.LineStart)
	require.Equal(t, "live/prod/terragrunt.hcl", attr.ModulePath[0].CodeLocation.Filename)
}

func TestTerragruntIgnoreCommentSuppresses(t *testing.T) {
	r := newTerragruntRepo(t, publicModule)
	r.write("live/prod/terragrunt.hcl",
		"terraform {\n  source = \"../../modules/bucket\"\n}\n\ninputs = {\n  # dd-iac-scan ignore-line\n  acl = \"public-read\"\n}\n")

	vulns := r.inspect(r.files("live/prod/terragrunt.hcl"))
	require.Len(t, vulns, 1)
	require.Equal(t, 7, vulns[0].ModuleAttribution.CallSite.LineStart)
	require.True(t, vulns[0].IsSuppressed, "the comment of terragrunt.hcl applies")
	require.Equal(t, model.SuppressionJustificationIgnoreComment, vulns[0].SuppressionJustification)
}

func TestTerragruntUnknownInputRaisesNoFinding(t *testing.T) {
	r := newTerragruntRepo(t, publicModule)
	r.write("live/prod/terragrunt.hcl",
		"terraform {\n  source = \"../../modules/bucket\"\n}\n\ninputs = {\n  acl = get_env(\"ACL\")\n}\n")

	require.Empty(t, r.inspect(r.files("live/prod/terragrunt.hcl")),
		"an unknown input must not fall back to the insecure module default")
}

func TestTerragruntIdenticalUnitsReportDistinctly(t *testing.T) {
	r := newTerragruntRepo(t, publicModule)
	r.write("live/a/terragrunt.hcl", publicUnit)
	r.write("live/b/terragrunt.hcl", publicUnit)
	files := r.files("live/a/terragrunt.hcl", "live/b/terragrunt.hcl")
	// Both units call ../../modules/bucket from live/<x>.
	vulns := r.inspect(files)
	require.Len(t, vulns, 2)
	chains := map[string]bool{}
	callers := map[string]bool{}
	for _, v := range vulns {
		chains[v.ModuleCallChain] = true
		callers[v.ModuleAttribution.CallSite.Filename] = true
	}
	require.Len(t, chains, 2, "each unit has its own call chain")
	require.Equal(t, map[string]bool{"live/a/terragrunt.hcl": true, "live/b/terragrunt.hcl": true}, callers)
	for chain := range chains {
		require.Contains(t, chain, "terragrunt.hcl|module.terragrunt")
	}
}

func TestTerragruntInventoryCallSitesAreRemapped(t *testing.T) {
	r := newTerragruntRepo(t, publicModule)
	unit := r.write("live/prod/terragrunt.hcl", publicUnit)
	files := r.files("live/prod/terragrunt.hcl")

	fsys, sites := overlayTranslations(files, r.root, vfs.DiskFS{})
	evaluator := tfeval.NewWithFS(fsys)
	dir := filepath.Dir(unit)
	resources, _, _, err := evaluator.EvaluateModule(context.Background(), dir, evaluator.LoadRootVarsWithContext(context.Background(), dir))
	require.NoError(t, err)

	inv := &terraformInventory{
		sink: &collectingSink{}, repoPath: r.root, sites: sites, documents: documentOccurrenceIndex{},
		files: map[string]*model.FileMetadata{},
	}
	targets := &ruleTargets{types: map[string]bool{"aws_s3_bucket": true}}
	occurrences := inv.addRoot(dir, resources, true, targets)
	require.Len(t, occurrences, 1)
	for _, o := range occurrences {
		require.Len(t, o.Terraform.CallChain, 1)
		hop := o.Terraform.CallChain[0]
		require.Equal(t, unit, hop.File, "the unit, not the virtual file")
		require.Equal(t, 2, hop.Range.Start.Line, "the terraform.source attribute")
		require.Equal(t, "live/prod/terragrunt.hcl", o.Terraform.Attribution.CallSite.Filename)
	}
}

func TestTerragruntVirtualFileNameAvoidsRealFile(t *testing.T) {
	r := newTerragruntRepo(t, publicModule)
	r.write("live/prod/terragrunt.hcl", publicUnit)
	r.write("live/prod/terragrunt.generated.tf", "# a real file\n")
	files := r.files("live/prod/terragrunt.hcl")

	fsys, sites := overlayTranslations(files, r.root, vfs.DiskFS{})
	real, err := fsys.ReadFile(filepath.Join(r.root, "live", "prod", "terragrunt.generated.tf"))
	require.NoError(t, err)
	require.Equal(t, "# a real file\n", string(real))
	require.Len(t, sites.byFile, 1)
	for virtual := range sites.byFile {
		require.Equal(t, filepath.Join(r.root, "live", "prod", "terragrunt.generated_1.tf"), virtual)
	}
	vulns := r.inspect(files)
	require.Len(t, vulns, 1)
	require.Equal(t, 6, vulns[0].ModuleAttribution.CallSite.LineStart)
}

func TestNoTranslationKeepsFilesystem(t *testing.T) {
	fsys := vfs.DiskFS{}
	got, sites := overlayTranslations(model.FileMetadatas{{FilePath: "main.tf"}, nil}, "/repo", fsys)
	require.Nil(t, sites)
	require.Equal(t, vfs.FS(fsys), got)
}

func TestTerragruntThroughSymlinkedCheckout(t *testing.T) {
	r := newTerragruntRepo(t, publicModule)
	r.write("live/prod/terragrunt.hcl", publicUnit)
	alias := filepath.Join(t.TempDir(), "checkout")
	require.NoError(t, os.Symlink(r.root, alias))
	r.root = alias

	vulns := r.inspect(r.files("live/prod/terragrunt.hcl"))
	require.Len(t, vulns, 1, "virtual files never reach a symlink-resolving OS call")
	require.Equal(t, "live/prod/terragrunt.hcl", vulns[0].ModuleAttribution.CallSite.Filename)
	require.Equal(t, 6, vulns[0].ModuleAttribution.CallSite.LineStart)
}

const (
	twoBucketModule = "variable \"acl\" {\n  default = \"private\"\n}\n\nvariable \"log_acl\" {\n  default = \"private\"\n}\n\n" +
		"variable \"unit\" {\n  default = \"\"\n}\n\n" +
		"resource \"aws_s3_bucket\" \"shared\" {\n  acl = var.acl\n}\n\nresource \"aws_s3_bucket\" \"logs\" {\n  acl = var.log_acl\n}\n"
	// The shared acl input is on line 11, terraform.source on line 6.
	rootHCL = "locals {\n  module_dir = \"${get_parent_terragrunt_dir()}/modules\"\n}\n\nterraform {\n" +
		"  source = \"${local.module_dir}//bucket\"\n}\n\ninputs = {\n  unit = path_relative_to_include()\n  acl  = \"public-read\"\n}\n"
	includeRoot = "include \"root\" {\n  path = find_in_parent_folders(\"root.hcl\")\n}\n"
)

func TestTerragruntIncludedRootProvidesSourceAndSharedInputs(t *testing.T) {
	r := newTerragruntRepo(t, twoBucketModule)
	r.write("root.hcl", rootHCL)
	r.write("live/a/terragrunt.hcl", includeRoot+"\ninputs = {\n  log_acl = \"public-read\"\n}\n")
	r.write("live/b/terragrunt.hcl", includeRoot)

	vulns := r.inspect(r.files("live/a/terragrunt.hcl", "live/b/terragrunt.hcl"))
	require.Len(t, vulns, 3, "unit a: shared and logs; unit b: shared")

	chains := map[string]bool{}
	for _, v := range vulns {
		require.Equal(t, filepath.Join(r.root, "modules", "bucket", "main.tf"), v.FileName)
		attr := v.ModuleAttribution
		require.NotNil(t, attr)
		require.Len(t, attr.ModulePath, 1)
		require.Equal(t, "root.hcl", attr.ModulePath[0].CodeLocation.Filename, "terraform.source comes from root.hcl")
		require.Equal(t, 6, attr.ModulePath[0].CodeLocation.LineStart)
		chains[v.ModuleCallChain] = true
	}
	require.Len(t, chains, 2, "each unit has its own call chain")

	shared, own := 0, 0
	for _, v := range vulns {
		cs := v.ModuleAttribution.CallSite
		switch cs.Filename {
		case "root.hcl":
			shared++
			require.Equal(t, 11, cs.LineStart, "the shared input of root.hcl")
		case "live/a/terragrunt.hcl":
			own++
			require.Equal(t, 6, cs.LineStart, "the input of the unit")
		default:
			t.Fatalf("unexpected call site %s", cs.Filename)
		}
	}
	require.Equal(t, 2, shared)
	require.Equal(t, 1, own)
}

const sharedRootInputs = "inputs = {\n%s  acl = \"public-read\"\n}\n"

func includedRootRepo(t *testing.T, header, comment string) *terragruntRepo {
	r := newTerragruntRepo(t, publicModule)
	r.write("root.hcl", header+"terraform {\n  source = \"${get_parent_terragrunt_dir()}/modules/bucket\"\n}\n\n"+
		strings.Replace(sharedRootInputs, "%s", comment, 1))
	r.write("live/a/terragrunt.hcl", includeRoot)
	r.write("live/b/terragrunt.hcl", includeRoot)
	return r
}

func TestTerragruntIgnoreCommentInIncludedFileSuppresses(t *testing.T) {
	r := includedRootRepo(t, "", "  # dd-iac-scan ignore-line\n")
	vulns := r.inspect(r.files("live/a/terragrunt.hcl", "live/b/terragrunt.hcl"))
	require.Len(t, vulns, 2)
	for _, v := range vulns {
		require.Equal(t, "root.hcl", v.ModuleAttribution.CallSite.Filename)
		require.True(t, v.IsSuppressed, "the comment of root.hcl applies to every unit including it")
		require.Equal(t, model.SuppressionJustificationIgnoreComment, v.SuppressionJustification)
	}
}

func TestTerragruntIncludedFileWithoutCommentIsNotSuppressed(t *testing.T) {
	r := includedRootRepo(t, "", "")
	vulns := r.inspect(r.files("live/a/terragrunt.hcl", "live/b/terragrunt.hcl"))
	require.Len(t, vulns, 2)
	for _, v := range vulns {
		require.False(t, v.IsSuppressed)
	}
}

func TestTerragruntDisableCommandInIncludedFileSuppresses(t *testing.T) {
	r := includedRootRepo(t, "# dd-iac-scan disable=acl-rule\n", "")
	vulns := r.inspect(r.files("live/a/terragrunt.hcl"))
	require.Len(t, vulns, 1)
	require.True(t, vulns[0].IsSuppressed)
	require.Equal(t, model.SuppressionJustificationDisableInFile, vulns[0].SuppressionJustification)
}

// A unit's tfr:// source is translated to a registry address and version, so
// the module the pre-scan fetched for the unit's directory is found and
// instantiated with the unit's inputs.
func TestTerragruntRemoteRegistrySource(t *testing.T) {
	fx := newRemoteBucketFixture(t)
	r := &terragruntRepo{root: fx.root, t: t}
	unit := r.write("stack/terragrunt.hcl", "terraform {\n  source = \"tfr://"+remoteBucketSource+"?version="+remoteBucketVersion+
		"\"\n}\n\ninputs = {\n  acl = \"public-read\"\n}\n")
	files := append(parseTerraform(t, fx.modPath), r.parseUnit(unit))

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
	require.Empty(t, ins.GetFailedQueries())
	require.Len(t, vulns, 1)
	v := vulns[0]
	require.Equal(t, fx.modPath, v.FileName)
	require.NotNil(t, v.ModuleAttribution)
	require.Equal(t, "stack/terragrunt.hcl", v.ModuleAttribution.CallSite.Filename)
	require.Equal(t, 6, v.ModuleAttribution.CallSite.LineStart, "the input that sets the value")
	require.Equal(t, remoteBucketSource, v.ModuleAttribution.Source)
	require.Equal(t, remoteBucketVersion, v.ModuleAttribution.Version)
}

// registerTerragruntRemote registers the module the pre-scan fetched for the
// unit in fx.callerRoot, keyed on the unit directory and the name "terragrunt".
func registerTerragruntRemote(ins *Inspector, fx remoteBucketFixture) map[string]RemoteModuleDirectory {
	directory := RemoteModuleDirectory{Path: fx.cacheDir, PackageRoot: fx.cacheDir}
	provenance := RemoteModuleProvenance{
		Source: remoteBucketSource, ResolvedVersion: remoteBucketVersion, CanonicalSource: remoteBucketSource,
		SourceType: "registry", ModuleRoot: fx.cacheDir,
	}
	dirs := map[string]RemoteModuleDirectory{}
	provs := map[string]RemoteModuleProvenance{}
	for _, key := range []string{
		RemoteModuleKey(fx.callerRoot, remoteBucketSource, remoteBucketVersion),
		RemoteModuleCallKey(fx.callerRoot, remoteBucketSource, remoteBucketVersion, "terragrunt"),
		RemoteModuleCallKey(fx.callerRoot, remoteBucketSource, "", "terragrunt"),
	} {
		dirs[key], provs[key] = directory, provenance
	}
	ins.SetRemoteModuleDirectories(dirs)
	ins.SetRemoteModuleProvenance(provs)
	return dirs
}

// The fetched module's own terraform.tfvars apply like a local module's, and
// the finding is reported at the unit, since the file is outside the repository.
func TestTerragruntFetchedModuleTfvars(t *testing.T) {
	fx := newRemoteBucketFixture(t)
	require.NoError(t, os.WriteFile(filepath.Join(fx.cacheDir, "terraform.tfvars"), []byte(`acl = "public-read"`), 0o600))
	r := &terragruntRepo{root: fx.callerRoot, t: t}
	unit := r.write("terragrunt.hcl", "terraform {\n  source = \"tfr://"+remoteBucketSource+"?version="+remoteBucketVersion+
		"\"\n}\n\ninputs = {\n  acl = \"private\"\n}\n")
	ins := newTestInspector(t, inspectorOpts{
		queries: []model.QueryMetadata{{
			Query: "acl_rule", Content: aclRule, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "acl-rule"}, Aggregation: 1,
		}},
		repoPath: fx.callerRoot, vb: DefaultVulnerabilityBuilder, flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	dirs := registerTerragruntRemote(ins, fx)
	// Wired like scan: the parser finds the unit's fetched module in the pre-scan's directories.
	fetched := func(callerRoot, source, version string) string {
		d, _ := LookupRemoteDir(dirs, callerRoot, source, version, terragrunt.ModuleName)
		return d.Path
	}
	files := append(parseTerraform(t, fx.modPath), r.parseUnitWith(unit, fetched))

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	require.Len(t, vulns, 1)
	v := vulns[0]
	require.Equal(t, fx.modPath, v.FileName)
	require.NotNil(t, v.ModuleAttribution)
	require.Equal(t, "terragrunt.hcl", v.ModuleAttribution.CallSite.Filename)
	require.Equal(t, 2, v.ModuleAttribution.CallSite.LineStart, "the source attribute")
}

func TestTerragruntUnitWithoutSourceUnknownInputReachesCalledModule(t *testing.T) {
	r := newTerragruntRepo(t, publicModule)
	r.write(unitMainTFRel, strings.Replace(unitModuleTF, `default = "private"`, `default = "public-read"`, 1))
	unit := r.write("live/prod/terragrunt.hcl", envInputUnit)

	files := append(r.files(), r.unitFiles(true, unitMainTFRel)...)
	files = append(files, r.parseUnit(unit))
	require.Empty(t, r.inspect(files), "the unknown input must not let a default apply in the module")
}
