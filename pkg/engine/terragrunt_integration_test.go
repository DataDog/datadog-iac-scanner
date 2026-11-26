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

	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	terraformParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	scanUtils "github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
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
	r.t.Helper()
	content, err := os.ReadFile(filepath.Clean(path))
	require.NoError(r.t, err)
	p := terraformParser.NewDefaultWithParams(vfs.DiskFS{}, "", model.SCIInfo{RepositoryDir: r.root})
	p.EnableTerragrunt()
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
	}
}

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
	ins := newTestInspector(r.t, inspectorOpts{
		queries: []model.QueryMetadata{{
			Query: "acl_rule", Content: aclRule, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "acl-rule"}, Aggregation: 1,
		}},
		repoPath:      r.root,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(r.t, err)
	require.Empty(r.t, ins.GetFailedQueries())
	return vulns
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
