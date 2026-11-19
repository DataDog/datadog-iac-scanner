package engine

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/internal/tracker"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/stretchr/testify/require"
)

// A plain .json file the scan recognizes as Terraform configuration by
// content escalates a local module call like a .tf file does: the model reads
// the configuration, so the checks that decide whether the model runs must
// see it, and a module directory the scan was not given is reported as
// missing.
func jsonConfigFixture(t *testing.T) (model.FileMetadatas, *vfs.MemFS) {
	t.Helper()
	config := `{
  "module": {
    "net": {
      "source": "../modules/networking"
    }
  }
}`
	require.True(t, tfpath.LooksLikeJSONConfig([]byte(config)),
		"the content must be recognized as configuration for this test to be meaningful")
	fsys := vfs.NewMemFS(map[string][]byte{"infra/main.json": []byte(config)})
	// The parsed document of a Terraform JSON configuration carries the same
	// sections as a .tf document.
	files := model.FileMetadatas{{
		ID: "json-config", ScanID: "test", Kind: model.KindTerraform,
		FilePath: "infra/main.json", OriginalData: config,
		Document: model.Document{"module": map[string]interface{}{
			"net": map[string]interface{}{"source": "../modules/networking"},
		}},
	}}
	return files, fsys
}

func jsonEscalationInspector(t *testing.T, fsys vfs.FS, rule model.QueryMetadata) *Inspector {
	t.Helper()
	ins, err := NewInspector(context.Background(), &stubQueriesSource{queries: []model.QueryMetadata{rule}},
		DefaultVulnerabilityBuilder, &tracker.CITracker{}, &source.QueryInspectorParameters{}, nil,
		"", false, false, 1, featureflags.NewLocalEvaluator(), fsys, false)
	require.NoError(t, err)
	return ins
}

func TestInspect_JsonConfigModuleCallEscalates(t *testing.T) {
	files, fsys := jsonConfigFixture(t)
	// The rule names a resource type the configuration does not declare, so
	// the decision to model rests on the module call alone.
	rule := model.QueryMetadata{
		Query: "bucket_rule", Content: rootBucketRule, InputData: "{}", Platform: "terraform",
		Metadata: map[string]interface{}{"id": "bucket-rule", "platform": "Terraform"}, Aggregation: 1,
	}
	ins := jsonEscalationInspector(t, fsys, rule)

	require.True(t, isTerraformConfigFile(files[0]), "the plain .json config must count as a Terraform configuration file")
	targets := ruleTargetedResourceTypes([]model.QueryMetadata{rule}, ins.terraformRuleLibraries()...)
	require.NotNil(t, targets)
	require.False(t, declaresTargetedResource(files, targets), "the configuration declares no targeted type")
	require.False(t, declaresExpandedBlock(files, targets))
	require.True(t, declaresLocalModuleCall(files), "the .json module call must keep modeling on")

	_, legacy := splitTerraformRules([]model.QueryMetadata{rule})
	_, err := ins.inspectTerraformLegacyStream(context.Background(), "test", files, legacy, false)
	require.NoError(t, err)
	require.Contains(t, fsys.MissingFiles(), "modules/networking",
		"the module directory the .json configuration calls must be escalated like a .tf call")
}

// readsFS records every path a filesystem is asked about.
type readsFS struct {
	vfs.FS
	paths []string
}

func (r *readsFS) ReadFile(name string) ([]byte, error) {
	r.paths = append(r.paths, name)
	return r.FS.ReadFile(name)
}

func (r *readsFS) Stat(name string) (fs.FileInfo, error) {
	r.paths = append(r.paths, name)
	return r.FS.Stat(name)
}

func (r *readsFS) ReadDir(name string) ([]fs.DirEntry, error) {
	r.paths = append(r.paths, name)
	return r.FS.ReadDir(name)
}

func (r *readsFS) Glob(pattern string) ([]string, error) {
	r.paths = append(r.paths, pattern)
	return r.FS.Glob(pattern)
}

func (r *readsFS) read(dir string) bool {
	return slices.ContainsFunc(r.paths, func(p string) bool { return strings.Contains(filepath.ToSlash(p), dir) })
}

// Once the model runs, only the roots that call a module or expand a targeted
// block are modeled. A root of plain blocks, such as a library module directory
// no scanned root calls, is scanned as written: its findings still come from
// its written document, and its directory is never read by the model.
func TestInspect_PlainRootsAreScannedAsWrittenWhenOthersAreModeled(t *testing.T) {
	const caller = `module "net" {
  source = "../modules/networking"
}
`
	const library = `resource "aws_s3_bucket" "lib" {
  bucket = "library"
}
`
	dir := t.TempDir()
	tree := map[string]string{
		"infra/main.tf":              caller,
		"modules/networking/main.tf": `variable "x" { default = 1 }`,
		"modules/library/main.tf":    library,
	}
	var files model.FileMetadatas
	for name, content := range tree {
		path := filepath.Join(dir, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	}
	files = append(files,
		&model.FileMetadata{
			ID: "caller", ScanID: "test", Kind: model.KindTerraform, Platform: "terraform",
			FilePath: filepath.Join(dir, "infra", "main.tf"), OriginalData: caller,
			Document: model.Document{"module": map[string]interface{}{
				"net": map[string]interface{}{"source": "../modules/networking"},
			}},
		},
		&model.FileMetadata{
			ID: "library", ScanID: "test", Kind: model.KindTerraform, Platform: "terraform",
			FilePath: filepath.Join(dir, "modules", "library", "main.tf"), OriginalData: library,
			Document: model.Document{"resource": map[string]interface{}{
				"aws_s3_bucket": map[string]interface{}{"lib": map[string]interface{}{"bucket": "library"}},
			}},
		},
	)
	rule := model.QueryMetadata{
		Query: "bucket_rule", Content: rootBucketRule, InputData: "{}", Platform: "terraform",
		Metadata: map[string]interface{}{"id": "bucket-rule", "platform": "Terraform"}, Aggregation: 1,
	}
	_, legacy := splitTerraformRules([]model.QueryMetadata{rule})
	ins := jsonEscalationInspector(t, vfs.DiskFS{}, rule)

	layout, err := ins.terraformLayout(context.Background(), files)
	require.NoError(t, err)
	written := ins.terraformFiles(files)
	targets := ruleTargetedResourceTypes(legacy, ins.terraformRuleLibraries()...)
	modeled, asWritten := legacyModeledRoots(layout.Roots, written, writtenByDir(written), targets)
	require.Equal(t, []string{filepath.Join(dir, "infra")}, modeled, "only the root calling a module is modeled")
	require.Equal(t, map[string]bool{filepath.Join(dir, "modules", "library", "main.tf"): true}, asWritten)

	vulns, err := ins.inspectTerraformLegacyStream(context.Background(), "test", files, legacy, false)
	require.NoError(t, err)
	require.Len(t, vulns, 1, "the library's bucket is found from its written document")
	require.Equal(t, "library", vulns[0].FileID)
}

// A local module call alone models the layout only where a read miss becomes
// an escalation request. On disk nothing is recorded, so the files are scanned
// as written, as main does: a repository of local module calls whose blocks no
// rule targets is not expanded root by root.
func TestInspect_LocalModuleCallModelsOnlyWhenMissesAreRecorded(t *testing.T) {
	const call = `module "net" {
  source = "../modules/networking"
}
`
	rule := model.QueryMetadata{
		Query: "bucket_rule", Content: rootBucketRule, InputData: "{}", Platform: "terraform",
		Metadata: map[string]interface{}{"id": "bucket-rule", "platform": "Terraform"}, Aggregation: 1,
	}
	_, legacy := splitTerraformRules([]model.QueryMetadata{rule})
	scanned := func(path string) model.FileMetadatas {
		return model.FileMetadatas{{
			ID: "root", ScanID: "test", Kind: model.KindTerraform, FilePath: path, OriginalData: call,
			Document: model.Document{"module": map[string]interface{}{
				"net": map[string]interface{}{"source": "../modules/networking"},
			}},
		}}
	}

	mem := vfs.NewMemFS(map[string][]byte{"infra/main.tf": []byte(call)})
	ins := jsonEscalationInspector(t, mem, rule)
	require.True(t, ins.recordsMissingFiles())
	_, err := ins.inspectTerraformLegacyStream(context.Background(), "test", scanned("infra/main.tf"), legacy, false)
	require.NoError(t, err)
	require.Contains(t, mem.MissingFiles(), "modules/networking")

	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "infra"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "modules", "networking"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "infra", "main.tf"), []byte(call), 0o600))
	disk := &readsFS{FS: vfs.DiskFS{}}
	ins = jsonEscalationInspector(t, disk, rule)
	require.False(t, ins.recordsMissingFiles())
	_, err = ins.inspectTerraformLegacyStream(context.Background(), "test", scanned(filepath.Join(dir, "infra", "main.tf")), legacy, false)
	require.NoError(t, err)
	require.False(t, disk.read("modules/networking"), "on disk the call is not modeled: %v", disk.paths)
}
