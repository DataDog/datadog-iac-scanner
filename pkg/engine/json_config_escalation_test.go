package engine

import (
	"context"
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

func jsonEscalationInspector(t *testing.T, fsys *vfs.MemFS, rule model.QueryMetadata) *Inspector {
	t.Helper()
	ins, err := NewInspector(context.Background(), &contractLibSource{queries: []model.QueryMetadata{rule}},
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
	_, err := ins.inspectTerraformLegacyStream(context.Background(), "test", files, legacy)
	require.NoError(t, err)
	require.Contains(t, fsys.MissingFiles(), "modules/networking",
		"the module directory the .json configuration calls must be escalated like a .tf call")
}
