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
// the configuration, and a module directory the scan was not given is
// reported as missing.
func TestInspect_JsonConfigModuleCallEscalates(t *testing.T) {
	config := `{
  "module": {
    "net": {
      "source": "../modules/networking"
    }
  }
}`
	fsys := vfs.NewMemFS(map[string][]byte{
		"infra/main.json": []byte(config),
	})
	ins, err := NewInspector(context.Background(), &stubQueriesSource{}, DefaultVulnerabilityBuilder,
		&tracker.CITracker{}, &source.QueryInspectorParameters{}, nil, "", false, false, 1,
		featureflags.NewLocalEvaluator(), fsys, false)
	require.NoError(t, err)

	require.True(t, tfpath.LooksLikeJSONConfig([]byte(config)), "the content must be recognized as configuration for this test to be meaningful")

	// The parsed document of a Terraform JSON configuration carries the same
	// sections as a .tf document.
	files := model.FileMetadatas{{
		ID: "json-config", ScanID: "test", Kind: model.KindTerraform,
		FilePath: "infra/main.json", OriginalData: config,
		Document: model.Document{"module": map[string]interface{}{
			"net": map[string]interface{}{"source": "../modules/networking"},
		}},
	}}
	require.True(t, isTerraformConfigFile(files[0]), "the plain .json config must count as a Terraform configuration file")

	contract, legacy := splitTerraformRules([]model.QueryMetadata{{
		Query: "any_rule", Content: "package datadog\nx = 1", InputData: "{}",
		Platform: "terraform", Metadata: map[string]any{"id": "any_rule"}, Aggregation: 1,
	}})
	require.Empty(t, contract)
	require.Len(t, legacy, 1)
	require.True(t, declaresLocalModuleCall(files), "the .json module call must keep modeling on")

	_, err = ins.inspectTerraformLegacyStream(context.Background(), "test", files, legacy)
	require.NoError(t, err)
	require.Contains(t, fsys.MissingFiles(), "modules/networking",
		"the module directory the .json configuration calls must be escalated like a .tf call")
}
