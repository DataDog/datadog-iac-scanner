package scan

import (
	"context"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/internal/storage"
	"github.com/DataDog/datadog-iac-scanner/internal/tracker"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The Terraform parser accepts terragrunt.hcl only when ShouldScanTerragrunt is set.
func TestTerraformParserAcceptsTerragruntOnlyWithFlag(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		params := &Parameters{
			PreviewLines:         3,
			RepoPath:             t.TempDir(),
			Path:                 []string{t.TempDir()},
			ShouldScanTerragrunt: enabled,
		}
		tr, err := tracker.NewTracker(params.PreviewLines)
		require.NoError(t, err)
		client := &Client{
			ScanParams:    params,
			Tracker:       tr,
			Storage:       storage.NewMemoryStorage(),
			FlagEvaluator: featureflags.NewLocalEvaluator(),
		}
		services, err := client.createService(context.Background(), nil, []string{params.Path[0]}, nil,
			client.Tracker, client.Storage, []string{"terraform"}, []string{""}, client.FlagEvaluator, nil, nil)
		require.NoError(t, err)

		found := false
		for _, s := range services {
			if s.Parser.Parsers.GetKind() != model.KindTerraform {
				continue
			}
			found = true
			_, ok := s.Parser.SupportedExtensions()["terragrunt.hcl"]
			assert.Equal(t, enabled, ok, "enabled=%v", enabled)
		}
		assert.True(t, found)
	}
}
