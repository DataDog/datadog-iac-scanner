package scan

import (
	"context"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/internal/storage"
	"github.com/DataDog/datadog-iac-scanner/internal/tracker"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/runner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestJSONParserRegistration verifies that the JSON parser is always registered
func TestJSONParserRegistration(t *testing.T) {
	ctx := context.Background()

	params := &Parameters{
		PreviewLines: 3,
		RepoPath:     t.TempDir(),
		Path:         []string{t.TempDir()},
	}

	tr, err := tracker.NewTracker(params.PreviewLines)
	require.NoError(t, err)

	client := &Client{
		ScanParams:    params,
		Tracker:       tr,
		Storage:       storage.NewMemoryStorage(),
		FlagEvaluator: featureflags.NewLocalEvaluator(),
	}

	platforms := []string{"terraform"}
	cloudProviders := []string{""}

	services, err := client.createService(
		ctx,
		nil, // inspector - not needed for this test
		[]string{params.Path[0]},
		nil, // remoteModulePaths
		client.Tracker,
		client.Storage,
		platforms,
		cloudProviders,
		client.FlagEvaluator,
		nil,
	)

	require.NoError(t, err)
	require.NotNil(t, services)

	jsonParserFound := false
	for _, service := range services {
		if service.Parser != nil && service.Parser.Parsers != nil {
			if service.Parser.Parsers.GetKind() == model.KindJSON {
				jsonParserFound = true
				break
			}
		}
	}
	assert.True(t, jsonParserFound, "JSON parser should always be registered")
}

// Helper function to count parsers of a specific type
func countParsersOfType(services []*runner.Service, parserType model.FileKind) int {
	count := 0
	for _, service := range services {
		if service.Parser != nil && service.Parser.Parsers != nil {
			if service.Parser.Parsers.GetKind() == parserType {
				count++
			}
		}
	}
	return count
}

// TestJSONParserNotDoubleRegistered ensures JSON parser isn't registered multiple times
func TestJSONParserNotDoubleRegistered(t *testing.T) {
	ctx := context.Background()

	params := &Parameters{
		PreviewLines: 3,
		RepoPath:     t.TempDir(),
		Path:         []string{t.TempDir()},
	}

	tr, err := tracker.NewTracker(params.PreviewLines)
	require.NoError(t, err)

	client := &Client{
		ScanParams:    params,
		Tracker:       tr,
		Storage:       storage.NewMemoryStorage(),
		FlagEvaluator: featureflags.NewLocalEvaluator(),
	}

	// Call createService multiple times
	for i := 0; i < 3; i++ {
		services, err := client.createService(
			ctx,
			nil,
			[]string{params.Path[0]},
			nil,
			client.Tracker,
			client.Storage,
			[]string{"terraform"},
			[]string{""},
			client.FlagEvaluator,
			nil,
		)

		require.NoError(t, err)
		require.NotNil(t, services)

		// Count JSON parsers - should only be one per service creation
		jsonCount := countParsersOfType(services, model.KindJSON)
		assert.LessOrEqual(t, jsonCount, 1,
			"Should have at most one JSON parser per service creation")
	}
}
