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

// TestJSONParserRegistration verifies that the JSON parser is only registered when ShouldScanTfPlans is true
func TestJSONParserRegistration(t *testing.T) {
	tests := []struct {
		name                    string
		shouldScanTfPlans       bool
		expectJSONParserPresent bool
	}{
		{
			name:                    "JSON parser registered when flag is true",
			shouldScanTfPlans:       true,
			expectJSONParserPresent: true,
		},
		{
			name:                    "JSON parser not registered when flag is false",
			shouldScanTfPlans:       false,
			expectJSONParserPresent: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			params := &Parameters{
				PreviewLines:      3,
				RepoPath:          t.TempDir(),
				Path:              []string{t.TempDir()},
				ShouldScanTfPlans: tt.shouldScanTfPlans,
			}

			tr, err := tracker.NewTracker(params.PreviewLines)
			require.NoError(t, err)

			client := &Client{
				ScanParams:    params,
				Tracker:       tr,
				Storage:       storage.NewMemoryStorage(),
				FlagEvaluator: featureflags.NewLocalEvaluator(),
			}

			// Create a mock inspector (we don't actually need to use it)
			// We just need to test the parser registration logic
			platforms := []string{"terraform"}
			cloudProviders := []string{""}

			// Call createService which contains the conditional JSON parser registration
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

			// Check if JSON parser is present in the services
			jsonParserFound := false
			for _, service := range services {
				if service.Parser != nil && service.Parser.Parsers != nil {
					if service.Parser.Parsers.GetKind() == model.KindJSON {
						jsonParserFound = true
						break
					}
				}
			}

			if tt.expectJSONParserPresent {
				assert.True(t, jsonParserFound,
					"JSON parser should be registered when ShouldScanTfPlans is true")
			} else {
				assert.False(t, jsonParserFound,
					"JSON parser should not be registered when ShouldScanTfPlans is false")
			}
		})
	}
}

// TestJSONParserBuilder verifies the parser builder correctly adds JSON parser based on flag
func TestJSONParserBuilder(t *testing.T) {
	ctx := context.Background()

	// First, create services without the flag to get baseline count
	paramsWithoutFlag := &Parameters{
		PreviewLines:      3,
		RepoPath:          t.TempDir(),
		Path:              []string{t.TempDir()},
		ShouldScanTfPlans: false,
	}

	tr1, err := tracker.NewTracker(paramsWithoutFlag.PreviewLines)
	require.NoError(t, err)

	clientWithoutFlag := &Client{
		ScanParams:    paramsWithoutFlag,
		Tracker:       tr1,
		Storage:       storage.NewMemoryStorage(),
		FlagEvaluator: featureflags.NewLocalEvaluator(),
	}

	platforms := []string{"terraform", "kubernetes", "cloudformation"}
	cloudProviders := []string{""}

	servicesWithoutFlag, err := clientWithoutFlag.createService(
		ctx,
		nil,
		[]string{paramsWithoutFlag.Path[0]},
		nil,
		clientWithoutFlag.Tracker,
		clientWithoutFlag.Storage,
		platforms,
		cloudProviders,
		clientWithoutFlag.FlagEvaluator,
		nil,
	)

	require.NoError(t, err)
	baselineCount := len(servicesWithoutFlag)

	// Check that JSON parser is NOT present when flag is false
	jsonParserFound := false
	for _, service := range servicesWithoutFlag {
		if service.Parser != nil && service.Parser.Parsers != nil {
			if service.Parser.Parsers.GetKind() == model.KindJSON {
				jsonParserFound = true
				break
			}
		}
	}
	assert.False(t, jsonParserFound, "JSON parser should not be present when flag is false")

	// Now create services with the flag enabled
	paramsWithFlag := &Parameters{
		PreviewLines:      3,
		RepoPath:          t.TempDir(),
		Path:              []string{t.TempDir()},
		ShouldScanTfPlans: true,
	}

	tr2, err := tracker.NewTracker(paramsWithFlag.PreviewLines)
	require.NoError(t, err)

	clientWithFlag := &Client{
		ScanParams:    paramsWithFlag,
		Tracker:       tr2,
		Storage:       storage.NewMemoryStorage(),
		FlagEvaluator: featureflags.NewLocalEvaluator(),
	}

	servicesWithFlag, err := clientWithFlag.createService(
		ctx,
		nil,
		[]string{paramsWithFlag.Path[0]},
		nil,
		clientWithFlag.Tracker,
		clientWithFlag.Storage,
		platforms,
		cloudProviders,
		clientWithFlag.FlagEvaluator,
		nil,
	)

	require.NoError(t, err)
	countWithFlag := len(servicesWithFlag)

	// Check that JSON parser IS present when flag is true
	jsonParserFound = false
	for _, service := range servicesWithFlag {
		if service.Parser != nil && service.Parser.Parsers != nil {
			if service.Parser.Parsers.GetKind() == model.KindJSON {
				jsonParserFound = true
				break
			}
		}
	}
	assert.True(t, jsonParserFound, "JSON parser should be present when flag is true")

	// When flag is enabled, we should have more services (JSON parser adds support for more platforms)
	assert.GreaterOrEqual(t, countWithFlag, baselineCount,
		"Should have at least as many parsers with flag enabled (found %d with flag vs %d without)", countWithFlag, baselineCount)
}

// TestCreateServiceWithTfPlanFlag is an integration-style test verifying the full flow
func TestCreateServiceWithTfPlanFlag(t *testing.T) {
	ctx := context.Background()

	t.Run("services created successfully with flag enabled", func(t *testing.T) {
		params := &Parameters{
			PreviewLines:      3,
			RepoPath:          t.TempDir(),
			Path:              []string{t.TempDir()},
			ShouldScanTfPlans: true,
		}

		tr, err := tracker.NewTracker(params.PreviewLines)
		require.NoError(t, err)

		client := &Client{
			ScanParams:    params,
			Tracker:       tr,
			Storage:       storage.NewMemoryStorage(),
			FlagEvaluator: featureflags.NewLocalEvaluator(),
		}

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
		assert.NotEmpty(t, services, "Services should be created")
	})

	t.Run("services created successfully with flag disabled", func(t *testing.T) {
		params := &Parameters{
			PreviewLines:      3,
			RepoPath:          t.TempDir(),
			Path:              []string{t.TempDir()},
			ShouldScanTfPlans: false,
		}

		tr, err := tracker.NewTracker(params.PreviewLines)
		require.NoError(t, err)

		client := &Client{
			ScanParams:    params,
			Tracker:       tr,
			Storage:       storage.NewMemoryStorage(),
			FlagEvaluator: featureflags.NewLocalEvaluator(),
		}

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
		assert.NotEmpty(t, services, "Services should be created even without JSON parser")
	})
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
		PreviewLines:      3,
		RepoPath:          t.TempDir(),
		Path:              []string{t.TempDir()},
		ShouldScanTfPlans: true,
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
